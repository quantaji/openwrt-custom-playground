// SPDX-License-Identifier: GPL-2.0-only
/* Resume only the failed ELFfba7e78b's already-started diagnostic retirement. */
#include <linux/debugfs.h>
#include <linux/kprobes.h>
#include <linux/completion.h>
#include <linux/iopoll.h>
#include <linux/jiffies.h>
#include <linux/ktime.h>
#include <linux/qdx.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/qdx_diag_fq.h>
#include <linux/rcupdate.h>
#include <linux/seq_file.h>
#include <linux/skbuff.h>
#include <linux/sysfs.h>
#include <linux/uaccess.h>
#include <linux/unaligned.h>
#include "qdx_bf_retirement_recovery_offsets.h"
extern bool qdx_diag_fq_table_idle(struct qdx_dma *);
struct recovery_sections { struct attribute_group grp; struct bin_attribute attrs[]; };
struct recovery_packet { struct sk_buff *skb; u8 expected[64]; u32 id; };
static_assert(sizeof(struct module) == 1216);
static_assert(sizeof(struct mutex) == 32);
static_assert(sizeof(struct recovery_packet) == 80);
static_assert(sizeof(struct qdx_diag_fq_view) == 4416);
static const u8 expected_build_id[20] = {
 0xd4,0x83,0x98,0x4d,0xa4,0x4c,0xdc,0x52,0x91,0xe1,
 0x01,0xed,0xa1,0x0e,0xc3,0x82,0xb5,0x23,0xe1,0xca };
static bool allow_writes, joined, started;
module_param(allow_writes, bool, 0400);
static u32 stage, payload_mask, issued, acknowledged;
static u64 clock_ms, due_ms, host_start_ns, elapsed_ns;
#define WAIT_MS 3000
#define WINDOW_NS (30ULL * NSEC_PER_SEC)
#define BF_PARENT_TAG 0x6d020000U
#define BF_GROUP_TAG 0x6d030000U
#define TABLE_TAG 0x6d010000U
#define ORIGINAL_FREE 5
static int result;
static u8 group_before[232], timer_before[32];
static u8 manager[20], account[312];
static struct dentry *directory;
static DEFINE_MUTEX(recovery_lock);
static unsigned long recovery_section(struct module *module, const char *name)
{
 struct recovery_sections *sections = (void *)module->sect_attrs;
 const struct bin_attribute *const *entry;
 unsigned int i;
 if (!sections || !sections->grp.bin_attrs) return 0;
 entry = sections->grp.bin_attrs;
 for (i = 0; i < 64 && entry[i]; i++)
  if (!strcmp(entry[i]->attr.name, name)) return (unsigned long)entry[i]->private;
 return 0;
}
#define SLOT(type, name) ((type *)(REC_##name##_BASE + REC_##name))
#define FLAG(name) (*SLOT(bool, name))
#define WORD(name) (*SLOT(u32, name))
#define POINTER(type, name) (*SLOT(type *, name))
static int recovery_join(void)
{
 struct kprobe finder = { .symbol_name = "find_module" };
 struct kprobe snapshot = { .symbol_name = "qdx_mirror_state_diag:state_bf_snapshot" };
 struct module *(*find_named)(const char *);
 int (*snapshot_owned)(void);
 int (*bf_command)(u32, u32, u32);
 int (*leaf_command)(int, bool, unsigned int);
 struct module *module;
 struct mutex *lock;
 struct recovery_packet *packets;
 struct sk_buff **copies;
 struct qdx_diag_fq_view *view;
 unsigned long text, data, bss, note, this_section;
 unsigned int i;
 bool drained;
 int error;
 if (joined) return 0;
 /* A partial mutation retains the original command journals. Never replay it
  * by silently taking a new snapshot or overwriting the first proof window. */
 if (started) return -EALREADY;
 error = register_kprobe(&finder);
 if (error) return error;
 find_named = (void *)finder.addr; unregister_kprobe(&finder);
 rcu_read_lock();
 module = find_named("qdx_mirror_state_diag");
 if (module && !try_module_get(module)) module = NULL;
 rcu_read_unlock();
 if (!module) return -ENOENT;
 if (module->state != MODULE_STATE_LIVE || strcmp(module_name(module), "qdx_mirror_state_diag")) {
  error = -ESTALE; goto release_module;
 }
 text = recovery_section(module, ".text"); data = recovery_section(module, ".data");
 bss = recovery_section(module, ".bss"); note = recovery_section(module, ".note.gnu.build-id");
 this_section = recovery_section(module, ".gnu.linkonce.this_module");
 if (!text || !data || !bss || !note || this_section != (unsigned long)module ||
     !within_module_mem_type(text, module, MOD_TEXT) ||
     !within_module_mem_type(text + 0x90b7, module, MOD_TEXT) ||
     !within_module_mem_type(data, module, MOD_DATA) ||
     !within_module_mem_type(data + 0xaf, module, MOD_DATA) ||
     !within_module_mem_type(bss, module, MOD_DATA) ||
     !within_module_mem_type(bss + 0x7f1f, module, MOD_DATA) ||
     !within_module(note, module) || !within_module(note + 35, module)) {
  error = -ERANGE; goto release_module;
 }
 if (get_unaligned_le32((void *)note) != 4 || get_unaligned_le32((void *)(note + 4)) != 20 ||
     get_unaligned_le32((void *)(note + 8)) != 3 || memcmp((void *)(note + 12), "GNU", 4) ||
     memcmp((void *)(note + 16), expected_build_id, 20)) {
  error = -ESTALE; goto release_module;
 }
 error = register_kprobe(&snapshot);
 if (error) goto release_module;
 snapshot_owned = (void *)snapshot.addr; unregister_kprobe(&snapshot);
 if ((unsigned long)snapshot_owned != text + REC_state_bf_snapshot) {
  error = -ESTALE; goto release_module;
 }
 bf_command = (void *)(text + REC_state_bf_command);
 leaf_command = (void *)(text + REC_state_command);
 lock = SLOT(struct mutex, state_lock);
 packets = SLOT(struct recovery_packet, probes);
 copies = SLOT(struct sk_buff *, owned_payload);
 view = SLOT(struct qdx_diag_fq_view, owned_view);
 mutex_lock(lock);
 if (!FLAG(pinned) || !FLAG(bf_mode) || !FLAG(bf_account_test) || !FLAG(bf_account_control) ||
     !FLAG(bf_pair_started) || !FLAG(bf_pair_retirement_started) || !FLAG(bf_pair_retire_configured) ||
     !FLAG(bf_cpu_owned) || !FLAG(adopt_cpu) || !FLAG(bf_ready) || !FLAG(bf_cut) || !FLAG(occupied_pass) ||
     FLAG(bf_pair_published) || FLAG(bf_pair_pointer_written) || FLAG(bf_pair_backing_started) ||
     FLAG(bf_pair_joined) || FLAG(bf_pair_closed) || FLAG(bf_pair_consequence_pass) || FLAG(bf_retired) ||
     FLAG(adopt_retiring) || FLAG(probe_started) || FLAG(closed) || FLAG(fault) ||
     WORD(probe_returns) || WORD(probe_disposed) || WORD(adopt_retired) || WORD(adopt_retirement_bad) ||
     WORD(bf_links) != 6 || WORD(bf_allocated) != 0x17 || !FLAG(bf_aux_attached) || !FLAG(allocated) ||
     WORD(probe_accepted) != 16 || WORD(bf_trigger_returns) != 4 || WORD(bf_trigger_valid) != 4 ||
     WORD(bf_trigger_disposed) || POINTER(struct qdx_request, request) ||
     POINTER(struct qdx_request, bf_request) || POINTER(struct qdx_packet_op, operation) ||
     POINTER(struct qdx_packet_op, bf_trigger_operation) || POINTER(struct qdx_packet_op, bf_private_operation) ||
     !POINTER(struct qdx_packet_op, probe_operation) || !POINTER(struct qdx_dma, table) ||
     !qdx_diag_fq_table_idle(POINTER(struct qdx_dma, table)) ||
     *SLOT(int, last_error) != -ETIMEDOUT) { error = -EPERM; goto unlock; }
 stage = 1;
 for (i = 0; i < 16; i++) {
  if (packets[i].id != i || !packets[i].skb || !copies[i] || copies[i]->len != 64 ||
      skb_is_nonlinear(copies[i]) || memcmp(copies[i]->data, packets[i].expected, 64)) {
   error = -EBADMSG; goto unlock;
  }
  payload_mask |= BIT(i);
 }
 /* The original snapshot uses real owned ranges and joins an already-running
  * manager before re-reading the queued event, account and clock. */
 host_start_ns = ktime_get_ns();
 error = snapshot_owned();
 if (error) goto unlock;
 memcpy(group_before, view->bf_group, sizeof(group_before));
 memcpy(timer_before, SLOT(u8, bf_timer), sizeof(timer_before));
 memcpy(manager, SLOT(u8, bf_epoch_after), sizeof(manager));
 memcpy(account, SLOT(u8, bf_account), sizeof(account));
 clock_ms = *SLOT(u64, bf_retire_clock);
 due_ms = get_unaligned_le64(timer_before + 16);
 if ((get_unaligned_le32(manager) & 1) || (get_unaligned_le32(manager + 16) & 1) ||
     (get_unaligned_le32(group_before) & 1) || !group_before[229] ||
     !(get_unaligned_le32(timer_before + 24) & 2) ||
     get_unaligned_le32(timer_before + 8) != 0x40086600 ||
     get_unaligned_le32(timer_before + 12) != get_unaligned_le32(view->node + 4) ||
     get_unaligned_le32(group_before + 168) != 0x4045bc80 ||
     get_unaligned_le32(group_before + 164) ||
     (s64)get_unaligned_le64(account + 292) < 0 || due_ms != 3816257741ULL ||
     due_ms <= clock_ms || due_ms - clock_ms < 60000 ||
     ktime_get_ns() - host_start_ns >= WINDOW_NS) { error = -ERANGE; goto unlock; }
 stage = 2;
 /* This exact far-future event cannot become due during the 30-second window.
  * No frequency command, selector reopen or new packet is permitted. Normal
  * FREE cancels the still-queued timer; this is NOT a general callback join. */
 started = true;
 FLAG(adopt_retiring) = true;
 stage = 3;
 issued |= BIT(0);
 error = bf_command(6, BF_GROUP_TAG, TABLE_TAG);
 if (error) goto unlock;
 acknowledged |= BIT(0); stage = 4;
 if (ktime_get_ns() - host_start_ns >= WINDOW_NS) { error = -ETIME; goto unlock; }
 issued |= BIT(1);
 error = leaf_command(ORIGINAL_FREE, true, WAIT_MS);
 if (error) goto unlock;
 acknowledged |= BIT(1); stage = 5;
 if (!completion_done(SLOT(struct completion, adopt_done)) &&
     !wait_for_completion_timeout(SLOT(struct completion, adopt_done), msecs_to_jiffies(WAIT_MS))) {
  error = -ETIMEDOUT; goto unlock;
 }
 error = read_poll_timeout(qdx_packet_op_drained, drained, drained, 10,
  WAIT_MS * 1000, false, POINTER(struct qdx_packet_op, probe_operation));
 if (error) goto unlock;
 if (WORD(adopt_retired) != 16 || WORD(adopt_retirement_bad)) { error = -EBADMSG; goto unlock; }
 qdx_packet_op_put(POINTER(struct qdx_packet_op, probe_operation));
 POINTER(struct qdx_packet_op, probe_operation) = NULL;
 FLAG(adopt_retiring) = false;
 FLAG(bf_retired) = true;
 stage = 6;
 if (ktime_get_ns() - host_start_ns >= WINDOW_NS) { error = -ETIME; goto unlock; }
 issued |= BIT(2);
 error = bf_command(6, BF_PARENT_TAG, BF_GROUP_TAG);
 if (error) goto unlock;
 acknowledged |= BIT(2); stage = 7;
 if (ktime_get_ns() - host_start_ns >= WINDOW_NS) { error = -ETIME; goto unlock; }
 issued |= BIT(3);
 error = bf_command(1, BF_GROUP_TAG, 0);
 if (error) goto unlock;
 acknowledged |= BIT(3); stage = 8;
 elapsed_ns = ktime_get_ns() - host_start_ns;
 if (elapsed_ns >= WINDOW_NS || WORD(bf_links) || WORD(bf_allocated) != 0x13 ||
     FLAG(allocated) || POINTER(struct qdx_request, request) || POINTER(struct qdx_request, bf_request) ||
     POINTER(struct qdx_packet_op, probe_operation)) { error = -ESTALE; goto unlock; }
 for (i = 0; i < 16; i++) {
  if (packets[i].skb || !copies[i] || copies[i]->len != 64 ||
      memcmp(copies[i]->data, packets[i].expected, 64)) { error = -EBADMSG; goto unlock; }
 }
 /* Native detach/FREE ACKs already changed the original bit journals. Advance
  * only the completed join/backing stages, so original close can retire AUX.
  * The original error, pass/consequence flags and all CPU copies are retained. */
 FLAG(bf_pair_joined) = true;
 FLAG(bf_pair_backing_started) = true;
 joined = true; stage = 9; error = 0;
unlock:
 if (host_start_ns) elapsed_ns = ktime_get_ns() - host_start_ns;
 mutex_unlock(lock);
release_module:
 module_put(module);
 return error;
}
static ssize_t recovery_control_write(struct file *file, const char __user *buffer,
 size_t count, loff_t *position)
{
 char command[16]; int error;
 if (!allow_writes) return -EPERM;
 if (!count || count >= sizeof(command)) return -EINVAL;
 if (copy_from_user(command, buffer, count)) return -EFAULT;
 command[count] = 0; strim(command);
 if (strcmp(command, "join")) return -EINVAL;
 mutex_lock(&recovery_lock); error = recovery_join(); result = error; mutex_unlock(&recovery_lock);
 return error ?: count;
}
static const struct file_operations recovery_control_fops = { .owner = THIS_MODULE, .write = recovery_control_write };
static int recovery_status_show(struct seq_file *seq, void *unused)
{
 mutex_lock(&recovery_lock);
 seq_printf(seq, "joined=%u started=%u stage=%u result=%d payload_mask=%x issued=%x acknowledged=%x original_run_failed=1\n",
  joined, started, stage, result, payload_mask, issued, acknowledged);
 seq_printf(seq, "clock_ms=%llu due_ms=%llu elapsed_ns=%llu bound_ns=%llu timer=%32phN manager=%20phN credit=%lld\n",
  clock_ms, due_ms, elapsed_ns, WINDOW_NS, timer_before, manager,
  (long long)(s64)get_unaligned_le64(account + 292));
 mutex_unlock(&recovery_lock); return 0;
}
DEFINE_SHOW_ATTRIBUTE(recovery_status);
static int __init recovery_init(void)
{
 struct dentry *entry;
 if (!allow_writes) return -EPERM;
 directory = debugfs_create_dir("qdx_bf_retirement_recovery", NULL);
 if (IS_ERR_OR_NULL(directory)) return -ENOMEM;
 entry = debugfs_create_file("control", 0200, directory, NULL, &recovery_control_fops);
 if (IS_ERR_OR_NULL(entry)) goto fail;
 entry = debugfs_create_file("status", 0400, directory, NULL, &recovery_status_fops);
 if (IS_ERR_OR_NULL(entry)) goto fail;
 return 0;
fail: debugfs_remove_recursive(directory); return -ENOMEM;
}
static void __exit recovery_exit(void) { debugfs_remove_recursive(directory); }
module_init(recovery_init); module_exit(recovery_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Cancel exact far-future BF event through native retirement before its deadline");
