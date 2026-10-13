// SPDX-License-Identifier: GPL-2.0-only
/* Resume only the failed ELF1210908f's already-started diagnostic retirement. */
#include <linux/debugfs.h>
#include <linux/kprobes.h>
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
 0xbe,0xec,0x26,0x6e,0x19,0x76,0xa1,0x68,0xda,0x34,
 0xa8,0x98,0xc0,0xc7,0x7f,0x55,0xfa,0x38,0xba,0x44 };
static bool allow_writes, joined;
module_param(allow_writes, bool, 0400);
static u32 stage, payload_mask;
static int result;
static u8 group_before[232], group_after[232], timer_before[32], timer_after[32];
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
 struct kprobe reader = { .symbol_name = "qdx_mirror_state_diag:state_owned_read" };
 struct module *(*find_named)(const char *);
 int (*read_owned)(enum qdx_diag_fq_range, unsigned int, unsigned int, void *);
 struct module *module;
 struct mutex *lock;
 struct recovery_packet *packets;
 struct sk_buff **copies;
 struct qdx_diag_fq_view *view;
 unsigned long text, data, bss, note, this_section;
 unsigned int i;
 int error;
 if (joined) return 0;
 error = register_kprobe(&finder);
 if (error) return error;
 find_named = (void *)finder.addr;
 unregister_kprobe(&finder);
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
     !within_module_mem_type(text + 0x8d47, module, MOD_TEXT) ||
     !within_module_mem_type(data, module, MOD_DATA) ||
     !within_module_mem_type(data + 0xaf, module, MOD_DATA) ||
     !within_module_mem_type(bss, module, MOD_DATA) ||
     !within_module_mem_type(bss + 0x3f0f, module, MOD_DATA) ||
     !within_module(note, module) || !within_module(note + 35, module)) {
  error = -ERANGE; goto release_module;
 }
 if (get_unaligned_le32((void *)note) != 4 || get_unaligned_le32((void *)(note + 4)) != 20 ||
     get_unaligned_le32((void *)(note + 8)) != 3 || memcmp((void *)(note + 12), "GNU", 4) ||
     memcmp((void *)(note + 16), expected_build_id, 20)) {
  error = -ESTALE; goto release_module;
 }
 error = register_kprobe(&reader);
 if (error) goto release_module;
 read_owned = (void *)reader.addr; unregister_kprobe(&reader);
 if ((unsigned long)read_owned != text + REC_state_owned_read) { error = -ESTALE; goto release_module; }
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
     WORD(bf_links) != 6 || WORD(bf_allocated) != 0x17 || !FLAG(bf_aux_attached) ||
     POINTER(struct qdx_request, request) || POINTER(struct qdx_request, bf_request) ||
     POINTER(struct qdx_packet_op, operation) || !POINTER(struct qdx_packet_op, probe_operation) ||
     !POINTER(struct qdx_dma, table) || !qdx_diag_fq_table_idle(POINTER(struct qdx_dma, table)) ||
     *SLOT(int, last_error) != -EAGAIN) { error = -EPERM; goto unlock; }
 stage = 1;
 for (i = 0; i < 16; i++) {
  if (packets[i].id != i || !copies[i] || copies[i]->len != 64 || skb_is_nonlinear(copies[i]) ||
      memcmp(copies[i]->data, packets[i].expected, 64)) { error = -EBADMSG; goto unlock; }
  payload_mask |= BIT(i);
 }
 /* Existing CONFIG made this obsolete account positive. Ingress and selection
  * remain cut. No caller can charge it or rearm its event while state_lock is held.
  * The callback itself stops rescheduling once that positive account is seen. */
 error = read_owned(QDX_DIAG_BF_GROUP, 0, 232, view->bf_group);
 if (!error) memcpy(group_before, view->bf_group, 232);
 if (!error) error = read_owned(QDX_DIAG_BF_TIMER, 0, 32, timer_before);
 if (error) goto unlock;
 if ((get_unaligned_le32(group_before) & 1) || group_before[229] ||
     (get_unaligned_le32(timer_before + 24) & 2)) { error = -EAGAIN; goto unlock; }
 stage = 2;
 /* Queued=0 alone is insufficient: the manager clears it before callback.
  * This later completed NSS copy of inactive manager proves that callback ended.
  * Unrelated subsequent callbacks do not write this now-inactive group. */
 error = read_owned(QDX_DIAG_BF_EPOCH, 0, 20, manager);
 if (error) goto unlock;
 if ((get_unaligned_le32(manager) & 1) || (get_unaligned_le32(manager + 16) & 1)) {
  error = -EAGAIN; goto unlock;
 }
 stage = 3;
 error = read_owned(QDX_DIAG_BF_GROUP, 0, 232, view->bf_group);
 if (!error) memcpy(group_after, view->bf_group, 232);
 if (!error) error = read_owned(QDX_DIAG_BF_TIMER, 0, 32, timer_after);
 if (!error) error = read_owned(QDX_DIAG_BF_ACCOUNT, 0, 312, account);
 if (error) goto unlock;
 if ((get_unaligned_le32(group_after) & 1) || group_after[229] ||
     (get_unaligned_le32(timer_after + 24) & 2) ||
     get_unaligned_le32(group_before + 220) != get_unaligned_le32(group_after + 220) ||
     !get_unaligned_le32(group_after + 220) ||
     get_unaligned_le32(group_before + 168) != get_unaligned_le32(group_after + 168) ||
     (s64)get_unaligned_le64(account + 292) < 0) { error = -ESTALE; goto unlock; }
 /* Advance exactly the three original close assignments AFTER its join loop.
  * No pass flag, hardware state, ownership callback or CONFIG is changed here.
  * Root next calls original bf-account-close and records retained copies.
  * Original restore is a separate explicit finite-diagnostic end, not service. */
 FLAG(bf_pair_joined) = true;
 FLAG(bf_pair_backing_started) = true;
 FLAG(adopt_retiring) = true;
 joined = true; stage = 4; error = 0;
unlock:
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
 seq_printf(seq, "joined=%u stage=%u result=%d payload_mask=%x original_run_failed=1\n", joined, stage, result, payload_mask);
 seq_printf(seq, "before_timer=%32phN after_timer=%32phN manager=%20phN before_wait=%u after_wait=%u credit=%lld\n",
  timer_before, timer_after, manager, group_before[229], group_after[229],
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
MODULE_DESCRIPTION("Join already-retired BF callback and resume original diagnostic close");
