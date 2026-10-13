// SPDX-License-Identifier: GPL-2.0-only
/* Close only the failed GROUP ELFbbca07f9 post-rebuild import fixture. Never repairs its test result. */
#include <linux/completion.h>
#include <linux/debugfs.h>
#include <linux/iopoll.h>
#include <linux/jiffies.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/qdx.h>
#include <linux/rcupdate.h>
#include <linux/seq_file.h>
#include <linux/skbuff.h>
#include <linux/sysfs.h>
#include <linux/uaccess.h>
#include <linux/unaligned.h>
#include "qdx_rate_safety_recovery_offsets.h"

struct recovery_sections { struct attribute_group grp; struct bin_attribute attrs[]; };
struct recovery_node {
 u32 tag, kind, gauge, bytes;
 u64 admitted, selected, dropped;
 bool allocated;
 int parent;
 u32 band;
 struct qdx_packet_op *operation;
};
struct recovery_packet {
 struct sk_buff *skb, *submitted;
 u32 id, length, returns;
 bool loaned, control;
 u8 expected[1514];
};
static_assert(sizeof(struct module) == 1216);
static_assert(sizeof(struct mutex) == 32);
static_assert(sizeof(struct recovery_node) == 64);
static_assert(sizeof(struct recovery_packet) == 1544);
struct recovery_copy_round {
 struct completion original_done, clone_done;
 u32 originals, clones, length;
 bool original_valid, clone_valid;
 u8 bytes[1004];
};
static_assert(sizeof(struct recovery_copy_round) == 1088);
extern bool qdx_diag_fq_table_idle(struct qdx_dma *);
enum { OUTER, INNER, MAIN, CLOCK, FQ, FIFO_A, FIFO_B, FIFO_C, SPARE_FIRST, MARKER = 40, NODES = 41 };
static const u32 tags[8] = { 0x71000000, 0x71080000, 0x71010000, 0x71020000,
 0x6d010000, 0x71030000, 0x71040000, 0x71050000 };
static const u32 kinds[8] = { 3, 3, 12, 5, 1, 4, 4, 4 };
static const int parents[8] = { -1, -1, INNER, INNER, INNER, 14, 22, 30 };
static const u32 bands[8] = { 0, 0, 0, 2, 1, 0, 0, 0 };
static const u32 selected_groups[3] = { 14, 22, 30 };
static const u8 expected_build_id[20] = {
 0x32,0x1b,0x6a,0xae,0x11,0x3c,0x16,0xd9,0xbb,0xf9,0x3b,0xc1,0x4f,0x37,0x2f,0xd9,0xcb,0xf7,0x2b,0x3d
};
static bool allow_writes, started, released, self_pinned;
module_param(allow_writes, bool, 0400);
static u32 stage, data_mask, anchor_mask, issued, acknowledged;
static u32 last_sub, last_node, last_arg;
static bool inspected, recall_completed;
static u32 returned_mask;
static int result;
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

/* Called only before publication or after the actual operation has drained. */
static bool recovery_packet_valid(struct recovery_packet *packet, u32 id,
 u32 length, bool control, bool returned, u32 returns)
{
 if (packet->id != id || packet->length != length || packet->control != control || packet->returns != returns ||
     get_unaligned_le32(packet->expected + 42) != 0x45544152 ||
     get_unaligned_le32(packet->expected + 46) != id) return false;
 if (!returned)
  return packet->loaned && packet->submitted && !packet->skb;
 return !packet->loaned && !packet->submitted && packet->skb &&
  packet->skb->len == length && !skb_is_nonlinear(packet->skb) &&
  !memcmp(packet->skb->data, packet->expected, length);
}

static int recovery_run(bool end_diagnostic)
{
 struct kprobe finder = { .symbol_name = "find_module" };
 struct kprobe commander = { .symbol_name = "qdx_rate_handover_diag:rate_tc" };
 struct module *(*find_named)(const char *);
 int (*tc)(u32, u32, u32, u32), (*join)(u32), (*gauge)(u32, u32);
 int (*command)(bool, u32, const void *, size_t);
 struct module *module;
 struct mutex *lock;
 struct recovery_node *nodes;
 struct recovery_packet *packets, *anchors, *private_packet, *warm_packets;
 unsigned long text, data, bss, note, this_section;
 __le32 unassign;
 unsigned int i, slot;
 int error;
 if (released) return end_diagnostic ? 0 : -EALREADY;
 if (started) return -EALREADY; /* Partial native actions require exact review. */
 error = register_kprobe(&finder);
 if (error) return error;
 find_named = (void *)finder.addr; unregister_kprobe(&finder);
 rcu_read_lock();
 module = find_named("qdx_rate_handover_diag");
 if (module && !try_module_get(module)) module = NULL;
 rcu_read_unlock();
 if (!module) return -ENOENT;
 if (module->state != MODULE_STATE_LIVE || strcmp(module_name(module), "qdx_rate_handover_diag")) {
  error = -ESTALE; goto release_module;
 }
 text = recovery_section(module, ".text"); data = recovery_section(module, ".data");
 bss = recovery_section(module, ".bss"); note = recovery_section(module, ".note.gnu.build-id");
 this_section = recovery_section(module, ".gnu.linkonce.this_module");
 if (!text || !data || !bss || !note || this_section != (unsigned long)module ||
     !within_module_mem_type(text, module, MOD_TEXT) ||
     !within_module_mem_type(text + 0x5fc3, module, MOD_TEXT) ||
     !within_module_mem_type(data, module, MOD_DATA) ||
     !within_module_mem_type(data + 0x53, module, MOD_DATA) ||
     !within_module_mem_type(bss, module, MOD_DATA) ||
     !within_module_mem_type(bss + 0x1e78f, module, MOD_DATA) ||
     !within_module(note, module) || !within_module(note + 35, module)) {
  error = -ERANGE; goto release_module;
 }
 if (get_unaligned_le32((void *)note) != 4 || get_unaligned_le32((void *)(note + 4)) != 20 ||
     get_unaligned_le32((void *)(note + 8)) != 3 || memcmp((void *)(note + 12), "GNU", 4) ||
     memcmp((void *)(note + 16), expected_build_id, 20)) {
  error = -ESTALE; goto release_module;
 }
 error = register_kprobe(&commander);
 if (error) goto release_module;
 tc = (void *)commander.addr; unregister_kprobe(&commander);
 if ((unsigned long)tc != text + REC_rate_tc) { error = -ESTALE; goto release_module; }
 command = (void *)(text + REC_rate_command);
 join = (void *)(text + REC_rate_join);
 gauge = (void *)(text + REC_rate_gauge);
 lock = SLOT(struct mutex, control_lock);
 nodes = SLOT(struct recovery_node, nodes);
 packets = SLOT(struct recovery_packet, packets);
 anchors = SLOT(struct recovery_packet, anchor_packets);
 private_packet = SLOT(struct recovery_packet, private_packet);
 warm_packets = SLOT(struct recovery_packet, warm_packets);
 mutex_lock(lock);
 if (!FLAG(pinned) || !FLAG(prepared) || !FLAG(loaded) || !FLAG(exported) || !FLAG(recalled) ||
     !FLAG(cpu_selected) || FLAG(rebuilt) || FLAG(passed) || FLAG(fault) || FLAG(closed) ||
     WORD(group_mode) != 1 || WORD(phase) != 3 || WORD(private_count) != 5 || WORD(recall_count) != 16 ||
     WORD(bad_packets) || WORD(disposals) || WORD(unexpected_clones) || WORD(controls_retired) ||
     WORD(selected_mask) != BIT(12) || WORD(resume_count) || FLAG(anchor_retiring) ||
     *SLOT(int, last_error) != -EBADMSG || private_packet->skb || private_packet->submitted ||
     private_packet->loaned || !FLAG(assigned) || !FLAG(enabled) || !FLAG(next_set) ||
     POINTER(struct qdx_request, request) || POINTER(struct qdx_packet_op, copy_operation) ||
     !POINTER(struct qdx_dma, table) || !qdx_diag_fq_table_idle(POINTER(struct qdx_dma, table)) ||
     !POINTER(struct qdx_endpoint, igs) || !POINTER(struct qdx_endpoint, mirror) ||
     !POINTER(struct qdx_receiver, receiver)) { error = -EPERM; goto unlock; }
 if (WORD(warm_returned) != 2) { error = -EBADMSG; goto unlock; }
 for (i = 0; i < 2; i++)
  if (warm_packets[i].id != 0x90000000U + i || warm_packets[i].length != 1514 ||
      warm_packets[i].control || warm_packets[i].skb || warm_packets[i].submitted ||
      warm_packets[i].loaned || warm_packets[i].returns != 1) {
   error = -EBADMSG; goto unlock;
  }
 for (i = 0; i < NODES; i++) {
  u32 tag = i < 8 ? tags[i] : i == MARKER ? 0x71060000 : 0x71200000 + (i - SPARE_FIRST) * 0x10000;
  u32 kind = i < 8 ? kinds[i] : i == MARKER ? 4 : 12;
  int parent = i < 8 ? parents[i] : i == MARKER ? OUTER : INNER;
  u32 band = i < 8 ? bands[i] : i == MARKER ? 2 : 3 + i - SPARE_FIRST;
  for (slot = 0; slot < 3; slot++)
   if (i == selected_groups[slot]) { parent = MAIN; band = 0; }
  if (nodes[i].tag != tag || nodes[i].kind != kind ||
      !nodes[i].allocated ||
      nodes[i].parent != parent || nodes[i].band != band ||
      ((i == FQ || (i >= FIFO_A && i <= FIFO_C)) ? !nodes[i].operation : !!nodes[i].operation)) { error = -ESTALE; goto unlock; }
 }
 for (i = 0; i < 16; i++) {
  if (!recovery_packet_valid(&packets[i], i, i == 12 ? 1514 : 64, false, i == 12, 1)) { error = -EBADMSG; goto unlock; }
  data_mask |= BIT(i);
 }
 for (i = 0; i < 2; i++) {
  if (!recovery_packet_valid(&anchors[i], 0x40000000 + i, 64, true, false, 0)) {
   error = -EBADMSG; goto unlock;
  }
  anchor_mask |= BIT(i);
 }
 for (slot = 0; slot < 3; slot++) {
  struct recovery_node *leaf = &nodes[FIFO_A + slot];
  if (SLOT(u32, group_id)[slot] != selected_groups[slot] ||
      leaf->gauge != (slot == 0 ? 8 : slot == 1 ? 4 : 3) ||
      leaf->bytes != (slot == 0 ? 512 : slot == 1 ? 256 : 192) ||
      leaf->admitted != (slot == 0 ? 18 : slot == 1 ? 9 : 7) ||
      leaf->selected != (slot == 0 ? 10 : slot == 1 ? 5 : 4) || leaf->dropped) {
   error = -EBADMSG; goto unlock;
  }
 }
 if (nodes[FQ].gauge != 2 || nodes[FQ].bytes != 128) { error = -EBADMSG; goto unlock; }
 inspected = true; stage = 1;
 if (!end_diagnostic) { error = 0; goto unlock; }
 /* Return the fifteen re-submitted originals through their existing positive
  * recipients. CPU-selected12 stays held throughout. No DATA leaf is freed
  * while occupied, and neither the CPU decision nor original recall is replayed. */
 if (!try_module_get(THIS_MODULE)) { error = -ENODEV; goto unlock; }
 self_pinned = true; started = true;
 /* Keep phase3: callbacks record the second positive return without
  * appending to the original recall trace or claiming resumed policy service. */
 for (slot = 0; slot < 3; slot++) {
  u32 leaf = FIFO_A + slot;
  last_sub = 6; last_node = selected_groups[slot]; last_arg = leaf; issued++;
  error = tc(last_sub, last_node, last_arg, 0);
  if (error) goto unlock;
  acknowledged++;
  last_sub = 5; last_node = OUTER; last_arg = leaf; issued++;
  error = tc(last_sub, last_node, last_arg, 1);
  if (error) goto unlock;
  acknowledged++;
  error = join(leaf);
  if (error) goto unlock;
  error = gauge(leaf, 0);
  if (error) goto unlock;
  last_sub = 6; last_node = OUTER; last_arg = leaf; issued++;
  error = tc(last_sub, last_node, last_arg, 0);
  if (error) goto unlock;
  acknowledged++;
 }
 if (WORD(recall_count) != 16) { error = -EBADMSG; goto unlock; }
 for (i = 0; i < 16; i++) {
  if (!recovery_packet_valid(&packets[i], i, i == 12 ? 1514 : 64, false, true, i == 12 ? 1 : 2) ||
      SLOT(u32, recall_order)[i] != i) { error = -EBADMSG; goto unlock; }
  returned_mask |= BIT(i);
 }
 recall_completed = true;
 /* Explicit finite diagnostic end now has all16 byte-verified CPU owners.
  * Keep them until all hardware and receiver ownership has closed normally.
  * exported/recalled/passed and the original error are never repaired. */
 FLAG(closed) = true;
 for (i = 0; i < NODES; i++) {
  if (i == FQ) continue;
  error = join(i);
  if (error) goto unlock;
 }
 stage = 2;
 for (i = NODES; i-- > 0;) {
  if (nodes[i].parent == -1) continue;
  last_sub = 6; last_node = nodes[i].parent; last_arg = i; issued++;
  error = tc(last_sub, last_node, last_arg, 0);
  if (error) goto unlock;
  acknowledged++;
 }
 stage = 3;
 FLAG(anchor_retiring) = true;
 last_sub = 1; last_node = FQ; last_arg = 0; issued++;
 error = tc(last_sub, last_node, last_arg, 0);
 if (error) goto unlock;
 acknowledged++;
 error = join(FQ);
 if (error) goto unlock;
 if (WORD(controls_retired) != 2 || WORD(bad_packets) || WORD(disposals)) { error = -EBADMSG; goto unlock; }
 for (i = 0; i < 2; i++)
  if (anchors[i].skb || anchors[i].submitted || anchors[i].loaned || anchors[i].returns != 1) {
   error = -EBADMSG; goto unlock;
  }
 stage = 4;
 for (i = NODES; i-- > 0;) {
  if (!nodes[i].allocated) continue;
  last_sub = 1; last_node = i; last_arg = 0; issued++;
  error = tc(last_sub, last_node, last_arg, 0);
  if (error) goto unlock;
  acknowledged++;
 }
 stage = 5;
 if (FLAG(enabled)) {
  last_sub = 2; last_node = U32_MAX; last_arg = 0; issued++;
  error = command(true, 2, NULL, 0);
  if (error) goto unlock;
  acknowledged++;
 }
 if (FLAG(next_set)) {
  last_sub = 4; last_node = U32_MAX; last_arg = 0; issued++;
  error = command(true, 4, NULL, 0);
  if (error) goto unlock;
  acknowledged++;
 }
 if (FLAG(assigned)) {
  unassign = cpu_to_le32(WORD(shaper));
  last_sub = 8; last_node = U32_MAX; last_arg = WORD(shaper); issued++;
  error = command(false, 8, &unassign, sizeof(unassign));
  if (error) goto unlock;
  acknowledged++;
 }
 if (!qdx_diag_fq_table_idle(POINTER(struct qdx_dma, table))) { error = -EBUSY; goto unlock; }
 stage = 6;
 if (!FLAG(igs_retired)) {
  error = qdx_endpoint_wait(POINTER(struct qdx_endpoint, igs), jiffies);
  if (!error) error = qdx_endpoint_retire(POINTER(struct qdx_endpoint, igs));
  if (error) goto unlock;
  FLAG(igs_retired) = true;
 }
 if (!FLAG(mirror_retired)) {
  error = qdx_endpoint_wait(POINTER(struct qdx_endpoint, mirror), jiffies);
  if (!error) error = qdx_endpoint_retire(POINTER(struct qdx_endpoint, mirror));
  if (error) goto unlock;
  FLAG(mirror_retired) = true;
 }
 if (POINTER(struct qdx_receiver, receiver)) {
  error = qdx_endpoint_receive_unregister(POINTER(struct qdx_receiver, receiver));
  if (error) goto unlock;
  POINTER(struct qdx_receiver, receiver) = NULL;
 }
 synchronize_net();
 stage = 7;
 /* Recheck before releasing the already CPU-owned finite test DATA. */
 for (i = 0; i < 16; i++)
  if (!recovery_packet_valid(&packets[i], i, i == 12 ? 1514 : 64, false, true, i == 12 ? 1 : 2)) {
   error = -EBADMSG; goto unlock;
  }
 for (i = 0; i < 16; i++) { dev_kfree_skb(packets[i].skb); packets[i].skb = NULL; }
 qdx_endpoint_put(POINTER(struct qdx_endpoint, mirror)); POINTER(struct qdx_endpoint, mirror) = NULL;
 qdx_endpoint_put(POINTER(struct qdx_endpoint, igs)); POINTER(struct qdx_endpoint, igs) = NULL;
 qdx_dma_release(POINTER(struct qdx_dma, table)); POINTER(struct qdx_dma, table) = NULL;
 qdx_service_put(POINTER(struct qdx_service, mirror_service)); POINTER(struct qdx_service, mirror_service) = NULL;
 qdx_service_put(POINTER(struct qdx_service, igs_service)); POINTER(struct qdx_service, igs_service) = NULL;
 dev_put(POINTER(struct net_device, port)); POINTER(struct net_device, port) = NULL;
 FLAG(pinned) = false;
 module_put(module); /* Original prepare's self-reference. */
 released = true; stage = 8;
 self_pinned = false; module_put(THIS_MODULE); error = 0;
unlock:
 mutex_unlock(lock);
release_module:
 module_put(module);
 return error;
}
static ssize_t recovery_control_write(struct file *file, const char __user *buffer,
 size_t count, loff_t *position)
{
 char command[16];
 int error;

 if (!allow_writes) return -EPERM;
 if (!count || count >= sizeof(command)) return -EINVAL;
 if (copy_from_user(command, buffer, count)) return -EFAULT;
 command[count] = 0;
 strim(command);
 mutex_lock(&recovery_lock);
 if (!strcmp(command, "inspect")) error = recovery_run(false);
 else if (!strcmp(command, "end")) error = recovery_run(true);
 else error = -EINVAL;
 result = error;
 mutex_unlock(&recovery_lock);
 return error ?: count;
}
static const struct file_operations recovery_control_fops = {
 .owner = THIS_MODULE, .write = recovery_control_write,
};
static int recovery_status_show(struct seq_file *seq, void *unused)
{
 mutex_lock(&recovery_lock);
 seq_printf(seq, "allow_writes=%u inspected=%u started=%u released=%u self_pinned=%u stage=%u result=%d data_mask=%x anchor_mask=%x issued=%u acknowledged=%u last_sub=%u last_node=%u last_arg=%u original_run_failed=1 recall_completed=%u returned_mask=%x\n",
  allow_writes, inspected, started, released, self_pinned, stage, result, data_mask, anchor_mask,
  issued, acknowledged, last_sub, last_node, last_arg, recall_completed, returned_mask);
 mutex_unlock(&recovery_lock);
 return 0;
}
DEFINE_SHOW_ATTRIBUTE(recovery_status);
static int __init recovery_init(void)
{
 struct dentry *entry;
 if (!allow_writes) return -EPERM;
 directory = debugfs_create_dir("qdx_rate_safety_recovery", NULL);
 if (IS_ERR_OR_NULL(directory)) return -ENOMEM;
 entry = debugfs_create_file("control", 0200, directory, NULL, &recovery_control_fops);
 if (IS_ERR_OR_NULL(entry)) goto fail;
 entry = debugfs_create_file("status", 0400, directory, NULL, &recovery_status_fops);
 if (IS_ERR_OR_NULL(entry)) goto fail;
 return 0;
fail:
 debugfs_remove_recursive(directory);
 return -ENOMEM;
}
static void __exit recovery_exit(void)
{
 WARN_ON(self_pinned || (started && !released));
 debugfs_remove_recursive(directory);
}
module_init(recovery_init);
module_exit(recovery_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Return fifteen rebuilt GROUP originals; retain CPU12 until finite end");
