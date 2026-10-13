// SPDX-License-Identifier: GPL-2.0-only
/* Close only the failed RED ELF995cf30c run. Never repairs its test result. */
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
#include "qdx_aqm_safety_recovery_offsets.h"

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
 struct sk_buff *skb, *submitted, *unexpected;
 u32 id, length, returns, nulls, positives;
 bool loaned, control, copied, expected_drop, cpu_selected;
 u8 expected[1514];
};
static_assert(sizeof(struct module) == 1216);
static_assert(sizeof(struct mutex) == 32);
static_assert(sizeof(struct recovery_node) == 64);
static_assert(sizeof(struct recovery_packet) == 1568);
extern bool qdx_diag_fq_table_idle(struct qdx_dma *);
enum { OUTER, INNER, FQ, LEAF_A, LEAF_B, LEAF_C, LEAF_D, NODES };
static const u32 tags[NODES] = { 0x710c0000, 0x710d0000, 0x6d010000, 0x710e0000,
 0x710f0000, 0x71100000, 0x71110000 };
static const u32 kinds[NODES] = { 3, 3, 1, 13, 13, 13, 13 };
static const int parents[NODES] = { -1, -1, INNER, INNER, -1, -1, -1 };
static const u32 bands[NODES] = { 0, 0, 1, 0, 0, 0, 0 };
static const u8 expected_build_id[20] = {
 0x29,0x01,0x6f,0x0b,0x8e,0x8e,0xa8,0x56,0x52,0x58,
 0xa2,0xd1,0x39,0x4a,0x9a,0xd2,0xfb,0x34,0x4d,0x92,
};
static bool allow_writes, started, returned_all, released, self_pinned;
module_param(allow_writes, bool, 0400);
static u32 stage, data_mask, anchor_mask, verified_policy_drops;
static u64 admitted[2], selected[2], dropped[2];
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
 u32 length, bool control, bool returned)
{
 if (packet->id != id || packet->length != length || packet->control != control ||
     packet->unexpected || packet->copied ||
     packet->expected_drop || packet->cpu_selected || packet->nulls ||
     get_unaligned_le32(packet->expected + 42) != 0x414d5144 ||
     get_unaligned_le32(packet->expected + 46) != id) return false;
 if (!returned)
  return packet->loaned && packet->submitted && !packet->skb &&
   !packet->returns && !packet->positives;
 return !packet->loaned && !packet->submitted && packet->skb &&
  packet->returns == 1 && packet->positives == 1 &&
  packet->skb->len == length && !skb_is_nonlinear(packet->skb) &&
  !memcmp(packet->skb->data, packet->expected, length);
}

static int recovery_run(bool close_resources)
{
 struct kprobe finder = { .symbol_name = "find_module" };
 struct kprobe commander = { .symbol_name = "qdx_aqm_handover_diag:aqm_tc" };
 struct module *(*find_named)(const char *);
 int (*tc)(u32, u32, u32, u32), (*gauge)(u32, u32);
 int (*join)(struct qdx_packet_op **);
 int (*command)(bool, u32, const void *, size_t), (*wait_command)(void);
 struct module *module;
 struct mutex *lock;
 struct recovery_node *nodes;
 struct recovery_packet *packets, *anchors;
 unsigned long text, data, bss, note, this_section;
 __le32 unassign;
 unsigned int i, leaf;
 int error;

 if (released) return close_resources ? 0 : -EALREADY;
 error = register_kprobe(&finder);
 if (error) return error;
 find_named = (void *)finder.addr;
 unregister_kprobe(&finder);
 rcu_read_lock();
 module = find_named("qdx_aqm_handover_diag");
 if (module && !try_module_get(module)) module = NULL;
 rcu_read_unlock();
 if (!module) return -ENOENT;
 if (module->state != MODULE_STATE_LIVE || strcmp(module_name(module), "qdx_aqm_handover_diag")) {
  error = -ESTALE; goto release_module;
 }
 text = recovery_section(module, ".text");
 data = recovery_section(module, ".data");
 bss = recovery_section(module, ".bss");
 note = recovery_section(module, ".note.gnu.build-id");
 this_section = recovery_section(module, ".gnu.linkonce.this_module");
 if (!text || !data || !bss || !note || this_section != (unsigned long)module ||
     !within_module_mem_type(text, module, MOD_TEXT) ||
     !within_module_mem_type(text + 0x4357, module, MOD_TEXT) ||
     !within_module_mem_type(data, module, MOD_DATA) ||
     !within_module_mem_type(data + 0x2f, module, MOD_DATA) ||
     !within_module_mem_type(bss, module, MOD_DATA) ||
     !within_module_mem_type(bss + 0x1400f, module, MOD_DATA) ||
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
 tc = (void *)commander.addr;
 unregister_kprobe(&commander);
 if ((unsigned long)tc != text + REC_aqm_tc) { error = -ESTALE; goto release_module; }
 wait_command = (void *)(text + REC_aqm_wait_command);
 command = (void *)(text + REC_aqm_command);
 join = (void *)(text + REC_aqm_join);
 gauge = (void *)(text + REC_aqm_gauge);
 lock = SLOT(struct mutex, control_lock);
 nodes = SLOT(struct recovery_node, nodes);
 packets = SLOT(struct recovery_packet, packets);
 anchors = SLOT(struct recovery_packet, anchor_packets);
 mutex_lock(lock);
 if (!FLAG(pinned) || !FLAG(prepared) || !FLAG(loaded) || FLAG(exported) || FLAG(adopted) ||
     FLAG(cpu_selected) || FLAG(rebuilt) || FLAG(served) || FLAG(passed) || FLAG(fault) ||
     WORD(algorithm) || WORD(stage) != 1 || WORD(leaf) != LEAF_A || WORD(copy_count) != 12 ||
     WORD(bad_packets) || WORD(unexpected_clones) || WORD(policy_drops) != 1 ||
     WORD(backing_retired) || WORD(controls_retired) || WORD(resumed_count) ||
     WORD(resumed_victims) || WORD(cpu_victims) || WORD(fresh_accepts) ||
     WORD(load_next) != 4 || WORD(rebuild_next) != 1 || WORD(probe_next) ||
     WORD(anchor_accepted) != 2 || WORD(queue_count) != 3 ||
     FLAG(old_backing_retired) || FLAG(leaf_reallocated) || FLAG(serve_prepared) || FLAG(serve_published) ||
     FLAG(anchor_retiring) || FLAG(data_retiring) || FLAG(temporary_config) ||
     POINTER(struct qdx_packet_op, copy_operation) || POINTER(struct qdx_packet_op, probe_operation) ||
     *SLOT(int, last_error) != -ESTALE) { error = -EPERM; goto unlock; }
 for (i = 0; i < NODES; i++)
  if (nodes[i].tag != tags[i] || nodes[i].kind != kinds[i]) { error = -ESTALE; goto unlock; }
 /* Packet3 was already a real RED admission victim. Never recreate it. */
 if (packets[3].id != 3 || packets[3].length != 1514 || !packets[3].expected_drop ||
     packets[3].returns != 1 || packets[3].nulls != 1 || packets[3].positives ||
     packets[3].skb || packets[3].submitted || packets[3].unexpected || packets[3].loaned ||
     packets[3].control || packets[3].copied || packets[3].cpu_selected ||
     get_unaligned_le32(packets[3].expected + 42) != 0x414d5144 ||
     get_unaligned_le32(packets[3].expected + 46) != 3) { error = -EBADMSG; goto unlock; }
 for (i = 4; i < 20; i++)
  if (packets[i].length || packets[i].skb || packets[i].submitted || packets[i].unexpected ||
      packets[i].loaned || packets[i].copied || packets[i].returns || packets[i].nulls ||
      packets[i].positives) { error = -ESTALE; goto unlock; }
 if (!started) {
  if (close_resources || FLAG(closed) || !FLAG(assigned) || !FLAG(enabled) || !FLAG(next_set) ||
      POINTER(struct qdx_request, request) || !POINTER(struct qdx_dma, table) ||
      !qdx_diag_fq_table_idle(POINTER(struct qdx_dma, table)) ||
      !POINTER(struct qdx_endpoint, igs) || !POINTER(struct qdx_endpoint, mirror) ||
      !POINTER(struct qdx_receiver, receiver)) { error = -EPERM; goto unlock; }
  for (i = 0; i < NODES; i++)
   if (!nodes[i].allocated || nodes[i].parent != parents[i] || nodes[i].band != bands[i]) { error = -ESTALE; goto unlock; }
  for (i = 0; i < 3; i++)
   if (!recovery_packet_valid(&packets[i], i, 1514, false, false)) {
    error = -EBADMSG; goto unlock;
   }
  for (i = 0; i < 2; i++)
   if (!recovery_packet_valid(&anchors[i], 0x40000000 + i, 64, true, false)) {
    error = -EBADMSG; goto unlock;
   }
  if (!nodes[LEAF_A].operation || !nodes[FQ].operation) { error = -ESTALE; goto unlock; }
  if (!try_module_get(THIS_MODULE)) { error = -ENODEV; goto unlock; }
  verified_policy_drops = WORD(policy_drops);
  self_pinned = true;
  started = true;
  stage = 1;
 }
 if (POINTER(struct qdx_request, request)) {
  error = wait_command();
  if (error) goto unlock;
 }
 if (!close_resources) {
  if (FLAG(closed)) { error = -EPERM; goto unlock; }
  if (!returned_all) {
   if (nodes[INNER].parent == -1) {
    error = tc(5, OUTER, INNER, 0);
    if (error) goto unlock;
   } else if (nodes[INNER].parent != OUTER || nodes[INNER].band) {
    error = -ESTALE; goto unlock;
   }
   stage = 2;
   error = join(&nodes[LEAF_A].operation);
   if (!error) error = join(&nodes[FQ].operation);
   if (error) goto unlock;
   stage = 3;
   for (i = 0; i < 3; i++) {
    if (!recovery_packet_valid(&packets[i], i, 1514, false, true)) {
     error = -EBADMSG; goto unlock;
    }
    data_mask |= BIT(i);
   }
   for (i = 0; i < 2; i++) {
    if (!recovery_packet_valid(&anchors[i], 0x40000000 + i, 64, true, true)) {
     error = -EBADMSG; goto unlock;
    }
    anchor_mask |= BIT(i);
   }
   for (i = 0; i < 2; i++) {
    leaf = i ? FQ : LEAF_A;
    error = gauge(leaf, 0);
    if (error) goto unlock;
    admitted[i] = nodes[leaf].admitted;
    selected[i] = nodes[leaf].selected;
    dropped[i] = nodes[leaf].dropped;
   }
   if (admitted[0] != 3 || admitted[1] != 2 ||
       selected[0] != 3 || selected[1] != 2 || dropped[0] != 1 || dropped[1]) { error = -EBADMSG; goto unlock; }
   returned_all = true;
   stage = 4;
  }
  error = 0;
  goto unlock;
 }
 if (!returned_all || data_mask != 7 || anchor_mask != 3) { error = -EPERM; goto unlock; }
 for (i = 0; i < 3; i++)
  if (!recovery_packet_valid(&packets[i], i, 1514, false, true)) {
   error = -EBADMSG; goto unlock;
  }
 for (i = 0; i < 2; i++)
  if (!recovery_packet_valid(&anchors[i], 0x40000000 + i, 64, true, true)) {
   error = -EBADMSG; goto unlock;
  }
 FLAG(closed) = true;
 stage = 5;
 for (i = 0; i < NODES; i++) {
  error = join(&nodes[i].operation);
  if (error) goto unlock;
 }
 for (i = NODES; i-- > 0;) {
  if (nodes[i].parent == -1) continue;
  error = tc(6, nodes[i].parent, i, 0);
  if (error) goto unlock;
 }
 stage = 6;
 for (i = NODES; i-- > 0;) {
  if (!nodes[i].allocated) continue;
  error = tc(1, i, 0, 0);
  if (error) goto unlock;
 }
 stage = 7;
 if (FLAG(enabled)) {
  error = command(true, 2, NULL, 0);
  if (error) goto unlock;
 }
 if (FLAG(next_set)) {
  error = command(true, 4, NULL, 0);
  if (error) goto unlock;
 }
 if (FLAG(assigned)) {
  unassign = cpu_to_le32(WORD(shaper));
  error = command(false, 8, &unassign, sizeof(unassign));
  if (error) goto unlock;
 }
 if (!qdx_diag_fq_table_idle(POINTER(struct qdx_dma, table))) { error = -EBUSY; goto unlock; }
 stage = 8;
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
 stage = 9;
 synchronize_net();
 for (i = 0; i < 3; i++) { dev_kfree_skb(packets[i].skb); packets[i].skb = NULL; }
 for (i = 0; i < 2; i++) { dev_kfree_skb(anchors[i].skb); anchors[i].skb = NULL; }
 qdx_endpoint_put(POINTER(struct qdx_endpoint, mirror)); POINTER(struct qdx_endpoint, mirror) = NULL;
 qdx_endpoint_put(POINTER(struct qdx_endpoint, igs)); POINTER(struct qdx_endpoint, igs) = NULL;
 qdx_dma_release(POINTER(struct qdx_dma, table)); POINTER(struct qdx_dma, table) = NULL;
 qdx_service_put(POINTER(struct qdx_service, mirror_service)); POINTER(struct qdx_service, mirror_service) = NULL;
 qdx_service_put(POINTER(struct qdx_service, igs_service)); POINTER(struct qdx_service, igs_service) = NULL;
 dev_put(POINTER(struct net_device, port)); POINTER(struct net_device, port) = NULL;
 FLAG(pinned) = false;
 module_put(module); /* Original prepare's self-reference, not this action's pin. */
 released = true;
 stage = 10;
 self_pinned = false;
 module_put(THIS_MODULE);
 error = 0;
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
 if (!strcmp(command, "return")) error = recovery_run(false);
 else if (!strcmp(command, "close")) error = recovery_run(true);
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
 unsigned int i;
 mutex_lock(&recovery_lock);
 seq_printf(seq, "allow_writes=%u started=%u returned_all=%u released=%u self_pinned=%u stage=%u result=%d data_mask=%x anchor_mask=%x original_run_failed=1 preserved_admission_victims=%u\n",
  allow_writes, started, returned_all, released, self_pinned, stage, result, data_mask, anchor_mask, verified_policy_drops);
 for (i = 0; i < 2; i++)
  seq_printf(seq, "leaf=%u admitted=%llu selected=%llu dropped=%llu\n", i,
   (unsigned long long)admitted[i], (unsigned long long)selected[i], (unsigned long long)dropped[i]);
 mutex_unlock(&recovery_lock);
 return 0;
}
DEFINE_SHOW_ATTRIBUTE(recovery_status);
static int __init recovery_init(void)
{
 struct dentry *entry;
 if (!allow_writes) return -EPERM;
 directory = debugfs_create_dir("qdx_aqm_safety_recovery", NULL);
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
MODULE_DESCRIPTION("Close actual RED diagnostic owners while preserving its failed result");
