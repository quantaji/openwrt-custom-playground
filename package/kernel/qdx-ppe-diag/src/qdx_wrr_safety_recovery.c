// SPDX-License-Identifier: GPL-2.0-only
/* Close only the failed WRR ELF50047967 run. Never repairs its test result. */
#include <linux/debugfs.h>
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
#include "qdx_wrr_safety_recovery_offsets.h"

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
extern bool qdx_diag_fq_table_idle(struct qdx_dma *);
enum { OUTER, ROOT, ANCHOR, GROUP_A, GROUP_B, FIFO_A, FIFO_B, PROBE, FQ, NODES };
static const u32 tags[NODES] = {
 0x6f000000,0x6f010000,0x6f020000,0x6f030000,0x6f040000,
 0x6f050000,0x6f060000,0x6f070000,0x6d010000,
};
static const u32 kinds[NODES] = { 3,9,10,10,10,4,4,4,1 };
static const int parents[NODES] = { -1,-1,ROOT,ROOT,ROOT,GROUP_A,GROUP_B,-1,ANCHOR };
static const u32 lengths[16] = {64,128,67,106,64,1514,128,106,106,64,256,67,512,64,128,106};
static const u8 expected_build_id[20] = {
 0x0e,0x79,0xd4,0x3c,0x91,0x53,0x2c,0x9b,0xfa,0xe4,
 0x0b,0x0f,0x55,0x41,0xe5,0x9a,0x9b,0x0c,0x24,0xcc,
};
static bool allow_writes, started, returned_all, released, self_pinned;
module_param(allow_writes, bool, 0400);
static u32 stage, data_mask, anchor_mask;
static u64 admitted[3], selected[3], dropped[3];
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
     get_unaligned_le32(packet->expected + 42) != 0x52525751 ||
     get_unaligned_le32(packet->expected + 46) != id) return false;
 if (!returned)
  return packet->loaned && packet->submitted && !packet->skb && !packet->returns;
 return !packet->loaned && !packet->submitted && packet->skb && packet->returns == 1 &&
  packet->skb->len == length && !skb_is_nonlinear(packet->skb) &&
  !memcmp(packet->skb->data, packet->expected, length);
}

static int recovery_run(bool close_resources)
{
 struct kprobe finder = { .symbol_name = "find_module" };
 struct kprobe commander = { .symbol_name = "qdx_wrr_handover_diag:wrr_tc" };
 struct module *(*find_named)(const char *);
 int (*tc)(u32, u32, u32, u32), (*join)(u32), (*gauge)(u32, u32);
 int (*command)(bool, u32, const void *, size_t), (*wait_command)(void);
 struct module *module;
 struct mutex *lock;
 struct recovery_node *nodes;
 struct recovery_packet *packets, *anchors, *private_packet;
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
 module = find_named("qdx_wrr_handover_diag");
 if (module && !try_module_get(module)) module = NULL;
 rcu_read_unlock();
 if (!module) return -ENOENT;
 if (module->state != MODULE_STATE_LIVE || strcmp(module_name(module), "qdx_wrr_handover_diag")) {
  error = -ESTALE; goto release_module;
 }
 text = recovery_section(module, ".text");
 data = recovery_section(module, ".data");
 bss = recovery_section(module, ".bss");
 note = recovery_section(module, ".note.gnu.build-id");
 this_section = recovery_section(module, ".gnu.linkonce.this_module");
 if (!text || !data || !bss || !note || this_section != (unsigned long)module ||
     !within_module_mem_type(text, module, MOD_TEXT) ||
     !within_module_mem_type(text + 0x3807, module, MOD_TEXT) ||
     !within_module_mem_type(data, module, MOD_DATA) ||
     !within_module_mem_type(data + 0x26b, module, MOD_DATA) ||
     !within_module_mem_type(bss, module, MOD_DATA) ||
     !within_module_mem_type(bss + 0xbebf, module, MOD_DATA) ||
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
 if ((unsigned long)tc != text + REC_wrr_tc) { error = -ESTALE; goto release_module; }
 wait_command = (void *)(text + REC_wrr_wait_command);
 command = (void *)(text + REC_wrr_command);
 join = (void *)(text + REC_wrr_join);
 gauge = (void *)(text + REC_wrr_gauge);
 lock = SLOT(struct mutex, control_lock);
 nodes = SLOT(struct recovery_node, nodes);
 packets = SLOT(struct recovery_packet, packets);
 anchors = SLOT(struct recovery_packet, anchor_packets);
 private_packet = SLOT(struct recovery_packet, private_packet);
 mutex_lock(lock);
 if (!FLAG(pinned) || !FLAG(prepared) || !FLAG(loaded) || FLAG(exported) || FLAG(recalled) ||
     FLAG(cpu_selected) || FLAG(rebuilt) || FLAG(passed) || FLAG(fault) ||
     WORD(byte_mode) || WORD(phase) != 1 || WORD(private_count) != 7 ||
     WORD(bad_packets) || WORD(disposals) || WORD(unexpected_clones) ||
     WORD(controls_retired) || WORD(selected_mask) || WORD(resume_count) ||
     FLAG(anchor_retiring) || *SLOT(int, last_error) != -EBADMSG ||
     POINTER(struct qdx_packet_op, copy_operation) || private_packet->skb ||
     private_packet->submitted || private_packet->loaned) {
  error = -EPERM; goto unlock;
 }
 for (i = 0; i < NODES; i++)
  if (nodes[i].tag != tags[i] || nodes[i].kind != kinds[i]) { error = -ESTALE; goto unlock; }
 if (!started) {
  if (close_resources || FLAG(closed) || !FLAG(assigned) || !FLAG(enabled) || !FLAG(next_set) ||
      POINTER(struct qdx_request, request) || !POINTER(struct qdx_dma, table) ||
      !qdx_diag_fq_table_idle(POINTER(struct qdx_dma, table)) ||
      !POINTER(struct qdx_endpoint, igs) || !POINTER(struct qdx_endpoint, mirror) ||
      !POINTER(struct qdx_receiver, receiver)) { error = -EPERM; goto unlock; }
  for (i = 0; i < NODES; i++)
   if (!nodes[i].allocated || nodes[i].parent != parents[i] || nodes[i].band) {
    error = -ESTALE; goto unlock;
   }
  for (i = 0; i < 16; i++)
   if (!recovery_packet_valid(&packets[i], i, lengths[i], false, false)) {
    error = -EBADMSG; goto unlock;
   }
  for (i = 0; i < 2; i++)
   if (!recovery_packet_valid(&anchors[i], 0x40000000 + i, 64, true, false)) {
    error = -EBADMSG; goto unlock;
   }
  if (!nodes[FIFO_A].operation || !nodes[FIFO_B].operation || !nodes[FQ].operation) {
   error = -ESTALE; goto unlock;
  }
  if (!try_module_get(THIS_MODULE)) { error = -ENODEV; goto unlock; }
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
   if (nodes[ROOT].parent == -1) {
    error = tc(5, OUTER, ROOT, 0);
    if (error) goto unlock;
   } else if (nodes[ROOT].parent != OUTER || nodes[ROOT].band) {
    error = -ESTALE; goto unlock;
   }
   stage = 2;
   error = join(FIFO_A);
   if (!error) error = join(FIFO_B);
   if (!error) error = join(FQ);
   if (error) goto unlock;
   stage = 3;
   for (i = 0; i < 16; i++) {
    if (!recovery_packet_valid(&packets[i], i, lengths[i], false, true)) {
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
   for (i = 0; i < 3; i++) {
    leaf = i == 2 ? FQ : FIFO_A + i;
    error = gauge(leaf, 0);
    if (error) goto unlock;
    admitted[i] = nodes[leaf].admitted;
    selected[i] = nodes[leaf].selected;
    dropped[i] = nodes[leaf].dropped;
   }
   if (admitted[0] != 13 || admitted[1] != 10 || admitted[2] != 2 ||
       selected[0] != 13 || selected[1] != 10 || selected[2] != 2 ||
       dropped[0] || dropped[1] || dropped[2]) { error = -EBADMSG; goto unlock; }
   returned_all = true;
   stage = 4;
  }
  error = 0;
  goto unlock;
 }
 if (!returned_all || data_mask != 0xffff || anchor_mask != 3) { error = -EPERM; goto unlock; }
 for (i = 0; i < 16; i++)
  if (!recovery_packet_valid(&packets[i], i, lengths[i], false, true)) {
   error = -EBADMSG; goto unlock;
  }
 for (i = 0; i < 2; i++)
  if (!recovery_packet_valid(&anchors[i], 0x40000000 + i, 64, true, true)) {
   error = -EBADMSG; goto unlock;
  }
 FLAG(closed) = true;
 stage = 5;
 for (i = 0; i < NODES; i++) {
  error = join(i);
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
 for (i = 0; i < 16; i++) { dev_kfree_skb(packets[i].skb); packets[i].skb = NULL; }
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
 seq_printf(seq, "allow_writes=%u started=%u returned_all=%u released=%u self_pinned=%u stage=%u result=%d data_mask=%x anchor_mask=%x original_run_failed=1\n",
  allow_writes, started, returned_all, released, self_pinned, stage, result, data_mask, anchor_mask);
 for (i = 0; i < 3; i++)
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
 directory = debugfs_create_dir("qdx_wrr_safety_recovery", NULL);
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
MODULE_DESCRIPTION("Close actual WRR diagnostic owners while preserving its failed result");
