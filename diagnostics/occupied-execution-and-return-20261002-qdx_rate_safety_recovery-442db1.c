// SPDX-License-Identifier: GPL-2.0-only
/* Close only the failed TBL ELF469ac5b5 run. Never repairs its test result. */
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
enum { OUTER, INNER, MAIN, CLOCK, FQ, FIFO_A, FIFO_B, FIFO_C, SPARE_FIRST, NODES = 40 };
static const u32 tags[8] = { 0x71000000, 0x71080000, 0x71010000, 0x71020000,
 0x6d010000, 0x71030000, 0x71040000, 0x71050000 };
static const u32 kinds[8] = { 3, 3, 5, 5, 1, 4, 4, 4 };
static const int parents[8] = { -1, -1, INNER, INNER, INNER, MAIN, -1, -1 };
static const u32 bands[8] = { 0, 0, 0, 2, 1, 0, 0, 0 };
static const u8 expected_build_id[20] = {
 0x2d,0xa1,0x71,0xcf,0xd1,0xb1,0x62,0x69,0x17,0xe1,
 0x63,0x77,0xd3,0xa5,0x2c,0xa7,0x74,0x6e,0x00,0x2a,
};
static bool allow_writes, started, returned_all, released, self_pinned;
module_param(allow_writes, bool, 0400);
static u32 stage, data_mask, anchor_mask;
static u64 admitted[2], selected[2], dropped[2];
static bool copy_closed;
static u32 copy_originals, copy_clones;
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
     get_unaligned_le32(packet->expected + 42) != 0x45544152 ||
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
 struct kprobe commander = { .symbol_name = "qdx_rate_handover_diag:rate_tc" };
 struct module *(*find_named)(const char *);
 int (*tc)(u32, u32, u32, u32), (*join)(u32), (*gauge)(u32, u32);
 int (*command)(bool, u32, const void *, size_t), (*wait_command)(void);
 struct module *module;
 struct mutex *lock;
 struct recovery_node *nodes;
 struct recovery_packet *packets, *anchors, *private_packet;
 struct recovery_copy_round *copy;
 bool drained;
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
 module = find_named("qdx_rate_handover_diag");
 if (module && !try_module_get(module)) module = NULL;
 rcu_read_unlock();
 if (!module) return -ENOENT;
 if (module->state != MODULE_STATE_LIVE || strcmp(module_name(module), "qdx_rate_handover_diag")) {
  error = -ESTALE; goto release_module;
 }
 text = recovery_section(module, ".text");
 data = recovery_section(module, ".data");
 bss = recovery_section(module, ".bss");
 note = recovery_section(module, ".note.gnu.build-id");
 this_section = recovery_section(module, ".gnu.linkonce.this_module");
 if (!text || !data || !bss || !note || this_section != (unsigned long)module ||
     !within_module_mem_type(text, module, MOD_TEXT) ||
     !within_module_mem_type(text + 0x52ef, module, MOD_TEXT) ||
     !within_module_mem_type(data, module, MOD_DATA) ||
     !within_module_mem_type(data + 0x33, module, MOD_DATA) ||
     !within_module_mem_type(bss, module, MOD_DATA) ||
     !within_module_mem_type(bss + 0x1da6f, module, MOD_DATA) ||
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
 if ((unsigned long)tc != text + REC_rate_tc) { error = -ESTALE; goto release_module; }
 wait_command = (void *)(text + REC_rate_wait_command);
 command = (void *)(text + REC_rate_command);
 join = (void *)(text + REC_rate_join);
 gauge = (void *)(text + REC_rate_gauge);
 lock = SLOT(struct mutex, control_lock);
 nodes = SLOT(struct recovery_node, nodes);
 packets = SLOT(struct recovery_packet, packets);
 anchors = SLOT(struct recovery_packet, anchor_packets);
 private_packet = SLOT(struct recovery_packet, private_packet);
 copy = SLOT(struct recovery_copy_round, copy_round);
 mutex_lock(lock);
 if (!FLAG(pinned) || !FLAG(prepared) || !FLAG(loaded) || FLAG(exported) || FLAG(recalled) ||
     FLAG(cpu_selected) || FLAG(rebuilt) || FLAG(passed) || FLAG(fault) ||
     WORD(group_mode) || WORD(phase) != 1 || WORD(private_count) != 2 || WORD(copy_count) != 10 ||
     WORD(bad_packets) || WORD(disposals) || WORD(unexpected_clones) ||
     WORD(controls_retired) || WORD(selected_mask) || WORD(resume_count) ||
     FLAG(anchor_retiring) || *SLOT(int, last_error) != -ETIMEDOUT || private_packet->skb ||
     private_packet->submitted || private_packet->loaned) {
  error = -EPERM; goto unlock;
 }
 for (i = 0; i < NODES; i++) {
  u32 tag = i < 8 ? tags[i] : 0x71200000 + (i - SPARE_FIRST) * 0x10000;
  u32 kind = i < 8 ? kinds[i] : 12;
  if (nodes[i].tag != tag || nodes[i].kind != kind) { error = -ESTALE; goto unlock; }
 }
 if (!started) {
  if (close_resources || FLAG(closed) || !FLAG(assigned) || !FLAG(enabled) || !FLAG(next_set) ||
      POINTER(struct qdx_request, request) || !POINTER(struct qdx_dma, table) ||
      !qdx_diag_fq_table_idle(POINTER(struct qdx_dma, table)) ||
      !POINTER(struct qdx_endpoint, igs) || !POINTER(struct qdx_endpoint, mirror) ||
      !POINTER(struct qdx_receiver, receiver)) { error = -EPERM; goto unlock; }
  for (i = 0; i < NODES; i++)
   if (nodes[i].allocated != (i <= FIFO_A) || nodes[i].parent != (i < 8 ? parents[i] : -1) ||
       nodes[i].band != (i < 8 ? bands[i] : 0)) { error = -ESTALE; goto unlock; }
  for (i = 0; i < 16; i++)
   if (!recovery_packet_valid(&packets[i], i, i ? 64 : 1514, false, false)) {
    error = -EBADMSG; goto unlock;
   }
  for (i = 0; i < 2; i++)
   if (!recovery_packet_valid(&anchors[i], 0x40000000 + i, 64, true, false)) {
    error = -EBADMSG; goto unlock;
   }
  if (!nodes[FIFO_A].operation || !nodes[FQ].operation ||
      !POINTER(struct qdx_packet_op, copy_operation) ||
      copy->length != 8 || copy->originals != 1 || !copy->original_valid ||
      copy->clones || copy->clone_valid || !completion_done(&copy->original_done) ||
      completion_done(&copy->clone_done)) { error = -ESTALE; goto unlock; }
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
  if (!copy_closed) {
   if (!POINTER(struct qdx_packet_op, copy_operation) || copy->length != 8 ||
       copy->originals != 1 || !copy->original_valid || copy->clones || copy->clone_valid ||
       !completion_done(&copy->original_done) || completion_done(&copy->clone_done) ||
       !qdx_diag_fq_table_idle(POINTER(struct qdx_dma, table))) { error = -ESTALE; goto unlock; }
   qdx_packet_op_close(POINTER(struct qdx_packet_op, copy_operation));
   error = read_poll_timeout(qdx_packet_op_drained, drained, drained, 10,
    6000000, false, POINTER(struct qdx_packet_op, copy_operation));
   if (error) goto unlock;
   copy_originals = copy->originals;
   copy_clones = copy->clones;
   qdx_packet_op_put(POINTER(struct qdx_packet_op, copy_operation));
   POINTER(struct qdx_packet_op, copy_operation) = NULL;
   copy_closed = true;
  }
  if (!returned_all) {
   if (nodes[INNER].parent == -1) {
    error = tc(5, OUTER, INNER, 0);
    if (error) goto unlock;
   } else if (nodes[INNER].parent != OUTER || nodes[INNER].band) {
    error = -ESTALE; goto unlock;
   }
   stage = 2;
   error = join(FIFO_A);
   if (!error) error = join(FQ);
   if (error) goto unlock;
   stage = 3;
   for (i = 0; i < 16; i++) {
    if (!recovery_packet_valid(&packets[i], i, i ? 64 : 1514, false, true)) {
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
    leaf = i ? FQ : FIFO_A;
    error = gauge(leaf, 0);
    if (error) goto unlock;
    admitted[i] = nodes[leaf].admitted;
    selected[i] = nodes[leaf].selected;
    dropped[i] = nodes[leaf].dropped;
   }
   if (admitted[0] != 18 || admitted[1] != 2 ||
       selected[0] != 18 || selected[1] != 2 || dropped[0] || dropped[1]) { error = -EBADMSG; goto unlock; }
   returned_all = true;
   stage = 4;
  }
  error = 0;
  goto unlock;
 }
 if (!returned_all || data_mask != 0xffff || anchor_mask != 3) { error = -EPERM; goto unlock; }
 for (i = 0; i < 16; i++)
  if (!recovery_packet_valid(&packets[i], i, i ? 64 : 1514, false, true)) {
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
 seq_printf(seq, "allow_writes=%u started=%u returned_all=%u released=%u self_pinned=%u stage=%u result=%d data_mask=%x anchor_mask=%x original_run_failed=1 copy_closed=%u copy_originals=%u copy_clones=%u\n",
  allow_writes, started, returned_all, released, self_pinned, stage, result, data_mask, anchor_mask, copy_closed, copy_originals, copy_clones);
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
MODULE_DESCRIPTION("Close actual TBL diagnostic owners while preserving its failed result");
