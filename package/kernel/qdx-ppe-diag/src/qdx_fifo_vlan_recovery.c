// SPDX-License-Identifier: GPL-2.0-only
/* Bounded repair for frozen FIFO ELF9693cc2a/run220001. No address input. */
#include <linux/debugfs.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/rtnetlink.h>
#include <linux/seq_file.h>
#include <linux/skbuff.h>
#include <linux/sysfs.h>
#include <linux/unaligned.h>
#include <linux/uaccess.h>
#include "qdx_fifo_vlan_recovery_offsets.h"

struct recovery_sections { struct attribute_group grp; struct bin_attribute attrs[]; };
static_assert(sizeof(struct module) == 1216);
static_assert(sizeof(struct mutex) == 32);
static_assert(sizeof(spinlock_t) == 4);
static bool allow_writes, observed_wire_marker;
module_param(allow_writes, bool, 0400);
module_param(observed_wire_marker, bool, 0400);
static bool witness_recovered, requeue_tagged, prefix_untagged;
static u64 marker_admitted, marker_selected, marker_dropped;
static u32 marker_gauge;
static int result;
static struct dentry *directory;
static DEFINE_MUTEX(recovery_lock);
static const u8 expected_build_id[20] = {
 0x95,0xb0,0x22,0x81,0x12,0x48,0x59,0x29,0xc3,0x9b,
 0x24,0x7b,0xa0,0x57,0x9c,0x80,0x59,0x2c,0x56,0x56
};

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

static bool recovery_packet(struct sk_buff *skb, unsigned int group, unsigned int sequence)
{
 const u8 *p;
 if (!skb || skb_is_nonlinear(skb) || skb->len != 106 || skb_mac_header(skb) != skb->data)
  return false;
 p = skb->data;
 return get_unaligned_be16(p + 12) == ETH_P_IP && p[14] == 0x45 && p[23] == IPPROTO_UDP &&
  get_unaligned_be32(p + 26) == 0xc0a80190 && get_unaligned_be32(p + 30) == 0xc0a80173 &&
  get_unaligned_be16(p + 34) == 41000 && get_unaligned_be16(p + 36) == 41001 &&
  !memcmp(p + 42, "QDXPROB1", 8) && get_unaligned_be64(p + 50) == 220001 &&
  p[58] == 1 && get_unaligned_be32(p + 59) == group && get_unaligned_be32(p + 63) == sequence;
}

static int recovery_run(unsigned int action)
{
 struct kprobe finder = { .symbol_name = "find_module" };
 struct kprobe commander = { .symbol_name = "qdx_fifo_handover_diag:phy_command" };
 struct module *(*find_named)(const char *);
 int (*command)(u32, u32);
 struct module *module;
 struct mutex *lock;
 spinlock_t *capture_lock;
 struct sk_buff **prefix, **queue;
 unsigned long text, data, bss, note, this_section, flags;
 u64 *admitted, *selected, *dropped;
 u32 *gauge;
 unsigned int i;
 int error;

 error = register_kprobe(&finder);
 if (error) return error;
 find_named = (void *)finder.addr; unregister_kprobe(&finder);
 rcu_read_lock();
 module = find_named("qdx_fifo_handover_diag");
 if (module && !try_module_get(module)) module = NULL;
 rcu_read_unlock();
 if (!module) return -ENOENT;
 if (module->state != MODULE_STATE_LIVE || strcmp(module_name(module), "qdx_fifo_handover_diag")) {
  error = -ESTALE; goto release;
 }
 text = recovery_section(module, ".text"); data = recovery_section(module, ".data");
 bss = recovery_section(module, ".bss"); note = recovery_section(module, ".note.gnu.build-id");
 this_section = recovery_section(module, ".gnu.linkonce.this_module");
 if (!text || !data || !bss || !note || this_section != (unsigned long)module ||
     !within_module_mem_type(text, module, MOD_TEXT) ||
     !within_module_mem_type(text + 0x1f9b, module, MOD_TEXT) ||
     !within_module_mem_type(data, module, MOD_DATA) ||
     !within_module_mem_type(data + 0xa7, module, MOD_DATA) ||
     !within_module_mem_type(bss, module, MOD_DATA) ||
     !within_module_mem_type(bss + 0x2bb, module, MOD_DATA) ||
     !within_module(note, module) || !within_module(note + 35, module)) {
  error = -ERANGE; goto release;
 }
 if (get_unaligned_le32((void *)note) != 4 || get_unaligned_le32((void *)(note + 4)) != 20 ||
     get_unaligned_le32((void *)(note + 8)) != 3 || memcmp((void *)(note + 12), "GNU", 4) ||
     memcmp((void *)(note + 16), expected_build_id, 20)) { error = -ESTALE; goto release; }
 error = register_kprobe(&commander);
 if (error) goto release;
 command = (void *)commander.addr; unregister_kprobe(&commander);
 if ((unsigned long)command != text + REC_phy_command) { error = -ESTALE; goto release; }
 lock = SLOT(struct mutex, control_lock);
 capture_lock = SLOT(spinlock_t, capture_lock);
 prefix = SLOT(struct sk_buff *, prefix); queue = SLOT(struct sk_buff *, cpu_queue);
 gauge = SLOT(u32, gauge); admitted = SLOT(u64, admitted);
 selected = SLOT(u64, selected); dropped = SLOT(u64, dropped);
 rtnl_lock(); mutex_lock(lock);
 if (!FLAG(pinned) || !FLAG(assigned) || !FLAG(rooted) || !FLAG(default_set) || !FLAG(hook) ||
     !FLAG(cut) || FLAG(fault) || FLAG(path_closed) || FLAG(released) ||
     WORD(allocated) != 7 || WORD(capture_bad) || WORD(native_sent) ||
     *SLOT(void *, request) || !skb_queue_empty(SLOT(struct sk_buff_head, quarantine)) ||
     *SLOT(u64, run_id) != 220001 || WORD(private_vid) != 4000 ||
     WORD(source_ip) != 0xc0a80190 || WORD(target_ip) != 0xc0a80173 ||
     WORD(source_port) != 41000 || WORD(target_port) != 41001) {
  error = -EPERM; goto unlock;
 }
 if (action == 0) {
  if (!observed_wire_marker || witness_recovered || FLAG(fenced) || FLAG(cpu_owned) || FLAG(on) ||
      WORD(markers) || WORD(marker_wait) != 1 || WORD(prefix_count) != 8 ||
      WORD(recalled) || WORD(resubmitted) || WORD(resumed) || WORD(linked) != 4 ||
      *SLOT(int, last_error) != -ETIMEDOUT) { error = -EPERM; goto unlock; }
  for (i = 0; i < 16; i++)
   if (i < 8 ? !recovery_packet(prefix[i], 0, i) || skb_vlan_tag_present(prefix[i]) : !!prefix[i]) {
    error = -EBADMSG; goto unlock;
   }
  for (i = 0; i < 8; i++) if (queue[i]) { error = -EBADMSG; goto unlock; }
  error = command(4, 1);
  if (!error) error = command(4, 2);
  if (error) goto unlock;
  marker_admitted = admitted[2]; marker_selected = selected[2];
  marker_dropped = dropped[2]; marker_gauge = gauge[2];
  if (gauge[1] != 8 || admitted[1] != 16 || selected[1] != 8 || dropped[1] ||
      marker_gauge || marker_admitted != 1 || marker_selected != 1 || marker_dropped) {
   error = -EBADMSG; goto unlock;
  }
  spin_lock_irqsave(capture_lock, flags);
  if (WORD(capture_bad) || WORD(markers) || WORD(prefix_count) != 8) error = -ESTALE;
  else {
   __vlan_hwaccel_put_tag(prefix[0], htons(ETH_P_8021Q), 4000);
   WORD(markers) = 1; FLAG(fenced) = true; *SLOT(int, last_error) = 0;
   witness_recovered = true; error = 0;
  }
  spin_unlock_irqrestore(capture_lock, flags);
 } else if (action == 1) {
  if (!witness_recovered || requeue_tagged || !FLAG(fenced) || !FLAG(cpu_owned) ||
      !FLAG(cpu_selected) || FLAG(on) || WORD(markers) != 3 || WORD(marker_wait) != 3 ||
      WORD(prefix_count) != 9 || WORD(recalled) != 8 || WORD(resubmitted) ||
      WORD(linked) != 4 || queue[0] || !recovery_packet(prefix[8], 1, 0)) {
   error = -EPERM; goto unlock;
  }
  for (i = 1; i < 8; i++)
   if (!recovery_packet(queue[i], 1, i) || skb_vlan_tag_present(queue[i])) {
    error = -EBADMSG; goto unlock;
   }
  for (i = 1; i < 8; i++) __vlan_hwaccel_put_tag(queue[i], htons(ETH_P_8021Q), 4000);
  requeue_tagged = true; error = 0;
 } else if (action == 2) {
  if (!witness_recovered || !requeue_tagged || prefix_untagged || !FLAG(on) ||
      WORD(markers) != 4 || WORD(marker_wait) != 4 || WORD(prefix_count) != 16 ||
      WORD(resubmitted) != 7 || WORD(resumed) != 7 || WORD(linked) != 4) {
   error = -EPERM; goto unlock;
  }
  for (i = 0; i < 16; i++)
   if (!recovery_packet(prefix[i], i >= 8, i % 8) ||
       (i ? skb_vlan_tag_present(prefix[i]) :
        !skb_vlan_tag_present(prefix[i]) || prefix[i]->vlan_proto != htons(ETH_P_8021Q) ||
        skb_vlan_tag_get(prefix[i]) != 4000)) { error = -EBADMSG; goto unlock; }
  __vlan_hwaccel_clear_tag(prefix[0]); prefix_untagged = true; error = 0;
 } else error = -EINVAL;
unlock:
 mutex_unlock(lock); rtnl_unlock();
release:
 module_put(module);
 return error;
}

static ssize_t recovery_control_write(struct file *file, const char __user *buffer,
 size_t count, loff_t *position)
{
 char command[24];
 int error;
 if (!allow_writes) return -EPERM;
 if (!count || count >= sizeof(command)) return -EINVAL;
 if (copy_from_user(command, buffer, count)) return -EFAULT;
 command[count] = 0; strim(command);
 mutex_lock(&recovery_lock);
 if (!strcmp(command, "witness")) error = recovery_run(0);
 else if (!strcmp(command, "tag-requeue")) error = recovery_run(1);
 else if (!strcmp(command, "untag-prefix")) error = recovery_run(2);
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
 seq_printf(seq, "allow_writes=%u observed_wire_marker=%u witness_recovered=%u requeue_tagged=%u prefix_untagged=%u result=%d original_run_failed=1 marker_gauge=%u admitted=%llu selected=%llu dropped=%llu\n",
  allow_writes, observed_wire_marker, witness_recovered, requeue_tagged, prefix_untagged, result,
  marker_gauge, (unsigned long long)marker_admitted, (unsigned long long)marker_selected,
  (unsigned long long)marker_dropped);
 mutex_unlock(&recovery_lock);
 return 0;
}
DEFINE_SHOW_ATTRIBUTE(recovery_status);
static int __init recovery_init(void)
{
 struct dentry *entry;
 if (!allow_writes || !observed_wire_marker) return -EPERM;
 directory = debugfs_create_dir("qdx_fifo_vlan_recovery", NULL);
 if (IS_ERR_OR_NULL(directory)) return -ENOMEM;
 entry = debugfs_create_file("control", 0200, directory, NULL, &recovery_control_fops);
 if (IS_ERR_OR_NULL(entry)) goto fail;
 entry = debugfs_create_file("status", 0400, directory, NULL, &recovery_status_fops);
 if (IS_ERR_OR_NULL(entry)) goto fail;
 return 0;
fail:
 debugfs_remove_recursive(directory); return -ENOMEM;
}
static void __exit recovery_exit(void)
{
 WARN_ON(witness_recovered && !prefix_untagged);
 debugfs_remove_recursive(directory);
}
module_init(recovery_init);
module_exit(recovery_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Bounded owner-preserving recovery of a physical FIFO VLAN diagnostic mistake");
