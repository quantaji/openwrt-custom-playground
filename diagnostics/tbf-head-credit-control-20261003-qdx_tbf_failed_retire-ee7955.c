// SPDX-License-Identifier: GPL-2.0-only
/* Exact failed TBF run23031005 retirement after independent four-original wire
 * proof. Never a successful handover, packet replay, purge, or generic API. */
#include <linux/capability.h>
#include <linux/debugfs.h>
#include <linux/io.h>
#include <linux/kprobes.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/rcupdate.h>
#include <linux/rtnetlink.h>
#include <linux/sched/task.h>
#include <linux/seq_file.h>
#include <linux/skbuff.h>
#include <linux/sysfs.h>
#include <linux/uaccess.h>
#include <linux/unaligned.h>
#define Q 193
#define HEAD (0x86c000 + 16 * Q)
#define USED (0x84e000 + 16 * Q)
#define DEQ (0x430000 + 16 * Q)
#define ENQ (0x85c000 + 16 * Q)
#define TX (0x024000 + 16 * Q)
#define H_COUNT 4
struct h_item {
    struct sk_buff *skb;
    u8 bytes[106];
    u16 length, before_id, rebuilt_id;
    bool received, consumed, arrived;
};
struct h_decision {
    s64 before_tokens, before_ptokens, before_time;
    s64 after_tokens, after_ptokens, after_time;
    s64 first_mean, first_peak;
    u64 first_check_ns, first_due_ns, publish_ns, complete_ns;
    u32 length, id, tx_before, tx_after;
    bool cpu, issued, done;
};
struct failed_handover {
    struct net_device *conduit, *output;
    void __iomem *edma;
    struct sk_buff_head quarantine;
    struct h_item item[H_COUNT];
    struct h_decision decision[H_COUNT];
    bool active, hook, sealed, recall_issued, recalled, maps_restored;
    bool c_touched, e_touched, route_touched, map_touched, port_touched;
    bool cpu_sent, cpu_done, class_one, import_open, complete, empty_abort;
    u16 priority_touched;
    u32 saved_c, expected_c, saved_e, expected_e;
    u32 saved_route, expected_route, expected_map, expected_port;
    u32 returned, bad, native_sent, queued, cpu_tx_before, cpu_tx_after;
    u32 phase, source_tx, recall_tx, resumed_tx, cpu_source_profile, cpu_source_mru, cpu_selector;
    s64 cut_tokens, cut_ptokens, cut_time;
    s64 resumed_tokens, resumed_ptokens, resumed_time;
    u64 cut_ns, recall_ns, cpu_ns, resume_ns;
    int error, stage_error, transport_error;
};

struct recovery_sections { struct attribute_group grp; struct bin_attribute attrs[]; };
static_assert(sizeof(struct module) == 1216);
static_assert(sizeof(struct mutex) == 32);
static_assert(sizeof(struct h_item) == 128);
static_assert(sizeof(struct h_decision) == 120);
static_assert(sizeof(struct failed_handover) == 1240);
static_assert(offsetof(struct failed_handover, quarantine) == 24);
static_assert(offsetof(struct failed_handover, item) == 48);
static_assert(offsetof(struct failed_handover, decision) == 560);
static_assert(offsetof(struct failed_handover, active) == 1040);
static_assert(offsetof(struct failed_handover, phase) == 1116);
static_assert(offsetof(struct failed_handover, error) == 1224);
static bool allow_writes;
module_param(allow_writes, bool, 0400);
static DEFINE_MUTEX(recovery_lock);
static struct dentry *directory;
static unsigned int progress;
static bool failed_terminated;
static int last_result;
static u32 mismatch_offset, expected_word, actual_word;
static unsigned long observed_text, observed_data, observed_bss;
static const u8 expected_build_id[20] = {
 0xae,0xe5,0x08,0x5d,0x44,0x8c,0x7b,0x7a,0x8d,0x5f,
 0x78,0x97,0x45,0x79,0x08,0xa7,0xfc,0x6f,0x39,0x20
};

static unsigned long owner_section(struct module *module, const char *name)
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

static int restore_word(void __iomem *base, u32 off, u32 *expected, u32 desired)
{
 u32 value = readl(base + off);
 if (value != *expected) {
  mismatch_offset = off; expected_word = *expected; actual_word = value;
  return -ESTALE;
 }
 *expected = desired; /* Any later mismatch preserves the attempted owner. */
 writel(desired, base + off);
 value = readl(base + off);
 if (value == desired) return 0;
 mismatch_offset = off; expected_word = desired; actual_word = value;
 return -EIO;
}

static int retire_failed_run(void)
{
 struct kprobe finder = { .symbol_name = "find_module" };
 struct kprobe anchor = { .symbol_name = "qdx_tbf_diag:control_write" };
 struct module *(*find_named)(const char *);
 struct module *module;
 struct mutex *lock;
 struct task_struct *task;
 struct failed_handover *h;
 void __iomem *ppe;
 unsigned long text, data, bss, note;
 unsigned int i;
 u32 route, desired;
 int err;
 if (failed_terminated) return -EALREADY;
 err = register_kprobe(&finder);
 if (err) return err;
 find_named = (void *)finder.addr;
 unregister_kprobe(&finder);
 rcu_read_lock();
 module = find_named("qdx_tbf_diag");
 if (module && !try_module_get(module)) module = NULL;
 rcu_read_unlock();
 if (!module) return -ENOENT;
 if (module->state != MODULE_STATE_LIVE || strcmp(module_name(module), "qdx_tbf_diag")) {
  err = -ESTALE; goto put;
 }
 text = owner_section(module,".text"); data = owner_section(module,".data");
 bss = owner_section(module,".bss"); note = owner_section(module,".note.gnu.build-id");
 if (!text || !data || !bss || !note ||
     owner_section(module,".gnu.linkonce.this_module") != (unsigned long)module ||
     !within_module_mem_type(text,module,MOD_TEXT) ||
     !within_module_mem_type(text+0x77d7,module,MOD_TEXT) ||
     !within_module_mem_type(data,module,MOD_DATA) ||
     !within_module_mem_type(data+0x67,module,MOD_DATA) ||
     !within_module_mem_type(bss,module,MOD_DATA) ||
     !within_module_mem_type(bss+0x18e1,module,MOD_DATA) ||
     !within_module(note,module) || !within_module(note+35,module)) {
  err = -ERANGE; goto put;
 }
 if (get_unaligned_le32((void *)note)!=4 || get_unaligned_le32((void *)(note+4))!=20 ||
     get_unaligned_le32((void *)(note+8))!=3 || memcmp((void *)(note+12),"GNU",4) ||
     memcmp((void *)(note+16),expected_build_id,20)) { err=-ESTALE; goto put; }
 err = register_kprobe(&anchor);
 if (err) goto put;
 err = (unsigned long)anchor.addr == text+0x5e24 ? 0 : -ESTALE;
 unregister_kprobe(&anchor);
 if (err) goto put;
 observed_text=text; observed_data=data; observed_bss=bss;
 lock=(void *)(data+0x30); h=(void *)bss;
 mutex_lock(lock);
 ppe=*(void __iomem **)(bss+0x4e8);
 if (!ppe || *(u64 *)(bss+0x1840)!=23031005 || !*(bool *)(bss+0x148b) ||
     *(bool *)(bss+0x148a) || !*(bool *)(bss+0x1489) || *(bool *)(bss+0x1488) ||
     *(bool *)(bss+0x530) || *(bool *)(bss+0x1448) || *(bool *)(bss+0x1449) ||
     *(int *)(bss+0x544) || *(u64 *)(bss+0x14f8)!=1 || *(u64 *)(bss+0x13e0)!=1 ||
     !h->active || h->phase!=3 || h->error!=-ETIMEDOUT || h->stage_error!=3 ||
     !h->sealed || !h->recall_issued || h->recalled || h->returned || h->bad ||
     h->cpu_sent || h->cpu_done || h->native_sent || h->queued || h->complete ||
     h->empty_abort || h->transport_error || h->priority_touched || h->class_one ||
     h->import_open || !h->edma || !h->output || !h->conduit ||
     !h->map_touched || !h->port_touched || !h->c_touched || !h->e_touched || !h->route_touched) {
  err=-EPERM; goto unlock;
 }
 synchronize_net();
 if (!skb_queue_empty(&h->quarantine) || !(readl(ppe+DEQ)&1) ||
     !(readl(ppe+ENQ)&1) || !(readl(ppe+HEAD)&1) ||
     (readl(ppe+USED)&0xfff) ||
     (u32)(readl(ppe+TX)-h->source_tx)!=4) {
  err=-EBUSY; goto unlock;
 }
 for(i=0;i<H_COUNT;i++)
  if(h->item[i].skb || h->item[i].received || h->item[i].consumed || h->item[i].arrived) {
   err=-EBUSY; goto unlock;
  }
 if (!h->decision[0].issued || !h->decision[0].done || h->decision[0].cpu ||
     h->decision[0].length!=67 || h->decision[1].issued ||
     h->decision[2].issued || h->decision[3].issued) { err=-EPERM; goto unlock; }
 task=*(struct task_struct **)(bss+0x4d8);
 if (!progress && !task) { err=-ESTALE; goto unlock; }
 if (task) {
  get_task_struct(task);
  mutex_unlock(lock);
  kthread_stop(task); /* The finished worker waits outside lock; never join under lock. */
  mutex_lock(lock);
  if (*(struct task_struct **)(bss+0x4d8)!=task || *(bool *)(bss+0x148a)) {
   put_task_struct(task); err=-ESTALE; goto unlock;
  }
  *(struct task_struct **)(bss+0x4d8)=NULL;
  put_task_struct(task);
 }
 progress=1;
 err=restore_word(ppe,0x402000+16*193,&h->expected_map,*(u32 *)(bss+0x13ac));
 if (err) goto unlock;
 err=restore_word(ppe,0x408000+16*193,&h->expected_port,*(u32 *)(bss+0x185c));
 if (err) goto unlock;
 progress=2;
 err=restore_word(ppe,0x404070,&h->expected_c,h->saved_c);
 if (err) goto unlock;
 err=restore_word(ppe,0x406070,&h->expected_e,h->saved_e);
 if (err) goto unlock;
 route=readl(h->edma+0x5a000+4*(193/8));
 if (((route>>4)&15)!=((h->expected_route>>4)&15)) {err=-ESTALE;goto unlock;}
 desired=(route&~(15U<<4))|(h->saved_route&(15U<<4));
 h->expected_route=desired; writel(desired,h->edma+0x5a000+4*(193/8));
 if(readl(h->edma+0x5a000+4*(193/8))!=desired){err=-EIO;goto unlock;}
 h->maps_restored=true;
 progress=3;
 if(h->hook){
  rtnl_lock();
  netdev_rx_handler_unregister(h->conduit);
  rtnl_unlock();
  h->hook=false;
 }
 synchronize_net();
 if(!skb_queue_empty(&h->quarantine)){err=-EBUSY;goto unlock;}
 dev_put(h->output); dev_put(h->conduit); iounmap(h->edma);
 h->output=h->conduit=NULL; h->edma=NULL; h->active=false;
 /* Original phase/error/zero returns/credit history/complete=false survive.
  * This terminal means failed experiment has no original work left, not H pass.
  * Root must next run the original unchanged normal restore. */
 *(bool *)(bss+0x1488)=true;
 failed_terminated=true; progress=4; err=0;
unlock:
 mutex_unlock(lock);
put:
 module_put(module);
 return err;
}

static ssize_t recovery_control_write(struct file *file, const char __user *buffer,
 size_t count, loff_t *position)
{
 char command[32]; int err;
 if(!allow_writes || !capable(CAP_SYS_ADMIN) || !count || count>=sizeof(command))return -EPERM;
 if(copy_from_user(command,buffer,count))return -EFAULT;
 command[count]=0;strim(command);
 if(strcmp(command,"retire-wire4"))return -EINVAL;
 mutex_lock(&recovery_lock);err=retire_failed_run();last_result=err;mutex_unlock(&recovery_lock);
 return err?:count;
}
static const struct file_operations recovery_control_fops={.owner=THIS_MODULE,.write=recovery_control_write};
static int recovery_status_show(struct seq_file *s,void *unused)
{
 mutex_lock(&recovery_lock);
 seq_printf(s,"failed_terminated=%u original_handover_pass=0 progress=%u result=%d mismatch=%06x expected=%08x actual=%08x text=%lx data=%lx bss=%lx\n",
  failed_terminated,progress,last_result,mismatch_offset,expected_word,actual_word,observed_text,observed_data,observed_bss);
 mutex_unlock(&recovery_lock);return 0;
}
DEFINE_SHOW_ATTRIBUTE(recovery_status);
static int __init recovery_init(void)
{
 directory=debugfs_create_dir("qdx_tbf_failed_retire",NULL);
 if(IS_ERR_OR_NULL(directory))return directory?PTR_ERR(directory):-ENOMEM;
 if(IS_ERR_OR_NULL(debugfs_create_file("status",0400,directory,NULL,&recovery_status_fops)) ||
    IS_ERR_OR_NULL(debugfs_create_file("control",0200,directory,NULL,&recovery_control_fops))){
  debugfs_remove_recursive(directory);return -ENOMEM;
 }
 return 0;
}
static void __exit recovery_exit(void){debugfs_remove_recursive(directory);}
module_init(recovery_init);module_exit(recovery_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Exact failed TBF native handover retirement, no successful H attestation");
