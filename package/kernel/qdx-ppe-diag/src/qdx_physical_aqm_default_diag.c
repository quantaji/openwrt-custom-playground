// SPDX-License-Identifier: GPL-2.0-only
/* Exact31d caller repair: one original SET_DEFAULT, never packet/history writes. */
#include <linux/debugfs.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/qdx.h>
#include <linux/qdx_diag_aqm.h>
#include <linux/rcupdate.h>
#include <linux/rtnetlink.h>
#include <linux/seq_file.h>
#include <linux/skbuff.h>
#include <linux/sysfs.h>
#include <linux/uaccess.h>
#include <linux/unaligned.h>
#include "qdx_physical_aqm_default_offsets.h"
struct recovery_sections { struct attribute_group grp; struct bin_attribute attrs[]; };
struct recovery_node {
 u32 tag, kind, gauge, bytes;
 u64 admitted, selected, dropped;
 bool allocated;
 int parent;
 u32 band;
 struct qdx_tx_path *path;
 bool path_closed;
};
struct recovery_packet {
 struct sk_buff *skb;
 u32 id, length, returns;
 bool loaned, control, copied, expected_drop, cpu_selected;
 u8 expected[1514];
};
struct recovery_snapshot {
 struct qdx_diag_fq_view view;
 struct qdx_diag_aqm_view aqm;
 struct qdx_diag_aqm_state state;
 u32 ids[16], lengths[16], classes[16];
 u64 ages[16], clock;
};
static_assert(sizeof(struct module) == 1216);
static_assert(sizeof(struct mutex) == 32);
static_assert(sizeof(struct recovery_node) == 72);
static_assert(sizeof(struct recovery_packet) == 1544);
static_assert(sizeof(struct recovery_snapshot) == 8344);
extern bool qdx_diag_fq_table_idle(struct qdx_dma *);
enum { OUTER, INNER, FQ, LEAF_A, LEAF_B, LEAF_C, LEAF_D, MARKER, NODES };
static const u32 tags[NODES] = { 0x710c0000, 0x710d0000, 0x6d010000, 0x710e0000,
 0x710f0000, 0x71100000, 0x71110000, 0x71400000 };
static const u32 kinds[NODES] = { 3, 3, 1, 13, 13, 13, 13, 4 };
static const u8 expected_build_id[20] = {
 0xdb,0xe9,0x9a,0xd7,0x57,0x0d,0x47,0x06,0x12,0xfb,0x13,0x49,0x1e,0xe3,0x03,0xfc,0x82,0xef,0x86,0xa1
};

static bool allow_writes, source_held, attempted, acknowledged;
module_param(allow_writes,bool,0400);
module_param(source_held,bool,0400);
/* Source/PPE hold is checked and journaled by the runner, not guessed here. */
static int result;
static u32 checks;
static struct dentry *directory;
static DEFINE_MUTEX(helper_lock);
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
#define PTR(type, name) (*SLOT(type *, name))


static int republish(void)
{
 struct kprobe finder = { .symbol_name = "find_module" };
 struct kprobe commander = { .symbol_name = "qdx_physical_aqm_diag:aqm_tc" };
 struct module *(*find_named)(const char *);
 struct module *module;
 struct mutex *lock;
 struct recovery_node *nodes;
 struct recovery_packet *packets, *anchors, *marker;
 struct recovery_snapshot *snapshots;
 struct qdx_diag_aqm_state *cpu;
 int (*tc)(u32,u32,u32,u32);
 unsigned long text,data,bss,note;
 const u32 ids[7] = {1,2,4,5,6,7,8};
 unsigned int i;
 int error;
 if (!allow_writes || !source_held || attempted) return -EPERM;
 error=register_kprobe(&finder);
 if (error) return error;
 find_named=(void *)finder.addr; unregister_kprobe(&finder);
 rcu_read_lock(); module=find_named("qdx_physical_aqm_diag");
 if (module && !try_module_get(module)) module=NULL;
 rcu_read_unlock();
 if (!module) return -ENOENT;
 text=recovery_section(module,".text"); data=recovery_section(module,".data");
 bss=recovery_section(module,".bss"); note=recovery_section(module,".note.gnu.build-id");
 if (module->state!=MODULE_STATE_LIVE || !text || !data || !bss || !note ||
     recovery_section(module,".gnu.linkonce.this_module")!=(unsigned long)module ||
     !within_module_mem_type(text+0x4ab7,module,MOD_TEXT) ||
     !within_module_mem_type(data+0x9f,module,MOD_DATA) ||
     !within_module_mem_type(bss+0x171df,module,MOD_DATA) ||
     !within_module(note,module) || !within_module(note+35,module) ||
     get_unaligned_le32((void *)note)!=4 || get_unaligned_le32((void *)(note+4))!=20 ||
     get_unaligned_le32((void *)(note+8))!=3 || memcmp((void *)(note+12),"GNU",4) ||
     memcmp((void *)(note+16),expected_build_id,20)) { error=-ESTALE; goto put; }
 error=register_kprobe(&commander);
 if (error) goto put;
 tc=(void *)commander.addr; unregister_kprobe(&commander);
 if ((unsigned long)tc!=text+REC_aqm_tc) { error=-ESTALE; goto put; }
 checks|=1;
 lock=SLOT(struct mutex,control_lock); nodes=SLOT(struct recovery_node,nodes);
 packets=SLOT(struct recovery_packet,packets); anchors=SLOT(struct recovery_packet,anchor_packets);
 marker=SLOT(struct recovery_packet,marker_packet); snapshots=SLOT(struct recovery_snapshot,snapshots);
 cpu=SLOT(struct qdx_diag_aqm_state,cpu_state);
 rtnl_lock(); mutex_lock(lock);
 if (!FLAG(pinned) || !FLAG(prepared) || !FLAG(loaded) || !FLAG(exported) ||
     !FLAG(adopted) || !FLAG(cpu_selected) || !FLAG(rebuilt) || FLAG(served) ||
     FLAG(passed) || FLAG(closed) || FLAG(fault) || WORD(algorithm)!=1 ||
     WORD(stage)!=3 || WORD(leaf)!=LEAF_A || *SLOT(u64,run_id)!=22101500 ||
     WORD(physical_ifnum)!=4 || WORD(mirror_ifnum)!=28 || WORD(shaper)!=14 ||
     !FLAG(assigned) || !FLAG(enabled) || !FLAG(next_set) || !FLAG(hook) ||
     !FLAG(source_opened) || WORD(source_default)!=LEAF_A || WORD(queue_count)!=8 ||
     WORD(input_events)!=10 || WORD(probe_events) || FLAG(probes_checked) || WORD(probe_drops) ||
     *SLOT(u64,probe_input_base)!=17 || *SLOT(u64,input_expected)!=18 ||
     *SLOT(u64,input_observed)!=17 || WORD(rebuild_stage)!=5 || WORD(rebuilt_submitted)!=7 ||
     WORD(rebuild_next)!=8 || !FLAG(old_backing_retired) || !FLAG(leaf_reallocated) ||
     FLAG(temporary_config) || FLAG(serve_prepared) || FLAG(serve_published) ||
     WORD(backing_retired)!=8 || WORD(controls_retired) || WORD(native_sent) ||
     FLAG(wire_complete) || WORD(resumed_count) || WORD(resumed_victims) ||
     WORD(bad_packets) || WORD(unexpected_clones) || WORD(anchor_accepted)!=2 ||
     WORD(markers)!=1 || WORD(marker_wait)!=1 || marker->loaned || marker->skb ||
     PTR(struct qdx_request,request) || PTR(struct qdx_packet_op,copy_operation) ||
     !skb_queue_empty(SLOT(struct sk_buff_head,quarantine)) ||
     !PTR(struct qdx_dma,table) || !qdx_diag_fq_table_idle(PTR(struct qdx_dma,table)) ||
     *SLOT(int,last_error)!=-ETIMEDOUT) { error=-EPERM; goto unlock; }
 checks|=2;
 for (i=0;i<NODES;i++)
  if (nodes[i].tag!=tags[i] || nodes[i].kind!=kinds[i] || !nodes[i].allocated)
   { error=-ESTALE; goto unlock; }
 if (nodes[OUTER].parent!=-1 || nodes[INNER].parent!=-1 ||
     nodes[FQ].parent!=INNER || nodes[FQ].band!=1 ||
     nodes[FQ].gauge!=2 || nodes[FQ].bytes!=256 || !nodes[FQ].path || !nodes[FQ].path_closed ||
     nodes[LEAF_A].parent!=INNER || nodes[LEAF_A].band ||
     nodes[LEAF_A].gauge!=7 || nodes[LEAF_A].bytes!=10598 ||
     nodes[LEAF_A].admitted!=15 || nodes[LEAF_A].selected || nodes[LEAF_A].dropped!=2 ||
     !nodes[LEAF_A].path || !nodes[LEAF_A].path_closed ||
     nodes[MARKER].parent!=OUTER || nodes[MARKER].band!=2 || nodes[MARKER].path ||
     !packets[0].skb || packets[0].loaned || !packets[0].cpu_selected ||
     packets[0].length!=1514 || packets[0].skb->len!=1514 ||
     !anchors[0].loaned || !anchors[1].loaned || anchors[0].skb || anchors[1].skb)
  { error=-EBADMSG; goto unlock; }
 for (i=0;i<7;i++)
  if (packets[ids[i]].skb || !packets[ids[i]].loaned || packets[ids[i]].length!=1514 ||
      packets[ids[i]].cpu_selected || packets[ids[i]].expected_drop ||
      snapshots[2].ids[i]!=ids[i] || snapshots[2].lengths[i]!=1514)
   { error=-EBADMSG; goto unlock; }
 checks|=4;
 if (cpu->count!=7 || cpu->average[1]!=3218 || cpu->average[2]!=6104 ||
     cpu->occupancy[1]!=3028 || cpu->occupancy[2]!=7570 || !cpu->active || cpu->idle ||
     memcmp(cpu,&snapshots[2].state,sizeof(*cpu))) { error=-EBADMSG; goto unlock; }
 checks|=8;
 /* Original command path journals its own pending request and ACK. No direct
  * writes to firmware data, original error flags, packet owners or histories. */
 attempted=true;
 error=tc(2,LEAF_A,0,0);
 if (!error) {
  if (PTR(struct qdx_request,request) || FLAG(fault) ||
      *SLOT(int,last_error)!=-ETIMEDOUT ||
      memcmp(cpu,&snapshots[2].state,sizeof(*cpu))) error=-EBADMSG;
  else { acknowledged=true; checks|=16; }
 }
unlock:
 mutex_unlock(lock); rtnl_unlock();
put:
 module_put(module);
 return error;
}

static int helper_status_show(struct seq_file *seq,void *unused)
{
 mutex_lock(&helper_lock);
 seq_printf(seq,"attempted=%u acknowledged=%u checks=%u result=%d source_held=%u\n",
  attempted,acknowledged,checks,result,source_held);
 mutex_unlock(&helper_lock);
 return 0;
}
DEFINE_SHOW_ATTRIBUTE(helper_status);
static ssize_t helper_control_write(struct file *file,const char __user *user,
 size_t count,loff_t *offset)
{
 char command[20];
 int error;
 if (!allow_writes || !count || count>=sizeof(command)) return -EPERM;
 if (copy_from_user(command,user,count)) return -EFAULT;
 command[count]=0; strim(command);
 if (strcmp(command,"republish")) return -EINVAL;
 mutex_lock(&helper_lock); error=republish(); result=error; mutex_unlock(&helper_lock);
 return error ?: count;
}
static const struct file_operations helper_control_ops = {
 .owner=THIS_MODULE,.write=helper_control_write,
};
static int __init helper_init(void)
{
 directory=debugfs_create_dir("qdx_physical_aqm_default_diag",NULL);
 if (IS_ERR(directory)) return PTR_ERR(directory);
 debugfs_create_file("status",0400,directory,NULL,&helper_status_fops);
 debugfs_create_file("control",0200,directory,NULL,&helper_control_ops);
 return 0;
}
static void __exit helper_exit(void) { debugfs_remove_recursive(directory); }
module_init(helper_init); module_exit(helper_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Bounded exact31d physical WRED default republishing");
