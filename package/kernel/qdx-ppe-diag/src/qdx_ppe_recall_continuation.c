// SPDX-License-Identifier: GPL-2.0-only
/* Exact retained1070 owner: same-map C-refill and disabled-row controls / actual-owner closure. */
#include <linux/build_bug.h>
#include <linux/capability.h>
#include <linux/debugfs.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/jiffies.h>
#include <linux/kprobes.h>
#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/rcupdate.h>
#include <linux/seq_file.h>
#include <linux/skbuff.h>
#include <linux/sysfs.h>
#include <linux/uaccess.h>
#include <linux/unaligned.h>
#include "qdx_ppe_recall_continuation_offsets.h"
struct recovery_sections { struct attribute_group grp; struct bin_attribute attrs[]; };
struct retaining_item {
 struct sk_buff *skb;
 u16 length, before_id, rebuilt_id;
 u8 bytes[1514];
 bool observed, received, tx_consumed, queue_arrived;
};
struct prefix_observation {
 u64 ns;
 u32 credit[2], compensation[3], config[3], tx[3];
 u32 enable, speed, mib, rx_pause, tx_unicast, tx_bytes[2];
};
struct retained_owner {
 bool active, hook, sealed, recall_issued, recalled, map_touched;
 bool c_touched, e_touched, route_touched, map_restored, cpu_selected;
 bool reinsert_issued, grant_issued, grant_complete, rest_issued, complete;
 bool prefix_mode, prefix_opened, prefix_cut, prefix_terminal, prefix_rerouted;
 bool prefix_direct, prefix_draining, gmac_touched, gmac_restored;
 u32 initial_count, arrival_count, recall_first, reinsert_first;
 u32 prefix_selected, gmac_saved, gmac_expected, gmac_speed, gmac_mib;
 u32 prefix_samples;
 struct prefix_observation prefix_sample[5];
 u32 source_if, source_ip, target_ip, source_port, target_port;
 u32 input_u, input_a, returned, native_sent, queued, bad, stage;
 u32 c_saved, e_saved, c_expected, e_expected, map_expected, port_expected;
 u32 route_saved, route_expected, cpu_parent_cfg[3], cpu_port_cfg[2];
 u32 original_tx[3], reinsert_tx[3], drop[6][3], tx_status;
 u32 head_before, head_after, descriptors[10][13];
 u64 run_id, recall_start_ns, recall_done_ns;
 int error;
 struct net_device *output, *conduit;
 struct retaining_item item[10];
 struct sk_buff_head quarantine;
};
static_assert(sizeof(struct module) == 1216);
static_assert(sizeof(struct mutex) == 32);
static_assert(sizeof(struct retained_owner) == 16632);
static_assert(sizeof(struct retaining_item) == 1536);
static_assert(offsetof(struct retained_owner, active) == 0);
static_assert(offsetof(struct retained_owner, hook) == 1);
static_assert(offsetof(struct retained_owner, sealed) == 2);
static_assert(offsetof(struct retained_owner, recall_issued) == 3);
static_assert(offsetof(struct retained_owner, recalled) == 4);
static_assert(offsetof(struct retained_owner, map_touched) == 5);
static_assert(offsetof(struct retained_owner, c_touched) == 6);
static_assert(offsetof(struct retained_owner, e_touched) == 7);
static_assert(offsetof(struct retained_owner, route_touched) == 8);
static_assert(offsetof(struct retained_owner, map_restored) == 9);
static_assert(offsetof(struct retained_owner, cpu_selected) == 10);
static_assert(offsetof(struct retained_owner, reinsert_issued) == 11);
static_assert(offsetof(struct retained_owner, grant_issued) == 12);
static_assert(offsetof(struct retained_owner, grant_complete) == 13);
static_assert(offsetof(struct retained_owner, rest_issued) == 14);
static_assert(offsetof(struct retained_owner, complete) == 15);
static_assert(offsetof(struct retained_owner, prefix_mode) == 16);
static_assert(offsetof(struct retained_owner, prefix_opened) == 17);
static_assert(offsetof(struct retained_owner, prefix_cut) == 18);
static_assert(offsetof(struct retained_owner, prefix_terminal) == 19);
static_assert(offsetof(struct retained_owner, prefix_rerouted) == 20);
static_assert(offsetof(struct retained_owner, prefix_direct) == 21);
static_assert(offsetof(struct retained_owner, prefix_draining) == 22);
static_assert(offsetof(struct retained_owner, gmac_touched) == 23);
static_assert(offsetof(struct retained_owner, gmac_restored) == 24);
static_assert(offsetof(struct retained_owner, initial_count) == 28);
static_assert(offsetof(struct retained_owner, arrival_count) == 32);
static_assert(offsetof(struct retained_owner, recall_first) == 36);
static_assert(offsetof(struct retained_owner, reinsert_first) == 40);
static_assert(offsetof(struct retained_owner, prefix_selected) == 44);
static_assert(offsetof(struct retained_owner, gmac_saved) == 48);
static_assert(offsetof(struct retained_owner, gmac_expected) == 52);
static_assert(offsetof(struct retained_owner, gmac_speed) == 56);
static_assert(offsetof(struct retained_owner, gmac_mib) == 60);
static_assert(offsetof(struct retained_owner, prefix_samples) == 64);
static_assert(offsetof(struct retained_owner, prefix_sample) == 72);
static_assert(offsetof(struct retained_owner, source_if) == 472);
static_assert(offsetof(struct retained_owner, source_ip) == 476);
static_assert(offsetof(struct retained_owner, target_ip) == 480);
static_assert(offsetof(struct retained_owner, source_port) == 484);
static_assert(offsetof(struct retained_owner, target_port) == 488);
static_assert(offsetof(struct retained_owner, input_u) == 492);
static_assert(offsetof(struct retained_owner, input_a) == 496);
static_assert(offsetof(struct retained_owner, returned) == 500);
static_assert(offsetof(struct retained_owner, native_sent) == 504);
static_assert(offsetof(struct retained_owner, queued) == 508);
static_assert(offsetof(struct retained_owner, bad) == 512);
static_assert(offsetof(struct retained_owner, stage) == 516);
static_assert(offsetof(struct retained_owner, c_saved) == 520);
static_assert(offsetof(struct retained_owner, e_saved) == 524);
static_assert(offsetof(struct retained_owner, c_expected) == 528);
static_assert(offsetof(struct retained_owner, e_expected) == 532);
static_assert(offsetof(struct retained_owner, map_expected) == 536);
static_assert(offsetof(struct retained_owner, port_expected) == 540);
static_assert(offsetof(struct retained_owner, route_saved) == 544);
static_assert(offsetof(struct retained_owner, route_expected) == 548);
static_assert(offsetof(struct retained_owner, cpu_parent_cfg) == 552);
static_assert(offsetof(struct retained_owner, cpu_port_cfg) == 564);
static_assert(offsetof(struct retained_owner, original_tx) == 572);
static_assert(offsetof(struct retained_owner, reinsert_tx) == 584);
static_assert(offsetof(struct retained_owner, drop) == 596);
static_assert(offsetof(struct retained_owner, tx_status) == 668);
static_assert(offsetof(struct retained_owner, head_before) == 672);
static_assert(offsetof(struct retained_owner, head_after) == 676);
static_assert(offsetof(struct retained_owner, descriptors) == 680);
static_assert(offsetof(struct retained_owner, run_id) == 1200);
static_assert(offsetof(struct retained_owner, recall_start_ns) == 1208);
static_assert(offsetof(struct retained_owner, recall_done_ns) == 1216);
static_assert(offsetof(struct retained_owner, error) == 1224);
static_assert(offsetof(struct retained_owner, output) == 1232);
static_assert(offsetof(struct retained_owner, conduit) == 1240);
static_assert(offsetof(struct retained_owner, item) == 1248);
static_assert(offsetof(struct retained_owner, quarantine) == 16608);

static const u8 expected_build_id[20] = {
 0xf8,0xe4,0x3b,0x24,0xc1,0x94,0x3d,0x0c,0x92,0x51,
 0x12,0x30,0xaf,0x97,0xe7,0xdd,0x54,0x0d,0x62,0x3f,
};
static bool allow_writes, inspected, attempted, finished, physical_pending, physical_terminal;
static unsigned int wire_count;
static bool refill_attempted, bypass_attempted, bypass_ready;
static u32 action_done;
static u32 expected_credit[2]={0x0fe056a5,0x2ff966f2},expected_comp[3];
static u32 eligibility_before[3],eligibility_running[3],eligibility_after[3];
module_param(allow_writes,bool,0400);
/* Root supplies1 only after exact P bytes on physical wire, not PTX alone. */
module_param(wire_count,uint,0400);
static int result, open_result = -ECANCELED, finish_result;
static bool row_write_issued, row_write_done, row_restore_issued, row_restored;
static int row_write_result, row_restore_result;
static u64 row_begin_ns, row_enabled_ns, row_stop_ns, row_stopped_ns;
static u32 enabled_config[3], stopped_config[3], transfer_returned, transfer_mac;
static u32 stage, returned, bad, before_credit[2], after_credit[2];
static u32 before_tx, after_tx, before_comp[3], after_comp[3];
static u32 mac_before, mac_after, port_credit, port_sign, map, destination;
static int old_error, old_last;
static u32 owner_stage, owner_recalled, maps_restored;
static struct dentry *directory;
static DEFINE_MUTEX(recovery_lock);
static unsigned long recovery_section(struct module *module,const char *name)
{
 struct recovery_sections *sections=(void *)module->sect_attrs;
 const struct bin_attribute *const *entry;
 unsigned int i;
 if (!sections || !sections->grp.bin_attrs) return 0;
 entry=sections->grp.bin_attrs;
 for (i=0;i<64 && entry[i];i++)
  if (!strcmp(entry[i]->attr.name,name)) return (unsigned long)entry[i]->private;
 return 0;
}
#define SLOT(type,name) ((type *)(REC_##name##_BASE + REC_##name))
#define FLAG(name) (*SLOT(bool,name))
#define WORD(name) (*SLOT(u32,name))
#define MMIO(offset) readl(ppe + (offset))

/* This function does not install any callback or acquire packet ownership.
 * The original reservation keeps the owner module pinned; the temporary
 * reference also spans the original hrtimer cancellation on every result. */
static int recovery_run(unsigned int action)
{
 struct kprobe finder={.symbol_name="find_module"};
 struct kprobe opener={.symbol_name="qdx_ppe_diag:open_window_on"};
 struct module *(*find_named)(const char *);
 struct module *module;
 struct retained_owner *owner;
 struct mutex *lock;
 void __iomem *ppe,*edma;
 int (*open)(unsigned int,unsigned int,bool),(*close)(void);
 int (*maps)(void),(*mac)(void),(*chain)(unsigned int,unsigned int,bool);
 int (*finish)(void),(*observe)(unsigned int);
 int (*write_row)(u32,const u32 *,unsigned int);
 int (*write)(u32,u32);
 u32 value,*saved_map,*saved_port;
 unsigned long text,data,bss,note,timeout;
 unsigned int i;
 u16 ids[2];
 int error,close_error;
 const u32 refill_config[3]={0xfffc0001,0xfffc0002,0x30};
 const u32 bypass_config[3]={0xfffc0000,0xfffc0000,0};
 const u32 status_offset[3]={0x424b00,0x466000,0x4662c0};
 const u32 *run_config;
 const u32 frozen_config[3]={0xfffc0000,0xfffc0000,0x30};
 if (action==1 && (!inspected || refill_attempted || bypass_attempted)) return -EPERM;
 if (action==3 && (!refill_attempted || bypass_attempted || !bypass_ready)) return -EPERM;
 if (!action && attempted) return -EPERM;
 if (action==2 && (!attempted || !physical_pending || physical_terminal)) return -EPERM;
 error=register_kprobe(&finder); if (error) return error;
 find_named=(void *)finder.addr; unregister_kprobe(&finder);
 rcu_read_lock(); module=find_named("qdx_ppe_diag");
 if (module && !try_module_get(module)) module=NULL;
 rcu_read_unlock(); if (!module) return -ENOENT;
 text=recovery_section(module,".text"); data=recovery_section(module,".data");
 bss=recovery_section(module,".bss"); note=recovery_section(module,".note.gnu.build-id");
 if (module->state!=MODULE_STATE_LIVE || !text || !data || !bss || !note ||
     recovery_section(module,".gnu.linkonce.this_module")!=(unsigned long)module ||
     !within_module_mem_type(text+0x11007,module,MOD_TEXT) ||
     !within_module_mem_type(data+0x2ef,module,MOD_DATA) ||
     !within_module_mem_type(bss+0xa947,module,MOD_DATA) ||
     !within_module(note,module) || !within_module(note+35,module) ||
     get_unaligned_le32((void *)note)!=4 || get_unaligned_le32((void *)(note+4))!=20 ||
     get_unaligned_le32((void *)(note+8))!=3 || memcmp((void *)(note+12),"GNU",4) ||
     memcmp((void *)(note+16),expected_build_id,20)) { error=-ESTALE; goto put_module; }
 error=register_kprobe(&opener); if (error) goto put_module;
 open=(void *)opener.addr; unregister_kprobe(&opener);
 if ((unsigned long)open!=text+REC_open_window_on) { error=-ESTALE; goto put_module; }
 close=(void *)(text+REC_close_window); maps=(void *)(text+REC_check_maps);
 mac=(void *)(text+REC_prefix_mac_check); chain=(void *)(text+REC_retaining_chain);
 finish=(void *)(text+REC_retaining_recall_finish); observe=(void *)(text+REC_prefix_observe);
 write_row=(void *)(text+REC_wr_row); write=(void *)(text+REC_wr);
 saved_map=SLOT(u32,l0_map); saved_port=SLOT(u32,l0_port);
 owner=SLOT(struct retained_owner,retaining); lock=SLOT(struct mutex,diag_lock);
 ppe=*SLOT(void __iomem *,ppe); edma=*SLOT(void __iomem *,edma);
 mutex_lock(lock);
 if (action==2) {
  /* Root supplies this command only after exact suffix wire bytes/order.
   * Empty hardware storage alone never permits this path. No CPU receipt
   * or recalled flag is fabricated; only actual transport completion is set. */
  if (!ppe || !edma || !row_restored || !FLAG(reserved) || FLAG(fault) || FLAG(window_open) || FLAG(drain_active) ||
      WORD(port)!=3 || WORD(queue)!=176 || WORD(l1)!=44 || MMIO(0x41cb04)!=0xfffc0000 ||
      !owner->active || !owner->hook || !owner->sealed || !owner->recall_issued || owner->recalled ||
      owner->run_id!=22101800 || !owner->prefix_mode || owner->prefix_selected!=1 ||
      owner->returned || owner->bad || owner->native_sent || owner->reinsert_issued ||
      owner->prefix_terminal || owner->prefix_rerouted || owner->initial_count!=3 ||
      owner->input_u!=3 || owner->arrival_count || owner->input_a || owner->error!=-ETIMEDOUT ||
      !skb_queue_empty(&owner->quarantine)) { error=-EPERM; goto unlock; }
  for (i=0;i<10;i++) if (owner->item[i].skb || owner->item[i].received ||
      owner->item[i].tx_consumed) { error=-EBUSY; goto unlock; }
  error=close(); if (!error) error=mac();
  if (!error) error=chain(0,0,false);
  if (!error) error=maps();
  if (error) goto unlock;
  synchronize_net();
  if (owner->returned || owner->bad || !skb_queue_empty(&owner->quarantine) ||
      MMIO(0x24000+16*176)-owner->original_tx[0]!=3 || MMIO(0x14f0)!=3 ||
      (MMIO(0x84eb00)&0xfff)) { error=-EBADMSG; goto unlock; }
  for (i=0;i<18;i++) if (MMIO(0x9e0000+96*176+(i/3)*16+(i%3)*4)!=owner->drop[i/3][i%3]) {
   error=-EBADMSG; goto unlock;
  }
  /* Restore the exact touched journal, including partial successful writes.
   * Only the original finish function's CPU-return prerequisite is replaced
   * by the independent actual physical terminal witness above. */
  if (owner->map_touched) {
   error=write(0x402b00,saved_map[176]); if (error) goto unlock;
   owner->map_expected=saved_map[176];
   error=write(0x408b00,saved_port[176]); if (error) goto unlock;
   owner->port_expected=saved_port[176];
  }
  if (owner->c_touched) {
   if (MMIO(0x404070)!=owner->c_expected) { error=-ESTALE; goto unlock; }
   error=write(0x404070,owner->c_saved); if (error) goto unlock;
   owner->c_expected=owner->c_saved;
  }
  if (owner->e_touched) {
   if (MMIO(0x406070)!=owner->e_expected) { error=-ESTALE; goto unlock; }
   error=write(0x406070,owner->e_saved); if (error) goto unlock;
   owner->e_expected=owner->e_saved;
  }
  if (owner->route_touched) {
   value=readl(edma+0x5a058);
   if ((value&15)!=(owner->route_expected&15)) { error=-ESTALE; goto unlock; }
   value=(value&~15U)|(owner->route_saved&15);
   writel(value,edma+0x5a058);
   if (readl(edma+0x5a058)!=value) { error=-EIO; goto unlock; }
   owner->route_expected=value;
  }
  owner->map_restored=true;
  owner->complete=true;
  returned=owner->returned; bad=owner->bad;
  owner_stage=owner->stage; owner_recalled=owner->recalled; maps_restored=owner->map_restored;
  physical_terminal=true; finished=true; stage=6;
  error=0; goto unlock;
 }
 if (!ppe || !edma || !FLAG(allow_writes) || !FLAG(reserved) || FLAG(fault) ||
     FLAG(window_open) || FLAG(drain_active) || WORD(port)!=3 || WORD(queue)!=176 || WORD(l1)!=44 ||
     !owner->active || !owner->hook || !owner->sealed || !owner->recall_issued || owner->recalled ||
     !owner->map_touched || !owner->c_touched || !owner->e_touched || !owner->route_touched ||
     owner->map_restored || owner->cpu_selected || owner->reinsert_issued || owner->complete ||
     !owner->prefix_mode || !owner->prefix_opened || !owner->prefix_cut || owner->prefix_terminal ||
     owner->prefix_rerouted || owner->prefix_direct || owner->prefix_draining ||
     !owner->gmac_touched || owner->gmac_restored || owner->initial_count!=3 || owner->arrival_count ||
     owner->recall_first!=1 || owner->prefix_selected!=1 || owner->input_u!=3 || owner->input_a ||
     owner->returned || owner->native_sent || owner->queued || owner->bad || owner->stage!=3 ||
     owner->run_id!=22101800 || owner->error!=-ETIMEDOUT ||
     owner->source_if!=4 || owner->source_ip!=0xc0a80173 || owner->target_ip!=0xc0a80190 ||
     owner->source_port!=41000 || owner->target_port!=41001 ||
     !skb_queue_empty(&owner->quarantine)) { error=-EPERM; goto unlock; }
 for (i=0;i<10;i++) if (owner->item[i].skb || owner->item[i].received ||
     owner->item[i].tx_consumed || owner->item[i].queue_arrived) { error=-EBUSY; goto unlock; }
 for (i=0;i<3;i++) if (!owner->item[i].observed ||
     owner->item[i].length!=(i==1 ? 1514 : 122)) { error=-EBADMSG; goto unlock; }
 ids[0]=owner->item[1].before_id; ids[1]=owner->item[2].before_id;
 error=maps(); if (!error) error=mac();
 if (!error) error=chain(1,2,false);
 if (error) goto unlock;
 if (owner->item[1].rebuilt_id!=ids[0] || owner->item[2].rebuilt_id!=ids[1]) { error=-ESTALE; goto unlock; }
 map=MMIO(0x402b00); destination=MMIO(0x408b00);
 port_credit=MMIO(0x472030); port_sign=MMIO(0x470030);
 before_tx=MMIO(0x24000+16*176); mac_before=MMIO(0x14f0);
 for (i=0;i<2;i++) before_credit[i]=MMIO(0x41ab00+4*i);
 for (i=0;i<3;i++) before_comp[i]=MMIO(0x426b00+4*i);
 if (map!=owner->map_expected || map!=0x00401fc0 || destination!=owner->port_expected || destination ||
     MMIO(0x404070)!=owner->c_expected || MMIO(0x406070)!=owner->e_expected ||
     (readl(edma+0x5a058)&15)!=(owner->route_expected&15) ||
     (owner->route_expected&15)!=15 || !(readl(edma+0x48018)&1) ||
     (MMIO(0x440000)&15) || (MMIO(0x446000)&15) ||
     MMIO(0x41cb00)!=0xfffc0000 || MMIO(0x41cb04)!=0xfffc0000 || MMIO(0x41cb08)!=0x30 ||
     MMIO(0x474030)!=0xfffc0000 || MMIO(0x474034)!=0x18 || port_credit!=0x003fffff || port_sign ||
     before_credit[0]!=expected_credit[0] || before_credit[1]!=expected_credit[1] ||
     before_comp[0]!=expected_comp[0] || before_comp[1]!=expected_comp[1] || before_comp[2]!=expected_comp[2] ||
     before_tx-owner->original_tx[0]!=1 || mac_before!=1 || !(MMIO(0x430b00)&1)) {
  error=-ESTALE; goto unlock;
 }
 for (i=0;i<3;i++) if (MMIO(0x45e000+4*i)!=owner->cpu_parent_cfg[i]) { error=-ESTALE; goto unlock; }
 for (i=0;i<2;i++) if (MMIO(0x474000+4*i)!=owner->cpu_port_cfg[i]) { error=-ESTALE; goto unlock; }
 if ((owner->cpu_parent_cfg[2]&0x30) || (owner->cpu_port_cfg[1]&0x10)) { error=-EXDEV; goto unlock; }
 for (i=0;i<3;i++) eligibility_before[i]=MMIO(status_offset[i]);
 old_error=owner->error; old_last=*SLOT(int,last_result);
 inspected=true; stage=1;
 if (!action) { error=0; goto unlock; }
 /* Separate cause controls, never a scan or retry: first the original
  * CIR1/EIR2 configuration. Only a qualified zero-progress result permits
  * the disabled-row control, carrying the first attempt's actual account.
  * Neither operation supplies PORT allowance or writes credit/compensation. */
 attempted=true; action_done=action; stage=2; bypass_ready=false;
 if (action==1) refill_attempted=true; else bypass_attempted=true;
 run_config=action==1 ? refill_config : bypass_config;
 row_write_issued=row_write_done=row_restore_issued=row_restored=false;
 row_write_result=row_restore_result=0; open_result=-ECANCELED; finish_result=0;
 row_write_issued=true; row_begin_ns=ktime_get_ns();
 row_write_result=write_row(0x41cb00,run_config,3);
 row_enabled_ns=ktime_get_ns();
 for (i=0;i<3;i++) enabled_config[i]=MMIO(0x41cb00+4*i);
 row_write_done=!row_write_result; error=row_write_result;
 if (!error) { open_result=open(176,100000,false); error=open_result; }
 if (!error) {
  timeout=jiffies+msecs_to_jiffies(3000);
  while (READ_ONCE(owner->returned)!=2 && !READ_ONCE(owner->bad) &&
         MMIO(0x14f0)<3 && time_before(jiffies,timeout))
   usleep_range(100,200);
 }
 /* The timer and this close hold selection on every exit. Join actual RX
  * before recording whether the suffix transferred. Never freeze before
  * the successful transfer witness; a timeout remains an owned failure. */
 close_error=close(); if (!error) error=close_error;
 synchronize_net();
 transfer_returned=READ_ONCE(owner->returned); transfer_mac=MMIO(0x14f0);
 for (i=0;i<3;i++) eligibility_running[i]=MMIO(status_offset[i]);
 /* Configuration-only stop: preserve all accrued C/E/compensation. Even
  * failed enable readback may have written hardware, so stop is attempted
  * once, with its own result retained separately from the first error. */
 row_restore_issued=true; row_stop_ns=ktime_get_ns();
 row_restore_result=write_row(0x41cb00,frozen_config,3);
 row_stopped_ns=ktime_get_ns();
 for (i=0;i<3;i++) stopped_config[i]=MMIO(0x41cb00+4*i);
 row_restored=!row_restore_result;
 if (!error) error=row_restore_result;
 if (!error && transfer_returned==2 && !READ_ONCE(owner->bad)) {
  finish_result=finish(); error=finish_result;
  if (!error) error=observe(3);
 } else if (!error && !transfer_returned && !READ_ONCE(owner->bad) &&
            MMIO(0x24000+16*176)-owner->original_tx[0]==3 && transfer_mac==3) {
  error=chain(0,0,false);
  if (!error) physical_pending=true;
 } else if (!error) error=owner->bad ? -EBADMSG : -ETIMEDOUT;
 returned=READ_ONCE(owner->returned); bad=READ_ONCE(owner->bad);
 owner_stage=owner->stage; owner_recalled=owner->recalled; maps_restored=owner->map_restored;
 after_tx=MMIO(0x24000+16*176); mac_after=MMIO(0x14f0);
 for (i=0;i<2;i++) after_credit[i]=MMIO(0x41ab00+4*i);
 for (i=0;i<3;i++) after_comp[i]=MMIO(0x426b00+4*i);
 for (i=0;i<3;i++) eligibility_after[i]=MMIO(status_offset[i]);
 /* Permit the second explicit command only after the first ordinary
  * no-progress result, not after partial ownership, loss or a write failure.
  * A later command rechecks the same original identities and this exact
  * captured account; it never substitutes a guessed post-refill value. */
 if (action==1 && error==-ETIMEDOUT && !open_result && row_write_done && row_restored &&
     !returned && !bad && after_tx==before_tx && mac_after==mac_before &&
     !FLAG(window_open) && !FLAG(fault) && !owner->map_restored &&
     MMIO(0x472030)==0x003fffff && !MMIO(0x470030) &&
     !chain(1,2,false) && owner->item[1].rebuilt_id==ids[0] && owner->item[2].rebuilt_id==ids[1]) {
  bool unchanged_drop=true;
  for (i=0;i<18;i++) if (MMIO(0x9e0000+96*176+(i/3)*16+(i%3)*4)!=owner->drop[i/3][i%3])
   unchanged_drop=false;
  if (unchanged_drop) {
   memcpy(expected_credit,after_credit,sizeof(expected_credit));
   memcpy(expected_comp,after_comp,sizeof(expected_comp));
   bypass_ready=true;
  }
 }
 if (owner->error!=(int)old_error || *SLOT(int,last_result)!=(int)old_last) {
  if (!error) error=-EUCLEAN;
  bypass_ready=false;
 }
 finished=!error && !physical_pending; stage=physical_pending ? 5 : finished ? 3 : 4;
unlock:
 mutex_unlock(lock);
put_module:
 module_put(module); return error;
}
static int recovery_show(struct seq_file *seq,void *unused)
{
 mutex_lock(&recovery_lock);
 seq_printf(seq,"stage=%u result=%d inspected=%u attempted=%u finished=%u wire_count=%u open_result=%d finish_result=%d physical_pending=%u physical_terminal=%u original_test_passed=0\n",
  stage,result,inspected,attempted,finished,wire_count,open_result,finish_result,physical_pending,physical_terminal);
 seq_printf(seq,"controls action=%u refill_attempted=%u bypass_attempted=%u bypass_ready=%u expected_credit=%08x,%08x expected_comp=%08x,%08x,%08x eligibility_before=%08x,%08x,%08x eligibility_running=%08x,%08x,%08x eligibility_after=%08x,%08x,%08x\n",
  action_done,refill_attempted,bypass_attempted,bypass_ready,expected_credit[0],expected_credit[1],expected_comp[0],expected_comp[1],expected_comp[2],
  eligibility_before[0],eligibility_before[1],eligibility_before[2],eligibility_running[0],eligibility_running[1],eligibility_running[2],eligibility_after[0],eligibility_after[1],eligibility_after[2]);
 seq_printf(seq,"config issued=%u written=%u write_result=%d restore_issued=%u restored=%u restore_result=%d begin_ns=%llu enabled_ns=%llu stop_ns=%llu stopped_ns=%llu enabled_config=%08x,%08x,%08x stopped_config=%08x,%08x,%08x transfer_returned=%u transfer_mac=%u\n",
  row_write_issued,row_write_done,row_write_result,row_restore_issued,row_restored,row_restore_result,
  row_begin_ns,row_enabled_ns,row_stop_ns,row_stopped_ns,
  enabled_config[0],enabled_config[1],enabled_config[2],stopped_config[0],stopped_config[1],stopped_config[2],transfer_returned,transfer_mac);
 seq_printf(seq,"returned=%u bad=%u owner_stage=%u owner_recalled=%u maps_restored=%u original_error=%d original_last=%d\n",
  returned,bad,owner_stage,owner_recalled,maps_restored,(int)old_error,(int)old_last);
 seq_printf(seq,"map=%08x destination=%08x port_credit=%08x port_sign=%08x tx=%u,%u mac=%u,%u credit_before=%08x,%08x credit_after=%08x,%08x comp_before=%08x,%08x,%08x comp_after=%08x,%08x,%08x\n",
  map,destination,port_credit,port_sign,before_tx,after_tx,mac_before,mac_after,
  before_credit[0],before_credit[1],after_credit[0],after_credit[1],
  before_comp[0],before_comp[1],before_comp[2],after_comp[0],after_comp[1],after_comp[2]);
 mutex_unlock(&recovery_lock); return 0;
}
DEFINE_SHOW_ATTRIBUTE(recovery);
static ssize_t recovery_write(struct file *file,const char __user *user,size_t count,loff_t *offset)
{
 char command[24]; unsigned int action; int error;
 if (!allow_writes || !capable(CAP_SYS_RAWIO) || !count || count>=sizeof(command)) return -EPERM;
 if (copy_from_user(command,user,count)) return -EFAULT;
 command[count]=0; strim(command);
 if (!strcmp(command,"inspect")) action=0;
 else if (!strcmp(command,"refill")) action=1;
 else if (!strcmp(command,"physical-terminal")) action=2;
 else if (!strcmp(command,"bypass")) action=3;
 else return -EINVAL;
 mutex_lock(&recovery_lock); error=recovery_run(action); result=error;
 mutex_unlock(&recovery_lock); return error ? error : count;
}
static const struct file_operations recovery_ops={.owner=THIS_MODULE,.write=recovery_write};
static int __init recovery_init(void)
{
 if (!allow_writes || wire_count!=1) return -EPERM;
 directory=debugfs_create_dir("qdx_ppe_recall_continuation",NULL);
 if (IS_ERR(directory)) return PTR_ERR(directory);
 debugfs_create_file("status",0400,directory,NULL,&recovery_fops);
 debugfs_create_file("control",0200,directory,NULL,&recovery_ops);
 return 0;
}
static void __exit recovery_exit(void) { debugfs_remove_recursive(directory); }
module_init(recovery_init); module_exit(recovery_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Exact1070 C-refill and disabled-row controls, no extra allowance or policy claim");
