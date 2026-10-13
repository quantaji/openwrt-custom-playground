// SPDX-License-Identifier: GPL-2.0-only
/* Exact failed d0bfc95 physical WRR owner: unchanged-policy service and closure. */
#include <linux/build_bug.h>
#include <linux/completion.h>
#include <linux/debugfs.h>
#include <linux/dma-mapping.h>
#include <linux/dsa/oob.h>
#include <linux/etherdevice.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/qdx.h>
#include <linux/qdx_diag_fq.h>
#include <linux/rcupdate.h>
#include <linux/rtnetlink.h>
#include <linux/seq_file.h>
#include <linux/skbuff.h>
#include <linux/sysfs.h>
#include <linux/uaccess.h>
#include <linux/unaligned.h>
#include <net/pkt_sched.h>
#include "qdx_physical_wrr_recovery_offsets.h"
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
 bool loaned, control;
 u8 expected[1514];
};
struct recovery_snapshot {
 struct qdx_diag_fq_view view;
 u32 root_address, group_address[3], active_tags[3], active_count;
 s32 deficit[2];
 u32 quantum[2];
};
static_assert(sizeof(struct module) == 1216);
static_assert(sizeof(struct mutex) == 32);
static_assert(sizeof(struct recovery_node) == 72);
static_assert(sizeof(struct recovery_packet) == 1536);
static_assert(sizeof(struct recovery_snapshot) == 4464);
static_assert(offsetof(struct recovery_snapshot,root_address) == 4416);
extern bool qdx_diag_fq_table_idle(struct qdx_dma *);
enum { OUTER, ROOT, ANCHOR, GROUP_A, GROUP_B, FIFO_A, FIFO_B, PROBE, FQ, MARKER, NODES };
static const u32 tags[NODES] = { 0x6f000000,0x6f010000,0x6f020000,0x6f030000,
 0x6f040000,0x6f050000,0x6f060000,0x6f070000,0x6d010000,0x6f080000 };
static const u32 kinds[NODES] = {3,9,10,10,10,4,4,4,1,4};
static const u32 lengths[16] = {128,192,256,128,128,1514,128,192,192,128,256,128,512,128,192,128};
/* Independently calculated from the actual saved -1,+1 credits, quanta2,3,
 * order A/B and two queues of eight. This is not the fresh-state order. */
static const u32 service_order[16] = {8,9,0,1,10,11,12,2,3,13,14,15,4,5,6,7};
static const u8 expected_build_id[20] = {
 0xa3,0x30,0x7f,0x5e,0x45,0x04,0x96,0xd6,0x7d,0xcb,
 0xba,0xe5,0x82,0x61,0x07,0x3a,0x6b,0x5a,0xef,0xcc,
};
static bool allow_writes, inspected, service_started, serviced, released, self_pinned;
module_param(allow_writes,bool,0400);
static u32 stage, wire_count, received_count, receive_bad, warm_verified;
static int result, wire_error;
static bool receive_hook;
static u32 table_address, old_derived, actual_derived, anchor_child;
static u8 initial_table[144], initial_node[280];
static s32 initial_deficit[2];
static u32 initial_quantum[2];
static u64 selected_after[2], dropped_after[2];
static struct sk_buff *received[16];
static struct sk_buff_head quarantine;
static DECLARE_COMPLETION(receive_done);
static DEFINE_SPINLOCK(receive_lock);
static DEFINE_MUTEX(recovery_lock);
static struct dentry *directory;

/* All original source frames are identifiable independently of the failing
 * caller's uninitialised packets[] array. Full byte equality is checked by
 * root against the original source PCAP after actual wire transmission. */
static bool recovery_header(const u8 *header)
{
 return get_unaligned_be16(header+12)==ETH_P_IP && header[14]==0x45 &&
  header[23]==IPPROTO_UDP && get_unaligned_be32(header+26)==0xc0a80190 &&
  get_unaligned_be32(header+30)==0xc0a80173 && get_unaligned_be16(header+34)==41000 &&
  get_unaligned_be16(header+36)==41001 && !memcmp(header+42,"QDXPROB1",8) &&
  get_unaligned_be64(header+50)==22101200;
}
static rx_handler_result_t recovery_receive(struct sk_buff **pskb)
{
 struct sk_buff *skb=*pskb;
 const struct dsa_oob_tag_info *tag;
 u8 header[67];
 unsigned long flags;
 u32 id;
 int offset;
 bool bad;
 if (!skb_mac_header_was_set(skb)) return RX_HANDLER_PASS;
 offset=skb_mac_offset(skb);
 if (offset!=-ETH_HLEN || skb_headroom(skb)<ETH_HLEN ||
     skb->len+ETH_HLEN<sizeof(header) || skb_copy_bits(skb,offset,header,sizeof(header)) ||
     !recovery_header(header)) return RX_HANDLER_PASS;
 tag=skb_ext_find(skb,SKB_EXT_DSA_OOB);
 bad=!tag || tag->port!=0 || skb_vlan_tag_present(skb);
 skb_push(skb,ETH_HLEN); skb_reset_mac_header(skb);
 if (tag) skb_ext_del(skb,SKB_EXT_DSA_OOB);
 id=get_unaligned_be32(header+63);
 spin_lock_irqsave(&receive_lock,flags);
 bad=bad || header[58]!=1 || get_unaligned_be32(header+59)!=1 ||
  id>=16 || received_count>=16;
 if (!bad) bad=id!=service_order[received_count] || skb->len+VLAN_HLEN!=lengths[id];
 if (bad) receive_bad++;
 else {
  received[received_count++]=skb;
  if (received_count==16) complete_all(&receive_done);
 }
 spin_unlock_irqrestore(&receive_lock,flags);
 if (bad) skb_queue_tail(&quarantine,skb);
 return RX_HANDLER_CONSUMED;
}
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
#define PTR(type,name) (*SLOT(type *,name))

/* Read only the completed owned copies. No new read command, firmware write,
 * or scheduler action is necessary to identify the failed address assumption. */
static int recovery_snapshot_check(struct recovery_snapshot *snapshot,struct qdx_dma *table)
{
 struct qdx_diag_fq_view *view=&snapshot->view;
 u32 i,j,entry,candidate,head,offset,previous,found,mask=0,tag;
 const u8 *group;
 if (!view->node_valid || view->wrr_valid!=15 || !view->wrr ||
     !qdx_diag_fq_table_idle(table)) return -EBADMSG;
 dma_rmb();
 if (memcmp(view->table,qdx_dma_cpu(table),144)) return -EBADMSG;
 table_address=(u32)qdx_dma_address(table);
 memcpy(initial_table,view->table,144); memcpy(initial_node,view->node,280);
 old_derived=get_unaligned_le32(view->table+4)-228;
 anchor_child=get_unaligned_le32(view->wrr_group[0]+188);
 actual_derived=0;
 for (i=0;i<2;i++) {
  if (get_unaligned_le32(view->table+i*72+24)!=1 ||
      get_unaligned_le32(view->table+i*72+64)!=128) return -EBADMSG;
  entry=get_unaligned_le32(view->table+i*72+4);
  if (entry==table_address || entry==table_address+72) continue;
  offset=view->table[i*72+68] ? 228 : 236;
  candidate=entry-offset;
  if (candidate<0x4027b62c || candidate>=0x4027b62c+256*280 ||
      (candidate-0x4027b62c)%280 || (actual_derived && actual_derived!=candidate))
   return -EBADMSG;
  actual_derived=candidate;
 }
 if (!actual_derived || actual_derived!=anchor_child || old_derived==actual_derived ||
     snapshot->root_address!=get_unaligned_le32(view->wrr_group[0]+4) ||
     get_unaligned_le32(view->wrr_root+184)!=0x400a7060) return -EBADMSG;
 for (i=0;i<3;i++) {
  group=view->wrr_group[i];
  tag=get_unaligned_le32(group+16);
  if (tag!=tags[ANCHOR+i] || get_unaligned_le32(group+8)!=10 || !group[24] ||
      get_unaligned_le32(group+4)!=snapshot->root_address ||
      get_unaligned_le32(group+20)!=get_unaligned_le32(view->node+20) ||
      get_unaligned_le32(group+36)!=get_unaligned_le32(view->node+36) ||
      get_unaligned_le32(group+48)!=0x400a7c80 ||
      get_unaligned_le32(group+60)!=0x400a7a80 ||
      get_unaligned_le32(group+68)!=0x400a7b80 ||
      get_unaligned_le32(group+72)!=0x400a7a40) return -EBADMSG;
  for (j=0;j<i;j++) if (snapshot->group_address[j]==snapshot->group_address[i]) return -EBADMSG;
  if (i) {
   initial_deficit[i-1]=(s32)get_unaligned_le32(group+176);
   initial_quantum[i-1]=get_unaligned_le32(group+172);
  }
 }
 if (initial_deficit[0]!=-1 || initial_deficit[1]!=1 ||
     initial_quantum[0]!=2 || initial_quantum[1]!=3) return -EBADMSG;
 /* Both structural and active links must be bidirectional and owned. */
 for (j=0;j<2;j++) {
  offset=j ? 164 : 180;
  head=snapshot->root_address+(j ? 164 : 172); previous=head;
  entry=get_unaligned_le32(view->wrr_root+(j ? 164 : 172)); mask=0;
  for (i=0;i<3;i++) {
   for (found=0;found<3;found++)
    if (entry==snapshot->group_address[found]+offset) break;
   if (found==3 || (mask&BIT(found))) return -EBADMSG;
   if (j && found!=(i+1)%3) return -EBADMSG;
   mask|=BIT(found); group=view->wrr_group[found];
   if (get_unaligned_le32(group+offset+4)!=previous || (j && !group[192])) return -EBADMSG;
   previous=entry; entry=get_unaligned_le32(group+offset);
  }
  if (entry!=head || get_unaligned_le32(view->wrr_root+(j ? 168 : 176))!=previous)
   return -EBADMSG;
 }
 return get_unaligned_le32(view->wrr_root+180)==3 ? 0 : -EBADMSG;
}

/* Explicit actions: inspect, service, wire, close. The source is sealed by
 * root; PPE capture stays installed through service. Root restores actual
 * egress before wire and verifies all23 source originals before close. */
static int recovery_run(unsigned int action)
{
 struct kprobe finder={.symbol_name="find_module"};
 struct kprobe commander={.symbol_name="qdx_physical_wrr_diag:wrr_tc"};
 struct module *(*find_named)(const char *);
 struct module *module;
 struct mutex *lock;
 struct recovery_node *nodes;
 struct recovery_packet *packets,*anchors,*marker,*private;
 struct recovery_snapshot *snapshot;
 struct sk_buff **warm,*skb;
 int (*tc)(u32,u32,u32,u32),(*gauge)(u32,u32),(*join)(u32);
 int (*command)(bool,u32,const void *,size_t),(*wait_command)(void);
 unsigned long text,data,bss,note;
 __le32 unassign;
 u8 header[67];
 unsigned int i,id;
 int error;
 if (released) return action==3 ? 0 : -EALREADY;
 error=register_kprobe(&finder); if (error) return error;
 find_named=(void *)finder.addr; unregister_kprobe(&finder);
 rcu_read_lock(); module=find_named("qdx_physical_wrr_diag");
 if (module && !try_module_get(module)) module=NULL;
 rcu_read_unlock(); if (!module) return -ENOENT;
 text=recovery_section(module,".text"); data=recovery_section(module,".data");
 bss=recovery_section(module,".bss"); note=recovery_section(module,".note.gnu.build-id");
 if (module->state!=MODULE_STATE_LIVE || !text || !data || !bss || !note ||
     recovery_section(module,".gnu.linkonce.this_module")!=(unsigned long)module ||
     !within_module_mem_type(text+0x4583,module,MOD_TEXT) ||
     !within_module_mem_type(data+0x3a7,module,MOD_DATA) ||
     !within_module_mem_type(bss+0xc4ff,module,MOD_DATA) ||
     !within_module(note,module) || !within_module(note+35,module) ||
     get_unaligned_le32((void *)note)!=4 || get_unaligned_le32((void *)(note+4))!=20 ||
     get_unaligned_le32((void *)(note+8))!=3 || memcmp((void *)(note+12),"GNU",4) ||
     memcmp((void *)(note+16),expected_build_id,20)) { error=-ESTALE; goto put_module; }
 error=register_kprobe(&commander); if (error) goto put_module;
 tc=(void *)commander.addr; unregister_kprobe(&commander);
 if ((unsigned long)tc!=text+REC_wrr_tc) { error=-ESTALE; goto put_module; }
 gauge=(void *)(text+REC_wrr_gauge); join=(void *)(text+REC_wrr_join);
 command=(void *)(text+REC_wrr_command); wait_command=(void *)(text+REC_wrr_wait_command);
 lock=SLOT(struct mutex,control_lock); nodes=SLOT(struct recovery_node,nodes);
 packets=SLOT(struct recovery_packet,packets); anchors=SLOT(struct recovery_packet,anchor_packets);
 marker=SLOT(struct recovery_packet,marker_packet); private=SLOT(struct recovery_packet,private_packet);
 snapshot=SLOT(struct recovery_snapshot,snapshots); warm=SLOT(struct sk_buff *,warm_prefix);
 mutex_lock(lock);
 /* Only invariants unchanged by our normal closure belong in this common
  * guard. Resource flags and pointers below may truthfully change mid-close. */
 if (!FLAG(pinned) || !FLAG(prepared) || !FLAG(loaded) || FLAG(exported) || FLAG(recalled) ||
     FLAG(cpu_selected) || FLAG(rebuilt) || FLAG(passed) || FLAG(fault) || WORD(byte_mode) ||
     WORD(admission_stage)!=4 || WORD(phase)!=1 || *SLOT(u64,run_id)!=22101200 ||
     WORD(physical_ifnum)!=4 || WORD(mirror_ifnum)!=28 || WORD(shaper)!=10 ||
     WORD(source_default)!=FIFO_B || WORD(warm_count)!=7 || WORD(bad_packets) ||
     WORD(unexpected_clones) || WORD(private_count) || WORD(selected_mask) || WORD(resume_count) ||
     WORD(native_sent) || FLAG(wire_complete) || WORD(markers)!=2 || WORD(marker_wait)!=2 ||
     marker->loaned || private->loaned || private->skb ||
     PTR(struct qdx_packet_op,copy_operation) || !skb_queue_empty(SLOT(struct sk_buff_head,quarantine)) ||
     *SLOT(int,last_error)!=-EBADMSG) { error=-EPERM; goto unlock; }
 for (i=0;i<NODES;i++) if (nodes[i].tag!=tags[i] || nodes[i].kind!=kinds[i]) { error=-ESTALE; goto unlock; }
 for (i=0;i<16;i++) if (packets[i].skb || packets[i].loaned) { error=-EBUSY; goto unlock; }
 if (PTR(struct qdx_request,request)) { error=wait_command(); if (error) goto unlock; }
 if (!self_pinned) {
  if (action || FLAG(closed) || !FLAG(assigned) || !FLAG(enabled) || !FLAG(next_set) ||
      !FLAG(hook) || !PTR(struct qdx_dma,table) || !qdx_diag_fq_table_idle(PTR(struct qdx_dma,table)) ||
      nodes[ROOT].parent!=-1 || nodes[ANCHOR].parent!=ROOT || nodes[FQ].parent!=ANCHOR ||
      nodes[GROUP_A].parent!=ROOT || nodes[GROUP_B].parent!=ROOT ||
      nodes[FIFO_A].parent!=GROUP_A || nodes[FIFO_B].parent!=GROUP_B ||
      nodes[MARKER].parent!=OUTER || nodes[MARKER].band!=2 || WORD(controls_retired)) {
   error=-EPERM; goto unlock;
  }
  for (i=0;i<NODES;i++) if (!nodes[i].allocated || (i!=FQ && nodes[i].path)) { error=-ESTALE; goto unlock; }
  if (!nodes[FQ].path || !nodes[FQ].path_closed || !anchors[0].loaned || !anchors[1].loaned ||
      anchors[0].skb || anchors[1].skb) { error=-ESTALE; goto unlock; }
  error=gauge(FIFO_A,8); if (!error) error=gauge(FIFO_B,8); if (error) goto unlock;
  if (nodes[FIFO_A].bytes!=2666 || nodes[FIFO_B].bytes!=1664 ||
      nodes[FIFO_A].admitted!=13 || nodes[FIFO_A].selected!=5 || nodes[FIFO_A].dropped ||
      nodes[FIFO_B].admitted!=10 || nodes[FIFO_B].selected!=2 || nodes[FIFO_B].dropped) {
   error=-EBADMSG; goto unlock;
  }
  if (!try_module_get(THIS_MODULE)) { error=-ENODEV; goto unlock; }
  self_pinned=true; stage=1;
 }
 if (!action) {
  if (service_started) { error=-EPERM; goto unlock; }
  if (!inspected) {
   error=recovery_snapshot_check(snapshot,PTR(struct qdx_dma,table)); if (error) goto unlock;
   for (i=0;i<7;i++) {
    skb=warm[i];
    if (!skb || skb->len!=124 || skb_copy_bits(skb,0,header,sizeof(header)) ||
        !recovery_header(header) || header[58]!=1 || get_unaligned_be32(header+59) ||
        get_unaligned_be32(header+63)!=i) { error=-EBADMSG; goto unlock; }
    warm_verified|=BIT(i);
   }
   inspected=true; stage=2;
  }
  error=0; goto unlock;
 }
 if (!inspected || warm_verified!=127) { error=-EPERM; goto unlock; }
 if (action==1) {
  if (serviced) { error=0; goto unlock; }
  if (FLAG(closed)) { error=-EPERM; goto unlock; }
  if (!service_started) {
   if (nodes[ROOT].parent!=-1) { error=-ESTALE; goto unlock; }
   service_started=true; stage=3;
  }
  /* Native detach removes only the private anchor membership. Real groups
   * keep their original deficits, child queues and relative active order. */
  if (nodes[ANCHOR].parent==ROOT) { error=tc(6,ROOT,ANCHOR,0); if (error) goto unlock; }
  else if (nodes[ANCHOR].parent!=-1) { error=-ESTALE; goto unlock; }
  if (FLAG(hook)) { netdev_rx_handler_unregister(PTR(struct net_device,conduit)); FLAG(hook)=false; }
  if (!receive_hook) {
   error=netdev_rx_handler_register(PTR(struct net_device,conduit),recovery_receive,NULL);
   if (error) goto unlock;
   receive_hook=true;
  }
  stage=4;
  if (nodes[ROOT].parent==-1) { error=tc(5,OUTER,ROOT,0); if (error) goto unlock; }
  else if (nodes[ROOT].parent!=OUTER || nodes[ROOT].band) { error=-ESTALE; goto unlock; }
  stage=5;
  error=gauge(FIFO_A,0); if (!error) error=gauge(FIFO_B,0); if (error) goto unlock;
  if (!wait_for_completion_timeout(&receive_done,msecs_to_jiffies(6000))) { error=-ETIMEDOUT; goto unlock; }
  if (receive_bad || received_count!=16 || !skb_queue_empty(&quarantine)) { error=-EBADMSG; goto unlock; }
  for (i=0;i<2;i++) {
   selected_after[i]=nodes[FIFO_A+i].selected; dropped_after[i]=nodes[FIFO_A+i].dropped;
   if (selected_after[i]!=(i ? 10 : 13) || dropped_after[i] ||
       nodes[FIFO_A+i].admitted!=selected_after[i] || nodes[FIFO_A+i].bytes) {
    error=-EBADMSG; goto unlock;
   }
  }
  serviced=true; stage=6; error=0; goto unlock;
 }
 if (!serviced || received_count!=16 || receive_bad || !skb_queue_empty(&quarantine)) { error=-EPERM; goto unlock; }
 if (action==2) {
  /* Root has restored PPE/output before issuing this separate command. */
  if (wire_error) { error=wire_error; goto unlock; }
  if (receive_hook) { netdev_rx_handler_unregister(PTR(struct net_device,conduit)); receive_hook=false; }
  while (wire_count<23) {
   skb=wire_count<7 ? warm[wire_count] : received[wire_count-7];
   id=wire_count<7 ? wire_count : service_order[wire_count-7];
   if (!skb || skb->len!=(wire_count<7 ? 124 : lengths[id]-VLAN_HLEN) ||
       skb_copy_bits(skb,0,header,sizeof(header)) || !recovery_header(header) || header[58]!=1 ||
       get_unaligned_be32(header+59)!=(wire_count<7 ? 0 : 1) || get_unaligned_be32(header+63)!=id) {
    error=-EBADMSG; goto unlock;
   }
   if (wire_count<7) warm[wire_count]=NULL; else received[wire_count-7]=NULL;
   skb->dev=PTR(struct net_device,port); skb->protocol=htons(ETH_P_IP); skb->ip_summed=CHECKSUM_NONE;
   skb_reset_mac_header(skb); skb_set_network_header(skb,ETH_HLEN);
   skb_set_transport_header(skb,ETH_HLEN+20); skb_set_queue_mapping(skb,0);
   error=dev_queue_xmit(skb); wire_count++;
   if (net_xmit_eval(error)) { wire_error=error<0 ? error : -ENOBUFS; error=wire_error; goto unlock; }
  }
  stage=7; error=0; goto unlock;
 }
 if (action!=3 || wire_count!=23 || wire_error || receive_hook) { error=-EPERM; goto unlock; }
 for (i=0;i<7;i++) if (warm[i]) { error=-EBUSY; goto unlock; }
 for (i=0;i<16;i++) if (received[i]) { error=-EBUSY; goto unlock; }
 /* No user skb remains. Only two private diagnostic anchors can be retired.
  * Preserve every completed normal teardown step if a later one fails. */
 for (i=FIFO_A;i<=FIFO_B;i++) {
  if (!nodes[i].allocated) continue;
  error=gauge(i,0); if (error) goto unlock;
 }
 FLAG(closed)=true; stage=8;
 for (i=0;i<NODES;i++) { if (i==FQ) continue; error=join(i); if (error) goto unlock; }
 for (i=NODES;i-->0;) {
  if (nodes[i].parent==-1) continue;
  error=tc(6,nodes[i].parent,i,0); if (error) goto unlock;
 }
 if (nodes[FQ].allocated) { error=tc(1,FQ,0,0); if (error) goto unlock; }
 error=join(FQ); if (error) goto unlock;
 if (anchors[0].loaned || anchors[1].loaned) {
  WORD(controls_retired)=anchors[0].loaned+anchors[1].loaned;
  anchors[0].loaned=anchors[1].loaned=false;
 }
 for (i=NODES;i-->0;) { if (!nodes[i].allocated) continue; error=tc(1,i,0,0); if (error) goto unlock; }
 stage=9;
 if (FLAG(enabled)) { error=command(true,2,NULL,0); if (error) goto unlock; }
 if (FLAG(next_set)) { error=command(true,4,NULL,0); if (error) goto unlock; }
 if (FLAG(assigned)) {
  unassign=cpu_to_le32(WORD(shaper)); error=command(false,8,&unassign,sizeof(unassign)); if (error) goto unlock;
 }
 if (PTR(struct qdx_dma,table) && !qdx_diag_fq_table_idle(PTR(struct qdx_dma,table))) { error=-EBUSY; goto unlock; }
 if (PTR(struct qdx_endpoint,mirror) && !FLAG(mirror_retired)) {
  error=qdx_endpoint_wait(PTR(struct qdx_endpoint,mirror),jiffies);
  if (!error) error=qdx_endpoint_retire(PTR(struct qdx_endpoint,mirror));
  if (error) goto unlock;
  FLAG(mirror_retired)=true;
 }
 if (PTR(struct qdx_receiver,receiver)) {
  error=qdx_endpoint_receive_unregister(PTR(struct qdx_receiver,receiver)); if (error) goto unlock;
  PTR(struct qdx_receiver,receiver)=NULL;
 }
 synchronize_net();
 for (i=0;i<2;i++) { dev_kfree_skb(anchors[i].skb); anchors[i].skb=NULL; }
 dev_kfree_skb(marker->skb); marker->skb=NULL;
 if (PTR(struct qdx_endpoint,mirror)) { qdx_endpoint_put(PTR(struct qdx_endpoint,mirror)); PTR(struct qdx_endpoint,mirror)=NULL; }
 if (PTR(struct qdx_endpoint,physical)) { qdx_endpoint_put(PTR(struct qdx_endpoint,physical)); PTR(struct qdx_endpoint,physical)=NULL; }
 if (PTR(struct qdx_dma,table)) { qdx_dma_release(PTR(struct qdx_dma,table)); PTR(struct qdx_dma,table)=NULL; }
 if (PTR(struct qdx_service,mirror_service)) { qdx_service_put(PTR(struct qdx_service,mirror_service)); PTR(struct qdx_service,mirror_service)=NULL; }
 if (PTR(struct qdx_service,physical_service)) { qdx_service_put(PTR(struct qdx_service,physical_service)); PTR(struct qdx_service,physical_service)=NULL; }
 if (PTR(struct net_device,conduit)) { dev_put(PTR(struct net_device,conduit)); PTR(struct net_device,conduit)=NULL; }
 if (PTR(struct net_device,port)) { dev_put(PTR(struct net_device,port)); PTR(struct net_device,port)=NULL; }
 FLAG(pinned)=false; module_put(module);
 released=true; stage=10; self_pinned=false; module_put(THIS_MODULE); error=0;
 /* The failed owner's loaded/phase/last_error/PASS flags stay unchanged. */
unlock:
 mutex_unlock(lock);
put_module:
 module_put(module); return error;
}
static int recovery_show(struct seq_file *seq,void *unused)
{
 unsigned int i,held=0,width;
 mutex_lock(&recovery_lock);
 for (i=0;i<16;i++) held+=!!READ_ONCE(received[i]);
 seq_printf(seq,"stage=%u result=%d inspected=%u warm_verified=%x service_started=%u serviced=%u released=%u self_pinned=%u original_test_passed=0\n",
  stage,result,inspected,warm_verified,service_started,serviced,released,self_pinned);
 seq_printf(seq,"receive_hook=%u received=%u receive_bad=%u quarantine=%u held_data=%u wire_count=%u wire_error=%d\n",
  receive_hook,READ_ONCE(received_count),READ_ONCE(receive_bad),skb_queue_len(&quarantine),held,wire_count,wire_error);
 seq_printf(seq,"table=%08x old_derived=%08x actual_derived=%08x anchor_child=%08x deficit=%d,%d quantum=%u,%u selected=%llu,%llu dropped=%llu,%llu\n",
  table_address,old_derived,actual_derived,anchor_child,initial_deficit[0],initial_deficit[1],
  initial_quantum[0],initial_quantum[1],selected_after[0],selected_after[1],dropped_after[0],dropped_after[1]);
 for (i=0;i<sizeof(initial_table);i+=width) {
  width=min_t(u32,64,sizeof(initial_table)-i);
  seq_printf(seq,"table_bytes offset=%u data=%*phN\n",i,width,initial_table+i);
 }
 for (i=0;i<sizeof(initial_node);i+=width) {
  width=min_t(u32,64,sizeof(initial_node)-i);
  seq_printf(seq,"node_bytes offset=%u data=%*phN\n",i,width,initial_node+i);
 }
 mutex_unlock(&recovery_lock); return 0;
}
DEFINE_SHOW_ATTRIBUTE(recovery);
static ssize_t recovery_write(struct file *file,const char __user *user,size_t count,loff_t *offset)
{
 char command[24]; unsigned int action; int error;
 if (!allow_writes || !count || count>=sizeof(command)) return -EPERM;
 if (copy_from_user(command,user,count)) return -EFAULT;
 command[count]=0; strim(command);
 if (!strcmp(command,"inspect")) action=0;
 else if (!strcmp(command,"service")) action=1;
 else if (!strcmp(command,"wire")) action=2;
 else if (!strcmp(command,"close")) action=3;
 else return -EINVAL;
 mutex_lock(&recovery_lock); rtnl_lock();
 error=recovery_run(action); result=error;
 rtnl_unlock(); mutex_unlock(&recovery_lock); return error ? error : count;
}
static const struct file_operations recovery_ops={.owner=THIS_MODULE,.write=recovery_write};
static int __init recovery_init(void)
{
 if (!allow_writes) return -EPERM;
 skb_queue_head_init(&quarantine);
 directory=debugfs_create_dir("qdx_physical_wrr_recovery",NULL);
 if (IS_ERR(directory)) return PTR_ERR(directory);
 debugfs_create_file("status",0400,directory,NULL,&recovery_fops);
 debugfs_create_file("control",0200,directory,NULL,&recovery_ops);
 return 0;
}
static void __exit recovery_exit(void)
{
 WARN_ON(self_pinned || receive_hook || !skb_queue_empty(&quarantine));
 debugfs_remove_recursive(directory);
}
module_init(recovery_init); module_exit(recovery_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Exact failed physical WRR original-policy recovery; never handover qualification");
