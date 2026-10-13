// SPDX-License-Identifier: GPL-2.0-only
/* Close the failed physical WRED 31d71217 diagnostic without changing its result. */
#include <linux/debugfs.h>
#include <linux/completion.h>
#include <linux/dsa/oob.h>
#include <linux/etherdevice.h>
#include <net/pkt_sched.h>
#include <linux/kprobes.h>
#include <linux/in.h>
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
#include "qdx_physical_aqm_recovery_offsets.h"
#include "source_frames.h"
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
static bool allow_writes, marker_received, marker_settled, inspected, service_started, serviced, released, self_pinned;
module_param(allow_writes, bool, 0400);
/* Root checks actual PPE tap run22101300 phase255/id1 before this consent. */
module_param(marker_received, bool, 0400);
static u32 stage, verified_mask, initial_average[7], initial_occupancy[7];
static u64 initial_clock, selected_after, dropped_after;
static int result;
static DEFINE_SPINLOCK(receive_lock);
static DECLARE_COMPLETION(receive_done);
static u32 resident_length[3], resident_class[3], resident_carrier[3];
static struct sk_buff *received[3];
static struct sk_buff_head quarantine;
static u32 received_count, receive_bad, wire_count;
static int wire_error;
static bool receive_hook;

static rx_handler_result_t recovery_receive(struct sk_buff **pskb)
{
 struct sk_buff *skb = *pskb;
 const struct dsa_oob_tag_info *tag;
 u8 header[67];
 unsigned long flags;
 u32 id;
 int offset;
 bool bad;
 if (!skb_mac_header_was_set(skb)) return RX_HANDLER_PASS;
 offset=skb_mac_offset(skb);
 if (offset!=-ETH_HLEN || skb_headroom(skb)<ETH_HLEN ||
     skb->len+ETH_HLEN<sizeof(header) || skb_copy_bits(skb,offset,header,sizeof(header)))
  return RX_HANDLER_PASS;
 if (get_unaligned_be16(header+12)!=ETH_P_IP || header[14]!=0x45 ||
     header[23]!=IPPROTO_UDP || get_unaligned_be32(header+26)!=0xc0a80190 ||
     get_unaligned_be32(header+30)!=0xc0a80173 || get_unaligned_be16(header+34)!=41000 ||
     get_unaligned_be16(header+36)!=41001 || memcmp(header+42,"QDXPROB1",8) ||
     get_unaligned_be64(header+50)!=22101300) return RX_HANDLER_PASS;
 tag=skb_ext_find(skb,SKB_EXT_DSA_OOB);
 bad=!tag || tag->port!=0 || skb_vlan_tag_present(skb);
 skb_push(skb,ETH_HLEN); skb_reset_mac_header(skb);
 if (tag) skb_ext_del(skb,SKB_EXT_DSA_OOB);
 id=get_unaligned_be32(header+63);
 spin_lock_irqsave(&receive_lock,flags);
 bad=bad || header[58]!=1 || get_unaligned_be32(header+59)!=1 ||
  id>=3 || id!=received_count || skb->len!=1514;
 if (!bad) bad=memcmp(skb->data,expected_source[id],1514)!=0;
 if (bad) receive_bad++;
 else {
  received[id]=skb; received_count++;
  if (received_count==3) complete_all(&receive_done);
 }
 spin_unlock_irqrestore(&receive_lock,flags);
 if (bad) skb_queue_tail(&quarantine,skb);
 return RX_HANDLER_CONSUMED;
}

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
#define PTR(type, name) (*SLOT(type *, name))

/* inspect copies/verifies; service collects the three actual selections; wire
 * sends those received originals after root restores output; close requires
 * root wire verification. No action marks the original test PASS. */
static int recovery_run(unsigned int action)
{
 struct kprobe finder = { .symbol_name = "find_module" };
 struct kprobe commander = { .symbol_name = "qdx_physical_aqm_diag:aqm_tc" };
 struct module *(*find_named)(const char *);
 struct module *module;
 struct mutex *lock;
 struct recovery_node *nodes;
 struct recovery_packet *packets, *anchors, *marker;
 struct recovery_snapshot *snapshot;
 struct sk_buff *skb;
 int (*tc)(u32,u32,u32,u32), (*gauge)(u32,u32), (*base)(struct recovery_snapshot *);
 int (*copy)(struct qdx_diag_fq_view *, enum qdx_diag_fq_range,u32,u32,void *);
 int (*join)(u32), (*command)(bool,u32,const void *,size_t), (*wait_command)(void);
 unsigned long text, data, bss, note;
 __le32 unassign;
 unsigned int i;
 u32 address, stride;
 int error;
 if (released) return action == 3 ? 0 : -EALREADY;
 error = register_kprobe(&finder);
 if (error) return error;
 find_named = (void *)finder.addr; unregister_kprobe(&finder);
 rcu_read_lock(); module = find_named("qdx_physical_aqm_diag");
 if (module && !try_module_get(module)) module = NULL;
 rcu_read_unlock();
 if (!module) return -ENOENT;
 text = recovery_section(module,".text"); data = recovery_section(module,".data");
 bss = recovery_section(module,".bss"); note = recovery_section(module,".note.gnu.build-id");
 if (module->state != MODULE_STATE_LIVE || !text || !data || !bss || !note ||
     recovery_section(module,".gnu.linkonce.this_module") != (unsigned long)module ||
     !within_module_mem_type(text + 0x4ab7,module,MOD_TEXT) ||
     !within_module_mem_type(data + 0x9f,module,MOD_DATA) ||
     !within_module_mem_type(bss + 0x171df,module,MOD_DATA) ||
     !within_module(note,module) || !within_module(note + 35,module) ||
     get_unaligned_le32((void *)note) != 4 || get_unaligned_le32((void *)(note+4)) != 20 ||
     get_unaligned_le32((void *)(note+8)) != 3 || memcmp((void *)(note+12),"GNU",4) ||
     memcmp((void *)(note+16),expected_build_id,20)) { error=-ESTALE; goto put_module; }
 error = register_kprobe(&commander);
 if (error) goto put_module;
 tc=(void *)commander.addr; unregister_kprobe(&commander);
 if ((unsigned long)tc != text + REC_aqm_tc) { error=-ESTALE; goto put_module; }
 gauge=(void *)(text+REC_aqm_gauge); base=(void *)(text+REC_aqm_base);
 copy=(void *)(text+REC_aqm_copy);
 join=(void *)(text+REC_aqm_join); command=(void *)(text+REC_aqm_command);
 wait_command=(void *)(text+REC_aqm_wait_command);
 lock=SLOT(struct mutex,control_lock); nodes=SLOT(struct recovery_node,nodes);
 packets=SLOT(struct recovery_packet,packets); anchors=SLOT(struct recovery_packet,anchor_packets);
 marker=SLOT(struct recovery_packet,marker_packet); snapshot=SLOT(struct recovery_snapshot,snapshots);
 mutex_lock(lock);
 if (!FLAG(pinned) || !FLAG(prepared) || !FLAG(loaded) || FLAG(exported) || FLAG(adopted) ||
     FLAG(cpu_selected) || FLAG(rebuilt) || FLAG(served) || FLAG(passed) || FLAG(fault) ||
     WORD(algorithm)!=1 || WORD(stage)!=1 || WORD(leaf)!=LEAF_A ||
     *SLOT(u64,run_id)!=22101300 || WORD(queue_count)!=0 || WORD(input_events)!=10 ||
     WORD(physical_ifnum)!=4 || WORD(mirror_ifnum)!=28 || WORD(shaper)!=11 ||
     WORD(bad_packets) || WORD(unexpected_clones) || WORD(backing_retired) ||
     WORD(resumed_count) || WORD(resumed_victims) || WORD(native_sent) || FLAG(wire_complete) ||
     WORD(rebuilt_submitted) || WORD(rebuild_stage) || FLAG(old_backing_retired) ||
     FLAG(leaf_reallocated) || FLAG(temporary_config) || FLAG(serve_prepared) || FLAG(serve_published) ||
     WORD(markers)!=0 || WORD(marker_wait)!=1 || WORD(anchor_accepted)!=2 ||
     !marker_received || marker->loaned != !marker_settled || marker->skb ||
     PTR(struct qdx_packet_op,copy_operation) ||
     !skb_queue_empty(SLOT(struct sk_buff_head,quarantine)) ||
     *SLOT(int,last_error)!=-ETIMEDOUT) { error=-EPERM; goto unlock; }
 for (i=0;i<NODES;i++)
  if (nodes[i].tag!=tags[i] || nodes[i].kind!=kinds[i]) { error=-ESTALE; goto unlock; }
 if (PTR(struct qdx_request,request)) {
  error=wait_command(); if (error) goto unlock;
 }
 if (!self_pinned) {
  if (action || FLAG(closed) || !FLAG(assigned) || !FLAG(enabled) || !FLAG(next_set) ||
      !FLAG(hook) || !FLAG(source_opened) || WORD(source_default)!=LEAF_A ||
      !PTR(struct qdx_dma,table) || !qdx_diag_fq_table_idle(PTR(struct qdx_dma,table)) ||
      nodes[INNER].parent!=-1 || nodes[FQ].parent!=INNER || nodes[FQ].band!=1 ||
      nodes[LEAF_A].parent!=INNER || nodes[LEAF_A].band ||
      nodes[MARKER].parent!=OUTER || nodes[MARKER].band!=2) { error=-EPERM; goto unlock; }
  for (i=0;i<NODES;i++)
   if (!nodes[i].allocated || (i!=FQ && nodes[i].path)) { error=-ESTALE; goto unlock; }
  if (!nodes[FQ].path || !nodes[FQ].path_closed) { error=-ESTALE; goto unlock; }
  error=gauge(LEAF_A,3);
  if (error) goto unlock;
  if (nodes[LEAF_A].bytes!=4554 || nodes[LEAF_A].admitted!=3 ||
      nodes[LEAF_A].selected || nodes[LEAF_A].dropped!=7) { error=-EBADMSG; goto unlock; }
  if (!try_module_get(THIS_MODULE)) { error=-ENODEV; goto unlock; }
  self_pinned=true; stage=1;
 }
 if (!action) {
  if (service_started) { error=-EPERM; goto unlock; }
  if (!inspected) {
   error=base(snapshot);
   if (error) goto unlock;
   if (snapshot->state.count!=3 || snapshot->state.occupancy[1]!=4554 ||
       snapshot->state.occupancy[2] || !snapshot->clock) { error=-EBADMSG; goto unlock; }
   /* Read the real chain and metadata; the current typed payload-copy operation
    * refuses1518B. Do not weaken its owner/extent guard or forge a shorter packet.
    * Source PCAP and later real stripped originals provide the full byte check. */
   for (i=0;i<3;i++) {
    address=i?get_unaligned_le32(snapshot->aqm.carrier[i-1]):
     get_unaligned_le32(snapshot->aqm.node+164);
    stride=address>=0x400ccac0?64:56;
    error=copy(&snapshot->view,QDX_DIAG_AQM_CARRIER,i,stride,snapshot->aqm.carrier[i]);
    if (error) goto unlock;
    snapshot->aqm.carrier_address[i]=address; snapshot->aqm.carrier_valid|=BIT(i);
    error=copy(&snapshot->view,QDX_DIAG_AQM_METADATA,i,96,snapshot->aqm.metadata[i]);
    if (error) goto unlock;
    snapshot->aqm.metadata_valid|=BIT(i);
    resident_carrier[i]=address;
    resident_length[i]=get_unaligned_le16(snapshot->aqm.carrier[i]+46);
    resident_class[i]=get_unaligned_le32(snapshot->aqm.metadata[i]+80);
    if (resident_length[i]!=1518 || resident_class[i]!=1 ||
        packets[i].skb || packets[i].copied || packets[i].loaned) {
     error=-EBADMSG; goto unlock;
    }
    verified_mask|=BIT(i);
   }
   /* The original aqm_join(MARKER) has already retired its TX owner. Its
    * actual CPU arrival was recorded by PPE, but the old hook passed the tag.
    * Settle only that logical loan flag; do not increment markers or clear error. */
   error=gauge(MARKER,0); if (error) goto unlock;
   if (nodes[MARKER].path || nodes[MARKER].admitted!=1 ||
       nodes[MARKER].selected!=1 || nodes[MARKER].dropped || marker->skb) {
    error=-EBADMSG; goto unlock;
   }
   marker->loaned=false; marker_settled=true;
   for (i=0;i<7;i++) {
    initial_average[i]=snapshot->state.average[i]; initial_occupancy[i]=snapshot->state.occupancy[i];
   }
   initial_clock=snapshot->clock; inspected=true; stage=2;
  }
  error=0; goto unlock;
 }
 if (!inspected || verified_mask!=7) { error=-EPERM; goto unlock; }
 if (action==1) {
  if (serviced) { error=0; goto unlock; }
  if (FLAG(closed)) { error=-EPERM; goto unlock; }
  /* Keep the existing PPE strip/capture rule. Source is sealed. Detach
   * anchors before selecting data, and retain the three real returned skbs. */
  if (!service_started) {
   if (nodes[INNER].parent!=-1) { error=-ESTALE; goto unlock; }
   service_started=true; stage=3;
  }
  if (nodes[FQ].parent==INNER) {
   error=tc(6,INNER,FQ,0); if (error) goto unlock;
  } else if (nodes[FQ].parent!=-1) { error=-ESTALE; goto unlock; }
  if (FLAG(hook)) {
   netdev_rx_handler_unregister(PTR(struct net_device,conduit)); FLAG(hook)=false;
  }
  if (!receive_hook) {
   error=netdev_rx_handler_register(PTR(struct net_device,conduit),recovery_receive,NULL);
   if (error) goto unlock;
   receive_hook=true;
  }
  stage=4;
  if (nodes[INNER].parent==-1) {
   error=tc(5,OUTER,INNER,0); if (error) goto unlock;
  } else if (nodes[INNER].parent!=OUTER || nodes[INNER].band) { error=-ESTALE; goto unlock; }
  stage=5;
  error=gauge(LEAF_A,0); if (error) goto unlock;
  if (!wait_for_completion_timeout(&receive_done,msecs_to_jiffies(6000))) {
   error=-ETIMEDOUT; goto unlock;
  }
  if (receive_bad || received_count!=3 || !skb_queue_empty(&quarantine)) {
   error=-EBADMSG; goto unlock;
  }
  selected_after=nodes[LEAF_A].selected; dropped_after=nodes[LEAF_A].dropped;
  if (selected_after!=3 || dropped_after!=7 || nodes[LEAF_A].admitted!=3 || nodes[LEAF_A].bytes) {
   error=-EBADMSG; goto unlock;
  }
  serviced=true; stage=6; error=0; goto unlock;
 }
 if (!serviced || selected_after!=3 || dropped_after!=7 || received_count!=3 ||
     receive_bad || !skb_queue_empty(&quarantine)) { error=-EPERM; goto unlock; }
 if (action==2) {
  /* Root has now restored PPE/output before this explicit wire command. */
  if (wire_error) { error=wire_error; goto unlock; }
  if (receive_hook) {
   netdev_rx_handler_unregister(PTR(struct net_device,conduit)); receive_hook=false;
  }
  while (wire_count<3) {
   skb=received[wire_count];
   if (!skb || skb->len!=1514 || memcmp(skb->data,expected_source[wire_count],1514)) {
    error=-EBADMSG; goto unlock;
   }
   received[wire_count]=NULL;
   skb->dev=PTR(struct net_device,port); skb->protocol=htons(ETH_P_IP);
   skb->ip_summed=CHECKSUM_NONE; skb_reset_mac_header(skb);
   skb_set_network_header(skb,ETH_HLEN); skb_set_transport_header(skb,ETH_HLEN+20);
   skb_set_queue_mapping(skb,0);
   error=dev_queue_xmit(skb); wire_count++;
   if (net_xmit_eval(error)) { wire_error=error<0?error:-ENOBUFS; error=wire_error; goto unlock; }
  }
  stage=7; error=0; goto unlock;
 }
 if (action!=3 || wire_count!=3 || wire_error || receive_hook) { error=-EPERM; goto unlock; }
 for (i=0;i<3;i++) if (received[i]) { error=-EBUSY; goto unlock; }
 /* Explicit close is issued only after root verifies complete source bytes
  * for actual IDs0/1/2 on the wire. No verification skb was allocated. */
 for (i=LEAF_A;i<=LEAF_D;i++) {
  if (!nodes[i].allocated) continue;
  error=gauge(i,0); if (error) goto unlock;
 }
 FLAG(closed)=true; stage=8;
 for (i=0;i<NODES;i++) {
  if (i==FQ) continue;
  error=join(i); if (error) goto unlock;
 }
 for (i=NODES;i-->0;) {
  if (nodes[i].parent==-1) continue;
  error=tc(6,nodes[i].parent,i,0); if (error) goto unlock;
 }
 if (nodes[FQ].allocated) {
  error=tc(1,FQ,0,0); if (error) goto unlock;
 }
 error=join(FQ); if (error) goto unlock;
 WORD(controls_retired)=WORD(anchor_accepted);
 anchors[0].loaned=anchors[1].loaned=false;
 for (i=NODES;i-->0;) {
  if (!nodes[i].allocated) continue;
  error=tc(1,i,0,0); if (error) goto unlock;
 }
 stage=9;
 if (FLAG(enabled)) { error=command(true,2,NULL,0); if (error) goto unlock; }
 if (FLAG(next_set)) { error=command(true,4,NULL,0); if (error) goto unlock; }
 if (FLAG(assigned)) {
  unassign=cpu_to_le32(WORD(shaper)); error=command(false,8,&unassign,sizeof(unassign));
  if (error) goto unlock;
 }
 if (PTR(struct qdx_dma,table) && !qdx_diag_fq_table_idle(PTR(struct qdx_dma,table))) {
  error=-EBUSY; goto unlock;
 }
 if (PTR(struct qdx_endpoint,mirror) && !FLAG(mirror_retired)) {
  error=qdx_endpoint_wait(PTR(struct qdx_endpoint,mirror),jiffies);
  if (!error) error=qdx_endpoint_retire(PTR(struct qdx_endpoint,mirror));
  if (error) goto unlock;
  FLAG(mirror_retired)=true;
 }
 if (PTR(struct qdx_receiver,receiver)) {
  error=qdx_endpoint_receive_unregister(PTR(struct qdx_receiver,receiver));
  if (error) goto unlock;
  PTR(struct qdx_receiver,receiver)=NULL;
 }
 synchronize_net();
 for (i=0;i<3;i++) { dev_kfree_skb(packets[i].skb); packets[i].skb=NULL; }
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
 /* loaded/error/stage/PASS in the failed owner are deliberately unchanged. */
unlock:
 mutex_unlock(lock);
put_module:
 module_put(module);
 return error;
}
static int recovery_show(struct seq_file *seq,void *unused)
{
 unsigned int i;
 mutex_lock(&recovery_lock);
 seq_printf(seq,"stage=%u result=%d inspected=%u verified_mask=%x service_started=%u serviced=%u released=%u self_pinned=%u initial_clock=%llu selected_after=%llu dropped_after=%llu original_test_passed=0\n",
  stage,result,inspected,verified_mask,service_started,serviced,released,self_pinned,
  initial_clock,selected_after,dropped_after);
 seq_printf(seq,"receive_hook=%u received=%u receive_bad=%u quarantine=%u wire_count=%u wire_error=%d held=%u,%u,%u\n",
  receive_hook,received_count,receive_bad,skb_queue_len(&quarantine),wire_count,wire_error,
  !!received[0],!!received[1],!!received[2]);
 seq_printf(seq,"marker_received=%u marker_settled=%u\n",marker_received,marker_settled);
 for (i=0;i<3;i++) seq_printf(seq,"resident=%u carrier=%08x length=%u class=%u\n",i,resident_carrier[i],resident_length[i],resident_class[i]);
 for (i=0;i<7;i++) seq_printf(seq,"class=%u average=%u occupancy=%u\n",i,initial_average[i],initial_occupancy[i]);
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
 rtnl_unlock(); mutex_unlock(&recovery_lock);
 return error ? error : count;
}
static const struct file_operations recovery_ops={.owner=THIS_MODULE,.write=recovery_write};
static int __init recovery_init(void)
{
 if (!allow_writes || !marker_received) return -EPERM;
 skb_queue_head_init(&quarantine);
 directory=debugfs_create_dir("qdx_physical_aqm_recovery",NULL);
 if (IS_ERR(directory)) return PTR_ERR(directory);
 debugfs_create_file("status",0400,directory,NULL,&recovery_fops);
 debugfs_create_file("control",0200,directory,NULL,&recovery_ops);
 return 0;
}
static void __exit recovery_exit(void)
{
 WARN_ON(self_pinned || receive_hook || !skb_queue_empty(&quarantine)); debugfs_remove_recursive(directory);
}
module_init(recovery_init); module_exit(recovery_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Exact failed physical WRED normal-service recovery; never qualification");
