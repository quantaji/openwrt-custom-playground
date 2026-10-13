// SPDX-License-Identifier: GPL-2.0-only
/* Isolated physical WRR history continuation. Not a qdisc or CPU baseline. */
#include <linux/build_bug.h>
#include <linux/completion.h>
#include <linux/debugfs.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/etherdevice.h>
#include <linux/in.h>
#include <linux/dsa/oob.h>
#include <linux/if_vlan.h>
#include <linux/rtnetlink.h>
#include <net/pkt_sched.h>
#include <linux/iopoll.h>
#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/qdx.h>
#include <linux/qdx_diag_fq.h>
#include <linux/seq_file.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/unaligned.h>
#include <net/checksum.h>
#include <net/net_namespace.h>

#define WAIT_MS 3000
#define TABLE_TAG 0x6d010000U
#define COPY_TAG 0x4d54424cU
#define TABLE_LEN 144
#define FRAME_MAX 1514
#define OWNED_TABLE ((enum qdx_diag_fq_range)U32_MAX)
/* Selected 116-byte wire layout from Qualcomm nss_shaper.h.
 * Copyright (c) 2014, 2017-2018 The Linux Foundation. All rights reserved.
 * Copyright (c) 2014-2021, The Linux Foundation. All rights reserved.
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
struct wrr_message { __le32 command, response, value[27]; };
static_assert(sizeof(struct wrr_message) == 116);
enum node_id { OUTER, ROOT, ANCHOR, GROUP_A, GROUP_B, FIFO_A, FIFO_B, PROBE, FQ, MARKER, NODES };
struct wrr_node {
 u32 tag, kind, gauge, bytes;
 u64 admitted, selected, dropped;
 bool allocated;
 int parent;
 u32 band;
 struct qdx_tx_path *path;
 bool path_closed;
};
static struct wrr_node nodes[NODES] = {
 [OUTER] = { .tag = 0x6f000000, .kind = 3, .parent = -1 },
 [ROOT] = { .tag = 0x6f010000, .kind = 9, .parent = -1 },
 [ANCHOR] = { .tag = 0x6f020000, .kind = 10, .parent = -1 },
 [GROUP_A] = { .tag = 0x6f030000, .kind = 10, .parent = -1 },
 [GROUP_B] = { .tag = 0x6f040000, .kind = 10, .parent = -1 },
 [FIFO_A] = { .tag = 0x6f050000, .kind = 4, .parent = -1 },
 [FIFO_B] = { .tag = 0x6f060000, .kind = 4, .parent = -1 },
 [PROBE] = { .tag = 0x6f070000, .kind = 4, .parent = -1 },
 [FQ] = { .tag = TABLE_TAG, .kind = 1, .parent = -1 },
 [MARKER] = { .tag = 0x6f080000, .kind = 4, .parent = -1 },
};
struct wrr_packet {
 struct sk_buff *skb;
 u32 id, length, returns;
 bool loaned, control;
 u8 expected[FRAME_MAX];
};
struct wrr_cpu { s32 deficit[2]; u32 position[2], order[2], active; };
struct wrr_snapshot {
 struct qdx_diag_fq_view view;
 u32 root_address, group_address[3], active_tags[3], active_count;
 s32 deficit[2];
 u32 quantum[2];
};
struct wrr_event { u32 phase, id, length; u64 time_ns; u32 type, ifnum; };
struct wrr_copy_round {
 struct completion original_done, clone_done;
 u32 originals, clones, length;
 bool original_valid, clone_valid;
 u8 bytes[280];
};
extern struct qdx_dma *qdx_diag_fq_table_alloc(struct qdx_service *, const struct qdx_owner *);
extern bool qdx_diag_fq_table_idle(struct qdx_dma *);
extern struct qdx_ready qdx_diag_fq_table_copy(struct qdx_packet_op *, struct qdx_dma *,
 const struct qdx_packet_recipient *);
static bool allow_writes;
static unsigned int byte_mode;
module_param(allow_writes, bool, 0400);
module_param(byte_mode, uint, 0400);
static DEFINE_MUTEX(control_lock);
static DEFINE_SPINLOCK(result_lock);
static struct dentry *directory;
static struct net_device *port;
static struct qdx_service *physical_service, *mirror_service;
static struct qdx_endpoint *physical, *mirror;
static struct qdx_receiver *receiver;
static struct qdx_dma *table;
static struct qdx_packet_op *copy_operation;
static struct qdx_request *request;
static struct qdx_result result;
static struct wrr_message pending_message;
static u32 pending_opcode, pending_length, pending_node, pending_arg, pending_extra;
static bool pending_mirror;
static struct wrr_packet packets[16], anchor_packets[2], private_packet;
static struct wrr_snapshot snapshots[3];
static struct wrr_cpu cpu;
static struct wrr_copy_round copy_round;
static struct wrr_event events[160];
static u32 event_count, bad_packets, disposals, unexpected_clones, controls_retired;
static u32 phase, private_count, physical_ifnum = U32_MAX, mirror_ifnum = U32_MAX, shaper;
static u32 selected_mask, expected[16], fresh[16], resume_order[13], resume_count;
static u32 recall_order[16], recall_count;
static u32 memory_size, command_count, copy_count;
static u64 copy_time_ns;
static bool pinned, assigned, enabled, next_set, prepared, loaded, exported;
static bool recalled, cpu_selected, rebuilt, passed, closed, fault, anchor_retiring;
static bool mirror_retired;
static int last_error;

/* Physical transport state. Host-created anchors/probes are never user service. */
static unsigned long long run_id = 22100291;
static unsigned int source_ip = 0xc0a80190, target_ip = 0xc0a80173;
static unsigned int source_port = 41000, target_port = 41001, private_vid = 4000;
module_param(run_id, ullong, 0400);
module_param(source_ip, uint, 0400);
module_param(target_ip, uint, 0400);
module_param(source_port, uint, 0400);
module_param(target_port, uint, 0400);
module_param(private_vid, uint, 0400);
static struct net_device *conduit;
static struct sk_buff *warm_prefix[7];
static struct sk_buff_head quarantine;
static struct wrr_packet marker_packet;
static DECLARE_COMPLETION(marker_done);
static DECLARE_COMPLETION(private_done);
static DECLARE_COMPLETION(recall_done);
static DECLARE_COMPLETION(resume_done);
static u32 warm_count, admission_stage, recalled_leaf, marker_wait, markers, native_sent;
static u32 observed_port = U32_MAX, source_default = U32_MAX;
static bool hook, wire_complete;
static const u32 lengths[16] = { 128,192,256,128,128,1514,128,192,192,128,256,128,512,128,192,128 };

/* The saved command, not a reconstructed request, remains held on timeout. */
static int wrr_wait_command(void)
{
 u8 reply[116] = {};
 struct wrr_message *message = (void *)reply;
 struct wrr_node *node = &nodes[pending_node];
 u32 sub = le32_to_cpu(pending_message.command);
 int error;

 if (!request) return 0;
 error = qdx_request_wait(request, jiffies + msecs_to_jiffies(WAIT_MS),
  &result, reply, sizeof(reply));
 if (result.outcome == QDX_UNKNOWN && !result.exposure_ended)
  return error ?: -EINPROGRESS;
 if (result.outcome == QDX_ACK) {
  if (result.declared_len != pending_length || result.received_len < pending_length ||
      (!pending_mirror && pending_opcode == 10 && message->command != pending_message.command)) {
   fault = true;
   return -EPROTO;
  }
  error = !pending_mirror && pending_opcode == 10 && le32_to_cpu(message->response) ?
   -EREMOTEIO : 0;
  if (!error && pending_mirror) {
   if (pending_opcode == 1) enabled = true;
   if (pending_opcode == 2) enabled = false;
   if (pending_opcode == 3) next_set = true;
   if (pending_opcode == 4) next_set = false;
  } else if (!error && pending_opcode == 6) {
   shaper = get_unaligned_le32(reply + 4);
   assigned = true;
   if (!shaper) { fault = true; return -EPROTO; }
  } else if (!error && pending_opcode == 8) {
   assigned = false;
  } else if (!error && pending_opcode == 10) {
   if (sub == 0) node->allocated = true;
   if (sub == 1) {
    node->allocated = false;
    if (pending_node == FQ && table) qdx_dma_access_end(table);
   }
   if (sub == 5) {
    nodes[pending_arg].parent = pending_node;
    nodes[pending_arg].band = pending_extra;
   }
   if (sub == 6) nodes[pending_arg].parent = -1;
   if (sub == 10) memory_size = get_unaligned_le32(reply + 12);
   if (sub == 4) {
    node->bytes = get_unaligned_le32(reply + 12);
    node->gauge = get_unaligned_le32(reply + 16);
    node->admitted += get_unaligned_le32(reply + 40);
    node->selected += get_unaligned_le32(reply + 56);
    node->dropped += get_unaligned_le32(reply + 48) + get_unaligned_le32(reply + 64);
   }
  }
 } else error = result.error ?: error ?: -EIO;
 qdx_request_put(request);
 request = NULL;
 return error;
}

static int wrr_command(bool mirror_command, u32 opcode, const void *payload, size_t length)
{
 struct qdx_reply_bounds bounds = { length, length, length };
 int error;

 if (request || fault) return fault ? -EPROTO : -EBUSY;
 pending_mirror = mirror_command;
 pending_opcode = opcode;
 pending_length = length;
 request = qdx_command_submit(mirror_command ? mirror : physical, opcode,
  payload, length, &bounds, NULL);
 if (IS_ERR(request)) { error = PTR_ERR(request); request = NULL; return error; }
 command_count++;
 return wrr_wait_command();
}

static int wrr_tc(u32 sub, u32 id, u32 arg, u32 extra)
{
 struct wrr_message message = {};
 u8 *wire = (void *)&message;

 if (id >= NODES || ((sub == 5 || sub == 6) && arg >= NODES)) return -EINVAL;
 message.command = cpu_to_le32(sub);
 message.value[0] = cpu_to_le32(nodes[id].tag);
 if (sub == 0) {
  message.value[0] = cpu_to_le32(nodes[id].kind);
  message.value[1] = cpu_to_le32(nodes[id].tag);
 } else if (sub == 5 || sub == 6) {
  message.value[1] = cpu_to_le32(sub == 6 && id == OUTER ? nodes[arg].band : nodes[arg].tag);
  message.value[2] = cpu_to_le32(extra);
 } else if (sub == 7 && id == FQ) {
  message.value[1] = cpu_to_le32(32);
  put_unaligned_le16(65535, wire + 16);
  put_unaligned_le16(32767, wire + 18);
  put_unaligned_le16(1500, wire + 20);
  put_unaligned_le32(2, wire + 24);
  put_unaligned_le32((u32)qdx_dma_address(table), wire + 28);
  put_unaligned_le32(TABLE_LEN, wire + 32);
  put_unaligned_le32(128, wire + 36);
  qdx_dma_expose(table);
 } else if (sub == 7) {
  message.value[1] = cpu_to_le32(arg);
  message.value[2] = cpu_to_le32(extra);
 }
 pending_message = message;
 pending_node = id;
 pending_arg = arg;
 pending_extra = extra;
 return wrr_command(false, 10, &message, sizeof(message));
}





static rx_handler_result_t wrr_receive(struct sk_buff **pskb)
{
 struct sk_buff *skb = *pskb;
 const struct dsa_oob_tag_info *tag;
 struct wrr_packet *packet = NULL;
 u8 header[67];
 unsigned long flags;
 u32 group, id, packet_phase, index;
 int offset;
 bool bad = false, internal = false;
 if (!skb_mac_header_was_set(skb)) return RX_HANDLER_PASS;
 offset = skb_mac_offset(skb);
 if (offset != -ETH_HLEN || skb_headroom(skb) < ETH_HLEN ||
     skb->len + ETH_HLEN < sizeof(header) ||
     skb_copy_bits(skb, offset, header, sizeof(header))) return RX_HANDLER_PASS;
 if (get_unaligned_be16(header + 12) != ETH_P_IP || header[14] != 0x45 ||
     header[23] != IPPROTO_UDP || get_unaligned_be32(header + 26) != source_ip ||
     get_unaligned_be32(header + 30) != target_ip ||
     get_unaligned_be16(header + 34) != source_port ||
     get_unaligned_be16(header + 36) != target_port ||
     memcmp(header + 42, "QDXPROB1", 8) || get_unaligned_be64(header + 50) != run_id)
  return RX_HANDLER_PASS;
 tag = skb_ext_find(skb, SKB_EXT_DSA_OOB);
 if (!tag || tag->port != 0 || skb_vlan_tag_present(skb)) {
  spin_lock_irqsave(&result_lock, flags);
  observed_port = tag ? tag->port : U32_MAX; bad_packets++;
  spin_unlock_irqrestore(&result_lock, flags);
  return RX_HANDLER_PASS;
 }
 skb_push(skb, ETH_HLEN); skb_reset_mac_header(skb);
 skb_ext_del(skb, SKB_EXT_DSA_OOB);
 packet_phase = header[58]; group = get_unaligned_be32(header + 59);
 id = get_unaligned_be32(header + 63);
 spin_lock_irqsave(&result_lock, flags);
 observed_port = 0;
 if (packet_phase == 255 && !group && id == marker_wait && id == markers + 1) {
  markers = id; internal = true; complete_all(&marker_done);
 } else if (packet_phase == 254 && !group && id == private_count &&
            !private_packet.skb && private_packet.loaned) {
  packet = &private_packet;
  if (skb->len + VLAN_HLEN != packet->length ||
      memcmp(skb->data, packet->expected, skb->len)) bad = true;
  else { packet->skb = skb; packet->loaned = false; packet->returns++; complete_all(&private_done); }
 } else if (packet_phase != 1) bad = true;
 else if (!group && phase == 0 && warm_count < 7 && id == warm_count &&
          !warm_prefix[warm_count] && skb->len + VLAN_HLEN == 128) {
  warm_prefix[warm_count++] = skb;
 } else if (group == 1 && id < 16 && (phase == 2 || phase == 4)) {
  packet = &packets[id];
  index = phase == 2 ? recall_count : resume_count;
  if (packet->skb || skb->len + VLAN_HLEN != lengths[id] ||
      (phase == 2 && (id != recall_count || id < (recalled_leaf * 8) || id >= (recalled_leaf * 8 + 8))) ||
      (phase == 4 && (index >= 13 || id != expected[index + 3] ||
       !packet->loaned || memcmp(skb->data, packet->expected, skb->len)))) bad = true;
  else {
   packet->skb = skb; packet->loaned = false; packet->returns++;
   if (phase == 2) {
    packet->id = id; packet->length = lengths[id];
    memcpy(packet->expected, skb->data, skb->len);
    recall_order[recall_count++] = id;
    if (recall_count == (recalled_leaf * 8 + 8)) complete_all(&recall_done);
   } else {
    resume_order[resume_count++] = id;
    
    if (resume_count == 13) complete_all(&resume_done);
   }
  }
 } else bad = true;
 if (bad) bad_packets++;
 if (!internal && event_count < ARRAY_SIZE(events))
  events[event_count++] = (struct wrr_event) { phase, id, skb->len + VLAN_HLEN,
   ktime_get_ns(), packet_phase, group };
 else if (!internal) bad_packets++;
 spin_unlock_irqrestore(&result_lock, flags);
 if (bad) skb_queue_tail(&quarantine, skb);
 else if (internal) consume_skb(skb);
 return RX_HANDLER_CONSUMED;
}

static int wrr_packet_create(struct wrr_packet *packet, u32 id, u32 length, u32 bin)
{
 struct sk_buff *skb;
 u8 *data;
 u32 native_length = length - VLAN_HLEN;
 if (packet->skb || packet->loaned || length < 128 || length > FRAME_MAX) return -EINVAL;
 skb = alloc_skb(136 + native_length, GFP_KERNEL);
 if (!skb) return -ENOMEM;
 skb_reserve(skb, 136); data = skb_put_zero(skb, native_length);
 ether_addr_copy(data, port->dev_addr); ether_addr_copy(data + ETH_ALEN, port->dev_addr);
 put_unaligned_be16(ETH_P_IP, data + 12); data[14] = 0x45;
 put_unaligned_be16(native_length - ETH_HLEN, data + 16);
 data[22] = 64; data[23] = IPPROTO_UDP;
 put_unaligned_be32(source_ip, data + 26); put_unaligned_be32(target_ip, data + 30);
 put_unaligned_be16(packet->control ? 20000 + bin : source_port, data + 34);
 put_unaligned_be16(target_port, data + 36);
 put_unaligned_be16(native_length - ETH_HLEN - 20, data + 38);
 memcpy(data + 42, "QDXPROB1", 8); put_unaligned_be64(run_id, data + 50);
 data[58] = packet == &marker_packet ? 255 : packet->control ? 253 : 254;
 put_unaligned_be32(0, data + 59); put_unaligned_be32(id, data + 63);
 put_unaligned(csum_fold(csum_partial(data + 14, 20, 0)), (__sum16 *)(data + 24));
 skb->dev = port; skb->protocol = htons(ETH_P_IP); skb_reset_mac_header(skb);
 packet->skb = skb; packet->id = id; packet->length = length;
 memcpy(packet->expected, data, native_length);
 return 0;
}


static int wrr_submit(u32 leaf, struct wrr_packet *packet)
{
 struct qdx_tx_class class = { nodes[leaf].tag, nodes[leaf].tag | 1 };
 struct qdx_ready ready;
 struct sk_buff *skb = packet->skb;
 struct netdev_queue *queue = netdev_get_tx_queue(conduit, 0);
 int error;
 if (!skb || packet->loaned || nodes[leaf].path_closed) return -EINVAL;
 if (!nodes[leaf].path) {
  nodes[leaf].path = qdx_tx_prepare(physical, port, 0, class, QDX_REQUIRED);
  if (IS_ERR(nodes[leaf].path)) { error = PTR_ERR(nodes[leaf].path); nodes[leaf].path = NULL; return error; }
 }
 error = skb_cow_head(skb, 136);
 if (error) return error;
 if (skb_vlan_tag_present(skb) || skb_mac_header(skb) != skb->data ||
     get_unaligned_be16(skb->data + 12) != ETH_P_IP || skb->len + VLAN_HLEN != packet->length)
  return -EPROTO;
 error = __vlan_insert_tag(skb, htons(ETH_P_8021Q), private_vid);
 if (error) return error;
 skb->protocol = htons(ETH_P_8021Q); skb->dev = port; skb_set_queue_mapping(skb, 0);
 packet->skb = NULL; packet->loaned = true;
 ready = qdx_xmit(nodes[leaf].path, skb, class, queue, skb->len);
 if (ready.status == QDX_ACCEPTED) return 0;
 packet->skb = skb; packet->loaned = false;
 /* The rejected original remains CPU owned. Restore only our inline tag. */
 error = skb_vlan_pop(skb);
 if (error) return error;
 return ready.error ?: -EAGAIN;
}


static int wrr_join(u32 leaf)
{
 bool drained;
 int error;
 if (!nodes[leaf].path) return 0;
 if (!nodes[leaf].path_closed) {
  qdx_tx_path_get(nodes[leaf].path); qdx_tx_release(nodes[leaf].path);
  nodes[leaf].path_closed = true;
 }
 error = read_poll_timeout(qdx_tx_drained, drained, drained, 50,
  WAIT_MS * 1000, false, nodes[leaf].path);
 if (error) return error;
 qdx_tx_path_put(nodes[leaf].path); nodes[leaf].path = NULL; nodes[leaf].path_closed = false;
 return bad_packets ? -EBADMSG : 0;
}


static int wrr_gauge(u32 leaf, u32 expected_count)
{
 unsigned long deadline = jiffies + msecs_to_jiffies(WAIT_MS);
 int error;

 do {
  error = wrr_tc(4, leaf, 0, 0);
  if (error) return error;
  if (nodes[leaf].dropped || bad_packets || disposals) return -EBADMSG;
  if (nodes[leaf].gauge == expected_count) return 0;
  usleep_range(1000, 1500);
 } while (time_before(jiffies, deadline));
 return -ETIMEDOUT;
}

static int wrr_private(u32 leaf, u32 length)
{
 int error;
 if (private_count >= 256 || private_packet.loaned) return -E2BIG;
 reinit_completion(&private_done);
 error = wrr_packet_create(&private_packet, private_count, length, 0);
 if (!error) error = wrr_submit(leaf, &private_packet);
 if (!error) error = wrr_join(leaf);
 if (error) return error;
 if (!wait_for_completion_timeout(&private_done, msecs_to_jiffies(WAIT_MS))) return -ETIMEDOUT;
 if (!private_packet.skb || private_packet.loaned || bad_packets) return -EBADMSG;
 dev_kfree_skb(private_packet.skb); private_packet.skb = NULL;
 private_count++;
 return wrr_gauge(leaf, 0);
}


static void wrr_copy_original(void *owner, struct sk_buff *original,
 struct sk_buff *returned, const struct qdx_rx_meta *meta, struct napi_struct *napi)
{
 copy_round.originals++;
 copy_round.original_valid = !original && !returned && meta &&
  meta->ifnum == READ_ONCE(mirror_ifnum) && meta->type == QDX_RECEIVE_PACKET;
 complete_all(&copy_round.original_done);
}

static void wrr_copy_clone(void *owner, struct sk_buff *skb,
 const struct qdx_rx_meta *meta, struct napi_struct *napi)
{
 if (!READ_ONCE(copy_operation)) {
  unexpected_clones++;
  dev_kfree_skb_any(skb);
  return;
 }
 copy_round.clones++;
 copy_round.clone_valid = meta && meta->ifnum == READ_ONCE(mirror_ifnum) &&
  meta->type == QDX_RECEIVE_PACKET && skb->len == copy_round.length && !skb_is_nonlinear(skb);
 if (copy_round.clone_valid) memcpy(copy_round.bytes, skb->data, skb->len);
 dev_kfree_skb_any(skb);
 complete_all(&copy_round.clone_done);
}
static const struct qdx_receive_ops copy_ops = { .packet = wrr_copy_clone };

static int wrr_copy(struct qdx_diag_fq_view *view, enum qdx_diag_fq_range kind,
 u32 index, u32 length, void *destination)
{
 struct qdx_packet_recipient recipient = {
  .owner = { .module = THIS_MODULE, .object = snapshots }, .returned = wrr_copy_original,
 };
 struct qdx_ready ready;
 u64 start;
 bool idle, drained;
 int error;

 if (nodes[ROOT].parent != -1 || !nodes[FQ].path || !nodes[FQ].path_closed || copy_operation || request ||
     !qdx_diag_fq_table_idle(table) || length > sizeof(copy_round.bytes) || !enabled)
  return -EPERM;
 memset(&copy_round, 0, sizeof(copy_round));
 init_completion(&copy_round.original_done);
 init_completion(&copy_round.clone_done);
 copy_round.length = length;
 copy_operation = qdx_packet_op_prepare(mirror, COPY_TAG, QDX_RECEIVE_PACKET);
 if (IS_ERR(copy_operation)) { error = PTR_ERR(copy_operation); copy_operation = NULL; return error; }
 start = ktime_get_ns();
 if (kind == OWNED_TABLE) ready = qdx_diag_fq_table_copy(copy_operation, table, &recipient);
 else ready = qdx_diag_fq_owned_copy(copy_operation, table, NULL,
  view, kind, index, &recipient);
 if (ready.status != QDX_ACCEPTED) {
  qdx_packet_op_close(copy_operation);
  qdx_packet_op_put(copy_operation);
  copy_operation = NULL;
  return ready.error ?: -EAGAIN;
 }
 if (!wait_for_completion_timeout(&copy_round.original_done, msecs_to_jiffies(WAIT_MS)) ||
     !wait_for_completion_timeout(&copy_round.clone_done, msecs_to_jiffies(WAIT_MS)))
  return -ETIMEDOUT;
 qdx_packet_op_close(copy_operation);
 error = read_poll_timeout(qdx_diag_fq_table_idle, idle, idle, 10,
  WAIT_MS * 1000, false, table);
 if (!error) error = read_poll_timeout(qdx_packet_op_drained, drained, drained, 10,
  WAIT_MS * 1000, false, copy_operation);
 if (error) return error;
 qdx_packet_op_put(copy_operation);
 copy_operation = NULL;
 if (copy_round.originals != 1 || copy_round.clones != 1 ||
     !copy_round.original_valid || !copy_round.clone_valid || unexpected_clones)
  return -EBADMSG;
 memcpy(destination, copy_round.bytes, length);
 copy_count++;
 copy_time_ns += ktime_get_ns() - start;
 return 0;
}


static int wrr_marker(void)
{
 u32 next = markers + 1;
 int error;
 if (marker_wait != markers || marker_packet.loaned) return -EBUSY;
 reinit_completion(&marker_done); marker_wait = next;
 error = wrr_packet_create(&marker_packet, next, 128, 0);
 if (!error) error = wrr_submit(MARKER, &marker_packet);
 if (!error) error = wrr_join(MARKER);
 if (error) return error;
 if (!wait_for_completion_timeout(&marker_done, msecs_to_jiffies(WAIT_MS))) return -ETIMEDOUT;
 marker_packet.loaned = false;
 return markers != next || bad_packets ? -EBADMSG : 0;
}

static int wrr_close_anchor(void)
{
 if (!nodes[FQ].path || nodes[FQ].path_closed) return -EINVAL;
 qdx_tx_path_get(nodes[FQ].path); qdx_tx_release(nodes[FQ].path);
 nodes[FQ].path_closed = true;
 return wrr_gauge(FQ, 2);
}

static int wrr_anchor_view(struct qdx_diag_fq_view *view)
{
 u32 i, address, stride;
 int error;
 if (!nodes[FQ].path || !nodes[FQ].path_closed) return -EPERM;
 view->physical_rebuild = nodes[FQ].path;
 for (i = 0; i < 2; i++) {
  address = get_unaligned_le32(view->table + i * 72 + 16);
  stride = address >= 0x400ccac0 ? 64 : 56;
  error = wrr_copy(view, QDX_DIAG_FQ_CARRIER, i, stride, view->carrier[i]);
  if (error) return error;
  view->carrier_address[i] = address; view->carrier_valid |= BIT(i);
  error = wrr_copy(view, QDX_DIAG_FQ_METADATA, i, 96, view->metadata[i]);
  if (error) return error;
  view->metadata_valid |= BIT(i);
 }
 return 0;
}

static int wrr_snapshot(u32 which)
{
 struct wrr_snapshot *snapshot = &snapshots[which];
 struct qdx_diag_fq_view *view = &snapshot->view;
 u32 node_address, sentinel, entry, previous, tag, slot, found, mask = 0;
 u32 i, j, address;
 u8 *group;
 int error;

 if (which >= ARRAY_SIZE(snapshots) || nodes[ANCHOR].parent != ROOT) return -EINVAL;
 memset(snapshot, 0, sizeof(*snapshot));
 view->wrr = true;
 view->physical_rebuild = nodes[FQ].path;
 error = wrr_copy(view, OWNED_TABLE, 0, 144, view->table);
 if (error) return error;
 dma_rmb();
 if (memcmp(view->table, qdx_dma_cpu(table), TABLE_LEN)) return -EBADMSG;
 for (i = 0; i < 2; i++)
  if (get_unaligned_le32(view->table + i * 72 + 24) != 1 ||
      get_unaligned_le32(view->table + i * 72 + 64) != 128)
   return -EBADMSG;
 error = wrr_copy(view, QDX_DIAG_FQ_NODE, 0, 280, view->node);
 if (error) return error;
 view->node_valid = true;
 error = wrr_anchor_view(view);
 if (error) return error;
 node_address = get_unaligned_le32(view->table + 4) - 228;
 snapshot->group_address[0] = get_unaligned_le32(view->node + 4);
 error = wrr_copy(view, QDX_DIAG_WRR_ANCHOR_GROUP, 0, 196, view->wrr_group[0]);
 if (error) return error;
 view->wrr_valid |= BIT(0);
 snapshot->root_address = get_unaligned_le32(view->wrr_group[0] + 4);
 error = wrr_copy(view, QDX_DIAG_WRR_ROOT, 0, 188, view->wrr_root);
 if (error) return error;
 view->wrr_valid |= BIT(1);
 /* The helper returns the first not-yet-copied structural child. Record the
  * same owner-derived address without relying on allocation order. */
 for (i = 1; i < 3; i++) {
  entry = get_unaligned_le32(view->wrr_root + 172);
  for (j = 0; j < 3; j++) {
   address = entry - 180;
   for (slot = 0; slot < i; slot++)
    if (snapshot->group_address[slot] == address) break;
   if (slot == i) break;
   entry = get_unaligned_le32(view->wrr_group[slot] + 180);
  }
  if (j == 3 || entry == snapshot->root_address + 172) return -EBADMSG;
  snapshot->group_address[i] = address;
  error = wrr_copy(view, QDX_DIAG_WRR_GROUP, i, 196, view->wrr_group[i]);
  if (error) return error;
  view->wrr_valid |= BIT(i + 1);
 }
 if (get_unaligned_le32(view->wrr_group[0] + 188) != node_address ||
     get_unaligned_le32(view->wrr_root + 184) != (byte_mode ? 0x400a7080 : 0x400a7060))
  return -EBADMSG;
 /* Validate every completed copy, including the final group which no later
  * helper call needs to traverse. These are fixed held nodes, not raw pointers. */
 for (i = 0; i < 3; i++) {
  group = view->wrr_group[i];
  if (get_unaligned_le32(group + 8) != 10 ||
      get_unaligned_le32(group + 20) != get_unaligned_le32(view->node + 20) ||
      !group[24] || get_unaligned_le32(group + 4) != snapshot->root_address ||
      get_unaligned_le32(group + 36) != get_unaligned_le32(view->node + 36) ||
      get_unaligned_le32(group + 48) != 0x400a7c80 ||
      get_unaligned_le32(group + 60) != 0x400a7a80 ||
      get_unaligned_le32(group + 68) != 0x400a7b80 ||
      get_unaligned_le32(group + 72) != 0x400a7a40)
   return -EBADMSG;
  for (j = 0; j < i; j++)
   if (snapshot->group_address[j] == snapshot->group_address[i]) return -ELOOP;
 }
 if (get_unaligned_le32(view->wrr_group[0] + 16) != nodes[ANCHOR].tag) return -EBADMSG;
 sentinel = snapshot->root_address + 172;
 previous = sentinel;
 entry = get_unaligned_le32(view->wrr_root + 172);
 for (i = 0; i < 3; i++) {
  found = 3;
  for (j = 0; j < 3; j++) if (entry == snapshot->group_address[j] + 180) found = j;
  if (found == 3 || (mask & BIT(found))) return -EBADMSG;
  mask |= BIT(found);
  group = view->wrr_group[found];
  if (get_unaligned_le32(group + 184) != previous) return -EBADMSG;
  previous = entry;
  entry = get_unaligned_le32(group + 180);
 }
 if (entry != sentinel || get_unaligned_le32(view->wrr_root + 176) != previous)
  return -EBADMSG;
 mask = 0;
 for (i = 1; i < 3; i++) {
  group = view->wrr_group[i];
  tag = get_unaligned_le32(group + 16);
  if (tag != nodes[GROUP_A].tag && tag != nodes[GROUP_B].tag) return -EBADMSG;
  slot = tag == nodes[GROUP_A].tag ? 0 : 1;
  if (mask & BIT(slot)) return -EBADMSG;
  mask |= BIT(slot);
  snapshot->deficit[slot] = (s32)get_unaligned_le32(group + 176);
  snapshot->quantum[slot] = get_unaligned_le32(group + 172);
  if (snapshot->quantum[slot] != (byte_mode ? 128 + slot * 64 : 2 + slot)) return -EBADMSG;
  if (!!get_unaligned_le32(group + 188) != (nodes[FIFO_A + slot].parent == GROUP_A + slot))
   return -EBADMSG;
 }
 sentinel = snapshot->root_address + 164;
 entry = get_unaligned_le32(view->wrr_root + 164);
 previous = sentinel;
 for (i = 0; entry != sentinel && i < 3; i++) {
  found = 3;
  for (j = 0; j < 3; j++) if (entry == snapshot->group_address[j] + 164) found = j;
  if (found == 3) return -EBADMSG;
  group = view->wrr_group[found];
  if (get_unaligned_le32(group + 168) != previous || !group[192]) return -EBADMSG;
  tag = get_unaligned_le32(group + 16);
  for (j = 0; j < i; j++) if (snapshot->active_tags[j] == tag) return -ELOOP;
  snapshot->active_tags[i] = tag;
  previous = entry;
  entry = get_unaligned_le32(group + 164);
 }
 snapshot->active_count = i;
 if (entry != sentinel || get_unaligned_le32(view->wrr_root + 168) != previous ||
     get_unaligned_le32(view->wrr_root + 180) != i) return -EBADMSG;
 return 0;
}

/* Exact firmware recurrence over real stored lengths; this is a candidate
 * same-law continuation and is never labelled upstream baseline. */
static int wrr_choose(struct wrr_cpu *state)
{
 u32 slot, id, rotations = 0;

 while (state->active) {
  slot = state->order[0];
  if (state->deficit[slot] < 0) {
   if (++rotations > 256) return -ERANGE;
   state->deficit[slot] += byte_mode ? 128 + slot * 64 : 2 + slot;
   if (state->active == 2) {
    state->order[0] = state->order[1];
    state->order[1] = slot;
   }
   continue;
  }
  if (state->position[slot] >= 8) return -EBADMSG;
  id = slot * 8 + state->position[slot]++;
  if (state->position[slot] == 8) {
   state->active--;
   if (state->active) state->order[0] = state->order[1];
  }
  state->deficit[slot] -= byte_mode ? lengths[id] : 1;
  return id;
 }
 return -ENOENT;
}

static int wrr_prepare(void)
{
 struct qdx_owner owner = { .module = THIS_MODULE, .object = snapshots };
 __le32 assignment[2] = {}, next = cpu_to_le32(156);
 struct { __le32 point; __le16 size, offset; } mirror_cfg = {
  cpu_to_le32(1), cpu_to_le16(280), 0,
 };
 unsigned int i;
 int error;

 if (pinned || closed || byte_mode > 1) return -EPERM;
 if (!try_module_get(THIS_MODULE)) return -ENODEV;
 pinned = true;

 port = dev_get_by_name(&init_net, "lan2");
 conduit = dev_get_by_name(&init_net, "eth0");
 if (!port || !conduit || !netif_running(port) || !netif_running(conduit)) return -ENODEV;
 if (!rtnl_dereference(port->qdisc) ||
     strcmp(rtnl_dereference(port->qdisc)->ops->id, "noqueue") ||
     rtnl_dereference(conduit->rx_handler)) return -EBUSY;
 physical_service = qdx_service_get(port, QDX_SERVICE_SHAPER);
 if (IS_ERR(physical_service)) { error = PTR_ERR(physical_service); physical_service = NULL; return error; }
 physical = qdx_endpoint_get(physical_service, port);
 if (IS_ERR(physical)) { error = PTR_ERR(physical); physical = NULL; return error; }
 error = qdx_endpoint_ifnum(physical, &physical_ifnum);
 if (error || physical_ifnum != 4) return error ?: -EXDEV;
 error = netdev_rx_handler_register(conduit, wrr_receive, NULL);
 if (error) return error;
 hook = true;
 mirror_service = qdx_service_get(port, QDX_SERVICE_MIRROR);
 if (IS_ERR(mirror_service)) { error = PTR_ERR(mirror_service); mirror_service = NULL; return error; }
 mirror = qdx_endpoint_alloc(mirror_service, 65);
 if (IS_ERR(mirror)) { error = PTR_ERR(mirror); mirror = NULL; return error; }
 error = qdx_endpoint_wait(mirror, jiffies + msecs_to_jiffies(WAIT_MS));
 if (!error) error = qdx_endpoint_ifnum(mirror, &mirror_ifnum);
 if (error) return error;
 receiver = qdx_endpoint_receive_register(mirror, QDX_RECEIVE_PACKET, &owner, &copy_ops);
 if (IS_ERR(receiver)) { error = PTR_ERR(receiver); receiver = NULL; return error; }
 error = wrr_command(false, 6, assignment, sizeof(assignment));
 for (i = 0; !error && i < NODES; i++) error = wrr_tc(0, i, 0, 0);
 if (!error) error = wrr_tc(10, FQ, 0, 0);
 if (error) return error;
 if (memory_size != 72) return -EPROTO;
 table = qdx_diag_fq_table_alloc(physical_service, &owner);
 if (IS_ERR(table)) { error = PTR_ERR(table); table = NULL; return error; }
 error = wrr_tc(7, FQ, 0, 0);
 for (i = FIFO_A; !error && i <= PROBE; i++) error = wrr_tc(7, i, 32, 1);
 for (i = ANCHOR; !error && i <= GROUP_B; i++) error = wrr_tc(5, ROOT, i, 0);
 if (!error) error = wrr_tc(7, ROOT, byte_mode, 0);
 if (!error) error = wrr_tc(7, ANCHOR, 1, 0);
 if (!error) error = wrr_tc(7, GROUP_A, byte_mode ? 128 : 2, 0);
 if (!error) error = wrr_tc(7, GROUP_B, byte_mode ? 192 : 3, 0);
 if (!error) error = wrr_tc(5, ANCHOR, FQ, 0);
 if (!error) error = wrr_tc(5, GROUP_A, FIFO_A, 0);
 if (!error) error = wrr_tc(5, GROUP_B, FIFO_B, 0);
 if (!error) error = wrr_tc(5, OUTER, ROOT, 0);
 if (!error) error = wrr_tc(7, MARKER, 8, 1);
 if (!error) error = wrr_tc(5, OUTER, MARKER, 2);
 if (!error) error = wrr_tc(3, OUTER, 0, 0);
 if (!error) error = wrr_command(true, 0, &mirror_cfg, sizeof(mirror_cfg));
 if (!error) error = wrr_command(true, 3, &next, sizeof(next));
 if (!error) error = wrr_command(true, 1, NULL, 0);
 if (error) return error;
 phase = 0;
 prepared = true;
 return 0;
}

static int wrr_load(void)
{
 unsigned int i;
 int error;
 if (!prepared || loaded || request || admission_stage != 4 || nodes[ROOT].parent != -1)
  return -EPERM;
 loaded = true; phase = 1;
 error = wrr_gauge(FIFO_A, 8);
 if (!error) error = wrr_gauge(FIFO_B, 8);
 if (!error) error = wrr_marker();
 if (error) return error;
 for (i = 0; i < 2; i++) {
  anchor_packets[i].control = true;
  error = wrr_packet_create(&anchor_packets[i], i, 128, i);
  if (!error) error = wrr_submit(FQ, &anchor_packets[i]);
  if (error) return error;
 }
 error = wrr_close_anchor();
 if (!error) error = wrr_snapshot(0);
 if (error) return error;
 if (snapshots[0].active_count != 3 ||
     snapshots[0].active_tags[0] != nodes[GROUP_A].tag ||
     snapshots[0].active_tags[1] != nodes[GROUP_B].tag ||
     snapshots[0].active_tags[2] != nodes[ANCHOR].tag ||
     snapshots[0].deficit[0] == snapshots[0].deficit[1]) return -EBADMSG;
 exported = true;
 return 0;
}


static int wrr_recall(void)
{
 unsigned int slot, i;
 int error;
 if (!exported || recalled || request) return -EPERM;
 phase = 2;
 error = wrr_tc(6, ROOT, ANCHOR, 0);
 for (slot = 0; !error && slot < 2; slot++) {
  recalled_leaf = slot; reinit_completion(&recall_done);
  error = wrr_tc(6, GROUP_A + slot, FIFO_A + slot, 0);
  if (!error) error = wrr_tc(5, OUTER, FIFO_A + slot, 1);
  if (!error && !wait_for_completion_timeout(&recall_done, msecs_to_jiffies(WAIT_MS))) error = -ETIMEDOUT;
  if (!error) error = wrr_gauge(FIFO_A + slot, 0);
  if (!error) error = wrr_marker();
  if (!error) error = wrr_tc(6, OUTER, FIFO_A + slot, 0);
 }
 if (error) return error;
 if (recall_count != 16) return -EBADMSG;
 for (i = 0; i < 16; i++)
  if (!packets[i].skb || packets[i].loaned || packets[i].returns != 1 || recall_order[i] != i)
   return -EBADMSG;
 recalled = true;
 return 0;
}


static int wrr_cpu_continue(void)
{
 struct wrr_cpu model, zero;
 unsigned int i;
 int id;

 if (!recalled || cpu_selected || request) return -EPERM;
 cpu = (struct wrr_cpu) {
  .deficit = { snapshots[0].deficit[0], snapshots[0].deficit[1] },
  .order = { 0, 1 }, .active = 2,
 };
 model = cpu;
 zero = cpu;
 zero.deficit[0] = zero.deficit[1] = 0;
 for (i = 0; i < 16; i++) {
  id = wrr_choose(&model);
  if (id < 0) return id;
  expected[i] = id;
  id = wrr_choose(&zero);
  if (id < 0) return id;
  fresh[i] = id;
 }
 if (!memcmp(expected, fresh, sizeof(expected))) return -ENODATA;
 phase = 3;
 for (i = 0; i < 3; i++) {
  id = wrr_choose(&cpu);
  if (id < 0 || id != expected[i] || !packets[id].skb) return -EBADMSG;
  selected_mask |= BIT(id);
 }
 cpu_selected = true;
 return 0;
}

/* Only real Ethernet-sized private frames program the unreachable executor.
 * Data packets remain CPU-owned and the data-group edges are never recreated. */
static int wrr_program_phase(u32 slot, s32 current_phase, s32 target)
{
 u32 amount, length, quantum;
 int error;

 error = wrr_tc(5, GROUP_A + slot, PROBE, 0);
 if (error) return error;
 if (current_phase < 0) {
  quantum = -current_phase;
  error = wrr_tc(7, ROOT, 0, 0);
  if (!error) error = wrr_tc(7, GROUP_A + slot, quantum, 0);
  if (!error) error = wrr_private(PROBE, 128);
 } else {
  amount = current_phase + 1;
  error = wrr_tc(7, ROOT, 1, 0);
  while (!error && amount >= 128) {
   length = min_t(u32, amount, FRAME_MAX);
   error = wrr_private(PROBE, length);
   amount -= length;
  }
  if (!error) error = wrr_tc(7, ROOT, 0, 0);
  while (!error && amount--) error = wrr_private(PROBE, 128);
 }
 if (error) return error;
 if (target >= -1) {
  error = wrr_tc(7, ROOT, 0, 0);
  if (!error) error = wrr_tc(7, GROUP_A + slot, target + 2, 0);
  if (!error) error = wrr_private(PROBE, 128);
 } else {
  length = max_t(u32, 128, -target);
  if (length > FRAME_MAX) return -ERANGE;
  error = wrr_tc(7, ROOT, 1, 0);
  if (!error) error = wrr_tc(7, GROUP_A + slot, target + length + 1, 0);
  if (!error) error = wrr_private(PROBE, length);
 }
 if (!error) error = wrr_tc(6, GROUP_A + slot, PROBE, 0);
 return error;
}

static int wrr_rebuild(void)
{
 unsigned int i, slot, id;
 int error;

 if (!cpu_selected || rebuilt || request || cpu.active != 2) return -EPERM;
 phase = 3;
 error = wrr_tc(5, OUTER, ROOT, 0);
 for (slot = 0; !error && slot < 2; slot++)
  error = wrr_program_phase(slot, snapshots[0].deficit[slot], cpu.deficit[slot]);
 if (!error) error = wrr_tc(6, OUTER, ROOT, 0);
 if (!error) error = wrr_tc(7, ROOT, byte_mode, 0);
 for (slot = 0; !error && slot < 2; slot++)
  error = wrr_tc(7, GROUP_A + slot, byte_mode ? 128 + slot * 64 : 2 + slot, 0);
 if (!error) error = wrr_tc(5, ROOT, ANCHOR, 0);
 if (!error) error = wrr_tc(7, ANCHOR, 1, 0);
 if (!error) error = wrr_snapshot(1);
 if (error) return error;
 for (slot = 0; slot < 2; slot++)
  if (snapshots[1].deficit[slot] != cpu.deficit[slot]) return -EBADMSG;
 if (snapshots[1].active_count != 1 || snapshots[1].active_tags[0] != nodes[ANCHOR].tag)
  return -EBADMSG;
 error = wrr_tc(6, ROOT, ANCHOR, 0);
 for (i = 0; !error && i < cpu.active; i++) {
  slot = cpu.order[i];
  error = wrr_tc(5, GROUP_A + slot, FIFO_A + slot, 0);
  for (id = slot * 8 + cpu.position[slot]; !error && id < slot * 8 + 8; id++)
   error = wrr_submit(FIFO_A + slot, &packets[id]);
  if (nodes[FIFO_A + slot].path && !nodes[FIFO_A + slot].path_closed) {
   qdx_tx_path_get(nodes[FIFO_A + slot].path); qdx_tx_release(nodes[FIFO_A + slot].path);
   nodes[FIFO_A + slot].path_closed = true;
  }
  if (!error) error = wrr_gauge(FIFO_A + slot, 8 - cpu.position[slot]);
 }
 if (!error) error = wrr_tc(5, ROOT, ANCHOR, 0);
 if (!error) error = wrr_tc(7, ANCHOR, 1, 0);
 if (!error) error = wrr_snapshot(2);
 if (error) return error;
 for (i = 0; i < 2; i++)
  if (snapshots[2].deficit[i] != cpu.deficit[i] ||
      snapshots[2].active_tags[i] != nodes[GROUP_A + cpu.order[i]].tag) return -EBADMSG;
 if (snapshots[2].active_count != 3 || snapshots[2].active_tags[2] != nodes[ANCHOR].tag)
  return -EBADMSG;
 error = wrr_tc(6, ROOT, ANCHOR, 0);
 if (error) return error;
 rebuilt = true;
 return 0;
}

static int wrr_serve(void)
{
 unsigned int i;
 int error;

 if (!rebuilt || passed || request) return -EPERM;
 phase = 4;
 reinit_completion(&resume_done);
 error = wrr_tc(5, OUTER, ROOT, 0);
 if (!error) error = wrr_join(FIFO_A);
 if (!error) error = wrr_join(FIFO_B);
 if (!error) error = wrr_gauge(FIFO_A, 0);
 if (!error) error = wrr_gauge(FIFO_B, 0);
 if (error) return error;
 if (!wait_for_completion_timeout(&resume_done, msecs_to_jiffies(WAIT_MS))) return -ETIMEDOUT;
 if (resume_count != 13 || memcmp(resume_order, expected + 3, sizeof(resume_order)))
  return -EBADMSG;
 for (i = 0; i < 16; i++)
  if (!packets[i].skb || packets[i].loaned ||
      packets[i].returns != ((selected_mask & BIT(i)) ? 1 : 2)) return -EBADMSG;
 error = wrr_marker();
 if (error) return error;
 passed = true;
 return 0;
}


static int wrr_wire(void)
{
 struct sk_buff *skb;
 struct wrr_packet *packet = NULL;
 int status;
 if (!passed || bad_packets || !skb_queue_empty(&quarantine)) return -EPERM;
 if (hook) { netdev_rx_handler_unregister(conduit); hook = false; }
 /* The runner has already restored both capture and output before this call. */
 while (native_sent < 7 + 16) {
  if (native_sent < 7) {
   skb = warm_prefix[native_sent];
   if (!skb) return -EBADMSG;
   warm_prefix[native_sent] = NULL;
  } else {
   packet = &packets[expected[native_sent - 7]];
   skb = packet->skb;
   if (!skb || packet->loaned) return -EBADMSG;
   packet->skb = NULL;
  }
  skb->dev = port; skb->protocol = htons(ETH_P_IP); skb->ip_summed = CHECKSUM_NONE;
  skb_reset_mac_header(skb); skb_set_network_header(skb, ETH_HLEN);
  skb_set_transport_header(skb, ETH_HLEN + 20); skb_set_queue_mapping(skb, 0);
  status = dev_queue_xmit(skb); native_sent++;
  if (net_xmit_eval(status)) return status < 0 ? status : -ENOBUFS;
 }
 wire_complete = true;
 return 0;
}

static int wrr_restore(void)
{
 __le32 unassign = cpu_to_le32(shaper);
 unsigned int i;
 int error;

 if (!pinned) return 0;
 /* No purge or synthetic disposal is a recovery for a failed logical run. */
 if ((loaded && (!passed || !wire_complete || native_sent != 23)) || request || fault || bad_packets || disposals || copy_operation)
  return -EBUSY;
 for (i = 0; i < 16; i++) if (packets[i].loaned || packets[i].skb) return -EBUSY;
 for (i = 0; i < ARRAY_SIZE(warm_prefix); i++) if (warm_prefix[i]) return -EBUSY;
 if (!skb_queue_empty(&quarantine) || marker_packet.loaned || private_packet.loaned)
  return -EBUSY;
 /* A source batch can already be admitted before load sets its flag. The
  * runner seals that source before teardown; read the actual leaf gauges. */
 for (i = FIFO_A; i <= FIFO_B; i++) {
  if (!nodes[i].allocated) continue;
  error = wrr_gauge(i, 0);
  if (error) return error;
 }
 closed = true;
 for (i = 0; i < NODES; i++) {
  if (i == FQ) continue;
  error = wrr_join(i);
  if (error) return error;
 }
 for (i = NODES; i-- > 0;) {
  if (nodes[i].parent == -1) continue;
  error = wrr_tc(6, nodes[i].parent, i, 0);
  if (error) return error;
 }
 if (nodes[FQ].allocated) {
  anchor_retiring = true;
  error = wrr_tc(1, FQ, 0, 0);
  if (!error) error = wrr_join(FQ);
  if (error) return error;
  controls_retired = anchor_packets[0].loaned + anchor_packets[1].loaned;
  anchor_packets[0].loaned = anchor_packets[1].loaned = false;
 }
 for (i = NODES; i-- > 0;) {
  if (!nodes[i].allocated) continue;
  error = wrr_tc(1, i, 0, 0);
  if (error) return error;
 }
 if (enabled) {
  error = wrr_command(true, 2, NULL, 0);
  if (error) return error;
 }
 if (next_set) {
  error = wrr_command(true, 4, NULL, 0);
  if (error) return error;
 }
 if (assigned) {
  error = wrr_command(false, 8, &unassign, sizeof(unassign));
  if (error) return error;
 }
 if (table && !qdx_diag_fq_table_idle(table)) return -EBUSY;
 if (mirror && !mirror_retired) {
  error = qdx_endpoint_wait(mirror, jiffies);
  if (!error) error = qdx_endpoint_retire(mirror);
  if (error) return error;
  mirror_retired = true;
 }
 if (receiver) {
  error = qdx_endpoint_receive_unregister(receiver);
  if (error) return error;
  receiver = NULL;
 }
 if (hook) { netdev_rx_handler_unregister(conduit); hook = false; }
 synchronize_net();
 for (i = 0; i < 16; i++) { dev_kfree_skb(packets[i].skb); packets[i].skb = NULL; }
 for (i = 0; i < 2; i++) { dev_kfree_skb(anchor_packets[i].skb); anchor_packets[i].skb = NULL; }
 dev_kfree_skb(private_packet.skb); private_packet.skb = NULL;
 if (mirror)
  qdx_endpoint_put(mirror);
 mirror = NULL;
 if (physical)
  qdx_endpoint_put(physical);
 physical = NULL;
 if (table) { qdx_dma_release(table); table = NULL; }
 if (mirror_service)
  qdx_service_put(mirror_service);
 mirror_service = NULL;
 if (physical_service)
  qdx_service_put(physical_service);
 physical_service = NULL;
 if (conduit) { dev_put(conduit); conduit = NULL; }
 if (port) dev_put(port);
 port = NULL;
 pinned = false;
 module_put(THIS_MODULE);
 return 0;
}

static int wrr_status_show(struct seq_file *seq, void *unused)
{
 unsigned int i, j, offset, width;

 mutex_lock(&control_lock);
 seq_printf(seq, "physical run=%llu sip=%08x dip=%08x sport=%u dport=%u vid=%u warm=%u stage=%u default_node=%u observed_port=%u hook=%u quarantine=%u markers=%u waiting=%u native_sent=%u wire_complete=%u\n",
  run_id, source_ip, target_ip, source_port, target_port, private_vid, warm_count,
  admission_stage, source_default, observed_port, hook, skb_queue_len(&quarantine), markers,
  marker_wait, native_sent, wire_complete);
 seq_printf(seq, "mode=%u pinned=%u prepared=%u loaded=%u exported=%u recalled=%u cpu_selected=%u rebuilt=%u passed=%u closed=%u fault=%u assigned=%u enabled=%u next_set=%u request=%u error=%d phase=%u physical=%u mirror=%u shaper=%u table_idle=%u copies=%u copy_ns=%llu commands=%u private_frames=%u bad=%u disposals=%u controls_retired=%u unexpected_clones=%u selected_mask=%x resumed=%u\n",
  byte_mode, pinned, prepared, loaded, exported, recalled, cpu_selected, rebuilt, passed,
  closed, fault, assigned, enabled, next_set, !!request, last_error, phase, physical_ifnum,
  mirror_ifnum, shaper, table ? qdx_diag_fq_table_idle(table) : true, copy_count,
  copy_time_ns, command_count, private_count, bad_packets, disposals, controls_retired,
  unexpected_clones, selected_mask, resume_count);
 seq_printf(seq, "request_id=%llu outcome=%u firmware_error=%u declared=%zu received=%zu published=%u exposure_ended=%u pending_opcode=%u pending_node=%u pending_sub=%u\n",
  result.id, result.outcome, result.firmware_error, result.declared_len, result.received_len,
  result.published, result.exposure_ended, pending_opcode, pending_node,
  le32_to_cpu(pending_message.command));
 for (i = 0; i < NODES; i++)
  seq_printf(seq, "node=%u tag=%08x kind=%u allocated=%u parent=%d band=%u gauge=%u bytes=%u admitted=%llu selected=%llu dropped=%llu path=%u path_closed=%u drained=%u\n",
   i, nodes[i].tag, nodes[i].kind, nodes[i].allocated, nodes[i].parent, nodes[i].band,
   nodes[i].gauge, nodes[i].bytes, nodes[i].admitted, nodes[i].selected, nodes[i].dropped,
   !!nodes[i].path, nodes[i].path_closed, nodes[i].path ? qdx_tx_drained(nodes[i].path) : true);
 for (i = 0; i < 3; i++) {
  seq_printf(seq, "snapshot=%u root=%08x valid=%x active=%u deficit_a=%d deficit_b=%d quantum_a=%u quantum_b=%u tags=%08x,%08x,%08x\n",
   i, snapshots[i].root_address, snapshots[i].view.wrr_valid, snapshots[i].active_count,
   snapshots[i].deficit[0], snapshots[i].deficit[1], snapshots[i].quantum[0],
   snapshots[i].quantum[1], snapshots[i].active_tags[0], snapshots[i].active_tags[1], snapshots[i].active_tags[2]);
  for (offset = 0; offset < 188; offset += width) {
   width = min_t(u32, 64, 188 - offset);
   seq_printf(seq, "snapshot_root_bytes=%u offset=%u data=%*phN\n",
    i, offset, width, snapshots[i].view.wrr_root + offset);
  }
  for (j = 0; j < 3; j++) {
   for (offset = 0; offset < 196; offset += width) {
    width = min_t(u32, 64, 196 - offset);
    seq_printf(seq, "snapshot_group_bytes=%u slot=%u address=%08x offset=%u data=%*phN\n",
     i, j, snapshots[i].group_address[j], offset, width, snapshots[i].view.wrr_group[j] + offset);
   }
  }
 }
 seq_printf(seq, "cpu deficit=%d,%d position=%u,%u order=%u,%u active=%u\n",
  cpu.deficit[0], cpu.deficit[1], cpu.position[0], cpu.position[1], cpu.order[0], cpu.order[1], cpu.active);
 for (i = 0; i < 16; i++)
  seq_printf(seq, "packet=%u length=%u held=%u loaned=%u returns=%u expected=%u fresh=%u\n",
   i, packets[i].length, !!packets[i].skb, packets[i].loaned, packets[i].returns, expected[i], fresh[i]);
 for (i = 0; i < min_t(u32, recall_count, ARRAY_SIZE(recall_order)); i++)
  seq_printf(seq, "recalled_index=%u id=%u\n", i, recall_order[i]);
 for (i = 0; i < min_t(u32, resume_count, ARRAY_SIZE(resume_order)); i++)
  seq_printf(seq, "resumed_index=%u id=%u\n", i, resume_order[i]);
 for (i = 0; i < min_t(u32, event_count, ARRAY_SIZE(events)); i++)
  seq_printf(seq, "event=%u phase=%u id=%u length=%u ns=%llu type=%u ifnum=%u\n", i,
   events[i].phase, events[i].id, events[i].length, events[i].time_ns, events[i].type, events[i].ifnum);
 mutex_unlock(&control_lock);
 return 0;
}
DEFINE_SHOW_ATTRIBUTE(wrr_status);

/* Each command follows a completed finite source batch. The runner seals the
 * source before load, keeps the output sink held, and records source PCAP. */
static int wrr_source_stage(u32 step)
{
 u32 target;
 int error;
 if (!prepared || loaded || request || bad_packets) return -EPERM;
 if (step == 0) {
  if (admission_stage || warm_count) return -EPERM;
  target = FIFO_A;
 } else if (step == 1) {
  if (admission_stage != 1 || warm_count != 5) return -EPERM;
  error = wrr_gauge(FIFO_A, 0);
  if (error) return error;
  target = FIFO_B;
 } else if (step == 2) {
  if (admission_stage != 2 || warm_count != 7) return -EPERM;
  error = wrr_gauge(FIFO_B, 0);
  if (!error) error = wrr_tc(6, OUTER, ROOT, 0);
  if (!error) error = wrr_marker();
  if (error) return error;
  target = FIFO_A;
 } else if (step == 3) {
  if (admission_stage != 3 || nodes[ROOT].parent != -1) return -EPERM;
  error = wrr_gauge(FIFO_A, 8);
  if (error) return error;
  target = FIFO_B;
 } else return -EINVAL;
 error = wrr_tc(2, target, 0, 0);
 if (error) return error;
 source_default = target; admission_stage = step + 1;
 return 0;
}

static ssize_t wrr_control_write(struct file *file, const char __user *user,
 size_t count, loff_t *offset)
{
 char command[32];
 int error;

 if (!allow_writes || !count || count >= sizeof(command)) return -EPERM;
 if (copy_from_user(command, user, count)) return -EFAULT;
 command[count] = 0;
 strim(command);
 rtnl_lock();
 mutex_lock(&control_lock);
 if (!strcmp(command, "poll")) error = wrr_wait_command();
 else if (!strcmp(command, "restore")) error = wrr_restore();
 else if (last_error || fault || request || closed) error = -EBUSY;
 else if (!strcmp(command, "prepare")) error = wrr_prepare();
 else if (!strcmp(command, "warm-a")) error = wrr_source_stage(0);
 else if (!strcmp(command, "warm-b")) error = wrr_source_stage(1);
 else if (!strcmp(command, "load-a")) error = wrr_source_stage(2);
 else if (!strcmp(command, "load-b")) error = wrr_source_stage(3);
 else if (!strcmp(command, "load")) error = wrr_load();
 else if (!strcmp(command, "wire")) error = wrr_wire();
 else if (!strcmp(command, "recall")) error = wrr_recall();
 else if (!strcmp(command, "cpu")) error = wrr_cpu_continue();
 else if (!strcmp(command, "rebuild")) error = wrr_rebuild();
 else if (!strcmp(command, "serve")) error = wrr_serve();
 else error = -EINVAL;
 last_error = error;
 mutex_unlock(&control_lock);
 rtnl_unlock();
 return error ?: count;
}
static const struct file_operations wrr_control_ops = {
 .owner = THIS_MODULE, .write = wrr_control_write,
};
static int __init wrr_init(void)
{
 if (!source_port || source_port > U16_MAX || !target_port || target_port > U16_MAX ||
     !private_vid || private_vid >= 4095) return -EINVAL;
 skb_queue_head_init(&quarantine);
 directory = debugfs_create_dir("qdx_physical_wrr_diag", NULL);
 if (IS_ERR(directory)) return PTR_ERR(directory);
 debugfs_create_file("status", 0400, directory, NULL, &wrr_status_fops);
 debugfs_create_file("control", 0200, directory, NULL, &wrr_control_ops);
 return 0;
}
static void __exit wrr_exit(void)
{
 WARN_ON(pinned || request || table || receiver || physical || mirror || copy_operation || hook ||
         !skb_queue_empty(&quarantine));
 debugfs_remove_recursive(directory);
}
module_init(wrr_init);
module_exit(wrr_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Isolated physical actual WRR history and finite CPU continuation diagnostic");
