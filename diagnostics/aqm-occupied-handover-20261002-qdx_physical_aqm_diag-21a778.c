// SPDX-License-Identifier: GPL-2.0-only
/* Isolated physical AQM occupied history continuation. Not a qdisc or CPU baseline. */
#include <linux/build_bug.h>
#include <linux/completion.h>
#include <linux/debugfs.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/etherdevice.h>
#include <linux/in.h>
#include <linux/iopoll.h>
#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/qdx.h>
#include <linux/qdx_diag_aqm.h>
#include <linux/dsa/oob.h>
#include <linux/if_vlan.h>
#include <linux/rtnetlink.h>
#include <net/pkt_sched.h>
#include <linux/seq_file.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/unaligned.h>
#include <net/checksum.h>
#include <net/net_namespace.h>

#define WAIT_MS 6000
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
struct aqm_message { __le32 command, response, value[27]; };
static_assert(sizeof(struct aqm_message) == 116);

enum node_id { OUTER, INNER, FQ, LEAF_A, LEAF_B, LEAF_C, LEAF_D, MARKER, NODES };
struct aqm_node {
 u32 tag, kind, gauge, bytes;
 u64 admitted, selected, dropped;
 bool allocated;
 int parent;
 u32 band;
 struct qdx_tx_path *path;
 bool path_closed;
};
struct aqm_packet {
 struct sk_buff *skb;
 u32 id, length, returns;
 bool loaned, control, copied, expected_drop, cpu_selected;
 u8 expected[FRAME_MAX];
};
struct aqm_snapshot {
 struct qdx_diag_fq_view view;
 struct qdx_diag_aqm_view aqm;
 struct qdx_diag_aqm_state state;
 u32 ids[16], lengths[16], classes[16];
 u64 ages[16], clock;
};
struct aqm_event { u32 stage, id, type, ifnum, positive; u64 host_ns; };
struct aqm_copy_round {
 struct completion original_done, clone_done;
 u32 originals, clones, length;
 bool original_valid, clone_valid;
 u8 bytes[FRAME_MAX];
};
extern struct qdx_dma *qdx_diag_fq_table_alloc(struct qdx_service *, const struct qdx_owner *);
extern bool qdx_diag_fq_table_idle(struct qdx_dma *);
extern struct qdx_ready qdx_diag_fq_table_copy(struct qdx_packet_op *, struct qdx_dma *,
 const struct qdx_packet_recipient *);
static bool allow_writes;
static unsigned int algorithm;
module_param(allow_writes, bool, 0400);
module_param(algorithm, uint, 0400);
MODULE_PARM_DESC(algorithm, "1=two-class WRED, 2=plain CoDel; finite physical handover");
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
static struct aqm_message pending_message;
static u32 pending_opcode, pending_length, pending_node, pending_arg, pending_extra;
static bool pending_mirror;
static struct aqm_node nodes[NODES];
static struct aqm_packet packets[20], anchor_packets[2];
static struct aqm_snapshot snapshots[5], discovery;
static struct qdx_diag_aqm_state cpu_state;
static struct aqm_copy_round copy_round;
static struct aqm_event events[96];
static u32 event_count, bad_packets, backing_retired, controls_retired;
static u32 unexpected_clones, stage, leaf = LEAF_A, memory_size, command_count, copy_count;
static u32 physical_ifnum = U32_MAX, mirror_ifnum = U32_MAX, shaper, queue[16], queue_count;
static u32 resumed_victims, resumed_order[16], resumed_count;
static u64 copy_time_ns, copy_started_ns, cpu_now, resume_now, publish_ns;
static u32 rebuild_next = 1, anchor_accepted;
static bool old_backing_retired, leaf_reallocated, serve_prepared, serve_published;
static bool pinned, assigned, enabled, next_set, prepared, loaded, exported, adopted;
static bool cpu_selected, rebuilt, served, passed, closed, fault;
static bool mirror_retired, temporary_config;
static int last_error;
/* Physical source identities use existing packet-probe wire encoding. */
static unsigned long long run_id = 22100361;
static unsigned int source_ip = 0xc0a80190, target_ip = 0xc0a80173;
static unsigned int source_port = 41000, target_port = 41001, private_vid = 4000;
module_param(run_id, ullong, 0400);
module_param(source_ip, uint, 0400);
module_param(target_ip, uint, 0400);
module_param(source_port, uint, 0400);
module_param(target_port, uint, 0400);
module_param(private_vid, uint, 0400);
static struct net_device *conduit;
static struct sk_buff_head quarantine;
static struct aqm_packet marker_packet;
static DECLARE_COMPLETION(marker_done);
static DECLARE_COMPLETION(resume_done);
static u32 marker_wait, markers, native_sent, observed_port = U32_MAX;
static u32 source_default = U32_MAX, admission_drops, probe_drops;
static u32 rebuild_stage, rebuilt_submitted, snapshot_kind = U32_MAX, snapshot_index;
static u64 first_return_ns, last_return_ns;
static bool hook, wire_complete, source_opened, probes_checked;

static int aqm_wait_command(void)
{
 u8 reply[116] = {};
 struct aqm_message *message = (void *)reply;
 struct aqm_node *node = &nodes[pending_node];
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

static int aqm_command(bool mirror_command, u32 opcode, const void *payload, size_t length)
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
 return aqm_wait_command();
}


static int aqm_tc(u32 sub, u32 id, u32 arg, u32 extra)
{
 struct aqm_message message = {};
 u8 *wire = (void *)&message;
 u32 minimum, maximum;

 if (id >= NODES || ((sub == 5 || sub == 6) && arg >= NODES)) return -EINVAL;
 message.command = cpu_to_le32(sub);
 message.value[0] = cpu_to_le32(nodes[id].tag);
 if (sub == 0) {
  message.value[0] = cpu_to_le32(nodes[id].kind);
  message.value[1] = cpu_to_le32(nodes[id].tag);
 } else if (sub == 5 || sub == 6) {
  message.value[1] = cpu_to_le32(sub == 6 ? nodes[arg].band : nodes[arg].tag);
  message.value[2] = cpu_to_le32(extra);
 } else if (sub == 7 && id == FQ) {
  put_unaligned_le32(32, wire + 12);
  put_unaligned_le16(65535, wire + 16);
  put_unaligned_le16(32767, wire + 18);
  put_unaligned_le16(1500, wire + 20);
  put_unaligned_le32(2, wire + 24);
  put_unaligned_le32((u32)qdx_dma_address(table), wire + 28);
  put_unaligned_le32(TABLE_LEN, wire + 32);
  put_unaligned_le32(128, wire + 36);
  qdx_dma_expose(table);
 } else if (sub == 7 && id == MARKER) {
  put_unaligned_le32(8, wire + 12);
  put_unaligned_le32(1, wire + 16);
 } else if (sub == 7 && id >= LEAF_A && id <= LEAF_D) {
  put_unaligned_le32(65536, wire + 12);
  if (algorithm == 2) {
   put_unaligned_le32(32, wire + 12);
   put_unaligned_le16(101, wire + 16);
   put_unaligned_le16(37, wire + 18);
   put_unaligned_le16(1500, wire + 20);
  } else {
   /* WRED topology is a distinct command; class CONFIG must follow it. */
   put_unaligned_le32(algorithm == 1 && !arg ? 2 : 0, wire + 20);
   put_unaligned_le32(algorithm == 1 ? 1 : 0, wire + 24);
   put_unaligned_le32(algorithm == 1 ? arg : 0, wire + 28);
   put_unaligned_le32(arg == 2 ? 8 : 0, wire + 32);
   minimum = temporary_config ? U32_MAX - 2 : arg == 2 ? 5999 : 2999;
   maximum = minimum + 1;
   put_unaligned_le32(minimum, wire + 36);
   put_unaligned_le32(maximum, wire + 40);
   put_unaligned_le32(0, wire + 44);
   put_unaligned_le32(1, wire + 48);
  }
 }
 pending_message = message;
 pending_node = id;
 pending_arg = arg;
 pending_extra = extra;
 return aqm_command(false, 10, &message, sizeof(message));
}

static int aqm_configure(void)
{
 int error = aqm_tc(7, leaf, 0, 0);
 if (!error && algorithm == 1) error = aqm_tc(7, leaf, 1, 0);
 if (!error && algorithm == 1) error = aqm_tc(7, leaf, 2, 0);
 return error;
}


static rx_handler_result_t aqm_receive(struct sk_buff **pskb)
{
 struct sk_buff *skb = *pskb;
 const struct dsa_oob_tag_info *tag;
 struct aqm_packet *packet;
 u8 header[67];
 unsigned long flags;
 u32 id, packet_phase, group, expected_id;
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
 } else if (packet_phase != 1 || group != 1 || id >= 16 || stage != 4 ||
            resumed_count >= queue_count - (algorithm == 2 ? 2 : 1)) bad = true;
 else {
  expected_id = queue[resumed_count + (algorithm == 2 ? 2 : 1)];
  packet = &packets[id];
  if (id != expected_id || packet->skb || !packet->loaned || packet->expected_drop ||
      skb->len + VLAN_HLEN != packet->length ||
      memcmp(skb->data, packet->expected, skb->len)) bad = true;
  else {
   packet->skb = skb; packet->loaned = false; packet->returns++;
   resumed_order[resumed_count++] = id;
   last_return_ns = ktime_get_ns();
   if (!first_return_ns) first_return_ns = last_return_ns;
   if (resumed_count == queue_count - (algorithm == 2 ? 2 : 1))
    complete_all(&resume_done);
  }
 }
 if (bad) bad_packets++;
 if (!internal && event_count < ARRAY_SIZE(events))
  events[event_count++] = (struct aqm_event) { stage, id, packet_phase, group,
   !bad, ktime_get_ns() };
 else if (!internal) bad_packets++;
 spin_unlock_irqrestore(&result_lock, flags);
 if (bad) skb_queue_tail(&quarantine, skb);
 else if (internal) consume_skb(skb);
 return RX_HANDLER_CONSUMED;
}

static int aqm_packet_create(struct aqm_packet *packet, u32 id, u32 length, u32 bin)
{
 struct sk_buff *skb;
 u8 *data;
 u32 native_length = length - VLAN_HLEN;
 if (packet->skb || packet->loaned || length < 110 || length > FRAME_MAX) return -EINVAL;
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
 data[58] = packet == &marker_packet ? 255 : 253;
 put_unaligned_be32(0, data + 59); put_unaligned_be32(id, data + 63);
 put_unaligned(csum_fold(csum_partial(data + 14, 20, 0)), (__sum16 *)(data + 24));
 skb->dev = port; skb->protocol = htons(ETH_P_IP); skb_reset_mac_header(skb);
 packet->skb = skb; packet->id = id; packet->length = length;
 memcpy(packet->expected, data, native_length);
 return 0;
}



static int aqm_submit(u32 leaf, struct aqm_packet *packet)
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


static int aqm_join(u32 leaf)
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


static int aqm_gauge(u32 id, u32 expected_count)
{
 unsigned long deadline = jiffies + msecs_to_jiffies(WAIT_MS);
 int error;
 do {
  error = aqm_tc(4, id, 0, 0);
  if (error || bad_packets) return error ?: -EBADMSG;
  if (nodes[id].gauge == expected_count) return 0;
  usleep_range(1000, 1500);
 } while (time_before(jiffies, deadline));
 return -ETIMEDOUT;
}

static void aqm_copy_original(void *owner, struct sk_buff *original,
 struct sk_buff *returned, const struct qdx_rx_meta *meta, struct napi_struct *napi)
{
 copy_round.originals++;
 copy_round.original_valid = !original && !returned && meta &&
  meta->ifnum == READ_ONCE(mirror_ifnum) && meta->type == QDX_RECEIVE_PACKET;
 complete_all(&copy_round.original_done);
}

static void aqm_copy_clone(void *owner, struct sk_buff *skb,
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
static const struct qdx_receive_ops copy_ops = { .packet = aqm_copy_clone };

/* Complete only the already accepted copy. Its caller may then repeat a
 * read, but never treats a late snapshot as an executed queue mutation. */
static int aqm_copy_finish(void)
{
 bool idle, drained;
 int error;
 if (!copy_operation) return 0;
 qdx_packet_op_close(copy_operation);
 if (!wait_for_completion_timeout(&copy_round.original_done, msecs_to_jiffies(WAIT_MS)) ||
     !wait_for_completion_timeout(&copy_round.clone_done, msecs_to_jiffies(WAIT_MS)))
  return -ETIMEDOUT;
 error = read_poll_timeout(qdx_diag_fq_table_idle, idle, idle, 10,
  WAIT_MS * 1000, false, table);
 if (!error) error = read_poll_timeout(qdx_packet_op_drained, drained, drained, 10,
  WAIT_MS * 1000, false, copy_operation);
 if (error) return error;
 qdx_packet_op_put(copy_operation);
 copy_operation = NULL;
 if (copy_round.originals != 1 || copy_round.clones != 1 ||
     !copy_round.original_valid || !copy_round.clone_valid || unexpected_clones) {
  fault = true;
  return -EBADMSG;
 }
 copy_count++;
 copy_time_ns += ktime_get_ns() - copy_started_ns;
 return 0;
}

static int aqm_copy(struct qdx_diag_fq_view *view, enum qdx_diag_fq_range kind,
 u32 index, u32 length, void *destination)
{
 struct qdx_packet_recipient recipient = {
  .owner = { .module = THIS_MODULE, .object = snapshots }, .returned = aqm_copy_original,
 };
 struct qdx_ready ready;
 int error;

 if (nodes[INNER].parent != -1 || !nodes[FQ].path || !nodes[FQ].path_closed || copy_operation || request ||
     !qdx_diag_fq_table_idle(table) || length > sizeof(copy_round.bytes) || !enabled)
  return -EPERM;
 memset(&copy_round, 0, sizeof(copy_round));
 init_completion(&copy_round.original_done);
 init_completion(&copy_round.clone_done);
 copy_round.length = length;
 copy_operation = qdx_packet_op_prepare(mirror, COPY_TAG, QDX_RECEIVE_PACKET);
 if (IS_ERR(copy_operation)) { error = PTR_ERR(copy_operation); copy_operation = NULL; return error; }
 copy_started_ns = ktime_get_ns();
 if (kind == OWNED_TABLE) ready = qdx_diag_fq_table_copy(copy_operation, table, &recipient);
 else ready = qdx_diag_fq_owned_copy(copy_operation, table, NULL,
  view, kind, index, &recipient);
 if (ready.status != QDX_ACCEPTED) {
  qdx_packet_op_close(copy_operation);
  qdx_packet_op_put(copy_operation);
  copy_operation = NULL;
  return ready.error ?: -EAGAIN;
 }
 error = aqm_copy_finish();
 if (!error) memcpy(destination, copy_round.bytes, length);
 return error;
}

static int aqm_marker(void)
{
 u32 next = markers + 1;
 int error;
 if (marker_wait != markers || marker_packet.loaned) return -EBUSY;
 reinit_completion(&marker_done); marker_wait = next;
 error = aqm_packet_create(&marker_packet, next, 128, 0);
 if (!error) error = aqm_submit(MARKER, &marker_packet);
 if (!error) error = aqm_join(MARKER);
 if (error) return error;
 if (!wait_for_completion_timeout(&marker_done, msecs_to_jiffies(WAIT_MS))) return -ETIMEDOUT;
 marker_packet.loaned = false;
 return markers != next || bad_packets ? -EBADMSG : 0;
}

static int aqm_base(struct aqm_snapshot *snapshot)
{
 struct qdx_diag_fq_view *view = &snapshot->view;
 struct qdx_diag_aqm_view *aqm = &snapshot->aqm;
 u8 clock[24];
 unsigned int i;
 int error;

 memset(snapshot, 0, sizeof(*snapshot));
 aqm->plain = algorithm == 2;
 aqm->physical_rebuild = old_backing_retired ? nodes[leaf].path : NULL;
 view->aqm = aqm;
 error = aqm_copy(view, OWNED_TABLE, 0, TABLE_LEN, view->table);
 if (error) return error;
 dma_rmb();
 if (memcmp(view->table, qdx_dma_cpu(table), TABLE_LEN)) return -EBADMSG;
 for (i = 0; i < 2; i++)
  if (get_unaligned_le32(view->table + i * 72 + 24) != 1 ||
      get_unaligned_le32(view->table + i * 72 + 64) != 128) return -EBADMSG;
 error = aqm_copy(view, QDX_DIAG_FQ_NODE, 0, 280, view->node);
 if (error) return error;
 view->node_valid = true;
 error = aqm_copy(view, QDX_DIAG_AQM_SELECTOR, 0, 320, aqm->selector);
 if (error) return error;
 aqm->valid |= QDX_AQM_SELECTOR_VALID;
 error = aqm_copy(view, QDX_DIAG_AQM_NODE, 0, algorithm == 2 ? 280 : 520, aqm->node);
 if (error) return error;
 aqm->valid |= QDX_AQM_NODE_VALID;
 /* This validates the leaf's actual immutable identity before using fields. */
 error = aqm_copy(view, QDX_DIAG_AQM_CLOCK, 0, 24, clock);
 if (error) return error;
 snapshot->clock = get_unaligned_le64(clock + 16);
 if (!snapshot->clock || get_unaligned_le32(aqm->node + 16) != nodes[leaf].tag)
  return -EBADMSG;
 snapshot->state.count = get_unaligned_le32(aqm->node + (algorithm == 2 ? 180 : 172));
 if (algorithm == 2) {
  snapshot->state.codel_count = get_unaligned_le32(aqm->node + 188);
  snapshot->state.first_above = get_unaligned_le64(aqm->node + 192);
  snapshot->state.drop_next = get_unaligned_le64(aqm->node + 200);
  snapshot->state.delay_max = get_unaligned_le32(aqm->node + 208);
  snapshot->state.delay_min = get_unaligned_le32(aqm->node + 212);
  snapshot->state.dropping = aqm->node[218];
  if (get_unaligned_le16(aqm->node + 184) != 101 ||
      get_unaligned_le16(aqm->node + 186) != 37 ||
      get_unaligned_le16(aqm->node + 216) != 1500) return -EBADMSG;
 } else {
  for (i = 0; i < 7; i++) {
   snapshot->state.average[i] = get_unaligned_le32(aqm->node + 184 + 44 * i);
   snapshot->state.occupancy[i] = get_unaligned_le32(aqm->node + 216 + 44 * i);
  }
  snapshot->state.idle = get_unaligned_le64(aqm->node + 500);
  snapshot->state.active = aqm->node[508];
  if (get_unaligned_le32(aqm->node + 488) != (algorithm == 1 ? 2 : 0) ||
      aqm->node[496] || aqm->node[497] != (algorithm == 1)) return -EBADMSG;
 }
 return 0;
}

static int aqm_snapshot(unsigned int which, bool copy_payloads)
{
 struct aqm_snapshot *snapshot;
 struct qdx_diag_aqm_view *aqm;
 struct aqm_packet *packet;
 /* All three call sites run under control_lock; no callback uses these.
  * Module-owned scratch avoids a 3028-byte temporary kernel stack allocation. */
 static u8 payload[FRAME_MAX], native[FRAME_MAX];
 u32 i, count, address, stride, id, length, previous = 0;
 int error;
 if (which >= ARRAY_SIZE(snapshots) || nodes[FQ].parent != INNER) return -EINVAL;
 snapshot = &snapshots[which];
 error = aqm_base(snapshot);
 if (error) return error;
 aqm = &snapshot->aqm; count = snapshot->state.count;
 if (count > 16) return -E2BIG;
 for (i = 0; i < count; i++) {
  address = i ? get_unaligned_le32(aqm->carrier[i - 1]) :
   get_unaligned_le32(aqm->node + (algorithm == 2 ? 172 : 164));
  stride = address >= 0x400ccac0 ? 64 : 56;
  snapshot_kind = QDX_DIAG_AQM_CARRIER; snapshot_index = i;
  error = aqm_copy(&snapshot->view, QDX_DIAG_AQM_CARRIER, i, stride, aqm->carrier[i]);
  if (error) return error;
  aqm->carrier_address[i] = address; aqm->carrier_valid |= BIT(i);
  snapshot_kind = QDX_DIAG_AQM_METADATA;
  error = aqm_copy(&snapshot->view, QDX_DIAG_AQM_METADATA, i, 96, aqm->metadata[i]);
  if (error) return error;
  aqm->metadata_valid |= BIT(i);
  length = get_unaligned_le16(aqm->carrier[i] + 46);
  if (length != (algorithm == 2 ? 110 : 1514)) return -ERANGE;
  snapshot_kind = QDX_DIAG_AQM_PAYLOAD;
  error = aqm_copy(&snapshot->view, QDX_DIAG_AQM_PAYLOAD, i, length, payload);
  if (error) return error;
  if (get_unaligned_be16(payload + 12) != ETH_P_8021Q ||
      get_unaligned_be16(payload + 14) != private_vid ||
      get_unaligned_be16(payload + 16) != ETH_P_IP) return -EBADMSG;
  memcpy(native, payload, 12); memcpy(native + 12, payload + 16, length - 16);
  id = get_unaligned_be32(native + 63);
  if (native[14] != 0x45 || native[23] != IPPROTO_UDP ||
      get_unaligned_be32(native + 26) != source_ip ||
      get_unaligned_be32(native + 30) != target_ip ||
      get_unaligned_be16(native + 34) != source_port ||
      get_unaligned_be16(native + 36) != target_port ||
      memcmp(native + 42, "QDXPROB1", 8) ||
      get_unaligned_be64(native + 50) != run_id || native[58] != 1 ||
      get_unaligned_be32(native + 59) != 1 || id >= (algorithm == 2 ? 16 : 10) ||
      (algorithm == 1 && (id == 3 || id == 9)) || (i && id <= previous) ||
      native[15] != (algorithm == 1 && id >= 4 ? 32 : 0)) return -EBADMSG;
  packet = &packets[id]; previous = id;
  snapshot->ids[i] = id; snapshot->lengths[i] = length;
  snapshot->ages[i] = get_unaligned_le64(aqm->metadata[i] + 72);
  snapshot->classes[i] = get_unaligned_le32(aqm->metadata[i] + 80);
  if (algorithm == 1 && snapshot->classes[i] != (id >= 4 ? 2 : 1)) return -EBADMSG;
  if (copy_payloads && !packet->copied) {
   if (packet->skb || packet->loaned) return -EEXIST;
   packet->skb = alloc_skb(136 + length - VLAN_HLEN, GFP_KERNEL);
   if (!packet->skb) return -ENOMEM;
   skb_reserve(packet->skb, 136);
   skb_put_data(packet->skb, native, length - VLAN_HLEN);
   packet->skb->dev = port; packet->skb->protocol = htons(ETH_P_IP);
   skb_reset_mac_header(packet->skb);
   packet->id = id; packet->length = length;
   memcpy(packet->expected, native, length - VLAN_HLEN);
   packet->copied = true;
  } else if (!packet->copied || packet->length != length || packet->expected_drop ||
             memcmp(packet->expected, native, length - VLAN_HLEN) ||
             (copy_payloads && (!packet->skb || packet->loaned))) return -EBADMSG;
 }
 return 0;
}


static int aqm_prepare(void)
{
 struct qdx_owner owner = { .module = THIS_MODULE, .object = snapshots };
 __le32 assignment[2] = {}, next = cpu_to_le32(156);
 struct { __le32 point; __le16 size, offset; } mirror_cfg = {
  cpu_to_le32(1), cpu_to_le16(FRAME_MAX), 0,
 };
 u32 i, address;
 int error;
 if (pinned || closed || (algorithm != 1 && algorithm != 2)) return -EPERM;
 if (!try_module_get(THIS_MODULE)) return -ENODEV;
 pinned = true;
 for (i = 0; i < NODES; i++) nodes[i].parent = -1;
 nodes[OUTER].tag = 0x710c0000; nodes[OUTER].kind = 3;
 nodes[INNER].tag = QDX_AQM_PARENT_TAG; nodes[INNER].kind = 3;
 nodes[FQ].tag = TABLE_TAG; nodes[FQ].kind = 1;
 nodes[LEAF_A].tag = QDX_AQM_LEAF_A_TAG;
 nodes[LEAF_B].tag = QDX_AQM_LEAF_B_TAG;
 nodes[LEAF_C].tag = QDX_AQM_LEAF_C_TAG;
 nodes[LEAF_D].tag = QDX_AQM_LEAF_D_TAG;
 for (i = LEAF_A; i <= (algorithm == 2 ? LEAF_A : LEAF_D); i++)
  nodes[i].kind = algorithm == 2 ? 1 : 13;
 nodes[MARKER].tag = 0x71400000; nodes[MARKER].kind = 4;
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
 error = netdev_rx_handler_register(conduit, aqm_receive, NULL);
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
 error = aqm_command(false, 6, assignment, sizeof(assignment));
 for (i = 0; !error && i < NODES; i++)
  if (nodes[i].kind) error = aqm_tc(0, i, 0, 0);
 if (!error) error = aqm_tc(10, FQ, 0, 0);
 if (error) return error;
 if (memory_size != 72) return -EPROTO;
 table = qdx_diag_fq_table_alloc(physical_service, &owner);
 if (IS_ERR(table)) { error = PTR_ERR(table); table = NULL; return error; }
 error = aqm_tc(7, FQ, 0, 0);
 if (!error) error = aqm_tc(5, INNER, FQ, 1);
 if (!error) error = aqm_tc(7, MARKER, 0, 0);
 if (!error) error = aqm_tc(5, OUTER, MARKER, 2);
 if (!error) error = aqm_tc(3, OUTER, 0, 0);
 if (!error) error = aqm_command(true, 0, &mirror_cfg, sizeof(mirror_cfg));
 if (!error) error = aqm_command(true, 3, &next, sizeof(next));
 if (!error) error = aqm_command(true, 1, NULL, 0);
 if (error) return error;
 for (i = 0; i < 2; i++) {
  anchor_packets[i].control = true;
  error = aqm_packet_create(&anchor_packets[i], 0x40000000 + i, 128, i);
  if (!error) error = aqm_submit(FQ, &anchor_packets[i]);
  if (error) return error;
  anchor_accepted++;
 }
 qdx_tx_path_get(nodes[FQ].path); qdx_tx_release(nodes[FQ].path);
 nodes[FQ].path_closed = true;
 error = aqm_gauge(FQ, 2);
 if (error) return error;
 for (leaf = LEAF_A; leaf <= (algorithm == 2 ? LEAF_A : LEAF_D); leaf++) {
  error = aqm_configure();
  if (!error) error = aqm_tc(5, INNER, leaf, 0);
  if (!error) error = aqm_base(&discovery);
  if (error) return error;
  address = get_unaligned_le32(discovery.aqm.selector + 164);
  if (algorithm == 2 || (address & 31) == 0 || (address & 31) == 24) break;
  error = aqm_tc(6, INNER, leaf, 0);
  if (error) return error;
 }
 if (leaf > LEAF_D) return -ENOSPC;
 prepared = true;
 return 0;
}


static int aqm_load(void)
{
 u32 i;
 int error;
 if (!prepared || !source_opened || loaded || exported || request ||
     nodes[INNER].parent != -1) return -EPERM;
 /* Root seals the actual physical source before this accepted-input fence. */
 loaded = true; stage = 1;
 error = aqm_marker();
 if (error) return error;
 queue_count = algorithm == 2 ? 16 : 8;
 error = aqm_gauge(leaf, queue_count);
 if (error) return error;
 admission_drops = nodes[leaf].dropped;
 if (admission_drops != (algorithm == 2 ? 0 : 2)) return -EBADMSG;
 error = aqm_snapshot(0, true);
 if (error) return error;
 for (i = 0; i < queue_count; i++) queue[i] = snapshots[0].ids[i];
 cpu_state = snapshots[0].state;
 if (cpu_state.count != queue_count || queue[0]) return -EBADMSG;
 if (algorithm == 2) {
  if (cpu_state.codel_count || cpu_state.first_above || cpu_state.drop_next || cpu_state.dropping)
   return -EBADMSG;
 } else if (cpu_state.average[1] != 3218 || cpu_state.average[2] != 6104 ||
            cpu_state.occupancy[1] != 4542 || cpu_state.occupancy[2] != 7570)
  return -EBADMSG;
 exported = true;
 return 0;
}


static int aqm_adopt(void)
{
 u32 i;
 int error;
 if (!exported || adopted || request || nodes[INNER].parent != -1) return -EPERM;
 for (i = 0; i < queue_count; i++)
  if (!packets[queue[i]].copied || !packets[queue[i]].skb || packets[queue[i]].loaned)
   return -EBADMSG;
 if (!old_backing_retired) {
  stage = 2;
  if (nodes[leaf].parent != -1) {
   error = aqm_tc(6, INNER, leaf, 0);
   if (error) return error;
  }
  if (nodes[leaf].allocated) {
   error = aqm_tc(1, leaf, 0, 0);
   if (error) return error;
  }
  /* FREE retires obsolete RX pool backing only after every logical original
   * has a CPU-owned byte copy and its original age/history. No user drop. */
  backing_retired = queue_count; old_backing_retired = true;
 }
 if (!nodes[leaf].allocated) {
  error = aqm_tc(0, leaf, 0, 0);
  if (error) return error;
 }
 leaf_reallocated = true; temporary_config = true;
 error = aqm_configure();
 if (!error && nodes[leaf].parent == -1) error = aqm_tc(5, INNER, leaf, 0);
 if (!error) error = aqm_base(&discovery);
 if (error) return error;
 if (discovery.state.count || (algorithm != 2 &&
     ((get_unaligned_le32(discovery.aqm.selector + 164) & 31) == 8 ||
      (get_unaligned_le32(discovery.aqm.selector + 164) & 31) == 16))) return -EXDEV;
 adopted = true;
 return 0;
}


static int aqm_cpu_continue(void)
{
 struct aqm_packet *packet;
 unsigned long deadline = jiffies + msecs_to_jiffies(WAIT_MS);
 u32 class;
 int error;
 if (!adopted || cpu_selected || !queue_count || request) return -EPERM;
 do {
  error = aqm_base(&discovery);
  if (error) return error;
  cpu_now = discovery.clock;
  if (algorithm != 2 || (cpu_now > snapshots[0].ages[0] &&
      cpu_now - snapshots[0].ages[0] > 37)) break;
  usleep_range(1000, 1500);
 } while (time_before(jiffies, deadline));
 packet = &packets[queue[0]];
 if (!packet->skb || packet->loaned || packet->expected_drop) return -EBADMSG;
 if (algorithm == 2) {
  if (cpu_now <= snapshots[0].ages[0] || cpu_now - snapshots[0].ages[0] <= 37 ||
      cpu_now - snapshots[0].ages[0] > U32_MAX || cpu_state.count <= 1 ||
      cpu_state.first_above || cpu_state.dropping || cpu_state.codel_count ||
      cpu_state.drop_next) return -ERANGE;
  cpu_state.first_above = cpu_now;
  if (cpu_now - snapshots[0].ages[0] > cpu_state.delay_max)
   cpu_state.delay_max = cpu_now - snapshots[0].ages[0];
 } else {
  class = snapshots[0].classes[0];
  if (class != 1 || cpu_state.occupancy[class] < packet->length) return -EBADMSG;
  /* Selecting an existing packet changes occupancy, not the RED average.
   * Both later arrival decisions are actual physical input, never synthetic. */
  cpu_state.occupancy[class] -= packet->length;
 }
 packet->cpu_selected = true; cpu_state.count--; stage = 3; cpu_selected = true;
 return 0;
}


static int aqm_import_state(struct aqm_snapshot *snapshot, bool ages)
{
 struct qdx_owner owner = { .module = THIS_MODULE, .object = snapshots };
 struct qdx_packet_op *operation;
 u32 i, j;
 int error = 0;
 if (request || copy_operation || !qdx_diag_fq_table_idle(table) ||
     nodes[INNER].parent != -1) return -EPERM;
 operation = qdx_packet_op_prepare(mirror, COPY_TAG, QDX_RECEIVE_PACKET);
 if (IS_ERR(operation)) return PTR_ERR(operation);
 qdx_packet_op_close(operation);
 if (ages) {
  for (i = 0; i < snapshot->state.count; i++) {
   for (j = 0; j < snapshots[0].state.count; j++)
    if (snapshots[0].ids[j] == snapshot->ids[i]) break;
   if (j == snapshots[0].state.count) { error = -EBADMSG; break; }
   error = qdx_diag_aqm_age_import(operation, table, NULL,
    &snapshot->view, i, snapshots[0].ages[j], &owner);
   if (error) break;
  }
 }
 if (!error) error = qdx_diag_aqm_import(operation, table, NULL,
  &snapshot->view, &cpu_state, &owner);
 qdx_packet_op_put(operation);
 return error;
}

static int aqm_rebuild(void)
{
 u32 i, class;
 int error;
 if (!cpu_selected || rebuilt || rebuild_stage || request || nodes[INNER].parent != -1)
  return -EPERM;
 rebuild_stage = 1;
 for (i = rebuild_next; i < queue_count; i++) {
  error = aqm_submit(leaf, &packets[queue[i]]);
  if (error) return error;
  rebuild_next = i + 1; rebuilt_submitted++;
 }
 qdx_tx_path_get(nodes[leaf].path); qdx_tx_release(nodes[leaf].path);
 nodes[leaf].path_closed = true; rebuild_stage = 2;
 error = aqm_gauge(leaf, queue_count - 1);
 if (error) return error;
 if (nodes[leaf].dropped != admission_drops) return -EBADMSG;
 /* CONFIG resets RED averages, so configuration precedes history import.
  * Actual reconstruction admissions are recorded separately from user input. */
 temporary_config = false;
 error = aqm_configure();
 if (!error) error = aqm_snapshot(1, false);
 if (error) return error;
 rebuild_stage = 3;
 error = aqm_import_state(&snapshots[1], algorithm == 2);
 if (error) return error;
 rebuild_stage = 4;
 error = aqm_snapshot(2, false);
 if (error) return error;
 if (snapshots[2].state.count != cpu_state.count) return -EBADMSG;
 for (i = 0; i < cpu_state.count; i++)
  if (snapshots[2].ids[i] != queue[i + 1]) return -EBADMSG;
 if (algorithm == 2) {
  if (snapshots[2].state.first_above != cpu_now || snapshots[2].state.codel_count ||
      snapshots[2].state.drop_next || snapshots[2].state.dropping ||
      snapshots[2].state.delay_max != cpu_state.delay_max ||
      snapshots[2].state.delay_min != cpu_state.delay_min) return -EBADMSG;
  for (i = 0; i < cpu_state.count; i++)
   if (snapshots[2].ages[i] != snapshots[0].ages[i + 1]) return -EBADMSG;
 } else {
  for (class = 0; class <= 2; class++)
   if (snapshots[2].state.average[class] != cpu_state.average[class] ||
       snapshots[2].state.occupancy[class] != cpu_state.occupancy[class]) return -EBADMSG;
  if (snapshots[2].state.active != cpu_state.active ||
      snapshots[2].state.idle != cpu_state.idle) return -EBADMSG;
 }
 rebuild_stage = 5; rebuilt = true;
 return 0;
}


static int aqm_serve(void)
{
 unsigned long deadline = jiffies + msecs_to_jiffies(WAIT_MS);
 u32 i, old_drops;
 int error;
 if (!rebuilt || served || request || (algorithm == 1 && !probes_checked)) return -EPERM;
 if (serve_prepared || serve_published) return -EALREADY;
 if (nodes[INNER].parent != -1) return -EPERM;
 stage = 4;
 if (algorithm == 2) {
  do {
   error = aqm_base(&discovery);
   if (error) return error;
   resume_now = discovery.clock;
   if (resume_now >= cpu_now && resume_now - cpu_now >= 102) break;
   usleep_range(1000, 1500);
  } while (time_before(jiffies, deadline));
  if (resume_now < cpu_now || resume_now - cpu_now < 102 ||
      resume_now - cpu_now > U32_MAX) return -ERANGE;
  packets[queue[1]].expected_drop = true;
 }
 error = aqm_tc(4, leaf, 0, 0);
 if (error) return error;
 old_drops = nodes[leaf].dropped;
 if (old_drops != admission_drops + probe_drops) return -EBADMSG;
 reinit_completion(&resume_done);
 serve_prepared = true;
 error = aqm_tc(6, INNER, FQ, 0);
 if (!error) error = aqm_tc(5, OUTER, INNER, 0);
 if (error) return error;
 serve_published = true; publish_ns = ktime_get_ns();
 error = aqm_join(leaf);
 if (error) return error;
 if (!wait_for_completion_timeout(&resume_done, msecs_to_jiffies(WAIT_MS))) return -ETIMEDOUT;
 if (nodes[INNER].parent != -1) {
  error = aqm_tc(6, OUTER, INNER, 0);
  if (error) return error;
 }
 error = aqm_marker();
 if (!error) error = aqm_tc(5, INNER, FQ, 1);
 if (!error) error = aqm_gauge(leaf, 0);
 if (!error) error = aqm_base(&discovery);
 if (error) return error;
 resumed_victims = nodes[leaf].dropped - old_drops;
 if (resumed_victims != (algorithm == 2 ? 1 : 0) ||
     resumed_count != queue_count - (algorithm == 2 ? 2 : 1) ||
     discovery.state.count || bad_packets || unexpected_clones ||
     !first_return_ns || last_return_ns < first_return_ns ||
     (algorithm == 2 && last_return_ns - first_return_ns >= 100000000ULL)) return -EBADMSG;
 for (i = 0; i < resumed_count; i++)
  if (resumed_order[i] != queue[i + (algorithm == 2 ? 2 : 1)]) return -EBADMSG;
 if (algorithm == 2) {
  /* The closed producer actually drained and exact survivor/counter closure
   * proves the one firmware policy victim. No NULL callback is fabricated. */
  if (packets[queue[1]].skb || !packets[queue[1]].loaned) return -EBADMSG;
  packets[queue[1]].loaned = false;
 }
 snapshots[3] = discovery; snapshots[3].view.aqm = &snapshots[3].aqm;
 served = true; passed = true;
 return 0;
}


static int aqm_source(void)
{
 int error;
 if (!prepared || loaded || source_opened || request || nodes[INNER].parent != -1)
  return -EPERM;
 error = aqm_tc(2, leaf, 0, 0);
 if (!error) { source_default = leaf; source_opened = true; }
 return error;
}

static int aqm_probes(void)
{
 u32 class, expected_average;
 int error;
 if (algorithm != 1 || !rebuilt || probes_checked || served || request ||
     nodes[INNER].parent != -1) return -EPERM;
 /* Runner issued two actual source packets, then sealed and emptied the
   physical ingress before this fence. Neither packet is host-submitted here. */
 error = aqm_marker();
 if (!error) error = aqm_gauge(leaf, queue_count - 1);
 if (!error) error = aqm_base(&discovery);
 if (error) return error;
 probe_drops = nodes[leaf].dropped - admission_drops;
 if (probe_drops != 2 || discovery.state.count != cpu_state.count) return -EBADMSG;
 for (class = 1; class <= 2; class++) {
  expected_average = cpu_state.average[class] - (cpu_state.average[class] >> 1) +
   (cpu_state.occupancy[class] >> 1);
  if (expected_average <= (class == 2 ? 6000 : 3000) ||
      (cpu_state.occupancy[class] >> 1) > (class == 2 ? 6000 : 3000) ||
      discovery.state.average[class] != expected_average ||
      discovery.state.occupancy[class] != cpu_state.occupancy[class]) return -EBADMSG;
 }
 snapshots[4] = discovery; snapshots[4].view.aqm = &snapshots[4].aqm;
 probes_checked = true;
 return 0;
}

static int aqm_wire(void)
{
 struct sk_buff *skb;
 struct aqm_packet *packet;
 u32 id;
 int status;
 if (!passed || bad_packets || !skb_queue_empty(&quarantine)) return -EPERM;
 if (hook) { netdev_rx_handler_unregister(conduit); hook = false; }
 /* Root restored source forwarding and pre-wire sink before this command. */
 while (native_sent < 1 + resumed_count) {
  id = native_sent ? resumed_order[native_sent - 1] : queue[0];
  packet = &packets[id]; skb = packet->skb;
  if (!skb || packet->loaned || packet->expected_drop) return -EBADMSG;
  packet->skb = NULL;
  skb->dev = port; skb->protocol = htons(ETH_P_IP); skb->ip_summed = CHECKSUM_NONE;
  skb_reset_mac_header(skb); skb_set_network_header(skb, ETH_HLEN);
  skb_set_transport_header(skb, ETH_HLEN + 20); skb_set_queue_mapping(skb, 0);
  status = dev_queue_xmit(skb); native_sent++;
  if (net_xmit_eval(status)) return status < 0 ? status : -ENOBUFS;
 }
 wire_complete = true;
 return 0;
}

static int aqm_restore(void)
{
 __le32 unassign = cpu_to_le32(shaper);
 u32 i;
 int error;
 if (!pinned) return 0;
 if ((loaded && (!passed || !wire_complete || native_sent != 1 + resumed_count)) ||
     request || fault || bad_packets || copy_operation || marker_packet.loaned ||
     !skb_queue_empty(&quarantine)) return -EBUSY;
 for (i = 0; i < ARRAY_SIZE(packets); i++)
  if (packets[i].loaned || packets[i].skb) return -EBUSY;
 /* Source is sealed. An arrival may precede load's flag; require actual empty
   data leaves before any FREE, not a guessed successful setup stage. */
 for (i = LEAF_A; i <= LEAF_D; i++) {
  if (!nodes[i].allocated) continue;
  error = aqm_gauge(i, 0);
  if (error) return error;
 }
 closed = true;
 for (i = 0; i < NODES; i++) {
  if (i == FQ) continue;
  error = aqm_join(i);
  if (error) return error;
 }
 for (i = NODES; i-- > 0;) {
  if (nodes[i].parent == -1) continue;
  error = aqm_tc(6, nodes[i].parent, i, 0);
  if (error) return error;
 }
 if (nodes[FQ].allocated) {
  error = aqm_tc(1, FQ, 0, 0);
  if (!error) error = aqm_join(FQ);
  if (error) return error;
  controls_retired = anchor_accepted;
  anchor_packets[0].loaned = anchor_packets[1].loaned = false;
 }
 for (i = NODES; i-- > 0;) {
  if (!nodes[i].allocated) continue;
  error = aqm_tc(1, i, 0, 0);
  if (error) return error;
 }
 if (enabled) { error = aqm_command(true, 2, NULL, 0); if (error) return error; }
 if (next_set) { error = aqm_command(true, 4, NULL, 0); if (error) return error; }
 if (assigned) { error = aqm_command(false, 8, &unassign, sizeof(unassign)); if (error) return error; }
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
 for (i = 0; i < 2; i++) { dev_kfree_skb(anchor_packets[i].skb); anchor_packets[i].skb = NULL; }
 dev_kfree_skb(marker_packet.skb); marker_packet.skb = NULL;
 if (mirror) { qdx_endpoint_put(mirror); mirror = NULL; }
 if (physical) { qdx_endpoint_put(physical); physical = NULL; }
 if (table) { qdx_dma_release(table); table = NULL; }
 if (mirror_service) { qdx_service_put(mirror_service); mirror_service = NULL; }
 if (physical_service) { qdx_service_put(physical_service); physical_service = NULL; }
 if (conduit) { dev_put(conduit); conduit = NULL; }
 if (port) { dev_put(port); port = NULL; }
 pinned = false; module_put(THIS_MODULE);
 return 0;
}


static int aqm_status_show(struct seq_file *seq, void *unused)
{
 u32 i, j, offset, length;
 struct aqm_snapshot *snapshot;
 mutex_lock(&control_lock);
 seq_printf(seq, "algorithm=%u pinned=%u prepared=%u loaded=%u exported=%u adopted=%u cpu_selected=%u rebuilt=%u served=%u passed=%u closed=%u fault=%u request=%u error=%d stage=%u leaf=%u physical=%u mirror=%u shaper=%u assigned=%u enabled=%u next_set=%u table=%u table_idle=%u copy_operation=%u copies=%u copy_ns=%llu commands=%u bad=%u admission_drops=%u backing_retired=%u controls_retired=%u unexpected_clones=%u probe_drops=%u probes_checked=%u resumed_victims=%u resumed_count=%u queue_count=%u cpu_now=%llu resume_now=%llu publish_ns=%llu first_return_ns=%llu last_return_ns=%llu\n",
  algorithm, pinned, prepared, loaded, exported, adopted, cpu_selected, rebuilt, served,
  passed, closed, fault, !!request, last_error, stage, leaf, physical_ifnum, mirror_ifnum, shaper,
  assigned, enabled, next_set, !!table, table ? qdx_diag_fq_table_idle(table) : true,
  !!copy_operation, copy_count, copy_time_ns, command_count, bad_packets, admission_drops,
  backing_retired, controls_retired, unexpected_clones, probe_drops, probes_checked,
  resumed_victims, resumed_count, queue_count, cpu_now, resume_now, publish_ns,
  first_return_ns, last_return_ns);
 seq_printf(seq, "physical run=%llu sip=%08x dip=%08x sport=%u dport=%u vid=%u hook=%u quarantine=%u native_sent=%u wire_complete=%u source_opened=%u source_default=%u marker_wait=%u markers=%u observed_port=%u\n",
  run_id, source_ip, target_ip, source_port, target_port, private_vid, hook,
  skb_queue_len(&quarantine), native_sent, wire_complete, source_opened, source_default,
  marker_wait, markers, observed_port);
 seq_printf(seq, "journal rebuild_next=%u rebuilt_submitted=%u rebuild_stage=%u anchor_accepted=%u old_backing_retired=%u leaf_reallocated=%u serve_prepared=%u serve_published=%u snapshot_kind=%u snapshot_index=%u\n",
  rebuild_next, rebuilt_submitted, rebuild_stage, anchor_accepted, old_backing_retired,
  leaf_reallocated, serve_prepared, serve_published, snapshot_kind, snapshot_index);
 seq_printf(seq, "request_id=%llu outcome=%u firmware_error=%u declared=%zu received=%zu published=%u exposure_ended=%u pending_opcode=%u pending_node=%u pending_sub=%u\n",
  result.id, result.outcome, result.firmware_error, result.declared_len, result.received_len,
  result.published, result.exposure_ended, pending_opcode, pending_node,
  le32_to_cpu(pending_message.command));
 for (i = 0; i < NODES; i++) {
  if (!nodes[i].kind) continue;
  seq_printf(seq, "node=%u tag=%08x kind=%u allocated=%u parent=%d band=%u gauge=%u bytes=%u admitted=%llu selected=%llu dropped=%llu path=%u path_closed=%u drained=%u\n",
   i, nodes[i].tag, nodes[i].kind, nodes[i].allocated, nodes[i].parent, nodes[i].band,
   nodes[i].gauge, nodes[i].bytes, nodes[i].admitted, nodes[i].selected, nodes[i].dropped,
   !!nodes[i].path, nodes[i].path_closed, nodes[i].path ? qdx_tx_drained(nodes[i].path) : true);
 }
 for (i = 0; i < ARRAY_SIZE(snapshots); i++) {
  snapshot = &snapshots[i];
  seq_printf(seq, "snapshot=%u valid=%u selector=%08x leaf_address=%08x count=%u clock=%llu first_above=%llu drop_next=%llu codel_count=%u dropping=%u idle=%llu active=%u delay_max=%u delay_min=%u\n",
   i, snapshot->aqm.valid, get_unaligned_le32(snapshot->view.node + 4),
   get_unaligned_le32(snapshot->aqm.selector + 164), snapshot->state.count,
   snapshot->clock, snapshot->state.first_above, snapshot->state.drop_next,
   snapshot->state.codel_count, snapshot->state.dropping, snapshot->state.idle,
   snapshot->state.active, snapshot->state.delay_max, snapshot->state.delay_min);
  for (j = 0; j < 7; j++)
   seq_printf(seq, "class snapshot=%u class=%u average=%u occupancy=%u\n", i, j,
    snapshot->state.average[j], snapshot->state.occupancy[j]);
  for (j = 0; j < min_t(u32, snapshot->state.count, 16); j++)
   seq_printf(seq, "queued snapshot=%u rank=%u id=%u length=%u class=%u age=%llu carrier=%08x metadata=%08x\n",
    i, j, snapshot->ids[j], snapshot->lengths[j], snapshot->classes[j], snapshot->ages[j],
    snapshot->aqm.carrier_address[j], get_unaligned_le32(snapshot->aqm.carrier[j] + 36));
  for (offset = 0; offset < (algorithm == 2 ? 280 : 520); offset += length) {
   length = min_t(u32, 64, (algorithm == 2 ? 280 : 520) - offset);
   seq_printf(seq, "node_bytes snapshot=%u offset=%u data=%*phN\n", i, offset,
    length, snapshot->aqm.node + offset);
  }
 }
 seq_printf(seq, "cpu count=%u first_above=%llu drop_next=%llu codel_count=%u dropping=%u idle=%llu active=%u delay_max=%u delay_min=%u\n",
  cpu_state.count, cpu_state.first_above, cpu_state.drop_next, cpu_state.codel_count,
  cpu_state.dropping, cpu_state.idle, cpu_state.active, cpu_state.delay_max, cpu_state.delay_min);
 for (i = 0; i < 7; i++)
  seq_printf(seq, "cpu_class=%u average=%u occupancy=%u\n", i,
   cpu_state.average[i], cpu_state.occupancy[i]);
 for (i = 0; i < 16; i++)
  seq_printf(seq, "packet=%u length=%u held=%u loaned=%u copied=%u cpu_selected=%u expected_drop=%u returns=%u\n",
   i, packets[i].length, !!packets[i].skb, packets[i].loaned,
   packets[i].copied, packets[i].cpu_selected, packets[i].expected_drop, packets[i].returns);
 for (i = 0; i < min_t(u32, resumed_count, ARRAY_SIZE(resumed_order)); i++)
  seq_printf(seq, "resumed_rank=%u id=%u\n", i, resumed_order[i]);
 for (i = 0; i < min_t(u32, event_count, ARRAY_SIZE(events)); i++)
  seq_printf(seq, "event=%u stage=%u id=%u type=%u group=%u positive=%u host_ns=%llu\n",
   i, events[i].stage, events[i].id, events[i].type, events[i].ifnum, events[i].positive,
   events[i].host_ns);
 mutex_unlock(&control_lock);
 return 0;
}

DEFINE_SHOW_ATTRIBUTE(aqm_status);

static ssize_t aqm_control_write(struct file *file, const char __user *user,
 size_t count, loff_t *offset)
{
 char command[32];
 int error;
 if (!allow_writes || !count || count >= sizeof(command)) return -EPERM;
 if (copy_from_user(command, user, count)) return -EFAULT;
 command[count] = 0; strim(command);
 rtnl_lock(); mutex_lock(&control_lock);
 if (!strcmp(command, "poll")) error = aqm_wait_command();
 else if (!strcmp(command, "finish-copy")) error = aqm_copy_finish();
 else if (!strcmp(command, "restore")) error = aqm_restore();
 else if (last_error || fault || request || copy_operation || closed || bad_packets) error = -EBUSY;
 else if (!strcmp(command, "prepare")) error = aqm_prepare();
 else if (!strcmp(command, "source")) error = aqm_source();
 else if (!strcmp(command, "load")) error = aqm_load();
 else if (!strcmp(command, "adopt")) error = aqm_adopt();
 else if (!strcmp(command, "cpu")) error = aqm_cpu_continue();
 else if (!strcmp(command, "rebuild")) error = aqm_rebuild();
 else if (!strcmp(command, "probes")) error = aqm_probes();
 else if (!strcmp(command, "serve")) error = aqm_serve();
 else if (!strcmp(command, "wire")) error = aqm_wire();
 else error = -EINVAL;
 last_error = error;
 mutex_unlock(&control_lock); rtnl_unlock();
 return error ?: count;
}

static const struct file_operations aqm_control_ops = {
 .owner = THIS_MODULE, .write = aqm_control_write,
};
static int __init aqm_init(void)
{
 if ((algorithm != 1 && algorithm != 2) || !source_port || source_port > U16_MAX ||
     !target_port || target_port > U16_MAX || !private_vid || private_vid >= 4095)
  return -EINVAL;
 skb_queue_head_init(&quarantine);
 directory = debugfs_create_dir("qdx_physical_aqm_diag", NULL);
 if (IS_ERR(directory)) return PTR_ERR(directory);
 debugfs_create_file("status", 0400, directory, NULL, &aqm_status_fops);
 debugfs_create_file("control", 0200, directory, NULL, &aqm_control_ops);
 return 0;
}

static void __exit aqm_exit(void)
{
 WARN_ON(pinned || request || table || receiver || physical || mirror || copy_operation || hook ||
         !skb_queue_empty(&quarantine));
 debugfs_remove_recursive(directory);
}

module_init(aqm_init);
module_exit(aqm_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Isolated physical WRED and plain CoDel consequential history handover");
