// SPDX-License-Identifier: GPL-2.0-only
/* Isolated finite AQM history continuation. Not a qdisc or CPU baseline. */
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

enum node_id { OUTER, INNER, FQ, LEAF_A, LEAF_B, LEAF_C, LEAF_D, NODES };
struct aqm_node {
 u32 tag, kind, gauge, bytes;
 u64 admitted, selected, dropped;
 bool allocated;
 int parent;
 u32 band;
 struct qdx_packet_op *operation;
};
struct aqm_packet {
 struct sk_buff *skb, *submitted, *unexpected;
 u32 id, length, returns, nulls, positives;
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
MODULE_PARM_DESC(algorithm, "0=plain RED, 1=two-class WRED, 2=plain CoDel; fixed finite laws");
static DEFINE_MUTEX(control_lock);
static DEFINE_SPINLOCK(result_lock);
static struct dentry *directory;
static struct net_device *port;
static struct qdx_service *igs_service, *mirror_service;
static struct qdx_endpoint *igs, *mirror;
static struct qdx_receiver *receiver;
static struct qdx_dma *table;
static struct qdx_packet_op *copy_operation, *probe_operation;
static struct qdx_request *request;
static struct qdx_result result;
static struct aqm_message pending_message;
static u32 pending_opcode, pending_length, pending_node, pending_arg, pending_extra;
static bool pending_mirror;
static struct aqm_node nodes[NODES];
static struct aqm_packet packets[20], anchor_packets[2];
static struct aqm_snapshot snapshots[4], discovery;
static struct qdx_diag_aqm_state cpu_state;
static struct aqm_copy_round copy_round;
static struct aqm_event events[96];
static u32 event_count, bad_packets, policy_drops, backing_retired, controls_retired;
static u32 unexpected_clones, stage, leaf = LEAF_A, memory_size, command_count, copy_count;
static u32 igs_ifnum = U32_MAX, mirror_ifnum = U32_MAX, shaper, queue[16], queue_count;
static u32 cpu_victims, fresh_accepts, resumed_victims, resumed_order[16], resumed_count;
static u64 copy_time_ns, copy_started_ns, cpu_now, resume_now, publish_ns;
static u32 load_next, rebuild_next = 1, probe_next, anchor_accepted;
static bool old_backing_retired, leaf_reallocated, serve_prepared, serve_published;
static bool pinned, assigned, enabled, next_set, prepared, loaded, exported, adopted;
static bool cpu_selected, rebuilt, served, passed, closed, fault, anchor_retiring, data_retiring;
static bool igs_retired, mirror_retired, temporary_config;
static int last_error;
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
 request = qdx_command_submit(mirror_command ? mirror : igs, opcode,
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
 } else if (sub == 7 && id >= LEAF_A) {
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

static void aqm_returned(void *owner, struct sk_buff *original,
 struct sk_buff *returned, const struct qdx_rx_meta *meta, struct napi_struct *napi)
{
 struct aqm_packet *packet = owner;
 unsigned long flags;
 bool valid = original && original == packet->submitted && meta;

 spin_lock_irqsave(&result_lock, flags);
 packet->loaned = false;
 packet->submitted = NULL;
 packet->returns++;
 if (!returned) {
  packet->nulls++;
  if (!valid || meta->type != 1) bad_packets++;
  else if (packet->control && anchor_retiring) controls_retired++;
  else if (data_retiring && packet->copied && packet->skb) backing_retired++;
  else if (packet->expected_drop) {
   policy_drops++;
   if (stage == 4) resumed_victims++;
  } else bad_packets++;
 } else {
  valid = valid && meta->ifnum == READ_ONCE(igs_ifnum) &&
   meta->type == QDX_RECEIVE_RETURNED && returned == original &&
   returned->len == packet->length && !skb_is_nonlinear(returned) &&
   !memcmp(returned->data, packet->expected, packet->length) && !packet->skb;
  if (!valid || packet->expected_drop) bad_packets++;
  /* Keep every actual positive owner even after a qualification failure. */
  if (!packet->skb) packet->skb = returned;
  else { packet->unexpected = returned; bad_packets++; }
  packet->positives++;
  if (stage == 4 && !packet->control) {
   if (resumed_count < ARRAY_SIZE(resumed_order)) resumed_order[resumed_count] = packet->id;
   resumed_count++;
  }
 }
 if (event_count < ARRAY_SIZE(events)) events[event_count++] = (struct aqm_event) {
  stage, packet->id, meta ? meta->type : U32_MAX, meta ? meta->ifnum : U32_MAX,
  !!returned, ktime_get_ns() };
 else bad_packets++;
 spin_unlock_irqrestore(&result_lock, flags);
}

static int aqm_packet_create(struct aqm_packet *packet, u32 id, u32 length, u32 bin)
{
 struct sk_buff *skb;
 u8 *data;

 if (packet->skb || packet->submitted || length < 64 || length > FRAME_MAX) return -EINVAL;
 skb = alloc_skb(130 + length, GFP_KERNEL);
 if (!skb) return -ENOMEM;
 skb_reserve(skb, 130);
 data = skb_put_zero(skb, length);
 ether_addr_copy(data, port->dev_addr);
 ether_addr_copy(data + ETH_ALEN, port->dev_addr);
 put_unaligned_be16(ETH_P_IP, data + 12);
 data[14] = 0x45;
 data[15] = bin ? 32 : 0;
 put_unaligned_be16(length - ETH_HLEN, data + 16);
 data[22] = 64;
 data[23] = IPPROTO_UDP;
 put_unaligned_be32(0xc0000201, data + 26);
 put_unaligned_be32(0xc0000202, data + 30);
 put_unaligned_be16(20000 + bin, data + 34);
 put_unaligned_be16(40000, data + 36);
 put_unaligned_be16(length - ETH_HLEN - 20, data + 38);
 put_unaligned_le32(0x414d5144, data + 42);
 put_unaligned_le32(id, data + 46);
 put_unaligned(csum_fold(csum_partial(data + 14, 20, 0)), (__sum16 *)(data + 24));
 skb->dev = port;
 skb->protocol = htons(ETH_P_IP);
 skb_reset_mac_header(skb);
 packet->skb = skb;
 packet->id = id;
 packet->length = length;
 memcpy(packet->expected, data, length);
 return 0;
}


static int aqm_submit(struct qdx_packet_op **operation, u32 tag, struct aqm_packet *packet)
{
 struct qdx_packet_recipient recipient = {
  .owner = { .module = THIS_MODULE, .object = packet }, .returned = aqm_returned,
 };
 struct qdx_ready ready;
 struct sk_buff *skb = packet->skb;
 int error;

 if (!skb || packet->loaned || packet->submitted) return -EINVAL;
 if (!*operation) {
  *operation = qdx_packet_op_prepare(igs, tag, QDX_RECEIVE_RETURNED);
  if (IS_ERR(*operation)) { error = PTR_ERR(*operation); *operation = NULL; return error; }
 }
 packet->submitted = skb; packet->skb = NULL; packet->loaned = true;
 ready = qdx_packet_op_submit(*operation, skb, &recipient);
 if (ready.status == QDX_ACCEPTED) {
  if (packet->control) anchor_accepted++;
  return 0;
 }
 packet->submitted = NULL; packet->loaned = false; packet->skb = skb;
 return ready.error ?: -EAGAIN;
}

static int aqm_join(struct qdx_packet_op **operation)
{
 bool drained;
 int error;
 if (!*operation) return 0;
 qdx_packet_op_close(*operation);
 error = read_poll_timeout(qdx_packet_op_drained, drained, drained, 10,
  WAIT_MS * 1000, false, *operation);
 if (error) return error;
 qdx_packet_op_put(*operation); *operation = NULL;
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

 if (nodes[INNER].parent != -1 || !nodes[FQ].operation || copy_operation || request ||
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
 else ready = qdx_diag_fq_owned_copy(copy_operation, table, nodes[FQ].operation,
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

static int aqm_base(struct aqm_snapshot *snapshot)
{
 struct qdx_diag_fq_view *view = &snapshot->view;
 struct qdx_diag_aqm_view *aqm = &snapshot->aqm;
 u8 clock[24];
 unsigned int i;
 int error;

 memset(snapshot, 0, sizeof(*snapshot));
 aqm->plain = algorithm == 2;
 aqm->data = nodes[leaf].operation;
 view->aqm = aqm;
 error = aqm_copy(view, OWNED_TABLE, 0, TABLE_LEN, view->table);
 if (error) return error;
 dma_rmb();
 if (memcmp(view->table, qdx_dma_cpu(table), TABLE_LEN)) return -EBADMSG;
 for (i = 0; i < 2; i++)
  if (get_unaligned_le32(view->table + i * 72 + 24) != 1 ||
      get_unaligned_le32(view->table + i * 72 + 64) != 64) return -EBADMSG;
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
 u8 payload[FRAME_MAX];
 u32 i, count, address, stride, id, length, previous = 0;
 int error;

 if (which >= ARRAY_SIZE(snapshots) || nodes[FQ].parent != INNER) return -EINVAL;
 snapshot = &snapshots[which];
 error = aqm_base(snapshot);
 if (error) return error;
 aqm = &snapshot->aqm;
 count = snapshot->state.count;
 if (count > 16) return -E2BIG;
 for (i = 0; i < count; i++) {
  address = i ? get_unaligned_le32(aqm->carrier[i - 1]) :
   get_unaligned_le32(aqm->node + (algorithm == 2 ? 172 : 164));
  stride = address >= 0x400ccac0 ? 64 : 56;
  error = aqm_copy(&snapshot->view, QDX_DIAG_AQM_CARRIER, i, stride, aqm->carrier[i]);
  if (error) return error;
  aqm->carrier_address[i] = address; aqm->carrier_valid |= BIT(i);
  error = aqm_copy(&snapshot->view, QDX_DIAG_AQM_METADATA, i, 96, aqm->metadata[i]);
  if (error) return error;
  aqm->metadata_valid |= BIT(i);
  length = get_unaligned_le16(aqm->carrier[i] + 46);
  if (length < 64 || length > FRAME_MAX) return -ERANGE;
  error = aqm_copy(&snapshot->view, QDX_DIAG_AQM_PAYLOAD, i, length, payload);
  if (error) return error;
  id = get_unaligned_le32(payload + 46);
  if (get_unaligned_le32(payload + 42) != 0x414d5144 || id >= ARRAY_SIZE(packets) ||
      (i && id <= previous)) return -EBADMSG;
  packet = &packets[id];
  if (!packet->loaned || packet->length != length || packet->expected_drop ||
      memcmp(payload, packet->expected, length)) return -EBADMSG;
  previous = id;
  snapshot->ids[i] = id; snapshot->lengths[i] = length;
  snapshot->ages[i] = get_unaligned_le64(aqm->metadata[i] + 72);
  snapshot->classes[i] = get_unaligned_le32(aqm->metadata[i] + 80);
  if (copy_payloads) {
   if (packet->copied) {
    if (!packet->skb || packet->skb->len != length ||
        memcmp(packet->skb->data, payload, length)) return -EBADMSG;
    continue;
   }
   if (packet->skb) return -EEXIST;
   packet->skb = alloc_skb(130 + length, GFP_KERNEL);
   if (!packet->skb) return -ENOMEM;
   skb_reserve(packet->skb, 130);
   skb_put_data(packet->skb, payload, length);
   packet->skb->dev = port; packet->skb->protocol = htons(ETH_P_IP);
   skb_reset_mac_header(packet->skb);
   packet->copied = true;
  }
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

 if (pinned || closed || algorithm > 2) return -EPERM;
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
 port = dev_get_by_name(&init_net, "lan3");
 if (!port || !netif_running(port)) return -ENODEV;
 igs_service = qdx_service_get(port, QDX_SERVICE_IGS);
 if (IS_ERR(igs_service)) { error = PTR_ERR(igs_service); igs_service = NULL; return error; }
 mirror_service = qdx_service_get(port, QDX_SERVICE_MIRROR);
 if (IS_ERR(mirror_service)) { error = PTR_ERR(mirror_service); mirror_service = NULL; return error; }
 igs = qdx_endpoint_alloc(igs_service, 53);
 if (IS_ERR(igs)) { error = PTR_ERR(igs); igs = NULL; return error; }
 error = qdx_endpoint_wait(igs, jiffies + msecs_to_jiffies(WAIT_MS));
 if (!error) error = qdx_endpoint_ifnum(igs, &igs_ifnum);
 if (error) return error;
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
 table = qdx_diag_fq_table_alloc(igs_service, &owner);
 if (IS_ERR(table)) { error = PTR_ERR(table); table = NULL; return error; }
 error = aqm_tc(7, FQ, 0, 0);
 if (!error) error = aqm_tc(5, INNER, FQ, 1);
 if (!error) error = aqm_tc(3, OUTER, 0, 0);
 if (!error) error = aqm_command(true, 0, &mirror_cfg, sizeof(mirror_cfg));
 if (!error) error = aqm_command(true, 3, &next, sizeof(next));
 if (!error) error = aqm_command(true, 1, NULL, 0);
 if (error) return error;
 for (i = 0; i < 2; i++) {
  error = aqm_packet_create(&anchor_packets[i], 0x40000000 + i, 64, i);
  if (error) return error;
  anchor_packets[i].control = true;
  error = aqm_submit(&nodes[FQ].operation, TABLE_TAG, &anchor_packets[i]);
  if (error) return error;
 }
 qdx_packet_op_close(nodes[FQ].operation);
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
 u32 i, count = algorithm == 2 ? 16 : algorithm == 1 ? 10 : 4, n;
 int error;

 if (!prepared || exported || request || nodes[INNER].parent != -1) return -EPERM;
 loaded = true; stage = 1;
 for (i = load_next; i < count; i++) {
  if (!packets[i].length) {
   error = aqm_packet_create(&packets[i], i, algorithm == 2 ? 64 : 1514,
    algorithm == 1 && i >= 4);
   if (error) return error;
  }
  packets[i].expected_drop = algorithm != 2 && (i == 3 || i == 9);
  error = aqm_submit(&nodes[leaf].operation, nodes[leaf].tag, &packets[i]);
  if (error) return error;
  load_next = i + 1;
 }
 qdx_packet_op_close(nodes[leaf].operation);
 queue_count = algorithm == 2 ? 16 : algorithm == 1 ? 8 : 3;
 error = aqm_gauge(leaf, queue_count);
 if (!error && algorithm != 2)
  error = read_poll_timeout(READ_ONCE, n, n == (algorithm == 1 ? 2 : 1),
   10, WAIT_MS * 1000, false, policy_drops);
 if (error) return error;
 error = aqm_snapshot(0, true);
 if (error) return error;
 for (i = 0; i < queue_count; i++) queue[i] = snapshots[0].ids[i];
 cpu_state = snapshots[0].state;
 if (cpu_state.count != queue_count) return -EBADMSG;
 if (algorithm == 2) {
  if (cpu_state.codel_count || cpu_state.first_above || cpu_state.drop_next || cpu_state.dropping)
   return -EBADMSG;
 } else if (cpu_state.average[algorithm == 1 ? 1 : 0] != 3218 ||
            (algorithm == 1 && cpu_state.average[2] != 6104)) return -EBADMSG;
 exported = true;
 return 0;
}

static int aqm_adopt(void)
{
 u32 i;
 int error;
 if (!exported || adopted || request || nodes[INNER].parent != -1) return -EPERM;
 for (i = 0; i < queue_count; i++)
  if (!packets[queue[i]].copied || !packets[queue[i]].skb) return -EBADMSG;
 if (!old_backing_retired) {
  if (!data_retiring) {
   for (i = 0; i < queue_count; i++)
    if (!packets[queue[i]].loaned) return -EBADMSG;
   data_retiring = true;
   stage = 2;
  }
  /* Actual ACK state makes a late command safe to continue after poll. */
  if (nodes[leaf].parent != -1) {
   error = aqm_tc(6, INNER, leaf, 0);
   if (error) return error;
  }
  if (nodes[leaf].allocated) {
   error = aqm_tc(1, leaf, 0, 0);
   if (error) return error;
  }
  error = aqm_join(&nodes[leaf].operation);
  if (error) return error;
  if (backing_retired != queue_count) return -EBADMSG;
  old_backing_retired = true;
  data_retiring = false;
 }
 /* The empty new allocation is not the logical queue owner. CPU copies
  * and cpu_state remain authoritative until rebuilding real carriers. */
 if (!nodes[leaf].allocated) {
  error = aqm_tc(0, leaf, 0, 0);
  if (error) return error;
 }
 leaf_reallocated = true;
 temporary_config = true;
 error = aqm_configure();
 if (error) return error;
 if (nodes[leaf].parent == -1) {
  error = aqm_tc(5, INNER, leaf, 0);
  if (error) return error;
 }
 error = aqm_base(&discovery);
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
 u32 i, class, q, h, limit, averages[2] = {};
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
 } else {
  class = snapshots[0].classes[0];
  if (class != (algorithm == 1 ? 1 : 0) || cpu_state.occupancy[class] < packet->length)
   return -EBADMSG;
  /* Validate both decisions and allocate both finite arrivals before changing
   * any CPU policy state. A failed allocation leaves the queue unchanged. */
  for (i = 0; i < (algorithm == 1 ? 2 : 1); i++) {
   class = algorithm == 1 ? i + 1 : 0;
   q = cpu_state.occupancy[class] - (i ? 0 : packet->length);
   h = cpu_state.average[class];
   h = h - (h >> 1) + (q >> 1);
   limit = class == 2 ? 6000 : 3000;
   if (h <= limit || (q >> 1) > limit) return -ENODATA;
   averages[i] = h;
   if (!packets[16 + i].length) {
    error = aqm_packet_create(&packets[16 + i], 16 + i, 1514, class == 2);
    if (error) return error;
   }
  }
 }
 if (algorithm == 2) {
  cpu_state.first_above = cpu_now;
  if (cpu_now - snapshots[0].ages[0] > cpu_state.delay_max)
   cpu_state.delay_max = cpu_now - snapshots[0].ages[0];
 } else {
  cpu_state.occupancy[algorithm == 1 ? 1 : 0] -= packet->length;
  for (i = 0; i < (algorithm == 1 ? 2 : 1); i++) {
   class = algorithm == 1 ? i + 1 : 0;
   cpu_state.average[class] = averages[i];
   packets[16 + i].expected_drop = true;
   dev_kfree_skb(packets[16 + i].skb); packets[16 + i].skb = NULL;
   cpu_victims++; fresh_accepts++;
  }
 }
 packet->cpu_selected = true;
 cpu_state.count--;
 stage = 3;
 cpu_selected = true;
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
   error = qdx_diag_aqm_age_import(operation, table, nodes[FQ].operation,
    &snapshot->view, i, snapshots[0].ages[j], &owner);
   if (error) break;
  }
 }
 if (!error) error = qdx_diag_aqm_import(operation, table, nodes[FQ].operation,
  &snapshot->view, &cpu_state, &owner);
 qdx_packet_op_put(operation);
 return error;
}

static int aqm_rebuild(void)
{
 u32 i, class;
 int error;
 if (!cpu_selected || rebuilt || request || nodes[INNER].parent != -1) return -EPERM;
 for (i = rebuild_next; i < queue_count; i++) {
  error = aqm_submit(&nodes[leaf].operation, nodes[leaf].tag, &packets[queue[i]]);
  if (error) return error;
  rebuild_next = i + 1;
 }
 qdx_packet_op_close(nodes[leaf].operation);
 error = aqm_gauge(leaf, queue_count - 1);
 if (error) return error;
 /* Original configuration first; RED CONFIG clears averages, not carriers.
  * Only then may CPU history be imported. Rebuild is not new user traffic. */
 temporary_config = false;
 error = aqm_configure();
 if (!error) error = aqm_snapshot(1, false);
 if (!error) error = aqm_import_state(&snapshots[1], algorithm == 2);
 if (!error) error = aqm_snapshot(2, false);
 if (error) return error;
 if (snapshots[2].state.count != cpu_state.count) return -EBADMSG;
 for (i = 0; i < cpu_state.count; i++)
  if (snapshots[2].ids[i] != queue[i + 1]) return -EBADMSG;
 if (algorithm == 2) {
  if (snapshots[2].state.first_above != cpu_now || snapshots[2].state.codel_count ||
      snapshots[2].state.drop_next || snapshots[2].state.dropping) return -EBADMSG;
  for (i = 0; i < cpu_state.count; i++)
   if (snapshots[2].ages[i] != snapshots[0].ages[i + 1]) return -EBADMSG;
 } else {
  for (class = 0; class <= (algorithm == 1 ? 2 : 0); class++)
   if (snapshots[2].state.average[class] != cpu_state.average[class] ||
       snapshots[2].state.occupancy[class] != cpu_state.occupancy[class]) return -EBADMSG;
  if (snapshots[2].state.active != cpu_state.active ||
      snapshots[2].state.idle != cpu_state.idle) return -EBADMSG;
 }
 rebuilt = true;
 return 0;
}

static int aqm_serve(void)
{
 unsigned long deadline = jiffies + msecs_to_jiffies(WAIT_MS);
 u32 i, class, h, expected_victims = algorithm == 1 ? 2 : 1;
 int error;
 if (!rebuilt || served || request) return -EPERM;
 stage = 4;
 if (!serve_prepared) {
  if (nodes[INNER].parent != -1) return -EPERM;
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
  } else {
   for (i = probe_next; i < expected_victims; i++) {
    class = algorithm == 1 ? i + 1 : 0;
    h = cpu_state.average[class] - (cpu_state.average[class] >> 1) +
     (cpu_state.occupancy[class] >> 1);
    if (h <= (class == 2 ? 6000 : 3000)) return -ENODATA;
    if (!packets[18 + i].length) {
     error = aqm_packet_create(&packets[18 + i], 18 + i, 1514, class == 2);
     if (error) return error;
    }
    packets[18 + i].expected_drop = true;
    error = aqm_submit(&probe_operation, nodes[leaf].tag, &packets[18 + i]);
    if (error) return error;
    cpu_state.average[class] = h;
    probe_next = i + 1;
   }
   error = aqm_join(&probe_operation);
   if (!error) error = aqm_gauge(leaf, queue_count - 1);
   if (!error) error = aqm_base(&discovery);
   if (error) return error;
   for (class = 0; class <= (algorithm == 1 ? 2 : 0); class++)
    if (discovery.state.average[class] != cpu_state.average[class]) return -EBADMSG;
   if (resumed_victims != expected_victims) return -EBADMSG;
  }
  serve_prepared = true;
 }
 if (!serve_published) {
  if (nodes[FQ].parent != -1) {
   error = aqm_tc(6, INNER, FQ, 0);
   if (error) return error;
  }
  if (nodes[INNER].parent == -1) {
   error = aqm_tc(5, OUTER, INNER, 0);
   if (error) return error;
  }
  if (nodes[INNER].parent != OUTER) return -EXDEV;
  serve_published = true;
  publish_ns = ktime_get_ns();
 }
 error = aqm_join(&nodes[leaf].operation);
 if (error) return error;
 if (nodes[INNER].parent != -1) {
  error = aqm_tc(6, OUTER, INNER, 0);
  if (error) return error;
 }
 if (nodes[FQ].parent == -1) {
  error = aqm_tc(5, INNER, FQ, 1);
  if (error) return error;
 }
 error = aqm_gauge(leaf, 0);
 if (!error) error = aqm_base(&discovery);
 if (error) return error;
 if (resumed_victims != expected_victims ||
     resumed_count != queue_count - 1 - (algorithm == 2 ? 1 : 0)) return -EBADMSG;
 for (i = 0; i < resumed_count; i++)
  if (resumed_order[i] != queue[i + (algorithm == 2 ? 2 : 1)]) return -EBADMSG;
 if (discovery.state.count || bad_packets || unexpected_clones) return -EBADMSG;
 snapshots[3] = discovery;
 snapshots[3].view.aqm = &snapshots[3].aqm;
 served = true; passed = true;
 return 0;
}

static int aqm_restore(void)
{
 __le32 unassign = cpu_to_le32(shaper);
 u32 i;
 int error;

 if (!pinned) return 0;
 /* Failed data qualification retains the real logical owners. A future
  * recovery must use this exact journal, never fabricate a completed run. */
 if ((loaded && !passed) || request || fault || bad_packets || copy_operation)
  return -EBUSY;
 for (i = 0; i < ARRAY_SIZE(packets); i++)
  if (packets[i].loaned || packets[i].submitted || packets[i].unexpected) return -EBUSY;
 closed = true;
 error = aqm_join(&probe_operation);
 if (error) return error;
 for (i = 0; i < NODES; i++) {
  if (i == FQ) continue;
  error = aqm_join(&nodes[i].operation);
  if (error) return error;
 }
 for (i = NODES; i-- > 0;) {
  if (nodes[i].parent == -1) continue;
  error = aqm_tc(6, nodes[i].parent, i, 0);
  if (error) return error;
 }
 if (nodes[FQ].allocated) {
  anchor_retiring = true;
  error = aqm_tc(1, FQ, 0, 0);
  if (error) return error;
 }
 error = aqm_join(&nodes[FQ].operation);
 if (error) return error;
 if (controls_retired != anchor_accepted) return -EBADMSG;
 for (i = NODES; i-- > 0;) {
  if (!nodes[i].allocated) continue;
  error = aqm_tc(1, i, 0, 0);
  if (error) return error;
 }
 if (enabled) { error = aqm_command(true, 2, NULL, 0); if (error) return error; }
 if (next_set) { error = aqm_command(true, 4, NULL, 0); if (error) return error; }
 if (assigned) { error = aqm_command(false, 8, &unassign, sizeof(unassign)); if (error) return error; }
 if (table && !qdx_diag_fq_table_idle(table)) return -EBUSY;
 if (igs && !igs_retired) {
  error = qdx_endpoint_wait(igs, jiffies);
  if (!error) error = qdx_endpoint_retire(igs);
  if (error) return error;
  igs_retired = true;
 }
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
 synchronize_net();
 for (i = 0; i < ARRAY_SIZE(packets); i++) {
  dev_kfree_skb(packets[i].skb); packets[i].skb = NULL;
 }
 for (i = 0; i < 2; i++) { dev_kfree_skb(anchor_packets[i].skb); anchor_packets[i].skb = NULL; }
 if (mirror) { qdx_endpoint_put(mirror); mirror = NULL; }
 if (igs) { qdx_endpoint_put(igs); igs = NULL; }
 if (table) { qdx_dma_release(table); table = NULL; }
 if (mirror_service) { qdx_service_put(mirror_service); mirror_service = NULL; }
 if (igs_service) { qdx_service_put(igs_service); igs_service = NULL; }
 if (port) { dev_put(port); port = NULL; }
 pinned = false;
 module_put(THIS_MODULE);
 return 0;
}

static int aqm_status_show(struct seq_file *seq, void *unused)
{
 u32 i, j, offset, length;
 struct aqm_snapshot *snapshot;
 mutex_lock(&control_lock);
 seq_printf(seq, "algorithm=%u pinned=%u prepared=%u loaded=%u exported=%u adopted=%u cpu_selected=%u rebuilt=%u served=%u passed=%u closed=%u fault=%u request=%u error=%d stage=%u leaf=%u igs=%u mirror=%u shaper=%u assigned=%u enabled=%u next_set=%u table=%u table_idle=%u copy_operation=%u probe_operation=%u copies=%u copy_ns=%llu commands=%u bad=%u policy_drops=%u backing_retired=%u controls_retired=%u unexpected_clones=%u cpu_victims=%u fresh_accepts=%u resumed_victims=%u resumed_count=%u queue_count=%u cpu_now=%llu resume_now=%llu publish_ns=%llu\n",
  algorithm, pinned, prepared, loaded, exported, adopted, cpu_selected, rebuilt, served,
  passed, closed, fault, !!request, last_error, stage, leaf, igs_ifnum, mirror_ifnum, shaper,
  assigned, enabled, next_set, !!table, table ? qdx_diag_fq_table_idle(table) : true,
  !!copy_operation, !!probe_operation, copy_count, copy_time_ns, command_count, bad_packets,
  policy_drops, backing_retired, controls_retired, unexpected_clones, cpu_victims,
  fresh_accepts, resumed_victims, resumed_count, queue_count, cpu_now, resume_now, publish_ns);
 seq_printf(seq, "journal load_next=%u rebuild_next=%u probe_next=%u anchor_accepted=%u old_backing_retired=%u leaf_reallocated=%u serve_prepared=%u serve_published=%u\n",
  load_next, rebuild_next, probe_next, anchor_accepted, old_backing_retired,
  leaf_reallocated, serve_prepared, serve_published);
 seq_printf(seq, "request_id=%llu outcome=%u firmware_error=%u declared=%zu received=%zu published=%u exposure_ended=%u pending_opcode=%u pending_node=%u pending_sub=%u\n",
  result.id, result.outcome, result.firmware_error, result.declared_len, result.received_len,
  result.published, result.exposure_ended, pending_opcode, pending_node,
  le32_to_cpu(pending_message.command));
 for (i = 0; i < NODES; i++) {
  if (!nodes[i].kind) continue;
  seq_printf(seq, "node=%u tag=%08x kind=%u allocated=%u parent=%d band=%u gauge=%u bytes=%u admitted=%llu selected=%llu dropped=%llu operation=%u drained=%u\n",
   i, nodes[i].tag, nodes[i].kind, nodes[i].allocated, nodes[i].parent, nodes[i].band,
   nodes[i].gauge, nodes[i].bytes, nodes[i].admitted, nodes[i].selected, nodes[i].dropped,
   !!nodes[i].operation, nodes[i].operation ? qdx_packet_op_drained(nodes[i].operation) : true);
 }
 for (i = 0; i < ARRAY_SIZE(snapshots); i++) {
  snapshot = &snapshots[i];
  seq_printf(seq, "snapshot=%u valid=%u anchor=%08x selector=%08x leaf_address=%08x count=%u clock=%llu first_above=%llu drop_next=%llu codel_count=%u dropping=%u idle=%llu active=%u\n",
   i, snapshot->aqm.valid, get_unaligned_le32(snapshot->view.table + 4) - 228,
   get_unaligned_le32(snapshot->view.node + 4), get_unaligned_le32(snapshot->aqm.selector + 164),
   snapshot->state.count, snapshot->clock, snapshot->state.first_above,
   snapshot->state.drop_next, snapshot->state.codel_count, snapshot->state.dropping,
   snapshot->state.idle, snapshot->state.active);
  for (j = 0; j < 7; j++)
   seq_printf(seq, "class snapshot=%u class=%u average=%u occupancy=%u\n",
    i, j, snapshot->state.average[j], snapshot->state.occupancy[j]);
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
 seq_printf(seq, "cpu count=%u first_above=%llu drop_next=%llu codel_count=%u dropping=%u idle=%llu active=%u\n",
  cpu_state.count, cpu_state.first_above, cpu_state.drop_next, cpu_state.codel_count,
  cpu_state.dropping, cpu_state.idle, cpu_state.active);
 for (i = 0; i < 7; i++)
  seq_printf(seq, "cpu_class=%u average=%u occupancy=%u\n", i,
   cpu_state.average[i], cpu_state.occupancy[i]);
 for (i = 0; i < ARRAY_SIZE(packets); i++)
  seq_printf(seq, "packet=%u length=%u held=%u loaned=%u submitted=%u copied=%u cpu_selected=%u expected_drop=%u returns=%u nulls=%u positives=%u unexpected=%u\n",
   i, packets[i].length, !!packets[i].skb, packets[i].loaned, !!packets[i].submitted,
   packets[i].copied, packets[i].cpu_selected, packets[i].expected_drop,
   packets[i].returns, packets[i].nulls, packets[i].positives, !!packets[i].unexpected);
 for (i = 0; i < min_t(u32, resumed_count, ARRAY_SIZE(resumed_order)); i++)
  seq_printf(seq, "resumed_rank=%u id=%u\n", i, resumed_order[i]);
 for (i = 0; i < min_t(u32, event_count, ARRAY_SIZE(events)); i++)
  seq_printf(seq, "event=%u stage=%u id=%u type=%u ifnum=%u positive=%u host_ns=%llu\n",
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
 mutex_lock(&control_lock);
 if (!strcmp(command, "poll")) error = aqm_wait_command();
 else if (!strcmp(command, "finish-copy")) error = aqm_copy_finish();
 else if (!strcmp(command, "restore")) error = aqm_restore();
 else if (fault || request || copy_operation || closed || bad_packets) error = -EBUSY;
 else if (!strcmp(command, "prepare")) error = aqm_prepare();
 else if (!strcmp(command, "load")) error = aqm_load();
 else if (!strcmp(command, "adopt")) error = aqm_adopt();
 else if (!strcmp(command, "cpu")) error = aqm_cpu_continue();
 else if (!strcmp(command, "rebuild")) error = aqm_rebuild();
 else if (!strcmp(command, "serve")) error = aqm_serve();
 else if (!strcmp(command, "run")) {
  error = exported ? 0 : aqm_load();
  if (!error && !adopted) error = aqm_adopt();
  if (!error && !cpu_selected) error = aqm_cpu_continue();
  if (!error && !rebuilt) error = aqm_rebuild();
  if (!error && !served) error = aqm_serve();
 } else error = -EINVAL;
 last_error = error;
 mutex_unlock(&control_lock);
 return error ?: count;
}
static const struct file_operations aqm_control_ops = {
 .owner = THIS_MODULE, .write = aqm_control_write,
};
static int __init aqm_init(void)
{
 directory = debugfs_create_dir("qdx_aqm_handover_diag", NULL);
 if (IS_ERR(directory)) return PTR_ERR(directory);
 debugfs_create_file("status", 0400, directory, NULL, &aqm_status_fops);
 debugfs_create_file("control", 0200, directory, NULL, &aqm_control_ops);
 return 0;
}
static void __exit aqm_exit(void)
{
 WARN_ON(pinned || request || table || receiver || igs || mirror || copy_operation || probe_operation);
 debugfs_remove_recursive(directory);
}
module_init(aqm_init);
module_exit(aqm_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Isolated RED/WRED and plain CoDel history continuation with actual owned payloads");
