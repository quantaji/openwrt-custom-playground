// SPDX-License-Identifier: GPL-2.0-only
/* Isolated finite rate history continuation. Not a qdisc or CPU baseline. */
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
#include <linux/qdx_diag_rate.h>
#include <linux/math64.h>
#include <linux/overflow.h>
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
struct rate_message { __le32 command, response, value[27]; };
static_assert(sizeof(struct rate_message) == 116);
enum node_id { OUTER, INNER, MAIN, CLOCK, FQ, FIFO_A, FIFO_B, FIFO_C,
 SPARE_FIRST, MARKER = SPARE_FIRST + 32, NODES };
struct rate_node {
 u32 tag, kind, gauge, bytes;
 u64 admitted, selected, dropped;
 bool allocated;
 int parent;
 u32 band;
 struct qdx_packet_op *operation;
};
static struct rate_node nodes[NODES];
struct rate_packet {
 struct sk_buff *skb, *submitted;
 u32 id, length, returns;
 bool loaned, control;
 u8 expected[FRAME_MAX];
};
struct rate_snapshot {
 struct qdx_diag_fq_view view;
 struct qdx_diag_rate_view rate;
 struct qdx_diag_rate_state state;
 u32 address[4], preferred_count, borrowing_count;
};
struct rate_cpu {
 struct qdx_diag_rate_state state;
 u32 position[3], borrowing_count;
};
struct rate_event { u32 phase, id, length; u64 time_ns; u32 type, ifnum; };
struct rate_clock_event { u64 start_ns, end_ns, raw, requested_sleep_ns, actual_sleep_ns; s64 credit; u32 stage; };
struct rate_copy_round {
 struct completion original_done, clone_done;
 u32 originals, clones, length;
 bool original_valid, clone_valid;
 u8 bytes[1004];
};
extern struct qdx_dma *qdx_diag_fq_table_alloc(struct qdx_service *, const struct qdx_owner *);
extern bool qdx_diag_fq_table_idle(struct qdx_dma *);
extern struct qdx_ready qdx_diag_fq_table_copy(struct qdx_packet_op *, struct qdx_dma *,
 const struct qdx_packet_recipient *);
static bool allow_writes;
static unsigned int group_mode;
module_param(allow_writes, bool, 0400);
module_param(group_mode, uint, 0400);
static DEFINE_MUTEX(control_lock);
static DEFINE_SPINLOCK(result_lock);
static struct dentry *directory;
static struct net_device *port;
static struct qdx_service *igs_service, *mirror_service;
static struct qdx_endpoint *igs, *mirror;
static struct qdx_receiver *receiver;
static struct qdx_dma *table;
static struct qdx_packet_op *copy_operation;
static struct qdx_request *request;
static struct qdx_result result;
static struct rate_message pending_message;
static u32 pending_opcode, pending_length, pending_node, pending_arg, pending_extra;
static bool pending_mirror;
static struct rate_packet packets[16], anchor_packets[2], private_packet;
static struct rate_snapshot snapshots[4], discovery;
static struct rate_cpu cpu;
static struct rate_copy_round copy_round;
static struct rate_event events[96];
static struct rate_clock_event clock_events[512];
static u32 event_count, clock_count, bad_packets, disposals, unexpected_clones, controls_retired;
static u32 phase, private_count, igs_ifnum = U32_MAX, mirror_ifnum = U32_MAX, shaper;
static u32 selected_mask, expected[16], fresh[16], collapsed[16], resume_order[15], resume_count;
static u32 recall_order[16], recall_count, group_id[3] = { U32_MAX, U32_MAX, U32_MAX };
static u32 memory_size, command_count, copy_count, lengths[16], joined_attempts[4];
static u64 copy_time_ns, publish_ns, first_return_ns, raw_at_import;
static bool pinned, assigned, enabled, next_set, prepared, loaded, exported;
static bool recalled, cpu_selected, rebuilt, passed, closed, fault, anchor_retiring;
static bool igs_retired, mirror_retired, initially_blocked, resumed_blocked;
static int last_error;
static const u32 quantum[3] = { 64, 128, 4096 };

/* The saved command, not a reconstructed request, remains held on timeout. */
static int rate_wait_command(void)
{
 u8 reply[116] = {};
 struct rate_message *message = (void *)reply;
 struct rate_node *node = &nodes[pending_node];
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

static int rate_command(bool mirror_command, u32 opcode, const void *payload, size_t length)
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
 return rate_wait_command();
}

static int rate_tc(u32 sub, u32 id, u32 arg, u32 extra)
{
 struct rate_message message = {};
 u8 *wire = (void *)&message;

 if (id >= NODES || ((sub == 5 || sub == 6) && arg >= NODES)) return -EINVAL;
 message.command = cpu_to_le32(sub);
 message.value[0] = cpu_to_le32(nodes[id].tag);
 if (sub == 0) {
  message.value[0] = cpu_to_le32(nodes[id].kind);
  message.value[1] = cpu_to_le32(nodes[id].tag);
 } else if (sub == 5 || sub == 6) {
  message.value[1] = cpu_to_le32(sub == 6 && nodes[id].kind == 3 ? nodes[arg].band : nodes[arg].tag);
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
  if (nodes[id].kind == 5) {
   put_unaligned_le32(id == MAIN ? 1000 : 1000000, wire + 12);
   put_unaligned_le32(id == MAIN ? 1514 : 65536, wire + 16);
   put_unaligned_le32(31, wire + 20);
  } else if (nodes[id].kind == 12) {
   u32 slot;
   for (slot = 0; slot < 3; slot++) if (group_id[slot] == id) break;
   put_unaligned_le32(slot < 3 ? quantum[slot] : 4096, wire + 12);
   put_unaligned_le32(slot == 0 ? 100 : 1000000, wire + 24);
   put_unaligned_le32(slot == 0 ? 1536 : 65536, wire + 28);
   put_unaligned_le32(31, wire + 32);
   put_unaligned_le32(id == MAIN ? 1000 : 1000000, wire + 40);
   put_unaligned_le32(id == MAIN ? 1514 : 65536, wire + 44);
   put_unaligned_le32(31, wire + 48);
  } else {
   message.value[1] = cpu_to_le32(arg);
   message.value[2] = cpu_to_le32(extra);
  }
 }
 pending_message = message;
 pending_node = id;
 pending_arg = arg;
 pending_extra = extra;
 return rate_command(false, 10, &message, sizeof(message));
}

static void rate_returned(void *owner, struct sk_buff *original,
 struct sk_buff *returned, const struct qdx_rx_meta *meta, struct napi_struct *napi)
{
 struct rate_packet *packet = owner;
 unsigned long flags;
 bool original_owned = original && original == packet->submitted;
 bool valid = original_owned && meta && meta->ifnum == READ_ONCE(igs_ifnum) &&
  meta->type == QDX_RECEIVE_RETURNED;

 spin_lock_irqsave(&result_lock, flags);
 packet->loaned = false;
 packet->submitted = NULL;
 packet->returns++;
 if (packet->control && anchor_retiring && !returned && original_owned && meta && meta->type == 1) {
  controls_retired++;
 } else if (!returned) {
  disposals++;
 } else {
  valid = valid && returned == original && returned->len == packet->length &&
   !skb_is_nonlinear(returned) && !memcmp(returned->data, packet->expected, packet->length);
  if (!valid) bad_packets++;
  /* Even a malformed positive result remains owned; failure never discards it. */
  packet->skb = returned;
  if (phase == 2 && !packet->control && packet != &private_packet) {
   if (recall_count < ARRAY_SIZE(recall_order)) recall_order[recall_count] = packet->id;
   recall_count++;
  }
  if (phase == 4 && !packet->control && packet != &private_packet) {
   if (resume_count < ARRAY_SIZE(resume_order)) resume_order[resume_count] = packet->id;
   resume_count++;
   if (!first_return_ns) first_return_ns = ktime_get_ns();
  }
 }
 if (event_count < ARRAY_SIZE(events))
  events[event_count++] = (struct rate_event) { phase, packet->id, packet->length,
   ktime_get_ns(), meta ? meta->type : U32_MAX, meta ? meta->ifnum : U32_MAX };
 else bad_packets++;
 spin_unlock_irqrestore(&result_lock, flags);
}

static int rate_packet_create(struct rate_packet *packet, u32 id, u32 length, u32 bin)
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
 put_unaligned_be16(length - ETH_HLEN, data + 16);
 data[22] = 64;
 data[23] = IPPROTO_UDP;
 put_unaligned_be32(0xc0000201, data + 26);
 put_unaligned_be32(0xc0000202, data + 30);
 put_unaligned_be16(20000 + bin, data + 34);
 put_unaligned_be16(40000, data + 36);
 put_unaligned_be16(length - ETH_HLEN - 20, data + 38);
 put_unaligned_le32(0x45544152, data + 42);
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

static int rate_submit(u32 leaf, struct rate_packet *packet)
{
 struct qdx_packet_recipient recipient = {
  .owner = { .module = THIS_MODULE, .object = packet }, .returned = rate_returned,
 };
 struct qdx_ready ready;
 struct sk_buff *skb = packet->skb;
 int error;

 if (!skb || packet->loaned || packet->submitted) return -EINVAL;
 if (!nodes[leaf].operation) {
  nodes[leaf].operation = qdx_packet_op_prepare(igs, nodes[leaf].tag, QDX_RECEIVE_RETURNED);
  if (IS_ERR(nodes[leaf].operation)) {
   error = PTR_ERR(nodes[leaf].operation); nodes[leaf].operation = NULL; return error;
  }
 }
 packet->submitted = skb;
 packet->skb = NULL;
 packet->loaned = true;
 ready = qdx_packet_op_submit(nodes[leaf].operation, skb, &recipient);
 if (ready.status == QDX_ACCEPTED) return 0;
 packet->submitted = NULL;
 packet->loaned = false;
 packet->skb = skb;
 return ready.error ?: -EAGAIN;
}

static int rate_join(u32 leaf)
{
 bool drained;
 int error;

 if (!nodes[leaf].operation) return 0;
 qdx_packet_op_close(nodes[leaf].operation);
 error = read_poll_timeout(qdx_packet_op_drained, drained, drained, 10,
  WAIT_MS * 1000, false, nodes[leaf].operation);
 if (error) return error;
 qdx_packet_op_put(nodes[leaf].operation);
 nodes[leaf].operation = NULL;
 return bad_packets || disposals ? -EBADMSG : 0;
}

static int rate_gauge(u32 leaf, u32 expected_count)
{
 unsigned long deadline = jiffies + msecs_to_jiffies(WAIT_MS);
 int error;

 do {
  error = rate_tc(4, leaf, 0, 0);
  if (error) return error;
  if (nodes[leaf].dropped || bad_packets || disposals) return -EBADMSG;
  if (nodes[leaf].gauge == expected_count) return 0;
  usleep_range(1000, 1500);
 } while (time_before(jiffies, deadline));
 return -ETIMEDOUT;
}

static int rate_private(u32 leaf, u32 length)
{
 int error;

 if (private_count >= 96) return -E2BIG;
 error = rate_packet_create(&private_packet, 0x80000000U + private_count, length, 0);
 if (!error) error = rate_submit(leaf, &private_packet);
 if (!error) error = rate_join(leaf);
 if (error) return error;
 if (!private_packet.skb || private_packet.loaned) return -EBADMSG;
 dev_kfree_skb(private_packet.skb);
 private_packet.skb = NULL;
 private_count++;
 return rate_gauge(leaf, 0);
}

static void rate_copy_original(void *owner, struct sk_buff *original,
 struct sk_buff *returned, const struct qdx_rx_meta *meta, struct napi_struct *napi)
{
 copy_round.originals++;
 copy_round.original_valid = !original && !returned && meta &&
  meta->ifnum == READ_ONCE(mirror_ifnum) && meta->type == QDX_RECEIVE_PACKET;
 complete_all(&copy_round.original_done);
}

static void rate_copy_clone(void *owner, struct sk_buff *skb,
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
static const struct qdx_receive_ops copy_ops = { .packet = rate_copy_clone };

static int rate_copy(struct qdx_diag_fq_view *view, enum qdx_diag_fq_range kind,
 u32 index, u32 length, void *destination)
{
 struct qdx_packet_recipient recipient = {
  .owner = { .module = THIS_MODULE, .object = snapshots }, .returned = rate_copy_original,
 };
 struct qdx_ready ready;
 u64 start;
 bool idle, drained;
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
 start = ktime_get_ns();
 if (kind == OWNED_TABLE) ready = qdx_diag_fq_table_copy(copy_operation, table, &recipient);
 else ready = qdx_diag_fq_owned_copy(copy_operation, table, nodes[FQ].operation,
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

static int rate_base(struct rate_snapshot *snapshot)
{
 struct qdx_diag_fq_view *view = &snapshot->view;
 struct qdx_diag_rate_view *rate = &snapshot->rate;
 unsigned int i;
 int error;

 memset(snapshot, 0, sizeof(*snapshot));
 rate->group_mode = group_mode;
 view->rate = rate;
 error = rate_copy(view, OWNED_TABLE, 0, TABLE_LEN, view->table);
 if (error) return error;
 dma_rmb();
 if (memcmp(view->table, qdx_dma_cpu(table), TABLE_LEN)) return -EBADMSG;
 for (i = 0; i < 2; i++)
  if (get_unaligned_le32(view->table + i * 72 + 24) != 1 ||
      get_unaligned_le32(view->table + i * 72 + 64) != 64)
   return -EBADMSG;
 error = rate_copy(view, QDX_DIAG_FQ_NODE, 0, 280, view->node);
 if (error) return error;
 view->node_valid = true;
 error = rate_copy(view, QDX_DIAG_RATE_SELECTOR, 0, 320, rate->selector);
 if (error) return error;
 rate->valid |= QDX_RATE_SELECTOR_VALID;
 error = rate_copy(view, QDX_DIAG_RATE_CLOCK_TBL, 0, 188, rate->clock_tbl);
 if (error) return error;
 rate->valid |= QDX_RATE_CLOCK_VALID;
 return 0;
}

static int rate_epoch(struct rate_snapshot *snapshot, unsigned int which)
{
 struct qdx_diag_rate_view *rate = &snapshot->rate;
 u8 clock[24], frequency_window[16];
 int error;

 error = rate_copy(&snapshot->view, QDX_DIAG_RATE_CLOCK, 0, 24, clock);
 if (!error) rate->clock_ms[which] = get_unaligned_le64(clock + 16);
 if (!error) error = rate_copy(&snapshot->view, QDX_DIAG_RATE_EPOCH, 0, 20, rate->epoch[which]);
 /* Clone transport retains its Ethernet-sized receive minimum. */
 if (!error) error = rate_copy(&snapshot->view, QDX_DIAG_RATE_FREQUENCY, 0, 16,
  frequency_window);
 if (!error) memcpy(rate->frequency[which], frequency_window + 4, 8);
 return error;
}

/* The legal empty TBL CONFIG invokes the fixed firmware's actual raw clock.
 * Its reference is used; its fresh credit is never used as policy history. */
static int rate_clock(struct rate_snapshot *snapshot, u64 *raw)
{
 struct qdx_diag_rate_view *rate = &snapshot->rate;
 struct rate_clock_event *event;
 int error;

 if (clock_count == ARRAY_SIZE(clock_events)) return -E2BIG;
 event = &clock_events[clock_count++];
 event->start_ns = ktime_get_ns();
 event->stage = phase;
 error = rate_tc(7, CLOCK, 0, 0);
 if (!error) error = rate_copy(&snapshot->view, QDX_DIAG_RATE_CLOCK_ACCOUNT,
  0, 312, rate->clock_account);
 event->end_ns = ktime_get_ns();
 if (error) return error;
 if (get_unaligned_le32(rate->clock_account + 280) ||
     get_unaligned_le32(rate->clock_account + 276) != 748800000)
  return -ERANGE;
 *raw = get_unaligned_le64(rate->clock_account + 300);
 event->raw = *raw;
 rate->valid |= QDX_RATE_CLOCK_ACCOUNT_VALID;
 return 0;
}

static int rate_orders(struct rate_snapshot *snapshot)
{
 struct qdx_diag_rate_view *rate = &snapshot->rate;
 struct qdx_diag_rate_state *state = &snapshot->state;
 u32 order, rank, offset, sentinel, entry, previous, count, slot, mask;
 u8 *child;

 for (order = 0; order < 2; order++) {
  for (rank = 0; rank < 4; rank++) {
   offset = (order ? 208 : 176) + rank * 8;
   sentinel = snapshot->address[0] + offset;
   entry = get_unaligned_le32(rate->group[0] + offset);
   previous = sentinel;
   count = 0;
   mask = 0;
   while (entry != sentinel) {
    if (rank || count == 3) return -ELOOP;
    for (slot = 0; slot < 3; slot++)
     if (entry == snapshot->address[slot + 1] + (order ? 988 : 972)) break;
    if (slot == 3 || (mask & BIT(slot))) return -EBADMSG;
    mask |= BIT(slot);
    child = rate->group[slot + 1] + (order ? 988 : 972);
    if (get_unaligned_le32(child + 4) != previous) return -EBADMSG;
    if (order) state->borrowing[count] = slot;
    else state->preferred[count] = slot;
    count++;
    previous = entry;
    entry = get_unaligned_le32(child);
   }
   if (get_unaligned_le32(rate->group[0] + offset + 4) != previous ||
       get_unaligned_le32(rate->group[0] + (order ? 256 : 240) + rank * 4) != count)
    return -EBADMSG;
   if (!rank) {
    if (order) snapshot->borrowing_count = count;
    else snapshot->preferred_count = state->preferred_count = count;
   }
  }
 }
 return 0;
}

/* The first copy observes pending one-shot callbacks; after their join the
 * second copy is the authoritative credit/list image and source release. */
static int rate_state_copy(struct rate_snapshot *snapshot)
{
 struct qdx_diag_rate_view *rate = &snapshot->rate;
 const u8 *account;
 u32 address, previous, alignment, header, i, j;
 int error;

 if (!group_mode) {
  error = rate_copy(&snapshot->view, QDX_DIAG_RATE_TBL, 0, 188, rate->tbl);
  if (error) return error;
  rate->valid |= QDX_RATE_TBL_VALID;
  error = rate_copy(&snapshot->view, QDX_DIAG_RATE_ACCOUNT, 0, 312, rate->account);
  if (!error) rate->valid |= QDX_RATE_ACCOUNT_VALID;
  if (!error) error = rate_copy(&snapshot->view, QDX_DIAG_RATE_TIMER, 0, 32, rate->timer);
  if (!error) error = rate_copy(&snapshot->view, QDX_DIAG_RATE_NOTIFIER, 0, 16, rate->notifier);
  if (!error) error = rate_copy(&snapshot->view, QDX_DIAG_RATE_ALLOCATOR, 0, 24, rate->allocator);
  if (error) return error;
  rate->valid |= QDX_RATE_ALLOCATOR_VALID;
  alignment = get_unaligned_le32(rate->allocator + 12);
  if (alignment < 4 || alignment > 64 || !is_power_of_2(alignment)) return -ERANGE;
  header = ALIGN(28, alignment);
  error = rate_copy(&snapshot->view, QDX_DIAG_RATE_ACCOUNT_HEADER, 0, header, rate->account_header);
  if (error) return error;
  rate->valid |= QDX_RATE_HEADER_VALID;
  snapshot->address[0] = get_unaligned_le32(rate->selector + 164);
  snapshot->state.credit[0][0] = (s64)get_unaligned_le64(rate->account + 292);
  snapshot->state.reference[0][0] = get_unaligned_le64(rate->account + 300);
 } else {
  snapshot->address[0] = get_unaligned_le32(rate->selector + 164);
  previous = snapshot->address[0] + 168;
  for (i = 0; i < 4; i++) {
   if (i) snapshot->address[i] = get_unaligned_le32(rate->group[i - 1] + (i == 1 ? 168 : 964)) - 964;
   address = snapshot->address[i];
   error = rate_copy(&snapshot->view, i ? QDX_DIAG_RATE_GROUP_CHILD : QDX_DIAG_RATE_GROUP_ROOT,
    i, 1004, rate->group[i]);
   if (error) return error;
   rate->valid |= QDX_RATE_GROUP_VALID(i);
   if (get_unaligned_le32(rate->group[i] + 16) != nodes[i ? group_id[i - 1] : MAIN].tag ||
       get_unaligned_le32(rate->group[i] + 8) != 12 ||
       get_unaligned_le32(rate->group[i] + 4) !=
        (i ? snapshot->address[0] : get_unaligned_le32(snapshot->view.node + 4)) ||
       (i && ((address + 1004) & 31)) ||
       (i && get_unaligned_le32(rate->group[i] + 968) != previous))
    return -EBADMSG;
   if (i) previous = address + 964;
   for (j = 0; j < 2; j++) {
    account = rate->group[i] + (j ? 600 : 288);
    snapshot->state.credit[i][j] = (s64)get_unaligned_le64(account + 292);
    snapshot->state.reference[i][j] = get_unaligned_le64(account + 300);
   }
   if (i) {
    snapshot->state.deficit[i - 1][0] = (s32)get_unaligned_le32(rate->group[i] + 984);
    snapshot->state.deficit[i - 1][1] = (s32)get_unaligned_le32(rate->group[i] + 1000);
    if (get_unaligned_le32(rate->group[i] + 980) != quantum[i - 1] ||
        get_unaligned_le32(rate->group[i] + 996) != quantum[i - 1]) return -EBADMSG;
   }
  }
  if (get_unaligned_le32(rate->group[3] + 964) != snapshot->address[0] + 168 ||
      get_unaligned_le32(rate->group[0] + 172) != previous) return -EBADMSG;
  error = rate_orders(snapshot);
  if (error) return error;
 }
 return 0;
}

static int rate_snapshot(unsigned int which)
{
 struct rate_snapshot *snapshot;
 struct qdx_diag_rate_view *rate;
 u64 raw;
 u32 freq, i, attempt, pass;
 int error;

 if (which >= ARRAY_SIZE(snapshots) || nodes[FQ].parent != INNER) return -EINVAL;
 snapshot = &snapshots[which];
 rate = &snapshot->rate;
 /* Producers and real selector calls are already joined. These TBL/GROUP
  * callbacks refill once and wake only the published root; they do not rearm
  * themselves. First observe every selected timer unqueued, then observe the
  * manager inactive. Only copies issued AFTER that point carry policy state.
  * Unrelated global timer generations may advance during the second copy. */
 for (attempt = 0; attempt < 20; attempt++) {
  error = rate_base(snapshot);
  if (error) return error;
  for (pass = 0; pass < 2; pass++) {
   error = rate_state_copy(snapshot);
   if (!error && pass) error = rate_clock(snapshot, &raw);
   if (!error) error = rate_epoch(snapshot, pass);
   if (error) return error;
   freq = get_unaligned_le32(rate->frequency[pass] + 4);
   if (get_unaligned_le32(rate->frequency[pass]) & 1) break;
   if (!group_mode) {
    if ((get_unaligned_le32(rate->timer + 24) & 2) ||
        get_unaligned_le32(rate->notifier + 12) != freq) break;
   } else {
    for (i = 0; i < 4; i++)
     if ((get_unaligned_le32(rate->group[i] + 952) & 2) ||
         (get_unaligned_le32(rate->group[i] + 960) & 1) ||
         get_unaligned_le32(rate->group[i] + 924) != freq) break;
    if (i != 4) break;
   }
   if (!pass) {
    if ((get_unaligned_le32(rate->epoch[0]) & 1) ||
        (get_unaligned_le32(rate->epoch[0] + 16) & 1)) break;
   } else if (get_unaligned_le32(rate->frequency[0] + 4) != freq ||
              rate->clock_ms[1] < rate->clock_ms[0] ||
              rate->clock_ms[1] - rate->clock_ms[0] >= 32768) break;
  }
  if (pass != 2) continue;
  rate->valid |= QDX_RATE_TIMERS_JOINED;
  joined_attempts[which] = attempt + 1;
  return 0;
 }
 return -EAGAIN;
}

static const u8 *rate_account(unsigned int group, unsigned int kind)
{
 return group_mode ? snapshots[0].rate.group[group] + (kind ? 600 : 288) :
  snapshots[0].rate.account;
}

static int rate_refill(struct qdx_diag_rate_state *state, unsigned int group,
 unsigned int kind, u64 now)
{
 const u8 *account = rate_account(group, kind);
 u32 shift = get_unaligned_le32(account + 272);
 s64 value, cap = (s64)get_unaligned_le64(account + 284);
 u64 elapsed;

 if (get_unaligned_le32(account + 280) || shift > 31 || cap <= 0 ||
     state->reference[group][kind] > now) return -ERANGE;
 elapsed = now - state->reference[group][kind];
 if (elapsed > (U64_MAX >> shift) || (elapsed << shift) > S64_MAX ||
     check_add_overflow(state->credit[group][kind], (s64)(elapsed << shift), &value))
  return -EOVERFLOW;
 state->credit[group][kind] = min(value, cap);
 state->reference[group][kind] = now;
 return 0;
}

/* Debt is in the account's left-shifted credit units, not raw ticks. */
static u64 rate_debt_ticks(const struct qdx_diag_rate_state *state,
 unsigned int group, unsigned int kind)
{
 const u8 *account = rate_account(group, kind);
 u32 shift = get_unaligned_le32(account + 272);
 s64 credit = state->credit[group][kind];

 if (credit >= 0 || credit == S64_MIN || shift > 31) return 0;
 return (u64)(-credit) >> shift;
}

static int rate_debit(struct qdx_diag_rate_state *state, unsigned int group,
 unsigned int kind, u32 length)
{
 const u8 *account = rate_account(group, kind);
 u64 cost, whole, remainder, quotient;
 s64 credit;

 if (!length || get_unaligned_le32(account + 268) || get_unaligned_le32(account + 308))
  return -ERANGE;
 quotient = (length - 1) / 31;
 remainder = length - quotient * 31;
 whole = get_unaligned_le64(account + 12 + 31 * 8);
 if (whole > S64_MAX || check_mul_overflow(quotient, whole, &cost) ||
     check_add_overflow(cost, get_unaligned_le64(account + 12 + remainder * 8), &cost) ||
     cost > S64_MAX || check_sub_overflow(state->credit[group][kind], (s64)cost, &credit))
  return -EOVERFLOW;
 state->credit[group][kind] = credit;
 return 0;
}

/* Under this fixture's directly checked regime, time gates only delay service:
 * A stays outside preferred; B/C and every child ceiling stay eligible.
 * The whole finite ordering oracle still preserves the two separate lists. */
static int rate_choose(struct rate_cpu *state)
{
 u8 *order;
 u32 count, which, slot, id, rotations = 0, i, j;
 s32 updated;

 if (!group_mode) return state->position[0] < 16 ? state->position[0]++ : -ENOENT;
 which = state->state.preferred_count ? 0 : 1;
 order = which ? state->state.borrowing : state->state.preferred;
 count = which ? state->borrowing_count : state->state.preferred_count;
 while (count) {
  slot = order[0];
  if (slot >= 3) return -EBADMSG;
  if (state->state.deficit[slot][which] < 0) {
   if (++rotations > 512 || check_add_overflow(state->state.deficit[slot][which],
       (s32)quantum[slot], &updated)) return -ERANGE;
   state->state.deficit[slot][which] = updated;
   for (i = 1; i < count; i++) order[i - 1] = order[i];
   order[count - 1] = slot;
   continue;
  }
  if (state->position[slot] >= (slot ? 4 : 8)) return -EBADMSG;
  id = (slot == 0 ? 0 : slot == 1 ? 8 : 12) + state->position[slot]++;
  state->state.deficit[slot][which] -= lengths[id];
  if (state->position[slot] == (slot ? 4 : 8)) {
   for (j = 0; j < 2; j++) {
    order = j ? state->state.borrowing : state->state.preferred;
    count = j ? state->borrowing_count : state->state.preferred_count;
    for (i = 0; i < count && order[i] != slot; i++) {}
    if (i == count) continue;
    for (; i + 1 < count; i++) order[i] = order[i + 1];
    if (j) state->borrowing_count--;
    else state->state.preferred_count--;
   }
  }
  return id;
 }
 return -ENOENT;
}
static int rate_prepare(void)
{
 struct qdx_owner owner = { .module = THIS_MODULE, .object = snapshots };
 __le32 assignment[2] = {}, next = cpu_to_le32(156);
 struct { __le32 point; __le16 size, offset; } mirror_cfg = {
  cpu_to_le32(1), cpu_to_le16(1004), 0,
 };
 u32 i, found = 0, address, selector_address;
 int error;

 if (pinned || closed || group_mode > 1) return -EPERM;
 if (!try_module_get(THIS_MODULE)) return -ENODEV;
 pinned = true;
 for (i = 0; i < NODES; i++) nodes[i].parent = -1;
 nodes[OUTER].tag = 0x71000000; nodes[OUTER].kind = 3;
 nodes[INNER].tag = 0x71080000; nodes[INNER].kind = 3;
 nodes[MAIN].tag = 0x71010000; nodes[MAIN].kind = group_mode ? 12 : 5;
 nodes[CLOCK].tag = 0x71020000; nodes[CLOCK].kind = 5;
 nodes[FQ].tag = TABLE_TAG; nodes[FQ].kind = 1;
 for (i = FIFO_A; i <= FIFO_C; i++) {
  nodes[i].tag = 0x71030000 + (i - FIFO_A) * 0x10000;
  nodes[i].kind = 4;
 }
 for (i = 0; i < 32; i++) {
  nodes[SPARE_FIRST + i].tag = 0x71200000 + i * 0x10000;
  nodes[SPARE_FIRST + i].kind = 12;
 }
 nodes[MARKER].tag = 0x71060000; nodes[MARKER].kind = 4;
 for (i = 0; i < 16; i++) lengths[i] = 64;
 lengths[group_mode ? 12 : 0] = 1514;
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
 error = rate_command(false, 6, assignment, sizeof(assignment));
 for (i = 0; !error && i < NODES; i++) {
  if (!group_mode && (i == FIFO_B || i == FIFO_C || (i >= SPARE_FIRST && i < MARKER))) continue;
  error = rate_tc(0, i, 0, 0);
 }
 if (!error) error = rate_tc(10, FQ, 0, 0);
 if (error) return error;
 if (memory_size != 72) return -EPROTO;
 table = qdx_diag_fq_table_alloc(igs_service, &owner);
 if (IS_ERR(table)) { error = PTR_ERR(table); table = NULL; return error; }
 error = rate_tc(7, FQ, 0, 0);
 for (i = FIFO_A; !error && i <= (group_mode ? FIFO_C : FIFO_A); i++)
  error = rate_tc(7, i, 32, 1);
 if (!error) error = rate_tc(5, INNER, MAIN, 0);
 if (!error) error = rate_tc(5, INNER, FQ, 1);
 if (!error) error = rate_tc(5, INNER, CLOCK, 2);
 if (!error) error = rate_tc(7, MAIN, 0, 0);
 if (!error) error = rate_tc(7, CLOCK, 0, 0);
 for (i = 0; !error && group_mode && i < 32; i++)
  error = rate_tc(5, INNER, SPARE_FIRST + i, 3 + i);
 if (!error) error = rate_tc(7, MARKER, 8, 1);
 if (!error) error = rate_tc(5, OUTER, MARKER, 2);
 if (!error) error = rate_tc(3, OUTER, 0, 0);
 if (!error) error = rate_command(true, 0, &mirror_cfg, sizeof(mirror_cfg));
 if (!error) error = rate_command(true, 3, &next, sizeof(next));
 if (!error) error = rate_command(true, 1, NULL, 0);
 if (error) return error;
 phase = 0;
 for (i = 0; i < 2; i++) {
  error = rate_packet_create(&anchor_packets[i], 0x40000000 + i, 64, i);
  if (error) return error;
  anchor_packets[i].control = true;
  error = rate_submit(FQ, &anchor_packets[i]);
  if (error) return error;
 }
 qdx_packet_op_close(nodes[FQ].operation);
 error = rate_gauge(FQ, 2);
 if (!error) error = rate_base(&discovery);
 if (error) return error;
 if (group_mode) {
  selector_address = get_unaligned_le32(discovery.view.node + 4);
  for (i = 0; i < 32; i++) {
   address = get_unaligned_le32(discovery.rate.selector + 176 + i * 4);
   if ((address + 1004) & 31) continue;
   error = rate_copy(&discovery.view, QDX_DIAG_RATE_SPARE_GROUP, i, 1004, discovery.rate.spare);
   if (error) return error;
   if (get_unaligned_le32(discovery.rate.spare + 8) != 12 ||
       get_unaligned_le32(discovery.rate.spare + 16) != nodes[SPARE_FIRST + i].tag ||
       get_unaligned_le32(discovery.rate.spare + 4) != selector_address ||
       !discovery.rate.spare[24] ||
       get_unaligned_le32(discovery.rate.spare + 20) != get_unaligned_le32(discovery.view.node + 20) ||
       get_unaligned_le32(discovery.rate.spare + 36) != get_unaligned_le32(discovery.view.node + 36) ||
       get_unaligned_le32(discovery.rate.spare + 48) != 0x400608e0 ||
       get_unaligned_le32(discovery.rate.spare + 60) != 0x4005fbc0 ||
       get_unaligned_le32(discovery.rate.spare + 164) ||
       get_unaligned_le32(discovery.rate.spare + 272)) return -EBADMSG;
   group_id[found++] = SPARE_FIRST + i;
   if (found == 3) break;
  }
  if (found != 3) return -ENOSPC;
  for (i = 0; !error && i < 3; i++) {
   error = rate_tc(6, INNER, group_id[i], 0);
   if (!error) error = rate_tc(5, MAIN, group_id[i], 0);
   if (!error) error = rate_tc(7, group_id[i], 0, 0);
   if (!error) error = rate_tc(5, group_id[i], FIFO_A + i, 0);
  }
 } else error = rate_tc(5, MAIN, FIFO_A, 0);
 if (error) return error;
 prepared = true;
 return 0;
}

static int rate_load(void)
{
 struct rate_snapshot *snapshot = &snapshots[0];
 u32 i, slot, leaf;
 int error;

 if (!prepared || loaded || request || nodes[INNER].parent != -1) return -EPERM;
 loaded = true;
 phase = 0;
 error = rate_tc(6, INNER, FQ, 0);
 if (!error) error = rate_tc(5, OUTER, INNER, 0);
 if (!error && group_mode) error = rate_private(FIFO_B, 64);
 if (!error) error = rate_private(FIFO_A, 1514);
 if (!error) error = rate_private(FIFO_A, 1514);
 if (error) return error;
 phase = 1;
 for (i = 0; i < 16; i++) {
  slot = !group_mode || i < 8 ? 0 : i < 12 ? 1 : 2;
  leaf = FIFO_A + slot;
  error = rate_packet_create(&packets[i], i, lengths[i], slot);
  if (!error) error = rate_submit(leaf, &packets[i]);
  if (error) return error;
 }
 for (i = 0; i < (group_mode ? 3 : 1); i++) {
  qdx_packet_op_close(nodes[FIFO_A + i].operation);
  error = rate_gauge(FIFO_A + i, group_mode ? (i ? 4 : 8) : 16);
  if (error) return error;
 }
 for (i = 0; i < 16; i++) if (packets[i].returns || !packets[i].loaned) return -EBADMSG;
 error = rate_tc(6, OUTER, INNER, 0);
 /* A detached child may already be inside a root dequeue. This ordinary
  * same-root private packet must return before the policy snapshot begins. */
 if (!error) error = rate_private(MARKER, 64);
 if (!error) error = rate_tc(5, INNER, FQ, 1);
 if (!error) error = rate_snapshot(0);
 if (error) return error;
 if (snapshot->state.credit[0][group_mode ? 1 : 0] >= 0) return -ENODATA;
 if (group_mode && (snapshot->preferred_count != 2 || snapshot->borrowing_count != 3 ||
     snapshot->state.preferred[0] != 1 || snapshot->state.preferred[1] != 2 ||
     snapshot->state.borrowing[0] != 0 || snapshot->state.borrowing[1] != 1 ||
     snapshot->state.borrowing[2] != 2 || snapshot->state.deficit[1][0] != -64 ||
     snapshot->state.deficit[2][0] != 0 || snapshot->state.credit[1][0] >= 0))
  return -EBADMSG;
 exported = true;
 return 0;
}

static int rate_recall(void)
{
 u32 slot, i;
 int error;

 if (!exported || recalled || request) return -EPERM;
 phase = 2;
 for (slot = 0; slot < (group_mode ? 3 : 1); slot++) {
  error = rate_tc(6, group_mode ? group_id[slot] : MAIN, FIFO_A + slot, 0);
  if (!error) error = rate_tc(5, OUTER, FIFO_A + slot, 1);
  if (!error) error = rate_join(FIFO_A + slot);
  if (!error) error = rate_gauge(FIFO_A + slot, 0);
  if (!error) error = rate_tc(6, OUTER, FIFO_A + slot, 0);
  if (error) return error;
 }
 if (recall_count != 16) return -EBADMSG;
 for (i = 0; i < 16; i++)
  if (!packets[i].skb || packets[i].loaned || packets[i].returns != 1 || recall_order[i] != i)
   return -EBADMSG;
 recalled = true;
 return 0;
}

static int rate_cpu_continue(void)
{
 struct rate_cpu model, reset, one_order;
 struct qdx_diag_rate_state eligibility;
 u64 raw, parent_time, debt_ns, elapsed_ns, wait_ns, sleep_start;
 u32 wait_us, i, kind = group_mode ? 1 : 0;
 unsigned long deadline = jiffies + msecs_to_jiffies(WAIT_MS);
 int error, id;

 if (!recalled || cpu_selected || request) return -EPERM;
 cpu.state = snapshots[0].state;
 cpu.borrowing_count = snapshots[0].borrowing_count;
 phase = 3;
 for (;;) {
  error = rate_clock(&snapshots[0], &raw);
  if (!error) error = rate_refill(&cpu.state, 0, kind, raw);
  if (error) return error;
  clock_events[clock_count - 1].credit = cpu.state.credit[0][kind];
  if (cpu.state.credit[0][kind] > 0) break;
  initially_blocked = true;
  if (time_after_eq(jiffies, deadline)) return -ETIMEDOUT;
  /* A wake hint only: subtract all host time since the actual clock command
   * began, so this estimate tends to wake early. Only the next NSS raw sample
   * grants eligibility. The20ms cap is not a policy timing tolerance. */
  debt_ns = div64_u64((min_t(u64, rate_debt_ticks(&cpu.state, 0, kind),
   748800000ULL * WAIT_MS / 1000) + 1) * NSEC_PER_SEC, 748800000);
  elapsed_ns = ktime_get_ns() - clock_events[clock_count - 1].start_ns;
  wait_ns = debt_ns > elapsed_ns ? debt_ns - elapsed_ns : 0;
  wait_us = clamp_t(u64, div_u64(wait_ns, 1000), 1000, 20000);
  clock_events[clock_count - 1].requested_sleep_ns = wait_us * 1000ULL;
  sleep_start = ktime_get_ns();
  usleep_range(wait_us, wait_us + 50);
  clock_events[clock_count - 1].actual_sleep_ns = ktime_get_ns() - sleep_start;
 }
 /* A real blocked attempt is required; an already expired copied debt is not
  * evidence that the CPU honoured a rate gate. No host-time approximation. */
 if (!initially_blocked) return -ENODATA;
 parent_time = raw;
 if (group_mode) {
  for (i = 1; i < 4; i++) {
   eligibility = cpu.state;
   error = rate_refill(&eligibility, i, 0, raw);
   if (!error) error = rate_refill(&eligibility, i, 1, raw);
   if (error) return error;
   if (eligibility.credit[i][1] <= 0 ||
       (i == 1 ? rate_debt_ticks(&eligibility, i, 0) <= 6ULL * 748800000 : eligibility.credit[i][0] <= 0))
    return -ERANGE;
  }
 }
 id = rate_choose(&cpu);
 if (id != (group_mode ? 12 : 0)) return -EBADMSG;
 expected[0] = id;
 if (group_mode) {
  /* Child ceil reads its own actual raw sample. Child own uses the parent's
   * start sample, as the fixed dequeue passes that earlier timestamp. */
  error = rate_clock(&snapshots[0], &raw);
  if (!error) error = rate_refill(&cpu.state, 3, 1, raw);
  if (!error && cpu.state.credit[3][1] <= 0) error = -ERANGE;
  if (!error) error = rate_debit(&cpu.state, 3, 1, lengths[id]);
  if (!error) error = rate_refill(&cpu.state, 3, 0, parent_time);
  if (!error) error = rate_debit(&cpu.state, 3, 0, lengths[id]);
  if (!error && cpu.state.credit[3][0] <= 0) error = -ERANGE;
  if (error) return error;
 }
 error = rate_debit(&cpu.state, 0, kind, lengths[id]);
 if (error) return error;
 if (rate_debt_ticks(&cpu.state, 0, kind) <= 748800000) return -ENODATA;
 selected_mask = BIT(id);
 model = cpu;
 reset = cpu;
 one_order = cpu;
 if (group_mode) {
  reset.state.preferred_count = 3;
  for (i = 0; i < 3; i++) {
   reset.state.preferred[i] = i;
   reset.state.deficit[i][0] = reset.state.deficit[i][1] = 0;
  }
  one_order.state.preferred[0] = 1;
  one_order.state.preferred[1] = 2;
 }
 for (i = 1; i < 16; i++) {
  id = rate_choose(&model);
  if (id < 0) return id;
  expected[i] = id;
  id = rate_choose(&reset);
  if (id < 0) return id;
  fresh[i] = id;
  id = rate_choose(&one_order);
  if (id < 0) return id;
  collapsed[i] = id;
 }
 if (group_mode && (!memcmp(expected + 1, fresh + 1, 15 * sizeof(u32)) ||
                    !memcmp(expected + 1, collapsed + 1, 15 * sizeof(u32)))) return -ENODATA;
 cpu_selected = true;
 return 0;
}
static int rate_rebuild(void)
{
 struct qdx_owner owner = { .module = THIS_MODULE, .object = snapshots };
 struct qdx_packet_op *operation;
 struct qdx_diag_rate_state eligibility;
 const u8 *before, *after;
 u32 i, j, slot, kind = group_mode ? 1 : 0;
 int error;

 if (!cpu_selected || rebuilt || request) return -EPERM;
 /* Deliberately exercise the real reset-prone parent attachments BEFORE
  * importing history; all accepted data originals remain in CPU ownership. */
 for (i = 0; group_mode && i < 3; i++) {
  error = rate_tc(6, MAIN, group_id[i], 0);
  if (error) return error;
 }
 for (i = 0; group_mode && i < 3; i++) {
  error = rate_tc(5, MAIN, group_id[i], 0);
  if (!error) error = rate_tc(7, group_id[i], 0, 0);
  if (error) return error;
 }
 error = rate_tc(7, MAIN, 0, 0);
 for (i = 0; !error && i < (group_mode ? 3 : 1); i++)
  error = rate_tc(5, group_mode ? group_id[i] : MAIN, FIFO_A + i, 0);
 if (error) return error;
 for (i = 0; i < 16; i++) {
  if (selected_mask & BIT(i)) continue;
  slot = !group_mode || i < 8 ? 0 : i < 12 ? 1 : 2;
  error = rate_submit(FIFO_A + slot, &packets[i]);
  if (error) return error;
 }
 for (i = 0; i < (group_mode ? 3 : 1); i++) {
  qdx_packet_op_close(nodes[FIFO_A + i].operation);
  error = rate_gauge(FIFO_A + i, group_mode ? (i == 0 ? 8 : i == 1 ? 4 : 3) : 15);
  if (error) return error;
 }
 error = rate_snapshot(1);
 if (error) return error;
 for (i = 0; i < (group_mode ? 4 : 1); i++) {
  for (j = 0; j < (group_mode ? 2 : 1); j++) {
   before = rate_account(i, j);
   after = group_mode ? snapshots[1].rate.group[i] + (j ? 600 : 288) : snapshots[1].rate.account;
   if (memcmp(before, after, 292)) return -ESTALE;
  }
 }
 raw_at_import = get_unaligned_le64(snapshots[1].rate.clock_account + 300);
 eligibility = cpu.state;
 error = rate_refill(&eligibility, 0, kind, raw_at_import);
 if (error) return error;
 if (rate_debt_ticks(&eligibility, 0, kind) <= 74880000) return -ENODATA;
 if (group_mode) {
  error = rate_refill(&eligibility, 1, 0, raw_at_import);
  if (error) return error;
  if (rate_debt_ticks(&eligibility, 1, 0) <= 6ULL * 748800000) return -ERANGE;
 }
 operation = qdx_packet_op_prepare(mirror, COPY_TAG, QDX_RECEIVE_PACKET);
 if (IS_ERR(operation)) return PTR_ERR(operation);
 qdx_packet_op_close(operation);
 error = qdx_diag_rate_import(operation, table, nodes[FQ].operation,
  &snapshots[1].view, &cpu.state, &owner);
 qdx_packet_op_put(operation);
 if (error) return error;
 error = rate_snapshot(2);
 if (error) return error;
 for (i = 0; i < (group_mode ? 4 : 1); i++)
  for (j = 0; j < (group_mode ? 2 : 1); j++)
   if (snapshots[2].state.credit[i][j] != cpu.state.credit[i][j] ||
       snapshots[2].state.reference[i][j] != cpu.state.reference[i][j]) return -EBADMSG;
 if (group_mode) {
  if (snapshots[2].preferred_count != 2 || snapshots[2].borrowing_count != 3 ||
      memcmp(snapshots[2].state.preferred, cpu.state.preferred, 2) ||
      memcmp(snapshots[2].state.borrowing, cpu.state.borrowing, 3) ||
      memcmp(snapshots[2].state.deficit, cpu.state.deficit, sizeof(cpu.state.deficit)))
   return -EBADMSG;
 }
 /* Import itself must not consume the whole remaining debt interval. */
 eligibility = cpu.state;
 error = rate_refill(&eligibility, 0, kind,
  get_unaligned_le64(snapshots[2].rate.clock_account + 300));
 if (error) return error;
 if (rate_debt_ticks(&eligibility, 0, kind) <= 7488000) return -ENODATA;
 rebuilt = true;
 return 0;
}

static int rate_serve(void)
{
 struct qdx_diag_rate_state eligibility;
 u64 raw;
 u32 i;
 int error;

 if (!rebuilt || passed || request || nodes[FQ].parent != INNER) return -EPERM;
 phase = 4;
 error = rate_clock(&snapshots[2], &raw);
 eligibility = cpu.state;
 if (!error) error = rate_refill(&eligibility, 0, group_mode ? 1 : 0, raw);
 if (error) return error;
 if (rate_debt_ticks(&eligibility, 0, group_mode ? 1 : 0) <= 74880000) return -ENODATA;
 error = rate_tc(6, INNER, FQ, 0);
 publish_ns = ktime_get_ns();
 if (!error) error = rate_tc(5, OUTER, INNER, 0);
 for (i = 0; !error && i < (group_mode ? 3 : 1); i++) {
  error = rate_tc(4, FIFO_A + i, 0, 0);
  if (!error && nodes[FIFO_A + i].gauge != (group_mode ? (i == 0 ? 8 : i == 1 ? 4 : 3) : 15))
   error = -ENODATA;
 }
 if (error) return error;
 if (READ_ONCE(resume_count)) return -ENODATA;
 resumed_blocked = true;
 for (i = 0; !error && i < (group_mode ? 3 : 1); i++) error = rate_join(FIFO_A + i);
 for (i = 0; !error && i < (group_mode ? 3 : 1); i++) error = rate_gauge(FIFO_A + i, 0);
 if (error) return error;
 if (resume_count != 15 || memcmp(resume_order, expected + 1, sizeof(resume_order)) ||
     !first_return_ns || first_return_ns <= publish_ns) return -EBADMSG;
 for (i = 0; i < 16; i++)
  if (!packets[i].skb || packets[i].loaned ||
      packets[i].returns != ((selected_mask & BIT(i)) ? 1 : 2)) return -EBADMSG;
 error = rate_tc(6, OUTER, INNER, 0);
 if (!error) error = rate_tc(5, INNER, FQ, 1);
 if (!error) error = rate_snapshot(3);
 if (error) return error;
 if (group_mode && (snapshots[3].preferred_count || snapshots[3].borrowing_count))
  return -EBADMSG;
 passed = true;
 return 0;
}
static int rate_restore(void)
{
 __le32 unassign = cpu_to_le32(shaper);
 unsigned int i;
 int error;

 if (!pinned) return 0;
 /* No purge or synthetic disposal is a recovery for a failed logical run. */
 if ((loaded && !passed) || request || fault || bad_packets || disposals || copy_operation)
  return -EBUSY;
 for (i = 0; i < 16; i++) if (packets[i].loaned) return -EBUSY;
 closed = true;
 for (i = 0; i < NODES; i++) {
  if (i == FQ) continue;
  error = rate_join(i);
  if (error) return error;
 }
 for (i = NODES; i-- > 0;) {
  if (nodes[i].parent == -1) continue;
  error = rate_tc(6, nodes[i].parent, i, 0);
  if (error) return error;
 }
 if (nodes[FQ].allocated) {
  anchor_retiring = true;
  error = rate_tc(1, FQ, 0, 0);
  if (!error) error = rate_join(FQ);
  if (error) return error;
  if (anchor_packets[1].control && controls_retired != 2) return -EBADMSG;
 }
 for (i = NODES; i-- > 0;) {
  if (!nodes[i].allocated) continue;
  error = rate_tc(1, i, 0, 0);
  if (error) return error;
 }
 if (enabled) {
  error = rate_command(true, 2, NULL, 0);
  if (error) return error;
 }
 if (next_set) {
  error = rate_command(true, 4, NULL, 0);
  if (error) return error;
 }
 if (assigned) {
  error = rate_command(false, 8, &unassign, sizeof(unassign));
  if (error) return error;
 }
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
 for (i = 0; i < 16; i++) { dev_kfree_skb(packets[i].skb); packets[i].skb = NULL; }
 for (i = 0; i < 2; i++) { dev_kfree_skb(anchor_packets[i].skb); anchor_packets[i].skb = NULL; }
 dev_kfree_skb(private_packet.skb); private_packet.skb = NULL;
 qdx_endpoint_put(mirror); mirror = NULL;
 qdx_endpoint_put(igs); igs = NULL;
 if (table) { qdx_dma_release(table); table = NULL; }
 qdx_service_put(mirror_service); mirror_service = NULL;
 qdx_service_put(igs_service); igs_service = NULL;
 if (port) dev_put(port);
 port = NULL;
 pinned = false;
 module_put(THIS_MODULE);
 return 0;
}

static int rate_status_show(struct seq_file *seq, void *unused)
{
 u32 i, j, kind, offset, width;
 const u8 *account;

 mutex_lock(&control_lock);
 seq_printf(seq, "mode=%u pinned=%u prepared=%u loaded=%u exported=%u recalled=%u cpu_selected=%u rebuilt=%u passed=%u closed=%u fault=%u assigned=%u enabled=%u next_set=%u request=%u error=%d phase=%u igs=%u mirror=%u shaper=%u table_idle=%u copies=%u copy_ns=%llu commands=%u private_frames=%u bad=%u disposals=%u controls_retired=%u unexpected_clones=%u selected_mask=%x resumed=%u blocked=%u resumed_blocked=%u publish_ns=%llu first_return_ns=%llu raw_at_import=%llu\n",
  group_mode, pinned, prepared, loaded, exported, recalled, cpu_selected, rebuilt, passed,
  closed, fault, assigned, enabled, next_set, !!request, last_error, phase, igs_ifnum,
  mirror_ifnum, shaper, table ? qdx_diag_fq_table_idle(table) : true, copy_count,
  copy_time_ns, command_count, private_count, bad_packets, disposals, controls_retired,
  unexpected_clones, selected_mask, resume_count, initially_blocked, resumed_blocked, publish_ns, first_return_ns,
  raw_at_import);
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
 for (i = 0; i < 4; i++) {
  seq_printf(seq, "snapshot=%u valid=%x joined_attempts=%u preferred_count=%u borrowing_count=%u preferred=%u,%u,%u borrowing=%u,%u,%u ms=%llu,%llu epoch=%u,%u frequency=%u,%u\n",
   i, snapshots[i].rate.valid, joined_attempts[i], snapshots[i].preferred_count,
   snapshots[i].borrowing_count, snapshots[i].state.preferred[0], snapshots[i].state.preferred[1],
   snapshots[i].state.preferred[2], snapshots[i].state.borrowing[0], snapshots[i].state.borrowing[1],
   snapshots[i].state.borrowing[2], snapshots[i].rate.clock_ms[0], snapshots[i].rate.clock_ms[1],
   get_unaligned_le16(snapshots[i].rate.epoch[0] + 12), get_unaligned_le16(snapshots[i].rate.epoch[1] + 12),
   get_unaligned_le32(snapshots[i].rate.frequency[0] + 4), get_unaligned_le32(snapshots[i].rate.frequency[1] + 4));
  for (j = 0; j < (group_mode ? 4 : 1); j++) {
   for (kind = 0; kind < (group_mode ? 2 : 1); kind++) {
    account = group_mode ? snapshots[i].rate.group[j] + (kind ? 600 : 288) : snapshots[i].rate.account;
    seq_printf(seq, "account snapshot=%u group=%u kind=%u address=%08x credit=%lld reference=%llu shift=%u time_shift=%u cap=%lld frequency=%u\n",
     i, j, kind, snapshots[i].address[j], snapshots[i].state.credit[j][kind],
     snapshots[i].state.reference[j][kind], get_unaligned_le32(account + 272),
     get_unaligned_le32(account + 280), (s64)get_unaligned_le64(account + 284), get_unaligned_le32(account + 276));
   }
   if (j) seq_printf(seq, "group snapshot=%u slot=%u id=%u deficit=%d,%d quantum=%u\n",
    i, j - 1, group_id[j - 1], snapshots[i].state.deficit[j - 1][0],
    snapshots[i].state.deficit[j - 1][1], quantum[j - 1]);
  }
 }
 for (i = 0; i < (group_mode ? 4 : 1); i++)
  for (j = 0; j < (group_mode ? 2 : 1); j++)
   seq_printf(seq, "cpu group=%u kind=%u credit=%lld reference=%llu\n",
    i, j, cpu.state.credit[i][j], cpu.state.reference[i][j]);
 for (i = 0; i < 16; i++)
  seq_printf(seq, "packet=%u length=%u held=%u loaned=%u returns=%u expected=%u fresh=%u collapsed=%u\n",
   i, packets[i].length, !!packets[i].skb, packets[i].loaned, packets[i].returns,
   expected[i], fresh[i], collapsed[i]);
 for (i = 0; i < min_t(u32, recall_count, ARRAY_SIZE(recall_order)); i++)
  seq_printf(seq, "recalled_index=%u id=%u\n", i, recall_order[i]);
 for (i = 0; i < min_t(u32, resume_count, ARRAY_SIZE(resume_order)); i++)
  seq_printf(seq, "resumed_index=%u id=%u\n", i, resume_order[i]);
 for (i = 0; i < min_t(u32, event_count, ARRAY_SIZE(events)); i++)
  seq_printf(seq, "event=%u phase=%u id=%u length=%u ns=%llu type=%u ifnum=%u\n",
   i, events[i].phase, events[i].id, events[i].length, events[i].time_ns, events[i].type, events[i].ifnum);
 for (i = 0; i < min_t(u32, clock_count, ARRAY_SIZE(clock_events)); i++)
  seq_printf(seq, "clock=%u stage=%u start_ns=%llu end_ns=%llu raw=%llu credit=%lld requested_sleep_ns=%llu actual_sleep_ns=%llu\n",
   i, clock_events[i].stage, clock_events[i].start_ns, clock_events[i].end_ns,
   clock_events[i].raw, clock_events[i].credit, clock_events[i].requested_sleep_ns,
   clock_events[i].actual_sleep_ns);
 /* Complete actual bytes remain reviewable; normal decisions use the summary
  * above. No host reads of guessed device addresses are exposed. */
 for (i = 0; i < 4; i++) {
  seq_printf(seq, "epoch_bytes snapshot=%u before=%*phN after=%*phN\n",
   i, 20, snapshots[i].rate.epoch[0], 20, snapshots[i].rate.epoch[1]);
  if (!group_mode) {
   seq_printf(seq, "allocator snapshot=%u manager=%*phN header=%*phN timer=%*phN notifier=%*phN\n",
    i, 24, snapshots[i].rate.allocator, 64, snapshots[i].rate.account_header,
    32, snapshots[i].rate.timer, 16, snapshots[i].rate.notifier);
  }
  for (j = 0; j < (group_mode ? 4 : 1); j++) {
   for (offset = 0; offset < (group_mode ? 1004 : 312); offset += width) {
    width = min_t(u32, 64, (group_mode ? 1004 : 312) - offset);
    seq_printf(seq, "state_bytes snapshot=%u group=%u offset=%u data=%*phN\n",
     i, j, offset, width, (group_mode ? snapshots[i].rate.group[j] : snapshots[i].rate.account) + offset);
   }
  }
 }
 mutex_unlock(&control_lock);
 return 0;
}
DEFINE_SHOW_ATTRIBUTE(rate_status);

static ssize_t rate_control_write(struct file *file, const char __user *user,
 size_t count, loff_t *offset)
{
 char command[32];
 int error;

 if (!allow_writes || !count || count >= sizeof(command)) return -EPERM;
 if (copy_from_user(command, user, count)) return -EFAULT;
 command[count] = 0;
 strim(command);
 mutex_lock(&control_lock);
 if (!strcmp(command, "poll")) error = rate_wait_command();
 else if (!strcmp(command, "restore")) error = rate_restore();
 else if (last_error || fault || request || closed) error = -EBUSY;
 else if (!strcmp(command, "prepare")) error = rate_prepare();
 else if (!strcmp(command, "load")) error = rate_load();
 else if (!strcmp(command, "recall")) error = rate_recall();
 else if (!strcmp(command, "cpu")) error = rate_cpu_continue();
 else if (!strcmp(command, "rebuild")) error = rate_rebuild();
 else if (!strcmp(command, "serve")) error = rate_serve();
 else if (!strcmp(command, "run")) {
  /* Keep the finite debt episode in one process, without SSH round trips. */
  error = rate_load();
  if (!error) error = rate_recall();
  if (!error) error = rate_cpu_continue();
  if (!error) error = rate_rebuild();
  if (!error) error = rate_serve();
 } else error = -EINVAL;
 last_error = error;
 mutex_unlock(&control_lock);
 return error ?: count;
}
static const struct file_operations rate_control_ops = {
 .owner = THIS_MODULE, .write = rate_control_write,
};
static int __init rate_init(void)
{
 directory = debugfs_create_dir("qdx_rate_handover_diag", NULL);
 if (IS_ERR(directory)) return PTR_ERR(directory);
 debugfs_create_file("status", 0400, directory, NULL, &rate_status_fops);
 debugfs_create_file("control", 0200, directory, NULL, &rate_control_ops);
 return 0;
}
static void __exit rate_exit(void)
{
 WARN_ON(pinned || request || table || receiver || igs || mirror || copy_operation);
 debugfs_remove_recursive(directory);
}
module_init(rate_init);
module_exit(rate_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Isolated actual TBL/GROUP debt and finite CPU continuation diagnostic");
