// SPDX-License-Identifier: GPL-2.0-only
/* Isolated finite WRR history continuation. Not a qdisc or CPU baseline. */
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
enum node_id { OUTER, ROOT, ANCHOR, GROUP_A, GROUP_B, FIFO_A, FIFO_B, PROBE, FQ, NODES };
struct wrr_node {
 u32 tag, kind, gauge, bytes;
 u64 admitted, selected, dropped;
 bool allocated;
 int parent;
 u32 band;
 struct qdx_packet_op *operation;
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
};
struct wrr_packet {
 struct sk_buff *skb, *submitted;
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
static struct qdx_service *igs_service, *mirror_service;
static struct qdx_endpoint *igs, *mirror;
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
static u32 phase, private_count, igs_ifnum = U32_MAX, mirror_ifnum = U32_MAX, shaper;
static u32 selected_mask, expected[16], fresh[16], resume_order[13], resume_count;
static u32 recall_order[16], recall_count;
static u32 memory_size, command_count, copy_count;
static u64 copy_time_ns;
static bool pinned, assigned, enabled, next_set, prepared, loaded, exported;
static bool recalled, cpu_selected, rebuilt, passed, closed, fault, anchor_retiring;
static bool igs_retired, mirror_retired;
static int last_error;
static const u32 lengths[16] = { 64,128,67,106,64,1514,128,106,106,64,256,67,512,64,128,106 };

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
 request = qdx_command_submit(mirror_command ? mirror : igs, opcode,
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

static void wrr_returned(void *owner, struct sk_buff *original,
 struct sk_buff *returned, const struct qdx_rx_meta *meta, struct napi_struct *napi)
{
 struct wrr_packet *packet = owner;
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
  }
 }
 if (event_count < ARRAY_SIZE(events))
  events[event_count++] = (struct wrr_event) { phase, packet->id, packet->length,
   ktime_get_ns(), meta ? meta->type : U32_MAX, meta ? meta->ifnum : U32_MAX };
 else bad_packets++;
 spin_unlock_irqrestore(&result_lock, flags);
}

static int wrr_packet_create(struct wrr_packet *packet, u32 id, u32 length, u32 bin)
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
 put_unaligned_le32(0x52525751, data + 42);
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

static int wrr_submit(u32 leaf, struct wrr_packet *packet)
{
 struct qdx_packet_recipient recipient = {
  .owner = { .module = THIS_MODULE, .object = packet }, .returned = wrr_returned,
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

static int wrr_join(u32 leaf)
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

 if (private_count >= 96) return -E2BIG;
 error = wrr_packet_create(&private_packet, 0x80000000U + private_count, length, 0);
 if (!error) error = wrr_submit(leaf, &private_packet);
 if (!error) error = wrr_join(leaf);
 if (error) return error;
 if (!private_packet.skb || private_packet.loaned) return -EBADMSG;
 dev_kfree_skb(private_packet.skb);
 private_packet.skb = NULL;
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

 if (nodes[ROOT].parent != -1 || !nodes[FQ].operation || copy_operation || request ||
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
 error = wrr_copy(view, OWNED_TABLE, 0, 144, view->table);
 if (error) return error;
 dma_rmb();
 if (memcmp(view->table, qdx_dma_cpu(table), TABLE_LEN)) return -EBADMSG;
 for (i = 0; i < 2; i++)
  if (get_unaligned_le32(view->table + i * 72 + 24) != 1 ||
      get_unaligned_le32(view->table + i * 72 + 64) != 64)
   return -EBADMSG;
 error = wrr_copy(view, QDX_DIAG_FQ_NODE, 0, 280, view->node);
 if (error) return error;
 view->node_valid = true;
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
  if (get_unaligned_le32(group + 8) != 10 || get_unaligned_le32(group + 20) ||
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
 error = wrr_command(false, 6, assignment, sizeof(assignment));
 for (i = 0; !error && i < NODES; i++) error = wrr_tc(0, i, 0, 0);
 if (!error) error = wrr_tc(10, FQ, 0, 0);
 if (error) return error;
 if (memory_size != 72) return -EPROTO;
 table = qdx_diag_fq_table_alloc(igs_service, &owner);
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
 if (!error) error = wrr_tc(3, OUTER, 0, 0);
 if (!error) error = wrr_command(true, 0, &mirror_cfg, sizeof(mirror_cfg));
 if (!error) error = wrr_command(true, 3, &next, sizeof(next));
 if (!error) error = wrr_command(true, 1, NULL, 0);
 if (error) return error;
 phase = 0;
 for (i = 0; !error && i < 5; i++) error = wrr_private(FIFO_A, lengths[i]);
 for (i = 8; !error && i < 10; i++) error = wrr_private(FIFO_B, lengths[i]);
 if (!error) error = wrr_tc(6, OUTER, ROOT, 0);
 if (error) return error;
 prepared = true;
 return 0;
}

static int wrr_load(void)
{
 unsigned int i, leaf;
 int error;

 if (!prepared || loaded || request || nodes[ROOT].parent != -1) return -EPERM;
 loaded = true;
 phase = 1;
 for (i = 0; i < 16; i++) {
  leaf = i < 8 ? FIFO_A : FIFO_B;
  error = wrr_packet_create(&packets[i], i, lengths[i], i / 8);
  if (!error) error = wrr_submit(leaf, &packets[i]);
  if (error) return error;
  if (i == 7 || i == 15) {
   qdx_packet_op_close(nodes[leaf].operation);
   error = wrr_gauge(leaf, 8);
   if (error) return error;
  }
 }
 for (i = 0; i < 2; i++) {
  error = wrr_packet_create(&anchor_packets[i], 0x40000000 + i, 64, i);
  if (error) return error;
  anchor_packets[i].control = true;
  error = wrr_submit(FQ, &anchor_packets[i]);
  if (error) return error;
 }
 qdx_packet_op_close(nodes[FQ].operation);
 error = wrr_gauge(FQ, 2);
 if (!error) error = wrr_snapshot(0);
 if (error) return error;
 if (snapshots[0].active_count != 3 ||
     snapshots[0].active_tags[0] != nodes[GROUP_A].tag ||
     snapshots[0].active_tags[1] != nodes[GROUP_B].tag ||
     snapshots[0].active_tags[2] != nodes[ANCHOR].tag ||
     snapshots[0].deficit[0] == snapshots[0].deficit[1] ||
     snapshots[0].deficit[0] < -FRAME_MAX || snapshots[0].deficit[0] > 192 ||
     snapshots[0].deficit[1] < -FRAME_MAX || snapshots[0].deficit[1] > 192) return -EBADMSG;
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
  error = wrr_tc(6, GROUP_A + slot, FIFO_A + slot, 0);
  if (!error) error = wrr_tc(5, OUTER, FIFO_A + slot, 1);
  if (!error) error = wrr_join(FIFO_A + slot);
  if (!error) error = wrr_gauge(FIFO_A + slot, 0);
  if (!error) error = wrr_tc(6, OUTER, FIFO_A + slot, 0);
 }
 if (error) return error;
 if (recall_count != 16) return -EBADMSG;
 for (i = 0; i < 16; i++)
  if (!packets[i].skb || packets[i].loaned || packets[i].returns != 1 ||
      recall_order[i] != i) return -EBADMSG;
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
  if (!error) error = wrr_private(PROBE, 64);
 } else {
  amount = current_phase + 1;
  error = wrr_tc(7, ROOT, 1, 0);
  while (!error && amount >= 64) {
   length = min_t(u32, amount, FRAME_MAX);
   error = wrr_private(PROBE, length);
   amount -= length;
  }
  if (!error) error = wrr_tc(7, ROOT, 0, 0);
  while (!error && amount--) error = wrr_private(PROBE, 64);
 }
 if (error) return error;
 if (target >= -1) {
  error = wrr_tc(7, ROOT, 0, 0);
  if (!error) error = wrr_tc(7, GROUP_A + slot, target + 2, 0);
  if (!error) error = wrr_private(PROBE, 64);
 } else {
  length = max_t(u32, 64, -target);
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
  if (nodes[FIFO_A + slot].operation) qdx_packet_op_close(nodes[FIFO_A + slot].operation);
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
 error = wrr_tc(5, OUTER, ROOT, 0);
 if (!error) error = wrr_join(FIFO_A);
 if (!error) error = wrr_join(FIFO_B);
 if (!error) error = wrr_gauge(FIFO_A, 0);
 if (!error) error = wrr_gauge(FIFO_B, 0);
 if (error) return error;
 if (resume_count != 13 || memcmp(resume_order, expected + 3, sizeof(resume_order)))
  return -EBADMSG;
 for (i = 0; i < 16; i++)
  if (!packets[i].skb || packets[i].loaned ||
      packets[i].returns != ((selected_mask & BIT(i)) ? 1 : 2)) return -EBADMSG;
 passed = true;
 return 0;
}

static int wrr_restore(void)
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
  if (loaded && controls_retired != 2) return -EBADMSG;
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

static int wrr_status_show(struct seq_file *seq, void *unused)
{
 unsigned int i, j, offset, width;

 mutex_lock(&control_lock);
 seq_printf(seq, "mode=%u pinned=%u prepared=%u loaded=%u exported=%u recalled=%u cpu_selected=%u rebuilt=%u passed=%u closed=%u fault=%u assigned=%u enabled=%u next_set=%u request=%u error=%d phase=%u igs=%u mirror=%u shaper=%u table_idle=%u copies=%u copy_ns=%llu commands=%u private_frames=%u bad=%u disposals=%u controls_retired=%u unexpected_clones=%u selected_mask=%x resumed=%u\n",
  byte_mode, pinned, prepared, loaded, exported, recalled, cpu_selected, rebuilt, passed,
  closed, fault, assigned, enabled, next_set, !!request, last_error, phase, igs_ifnum,
  mirror_ifnum, shaper, table ? qdx_diag_fq_table_idle(table) : true, copy_count,
  copy_time_ns, command_count, private_count, bad_packets, disposals, controls_retired,
  unexpected_clones, selected_mask, resume_count);
 seq_printf(seq, "request_id=%llu outcome=%u firmware_error=%u declared=%zu received=%zu published=%u exposure_ended=%u pending_opcode=%u pending_node=%u pending_sub=%u\n",
  result.id, result.outcome, result.firmware_error, result.declared_len, result.received_len,
  result.published, result.exposure_ended, pending_opcode, pending_node,
  le32_to_cpu(pending_message.command));
 for (i = 0; i < NODES; i++)
  seq_printf(seq, "node=%u tag=%08x kind=%u allocated=%u parent=%d band=%u gauge=%u bytes=%u admitted=%llu selected=%llu dropped=%llu operation=%u drained=%u\n",
   i, nodes[i].tag, nodes[i].kind, nodes[i].allocated, nodes[i].parent, nodes[i].band,
   nodes[i].gauge, nodes[i].bytes, nodes[i].admitted, nodes[i].selected, nodes[i].dropped,
   !!nodes[i].operation, nodes[i].operation ? qdx_packet_op_drained(nodes[i].operation) : true);
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

static ssize_t wrr_control_write(struct file *file, const char __user *user,
 size_t count, loff_t *offset)
{
 char command[32];
 int error;

 if (!allow_writes || !count || count >= sizeof(command)) return -EPERM;
 if (copy_from_user(command, user, count)) return -EFAULT;
 command[count] = 0;
 strim(command);
 mutex_lock(&control_lock);
 if (!strcmp(command, "poll")) error = wrr_wait_command();
 else if (!strcmp(command, "restore")) error = wrr_restore();
 else if (last_error || fault || request || closed) error = -EBUSY;
 else if (!strcmp(command, "prepare")) error = wrr_prepare();
 else if (!strcmp(command, "load")) error = wrr_load();
 else if (!strcmp(command, "recall")) error = wrr_recall();
 else if (!strcmp(command, "cpu")) error = wrr_cpu_continue();
 else if (!strcmp(command, "rebuild")) error = wrr_rebuild();
 else if (!strcmp(command, "serve")) error = wrr_serve();
 else error = -EINVAL;
 last_error = error;
 mutex_unlock(&control_lock);
 return error ?: count;
}
static const struct file_operations wrr_control_ops = {
 .owner = THIS_MODULE, .write = wrr_control_write,
};
static int __init wrr_init(void)
{
 directory = debugfs_create_dir("qdx_wrr_handover_diag", NULL);
 if (IS_ERR(directory)) return PTR_ERR(directory);
 debugfs_create_file("status", 0400, directory, NULL, &wrr_status_fops);
 debugfs_create_file("control", 0200, directory, NULL, &wrr_control_ops);
 return 0;
}
static void __exit wrr_exit(void)
{
 WARN_ON(pinned || request || table || receiver || igs || mirror || copy_operation);
 debugfs_remove_recursive(directory);
}
module_init(wrr_init);
module_exit(wrr_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Isolated actual WRR history and finite CPU continuation diagnostic");
