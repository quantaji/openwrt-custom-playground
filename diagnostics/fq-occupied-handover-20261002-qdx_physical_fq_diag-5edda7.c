// SPDX-License-Identifier: GPL-2.0-only
/* Isolated physical FQ ownership/history diagnostic, not a product qdisc. */
#include <linux/completion.h>
#include <linux/dma-mapping.h>
#include <linux/debugfs.h>
#include <linux/delay.h>
#include <linux/dsa/oob.h>
#include <linux/etherdevice.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/iopoll.h>
#include <linux/ktime.h>
#include <linux/math64.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/qdx.h>
#include <linux/qdx_diag_fq.h>
#include <linux/rtnetlink.h>
#include <linux/seq_file.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/unaligned.h>
#include <net/net_namespace.h>
#include <net/pkt_sched.h>

#define WAIT_MS 3000
#define ROOT_TAG 0x6e010000U
#define DATA_TAG 0x6d010000U
#define MARK_TAG 0x6e030000U
#define SOURCE_IF 3
#define TARGET_IF 4
#define COUNT 8
#define ASSIGN 100
#define UNASSIGN 101
/* NSS11.4 nss_shaper_configure fields; actual wire extent116. */
struct phy_message { __le32 command, response, value[27]; };
static_assert(sizeof(struct phy_message) == 116);
static bool allow_writes;
static unsigned long long run_id = 22100281;
static unsigned int source_ip = 0xc0000201, target_ip = 0xc0000202;
static unsigned int source_port = 20000, target_port = 40000, private_vid = 4000;
module_param(allow_writes, bool, 0400);
module_param(run_id, ullong, 0400);
module_param(source_ip, uint, 0400);
module_param(target_ip, uint, 0400);
module_param(source_port, uint, 0400);
module_param(target_port, uint, 0400);
module_param(private_vid, uint, 0400);
static DEFINE_MUTEX(control_lock);
static DEFINE_SPINLOCK(capture_lock);
static struct dentry *directory;
static struct net_device *port, *conduit;
static struct qdx_service *service;
static struct qdx_endpoint *endpoint;
static struct qdx_request *request;
static struct qdx_result result;
static struct qdx_tx_path *marker_path, *data_path;
static struct qdx_tx_class marker_class = { MARK_TAG, 0x6e030001 };
static struct qdx_tx_class data_class = { DATA_TAG, 0x6d010001 };
static struct phy_message pending_message;
static u32 pending_command, pending_node, shaper, gauge[3], bytes[3];
static u64 admitted[3], selected[3], dropped[3];
static u32 allocated, linked, markers, marker_wait, capture_bad, native_sent;
static u32 prefix_count, recalled, resumed, resubmitted, observed_port = U32_MAX;
static bool pinned, assigned, rooted, default_set, hook, cut, fenced, cpu_owned;
static bool cpu_selected, rebuilt, on, path_closed, released, fault;
static int last_error;
static struct sk_buff *prefix[16], *cpu_queue[8];
static struct sk_buff_head quarantine;
static DECLARE_COMPLETION(marker_done);
static DECLARE_COMPLETION(resume_done);
/* 0=selected prefix,2=re-enabled selected prefix; export is non-destructive. */
static u32 capture_phase;
static u64 cut_ns, off_ns, on_ns;


#define COPY_TAG 0x4d54424cU
#define FQ_TABLE 144
#define COPY_TABLE ((enum qdx_diag_fq_range)U32_MAX)
extern struct qdx_dma *qdx_diag_fq_table_alloc(struct qdx_service *, const struct qdx_owner *);
extern bool qdx_diag_fq_table_idle(struct qdx_dma *);
extern struct qdx_ready qdx_diag_fq_table_copy(struct qdx_packet_op *, struct qdx_dma *,
 const struct qdx_packet_recipient *);
static struct qdx_service *copy_service;
static struct qdx_endpoint *copy_endpoint;
static struct qdx_receiver *copy_receiver;
static struct qdx_request *copy_request;
static struct qdx_packet_op *copy_operation;
static struct qdx_dma *fq_table;
static u32 fq_table_address, copy_ifnum, copy_pending;
static struct qdx_result copy_result;
static bool copy_enabled, copy_next, data_closed, imported, obsolete_retired;
static struct qdx_diag_fq_view view;
static struct {
 struct completion clone_done, original_done;
 u32 originals, clones, length, kind;
 bool original_valid, clone_valid;
 u8 bytes[280];
 struct sk_buff *payload;
} copied;
static u8 original_table[144], cpu_table[144], original_node[280], expected_frames[8][110];
static u64 enqueue_age[8], cpu_now, resume_now;
static u32 fq_bin, original_bin, original_node_address, new_node_address, node_values[8], victim_mask;
static bool copy_retired;
static u64 resume_first_ns, resume_last_ns;
static s32 cpu_deficit;
static u64 old_admitted, old_selected, old_dropped;
static u64 copy_calls, copy_total_ns, copy_max_ns;

static int phy_command(u32 command, u32 node)
{
 struct phy_message message = {};
 struct qdx_reply_bounds bounds;
 __le32 assignment[2] = {};
 u8 reply[sizeof(message)] = {};
 u32 opcode, tag = node == 1 ? DATA_TAG : ROOT_TAG + node * 0x10000;
 const void *payload;
 size_t length;
 int error;

 if (fault || node > 2 || (request &&
     (pending_command != command || pending_node != node)))
  return fault ? -EPROTO : -EBUSY;
 if (command == ASSIGN || command == UNASSIGN) {
  opcode = command == ASSIGN ? 6 : 8;
  assignment[0] = cpu_to_le32(command == ASSIGN ? 0 : shaper);
  payload = assignment;
  length = command == ASSIGN ? 8 : 4;
 } else {
  opcode = 10;
  message.command = cpu_to_le32(command);
  message.value[0] = cpu_to_le32(tag);
  if (command == 0) {
   message.value[0] = cpu_to_le32(node == 1 ? 1 : node == 2 ? 4 : 3);
   message.value[1] = cpu_to_le32(tag);
  } else if (command == 5 || command == 6) {
   if (!node) return -EINVAL;
   message.value[0] = cpu_to_le32(ROOT_TAG);
   message.value[1] = cpu_to_le32(command == 5 ? tag : node - 1);
   if (command == 5) message.value[2] = cpu_to_le32(node - 1);
  } else if (command == 7) {
   if (!node) return -EINVAL;
   if (node == 1) {
    message.value[1] = cpu_to_le32(32);
    put_unaligned_le16(101, (u8 *)&message + 16);
    put_unaligned_le16(37, (u8 *)&message + 18);
    put_unaligned_le16(1500, (u8 *)&message + 20);
    message.value[4] = cpu_to_le32(2);
    message.value[5] = cpu_to_le32(fq_table_address);
    message.value[6] = cpu_to_le32(144);
    message.value[7] = cpu_to_le32(128);
   } else {
    message.value[1] = cpu_to_le32(8);
    message.value[2] = cpu_to_le32(1);
   }
  } else if (command != 1 && command != 2 && command != 3 && command != 4 && command != 10) {
   return -EINVAL;
  }
  payload = &message;
  length = sizeof(message);
 }
 if (!request) {
  bounds = (struct qdx_reply_bounds) { length, length, length };
  if (command == 7 && node == 1) qdx_dma_expose(fq_table);
  request = qdx_command_submit(endpoint, opcode, payload, length, &bounds, NULL);
  if (IS_ERR(request)) { error = PTR_ERR(request); request = NULL; return error; }
  pending_command = command;
  pending_node = node;
  pending_message = message;
 }
 error = qdx_request_wait(request, jiffies + msecs_to_jiffies(WAIT_MS),
  &result, reply, sizeof(reply));
 if (result.outcome == QDX_UNKNOWN && !result.exposure_ended)
  return error ?: -EINPROGRESS;
 if (result.outcome == QDX_ACK) {
  if (result.declared_len != length || result.received_len < length) {
   fault = true; return -EPROTO;
  }
  error = 0;
  if (opcode == 10) {
   memcpy(&message, reply, sizeof(message));
   if (message.command != pending_message.command) { fault = true; return -EPROTO; }
   error = le32_to_cpu(message.response) ? -EREMOTEIO : 0;
  }
  if (!error) {
   if (command == ASSIGN) {
    shaper = get_unaligned_le32(reply + 4);
    if (!shaper) { fault = true; return -EPROTO; }
    assigned = true;
   } else if (command == UNASSIGN) assigned = false;
   else if (command == 0) allocated |= BIT(node);
   else if (command == 1) {
    allocated &= ~BIT(node);
    if (node == 1 && fq_table) qdx_dma_access_end(fq_table);
   } else if (command == 10 && node == 1 && le32_to_cpu(message.value[1]) != 72) {
    fault = true; error = -EPROTO;
   }
   else if (command == 2) default_set = true;
   else if (command == 3) rooted = true;
   else if (command == 5) linked |= BIT(node);
   else if (command == 6) linked &= ~BIT(node);
   else if (command == 4) {
    bytes[node] = le32_to_cpu(message.value[1]);
    gauge[node] = le32_to_cpu(message.value[2]);
    admitted[node] += le32_to_cpu(message.value[8]);
    selected[node] += le32_to_cpu(message.value[12]);
    dropped[node] += le32_to_cpu(message.value[10]) + le32_to_cpu(message.value[14]);
   }
  }
 } else error = result.error ?: error ?: -EIO;
 qdx_request_put(request);
 request = NULL;
 return error;
}

/* Native EDMA supplies full original ownership at this RX-handler point.
 * Return PASS for anything outside the exact finite run; never consume a tap.
 */
static rx_handler_result_t phy_receive(struct sk_buff **pskb)
{
 struct sk_buff *skb = *pskb;
 const struct dsa_oob_tag_info *tag;
 u8 header[67];
 u32 group, sequence, phase;
 unsigned long flags;
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
     memcmp(header + 42, "QDXPROB1", 8) ||
     get_unaligned_be64(header + 50) != run_id) return RX_HANDLER_PASS;
 tag = skb_ext_find(skb, SKB_EXT_DSA_OOB);
 if (!tag || tag->port != 0 || skb_vlan_tag_present(skb)) {
  spin_lock_irqsave(&capture_lock, flags);
  observed_port = tag ? tag->port : U32_MAX;
  capture_bad++;
  spin_unlock_irqrestore(&capture_lock, flags);
  return RX_HANDLER_PASS;
 }
 phase = header[58];
 group = get_unaligned_be32(header + 59);
 sequence = get_unaligned_be32(header + 63);
 skb_push(skb, ETH_HLEN);
 skb_reset_mac_header(skb);
 skb_ext_del(skb, SKB_EXT_DSA_OOB);
 spin_lock_irqsave(&capture_lock, flags);
 observed_port = 0;
 if (phase == 255 && group == 0 && sequence == marker_wait &&
     sequence == markers + 1) {
  markers = sequence;
  internal = true;
  complete_all(&marker_done);
 } else if (phase != 1 || group > 1 || sequence >= COUNT) {
  bad = true;
 } else if (capture_phase == 0 && group == 0 && sequence == prefix_count &&
            prefix_count < COUNT && !prefix[sequence]) {
  prefix[sequence] = skb;
  prefix_count++;

 } else if (capture_phase == 2 && group == 1 && sequence == resumed + 2 &&
            resumed < 6 && !prefix[9 + resumed]) {
  prefix[9 + resumed] = skb;
  if (!resumed) resume_first_ns = ktime_get_ns();
  resume_last_ns = ktime_get_ns();
  resumed++;
  prefix_count++;
  if (resumed == 6) complete_all(&resume_done);
 } else bad = true;
 if (bad) capture_bad++;
 spin_unlock_irqrestore(&capture_lock, flags);
 if (bad) skb_queue_tail(&quarantine, skb);
 else if (internal) consume_skb(skb);
 return RX_HANDLER_CONSUMED;
}


static void phy_copy_original(void *owner, struct sk_buff *original,
 struct sk_buff *returned, const struct qdx_rx_meta *meta, struct napi_struct *napi)
{
 copied.originals++;
 copied.original_valid = !original && !returned && meta &&
  meta->type == QDX_RECEIVE_PACKET && meta->ifnum == copy_ifnum;
 complete_all(&copied.original_done);
}

static void phy_copy_clone(void *owner, struct sk_buff *skb,
 const struct qdx_rx_meta *meta, struct napi_struct *napi)
{
 copied.clones++;
 copied.clone_valid = meta && meta->ifnum == copy_ifnum &&
  meta->type == QDX_RECEIVE_PACKET && !skb_is_nonlinear(skb) &&
  skb->len == copied.length &&
  (copied.kind != QDX_DIAG_FQ_CLOCK || !((unsigned long)skb->data & 3));
 if (copied.clone_valid && copied.kind == QDX_DIAG_FQ_PAYLOAD && !copied.payload)
  copied.payload = skb;
 else {
  if (copied.clone_valid) memcpy(copied.bytes, skb->data, copied.length);
  dev_kfree_skb_any(skb);
 }
 complete_all(&copied.clone_done);
}
static const struct qdx_receive_ops phy_copy_ops = { .packet = phy_copy_clone };

static int phy_copy_command(u32 opcode)
{
 /* Fixed11.4 DEFAULT clone point1; original source returns through N2H156.
  * Zero is not DEFAULT, and U32_MAX is not a legal next-hop interface. */
 struct { __le32 point; __le16 size, offset; } config = {
  cpu_to_le32(1), cpu_to_le16(280), 0,
 };
 __le32 next = cpu_to_le32(156);
 struct qdx_reply_bounds bounds;
 const void *payload = opcode == 0 ? (void *)&config : opcode == 3 ? (void *)&next : NULL;
 size_t length = opcode == 0 ? 8 : opcode == 3 ? 4 : 0;
 u8 reply[8];
 int error;

 if (fault || !copy_endpoint || (copy_request && copy_pending != opcode)) return -EBUSY;
 if (!copy_request) {
  bounds = (struct qdx_reply_bounds) { length, length, length };
  copy_request = qdx_command_submit(copy_endpoint, opcode, payload, length, &bounds, NULL);
  if (IS_ERR(copy_request)) { error = PTR_ERR(copy_request); copy_request = NULL; return error; }
  copy_pending = opcode;
 }
 error = qdx_request_wait(copy_request, jiffies + msecs_to_jiffies(WAIT_MS),
  &copy_result, reply, sizeof(reply));
 if (copy_result.outcome == QDX_UNKNOWN && !copy_result.exposure_ended)
  return error ?: -EINPROGRESS;
 if (copy_result.outcome == QDX_ACK) {
  if (copy_result.declared_len != length || copy_result.received_len < length) {
   fault = true; return -EPROTO;
  }
  error = 0;
  if (opcode == 1) copy_enabled = true;
  if (opcode == 2) copy_enabled = false;
  if (opcode == 3) copy_next = true;
  if (opcode == 4) copy_next = false;
 } else error = copy_result.error ?: error ?: -EIO;
 qdx_request_put(copy_request); copy_request = NULL;
 return error;
}

static int phy_copy_setup(void)
{
 struct qdx_owner owner = { .module = THIS_MODULE, .object = &view };
 int error;

 fq_table = qdx_diag_fq_table_alloc(service, &owner);
 if (IS_ERR(fq_table)) { error = PTR_ERR(fq_table); fq_table = NULL; return error; }
 fq_table_address = qdx_dma_address(fq_table);
 copy_service = qdx_service_get(port, QDX_SERVICE_MIRROR);
 if (IS_ERR(copy_service)) { error = PTR_ERR(copy_service); copy_service = NULL; return error; }
 copy_endpoint = qdx_endpoint_alloc(copy_service, 65);
 if (IS_ERR(copy_endpoint)) { error = PTR_ERR(copy_endpoint); copy_endpoint = NULL; return error; }
 error = qdx_endpoint_wait(copy_endpoint, jiffies + msecs_to_jiffies(WAIT_MS));
 if (!error) error = qdx_endpoint_ifnum(copy_endpoint, &copy_ifnum);
 if (error) return error;
 copy_receiver = qdx_endpoint_receive_register(copy_endpoint, QDX_RECEIVE_PACKET,
  &owner, &phy_copy_ops);
 if (IS_ERR(copy_receiver)) { error = PTR_ERR(copy_receiver); copy_receiver = NULL; return error; }
 error = phy_copy_command(0);
 if (!error) error = phy_copy_command(3);
 if (!error) error = phy_copy_command(1);
 return error;
}

static int phy_copy(enum qdx_diag_fq_range kind, unsigned int index,
 unsigned int length, void *destination)
{
 struct qdx_packet_recipient recipient = {
  .owner = { .module = THIS_MODULE, .object = &view }, .returned = phy_copy_original,
 };
 struct qdx_ready ready;
 bool idle, drained;
 u64 start, elapsed;
 int error;

 if (!copy_enabled || copy_request || request || fault || copy_operation ||
     copied.payload || !length || length > 280 || !qdx_diag_fq_table_idle(fq_table))
  return -EBUSY;
 memset(&copied, 0, sizeof(copied));
 init_completion(&copied.original_done); init_completion(&copied.clone_done);
 copied.kind = kind; copied.length = length;
 copy_operation = qdx_packet_op_prepare(copy_endpoint, COPY_TAG, QDX_RECEIVE_PACKET);
 if (IS_ERR(copy_operation)) { error = PTR_ERR(copy_operation); copy_operation = NULL; return error; }
 start = ktime_get_ns();
 ready = kind == COPY_TABLE ? qdx_diag_fq_table_copy(copy_operation, fq_table, &recipient) :
  qdx_diag_fq_owned_copy(copy_operation, fq_table, NULL, &view, kind, index, &recipient);
 if (ready.status != QDX_ACCEPTED) {
  qdx_packet_op_close(copy_operation); qdx_packet_op_put(copy_operation); copy_operation = NULL;
  return ready.error ?: -EAGAIN;
 }
 if (!wait_for_completion_timeout(&copied.original_done, msecs_to_jiffies(WAIT_MS)) ||
     !wait_for_completion_timeout(&copied.clone_done, msecs_to_jiffies(WAIT_MS))) return -ETIMEDOUT;
 qdx_packet_op_close(copy_operation);
 error = read_poll_timeout(qdx_diag_fq_table_idle, idle, idle, 10, WAIT_MS * 1000, false, fq_table);
 if (!error) error = read_poll_timeout(qdx_packet_op_drained, drained, drained, 10,
  WAIT_MS * 1000, false, copy_operation);
 if (error) return error;
 qdx_packet_op_put(copy_operation); copy_operation = NULL;
 elapsed = ktime_get_ns() - start; copy_calls++; copy_total_ns += elapsed;
 copy_max_ns = max(copy_max_ns, elapsed);
 if (copied.originals != 1 || copied.clones != 1 || !copied.original_valid || !copied.clone_valid)
  return -EBADMSG;
 if (kind != QDX_DIAG_FQ_PAYLOAD && destination) memcpy(destination, copied.bytes, length);
 if (kind == COPY_TABLE) {
  dma_rmb();
  if (memcmp(copied.bytes, qdx_dma_cpu(fq_table), 144)) return -ESTALE;
 }
 return 0;
}

/* Fixed one-flow physical fixture: accept either actual hash bin. */
static int phy_snapshot(bool rebuilding)
{
 const struct qdx_tx_path *path = rebuilding ? data_path : NULL;
 unsigned int i, count = rebuilding ? 7 : 8, length;
 u32 address, node, sequence;
 u8 *bin;
 int error;

 memset(&view, 0, sizeof(view)); view.physical_rebuild = path;
 error = phy_copy(COPY_TABLE, 0, 144, view.table);
 if (error) return error;
 if (get_unaligned_le32(view.table + 24) == count && !get_unaligned_le32(view.table + 96)) fq_bin = 0;
 else if (!get_unaligned_le32(view.table + 24) && get_unaligned_le32(view.table + 96) == count) fq_bin = 1;
 else return -EBADMSG;
 bin = view.table + 72 * fq_bin;
 node = get_unaligned_le32(bin + 4) - (bin[68] ? 228 : 236);
 error = phy_copy(QDX_DIAG_FQ_NODE, 0, 280, view.node);
 if (error) return error;
 if (get_unaligned_le32(view.node + 8) != 1 || get_unaligned_le32(view.node + 16) != DATA_TAG ||
     view.node[24] || get_unaligned_le32(view.node + 220) != fq_table_address ||
     get_unaligned_le16(view.node + 264) != 2 || get_unaligned_le16(view.node + 266) != 1 ||
     node < 0x4027b62c || (node - 0x4027b62c) % 280 || get_unaligned_le32(bin + 64) != count * 110)
  return -EBADMSG;
 view.node_valid = true;
 if (rebuilding) new_node_address = node; else original_node_address = node;
 for (i = 0; i < count; i++) {
  address = i ? get_unaligned_le32(view.carrier[i - 1]) : get_unaligned_le32(bin + 16);
  length = address < 0x40000000 ? 56 : 64;
  error = phy_copy(QDX_DIAG_FQ_CARRIER, i, length, view.carrier[i]);
  if (error) return error;
  view.carrier_address[i] = address; view.carrier_valid |= BIT(i);
  error = phy_copy(QDX_DIAG_FQ_METADATA, i, 96, view.metadata[i]);
  if (error) return error;
  view.metadata_valid |= BIT(i);
  error = phy_copy(QDX_DIAG_FQ_PAYLOAD, i, 110, NULL);
  if (error) return error;
  if (!copied.payload || get_unaligned_be16(copied.payload->data + 12) != ETH_P_8021Q ||
      (get_unaligned_be16(copied.payload->data + 14) & VLAN_VID_MASK) != private_vid ||
      get_unaligned_be16(copied.payload->data + 16) != ETH_P_IP ||
      memcmp(copied.payload->data + 46, "QDXPROB1", 8) ||
      get_unaligned_be64(copied.payload->data + 54) != run_id || copied.payload->data[62] != 1 ||
      get_unaligned_be32(copied.payload->data + 63) != 1)
   return -EBADMSG;
  sequence = get_unaligned_be32(copied.payload->data + 67);
  if (sequence != i + (rebuilding ? 1 : 0)) return -EBADMSG;
  if (rebuilding) {
   if (memcmp(copied.payload->data, expected_frames[sequence], 110)) return -EBADMSG;
   dev_kfree_skb(copied.payload); copied.payload = NULL;
  } else {
   if (cpu_queue[i]) return -EALREADY;
   cpu_queue[i] = copied.payload; copied.payload = NULL;
   memcpy(expected_frames[i], cpu_queue[i]->data, 110);
   enqueue_age[i] = get_unaligned_le64(view.metadata[i] + 72);
   if (!enqueue_age[i]) return -EBADMSG;
  }
 }
 return 0;
}

static int phy_import(unsigned int index, bool node)
{
 struct qdx_owner owner = { .module = THIS_MODULE, .object = &view };
 int error;
 if (copy_operation || !data_closed || !qdx_diag_fq_table_idle(fq_table)) return -EBUSY;
 copy_operation = qdx_packet_op_prepare(copy_endpoint, COPY_TAG, QDX_RECEIVE_PACKET);
 if (IS_ERR(copy_operation)) { error = PTR_ERR(copy_operation); copy_operation = NULL; return error; }
 qdx_packet_op_close(copy_operation);
 error = node ? qdx_diag_fq_node_import(copy_operation, fq_table, NULL, &view, node_values, &owner) :
  qdx_diag_fq_age_import(copy_operation, fq_table, NULL, &view, index, enqueue_age[index + 1], &owner);
 qdx_packet_op_put(copy_operation); copy_operation = NULL;
 return error;
}

static int phy_prepare(void)
{
 struct Qdisc *q;
 u32 ifnum;
 unsigned int i;
 int error;

 ASSERT_RTNL();
 if (pinned || released) return -EBUSY;
 if (!try_module_get(THIS_MODULE)) return -ENODEV;
 pinned = true;
 port = dev_get_by_name(&init_net, "lan2");
 conduit = dev_get_by_name(&init_net, "eth0");
 if (!port || !conduit || !netif_running(port) || !netif_running(conduit))
  return -ENODEV;
 q = rtnl_dereference(port->qdisc);
 if (!q || strcmp(q->ops->id, "noqueue") || rtnl_dereference(conduit->rx_handler))
  return -EBUSY;
 service = qdx_service_get(port, QDX_SERVICE_SHAPER);
 if (IS_ERR(service)) { error = PTR_ERR(service); service = NULL; return error; }
 endpoint = qdx_endpoint_get(service, port);
 if (IS_ERR(endpoint)) { error = PTR_ERR(endpoint); endpoint = NULL; return error; }
 error = qdx_endpoint_ifnum(endpoint, &ifnum);
 if (error || ifnum != TARGET_IF) return error ?: -EXDEV;
 error = netdev_rx_handler_register(conduit, phy_receive, NULL);
 if (error) return error;
 hook = true;
 error = phy_command(ASSIGN, 0);
 for (i = 0; !error && i < 3; i++) error = phy_command(0, i);
 if (!error) error = phy_command(10, 1);
 if (!error) error = phy_copy_setup();
 for (i = 1; !error && i < 3; i++) error = phy_command(7, i);
 for (i = 1; !error && i < 3; i++) error = phy_command(5, i);
 if (!error) error = phy_command(2, 1);
 if (!error) error = phy_command(3, 0);
 if (error) return error;
 marker_path = qdx_tx_prepare(endpoint, port, 0, marker_class, QDX_REQUIRED);
 if (IS_ERR(marker_path)) { error = PTR_ERR(marker_path); marker_path = NULL; return error; }
 data_path = qdx_tx_prepare(endpoint, port, 0, data_class, QDX_REQUIRED);
 if (IS_ERR(data_path)) { error = PTR_ERR(data_path); data_path = NULL; return error; }
 return 0;
}

static int phy_submit(struct sk_buff *skb, struct qdx_tx_path *path,
                      struct qdx_tx_class class)
{
 struct qdx_ready ready;
 struct netdev_queue *queue = netdev_get_tx_queue(conduit, 0);
 int error;

 error = skb_cow_head(skb, 136);
 if (error) return error;
 /* qdx_xmit publishes bytes; it has no accelerated-VLAN metadata field. */
 if (skb_vlan_tag_present(skb) || skb->len < ETH_HLEN ||
     skb_mac_header(skb) != skb->data ||
     get_unaligned_be16(skb->data + 12) != ETH_P_IP)
  return -EPROTO;
 error = __vlan_insert_tag(skb, htons(ETH_P_8021Q), private_vid);
 if (error) return error;
 skb->protocol = htons(ETH_P_8021Q);
 skb->dev = port;
 skb_set_queue_mapping(skb, 0);
 ready = qdx_xmit(path, skb, class, queue, skb->len);
 if (ready.status != QDX_ACCEPTED) return ready.error ?: -EAGAIN;
 return 0;
}

static int phy_marker(void)
{
 struct sk_buff *skb;
 u32 next = markers + 1;
 int error;

 if (!prefix[0] || next > 4 || marker_wait != markers) return -EPERM;
 skb = skb_copy(prefix[0], GFP_KERNEL);
 if (!skb) return -ENOMEM;
 if (skb_linearize(skb)) { kfree_skb(skb); return -ENOMEM; }
 skb->data[58] = 255;
 put_unaligned_be32(0, skb->data + 59);
 put_unaligned_be32(next, skb->data + 63);
 put_unaligned_be16(0, skb->data + 40); /* Legal IPv4 UDP checksum disabled. */
 marker_wait = next;
 reinit_completion(&marker_done);
 error = phy_submit(skb, marker_path, marker_class);
 if (error) { kfree_skb(skb); return error; }
 if (!wait_for_completion_timeout(&marker_done, msecs_to_jiffies(WAIT_MS)))
  return -ETIMEDOUT;
 return capture_bad || markers != next ? -EBADMSG : 0;
}

static int phy_cut(void)
{
 int error;
 if (!default_set || !rooted || cut || prefix_count != COUNT || capture_bad || request)
  return -EPERM;
 cut_ns = ktime_get_ns();
 error = phy_command(6, 1);
 if (!error) cut = true;
 return error;
}

static int phy_fence(void)
{
 unsigned long deadline;
 int error;
 if (!cut || fenced || linked & BIT(1) || capture_bad || request)
  return -EPERM;
 deadline = jiffies + msecs_to_jiffies(WAIT_MS);
 do {
  error = phy_command(4, 1);
  if (error) return error;
  if (dropped[1] || gauge[1] > COUNT || admitted[1] > 2 * COUNT ||
      selected[1] != COUNT) return -EBADMSG;
  if (gauge[1] == COUNT && admitted[1] == 2 * COUNT) break;
  usleep_range(1000, 1500);
 } while (time_before(jiffies, deadline));
 if (gauge[1] != COUNT || admitted[1] != 2 * COUNT) return -ETIMEDOUT;
 error = phy_marker();
 if (!error) error = phy_command(4, 1);
 if (!error && gauge[1] != COUNT) error = -EBADMSG;
 if (!error) fenced = true;
 return error;
}

static int phy_export(void)
{
 const u8 *bin, *other;
 u32 other_address;
 int error;
 if (!fenced || cpu_owned || capture_bad || recalled || request || linked & BIT(1))
  return -EPERM;
 error = phy_snapshot(false);
 if (error) return error;
 bin = view.table + 72 * fq_bin;
 other = view.table + 72 * (fq_bin ^ 1);
 other_address = fq_table_address + 72 * (fq_bin ^ 1);
 /* One actual flow, no inactive-bin residue affecting the next selection. */
 if (get_unaligned_le32(other) != other_address ||
     get_unaligned_le32(other + 4) != other_address ||
     get_unaligned_le32(bin) != original_node_address + (bin[68] ? 228 : 236) ||
     get_unaligned_le32(bin + 4) != get_unaligned_le32(bin) ||
     get_unaligned_le32(view.node + 252) != !!bin[68] ||
     get_unaligned_le32(view.node + 256) != !bin[68] ||
     get_unaligned_le32(view.node + 260) != 110)
  return -EBADMSG;
 memcpy(original_table, view.table, 144);
 memcpy(cpu_table, view.table, 144);
 memcpy(original_node, view.node, 280);
 original_bin = fq_bin;
 node_values[0] = get_unaligned_le32(view.node + 224);
 node_values[7] = get_unaligned_le32(view.node + 260);
 recalled = 8;
 cpu_owned = true;
 off_ns = ktime_get_ns();
 return 0;
}

static int phy_cpu_select(void)
{
 u8 clock[24], *bin = cpu_table + original_bin * 72;
 struct sk_buff *skb;
 u64 delay, quantum, deficit_add;
 s64 deficit;
 int error;
 if (!cpu_owned || cpu_selected || capture_bad || prefix_count != 8 ||
     !cpu_queue[0] || prefix[8] || linked & BIT(1)) return -EPERM;
 /* Consequential first-above branch, not a fresh-history replacement. */
 if (get_unaligned_le16(bin + 28) != 101 || get_unaligned_le16(bin + 30) != 37 ||
     get_unaligned_le32(bin + 32) || get_unaligned_le64(bin + 36) ||
     get_unaligned_le64(bin + 44) || bin[62] ||
     get_unaligned_le32(bin + 24) != 8 || get_unaligned_le32(bin + 64) != 880)
  return -EBADMSG;
 error = phy_copy(QDX_DIAG_FQ_CLOCK, 0, 24, clock);
 if (error) return error;
 cpu_now = get_unaligned_le64(clock + 16);
 if (!cpu_now || cpu_now < enqueue_age[0] || cpu_now - enqueue_age[0] <= 37 ||
     cpu_now - enqueue_age[0] > U32_MAX || lower_32_bits(cpu_now) < 2 * WAIT_MS ||
     lower_32_bits(cpu_now) > U32_MAX - 2 * WAIT_MS) return -ERANGE;
 delay = cpu_now - enqueue_age[0];
 quantum = get_unaligned_le32(bin + 8);
 deficit = (s32)get_unaligned_le32(bin + 12);
 if (!quantum || quantum > S32_MAX) return -ERANGE;
 /* A lone negative-credit bin is revisited until it can select its head.
  * This is the firmware loop's exact integer result, without dummy frames.
  */
 if (deficit < 0) {
  deficit_add = DIV_ROUND_UP_ULL(-deficit, quantum) * quantum;
  deficit += deficit_add;
 }
 if (deficit > S32_MAX) return -ERANGE;
 cpu_deficit = deficit - 110;
 skb = cpu_queue[0];
 skb_reset_mac_header(skb);
 skb_set_network_header(skb, VLAN_ETH_HLEN);
 skb_set_transport_header(skb, VLAN_ETH_HLEN + 20);
 skb->protocol = htons(ETH_P_8021Q);
 error = skb_vlan_pop(skb);
 if (error) return error;
 if (skb->len != 106 || get_unaligned_be16(skb->data + 12) != ETH_P_IP ||
     skb_vlan_tag_present(skb)) return -EBADMSG;
 put_unaligned_le64(cpu_now, bin + 36);
 if (delay > get_unaligned_le32(bin + 52)) put_unaligned_le32(delay, bin + 52);
 put_unaligned_le32(get_unaligned_le32(view.carrier[0]), bin + 16);
 put_unaligned_le32(7, bin + 24);
 put_unaligned_le32(770, bin + 64);
 put_unaligned_le32(cpu_deficit, bin + 12);
 if (cpu_deficit < 0) bin[68] = 0;
 /* No other active flow exists; list identity will be rebased on import. */
 prefix[8] = skb;
 cpu_queue[0] = NULL;
 prefix_count = 9;
 cpu_selected = true;
 return 0;
}

static int phy_requeue(void)
{
 static const u16 offsets[8] = {224, 228, 232, 236, 240, 252, 256, 260};
 struct qdx_ready ready;
 struct sk_buff *skb;
 struct netdev_queue *queue = netdev_get_tx_queue(conduit, 0);
 unsigned long deadline;
 unsigned int i;
 u32 sentinel, address;
 u8 verified[280], *bin;
 int error;
 if (!cpu_selected || rebuilt || obsolete_retired || resubmitted || capture_bad ||
     linked & BIT(1) || request || copied.payload || copy_operation)
  return -EPERM;
 error = phy_command(4, 1);
 if (error) return error;
 if (gauge[1] != 8 || admitted[1] != 16 || selected[1] != 8 || dropped[1]) return -EBADMSG;
 old_admitted = admitted[1]; old_selected = selected[1]; old_dropped = dropped[1];
 /* CPU now owns all eight bytes and their actual history. The old autonomous
  * pool backing follows NSS's normal free/refill path, never a host fake free.
  */
 error = phy_command(1, 1);
 if (error) return error;
 obsolete_retired = true;
 admitted[1] = selected[1] = dropped[1] = 0;
 gauge[1] = bytes[1] = 0;
 error = phy_command(0, 1);
 if (!error) error = phy_command(10, 1);
 if (!error) error = phy_command(7, 1);
 if (!error) error = phy_command(2, 1);
 if (error) return error;
 for (i = 1; i < COUNT; i++) {
  skb = cpu_queue[i];
  if (!skb || skb->len != 110 || memcmp(skb->data, expected_frames[i], 110) ||
      skb_vlan_tag_present(skb)) return -EBADMSG;
  error = skb_cow_head(skb, 136);
  if (error) return error;
  skb->dev = port; skb->protocol = htons(ETH_P_8021Q);
  skb_reset_mac_header(skb);
  skb_set_network_header(skb, VLAN_ETH_HLEN);
  skb_set_transport_header(skb, VLAN_ETH_HLEN + 20);
  skb_set_queue_mapping(skb, 0);
  skb->ip_summed = CHECKSUM_NONE;
  ready = qdx_xmit(data_path, skb, data_class, queue, skb->len);
  if (ready.status != QDX_ACCEPTED) return ready.error ?: -EAGAIN;
  cpu_queue[i] = NULL;
  resubmitted++;
 }
 /* Actual registered TRANSMIT owners remain pinned while their closed path
  * proves that no further producer can change the imported population.
  */
 qdx_tx_path_get(data_path); qdx_tx_release(data_path); data_closed = true;
 deadline = jiffies + msecs_to_jiffies(WAIT_MS);
 do {
  error = phy_command(4, 1);
  if (error) return error;
  if (dropped[1] || selected[1] || gauge[1] > 7 || admitted[1] > 7) return -EBADMSG;
  if (gauge[1] == 7 && admitted[1] == 7) break;
  usleep_range(1000, 1500);
 } while (time_before(jiffies, deadline));
 if (gauge[1] != 7 || admitted[1] != 7) return -ETIMEDOUT;
 error = phy_snapshot(true);
 if (error) return error;
 if (fq_bin != original_bin ||
     memcmp(view.table + (fq_bin ^ 1) * 72 + 8,
            original_table + (fq_bin ^ 1) * 72 + 8, 64)) return -EBADMSG;
 for (i = 0; i < 7; i++) {
  error = phy_import(i, false);
  if (error) return error;
 }
 for (i = 0; i < 7; i++) {
  error = phy_copy(QDX_DIAG_FQ_METADATA, i, 96, verified);
  if (error) return error;
  if (get_unaligned_le64(verified + 72) != enqueue_age[i + 1] ||
      memcmp(verified, view.metadata[i], 72) ||
      memcmp(verified + 80, view.metadata[i] + 80, 16)) return -EBADMSG;
  memcpy(view.metadata[i], verified, 96);
 }
 bin = view.table + 72 * fq_bin;
 memcpy(bin + 8, cpu_table + 72 * fq_bin + 8, 8);
 memcpy(bin + 28, cpu_table + 72 * fq_bin + 28, 36);
 bin[68] = cpu_table[72 * fq_bin + 68];
 sentinel = new_node_address + (bin[68] ? 228 : 236);
 address = fq_table_address + 72 * fq_bin;
 put_unaligned_le32(sentinel, bin); put_unaligned_le32(sentinel, bin + 4);
 node_values[1] = node_values[2] = bin[68] ? address : new_node_address + 228;
 node_values[3] = node_values[4] = bin[68] ? new_node_address + 236 : address;
 node_values[5] = !!bin[68]; node_values[6] = !bin[68];
 memcpy(qdx_dma_cpu(fq_table), view.table, 144);
 dma_wmb();
 error = phy_import(0, true);
 if (error) return error;
 error = phy_copy(COPY_TABLE, 0, 144, verified);
 if (error) return error;
 if (memcmp(verified, view.table, 144)) return -EBADMSG;
 error = phy_copy(QDX_DIAG_FQ_NODE, 0, 280, verified);
 if (error) return error;
 for (i = 0; i < 8; i++)
  if (get_unaligned_le32(verified + offsets[i]) != node_values[i]) return -EBADMSG;
 memcpy(view.node, verified, 280);
 imported = true; rebuilt = true;
 return 0;
}

static int phy_resume(void)
{
 unsigned long flags, deadline;
 u8 clock[24];
 bool drained;
 int error;
 if (!rebuilt || !imported || on || capture_bad || markers != 1 || linked & BIT(1))
  return -EPERM;
 deadline = jiffies + msecs_to_jiffies(WAIT_MS);
 do {
  error = phy_copy(QDX_DIAG_FQ_CLOCK, 0, 24, clock);
  if (error) return error;
  resume_now = get_unaligned_le64(clock + 16);
  if (resume_now >= cpu_now + 102) break;
  usleep_range(1000, 1500);
 } while (time_before(jiffies, deadline));
 if (resume_now < cpu_now + 102) return -ETIMEDOUT;
 spin_lock_irqsave(&capture_lock, flags);
 capture_phase = 2;
 spin_unlock_irqrestore(&capture_lock, flags);
 error = phy_command(5, 1);
 if (!error) error = phy_marker();
 if (error) return error;
 if (!wait_for_completion_timeout(&resume_done, msecs_to_jiffies(WAIT_MS)))
  return -ETIMEDOUT;
 error = phy_command(6, 1);
 if (!error) error = phy_command(4, 1);
 if (!error) error = read_poll_timeout(qdx_tx_drained, drained, drained, 50,
  WAIT_MS * 1000, false, data_path);
 if (error) return error;
 if (gauge[1] || admitted[1] != 7 || dropped[1] != 1 || selected[1] != 6 ||
     resumed != 6 || prefix_count != 15 || capture_bad ||
     resume_last_ns - resume_first_ns >= 100 * NSEC_PER_MSEC) return -EBADMSG;
 victim_mask = BIT(1);
 on = true;
 on_ns = ktime_get_ns();
 return 0;
}

/* Root must first close/settle source and restore the exact PPE capture rules.
 * This command cannot turn an external capture classifier off by itself.
 */
static int phy_wire(void)
{
 struct sk_buff *skb;
 unsigned int i;
 int status;
 if (!on || native_sent || capture_bad || !skb_queue_empty(&quarantine)) return -EPERM;
 if (hook) {
  netdev_rx_handler_unregister(conduit);
  hook = false;
 }
 for (i = 0; i < 15; i++) {
  skb = prefix[i];
  if (!skb) return -EBADMSG;
  prefix[i] = NULL;
  skb->dev = port;
  skb->protocol = htons(ETH_P_IP);
  skb->ip_summed = CHECKSUM_NONE;
  skb_reset_mac_header(skb);
  skb_set_network_header(skb, ETH_HLEN);
  skb_set_transport_header(skb, ETH_HLEN + 20);
  skb_set_queue_mapping(skb, 0);
  status = dev_queue_xmit(skb);
  native_sent++;
  if (net_xmit_eval(status)) return status < 0 ? status : -ENOBUFS;
 }
 return 0;
}

static int phy_restore(bool empty)
{
 bool drained;
 unsigned int i;
 int error;
 if (!pinned || released || capture_bad || request || copied.payload || copy_operation ||
     copy_request || !skb_queue_empty(&quarantine)) return -EPERM;
 if (empty) {
  if (prefix_count || recalled || resubmitted || native_sent || markers || marker_wait)
   return -EPERM;
  for (i = 0; i < 3; i++) {
   if (!(allocated & BIT(i))) continue;
   error = phy_command(4, i);
   if (error) return error;
   if (gauge[i] || admitted[i] || selected[i] || dropped[i]) return -EBUSY;
  }
 } else if (native_sent != 15 || !on || victim_mask != BIT(1)) return -EPERM;
 if (!path_closed) {
  /* Keep one query reference after admission closes. These close operations
   * do not call qdx_tx_hold or change the physical output gate.
   */
  if (marker_path) { qdx_tx_path_get(marker_path); qdx_tx_release(marker_path); }
  if (data_path && !data_closed) {
   qdx_tx_path_get(data_path); qdx_tx_release(data_path); data_closed = true;
  }
  path_closed = true;
 }
 error = 0;
 if (marker_path) error = read_poll_timeout(qdx_tx_drained, drained, drained, 50,
  WAIT_MS * 1000, false, marker_path);
 if (!error && data_path) error = read_poll_timeout(qdx_tx_drained, drained, drained, 50,
  WAIT_MS * 1000, false, data_path);
 if (error) return error;
 for (i = 1; i < 3; i++) {
  if (!(allocated & BIT(i))) continue;
  error = phy_command(4, i);
  if (error) return error;
  if (gauge[i] || dropped[i] != ((!empty && i == 1) ? 1 : 0)) return -EBADMSG;
 }
 for (i = 1; i < 3; i++) {
  if (!(linked & BIT(i))) continue;
  error = phy_command(6, i);
  if (error) return error;
 }
 for (i = 3; i; i--) {
  if (!(allocated & BIT(i - 1))) continue;
  error = phy_command(1, i - 1);
  if (error) return error;
 }
 if (assigned) { error = phy_command(UNASSIGN, 0); if (error) return error; }
 if (copy_operation || copied.payload || copy_request) return -EBUSY;
 if (copy_enabled) { error = phy_copy_command(2); if (error) return error; }
 if (copy_next) { error = phy_copy_command(4); if (error) return error; }
 if (copy_endpoint && !copy_retired) {
  error = qdx_endpoint_wait(copy_endpoint, jiffies);
  if (!error) error = qdx_endpoint_retire(copy_endpoint);
  if (error) return error;
  copy_retired = true;
 }
 if (copy_receiver) {
  error = qdx_endpoint_receive_unregister(copy_receiver);
  if (error) return error;
  copy_receiver = NULL;
 }
 if (copy_endpoint) { qdx_endpoint_put(copy_endpoint); copy_endpoint = NULL; }
 if (fq_table) { qdx_dma_release(fq_table); fq_table = NULL; }
 if (copy_service) { qdx_service_put(copy_service); copy_service = NULL; }
 if (hook) { netdev_rx_handler_unregister(conduit); hook = false; }
 if (marker_path) { qdx_tx_path_put(marker_path); marker_path = NULL; }
 if (data_path) { qdx_tx_path_put(data_path); data_path = NULL; }
 qdx_endpoint_put(endpoint); endpoint = NULL;
 qdx_service_put(service); service = NULL;
 if (port) { dev_put(port); port = NULL; }
 if (conduit) { dev_put(conduit); conduit = NULL; }
 released = true;
 pinned = false;
 module_put(THIS_MODULE);
 return 0;
}

static int phy_status_show(struct seq_file *seq, void *unused)
{
 unsigned int i;
 mutex_lock(&control_lock);
 seq_printf(seq, "allow_writes=%u pinned=%u assigned=%u allocated=%x linked=%x rooted=%u default=%u hook=%u request=%u fault=%u error=%d\n",
  allow_writes, pinned, assigned, allocated, linked, rooted, default_set, hook, !!request, fault, last_error);
 seq_printf(seq, "run=%llu sip=%08x dip=%08x sport=%u dport=%u vid=%u physical_if=4 observed_port=%u capture_phase=%u bad=%u quarantine=%u\n",
  run_id, source_ip, target_ip, source_port, target_port, private_vid, observed_port,
  capture_phase, capture_bad, skb_queue_len(&quarantine));
 seq_printf(seq, "prefix=%u recalled=%u resubmitted=%u resumed=%u markers=%u waiting=%u cut=%u fenced=%u cpu_owned=%u cpu_selected=%u rebuilt=%u on=%u native_sent=%u path_closed=%u released=%u\n",
  prefix_count, recalled, resubmitted, resumed, markers, marker_wait, cut, fenced,
  cpu_owned, cpu_selected, rebuilt, on, native_sent, path_closed, released);
 seq_printf(seq, "cut_ns=%llu off_ns=%llu on_ns=%llu\n", cut_ns, off_ns, on_ns);
 for (i = 0; i < 3; i++)
  seq_printf(seq, "node=%u tag=%08x queue=%u bytes=%u admitted=%llu selected=%llu dropped=%llu\n",
   i, i == 1 ? DATA_TAG : ROOT_TAG + i * 0x10000, gauge[i], bytes[i], admitted[i], selected[i], dropped[i]);
 for (i = 0; i < 16; i++)
  if (prefix[i]) seq_printf(seq, "prefix%u length=%u group=%u seq=%u\n", i, prefix[i]->len,
    get_unaligned_be32(prefix[i]->data + 59), get_unaligned_be32(prefix[i]->data + 63));
 for (i = 0; i < 8; i++)
  if (cpu_queue[i]) seq_printf(seq, "cpu%u length=%u group=%u seq=%u\n", i, cpu_queue[i]->len,
    get_unaligned_be32(cpu_queue[i]->data + 63), get_unaligned_be32(cpu_queue[i]->data + 67));
 seq_printf(seq, "fq_bin=%u original_bin=%u old_node=%08x new_node=%08x table=%08x obsolete_retired=%u data_closed=%u imported=%u victim_mask=%x\n",
  fq_bin, original_bin, original_node_address, new_node_address, fq_table_address,
  obsolete_retired, data_closed, imported, victim_mask);
 seq_printf(seq, "old_admitted=%llu old_selected=%llu old_dropped=%llu cpu_now=%llu resume_now=%llu cpu_deficit=%d resume_first_ns=%llu resume_last_ns=%llu\n",
  old_admitted, old_selected, old_dropped, cpu_now, resume_now, cpu_deficit,
  resume_first_ns, resume_last_ns);
 seq_printf(seq, "copy_calls=%llu copy_total_ns=%llu copy_max_ns=%llu copy_request=%u copy_operation=%u copy_enabled=%u copy_retired=%u carriers=%04x metadata=%04x\n",
  copy_calls, copy_total_ns, copy_max_ns, !!copy_request, !!copy_operation, copy_enabled,
  copy_retired, view.carrier_valid, view.metadata_valid);
 seq_printf(seq, "copy_pending=%u copy_next=%u copy_id=%llu copy_outcome=%u copy_error=%d copy_firmware_error=%u copy_declared=%zu copy_received=%zu copy_published=%u copy_exposure_ended=%u\n",
  copy_pending, copy_next, copy_result.id, copy_result.outcome, copy_result.error,
  copy_result.firmware_error, copy_result.declared_len, copy_result.received_len,
  copy_result.published, copy_result.exposure_ended);
 for (i = 0; i < 8; i++) seq_printf(seq, "age%u=%llu node_value%u=%08x\n", i, enqueue_age[i], i, node_values[i]);
 for (i = 0; cpu_owned && i < 144; i += 48)
  seq_printf(seq, "original_table%u=%48phN cpu_table%u=%48phN\n", i, original_table + i, i, cpu_table + i);
 seq_printf(seq, "id=%llu outcome=%u declared=%zu received=%zu published=%u exposure_ended=%u\n",
  result.id, result.outcome, result.declared_len, result.received_len, result.published, result.exposure_ended);
 mutex_unlock(&control_lock);
 return 0;
}
DEFINE_SHOW_ATTRIBUTE(phy_status);
static ssize_t phy_control_write(struct file *file, const char __user *buffer,
                                  size_t count, loff_t *position)
{
 char command[24];
 int error;
 if (!allow_writes || !count || count >= sizeof(command)) return -EPERM;
 if (copy_from_user(command, buffer, count)) return -EFAULT;
 command[count] = '\0';
 strim(command);
 rtnl_lock();
 mutex_lock(&control_lock);
 if (!strcmp(command, "prepare")) error = phy_prepare();
 else if (!strcmp(command, "cut")) error = phy_cut();
 else if (!strcmp(command, "fence")) error = phy_fence();
 else if (!strcmp(command, "export")) error = phy_export();
 else if (!strcmp(command, "cpu-select")) error = phy_cpu_select();
 else if (!strcmp(command, "requeue")) error = phy_requeue();
 else if (!strcmp(command, "resume")) error = phy_resume();
 else if (!strcmp(command, "wire")) error = phy_wire();
 else if (!strcmp(command, "restore")) error = phy_restore(false);
 else if (!strcmp(command, "restore-empty")) error = phy_restore(true);
 else if (!strcmp(command, "poll")) error = request ? phy_command(pending_command, pending_node) : 0;
 else error = -EINVAL;
 last_error = error;
 mutex_unlock(&control_lock);
 rtnl_unlock();
 return error ?: count;
}
static const struct file_operations phy_control_fops = { .owner = THIS_MODULE, .write = phy_control_write };
static int __init phy_init(void)
{
 struct dentry *entry;
 if (!source_port || source_port > U16_MAX || !target_port || target_port > U16_MAX ||
     !private_vid || private_vid >= 4095) return -EINVAL;
 skb_queue_head_init(&quarantine);
 directory = debugfs_create_dir("qdx_physical_fq_diag", NULL);
 if (IS_ERR_OR_NULL(directory)) return directory ? PTR_ERR(directory) : -ENOMEM;
 entry = debugfs_create_file("control", 0200, directory, NULL, &phy_control_fops);
 if (IS_ERR_OR_NULL(entry)) goto fail;
 entry = debugfs_create_file("status", 0400, directory, NULL, &phy_status_fops);
 if (IS_ERR_OR_NULL(entry)) goto fail;
 return 0;
fail:
 debugfs_remove_recursive(directory);
 return entry ? PTR_ERR(entry) : -ENOMEM;
}
static void __exit phy_exit(void)
{
 WARN_ON(pinned || request || hook || marker_path || data_path || allocated || assigned ||
         copy_endpoint || copy_request || copy_operation || fq_table ||
         !skb_queue_empty(&quarantine));
 debugfs_remove_recursive(directory);
}
module_init(phy_init);
module_exit(phy_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Bounded physical FQ occupied history and CPU handover diagnostic");
