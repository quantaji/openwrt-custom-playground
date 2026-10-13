// SPDX-License-Identifier: GPL-2.0-only
/* Isolated physical FIFO ownership/marker diagnostic, not a product qdisc. */
#include <linux/completion.h>
#include <linux/debugfs.h>
#include <linux/delay.h>
#include <linux/dsa/oob.h>
#include <linux/etherdevice.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/iopoll.h>
#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/qdx.h>
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
#define DATA_TAG 0x6e020000U
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
static struct qdx_tx_class data_class = { DATA_TAG, 0x6e020001 };
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
static DECLARE_COMPLETION(export_done);
static DECLARE_COMPLETION(resume_done);
/* 0=selected prefix,1=recall,2=re-enabled selected prefix. */
static u32 capture_phase;
static u64 cut_ns, off_ns, on_ns;

static int phy_command(u32 command, u32 node)
{
 struct phy_message message = {};
 struct qdx_reply_bounds bounds;
 __le32 assignment[2] = {};
 u8 reply[sizeof(message)] = {};
 u32 opcode, tag = ROOT_TAG + node * 0x10000;
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
   message.value[0] = cpu_to_le32(node ? 4 : 3);
   message.value[1] = cpu_to_le32(tag);
  } else if (command == 5 || command == 6) {
   if (!node) return -EINVAL;
   message.value[0] = cpu_to_le32(ROOT_TAG);
   message.value[1] = cpu_to_le32(command == 5 ? tag : node - 1);
   if (command == 5) message.value[2] = cpu_to_le32(node - 1);
  } else if (command == 7) {
   if (!node) return -EINVAL;
   message.value[1] = cpu_to_le32(node == 1 ? 32 : 8);
   message.value[2] = cpu_to_le32(1);
  } else if (command != 1 && command != 2 && command != 3 && command != 4) {
   return -EINVAL;
  }
  payload = &message;
  length = sizeof(message);
 }
 if (!request) {
  bounds = (struct qdx_reply_bounds) { length, length, length };
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
   else if (command == 1) allocated &= ~BIT(node);
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
 } else if (capture_phase == 1 && group == 1 && sequence == recalled &&
            recalled < COUNT && !cpu_queue[sequence]) {
  cpu_queue[sequence] = skb;
  recalled++;
  if (recalled == COUNT) complete_all(&export_done);
 } else if (capture_phase == 2 && group == 1 && sequence == resumed + 1 &&
            resumed < 7 && !prefix[9 + resumed]) {
  prefix[9 + resumed] = skb;
  resumed++;
  prefix_count++;
  if (resumed == 7) complete_all(&resume_done);
 } else bad = true;
 if (bad) capture_bad++;
 spin_unlock_irqrestore(&capture_lock, flags);
 if (bad) skb_queue_tail(&quarantine, skb);
 else if (internal) consume_skb(skb);
 return RX_HANDLER_CONSUMED;
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
 error = skb_vlan_push(skb, htons(ETH_P_8021Q), private_vid);
 if (error) return error;
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
 unsigned long flags;
 int error;
 if (!fenced || cpu_owned || capture_bad || recalled || request) return -EPERM;
 spin_lock_irqsave(&capture_lock, flags);
 capture_phase = 1;
 spin_unlock_irqrestore(&capture_lock, flags);
 error = phy_command(5, 1);
 if (!error) error = phy_marker();
 if (error) return error;
 if (!wait_for_completion_timeout(&export_done, msecs_to_jiffies(WAIT_MS)))
  return -ETIMEDOUT;
 error = phy_command(6, 1);
 if (!error) error = phy_marker();
 if (!error) error = phy_command(4, 1);
 if (error) return error;
 if (gauge[1] || dropped[1] || recalled != COUNT || capture_bad) return -EBADMSG;
 cpu_owned = true;
 off_ns = ktime_get_ns();
 return 0;
}

static int phy_cpu_select(void)
{
 if (!cpu_owned || cpu_selected || capture_bad || prefix_count != 8 ||
     !cpu_queue[0] || prefix[8]) return -EPERM;
 prefix[8] = cpu_queue[0];
 cpu_queue[0] = NULL;
 prefix_count = 9;
 cpu_selected = true;
 return 0;
}

static int phy_requeue(void)
{
 unsigned long deadline;
 unsigned int i;
 int error;
 if (!cpu_selected || rebuilt || resubmitted || capture_bad || linked & BIT(1))
  return -EPERM;
 for (i = 1; i < COUNT; i++) {
  if (!cpu_queue[i]) return -EBADMSG;
  error = phy_submit(cpu_queue[i], data_path, data_class);
  if (error) return error;
  cpu_queue[i] = NULL;
  resubmitted++;
 }
 deadline = jiffies + msecs_to_jiffies(WAIT_MS);
 do {
  error = phy_command(4, 1);
  if (error) return error;
  if (dropped[1] || gauge[1] > 7) return -EBADMSG;
  if (gauge[1] == 7) break;
  usleep_range(1000, 1500);
 } while (time_before(jiffies, deadline));
 if (gauge[1] != 7) return -ETIMEDOUT;
 rebuilt = true;
 return 0;
}

static int phy_resume(void)
{
 unsigned long flags;
 int error;
 if (!rebuilt || on || capture_bad || markers != 3 || linked & BIT(1))
  return -EPERM;
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
 if (error) return error;
 if (gauge[1] || dropped[1] || resumed != 7 || prefix_count != 16 || capture_bad)
  return -EBADMSG;
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
 for (i = 0; i < 16; i++) {
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
 if (!pinned || released || capture_bad || request ||
     !skb_queue_empty(&quarantine)) return -EPERM;
 if (empty) {
  if (prefix_count || recalled || resubmitted || native_sent || markers || marker_wait)
   return -EPERM;
  for (i = 0; i < 3; i++) {
   if (!(allocated & BIT(i))) continue;
   error = phy_command(4, i);
   if (error) return error;
   if (gauge[i] || admitted[i] || selected[i] || dropped[i]) return -EBUSY;
  }
 } else if (native_sent != 16) return -EPERM;
 if (!path_closed) {
  /* Keep one query reference after admission closes. These close operations
   * do not call qdx_tx_hold or change the physical output gate.
   */
  if (marker_path) { qdx_tx_path_get(marker_path); qdx_tx_release(marker_path); }
  if (data_path) { qdx_tx_path_get(data_path); qdx_tx_release(data_path); }
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
  if (gauge[i] || dropped[i]) return -EBADMSG;
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
   i, ROOT_TAG + i * 0x10000, gauge[i], bytes[i], admitted[i], selected[i], dropped[i]);
 for (i = 0; i < 16; i++)
  if (prefix[i]) seq_printf(seq, "prefix%u length=%u group=%u seq=%u\n", i, prefix[i]->len,
    get_unaligned_be32(prefix[i]->data + 59), get_unaligned_be32(prefix[i]->data + 63));
 for (i = 0; i < 8; i++)
  if (cpu_queue[i]) seq_printf(seq, "cpu%u length=%u group=%u seq=%u\n", i, cpu_queue[i]->len,
    get_unaligned_be32(cpu_queue[i]->data + 59), get_unaligned_be32(cpu_queue[i]->data + 63));
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
 directory = debugfs_create_dir("qdx_fifo_handover_diag", NULL);
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
         !skb_queue_empty(&quarantine));
 debugfs_remove_recursive(directory);
}
module_init(phy_init);
module_exit(phy_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Bounded physical FIFO marker and occupied CPU handover diagnostic");
