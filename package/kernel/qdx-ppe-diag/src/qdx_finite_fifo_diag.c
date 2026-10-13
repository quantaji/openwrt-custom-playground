// SPDX-License-Identifier: GPL-2.0-only
/* Finite D admission only. No ARM packet submission, receive hook or qdisc.
 * The operator owns the exclusive no-input fixture while prepare runs.
 * Existing scalar IPv4 rules hold an explicit binding through final retirement.
 * All commands use the existing NSS11.4/QDX service, with immutable pending
 * requests. A timeout keeps that request and every tree/reference owner.
 */
#include <linux/build_bug.h>
#include <linux/debugfs.h>
#include <linux/err.h>
#include <linux/jiffies.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/qdx.h>
#include <linux/rtnetlink.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/unaligned.h>
#include <net/net_namespace.h>
#include <net/pkt_sched.h>
#include "qdx_finite_fifo_diag.h"

#define WAIT_MS 3000
#define TARGET_IF 4
#define ROOT_TAG 0x6e010000U
#define LEAF_TAG 0x6e020000U
#define PACKET_LIMIT 3
#define BYTE_THRESHOLD 2048

struct finite_message { __le32 command, response, value[27]; };
static_assert(sizeof(struct finite_message) == 116);
enum finite_step {
 STEP_NONE, STEP_ASSIGN, STEP_ROOT_ALLOC, STEP_LEAF_ALLOC,
 STEP_PACKET_CONFIG, STEP_BYTE_SETUP, STEP_BYTE_CLASS,
 STEP_ATTACH, STEP_DETACH, STEP_DEFAULT, STEP_ROOT, STEP_GET,
 STEP_LEAF_FREE, STEP_ROOT_FREE, STEP_UNASSIGN,
};
/* byte_mode selects a disclosed different law: old occupancy <=2047,
 * then add the arriving frame. It is not Linux prospective BFIFO.
 */
static bool allow_writes, fixture_reserved, byte_mode;
module_param(allow_writes, bool, 0400);
module_param(fixture_reserved, bool, 0400);
module_param(byte_mode, bool, 0400);
MODULE_PARM_DESC(fixture_reserved, "Exclusive lan2 shaper, no input during prepare, native noqueue");
MODULE_PARM_DESC(byte_mode, "false=PFIFO3; true=weighted class1 old-Q threshold2048");
static DEFINE_MUTEX(finite_lock);
static struct dentry *directory;
static struct net_device *port;
static struct qdx_service *service;
static struct qdx_endpoint *endpoint;
static struct qdx_request *request;
static struct qdx_result last_result;
static struct finite_message pending_message;
static enum finite_step pending_step;
static u32 shaper, prepare_step, bindings, queue_packets, queue_bytes;
static u64 admitted, enqueue_dropped, selected, dequeue_dropped, queries;
static bool pinned, assigned, root_allocated, leaf_allocated, attached;
static bool default_set, root_set, prepared, released, protocol_fault;
static bool endpoint_ready, pending_prepare;
static int last_error;

/* Caller owns finite_lock; no callback invokes module code. The retained
 * request owns its reply until one settled wait consumes it. Module pin and
 * service/endpoint remain live through UNKNOWN; poll does not resubmit.
 */
static int finite_command(enum finite_step step, bool submit)
{
 struct finite_message message = {};
 struct qdx_reply_bounds bounds;
 __le32 assignment[2] = {};
 u8 answer[sizeof(message)] = {};
 const void *payload = &message;
 size_t length = sizeof(message);
 u32 opcode = 10;
 int error;

 if (protocol_fault || (request && pending_step != step))
  return protocol_fault ? -EPROTO : -EBUSY;
 if (!request) {
  if (!submit) return 0;
  message.value[0] = cpu_to_le32(LEAF_TAG);
  switch (step) {
  case STEP_ASSIGN:
   opcode = 6; length = sizeof(assignment); payload = assignment; break;
  case STEP_UNASSIGN:
   opcode = 8; assignment[0] = cpu_to_le32(shaper);
   length = sizeof(assignment[0]); payload = assignment; break;
  case STEP_ROOT_ALLOC:
  case STEP_LEAF_ALLOC:
   message.command = cpu_to_le32(0);
   message.value[0] = cpu_to_le32(step == STEP_ROOT_ALLOC ? 3 : byte_mode ? 13 : 4);
   message.value[1] = cpu_to_le32(step == STEP_ROOT_ALLOC ? ROOT_TAG : LEAF_TAG);
   break;
  case STEP_PACKET_CONFIG:
   message.command = cpu_to_le32(7);
   message.value[1] = cpu_to_le32(PACKET_LIMIT);
   message.value[2] = cpu_to_le32(1); /* actual FIFO tail field */
   break;
  case STEP_BYTE_SETUP:
   message.command = cpu_to_le32(7);
   message.value[3] = cpu_to_le32(1); /* traffic_classes */
   message.value[4] = cpu_to_le32(1); /* default_class */
   break;
  case STEP_BYTE_CLASS:
   message.command = cpu_to_le32(7);
   message.value[1] = cpu_to_le32(BYTE_THRESHOLD); /* informational limit */
   message.value[5] = cpu_to_le32(1); /* traffic_id; same class as setup */
   message.value[7] = cpu_to_le32(BYTE_THRESHOLD); /* minimum */
   message.value[8] = cpu_to_le32(BYTE_THRESHOLD - 1); /* maximum */
   /* weight0, probability0, Wlog0, ECN0: actual old-Q branch. */
   break;
  case STEP_ATTACH:
   message.command = cpu_to_le32(5);
   message.value[0] = cpu_to_le32(ROOT_TAG);
   message.value[1] = cpu_to_le32(LEAF_TAG);
   message.value[2] = cpu_to_le32(0); /* PRIO child slot */
   break;
  case STEP_DETACH:
   message.command = cpu_to_le32(6);
   message.value[0] = cpu_to_le32(ROOT_TAG);
   message.value[1] = cpu_to_le32(0); /* PRIO child slot, not tag */
   break;
  case STEP_DEFAULT: message.command = cpu_to_le32(2); break;
  case STEP_ROOT:
   message.command = cpu_to_le32(3);
   message.value[0] = cpu_to_le32(ROOT_TAG); break;
  case STEP_GET: message.command = cpu_to_le32(4); break;
  case STEP_LEAF_FREE: message.command = cpu_to_le32(1); break;
  case STEP_ROOT_FREE:
   message.command = cpu_to_le32(1);
   message.value[0] = cpu_to_le32(ROOT_TAG); break;
  default: return -EINVAL;
  }
  bounds = (struct qdx_reply_bounds) { length, length, length };
  request = qdx_command_submit(endpoint, opcode, payload, length, &bounds, NULL);
  if (IS_ERR(request)) { error = PTR_ERR(request); request = NULL; return error; }
  pending_message = message;
  pending_step = step;
 }
 /* For a retained request, derive the reply extent from its immutable step. */
 if (step == STEP_ASSIGN) length = sizeof(assignment);
 else if (step == STEP_UNASSIGN) length = sizeof(assignment[0]);
 error = qdx_request_wait(request, jiffies + msecs_to_jiffies(WAIT_MS),
                          &last_result, answer, sizeof(answer));
 if (last_result.outcome == QDX_UNKNOWN && !last_result.exposure_ended)
  return error ?: -EINPROGRESS;
 if (last_result.outcome == QDX_ACK) {
  if (last_result.declared_len != length || last_result.received_len < length) {
   protocol_fault = true; return -EPROTO;
  }
  error = 0;
  if (step != STEP_ASSIGN && step != STEP_UNASSIGN) {
   memcpy(&message, answer, sizeof(message));
   if (message.command != pending_message.command) {
    protocol_fault = true; return -EPROTO;
   }
   error = le32_to_cpu(message.response) ? -EREMOTEIO : 0;
  }
  if (!error) {
   switch (step) {
   case STEP_ASSIGN: shaper = get_unaligned_le32(answer + 4); assigned = true; break;
   case STEP_UNASSIGN: assigned = false; break;
   case STEP_ROOT_ALLOC: root_allocated = true; break;
   case STEP_LEAF_ALLOC: leaf_allocated = true; break;
   case STEP_ATTACH: attached = true; break;
   case STEP_DETACH: attached = false; break;
   case STEP_DEFAULT: default_set = true; break;
   case STEP_ROOT: root_set = true; break;
   case STEP_LEAF_FREE: leaf_allocated = false; default_set = false; break;
   case STEP_ROOT_FREE: root_allocated = false; root_set = false; break;
   case STEP_GET:
    queue_bytes = le32_to_cpu(message.value[1]);
    queue_packets = le32_to_cpu(message.value[2]);
    admitted += le32_to_cpu(message.value[8]);
    enqueue_dropped += le32_to_cpu(message.value[10]);
    selected += le32_to_cpu(message.value[12]);
    dequeue_dropped += le32_to_cpu(message.value[14]);
    queries++;
    break;
   default: break;
   }
  }
 } else error = last_result.error ?: error ?: -EIO;
 qdx_request_put(request);
 request = NULL;
 pending_step = STEP_NONE;
 return error;
}

static int finite_prepare(void)
{
 static const enum finite_step stages[] = {
  STEP_ASSIGN, STEP_ROOT_ALLOC, STEP_LEAF_ALLOC, STEP_PACKET_CONFIG,
  STEP_BYTE_SETUP, STEP_BYTE_CLASS, STEP_ATTACH, STEP_DEFAULT,
  STEP_ROOT, STEP_DETACH,
 };
 struct Qdisc *qdisc;
 u32 ifnum;
 int error;

 ASSERT_RTNL();
 if (released || prepared || request) return -EBUSY;
 if (!pinned) {
  if (!fixture_reserved) return -EPERM;
  port = dev_get_by_name(&init_net, "lan2");
  if (!port || !netif_running(port)) { if (port) dev_put(port); port = NULL; return -ENODEV; }
  qdisc = rtnl_dereference(port->qdisc);
  if (!qdisc || strcmp(qdisc->ops->id, "noqueue")) { dev_put(port); port = NULL; return -EBUSY; }
  if (!try_module_get(THIS_MODULE)) { dev_put(port); port = NULL; return -ENODEV; }
  pinned = true;
  service = qdx_service_get(port, QDX_SERVICE_SHAPER);
  if (IS_ERR(service)) { error = PTR_ERR(service); service = NULL; return error; }
  endpoint = qdx_endpoint_get(service, port);
  if (IS_ERR(endpoint)) { error = PTR_ERR(endpoint); endpoint = NULL; return error; }
  error = qdx_endpoint_ifnum(endpoint, &ifnum);
  if (error || ifnum != TARGET_IF) return error ?: -EXDEV;
  endpoint_ready = true;
 }
 if (!endpoint_ready) return -ENODEV;
 while (prepare_step < ARRAY_SIZE(stages)) {
  enum finite_step step = stages[prepare_step];
  if ((byte_mode && step == STEP_PACKET_CONFIG) ||
      (!byte_mode && (step == STEP_BYTE_SETUP || step == STEP_BYTE_CLASS))) {
   prepare_step++;
   continue;
  }
  pending_prepare = true;
  error = finite_command(step, true);
  if (error) { if (!request) pending_prepare = false; return error; }
  pending_prepare = false;
  prepare_step++;
 }
 prepared = true;
 return 0;
}

/* Only the finite scalar companion calls these. Its actual flow and receiver
 * lifetime must end before put; the native TC translator is not fabricated.
 */
int qdx_finite_fifo_acquire(struct qdx_endpoint **bound, u32 *tag)
{
 int error = 0;
 mutex_lock(&finite_lock);
 if (!prepared || released || protocol_fault || request || attached || bindings)
  error = -EBUSY;
 else if (!try_module_get(THIS_MODULE))
  error = -ENODEV;
 else {
  qdx_endpoint_hold(endpoint);
  bindings++;
  *tag = LEAF_TAG;
  *bound = endpoint;
 }
 mutex_unlock(&finite_lock);
 return error;
}
EXPORT_SYMBOL_GPL(qdx_finite_fifo_acquire);

void qdx_finite_fifo_put(struct qdx_endpoint *bound)
{
 mutex_lock(&finite_lock);
 if (WARN_ON(bindings != 1 || bound != endpoint)) {
  mutex_unlock(&finite_lock);
  return;
 }
 bindings--;
 qdx_endpoint_put(bound);
 mutex_unlock(&finite_lock);
 module_put(THIS_MODULE);
}
EXPORT_SYMBOL_GPL(qdx_finite_fifo_put);

/* Called only after source actors stop, scalar flows reach final retirement,
 * and their binding is returned. Queue-empty is observed, not assumed from ACK.
 * Legitimate admission drops are evidence, not a reason to refuse retirement.
 */
static int finite_restore(void)
{
 int error;
 if (!pinned || released) return 0;
 if (bindings || request || protocol_fault) return -EBUSY;
 if (leaf_allocated) {
  error = finite_command(STEP_GET, true);
  if (error) return error;
  if (queue_packets || queue_bytes) return -EBUSY;
 }
 if (attached) {
  error = finite_command(STEP_DETACH, true);
  if (error) return error;
 }
 if (leaf_allocated) {
  error = finite_command(STEP_LEAF_FREE, true);
  if (error) return error;
 }
 if (root_allocated) {
  error = finite_command(STEP_ROOT_FREE, true);
  if (error) return error;
 }
 if (assigned) {
  error = finite_command(STEP_UNASSIGN, true);
  if (error) return error;
 }
 if (endpoint) { qdx_endpoint_put(endpoint); endpoint = NULL; }
 if (service) { qdx_service_put(service); service = NULL; }
 if (port) { dev_put(port); port = NULL; }
 released = true;
 pinned = false;
 module_put(THIS_MODULE);
 return 0;
}

static int finite_status_show(struct seq_file *seq, void *unused)
{
 mutex_lock(&finite_lock);
 seq_printf(seq, "allow_writes=%u fixture_reserved=%u byte_mode=%u packet_limit=%u byte_threshold=%u\n",
  allow_writes, fixture_reserved, byte_mode, PACKET_LIMIT, BYTE_THRESHOLD);
 seq_printf(seq, "pinned=%u assigned=%u shaper=%u root_allocated=%u leaf_allocated=%u attached=%u default=%u root=%u prepared=%u prepare_step=%u bindings=%u released=%u\n",
  pinned, assigned, shaper, root_allocated, leaf_allocated, attached,
  default_set, root_set, prepared, prepare_step, bindings, released);
 seq_printf(seq, "queue_packets=%u queue_bytes=%u admitted=%llu enqueue_dropped=%llu selected=%llu dequeue_dropped=%llu queries=%llu\n",
  queue_packets, queue_bytes, admitted, enqueue_dropped, selected, dequeue_dropped, queries);
 seq_printf(seq, "pending=%u step=%u protocol_fault=%u last_error=%d id=%llu outcome=%u result_error=%d declared=%zu received=%zu published=%u exposure_ended=%u\n",
  !!request, pending_step, protocol_fault, last_error, last_result.id, last_result.outcome,
  last_result.error, last_result.declared_len, last_result.received_len,
  last_result.published, last_result.exposure_ended);
 mutex_unlock(&finite_lock);
 return 0;
}
DEFINE_SHOW_ATTRIBUTE(finite_status);

static ssize_t finite_control_write(struct file *file, const char __user *buffer,
                                     size_t count, loff_t *position)
{
 char command[24], *text;
 int error;
 if (!allow_writes || !count || count >= sizeof(command)) return -EPERM;
 if (copy_from_user(command, buffer, count)) return -EFAULT;
 command[count] = '\0';
 text = strim(command);
 rtnl_lock();
 mutex_lock(&finite_lock);
 if (!strcmp(text, "prepare")) error = finite_prepare();
 else if (!strcmp(text, "restore")) error = finite_restore();
 else if (!strcmp(text, "poll")) {
  enum finite_step step = pending_step;
  error = request ? finite_command(step, false) : 0;
  /* A pending prepare step settles exactly once; resume at the next step. */
  if (!error && pending_prepare && step != STEP_NONE) {
   prepare_step++;
   pending_prepare = false;
  } else if (!request) pending_prepare = false;
 }
 else if (!prepared || released || protocol_fault || request) error = -EPERM;
 else if (!strcmp(text, "query")) error = finite_command(STEP_GET, true);
 else if (!strcmp(text, "release"))
  error = attached ? 0 : finite_command(STEP_ATTACH, true);
 else error = -EINVAL;
 last_error = error;
 mutex_unlock(&finite_lock);
 rtnl_unlock();
 return error ?: count;
}
static const struct file_operations finite_control_fops = {
 .owner = THIS_MODULE, .write = finite_control_write,
};
static int __init finite_init(void)
{
 struct dentry *entry;
 directory = debugfs_create_dir("qdx_finite_fifo_diag", NULL);
 if (IS_ERR_OR_NULL(directory)) return directory ? PTR_ERR(directory) : -ENOMEM;
 entry = debugfs_create_file("control", 0200, directory, NULL, &finite_control_fops);
 if (IS_ERR_OR_NULL(entry)) goto fail;
 entry = debugfs_create_file("status", 0400, directory, NULL, &finite_status_fops);
 if (IS_ERR_OR_NULL(entry)) goto fail;
 return 0;
fail:
 debugfs_remove_recursive(directory);
 return entry ? PTR_ERR(entry) : -ENOMEM;
}
static void __exit finite_exit(void)
{
 WARN_ON(pinned || request || bindings || assigned || root_allocated || leaf_allocated);
 debugfs_remove_recursive(directory);
}
module_init(finite_init);
module_exit(finite_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Finite autonomous PFIFO3 and old-Q2048 admission diagnostic");
