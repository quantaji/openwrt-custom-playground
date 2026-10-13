// SPDX-License-Identifier: GPL-2.0-only
/* Isolated, never-published two-bin FQ cache transfer discriminator. */
#include <linux/build_bug.h>
#include <linux/completion.h>
#include <linux/debugfs.h>
#include <linux/dma-mapping.h>
#include <linux/delay.h>
#include <linux/in.h>
#include <linux/etherdevice.h>
#include <linux/jiffies.h>
#include <linux/iopoll.h>
#include <linux/ktime.h>
#include <linux/kprobes.h>
#include <linux/math64.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/overflow.h>
#include <linux/mutex.h>
#include <linux/qdx.h>
#include <linux/qdx_diag_fq.h>
#include <linux/qdx_diag_bf.h>
#include <linux/seq_file.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/unaligned.h>
#include <net/net_namespace.h>
#include <net/checksum.h>

#define TABLE_LEN 144
#define TABLE_TAG 0x6d010000U
#define COPY_TAG 0x4d54424cU
#define WAIT_MS 3000
#define PROBE_PACKETS 16
#define PROBE_LENGTH 64
#define PROBE_HEADROOM 130
#define OWNED_TABLE ((enum qdx_diag_fq_range)U32_MAX)

/* Private isolated diagnostic symbols; no user address input. */
extern struct qdx_dma *qdx_diag_fq_table_alloc(struct qdx_service *service,
	const struct qdx_owner *owner);
extern bool qdx_diag_fq_table_idle(struct qdx_dma *region);
extern struct qdx_ready qdx_diag_fq_table_copy(struct qdx_packet_op *operation,
	struct qdx_dma *region, const struct qdx_packet_recipient *recipient);

/* Selected wire members from Qualcomm exports/nss_shaper.h/nss_mirror.h.
 * Copyright (c) 2014, 2017-2018 The Linux Foundation. All rights reserved.
 * Copyright (c) 2014-2021, The Linux Foundation. All rights reserved.
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
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
struct table_config {
	__le32 command, response;
	union {
		struct { __le32 kind, tag; } allocate;
		struct {
			__le32 tag, limit;
			__le16 interval, target, mtu, reserved;
			__le32 flows, memory, size, quantum, ecn;
		} codel;
		struct { __le32 tag, bytes; } memory;
		__le32 tag;
		u8 reserved[108];
	} data;
};
struct mirror_config { __le32 point; __le16 size, offset; };
static_assert(sizeof(struct table_config) == 116);
static_assert(offsetof(struct table_config, data.codel.memory) == 28);
static_assert(sizeof(struct mirror_config) == 8);
enum step { NONE, ASSIGN, ALLOC, MEMORY, CONFIG, FREE, UNASSIGN, STATS, ROOT,
	MIRROR_CONFIG, MIRROR_NEXT, MIRROR_ENABLE, MIRROR_DISABLE, MIRROR_RESET };
struct table_round {
	struct completion original_done, clone_done;
	bool submitted, original_valid, clone_valid, host_equal;
	u32 originals, clones, original_type, original_ifnum, clone_type, clone_ifnum;
	u32 clone_length;
	u64 start_ns, elapsed_ns;
	u8 expected[TABLE_LEN], actual[TABLE_LEN], host_after[TABLE_LEN];
};

static bool allow_writes;
module_param(allow_writes, bool, 0400);
/* Test starts with this policy; it never changes the CPU-owned rate in place. */
static bool bf_account_test, bf_account_control;
module_param(bf_account_test, bool, 0400);
module_param(bf_account_control, bool, 0400);
static bool bf_positive_test;
module_param(bf_positive_test, bool, 0400);
/* Optional fresh-fixture notification; never changes the NSS clock rate. */
static bool bf_native_frequency_sync;
module_param(bf_native_frequency_sync, bool, 0400);
static DEFINE_MUTEX(state_lock);
static DEFINE_SPINLOCK(result_lock);
static struct dentry *directory;
static struct net_device *port;
static struct qdx_service *igs_service, *mirror_service;
static struct qdx_endpoint *igs, *mirror;
static struct qdx_receiver *receiver;
static struct qdx_packet_op *operation;
static struct qdx_dma *table;
static struct qdx_request *request;
static struct qdx_result result;
static enum step pending;
static struct table_round rounds[4];
struct probe_packet { struct sk_buff *skb; u8 expected[PROBE_LENGTH]; u32 id; };
static struct probe_packet probes[PROBE_PACKETS];
static struct qdx_packet_op *probe_operation;
static DECLARE_COMPLETION(probe_done);
static u32 probe_accepted, probe_returns, probe_valid, probe_disposed;
static u32 probe_order[PROBE_PACKETS], probe_qlen, probe_drops;
static bool probe_loaded, probe_queued, probe_snapshot_valid, probe_started, probe_pass;
static u64 probe_first_ns, probe_last_ns;
static u32 igs_ifnum = U32_MAX, mirror_ifnum = U32_MAX, active = U32_MAX;
static u32 shaper, memory_size, table_address, unexpected_clones;
static bool pinned, assigned, allocated, memory_checked, configured;
static bool mirror_configured, next_set, enabled, closed, fault;
static bool igs_retired, mirror_retired, word_changed, word_restored;
static int last_error;
/* Separate completed-clone storage for typed occupied reads. */
struct owned_round {
 struct completion original_done, clone_done;
 bool submitted, original_valid, clone_valid;
 u32 originals, clones, length, kind, index, clone_data_mod4;
 u64 elapsed_ns, original_ns, clone_ns;
 u8 bytes[312];
 struct sk_buff *payload;
};
static struct owned_round owned;
/* Last256 successful reads only; printed after the command, never to console
 * inside a pending firmware event window. All *_ns values are durations. */
struct owned_copy_cost {
 u32 kind, index;
 u64 submit_ns, original_ns, clone_ns, callbacks_ns;
 u64 close_table_ns, operation_wait_ns, total_ns;
};
static struct owned_copy_cost owned_cost[256];
static u32 owned_cost_count;
static struct qdx_diag_fq_view owned_view;
static struct sk_buff *owned_payload[PROBE_PACKETS];
static u8 owned_clock[4][24], age_changed_bytes[96], age_restored_bytes[96];
static u64 owned_read_ns[1 + 3 * PROBE_PACKETS + 4];
static u32 owned_read_count, mirror_copy_size = TABLE_LEN;
static bool occupied_read, occupied_pass, age_changed, age_restored;
static u64 saved_age;
static u32 clock_host_before[4][6], clock_host_after[4][6], clock_host_poll[8][6];
static u64 clock_host_before_ns[4][2], clock_host_after_ns[4][2], clock_host_poll_ns[8][2];
/* Distinct accounting for logical packets and obsolete backing retirement. */
static bool adopt_cpu, adopt_retiring, adopt_rebuild_started, adopt_imported, adopt_pass;
static u32 adopt_retired, adopt_retirement_bad, adopt_accepted, adopt_returns;
static u32 adopt_valid, adopt_disposed, adopt_bad_owner, adopt_order[14], adopt_disposed_mask;
static u64 adopt_first_ns, adopt_last_ns, adopt_clock[2], adopt_age[PROBE_PACKETS];
static u8 adopt_history[2][36], adopt_before[TABLE_LEN], adopt_after[TABLE_LEN];
static u8 adopt_cpu_table[TABLE_LEN];
static u32 adopt_node_values[8];
static DECLARE_COMPLETION(adopt_done);

/* Explicit BF transfer fixture. Its private triggers are not user traffic. */
#define BF_OUTER_TAG 0x6d040000U
#define BF_PARENT_TAG 0x6d020000U
#define BF_GROUP_TAG 0x6d030000U
#define BF_PRIVATE_TAG 0x6d050000U
#define BF_AUX_TAG 0x6d060000U
static struct qdx_request *bf_request;
static struct qdx_result bf_result;
static u32 bf_command_pending, bf_tag_pending, bf_child_pending, bf_allocated, bf_links;
static bool bf_mode, bf_ready, bf_cut, bf_cpu_owned, bf_retired, bf_pass;
static struct probe_packet bf_triggers[4];
static struct qdx_packet_op *bf_trigger_operation;
static DECLARE_COMPLETION(bf_trigger_done);
static u32 bf_trigger_accepted, bf_trigger_returns, bf_trigger_valid, bf_trigger_disposed;
static u32 bf_trigger_queued_before_open;
static u8 bf_account[312], bf_timer[32], bf_notifier[16];
static u8 bf_epoch_before[20], bf_epoch_after[20], bf_frequency[2][8];
static u8 bf_saved_group[232], bf_saved_parent[200], bf_saved_account[312], bf_saved_timer[32];
static u8 bf_cpu_account[312], bf_cpu_group[232], bf_retired_account[312];
static u64 bf_cut_clock, bf_retire_clock, bf_cpu_pending_ms, bf_credit_delta, bf_snapshot_begin;
static u32 bf_snapshot_attempts, bf_retirement_attempts, bf_cpu_selected;
static s64 bf_credit_before, bf_credit_after;
static s32 bf_deficit_before, bf_deficit_after;
static bool bf_rebuild_ready, bf_rearm_started, bf_rearm_pass, bf_reverse_done;
static bool bf_reverse_retired, bf_lifetime_pinned;
static struct probe_packet bf_private_packet;
static struct qdx_packet_op *bf_private_operation;
static DECLARE_COMPLETION(bf_private_done);
static u32 bf_private_returned, bf_private_valid, bf_private_disposed;
static u64 bf_private_ns, bf_event_due_ms, bf_event_observed_ms, bf_successor_ms;
static u64 bf_callback_reference, bf_callback_deadline;
static u8 bf_import_account[312], bf_after_event_account[312];
static u8 bf_after_event_timer[32];
static s32 bf_import_deficit;
static bool bf_positive_pass;
static s64 bf_positive_credit;
static u64 bf_positive_reference, bf_positive_activation_reference;
static s64 bf_positive_packet_cost, bf_positive_service_credit;
static u64 bf_positive_service_reference, bf_positive_service_refill;
static bool bf_positive_service_pass;
static u8 bf_positive_service_account[312];
static struct qdx_diag_bf_pair bf_pair;
static struct qdx_diag_bf_pair_update bf_pair_update;
static bool bf_aux_attached, bf_pair_started, bf_pair_published, bf_pair_visible;
static bool bf_pair_joined, bf_pair_pointer_written, bf_pair_pointer_restored, bf_pair_consequence_pass, bf_pair_closed;
static bool bf_pair_retirement_started, bf_pair_retire_configured, bf_pair_backing_started;
static bool bf_pair_child_started;
static u64 bf_pair_original_due, bf_pair_observed_ms, bf_pair_reference[2], bf_pair_cost;
static bool bf_pair_callback_valid, bf_pair_callback_discriminating;
static s64 bf_pair_expected_credit, bf_pair_unchanged_credit;
static u32 bf_pair_callback_branch; /* 1=positive/joined, 2=nonpositive/rearmed */
static u16 bf_pair_publication_epoch;
static bool bf_timer_joined;
static s64 bf_pair_before_credit[2], bf_pair_after_credit[2];
static u8 bf_pair_consequence_account[312], bf_pair_consequence_timer[32], bf_pair_consequence_group[232];
static int state_bf_pair_debit(unsigned int selection);

/* Native ABI from qdx-drv/abi.h: interface175, CHANGE1, ACK2, twenty bytes.
 * Existing device.c receiver remains the sole receiver. Two passive probes
 * obtain the actual core from our send and observe that same core's reply.
 */
#define BF_NATIVE_HZ 748800000U
struct bf_frequency_message {
 __le32 frequency, step, stats_enable, current_frequency, ack;
};
static_assert(sizeof(struct bf_frequency_message) == 20);
static struct bf_frequency_message bf_frequency_message;
struct bf_frequency_reply {
 u32 count, response, error, received, declared, frequency, ack;
 u64 ns;
};
static struct bf_frequency_reply bf_frequency_reply[2];
static struct task_struct *bf_frequency_sender;
static void *bf_frequency_core;
static u32 bf_frequency_step, bf_frequency_calls[2], bf_frequency_attempted;
static u32 bf_frequency_published, bf_frequency_observed;
static int bf_frequency_send_error[2], bf_frequency_observation_error;
static bool bf_frequency_started, bf_frequency_complete;
static u64 bf_frequency_start_ns[2];
static DECLARE_COMPLETION(bf_frequency_done);
static u64 bf_pair_wait_limit_ms, bf_pair_wait_remaining_ms, bf_pair_wait_budget_ms;

static int state_bf_frequency_send_probe(struct kprobe *probe, struct pt_regs *regs)
{
 unsigned long flags;
 void *core = (void *)regs->regs[0];
 u32 step;

 if (current != READ_ONCE(bf_frequency_sender) || regs->regs[1] != 175 ||
     regs->regs[2] != 1 || regs->regs[3] != (unsigned long)&bf_frequency_message ||
     regs->regs[4] != sizeof(bf_frequency_message)) return 0;
 spin_lock_irqsave(&result_lock, flags);
 step = bf_frequency_step;
 if (step < 2) {
  bf_frequency_calls[step]++;
  if (!step && !bf_frequency_core) bf_frequency_core = core;
  if (core != bf_frequency_core) bf_frequency_observation_error = -EXDEV;
 }
 spin_unlock_irqrestore(&result_lock, flags);
 return 0;
}

static int state_bf_frequency_reply_probe(struct kprobe *probe, struct pt_regs *regs)
{
 const struct bf_frequency_message *event = (void *)regs->regs[4];
 struct bf_frequency_reply *reply;
 unsigned long flags;
 u32 step;
 bool valid;

 if (regs->regs[1] != 2) return 0;
 spin_lock_irqsave(&result_lock, flags);
 if ((void *)regs->regs[0] != bf_frequency_core) goto out;
 step = READ_ONCE(bf_frequency_step);
 if (step >= 2) goto out;
 reply = &bf_frequency_reply[step];
 valid = event && regs->regs[6] >= sizeof(*event) &&
  regs->regs[5] >= regs->regs[6];
 /* Ignore an already observed earlier phase, never count it as this reply. */
 if (valid && le32_to_cpu(event->ack) != step) goto out;
 reply->count++;
 reply->response = regs->regs[2]; reply->error = regs->regs[3];
 reply->received = regs->regs[5]; reply->declared = regs->regs[6];
 if (reply->count == 1) reply->ns = ktime_get_ns();
 if (valid) {
  reply->frequency = le32_to_cpu(event->current_frequency);
  reply->ack = le32_to_cpu(event->ack);
 }
 if (!valid ||
     (reply->response != 0 && reply->response != 5) ||
     reply->frequency != BF_NATIVE_HZ)
  bf_frequency_observation_error = -EBADMSG;
 else bf_frequency_observed |= BIT(step);
 complete_all(&bf_frequency_done);
out:
 spin_unlock_irqrestore(&result_lock, flags);
 return 0;
}

static int state_bf_frequency_sync(void)
{
 struct qdx_endpoint *(*get_static)(struct qdx_service *, unsigned int, u32);
 struct kprobe resolver = { .symbol_name = "qdx_endpoint_static" };
 struct kprobe send_probe = { .symbol_name = "qdx_message_core",
  .pre_handler = state_bf_frequency_send_probe };
 struct kprobe reply_probe = { .symbol_name = "qdx_frequency_event",
  .pre_handler = state_bf_frequency_reply_probe };
 struct qdx_endpoint *endpoint;
 unsigned int step;
 u32 ifnum;
 int error;

 if (!bf_native_frequency_sync || !bf_account_test || bf_frequency_started ||
     bf_trigger_operation || bf_trigger_accepted || probe_loaded ||
     qdx_service_state(igs_service) != QDX_AVAILABLE) return -EPERM;
 bf_frequency_started = true; /* Even a partial notification is never replayed. */
 error = register_kprobe(&resolver);
 if (error) return error;
 get_static = (void *)resolver.addr;
 unregister_kprobe(&resolver);
 endpoint = get_static(igs_service, 0, 175);
 if (IS_ERR(endpoint)) return PTR_ERR(endpoint);
 error = qdx_endpoint_ifnum(endpoint, &ifnum);
 if (error || ifnum != 175) { error = error ?: -EXDEV; goto put; }
 error = register_kprobe(&send_probe);
 if (error) goto put;
 error = register_kprobe(&reply_probe);
 if (error) goto unregister_send;
 for (step = 0; step < 2; step++) {
  WRITE_ONCE(bf_frequency_step, step);
  reinit_completion(&bf_frequency_done);
  bf_frequency_message = (struct bf_frequency_message) {
   .frequency = cpu_to_le32(BF_NATIVE_HZ), .step = cpu_to_le32(step),
  };
  bf_frequency_start_ns[step] = ktime_get_ns();
  bf_frequency_attempted |= BIT(step);
  WRITE_ONCE(bf_frequency_sender, current);
  error = qdx_message_send(endpoint, 1, &bf_frequency_message, sizeof(bf_frequency_message));
  WRITE_ONCE(bf_frequency_sender, NULL);
  bf_frequency_send_error[step] = error;
  if (error) break;
  bf_frequency_published |= BIT(step);
  if (bf_frequency_calls[step] != 1 || !bf_frequency_core) {
   error = -EPROTO; break;
  }
  if (!wait_for_completion_timeout(&bf_frequency_done, msecs_to_jiffies(WAIT_MS))) {
   error = -ETIMEDOUT; break;
  }
  error = READ_ONCE(bf_frequency_observation_error);
  if (error || !(READ_ONCE(bf_frequency_observed) & BIT(step))) {
   error = error ?: -EPROTO; break;
  }
 }
 unregister_kprobe(&reply_probe); /* Join probe callbacks before stack removal. */
 if (!error) bf_frequency_complete = true;
unregister_send:
 unregister_kprobe(&send_probe);
put:
 qdx_endpoint_put(endpoint); /* Borrowed static endpoint: never retire it. */
 return error;
}






static int state_command(enum step step, bool submit, unsigned int wait_ms)
{
	struct qdx_endpoint *endpoint = igs;
	struct table_config message = {};
	struct mirror_config copy = { cpu_to_le32(1), cpu_to_le16(mirror_copy_size), 0 };
	__le32 assignment[2] = {}, next = cpu_to_le32(156);
	struct qdx_reply_bounds bounds;
	u8 reply[sizeof(message)] = {};
	const void *payload;
	size_t length;
	u32 opcode, subcommand = U32_MAX;
	int error;

	if (bf_request || fault || (request && pending != step))
		return fault ? -EPROTO : -EBUSY;
	if (step == ASSIGN || step == UNASSIGN) {
		opcode = step == ASSIGN ? 6 : 8;
		assignment[0] = cpu_to_le32(step == ASSIGN ? 0 : shaper);
		payload = assignment;
		length = step == ASSIGN ? 8 : 4;
	} else if (step >= MIRROR_CONFIG) {
		endpoint = mirror;
		opcode = step == MIRROR_CONFIG ? 0 : step == MIRROR_NEXT ? 3 :
			step == MIRROR_ENABLE ? 1 : step == MIRROR_DISABLE ? 2 : 4;
		payload = step == MIRROR_CONFIG ? (void *)&copy :
			step == MIRROR_NEXT ? (void *)&next : NULL;
		length = step == MIRROR_CONFIG ? sizeof(copy) : step == MIRROR_NEXT ? 4 : 0;
	} else {
		opcode = 10;
		message.data.tag = cpu_to_le32(TABLE_TAG);
		if (step == ALLOC) {
			subcommand = 0;
			message.data.allocate.kind = cpu_to_le32(1);
			message.data.allocate.tag = cpu_to_le32(TABLE_TAG);
		} else if (step == FREE) {
			subcommand = 1;
		} else if (step == STATS) {
			subcommand = 4;
		} else if (step == ROOT) {
			subcommand = 3;
		} else if (step == MEMORY) {
			subcommand = 10;
		} else if (step == CONFIG) {
			subcommand = 7;
			message.data.codel.limit = cpu_to_le32(32);
			message.data.codel.interval = cpu_to_le16(101);
			message.data.codel.target = cpu_to_le16(37);
			message.data.codel.mtu = cpu_to_le16(1500);
			message.data.codel.flows = cpu_to_le32(2);
			message.data.codel.memory = cpu_to_le32(table_address);
			message.data.codel.size = cpu_to_le32(TABLE_LEN);
			message.data.codel.quantum = cpu_to_le32(128);
		} else {
			return -EINVAL;
		}
		message.command = cpu_to_le32(subcommand);
		payload = &message;
		length = sizeof(message);
	}
	if (!request) {
		if (!submit)
			return 0;
		bounds = (struct qdx_reply_bounds) { length, length, length };
		if (step == CONFIG)
			qdx_dma_expose(table);
		request = qdx_command_submit(endpoint, opcode, payload, length, &bounds, NULL);
		if (IS_ERR(request)) {
			error = PTR_ERR(request);
			request = NULL;
			return error;
		}
		pending = step;
	}
	error = qdx_request_wait(request, jiffies + msecs_to_jiffies(wait_ms),
		&result, reply, sizeof(reply));
	if (result.outcome == QDX_UNKNOWN && !result.exposure_ended)
		return error ?: -EINPROGRESS;
	if (result.outcome == QDX_ACK) {
		if (result.declared_len != length || result.received_len < length) {
			fault = true;
			return -EPROTO;
		}
		error = 0;
		if (opcode == 10) {
			memcpy(&message, reply, sizeof(message));
			if (le32_to_cpu(message.command) != subcommand) {
				fault = true;
				return -EPROTO;
			}
			error = le32_to_cpu(message.response) ? -EREMOTEIO : 0;
		}
		if (!error) {
			switch (step) {
			case ASSIGN:
				shaper = get_unaligned_le32(reply + 4);
				assigned = true;
				break;
			case ALLOC: allocated = true; break;
			case MEMORY:
				memory_size = le32_to_cpu(message.data.memory.bytes);
				memory_checked = memory_size == 72;
				error = memory_checked ? 0 : -EPROTO;
				break;
			case CONFIG: configured = true; break;
			case STATS:
				probe_qlen = get_unaligned_le32(reply + 16);
				probe_drops += get_unaligned_le32(reply + 48) +
					get_unaligned_le32(reply + 64);
				break;
			case ROOT: probe_started = true; break;
			case FREE:
				allocated = configured = false;
				if (table)
					qdx_dma_access_end(table);
				break;
			case UNASSIGN: assigned = false; break;
			case MIRROR_CONFIG: mirror_configured = true; break;
			case MIRROR_NEXT: next_set = true; break;
			case MIRROR_ENABLE: enabled = true; break;
			case MIRROR_DISABLE: enabled = false; break;
			case MIRROR_RESET: next_set = false; break;
			default: break;
			}
		}
	} else {
		error = result.error ?: error ?: -EIO;
	}
	qdx_request_put(request);
	request = NULL;
	pending = NONE;
	return error;
}

/* Fixed legal graph operations only; unresolved commands keep their identity. */
static int state_bf_command(u32 command, u32 tag, u32 child)
{
 struct table_config message = {};
 struct qdx_reply_bounds bounds = { sizeof(message), sizeof(message), sizeof(message) };
 u8 reply[sizeof(message)];
 u32 *words = (u32 *)message.data.reserved;
 unsigned int bit = tag == BF_OUTER_TAG ? 0 : tag == BF_PARENT_TAG ? 1 :
  tag == BF_GROUP_TAG ? 2 : tag == BF_PRIVATE_TAG ? 3 : 4;
 int error;

 /* The known BF fixtures reserve OUTER before the first FQ allocation.
  * Before bf-stage, only that empty root may be allocated or released. */
 if ((!bf_mode && !((bf_account_test || bf_positive_test) &&
      tag == BF_OUTER_TAG && (command == 0 || command == 1))) ||
     fault || request || (tag != BF_OUTER_TAG && tag != BF_PARENT_TAG && tag != BF_GROUP_TAG &&
     tag != BF_PRIVATE_TAG && (!bf_account_test || tag != BF_AUX_TAG)))
  return -EPERM;
 if (bf_request && (bf_command_pending != command || bf_tag_pending != tag || bf_child_pending != child))
  return -EBUSY;
 message.command = cpu_to_le32(command);
 words[0] = cpu_to_le32(tag);
 if (command == 0) {
  words[0] = cpu_to_le32(tag == BF_OUTER_TAG ? 3 : tag == BF_PARENT_TAG ? 6 :
   (tag == BF_GROUP_TAG || tag == BF_AUX_TAG) ? 7 : 4);
  words[1] = cpu_to_le32(tag);
 } else if (command == 5 || command == 6) {
  words[1] = cpu_to_le32(tag == BF_OUTER_TAG && command == 6 ? 0 : child);
 } else if (command == 7 && tag == BF_PRIVATE_TAG) {
  words[1] = cpu_to_le32(1); /* exactly one private packet */
  words[2] = cpu_to_le32(1); /* packet, not byte limit */
 } else if (command == 7 && (tag == BF_GROUP_TAG || tag == BF_AUX_TAG)) {
  words[1] = cpu_to_le32(128); /* quantum */
  words[2] = cpu_to_le32(bf_positive_test ? 8 : 1); /* fixed initial policy */
  words[3] = cpu_to_le32(96);  /* second64-byte debit leaves negative credit */
  words[4] = cpu_to_le32(64);  /* actual control/probe frame size */
 } else if (command != 1 && command != 3 && command != 4) {
  return -EINVAL;
 }
 if (!bf_request) {
  bf_command_pending = command; bf_tag_pending = tag; bf_child_pending = child;
  bf_request = qdx_command_submit(igs, 10, &message, sizeof(message), &bounds, NULL);
  if (IS_ERR(bf_request)) { error = PTR_ERR(bf_request); bf_request = NULL; return error; }
 }
 error = qdx_request_wait(bf_request, jiffies + msecs_to_jiffies(WAIT_MS),
  &bf_result, reply, sizeof(reply));
 if (bf_result.outcome == QDX_UNKNOWN && !bf_result.exposure_ended)
  return error ?: -EINPROGRESS;
 if (bf_result.outcome == QDX_ACK) {
  if (bf_result.declared_len != sizeof(message) || bf_result.received_len < sizeof(message) ||
      get_unaligned_le32(reply) != command) { fault = true; return -EPROTO; }
  error = get_unaligned_le32(reply + 4) ? -EREMOTEIO : 0;
  if (!error) {
   if (bf_account_test && bf_pair_retirement_started && command == 7 && tag == BF_GROUP_TAG)
    bf_pair_retire_configured = true;
   if (!command) bf_allocated |= BIT(bit);
   if (command == 1) bf_allocated &= ~BIT(bit);
   if (tag == BF_PARENT_TAG && child == BF_AUX_TAG) {
    if (command == 5) bf_aux_attached = true;
    if (command == 6) bf_aux_attached = false;
   } else {
    if (command == 5) bf_links |= BIT(bit);
    if (command == 6) bf_links &= ~BIT(bit);
   }
  }
 } else error = bf_result.error ?: error ?: -EIO;
 qdx_request_put(bf_request); bf_request = NULL;
 return error;
}

static void state_bf_trigger_returned(void *owner, struct sk_buff *original,
 struct sk_buff *returned, const struct qdx_rx_meta *meta, struct napi_struct *napi)
{
 struct probe_packet *packet = owner;
 bool valid = original == packet->skb && returned == original && returned && meta &&
  meta->type == QDX_RECEIVE_RETURNED && meta->ifnum == igs_ifnum &&
  returned->len == PROBE_LENGTH && !memcmp(returned->data, packet->expected, PROBE_LENGTH);
 unsigned long flags;

 packet->skb = NULL;
 spin_lock_irqsave(&result_lock, flags);
 if (returned) { bf_trigger_returns++; bf_trigger_valid += valid; }
 else bf_trigger_disposed++;
 if (bf_trigger_returns + bf_trigger_disposed == 4) complete_all(&bf_trigger_done);
 spin_unlock_irqrestore(&result_lock, flags);
 dev_kfree_skb_any(returned);
}

/* The account fixture preloads all four private triggers before opening
 * selection: an empty-child callback otherwise clears preferred before debit.
 * Their real returns precede leaf reset; only a later snapshot proves a timer.
 */
static int state_bf_stage(void)
{
 struct qdx_packet_recipient recipient = {
  .owner = { .module = THIS_MODULE }, .returned = state_bf_trigger_returned,
 };
 struct qdx_ready ready;
 struct sk_buff *skb;
 u8 *data;
 unsigned long deadline;
 unsigned int i;
 bool drained;
 int error;

 /* SET_ROOT validates attachment; it does not change the first ALLOC
  * selected by the firmware. Refuse the unprepared legacy command. */
 if (!(bf_allocated & BIT(0))) return -EPERM;
 if (bf_mode || !configured || !word_restored || !rounds[2].host_equal || operation ||
     probe_loaded || closed || fault || request || !qdx_diag_fq_table_idle(table))
  return -EPERM;
 bf_mode = true;
 error = state_bf_command(0, BF_PARENT_TAG, 0);
 if (!error && bf_account_test) error = state_bf_command(0, BF_AUX_TAG, 0);
 if (!error) error = state_bf_command(0, BF_GROUP_TAG, 0);
 if (!error) error = state_bf_command(5, BF_GROUP_TAG, TABLE_TAG);
 if (!error) error = state_bf_command(5, BF_PARENT_TAG, BF_GROUP_TAG);
 if (!error && bf_account_test) error = state_bf_command(5, BF_PARENT_TAG, BF_AUX_TAG);
 /* Parent ATTACH initializes each complete 16-byte DRR entry, including
  * quantum and deficit. Configure only after both parent links exist. */
 if (!error) error = state_bf_command(7, BF_GROUP_TAG, 0);
 if (!error && bf_account_test) error = state_bf_command(7, BF_AUX_TAG, 0);
 if (!error && !bf_account_test)
  error = state_bf_command(5, BF_OUTER_TAG, BF_PARENT_TAG);
 if (!error) error = state_bf_command(3, BF_OUTER_TAG, 0);
 if (!error && bf_native_frequency_sync) error = state_bf_frequency_sync();
 if (error) return error;
 bf_trigger_operation = qdx_packet_op_prepare(igs, TABLE_TAG, QDX_RECEIVE_RETURNED);
 if (IS_ERR(bf_trigger_operation)) {
  error = PTR_ERR(bf_trigger_operation); bf_trigger_operation = NULL; return error;
 }
 for (i = 0; i < 4; i++) {
  skb = alloc_skb(PROBE_HEADROOM + PROBE_LENGTH, GFP_KERNEL);
  if (!skb) { error = -ENOMEM; break; }
  skb_reserve(skb, PROBE_HEADROOM); data = skb_put_zero(skb, PROBE_LENGTH);
  ether_addr_copy(data, port->dev_addr); ether_addr_copy(data + ETH_ALEN, port->dev_addr);
  put_unaligned_be16(ETH_P_IP, data + 12); data[14] = 0x45;
  put_unaligned_be16(PROBE_LENGTH - ETH_HLEN, data + 16);
  data[22] = 64; data[23] = IPPROTO_UDP;
  put_unaligned_be32(0xc0000201, data + 26); put_unaligned_be32(0xc0000202, data + 30);
  put_unaligned_be16(21000, data + 34); put_unaligned_be16(40000, data + 36);
  put_unaligned_be16(PROBE_LENGTH - ETH_HLEN - 20, data + 38);
  put_unaligned_le32(0x42465452, data + 42); put_unaligned_le32(i, data + 46);
  put_unaligned(csum_fold(csum_partial(data + 14, 20, 0)), (__sum16 *)(data + 24));
  skb->dev = port; skb->protocol = htons(ETH_P_IP); skb_reset_mac_header(skb);
  bf_triggers[i].skb = skb; memcpy(bf_triggers[i].expected, data, PROBE_LENGTH);
  recipient.owner.object = &bf_triggers[i];
  ready = qdx_packet_op_submit(bf_trigger_operation, skb, &recipient);
  if (ready.status != QDX_ACCEPTED) {
   bf_triggers[i].skb = NULL; dev_kfree_skb(skb); error = ready.error ?: -EAGAIN; break;
  }
  bf_trigger_accepted++;
 }
 qdx_packet_op_close(bf_trigger_operation);
 if (error) return error;
 if (bf_account_test) {
  /* H2N acceptance is not leaf enqueue completion. The detached selector
   * cannot drain these originals; wait only for their actual admission. */
  deadline = jiffies + msecs_to_jiffies(WAIT_MS);
  do {
   error = state_command(STATS, true, WAIT_MS);
   if (error) return error;
   if (probe_drops || bf_trigger_returns || bf_trigger_disposed || probe_qlen > 4)
    return -EBADMSG;
   if (probe_qlen == 4) break;
   usleep_range(500, 1000);
  } while (time_before(jiffies, deadline));
  if (probe_qlen != 4) return -ETIMEDOUT;
  bf_trigger_queued_before_open = probe_qlen;
  error = state_bf_command(5, BF_OUTER_TAG, BF_PARENT_TAG);
  if (error) return error;
 }
 if (!wait_for_completion_timeout(&bf_trigger_done, msecs_to_jiffies(WAIT_MS))) return -ETIMEDOUT;
 error = read_poll_timeout(qdx_packet_op_drained, drained, drained, 10,
  WAIT_MS * 1000, false, bf_trigger_operation);
 if (error || bf_trigger_returns != 4 || bf_trigger_valid != 4 || bf_trigger_disposed)
  return error ?: -EBADMSG;
 qdx_packet_op_put(bf_trigger_operation); bf_trigger_operation = NULL;
 error = state_bf_command(6, BF_OUTER_TAG, BF_PARENT_TAG);
 if (error) return error;
 bf_cut = true;
 error = state_bf_command(6, BF_GROUP_TAG, TABLE_TAG);
 if (!error) error = state_command(STATS, true, WAIT_MS);
 if (error || probe_qlen || probe_drops) return error ?: -EBADMSG;
 error = state_command(FREE, true, WAIT_MS);
 if (!error) error = state_command(ALLOC, true, WAIT_MS);
 if (!error) error = state_command(CONFIG, true, WAIT_MS);
 if (!error) error = state_bf_command(5, BF_GROUP_TAG, TABLE_TAG);
 if (error) return error;
 bf_ready = true;
 return 0;
}

static void state_original(void *owner, struct sk_buff *original,
	struct sk_buff *returned, const struct qdx_rx_meta *meta, struct napi_struct *napi)
{
	struct table_round *round;
	unsigned long flags;
	u32 index = READ_ONCE(active);

	if (WARN_ON_ONCE(index >= ARRAY_SIZE(rounds)))
		return;
	round = &rounds[index];
	spin_lock_irqsave(&result_lock, flags);
	round->originals++;
	round->original_valid = !original && !returned && meta &&
		meta->ifnum == READ_ONCE(mirror_ifnum) && meta->type == QDX_RECEIVE_PACKET;
	round->original_type = meta ? meta->type : U32_MAX;
	round->original_ifnum = meta ? meta->ifnum : U32_MAX;
	spin_unlock_irqrestore(&result_lock, flags);
	complete_all(&round->original_done);
}

static void state_owned_original(void *owner, struct sk_buff *original,
 struct sk_buff *returned, const struct qdx_rx_meta *meta, struct napi_struct *napi)
{
 owned.original_ns = ktime_get_ns();
 owned.originals++;
 owned.original_valid = !original && !returned && meta &&
  meta->ifnum == READ_ONCE(mirror_ifnum) && meta->type == QDX_RECEIVE_PACKET;
 complete_all(&owned.original_done);
}

static void state_owned_clone(struct sk_buff *skb, const struct qdx_rx_meta *meta)
{
 owned.clone_ns = ktime_get_ns();
 owned.clones++;
 owned.clone_data_mod4 = (unsigned long)skb->data & 3;
 owned.clone_valid = meta && meta->ifnum == READ_ONCE(mirror_ifnum) &&
  meta->type == QDX_RECEIVE_PACKET && skb->len == owned.length && !skb_is_nonlinear(skb) &&
  (owned.kind != QDX_DIAG_FQ_CLOCK || !owned.clone_data_mod4);
 if (owned.clone_valid && owned.kind != QDX_DIAG_FQ_PAYLOAD)
  memcpy(owned.bytes, skb->data, owned.length);
 if (owned.clone_valid && owned.kind == QDX_DIAG_FQ_PAYLOAD && !owned.payload)
  owned.payload = skb;
 else
  dev_kfree_skb_any(skb);
 complete_all(&owned.clone_done);
}

static void state_clone(void *owner, struct sk_buff *skb,
	const struct qdx_rx_meta *meta, struct napi_struct *napi)
{
	struct table_round *round;
	unsigned long flags;
	u32 index = READ_ONCE(active);

	if (index == ARRAY_SIZE(rounds)) {
		state_owned_clone(skb, meta);
		return;
	}
	if (index >= ARRAY_SIZE(rounds)) {
		spin_lock_irqsave(&result_lock, flags);
		unexpected_clones++;
		spin_unlock_irqrestore(&result_lock, flags);
		dev_kfree_skb_any(skb);
		return;
	}
	round = &rounds[index];
	spin_lock_irqsave(&result_lock, flags);
	round->clones++;
	round->clone_type = meta ? meta->type : U32_MAX;
	round->clone_ifnum = meta ? meta->ifnum : U32_MAX;
	round->clone_length = skb->len;
	round->clone_valid = meta && meta->ifnum == READ_ONCE(mirror_ifnum) &&
		meta->type == QDX_RECEIVE_PACKET && skb->len == TABLE_LEN &&
		!skb_is_nonlinear(skb);
	if (round->clone_valid) {
		memcpy(round->actual, skb->data, TABLE_LEN);
		round->clone_valid = index == 3 ||
			!memcmp(round->actual, round->expected, TABLE_LEN);
	}
	spin_unlock_irqrestore(&result_lock, flags);
	dev_kfree_skb_any(skb);
	complete_all(&round->clone_done);
}
static const struct qdx_receive_ops state_receive_ops = { .packet = state_clone };

static void state_probe_returned(void *owner, struct sk_buff *original,
	struct sk_buff *returned, const struct qdx_rx_meta *meta, struct napi_struct *napi)
{
	struct probe_packet *packet = owner;
	unsigned long flags;
	u64 now = ktime_get_ns();
	bool original_owned = original && original == packet->skb;
	bool valid = returned && returned == original && original_owned &&
		meta && meta->type == QDX_RECEIVE_RETURNED &&
		meta->ifnum == READ_ONCE(igs_ifnum) && returned->len == PROBE_LENGTH &&
		!skb_is_nonlinear(returned) &&
		!memcmp(returned->data, packet->expected, PROBE_LENGTH);

	packet->skb = NULL;
	spin_lock_irqsave(&result_lock, flags);
 if (adopt_retiring) {
  adopt_retired++;
  adopt_retirement_bad += !!returned || !original || !original_owned;
  if (adopt_retired == PROBE_PACKETS)
   complete_all(&adopt_done);
  spin_unlock_irqrestore(&result_lock, flags);
  dev_kfree_skb_any(returned);
  return;
 }
 if (adopt_rebuild_started) {
  adopt_bad_owner += !original_owned;
  if (!adopt_first_ns) adopt_first_ns = now;
  adopt_last_ns = now;
  if (returned) {
   if (adopt_returns < ARRAY_SIZE(adopt_order))
    adopt_order[adopt_returns] = packet->id;
   adopt_returns++;
   adopt_valid += valid;
  } else {
   adopt_disposed++;
   adopt_disposed_mask |= BIT(packet->id);
  }
  if (adopt_returns + adopt_disposed == 14)
   complete_all(&adopt_done);
  spin_unlock_irqrestore(&result_lock, flags);
  dev_kfree_skb_any(returned);
  return;
 }

	if (!probe_first_ns)
		probe_first_ns = now;
	probe_last_ns = now;
	if (returned) {
		if (probe_returns < PROBE_PACKETS)
			probe_order[probe_returns] = packet->id;
		probe_returns++;
		probe_valid += valid;
	} else {
		probe_disposed++;
	}
	if (probe_returns + probe_disposed >= PROBE_PACKETS)
		complete_all(&probe_done);
	spin_unlock_irqrestore(&result_lock, flags);
	/* Only a positive returned skb transfers to us. QDX frees NULL originals. */
	dev_kfree_skb_any(returned);
}

static int state_prepare(void)
{
	struct qdx_owner owner = { .module = THIS_MODULE, .object = rounds };
	int error;

	if (closed || fault)
		return -EPERM;
	if (!pinned) {
		if (!try_module_get(THIS_MODULE))
			return -ENODEV;
		pinned = true;
	}
	if (!port)
		port = dev_get_by_name(&init_net, "lan3");
	if (!port || !netif_running(port))
		return -ENODEV;
	if (!igs_service) {
		igs_service = qdx_service_get(port, QDX_SERVICE_IGS);
		if (IS_ERR(igs_service)) {
			error = PTR_ERR(igs_service);
			igs_service = NULL;
			return error;
		}
	}
	if (!mirror_service) {
		mirror_service = qdx_service_get(port, QDX_SERVICE_MIRROR);
		if (IS_ERR(mirror_service)) {
			error = PTR_ERR(mirror_service);
			mirror_service = NULL;
			return error;
		}
	}
	if (!igs) {
		igs = qdx_endpoint_alloc(igs_service, 53);
		if (IS_ERR(igs)) {
			error = PTR_ERR(igs);
			igs = NULL;
			return error;
		}
	}
	error = qdx_endpoint_wait(igs, jiffies + msecs_to_jiffies(WAIT_MS));
	if (error)
		return error;
	error = qdx_endpoint_ifnum(igs, &igs_ifnum);
	if (error)
		return error;
	if (!mirror) {
		mirror = qdx_endpoint_alloc(mirror_service, 65);
		if (IS_ERR(mirror)) {
			error = PTR_ERR(mirror);
			mirror = NULL;
			return error;
		}
	}
	error = qdx_endpoint_wait(mirror, jiffies + msecs_to_jiffies(WAIT_MS));
	if (error)
		return error;
	error = qdx_endpoint_ifnum(mirror, &mirror_ifnum);
	if (error)
		return error;
	if (!receiver) {
		receiver = qdx_endpoint_receive_register(mirror, QDX_RECEIVE_PACKET,
			&owner, &state_receive_ops);
		if (IS_ERR(receiver)) {
			error = PTR_ERR(receiver);
			receiver = NULL;
			return error;
		}
	}
	if (request) {
		error = state_command(pending, false, WAIT_MS);
		if (error)
			return error;
	}
	if (!assigned) {
		error = state_command(ASSIGN, true, WAIT_MS);
		if (error)
			return error;
	}
	/* NSS assigns the actual worker root only while it is null. Preserve
	 * the ordinary FQ fixture; declared BF fixtures must allocate OUTER first.
	 */
	if ((bf_account_test || bf_positive_test) && !(bf_allocated & BIT(0))) {
		error = state_bf_command(0, BF_OUTER_TAG, 0);
		if (error)
			return error;
	}
	if (!allocated) {
		error = state_command(ALLOC, true, WAIT_MS);
		if (error)
			return error;
	}
	if (!memory_checked) {
		error = state_command(MEMORY, true, WAIT_MS);
		if (error)
			return error;
	}
	if (!table) {
		table = qdx_diag_fq_table_alloc(igs_service, &owner);
		if (IS_ERR(table)) {
			error = PTR_ERR(table);
			table = NULL;
			return error;
		}
		table_address = (u32)qdx_dma_address(table);
	}
	if (!configured) {
		error = state_command(CONFIG, true, WAIT_MS);
		if (error)
			return error;
	}
	if (!mirror_configured) {
		error = state_command(MIRROR_CONFIG, true, WAIT_MS);
		if (error)
			return error;
	}
	if (!next_set) {
		error = state_command(MIRROR_NEXT, true, WAIT_MS);
		if (error)
			return error;
	}
	if (!enabled) {
		error = state_command(MIRROR_ENABLE, true, WAIT_MS);
		if (error)
			return error;
	}
	if (!operation) {
		operation = qdx_packet_op_prepare(mirror, COPY_TAG, QDX_RECEIVE_PACKET);
		if (IS_ERR(operation)) {
			error = PTR_ERR(operation);
			operation = NULL;
			return error;
		}
	}
	return 0;
}

static int state_read(unsigned int index)
{
	struct table_round *round = &rounds[index];
	struct qdx_packet_recipient recipient = {
		.owner = { .module = THIS_MODULE, .object = rounds },
		.returned = state_original,
	};
	struct qdx_ready ready;
	unsigned int bin;
	u8 *expected;
	bool idle;
	int error;

	if (!table || !configured || !enabled || !next_set ||
	    closed || request || fault || !qdx_diag_fq_table_idle(table))
		return -EINVAL;
	if (round->submitted)
		return -EALREADY;
	if ((index == 1 && !word_changed) || (index == 2 && !word_restored) ||
	    (index == 3 && (!probe_queued || probe_started)))
		return -EPERM;
	for (bin = 0; index < 3 && bin < 2; bin++) {
		expected = round->expected + 72 * bin;
		put_unaligned_le32(table_address + 72 * bin, expected);
		put_unaligned_le32(table_address + 72 * bin, expected + 4);
		put_unaligned_le32(index == 1 && !bin ? 192 : 128, expected + 8);
		put_unaligned_le16(101, expected + 28);
		put_unaligned_le16(37, expected + 30);
		put_unaligned_le16(1500, expected + 60);
	}
	if (!operation) {
		operation = qdx_packet_op_prepare(mirror, COPY_TAG, QDX_RECEIVE_PACKET);
		if (IS_ERR(operation)) {
			error = PTR_ERR(operation);
			operation = NULL;
			return error;
		}
	}
	WRITE_ONCE(active, index);
	round->start_ns = ktime_get_ns();
	ready = qdx_diag_fq_table_copy(operation, table, &recipient);
	if (ready.status != QDX_ACCEPTED)
		return ready.error ?: -EAGAIN;
	round->submitted = true;
	if (!wait_for_completion_timeout(&round->original_done, msecs_to_jiffies(WAIT_MS)) ||
	    !wait_for_completion_timeout(&round->clone_done, msecs_to_jiffies(WAIT_MS)))
		return -ETIMEDOUT;
	/* Callback completion precedes the actual loan-counter release. Seal
	 * this one-copy operation and wait for the real region/operation tail.
	 */
	qdx_packet_op_close(operation);
	error = read_poll_timeout(qdx_diag_fq_table_idle, idle, idle, 50,
		WAIT_MS * 1000, false, table);
	if (error || !qdx_packet_op_drained(operation))
		return error ?: -EBUSY;
	synchronize_net();
	qdx_packet_op_put(operation);
	operation = NULL;
	dma_rmb();
	memcpy(round->host_after, qdx_dma_cpu(table), TABLE_LEN);
	round->host_equal = !memcmp(round->actual, round->host_after, TABLE_LEN);
	round->elapsed_ns = ktime_get_ns() - round->start_ns;
	return round->originals == 1 && round->clones == 1 && round->original_valid &&
		round->clone_valid && round->host_equal ? 0 : -EBADMSG;
}

static int state_write_word(bool restore)
{
	struct table_round *previous = &rounds[restore ? 1 : 0];
	u32 value = restore ? 128 : 192;

	if (!table || closed || request || fault || !configured || probe_loaded ||
	    !completion_done(&previous->original_done) ||
	    !completion_done(&previous->clone_done))
		return -EINVAL;
	synchronize_net();
	if (!qdx_diag_fq_table_idle(table) ||
	    (operation && !qdx_packet_op_drained(operation)) || previous->originals != 1 ||
	    previous->clones != 1 || !previous->original_valid)
		return -EBUSY;
	if (!restore && (!previous->clone_valid || !previous->host_equal || word_changed))
		return -EPERM;
	if (restore && (!word_changed || word_restored))
		return -EPERM;
	/* This node has never had a parent/default/root publication or producer.
	 * Only the identified quantum word changes; all pointers remain untouched.
	 */
	WRITE_ONCE(*(__le32 *)(qdx_dma_cpu(table) + 8), cpu_to_le32(value));
	dma_wmb();
	if (restore)
		word_restored = true;
	else
		word_changed = true;
	return 0;
}

/* No user packet, pointer, tag, count, length or quantum is configurable here. */
static int state_probe_load(void)
{
	struct qdx_packet_recipient recipient = {
		.owner = { .module = THIS_MODULE }, .returned = state_probe_returned,
	};
	struct qdx_ready ready;
	struct sk_buff *skb;
	u8 *data;
	unsigned long deadline;
	unsigned int i, index;
	u32 sentinel;
	int error;

	if (closed || fault || request || !word_restored || probe_loaded ||
	    !rounds[2].clone_valid || !rounds[2].host_equal ||
	    !rounds[2].original_valid || rounds[2].originals != 1 ||
	    rounds[2].clones != 1 || !qdx_diag_fq_table_idle(table) || operation)
		return -EPERM;
	for (i = 0; i < PROBE_PACKETS; i++) {
		probes[i].skb = alloc_skb(PROBE_HEADROOM + PROBE_LENGTH, GFP_KERNEL);
		if (!probes[i].skb) {
			while (i) {
				dev_kfree_skb(probes[--i].skb);
				probes[i].skb = NULL;
			}
			return -ENOMEM;
		}
	}
	probe_operation = qdx_packet_op_prepare(igs, TABLE_TAG, QDX_RECEIVE_RETURNED);
	if (IS_ERR(probe_operation)) {
		error = PTR_ERR(probe_operation);
		probe_operation = NULL;
		goto free_unsubmitted;
	}
	/* C proved release of this whole never-published table. No packet yet exists. */
	WRITE_ONCE(*(__le32 *)(qdx_dma_cpu(table) + 8), cpu_to_le32(192));
	dma_wmb();
	probe_loaded = true;
	for (i = 0; i < PROBE_PACKETS; i++) {
		skb = probes[i].skb;
		skb_reserve(skb, PROBE_HEADROOM);
		data = skb_put_zero(skb, PROBE_LENGTH);
		ether_addr_copy(data, port->dev_addr);
		ether_addr_copy(data + ETH_ALEN, port->dev_addr);
		put_unaligned_be16(ETH_P_IP, data + 12);
		data[14] = 0x45;
		put_unaligned_be16(PROBE_LENGTH - ETH_HLEN, data + 16);
		data[22] = 64;
		data[23] = IPPROTO_UDP;
		put_unaligned_be32(0xc0000201, data + 26);
		put_unaligned_be32(0xc0000202, data + 30);
		put_unaligned_be16(20000 + (i >= 8), data + 34);
		put_unaligned_be16(40000, data + 36);
		put_unaligned_be16(PROBE_LENGTH - ETH_HLEN - 20, data + 38);
		put_unaligned_le32(0x46515354, data + 42);
		put_unaligned_le32(i, data + 46);
		put_unaligned(csum_fold(csum_partial(data + 14, 20, 0)), (__sum16 *)(data + 24));
		skb->dev = port;
		skb->protocol = htons(ETH_P_IP);
		skb_reset_mac_header(skb);
		probes[i].id = i;
		memcpy(probes[i].expected, data, PROBE_LENGTH);
		recipient.owner.object = &probes[i];
		ready = qdx_packet_op_submit(probe_operation, skb, &recipient);
		if (ready.status != QDX_ACCEPTED) {
			error = ready.error ?: -EAGAIN;
			qdx_packet_op_close(probe_operation);
			goto free_unsubmitted;
		}
		probe_accepted++;
	}
	qdx_packet_op_close(probe_operation);
	deadline = jiffies + msecs_to_jiffies(WAIT_MS);
	do {
		error = state_command(STATS, true, WAIT_MS);
		if (error)
			return error;
		if (probe_qlen == PROBE_PACKETS)
			break;
		if (READ_ONCE(probe_returns) || READ_ONCE(probe_disposed) || probe_drops)
			return -EBADMSG;
		usleep_range(1000, 1500);
	} while (time_before(jiffies, deadline));
	if (probe_qlen != PROBE_PACKETS || READ_ONCE(probe_returns) ||
	    READ_ONCE(probe_disposed) || probe_drops)
		return -EBADMSG;
	probe_queued = true;
	error = state_read(3);
	if (error)
		return error;
	data = rounds[3].actual;
	for (index = 0; index < 2; index++) {
		u8 *bin = data + index * 72;
		if (get_unaligned_le32(bin + 8) != (index ? 128 : 192) ||
		    get_unaligned_le32(bin + 12) || get_unaligned_le32(bin + 24) != 8 ||
		    get_unaligned_le32(bin + 64) != 512 || bin[68] != 1 ||
		    !get_unaligned_le32(bin + 16) || !get_unaligned_le32(bin + 20))
			return -EBADMSG;
	}
	sentinel = get_unaligned_le32(data + 4);
	if (get_unaligned_le32(data) != table_address + 72 ||
	    get_unaligned_le32(data + 76) != table_address ||
	    get_unaligned_le32(data + 72) != sentinel ||
	    sentinel < 0x4027b62c + 228 || sentinel >= 0x4027b62c + 256 * 280 + 228 ||
	    (sentinel - 0x4027b62c - 228) % 280)
		return -EBADMSG;
	probe_snapshot_valid = true;
	return 0;

free_unsubmitted:
	for (i = probe_accepted; i < PROBE_PACKETS; i++) {
		dev_kfree_skb(probes[i].skb);
		probes[i].skb = NULL;
	}
	return error;
}

/* No per-read RCU grace period: callback storage and receiver stay pinned,
 * and callbacks perform no access after signalling. Join actual loan tails.
 */
static int state_owned_read(enum qdx_diag_fq_range kind, unsigned int index,
 unsigned int length, void *destination)
{
 struct qdx_packet_recipient recipient = {
  .owner = { .module = THIS_MODULE, .object = rounds },
  .returned = state_owned_original,
 };
 struct qdx_ready ready;
 struct owned_copy_cost *cost;
 u64 start, submitted, callbacks, table_idle, operation_idle;
 bool idle, drained;
 int error;

 if (closed || fault || request || !probe_snapshot_valid || probe_started ||
     !table || !qdx_diag_fq_table_idle(table) || operation || owned.payload ||
     !length || length > mirror_copy_size || !enabled ||
     (kind == QDX_DIAG_FQ_PAYLOAD ? length > 2048 : length > sizeof(owned.bytes)))
  return -EPERM;
 memset(&owned, 0, sizeof(owned));
 init_completion(&owned.original_done);
 init_completion(&owned.clone_done);
 owned.kind = kind; owned.index = index; owned.length = length;
 operation = qdx_packet_op_prepare(mirror, COPY_TAG, QDX_RECEIVE_PACKET);
 if (IS_ERR(operation)) {
  error = PTR_ERR(operation);
  operation = NULL;
  return error;
 }
 WRITE_ONCE(active, ARRAY_SIZE(rounds));
 start = ktime_get_ns();
 if (kind == OWNED_TABLE)
  ready = qdx_diag_fq_table_copy(operation, table, &recipient);
 else
  ready = qdx_diag_fq_owned_copy(operation, table, probe_operation,
   &owned_view, kind, index, &recipient);
 submitted = ktime_get_ns();
 if (ready.status != QDX_ACCEPTED) {
  qdx_packet_op_close(operation);
  qdx_packet_op_put(operation);
  operation = NULL;
  return ready.error ?: -EAGAIN;
 }
 owned.submitted = true;
 if (!wait_for_completion_timeout(&owned.original_done, msecs_to_jiffies(WAIT_MS)) ||
     !wait_for_completion_timeout(&owned.clone_done, msecs_to_jiffies(WAIT_MS)))
  return -ETIMEDOUT;
 callbacks = ktime_get_ns();
 qdx_packet_op_close(operation);
 error = read_poll_timeout(qdx_diag_fq_table_idle, idle, idle, 10,
  WAIT_MS * 1000, false, table);
 table_idle = ktime_get_ns();
 if (!error)
  error = read_poll_timeout(qdx_packet_op_drained, drained, drained, 10,
   WAIT_MS * 1000, false, operation);
 operation_idle = ktime_get_ns();
 if (error)
  return error;
 owned.elapsed_ns = ktime_get_ns() - start;
 qdx_packet_op_put(operation);
 operation = NULL;
 if (owned.originals != 1 || owned.clones != 1 ||
     !owned.original_valid || !owned.clone_valid)
  return -EBADMSG;
 if (kind != QDX_DIAG_FQ_PAYLOAD && destination && destination != owned.bytes)
  memcpy(destination, owned.bytes, length);
 if (owned_read_count < ARRAY_SIZE(owned_read_ns))
  owned_read_ns[owned_read_count++] = owned.elapsed_ns;
 cost = &owned_cost[owned_cost_count++ % ARRAY_SIZE(owned_cost)];
 cost->kind = kind;
 cost->index = index;
 cost->submit_ns = submitted - start;
 cost->original_ns = owned.original_ns - start;
 cost->clone_ns = owned.clone_ns - start;
 cost->callbacks_ns = callbacks - start;
 cost->close_table_ns = table_idle - callbacks;
 cost->operation_wait_ns = operation_idle - table_idle;
 cost->total_ns = owned.elapsed_ns;
 return 0;
}

static int state_host_clock(u32 words[6], u64 times[2])
{
 struct qdx_owner owner = { .module = THIS_MODULE, .object = rounds };
 int error;

 if (operation || closed || fault || request || probe_started ||
     !qdx_diag_fq_table_idle(table))
  return -EPERM;
 operation = qdx_packet_op_prepare(mirror, COPY_TAG, QDX_RECEIVE_PACKET);
 if (IS_ERR(operation)) {
  error = PTR_ERR(operation); operation = NULL; return error;
 }
 qdx_packet_op_close(operation);
 times[0] = ktime_get_ns();
 error = qdx_diag_fq_clock_host(operation, table, probe_operation, &owned_view, &owner, words);
 times[1] = ktime_get_ns();
 qdx_packet_op_put(operation); operation = NULL;
 return error;
}

static int state_occupied_read(void)
{
 unsigned int i, length;
 u32 address, node, id;
 int error;

 if (!probe_snapshot_valid || probe_started || occupied_read || request ||
     closed || fault || operation || !qdx_diag_fq_table_idle(table))
  return -EPERM;
 occupied_read = true;
 memcpy(owned_view.table, rounds[3].actual, TABLE_LEN);
 error = state_command(MIRROR_DISABLE, true, WAIT_MS);
 if (error)
  return error;
 mirror_copy_size = bf_mode ? 312 : 280;
 error = state_command(MIRROR_CONFIG, true, WAIT_MS);
 if (!error)
  error = state_command(MIRROR_ENABLE, true, WAIT_MS);
 if (error)
  return error;
 error = state_owned_read(QDX_DIAG_FQ_NODE, 0, 280, owned_view.node);
 if (error)
  return error;
 node = get_unaligned_le32(owned_view.table + 4) - 228;
 if (get_unaligned_le32(owned_view.node + 8) != 1 ||
     get_unaligned_le32(owned_view.node + 16) != TABLE_TAG ||
     (bf_mode ? !owned_view.node[24] : owned_view.node[24]) ||
     get_unaligned_le32(owned_view.node + 220) != table_address ||
     get_unaligned_le16(owned_view.node + 264) != 2 ||
     get_unaligned_le16(owned_view.node + 266) != 1 ||
     get_unaligned_le32(owned_view.node + 228) != table_address ||
     get_unaligned_le32(owned_view.node + 232) != table_address + 72 ||
     get_unaligned_le32(owned_view.node + 236) != node + 236 ||
     get_unaligned_le32(owned_view.node + 240) != node + 236)
  return -EBADMSG;
 owned_view.node_valid = true;
 if (bf_mode) {
  if (!bf_ready || !bf_cut || bf_links != (BIT(1) | BIT(2))) return -EPERM;
  owned_view.bf = true;
  error = state_owned_read(QDX_DIAG_BF_GROUP, 0, 232, owned_view.bf_group);
  if (error) return error;
  owned_view.bf_valid |= 1;
  error = state_owned_read(QDX_DIAG_BF_PARENT, 0, 200, owned_view.bf_parent);
  if (error) return error;
  owned_view.bf_valid |= 2;
 }
 for (i = 0; i < PROBE_PACKETS; i++) {
  address = i % 8 ? get_unaligned_le32(owned_view.carrier[i - 1]) :
   get_unaligned_le32(owned_view.table + (i / 8) * 72 + 16);
  length = address < 0x40000000 ? 56 : 64;
  error = state_owned_read(QDX_DIAG_FQ_CARRIER, i, length, owned_view.carrier[i]);
  if (error)
   return error;
  owned_view.carrier_address[i] = address;
  owned_view.carrier_valid |= BIT(i);
  error = state_owned_read(QDX_DIAG_FQ_METADATA, i, 96, owned_view.metadata[i]);
  if (error)
   return error;
  owned_view.metadata_valid |= BIT(i);
  error = state_owned_read(QDX_DIAG_FQ_PAYLOAD, i, PROBE_LENGTH, owned.bytes);
  if (error)
   return error;
  owned_payload[i] = owned.payload;
  owned.payload = NULL;
  id = get_unaligned_le32(owned_payload[i]->data + 46);
  if (id != i || memcmp(owned_payload[i]->data, probes[i].expected, PROBE_LENGTH))
   return -EBADMSG;
 }
 /* Observe the host mapping for several ticks before any clock MIRROR
  * can flush its source. This delay belongs only to the discriminator.
  */
 for (i = 0; i < ARRAY_SIZE(clock_host_poll); i++) {
  error = state_host_clock(clock_host_poll[i], clock_host_poll_ns[i]);
  if (error)
   return error;
  if (i + 1 < ARRAY_SIZE(clock_host_poll))
   usleep_range(2000, 2500);
 }
 for (i = 0; i < ARRAY_SIZE(owned_clock); i++) {
  error = state_host_clock(clock_host_before[i], clock_host_before_ns[i]);
  if (!error)
   error = state_owned_read(QDX_DIAG_FQ_CLOCK, 0, 24, owned_clock[i]);
  if (!error)
   error = state_host_clock(clock_host_after[i], clock_host_after_ns[i]);
  if (error)
   return error;
 }
 occupied_pass = true;
 return 0;
}

static int state_age_restore(void)
{
 struct qdx_owner owner = { .module = THIS_MODULE, .object = rounds };
 int error;

 if (!age_changed || age_restored || probe_started || closed || fault || request ||
     !qdx_diag_fq_table_idle(table))
  return -EPERM;
 if (operation) {
  qdx_packet_op_close(operation);
  if (!qdx_packet_op_drained(operation) ||
      !completion_done(&owned.original_done) || !completion_done(&owned.clone_done))
   return -EINPROGRESS;
  qdx_packet_op_put(operation); operation = NULL;
 }
 operation = qdx_packet_op_prepare(mirror, COPY_TAG, QDX_RECEIVE_PACKET);
 if (IS_ERR(operation)) {
  error = PTR_ERR(operation); operation = NULL; return error;
 }
 qdx_packet_op_close(operation);
 error = qdx_diag_fq_age_import(operation, table, probe_operation,
  &owned_view, 0, saved_age, &owner);
 qdx_packet_op_put(operation); operation = NULL;
 if (error)
  return error;
 error = state_owned_read(QDX_DIAG_FQ_METADATA, 0, 96, age_restored_bytes);
 if (error)
  return error;
 if (memcmp(age_restored_bytes, owned_view.metadata[0], 96))
  return -EBADMSG;
 age_restored = true;
 return 0;
}

static int state_age_check(void)
{
 struct qdx_owner owner = { .module = THIS_MODULE, .object = rounds };
 int error, restore_error;

 if (!occupied_pass || probe_started || closed || fault || request || operation ||
     age_changed || age_restored || !qdx_diag_fq_table_idle(table))
  return -EPERM;
 saved_age = get_unaligned_le64(owned_view.metadata[0] + 72);
 operation = qdx_packet_op_prepare(mirror, COPY_TAG, QDX_RECEIVE_PACKET);
 if (IS_ERR(operation)) {
  error = PTR_ERR(operation); operation = NULL; return error;
 }
 qdx_packet_op_close(operation);
 error = qdx_diag_fq_age_import(operation, table, probe_operation,
  &owned_view, 0, saved_age + 1, &owner);
 qdx_packet_op_put(operation); operation = NULL;
 if (error)
  return error;
 age_changed = true;
 error = state_owned_read(QDX_DIAG_FQ_METADATA, 0, 96, age_changed_bytes);
 if (error)
  return error;
 if (get_unaligned_le64(age_changed_bytes + 72) != saved_age + 1 ||
     memcmp(age_changed_bytes, owned_view.metadata[0], 72) ||
     memcmp(age_changed_bytes + 80, owned_view.metadata[0] + 80, 16))
  error = -EBADMSG;
 /* A completed but negative discriminator still restores the original age.
  * An unresolved source read stays pinned for explicit age-restore retry.
  */
 restore_error = state_age_restore();
 return error ?: restore_error;
}

/* The fixed fresh fixture needs only the real first-above branch here.
 * This is the NSS law's CPU continuation, not a substitute CPU baseline.
 */
static int state_adopt_cpu(void)
{
 unsigned int i;
 u64 age, now, delay;
 u32 node;
 u8 *history, *bin;
 int error;

 if ((bf_mode && !bf_cpu_owned) || !occupied_pass || !age_restored || probe_started || adopt_cpu || request ||
     closed || fault || operation || probe_returns || probe_disposed ||
     !qdx_diag_fq_table_idle(table))
  return -EPERM;
 for (i = 0; i < PROBE_PACKETS; i++) {
  if (!owned_payload[i] || owned_payload[i]->len != PROBE_LENGTH ||
      memcmp(owned_payload[i]->data, probes[i].expected, PROBE_LENGTH))
   return -EBADMSG;
  adopt_age[i] = get_unaligned_le64(owned_view.metadata[i] + 72);
 }
 memcpy(adopt_before, owned_view.table, TABLE_LEN);
 memcpy(adopt_cpu_table, owned_view.table, TABLE_LEN);
 node = get_unaligned_le32(owned_view.table + 4) - 228;
 adopt_node_values[0] = get_unaligned_le32(owned_view.node + 224);
 adopt_node_values[7] = get_unaligned_le32(owned_view.node + 260);
 for (i = 0; i < 2; i++) {
  history = adopt_history[i];
  memcpy(history, owned_view.table + 72 * i + 28, 36);
  if (get_unaligned_le16(history) != 101 || get_unaligned_le16(history + 2) != 37 ||
      get_unaligned_le32(history + 4) || get_unaligned_le64(history + 8) ||
      get_unaligned_le64(history + 16) || history[34] ||
      get_unaligned_le32(owned_view.table + 72 * i + 24) != 8 ||
      get_unaligned_le32(owned_view.table + 72 * i + 12))
   return -EBADMSG;
  if (bf_account_test) {
   error = state_bf_pair_debit(i);
   if (error) return error;
  }
  error = state_owned_read(QDX_DIAG_FQ_CLOCK, 0, 24, owned_clock[i]);
  if (error)
   return error;
  /* Copy of aligned32-bit words, bounded no-rollover finite experiment.
   * Actual cache/tick characterization remains visible in occupied-read.
   */
  now = get_unaligned_le64(owned_clock[i] + 16);
  age = adopt_age[i * 8];
  if (now < age || now - age <= 37 || now - age > U32_MAX || !now ||
      lower_32_bits(now) < 2 * WAIT_MS || lower_32_bits(now) > U32_MAX - 2 * WAIT_MS)
   return -ERANGE;
  delay = now - age;
  adopt_clock[i] = now;
  put_unaligned_le64(now, history + 8);
  if (delay > get_unaligned_le32(history + 24))
   put_unaligned_le32(delay, history + 24);
  bin = adopt_cpu_table + 72 * i;
  if (get_unaligned_le32(bin + 16) != owned_view.carrier_address[i * 8])
   return -EBADMSG;
  put_unaligned_le32(get_unaligned_le32(owned_view.carrier[i * 8]), bin + 16);
  put_unaligned_le32(get_unaligned_le32(bin + 24) - 1, bin + 24);
  put_unaligned_le32(get_unaligned_le32(bin + 64) - PROBE_LENGTH, bin + 64);
  put_unaligned_le32(get_unaligned_le32(bin + 12) - PROBE_LENGTH, bin + 12);
  memcpy(bin + 28, history, 36);
  put_unaligned_le32(i ? node + 236 : table_address + 72, bin);
  put_unaligned_le32(i ? table_address : node + 236, bin + 4);
  bin[68] = 0;
  if (bf_account_test) {
   put_unaligned_le64(bf_pair_update.credit, bf_cpu_account + 292);
   put_unaligned_le64(bf_pair_update.reference, bf_cpu_account + 300);
   put_unaligned_le32(bf_pair_update.deficit, bf_cpu_group + 184);
   bf_cpu_selected++;
  }
 }
 adopt_node_values[1] = node + 228;
 adopt_node_values[2] = node + 228;
 adopt_node_values[3] = table_address;
 adopt_node_values[4] = table_address + 72;
 adopt_node_values[5] = 0;
 adopt_node_values[6] = 2;
 /* All bytes and consequential state are present before publishing CPU
  * ownership. IDs0,8 are now selected prefix; the other14 remain queued.
  */
 adopt_cpu = true;
 return 0;
}

/* Selection/producers/configuration are closed. Only this group's callback
 * can still write its policy state; unrelated global timer ticks are harmless.
 */
static int state_bf_snapshot(void)
{
 u8 clock_before[24], clock_after[24], frequency_window[16], first_timer[32];
 u64 before, after, due;
 u32 group_address, parent_address;
 unsigned int attempt;
 bool queued;
 int error;

 if (!bf_mode || !bf_ready || !bf_cut || !owned_view.bf || !occupied_pass ||
     probe_started || request || bf_request || operation || closed || fault)
  return -EPERM;
 group_address = get_unaligned_le32(owned_view.node + 4);
 bf_timer_joined = false;
 for (attempt = 0; attempt < 16; attempt++) {
  bf_snapshot_attempts++;
  error = state_owned_read(QDX_DIAG_BF_GROUP, 0, 232, owned_view.bf_group);
  if (!error) error = state_owned_read(QDX_DIAG_BF_TIMER, 0, 32, first_timer);
  if (!error) error = state_owned_read(QDX_DIAG_BF_EPOCH, 0, 20, bf_epoch_before);
  if (error) return error;
  if ((get_unaligned_le32(bf_epoch_before) & 1) ||
      (get_unaligned_le32(bf_epoch_before + 16) & 1)) continue;
  queued = !!(get_unaligned_le32(first_timer + 24) & 2);
  due = get_unaligned_le64(first_timer + 16);
  /* For an inactive event, this later manager read joins a callback already
   * removed from the timer list. Re-read all policy data after that boundary.
   * For a pending event, all policy reads must finish before this same due. */
  error = state_owned_read(QDX_DIAG_FQ_CLOCK, 0, 24, clock_before);
  if (!error) error = state_owned_read(QDX_DIAG_BF_FREQUENCY, 0, 16, frequency_window);
  if (!error) memcpy(bf_frequency[0], frequency_window + 4, 8);
  if (!error) error = state_owned_read(QDX_DIAG_BF_GROUP, 0, 232, owned_view.bf_group);
  if (!error) error = state_owned_read(QDX_DIAG_BF_PARENT, 0, 200, owned_view.bf_parent);
  if (!error) error = state_owned_read(QDX_DIAG_BF_ACCOUNT, 0, 312, bf_account);
  if (!error) error = state_owned_read(QDX_DIAG_BF_NOTIFIER, 0, 16, bf_notifier);
  if (!error) error = state_owned_read(QDX_DIAG_BF_FREQUENCY, 0, 16, frequency_window);
  if (!error) memcpy(bf_frequency[1], frequency_window + 4, 8);
  if (!error) error = state_owned_read(QDX_DIAG_BF_TIMER, 0, 32, bf_timer);
  if (!error) error = state_owned_read(QDX_DIAG_BF_EPOCH, 0, 20, bf_epoch_after);
  if (!error) error = state_owned_read(QDX_DIAG_FQ_CLOCK, 0, 24, clock_after);
  if (error) return error;
  before = get_unaligned_le64(clock_before + 16);
  after = get_unaligned_le64(clock_after + 16);
  if (after < before || after - before >= 32768) return -ERANGE;
  if ((get_unaligned_le32(bf_frequency[0]) & 1) ||
      (get_unaligned_le32(bf_frequency[1]) & 1) ||
      get_unaligned_le32(bf_frequency[0] + 4) != get_unaligned_le32(bf_frequency[1] + 4) ||
      get_unaligned_le32(bf_notifier + 12) != get_unaligned_le32(bf_frequency[1] + 4) ||
      (get_unaligned_le32(owned_view.bf_group) & 1) ||
      (get_unaligned_le32(owned_view.bf_parent) & 1)) continue;
  if (queued) {
   if (!owned_view.bf_group[229] || !(get_unaligned_le32(bf_timer + 24) & 2) ||
       get_unaligned_le32(first_timer + 8) != 0x40086600 ||
       get_unaligned_le32(first_timer + 12) != group_address ||
       memcmp(first_timer + 8, bf_timer + 8, 16) ||
       get_unaligned_le16(first_timer + 28) != get_unaligned_le16(bf_timer + 28) ||
       after >= due) continue;
  } else if (owned_view.bf_group[229] || (get_unaligned_le32(bf_timer + 24) & 2)) {
   continue; /* A previously running negative callback rearmed: retry. */
  }
  parent_address = get_unaligned_le32(owned_view.bf_group + 4);
  /* +164 is a cached clock frequency, initialized to zero, not identity.
   * The owned group must belong to the same shaper generation as its leaf. */
  if (get_unaligned_le32(bf_notifier + 4) != 0x40086900 ||
      get_unaligned_le32(bf_notifier + 8) != group_address ||
      get_unaligned_le32(owned_view.bf_group + 20) !=
       get_unaligned_le32(owned_view.node + 20) ||
      get_unaligned_le32(owned_view.bf_group + 196) != 128)
   return -EBADMSG;
  if (bf_reverse_done) {
   if (owned_view.bf_group[228] ||
       get_unaligned_le32(owned_view.bf_parent + 196) ||
       get_unaligned_le32(owned_view.bf_parent + 172) != parent_address + 172 ||
       get_unaligned_le32(owned_view.bf_parent + 176) != parent_address + 172 ||
       get_unaligned_le32(owned_view.bf_parent + 180) != parent_address + 180 ||
       get_unaligned_le32(owned_view.bf_parent + 184) != parent_address + 180)
    return -EBADMSG;
  } else if (get_unaligned_le32(owned_view.bf_parent + 180) != group_address + 188 ||
      get_unaligned_le32(owned_view.bf_parent + 184) != group_address + 188 ||
      get_unaligned_le32(owned_view.bf_group + 188) != parent_address + 180 ||
      get_unaligned_le32(owned_view.bf_group + 192) != parent_address + 180 ||
      !owned_view.bf_group[228]) return -EBADMSG;
  bf_timer_joined = !queued;
  bf_snapshot_begin = before;
  bf_retire_clock = after;
  return 0;
 }
 return -EAGAIN;
}

/* One retained native event, two real accounts. This is not a full physical
 * handover claim: the retained CPU copies remain owned through diagnostic end.
 */
static int state_bf_pair_read(void)
{
 unsigned int alignment, header;
 int error;

 owned_view.bf_pair = &bf_pair;
 error = state_owned_read(QDX_DIAG_BF_AUX_GROUP, 0, 232, bf_pair.group);
 if (error) return error;
 bf_pair.valid |= 1;
 error = state_owned_read(QDX_DIAG_BF_AUX_ACCOUNT, 0, 312, bf_pair.account);
 if (error) return error;
 bf_pair.valid |= 2;
 error = state_owned_read(QDX_DIAG_BF_ALLOCATOR, 0, 24, owned_view.bf_allocator);
 if (error) return error;
 owned_view.bf_valid |= 4;
 alignment = get_unaligned_le32(owned_view.bf_allocator + 12);
 if (alignment < 4 || alignment > 64 || !is_power_of_2(alignment)) return -EBADMSG;
 header = ALIGN(28, alignment);
 error = state_owned_read(QDX_DIAG_BF_AUX_HEADER, 0, header, bf_pair.header);
 if (error) return error;
 bf_pair.valid |= 4;
 error = state_owned_read(QDX_DIAG_BF_AUX_TIMER, 0, 32, bf_pair.timer);
 if (error) return error;
 bf_pair.valid |= 8;
 error = state_owned_read(QDX_DIAG_BF_AUX_NOTIFIER, 0, 16, bf_pair.notifier);
 if (error) return error;
 bf_pair.valid |= 16;
 return 0;
}

static int state_bf_pair_write(enum qdx_diag_bf_pair_action action)
{
 struct qdx_owner owner = { .module = THIS_MODULE, .object = rounds };
 struct qdx_diag_bf_state observed = {};
 int error;

 if (operation || closed || fault || request || bf_request) return -EPERM;
 memcpy(observed.current_account, bf_account, sizeof(bf_account));
 memcpy(observed.timer, bf_timer, sizeof(bf_timer));
 memcpy(observed.notifier, bf_notifier, sizeof(bf_notifier));
 memcpy(observed.epoch[0], bf_epoch_before, 20);
 memcpy(observed.epoch[1], bf_epoch_after, 20);
 memcpy(observed.frequency, bf_frequency, sizeof(bf_frequency));
 observed.clock_ms[0] = bf_snapshot_begin;
 observed.clock_ms[1] = bf_retire_clock;
 observed.timer_joined = bf_timer_joined;
 bf_pair_update.action = action;
 operation = qdx_packet_op_prepare(mirror, COPY_TAG, QDX_RECEIVE_PACKET);
 if (IS_ERR(operation)) {
  error = PTR_ERR(operation); operation = NULL; return error;
 }
 qdx_packet_op_close(operation);
 error = qdx_diag_bf_pair_write(operation, table, probe_operation,
  &owned_view, &observed, &bf_pair_update, &owner);
 qdx_packet_op_put(operation); operation = NULL;
 if (!error && action == QDX_DIAG_BF_PAIR_PUBLISH) bf_pair_published = true;
 if (!error && action == QDX_DIAG_BF_PAIR_RESTORE) bf_pair_pointer_written = true;
 return error;
}

/* Called immediately before each genuine FQ child selection. Native CONFIG
 * touches only the idle auxiliary account and supplies a real raw-clock sample;
 * its fresh cap is not substituted for the adopted CPU account.
 */
static int state_bf_pair_debit(unsigned int selection)
{
 u64 reference, previous, elapsed, increase, cost;
 s64 credit, cap;
 s32 deficit;
 u32 shift, index;
 int error;

 if (!bf_account_test || bf_account_control || selection > 1 || bf_pair_published)
  return -EPERM;
 error = state_bf_command(7, BF_AUX_TAG, 0);
 if (!error) error = state_bf_pair_read();
 if (error) return error;
 if (memcmp(bf_cpu_account, bf_pair.account, 292)) return -ESTALE;
 reference = get_unaligned_le64(bf_pair.account + 300);
 previous = get_unaligned_le64(bf_cpu_account + 300);
 shift = get_unaligned_le32(bf_cpu_account + 272);
 index = get_unaligned_le32(bf_cpu_account + 268);
 if (shift >= 63 || index >= 32 || reference < previous) return -ERANGE;
 index = PROBE_LENGTH >> index;
 if (index >= 32) return -ERANGE;
 cost = get_unaligned_le64(bf_cpu_account + 12 + 8 * index);
 cap = (s64)get_unaligned_le64(bf_cpu_account + 284);
 elapsed = reference - previous;
 if (elapsed > ((u64)S64_MAX >> shift) || !cost || cost > S64_MAX || cap <= 0)
  return -ERANGE;
 increase = elapsed << shift;
 if (check_add_overflow((s64)get_unaligned_le64(bf_cpu_account + 292),
      (s64)increase, &credit)) return -ERANGE;
 credit = min(credit, cap);
 if (credit <= 0) return -ERANGE; /* Real parent must have saved positive sign. */
 bf_pair_before_credit[selection] = credit;
 if (check_sub_overflow(credit, (s64)cost, &credit)) return -ERANGE;
 deficit = (s32)get_unaligned_le32(bf_cpu_group + 184);
 if (deficit < 0) deficit += 128;
 deficit -= PROBE_LENGTH;
 bf_pair_after_credit[selection] = credit;
 bf_pair_reference[selection] = reference;
 bf_pair_cost = cost;
 bf_pair_update.credit = credit;
 bf_pair_update.reference = reference;
 bf_pair_update.deficit = deficit;
 return 0;
}

/* Four queued triggers first arm before the third preferred debit. With
 * positive initial cap and two 64-byte costs, the initial debt cannot exceed
 * 2*cost-cap; refill can only reduce it. Firmware arithmetically shifts that
 * negative credit, divides its magnitude*1024 by cached Hz and floors at100.
 * This bounds only this fixed fixture, not arbitrary BF topology/debt.
 */
static int state_bf_pair_wait_budget(u64 due, u64 now, unsigned long *deadline)
{
 u64 cost, cap, twice_cost, debt, scaled, delay, remaining;
 u32 shift = get_unaligned_le32(bf_account + 272);
 u32 bucket = get_unaligned_le32(bf_account + 268);

 if (bf_trigger_queued_before_open != 4 || bf_trigger_returns != 4 ||
     bf_trigger_disposed || shift >= 63 || bucket >= 32 ||
     get_unaligned_le32(owned_view.bf_group + 164) != BF_NATIVE_HZ ||
     get_unaligned_le32(bf_account + 276) != BF_NATIVE_HZ) return -ERANGE;
 bucket = PROBE_LENGTH >> bucket;
 if (bucket >= 32) return -ERANGE;
 cost = get_unaligned_le64(bf_account + 12 + 8 * bucket);
 cap = get_unaligned_le64(bf_account + 284);
 if (!cost || !cap || cap > S64_MAX || cost > S64_MAX ||
     check_mul_overflow(cost, 2ULL, &twice_cost) || twice_cost <= cap)
  return -ERANGE;
 debt = twice_cost - cap;
 /* Magnitude after arithmetic right shift of negative credit rounds up. */
 scaled = (debt >> shift) + !!(debt & ((1ULL << shift) - 1));
 if (check_mul_overflow(scaled, 1024ULL, &scaled)) return -ERANGE;
 delay = max_t(u64, 100, div_u64(scaled, BF_NATIVE_HZ));
 /* Thirty-two charged bytes at 1B/s bound the original fixture event.
  * Reject a changed table/law instead of granting an arbitrary longer wait. */
 remaining = due > now ? due - now : 0;
 bf_pair_wait_limit_ms = delay;
 bf_pair_wait_remaining_ms = remaining;
 if (delay > 32 * 1024 || remaining > delay) return -ERANGE;
 bf_pair_wait_budget_ms = remaining + WAIT_MS;
 *deadline = jiffies + msecs_to_jiffies(bf_pair_wait_budget_ms);
 return 0;
}

static int state_bf_pair_run(void)
{
 struct qdx_owner owner = { .module = THIS_MODULE, .object = rounds };
 u64 due, now, reference, elapsed, increment, unchanged_reference;
 s64 expected, unchanged;
 u32 group, parent, alignment, header, shift;
 unsigned long deadline;
 int error;

 if (!bf_account_test || !bf_mode || !bf_aux_attached || bf_pair_started ||
     !occupied_pass || !age_restored || bf_cpu_owned || adopt_cpu ||
     request || bf_request || operation || closed || fault) return -EPERM;
 bf_pair_started = true;
 /* The original negative timer already exists; wait at most one real retry
  * for a witnessed useful remaining interval. This is fixture preparation.
  */
 deadline = jiffies + msecs_to_jiffies(WAIT_MS);
 do {
  error = state_bf_snapshot();
  if (error && error != -EAGAIN) return error;
  due = get_unaligned_le64(bf_timer + 16); now = bf_retire_clock;
  if (!error && owned_view.bf_group[229] &&
      (get_unaligned_le32(bf_timer + 24) & 2) && due > now && due - now >= 60)
   break;
  usleep_range(1000, 1500);
 } while (time_before(jiffies, deadline));
 if (error || due <= now || due - now < 60) return error ?: -ETIMEDOUT;
 bf_pair_original_due = due;
 error = state_bf_pair_wait_budget(due, now, &deadline);
 if (error) return error; /* Sixteen backings/copies remain owned; no CPU adoption. */
 /* This real configuration change belongs to initial fixture history,
  * before CPU authority; it leaves the already pending timer in place.
  */
 error = state_bf_command(7, BF_GROUP_TAG, 0);
 if (!error) error = state_bf_command(6, BF_GROUP_TAG, TABLE_TAG);
 if (!error) error = state_bf_command(5, BF_GROUP_TAG, TABLE_TAG);
 if (!error) error = state_bf_pair_read();
 if (!error) error = state_bf_snapshot();
 if (error) return error;
 group = get_unaligned_le32(owned_view.node + 4);
 parent = get_unaligned_le32(owned_view.bf_group + 4);
 if ((!bf_account_control && (group & 31) != 20) ||
     get_unaligned_le32(owned_view.bf_group + 224) != 1 ||
     !owned_view.bf_group[229] || !(get_unaligned_le32(bf_timer + 24) & 2) ||
     get_unaligned_le64(bf_timer + 16) != due || bf_retire_clock >= due ||
     (s64)get_unaligned_le64(bf_account + 292) <= 0 ||
     get_unaligned_le32(owned_view.bf_parent + 172) != group + 172 ||
     get_unaligned_le32(owned_view.bf_group + 172) != parent + 172)
  return -ESTALE;
 alignment = get_unaligned_le32(owned_view.bf_allocator + 12);
 if (alignment < 4 || alignment > 64 || !is_power_of_2(alignment)) return -EBADMSG;
 header = ALIGN(28, alignment);
 error = state_owned_read(QDX_DIAG_BF_ACCOUNT_HEADER, 0, header, owned_view.bf_header);
 if (error) return error;
 owned_view.bf_valid |= 8;
 operation = qdx_packet_op_prepare(mirror, COPY_TAG, QDX_RECEIVE_PACKET);
 if (IS_ERR(operation)) { error = PTR_ERR(operation); operation = NULL; return error; }
 qdx_packet_op_close(operation);
 error = qdx_diag_bf_pin(operation, table, probe_operation, &owned_view, &owner);
 qdx_packet_op_put(operation); operation = NULL;
 if (error) return error;
 bf_pair_update.original_account = get_unaligned_le32(owned_view.bf_group + 168);
 bf_lifetime_pinned = true;
 memcpy(bf_saved_group, owned_view.bf_group, 232);
 memcpy(bf_saved_parent, owned_view.bf_parent, 200);
 memcpy(bf_saved_account, bf_account, 312);
 memcpy(bf_saved_timer, bf_timer, 32);
 memcpy(bf_cpu_account, bf_account, 312);
 memcpy(bf_cpu_group, owned_view.bf_group, 232);
 /* All sixteen real bytes/ages remain held; only now publish CPU authority. */
 bf_cpu_owned = true;
 if (bf_account_control) {
  adopt_cpu = true; /* no child selected; all sixteen remain CPU queued */
  memcpy(adopt_cpu_table, owned_view.table, TABLE_LEN);
 } else {
  bf_pair_child_started = true;
  error = state_adopt_cpu();
  if (error) return error;
  if (bf_cpu_selected != 2) return -EBADMSG;
  if (bf_pair_after_credit[0] <= 0 || bf_pair_after_credit[1] >= 0) return -ERANGE;
  error = state_bf_pair_read();
  if (!error) error = state_bf_snapshot();
  if (error) return error;
  if (!owned_view.bf_group[229] || get_unaligned_le64(bf_timer + 16) != due ||
      bf_retire_clock >= due) return -ESTALE;
  error = state_bf_pair_write(QDX_DIAG_BF_PAIR_PREPARE);
  if (!error) error = state_bf_pair_read(); /* actual NSS visibility and release */
  if (!error) error = state_bf_snapshot();
  if (error) return error;
  if (!owned_view.bf_group[229] || get_unaligned_le64(bf_timer + 16) != due ||
      bf_retire_clock >= due) return -ESTALE;
  bf_pair_publication_epoch = get_unaligned_le16(bf_epoch_after + 12);
  error = state_bf_pair_write(QDX_DIAG_BF_PAIR_PUBLISH);
  if (!error) error = state_bf_snapshot();
  if (error) return error;
  if (get_unaligned_le32(owned_view.bf_group + 168) != get_unaligned_le32(bf_pair.group + 168) ||
      get_unaligned_le64(bf_timer + 16) != due || !owned_view.bf_group[229] ||
      !(get_unaligned_le32(bf_timer + 24) & 2)) return -ESTALE;
  bf_pair_visible = true;
 }
 error = state_bf_pair_wait_budget(due, bf_retire_clock, &deadline);
 if (error) return error;
 /* No packet is awaiting this diagnostic polling loop. Let the original
  * firmware event run; retain WAIT_MS for bounded observation/copy overhead. */
 if (bf_pair_wait_remaining_ms > WAIT_MS)
  msleep(bf_pair_wait_remaining_ms - WAIT_MS);
 do {
  error = state_bf_snapshot();
  if (error && error != -EAGAIN) return error;
  if (!error && bf_retire_clock >= due &&
      ((!owned_view.bf_group[229] && !(get_unaligned_le32(bf_timer + 24) & 2)) ||
       (owned_view.bf_group[229] && (get_unaligned_le32(bf_timer + 24) & 2) &&
        get_unaligned_le64(bf_timer + 16) > due))) break;
  usleep_range(500, 1000);
 } while (time_before(jiffies, deadline));
 if (error || bf_retire_clock < due) return error ?: -ETIMEDOUT;
 memcpy(bf_pair_consequence_account, bf_account, 312);
 memcpy(bf_pair_consequence_timer, bf_timer, 32);
 memcpy(bf_pair_consequence_group, owned_view.bf_group, 232);
 bf_pair_observed_ms = bf_retire_clock;
 if (get_unaligned_le32(owned_view.bf_group + 224) != 1 ||
     get_unaligned_le32(owned_view.bf_parent + 172) != group + 172 ||
     get_unaligned_le32(owned_view.bf_parent + 196) != 1 || probe_returns || probe_disposed)
  return -EBADMSG;
 if (bf_account_control) {
  if (owned_view.bf_group[229] || (get_unaligned_le32(bf_timer + 24) & 2) ||
      (s64)get_unaligned_le64(bf_account + 292) <= 0) return -EBADMSG;
  bf_pair_callback_branch = 1;
  bf_pair_callback_valid = true;
 } else {
  reference = get_unaligned_le64(bf_account + 300);
  shift = get_unaligned_le32(bf_cpu_account + 272);
  if (reference < bf_pair_update.reference || shift >= 63) return -ERANGE;
  elapsed = reference - bf_pair_update.reference;
  if (elapsed > ((u64)S64_MAX >> shift)) return -ERANGE;
  increment = elapsed << shift;
  if (check_add_overflow(bf_pair_update.credit, (s64)increment, &expected))
   return -ERANGE;
  expected = min_t(s64, expected, (s64)get_unaligned_le64(bf_cpu_account + 284));
  if (reference == bf_pair_update.reference ||
      (s64)get_unaligned_le64(bf_account + 292) != expected ||
      (s32)get_unaligned_le32(owned_view.bf_group + 184) != bf_pair_update.deficit)
   return -EBADMSG;
  /* Timing, not our desired verdict, determines the callback branch. Both
   * must consume the published CPU account with the exact native recurrence. */
  if (expected > 0) {
   if (owned_view.bf_group[229] || (get_unaligned_le32(bf_timer + 24) & 2) ||
       !bf_timer_joined) return -EBADMSG;
   bf_pair_callback_branch = 1;
  } else {
   if (!owned_view.bf_group[229] || !(get_unaligned_le32(bf_timer + 24) & 2) ||
       get_unaligned_le64(bf_timer + 16) <= due) return -EBADMSG;
   bf_pair_callback_branch = 2;
  }
  bf_pair_callback_valid = true;
  bf_pair_expected_credit = expected;
  /* The untouched original account is the counterfactual at this exact
   * callback reference. A common saturated cap would not discriminate which
   * account the callback consumed, even when both are otherwise valid. */
  unchanged_reference = get_unaligned_le64(bf_saved_account + 300);
  if (reference < unchanged_reference) return -ERANGE;
  elapsed = reference - unchanged_reference;
  if (elapsed > ((u64)S64_MAX >> shift)) return -ERANGE;
  if (check_add_overflow((s64)get_unaligned_le64(bf_saved_account + 292),
       (s64)(elapsed << shift), &unchanged)) return -ERANGE;
  unchanged = min_t(s64, unchanged, (s64)get_unaligned_le64(bf_saved_account + 284));
  bf_pair_unchanged_credit = unchanged;
  if (expected == unchanged) return -ENODATA;
  bf_pair_callback_discriminating = true;
 }
 bf_pair_consequence_pass = true;
 return 0;
}

/* Explicit finite recovery, callable after a semantic rejection. It does not
 * claim the failed experiment passed. CPU copies precede backing retirement.
 */
static int state_bf_pair_close(void)
{
 unsigned long deadline;
 unsigned int i;
 bool drained;
 int error;

 if (!bf_account_test || !bf_ready || !occupied_pass || !bf_cut ||
     request || bf_request || operation || closed || fault) return -EPERM;
 for (i = 0; i < PROBE_PACKETS; i++)
  if (!owned_payload[i] || owned_payload[i]->len != PROBE_LENGTH ||
      memcmp(owned_payload[i]->data, probes[i].expected, PROBE_LENGTH)) return -EBADMSG;
 bf_cpu_owned = true;
 if (!adopt_cpu) {
  if (!bf_pair_child_started) memcpy(adopt_cpu_table, owned_view.table, TABLE_LEN);
  adopt_cpu = true;
 }
 if (!bf_pair_backing_started) {
  /* Native CONFIG changes only an obsolete unreachable executor. */
  if (!bf_pair_retire_configured) {
   bf_pair_retirement_started = true;
   error = state_bf_command(7, BF_GROUP_TAG, 0);
   if (error) return error;
   bf_pair_retire_configured = true;
  }
  /* CONFIG does not cancel or reschedule the original pending timer. */
  deadline = jiffies + msecs_to_jiffies(WAIT_MS);
  do {
   error = state_bf_snapshot();
   if (error != -EAGAIN) break;
   usleep_range(500, 1000);
  } while (time_before(jiffies, deadline));
  if (error) return error;
  error = state_bf_pair_wait_budget(
   (get_unaligned_le32(bf_timer + 24) & 2) ? get_unaligned_le64(bf_timer + 16) :
    bf_retire_clock, bf_retire_clock, &deadline);
  if (error) return error;
  if (bf_pair_wait_remaining_ms > WAIT_MS)
   msleep(bf_pair_wait_remaining_ms - WAIT_MS);
  do {
   error = state_bf_snapshot();
   if (error && error != -EAGAIN) return error;
   if (!error && !owned_view.bf_group[229] && !(get_unaligned_le32(bf_timer + 24) & 2)) break;
   usleep_range(500, 1000);
  } while (time_before(jiffies, deadline));
  if (error || owned_view.bf_group[229] || (get_unaligned_le32(bf_timer + 24) & 2))
   return error ?: -ETIMEDOUT;
  bf_pair_joined = true;
  if (bf_pair_published && !bf_pair_pointer_restored) {
   error = state_bf_pair_read();
   if (!error) error = state_bf_snapshot();
   if (!error && !bf_pair_pointer_written) error = state_bf_pair_write(QDX_DIAG_BF_PAIR_RESTORE);
   if (!error) error = state_bf_snapshot();
   if (error) return error;
   if (get_unaligned_le32(owned_view.bf_group + 168) != bf_pair_update.original_account)
    return -EBADMSG;
   bf_pair_pointer_restored = true;
  }
  bf_pair_backing_started = true;
  adopt_retiring = true;
 }
 if (!bf_retired) {
  if (bf_links & BIT(2)) {
   error = state_bf_command(6, BF_GROUP_TAG, TABLE_TAG);
   if (error) return error;
  }
  if (allocated) {
   error = state_command(FREE, true, WAIT_MS);
   if (error) return error;
  }
  if (!completion_done(&adopt_done) &&
      !wait_for_completion_timeout(&adopt_done, msecs_to_jiffies(WAIT_MS))) return -ETIMEDOUT;
  error = read_poll_timeout(qdx_packet_op_drained, drained, drained, 10,
   WAIT_MS * 1000, false, probe_operation);
  if (error) return error;
  if (adopt_retired != 16 || adopt_retirement_bad) return -EBADMSG;
  qdx_packet_op_put(probe_operation); probe_operation = NULL;
  adopt_retiring = false; bf_retired = true;
 }
 if (bf_aux_attached) {
  error = state_bf_command(6, BF_PARENT_TAG, BF_AUX_TAG);
  if (error) return error;
 }
 if (bf_allocated & BIT(4)) {
  error = state_bf_command(1, BF_AUX_TAG, 0);
  if (error) return error;
 }
 bf_pair_closed = true;
 return 0;
}

static int state_bf_adopt(void)
{
 u64 old_reference, new_reference, increment, elapsed;
 u32 shift, parent_address;
 s64 credit;
 s32 deficit;
 unsigned int i;
 unsigned long deadline;
 bool joined = false;
 int error;

 if (!bf_mode || !bf_ready || !bf_cut || !occupied_pass || !age_restored ||
     bf_cpu_owned || adopt_cpu || probe_returns || probe_disposed ||
     request || bf_request || operation || closed || fault)
  return -EPERM;
 error = state_bf_snapshot();
 if (error) return error;
 parent_address = get_unaligned_le32(owned_view.bf_group + 4);
 credit = (s64)get_unaligned_le64(bf_account + 292);
 if (credit >= 0 || !owned_view.bf_group[229] ||
     !(get_unaligned_le32(bf_timer + 24) & 2) ||
     get_unaligned_le32(owned_view.bf_group + 224) ||
     get_unaligned_le32(owned_view.bf_parent + 172) != parent_address + 172 ||
     get_unaligned_le32(owned_view.bf_parent + 176) != parent_address + 172)
  return -EBADMSG;
 for (i = 0; i < PROBE_PACKETS; i++)
  if (!owned_payload[i] || owned_payload[i]->len != PROBE_LENGTH ||
      memcmp(owned_payload[i]->data, probes[i].expected, PROBE_LENGTH)) return -EBADMSG;
 memcpy(bf_saved_group, owned_view.bf_group, 232);
 memcpy(bf_saved_parent, owned_view.bf_parent, 200);
 memcpy(bf_saved_account, bf_account, 312);
 memcpy(bf_saved_timer, bf_timer, 32);
 memcpy(bf_cpu_account, bf_account, 312);
 memcpy(bf_cpu_group, owned_view.bf_group, 232);
 bf_cut_clock = bf_retire_clock;
 bf_credit_before = credit;
 bf_deficit_before = (s32)get_unaligned_le32(bf_cpu_group + 200);
 bf_cpu_pending_ms = get_unaligned_le64(bf_timer + 16);
 /* All originals have real CPU packet/age/state copies. Only now may the
  * unreachable obsolete account be configured for finite callback retirement.
  */
 bf_cpu_owned = true;
 error = state_bf_command(7, BF_GROUP_TAG, 0);
 if (error) return error;
 deadline = jiffies + msecs_to_jiffies(WAIT_MS);
 do {
  bf_retirement_attempts++;
  error = state_bf_snapshot();
  if (error && error != -EAGAIN) return error;
  joined = !error && !(get_unaligned_le32(bf_timer + 24) & 2) &&
   !owned_view.bf_group[229];
  if (joined) break;
  usleep_range(500, 1000);
 } while (time_before(jiffies, deadline));
 if (!joined) return -ETIMEDOUT;
 if ((s64)get_unaligned_le64(bf_account + 292) <= 0) return -EBADMSG;
 memcpy(bf_retired_account, bf_account, 312);
 /* CONFIG and the last joined callback both use the real raw-clock reader.
  * Their reference is in exactly the saved account's units. Never substitute
  * the cleanup credit, callback wall time or the coarse CoDel clock.
  */
 if (memcmp(bf_account, bf_saved_account, 292)) return -ESTALE;
 old_reference = get_unaligned_le64(bf_saved_account + 300);
 new_reference = get_unaligned_le64(bf_retired_account + 300);
 shift = get_unaligned_le32(bf_saved_account + 272);
 if (shift >= 64 || new_reference < old_reference) return -ERANGE;
 elapsed = new_reference - old_reference;
 if (elapsed > ((u64)S64_MAX >> shift)) return -ERANGE;
 increment = elapsed << shift;
 if (check_add_overflow(bf_credit_before, (s64)increment, &credit) || credit >= 0)
  return -ERANGE; /* This finite case intentionally keeps original debt negative. */
 bf_credit_delta = increment;
 put_unaligned_le64(credit, bf_cpu_account + 292);
 put_unaligned_le64(new_reference, bf_cpu_account + 300);
 /* Any old due callback executed by CPU at this observation still sees debt.
  * It preserves excess membership and schedules the same capped100ms retry.
  */
 if (bf_cpu_pending_ms <= bf_retire_clock) bf_cpu_pending_ms = bf_retire_clock + 100;
 deficit = bf_deficit_before;
 for (i = 0; i < 2; i++) {
  if (deficit < -128 || deficit > 128) return -ERANGE;
  if (deficit < 0) deficit += 128;
  deficit -= PROBE_LENGTH;
 }
 put_unaligned_le32(deficit, bf_cpu_group + 200);
 bf_deficit_after = deficit; bf_credit_after = credit;
 /* FQ runs its already-qualified real first-above CPU branch on real copies.
  * The original negative BF entitlement selects its excess list; no extra
  * entitlement debit is made while preferred membership is false.
  */
 error = state_adopt_cpu();
 if (error) return error;
 bf_cpu_selected = 2;
 adopt_retiring = true;
 error = state_bf_command(6, BF_GROUP_TAG, TABLE_TAG);
 if (!error) error = state_command(FREE, true, WAIT_MS);
 if (error) return error;
 if (!wait_for_completion_timeout(&adopt_done, msecs_to_jiffies(WAIT_MS))) return -ETIMEDOUT;
 {
  bool drained;
  error = read_poll_timeout(qdx_packet_op_drained, drained, drained, 10,
   WAIT_MS * 1000, false, probe_operation);
 }
 if (error) return error;
 synchronize_net();
 if (adopt_retired != 16 || adopt_retirement_bad) return -EBADMSG;
 qdx_packet_op_put(probe_operation); probe_operation = NULL;
 adopt_retiring = false; bf_retired = true;
 for (i = 0; i < PROBE_PACKETS; i++)
  if (!owned_payload[i] || memcmp(owned_payload[i]->data, probes[i].expected, PROBE_LENGTH))
   return -EBADMSG;
 bf_pass = true;
 return 0;
}

static int state_adopt_rebuild(void)
{
 struct qdx_packet_recipient recipient = {
  .owner = { .module = THIS_MODULE }, .returned = state_probe_returned,
 };
 struct qdx_owner owner = { .module = THIS_MODULE, .object = rounds };
 struct qdx_ready ready;
 struct sk_buff *skb;
 u8 *bin;
 u32 node, address, id, seen = 0;
 unsigned int i, length;
 unsigned long deadline;
 bool drained;
 int error;

 if ((bf_mode && (!bf_pass || !bf_retired || allocated || probe_operation)) ||
     !adopt_cpu || adopt_rebuild_started || adopt_retiring || probe_started ||
     closed || fault || request || operation || !qdx_diag_fq_table_idle(table))
  return -EPERM;
 if (!bf_mode) {
  adopt_retiring = true;
  error = state_command(FREE, true, WAIT_MS);
  if (error) return error;
  if (!wait_for_completion_timeout(&adopt_done, msecs_to_jiffies(WAIT_MS)))
   return -ETIMEDOUT;
  error = read_poll_timeout(qdx_packet_op_drained, drained, drained, 10,
   WAIT_MS * 1000, false, probe_operation);
  if (error) return error;
  synchronize_net();
  qdx_packet_op_put(probe_operation); probe_operation = NULL;
  adopt_retiring = false;
 }
 if (adopt_retired != PROBE_PACKETS || adopt_retirement_bad)
  return -EBADMSG;
 adopt_rebuild_started = true;
 reinit_completion(&adopt_done);
 error = state_command(ALLOC, true, WAIT_MS);
 if (!error) error = state_command(CONFIG, true, WAIT_MS);
 if (error)
  return error;
 probe_operation = qdx_packet_op_prepare(igs, TABLE_TAG, QDX_RECEIVE_RETURNED);
 if (IS_ERR(probe_operation)) {
  error = PTR_ERR(probe_operation); probe_operation = NULL; return error;
 }
 for (i = 0; i < PROBE_PACKETS; i++) {
  if (i == 0 || i == 8) continue;
  skb = owned_payload[i];
  if (!skb || skb->len != PROBE_LENGTH) { error = -EBADMSG; goto close; }
  probes[i].skb = skb;
  recipient.owner.object = &probes[i];
  ready = qdx_packet_op_submit(probe_operation, skb, &recipient);
  if (ready.status != QDX_ACCEPTED) {
   probes[i].skb = NULL;
   error = ready.error ?: -EAGAIN; goto close;
  }
  owned_payload[i] = NULL;
  adopt_accepted++;
 }
 error = 0;
close:
 qdx_packet_op_close(probe_operation);
 if (error)
  return error;
 deadline = jiffies + msecs_to_jiffies(WAIT_MS);
 do {
  error = state_command(STATS, true, WAIT_MS);
  if (error) return error;
  if (probe_qlen == 14) break;
  if (adopt_returns || adopt_disposed || probe_drops) return -EBADMSG;
  usleep_range(1000, 1500);
 } while (time_before(jiffies, deadline));
 if (probe_qlen != 14 || adopt_returns || adopt_disposed || probe_drops)
  return -EBADMSG;
 memset(&owned_view, 0, sizeof(owned_view));
 error = state_owned_read(OWNED_TABLE, 0, TABLE_LEN, owned_view.table);
 if (error) return error;
 node = get_unaligned_le32(owned_view.table + 4) - 228;
 for (i = 0; i < 2; i++) {
  bin = owned_view.table + 72 * i;
  if (get_unaligned_le32(bin + 24) != 7 || get_unaligned_le32(bin + 64) != 448 ||
      get_unaligned_le32(bin + 12) || bin[68] != 1)
   return -EBADMSG;
 }
 error = state_owned_read(QDX_DIAG_FQ_NODE, 0, 280, owned_view.node);
 if (error) return error;
 owned_view.node_valid = true;
 for (i = 0; i < 14; i++) {
  address = i % 7 ? get_unaligned_le32(owned_view.carrier[i - 1]) :
   get_unaligned_le32(owned_view.table + (i / 7) * 72 + 16);
  length = address < 0x40000000 ? 56 : 64;
  error = state_owned_read(QDX_DIAG_FQ_CARRIER, i, length, owned_view.carrier[i]);
  if (error) return error;
  owned_view.carrier_address[i] = address;
  owned_view.carrier_valid |= BIT(i);
  error = state_owned_read(QDX_DIAG_FQ_METADATA, i, 96, owned_view.metadata[i]);
  if (error) return error;
  owned_view.metadata_valid |= BIT(i);
  error = state_owned_read(QDX_DIAG_FQ_PAYLOAD, i, PROBE_LENGTH, NULL);
  if (error) return error;
  id = get_unaligned_le32(owned.payload->data + 46);
  if (id != i + 1 + (i >= 7) || id >= PROBE_PACKETS || (seen & BIT(id)) ||
      memcmp(owned.payload->data, probes[id].expected, PROBE_LENGTH))
   return -EBADMSG;
  seen |= BIT(id);
  dev_kfree_skb(owned.payload); owned.payload = NULL;
 }
 /* The copy just completed source release for every metadata line. */
 operation = qdx_packet_op_prepare(mirror, COPY_TAG, QDX_RECEIVE_PACKET);
 if (IS_ERR(operation)) { error = PTR_ERR(operation); operation = NULL; return error; }
 qdx_packet_op_close(operation);
 for (i = 0; i < 14; i++) {
  id = i + 1 + (i >= 7);
  error = qdx_diag_fq_age_import(operation, table, probe_operation,
   &owned_view, i, adopt_age[id], &owner);
  if (error) break;
 }
 qdx_packet_op_put(operation); operation = NULL;
 if (error) return error;
 for (i = 0; i < 14; i++) {
  id = i + 1 + (i >= 7);
  error = state_owned_read(QDX_DIAG_FQ_METADATA, i, 96, age_restored_bytes);
  if (error) return error;
  if (get_unaligned_le64(age_restored_bytes + 72) != adopt_age[id] ||
      memcmp(age_restored_bytes, owned_view.metadata[i], 72) ||
      memcmp(age_restored_bytes + 80, owned_view.metadata[i] + 80, 16))
   return -EBADMSG;
  memcpy(owned_view.metadata[i], age_restored_bytes, 96);
 }
 /* Rebase only list identity; preserve new real carrier head/tail/counts. */
 for (i = 0; i < 2; i++) {
  bin = owned_view.table + i * 72;
  put_unaligned_le32(i ? node + 236 : table_address + 72, bin);
  put_unaligned_le32(i ? table_address : node + 236, bin + 4);
  if (get_unaligned_le32(bin + 24) != get_unaligned_le32(adopt_cpu_table + i * 72 + 24) ||
      get_unaligned_le32(bin + 64) != get_unaligned_le32(adopt_cpu_table + i * 72 + 64))
   return -EBADMSG;
  memcpy(bin + 8, adopt_cpu_table + i * 72 + 8, 8);
  memcpy(bin + 28, adopt_cpu_table + i * 72 + 28, 36);
  bin[68] = 0;
 }
 memcpy(qdx_dma_cpu(table), owned_view.table, TABLE_LEN);
 dma_wmb();
 adopt_node_values[1] = node + 228;
 adopt_node_values[2] = node + 228;
 adopt_node_values[3] = table_address;
 adopt_node_values[4] = table_address + 72;
 adopt_node_values[5] = 0;
 adopt_node_values[6] = 2;
 /* Cached largest-bin candidate/threshold retain their old history. */
 operation = qdx_packet_op_prepare(mirror, COPY_TAG, QDX_RECEIVE_PACKET);
 if (IS_ERR(operation)) { error = PTR_ERR(operation); operation = NULL; return error; }
 qdx_packet_op_close(operation);
 error = qdx_diag_fq_node_import(operation, table, probe_operation,
  &owned_view, adopt_node_values, &owner);
 qdx_packet_op_put(operation); operation = NULL;
 if (error) return error;
 error = state_owned_read(OWNED_TABLE, 0, TABLE_LEN, adopt_after);
 if (error) return error;
 if (memcmp(adopt_after, owned_view.table, TABLE_LEN)) return -EBADMSG;
 error = state_owned_read(QDX_DIAG_FQ_NODE, 0, 280, owned_view.node);
 if (error) return error;
 if (get_unaligned_le32(owned_view.node + 228) != node + 228 ||
     get_unaligned_le32(owned_view.node + 232) != node + 228 ||
     get_unaligned_le32(owned_view.node + 236) != table_address ||
     get_unaligned_le32(owned_view.node + 240) != table_address + 72 ||
     get_unaligned_le32(owned_view.node + 252) ||
     get_unaligned_le32(owned_view.node + 256) != 2)
  return -EBADMSG;
 adopt_imported = true;
 return 0;
}


/* The returned original is a separate private event, never a policy packet. */
static void state_bf_private_returned(void *owner, struct sk_buff *original,
 struct sk_buff *returned, const struct qdx_rx_meta *meta, struct napi_struct *napi)
{
 struct probe_packet *packet = owner;
 bool valid = original == packet->skb && returned == original && returned && meta &&
  meta->type == QDX_RECEIVE_RETURNED && meta->ifnum == igs_ifnum &&
  returned->len == PROBE_LENGTH && !skb_is_nonlinear(returned) &&
  !memcmp(returned->data, packet->expected, PROBE_LENGTH);

 packet->skb = NULL;
 bf_private_ns = ktime_get_ns();
 if (returned) { bf_private_returned++; bf_private_valid += valid; }
 else bf_private_disposed++;
 dev_kfree_skb_any(returned);
 complete_all(&bf_private_done);
}

/* Reuse the exact qualified FQ packet/age/history reconstruction. The BF
 * forward command has already retired the old leaf's original carriers.
 */
static int state_bf_rebuild(void)
{
 struct qdx_owner owner = { .module = THIS_MODULE, .object = rounds };
 u32 alignment;
 int error;

 if (!bf_mode || !bf_pass || !bf_retired || bf_rebuild_ready || bf_rearm_started ||
     bf_request || request || operation || closed || fault) return -EPERM;
 error = state_adopt_rebuild();
 if (error) return error;
 error = state_bf_command(5, BF_GROUP_TAG, TABLE_TAG);
 if (error) return error;
 owned_view.bf = true;
 error = state_owned_read(QDX_DIAG_FQ_NODE, 0, 280, owned_view.node);
 if (!error) error = state_owned_read(QDX_DIAG_BF_GROUP, 0, 232, owned_view.bf_group);
 if (error) return error;
 owned_view.bf_valid = 1;
 error = state_owned_read(QDX_DIAG_BF_PARENT, 0, 200, owned_view.bf_parent);
 if (error) return error;
 owned_view.bf_valid |= 2;
 error = state_bf_snapshot();
 if (error) return error;
 if ((get_unaligned_le32(bf_timer + 24) & 2) || owned_view.bf_group[229] ||
     memcmp(bf_account, bf_cpu_account, 292) ||
     memcmp(bf_account + 308, bf_cpu_account + 308, 4)) return -EBADMSG;
 error = state_owned_read(QDX_DIAG_BF_ALLOCATOR, 0, 24, owned_view.bf_allocator);
 if (error) return error;
 owned_view.bf_valid |= 4;
 alignment = get_unaligned_le32(owned_view.bf_allocator + 12);
 if (alignment < 4 || alignment > 64 || !is_power_of_2(alignment)) return -EBADMSG;
 error = state_owned_read(QDX_DIAG_BF_ACCOUNT_HEADER, 0, ALIGN(28, alignment),
  owned_view.bf_header);
 if (error) return error;
 owned_view.bf_valid |= 8;
 operation = qdx_packet_op_prepare(mirror, COPY_TAG, QDX_RECEIVE_PACKET);
 if (IS_ERR(operation)) { error = PTR_ERR(operation); operation = NULL; return error; }
 qdx_packet_op_close(operation);
 error = qdx_diag_bf_pin(operation, table, probe_operation, &owned_view, &owner);
 qdx_packet_op_put(operation); operation = NULL;
 if (error) return error;
 bf_lifetime_pinned = true;
 bf_rebuild_ready = true;
 return 0;
}

/* One real due event transfers timer responsibility. All numeric imports
 * occur BEFORE a new timer is armed; no optimistic post-arm host write.
 */
static int state_bf_rearm(void)
{
 struct qdx_owner owner = { .module = THIS_MODULE, .object = rounds };
 struct qdx_packet_recipient recipient = {
  .owner = { .module = THIS_MODULE, .object = &bf_private_packet },
  .returned = state_bf_private_returned,
 };
 struct qdx_diag_bf_state imported = {};
 struct qdx_ready ready;
 struct sk_buff *skb;
 u64 reference, before_reference, elapsed, increment, now;
 s64 credit;
 s32 deficit;
 u32 shift, parent;
 unsigned long deadline;
 bool drained, advanced = false;
 int error;

 if (!bf_rebuild_ready || !bf_lifetime_pinned || bf_rearm_started || bf_request ||
     request || operation || closed || fault || !adopt_imported ||
     adopt_returns || adopt_disposed || !probe_operation) return -EPERM;
 error = state_bf_command(0, BF_PRIVATE_TAG, 0);
 if (!error) error = state_bf_command(7, BF_PRIVATE_TAG, 0);
 if (error) return error;
 bf_event_due_ms = bf_cpu_pending_ms;
 deadline = jiffies + msecs_to_jiffies(WAIT_MS);
 do {
  error = state_owned_read(QDX_DIAG_FQ_CLOCK, 0, 24, owned_clock[3]);
  if (error) return error;
  now = get_unaligned_le64(owned_clock[3] + 16);
  if (now >= bf_event_due_ms) break;
  usleep_range(500, 1000);
 } while (time_before(jiffies, deadline));
 if (now < bf_event_due_ms) return -ETIMEDOUT;
 bf_event_observed_ms = now;
 /* Fresh copies release every imported line. No timer or producer can
  * write these objects: the old callback joined and the outer edge is cut.
  */
 error = state_bf_snapshot();
 if (error) return error;
 if ((get_unaligned_le32(bf_timer + 24) & 2) || owned_view.bf_group[229]) return -EBUSY;
 memcpy(imported.current_account, bf_account, 312);
 memcpy(imported.timer, bf_timer, 32);
 memcpy(imported.notifier, bf_notifier, 16);
 memcpy(imported.epoch[0], bf_epoch_before, 20);
 memcpy(imported.epoch[1], bf_epoch_after, 20);
 memcpy(imported.frequency, bf_frequency, sizeof(bf_frequency));
 imported.clock_ms[0] = bf_snapshot_begin; imported.clock_ms[1] = bf_retire_clock;
 imported.timer_joined = bf_timer_joined;
 imported.credit = (s64)get_unaligned_le64(bf_cpu_account + 292);
 imported.reference = get_unaligned_le64(bf_cpu_account + 300);
 imported.deficit[0] = (s32)get_unaligned_le32(bf_cpu_group + 184);
 deficit = (s32)get_unaligned_le32(bf_cpu_group + 200);
 if (imported.credit >= 0 || deficit < -PROBE_LENGTH || deficit > 128)
  return -ERANGE;
 imported.deficit[1] = deficit + PROBE_LENGTH;
 operation = qdx_packet_op_prepare(mirror, COPY_TAG, QDX_RECEIVE_PACKET);
 if (IS_ERR(operation)) { error = PTR_ERR(operation); operation = NULL; return error; }
 qdx_packet_op_close(operation);
 error = qdx_diag_bf_import(operation, table, probe_operation, &owned_view,
  &imported, &owner);
 qdx_packet_op_put(operation); operation = NULL;
 if (error) return error;
 bf_rearm_started = true;
 bf_import_deficit = deficit;
 error = state_owned_read(QDX_DIAG_BF_ACCOUNT, 0, 312, bf_import_account);
 if (!error) error = state_owned_read(QDX_DIAG_BF_GROUP, 0, 232, owned_view.bf_group);
 if (error) return error;
 if (get_unaligned_le64(bf_import_account + 292) != (u64)imported.credit ||
     get_unaligned_le64(bf_import_account + 300) != imported.reference ||
     (s32)get_unaligned_le32(owned_view.bf_group + 184) != imported.deficit[0] ||
     (s32)get_unaligned_le32(owned_view.bf_group + 200) != imported.deficit[1])
  return -EBADMSG;
 error = state_bf_command(6, BF_GROUP_TAG, TABLE_TAG);
 if (!error) error = state_bf_command(5, BF_GROUP_TAG, BF_PRIVATE_TAG);
 if (error) return error;
 skb = alloc_skb(PROBE_HEADROOM + PROBE_LENGTH, GFP_KERNEL);
 if (!skb) return -ENOMEM;
 skb_reserve(skb, PROBE_HEADROOM);
 memcpy(skb_put(skb, PROBE_LENGTH), bf_triggers[0].expected, PROBE_LENGTH);
 put_unaligned_be16(21001, skb->data + 34);
 put_unaligned_le32(0x42524656, skb->data + 42);
 skb->dev = port; skb->protocol = htons(ETH_P_IP); skb_reset_mac_header(skb);
 bf_private_packet.skb = skb;
 memcpy(bf_private_packet.expected, skb->data, PROBE_LENGTH);
 bf_private_operation = qdx_packet_op_prepare(igs, BF_PRIVATE_TAG, QDX_RECEIVE_RETURNED);
 if (IS_ERR(bf_private_operation)) {
  error = PTR_ERR(bf_private_operation); bf_private_operation = NULL;
  bf_private_packet.skb = NULL; dev_kfree_skb(skb); return error;
 }
 ready = qdx_packet_op_submit(bf_private_operation, skb, &recipient);
 if (ready.status != QDX_ACCEPTED) {
  error = ready.error ?: -EAGAIN;
  bf_private_packet.skb = NULL; dev_kfree_skb(skb);
  qdx_packet_op_close(bf_private_operation);
  qdx_packet_op_put(bf_private_operation); bf_private_operation = NULL;
  return error;
 }
 qdx_packet_op_close(bf_private_operation);
 error = state_bf_command(5, BF_OUTER_TAG, BF_PARENT_TAG);
 if (error) return error;
 bf_cut = false;
 if (!wait_for_completion_timeout(&bf_private_done, msecs_to_jiffies(WAIT_MS)))
  return -ETIMEDOUT;
 error = read_poll_timeout(qdx_packet_op_drained, drained, drained, 10,
  WAIT_MS * 1000, false, bf_private_operation);
 if (error) return error;
 if (bf_private_returned != 1 || bf_private_valid != 1 || bf_private_disposed)
  return -EBADMSG;
 qdx_packet_op_put(bf_private_operation); bf_private_operation = NULL;
 error = state_bf_command(6, BF_OUTER_TAG, BF_PARENT_TAG);
 if (error) return error;
 bf_cut = true;
 error = state_bf_command(6, BF_GROUP_TAG, BF_PRIVATE_TAG);
 if (!error) error = state_bf_command(5, BF_GROUP_TAG, TABLE_TAG);
 if (!error) error = state_owned_read(QDX_DIAG_FQ_NODE, 0, 280, owned_view.node);
 if (!error) error = state_bf_snapshot();
 if (error) return error;
 parent = get_unaligned_le32(owned_view.bf_group + 4);
 reference = get_unaligned_le64(bf_account + 300);
 before_reference = get_unaligned_le64(bf_import_account + 300);
 shift = get_unaligned_le32(bf_account + 272);
 if (shift >= 63 || reference < before_reference) return -ERANGE;
 elapsed = reference - before_reference;
 if (elapsed > ((u64)S64_MAX >> shift)) return -ERANGE;
 increment = elapsed << shift;
 if (check_add_overflow(imported.credit, (s64)increment, &credit) || credit >= 0)
  return -ERANGE;
 if ((s64)get_unaligned_le64(bf_account + 292) != credit ||
     memcmp(bf_account, bf_import_account, 292) ||
     memcmp(bf_account + 308, bf_import_account + 308, 4) ||
     (s32)get_unaligned_le32(owned_view.bf_group + 184) != imported.deficit[0] ||
     (s32)get_unaligned_le32(owned_view.bf_group + 200) != deficit ||
     get_unaligned_le32(owned_view.bf_group + 224) || !owned_view.bf_group[229] ||
     !(get_unaligned_le32(bf_timer + 24) & 2) ||
     get_unaligned_le32(owned_view.bf_parent + 172) != parent + 172 ||
     get_unaligned_le32(owned_view.bf_parent + 176) != parent + 172)
  return -EBADMSG;
 memcpy(bf_after_event_account, bf_account, 312);
 memcpy(bf_after_event_timer, bf_timer, 32);
 bf_successor_ms = get_unaligned_le64(bf_timer + 16);
 /* Observe an actual later callback, not merely a queued flag/readback. */
 deadline = jiffies + msecs_to_jiffies(WAIT_MS);
 do {
  error = state_bf_snapshot();
  if (error && error != -EAGAIN) return error;
  advanced = !error && get_unaligned_le64(bf_account + 300) > reference &&
   get_unaligned_le64(bf_timer + 16) > bf_successor_ms;
  if (advanced) break;
  usleep_range(500, 1000);
 } while (time_before(jiffies, deadline));
 if (!advanced) return -ETIMEDOUT;
 bf_callback_reference = get_unaligned_le64(bf_account + 300);
 bf_callback_deadline = get_unaligned_le64(bf_timer + 16);
 if ((s64)get_unaligned_le64(bf_account + 292) >= 0 ||
     get_unaligned_le32(owned_view.bf_group + 224) || !owned_view.bf_group[229] ||
     !(get_unaligned_le32(bf_timer + 24) & 2)) return -EBADMSG;
 bf_rearm_pass = true;
 return 0;
}

/* Data are served only after the original debt and real timer are restored.
 * A final empty, obsolete executor is configured positive solely for join.
 */
/* One-group CPU continuation whose original due event is now positive.
 * The deliberate off interval belongs to the test caller; this command never
 * waits for debt repayment. Negative-event source and completion are separate.
 */
static int state_bf_positive_rearm(void)
{
 struct qdx_owner owner = { .module = THIS_MODULE, .object = rounds };
 struct qdx_diag_bf_state imported = {};
 u64 old_reference, reference, elapsed, increment, now;
 s64 credit, cap, room, expected;
 u32 shift, parent, group, cost_shift, cost_index;
 unsigned long deadline;
 int error;

 if (!bf_positive_test || !bf_rebuild_ready || !bf_lifetime_pinned ||
     bf_rearm_started || bf_request || request || operation || closed || fault ||
     !adopt_imported || adopt_returns || adopt_disposed || !probe_operation)
  return -EPERM;
 bf_event_due_ms = bf_cpu_pending_ms;
 deadline = jiffies + msecs_to_jiffies(WAIT_MS);
 do {
  error = state_owned_read(QDX_DIAG_FQ_CLOCK, 0, 24, owned_clock[3]);
  if (error) return error;
  now = get_unaligned_le64(owned_clock[3] + 16);
  if (now >= bf_event_due_ms) break;
  usleep_range(500, 1000);
 } while (time_before(jiffies, deadline));
 if (now < bf_event_due_ms) return -ETIMEDOUT;
 bf_event_observed_ms = now;
 error = state_bf_snapshot();
 if (error) return error;
 if ((get_unaligned_le32(bf_timer + 24) & 2) || owned_view.bf_group[229])
  return -EBUSY;
 /* This joined, unreachable account is already obsolete. CONFIG supplies an
  * actual same-domain raw-time reference; its reset credit is never adopted.
  */
 error = state_bf_command(7, BF_GROUP_TAG, 0);
 if (!error) error = state_bf_snapshot();
 if (error) return error;
 if ((get_unaligned_le32(bf_timer + 24) & 2) || owned_view.bf_group[229] ||
     memcmp(bf_account, bf_cpu_account, 292) ||
     memcmp(bf_account + 308, bf_cpu_account + 308, 4)) return -EBADMSG;
 old_reference = get_unaligned_le64(bf_cpu_account + 300);
 reference = get_unaligned_le64(bf_account + 300);
 shift = get_unaligned_le32(bf_cpu_account + 272);
 credit = (s64)get_unaligned_le64(bf_cpu_account + 292);
 cap = (s64)get_unaligned_le64(bf_cpu_account + 284);
 if (shift >= 63 || reference < old_reference || cap <= 0 || credit > cap ||
     check_sub_overflow(cap, credit, &room)) return -ERANGE;
 elapsed = reference - old_reference;
 if (elapsed > ((u64)S64_MAX >> shift)) return -ERANGE;
 increment = elapsed << shift;
 credit = increment >= room ? cap : credit + (s64)increment;
 /* This discriminator starts consequential service at the original cap.
  * The runner supplies an explicit CPU-off interval; the importer does not
  * wait for repayment or replace the original credit with CONFIG's credit.
  */
 if (credit != cap) return -EAGAIN;
 cost_shift = get_unaligned_le32(bf_cpu_account + 268);
 if (cost_shift >= 32 || get_unaligned_le32(bf_cpu_account + 8) < PROBE_LENGTH)
  return -ERANGE;
 cost_index = PROBE_LENGTH >> cost_shift;
 if (cost_index >= 32) return -ERANGE;
 bf_positive_packet_cost = (s64)get_unaligned_le64(bf_cpu_account + 12 + 8 * cost_index);
 if (bf_positive_packet_cost <= 0 || bf_positive_packet_cost > S64_MAX / 3 ||
     cap <= bf_positive_packet_cost || cap >= 2 * bf_positive_packet_cost)
  return -ERANGE;
 memcpy(imported.current_account, bf_account, 312);
 memcpy(imported.timer, bf_timer, 32);
 memcpy(imported.notifier, bf_notifier, 16);
 memcpy(imported.epoch[0], bf_epoch_before, 20);
 memcpy(imported.epoch[1], bf_epoch_after, 20);
 memcpy(imported.frequency, bf_frequency, sizeof(bf_frequency));
 imported.clock_ms[0] = bf_snapshot_begin; imported.clock_ms[1] = bf_retire_clock;
 imported.timer_joined = bf_timer_joined;
 imported.credit = credit; imported.reference = reference;
 imported.deficit[0] = (s32)get_unaligned_le32(bf_cpu_group + 184);
 imported.deficit[1] = (s32)get_unaligned_le32(bf_cpu_group + 200);
 operation = qdx_packet_op_prepare(mirror, COPY_TAG, QDX_RECEIVE_PACKET);
 if (IS_ERR(operation)) { error = PTR_ERR(operation); operation = NULL; return error; }
 qdx_packet_op_close(operation);
 error = qdx_diag_bf_import(operation, table, probe_operation, &owned_view,
  &imported, &owner);
 qdx_packet_op_put(operation); operation = NULL;
 if (error) return error;
 bf_rearm_started = true;
 bf_positive_credit = credit; bf_positive_reference = reference;
 bf_import_deficit = imported.deficit[1];
 put_unaligned_le64(credit, bf_cpu_account + 292);
 put_unaligned_le64(reference, bf_cpu_account + 300);
 put_unaligned_le32(1, bf_cpu_group + 224); bf_cpu_group[229] = 0;
 error = state_owned_read(QDX_DIAG_BF_ACCOUNT, 0, 312, bf_import_account);
 if (!error) error = state_owned_read(QDX_DIAG_BF_GROUP, 0, 232, owned_view.bf_group);
 if (error) return error;
 if (get_unaligned_le64(bf_import_account + 292) != (u64)credit ||
     get_unaligned_le64(bf_import_account + 300) != reference ||
     (s32)get_unaligned_le32(owned_view.bf_group + 184) != imported.deficit[0] ||
     (s32)get_unaligned_le32(owned_view.bf_group + 200) != imported.deficit[1])
  return -EBADMSG;
 error = state_bf_command(6, BF_GROUP_TAG, TABLE_TAG);
 if (!error) error = state_bf_command(5, BF_GROUP_TAG, TABLE_TAG);
 if (!error) error = state_bf_snapshot();
 if (error) return error;
 bf_positive_activation_reference = get_unaligned_le64(bf_account + 300);
 if (bf_positive_activation_reference < reference) return -ERANGE;
 elapsed = bf_positive_activation_reference - reference;
 if (elapsed > ((u64)S64_MAX >> shift)) return -ERANGE;
 increment = elapsed << shift;
 room = cap - credit;
 expected = increment >= room ? cap : credit + (s64)increment;
 group = get_unaligned_le32(owned_view.node + 4);
 parent = get_unaligned_le32(owned_view.bf_group + 4);
 if ((s64)get_unaligned_le64(bf_account + 292) != expected || expected <= 0 ||
     owned_view.bf_group[229] || (get_unaligned_le32(bf_timer + 24) & 2) ||
     get_unaligned_le32(owned_view.bf_group + 224) != 1 ||
     (s32)get_unaligned_le32(owned_view.bf_group + 184) != imported.deficit[0] ||
     (s32)get_unaligned_le32(owned_view.bf_group + 200) != imported.deficit[1] ||
     get_unaligned_le32(owned_view.bf_parent + 172) != group + 172 ||
     get_unaligned_le32(owned_view.bf_parent + 176) != group + 172 ||
     get_unaligned_le32(owned_view.bf_group + 172) != parent + 172 ||
     get_unaligned_le32(owned_view.bf_group + 176) != parent + 172 ||
     bf_private_returned || bf_private_disposed || adopt_returns || adopt_disposed)
  return -EBADMSG;
 memcpy(bf_after_event_account, bf_account, 312);
 memcpy(bf_after_event_timer, bf_timer, 32);
 bf_positive_pass = true; bf_rearm_pass = true;
 return 0;
}

static int state_bf_serve(void)
{
 static const u32 expected[12] = { 2, 3, 4, 10, 11, 5, 6, 7, 12, 13, 14, 15 };
 unsigned int i;
 unsigned long deadline;
 bool drained, joined = false;
 int error;

 if (!bf_rearm_pass || bf_reverse_done || bf_request || request || operation ||
     closed || fault || !owned_payload[0] || !owned_payload[8]) return -EPERM;
 error = state_bf_command(5, BF_OUTER_TAG, BF_PARENT_TAG);
 if (error) return error;
 bf_cut = false;
 if (!wait_for_completion_timeout(&adopt_done, msecs_to_jiffies(WAIT_MS)))
  return -ETIMEDOUT;
 error = read_poll_timeout(qdx_packet_op_drained, drained, drained, 10,
  WAIT_MS * 1000, false, probe_operation);
 if (error) return error;
 error = state_bf_command(6, BF_OUTER_TAG, BF_PARENT_TAG);
 if (error) return error;
 bf_cut = true;
 error = state_command(STATS, true, WAIT_MS);
 if (error) return error;
 if (probe_qlen || probe_drops != 2 || adopt_accepted != 14 ||
     adopt_returns != 12 || adopt_valid != 12 || adopt_bad_owner || adopt_disposed != 2 ||
     adopt_disposed_mask != (BIT(1) | BIT(9)) ||
     adopt_last_ns - adopt_first_ns >= 100 * NSEC_PER_MSEC) return -EBADMSG;
 for (i = 0; i < 12; i++) if (adopt_order[i] != expected[i]) return -EBADMSG;
 bf_reverse_done = true;
 /* No policy packet remains in this executor; timer history is obsolete. */
 error = state_owned_read(OWNED_TABLE, 0, TABLE_LEN, owned_view.table);
 if (!error) error = state_owned_read(QDX_DIAG_FQ_NODE, 0, 280, owned_view.node);
 if (error) return error;
 if (bf_positive_test) {
  s64 cap = (s64)get_unaligned_le64(bf_after_event_account + 284);
  s64 cost = bf_positive_packet_cost, base = cap - 3 * cost;
  s32 preferred = (s32)get_unaligned_le32(bf_cpu_group + 184);
  s32 excess = (s32)get_unaligned_le32(bf_cpu_group + 200);
  u32 shift = get_unaligned_le32(bf_after_event_account + 272);
  u64 elapsed;

  /* Preserve the account actually used by the twelve packet decisions,
   * before retirement CONFIG deliberately makes the empty executor obsolete.
   * The third preferred packet sees nonpositive credit, arms its actual timer
   * and still debits its old preferred membership before the parent removes it.
   */
  error = state_bf_snapshot();
  if (error) return error;
  memcpy(bf_positive_service_account, bf_account, sizeof(bf_account));
  bf_positive_service_credit = (s64)get_unaligned_le64(bf_account + 292);
  bf_positive_service_reference = get_unaligned_le64(bf_account + 300);
  if (shift >= 63 || bf_positive_service_reference < bf_positive_activation_reference)
   return -ERANGE;
  elapsed = bf_positive_service_reference - bf_positive_activation_reference;
  if (elapsed > ((u64)S64_MAX >> shift)) return -ERANGE;
  bf_positive_service_refill = elapsed << shift;
  for (i = 0; i < 3; i++) {
   if (preferred < 0) preferred += 128;
   preferred -= PROBE_LENGTH;
  }
  for (i = 0; i < 9; i++) {
   if (excess < 0) excess += 128;
   excess -= PROBE_LENGTH;
  }
  bf_positive_service_pass = bf_positive_service_refill < min_t(u64, cap - cost, 2 * cost - cap) &&
   bf_positive_service_credit >= base &&
   bf_positive_service_credit <= base + (s64)bf_positive_service_refill &&
   (s32)get_unaligned_le32(owned_view.bf_group + 184) == preferred &&
   (s32)get_unaligned_le32(owned_view.bf_group + 200) == excess;
 }
 error = state_bf_command(7, BF_GROUP_TAG, 0);
 if (error) return error;
 deadline = jiffies + msecs_to_jiffies(WAIT_MS);
 do {
  error = state_bf_snapshot();
  if (error && error != -EAGAIN) return error;
  joined = !error && !(get_unaligned_le32(bf_timer + 24) & 2) &&
   !owned_view.bf_group[229];
  if (joined) break;
  usleep_range(500, 1000);
 } while (time_before(jiffies, deadline));
 if (!joined) return -ETIMEDOUT;
 if ((s64)get_unaligned_le64(bf_account + 292) <= 0) return -EBADMSG;
 bf_reverse_retired = true;
 adopt_pass = !bf_positive_test || bf_positive_service_pass;
 return adopt_pass ? 0 : -EBADMSG;
}

static int state_adopt_serve(void)
{
 static const u32 expected[12] = { 2, 3, 4, 10, 11, 5, 6, 7, 12, 13, 14, 15 };
 unsigned int i;
 unsigned long deadline;
 u64 now;
 bool drained;
 int error;

 if (bf_mode || !adopt_imported || probe_started || request || closed || fault || operation ||
     !owned_payload[0] || !owned_payload[8])
  return -EPERM;
 deadline = jiffies + msecs_to_jiffies(WAIT_MS);
 do {
  error = state_owned_read(QDX_DIAG_FQ_CLOCK, 0, 24, owned_clock[3]);
  if (error) return error;
  now = get_unaligned_le64(owned_clock[3] + 16);
  if (now >= adopt_clock[0] + 102 && now >= adopt_clock[1] + 102) break;
  usleep_range(1000, 1500);
 } while (time_before(jiffies, deadline));
 if (now < adopt_clock[0] + 102 || now < adopt_clock[1] + 102)
  return -ETIMEDOUT;
 error = state_command(ROOT, true, WAIT_MS);
 if (error) return error;
 if (!wait_for_completion_timeout(&adopt_done, msecs_to_jiffies(WAIT_MS)))
  return -ETIMEDOUT;
 error = read_poll_timeout(qdx_packet_op_drained, drained, drained, 10,
  WAIT_MS * 1000, false, probe_operation);
 if (error) return error;
 synchronize_net();
 error = state_command(STATS, true, WAIT_MS);
 if (error) return error;
 if (probe_qlen || probe_drops != 2 || adopt_accepted != 14 ||
     adopt_returns != 12 || adopt_valid != 12 || adopt_bad_owner || adopt_disposed != 2 ||
     adopt_disposed_mask != (BIT(1) | BIT(9)) ||
     adopt_last_ns - adopt_first_ns >= 100 * NSEC_PER_MSEC)
  return -EBADMSG;
 for (i = 0; i < 12; i++)
  if (adopt_order[i] != expected[i]) return -EBADMSG;
 adopt_pass = true;
 return 0;
}

static int state_probe_serve(void)
{
	static const u32 expected[PROBE_PACKETS] = {
		0, 8, 1, 2, 3, 9, 10, 4, 5, 6, 11, 12, 7, 13, 14, 15,
	};
	unsigned int i;
	bool drained;
	int error;

	if (bf_mode || !probe_snapshot_valid || probe_started || request || closed || fault || adopt_cpu ||
	    (age_changed && !age_restored) ||
	    !rounds[3].host_equal || !rounds[3].clone_valid || operation)
		return -EPERM;
	error = state_command(ROOT, true, WAIT_MS);
	if (error)
		return error;
	if (!wait_for_completion_timeout(&probe_done, msecs_to_jiffies(WAIT_MS)))
		return -ETIMEDOUT;
	error = read_poll_timeout(qdx_packet_op_drained, drained, drained, 50,
		WAIT_MS * 1000, false, probe_operation);
	if (error)
		return error;
	synchronize_net();
	error = state_command(STATS, true, WAIT_MS);
	if (error)
		return error;
	if (probe_qlen || probe_drops || probe_returns != PROBE_PACKETS ||
	    probe_valid != PROBE_PACKETS || probe_disposed ||
	    probe_last_ns - probe_first_ns >= 100 * NSEC_PER_MSEC)
		return -EBADMSG;
	for (i = 0; i < PROBE_PACKETS; i++)
		if (probe_order[i] != expected[i])
			return -EBADMSG;
	probe_pass = true;
	return 0;
}

static int state_restore(void)
{
	unsigned int i;
	int error;

	if (!pinned)
		return 0;
 /* A failed empty prepare may own only the acknowledged OUTER. Unknown
  * commands need poll; a started packet fixture retains its strict close. */
 if (!bf_mode && bf_request) return -EINPROGRESS;
 if (!bf_mode && bf_allocated &&
     (bf_allocated != BIT(0) || bf_links || probe_loaded)) return -EBUSY;
 if (bf_mode && ((bf_account_test ? !bf_pair_closed : !bf_pass) || !bf_retired || bf_request || bf_trigger_operation ||
     bf_private_operation || (adopt_rebuild_started && !bf_reverse_retired)))
  return -EBUSY;
	closed = true;
	if (probe_operation) {
		qdx_packet_op_close(probe_operation);
		if (!qdx_packet_op_drained(probe_operation))
			return -EINPROGRESS;
	}
	if (operation) {
		qdx_packet_op_close(operation);
		if (!qdx_packet_op_drained(operation))
			return -EINPROGRESS;
	}
	for (i = 0; i < ARRAY_SIZE(rounds); i++)
		if (rounds[i].submitted && !completion_done(&rounds[i].original_done))
			return -EINPROGRESS;
	synchronize_net();
	if (table && !qdx_diag_fq_table_idle(table))
		return -EINPROGRESS;
	if (request) {
		error = state_command(pending, false, WAIT_MS);
		if (request || error)
			return error;
	}
	if (enabled) {
		error = state_command(MIRROR_DISABLE, true, WAIT_MS);
		if (error)
			return error;
	}
	if (next_set) {
		error = state_command(MIRROR_RESET, true, WAIT_MS);
		if (error)
			return error;
	}
 if (bf_mode && (bf_links & BIT(2))) {
  error = state_bf_command(6, BF_GROUP_TAG, TABLE_TAG);
  if (error) return error;
 }
	if (allocated) {
		error = state_command(FREE, true, WAIT_MS);
		if (error)
			return error;
	}
 if (bf_mode || bf_allocated) {
  if (bf_links & BIT(1)) {
   error = state_bf_command(6, BF_PARENT_TAG, BF_GROUP_TAG);
   if (error) return error;
  }
  if (bf_allocated & BIT(3)) { error = state_bf_command(1, BF_PRIVATE_TAG, 0); if (error) return error; }
  if (bf_allocated & BIT(2)) { error = state_bf_command(1, BF_GROUP_TAG, 0); if (error) return error; }
  if (bf_allocated & BIT(1)) { error = state_bf_command(1, BF_PARENT_TAG, 0); if (error) return error; }
  if (bf_allocated & BIT(0)) { error = state_bf_command(1, BF_OUTER_TAG, 0); if (error) return error; }
 }
	if (assigned) {
		error = state_command(UNASSIGN, true, WAIT_MS);
		if (error)
			return error;
	}
	if (igs && !igs_retired) {
		error = qdx_endpoint_wait(igs, jiffies);
		if (error)
			return error;
		error = qdx_endpoint_retire(igs);
		if (error)
			return error;
		igs_retired = true;
	}
	if (mirror && !mirror_retired) {
		error = qdx_endpoint_wait(mirror, jiffies);
		if (error)
			return error;
		error = qdx_endpoint_retire(mirror);
		if (error)
			return error;
		mirror_retired = true;
	}
	if (receiver) {
		error = qdx_endpoint_receive_unregister(receiver);
		if (error)
			return error;
		receiver = NULL;
	}
	for (i = 0; i < PROBE_PACKETS; i++) {
		dev_kfree_skb_any(owned_payload[i]);
		owned_payload[i] = NULL;
	}
	dev_kfree_skb_any(owned.payload);
	owned.payload = NULL;
	qdx_packet_op_put(operation);
	operation = NULL;
	qdx_packet_op_put(probe_operation);
	probe_operation = NULL;
	qdx_endpoint_put(mirror);
	mirror = NULL;
	qdx_endpoint_put(igs);
	igs = NULL;
	if (table) {
		qdx_dma_release(table);
		table = NULL;
	}
	qdx_service_put(mirror_service);
	mirror_service = NULL;
	qdx_service_put(igs_service);
	igs_service = NULL;
	if (port)
		dev_put(port);
	port = NULL;
	pinned = false;
	module_put(THIS_MODULE);
	return 0;
}

static int state_status_show(struct seq_file *seq, void *unused)
{
	struct table_round *round;
	u8 actual[TABLE_LEN];
	u32 values[9];
	unsigned int i, offset, length, cost_rows, cost_sequence;
 struct owned_copy_cost *cost;
	unsigned long flags;

	mutex_lock(&state_lock);
 seq_printf(seq, "bf_native_frequency_sync=%u started=%u complete=%u attempted=%u published=%u observed=%u observation_error=%d core_seen=%u wait_limit_ms=%llu remaining_ms=%llu wait_budget_ms=%llu\n",
  bf_native_frequency_sync, bf_frequency_started, bf_frequency_complete,
  bf_frequency_attempted, bf_frequency_published, bf_frequency_observed,
  bf_frequency_observation_error, !!bf_frequency_core,
  bf_pair_wait_limit_ms, bf_pair_wait_remaining_ms, bf_pair_wait_budget_ms);
 for (i = 0; i < 2; i++)
  seq_printf(seq, "bf_native_frequency_step=%u calls=%u send_error=%d replies=%u response=%u firmware_error=%u received=%u declared=%u frequency=%u ack=%u start_ns=%llu observed_ns=%llu\n",
   i, bf_frequency_calls[i], bf_frequency_send_error[i], bf_frequency_reply[i].count,
   bf_frequency_reply[i].response, bf_frequency_reply[i].error,
   bf_frequency_reply[i].received, bf_frequency_reply[i].declared,
   bf_frequency_reply[i].frequency, bf_frequency_reply[i].ack,
   bf_frequency_start_ns[i], bf_frequency_reply[i].ns);
 seq_printf(seq, "bf_callback branch=%u native_valid=%u discriminating=%u expected_credit=%lld unchanged_credit=%lld\n",
  bf_pair_callback_branch, bf_pair_callback_valid, bf_pair_callback_discriminating,
  bf_pair_expected_credit, bf_pair_unchanged_credit);
 seq_printf(seq, "bf_account_test=%u control=%u started=%u aux_attached=%u published=%u visible=%u consequence=%u callback_branch=%u joined=%u pointer_written=%u pointer_restored=%u retire_configured=%u backing_started=%u closed=%u original_account=%08x original_due=%llu observed_ms=%llu cost=%llu before0=%lld after0=%lld before1=%lld after1=%lld reference0=%llu reference1=%llu\n",
  bf_account_test, bf_account_control, bf_pair_started, bf_aux_attached,
  bf_pair_published, bf_pair_visible, bf_pair_consequence_pass, bf_pair_callback_branch, bf_pair_joined,
  bf_pair_pointer_written, bf_pair_pointer_restored, bf_pair_retire_configured, bf_pair_backing_started,
  bf_pair_closed, bf_pair_update.original_account, bf_pair_original_due, bf_pair_observed_ms,
  bf_pair_cost, bf_pair_before_credit[0], bf_pair_after_credit[0],
  bf_pair_before_credit[1], bf_pair_after_credit[1], bf_pair_reference[0], bf_pair_reference[1]);
 for (offset = 0; bf_pair_started && offset < 312; offset += 24)
  seq_printf(seq, "bf_pair_account_offset%u=%24phN\n", offset, bf_pair_consequence_account + offset);
 if (bf_pair_started) {
  seq_printf(seq, "bf_pair_event=%32phN publication_epoch=%u\n", bf_pair_consequence_timer, bf_pair_publication_epoch);
  for (offset = 0; offset < 232; offset += 8)
   seq_printf(seq, "bf_pair_group_offset%u=%8phN\n", offset, bf_pair_consequence_group + offset);
 }
	seq_printf(seq, "allow_writes=%u pinned=%u closed=%u fault=%u assigned=%u allocated=%u configured=%u memory_checked=%u memory_size=%u igs_ifnum=%u mirror_ifnum=%u shaper=%u table_address=%08x table_length=%u idle=%u op_drained=%u enabled=%u next_set=%u pending=%u error=%d word_changed=%u word_restored=%u unexpected_clones=%u\n",
		allow_writes, pinned, closed, fault, assigned, allocated, configured,
		memory_checked, memory_size, igs_ifnum, mirror_ifnum, shaper, table_address,
		TABLE_LEN, table ? qdx_diag_fq_table_idle(table) : true,
		operation ? qdx_packet_op_drained(operation) : true, enabled, next_set,
		pending, last_error, word_changed, word_restored, READ_ONCE(unexpected_clones));
	seq_printf(seq, "request_id=%llu outcome=%u firmware_error=%u received=%zu declared=%zu published=%u exposure_ended=%u\n",
		(unsigned long long)result.id, result.outcome, result.firmware_error,
		result.received_len, result.declared_len, result.published, result.exposure_ended);
	for (i = 0; i < ARRAY_SIZE(rounds); i++) {
		round = &rounds[i];
		spin_lock_irqsave(&result_lock, flags);
		values[0] = round->originals; values[1] = round->clones;
		values[2] = round->original_valid; values[3] = round->clone_valid;
		values[4] = round->original_type; values[5] = round->original_ifnum;
		values[6] = round->clone_type; values[7] = round->clone_ifnum;
		values[8] = round->clone_length;
		memcpy(actual, round->actual, TABLE_LEN);
		spin_unlock_irqrestore(&result_lock, flags);
		seq_printf(seq, "round=%c submitted=%u originals=%u clones=%u original_valid=%u clone_valid=%u original_type=%u original_ifnum=%u clone_type=%u clone_ifnum=%u clone_length=%u host_equal=%u elapsed_ns=%llu\n",
			'A' + i, round->submitted, values[0], values[1], values[2], values[3],
			values[4], values[5], values[6], values[7], values[8], round->host_equal,
			(unsigned long long)round->elapsed_ns);
		for (offset = 0; offset < TABLE_LEN; offset += 64) {
			length = min_t(unsigned int, 64, TABLE_LEN - offset);
			seq_printf(seq, "clone_%c_offset%u=%*phN\n", 'A' + i, offset, length, actual + offset);
			seq_printf(seq, "host_%c_offset%u=%*phN\n", 'A' + i, offset, length, round->host_after + offset);
		}
	}
	seq_printf(seq, "probe_loaded=%u queued=%u snapshot_valid=%u started=%u accepted=%u returned=%u valid=%u disposed=%u qlen=%u drops=%u span_ns=%llu drained=%u pass=%u\n",
		probe_loaded, probe_queued, probe_snapshot_valid, probe_started, probe_accepted, probe_returns,
		probe_valid, probe_disposed, probe_qlen, probe_drops,
		(unsigned long long)(probe_last_ns - probe_first_ns),
		probe_operation ? qdx_packet_op_drained(probe_operation) : true, probe_pass);
	for (i = 0; i < min_t(u32, READ_ONCE(probe_returns), PROBE_PACKETS); i++)
		seq_printf(seq, "probe_return%u_id=%u\n", i, READ_ONCE(probe_order[i]));
 seq_printf(seq, "occupied_read=%u occupied_pass=%u node_valid=%u carrier_valid=%04x metadata_valid=%04x age_changed=%u age_restored=%u saved_age=%llu owned_error_kind=%u owned_error_index=%u owned_originals=%u owned_clones=%u owned_original_valid=%u owned_clone_valid=%u clone_data_mod4=%u\n",
  occupied_read, occupied_pass, owned_view.node_valid, owned_view.carrier_valid,
  owned_view.metadata_valid, age_changed, age_restored, (unsigned long long)saved_age,
  owned.kind, owned.index, owned.originals, owned.clones, owned.original_valid, owned.clone_valid, owned.clone_data_mod4);
 seq_printf(seq, "adopt_cpu=%u retiring=%u retired=%u retirement_bad=%u rebuild_started=%u accepted=%u imported=%u returned=%u valid=%u disposed=%u bad_owner=%u disposed_mask=%04x pass=%u span_ns=%llu prefix0_retained=%u prefix8_retained=%u\n",
  adopt_cpu, adopt_retiring, adopt_retired, adopt_retirement_bad, adopt_rebuild_started,
  adopt_accepted, adopt_imported, adopt_returns, adopt_valid, adopt_disposed,
  adopt_bad_owner, adopt_disposed_mask, adopt_pass, (unsigned long long)(adopt_last_ns - adopt_first_ns),
  !!owned_payload[0], !!owned_payload[8]);
 for (i = 0; i < 2; i++)
  seq_printf(seq, "adopt_bin%u_cpu_clock=%llu history=%36phN\n", i,
   (unsigned long long)adopt_clock[i], adopt_history[i]);
 for (i = 0; i < min_t(u32, READ_ONCE(adopt_returns), 14); i++)
  seq_printf(seq, "adopt_return%u_id=%u\n", i, READ_ONCE(adopt_order[i]));
 for (offset = 0; adopt_cpu && offset < TABLE_LEN; offset += 48) {
  seq_printf(seq, "adopt_before_offset%u=%48phN\n", offset, adopt_before + offset);
  seq_printf(seq, "adopt_after_offset%u=%48phN\n", offset, adopt_after + offset);
  seq_printf(seq, "adopt_cpu_offset%u=%48phN\n", offset, adopt_cpu_table + offset);
 }
 for (i = 0; i < owned_read_count; i++)
  seq_printf(seq, "owned_read%u_ns=%llu\n", i, (unsigned long long)owned_read_ns[i]);
 cost_rows = min_t(u32, owned_cost_count, ARRAY_SIZE(owned_cost));
 seq_printf(seq, "owned_cost_count=%u retained=%u\n", owned_cost_count, cost_rows);
 for (i = 0; i < cost_rows; i++) {
  cost_sequence = owned_cost_count - cost_rows + i;
  cost = &owned_cost[cost_sequence % ARRAY_SIZE(owned_cost)];
  seq_printf(seq, "owned_cost=%u kind=%u index=%u submit_ns=%llu original_ns=%llu clone_ns=%llu callbacks_ns=%llu close_table_ns=%llu operation_wait_ns=%llu total_ns=%llu\n",
   cost_sequence, cost->kind, cost->index,
   (unsigned long long)cost->submit_ns, (unsigned long long)cost->original_ns,
   (unsigned long long)cost->clone_ns, (unsigned long long)cost->callbacks_ns,
   (unsigned long long)cost->close_table_ns, (unsigned long long)cost->operation_wait_ns,
   (unsigned long long)cost->total_ns);
 }
 if (occupied_read) {
  for (offset = 0; offset < 280; offset += 56)
   seq_printf(seq, "owned_node_offset%u=%56phN\n", offset, owned_view.node + offset);
  for (i = 0; i < PROBE_PACKETS; i++) {
   seq_printf(seq, "owned_packet%u_carrier_address=%08x carrier=%64phN\n", i,
    owned_view.carrier_address[i], owned_view.carrier[i]);
   seq_printf(seq, "owned_packet%u_metadata_offset0=%48phN\n", i, owned_view.metadata[i]);
   seq_printf(seq, "owned_packet%u_metadata_offset48=%48phN\n", i, owned_view.metadata[i] + 48);
   if (owned_payload[i])
    seq_printf(seq, "owned_packet%u_payload=%64phN\n", i, owned_payload[i]->data);
  }
  for (i = 0; i < ARRAY_SIZE(owned_clock); i++) {
   seq_printf(seq, "owned_clock%u=%24phN\n", i, owned_clock[i]);
   seq_printf(seq, "clock_before%u=%24phN start_ns=%llu end_ns=%llu\n", i,
    clock_host_before[i], (unsigned long long)clock_host_before_ns[i][0],
    (unsigned long long)clock_host_before_ns[i][1]);
   seq_printf(seq, "clock_after%u=%24phN start_ns=%llu end_ns=%llu\n", i,
    clock_host_after[i], (unsigned long long)clock_host_after_ns[i][0],
    (unsigned long long)clock_host_after_ns[i][1]);
  }
  for (i = 0; i < ARRAY_SIZE(clock_host_poll); i++)
   seq_printf(seq, "clock_poll%u=%24phN start_ns=%llu end_ns=%llu\n", i,
    clock_host_poll[i], (unsigned long long)clock_host_poll_ns[i][0],
    (unsigned long long)clock_host_poll_ns[i][1]);
  seq_printf(seq, "age_changed_offset0=%48phN\nage_changed_offset48=%48phN\n", age_changed_bytes, age_changed_bytes + 48);
  seq_printf(seq, "age_restored_offset0=%48phN\nage_restored_offset48=%48phN\n", age_restored_bytes, age_restored_bytes + 48);
 }
 seq_printf(seq, "bf_mode=%u ready=%u cut=%u allocated=%x links=%x trigger_accepted=%u trigger_returned=%u trigger_valid=%u trigger_disposed=%u request=%u cpu_owned=%u cpu_selected=%u retired=%u pass=%u snapshots=%u retirement_attempts=%u\n",
  bf_mode,bf_ready,bf_cut,bf_allocated,bf_links,bf_trigger_accepted,bf_trigger_returns,
  bf_trigger_valid,bf_trigger_disposed,!!bf_request,bf_cpu_owned,bf_cpu_selected,bf_retired,
  bf_pass,bf_snapshot_attempts,bf_retirement_attempts);
 seq_printf(seq, "bf_trigger_queued_before_open=%u\n", bf_trigger_queued_before_open);
 seq_printf(seq, "bf_credit_before=%lld credit_after=%lld increment=%llu deficit_before=%d deficit_after=%d cut_ms=%llu retire_ms=%llu cpu_pending_ms=%llu\n",
  (long long)bf_credit_before,(long long)bf_credit_after,(unsigned long long)bf_credit_delta,
  bf_deficit_before,bf_deficit_after,(unsigned long long)bf_cut_clock,
  (unsigned long long)bf_retire_clock,(unsigned long long)bf_cpu_pending_ms);
 seq_printf(seq, "bf_reverse_rebuilt=%u pinned=%u started=%u rearmed=%u data_done=%u timer_joined=%u private_returned=%u private_valid=%u private_disposed=%u private_ns=%llu due_ms=%llu event_observed_ms=%llu successor_ms=%llu callback_reference=%llu callback_deadline=%llu deficit=%d\n",
  bf_rebuild_ready,bf_lifetime_pinned,bf_rearm_started,bf_rearm_pass,bf_reverse_done,
  bf_reverse_retired,bf_private_returned,bf_private_valid,bf_private_disposed,
  (unsigned long long)bf_private_ns,(unsigned long long)bf_event_due_ms,
  (unsigned long long)bf_event_observed_ms,(unsigned long long)bf_successor_ms,
  (unsigned long long)bf_callback_reference,(unsigned long long)bf_callback_deadline,
  bf_import_deficit);
 seq_printf(seq, "bf_positive_test=%u pass=%u credit=%lld reference=%llu activation_reference=%llu\n",
  bf_positive_test, bf_positive_pass, (long long)bf_positive_credit,
  (unsigned long long)bf_positive_reference,
  (unsigned long long)bf_positive_activation_reference);
 seq_printf(seq, "bf_positive_service_pass=%u packet_cost=%lld credit=%lld reference=%llu refill_bound=%llu\n",
  bf_positive_service_pass, (long long)bf_positive_packet_cost,
  (long long)bf_positive_service_credit, (unsigned long long)bf_positive_service_reference,
  (unsigned long long)bf_positive_service_refill);
 if (bf_mode) {
  seq_printf(seq, "bf_current_account credit=%lld reference=%llu cached_frequency=%u timer_queued=%u\n",
   (long long)(s64)get_unaligned_le64(bf_account + 292),
   (unsigned long long)get_unaligned_le64(bf_account + 300),
   get_unaligned_le32(owned_view.bf_group + 164),
   !!(get_unaligned_le32(bf_timer + 24) & 2));
  seq_printf(seq, "bf_epoch_before=%20phN after=%20phN frequency_before=%8phN after=%8phN notifier=%16phN timer=%32phN saved_timer=%32phN\n",
   bf_epoch_before,bf_epoch_after,bf_frequency[0],bf_frequency[1],bf_notifier,bf_timer,bf_saved_timer);
  seq_printf(seq,"bf_reverse_after_timer=%32phN\n",bf_after_event_timer);
  for (offset=0;offset<312;offset+=24) {
   seq_printf(seq,"bf_import_account_offset%u=%24phN\n",offset,bf_import_account+offset);
   seq_printf(seq,"bf_after_event_account_offset%u=%24phN\n",offset,bf_after_event_account+offset);
   seq_printf(seq,"bf_positive_service_account_offset%u=%24phN\n",offset,bf_positive_service_account+offset);
   seq_printf(seq,"bf_saved_account_offset%u=%24phN\n",offset,bf_saved_account+offset);
   seq_printf(seq,"bf_retired_account_offset%u=%24phN\n",offset,bf_retired_account+offset);
   seq_printf(seq,"bf_cpu_account_offset%u=%24phN\n",offset,bf_cpu_account+offset);
  }
  for (offset=0;offset<232;offset+=8)
   seq_printf(seq,"bf_group_offset%u saved=%8phN current=%8phN cpu=%8phN\n",offset,bf_saved_group+offset,owned_view.bf_group+offset,bf_cpu_group+offset);
  for (offset=0;offset<200;offset+=8)
   seq_printf(seq,"bf_parent_offset%u saved=%8phN current=%8phN\n",offset,bf_saved_parent+offset,owned_view.bf_parent+offset);
 }
	mutex_unlock(&state_lock);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(state_status);

static ssize_t state_control_write(struct file *file, const char __user *buffer,
	size_t count, loff_t *position)
{
	char command[24];
	int error;

	if (!allow_writes)
		return -EPERM;
	if (!count || count >= sizeof(command))
		return -EINVAL;
	if (copy_from_user(command, buffer, count))
		return -EFAULT;
	command[count] = 0;
	strim(command);
	mutex_lock(&state_lock);
	if (!strcmp(command, "prepare")) error = state_prepare();
	else if (!strcmp(command, "read-a")) error = state_read(0);
	else if (!strcmp(command, "write-b")) error = state_write_word(false);
	else if (!strcmp(command, "read-b")) error = state_read(1);
	else if (!strcmp(command, "probe-load")) error = state_probe_load();
 else if (!strcmp(command, "bf-stage")) error = state_bf_stage();
 else if (!strcmp(command, "bf-account-run")) error = state_bf_pair_run();
 else if (!strcmp(command, "bf-account-close")) error = state_bf_pair_close();
 else if (!strcmp(command, "bf-adopt")) error = state_bf_adopt();
 else if (!strcmp(command, "bf-rebuild")) error = state_bf_rebuild();
 else if (!strcmp(command, "bf-rearm")) error = state_bf_rearm();
 else if (!strcmp(command, "bf-positive-rearm")) error = state_bf_positive_rearm();
 else if (!strcmp(command, "bf-serve")) error = state_bf_serve();
	else if (!strcmp(command, "probe-serve")) error = state_probe_serve();
	else if (!strcmp(command, "occupied-read")) error = state_occupied_read();
 else if (!strcmp(command, "adopt-cpu")) error = bf_mode ? -EPERM : state_adopt_cpu();
 else if (!strcmp(command, "adopt-rebuild")) error = state_adopt_rebuild();
 else if (!strcmp(command, "adopt-serve")) error = state_adopt_serve();
	else if (!strcmp(command, "age-check")) error = state_age_check();
	else if (!strcmp(command, "age-restore")) error = state_age_restore();
	else if (!strcmp(command, "restore-word")) error = state_write_word(true);
	else if (!strcmp(command, "read-c")) error = state_read(2);
	else if (!strcmp(command, "poll")) error = bf_request ?
  state_bf_command(bf_command_pending, bf_tag_pending, bf_child_pending) :
  request ? state_command(pending, false, 0) : 0;
	else if (!strcmp(command, "stop")) {
		closed = true;
		if (operation) qdx_packet_op_close(operation);
		error = 0;
	} else if (!strcmp(command, "restore")) error = state_restore();
	else error = -EINVAL;
	last_error = error;
	mutex_unlock(&state_lock);
	return error ?: count;
}
static const struct file_operations state_control_fops = { .owner = THIS_MODULE, .write = state_control_write };

static int __init state_init(void)
{
	struct dentry *entry;
	unsigned int i;

 if ((bf_account_control && !bf_account_test) || (bf_account_test && bf_positive_test) ||
     (bf_native_frequency_sync && !bf_account_test))
  return -EINVAL;
	for (i = 0; i < ARRAY_SIZE(rounds); i++) {
		init_completion(&rounds[i].original_done);
		init_completion(&rounds[i].clone_done);
	}
	directory = debugfs_create_dir("qdx_mirror_state_diag", NULL);
	if (IS_ERR_OR_NULL(directory)) return -ENOMEM;
	entry = debugfs_create_file("control", 0200, directory, NULL, &state_control_fops);
	if (IS_ERR_OR_NULL(entry)) goto fail;
	entry = debugfs_create_file("status", 0400, directory, NULL, &state_status_fops);
	if (IS_ERR_OR_NULL(entry)) goto fail;
	return 0;
fail:
	debugfs_remove_recursive(directory);
	return -ENOMEM;
}
static void __exit state_exit(void)
{
	WARN_ON(pinned || request || operation || probe_operation || receiver || table || igs || mirror);
	debugfs_remove_recursive(directory);
}
module_init(state_init);
module_exit(state_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Isolated owned two-bin FQ table cache transfer discriminator");
