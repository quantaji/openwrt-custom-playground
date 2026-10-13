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
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/qdx.h>
#include <linux/qdx_diag_fq.h>
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
 u64 elapsed_ns;
 u8 bytes[QDX_DIAG_FQ_NODE_BYTES];
 struct sk_buff *payload;
};
static struct owned_round owned;
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

	if (fault || (request && pending != step))
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
 owned.originals++;
 owned.original_valid = !original && !returned && meta &&
  meta->ifnum == READ_ONCE(mirror_ifnum) && meta->type == QDX_RECEIVE_PACKET;
 complete_all(&owned.original_done);
}

static void state_owned_clone(struct sk_buff *skb, const struct qdx_rx_meta *meta)
{
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
 u64 start;
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
 qdx_packet_op_close(operation);
 error = read_poll_timeout(qdx_diag_fq_table_idle, idle, idle, 10,
  WAIT_MS * 1000, false, table);
 if (!error)
  error = read_poll_timeout(qdx_packet_op_drained, drained, drained, 10,
   WAIT_MS * 1000, false, operation);
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
 mirror_copy_size = 280;
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
     get_unaligned_le32(owned_view.node + 16) != TABLE_TAG || owned_view.node[24] ||
     get_unaligned_le32(owned_view.node + 220) != table_address ||
     get_unaligned_le16(owned_view.node + 264) != 2 ||
     get_unaligned_le16(owned_view.node + 266) != 1 ||
     get_unaligned_le32(owned_view.node + 228) != table_address ||
     get_unaligned_le32(owned_view.node + 232) != table_address + 72 ||
     get_unaligned_le32(owned_view.node + 236) != node + 236 ||
     get_unaligned_le32(owned_view.node + 240) != node + 236)
  return -EBADMSG;
 owned_view.node_valid = true;
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

 if (!occupied_pass || !age_restored || probe_started || adopt_cpu || request ||
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

 if (!adopt_cpu || adopt_rebuild_started || adopt_retiring || probe_started ||
     closed || fault || request || operation || !qdx_diag_fq_table_idle(table))
  return -EPERM;
 adopt_retiring = true;
 error = state_command(FREE, true, WAIT_MS);
 if (error)
  return error;
 if (!wait_for_completion_timeout(&adopt_done, msecs_to_jiffies(WAIT_MS)))
  return -ETIMEDOUT;
 error = read_poll_timeout(qdx_packet_op_drained, drained, drained, 10,
  WAIT_MS * 1000, false, probe_operation);
 if (error)
  return error;
 synchronize_net();
 if (adopt_retired != PROBE_PACKETS || adopt_retirement_bad)
  return -EBADMSG;
 qdx_packet_op_put(probe_operation); probe_operation = NULL;
 adopt_retiring = false;
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

static int state_adopt_serve(void)
{
 static const u32 expected[12] = { 2, 3, 4, 10, 11, 5, 6, 7, 12, 13, 14, 15 };
 unsigned int i;
 unsigned long deadline;
 u64 now;
 bool drained;
 int error;

 if (!adopt_imported || probe_started || request || closed || fault || operation ||
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

	if (!probe_snapshot_valid || probe_started || request || closed || fault || adopt_cpu ||
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
	if (allocated) {
		error = state_command(FREE, true, WAIT_MS);
		if (error)
			return error;
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
	unsigned int i, offset, length;
	unsigned long flags;

	mutex_lock(&state_lock);
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
	else if (!strcmp(command, "probe-serve")) error = state_probe_serve();
	else if (!strcmp(command, "occupied-read")) error = state_occupied_read();
 else if (!strcmp(command, "adopt-cpu")) error = state_adopt_cpu();
 else if (!strcmp(command, "adopt-rebuild")) error = state_adopt_rebuild();
 else if (!strcmp(command, "adopt-serve")) error = state_adopt_serve();
	else if (!strcmp(command, "age-check")) error = state_age_check();
	else if (!strcmp(command, "age-restore")) error = state_age_restore();
	else if (!strcmp(command, "restore-word")) error = state_write_word(true);
	else if (!strcmp(command, "read-c")) error = state_read(2);
	else if (!strcmp(command, "poll")) error = request ? state_command(pending, false, 0) : 0;
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
