// SPDX-License-Identifier: GPL-2.0-only
/* Isolated, never-published two-bin FQ cache transfer discriminator. */
#include <linux/build_bug.h>
#include <linux/completion.h>
#include <linux/debugfs.h>
#include <linux/dma-mapping.h>
#include <linux/etherdevice.h>
#include <linux/jiffies.h>
#include <linux/iopoll.h>
#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/qdx.h>
#include <linux/seq_file.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/unaligned.h>
#include <net/net_namespace.h>

#define TABLE_LEN 144
#define TABLE_TAG 0x6d010000U
#define COPY_TAG 0x4d54424cU
#define WAIT_MS 3000

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
enum step { NONE, ASSIGN, ALLOC, MEMORY, CONFIG, FREE, UNASSIGN,
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
static struct table_round rounds[3];
static u32 igs_ifnum = U32_MAX, mirror_ifnum = U32_MAX, active = U32_MAX;
static u32 shaper, memory_size, table_address, unexpected_clones;
static bool pinned, assigned, allocated, memory_checked, configured;
static bool mirror_configured, next_set, enabled, closed, fault;
static bool igs_retired, mirror_retired, word_changed, word_restored;
static int last_error;

static int state_command(enum step step, bool submit, unsigned int wait_ms)
{
	struct qdx_endpoint *endpoint = igs;
	struct table_config message = {};
	struct mirror_config copy = { cpu_to_le32(1), cpu_to_le16(TABLE_LEN), 0 };
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

static void state_clone(void *owner, struct sk_buff *skb,
	const struct qdx_rx_meta *meta, struct napi_struct *napi)
{
	struct table_round *round;
	unsigned long flags;
	u32 index = READ_ONCE(active);

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
		round->clone_valid = !memcmp(round->actual, round->expected, TABLE_LEN);
	}
	spin_unlock_irqrestore(&result_lock, flags);
	dev_kfree_skb_any(skb);
	complete_all(&round->clone_done);
}
static const struct qdx_receive_ops state_receive_ops = { .packet = state_clone };

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
	if ((index == 1 && !word_changed) || (index == 2 && !word_restored))
		return -EPERM;
	for (bin = 0; bin < 2; bin++) {
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

	if (!table || closed || request || fault || !configured ||
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

static int state_restore(void)
{
	unsigned int i;
	int error;

	if (!pinned)
		return 0;
	closed = true;
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
	qdx_packet_op_put(operation);
	operation = NULL;
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
	WARN_ON(pinned || request || operation || receiver || table || igs || mirror);
	debugfs_remove_recursive(directory);
}
module_init(state_init);
module_exit(state_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Isolated owned two-bin FQ table cache transfer discriminator");
