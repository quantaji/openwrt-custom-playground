// SPDX-License-Identifier: GPL-2.0-only
/* Isolated owned-buffer NSS11.4 MIRROR A/B cache discriminator.
 * Exactly one host skb, two finite sends, no raw addresses or queue mutation.
 */
#include <linux/build_bug.h>
#include <linux/completion.h>
#include <linux/debugfs.h>
#include <linux/etherdevice.h>
#include <linux/jiffies.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/qdx.h>
#include <linux/seq_file.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <net/net_namespace.h>

#define COPY_LEN 256
#define COPY_TAG 0x4d435059U
#define COPY_WAIT_MS 3000
#define MIRROR_TYPE 65
#define N2H_IFNUM 156

/* Wire layout from Qualcomm exports/nss_mirror.h.
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
struct mirror_config { __le32 point; __le16 size, offset; };
static_assert(sizeof(struct mirror_config) == 8);
enum copy_command { COPY_CONFIG = 0, COPY_ENABLE = 1, COPY_DISABLE = 2,
	COPY_NEXT = 3, COPY_RESET_NEXT = 4, COPY_NONE = 255 };
struct copy_round {
	struct completion original_done, clone_done;
	bool submitted, original_valid, clone_valid;
	u32 original_count, clone_count, original_ifnum, original_type;
	u32 clone_ifnum, clone_type, original_length, clone_length;
	u8 expected[COPY_LEN], actual[COPY_LEN];
};

static bool allow_writes;
module_param(allow_writes, bool, 0400);
static DEFINE_MUTEX(copy_lock);
static DEFINE_SPINLOCK(result_lock);
static struct dentry *directory;
static struct net_device *port;
static struct qdx_service *service;
static struct qdx_endpoint *endpoint;
static struct qdx_receiver *receiver;
static struct qdx_packet_op *operation;
static struct qdx_request *request;
static struct qdx_result last_result;
static enum copy_command pending = COPY_NONE;
static struct copy_round rounds[2];
static struct sk_buff *owned;
static u8 *initial_head, *initial_data;
static u32 ifnum = U32_MAX, active = U32_MAX, unexpected_clones;
static bool pinned, configured, enabled, next_set, closed, retired, fault;
static int last_error;

/* Keep the exact command/request after an unknown result. A retry polls that
 * request; it never publishes a second command while the first is unsettled.
 */
static int copy_command(enum copy_command command, bool submit, unsigned int wait_ms)
{
	struct mirror_config config = { cpu_to_le32(1), cpu_to_le16(COPY_LEN), 0 };
	__le32 next = cpu_to_le32(N2H_IFNUM);
	struct qdx_reply_bounds bounds;
	u8 reply[sizeof(config)] = {};
	const void *payload = NULL;
	size_t length = 0;
	int error;

	if (fault)
		return -EPROTO;
	if (request && pending != command)
		return -EBUSY;
	if (command == COPY_CONFIG) {
		payload = &config;
		length = sizeof(config);
	} else if (command == COPY_NEXT) {
		payload = &next;
		length = sizeof(next);
	} else if (command != COPY_ENABLE && command != COPY_DISABLE &&
		   command != COPY_RESET_NEXT) {
		return -EINVAL;
	}
	if (!request) {
		if (!submit)
			return 0;
		bounds = (struct qdx_reply_bounds) { length, length, length };
		request = qdx_command_submit(endpoint, command, payload, length, &bounds, NULL);
		if (IS_ERR(request)) {
			error = PTR_ERR(request);
			request = NULL;
			return error;
		}
		pending = command;
	}
	error = qdx_request_wait(request, jiffies + msecs_to_jiffies(wait_ms),
		&last_result, reply, sizeof(reply));
	if (last_result.outcome == QDX_UNKNOWN && !last_result.exposure_ended)
		return error ?: -EINPROGRESS;
	if (last_result.outcome == QDX_ACK) {
		/* Actual RX storage can include padding. The common header declares
		 * the protocol payload, which must fit that returned storage.
		 */
		if (last_result.declared_len != length ||
		    last_result.received_len < last_result.declared_len) {
			fault = true;
			return -EPROTO;
		}
		error = 0;
		if (command == COPY_CONFIG)
			configured = true;
		else if (command == COPY_ENABLE)
			enabled = true;
		else if (command == COPY_DISABLE)
			enabled = false;
		else if (command == COPY_NEXT)
			next_set = true;
		else if (command == COPY_RESET_NEXT)
			next_set = false;
	} else {
		error = last_result.error ?: error ?: -EIO;
	}
	qdx_request_put(request);
	request = NULL;
	pending = COPY_NONE;
	return error;
}

static void copy_original(void *owner, struct sk_buff *original,
	struct sk_buff *returned, const struct qdx_rx_meta *meta, struct napi_struct *napi)
{
	struct copy_round *round = owner;
	unsigned long flags;
	bool identity = returned && returned == original && original == READ_ONCE(owned);
	bool valid = identity && returned->head == initial_head &&
		returned->data == initial_data && returned->len == COPY_LEN &&
		meta && meta->ifnum == READ_ONCE(ifnum) && meta->type == QDX_RECEIVE_PACKET &&
		!memcmp(returned->data, round->expected, COPY_LEN);

	spin_lock_irqsave(&result_lock, flags);
	round->original_count++;
	round->original_valid = valid;
	round->original_ifnum = meta ? meta->ifnum : U32_MAX;
	round->original_type = meta ? meta->type : U32_MAX;
	round->original_length = returned ? returned->len : 0;
	/* NULL means driver disposal. A returned skb transfers its ownership to
	 * this callback, even if a metadata check failed. Never leave a dangling
	 * original pointer after NULL disposal.
	 */
	WRITE_ONCE(owned, returned);
	spin_unlock_irqrestore(&result_lock, flags);
	complete_all(&round->original_done);
}

static void copy_clone(void *owner, struct sk_buff *skb,
	const struct qdx_rx_meta *meta, struct napi_struct *napi)
{
	struct copy_round *round;
	unsigned long flags;
	u32 index = READ_ONCE(active);
	bool valid;

	if (index >= ARRAY_SIZE(rounds)) {
		spin_lock_irqsave(&result_lock, flags);
		unexpected_clones++;
		spin_unlock_irqrestore(&result_lock, flags);
		dev_kfree_skb_any(skb);
		return;
	}
	round = &rounds[index];
	valid = meta && meta->ifnum == READ_ONCE(ifnum) &&
		meta->type == QDX_RECEIVE_PACKET && skb->len == COPY_LEN &&
		!skb_is_nonlinear(skb) && !memcmp(skb->data, round->expected, COPY_LEN);
	spin_lock_irqsave(&result_lock, flags);
	round->clone_count++;
	round->clone_valid = valid;
	round->clone_ifnum = meta ? meta->ifnum : U32_MAX;
	round->clone_type = meta ? meta->type : U32_MAX;
	round->clone_length = skb->len;
	if (skb->len == COPY_LEN && !skb_is_nonlinear(skb))
		memcpy(round->actual, skb->data, COPY_LEN);
	spin_unlock_irqrestore(&result_lock, flags);
	dev_kfree_skb_any(skb);
	complete_all(&round->clone_done);
}
static const struct qdx_receive_ops copy_receive_ops = { .packet = copy_clone };

static int copy_prepare(void)
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
	if (!service) {
		service = qdx_service_get(port, QDX_SERVICE_MIRROR);
		if (IS_ERR(service)) {
			error = PTR_ERR(service);
			service = NULL;
			return error;
		}
	}
	if (qdx_service_state(service) != QDX_AVAILABLE)
		return -ENODEV;
	if (!endpoint) {
		endpoint = qdx_endpoint_alloc(service, MIRROR_TYPE);
		if (IS_ERR(endpoint)) {
			error = PTR_ERR(endpoint);
			endpoint = NULL;
			return error;
		}
	}
	error = qdx_endpoint_wait(endpoint, jiffies + msecs_to_jiffies(COPY_WAIT_MS));
	if (error)
		return error;
	error = qdx_endpoint_ifnum(endpoint, &ifnum);
	if (error)
		return error;
	if (!receiver) {
		receiver = qdx_endpoint_receive_register(endpoint, QDX_RECEIVE_PACKET,
			&owner, &copy_receive_ops);
		if (IS_ERR(receiver)) {
			error = PTR_ERR(receiver);
			receiver = NULL;
			return error;
		}
	}
	if (request) {
		error = copy_command(pending, false, COPY_WAIT_MS);
		if (error)
			return error;
	}
	if (!configured) {
		error = copy_command(COPY_CONFIG, true, COPY_WAIT_MS);
		if (error)
			return error;
	}
	if (!next_set) {
		error = copy_command(COPY_NEXT, true, COPY_WAIT_MS);
		if (error)
			return error;
	}
	if (!enabled) {
		error = copy_command(COPY_ENABLE, true, COPY_WAIT_MS);
		if (error)
			return error;
	}
	if (!operation) {
		operation = qdx_packet_op_prepare(endpoint, COPY_TAG, QDX_RECEIVE_PACKET);
		if (IS_ERR(operation)) {
			error = PTR_ERR(operation);
			operation = NULL;
			return error;
		}
	}
	return 0;
}

static int copy_send(unsigned int index)
{
	struct copy_round *round = &rounds[index];
	struct qdx_packet_recipient recipient = {
		.owner = { .module = THIS_MODULE, .object = round },
		.returned = copy_original,
	};
	struct qdx_ready ready;
	struct sk_buff *skb;
	unsigned int i;

	if (!enabled || !next_set || !operation || closed || request || fault)
		return -EINVAL;
	if (round->submitted)
		return -EALREADY;
	if (index && (!completion_done(&rounds[0].original_done) ||
	    !completion_done(&rounds[0].clone_done) || !rounds[0].original_valid ||
	    !rounds[0].clone_valid || rounds[0].original_count != 1 || rounds[0].clone_count != 1))
		return -EAGAIN;
	if (!index && !owned) {
		owned = alloc_skb(130 + COPY_LEN, GFP_KERNEL);
		if (!owned)
			return -ENOMEM;
		skb_reserve(owned, 130);
		skb_put_zero(owned, COPY_LEN);
		initial_head = owned->head;
		initial_data = owned->data;
	}
	skb = owned;
	if (!skb || skb->head != initial_head || skb->data != initial_data ||
	    skb->len != COPY_LEN || skb_shared(skb) || skb_cloned(skb))
		return -ESTALE;
	for (i = 0; i < COPY_LEN; i++)
		skb->data[i] = (u8)((i * 17 + (index ? 0xa7 : 0x39)) ^ (i >> 2));
	skb->dev = port;
	skb->protocol = htons(0x88b5);
	skb_reset_mac_header(skb);
	memcpy(round->expected, skb->data, COPY_LEN);
	WRITE_ONCE(active, index);
	ready = qdx_packet_op_submit(operation, skb, &recipient);
	if (ready.status != QDX_ACCEPTED)
		return ready.error ?: -EAGAIN;
	round->submitted = true;
	if (!wait_for_completion_timeout(&round->original_done, msecs_to_jiffies(COPY_WAIT_MS)))
		return -ETIMEDOUT;
	if (!wait_for_completion_timeout(&round->clone_done, msecs_to_jiffies(COPY_WAIT_MS)))
		return -ETIMEDOUT;
	return READ_ONCE(round->original_valid) && READ_ONCE(round->clone_valid) &&
		round->original_count == 1 && round->clone_count == 1 ? 0 : -EBADMSG;
}

static int copy_restore(void)
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
	if (request) {
		error = copy_command(pending, false, COPY_WAIT_MS);
		if (request || error)
			return error;
	}
	if (enabled) {
		error = copy_command(COPY_DISABLE, true, COPY_WAIT_MS);
		if (error)
			return error;
	}
	if (next_set) {
		error = copy_command(COPY_RESET_NEXT, true, COPY_WAIT_MS);
		if (error)
			return error;
	}
	if (endpoint && !retired) {
		/* Existing API retires one dynamic endpoint and joins its receive
		 * prefix. Any fatal timeout in that shared API is a failed diagnostic,
		 * never evidence for an NSS-restart handover.
		 */
		error = qdx_endpoint_wait(endpoint, jiffies);
		if (error)
			return error;
		error = qdx_endpoint_retire(endpoint);
		if (error)
			return error;
		retired = true;
	}
	if (receiver) {
		error = qdx_endpoint_receive_unregister(receiver);
		if (error)
			return error;
		receiver = NULL;
	}
	qdx_packet_op_put(operation);
	operation = NULL;
	qdx_endpoint_put(endpoint);
	endpoint = NULL;
	qdx_service_put(service);
	service = NULL;
	if (port)
		dev_put(port);
	port = NULL;
	kfree_skb(owned);
	owned = NULL;
	pinned = false;
	module_put(THIS_MODULE);
	return 0;
}

static int copy_status_show(struct seq_file *seq, void *unused)
{
	struct copy_round *round;
	u8 actual[COPY_LEN];
	u32 values[10], owned_present, same_head, same_data, unexpected;
	unsigned long flags;
	unsigned int i, offset;

	mutex_lock(&copy_lock);
	spin_lock_irqsave(&result_lock, flags);
	owned_present = !!owned;
	same_head = owned && owned->head == initial_head;
	same_data = owned && owned->data == initial_data;
	unexpected = unexpected_clones;
	spin_unlock_irqrestore(&result_lock, flags);
	seq_printf(seq, "allow_writes=%u pinned=%u configured=%u enabled=%u next_set=%u closed=%u retired=%u fault=%u ifnum=%u active=%u pending=%u error=%d unexpected_clones=%u owned=%u same_head=%u same_data=%u drained=%u\n",
		allow_writes, pinned, configured, enabled, next_set, closed, retired, fault,
		ifnum, active, pending, last_error, unexpected, owned_present,
		same_head, same_data,
		operation ? qdx_packet_op_drained(operation) : true);
	seq_printf(seq, "request_id=%llu outcome=%u error=%d firmware_error=%u published=%u exposure_ended=%u received=%zu declared=%zu\n",
		(unsigned long long)last_result.id, last_result.outcome, last_result.error,
		last_result.firmware_error, last_result.published, last_result.exposure_ended,
		last_result.received_len, last_result.declared_len);
	for (i = 0; i < ARRAY_SIZE(rounds); i++) {
		round = &rounds[i];
		spin_lock_irqsave(&result_lock, flags);
		values[0] = round->original_count;
		values[1] = round->clone_count;
		values[2] = round->original_valid;
		values[3] = round->clone_valid;
		values[4] = round->original_ifnum;
		values[5] = round->original_type;
		values[6] = round->original_length;
		values[7] = round->clone_ifnum;
		values[8] = round->clone_type;
		values[9] = round->clone_length;
		memcpy(actual, round->actual, sizeof(actual));
		spin_unlock_irqrestore(&result_lock, flags);
		seq_printf(seq, "round=%c submitted=%u original_count=%u clone_count=%u original_valid=%u clone_valid=%u original_ifnum=%u original_type=%u original_length=%u clone_ifnum=%u clone_type=%u clone_length=%u\n",
			'A' + i, round->submitted, values[0], values[1], values[2], values[3],
			values[4], values[5], values[6], values[7], values[8], values[9]);
		for (offset = 0; offset < COPY_LEN; offset += 64)
			seq_printf(seq, "clone_%c_offset%u=%*phN\n", 'A' + i,
				offset, 64, actual + offset);
	}
	mutex_unlock(&copy_lock);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(copy_status);

static ssize_t copy_control_write(struct file *file, const char __user *buffer,
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
	mutex_lock(&copy_lock);
	if (!strcmp(command, "prepare"))
		error = copy_prepare();
	else if (!strcmp(command, "send-a"))
		error = copy_send(0);
	else if (!strcmp(command, "send-b"))
		error = copy_send(1);
	else if (!strcmp(command, "poll"))
		error = request ? copy_command(pending, false, 0) : 0;
	else if (!strcmp(command, "stop")) {
		closed = true;
		if (operation)
			qdx_packet_op_close(operation);
		error = 0;
	} else if (!strcmp(command, "restore")) {
		error = copy_restore();
	} else {
		error = -EINVAL;
	}
	last_error = error;
	mutex_unlock(&copy_lock);
	return error ?: count;
}
static const struct file_operations copy_control_fops = {
	.owner = THIS_MODULE, .write = copy_control_write,
};

static int __init copy_init(void)
{
	struct dentry *entry;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(rounds); i++) {
		init_completion(&rounds[i].original_done);
		init_completion(&rounds[i].clone_done);
	}
	directory = debugfs_create_dir("qdx_mirror_copy_diag", NULL);
	if (IS_ERR_OR_NULL(directory))
		return -ENOMEM;
	entry = debugfs_create_file("control", 0200, directory, NULL, &copy_control_fops);
	if (IS_ERR_OR_NULL(entry))
		goto fail;
	entry = debugfs_create_file("status", 0400, directory, NULL, &copy_status_fops);
	if (IS_ERR_OR_NULL(entry))
		goto fail;
	return 0;
fail:
	debugfs_remove_recursive(directory);
	return -ENOMEM;
}
static void __exit copy_exit(void)
{
	WARN_ON(pinned || request || operation || receiver || endpoint || owned);
	debugfs_remove_recursive(directory);
}
module_init(copy_init);
module_exit(copy_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Isolated owned-buffer MIRROR clone and A/B cache discriminator");
