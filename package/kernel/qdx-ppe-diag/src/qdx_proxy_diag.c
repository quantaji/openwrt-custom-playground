// SPDX-License-Identifier: GPL-2.0-only
/* Isolated NSS11.4 PPE proxy witness. Not a production interface.
 * Uses a firmware-created GENERIC_REDIR_N2H/H2N pair(types32/33),
 * retaining real lan3 for MAC/instance identity. No physical shaper is changed.
 * External preconditions: no other proxy4/5 user; CPU queue2 is exclusive.
 * Only SC4/source-profile0 selector is written by this module. NSS PPE_SN
 * configuration separately resets the selected queue's accounting rows.
 */
#include <linux/build_bug.h>
#include <linux/completion.h>
#include <linux/debugfs.h>
#include <linux/etherdevice.h>
#include <linux/io.h>
#include <linux/jiffies.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/qdx.h>
#include <linux/seq_file.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <net/net_namespace.h>

#define WAIT_MS 3000
#define PORT_IFNUM 3
#define REDIR_N2H 32
#define REDIR_H2N 33
#define REDIR_CONFIG 10000
#define PROXY_TAG 0x71010000U
#define FRAME_LEN 96
#define SC4_MAP 0x818040
#define SC5_MAP 0x818050
#define PRIVATE_MAP 0x20U /* UC base2, offset profile0 */
#define Q2_HEAD 0x86c020
#define Q2_PENDING 0x84e020
#define Q2_PTX 0x024020
#define RX0_PROD 0x39004
#define RX0_CONS 0x39008

/* Wire layout: matched exports/nss_if.h and exports/nss_shaper.h. Only the
 * actual union members used here are named; reserved space preserves116B ABI.
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
struct proxy_config {
	__le32 request, response;
	union {
		struct { __le32 type, tag; } allocate;
		__le32 tag;
		struct {
			__le32 tag, type;
			__le16 ucast_base, ucast_offset, mcast_base, mcast_offset;
			u8 port, reserved;
			__le16 limit;
		} node;
		u8 reserved[108];
	} data;
};
static_assert(sizeof(struct proxy_config) == 116);
static_assert(offsetof(struct proxy_config, data.node.limit) == 26);

struct proxy_redirect_config {
	__le32 flags, sibling, nexthop;
	u8 mac[ETH_ALEN], reserved[2];
};
static_assert(sizeof(struct proxy_redirect_config) == 20);

enum proxy_step { STEP_NONE, STEP_N2H_CONFIG, STEP_H2N_CONFIG,
	STEP_ASSIGN, STEP_ALLOC, STEP_ROOT,
	STEP_CONFIG, STEP_FREE, STEP_UNASSIGN };
struct proxy_marker {
	struct completion done;
	struct sk_buff *original;
	bool submitted, returned, witnessed, valid;
	u8 id, expected[FRAME_LEN];
	u32 ifnum, type, length, service;
};

static bool allow_writes, fixture_reserved;
module_param(allow_writes, bool, 0400);
module_param(fixture_reserved, bool, 0400);
MODULE_PARM_DESC(fixture_reserved, "Operator confirms exclusive SC4/5 manager and unused CPUq2; actual lan3 retained; default false");
static DEFINE_MUTEX(proxy_lock);
static DEFINE_SPINLOCK(marker_lock);
static struct dentry *directory;
static void __iomem *ppe, *edma;
static struct net_device *port;
static struct qdx_service *service;
static struct qdx_endpoint *endpoint, *sibling;
static u32 endpoint_ifnum = U32_MAX, sibling_ifnum = U32_MAX;
static bool n2h_configured, h2n_configured, endpoint_retired, sibling_retired;
static struct qdx_packet_op *operation;
static struct qdx_request *request;
static enum proxy_step pending_step;
static struct qdx_result last_result;
static struct proxy_marker markers[2];
static bool pinned, mapped, assigned, allocated, rooted, configured, closed;
static bool protocol_fault;
static u32 shaper_id, saved_map, saved_sc5, saved_services[2][5];
static u32 saved_l0, saved_l0_port, saved_route;
static int last_error;
static u32 last_shaper_response;

/* Reading entries in word order matches the existing HPPE accessor contract. */
static void proxy_row_read(u32 offset, u32 *words, unsigned int count)
{
	unsigned int i;

	for (i = 0; i < count; i++)
		words[i] = readl(ppe + offset + 4 * i);
}

static void proxy_service_read(unsigned int code, u32 *row)
{
	row[0] = readl(ppe + 0x15000 + 16 * code);
	row[1] = readl(ppe + 0x15004 + 16 * code);
	row[2] = readl(ppe + 0x64000 + 16 * code);
	row[3] = readl(ppe + 0x2c000 + 8 * code);
	row[4] = readl(ppe + 0x2c004 + 8 * code);
}

static int proxy_fixture_check(bool empty)
{
	u32 row[5], mru[2], leaf[3], parent[3], port_shape[2];
	unsigned int i;

	proxy_row_read(0x63000, mru, 2);
	proxy_row_read(0x41c020, leaf, 3);
	proxy_row_read(0x45e000, parent, 3);
	proxy_row_read(0x474000, port_shape, 2);
	if (mapped && (readl(ppe + SC4_MAP) != PRIVATE_MAP ||
	    readl(ppe + SC5_MAP) != saved_sc5 ||
	    readl(ppe + 0x402020) != saved_l0 ||
	    readl(ppe + 0x408020) != saved_l0_port ||
	    readl(edma + 0x5a000) != saved_route))
		return -ESTALE;
	if (((mru[1] >> 2) & 3) ||
	    (readl(ppe + 0x402020) & 0x3f) ||
	    (readl(ppe + 0x408020) & 0xf) ||
	    (readl(ppe + 0x440000) & 0xf) ||
	    (readl(ppe + 0x446000) & 0xf) ||
	    ((readl(edma + 0x5a000) >> 8) & 0xf) ||
	    !(readl(edma + 0x39018) & 1) ||
	    (readl(ppe + 0x430020) & 1) ||
	    (readl(ppe + 0x85c020) & 1) ||
	    (readl(ppe + 0x864020) & 1) ||
	    (leaf[2] & 0x30) ||
	    (parent[2] & 0x30) ||
	    (port_shape[1] & 0x10))
		return -EXDEV;
	if (empty && (!(readl(ppe + Q2_HEAD) & 1) ||
	    (readl(ppe + Q2_PENDING) & 0xfff)))
		return -EBUSY;
	for (i = 0; i < 16; i++)
		if (readl(ppe + 0x842000 + 16 * i) & 0xf)
			return -EXDEV;
	for (i = 0; i < 256; i++)
		if (readl(ppe + 0x830000 + 16 * i) & 0xff)
			return -EXDEV;
	for (i = 0; i < 2; i++) {
		proxy_service_read(4 + i, row);
		if (row[0] != 0xfffefcf7 || row[1] ||
		    row[2] != 0x003fffc1 || row[3] != 0xc0 || row[4] != 5)
			return -EXDEV;
		if (mapped && memcmp(row, saved_services[i], sizeof(row)))
			return -ESTALE;
	}
	return 0;
}

/* No command callback is needed: the retained request itself owns the bounded
 * reply and late identity. The explicit module pin survives every UNKNOWN.
 */
static int proxy_command(enum proxy_step step, bool submit, unsigned int wait_ms)
{
	struct proxy_config config = {};
	struct proxy_redirect_config redirect = {};
	struct qdx_endpoint *command_endpoint = endpoint;
	__le32 assignment[2] = {};
	struct qdx_reply_bounds bounds;
	u8 reply[sizeof(config)] = {};
	void *payload;
	u32 opcode, subcommand = 0;
	size_t length;
	int error;

	if (protocol_fault)
		return -EPROTO;
	if (request && pending_step != step)
		return -EBUSY;
	if (step == STEP_N2H_CONFIG || step == STEP_H2N_CONFIG) {
		opcode = REDIR_CONFIG;
		redirect.sibling = cpu_to_le32(step == STEP_N2H_CONFIG ?
			sibling_ifnum : endpoint_ifnum);
		redirect.nexthop = cpu_to_le32(step == STEP_N2H_CONFIG ? 156 : 158);
		ether_addr_copy(redirect.mac, port->dev_addr);
		command_endpoint = step == STEP_N2H_CONFIG ? endpoint : sibling;
		payload = &redirect;
		length = sizeof(redirect);
	} else if (step == STEP_ASSIGN || step == STEP_UNASSIGN) {
		opcode = step == STEP_ASSIGN ? 7 : 9;
		assignment[0] = cpu_to_le32(step == STEP_ASSIGN ? 0 : shaper_id);
		payload = assignment;
		length = step == STEP_ASSIGN ? 8 : 4;
	} else {
		opcode = 11;
		if (step == STEP_ALLOC) {
			subcommand = 0;
			config.data.allocate.type = cpu_to_le32(14);
			config.data.allocate.tag = cpu_to_le32(PROXY_TAG);
		} else if (step == STEP_ROOT) {
			subcommand = 3;
			config.data.tag = cpu_to_le32(PROXY_TAG);
		} else if (step == STEP_CONFIG) {
			subcommand = 7;
			config.data.node.tag = cpu_to_le32(PROXY_TAG);
			config.data.node.type = cpu_to_le32(256);
			config.data.node.ucast_base = cpu_to_le16(2);
			config.data.node.limit = cpu_to_le16(1);
		} else if (step == STEP_FREE) {
			subcommand = 1;
			config.data.tag = cpu_to_le32(PROXY_TAG);
		} else {
			return -EINVAL;
		}
		config.request = cpu_to_le32(subcommand);
		payload = &config;
		length = sizeof(config);
	}
	if (!request) {
		if (!submit)
			return 0;
		bounds = (struct qdx_reply_bounds) { length, length, length };
		request = qdx_command_submit(command_endpoint, opcode, payload, length, &bounds, NULL);
		if (IS_ERR(request)) {
			error = PTR_ERR(request);
			request = NULL;
			return error;
		}
		pending_step = step;
	}
	error = qdx_request_wait(request, jiffies + msecs_to_jiffies(wait_ms),
		&last_result, reply, sizeof(reply));
	if (last_result.outcome == QDX_UNKNOWN && !last_result.exposure_ended)
		return error ?: -EINPROGRESS;
	if (last_result.outcome == QDX_ACK) {
		if (last_result.received_len < length || last_result.declared_len != length) {
			protocol_fault = true;
			return -EPROTO;
		}
		if (opcode == 11) {
			memcpy(&config, reply, sizeof(config));
			if (le32_to_cpu(config.request) != subcommand) {
				protocol_fault = true;
				return -EPROTO;
			}
			last_shaper_response = le32_to_cpu(config.response);
			error = last_shaper_response ? -EREMOTEIO : 0;
		} else if (step == STEP_ASSIGN) {
			memcpy(assignment, reply, sizeof(assignment));
			shaper_id = le32_to_cpu(assignment[1]);
			if (!shaper_id) {
				protocol_fault = true;
				return -EPROTO;
			}
			error = 0;
		} else {
			error = 0;
		}
		if (!error) {
			if (step == STEP_N2H_CONFIG)
				n2h_configured = true;
			if (step == STEP_H2N_CONFIG)
				h2n_configured = true;
			if (step == STEP_ASSIGN)
				assigned = true;
			if (step == STEP_ALLOC)
				allocated = true;
			if (step == STEP_ROOT)
				rooted = true;
			if (step == STEP_CONFIG)
				configured = true;
			if (step == STEP_FREE)
				allocated = rooted = configured = false;
			if (step == STEP_UNASSIGN)
				assigned = false;
		}
	} else {
		error = last_result.error ?: error ?: -EIO;
	}
	qdx_request_put(request);
	request = NULL;
	pending_step = STEP_NONE;
	return error;
}

static void proxy_returned(void *owner, struct sk_buff *original,
		struct sk_buff *returned, const struct qdx_rx_meta *meta,
		struct napi_struct *napi)
{
	struct proxy_marker *marker = owner;
	unsigned long flags;
	bool witnessed = returned && returned == original &&
		original == READ_ONCE(marker->original) &&
		meta && meta->ifnum == READ_ONCE(endpoint_ifnum) &&
		meta->type == QDX_RECEIVE_BRIDGE_RETURNED;
	bool valid = witnessed && returned->len == FRAME_LEN &&
		!memcmp(returned->data, marker->expected, FRAME_LEN);
	spin_lock_irqsave(&marker_lock, flags);
	marker->returned = true;
	marker->witnessed = witnessed;
	marker->valid = valid;
	marker->ifnum = meta ? meta->ifnum : U32_MAX;
	marker->type = meta ? meta->type : U32_MAX;
	marker->service = meta ? meta->service_code : U32_MAX;
	marker->length = returned ? returned->len : 0;
	spin_unlock_irqrestore(&marker_lock, flags);
	if (returned)
		dev_kfree_skb_any(returned);
	complete_all(&marker->done);
}

static int proxy_prepare(void)
{
	struct qdx_endpoint *physical;
	u32 ifnum, ptx[3];
	unsigned int i;
	int error;

	if (!fixture_reserved || closed || protocol_fault)
		return -EPERM;
	if (!pinned) {
		if (!try_module_get(THIS_MODULE))
			return -ENODEV;
		pinned = true;
		port = dev_get_by_name(&init_net, "lan3");
		if (!port || !netif_running(port))
			return -ENODEV;
		service = qdx_service_get(port, QDX_SERVICE_SHAPER);
		if (IS_ERR(service)) {
			error = PTR_ERR(service);
			service = NULL;
			return error;
		}
	}
	if (!service || qdx_service_state(service) != QDX_AVAILABLE)
		return -ENODEV;
	physical = qdx_endpoint_get(service, port);
	if (IS_ERR(physical))
		return PTR_ERR(physical);
	error = qdx_endpoint_ifnum(physical, &ifnum);
	qdx_endpoint_put(physical);
	if (error || ifnum != PORT_IFNUM)
		return error ?: -EXDEV;
	/* Retain each allocator attempt across timeout; prepare retries wait on
	 * that same object, never allocate an alias for an unknown result.
	 */
	if (!endpoint) {
		endpoint = qdx_endpoint_alloc(service, REDIR_N2H);
		if (IS_ERR(endpoint)) {
			error = PTR_ERR(endpoint);
			endpoint = NULL;
			return error;
		}
	}
	error = qdx_endpoint_wait(endpoint, jiffies + msecs_to_jiffies(WAIT_MS));
	if (error)
		return error;
	error = qdx_endpoint_ifnum(endpoint, &endpoint_ifnum);
	if (error)
		return error;
	if (!sibling) {
		sibling = qdx_endpoint_alloc(service, REDIR_H2N);
		if (IS_ERR(sibling)) {
			error = PTR_ERR(sibling);
			sibling = NULL;
			return error;
		}
	}
	error = qdx_endpoint_wait(sibling, jiffies + msecs_to_jiffies(WAIT_MS));
	if (error)
		return error;
	error = qdx_endpoint_ifnum(sibling, &sibling_ifnum);
	if (error || endpoint_ifnum == sibling_ifnum)
		return error ?: -EPROTO;
	error = proxy_fixture_check(true);
	if (error)
		return error;
	if (!mapped) {
		/* Counter reset belongs only to this empty, externally reserved queue. */
		proxy_row_read(Q2_PTX, ptx, 3);
		if (ptx[0] || ptx[1] || ptx[2])
			return -EBUSY;
		saved_map = readl(ppe + SC4_MAP);
		saved_sc5 = readl(ppe + SC5_MAP);
		saved_l0 = readl(ppe + 0x402020);
		saved_l0_port = readl(ppe + 0x408020);
		saved_route = readl(edma + 0x5a000);
		for (i = 0; i < 2; i++)
			proxy_service_read(4 + i, saved_services[i]);
		mapped = true;
		writel(PRIVATE_MAP, ppe + SC4_MAP);
		if (readl(ppe + SC4_MAP) != PRIVATE_MAP)
			return -EIO;
	}
	if (request) {
		error = proxy_command(pending_step, false, WAIT_MS);
		if (error)
			return error;
	}
	if (!n2h_configured) {
		error = proxy_command(STEP_N2H_CONFIG, true, WAIT_MS);
		if (error)
			return error;
	}
	if (!h2n_configured) {
		error = proxy_command(STEP_H2N_CONFIG, true, WAIT_MS);
		if (error)
			return error;
	}
	if (!assigned) {
		error = proxy_command(STEP_ASSIGN, true, WAIT_MS);
		if (error)
			return error;
	}
	if (!allocated) {
		error = proxy_command(STEP_ALLOC, true, WAIT_MS);
		if (error)
			return error;
	}
	if (!rooted) {
		error = proxy_command(STEP_ROOT, true, WAIT_MS);
		if (error)
			return error;
	}
	if (!configured) {
		error = proxy_command(STEP_CONFIG, true, WAIT_MS);
		if (error)
			return error;
	}
	if (!operation) {
		operation = qdx_packet_op_prepare(endpoint, PROXY_TAG, QDX_RECEIVE_BRIDGE_RETURNED);
		if (IS_ERR(operation)) {
			error = PTR_ERR(operation);
			operation = NULL;
			return error;
		}
	}
	return 0;
}

static int proxy_send(unsigned int index)
{
	struct proxy_marker *marker = &markers[index];
	struct qdx_packet_recipient recipient = {
		.owner = { .module = THIS_MODULE, .object = marker },
		.returned = proxy_returned,
	};
	struct qdx_ready ready;
	struct sk_buff *skb;
	unsigned int i;
	int error;

	if (!configured || !operation || closed || request || protocol_fault)
		return -EINVAL;
	if (index && (!completion_done(&markers[0].done) || !READ_ONCE(markers[0].valid)))
		return -EAGAIN;
	if (marker->submitted)
		return -EALREADY;
	error = proxy_fixture_check(true);
	if (error)
		return error;
	skb = alloc_skb(128 + FRAME_LEN, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;
	skb_reserve(skb, 128);
	skb_put_zero(skb, FRAME_LEN);
	ether_addr_copy(skb->data, port->dev_addr);
	ether_addr_copy(skb->data + ETH_ALEN, port->dev_addr);
	skb->data[12] = 0x88;
	skb->data[13] = 0xb5;
	for (i = ETH_HLEN; i < FRAME_LEN; i++)
		skb->data[i] = (u8)(i ^ marker->id ^ 0xa5);
	skb->dev = port;
	skb->protocol = htons(0x88b5);
	skb_reset_mac_header(skb);
	memcpy(marker->expected, skb->data, FRAME_LEN);
	WRITE_ONCE(marker->original, skb);
	ready = qdx_packet_op_submit(operation, skb, &recipient);
	if (ready.status != QDX_ACCEPTED) {
		WRITE_ONCE(marker->original, NULL);
		kfree_skb(skb);
		return ready.error ?: -EAGAIN;
	}
	marker->submitted = true;
	if (!wait_for_completion_timeout(&marker->done, msecs_to_jiffies(WAIT_MS)))
		return -ETIMEDOUT;
	return READ_ONCE(marker->valid) ? 0 : -EBADMSG;
}

static int proxy_restore(void)
{
	unsigned int i;
	int error;
	u32 observed;

	if (!pinned)
		return 0;
	closed = true;
	if (operation) {
		qdx_packet_op_close(operation);
		if (!qdx_packet_op_drained(operation))
			return -EINPROGRESS;
	}
	/* Disposal is not the service5 witness needed to retire a live manager. */
	for (i = 0; i < 2; i++)
		if (markers[i].submitted && !READ_ONCE(markers[i].witnessed) &&
		    !(service && qdx_service_access_ended(service)))
			return -EINPROGRESS;
	if (service && qdx_service_access_ended(service)) {
		if (request)
			qdx_request_put(request);
		request = NULL;
		pending_step = STEP_NONE;
		assigned = allocated = rooted = configured = false;
	} else if (request) {
		error = proxy_command(pending_step, false, WAIT_MS);
		if (request)
			return error;
	}
	if (allocated) {
		error = proxy_command(STEP_FREE, true, WAIT_MS);
		if (error)
			return error;
	}
	if (assigned) {
		error = proxy_command(STEP_UNASSIGN, true, WAIT_MS);
		if (error)
			return error;
	}
	/* The actual virtual teardown withdraws its published identity and sibling
	 * references. Match the vendor pair's N2H then H2N command order. Each
	 * public retire waits for its original ACK and receive-prefix drain.
	 * A timeout is retained; the existing driver may declare service failure.
	 */
	if (endpoint && !endpoint_retired) {
		if (!qdx_service_access_ended(service) &&
		    qdx_endpoint_wait(endpoint, jiffies) == -ETIMEDOUT)
			return -EINPROGRESS;
		error = qdx_endpoint_retire(endpoint);
		if (error)
			return error;
		endpoint_retired = true;
	}
	if (sibling && !sibling_retired) {
		if (!qdx_service_access_ended(service) &&
		    qdx_endpoint_wait(sibling, jiffies) == -ETIMEDOUT)
			return -EINPROGRESS;
		error = qdx_endpoint_retire(sibling);
		if (error)
			return error;
		sibling_retired = true;
	}
	if (mapped) {
		error = proxy_fixture_check(true);
		if (error)
			return error;
		observed = readl(ppe + SC4_MAP);
		if (observed != PRIVATE_MAP)
			return -ESTALE;
		writel(saved_map, ppe + SC4_MAP);
		if (readl(ppe + SC4_MAP) != saved_map)
			return -EIO;
		mapped = false;
	}
	qdx_packet_op_put(operation);
	operation = NULL;
	qdx_endpoint_put(endpoint);
	endpoint = NULL;
	qdx_endpoint_put(sibling);
	sibling = NULL;
	qdx_service_put(service);
	service = NULL;
	if (port)
		dev_put(port);
	port = NULL;
	pinned = false;
	module_put(THIS_MODULE);
	return 0;
}

static int proxy_status_show(struct seq_file *seq, void *unused)
{
	u32 row[5], ptx[3], fields[8];
	u32 mru[2], leaf[3], parent[3], port_shape[2];
	int fixture_error;
	unsigned int i;
	unsigned long flags;

	mutex_lock(&proxy_lock);
	seq_printf(seq, "allow_writes=%u fixture_reserved=%u pinned=%u mapped=%u assigned=%u allocated=%u rooted=%u configured=%u closed=%u fault=%u shaper=%u tag=%08x pending=%u error=%d\n",
		allow_writes, fixture_reserved, pinned, mapped, assigned, allocated, rooted,
		configured, closed, protocol_fault, shaper_id, PROXY_TAG, pending_step, last_error);
	seq_printf(seq, "n2h_ifnum=%u h2n_ifnum=%u n2h_configured=%u h2n_configured=%u n2h_retired=%u h2n_retired=%u\n",
		endpoint_ifnum, sibling_ifnum, n2h_configured, h2n_configured,
		endpoint_retired, sibling_retired);
	seq_printf(seq, "request_id=%llu outcome=%u error=%d firmware_error=%u shaper_response=%u published=%u exposure_ended=%u received=%zu declared=%zu op_drained=%u\n",
		(unsigned long long)last_result.id, last_result.outcome, last_result.error,
		last_result.firmware_error, last_shaper_response, last_result.published, last_result.exposure_ended,
		last_result.received_len, last_result.declared_len,
		operation ? qdx_packet_op_drained(operation) : true);
	for (i = 0; i < 2; i++) {
		spin_lock_irqsave(&marker_lock, flags);
		fields[0] = markers[i].submitted;
		fields[1] = markers[i].returned;
		fields[2] = markers[i].valid;
		fields[3] = markers[i].ifnum;
		fields[4] = markers[i].type;
		fields[5] = markers[i].length;
		fields[6] = markers[i].service;
		fields[7] = markers[i].witnessed;
		spin_unlock_irqrestore(&marker_lock, flags);
		seq_printf(seq, "marker=%c submitted=%u returned=%u valid=%u ifnum=%u type=%u length=%u service=%u witnessed=%u\n",
			'A' + i, fields[0], fields[1], fields[2], fields[3], fields[4], fields[5], fields[6], fields[7]);
	}
	proxy_row_read(Q2_PTX, ptx, 3);
	seq_printf(seq, "sc4_map=%08x saved=%08x sc5_map=%08x q2_head=%08x q2_pending=%08x q2_ptx=%08x,%08x,%08x rx0_prod=%08x rx0_cons=%08x route=%08x\n",
		readl(ppe + SC4_MAP), saved_map, readl(ppe + SC5_MAP), readl(ppe + Q2_HEAD),
		readl(ppe + Q2_PENDING), ptx[0], ptx[1], ptx[2], readl(edma + RX0_PROD),
		readl(edma + RX0_CONS), readl(edma + 0x5a000));
	fixture_error = proxy_fixture_check(true);
	proxy_row_read(0x63000, mru, 2);
	proxy_row_read(0x41c020, leaf, 3);
	proxy_row_read(0x45e000, parent, 3);
	proxy_row_read(0x474000, port_shape, 2);
	seq_printf(seq, "fixture_check=%d cpu0_mru=%08x,%08x q2_l0=%08x q2_port=%08x l1_map=%08x l1_port=%08x q2_deq=%08x q2_enq=%08x q2_drop=%08x q2_shaper=%08x l1_shaper=%08x port0_shaper=%08x rx0_ctrl=%08x\n",
		fixture_error, mru[0], mru[1],
		readl(ppe + 0x402020), readl(ppe + 0x408020),
		readl(ppe + 0x440000), readl(ppe + 0x446000),
		readl(ppe + 0x430020), readl(ppe + 0x85c020),
		readl(ppe + 0x864020), leaf[2], parent[2], port_shape[1],
		readl(edma + 0x39018));
	for (i = 0; i < 16; i++) {
		fields[0] = readl(ppe + 0x842000 + 16 * i);
		if (fields[0] & 0xf)
			seq_printf(seq, "profile0_priority_nonzero index=%u raw=%08x\n", i, fields[0]);
	}
	for (i = 0; i < 256; i++) {
		fields[0] = readl(ppe + 0x830000 + 16 * i);
		if (fields[0] & 0xff)
			seq_printf(seq, "profile0_hash_nonzero index=%u raw=%08x\n", i, fields[0]);
	}
	for (i = 4; i <= 5; i++) {
		proxy_service_read(i, row);
		seq_printf(seq, "service=%u ingress=%08x,%08x l2=%08x egress=%08x,%08x\n",
			i, row[0], row[1], row[2], row[3], row[4]);
	}
	for (i = 0; i < 8; i++) {
		/* Read-only IPR observation; these are not a claimed input fence. */
		fields[0] = readl(ppe + 0x2080 + 4 * i);
		fields[1] = readl(ppe + 0x20a0 + 4 * i);
		fields[2] = readl(ppe + 0x20c0 + 4 * i);
		fields[3] = readl(ppe + 0xb024 + 4 * i);
		seq_printf(seq, "ipr_port=%u packets=%08x bytes_lo=%08x bytes_hi=%08x prxdrop=%08x\n",
			i, fields[0], fields[1], fields[2], fields[3]);
	}
	seq_puts(seq, "bm_used=");
	for (i = 0; i < 15; i++)
		seq_printf(seq, "%s%u:%u", i ? "," : "", i,
			readl(ppe + 0x6001c0 + 4 * i) & 0x7ff);
	seq_putc(seq, '\n');
	mutex_unlock(&proxy_lock);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(proxy_status);

static ssize_t proxy_control_write(struct file *file, const char __user *buffer,
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
	mutex_lock(&proxy_lock);
	if (!strcmp(command, "prepare"))
		error = proxy_prepare();
	else if (!strcmp(command, "send-a"))
		error = proxy_send(0);
	else if (!strcmp(command, "send-b"))
		error = proxy_send(1);
	else if (!strcmp(command, "poll"))
		error = request ? proxy_command(pending_step, false, 0) : 0;
	else if (!strcmp(command, "stop")) {
		closed = true;
		if (operation)
			qdx_packet_op_close(operation);
		error = 0;
	} else if (!strcmp(command, "restore")) {
		error = proxy_restore();
	} else {
		error = -EINVAL;
	}
	last_error = error;
	mutex_unlock(&proxy_lock);
	return error ?: count;
}
static const struct file_operations proxy_control_fops = {
	.owner = THIS_MODULE, .write = proxy_control_write,
};

static int __init proxy_init(void)
{
	struct dentry *entry;
	unsigned int i;

	ppe = ioremap(0x3a000000, 0xa00000);
	edma = ioremap(0x3ab00000, 0x60000);
	if (!ppe || !edma)
		goto fail;
	for (i = 0; i < 2; i++) {
		init_completion(&markers[i].done);
		markers[i].id = i + 1;
	}
	directory = debugfs_create_dir("qdx_proxy_diag", NULL);
	if (IS_ERR_OR_NULL(directory))
		goto fail;
	entry = debugfs_create_file("control", 0200, directory, NULL, &proxy_control_fops);
	if (IS_ERR_OR_NULL(entry))
		goto fail;
	entry = debugfs_create_file("status", 0400, directory, NULL, &proxy_status_fops);
	if (IS_ERR_OR_NULL(entry))
		goto fail;
	return 0;
fail:
	if (!IS_ERR_OR_NULL(directory))
		debugfs_remove_recursive(directory);
	if (edma)
		iounmap(edma);
	if (ppe)
		iounmap(ppe);
	return -ENOMEM;
}
static void __exit proxy_exit(void)
{
	WARN_ON(pinned || request || operation || endpoint || sibling || mapped || assigned || allocated);
	debugfs_remove_recursive(directory);
	iounmap(edma);
	iounmap(ppe);
}
module_init(proxy_init);
module_exit(proxy_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Isolated virtual-pair PPE proxy4/5 receive-ring witness");
