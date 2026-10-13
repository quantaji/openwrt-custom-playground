// SPDX-License-Identifier: GPL-2.0-only
/* Isolated 114368 diagnostic: physical LAN3/if3 -> LAN2/if4 raw NSS relay.
 * Root must stop traffic and verify the documented fixture first.
 * The optional default command retains a real current diagnostic storage leaf;
 * remove that native test qdisc after restore to clear firmware default.
 * These historical APIs are a diagnostic carrier, not a Phase 2.5 API proposal.
 */
#include <linux/build_bug.h>
#include <linux/debugfs.h>
#include <linux/err.h>
#include <linux/jiffies.h>
#include <linux/module.h>
#include <linux/math64.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/qdx.h>
#include <linux/qdx/tc.h>
#include <linux/rtnetlink.h>
#include <linux/refcount.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <net/net_namespace.h>
#include <net/pkt_sched.h>
#include <net/pkt_cls.h>

#define RELAY_SOURCE_NAME "lan3"
#define RELAY_TARGET_NAME "lan2"
#define RELAY_SOURCE_IFNUM 3
#define RELAY_TARGET_IFNUM 4
#define RELAY_SET_NEXTHOP 15
#define RELAY_RESET_NEXTHOP 18
#define RELAY_WAIT_MS 3000
#define RELAY_ISHAPER_CONFIG 10
#define RELAY_SET_DEFAULT 2
#define RELAY_RED_CONFIG 7

/* NSS 11.4 nss_shaper_configure: the unchanged 116-byte wire extent.
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
struct relay_red_parameters {
	__le32 limit, weight_mode, traffic_classes, default_class;
	__le32 traffic_id, weight_value, minimum, maximum, probability, ewma_log;
	u8 ecn, reserved[3];
};
static_assert(sizeof(struct relay_red_parameters) == 44);

struct relay_shaper_message {
	__le32 command, response, tag;
	union {
		struct relay_red_parameters red;
		u8 reserved[104];
	} data;
};
static_assert(sizeof(struct relay_shaper_message) == 116);

struct relay_tc_hold {
	refcount_t refs;
	struct qdx_binding_use use;
	struct qdx_tc_ref *reference;
	struct Qdisc *leaf; /* Identity only; current object reread under RTNL. */
	bool invalid;
};
static struct relay_tc_hold *tc_hold;
static bool default_acked, shaper_uncertain;
static bool red_required, red_config_acked, ever_armed;
/* Original submitted payload remains unchanged through UNKNOWN and poll. */
static struct relay_shaper_message shaper_message;
static u32 default_tag;
/* Bounded021 policy probes; retain the exact step through UNKNOWN. */
static u32 extra_step, extra_acked;

static bool allow_writes;
module_param(allow_writes, bool, 0400);
MODULE_PARM_DESC(allow_writes, "Enable fixed diagnostic commands; default false");

static DEFINE_MUTEX(relay_lock);
struct relay_reply {
	refcount_t refs;
	spinlock_t lock;
	struct qdx_result result;
	unsigned int deliveries;
};
static struct relay_reply *pending_reply;
static struct dentry *relay_debugfs;
static struct net_device *source_dev, *target_dev;
static struct qdx_service *relay_service;
static struct qdx_endpoint *source_endpoint, *target_endpoint;
static struct qdx_rx_use *source_rx, *resume_rx;
static struct qdx_request *pending_request;
static struct qdx_result last_result;
static u32 pending_opcode;
static bool self_pinned, attached, held, running;
static unsigned int result_deliveries;
static int last_error;

/* Each request has its own callback storage. A final callback from an older
 * request cannot write a later command's result, even after its waiter settles.
 */
static bool relay_reply_get(void *owner)
{
	struct relay_reply *reply = owner;

	return refcount_inc_not_zero(&reply->refs);
}

static void relay_reply_put(void *owner)
{
	struct relay_reply *reply = owner;

	if (refcount_dec_and_test(&reply->refs))
		kfree(reply);
}

/* NAPI-safe; never takes relay_lock, including while the command waits. */
static void relay_result(void *owner, const struct qdx_result *result,
                         const void *payload, size_t length)
{
	struct relay_reply *reply = owner;
	unsigned long flags;

	spin_lock_irqsave(&reply->lock, flags);
	reply->result = *result;
	reply->deliveries++;
	spin_unlock_irqrestore(&reply->lock, flags);
}

/* Only settled commands can be consumed. UNKNOWN remains the original object. */
static int relay_command(u32 opcode, bool submit, unsigned long wait_ms)
{
	struct qdx_command_recipient recipient = {
		.owner = { .module = THIS_MODULE, .get = relay_reply_get,
			.put = relay_reply_put },
		.result = relay_result,
	};
	struct relay_shaper_message answer = {};
	bool shaper = opcode == RELAY_ISHAPER_CONFIG;
	struct qdx_reply_bounds bounds = {
		.minimum = shaper ? sizeof(shaper_message) : 0,
		.maximum = shaper ? sizeof(shaper_message) :
			(opcode == RELAY_SET_NEXTHOP ? sizeof(__le32) : 0),
		.capacity = sizeof(shaper_message),
	};
	struct qdx_result result;
	struct qdx_request *request;
	struct relay_reply *reply;
	__le32 target = cpu_to_le32(RELAY_TARGET_IFNUM);
	unsigned long flags;
	bool wait_acked;
	int error;

	if (shaper && (!tc_hold ||
	    (le32_to_cpu(shaper_message.command) != RELAY_SET_DEFAULT &&
	     le32_to_cpu(shaper_message.command) != RELAY_RED_CONFIG)))
		return -EINVAL;
	if (shaper && pending_request &&
	    qdx_service_access_ended(relay_service)) {
		/* Actual feature access end, never a timeout, ends an uncertain SET.
		 * Independent recipient references still protect late callback storage.
		 */
		qdx_request_put(pending_request);
		pending_request = NULL;
		relay_reply_put(pending_reply);
		pending_reply = NULL;
		pending_opcode = 0;
		shaper_uncertain = false;
		default_acked = false;
		red_config_acked = false;
		attached = false;
		return 0;
	}
	if (shaper_uncertain)
		return -EPROTO;
	if (pending_request && pending_opcode != opcode)
		return -EBUSY;
	if (!pending_request) {
		if (!submit)
			return 0;
		reply = kzalloc(sizeof(*reply), GFP_KERNEL);
		if (!reply)
			return -ENOMEM;
		refcount_set(&reply->refs, 1);
		spin_lock_init(&reply->lock);
		reply->result = (struct qdx_result) {
			.ifnum = shaper ? RELAY_TARGET_IFNUM : RELAY_SOURCE_IFNUM,
			.opcode = opcode,
			.outcome = QDX_UNKNOWN, .error = -EINPROGRESS,
		};
		last_result = reply->result;
		result_deliveries = 0;
		recipient.owner.object = reply;
		request = qdx_command_submit(shaper ? tc_hold->reference->class_endpoint :
			source_endpoint, opcode,
			shaper ? (void *)&shaper_message :
				(opcode == RELAY_SET_NEXTHOP ? (void *)&target : NULL),
			shaper ? sizeof(shaper_message) :
				(opcode == RELAY_SET_NEXTHOP ? sizeof(target) : 0),
			&bounds, &recipient);
		if (IS_ERR(request)) {
			error = PTR_ERR(request);
			last_result.outcome = QDX_NOT_SUBMITTED;
			last_result.error = error;
			relay_reply_put(reply);
			return error;
		}
		pending_reply = reply;
		pending_request = request;
		pending_opcode = opcode;
	}
	error = qdx_request_wait(pending_request,
		jiffies + msecs_to_jiffies(wait_ms), &result,
		shaper ? &answer : NULL, shaper ? sizeof(answer) : 0);
	wait_acked = result.outcome == QDX_ACK;
	/* The callback may publish a newer final reply just after wait returns.
	 * Never replace its final outcome with this waiter's older UNKNOWN copy.
	 */
	reply = pending_reply;
	spin_lock_irqsave(&reply->lock, flags);
	if (reply->result.outcome == QDX_UNKNOWN ||
	    result.outcome != QDX_UNKNOWN || result.exposure_ended)
		reply->result = result;
	result = reply->result;
	last_result = result;
	result_deliveries = reply->deliveries;
	spin_unlock_irqrestore(&reply->lock, flags);
	if (result.outcome == QDX_UNKNOWN && !result.exposure_ended)
		return error ?: result.error ?: -EINPROGRESS;
	/* If delivery overtook an UNKNOWN wait, revisit this same request to get
	 * its settled payload. Never validate an unfilled local answer buffer.
	 */
	if (shaper && result.outcome == QDX_ACK && !wait_acked)
		return -EINPROGRESS;
	if (shaper && result.outcome == QDX_ACK &&
	    (result.declared_len != sizeof(answer) ||
	     result.received_len < sizeof(answer) ||
	     answer.command != shaper_message.command ||
	     answer.tag != shaper_message.tag ||
	     (!answer.response &&
	      le32_to_cpu(shaper_message.command) == RELAY_RED_CONFIG &&
	      memcmp(&answer.data, &shaper_message.data, sizeof(answer.data))))) {
		shaper_uncertain = true;
		return -EPROTO; /* keep request/tree/hold; no fabricated rollback */
	}
	qdx_request_put(pending_request);
	pending_request = NULL;
	pending_reply = NULL;
	relay_reply_put(reply);
	pending_opcode = 0;
	if (result.outcome == QDX_ACK) {
		if (shaper) {
			if (answer.response)
				return -EREMOTEIO;
			if (le32_to_cpu(shaper_message.command) == RELAY_RED_CONFIG) {
				if (extra_step)
					extra_acked |= BIT(extra_step);
				red_config_acked = !extra_step ||
					(extra_step == 3 && (extra_acked & 14) == 14) ||
					(extra_step == 5 && (extra_acked & 48) == 48);
			} else
				default_acked = true;
		} else {
			attached = opcode == RELAY_SET_NEXTHOP;
		}
		return 0;
	}
	if (qdx_service_access_ended(relay_service))
		attached = false;
	return result.error ?: error ?: -EIO;
}

/* No packet storage or physical firmware endpoint is destroyed here. */
static void relay_put_refs(void)
{
	qdx_endpoint_put(target_endpoint);
	target_endpoint = NULL;
	qdx_endpoint_put(source_endpoint);
	source_endpoint = NULL;
	qdx_service_put(relay_service);
	relay_service = NULL;
	if (target_dev)
		dev_put(target_dev);
	target_dev = NULL;
	if (source_dev)
		dev_put(source_dev);
	source_dev = NULL;
	red_required = false;
	red_config_acked = false;
	extra_step = 0;
	extra_acked = 0;
	ever_armed = false;
	if (self_pinned) {
		self_pinned = false;
		module_put(THIS_MODULE);
	}
}

static int relay_prepare(void)
{
	u32 source, target;
	int error;

	if (attached || running || resume_rx)
		return -EBUSY;
	if (pending_request)
		return pending_opcode == RELAY_SET_NEXTHOP ?
			relay_command(RELAY_SET_NEXTHOP, false, RELAY_WAIT_MS) : -EBUSY;
	if (source_rx)
		return held ? relay_command(RELAY_SET_NEXTHOP, true, RELAY_WAIT_MS) : -EBUSY;
	if (!try_module_get(THIS_MODULE))
		return -ENODEV;
	self_pinned = true;
	source_dev = dev_get_by_name(&init_net, RELAY_SOURCE_NAME);
	target_dev = dev_get_by_name(&init_net, RELAY_TARGET_NAME);
	if (!source_dev || !target_dev || source_dev == target_dev) {
		error = -ENODEV;
		goto put_refs;
	}
	if (!netif_running(source_dev) || !netif_running(target_dev) ||
	    !netif_carrier_ok(source_dev) || !netif_carrier_ok(target_dev)) {
		error = -ENETDOWN;
		goto put_refs;
	}
	relay_service = qdx_service_get(source_dev, QDX_SERVICE_ETHERNET);
	if (IS_ERR(relay_service)) {
		error = PTR_ERR(relay_service);
		relay_service = NULL;
		goto put_refs;
	}
	source_endpoint = qdx_endpoint_get(relay_service, source_dev);
	if (IS_ERR(source_endpoint)) {
		error = PTR_ERR(source_endpoint);
		source_endpoint = NULL;
		goto put_refs;
	}
	target_endpoint = qdx_endpoint_get(relay_service, target_dev);
	if (IS_ERR(target_endpoint)) {
		error = PTR_ERR(target_endpoint);
		target_endpoint = NULL;
		goto put_refs;
	}
	error = qdx_endpoint_ifnum(source_endpoint, &source);
	if (!error)
		error = qdx_endpoint_ifnum(target_endpoint, &target);
	if (error)
		goto put_refs;
	if (source != RELAY_SOURCE_IFNUM || target != RELAY_TARGET_IFNUM ||
	    source == target) {
		error = -EXDEV;
		goto put_refs;
	}
	source_rx = qdx_rx_acquire(source_endpoint, source_dev);
	if (IS_ERR(source_rx)) {
		error = PTR_ERR(source_rx);
		source_rx = NULL;
		goto put_refs;
	}
	/* acquire initially enables the native RX reservation. No fixture traffic
	 * is allowed until arm. The old default receive path exists in this gap.
	 */
	error = qdx_rx_hold(source_rx);
	if (error)
		return error; /* retain the exact reservation for explicit restore */
	held = true;
	return relay_command(RELAY_SET_NEXTHOP, true, RELAY_WAIT_MS);
put_refs:
	relay_put_refs();
	return error;
}

static int relay_arm(void)
{
	int error;

	if (!source_rx || !held || !attached || pending_request || running)
		return -EINVAL;
	if (tc_hold && (!default_acked || READ_ONCE(tc_hold->invalid)))
		return -ESTALE;
	if (red_required && !red_config_acked)
		return -EAGAIN;
	if (qdx_service_state(relay_service) != QDX_AVAILABLE ||
	    !netif_running(source_dev) || !netif_running(target_dev) ||
	    !netif_carrier_ok(source_dev) || !netif_carrier_ok(target_dev))
		return -ENETDOWN;
	if (!resume_rx) {
		resume_rx = qdx_rx_acquire(source_endpoint, source_dev);
		if (IS_ERR(resume_rx)) {
			error = PTR_ERR(resume_rx);
			resume_rx = NULL;
			return error;
		}
	}
	error = qdx_rx_release(source_rx);
	if (error)
		return error; /* both exact handles remain retained */
	source_rx = resume_rx;
	resume_rx = NULL;
	held = false;
	running = true;
	ever_armed = true;
	return 0;
}

static int relay_stop(void)
{
	int error;

	if (!source_rx)
		return 0;
	error = qdx_rx_hold(source_rx);
	if (!error) {
		held = true;
		running = false;
	}
	return error;
}

/* A separate object survives a late invalidation delivery after restore.
 * Controls take RTNL before relay_lock; native invalidation already has RTNL.
 */
static bool relay_tc_get(void *object)
{
	struct relay_tc_hold *hold = object;

	return refcount_inc_not_zero(&hold->refs);
}

static void relay_tc_put(void *object)
{
	struct relay_tc_hold *hold = object;

	if (refcount_dec_and_test(&hold->refs))
		kfree(hold);
}

static int relay_tc_invalid(void *object, bool may_sleep)
{
	struct relay_tc_hold *hold = object;
	int error = 0;

	WRITE_ONCE(hold->invalid, true);
	if (!may_sleep)
		return -EWOULDBLOCK;
	mutex_lock(&relay_lock);
	if (tc_hold == hold && source_rx &&
	    !qdx_service_access_ended(relay_service))
		error = relay_stop();
	mutex_unlock(&relay_lock);
	return error;
}

/* Retain the actual current PFIFO, CoDel, FQ-CoDel or RED diagnostic leaf,
 * optionally below one TBF. The historical translator supplies the real node
 * association, not proof of Linux-equivalent firmware behavior. The experiment
 * records the requested and actual algorithm separately. Unknown packet fields
 * are not invented as known zeros; no live qdisc change is allowed while held.
 */
static int relay_default(void)
{
	struct qdx_tc_position position = {
		.dev = target_dev, .direction = QDX_TC_EGRESS,
	};
	struct qdx_packet_geometry geometry = {};
	struct flow_dissector dissector = {};
	struct flow_rule facts = { .match.dissector = &dissector };
	struct qdx_owner consumer = {
		.module = THIS_MODULE, .get = relay_tc_get, .put = relay_tc_put,
	};
	struct relay_tc_hold *hold;
	struct Qdisc *root, *leaf;
	u32 ifnum;
	int error;

	ASSERT_RTNL();
	if (!source_rx || !held || !attached || running)
		return -EINVAL;
	if (pending_request)
		return pending_opcode == RELAY_ISHAPER_CONFIG ?
			relay_command(RELAY_ISHAPER_CONFIG, false, RELAY_WAIT_MS) : -EBUSY;
	if (tc_hold)
		return READ_ONCE(tc_hold->invalid) ? -ESTALE :
			(default_acked ? 0 : relay_command(RELAY_ISHAPER_CONFIG, true,
						     RELAY_WAIT_MS));
	root = rtnl_dereference(target_dev->qdisc);
	leaf = root;
	if (!strcmp(root->ops->id, "tbf")) {
		if (!root->ops->cl_ops || !root->ops->cl_ops->leaf)
			return -EOPNOTSUPP;
		leaf = root->ops->cl_ops->leaf(root, 1);
	}
	if (!leaf ||
	    (strcmp(leaf->ops->id, "pfifo") &&
	     strcmp(leaf->ops->id, "codel") &&
	     strcmp(leaf->ops->id, "fq_codel") &&
	     strcmp(leaf->ops->id, "red")))
		return -EOPNOTSUPP;
	hold = kzalloc(sizeof(*hold), GFP_KERNEL);
	if (!hold)
		return -ENOMEM;
	refcount_set(&hold->refs, 1);
	INIT_LIST_HEAD(&hold->use.node);
	consumer.object = hold;
	error = qdx_tc_position_get(&position, &facts, &geometry, &hold->use,
		&consumer, relay_tc_invalid, &hold->reference);
	if (error)
		goto put;
	if (hold->reference->effects != QDX_TC_CLASS ||
	    hold->reference->input_priority_used || hold->reference->output_priority_used ||
	    !hold->reference->class_endpoint || !hold->reference->class_tag ||
	    (hold->reference->class_tag & 0xffff)) {
		error = -EOPNOTSUPP;
		goto put_reference;
	}
	error = qdx_endpoint_ifnum(hold->reference->class_endpoint, &ifnum);
	if (error || ifnum != RELAY_TARGET_IFNUM) {
		error = error ?: -EXDEV;
		goto put_reference;
	}
	hold->leaf = leaf;
	tc_hold = hold;
	default_tag = hold->reference->class_tag;
	red_required = !strcmp(leaf->ops->id, "red");
	red_config_acked = false;
	shaper_message = (struct relay_shaper_message) {
		.command = cpu_to_le32(RELAY_SET_DEFAULT),
		.tag = cpu_to_le32(default_tag),
	};
	default_acked = false;
	shaper_uncertain = false;
	return relay_command(RELAY_ISHAPER_CONFIG, true, RELAY_WAIT_MS);
put_reference:
	qdx_tc_ref_put(hold->reference);
put:
	relay_tc_put(hold);
	return error;
}

/* Inspect the real current native RED offer, not a private qdisc layout.
 * This historical project replay API is used only by this diagnostic carrier.
 */
static int relay_red_offer(enum tc_setup_type type, void *data, void *private)
{
	const struct tc_red_qopt_offload *offer = data;
	const struct tc_red_qopt_offload_params *p;
	u64 probability;

	if (type != TC_SETUP_QDISC_RED || offer->command != TC_RED_REPLACE ||
	    offer->owner.sch != private)
		return -EOPNOTSUPP;
	p = &offer->set;
	probability = DIV64_U64_ROUND_UP((u64)p->probability * 255, 1ULL << 32);
	if (p->min != 8192 || p->max != 24576 || p->limit != 65536 ||
	    p->Wlog != 4 || probability != 13 || !p->is_ecn ||
	    p->is_harddrop || p->is_nodrop || p->adaptive ||
	    p->flags != TC_RED_ECN || p->early_drop_block || p->mark_block ||
	    !p->child || strcmp(p->child->ops->id, "bfifo") ||
	    p->child->limit != p->limit || rtnl_dereference(p->child->stab))
		return -EOPNOTSUPP;
	/* The old translator already established one weighted class. With zero
	 * classes and id1 this distinct CONFIG writes that class's parameters;
	 * it does not repeat setup or switch to plain RED/class0.
	 */
	shaper_message = (struct relay_shaper_message) {
		.command = cpu_to_le32(RELAY_RED_CONFIG),
		.tag = cpu_to_le32(default_tag),
		.data.red = {
			.limit = cpu_to_le32(p->limit),
			.traffic_id = cpu_to_le32(1),
			.minimum = cpu_to_le32(p->min),
			.maximum = cpu_to_le32(p->max),
			.probability = cpu_to_le32(probability),
			.ewma_log = cpu_to_le32(p->Wlog),
			.ecn = 1,
		},
	};
	return 0;
}

static int relay_red_config(void)
{
	struct Qdisc *root, *leaf;
	int error;

	ASSERT_RTNL();
	if (!source_rx || !held || !attached || running || ever_armed ||
	    !tc_hold || READ_ONCE(tc_hold->invalid) || !default_acked ||
	    !red_required)
		return -EINVAL;
	if (pending_request)
		return pending_opcode == RELAY_ISHAPER_CONFIG &&
		       le32_to_cpu(shaper_message.command) == RELAY_RED_CONFIG ?
			relay_command(RELAY_ISHAPER_CONFIG, false, RELAY_WAIT_MS) : -EBUSY;
	if (shaper_uncertain)
		return -EPROTO;
	if (extra_step)
		return -EINVAL;
	if (red_config_acked)
		return 0;
	root = rtnl_dereference(target_dev->qdisc);
	leaf = root;
	if (!strcmp(root->ops->id, "tbf")) {
		if (!root->ops->cl_ops || !root->ops->cl_ops->leaf)
			return -EOPNOTSUPP;
		leaf = root->ops->cl_ops->leaf(root, 1);
	}
	if (!leaf || leaf != tc_hold->leaf || strcmp(leaf->ops->id, "red") ||
	    rtnl_dereference(leaf->stab))
		return -ESTALE;
	error = qdisc_offload_replay(leaf, 0, relay_red_offer, leaf, NULL);
	if (error)
		return error;
	return relay_command(RELAY_ISHAPER_CONFIG, true, RELAY_WAIT_MS);
}

/* These are explicitly different firmware policies, never native RED offers.
 * A held, unchanged native leaf supplies only its real tag and lifetime.
 * Steps1..3: two DSCP occupancies sharing a FIFO;4..5: old-byte threshold FIFO.
 * Steps6/7: empty-input FIFO0/128 for an actual blackhole load window.
 */
static int relay_extra_config(u32 step)
{
	struct relay_red_parameters *p;

	ASSERT_RTNL();
	if (!source_rx || !held || !attached || running || !tc_hold ||
	    READ_ONCE(tc_hold->invalid) || !default_acked || shaper_uncertain)
		return -EINVAL;
	if (pending_request)
		return pending_opcode == RELAY_ISHAPER_CONFIG && extra_step == step ?
			relay_command(RELAY_ISHAPER_CONFIG, false, RELAY_WAIT_MS) : -EBUSY;
	if (step < 1 || step > 7)
		return -EINVAL;
	if (step <= 5 && (!red_required || ever_armed))
		return -EINVAL;
	if (step >= 6 && (red_required || strcmp(tc_hold->leaf->ops->id, "pfifo")))
		return -EINVAL;
	if ((step == 2 && !(extra_acked & BIT(1))) ||
	    (step == 3 && !(extra_acked & BIT(2))) ||
	    (step == 5 && !(extra_acked & BIT(4))))
		return -EINVAL;
	if (step == 1 || step == 4)
		extra_acked = 0;
	extra_step = step;
	shaper_message = (struct relay_shaper_message) {
		.command = cpu_to_le32(RELAY_RED_CONFIG),
		.tag = cpu_to_le32(default_tag),
	};
	p = &shaper_message.data.red;
	if (step >= 6) {
		p->limit = cpu_to_le32(step == 6 ? 0 : 128);
		p->weight_mode = cpu_to_le32(1); /* FIFO TAIL field; selected image ignores it. */
	} else if (step == 1 || step == 4) {
		p->traffic_classes = cpu_to_le32(step == 1 ? 2 : 1);
		p->default_class = cpu_to_le32(1);
	} else {
		p->traffic_id = cpu_to_le32(step == 3 ? 2 : 1);
		p->weight_value = cpu_to_le32(step == 3 ? 8 : 0);
		p->limit = cpu_to_le32(65536); /* Not a claimed firmware-enforced cap. */
		p->minimum = cpu_to_le32(step == 5 ? 65536 : step == 2 ? 4096 : 16384);
		p->maximum = cpu_to_le32(step == 5 ? 65535 : step == 2 ? 12288 : 49152);
		p->probability = cpu_to_le32(step == 5 ? 0 : 13);
		p->ewma_log = cpu_to_le32(step == 5 ? 0 : 4);
	}
	red_config_acked = false;
	return relay_command(RELAY_ISHAPER_CONFIG, true, RELAY_WAIT_MS);
}

static int relay_restore(void)
{
	int error;

	if (!self_pinned)
		return 0;
	error = relay_stop();
	if (error)
		return error;
	if (pending_request) {
		error = relay_command(pending_opcode, false, RELAY_WAIT_MS);
		if (pending_request)
			return error; /* no inverse command after UNKNOWN */
		/* A settled rejected SET changed nothing. A rejected RESET below
		 * leaves attached true and can be explicitly retried by restore.
		 */
	}
	if (qdx_service_access_ended(relay_service))
		attached = false;
	if (attached) {
		error = relay_command(RELAY_RESET_NEXTHOP, true, RELAY_WAIT_MS);
		if (error)
			return error;
	}
	if (resume_rx) {
		error = qdx_rx_release(resume_rx);
		if (error)
			return error;
		resume_rx = NULL;
	}
	if (source_rx) {
		error = qdx_rx_release(source_rx);
		if (error)
			return error;
		source_rx = NULL;
	}
	held = false;
	running = false;
	if (tc_hold) {
		struct relay_tc_hold *hold = tc_hold;

		tc_hold = NULL;
		qdx_tc_ref_put(hold->reference);
		relay_tc_put(hold);
	}
	/* SET_DEFAULT has no zero-tag clear. After finite traffic settlement and
	 * this relay restore, root removes the native test qdisc; actual node FREE
	 * clears the firmware default. We do not free another owner's node here.
	 */
	relay_put_refs();
	return 0;
}

static int relay_status_show(struct seq_file *seq, void *unused)
{
	struct qdx_result result;
	unsigned long flags;
	unsigned int deliveries;

	mutex_lock(&relay_lock);
	result = last_result;
	deliveries = result_deliveries;
	if (pending_reply) {
		spin_lock_irqsave(&pending_reply->lock, flags);
		result = pending_reply->result;
		deliveries = pending_reply->deliveries;
		spin_unlock_irqrestore(&pending_reply->lock, flags);
	}
	seq_printf(seq, "source=%s source_ifnum=%u target=%s target_ifnum=%u\n",
		RELAY_SOURCE_NAME, RELAY_SOURCE_IFNUM,
		RELAY_TARGET_NAME, RELAY_TARGET_IFNUM);
	seq_printf(seq, "allow_writes=%u pinned=%u source_rx=%u resume_rx=%u held=%u attached=%u running=%u\n",
		allow_writes, self_pinned, !!source_rx, !!resume_rx,
		held, attached, running);
	seq_printf(seq, "tc_reference=%u tc_invalid=%u default_tag=%#x default_acked=%u shaper_uncertain=%u\n",
		!!tc_hold, tc_hold ? READ_ONCE(tc_hold->invalid) : false,
		default_tag, default_acked, shaper_uncertain);
	seq_printf(seq, "shaper_command=%u red_required=%u red_config_acked=%u ever_armed=%u\n",
		le32_to_cpu(shaper_message.command), red_required, red_config_acked, ever_armed);
	if (le32_to_cpu(shaper_message.command) == RELAY_RED_CONFIG)
		seq_printf(seq, "red_limit=%u red_classes=%u red_id=%u red_min=%u red_max=%u red_probability=%u red_ewma_log=%u red_ecn=%u\n",
			le32_to_cpu(shaper_message.data.red.limit),
			le32_to_cpu(shaper_message.data.red.traffic_classes),
			le32_to_cpu(shaper_message.data.red.traffic_id),
			le32_to_cpu(shaper_message.data.red.minimum),
			le32_to_cpu(shaper_message.data.red.maximum),
			le32_to_cpu(shaper_message.data.red.probability),
			le32_to_cpu(shaper_message.data.red.ewma_log), shaper_message.data.red.ecn);
	seq_printf(seq, "extra_step=%u extra_acked=%#x\n", extra_step, extra_acked);
	seq_printf(seq, "service_state=%d access_ended=%u pending=%u pending_opcode=%u last_error=%d\n",
		relay_service ? (int)qdx_service_state(relay_service) : -1,
		relay_service ? qdx_service_access_ended(relay_service) : false,
		!!pending_request, pending_opcode, last_error);
	seq_printf(seq, "id=%llu opcode=%u ifnum=%u outcome=%u error=%d firmware_error=%u published=%u exposure_ended=%u received=%zu declared=%zu deliveries=%u\n",
		(unsigned long long)result.id, result.opcode, result.ifnum,
		result.outcome, result.error, result.firmware_error,
		result.published, result.exposure_ended, result.received_len,
		result.declared_len, deliveries);
	mutex_unlock(&relay_lock);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(relay_status);

static ssize_t relay_control_write(struct file *file, const char __user *buffer,
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
	command[count] = '\0';
	strim(command);
	rtnl_lock();
	mutex_lock(&relay_lock);
	if (!strcmp(command, "prepare"))
		error = relay_prepare();
	else if (!strcmp(command, "default"))
		error = relay_default();
	else if (!strcmp(command, "red-config"))
		error = relay_red_config();
	else if (!strcmp(command, "wred-setup"))
		error = relay_extra_config(1);
	else if (!strcmp(command, "wred-low"))
		error = relay_extra_config(2);
	else if (!strcmp(command, "wred-high"))
		error = relay_extra_config(3);
	else if (!strcmp(command, "byte-setup"))
		error = relay_extra_config(4);
	else if (!strcmp(command, "byte-fifo"))
		error = relay_extra_config(5);
	else if (!strcmp(command, "fifo-zero"))
		error = relay_extra_config(6);
	else if (!strcmp(command, "fifo-restore"))
		error = relay_extra_config(7);
	else if (!strcmp(command, "arm"))
		error = relay_arm();
	else if (!strcmp(command, "stop"))
		error = relay_stop();
	else if (!strcmp(command, "restore"))
		error = relay_restore();
	else if (!strcmp(command, "poll"))
		error = pending_request ? relay_command(pending_opcode, false, 0) : 0;
	else
		error = -EINVAL;
	last_error = error;
	mutex_unlock(&relay_lock);
	rtnl_unlock();
	return error ?: count;
}

static const struct file_operations relay_control_fops = {
	.owner = THIS_MODULE,
	.write = relay_control_write,
};

static int __init relay_init(void)
{
	struct dentry *entry;

	relay_debugfs = debugfs_create_dir("qdx_relay_diag", NULL);
	if (IS_ERR_OR_NULL(relay_debugfs))
		return relay_debugfs ? PTR_ERR(relay_debugfs) : -ENOMEM;
	entry = debugfs_create_file("control", 0200, relay_debugfs, NULL,
		&relay_control_fops);
	if (IS_ERR_OR_NULL(entry))
		goto fail;
	entry = debugfs_create_file("status", 0400, relay_debugfs, NULL,
		&relay_status_fops);
	if (IS_ERR_OR_NULL(entry))
		goto fail;
	return 0;
fail:
	debugfs_remove_recursive(relay_debugfs);
	return entry ? PTR_ERR(entry) : -ENOMEM;
}

static void __exit relay_exit(void)
{
	/* Normal unload is refused by explicit and command-recipient references
	 * while resources or an unknown result survive. No timed cleanup here.
	 */
	WARN_ON(self_pinned || pending_request || pending_reply || source_rx || resume_rx || attached || tc_hold);
	debugfs_remove_recursive(relay_debugfs);
}
module_init(relay_init);
module_exit(relay_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Isolated fixed NSS relay with native TC default leaf for QDX 114368");
