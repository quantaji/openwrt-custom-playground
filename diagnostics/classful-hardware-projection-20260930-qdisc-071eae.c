// SPDX-License-Identifier: GPL-2.0-only
#include <linux/math64.h>
#include <linux/overflow.h>
#include <linux/rtnetlink.h>
#include <linux/slab.h>
#include <net/codel.h>
#include <net/red.h>
#include "tc.h"

static int qdx_tc_rate(struct qdx_shaper_rate *wire,
		       const struct psched_ratecfg *rate, s64 ns,
		       u32 explicit_bytes, u32 maximum, bool common_overhead)
{
	u64 seconds, remainder, whole, part, burst;

	if (!rate->rate_bytes_ps || rate->rate_bytes_ps > U32_MAX || !maximum ||
	    rate->mpu || rate->linklayer == TC_LINKLAYER_ATM ||
	    (!common_overhead && rate->overhead) || ns < 0)
		return -EOPNOTSUPP;
	if (explicit_bytes) {
		burst = explicit_bytes;
	} else {
		seconds = div64_u64_rem(ns, NSEC_PER_SEC, &remainder);
		if (check_mul_overflow(rate->rate_bytes_ps, seconds, &whole))
			return -ERANGE;
		/* The admitted u32 rate times a sub-second remainder fits u64. */
		part = div64_u64(rate->rate_bytes_ps * remainder, NSEC_PER_SEC);
		if (check_add_overflow(whole, part, &burst))
			return -ERANGE;
	}
	if (burst < maximum || burst > U32_MAX)
		return -ERANGE;
	wire->rate_bytes_ps = cpu_to_le32(rate->rate_bytes_ps);
	wire->burst_bytes = cpu_to_le32(burst);
	wire->max_size = cpu_to_le32(maximum);
	return 0;
}

static int qdx_tc_codel_time(u32 ticks, __le16 *wire)
{
	u64 ms = DIV_ROUND_UP_ULL((u64)ticks << CODEL_SHIFT, NSEC_PER_MSEC);

	if (!ms || ms > U16_MAX ||
	    (ms * NSEC_PER_MSEC >> CODEL_SHIFT) != ticks)
		return -ERANGE;
	*wire = cpu_to_le16(ms);
	return 0;
}

static int qdx_tc_codel(struct qdx_shaper_codel *wire,
			const struct tc_codel_qopt_offload_params *native)
{
	int err;

	if (native->ecn || native->ce_threshold != CODEL_DISABLED_THRESHOLD ||
	    !native->mtu || native->mtu > U16_MAX || !native->limit ||
	    native->limit > S32_MAX)
		return -EOPNOTSUPP;
	err = qdx_tc_codel_time(native->target, &wire->target_ms);
	if (err)
		return err;
	err = qdx_tc_codel_time(native->interval, &wire->interval_ms);
	if (err)
		return err;
	wire->mtu = cpu_to_le16(native->mtu);
	wire->limit_packets = cpu_to_le32(native->limit);
	return 0;
}

struct qdx_tc_parameters {
	struct tc_qdisc_offload_owner native;
	enum qdx_shaper_kind kind;
	union qdx_shaper_parameters parameters;
	union qdx_shaper_parameters peak;
	bool output_peak; /* Selected only after the complete native walk. */
	bool fq;
};

/* One translation point for normal typed offers and native current replay.
 * Traversal supplies the actual parent; no netlink/private-state parser lives
 * here. Owner/sink pointers remain borrowed until this call returns.
 */
static int qdx_tc_translate(struct net_device *dev, enum qdx_shaper_kind parent_kind,
			    enum tc_setup_type type, const void *data,
			    bool bucket_empty, struct qdx_tc_parameters *result)
{
	struct tc_qdisc_offload_owner *native = &result->native;
	union qdx_shaper_parameters parameters = {};
	enum qdx_shaper_kind kind;
	int err;

	switch (type) {
	case TC_SETUP_QDISC_TBF: {
		const struct tc_tbf_qopt_offload *offer = data;
		const struct tc_tbf_qopt_offload_replace_params *p = &offer->replace_params;

		*native = offer->owner;
		kind = QDX_SHAPER_TBL;
		err = qdx_tc_rate(&parameters.tbf.rate, &p->rate, p->buffer_ns,
				  p->burst, p->max_size, false);
		if (err)
			return err;
		/* M31 selects the exact-byte table, not a packet-size admission cap.
		 * Keep the native envelope check above; do not clamp allowed frames.
		 */
		if (le32_to_cpu(parameters.tbf.rate.burst_bytes) < 31)
			return -ERANGE;
		parameters.tbf.rate.max_size = cpu_to_le32(31);
		parameters.tbf.peak.short_circuit = 1; /* TBL does not enforce PIR. */
		if (p->peak.rate_bytes_ps) {
			err = qdx_tc_rate(&result->peak.htb.ceil, &p->peak, p->peak_buffer_ns,
					  p->peak_burst, p->max_size, false);
			if (err)
				return err;
			if (le32_to_cpu(result->peak.htb.ceil.burst_bytes) < 31)
				return -ERANGE;
			result->peak.htb.ceil.max_size = cpu_to_le32(31);
			result->peak.htb.rate = result->peak.htb.ceil;
			result->peak.htb.quantum = cpu_to_le32(p->max_size);
		}
		break;
	}
	case TC_SETUP_QDISC_FIFO: {
		const struct tc_fifo_qopt_offload *offer = data;

		*native = offer->owner;
		kind = QDX_SHAPER_FIFO;
		if (!offer->limit)
			return -ERANGE;
		if (offer->byte_limit) {
			if (parent_kind != QDX_SHAPER_TBL ||
			    offer->head_drop)
				return -EOPNOTSUPP;
			/* Separate plain storage for the selected native rate stage;
			 * this never claims the native BFIFO byte limit moved here.
			 */
			parameters.fifo.limit_packets = cpu_to_le32(128);
		} else {
			parameters.fifo.limit_packets = cpu_to_le32(offer->limit);
		}
		parameters.fifo.drop_mode = cpu_to_le32(offer->head_drop ? 0 : 1);
		break;
	}
	case TC_SETUP_QDISC_PRIO: {
		const struct tc_prio_qopt_offload *offer = data;

		*native = offer->owner;
		if (offer->replace_params.bands < 1 ||
		    offer->replace_params.bands > TCQ_PRIO_BANDS)
			return -ERANGE;
		kind = QDX_SHAPER_PRIO;
		break;
	}
	case TC_SETUP_QDISC_HTB: {
		const struct tc_htb_qopt_offload *offer = data;

		*native = offer->owner;
		if (!offer->explicit_offload)
			return -EOPNOTSUPP;
		if (!offer->owner.class) {
			kind = QDX_SHAPER_HTB;
			break;
		}
		kind = QDX_SHAPER_HTB_GROUP;
		if (offer->ratecfg.overhead != offer->ceilcfg.overhead ||
		    offer->effective_prio >= TC_HTB_NUMPRIO ||
		    !offer->effective_quantum)
			return -EOPNOTSUPP;
		err = qdx_tc_rate(&parameters.htb.rate, &offer->ratecfg,
				  offer->buffer_ns, 0, psched_mtu(dev), true);
		if (err)
			return err;
		err = qdx_tc_rate(&parameters.htb.ceil, &offer->ceilcfg,
				  offer->ceil_buffer_ns, 0, psched_mtu(dev), true);
		if (err)
			return err;
		parameters.htb.quantum = cpu_to_le32(offer->effective_quantum);
		parameters.htb.priority = cpu_to_le32(offer->effective_prio);
		parameters.htb.overhead = cpu_to_le32(offer->ratecfg.overhead);
		break;
	}
	case TC_SETUP_QDISC_CODEL: {
		const struct tc_codel_qopt_offload *offer = data;

		*native = offer->owner;
		kind = QDX_SHAPER_CODEL;
		err = qdx_tc_codel(&parameters.codel, &offer->set);
		if (err)
			return err;
		break;
	}
	case TC_SETUP_QDISC_FQ_CODEL: {
		const struct tc_fq_codel_qopt_offload *offer = data;

		*native = offer->owner;
		kind = QDX_SHAPER_CODEL;
		if (!offer->flows || !offer->quantum || !bucket_empty)
			return -EOPNOTSUPP;
		err = qdx_tc_codel(&parameters.codel, &offer->codel);
		if (err)
			return err;
		parameters.codel.flows = cpu_to_le32(offer->flows);
		parameters.codel.quantum = cpu_to_le32(offer->quantum);
		result->fq = true;
		break;
	}
	case TC_SETUP_QDISC_RED: {
		const struct tc_red_qopt_offload *offer = data;
		const struct tc_red_qopt_offload_params *p = &offer->set;

		*native = offer->owner;
		kind = QDX_SHAPER_RED;
		if (!p->is_ecn || p->is_harddrop || p->is_nodrop || p->adaptive ||
		    p->early_drop_block || p->mark_block ||
		    p->flags != TC_RED_ECN || !p->limit || p->min >= p->max ||
		    p->max > p->limit)
			return -EOPNOTSUPP;
		parameters.red.limit_bytes = cpu_to_le32(p->limit);
		parameters.red.traffic_classes = cpu_to_le32(1);
		parameters.red.default_class = cpu_to_le32(1);
		parameters.red.traffic_id = cpu_to_le32(1);
		parameters.red.minimum = cpu_to_le32(p->min);
		parameters.red.maximum = cpu_to_le32(p->max);
		/* The u32 probability product plus rounding adjustment fits in u40. */
		parameters.red.probability = cpu_to_le32(
			DIV64_U64_ROUND_UP((u64)p->probability * 255, 1ULL << 32));
		parameters.red.ewma_log = cpu_to_le32(p->Wlog);
		parameters.red.ecn = 1;
		break;
	}
	default:
		return -EOPNOTSUPP;
	}
	if (!native->sch || rtnl_dereference(native->sch->stab))
		return -EOPNOTSUPP;
	result->kind = kind;
	result->parameters = parameters;
	return 0;
}

/* Compare the actual compound execution, including a pending peak allocation.
 * FQ DMA addresses are storage, not native configuration inputs.
 */
static bool qdx_tc_parameters_match(const struct qdx_tc_node *node,
				    const struct qdx_tc_parameters *parameters)
{
	union qdx_shaper_parameters existing = node->parameters;
	bool output_peak = node->tree->peak_node == node;
	bool peak = parameters->peak.htb.ceil.rate_bytes_ps && !parameters->output_peak;

	if (node->fq) {
		existing.codel.flows_memory = 0;
		existing.codel.flows_memory_size = 0;
	}
	if (output_peak != parameters->output_peak)
		return false;
	if (output_peak &&
	    (node->tree->peak_parameters.rate_bytes_ps !=
	     le32_to_cpu(parameters->peak.htb.ceil.rate_bytes_ps) ||
	     node->tree->peak_parameters.burst_bytes !=
	     le32_to_cpu(parameters->peak.htb.ceil.burst_bytes)))
		return false;
	if (node->kind != parameters->kind ||
	    memcmp(&existing, &parameters->parameters, sizeof(existing)) ||
	    !!node->tbf_peak != peak)
		return false;
	return !peak || (node->tbf_peak->kind == QDX_SHAPER_HTB_GROUP &&
		!node->tbf_peak->retiring &&
		!memcmp(&node->tbf_peak->parameters, &parameters->peak, sizeof(existing)));
}

bool qdx_tc_tree_get(void *object)
{
	struct qdx_tc_tree *tree = object;

	return refcount_inc_not_zero(&tree->refs);
}

void qdx_tc_tree_put(void *object)
{
	struct qdx_tc_tree *tree = object;

	if (!refcount_dec_and_test(&tree->refs))
		return;
	WARN_ON_ONCE(!list_empty(&tree->nodes));
	WARN_ON_ONCE(tree->htb_parent || tree->peak || tree->peak_node);
	WARN_ON_ONCE(rcu_access_pointer(tree->selection));
	if (tree->previous_root)
		qdx_tc_tree_put(tree->previous_root);
	kfree(tree->selection_storage[0]);
	kfree(tree->selection_storage[1]);
	kfree(tree->packet_nodes);
	qdx_endpoint_put(tree->endpoint);
	qdx_tc_owner_put(tree->owner);
	kfree(tree);
}

bool qdx_tc_node_get(void *object)
{
	struct qdx_tc_node *node = object;

	return refcount_inc_not_zero(&node->refs);
}

void qdx_tc_node_put(void *object)
{
	struct qdx_tc_node *node = object;

	if (!refcount_dec_and_test(&node->refs))
		return;
	WARN_ON_ONCE(node->allocated || node->linked || node->flows_memory ||
		     node->queue || node->path || node->tbf_peak || node->stats.query_source ||
		     node->tree->owner->root_allocation == node);
	if (node->stats.source)
		gnet_stats_hw_source_put(node->stats.source);
	ida_free(&node->tree->owner->tags, node->tag >> QDX_SHAPER_TAG_SHIFT);
	qdx_tc_tree_put(node->tree);
	kfree(node);
}

static void qdx_tc_node_progress(void *object)
{
	struct qdx_tc_node *node = object;

	/* This callback runs outside the driver resource lock. The same owner
	 * may synchronously await scope cleanup while holding RTNL, independently
	 * of its scheduled worker and of which node now owns a transferred qid.
	 */
	complete(&node->tree->owner->drain_progress);
	qdx_tc_schedule(node->tree->owner);
}

static struct qdx_tc_node *qdx_tc_node_alloc(struct qdx_tc_tree *tree)
{
	struct qdx_owner holder;
	struct qdx_tc_node *node;
	int tag, i;

	tag = ida_alloc_range(&tree->owner->tags, 1, U16_MAX, GFP_KERNEL);
	if (tag < 0)
		return ERR_PTR(tag);
	node = kzalloc(sizeof(*node), GFP_KERNEL);
	if (!node) {
		ida_free(&tree->owner->tags, tag);
		return ERR_PTR(-ENOMEM);
	}
	refcount_set(&node->refs, 1);
	INIT_LIST_HEAD(&node->list);
	qdx_tc_tree_get(tree);
	node->tree = tree;
	node->endpoint = tree->endpoint;
	/* Keep the allocated compact identity separate from its firmware encoding.
	 * A small integer can ACK allocation without selecting that packet node.
	 */
	node->tag = (u32)tag << QDX_SHAPER_TAG_SHIFT;
	node->qid = U16_MAX;
	holder = (struct qdx_owner) {
		.module = THIS_MODULE,
		.object = node,
		.get = qdx_tc_node_get,
		.put = qdx_tc_node_put,
	};
	for (i = 0; i < QDX_TC_NODE_OPERATIONS; i++)
		qdx_tc_command_init(&node->command[i], tree->owner, &holder);
	qdx_tc_command_init(&node->stats.command, tree->owner, &holder);
	INIT_LIST_HEAD(&node->drain_wait.node);
	node->drain_wait.owner = holder;
	node->drain_wait.progress = qdx_tc_node_progress;
	list_add_tail(&node->list, &tree->nodes);
	return node;
}

static struct qdx_tc_tree *qdx_tc_tree_alloc(struct qdx_tc_owner *owner,
					    struct Qdisc *root)
{
	struct qdx_owner holder;
	struct qdx_tc_tree *tree;
	struct qdx_endpoint *endpoint;

	if (owner->ifb_state && !owner->endpoint)
		return ERR_PTR(-EAGAIN);
	if (!owner->endpoint) {
		endpoint = qdx_endpoint_get(owner->service, owner->dev);
		if (IS_ERR(endpoint))
			return ERR_CAST(endpoint);
		owner->endpoint = endpoint;
	}
	endpoint = owner->endpoint;
	qdx_endpoint_hold(endpoint);
	tree = kzalloc(sizeof(*tree), GFP_KERNEL);
	if (!tree) {
		qdx_endpoint_put(endpoint);
		return ERR_PTR(-ENOMEM);
	}
	refcount_set(&tree->refs, 1);
	INIT_LIST_HEAD(&tree->nodes);
	INIT_LIST_HEAD(&tree->list);
	qdx_tc_owner_get(owner);
	tree->owner = owner;
	tree->endpoint = endpoint;
	tree->root_handle = root->handle;
	tree->normal_direct_count = owner->port_ops ?
		owner->port_ops->normal_direct_count : owner->dev->real_num_tx_queues;
	tree->class_capacity = owner->dev->num_tx_queues - tree->normal_direct_count;
	tree->held = true;
	holder = (struct qdx_owner) {
		.module = THIS_MODULE,
		.object = tree,
		.get = qdx_tc_tree_get,
		.put = qdx_tc_tree_put,
	};
	qdx_tc_command_init(&tree->root_command, owner, &holder);
	qdx_tc_command_init(&tree->default_command, owner, &holder);
	list_add_tail_rcu(&tree->list, &owner->trees);
	return tree;
}

/* Execute, or revisit, one original operation. An unresolved request is never
 * replaced. The caller records the resulting real state before reusing storage.
 */
static int qdx_tc_shaper_command(struct qdx_tc_command *command,
				 struct qdx_endpoint *endpoint,
				 struct qdx_shaper_message *message)
{
	const struct qdx_reply_bounds bounds = {
		.minimum = sizeof(*message), .maximum = sizeof(*message),
		.capacity = sizeof(*message),
	};
	struct qdx_result result;
	u32 opcode = le32_to_cpu(message->command);
	bool malformed;
	int err;

	if (!command->request) {
		err = qdx_tc_command_start(command, endpoint, QDX_TC_ISHAPER_CONFIG,
					   message, sizeof(*message), &bounds);
		if (err)
			return err;
	}
	err = qdx_tc_command_wait(command);
	spin_lock_bh(&command->lock);
	result = command->result;
	if (result.outcome == QDX_ACK && command->reply_length == sizeof(*message))
		memcpy(message, command->reply, sizeof(*message));
	malformed = result.outcome == QDX_ACK &&
		(result.declared_len != sizeof(*message) ||
		 command->reply_length != sizeof(*message) ||
		 le32_to_cpu(message->command) != opcode);
	spin_unlock_bh(&command->lock);
	if (result.outcome == QDX_UNKNOWN && !result.exposure_ended)
		return err ?: -EINPROGRESS;
	if (malformed) {
		spin_lock_bh(&command->lock);
		command->malformed_reply = true;
		command->result.outcome = QDX_UNKNOWN;
		command->result.error = -EPROTO;
		spin_unlock_bh(&command->lock);
		qdx_stop_execution(command->owner->service, -EPROTO);
		return -EPROTO;
	}
	qdx_tc_command_clear(command);
	if (result.outcome != QDX_ACK)
		return result.error ?: err ?: -EIO;
	if (message->response)
		return -EREMOTEIO;
	return 0;
}

static int qdx_tc_assignment(struct qdx_tc_tree *tree, bool attach)
{
	struct qdx_shaper_assignment message = {};
	struct qdx_tc_owner *owner = tree->owner;
	struct qdx_tc_command *command = attach ? &owner->assign : &owner->unassign;
	struct qdx_tc_command *opposite = attach ? &owner->unassign : &owner->assign;
	const size_t length = attach ? sizeof(message) : sizeof(message.shaper);
	const struct qdx_reply_bounds bounds = {
		.minimum = length, .maximum = length, .capacity = length,
	};
	struct qdx_result result;
	bool malformed;
	int err;

	/* A new generation cannot pass an original opposite operation. Retirement
	 * records a late ASSIGN grant before UNASSIGN; forward prepare may finish
	 * the already submitted UNASSIGN, never start a second one over it.
	 */
	if (opposite->request) {
		if (!attach)
			return -EINPROGRESS;
		err = qdx_tc_assignment(tree, false);
		if (err)
			return err;
	}
	if (!wait_for_completion_timeout(&opposite->recipient_done, QDX_TC_COMMAND_TIMEOUT))
		return -EINPROGRESS;
	if (!command->request && qdx_service_access_ended(owner->service)) {
		owner->assigned = false;
		return attach ? -ESHUTDOWN : 0;
	}
	if (owner->assigned == attach && !command->request)
		return wait_for_completion_timeout(&command->recipient_done,
						   QDX_TC_COMMAND_TIMEOUT) ? 0 : -EINPROGRESS;
	message.shaper = cpu_to_le32(attach ? 0 : owner->shaper);
	if (!command->request) {
		err = qdx_tc_command_start(command, tree->endpoint,
			attach ? QDX_TC_ISHAPER_ASSIGN : QDX_TC_ISHAPER_UNASSIGN,
			&message, length, &bounds);
		if (err)
			return err;
	}
	err = qdx_tc_command_wait(command);
	spin_lock_bh(&command->lock);
	result = command->result;
	if (result.outcome == QDX_ACK && command->reply_length == length)
		memcpy(&message, command->reply, length);
	malformed = result.outcome == QDX_ACK &&
		(result.declared_len != length || command->reply_length != length);
	if (malformed) {
		command->malformed_reply = true;
		command->result.outcome = QDX_UNKNOWN;
		command->result.error = -EPROTO;
	}
	spin_unlock_bh(&command->lock);
	if (malformed) {
		/* An accepted assignment may have created a real shaper. Retain
		 * this original record until qualified access end, not a new ASSIGN.
		 */
		qdx_stop_execution(owner->service, -EPROTO);
		return -EPROTO;
	}
	if (result.outcome == QDX_UNKNOWN && !result.exposure_ended)
		return err ?: -EINPROGRESS;
	if (qdx_service_access_ended(owner->service)) {
		owner->assigned = false;
		qdx_tc_command_clear(command);
		return attach ? -ESHUTDOWN : 0;
	}
	if (result.outcome != QDX_ACK) {
		qdx_tc_command_clear(command);
		return result.error ?: err ?: -EIO;
	}
	owner->assigned = attach;
	if (attach)
		owner->shaper = le32_to_cpu(message.assigned);
	qdx_tc_command_clear(command);
	return 0;
}

static int qdx_tc_node_create(struct qdx_tc_node *node, bool intended_root)
{
	struct qdx_tc_owner *owner = node->tree->owner;
	struct qdx_tc_node *root = owner->root_allocation;
	struct qdx_tc_command *allocate = &node->command[QDX_TC_NODE_ALLOC];
	struct qdx_shaper_message message = {};
	size_t bytes;
	dma_addr_t address;
	u32 flows;
	int err;

	lockdep_assert_held(&owner->cfg);
	if (node->retiring || node->tree->retiring)
		return -EAGAIN;
	if (!root) {
		/* A retained allocation cannot be promoted by SET_ROOT. Its own
		 * FREE/re-ALLOC must follow the previous actual root's retirement.
		 */
		if (!intended_root || node->allocated)
			return -EAGAIN;
		owner->root_allocation = node;
	} else if (root != node) {
		if (intended_root || !root->allocated || root->retiring ||
		    root->tree->retiring || root->command[QDX_TC_NODE_ALLOC].request ||
		    root->command[QDX_TC_NODE_FREE].request)
			return -EAGAIN;
	} else if (!intended_root) {
		return -EAGAIN;
	}
	err = qdx_tc_assignment(node->tree, true);
	if (err)
		return err;
	if (!node->allocated) {
		message.command = cpu_to_le32(QDX_SHAPER_ALLOC);
		message.data.allocate.kind = cpu_to_le32(node->kind);
		message.data.allocate.tag = cpu_to_le32(node->tag);
		err = qdx_tc_shaper_command(allocate, node->endpoint, &message);
		if (err) {
			if (owner->root_allocation == node && !allocate->request &&
			    completion_done(&allocate->recipient_done))
				owner->root_allocation = NULL;
			return err;
		}
		node->allocated = true;
		node->stats.close = QDX_TC_STATS_OPEN;
		node->memory_queried = false;
		node->probability_reported = false;
	}
	if (node->fq && !node->memory_queried) {
		memset(&message, 0, sizeof(message));
		message.command = cpu_to_le32(QDX_SHAPER_MEMORY);
		message.data.node.tag = cpu_to_le32(node->tag);
		err = qdx_tc_shaper_command(&node->command[QDX_TC_NODE_MEMORY],
					     node->endpoint, &message);
		if (err)
			return err;
		node->memory_per_flow = le32_to_cpu(message.data.node.parameters.memory_per_flow);
		if (!node->memory_per_flow)
			return -EPROTO;
		node->memory_queried = true;
	}
	if (node->fq && !node->flows_memory) {
		flows = le32_to_cpu(node->parameters.codel.flows);
		if (check_mul_overflow((size_t)flows, (size_t)node->memory_per_flow, &bytes) ||
		    !bytes || bytes > U32_MAX)
			return -ERANGE;
		node->flows_memory = qdx_dma_alloc(node->tree->owner->service, bytes, 64,
						 DMA_BIDIRECTIONAL);
		if (IS_ERR(node->flows_memory)) {
			err = PTR_ERR(node->flows_memory);
			node->flows_memory = NULL;
			return err;
		}
		address = qdx_dma_address(node->flows_memory);
		if (upper_32_bits(address) || bytes - 1 > U32_MAX - address) {
			qdx_dma_release(node->flows_memory);
			node->flows_memory = NULL;
			return -ERANGE;
		}
		node->flows_memory_size = bytes;
		node->parameters.codel.flows_memory = cpu_to_le32(address);
		node->parameters.codel.flows_memory_size = cpu_to_le32(bytes);
	}
	/* GROUP attachment initializes both child scheduling lists, including
	 * their quantum. Configure those lists only after the actual link.
	 */
	if (node->kind == QDX_SHAPER_HTB_GROUP && node->parent &&
	    node->parent->kind == QDX_SHAPER_HTB_GROUP && !node->linked)
		return 0;
	if (node->configured)
		return 0;
	if (node->kind == QDX_SHAPER_HTB || node->kind == QDX_SHAPER_PRIO) {
		/* These nodes have topology, not a CHANGE_PARAM payload. */
		node->configured = true;
		return 0;
	}
	if (node->restore_config && node->command[QDX_TC_NODE_CONFIG].request) {
		memset(&message, 0, sizeof(message));
		message.command = cpu_to_le32(QDX_SHAPER_CONFIG);
		message.data.node.tag = cpu_to_le32(node->tag);
		message.data.node.parameters = node->attempted;
		err = qdx_tc_shaper_command(&node->command[QDX_TC_NODE_CONFIG],
					     node->endpoint, &message);
		if (err && node->command[QDX_TC_NODE_CONFIG].request)
			return err;
		/* The failed native update never committed. Even a late ACK must
		 * be followed by the current old parameters under this same hold.
		 */
	}
	memset(&message, 0, sizeof(message));
	message.command = cpu_to_le32(QDX_SHAPER_CONFIG);
	message.data.node.tag = cpu_to_le32(node->tag);
	message.data.node.parameters = node->parameters;
	if (node->flows_memory)
		qdx_dma_expose(node->flows_memory);
	err = qdx_tc_shaper_command(&node->command[QDX_TC_NODE_CONFIG],
				     node->endpoint, &message);
	if (err)
		return err;
	node->configured = true;
	node->restore_config = false;
	if (node->kind == QDX_SHAPER_RED && !node->probability_reported) {
		netdev_info(node->tree->owner->dev,
			    "TC root %x node %x device RED probability %u/255\n",
			    node->tree->root_handle, node->handle,
			    le32_to_cpu(node->parameters.red.probability));
		node->probability_reported = true;
	}
	return 0;
}

static int qdx_tc_node_link(struct qdx_tc_node *node, bool attach)
{
	struct qdx_shaper_message message = {};
	struct qdx_tc_node *parent = node->parent;
	unsigned int operation = attach ? QDX_TC_NODE_ATTACH : QDX_TC_NODE_DETACH;
	int err;

	if (!parent)
		return 0;
	if (node->linked == attach)
		goto configure;
	/* An unresolved post-ATTACH CONFIG must settle before its inverse.
	 * Retirement reconciles the original request under the existing hold.
	 */
	if (!attach && node->command[QDX_TC_NODE_CONFIG].request)
		return -EINPROGRESS;
	message.command = cpu_to_le32(attach ? QDX_SHAPER_ATTACH : QDX_SHAPER_DETACH);
	message.data.node.tag = cpu_to_le32(parent->tag);
	if (parent->kind == QDX_SHAPER_PRIO && !attach) {
		/* PRIO DETACH names the actual band in the first payload word. */
		message.data.node.parameters.attach.child = cpu_to_le32(node->band);
	} else {
		message.data.node.parameters.attach.child = cpu_to_le32(node->tag);
		if (parent->kind == QDX_SHAPER_PRIO)
			message.data.node.parameters.attach.priority = cpu_to_le32(node->band);
	}
	err = qdx_tc_shaper_command(&node->command[operation], node->endpoint, &message);
	if (err)
		return err;
	node->linked = attach;
	if (attach && node->kind == QDX_SHAPER_HTB_GROUP &&
	    parent->kind == QDX_SHAPER_HTB_GROUP)
		node->configured = false;
configure:
	/* Finish a retained CONFIG before use. A closed rollback allocation
	 * stays held for retirement; restoring its edge must not revive it.
	 */
	if (attach && node->kind == QDX_SHAPER_HTB_GROUP &&
	    parent->kind == QDX_SHAPER_HTB_GROUP &&
	    !node->retiring && !node->tree->retiring)
		return qdx_tc_node_create(node, false);
	return 0;
}

/* The HTB root has one hardware child. This node supplies the approved finite
 * total budget and holds all actual top-level classes, without a native class,
 * queue or statistics source of its own. Reuse its original pending commands.
 */
static int qdx_tc_htb_parent_prepare(struct qdx_tc_tree *tree)
{
	struct qdx_tc_node *parent = tree->htb_parent;
	int err;

	lockdep_assert_held(&tree->owner->cfg);
	if (parent && (parent->retiring || parent->parent != tree->root)) {
		tree->retiring = true;
		return -EAGAIN;
	}
	if (!parent) {
		parent = qdx_tc_node_alloc(tree);
		if (IS_ERR(parent))
			return PTR_ERR(parent);
		parent->kind = QDX_SHAPER_HTB_GROUP;
		parent->parent = tree->root;
		parent->parameters.htb.quantum = cpu_to_le32(1);
		parent->parameters.htb.rate.rate_bytes_ps = cpu_to_le32(1U << 31);
		/* Firmware divides burst * scaled_clock as signed64. S32_MAX
		 * keeps that product positive for every u32 scaled clock.
		 */
		parent->parameters.htb.rate.burst_bytes = cpu_to_le32(S32_MAX);
		parent->parameters.htb.rate.max_size = cpu_to_le32(31);
		parent->parameters.htb.ceil = parent->parameters.htb.rate;
		tree->htb_parent = parent;
	}
	err = qdx_tc_node_create(parent, false);
	if (err)
		return err;
	return qdx_tc_node_link(parent, true);
}

/* Prepare one native qdisc's actual execution nodes. Construct the peak record
 * before publishing outer ALLOC so an UNKNOWN retry retains the whole input.
 * Only the outer node has native identity/source; both own ordinary commands.
 */
static int qdx_tc_qdisc_prepare(struct qdx_tc_node *node,
			       const struct qdx_tc_parameters *parameters,
			       bool intended_root)
{
	struct qdx_tc_node *peak = node->tbf_peak;
	bool nss_peak = parameters->peak.htb.ceil.rate_bytes_ps && !parameters->output_peak;
	int err;

	if (peak && (!nss_peak || peak->retiring ||
	    memcmp(&peak->parameters, &parameters->peak, sizeof(peak->parameters)))) {
		/* Even an unallocated prospective outer may own a pending GROUP.
		 * Keep that original encoding until its real retirement completes.
		 */
		node->tree->retiring = true;
		return -EAGAIN;
	}
	if (!node->allocated && !node->command[QDX_TC_NODE_ALLOC].request) {
		node->kind = parameters->kind;
		node->parameters = parameters->parameters;
		node->fq = parameters->fq;
	}
	if (nss_peak && !peak) {
		peak = qdx_tc_node_alloc(node->tree);
		if (IS_ERR(peak))
			return PTR_ERR(peak);
		peak->kind = QDX_SHAPER_HTB_GROUP;
		peak->parameters = parameters->peak;
		peak->parent = node;
		node->tbf_peak = peak;
	}
	err = qdx_tc_node_create(node, intended_root);
	if (err)
		return err;
	if (node->kind == QDX_SHAPER_HTB)
		return qdx_tc_htb_parent_prepare(node->tree);
	if (!peak)
		return 0;
	err = qdx_tc_node_create(peak, false);
	if (err)
		return err;
	/* GROUP activity requires a real parent before its child is attached. */
	return qdx_tc_node_link(peak, true);
}

static int qdx_tc_tree_root(struct qdx_tc_tree *tree, struct qdx_tc_node *node,
			    bool default_node)
{
	struct qdx_shaper_message message = {
		.command = cpu_to_le32(default_node ? QDX_SHAPER_SET_DEFAULT : QDX_SHAPER_SET_ROOT),
		.data.tag = cpu_to_le32(node->tag),
	};
	int err;

	/* The first eligible ALLOC selects the firmware dequeue root. This
	 * command only completes its attach state; it cannot switch that root.
	 */
	if (!default_node && !tree->root_command.request &&
	    (tree->owner->root_allocation != node || !node->allocated))
		return -EAGAIN;
	err = qdx_tc_shaper_command(default_node ? &tree->default_command : &tree->root_command,
				     tree->endpoint, &message);
	if (!err) {
		if (default_node)
			tree->defaulted = true;
		else
			tree->rooted = true;
	}
	return err;
}

static struct qdx_tc_tree *qdx_tc_find_tree(struct qdx_tc_owner *owner,
					   struct Qdisc *root)
{
	struct qdx_tc_tree *tree;

	list_for_each_entry(tree, &owner->trees, list)
		if (tree->root && tree->root->native == root && !tree->native_dead)
			return tree;
	return NULL;
}

static struct qdx_tc_node *qdx_tc_find_class(struct qdx_tc_tree *tree,
					    unsigned long native_class)
{
	struct qdx_tc_node *node;

	list_for_each_entry(node, &tree->nodes, list)
		if (node->native == tree->root->native &&
		    node->native_class == native_class && !node->native_dead)
			return node;
	return NULL;
}

static struct qdx_tc_node *qdx_tc_storage_child(struct qdx_tc_node *parent)
{
	struct qdx_tc_node *node;

	list_for_each_entry(node, &parent->tree->nodes, list)
		if (node->parent == parent && node->kind != QDX_SHAPER_HTB_GROUP &&
		    !node->retiring)
			return node;
	return NULL;
}

/* The native queue/class decision has already happened. Only descend its
 * unique hardware storage chain; a branching scheduler needs that decision.
 * The caller holds cfg or the available view's data lock and retains its tree.
 */
struct qdx_tc_node *qdx_tc_enqueue_node(struct qdx_tc_node *node)
{
	struct qdx_tc_tree *tree = node->tree;
	struct qdx_tc_node *candidate, *child;
	unsigned int remaining = 0;
	bool storage;

	list_for_each_entry(candidate, &tree->nodes, list)
		remaining++;
	while (remaining--) {
		if (!node->allocated || !node->configured || node->retiring ||
		    node->native_dead || (node->parent && !node->linked))
			return ERR_PTR(-EAGAIN);
		storage = node->kind == QDX_SHAPER_FIFO ||
			  node->kind == QDX_SHAPER_CODEL || node->kind == QDX_SHAPER_RED;
		if (!storage && node->kind != QDX_SHAPER_TBL &&
		    !(node->kind == QDX_SHAPER_HTB_GROUP &&
		      (node->native_leaf || !node->native)))
			return ERR_PTR(-EOPNOTSUPP);
		child = NULL;
		list_for_each_entry(candidate, &tree->nodes, list) {
			if (candidate->parent != node)
				continue;
			if (candidate->retiring) {
				if (candidate->linked)
					return ERR_PTR(-EAGAIN);
				continue;
			}
			if (child)
				return ERR_PTR(-EOPNOTSUPP);
			child = candidate;
		}
		if (storage)
			return child ? ERR_PTR(-EOPNOTSUPP) : node;
		if (!child)
			return ERR_PTR(-EOPNOTSUPP);
		node = child;
	}
	return ERR_PTR(-ELOOP);
}

/* Only actual queue claims go into this view. Inactive-array insertion is
 * bounded by physical allocation and leaves every slot's qid unchanged.
 */
static int qdx_tc_selection_update(struct qdx_tc_tree *tree)
{
	struct qdx_tc_selection *active, *next;
	struct qdx_tc_node *node;
	unsigned int i, at;

	lockdep_assert_held(&tree->owner->cfg);
	active = rcu_dereference_protected(tree->selection,
					 lockdep_is_held(&tree->owner->cfg));
	next = active == tree->selection_storage[0] ?
		tree->selection_storage[1] : tree->selection_storage[0];
	if (!next)
		return -ENOMEM;
	next->major = TC_H_MAJ(tree->root_handle) >> 16;
	next->default_minor = tree->default_class;
	next->count = 0;
	list_for_each_entry(node, &tree->nodes, list) {
		if (!node->native_leaf || node->native_dead || node->qid == U16_MAX)
			continue;
		if (next->count == tree->class_capacity ||
		    node->qid < tree->normal_direct_count ||
		    node->qid >= tree->owner->dev->real_num_tx_queues)
			return -ERANGE;
		at = 0;
		while (at < next->count && next->leaves[at].minor < TC_H_MIN(node->classid))
			at++;
		if (at < next->count && next->leaves[at].minor == TC_H_MIN(node->classid))
			return -EEXIST;
		for (i = next->count; i > at; i--)
			next->leaves[i] = next->leaves[i - 1];
		next->leaves[at] = (struct qdx_tc_leaf) {
			.minor = TC_H_MIN(node->classid), .qid = node->qid, .node = node,
		};
		next->count++;
	}
	/* The owning tree/list keeps nodes alive until the old reader grace ends. */
	rcu_assign_pointer(tree->selection, next);
	synchronize_net();
	return 0;
}

bool qdx_tc_select_queue(struct qdx_tc_owner *owner,
			 const struct sk_buff *skb, u16 *queue)
{
	struct qdx_tc_selection *view;
	struct qdx_tc_tree *tree;
	u16 minor;
	unsigned int lo, hi, mid;
	bool selected = false;

	rcu_read_lock();
	list_for_each_entry_rcu(tree, &owner->trees, list) {
		view = rcu_dereference(tree->selection);
		if (!view)
			continue;
		minor = TC_H_MAJ(skb->priority) >> 16 == view->major ?
			TC_H_MIN(skb->priority) : view->default_minor;
		if (!minor)
			break;
		lo = 0;
		hi = view->count;
		while (lo < hi) {
			mid = lo + (hi - lo) / 2;
			if (view->leaves[mid].minor < minor)
				lo = mid + 1;
			else
				hi = mid;
		}
		if (lo < view->count && view->leaves[lo].minor == minor) {
			*queue = view->leaves[lo].qid;
			selected = true;
		}
		break;
	}
	rcu_read_unlock();
	return selected;
}

/* Prepare the allocation boundary of a real prospective root. RTNL keeps
 * native identities stable; cfg is dropped for invalidation and retirement.
 * Waits cover original command/recipient completions and independent native
 * scope cleanup. A view user or accepted packet still outstanding returns pending.
 */
static int qdx_tc_root_prepare(struct qdx_tc_node *node)
{
	struct qdx_tc_owner *owner = node->tree->owner;
	struct qdx_tc_node *root = owner->root_allocation;
	struct qdx_tc_tree *old;
	int err;

	ASSERT_RTNL();
	lockdep_assert_held(&owner->cfg);
	if (node->native_dead || node->tree->native_dead)
		return -ESTALE;
	if (root == node && !node->retiring && !node->tree->retiring)
		return 0;
	if (root) {
		old = root->tree;
		if (old != node->tree && !node->tree->previous_root &&
		    !old->native_dead && root->native == rtnl_dereference(owner->dev->qdisc)) {
			node->tree->previous_root = old;
			qdx_tc_tree_get(old);
		}
		qdx_tc_tree_get(old);
		old->retiring = true;
		mutex_unlock(&owner->cfg);
		err = qdx_tc_invalidate(owner, true, true);
		if (!err)
			err = qdx_tc_tree_retire(old, true);
		mutex_lock(&owner->cfg);
		if (!err && !old->native_dead)
			old->retiring = false;
		qdx_tc_tree_put(old);
		if (err)
			return err;
	}
	/* An acknowledged prospective allocation is not selected retroactively
	 * when another root is freed. Retire this actual storage before reuse.
	 */
	if (node->allocated || node->tree->retiring) {
		old = node->tree;
		qdx_tc_tree_get(old);
		old->retiring = true;
		mutex_unlock(&owner->cfg);
		err = qdx_tc_invalidate(owner, true, true);
		if (!err)
			err = qdx_tc_tree_retire(old, true);
		mutex_lock(&owner->cfg);
		if (!err)
			old->retiring = false;
		qdx_tc_tree_put(old);
		if (err)
			return err;
	}
	if (owner->closing || !tc_can_offload(owner->dev) ||
	    qdx_service_state(owner->service) != QDX_AVAILABLE)
		return -EAGAIN;
	node->retiring = false;
	return 0;
}

static int qdx_tc_node_reconcile(struct qdx_tc_node *node);

/* The same collector closes both synchronous HTB mutations and whole-tree
 * retirement. Its original query/source and recipient remain independently owned.
 */
static int qdx_tc_node_stats_close(struct qdx_tc_node *node, bool wait_commands)
{
	struct qdx_tc_command *command;
	bool unresolved;
	int err;

	lockdep_assert_held(&node->tree->owner->cfg);
	/* Preserve one final pre-FREE delta through the original collector.
	 * Its old query and recipient drain before this closing submission.
	 */
	if (node->stats.close == QDX_TC_STATS_OPEN)
		node->stats.close = QDX_TC_STATS_CLOSING;
	for (;;) {
		qdx_tc_stats_collect(node);
		if (qdx_tc_stats_drained(node))
			break;
		if (!wait_commands)
			return -EINPROGRESS;
		command = &node->stats.command;
		if (command->request) {
			err = qdx_tc_command_wait(command);
			spin_lock_bh(&command->lock);
			unresolved = command->result.outcome == QDX_UNKNOWN &&
				!command->result.exposure_ended;
			spin_unlock_bh(&command->lock);
			/* Consume its exact query source before waiting for the final
			 * recipient put, then let the same collector try closing once.
			 */
			qdx_tc_stats_collect(node);
			if (unresolved)
				return err ?: -EINPROGRESS;
			if (command->request)
				continue; /* The collector has started its one closing GET. */
		}
		if (!wait_for_completion_timeout(&command->recipient_done,
						 QDX_TC_COMMAND_TIMEOUT))
			return -EINPROGRESS;
	}
	return 0;
}

/* An old native leaf may contain TBF/peak/FQ or PRIO descendants. Close their
 * existing collectors from leaves to this root while every parent edge remains.
 * A failed native mutation restores its claim/qdisc, not a CLOSED allocation;
 * current replay retires these held nodes before preparing that native tree again.
 */
static int qdx_tc_htb_close_stats(struct qdx_tc_node *root)
{
	struct qdx_tc_node *node, *ancestor, *child;
	bool pending, progress, ready;
	int err = 0;

	ASSERT_RTNL();
	lockdep_assert_held(&root->tree->owner->cfg);
	list_for_each_entry(node, &root->tree->nodes, list) {
		for (ancestor = node; ancestor && ancestor != root;
		     ancestor = ancestor->parent)
			;
		if (!ancestor)
			continue;
		node->retiring = true;
		qdx_tc_stats_detach(node);
		/* In particular, a late ALLOC must be known before its closing GET
		 * and before an ancestor can lose the firmware propagation edge.
		 */
		if (!err)
			err = qdx_tc_node_reconcile(node);
	}
	/* Even if an earlier child is pending, current replay must rebuild the
	 * whole closed subtree, including its native root. Keep the first error.
	 */
	if (err)
		return err;
	do {
		pending = false;
		progress = false;
		list_for_each_entry_reverse(node, &root->tree->nodes, list) {
			for (ancestor = node; ancestor && ancestor != root;
			     ancestor = ancestor->parent)
				;
			if (!ancestor || (node->stats.close == QDX_TC_STATS_CLOSED &&
			    qdx_tc_stats_drained(node)))
				continue;
			pending = true;
			ready = true;
			list_for_each_entry(child, &root->tree->nodes, list) {
				if (child->parent == node &&
				    (child->stats.close != QDX_TC_STATS_CLOSED ||
				     !qdx_tc_stats_drained(child))) {
					ready = false;
					break;
				}
			}
			if (!ready)
				continue;
			err = qdx_tc_node_stats_close(node, true);
			if (err)
				return err;
			progress = true;
		}
	} while (pending && progress);
	return pending ? -EINPROGRESS : 0;
}

static int qdx_tc_htb_create(struct qdx_tc_owner *owner,
			     struct tc_htb_qopt_offload *offer)
{
	struct qdx_tc_parameters parameters = {};
	struct qdx_tc_tree *tree;
	struct qdx_tc_node *root;
	size_t view_size;
	int err;

	if (qdx_tc_find_tree(owner, offer->owner.sch))
		return -EEXIST;
	tree = qdx_tc_tree_alloc(owner, offer->owner.sch);
	if (IS_ERR(tree))
		return PTR_ERR(tree);
	tree->explicit_htb = true;
	tree->default_class = offer->default_class;
	view_size = struct_size(tree->selection_storage[0], leaves, tree->class_capacity);
	tree->selection_storage[0] = kzalloc(view_size, GFP_KERNEL);
	tree->selection_storage[1] = kzalloc(view_size, GFP_KERNEL);
	if (!tree->selection_storage[0] || !tree->selection_storage[1]) {
		err = -ENOMEM;
		goto fail;
	}
	root = qdx_tc_node_alloc(tree);
	if (IS_ERR(root)) {
		err = PTR_ERR(root);
		goto fail;
	}
	tree->root = root;
	err = qdx_tc_translate(owner->dev, 0, TC_SETUP_QDISC_HTB, offer, true, &parameters);
	if (err)
		goto fail;
	root->kind = parameters.kind;
	root->parameters = parameters.parameters;
	root->native = parameters.native.sch;
	root->handle = parameters.native.sch->handle;
	err = qdx_tc_root_prepare(root);
	if (err)
		goto fail;
	err = qdx_tc_node_create(root, true);
	if (err)
		goto fail;
	err = qdx_tc_htb_parent_prepare(tree);
	if (err)
		goto fail;
	err = qdx_tc_tree_root(tree, root, false);
	if (err)
		goto fail;
	root->stats.source = gnet_stats_hw_source_open(parameters.native.hw_stats);
	if (IS_ERR(root->stats.source)) {
		err = PTR_ERR(root->stats.source);
		root->stats.source = NULL;
		goto fail;
	}
	/* No native class exists yet. Native htb_init consumes success before its
	 * first queue operation. Execution remains held until current preparation.
	 */
	return qdx_tc_selection_update(tree);
fail:
	tree->cancelled = true;
	tree->native_dead = true;
	tree->retiring = true;
	if (tree->root)
		tree->root->native_dead = true;
	qdx_tc_schedule(owner);
	return err;
}

static int qdx_tc_htb_add(struct qdx_tc_tree *tree,
			  struct tc_htb_qopt_offload *offer)
{
	struct qdx_tc_owner *owner = tree->owner;
	const struct qdx_tc_queue_ops *queues = owner->port_ops ? owner->port_ops->queues : NULL;
	struct qdx_tc_queue_owner claim = {
		.root = offer->owner.sch, .class = offer->owner.class,
	};
	struct qdx_tc_parameters parameters = {};
	struct qdx_tc_node *node, *parent, *old_storage = NULL;
	struct qdx_tc_queue *slot = NULL;
	bool transfer = offer->command == TC_HTB_LEAF_TO_INNER;
	bool detached = false;
	u16 qid = U16_MAX;
	int err, cleanup;

	if (owner->root_allocation != tree->root || !tree->root->allocated ||
	    tree->retiring || tree->root->retiring)
		return -EAGAIN;
	if (!offer->owner.class || qdx_tc_find_class(tree, offer->owner.class))
		return -EEXIST;
	if (!tree->htb_parent || !tree->htb_parent->allocated ||
	    !tree->htb_parent->configured || !tree->htb_parent->linked ||
	    tree->htb_parent->retiring)
		return -EAGAIN;
	parent = offer->parent_class ? qdx_tc_find_class(tree, offer->parent_class) :
		tree->htb_parent;
	if (!parent || parent->kind != QDX_SHAPER_HTB_GROUP)
		return -ENOENT;
	if (!queues)
		return -ENOSPC; /* The actual IFB allocation has no class suffix. */
	if (transfer) {
		if (!parent->native_leaf || !parent->queue)
			return -EINVAL;
		slot = parent->queue;
		qid = parent->qid;
		old_storage = qdx_tc_storage_child(parent);
		if (parent->path) {
			err = qdx_tx_hold(parent->path);
			if (err)
				return err;
			if (!qdx_tx_drained(parent->path))
				return -EBUSY;
		}
	} else {
		if (parent->native_leaf)
			return -EINVAL;
		err = queues->reserve(owner->port, &claim, U16_MAX, &slot, &qid);
		if (err)
			return err;
		if (!(rtnl_dereference(netdev_get_tx_queue(owner->dev, qid)->qdisc_sleeping)->flags &
		      TCQ_F_BUILTIN)) {
			err = -EBUSY;
			goto release_new_slot;
		}
	}
	node = qdx_tc_node_alloc(tree);
	if (IS_ERR(node)) {
		err = PTR_ERR(node);
		goto release_new_slot;
	}
	node->parent = parent;
	node->classid = offer->classid;
	err = qdx_tc_translate(node->tree->owner->dev, QDX_SHAPER_HTB,
			       TC_SETUP_QDISC_HTB, offer, true, &parameters);
	if (err)
		goto fail;
	node->kind = parameters.kind;
	node->parameters = parameters.parameters;
	node->native = parameters.native.sch;
	node->native_class = parameters.native.class;
	node->handle = parameters.native.sch->handle;
	err = qdx_tc_node_create(node, false);
	if (err)
		goto fail;
	node->stats.source = gnet_stats_hw_source_open(parameters.native.hw_stats);
	if (IS_ERR(node->stats.source)) {
		err = PTR_ERR(node->stats.source);
		node->stats.source = NULL;
		goto fail;
	}
	if (old_storage && old_storage->linked) {
		err = qdx_tc_htb_close_stats(old_storage);
		if (err)
			goto fail;
		err = qdx_tc_node_link(old_storage, false);
		if (err)
			goto fail;
		detached = true;
	}
	err = qdx_tc_node_link(node, true);
	if (err)
		goto restore;
	mutex_unlock(&owner->cfg);
	err = queues->activate(slot);
	mutex_lock(&owner->cfg);
	if (err || owner->closing) {
		err = err ?: -ESHUTDOWN;
		goto restore;
	}
	err = queues->claim(slot, &claim);
	if (err)
		goto restore;
	node->queue = slot;
	node->queue_owner = claim;
	node->qid = qid;
	node->native_leaf = true;
	if (transfer) {
		parent->queue = NULL;
		parent->qid = U16_MAX;
		parent->native_leaf = false;
		if (old_storage)
			old_storage->retiring = true;
	}
	err = qdx_tc_selection_update(tree);
	if (WARN_ON_ONCE(err))
		goto restore_claim;
	offer->qid = qid;
	return 0;
restore_claim:
	if (transfer) {
		claim.class = parent->native_class;
		queues->claim(slot, &claim);
		parent->queue = slot;
		parent->queue_owner = claim;
		parent->qid = qid;
		parent->native_leaf = true;
	} else {
		queues->claim(slot, NULL);
	}
	node->queue = NULL;
	node->qid = U16_MAX;
	node->native_leaf = false;
restore:
	cleanup = qdx_tc_node_link(node, false);
	if (!cleanup && detached && !parent->native_dead)
		cleanup = qdx_tc_node_link(old_storage, true);
	/* An old allocation whose collector closed stays retiring even after
	 * link rollback. The original native old_q remains valid for rebuild.
	 */
	if (cleanup)
		tree->hold_error = cleanup;
fail:
	node->native_dead = true;
	node->retiring = true;
	qdx_tc_stats_detach(node);
	if (!transfer) {
		/* Independent failed-operation retirement owns the reserved slot. */
		node->queue = slot;
		node->queue_owner = claim;
		node->qid = qid;
		queues->claim(slot, NULL);
	}
	qdx_tc_schedule(owner);
	return err;
release_new_slot:
	if (!transfer) {
		queues->claim(slot, NULL);
		queues->retire(slot);
		mutex_unlock(&owner->cfg);
		cleanup = queues->release(slot, NULL);
		mutex_lock(&owner->cfg);
		WARN_ON_ONCE(cleanup); /* Never exposed, no native claim or cache. */
	}
	return err;
}

static int qdx_tc_htb_modify(struct qdx_tc_node *node,
			     struct tc_htb_qopt_offload *offer)
{
	struct qdx_tc_parameters parameters = {};
	union qdx_shaper_parameters old = node->parameters;
	struct qdx_shaper_message message = {};
	int err;

	if (node->tree->owner->root_allocation != node->tree->root ||
	    node->tree->retiring || node->retiring || !node->allocated || !node->configured)
		return -EAGAIN;
	err = qdx_tc_translate(node->tree->owner->dev, QDX_SHAPER_HTB,
			       TC_SETUP_QDISC_HTB, offer, true, &parameters);
	if (err)
		return err;
	node->parameters = parameters.parameters;
	message.command = cpu_to_le32(QDX_SHAPER_CONFIG);
	message.data.node.tag = cpu_to_le32(node->tag);
	message.data.node.parameters = node->parameters;
	node->attempted = node->parameters;
	err = qdx_tc_shaper_command(&node->command[QDX_TC_NODE_CONFIG],
				     node->endpoint, &message);
	if (err) {
		node->parameters = old;
		/* The retained original request may still report an ACK. Current
		 * native replay must restore this old encoding before publication.
		 */
		if (node->command[QDX_TC_NODE_CONFIG].request) {
			node->restore_config = true;
			node->configured = false;
		}
	}
	return err;
}

/* Resolve already-published work before deciding its inverse. A late ACK on a
 * cancelled native creation changes acquired hardware state, never permission.
 */
static int qdx_tc_node_reconcile(struct qdx_tc_node *node)
{
	struct qdx_shaper_message message;
	unsigned int operation;
	int err;

	for (operation = 0; operation < QDX_TC_NODE_OPERATIONS; operation++) {
		if (!node->command[operation].request)
			continue;
		memset(&message, 0, sizeof(message));
		switch (operation) {
		case QDX_TC_NODE_ALLOC:
			message.command = cpu_to_le32(QDX_SHAPER_ALLOC);
			message.data.allocate.kind = cpu_to_le32(node->kind);
			message.data.allocate.tag = cpu_to_le32(node->tag);
			break;
		case QDX_TC_NODE_MEMORY:
			message.command = cpu_to_le32(QDX_SHAPER_MEMORY);
			message.data.node.tag = cpu_to_le32(node->tag);
			break;
		case QDX_TC_NODE_CONFIG:
			message.command = cpu_to_le32(QDX_SHAPER_CONFIG);
			message.data.node.tag = cpu_to_le32(node->tag);
			message.data.node.parameters = node->restore_config ?
				node->attempted : node->parameters;
			break;
		case QDX_TC_NODE_ATTACH:
		case QDX_TC_NODE_DETACH:
			message.command = cpu_to_le32(operation == QDX_TC_NODE_ATTACH ?
				QDX_SHAPER_ATTACH : QDX_SHAPER_DETACH);
			message.data.node.tag = cpu_to_le32(node->parent->tag);
			break;
		case QDX_TC_NODE_FREE:
			message.command = cpu_to_le32(QDX_SHAPER_FREE);
			message.data.tag = cpu_to_le32(node->tag);
			break;
		}
		err = qdx_tc_shaper_command(&node->command[operation], node->endpoint, &message);
		if (node->command[operation].request)
			return err ?: -EINPROGRESS;
		if (err)
			continue; /* An actual rejected acquisition creates no state. */
		switch (operation) {
		case QDX_TC_NODE_ALLOC:
			node->allocated = true;
			node->stats.close = QDX_TC_STATS_OPEN;
			node->memory_queried = false;
			node->probability_reported = false;
			break;
		case QDX_TC_NODE_CONFIG:
			node->configured = true;
			break;
		case QDX_TC_NODE_ATTACH:
			node->linked = true;
			if (node->kind == QDX_SHAPER_HTB_GROUP && node->parent &&
			    node->parent->kind == QDX_SHAPER_HTB_GROUP)
				node->configured = false;
			break;
		case QDX_TC_NODE_DETACH:
			node->linked = false;
			break;
		case QDX_TC_NODE_FREE:
			node->allocated = false;
			node->configured = false;
			if (node->tree->owner->root_allocation == node)
				node->tree->rooted = false;
			break;
		default:
			break;
		}
	}
	return 0;
}

static int qdx_tc_node_unconfigure(struct qdx_tc_node *node, bool wait_commands)
{
	struct qdx_tc_owner *owner = node->tree->owner;
	struct qdx_tc_node *child;
	struct qdx_tc_tree *other;
	struct qdx_tc_command *command;
	struct qdx_shaper_message message = {
		.command = cpu_to_le32(QDX_SHAPER_FREE),
		.data.tag = cpu_to_le32(node->tag),
	};
	unsigned int operation;
	int err;

	lockdep_assert_held(&owner->cfg);
	node->retiring = true;
	qdx_tc_stats_detach(node);
	if (node->queue) {
		err = owner->port_ops->queues->retire(node->queue);
		/* A pending scope may belong to a path retained by another node
		 * after native queue transfer. Confirm the execution's actual hold,
		 * then allow FREE and final path release before scope handback.
		 */
		if (err == -EINPROGRESS)
			err = owner->port_ops->queues->hold(node->queue);
		if (err)
			return err;
	}
	if (node->path) {
		err = qdx_tx_hold(node->path);
		if (err)
			return err;
	}
	err = qdx_tc_node_reconcile(node);
	if (err)
		return err;
	if (qdx_service_access_ended(owner->service)) {
		/* The qualified terminal fence ends firmware access, not recipient
		 * callbacks or accepted host carriers checked independently here.
		 */
		node->allocated = false;
		node->configured = false;
		node->linked = false;
		if (owner->root_allocation == node)
			node->tree->rooted = false;
	}
	list_for_each_entry(child, &node->tree->nodes, list)
		if (child->parent == node && (child->linked || child->allocated ||
		    child->command[QDX_TC_NODE_ALLOC].request))
			return -EINPROGRESS;
	err = qdx_tc_node_stats_close(node, wait_commands);
	if (err)
		return err;
	/* GET propagates through the firmware's current parent pointer. Keep
	 * this link until the sole closing query and its recipient have ended.
	 * Events after that sample remain outside its pre-FREE observation.
	 */
	if (node->linked) {
		err = qdx_tc_node_link(node, false);
		if (err)
			return err;
	}
	if (node->allocated && owner->root_allocation == node) {
		/* A child ALLOC already published in another prospective container
		 * must finish before this FREE empties the actual root pointer.
		 * Reconcile its acquisition; do not free unrelated acknowledged nodes.
		 */
		list_for_each_entry(other, &owner->trees, list) {
			list_for_each_entry(child, &other->nodes, list) {
				if (child == node || !child->command[QDX_TC_NODE_ALLOC].request)
					continue;
				err = qdx_tc_node_reconcile(child);
				if (err)
					return err;
			}
		}
	}
	if (node->allocated) {
		err = qdx_tc_shaper_command(&node->command[QDX_TC_NODE_FREE],
					     node->endpoint, &message);
		if (err)
			return err;
		node->allocated = false;
		node->configured = false;
		if (owner->root_allocation == node)
			node->tree->rooted = false;
	}
	for (operation = 0; operation < QDX_TC_NODE_OPERATIONS; operation++) {
		command = &node->command[operation];
		if (completion_done(&command->recipient_done))
			continue;
		if (!wait_commands || !wait_for_completion_timeout(&command->recipient_done,
								 QDX_TC_COMMAND_TIMEOUT))
			return -EINPROGRESS;
	}
	return 0;
}

static void qdx_tc_node_release(struct qdx_tc_node *node)
{
	/* Producer closure, accepted return/disposal, actual FREE ACK and every
	 * original response/sample callback have all completed. This is the
	 * selected loaded-FQ release proof, not a general command-ACK DMA fence.
	 */
	if (node->flows_memory) {
		qdx_dma_access_end(node->flows_memory);
		qdx_dma_release(node->flows_memory);
		node->flows_memory = NULL;
		node->flows_memory_size = 0;
		node->parameters.codel.flows_memory = 0;
		node->parameters.codel.flows_memory_size = 0;
	}
	if (node->path) {
		qdx_tx_release(node->path);
		node->path = NULL;
	}
	if (node->stats.source) {
		gnet_stats_hw_source_put(node->stats.source);
		node->stats.source = NULL;
	}
}

static int qdx_tc_htb_delete(struct qdx_tc_tree *tree,
			     struct tc_htb_qopt_offload *offer)
{
	struct qdx_tc_owner *owner = tree->owner;
	const struct qdx_tc_queue_ops *queues = owner->port_ops->queues;
	struct qdx_tc_node *node, *parent, *storage;
	struct qdx_tc_queue_owner claim;
	bool last = offer->command != TC_HTB_LEAF_DEL;
	bool force = offer->command == TC_HTB_LEAF_DEL_LAST_FORCE;
	bool storage_detached = false, group_detached = false;
	int err, restore;

	node = qdx_tc_find_class(tree, offer->owner.class);
	if (!node || !node->native_leaf || !node->queue)
		return -ENOENT;
	/* LAST/FORCE can transfer a queue only to the actual native parent.
	 * Top-level classes have a hardware parent, but no native parent class.
	 */
	parent = offer->parent_class ? qdx_tc_find_class(tree, offer->parent_class) : NULL;
	storage = qdx_tc_storage_child(node);
	if (node->path) {
		err = qdx_tx_hold(node->path);
		if (!err && !qdx_tx_drained(node->path))
			err = -EBUSY;
		if (err)
			goto failed;
	}
	if (node->linked || (storage && storage->linked)) {
		err = qdx_tc_htb_close_stats(node);
		if (err)
			goto failed;
	}
	if (storage && storage->linked) {
		err = qdx_tc_node_link(storage, false);
		if (err)
			goto failed;
		storage_detached = true;
	}
	if (node->linked) {
		err = qdx_tc_node_link(node, false);
		if (err)
			goto failed;
		group_detached = true;
	}
	if (last && (!parent || parent == tree->root)) {
		err = -EINVAL;
		goto failed;
	}
	if (last) {
		claim = (struct qdx_tc_queue_owner) {
			.root = offer->owner.sch, .class = parent->native_class,
		};
		err = queues->claim(node->queue, &claim);
		if (err)
			goto failed;
		parent->queue = node->queue;
		parent->queue_owner = claim;
		parent->qid = node->qid;
		parent->native_leaf = true;
		node->queue = NULL;
		node->qid = U16_MAX;
	} else {
		queues->claim(node->queue, NULL);
		offer->classid = TC_H_MIN(node->classid); /* no unrelated queue move */
	}
	node->native_leaf = false;
	node->native_dead = true;
	node->retiring = true;
	if (storage)
		storage->retiring = true;
	return qdx_tc_selection_update(tree);
failed:
	if (force) {
		/* The native destructor frees the child regardless of this result. */
		if (parent && parent != tree->root) {
			claim = (struct qdx_tc_queue_owner) {
				.root = offer->owner.sch, .class = parent->native_class,
			};
			queues->claim(node->queue, &claim);
			parent->queue = node->queue;
			parent->queue_owner = claim;
			parent->qid = node->qid;
			parent->native_leaf = true;
			node->queue = NULL;
			node->qid = U16_MAX;
		}
		node->native_dead = true;
		node->native_leaf = false;
		node->retiring = true;
		if (storage)
			storage->retiring = true;
		qdx_tc_selection_update(tree);
		return err;
	}
	if (group_detached) {
		restore = qdx_tc_node_link(node, true);
		if (restore)
			tree->hold_error = restore;
	}
	if (storage_detached && node->linked) {
		restore = qdx_tc_node_link(storage, true);
		if (restore)
			tree->hold_error = restore;
	}
	return err;
}

int qdx_tc_htb_setup(struct qdx_tc_owner *owner,
		     struct tc_htb_qopt_offload *offer)
{
	struct qdx_tc_tree *tree;
	struct qdx_tc_node *node;
	unsigned int direct = owner->port_ops ? owner->port_ops->normal_direct_count :
		owner->dev->num_tx_queues;
	bool removing;
	int err;

	ASSERT_RTNL();
	if (!offer->owner.sch)
		return -EINVAL;
	if (offer->command == TC_HTB_LEAF_QUERY_QUEUE) {
		mutex_lock(&owner->cfg);
		tree = qdx_tc_find_tree(owner, offer->owner.sch);
		node = tree ? qdx_tc_find_class(tree, offer->owner.class) : NULL;
		err = -ENOENT;
		if (node && node->native_leaf && node->qid < owner->dev->real_num_tx_queues) {
			offer->qid = node->qid;
			err = 0;
		}
		mutex_unlock(&owner->cfg);
		return err;
	}
	removing = offer->command == TC_HTB_DESTROY || offer->command == TC_HTB_LEAF_DEL ||
		offer->command == TC_HTB_LEAF_DEL_LAST || offer->command == TC_HTB_LEAF_DEL_LAST_FORCE;
	if (!removing && !tc_can_offload(owner->dev))
		return -EOPNOTSUPP;
	if (offer->command == TC_HTB_CREATE && owner->dev->real_num_tx_queues != direct) {
		NL_SET_ERR_MSG(offer->extack, "Existing or retiring class queues still own the active range");
		return -EBUSY;
	}
	err = qdx_tc_invalidate(owner, false, true);
	mutex_lock(&owner->cfg);
	tree = qdx_tc_find_tree(owner, offer->owner.sch);
	if (err && offer->command != TC_HTB_DESTROY) {
		if (offer->command == TC_HTB_LEAF_DEL_LAST_FORCE && tree) {
			node = qdx_tc_find_class(tree, offer->owner.class);
			if (node)
				node->native_dead = true;
		}
		goto out;
	}
	if (offer->command == TC_HTB_CREATE) {
		if (owner->ifb_state) {
			err = qdx_tc_ifb_prepare(owner);
			if (err)
				goto out;
		}
		err = qdx_tc_htb_create(owner, offer);
		goto out;
	}
	if (!tree) {
		err = -ENOENT;
		goto out;
	}
	if (!removing) {
		bool restore = tree->retiring || owner->root_allocation != tree->root ||
			!tree->root->allocated || !tree->root->configured || tree->root->retiring ||
			!tree->htb_parent || !tree->htb_parent->allocated ||
			!tree->htb_parent->configured || !tree->htb_parent->linked ||
			tree->htb_parent->retiring;

		node = offer->command == TC_HTB_NODE_MODIFY ?
			qdx_tc_find_class(tree, offer->owner.class) : NULL;
		if (node && (!node->allocated || !node->configured || node->retiring))
			restore = true;
		if (restore) {
			/* This is the committed native tree, before the new class/change
			 * is accepted. A prospective init is restored only by CREATE.
			 */
			if (rtnl_dereference(owner->dev->qdisc) != offer->owner.sch) {
				err = -EAGAIN;
				goto out;
			}
			if ((node && node->retiring) ||
			    (tree->htb_parent && tree->htb_parent->retiring))
				tree->retiring = true;
			err = qdx_tc_root_prepare(tree->root);
			if (err)
				goto out;
			mutex_unlock(&owner->cfg);
			err = qdx_tc_tree_prepare(owner, NULL);
			mutex_lock(&owner->cfg);
			if (err)
				goto out;
		}
	}
	switch (offer->command) {
	case TC_HTB_LEAF_ALLOC_QUEUE:
	case TC_HTB_LEAF_TO_INNER:
		err = qdx_tc_htb_add(tree, offer);
		break;
	case TC_HTB_NODE_MODIFY:
		node = qdx_tc_find_class(tree, offer->owner.class);
		err = node ? qdx_tc_htb_modify(node, offer) : -ENOENT;
		break;
	case TC_HTB_LEAF_DEL:
	case TC_HTB_LEAF_DEL_LAST:
	case TC_HTB_LEAF_DEL_LAST_FORCE:
		err = qdx_tc_htb_delete(tree, offer);
		break;
	case TC_HTB_DESTROY:
		if (tree->previous_root && tree->previous_root->root &&
		    rtnl_dereference(owner->dev->qdisc) == tree->previous_root->root->native)
			tree->cancelled = true; /* Prepared init never replaced the native root. */
		tree->native_dead = true;
		tree->retiring = true;
		rcu_assign_pointer(tree->selection, NULL);
		synchronize_net();
		list_for_each_entry(node, &tree->nodes, list) {
			node->native_dead = true;
			node->native_leaf = false;
			if (node->queue)
				owner->port_ops->queues->claim(node->queue, NULL);
		}
		err = 0;
		break;
	default:
		err = -EOPNOTSUPP;
	}
 out:
	owner->replay_needed = true;
	mutex_unlock(&owner->cfg);
	qdx_tc_schedule(owner);
	return err;
}

int qdx_tc_tree_retire(struct qdx_tc_tree *tree, bool synchronous)
{
	struct qdx_tc_owner *owner = tree->owner;
	struct qdx_tc_tree *other;
	struct qdx_tc_node *node, *next, *child;
	struct qdx_tc_view *view;
	struct Qdisc *native_root;
	bool instance_busy = false, progress, was_allocated;
	unsigned int operation;
	unsigned long deadline = jiffies + QDX_TC_COMMAND_TIMEOUT;
	long remaining;
	int err = 0, result;

	/* Caller retains tree, holds RTNL and no cfg. No removed Qdisc reference
	 * is acquired merely to keep a late hardware reply's identity alive.
	 */
	ASSERT_RTNL();
	mutex_lock(&owner->cfg);
	tree->retiring = true;
	/* Closing producers precedes FREE. Node FREE disposes queued packets;
	 * the last UNASSIGN also disposes the worker's pending packet before
	 * waiting for accepted carriers.
	 */
	list_for_each_entry(node, &tree->nodes, list) {
		if (!node->path)
			continue;
		result = qdx_tx_hold(node->path);
		if (result) {
			err = result;
			goto out;
		}
	}
	spin_lock_bh(&owner->data_lock);
	list_for_each_entry(view, &owner->views, list) {
		if (view->tree == tree && refcount_read(&view->refs) > 1) {
			err = -EINPROGRESS;
			break;
		}
	}
	spin_unlock_bh(&owner->data_lock);
	if (err)
		goto out; /* Actual projection put queues this same retirement. */
	if (owner->ifb_state) {
		qdx_tc_ifb_tree_close(tree);
	}
	if (owner->assign.request) {
		err = qdx_tc_assignment(tree, true);
		if (owner->assign.request)
			goto out;
	}
	if (tree->root_command.request && tree->root) {
		err = qdx_tc_tree_root(tree, tree->root, false);
		if (tree->root_command.request)
			goto out;
	}
	/* A cancelled prospective root cannot restore an old allocation by
	 * SET_ROOT. Once its own inverses finish, ordinary current-tree replay
	 * makes the still-native predecessor the next actual root allocation.
	 */
	if (tree->default_command.request && tree->root) {
		err = qdx_tc_tree_root(tree, tree->root, true);
		if (tree->default_command.request)
			goto out;
	}
	if (synchronous) {
		if (!wait_for_completion_timeout(&tree->root_command.recipient_done,
						 QDX_TC_COMMAND_TIMEOUT) ||
		    !wait_for_completion_timeout(&tree->default_command.recipient_done,
						 QDX_TC_COMMAND_TIMEOUT)) {
			err = -EINPROGRESS;
			goto out;
		}
	} else if (!completion_done(&tree->root_command.recipient_done) ||
		   !completion_done(&tree->default_command.recipient_done)) {
		err = -EINPROGRESS;
		goto out;
	}
	/* Native collection inserts parents before children. Explicit groups can
	 * be appended later; repeated progress passes retain a still-linked parent
	 * until every actual child has been detached and freed.
	 */
	do {
		progress = false;
		err = 0;
		list_for_each_entry_reverse(node, &tree->nodes, list) {
			was_allocated = node->allocated;
			result = qdx_tc_node_unconfigure(node, synchronous);
			if (was_allocated && !node->allocated)
				progress = true;
			if (result && !err)
				err = result;
		}
		/* A parent visited before its appended child gets another pass
		 * only after a real FREE. No polling for an RTNL-dependent owner.
		 */
	} while (synchronous && err == -EINPROGRESS && progress);
	if (err)
		goto out;
	/* The last UNASSIGN disposes the instance's already-dequeued pending
	 * packet. Do not wait for that carrier before issuing its disposal.
	 * Another tree may still own this assignment or an original command;
	 * only stop after every such execution and recipient has ended.
	 */
	list_for_each_entry(other, &owner->trees, list) {
		if (other->root_command.request || other->default_command.request ||
		    !completion_done(&other->root_command.recipient_done) ||
		    !completion_done(&other->default_command.recipient_done))
			instance_busy = true;
		list_for_each_entry(node, &other->nodes, list) {
			if (node->allocated || node->linked || !qdx_tc_stats_drained(node))
				instance_busy = true;
			for (operation = 0; operation < QDX_TC_NODE_OPERATIONS; operation++)
				if (node->command[operation].request ||
				    !completion_done(&node->command[operation].recipient_done))
					instance_busy = true;
		}
	}
	spin_lock_bh(&owner->data_lock);
	list_for_each_entry(view, &owner->views, list) {
		if (view->tree && (refcount_read(&view->refs) > 1 ||
		    (view->available && !view->invalid)))
			instance_busy = true;
	}
	spin_unlock_bh(&owner->data_lock);
	if (!instance_busy && (owner->assigned || owner->unassign.request ||
	    !completion_done(&owner->unassign.recipient_done))) {
		/* Freed trees can retain paths and IFB operations until their
		 * accepted packets return. Close all those existing producers;
		 * their storage and endpoint references remain owned below.
		 */
		list_for_each_entry(other, &owner->trees, list) {
			list_for_each_entry(node, &other->nodes, list) {
				if (!node->path)
					continue;
				err = qdx_tx_hold(node->path);
				if (err)
					goto out;
			}
			if (owner->ifb_state)
				qdx_tc_ifb_tree_close(other);
		}
		err = qdx_tc_assignment(tree, false);
		if (err)
			goto out;
		if (!completion_done(&owner->unassign.recipient_done) &&
		    (!synchronous || !wait_for_completion_timeout(
			    &owner->unassign.recipient_done, QDX_TC_COMMAND_TIMEOUT))) {
			err = -EINPROGRESS;
			goto out;
		}
	}
	/* All matching node FREE operations have now ACKed (or qualified access
	 * ended). Their returned/EMPTY carriers can finish on independent NAPI.
	 * A parent class path can reference descendant FQ memory, so this check
	 * covers every actual path before releasing any region in this tree.
	 */
	list_for_each_entry(node, &tree->nodes, list) {
		if (!node->path)
			continue;
		if (!node->drain_wait.armed)
			node->drain_wait.owner.module = READ_ONCE(qdx_tc_exit_draining) ? NULL : THIS_MODULE;
		qdx_tx_wait_arm(node->path, &node->drain_wait, QDX_RESOURCE_CARRIER);
		if (!qdx_tx_drained(node->path)) {
			err = -EINPROGRESS;
			goto out;
		}
	}
	if (owner->ifb_state) {
		err = qdx_tc_ifb_tree_drained(tree);
		if (err)
			goto out;
	}
	/* Restore the physical row while the old native path holds still stop
	 * this output. NSS stop/accepted drain does not itself restore PPE.
	 * A failed restore retains the exact resource and forbids CPU release.
	 */
	if (tree->peak) {
		err = owner->port_ops->peak_release(tree->peak);
		if (err)
			goto out;
		tree->peak = NULL;
	}
	tree->peak_node = NULL;
	memset(&tree->peak_parameters, 0, sizeof(tree->peak_parameters));
	/* A native queue may have moved to another node while the old node
	 * still owns its path. Keep each real path's progress subscription and
	 * node storage until every queue in this tree has recorded handback.
	 */
	list_for_each_entry_reverse(node, &tree->nodes, list)
		qdx_tc_node_release(node);
	list_for_each_entry_reverse(node, &tree->nodes, list) {
		if (!node->queue)
			continue;
		for (;;) {
			/* Arm before testing: a final path release between the test
			 * and wait must remain visible. An unrelated credit only wakes
			 * this recheck; it never proves this queue's actual handback.
			 */
			reinit_completion(&owner->drain_progress);
			result = owner->port_ops->queues->retire(node->queue);
			remaining = deadline - jiffies;
			if (!synchronous || result != -EINPROGRESS || remaining <= 0)
				break;
			wait_for_completion_timeout(&owner->drain_progress, remaining);
		}
		if (result && !err)
			err = result;
	}
	if (err)
		goto out;
	list_for_each_entry_safe_reverse(node, next, &tree->nodes, list) {
		qdx_resource_wait_disarm(&node->drain_wait);
		qdx_resource_wait_drain(&node->drain_wait);
		if (node->queue && (node->native_dead || tree->native_dead)) {
			owner->port_ops->queues->claim(node->queue, NULL);
			mutex_unlock(&owner->cfg);
			/* A nested class selects the qid, but the actual egress root
			 * retains already selected packets in its native TX caches.
			 */
			native_root = rtnl_dereference(owner->dev->qdisc);
			result = owner->port_ops->queues->release(node->queue, native_root);
			mutex_lock(&owner->cfg);
			if (result) {
				if (!err)
					err = result;
				continue;
			}
			node->queue = NULL;
			node->qid = U16_MAX;
		}
	}
	if (err)
		goto out;
	if (owner->root_allocation && owner->root_allocation->tree == tree) {
		/* FREE and every old view/packet/region/path/wait/queue obligation
		 * have ended. Clear this borrow before removing any node-list ref.
		 */
		owner->root_allocation = NULL;
		tree->rooted = false;
	}
	list_for_each_entry_safe_reverse(node, next, &tree->nodes, list) {
		if (node->native)
			continue;
		if (node == tree->htb_parent)
			tree->htb_parent = NULL;
		else if (node->parent && node->parent->tbf_peak == node)
			node->parent->tbf_peak = NULL;
		else
			continue;
		/* All hardware and consumers ended above. Retained native children
		 * will acquire their real parent again during current replay.
		 */
		list_for_each_entry(child, &tree->nodes, list)
			if (child->parent == node)
				child->parent = NULL;
		list_del(&node->list);
		qdx_tc_node_put(node);
	}
	list_for_each_entry_safe_reverse(node, next, &tree->nodes, list) {
		if (node->queue || (!node->native_dead && !tree->native_dead)) {
			/* Retirement really completed. The live native record/claim
			 * remains, with no configured storage or current stats source.
			 */
			node->retiring = false;
			continue;
		}
		if (node == tree->root)
			tree->root = NULL;
		list_del(&node->list);
		qdx_tc_node_put(node);
	}
	if (!err && tree->cancelled && tree->previous_root && tree->previous_root->root &&
	    !tree->previous_root->native_dead &&
	    rtnl_dereference(owner->dev->qdisc) == tree->previous_root->root->native)
		owner->replay_needed = true;
	if (!err && tree->native_dead && list_empty(&tree->nodes) &&
	    !tree->root_command.request && !tree->default_command.request &&
	    completion_done(&tree->root_command.recipient_done) &&
	    completion_done(&tree->default_command.recipient_done)) {
		rcu_assign_pointer(tree->selection, NULL);
		list_del_rcu(&tree->list);
		synchronize_net();
		qdx_tc_tree_put(tree); /* Owner-list reference; caller still owns one. */
	}
 out:
	mutex_unlock(&owner->cfg);
	return err;
}

/* A current RTNL operation owns these borrowed native slots and observations.
 * They are discarded before returning; only encoded execution survives it.
 */
struct qdx_tc_native_node {
	struct list_head list;
	struct qdx_tc_parameters parameters;
	struct qdx_tc_native_node *parent;
	struct qdx_tc_node *node;
	struct Qdisc *child;
	unsigned long parent_class;
	u32 classid;
	u16 qid;
	u16 band;
	u16 bands;
	u8 priomap[TC_PRIO_MAX + 1];
	struct tcf_block *block;
	u64 sequence;
	bool leaf;
	bool folded;
	bool leading_tbf;
	bool visited;
	u16 default_class;
};

struct qdx_tc_native_tree {
	struct qdx_tc_owner *owner;
	struct list_head nodes;
	struct qdx_tc_native_node *parent;
	struct qdx_tc_native_node *last;
	struct qdx_tc_native_node *peak;
	unsigned int peak_count;
	u16 band;
	int error;
};

struct qdx_tc_native_walk {
	struct qdisc_walker walk;
	struct qdx_tc_native_tree *tree;
	struct qdx_tc_native_node *parent;
};

static int qdx_tc_nonempty(struct tcf_proto *tp, void *filter,
			   struct tcf_walker *walker)
{
	walker->nonempty = true;
	return -1;
}

static int qdx_tc_bucket_empty(struct tcf_block *block, u64 *sequence)
{
	struct tcf_block_state before, after;
	struct tcf_chain *chain;
	struct tcf_proto *proto;
	bool empty = true;

	tcf_block_read_state(block, &before);
	if (before.active)
		return -EAGAIN;
	for (chain = tcf_get_next_chain(block, NULL); chain;
	     chain = tcf_get_next_chain(block, chain)) {
		for (proto = tcf_get_next_proto(chain, NULL); proto;
		     proto = tcf_get_next_proto(chain, proto)) {
			struct tcf_walker walker = { .fn = qdx_tc_nonempty };

			if (!proto->ops->walk) {
				empty = false;
				continue;
			}
			proto->ops->walk(proto, &walker, true);
			if (walker.nonempty)
				empty = false;
		}
	}
	tcf_block_read_state(block, &after);
	if (after.active || before.sequence != after.sequence)
		return -EAGAIN;
	*sequence = after.sequence;
	return empty ? 0 : -EOPNOTSUPP;
}

static int qdx_tc_collect_offer(enum tc_setup_type type, void *data, void *private)
{
	struct qdx_tc_native_tree *collect = private;
	struct qdx_tc_native_node *entry;
	struct tcf_block_state state;
	struct tcf_block *block = NULL;
	struct tcf_block *bucket = NULL;
	u64 sequence = 0;
	int err;

	if (type == TC_SETUP_QDISC_FQ_CODEL) {
		block = ((struct tc_fq_codel_qopt_offload *)data)->block;
		bucket = block;
		if (block) {
			err = qdx_tc_bucket_empty(block, &sequence);
			if (err)
				return err;
		}
	}
	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;
	entry->parent = collect->parent;
	entry->band = collect->band;
	entry->qid = U16_MAX;
	if (type == TC_SETUP_QDISC_FIFO && collect->parent &&
	    collect->parent->parameters.kind == QDX_SHAPER_RED) {
		const struct tc_fifo_qopt_offload *fifo = data;

		if (!fifo->byte_limit || fifo->head_drop || !fifo->owner.sch ||
		    rtnl_dereference(fifo->owner.sch->stab) || fifo->limit !=
		    le32_to_cpu(collect->parent->parameters.parameters.red.limit_bytes)) {
			err = -EOPNOTSUPP;
			goto fail;
		}
		/* RED's device node already owns this exact plain byte storage.
		 * The real native child remains in the checked tree, without a
		 * second hardware node, collector, sink or invented BFIFO service.
		 */
		entry->parameters.native = fifo->owner;
		entry->folded = true;
		goto append;
	}
	err = qdx_tc_translate(collect->owner->dev,
		collect->parent ? collect->parent->parameters.kind : 0,
		type, data, true, &entry->parameters);
	if (err)
		goto fail;
	/* Inherit the common population only along actual single-child TBF
	 * ancestry. Branch arbitration and other storage end this prefix.
	 * The completed walk must contain exactly one requested prefix peak.
	 */
	entry->leading_tbf = entry->parameters.kind == QDX_SHAPER_TBL &&
		(!collect->parent || collect->parent->leading_tbf);
	if (entry->leading_tbf && entry->parameters.peak.htb.ceil.rate_bytes_ps) {
		collect->peak = entry;
		collect->peak_count++;
	}
	if (entry->parameters.native.sch->ops->cl_ops &&
	    entry->parameters.native.sch->ops->cl_ops->tcf_block) {
		block = entry->parameters.native.sch->ops->cl_ops->tcf_block(
			entry->parameters.native.sch, entry->parameters.native.class, NULL);
		if (IS_ERR(block)) {
			err = PTR_ERR(block);
			goto fail;
		}
		if (block) {
			tcf_block_read_state(block, &state);
			if (state.active || (bucket &&
			    (block != bucket || state.sequence != sequence))) {
				err = -EAGAIN;
				goto fail;
			}
			sequence = state.sequence;
		}
	}
	entry->block = block;
	entry->sequence = sequence;
	if (type == TC_SETUP_QDISC_HTB) {
		const struct tc_htb_qopt_offload *offer = data;

		entry->classid = offer->classid;
		entry->parent_class = offer->parent_class;
		entry->child = offer->child;
		entry->leaf = offer->leaf;
		entry->qid = offer->leaf ? offer->qid : U16_MAX;
		entry->default_class = offer->default_class;
	} else if (type == TC_SETUP_QDISC_PRIO) {
		const struct tc_prio_qopt_offload *offer = data;

		entry->bands = offer->replace_params.bands;
		memcpy(entry->priomap, offer->replace_params.priomap, sizeof(entry->priomap));
	}
append:
	list_add_tail(&entry->list, &collect->nodes);
	collect->last = entry;
	return 0;
fail:
	kfree(entry);
	return err;
}

static int qdx_tc_collect_qdisc(struct qdx_tc_native_tree *collect,
				struct Qdisc *sch, struct qdx_tc_native_node *parent,
				u16 band);

static int qdx_tc_collect_class(struct Qdisc *sch, unsigned long native_class,
				struct qdisc_walker *walk)
{
	struct qdx_tc_native_walk *classes = container_of(walk, struct qdx_tc_native_walk, walk);
	struct qdx_tc_native_tree *collect = classes->tree;
	const struct Qdisc_class_ops *ops = sch->ops->cl_ops;
	struct qdx_tc_native_node *parent = classes->parent;
	struct Qdisc *child;
	int err;

	if (ops->offload_replay) {
		collect->parent = parent;
		collect->band = 0;
		err = qdisc_offload_replay(sch, native_class, qdx_tc_collect_offer, collect, NULL);
		if (err)
			goto fail;
		parent = collect->last;
		child = parent->child;
	} else {
		child = ops->leaf ? ops->leaf(sch, native_class) : NULL;
	}
	if (!child)
		return 0;
	err = qdx_tc_collect_qdisc(collect, child, parent,
		parent->parameters.kind == QDX_SHAPER_PRIO ? native_class - 1 : 0);
	if (!err)
		return 0;
fail:
	collect->error = err;
	return -1;
}

static int qdx_tc_collect_qdisc(struct qdx_tc_native_tree *collect,
				struct Qdisc *sch, struct qdx_tc_native_node *parent,
				u16 band)
{
	struct qdx_tc_native_walk classes = {
		.walk.fn = qdx_tc_collect_class,
		.tree = collect,
	};
	struct qdx_tc_native_node *entry;
	int err;

	if (!sch || sch->flags & TCQ_F_BUILTIN)
		return -EOPNOTSUPP;
	list_for_each_entry(entry, &collect->nodes, list)
		if (entry->parameters.native.sch == sch && !entry->parameters.native.class)
			return -ELOOP;
	collect->parent = parent;
	collect->band = band;
	err = qdisc_offload_replay(sch, 0, qdx_tc_collect_offer, collect, NULL);
	if (err)
		return err;
	classes.parent = collect->last;
	if (sch->ops->cl_ops && sch->ops->cl_ops->walk) {
		sch->ops->cl_ops->walk(sch, &classes.walk);
		if (collect->error)
			return collect->error;
	}
	return 0;
}

static struct qdx_tc_node *qdx_tc_native_find_node(struct qdx_tc_tree *tree,
						 const struct qdx_tc_native_node *entry)
{
	struct qdx_tc_node *node;

	list_for_each_entry(node, &tree->nodes, list)
		if (node->native == entry->parameters.native.sch &&
		    node->native_class == entry->parameters.native.class && !node->native_dead)
			return node;
	return NULL;
}

/* Exactly those PRIO branches whose successful dequeue is not followed by a
 * deeper mapped PRIO decision need a stamp here. An ancestor leaves U16_MAX
 * so it cannot overwrite the actual descendant decision on the same skb.
 */
static bool qdx_tc_deeper_prio(struct qdx_tc_native_tree *collect,
			       struct qdx_tc_native_node *branch)
{
	struct qdx_tc_native_node *entry, *parent;

	list_for_each_entry(entry, &collect->nodes, list) {
		if (entry->parameters.kind != QDX_SHAPER_PRIO)
			continue;
		for (parent = entry; parent; parent = parent->parent)
			if (parent == branch)
				return true;
	}
	return false;
}

/* A worker passes its actual pending view. A synchronous native HTB callback
 * passes NULL to restore only the committed hardware graph under hold; the same
 * typed native walk is used and no flow/IFB availability is published here.
 */
int qdx_tc_tree_prepare(struct qdx_tc_owner *owner, struct qdx_tc_view *view)
{
	struct qdx_tc_native_tree collect = { .owner = owner };
	struct qdx_tc_native_node *entry, *parent, *next;
	const struct qdx_tc_queue_ops *queues = owner->port_ops ? owner->port_ops->queues : NULL;
	struct qdx_tc_tree *tree, *prepared, *next_tree;
	struct qdx_tc_node *node, *enqueue;
	struct qdx_tc_view *reader;
	struct qdx_tc_queue_owner claim;
	struct Qdisc *root;
	unsigned int count = 0, complete = 0, before;
	u16 ifb_queue = 0, qid;
	bool has_prio = false;
	int err = 0;

	ASSERT_RTNL();
	lockdep_assert_not_held(&owner->cfg);
	if ((view && (view != owner->pending || view->invalid)) ||
	    !tc_can_offload(owner->dev) || owner->closing ||
	    qdx_service_state(owner->service) != QDX_AVAILABLE)
		return -EAGAIN;
	if (owner->direction == QDX_TC_INGRESS && !owner->ifb_state)
		return 0;
	root = rtnl_dereference(owner->dev->qdisc);
	if (!root || root->flags & TCQ_F_BUILTIN)
		return 0;
	INIT_LIST_HEAD(&collect.nodes);
	err = qdx_tc_collect_qdisc(&collect, root, NULL, 0);
	if (err)
		goto free_inputs;
	if (collect.peak_count == 1 && owner->direction == QDX_TC_EGRESS &&
	    !owner->ifb_state && owner->port_ops && owner->port_ops->peak_prepare &&
	    owner->port_ops->peak_publish && owner->port_ops->peak_release)
		collect.peak->parameters.output_peak = true;
	else
		collect.peak = NULL;
	/* Native HTB walks classes by its own indexing, not parent-first order. */
	list_for_each_entry(entry, &collect.nodes, list) {
		count++;
		if (entry->parameters.kind == QDX_SHAPER_PRIO)
			has_prio = true;
		if (entry->parameters.kind != QDX_SHAPER_HTB_GROUP || !entry->parent_class)
			continue;
		parent = NULL;
		list_for_each_entry(next, &collect.nodes, list) {
			if (next->parameters.native.sch == entry->parameters.native.sch &&
			    next->parameters.native.class == entry->parent_class) {
				parent = next;
				break;
			}
		}
		if (!parent || parent == entry) {
			err = -EINVAL;
			goto free_inputs;
		}
		entry->parent = parent;
	}
	list_for_each_entry(entry, &collect.nodes, list) {
		if (!view || !entry->block)
			continue;
		err = qdx_tc_view_observe(view, entry->block, entry->sequence);
		if (err)
			goto free_inputs;
	}
	mutex_lock(&owner->cfg);
	if ((view && view->invalid) || owner->closing) {
		err = -EAGAIN;
		goto unlock;
	}
	if (owner->ifb_state) {
		err = qdx_tc_ifb_prepare(owner);
		if (err)
			goto unlock;
	}
	tree = qdx_tc_find_tree(owner, root);
	if (!tree) {
		tree = qdx_tc_tree_alloc(owner, root);
		if (IS_ERR(tree)) {
			err = PTR_ERR(tree);
			goto unlock;
		}
	}
	if (view) {
		if (!view->tree) {
			qdx_tc_tree_get(tree);
			view->tree = tree;
		} else if (view->tree != tree) {
			err = -ESTALE;
			goto unlock;
		}
	}
	if (tree->retiring || (owner->root_allocation &&
	    owner->root_allocation->tree->retiring)) {
		err = -EAGAIN;
		goto unlock;
	}
	if (!view) {
		spin_lock_bh(&owner->data_lock);
		list_for_each_entry(reader, &owner->views, list)
			if (reader->tree == tree && refcount_read(&reader->refs) > 1)
				err = -EINPROGRESS;
		spin_unlock_bh(&owner->data_lock);
		if (err)
			goto unlock; /* Its real consumer may need the caller's RTNL. */
	}
	/* The invalid predecessor view remains immutable to its real readers.
	 * The worker retires its exposure and waits for those refs before reuse.
	 */
	list_for_each_entry(entry, &collect.nodes, list) {
		if (entry->folded)
			continue;
		entry->node = qdx_tc_native_find_node(tree, entry);
		if (!entry->node) {
			list_for_each_entry_safe(prepared, next_tree, &owner->trees, list) {
				if (prepared == tree || !prepared->prospective ||
				    prepared->endpoint != tree->endpoint || prepared->native_dead)
					continue;
				node = qdx_tc_native_find_node(prepared, entry);
				if (!node || node->linked || prepared->rooted || prepared->retiring)
					continue;
				if (owner->root_allocation == node && entry->parent) {
					prepared->retiring = true;
					tree->retiring = true;
					err = -EAGAIN;
					goto unlock;
				}
				/* Same owner, endpoint and actual I-shaper assignment. This
				 * moves the actual execution, never copies a scheduler.
				 */
				qdx_tc_tree_get(tree);
				list_move_tail(&node->list, &tree->nodes);
				node->tree = tree;
				qdx_tc_tree_put(prepared); /* Node's old container ref. */
				if (node->tbf_peak) {
					enqueue = node->tbf_peak;
					qdx_tc_tree_get(tree);
					list_move_tail(&enqueue->list, &tree->nodes);
					enqueue->tree = tree;
					qdx_tc_tree_put(prepared);
				}
				entry->node = node;
				prepared->root = NULL;
				if (list_empty(&prepared->nodes)) {
					list_del_rcu(&prepared->list);
					synchronize_net();
					qdx_tc_tree_put(prepared); /* Old owner-list ref. */
				}
				break;
			}
		}
		if (!entry->node)
			continue;
		if (entry->node->retiring ||
		    (owner->root_allocation == entry->node && entry->parent) ||
		    (!entry->parent && entry->node->allocated &&
		     owner->root_allocation != entry->node)) {
			tree->retiring = true;
			err = -EAGAIN;
			goto unlock;
		}
		if (!entry->node->allocated && !entry->node->command[QDX_TC_NODE_ALLOC].request)
			continue;
		if (!qdx_tc_parameters_match(entry->node, &entry->parameters)) {
			tree->retiring = true;
			err = -EAGAIN;
			goto unlock;
		}
	}
	if (tree->peak && (!collect.peak || tree->peak_node != collect.peak->node ||
	    !qdx_tc_parameters_match(tree->peak_node, &collect.peak->parameters))) {
		tree->retiring = true;
		err = -EAGAIN;
		goto unlock;
	}
	while (complete != count) {
		before = complete;
		list_for_each_entry(entry, &collect.nodes, list) {
			if (entry->visited)
				continue; /* This operation's parent-order visit is complete. */
			if (entry->parent && !entry->parent->visited)
				continue;
			if (entry->folded) {
				entry->node = entry->parent->node;
				entry->visited = true;
				complete++;
				continue;
			}
			node = entry->node;
			if (!node) {
				node = qdx_tc_node_alloc(tree);
				if (IS_ERR(node)) {
					err = PTR_ERR(node);
					goto unlock;
				}
				entry->node = node;
			}
			if (!node->allocated && !node->command[QDX_TC_NODE_ALLOC].request) {
				node->kind = entry->parameters.kind;
				node->parameters = entry->parameters.parameters;
				node->fq = entry->parameters.fq;
				node->retiring = false;
				node->memory_queried = false;
				node->probability_reported = false;
			}
			node->native = entry->parameters.native.sch;
			node->native_class = entry->parameters.native.class;
			node->handle = node->native->handle;
			node->classid = entry->classid;
			node->parent = entry->parent ? entry->parent->node : NULL;
			if (node->kind == QDX_SHAPER_HTB_GROUP && node->parent == tree->root &&
			    tree->explicit_htb)
				node->parent = tree->htb_parent;
			if (node->parent && node->parent->tbf_peak)
				node->parent = node->parent->tbf_peak;
			node->band = entry->band;
			node->bands = entry->bands;
			memcpy(node->priomap, entry->priomap, sizeof(node->priomap));
			node->native_block = entry->block;
			if (!entry->parent) {
				tree->root = node;
				tree->explicit_htb = node->kind == QDX_SHAPER_HTB;
				tree->default_class = entry->default_class;
			}
			if (entry == collect.peak) {
				tree->peak_node = node;
				tree->peak_parameters.rate_bytes_ps =
					le32_to_cpu(entry->parameters.peak.htb.ceil.rate_bytes_ps);
				tree->peak_parameters.burst_bytes =
					le32_to_cpu(entry->parameters.peak.htb.ceil.burst_bytes);
			}
			err = qdx_tc_qdisc_prepare(node, &entry->parameters, !entry->parent);
			if (err)
				goto unlock;
			if (!node->stats.source) {
				node->stats.source = gnet_stats_hw_source_open(entry->parameters.native.hw_stats);
				if (IS_ERR(node->stats.source)) {
					err = PTR_ERR(node->stats.source);
					node->stats.source = NULL;
					goto unlock;
				}
				node->stats.detached = false;
			}
			err = qdx_tc_node_link(node, true);
			if (err)
				goto unlock;
			entry->visited = true;
			complete++;
		}
		if (before == complete) {
			err = -ELOOP;
			goto unlock;
		}
	}
	if (!tree->rooted) {
		err = qdx_tc_tree_root(tree, tree->root, false);
		if (err)
			goto unlock;
	}
	if (collect.peak && !tree->peak) {
		/* A partial native write can return an owned handle on failure.
		 * Keep it on this actual tree for the same retirement path.
		 */
		err = owner->port_ops->peak_prepare(owner->port, &tree->peak_parameters,
						 &tree->peak);
		if (err)
			goto unlock;
	}
	/* Reserve only native decisions which can actually select a host queue.
	 * Explicit HTB groups already own their exact synchronous class claim.
	 */
	list_for_each_entry(entry, &collect.nodes, list) {
		if (entry->folded)
			continue;
		node = entry->node;
		if (node->native_leaf) {
			if (node->qid == U16_MAX || !node->queue) {
				err = -ESTALE;
				goto unlock;
			}
		} else if (entry->parent && entry->parent->parameters.kind == QDX_SHAPER_PRIO &&
			   !qdx_tc_deeper_prio(&collect, entry)) {
			claim = (struct qdx_tc_queue_owner) {
				.root = entry->parent->parameters.native.sch,
				.class = entry->band + 1,
			};
			if (!queues) {
				if (ifb_queue >= owner->dev->real_num_tx_queues) {
					err = -ENOSPC;
					goto unlock;
				}
				node->qid = ifb_queue++;
				continue;
			}
			if (!node->queue) {
				err = queues->reserve(owner->port, &claim, U16_MAX, &node->queue, &node->qid);
				if (err)
					goto unlock;
				node->queue_owner = claim;
				err = queues->claim(node->queue, &claim);
				if (err)
					goto unlock;
			}
		} else if (node == tree->root && !has_prio && !tree->explicit_htb) {
			node->qid = 0;
			if (!queues)
				continue;
			if (!node->queue) {
				claim = (struct qdx_tc_queue_owner) { .root = root };
				err = queues->reserve(owner->port, &claim, 0, &node->queue, &node->qid);
				if (err)
					goto unlock;
				node->queue_owner = claim;
				err = queues->claim(node->queue, &claim);
				if (err)
					goto unlock;
			}
		} else {
			continue;
		}
		if (!queues || node->path)
			continue;
		mutex_unlock(&owner->cfg);
		err = queues->activate(node->queue);
		mutex_lock(&owner->cfg);
		if (err || (view && view->invalid) || owner->closing) {
			err = err ?: -EAGAIN;
			goto unlock;
		}
		enqueue = qdx_tc_enqueue_node(node);
		if (IS_ERR(enqueue)) {
			err = PTR_ERR(enqueue);
			goto unlock;
		}
		/* The native claim remains on node; its packet enters the actual
		 * storage leaf and is scheduled through these same ancestor links.
		 */
		err = queues->execution_prepare(node->queue, enqueue->endpoint, enqueue->tag,
			tree->explicit_htb ? QDX_REQUIRED : QDX_OPTIONAL, &node->path, &node->token);
		if (err)
			goto unlock;
	}
	/* Mappings are installed only after the complete graph is representable.
	 * The actual concrete/native provider still holds execution admission.
	 */
	list_for_each_entry(entry, &collect.nodes, list) {
		if (!entry->parent || entry->parent->parameters.kind != QDX_SHAPER_PRIO)
			continue;
		qid = qdx_tc_deeper_prio(&collect, entry) ? U16_MAX : entry->node->qid;
		err = entry->parent->parameters.native.sch->ops->cl_ops->offload_queue(
			entry->parent->parameters.native.sch, entry->band + 1, qid);
		if (err)
			goto unlock;
	}
	if (owner->ifb_state) {
		kfree(tree->packet_nodes);
		tree->packet_queues = owner->dev->real_num_tx_queues;
		tree->packet_nodes = kcalloc(tree->packet_queues, sizeof(*tree->packet_nodes), GFP_KERNEL);
		if (!tree->packet_nodes) {
			err = -ENOMEM;
			goto unlock;
		}
		if (!has_prio && !tree->explicit_htb) {
			enqueue = qdx_tc_enqueue_node(tree->root);
			if (IS_ERR(enqueue)) {
				err = PTR_ERR(enqueue);
				goto unlock;
			}
			for (qid = 0; qid < tree->packet_queues; qid++)
				tree->packet_nodes[qid] = enqueue;
		} else {
			list_for_each_entry(node, &tree->nodes, list) {
				if (node->retiring || node->qid >= tree->packet_queues)
					continue;
				enqueue = qdx_tc_enqueue_node(node);
				if (IS_ERR(enqueue)) {
					err = PTR_ERR(enqueue);
					goto unlock;
				}
				tree->packet_nodes[node->qid] = enqueue;
			}
		}
		err = qdx_tc_ifb_tree_prepare(tree);
		if (err)
			goto unlock;
	}
	tree->retiring = false;
	tree->prospective = false;
	if (tree->previous_root) {
		qdx_tc_tree_put(tree->previous_root);
		tree->previous_root = NULL;
	}
	if (view)
		view->neutral = false;
unlock:
	mutex_unlock(&owner->cfg);
free_inputs:
	list_for_each_entry_safe(entry, next, &collect.nodes, list) {
		list_del(&entry->list);
		kfree(entry);
	}
	return err;
}

int qdx_tc_tree_publish(struct qdx_tc_tree *tree)
{
	struct qdx_tc_node *node;
	int err;

	lockdep_assert_held(&tree->owner->cfg);
	if (tree->owner->root_allocation != tree->root || !tree->root ||
	    !tree->root->allocated || !tree->rooted || tree->retiring)
		return -EAGAIN;
	if (tree->explicit_htb &&
	    (!tree->htb_parent || !tree->htb_parent->allocated ||
	     !tree->htb_parent->configured || !tree->htb_parent->linked ||
	     tree->htb_parent->retiring))
		return -EAGAIN;
	if (tree->peak_node && !tree->peak)
		return -EAGAIN;
	if (tree->owner->ifb_state)
		return 0; /* Its original IFB query reads the published view. */
	list_for_each_entry(node, &tree->nodes, list) {
		if (!node->path)
			continue;
		err = tree->owner->port_ops->queues->publish(node->queue, node->path);
		if (err)
			return err;
	}
	if (tree->peak) {
		err = tree->owner->port_ops->peak_publish(tree->peak);
		if (err)
			return err;
	}
	tree->held = false;
	return 0;
}

int qdx_tc_qdisc_setup(struct qdx_tc_owner *owner, enum tc_setup_type type, void *data)
{
	struct tc_qdisc_offload_owner native;
	struct qdx_tc_parameters parameters = {};
	struct qdx_tc_tree *tree, *found_tree = NULL;
	struct qdx_tc_node *node, *found = NULL;
	enum qdx_shaper_kind parent_kind = 0;
	bool removing, stats, graft = false;
	u32 parent_handle;
	u64 sequence;
	int err;

	ASSERT_RTNL();
	lockdep_assert_not_held(&owner->cfg);
	switch (type) {
	case TC_SETUP_QDISC_TBF: {
		struct tc_tbf_qopt_offload *offer = data;
		native = offer->owner;
		parent_handle = offer->parent;
		removing = offer->command == TC_TBF_DESTROY;
		stats = offer->command == TC_TBF_STATS;
		graft = offer->command == TC_TBF_GRAFT;
		break;
	}
	case TC_SETUP_QDISC_FIFO: {
		struct tc_fifo_qopt_offload *offer = data;
		native = offer->owner;
		parent_handle = offer->parent;
		removing = offer->command == TC_FIFO_DESTROY;
		stats = offer->command == TC_FIFO_STATS;
		break;
	}
	case TC_SETUP_QDISC_PRIO: {
		struct tc_prio_qopt_offload *offer = data;
		native = offer->owner;
		parent_handle = offer->parent;
		removing = offer->command == TC_PRIO_DESTROY;
		stats = offer->command == TC_PRIO_STATS;
		graft = offer->command == TC_PRIO_GRAFT;
		break;
	}
	case TC_SETUP_QDISC_RED: {
		struct tc_red_qopt_offload *offer = data;
		native = offer->owner;
		parent_handle = offer->parent;
		removing = offer->command == TC_RED_DESTROY;
		stats = offer->command == TC_RED_STATS || offer->command == TC_RED_XSTATS;
		graft = offer->command == TC_RED_GRAFT;
		break;
	}
	case TC_SETUP_QDISC_CODEL: {
		struct tc_codel_qopt_offload *offer = data;
		native = offer->owner;
		parent_handle = offer->parent;
		removing = offer->command == TC_CODEL_DESTROY;
		stats = offer->command == TC_CODEL_STATS;
		break;
	}
	case TC_SETUP_QDISC_FQ_CODEL: {
		struct tc_fq_codel_qopt_offload *offer = data;
		native = offer->owner;
		parent_handle = offer->parent;
		removing = offer->command == TC_CODEL_DESTROY;
		stats = offer->command == TC_CODEL_STATS;
		break;
	}
	default:
		return -EOPNOTSUPP;
	}
	if (!native.sch)
		return -EINVAL;
	if (!stats) {
		err = qdx_tc_invalidate(owner, false, true);
		if (err && !removing)
			return err;
	}
	mutex_lock(&owner->cfg);
	list_for_each_entry(tree, &owner->trees, list) {
		list_for_each_entry(node, &tree->nodes, list) {
			if (node->native == native.sch && node->native_class == native.class &&
			    !node->native_dead) {
				found = node;
				found_tree = tree;
			}
			if (node->native && node->handle == TC_H_MAJ(parent_handle) &&
			    !node->native_class && !node->native_dead)
				parent_kind = node->kind;
		}
	}
	if (stats) {
		err = -EOPNOTSUPP;
		if (found && found->allocated && found->configured && !found->retiring &&
		    found->stats.source && !found->stats.detached) {
			qdx_tc_stats_request(found);
			err = 0;
		}
		goto unlock;
	}
	if (removing) {
		if (found) {
			found->native_dead = true;
			found->retiring = true;
			qdx_tc_stats_detach(found);
			if (found == found_tree->root)
				found_tree->native_dead = true;
			found_tree->retiring = true;
		}
		err = 0;
		goto changed;
	}
	if (graft) {
		err = 0;
		goto changed;
	}
	if (!tc_can_offload(owner->dev) || owner->closing ||
	    qdx_service_state(owner->service) != QDX_AVAILABLE) {
		err = -EOPNOTSUPP;
		goto changed;
	}
	mutex_unlock(&owner->cfg);
	if (type == TC_SETUP_QDISC_FQ_CODEL &&
	    ((struct tc_fq_codel_qopt_offload *)data)->block) {
		err = qdx_tc_bucket_empty(((struct tc_fq_codel_qopt_offload *)data)->block,
			&sequence);
		if (err)
			goto schedule;
	}
	err = qdx_tc_translate(owner->dev, parent_kind, type, data, true, &parameters);
	mutex_lock(&owner->cfg);
	if (err)
		goto changed;
	/* A typed update supplies parameters, not the committed whole-tree
	 * population. Preserve an unchanged actual representation here; the
	 * current native walk decides whether its placement remains eligible.
	 */
	if (found && found_tree->peak_node == found)
		parameters.output_peak = true;
	if (found && (found->allocated || found->command[QDX_TC_NODE_ALLOC].request)) {
		if (!qdx_tc_parameters_match(found, &parameters)) {
			/* The old device stage remains held. Its actual queued packets,
			 * FQ region and source must retire before a different encoding.
			 * Native callers retain their own original error/commit behavior.
			 */
			found_tree->retiring = true;
			err = -EAGAIN;
			goto changed;
		}
	}
	if (owner->ifb_state) {
		err = qdx_tc_ifb_prepare(owner);
		if (err)
			goto changed;
	}
	if (!found) {
		tree = qdx_tc_tree_alloc(owner, native.sch);
		if (IS_ERR(tree)) {
			err = PTR_ERR(tree);
			goto changed;
		}
		tree->prospective = true;
		found = qdx_tc_node_alloc(tree);
		if (IS_ERR(found)) {
			err = PTR_ERR(found);
			tree->native_dead = true;
			tree->retiring = true;
			goto changed;
		}
		found_tree = tree;
		tree->root = found;
		found->native = native.sch;
		found->native_class = native.class;
		found->handle = native.sch->handle;
	}
	if (parent_handle == TC_H_ROOT) {
		err = qdx_tc_root_prepare(found);
		if (err)
			goto changed;
	}
	if (found->retiring || found_tree->retiring) {
		err = -EAGAIN;
		goto changed;
	}
	err = qdx_tc_qdisc_prepare(found, &parameters, parent_handle == TC_H_ROOT);
	if (!err && !found->stats.source) {
		found->stats.source = gnet_stats_hw_source_open(native.hw_stats);
		if (IS_ERR(found->stats.source)) {
			err = PTR_ERR(found->stats.source);
			found->stats.source = NULL;
		} else {
			found->stats.detached = false;
		}
	}
	/* A proven root's first ALLOC reserves the actual firmware root. No
	 * SET_ROOT/default/link/queue/flow publication is implied by this node
	 * preparation result; the complete current graph still gates execution.
	 */
changed:
	owner->replay_needed = true;
unlock:
	mutex_unlock(&owner->cfg);
schedule:
	qdx_tc_schedule(owner);
	return err;
}
