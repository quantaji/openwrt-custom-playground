// SPDX-License-Identifier: GPL-2.0-only
#include <linux/etherdevice.h>
#include <linux/jiffies.h>
#include <linux/slab.h>
#include <net/rtnetlink.h>
#include "tc.h"

/* A prepared operation belongs to one actual IFB TX queue and one immutable
 * node. Different queues may use the same node, but never the same wait.
 */
struct qdx_tc_ifb_operation {
	struct list_head list;
	refcount_t refs;
	struct qdx_tc_node *node;
	struct qdx_packet_op *packet;
	struct qdx_resource_wait wait;
	struct ifb_binding *wait_binding;
	u16 queue;
	bool closed;
};

struct qdx_tc_ifb {
	struct list_head operations;
	/* A completed control-plane handback, not a copy of HW_TC permission. */
	bool native_return;
};

enum qdx_tc_igs_command {
	QDX_IGS_ASSIGN,
	QDX_IGS_NEXTHOP,
	QDX_IGS_RESET,
	QDX_IGS_CLEAR,
	QDX_IGS_COMMANDS,
};

struct qdx_tc_igs {
	struct list_head list;
	refcount_t refs;
	struct qdx_tc_owner *owner;
	struct qdx_tc_view *target;
	struct qdx_binding_use target_use;
	struct qdx_endpoint *source;
	struct qdx_rx_use *rx;
	struct qdx_receiver *receiver;
	struct qdx_tc_command command[QDX_IGS_COMMANDS];
	u32 ifnum;
	unsigned int users;
	bool assigned;
	bool nexthop;
	bool available;
	bool retiring;
};

static bool qdx_tc_ifb_operation_get(void *object)
{
	struct qdx_tc_ifb_operation *operation = object;

	return refcount_inc_not_zero(&operation->refs);
}

static void qdx_tc_ifb_operation_put(void *object)
{
	struct qdx_tc_ifb_operation *operation = object;
	struct qdx_tc_owner *owner = operation->node->tree->owner;
	bool closing = READ_ONCE(operation->closed);

	if (closing)
		qdx_tc_owner_get(owner);
	if (!refcount_dec_and_test(&operation->refs)) {
		if (closing) {
			qdx_tc_schedule(owner);
			qdx_tc_owner_put(owner);
		}
		return;
	}
	WARN_ON_ONCE(!operation->closed || operation->wait.armed ||
		     refcount_read(&operation->wait.calls));
	qdx_packet_op_put(operation->packet);
	qdx_tc_node_put(operation->node);
	kfree(operation);
	if (closing) {
		qdx_tc_schedule(owner);
		qdx_tc_owner_put(owner);
	}
}

static void qdx_tc_ifb_credit(void *object)
{
	struct qdx_tc_ifb_operation *operation = object;
	struct ifb_binding *binding = READ_ONCE(operation->wait_binding);

	/* Native unbind cannot release this binding until stop has drained the
	 * admitted resource callbacks. No provider/configuration lock is held.
	 */
	if (binding)
		ifb_tx_resource_progress(binding, operation->queue);
}

static enum ifb_disposition qdx_tc_ifb_query(void *object, u16 queue, void **result)
{
	struct qdx_tc_owner *owner = object;
	struct qdx_tc_ifb_operation *operation;
	struct qdx_tc_view *view;
	enum ifb_disposition disposition = IFB_HOLD;

	*result = NULL;
	spin_lock_bh(&owner->data_lock);
	if (!owner->ifb_state)
		goto out;
	if (owner->native_dead) {
		disposition = IFB_DISPOSE;
		goto out;
	}
	if (owner->ifb_state->native_return) {
		disposition = IFB_NATIVE;
		goto out;
	}
	view = owner->available;
	if (owner->closing || !view || view->invalid || !view->available || !view->tree)
		goto out;
	/* The native HTB direct prefix deliberately bypasses its shaper. It is
	 * distinct from an unavailable class queue or a whole-owner handback.
	 */
	if (view->tree->explicit_htb && queue < view->tree->normal_direct_count &&
	    queue < view->tree->packet_queues && !view->tree->packet_nodes[queue]) {
		disposition = IFB_NATIVE;
		goto out;
	}
	list_for_each_entry(operation, &owner->ifb_state->operations, list) {
		if (operation->queue != queue || operation->node->tree != view->tree ||
		    operation->closed)
			continue;
		if (qdx_tc_ifb_operation_get(operation)) {
			*result = operation;
			disposition = IFB_DEVICE;
		}
		break;
	}
out:
	spin_unlock_bh(&owner->data_lock);
	return disposition;
}

static bool qdx_tc_ifb_operation_current(struct qdx_tc_ifb_operation *operation)
{
	struct qdx_tc_owner *owner = operation->node->tree->owner;
	struct qdx_tc_view *view = owner->available;

	lockdep_assert_held(&owner->data_lock);
	return !owner->closing && !operation->closed && view && view->available &&
		!view->invalid && view->tree == operation->node->tree;
}

static struct ifb_ready qdx_tc_ifb_ready(void *object, size_t charge)
{
	struct qdx_tc_ifb_operation *operation = object;
	struct qdx_tc_owner *owner = operation->node->tree->owner;
	struct qdx_ready ready;

	spin_lock_bh(&owner->data_lock);
	if (!qdx_tc_ifb_operation_current(operation)) {
		spin_unlock_bh(&owner->data_lock);
		return (struct ifb_ready) { .status = IFB_CLOSED };
	}
	ready = qdx_packet_op_ready(operation->packet, charge);
	spin_unlock_bh(&owner->data_lock);
	switch (ready.status) {
	case QDX_ACCEPTED:
		return (struct ifb_ready) { .status = IFB_ACCEPTED };
	case QDX_RESOURCE_WAIT:
		return (struct ifb_ready) {
			.status = IFB_RESOURCE_WAIT, .resources = ready.resources,
		};
	case QDX_CLOSED:
		return (struct ifb_ready) { .status = IFB_CLOSED };
	case QDX_REFUSED:
	default:
		return (struct ifb_ready) { .status = IFB_REFUSED };
	}
}

static void qdx_tc_ifb_result(void *object, struct sk_buff *original,
		struct sk_buff *returned, const struct qdx_rx_meta *metadata,
		struct napi_struct *napi)
{
	struct qdx_tc_ifb_operation *operation = object;
	struct qdx_tc_owner *owner = operation->node->tree->owner;

	if (!returned) {
		ifb_loan_dispose(original);
	} else if (!metadata || metadata->type != QDX_RECEIVE_RETURNED ||
		   READ_ONCE(operation->closed) ||
		   (metadata->ifnum | ((metadata->core + 1) << 24)) !=
			qdx_endpoint_wire_ifnum(operation->node->endpoint) ||
		   returned->len < ETH_HLEN) {
		ifb_loan_dispose(original);
		dev_kfree_skb_any(returned);
	} else {
		ifb_loan_complete(original, returned);
	}
	/* Completion may already have consumed the original cb/storage. */
	qdx_tc_schedule(owner);
}

static struct ifb_ready qdx_tc_ifb_submit(void *object, struct sk_buff *skb)
{
	struct qdx_tc_ifb_operation *operation = object;
	struct qdx_tc_owner *owner = operation->node->tree->owner;
	struct qdx_packet_recipient recipient = {
		.owner = {
			.module = THIS_MODULE,
			.object = operation,
			.get = qdx_tc_ifb_operation_get,
			.put = qdx_tc_ifb_operation_put,
		},
		.returned = qdx_tc_ifb_result,
	};
	struct qdx_ready result;

	if (skb_is_nonlinear(skb) || skb->len < ETH_HLEN)
		return (struct ifb_ready) { .status = IFB_REFUSED };
	spin_lock_bh(&owner->data_lock);
	if (!qdx_tc_ifb_operation_current(operation)) {
		spin_unlock_bh(&owner->data_lock);
		return (struct ifb_ready) { .status = IFB_CLOSED };
	}
	result = qdx_packet_op_submit(operation->packet, skb, &recipient);
	spin_unlock_bh(&owner->data_lock);
	/* An accepted callback can consume skb before submit returns. */
	switch (result.status) {
	case QDX_ACCEPTED:
		return (struct ifb_ready) { .status = IFB_ACCEPTED };
	case QDX_RESOURCE_WAIT:
		return (struct ifb_ready) {
			.status = IFB_RESOURCE_WAIT, .resources = result.resources,
		};
	case QDX_CLOSED:
		return (struct ifb_ready) { .status = IFB_CLOSED };
	case QDX_REFUSED:
	default:
		return (struct ifb_ready) { .status = IFB_REFUSED };
	}
}

static void qdx_tc_ifb_arm(void *object, struct ifb_binding *binding, u16 queue,
			   unsigned int resources)
{
	struct qdx_tc_ifb_operation *operation = object;

	if (WARN_ON_ONCE(queue != operation->queue))
		return;
	WRITE_ONCE(operation->wait_binding, binding);
	qdx_packet_op_wait_arm(operation->packet, &operation->wait, resources);
}

static void qdx_tc_ifb_disarm(void *object, u16 queue)
{
	struct qdx_tc_ifb_operation *operation = object;

	if (WARN_ON_ONCE(queue != operation->queue))
		return;
	qdx_resource_wait_disarm(&operation->wait);
	/* Already-admitted callbacks retain this exact binding until stop drains
	 * them. Reusing this operation still names the same native queue/binding.
	 */
}

static int qdx_tc_ifb_setup(void *object, enum tc_setup_type type, void *data)
{
	return qdx_tc_setup(object, type, data);
}

static int qdx_tc_ifb_setup_block(void *object, struct tcf_block *block,
		enum flow_block_binder_type binder, enum tc_setup_type type, void *data)
{
	return qdx_tc_setup_block(object, block, binder, type, data);
}

void qdx_tc_ifb_tree_close(struct qdx_tc_tree *tree)
{
	struct qdx_tc_owner *owner = tree->owner;
	struct qdx_tc_ifb_operation *operation;

	lockdep_assert_held(&owner->cfg);
	if (!owner->ifb_state)
		return;
	spin_lock_bh(&owner->data_lock);
	owner->ifb_state->native_return = false;
	list_for_each_entry(operation, &owner->ifb_state->operations, list) {
		if (operation->node->tree != tree)
			continue;
		WRITE_ONCE(operation->closed, true);
		qdx_packet_op_close(operation->packet);
	}
	spin_unlock_bh(&owner->data_lock);
}

int qdx_tc_ifb_node_drained(struct qdx_tc_node *node)
{
	struct qdx_tc_owner *owner = node->tree->owner;
	struct qdx_tc_ifb_operation *operation, *next;
	int err = 0;

	lockdep_assert_held(&owner->cfg);
	if (!owner->ifb_state)
		return 0;
	list_for_each_entry_safe(operation, next, &owner->ifb_state->operations, list) {
		if (operation->node != node)
			continue;
		spin_lock_bh(&owner->data_lock);
		WRITE_ONCE(operation->closed, true);
		qdx_packet_op_close(operation->packet);
		spin_unlock_bh(&owner->data_lock);
		qdx_resource_wait_disarm(&operation->wait);
		qdx_resource_wait_drain(&operation->wait);
		if (!qdx_packet_op_drained(operation->packet) ||
		    refcount_read(&operation->refs) != 1) {
			err = -EINPROGRESS;
			continue;
		}
		spin_lock_bh(&owner->data_lock);
		list_del(&operation->list);
		spin_unlock_bh(&owner->data_lock);
		qdx_tc_ifb_operation_put(operation);
	}
	return err;
}

int qdx_tc_ifb_tree_drained(struct qdx_tc_tree *tree)
{
	struct qdx_tc_node *node;
	int err = 0, result;

	lockdep_assert_held(&tree->owner->cfg);
	qdx_tc_ifb_tree_close(tree);
	list_for_each_entry(node, &tree->nodes, list) {
		result = qdx_tc_ifb_node_drained(node);
		if (result && !err)
			err = result;
	}
	return err;
}

void qdx_tc_ifb_native(struct qdx_tc_owner *owner)
{
	lockdep_assert_held(&owner->cfg);
	if (!owner->ifb_state)
		return;
	/* The caller has completed source withdrawal, operation and tree cleanup
	 * and checked the current native root's ordinary CPU permission.
	 */
	if (WARN_ON_ONCE(owner->assigned || !list_empty(&owner->ifb_state->operations)))
		return;
	spin_lock_bh(&owner->data_lock);
	owner->ifb_state->native_return = true;
	spin_unlock_bh(&owner->data_lock);
}

void qdx_tc_ifb_progress(struct qdx_tc_owner *owner)
{
	ASSERT_RTNL();
	lockdep_assert_not_held(&owner->cfg);
	if (owner->ifb)
		ifb_tx_disposition_progress(owner->ifb);
}

static int qdx_tc_ifb_stop(void *object)
{
	struct qdx_tc_owner *owner = object;
	struct qdx_tc_tree *tree;
	int err, result;

	ASSERT_RTNL();
	err = qdx_tc_invalidate(owner, false, true);
	mutex_lock(&owner->cfg);
	list_for_each_entry(tree, &owner->trees, list) {
		qdx_tc_ifb_tree_close(tree);
		result = qdx_tc_ifb_tree_drained(tree);
		if (result && !err)
			err = result;
	}
	if (owner->assigned && !err)
		err = -EINPROGRESS;
	mutex_unlock(&owner->cfg);
	return err;
}

static void qdx_tc_ifb_drained(void *object)
{
	/* Native binding storage may have been freed after the reference decrement.
	 * Only this still-retained provider owner is accessed here.
	 */
	qdx_tc_schedule(object);
}

static const struct ifb_provider_ops qdx_tc_ifb_ops = {
	.owner = THIS_MODULE,
	.get = qdx_tc_owner_get,
	.put = qdx_tc_owner_put,
	.query = qdx_tc_ifb_query,
	.operation_get = qdx_tc_ifb_operation_get,
	.operation_put = qdx_tc_ifb_operation_put,
	.ready = qdx_tc_ifb_ready,
	.submit = qdx_tc_ifb_submit,
	.arm = qdx_tc_ifb_arm,
	.disarm = qdx_tc_ifb_disarm,
	.setup_tc = qdx_tc_ifb_setup,
	.setup_block = qdx_tc_ifb_setup_block,
	.stop = qdx_tc_ifb_stop,
	.drained = qdx_tc_ifb_drained,
};

int qdx_tc_ifb_bind(struct qdx_tc_owner *owner)
{
	struct qdx_tc_ifb *state;
	struct ifb_binding *binding;

	ASSERT_RTNL();
	lockdep_assert_not_held(&owner->cfg);
	if (owner->ifb)
		return 0;
	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return -ENOMEM;
	INIT_LIST_HEAD(&state->operations);
	/* No qdx execution has existed for this newly attached provider. */
	state->native_return = true;
	owner->ifb_state = state;
	binding = ifb_provider_bind(owner->dev, &qdx_tc_ifb_ops, owner);
	if (IS_ERR(binding)) {
		owner->ifb_state = NULL;
		kfree(state);
		return PTR_ERR(binding);
	}
	owner->ifb = binding;
	return 0;
}

int qdx_tc_ifb_prepare(struct qdx_tc_owner *owner)
{
	struct qdx_endpoint *endpoint;
	struct qdx_service *service;

	ASSERT_RTNL();
	lockdep_assert_held(&owner->cfg);
	if (!owner->ifb_state || !tc_can_offload(owner->dev))
		return -EOPNOTSUPP;
	spin_lock_bh(&owner->data_lock);
	owner->ifb_state->native_return = false;
	spin_unlock_bh(&owner->data_lock);
	if (!owner->endpoint) {
		/* RTNL prevents replacement of the available owner's NSS instance.
		 * The resulting endpoint retains its own IGS service reference.
		 */
		if (qdx_service_state(owner->service) != QDX_AVAILABLE)
			return -EAGAIN;
		service = qdx_service_get(NULL, QDX_SERVICE_IGS);
		if (IS_ERR(service))
			return PTR_ERR(service);
		endpoint = qdx_endpoint_alloc(service, QDX_TC_DYNAMIC_IGS);
		qdx_service_put(service);
		if (IS_ERR(endpoint))
			return PTR_ERR(endpoint);
		owner->endpoint = endpoint;
	}
	return qdx_endpoint_wait(owner->endpoint, jiffies + msecs_to_jiffies(3000));
}

int qdx_tc_ifb_tree_prepare(struct qdx_tc_tree *tree)
{
	struct qdx_tc_owner *owner = tree->owner;
	struct qdx_tc_ifb_operation *operation;
	struct qdx_tc_node *node;
	struct qdx_packet_op *packet;
	u16 queue;
	bool found;

	ASSERT_RTNL();
	lockdep_assert_held(&owner->cfg);
	if (!owner->ifb_state || !tree->rooted || !tree->packet_nodes ||
	    tree->packet_queues > owner->dev->real_num_tx_queues)
		return -EOPNOTSUPP;
	for (queue = 0; queue < tree->packet_queues; queue++) {
		node = tree->packet_nodes[queue];
		if (!node)
			continue;
		found = false;
		list_for_each_entry(operation, &owner->ifb_state->operations, list) {
			if (operation->node->tree == tree && operation->queue == queue) {
				if (operation->closed)
					return -EINPROGRESS;
				if (operation->node != node)
					return -EINVAL;
				found = true;
				break;
			}
		}
		if (found)
			continue;
		if (!node->allocated || !node->configured)
			return -EOPNOTSUPP;
		packet = qdx_packet_op_prepare(node->endpoint, node->tag,
					       QDX_RECEIVE_RETURNED);
		if (IS_ERR(packet))
			return PTR_ERR(packet);
		operation = kzalloc(sizeof(*operation), GFP_KERNEL);
		if (!operation) {
			qdx_packet_op_close(packet);
			qdx_packet_op_put(packet);
			return -ENOMEM;
		}
		refcount_set(&operation->refs, 1);
		qdx_tc_node_get(node);
		operation->node = node;
		operation->packet = packet;
		operation->queue = queue;
		INIT_LIST_HEAD(&operation->wait.node);
		operation->wait.owner = (struct qdx_owner) {
			.module = THIS_MODULE, .object = operation,
			.get = qdx_tc_ifb_operation_get,
			.put = qdx_tc_ifb_operation_put,
		};
		operation->wait.progress = qdx_tc_ifb_credit;
		spin_lock_bh(&owner->data_lock);
		list_add_tail(&operation->list, &owner->ifb_state->operations);
		spin_unlock_bh(&owner->data_lock);
	}
	return 0;
}

int qdx_tc_ifb_retire(struct qdx_tc_owner *owner)
{
	int err;

	ASSERT_RTNL();
	lockdep_assert_not_held(&owner->cfg);
	if (owner->ifb) {
		err = ifb_provider_unbind(owner->ifb);
		if (err)
			return err;
		owner->ifb = NULL;
	}
	if (owner->ifb_state) {
		if (WARN_ON_ONCE(!list_empty(&owner->ifb_state->operations)))
			return -EINPROGRESS;
		kfree(owner->ifb_state);
		owner->ifb_state = NULL;
	}
	if (owner->endpoint) {
		err = qdx_endpoint_retire(owner->endpoint);
		if (err)
			return err;
		qdx_endpoint_put(owner->endpoint);
		owner->endpoint = NULL;
	}
	return 0;
}

static bool qdx_tc_igs_get(void *object)
{
	struct qdx_tc_igs *association = object;

	return refcount_inc_not_zero(&association->refs);
}

static void qdx_tc_igs_put(void *object)
{
	struct qdx_tc_igs *association = object;
	struct qdx_tc_owner *owner = association->owner;
	bool retiring = READ_ONCE(association->retiring);

	if (retiring)
		qdx_tc_owner_get(owner);
	if (!refcount_dec_and_test(&association->refs)) {
		if (retiring) {
			qdx_tc_schedule(owner);
			qdx_tc_owner_put(owner);
		}
		return;
	}
	WARN_ON_ONCE(association->users || association->rx || association->receiver ||
		     association->target || association->target_use.linked ||
		     refcount_read(&association->target_use.deliveries));
	if (association->source)
		qdx_endpoint_put(association->source);
	qdx_tc_owner_put(association->owner);
	kfree(association);
	if (retiring) {
		qdx_tc_schedule(owner);
		qdx_tc_owner_put(owner);
	}
}

static int qdx_tc_igs_invalid(void *object, bool may_sleep)
{
	struct qdx_tc_igs *association = object;
	struct qdx_tc_owner *owner = association->owner;
	int err;

	WRITE_ONCE(association->available, false);
	WRITE_ONCE(owner->replay_needed, true);
	err = qdx_tc_invalidate(owner, true, may_sleep);
	if (may_sleep) {
		mutex_lock(&owner->cfg);
		if (association->rx) {
			int result = qdx_rx_hold(association->rx);

			if (result && !err)
				err = result;
		}
		mutex_unlock(&owner->cfg);
	}
	return err;
}

/* The four real source-interface operations carry exactly one IGS ifnum.
 * Revisit the original request after timeout before deciding its inverse.
 */
static int qdx_tc_igs_command(struct qdx_tc_igs *association,
			      enum qdx_tc_igs_command operation)
{
	static const u32 opcode[QDX_IGS_COMMANDS] = {
		[QDX_IGS_ASSIGN] = QDX_TC_SET_IGS,
		[QDX_IGS_NEXTHOP] = QDX_TC_SET_NEXTHOP,
		[QDX_IGS_RESET] = QDX_TC_RESET_NEXTHOP,
		[QDX_IGS_CLEAR] = QDX_TC_CLEAR_IGS,
	};
	const struct qdx_reply_bounds bounds = {
		.minimum = sizeof(__le32), .maximum = sizeof(__le32),
		.capacity = sizeof(__le32),
	};
	struct qdx_tc_command *command = &association->command[operation];
	__le32 payload = cpu_to_le32(association->ifnum);
	struct qdx_result result;
	bool malformed;
	int err;

	lockdep_assert_held(&association->owner->cfg);
	if (!command->request) {
		err = qdx_tc_command_start(command, association->source, opcode[operation],
					   &payload, sizeof(payload), &bounds);
		if (err)
			return err;
	}
	err = qdx_tc_command_wait(command);
	spin_lock_bh(&command->lock);
	result = command->result;
	malformed = result.outcome == QDX_ACK &&
		command->reply_length != sizeof(payload);
	if (malformed) {
		command->malformed_reply = true;
		command->result.outcome = QDX_UNKNOWN;
		command->result.error = -EPROTO;
	}
	spin_unlock_bh(&command->lock);
	if (malformed) {
		qdx_stop_execution(association->owner->service, -EPROTO);
		return -EPROTO;
	}
	if (result.outcome == QDX_UNKNOWN && !result.exposure_ended)
		/* A transport warning or waiter timeout leaves this same request
		 * pending. Keep its original error in command->result; only an
		 * explicit cancellation ends the caller's preparation desire.
		 */
		return result.error == -ECANCELED ? -ECANCELED : -EINPROGRESS;
	qdx_tc_command_clear(command);
	if (result.outcome != QDX_ACK)
		return result.error ?: err ?: -EIO;
	switch (operation) {
	case QDX_IGS_ASSIGN:
		association->assigned = true;
		break;
	case QDX_IGS_NEXTHOP:
		association->nexthop = true;
		break;
	case QDX_IGS_RESET:
		association->nexthop = false;
		break;
	case QDX_IGS_CLEAR:
		association->assigned = false;
		break;
	default:
		break;
	}
	return 0;
}

static void qdx_tc_igs_fresh(void *object, struct sk_buff *skb,
		const struct qdx_rx_meta *metadata, struct napi_struct *napi)
{
	struct qdx_tc_igs *association = object;
	struct net_device *source = association->owner->dev;
	struct net_device *ifb = association->target->owner->dev;
	bool available;

	qdx_uses_lock();
	available = READ_ONCE(association->available) &&
		qdx_use_available_locked(&association->target_use);
	qdx_uses_unlock();
	/* 11.4 PACKET + INGRESS_SHAPED identifies a fresh physical-source return.
	 * The original association survives source detachment and N2H drain;
	 * this is never a lookup of the current owner of a numeric IFB index.
	 */
	if (!available || READ_ONCE(association->retiring) ||
	    metadata->type != QDX_RECEIVE_PACKET || !(metadata->flags & BIT(4)) ||
	    (metadata->ifnum | ((metadata->core + 1) << 24)) !=
		qdx_endpoint_wire_ifnum(association->source) ||
	    READ_ONCE(source->reg_state) != NETREG_REGISTERED ||
	    READ_ONCE(ifb->reg_state) != NETREG_REGISTERED ||
	    !pskb_may_pull(skb, ETH_HLEN)) {
		dev_kfree_skb_any(skb);
		return;
	}
	/* Establish the real Ethernet receive geometry, then leave the saved MAC
	 * bytes present for IFB's one native ingress continuation pull.
	 */
	skb->protocol = eth_type_trans(skb, source);
	skb_push(skb, ETH_HLEN);
	skb->mac_len = ETH_HLEN;
	skb->skb_iif = ifb->ifindex;
	dev_hold(source);
	ifb_fresh_ingress_continue(source, skb, ETH_HLEN);
}

static const struct qdx_receive_ops qdx_tc_igs_receive = {
	.packet = qdx_tc_igs_fresh,
};

const struct qdx_tc_view *qdx_tc_igs_view(const struct qdx_tc_igs *association)
{
	return association->target;
}

bool qdx_tc_igs_available_locked(const struct qdx_tc_igs *association)
{
	return READ_ONCE(association->available) && !READ_ONCE(association->retiring) &&
		qdx_use_available_locked(&association->target_use);
}

int qdx_tc_igs_prepare(struct qdx_tc_rule *rule)
{
	struct qdx_tc_owner *owner = rule->owner;
	struct qdx_tc_igs *association = rule->igs;
	struct qdx_tc_rule *user;
	struct qdx_owner holder;
	struct qdx_tc_tree *tree;
	struct qdx_endpoint *source;
	struct qdx_receiver *receiver;
	struct qdx_rx_use *rx;
	unsigned int operation;
	int err;

	ASSERT_RTNL();
	lockdep_assert_held(&owner->cfg);
	/* Classifier admission established the terminal source-stable position,
	 * explicit disabled action accounting and zero native in_hw obligation.
	 */
	if (owner->direction != QDX_TC_INGRESS ||
	    rule->action != QDX_TC_REDIRECT_IFB || !rule->target)
		return -EOPNOTSUPP;
	if (!rule->target->rtnl_link_ops ||
	    strcmp(rule->target->rtnl_link_ops->kind, "ifb"))
		return -EOPNOTSUPP;
	if (owner->dev->rtnl_link_ops &&
	    !strcmp(owner->dev->rtnl_link_ops->kind, "ifb"))
		return -EOPNOTSUPP;
	if (!association) {
		list_for_each_entry(association, &owner->associations, list) {
			if (association->retiring || !association->target ||
			    association->target->owner->dev != rule->target)
				return -EINPROGRESS;
			qdx_uses_lock();
			err = READ_ONCE(association->available) &&
				qdx_use_available_locked(&association->target_use) ? 0 : -ESTALE;
			qdx_uses_unlock();
			if (err)
				return err;
			qdx_tc_igs_get(association);
			association->users++;
			rule->igs = association;
			return 0;
		}
		association = kzalloc(sizeof(*association), GFP_KERNEL);
		if (!association)
			return -ENOMEM;
		refcount_set(&association->refs, 2); /* Actual source list and rule. */
		qdx_tc_owner_get(owner);
		association->owner = owner;
		association->users = 1;
		holder = (struct qdx_owner) {
			.module = THIS_MODULE, .object = association,
			.get = qdx_tc_igs_get, .put = qdx_tc_igs_put,
		};
		for (operation = 0; operation < QDX_IGS_COMMANDS; operation++)
			qdx_tc_command_init(&association->command[operation], owner, &holder);
		INIT_LIST_HEAD(&association->target_use.node);
		list_add_tail(&association->list, &owner->associations);
		rule->igs = association;
		err = qdx_tc_view_acquire(rule->target, QDX_TC_EGRESS,
					  &association->target_use, &holder,
					  qdx_tc_igs_invalid, &association->target);
		if (err) {
			/* No target view was acquired. Its actual later publication
			 * reoffers the native memo; this is not a pending command.
			 */
			if (err == -EAGAIN)
				err = -EOPNOTSUPP;
			goto failed;
		}
	}
	if (association->retiring) {
		rule->release_igs = true;
		return -EINPROGRESS;
	}
	qdx_uses_lock();
	err = qdx_use_available_locked(&association->target_use) ? 0 : -ESTALE;
	qdx_uses_unlock();
	if (err)
		goto failed;
	if (READ_ONCE(association->available))
		return 0;
	tree = association->target ? association->target->tree : NULL;
	if (!tree || !tree->rooted || !tree->root || !tree->owner->ifb) {
		err = -EOPNOTSUPP;
		goto failed;
	}
	if (!association->source) {
		source = qdx_endpoint_get(owner->service, owner->dev);
		if (IS_ERR(source)) {
			err = PTR_ERR(source);
			goto failed;
		}
		association->source = source;
	}
	err = qdx_endpoint_ifnum(tree->endpoint, &association->ifnum);
	if (err)
		goto failed;
	/* This selected wired service uses one registered device and one core.
	 * Cross-core source/target forwarding is not inferred from local ifnums.
	 */
	if ((qdx_endpoint_wire_ifnum(tree->endpoint) >> 24) !=
	    (qdx_endpoint_wire_ifnum(association->source) >> 24)) {
		err = -EXDEV;
		goto failed;
	}
	if (!association->receiver) {
		holder = (struct qdx_owner) {
			.module = THIS_MODULE, .object = association,
			.get = qdx_tc_igs_get, .put = qdx_tc_igs_put,
		};
		receiver = qdx_endpoint_receive_register(association->source,
			QDX_RECEIVE_INGRESS_SHAPED, &holder, &qdx_tc_igs_receive);
		if (IS_ERR(receiver)) {
			err = PTR_ERR(receiver);
			goto failed;
		}
		association->receiver = receiver;
	}
	if (!association->rx) {
		rx = qdx_rx_acquire(association->source, owner->dev);
		if (IS_ERR(rx)) {
			err = PTR_ERR(rx);
			goto failed;
		}
		association->rx = rx;
	}
	if (!association->assigned) {
		err = qdx_tc_igs_command(association, QDX_IGS_ASSIGN);
		if (err == -EINPROGRESS)
			goto pending;
		if (err)
			goto failed;
	}
	if (!association->nexthop) {
		err = qdx_tc_igs_command(association, QDX_IGS_NEXTHOP);
		if (err == -EINPROGRESS)
			goto pending;
		if (err)
			goto failed;
	}
	qdx_uses_lock();
	if (!qdx_use_available_locked(&association->target_use)) {
		err = -ESTALE;
	} else {
		association->available = true;
		err = 0;
	}
	qdx_uses_unlock();
	if (!err)
		return 0;
	goto failed;
pending:
	/* The reply callback schedules this owner and retains the association.
	 * A late ACK may already be present: revisit that original command, not
	 * a replacement association, while its real target use remains valid.
	 */
	qdx_uses_lock();
	err = qdx_use_available_locked(&association->target_use) ?
		-EINPROGRESS : -ESTALE;
	qdx_uses_unlock();
	if (err == -EINPROGRESS)
		return err;
failed:
	/* Every real rule join must release this failed association. Preserve a
	 * dependency change until those joins and the source execution have ended;
	 * an unavailable first query or NACK creates no replay event.
	 */
	list_for_each_entry(user, &owner->rules, list) {
		if (user->igs != association)
			continue;
		user->release_igs = true;
		if (err == -ESTALE && user->block && !user->block->dead)
			user->block->replay_needed = true;
	}
	WRITE_ONCE(association->retiring, true);
	WRITE_ONCE(association->available, false);
	qdx_tc_schedule(owner);
	return err;
}

int qdx_tc_igs_retire(struct qdx_tc_igs *association)
{
	struct qdx_tc_owner *owner = association->owner;
	unsigned int operation;
	int err;

	ASSERT_RTNL();
	lockdep_assert_held(&owner->cfg);
	if (association->users > 1) {
		association->users--;
		qdx_tc_igs_put(association);
		return 0; /* Only this rule's real join ended. */
	}
	WRITE_ONCE(association->retiring, true);
	WRITE_ONCE(association->available, false);
	if (association->rx) {
		err = qdx_rx_hold(association->rx);
		if (err)
			return err;
	}
	for (operation = 0; operation < QDX_IGS_COMMANDS; operation++) {
		if (!association->command[operation].request)
			continue;
		err = qdx_tc_igs_command(association, operation);
		if (association->command[operation].request)
			return err ?: -EINPROGRESS;
	}
	if (qdx_service_access_ended(owner->service)) {
		association->assigned = false;
		association->nexthop = false;
	}
	if (association->nexthop) {
		err = qdx_tc_igs_command(association, QDX_IGS_RESET);
		if (err)
			return err;
	}
	if (association->assigned) {
		err = qdx_tc_igs_command(association, QDX_IGS_CLEAR);
		if (err)
			return err;
	}
	/* Source producer removal and the captured N2H prefix must precede reuse
	 * of this source's unversioned fresh-return category.
	 */
	if (association->receiver) {
		err = qdx_endpoint_receive_unregister(association->receiver);
		if (err)
			return err;
		association->receiver = NULL;
	}
	if (association->rx) {
		err = qdx_rx_release(association->rx);
		if (err)
			return err;
		association->rx = NULL;
	}
	for (operation = 0; operation < QDX_IGS_COMMANDS; operation++)
		if (!completion_done(&association->command[operation].recipient_done))
			return -EINPROGRESS;
	if (association->target) {
		qdx_tc_view_put(association->target);
		association->target = NULL;
	}
	qdx_binding_use_put(&association->target_use);
	if (refcount_read(&association->target_use.deliveries))
		return -EINPROGRESS;
	association->users = 0;
	list_del(&association->list);
	qdx_tc_igs_put(association); /* Actual rule join. */
	qdx_tc_igs_put(association); /* Actual source-list ownership. */
	return 0;
}
