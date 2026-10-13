// SPDX-License-Identifier: GPL-2.0-only
#include <linux/jiffies.h>
#include <linux/hardirq.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/rtnetlink.h>
#include <linux/srcu.h>
#include <net/net_namespace.h>
#include <net/rtnetlink.h>
#include <net/tcx.h>
#include "tc.h"

/* Set only after module_exit closes every new native/provider admission.
 * That function retains the code until all cleanup recipients/work drain.
 */
bool qdx_tc_exit_draining;
static struct workqueue_struct *qdx_tc_wq;
static DECLARE_WAIT_QUEUE_HEAD(qdx_tc_drained);

static bool qdx_tc_command_get(void *object)
{
	struct qdx_tc_command *command = object;

	if (!command->holder.get(command->holder.object))
		return false;
	reinit_completion(&command->recipient_done);
	return true;
}

static void qdx_tc_command_put(void *object)
{
	struct qdx_tc_command *command = object;
	struct qdx_owner holder = command->holder;
	struct qdx_tc_owner *owner = command->owner;

	/* The shared request's final recipient put follows every delivery. This
	 * is the actual reuse boundary, independently of waiter completion.
	 */
	complete_all(&command->recipient_done);
	qdx_tc_schedule(owner);
	holder.put(holder.object);
}

static void qdx_tc_command_result(void *object, const struct qdx_result *result,
				  const void *payload, size_t length)
{
	struct qdx_tc_command *command = object;

	spin_lock_bh(&command->lock);
	if (!command->malformed_reply &&
	    (!command->replied || command->result.outcome == QDX_UNKNOWN)) {
		command->result = *result;
		/* The carrier can expose padding beyond the declared ABI reply.
		 * Store only logical reply bytes actually supplied by the recipient.
		 */
		command->reply_length = min(length, result->declared_len);
		if (payload && command->reply_length <= sizeof(command->reply))
			memcpy(command->reply, payload, command->reply_length);
		command->replied = true;
	}
	spin_unlock_bh(&command->lock);
	qdx_tc_schedule(command->owner);
}

void qdx_tc_command_init(struct qdx_tc_command *command,
			 struct qdx_tc_owner *owner, const struct qdx_owner *holder)
{
	spin_lock_init(&command->lock);
	init_completion(&command->recipient_done);
	complete_all(&command->recipient_done);
	command->owner = owner;
	command->holder = *holder;
}

int qdx_tc_command_start(struct qdx_tc_command *command,
			 struct qdx_endpoint *endpoint, u32 opcode,
			 const void *payload, size_t length,
			 const struct qdx_reply_bounds *bounds)
{
	struct qdx_command_recipient recipient = {
		.owner = {
			.module = THIS_MODULE,
			.object = command,
			.get = qdx_tc_command_get,
			.put = qdx_tc_command_put,
		},
		.result = qdx_tc_command_result,
	};
	struct qdx_request *request;

	if (READ_ONCE(qdx_tc_exit_draining))
		recipient.owner.module = NULL; /* code lifetime held by module_exit drain */

	lockdep_assert_held(&command->owner->cfg);
	if (command->request)
		return -EALREADY;
	if (bounds->capacity > sizeof(command->reply))
		return -E2BIG;
	/* Only an old request's independent recipient release can satisfy this
	 * bounded wait. No RTNL or TC worker is needed for that release.
	 */
	if (!wait_for_completion_timeout(&command->recipient_done,
					 QDX_TC_COMMAND_TIMEOUT))
		return -EINPROGRESS;
	spin_lock_bh(&command->lock);
	memset(&command->result, 0, sizeof(command->result));
	command->result.outcome = QDX_NOT_SUBMITTED;
	command->replied = false;
	command->malformed_reply = false;
	command->reply_length = 0;
	spin_unlock_bh(&command->lock);
	request = qdx_command_submit(endpoint, opcode, payload, length, bounds,
				     &recipient);
	if (IS_ERR(request))
		return PTR_ERR(request);
	command->request = request;
	return 0;
}

int qdx_tc_command_wait(struct qdx_tc_command *command)
{
	u8 payload[sizeof(command->reply)];
	struct qdx_result result;
	int err;

	lockdep_assert_held(&command->owner->cfg);
	if (!command->request)
		return -ENOENT;
	if (command->malformed_reply) {
		spin_lock_bh(&command->lock);
		command->result.exposure_ended =
			qdx_service_access_ended(command->owner->service);
		spin_unlock_bh(&command->lock);
		return -EPROTO;
	}
	err = qdx_request_wait(command->request, jiffies + QDX_TC_COMMAND_TIMEOUT,
			       &result, payload, sizeof(payload));
	/* The shared waiter can precede the recipient. Save this exact original
	 * request's result; its still-live recipient prevents storage reuse.
	 */
	spin_lock_bh(&command->lock);
	if (!command->replied || command->result.outcome == QDX_UNKNOWN) {
		command->result = result;
		/* A valid declared extent is within the original request capacity;
		 * received_len can be larger than the bytes copied by this waiter.
		 */
		command->reply_length = min(result.declared_len, sizeof(payload));
		if (command->reply_length)
			memcpy(command->reply, payload, command->reply_length);
		command->replied = true;
	}
	spin_unlock_bh(&command->lock);
	return err;
}

void qdx_tc_command_clear(struct qdx_tc_command *command)
{
	struct qdx_request *request = command->request;
	bool settled;

	lockdep_assert_held(&command->owner->cfg);
	if (!request)
		return;
	spin_lock_bh(&command->lock);
	settled = command->replied &&
		(command->result.outcome == QDX_ACK ||
		 command->result.outcome == QDX_REJECTED ||
		 command->result.exposure_ended);
	spin_unlock_bh(&command->lock);
	if (WARN_ON_ONCE(!settled))
		return;
	command->request = NULL;
	qdx_request_put(request);
}

bool qdx_tc_owner_get(void *object)
{
	struct qdx_tc_owner *owner = object;

	return refcount_inc_not_zero(&owner->refs);
}

void qdx_tc_owner_put(void *object)
{
	struct qdx_tc_owner *owner = object;

	if (!refcount_dec_and_test(&owner->refs))
		return;
	WARN_ON_ONCE(!list_empty(&owner->trees) || !list_empty(&owner->rules) ||
		     !list_empty(&owner->blocks) || !list_empty(&owner->views) ||
		     !list_empty(&owner->associations) || owner->binding || owner->ifb ||
		     owner->root_allocation);
	if (owner->port_use.linked)
		qdx_binding_use_put(&owner->port_use);
	if (owner->port)
		qdx_binding_put(owner->port);
	if (owner->endpoint)
		qdx_endpoint_put(owner->endpoint);
	if (owner->service)
		qdx_service_put(owner->service);
	ida_destroy(&owner->tags);
	dev_put(owner->dev);
	kfree(owner);
}

void qdx_tc_schedule(struct qdx_tc_owner *owner)
{
	if (!in_interrupt() && current_work() == &owner->work.work)
		return;
	if (!qdx_tc_owner_get(owner))
		return;
	/* A newly queued invocation owns the reference before it can execute.
	 * Updating an already pending invocation needs no second reference.
	 */
	if (mod_delayed_work(qdx_tc_wq, &owner->work, 0))
		qdx_tc_owner_put(owner);
}

int qdx_tc_invalidate(struct qdx_tc_owner *owner, bool pending, bool may_sleep)
{
	struct qdx_binding_scan scan;
	struct qdx_binding_use *use;
	struct qdx_tc_view *view;
	struct qdx_tc_tree *tree;
	struct qdx_tc_node *node;
	struct qdx_tc_rule *rule;
	int err = 0, result;

	qdx_uses_lock();
	spin_lock_bh(&owner->data_lock);
	list_for_each_entry(view, &owner->views, list) {
		if (view == owner->pending && !pending)
			continue;
		view->invalid = true;
		view->available = false;
	}
	spin_unlock_bh(&owner->data_lock);
	qdx_uses_unlock();
	if (owner->binding)
		qdx_binding_invalidate(owner->binding);
	if (!may_sleep) {
		qdx_tc_schedule(owner);
		return 0; /* Admission is closed; the worker still owes actual stop. */
	}
	if (owner->binding) {
		qdx_binding_scan_start(owner->binding, &scan);
		while ((use = qdx_binding_user_get(owner->binding, &scan))) {
			result = use->invalidate ?
				use->invalidate(use->consumer.object, true) : 0;
			if (result && !err)
				err = result;
			qdx_binding_user_put(use);
		}
	}
	mutex_lock(&owner->cfg);
	list_for_each_entry(tree, &owner->trees, list) {
		/* Native ADD/replay stops old published execution. It must not close
		 * the unpublished path this same coherent preparation just acquired.
		 * Real native mutation completion invalidates pending=true instead.
		 */
		if (!pending && owner->pending && owner->pending->tree == tree &&
		    (!owner->available || owner->available->tree != tree))
			continue;
		list_for_each_entry(node, &tree->nodes, list) {
			result = node->queue ? owner->port_ops->queues->hold(node->queue) : 0;
			if (!result && node->path)
				result = qdx_tx_hold(node->path);
			if (result && !err)
				err = result;
		}
		if (owner->ifb_state)
			qdx_tc_ifb_tree_close(tree);
		tree->held = true;
		tree->hold_error = err;
	}
	if (owner->match.rx) {
		result = qdx_rx_hold(owner->match.rx);
		if (!result)
			owner->match.held = true;
		if (result && !err)
			err = result;
	}
	list_for_each_entry(rule, &owner->rules, list) {
		if (!rule->rx)
			continue;
		result = qdx_rx_hold(rule->rx);
		if (!result)
			rule->held = true;
		if (result && !err)
			err = result;
	}
	mutex_unlock(&owner->cfg);
	if (err)
		qdx_stop_execution(owner->service, err);
	qdx_tc_schedule(owner);
	return err;
}

int qdx_tc_view_acquire(struct net_device *dev, enum qdx_tc_direction direction,
			struct qdx_binding_use *use, const struct qdx_owner *consumer,
			int (*invalidate)(void *consumer, bool may_sleep),
			struct qdx_tc_view **result)
{
	struct qdx_binding_key key = {
		.dev = dev, .identity = (void *)(unsigned long)(direction + 1),
		.role = QDX_BINDING_TC,
	};
	struct qdx_binding *binding;
	struct qdx_tc_owner *owner;
	struct qdx_tc_view *view;
	int err;

	*result = NULL;
	binding = qdx_binding_lookup(&key);
	if (IS_ERR(binding))
		return PTR_ERR(binding);
	if (!binding)
		return -EOPNOTSUPP;
	owner = qdx_binding_owner(binding);
	err = qdx_binding_use(binding, use, consumer, invalidate);
	if (err)
		goto put;
	qdx_uses_lock();
	spin_lock_bh(&owner->data_lock);
	view = owner->available;
	if (!view || view->invalid || !view->available ||
	    !qdx_use_available_locked(use) || owner->closing) {
		err = -EAGAIN;
	} else {
		refcount_inc(&view->refs);
		qdx_use_publish_locked(use);
		*result = view;
	}
	spin_unlock_bh(&owner->data_lock);
	qdx_uses_unlock();
	if (err)
		qdx_binding_use_put(use);
put:
	qdx_binding_put(binding);
	return err;
}

void qdx_tc_view_put(struct qdx_tc_view *view)
{
	struct qdx_tc_block *block;
	struct qdx_tc_owner *owner = view->owner;
	unsigned int i;

	/* Hold the owner before dropping a view reference: the worker may
	 * remove its list reference immediately after this decrement.
	 */
	qdx_tc_owner_get(owner);
	if (!refcount_dec_and_test(&view->refs)) {
		qdx_tc_schedule(owner);
		qdx_tc_owner_put(owner);
		return;
	}
	for (i = 0; i < view->nr_rules; i++)
		qdx_tc_rule_put(view->rules[i]);
	for (i = 0; i < view->nr_blocks; i++) {
		block = view->blocks[i].block;
		if (block && refcount_dec_and_test(&block->refs)) {
			qdx_tc_owner_put(block->owner);
			kfree(block);
		}
	}
	kfree(view->rules);
	kfree(view->blocks);
	if (view->tree)
		qdx_tc_tree_put(view->tree);
	qdx_tc_owner_put(owner);
	kfree(view);
	qdx_tc_owner_put(owner);
}

int qdx_tc_view_observe(struct qdx_tc_view *view, struct tcf_block *block,
			u64 sequence)
{
	struct qdx_tc_view_block *observations, *old;
	struct qdx_tc_owner *owner = view->owner;
	unsigned int count = view->nr_blocks, i;

	ASSERT_RTNL();
	for (i = 0; i < count; i++)
		if (view->blocks[i].native == block)
			return view->blocks[i].sequence == sequence ? 0 : -EAGAIN;
	observations = kmalloc_array(count + 1, sizeof(*observations), GFP_KERNEL);
	if (!observations)
		return -ENOMEM;
	if (count)
		memcpy(observations, view->blocks, count * sizeof(*observations));
	observations[count] = (struct qdx_tc_view_block) {
		.native = block, .sequence = sequence,
	};
	qdx_uses_lock();
	spin_lock_bh(&owner->data_lock);
	old = view->blocks;
	view->blocks = observations;
	view->nr_blocks++;
	spin_unlock_bh(&owner->data_lock);
	qdx_uses_unlock();
	kfree(old);
	return 0;
}

static LIST_HEAD(qdx_tc_owners);
DEFINE_STATIC_SRCU(qdx_tc_owners_srcu);
static struct qdx_binding *qdx_tc_provider;
static struct qdx_listener *qdx_tc_listener;
static struct work_struct qdx_tc_scan_work;
static bool qdx_tc_admitting;
static const struct qdx_tc_ops qdx_tc_provider_ops;
static void qdx_tc_owner_work(struct work_struct *work);

static struct qdx_tc_owner *qdx_tc_owner_find(struct net_device *dev,
					    enum qdx_tc_direction direction)
{
	struct qdx_tc_owner *owner;

	ASSERT_RTNL();
	list_for_each_entry(owner, &qdx_tc_owners, list)
		if (owner->dev == dev && owner->direction == direction)
			return owner;
	return NULL;
}

static int qdx_tc_port_invalid(void *object, bool may_sleep)
{
	struct qdx_tc_owner *owner = object;

	WRITE_ONCE(owner->closing, true);
	WRITE_ONCE(owner->native_dead, true);
	return qdx_tc_invalidate(owner, true, may_sleep);
}

static void qdx_tc_port_use_put(void *object)
{
	struct qdx_tc_owner *owner = object;

	/* This is the original observer's last delivery/storage release, after
	 * unlink. Schedule while its real holder still keeps the owner alive.
	 */
	if (READ_ONCE(owner->closing))
		qdx_tc_schedule(owner);
	qdx_tc_owner_put(owner);
}

static struct qdx_tc_owner *qdx_tc_owner_create(struct net_device *dev,
			enum qdx_tc_direction direction, struct qdx_binding *port)
{
	struct qdx_binding_key key = {
		.dev = dev, .identity = (void *)(unsigned long)(direction + 1),
		.role = QDX_BINDING_TC,
	};
	struct qdx_tc_owner *owner;
	struct qdx_owner holder, observation;
	int err;

	ASSERT_RTNL();
	owner = qdx_tc_owner_find(dev, direction);
	if (owner)
		return owner;
	if (!READ_ONCE(qdx_tc_admitting))
		return ERR_PTR(-ESHUTDOWN);
	owner = kzalloc(sizeof(*owner), GFP_KERNEL);
	if (!owner)
		return ERR_PTR(-ENOMEM);
	refcount_set(&owner->refs, 1); /* Actual owner index. */
	mutex_init(&owner->cfg);
	spin_lock_init(&owner->data_lock);
	INIT_DELAYED_WORK(&owner->work, qdx_tc_owner_work);
	init_completion(&owner->drain_progress);
	INIT_LIST_HEAD(&owner->list);
	INIT_LIST_HEAD(&owner->trees);
	INIT_LIST_HEAD(&owner->blocks);
	INIT_LIST_HEAD(&owner->rules);
	INIT_LIST_HEAD(&owner->associations);
	INIT_LIST_HEAD(&owner->views);
	INIT_LIST_HEAD(&owner->port_use.node);
	ida_init(&owner->tags);
	owner->dev = dev;
	owner->direction = direction;
	dev_hold(dev);
	owner->service = qdx_service_get(port ? dev : NULL, QDX_SERVICE_SHAPER);
	if (IS_ERR(owner->service)) {
		err = PTR_ERR(owner->service);
		owner->service = NULL;
		goto fail;
	}
	holder = (struct qdx_owner) {
		.module = THIS_MODULE, .object = owner,
		.get = qdx_tc_owner_get, .put = qdx_tc_owner_put,
	};
	qdx_tc_command_init(&owner->assign, owner, &holder);
	qdx_tc_command_init(&owner->unassign, owner, &holder);
	if (port) {
		if (!qdx_binding_hold(port)) {
			err = -ENODEV;
			goto fail;
		}
		owner->port = port;
		owner->port_ops = qdx_binding_ops(port);
		observation = holder;

		/* This module unregisters and drains its own idle observation before
		 * exit returns. Actual delegated consumers retain normal code pins.
		 */
		observation.module = NULL;
		observation.put = qdx_tc_port_use_put;
		err = qdx_binding_use(port, &owner->port_use, &observation, qdx_tc_port_invalid);
		if (err)
			goto fail;
	}
	owner->binding = qdx_binding_publish(&key, &holder, &qdx_tc_provider_ops);
	if (IS_ERR(owner->binding)) {
		err = PTR_ERR(owner->binding);
		owner->binding = NULL;
		goto fail;
	}
	list_add_tail_rcu(&owner->list, &qdx_tc_owners);
	if (!port) {
		err = qdx_tc_ifb_bind(owner);
		if (err) {
			owner->closing = true;
			qdx_tc_schedule(owner);
			return ERR_PTR(err);
		}
	}
	owner->replay_needed = true;
	qdx_tc_schedule(owner);
	return owner;
fail:
	if (owner->port_use.linked)
		qdx_binding_use_put(&owner->port_use);
	qdx_tc_owner_put(owner);
	return ERR_PTR(err);
}

int qdx_tc_setup(struct qdx_tc_owner *owner, enum tc_setup_type type, void *data)
{
	ASSERT_RTNL();
	lockdep_assert_not_held(&owner->cfg);
	if (type == TC_SETUP_QDISC_HTB)
		return qdx_tc_htb_setup(owner, data);
	if (type == TC_SETUP_ROOT_QDISC) {
		int err = qdx_tc_invalidate(owner, true, true);

		owner->replay_needed = true;
		qdx_tc_schedule(owner);
		return err;
	}
	return qdx_tc_qdisc_setup(owner, type, data);
}

int qdx_tc_setup_block(struct qdx_tc_owner *owner, struct tcf_block *native,
		enum flow_block_binder_type binder, enum tc_setup_type type, void *data)
{
	struct qdx_tc_block *block, *found = NULL;
	struct flow_block_offload *offer = data;
	struct qdx_tc_rule *rule;
	int err;

	ASSERT_RTNL();
	lockdep_assert_not_held(&owner->cfg);
	list_for_each_entry(block, &owner->blocks, list)
		if (block->native == native && block->binder == binder && !block->dead) {
			found = block;
			break;
		}
	if (type != TC_SETUP_BLOCK)
		return found ? qdx_tc_block_setup(found, type, data) : -ENOENT;
	if (offer->command == FLOW_BLOCK_BIND) {
		/* Concrete callbacks reoffer a still-live borrow for late loading.
		 * This is idempotent and never recursively invokes native replay.
		 */
		if (found)
			return 0;
		block = kzalloc(sizeof(*block), GFP_KERNEL);
		if (!block)
			return -ENOMEM;
		refcount_set(&block->refs, 1);
		qdx_tc_owner_get(owner);
		block->owner = owner;
		block->native = native;
		block->binder = binder;
		block->replay_needed = true;
		spin_lock_bh(&owner->data_lock);
		list_add_tail(&block->list, &owner->blocks);
		spin_unlock_bh(&owner->data_lock);
		if (!owner->pending) {
			owner->replay_needed = true;
			qdx_tc_schedule(owner);
		}
		return 0;
	}
	if (offer->command != FLOW_BLOCK_UNBIND)
		return -EOPNOTSUPP;
	if (!found)
		return 0;
	err = qdx_tc_invalidate(owner, true, true);
	mutex_lock(&owner->cfg);
	spin_lock_bh(&owner->data_lock);
	found->dead = true;
	found->native = NULL;
	list_del(&found->list);
	spin_unlock_bh(&owner->data_lock);
	/* Native playback already returned this exact callback's obligations.
	 * Hardware tombstones retain independent rule/block storage references.
	 */
	list_for_each_entry(rule, &owner->rules, list)
		if (rule->block == found) {
			rule->native_current = false;
			rule->retiring = true;
			if (rule->native_count) {
				rule->native_count = false;
				module_put(THIS_MODULE);
			}
		}
	mutex_unlock(&owner->cfg);
	if (refcount_dec_and_test(&found->refs)) {
		qdx_tc_owner_put(owner);
		kfree(found);
	}
	owner->replay_needed = true;
	qdx_tc_schedule(owner);
	return err;
}

static int qdx_tc_native_setup(struct qdx_binding *provider,
		struct qdx_binding *port, enum tc_setup_type type, void *data)
{
	struct qdx_tc_owner *owner;

	owner = qdx_tc_owner_create(qdx_binding_dev(port), QDX_TC_EGRESS, port);
	return IS_ERR(owner) ? PTR_ERR(owner) : qdx_tc_setup(owner, type, data);
}

static int qdx_tc_native_block(struct qdx_binding *provider,
		struct qdx_binding *port, struct tcf_block *native,
		enum flow_block_binder_type binder, enum tc_setup_type type, void *data)
{
	enum qdx_tc_direction direction = binder == FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS ?
		QDX_TC_INGRESS : QDX_TC_EGRESS;
	struct qdx_tc_owner *owner;

	owner = qdx_tc_owner_create(qdx_binding_dev(port), direction, port);
	return IS_ERR(owner) ? PTR_ERR(owner) :
		qdx_tc_setup_block(owner, native, binder, type, data);
}

static bool qdx_tc_native_select(struct qdx_binding *provider,
		struct net_device *dev, const struct sk_buff *skb, u16 *queue)
{
	struct qdx_tc_owner *owner;
	bool found = false;
	int index;

	index = srcu_read_lock(&qdx_tc_owners_srcu);
	list_for_each_entry_rcu(owner, &qdx_tc_owners, list,
			       srcu_read_lock_held(&qdx_tc_owners_srcu)) {
		if (owner->dev == dev && owner->direction == QDX_TC_EGRESS) {
			found = qdx_tc_select_queue(owner, skb, queue);
			break;
		}
	}
	srcu_read_unlock(&qdx_tc_owners_srcu, index);
	return found;
}

static const struct qdx_tc_ops qdx_tc_provider_ops = {
	.setup_tc = qdx_tc_native_setup,
	.setup_block = qdx_tc_native_block,
	.select_queue = qdx_tc_native_select,
	.get = qdx_tc_project,
	.put = qdx_tc_projection_put,
};

static int qdx_tc_replay(struct qdx_tc_owner *owner, struct tcf_block *native,
			enum flow_block_binder_type binder, bool add)
{
	struct qdx_tc_rule *rule;
	int err;

	ASSERT_RTNL();
	lockdep_assert_not_held(&owner->cfg);
	if (add) {
		/* A changed native action may no longer export any typed ADD. Its
		 * old uncounted memo cannot stand in for that current native action.
		 * Real counted contributions are returned by native remove replay.
		 */
		mutex_lock(&owner->cfg);
		list_for_each_entry(rule, &owner->rules, list)
			if (rule->native_block == native && rule->block &&
			    rule->block->binder == binder && rule->memo_only && !rule->native_count)
				rule->retiring = true;
		mutex_unlock(&owner->cfg);
	}
	if (owner->ifb)
		err = ifb_provider_replay(owner->ifb, native, binder, add, NULL);
	else
		err = owner->port_ops ? owner->port_ops->replay(owner->port, native, binder, add, NULL) :
			-ENODEV;
	if (err || !add)
		return err;
	/* Native optional replay can succeed while an offer requested actual
	 * source-association retirement. Keep that block's replay obligation.
	 */
	mutex_lock(&owner->cfg);
	list_for_each_entry(rule, &owner->rules, list)
		if (rule->release_igs && rule->igs)
			err = -EINPROGRESS;
	mutex_unlock(&owner->cfg);
	return err;
}

/* Discover only real currently bound objects. Their native callbacks establish
 * the borrowed identity even if this peer was absent at original creation.
 */
static int qdx_tc_replay_current(struct qdx_tc_owner *owner)
{
	struct netdev_queue *ingress = dev_ingress_queue(owner->dev);
	struct Qdisc *sch;
	struct tcf_block *native;
	struct qdx_tc_block *block;
	struct qdx_tc_rule *rule;
	bool counted;
	int err;

	ASSERT_RTNL();
	err = 0;
	mutex_lock(&owner->cfg);
	list_for_each_entry(rule, &owner->rules, list)
		if (rule->release_igs && rule->igs)
			err = -EINPROGRESS;
	mutex_unlock(&owner->cfg);
	if (err)
		return err; /* No repeated count removal while this actual source is retiring. */
	if (ingress) {
		sch = rtnl_dereference(ingress->qdisc_sleeping);
		if (sch && !(sch->flags & TCQ_F_BUILTIN) && sch->ops->cl_ops &&
		    sch->ops->cl_ops->tcf_block) {
			native = sch->ops->cl_ops->tcf_block(sch, owner->direction == QDX_TC_INGRESS ?
				TC_H_MIN_INGRESS : TC_H_MIN_EGRESS, NULL);
			if (!IS_ERR_OR_NULL(native)) {
				bool known = false;

				list_for_each_entry(block, &owner->blocks, list)
					if (block->native == native)
						known = true;
				if (!known) {
					err = qdx_tc_replay(owner, native, owner->direction == QDX_TC_INGRESS ?
						FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS :
						FLOW_BLOCK_BINDER_TYPE_CLSACT_EGRESS, true);
					if (err)
						return err;
					list_for_each_entry(block, &owner->blocks, list)
						if (block->native == native)
							block->replay_needed = false;
				}
			}
		}
	}
	if (owner->pending) {
		unsigned int i;

		for (i = 0; i < owner->pending->nr_blocks; i++) {
			native = owner->pending->blocks[i].native;
			counted = false;
			list_for_each_entry(block, &owner->blocks, list)
				if (block->native == native)
					counted = true;
			if (counted)
				continue;
			err = qdx_tc_replay(owner, native, FLOW_BLOCK_BINDER_TYPE_UNSPEC, true);
			if (err)
				return err;
			list_for_each_entry(block, &owner->blocks, list)
				if (block->native == native)
					block->replay_needed = false;
		}
	}
	list_for_each_entry(block, &owner->blocks, list) {
		if (block->dead || !block->native || !block->replay_needed)
			continue;
		counted = false;
		mutex_lock(&owner->cfg);
		list_for_each_entry(rule, &owner->rules, list)
			if (rule->block == block && rule->native_count)
				counted = true;
		mutex_unlock(&owner->cfg);
		if (counted) {
			err = qdx_tc_replay(owner, block->native, block->binder, false);
			if (err)
				return err;
		}
		err = qdx_tc_replay(owner, block->native, block->binder, true);
		if (err)
			return err;
		block->replay_needed = false;
	}
	return 0;
}

static int qdx_tc_remove_counts(struct qdx_tc_owner *owner)
{
	struct qdx_tc_block *block;
	struct qdx_tc_rule *rule;
	bool counted;
	int err = 0, result;

	ASSERT_RTNL();
	list_for_each_entry(block, &owner->blocks, list) {
		if (block->dead || !block->native)
			continue;
		counted = false;
		mutex_lock(&owner->cfg);
		list_for_each_entry(rule, &owner->rules, list)
			if (rule->block == block && rule->native_count)
				counted = true;
		mutex_unlock(&owner->cfg);
		if (!counted)
			continue;
		result = qdx_tc_replay(owner, block->native, block->binder, false);
		if (result && !err)
			err = result;
		block->replay_needed = true;
	}
	return err;
}

static void qdx_tc_target_progress(struct qdx_tc_owner *target)
{
	struct qdx_tc_owner *source;
	struct qdx_tc_rule *rule;
	bool affected;

	ASSERT_RTNL();
	lockdep_assert_not_held(&target->cfg);
	/* An unavailable first query has no active target use to notify. The
	 * existing native rule still owns its exact target device dependency.
	 */
	list_for_each_entry(source, &qdx_tc_owners, list) {
		if (source == target || source->closing)
			continue;
		affected = false;
		mutex_lock(&source->cfg);
		list_for_each_entry(rule, &source->rules, list)
			if (rule->action == QDX_TC_REDIRECT_IFB && rule->target == target->dev &&
			    rule->block && !rule->block->dead) {
				if (rule->igs)
					rule->release_igs = true;
				rule->block->replay_needed = true;
				affected = true;
			}
		if (affected)
			WRITE_ONCE(source->replay_needed, true);
		mutex_unlock(&source->cfg);
		if (affected)
			qdx_tc_schedule(source);
	}
}

static void qdx_tc_owner_work(struct work_struct *work)
{
	struct qdx_tc_owner *owner = container_of(to_delayed_work(work), struct qdx_tc_owner, work);
	struct qdx_tc_view *view, *next_view;
	struct qdx_tc_tree *tree, *next_tree;
	struct qdx_tc_node *node;
	struct qdx_tc_rule *rule;
	struct tcf_block_state state;
	struct bpf_mprog_entry *tcx;
	struct Qdisc *native_root;
	unsigned int i;
	bool prepare, changed, closing, permission, current_valid, release_igs;
	bool conflict = false, publish = false;
	int err = 0, result;

	rtnl_lock();
	closing = owner->closing || READ_ONCE(owner->dev->reg_state) != NETREG_REGISTERED;
	permission = !closing && tc_can_offload(owner->dev) &&
		qdx_service_state(owner->service) == QDX_AVAILABLE;
	changed = permission && READ_ONCE(owner->replay_needed);
	prepare = permission && (changed || (owner->pending && !owner->pending->invalid));
	if (closing || !permission || changed)
		qdx_tc_invalidate(owner, true, true);
	if (closing || !permission)
		qdx_tc_remove_counts(owner);

retire_state:
	conflict = false;
	/* A real consumer put, not hold success, permits removal of its view.
	 * It still owns its native action/node projection until this reference ends.
	 */
	list_for_each_entry_safe(view, next_view, &owner->views, list) {
		bool remove;

		qdx_uses_lock();
		spin_lock_bh(&owner->data_lock);
		remove = view->invalid && refcount_read(&view->refs) == 1;
		if (remove) {
			if (owner->pending == view)
				owner->pending = NULL;
			if (owner->available == view)
				owner->available = NULL;
			list_del(&view->list);
		}
		spin_unlock_bh(&owner->data_lock);
		qdx_uses_unlock();
		if (remove)
			qdx_tc_view_put(view);
	}
	native_root = rtnl_dereference(owner->dev->qdisc);
	/* Even an unlinked prospective root occupies the firmware dequeue root
	 * from its first ALLOC. Native replacement must end that actual root;
	 * a SET_ROOT on another already allocated node cannot replace it.
	 */
	mutex_lock(&owner->cfg);
	if (owner->root_allocation && owner->root_allocation->native != native_root)
		owner->root_allocation->tree->retiring = true;
	mutex_unlock(&owner->cfg);
	list_for_each_entry_safe(tree, next_tree, &owner->trees, list) {
		if (!tree->prospective && tree->root && tree->root->native != native_root)
			tree->native_dead = true;
		if (closing)
			tree->native_dead = true;
		if (!permission || tree->native_dead || (!tree->prospective &&
		    (!owner->available || owner->available->invalid) &&
		    (!owner->pending || owner->pending->invalid || owner->pending->tree != tree)))
			tree->retiring = true;
		if (!tree->retiring)
			continue;
		qdx_tc_tree_get(tree);
		result = qdx_tc_tree_retire(tree, false);
		if (result)
			conflict = true;
		if (!result && !tree->native_dead)
			tree->retiring = false;
		qdx_tc_tree_put(tree);
	}
	mutex_lock(&owner->cfg);
	if (owner->native_dead) {
		/* Real native destruction ends any remaining callback obligation;
		 * no later member DESTROY can arrive for this dead native owner.
		 */
		list_for_each_entry(rule, &owner->rules, list) {
			rule->native_current = false;
			if (rule->native_count) {
				rule->native_count = false;
				module_put(THIS_MODULE);
			}
		}
	}
	qdx_tc_rules_retire(owner);
	mutex_unlock(&owner->cfg);
	if (!permission) {
		mutex_lock(&owner->cfg);
		if (!owner->assigned && !conflict && owner->ifb_state)
			qdx_tc_ifb_native(owner);
		mutex_unlock(&owner->cfg);
		if (owner->ifb)
			qdx_tc_ifb_progress(owner);
		goto retire_owner;
	}
	if (conflict || !prepare)
		goto collect_stats;
	/* Begin exactly one current read. Command/progress callbacks do not set
	 * replay_needed; a stable unsupported native policy is not retried forever.
	 */
	owner->replay_needed = false;
	view = owner->pending;
	if (!view) {
		view = kzalloc(sizeof(*view), GFP_KERNEL);
		if (!view) {
			err = -ENOMEM;
			goto collect_stats;
		}
		refcount_set(&view->refs, 1);
		qdx_tc_owner_get(owner);
		view->owner = owner;
		view->neutral = true;
		qdx_uses_lock();
		spin_lock_bh(&owner->data_lock);
		list_add_tail(&view->list, &owner->views);
		owner->pending = view;
		spin_unlock_bh(&owner->data_lock);
		qdx_uses_unlock();
		qdx_binding_prepare(owner->binding);
	}
	/* A present miniq with zero BPF programs is not a TCX program. */
	tcx = tcx_entry_fetch(owner->dev, owner->direction == QDX_TC_INGRESS);
	if (tcx && bpf_mprog_total(tcx)) {
		err = -EOPNOTSUPP;
		goto failed;
	}
	err = qdx_tc_tree_prepare(owner, view);
	if (err)
		goto failed;
	err = qdx_tc_replay_current(owner);
	if (err)
		goto failed;
	if (!view->members_ready) {
		err = qdx_tc_members_prepare(owner, view);
		if (err)
			goto failed;
		view->members_ready = true;
	}
	/* Native block getters precede cfg: no reverse block-lock dependency. */
	for (i = 0; i < view->nr_blocks; i++) {
		tcf_block_read_state(view->blocks[i].native, &state);
		if (state.active || state.sequence != view->blocks[i].sequence) {
			err = -EAGAIN;
			goto failed;
		}
	}
	mutex_lock(&owner->cfg);
	qdx_binding_prepare(owner->binding);
	qdx_uses_lock();
	spin_lock_bh(&owner->data_lock);
	publish = owner->pending == view && !view->invalid && !owner->closing &&
		tc_can_offload(owner->dev) && qdx_service_state(owner->service) == QDX_AVAILABLE &&
		(!owner->port || qdx_use_available_locked(&owner->port_use));
	/* An original IGS preparation can still be awaiting its actual command.
	 * Activation resumes it and checks the held target use. Only the final
	 * publication gate requires its completed available execution.
	 */
	if (!publish)
		view->invalid = true;
	spin_unlock_bh(&owner->data_lock);
	qdx_uses_unlock();
	if (publish) {
		if (view->tree)
			err = qdx_tc_tree_publish(view->tree);
		if (!err)
			err = qdx_tc_rules_activate(owner, view);
		if (err)
			publish = false;
	}
	qdx_uses_lock();
	spin_lock_bh(&owner->data_lock);
	current_valid = owner->pending == view && !view->invalid && !owner->closing &&
		tc_can_offload(owner->dev) && qdx_service_state(owner->service) == QDX_AVAILABLE &&
		(!owner->port || qdx_use_available_locked(&owner->port_use));
	for (i = 0; !err && current_valid && i < view->nr_rules; i++)
		if (view->rules[i]->igs && !qdx_tc_igs_available_locked(view->rules[i]->igs))
			current_valid = false;
	publish = publish && current_valid;
	if (publish) {
		view->available = true;
		owner->available = view;
		owner->pending = NULL;
		if (owner->port)
			qdx_use_publish_locked(&owner->port_use);
	} else if (!current_valid) {
		view->invalid = true;
	}
	spin_unlock_bh(&owner->data_lock);
	qdx_uses_unlock();
	mutex_unlock(&owner->cfg);
	if (!publish) {
		err = err ?: -EAGAIN;
		goto failed;
	}
	qdx_binding_available(owner->binding);
	if (owner->ifb)
		qdx_tc_ifb_progress(owner);
	qdx_tc_target_progress(owner); /* This actual unavailable-to-available transition only. */
	goto collect_stats;
failed:
	release_igs = false;
	mutex_lock(&owner->cfg);
	list_for_each_entry(rule, &owner->rules, list)
		if (rule->release_igs && rule->igs)
			release_igs = true;
	mutex_unlock(&owner->cfg);
	if (!release_igs && !view->invalid && owner->pending == view &&
	    (!view->tree || !view->tree->retiring) &&
	    (err == -EINPROGRESS || err == -ETIMEDOUT || err == -EAGAIN)) {
		/* Continue this original request/recipient/resource attempt. A real
		 * native completion invalidates it if policy changed in the meantime.
		 * Neither an ordinary timeout nor a late reply grants fresh admission.
		 */
		goto collect_stats;
	}
	if (err == -EAGAIN && view->tree && view->tree->retiring)
		WRITE_ONCE(owner->replay_needed, true); /* Existing native change still needs cleanup. */
	/* Successful callback counters are native obligations even when a later
	 * complete scope is unknown/overlapping. Return them synchronously now.
	 */
	qdx_tc_invalidate(owner, true, true);
	qdx_tc_remove_counts(owner);
	mutex_lock(&owner->cfg);
	qdx_tc_rules_retire(owner);
	if (view->tree)
		view->tree->retiring = true;
	mutex_unlock(&owner->cfg);
	/* An unresolved original request retains the pending attempt until its
	 * actual completion; a native/dependency event authorizes another read.
	 */
	prepare = false;
	goto retire_state;
collect_stats:
	mutex_lock(&owner->cfg);
	list_for_each_entry(tree, &owner->trees, list)
		list_for_each_entry(node, &tree->nodes, list)
			qdx_tc_stats_collect(node);
	mutex_unlock(&owner->cfg);
	if (owner->available && owner->available->available && !owner->available->invalid) {
		qdx_tc_owner_get(owner);
		if (mod_delayed_work(qdx_tc_wq, &owner->work, HZ))
			qdx_tc_owner_put(owner);
	}
retire_owner:
	if (closing) {
		struct qdx_tc_block *block, *next_block;
		bool empty;

		if (owner->binding) {
			qdx_binding_withdraw(owner->binding);
			owner->binding = NULL;
		}
		if (!owner->port && !conflict)
			qdx_tc_ifb_retire(owner);
		if (!owner->ifb) {
			list_for_each_entry_safe(block, next_block, &owner->blocks, list) {
				spin_lock_bh(&owner->data_lock);
				block->dead = true;
				block->native = NULL;
				list_del(&block->list);
				spin_unlock_bh(&owner->data_lock);
				if (refcount_dec_and_test(&block->refs)) {
					qdx_tc_owner_put(owner);
					kfree(block);
				}
			}
		}
		mutex_lock(&owner->cfg);
		empty = list_empty(&owner->trees) && list_empty(&owner->rules) &&
			list_empty(&owner->views) && list_empty(&owner->blocks) &&
			list_empty(&owner->associations) && !owner->ifb && !owner->ifb_state &&
			(owner->port || !owner->endpoint) &&
			!owner->root_allocation && !owner->assign.request &&
			!owner->unassign.request &&
			completion_done(&owner->assign.recipient_done) &&
			completion_done(&owner->unassign.recipient_done);
		mutex_unlock(&owner->cfg);
		if (empty && !list_empty(&owner->list)) {
			if (owner->port_use.linked)
				qdx_binding_use_put(&owner->port_use);
			if (refcount_read(&owner->port_use.deliveries))
				goto owner_pending;
			list_del_rcu(&owner->list);
			synchronize_srcu(&qdx_tc_owners_srcu);
			INIT_LIST_HEAD(&owner->list);
			wake_up_all(&qdx_tc_drained);
			qdx_tc_owner_put(owner); /* Actual index reference. */
		}
	}
owner_pending:
	/* A real resource/target transition can authorize replay inside this
	 * invocation's retirement. Local puts deliberately do not requeue work;
	 * preserve this actual event without polling unresolved resource holds.
	 */
	if (permission && !conflict && READ_ONCE(owner->replay_needed)) {
		qdx_tc_owner_get(owner);
		if (mod_delayed_work(qdx_tc_wq, &owner->work, 0))
			qdx_tc_owner_put(owner);
	}
	rtnl_unlock();
	qdx_tc_owner_put(owner); /* This queued invocation. */
}

static int qdx_tc_block_event(struct notifier_block *nb, unsigned long event, void *data)
{
	const struct tcf_block_event *change = data;
	struct qdx_tc_owner *owner;
	struct qdx_tc_view *view;
	struct qdx_tc_block *block;
	unsigned int i;
	bool affected;
	int index;

	if (event != TCF_BLOCK_CHANGE)
		return NOTIFY_DONE;
	index = srcu_read_lock(&qdx_tc_owners_srcu);
	list_for_each_entry_rcu(owner, &qdx_tc_owners, list,
			       srcu_read_lock_held(&qdx_tc_owners_srcu)) {
		affected = false;
		spin_lock_bh(&owner->data_lock);
		list_for_each_entry(view, &owner->views, list)
			for (i = 0; i < view->nr_blocks; i++)
				if (view->blocks[i].native == change->block &&
				    view->blocks[i].sequence != change->sequence)
					affected = true;
		list_for_each_entry(block, &owner->blocks, list)
			if (block->native == change->block && !block->dead)
				affected = true;
		if (affected)
			WRITE_ONCE(owner->replay_needed, true);
		spin_unlock_bh(&owner->data_lock);
		if (affected)
			qdx_tc_invalidate(owner, true, true);
	}
	srcu_read_unlock(&qdx_tc_owners_srcu, index);
	return NOTIFY_OK;
}

static int qdx_tc_action_event(struct net_device *dev, struct Qdisc *sch,
		void *private, enum tc_setup_type type, void *type_data, void *data,
		void (*cleanup)(struct flow_block_cb *cb))
{
	const struct flow_offload_action *change = data;
	struct qdx_tc_owner *owner;
	struct qdx_tc_view *view;
	struct qdx_tc_block *block;
	unsigned int i, j;
	bool affected;
	int index;

	/* Action dispatch puts its payload in data; type_data is the optional
	 * block offer and is NULL for both direct action calls and replay.
	 */
	if (type != TC_SETUP_ACT || !change || change->command != FLOW_ACT_CHANGE)
		return -EOPNOTSUPP;
	index = srcu_read_lock(&qdx_tc_owners_srcu);
	list_for_each_entry_rcu(owner, &qdx_tc_owners, list,
			       srcu_read_lock_held(&qdx_tc_owners_srcu)) {
		spin_lock_bh(&owner->data_lock);
		/* A pending native walk has not yet enumerated all its action uses.
		 * It cannot publish across an unobserved common action commit.
		 */
		affected = owner->pending != NULL;
		list_for_each_entry(view, &owner->views, list)
			for (i = 0; i < view->nr_rules; i++)
				for (j = 0; j < view->rules[i]->nr_actions; j++)
					if (view->rules[i]->actions[j].identity == change->cookie)
						affected = true;
		if (affected) {
			WRITE_ONCE(owner->replay_needed, true);
			list_for_each_entry(block, &owner->blocks, list)
				WRITE_ONCE(block->replay_needed, true);
		}
		spin_unlock_bh(&owner->data_lock);
		if (affected)
			qdx_tc_invalidate(owner, true, true);
	}
	srcu_read_unlock(&qdx_tc_owners_srcu, index);
	/* Identity observation contributes no standalone action offload count. */
	return -EOPNOTSUPP;
}

static int qdx_tc_netdev_event(struct notifier_block *nb, unsigned long event, void *data)
{
	struct net_device *dev = netdev_notifier_info_to_dev(data);
	struct qdx_tc_owner *owner;
	struct qdx_tc_block *block;
	u8 directions = NETDEV_TC_INGRESS | NETDEV_TC_EGRESS;

	ASSERT_RTNL();
	if (event == NETDEV_REGISTER) {
		if (READ_ONCE(qdx_tc_admitting))
			queue_work(qdx_tc_wq, &qdx_tc_scan_work);
		return NOTIFY_DONE;
	}
	if (event != NETDEV_CHANGE_TC && event != NETDEV_FEAT_CHANGE &&
	    event != NETDEV_CHANGEMTU && event != NETDEV_UNREGISTER)
		return NOTIFY_DONE;
	if (event == NETDEV_CHANGE_TC)
		directions = ((struct netdev_notifier_tc_info *)data)->directions;
	list_for_each_entry(owner, &qdx_tc_owners, list) {
		if (owner->dev != dev || !(directions & (owner->direction == QDX_TC_INGRESS ?
		    NETDEV_TC_INGRESS : NETDEV_TC_EGRESS)))
			continue;
		if (event == NETDEV_UNREGISTER) {
			WRITE_ONCE(owner->closing, true);
			WRITE_ONCE(owner->native_dead, true);
		}
		WRITE_ONCE(owner->replay_needed, true);
		if (event == NETDEV_FEAT_CHANGE) {
			list_for_each_entry(block, &owner->blocks, list)
				WRITE_ONCE(block->replay_needed, true);
		}
		qdx_tc_invalidate(owner, true, true);
	}
	return NOTIFY_OK;
}

static void qdx_tc_scan(struct work_struct *work)
{
	struct qdx_binding_key key = { .role = QDX_BINDING_TC_PORT };
	struct qdx_binding *port;
	struct qdx_tc_owner *owner;
	struct net_device *dev;
	struct net *net;

	rtnl_lock();
	if (!READ_ONCE(qdx_tc_admitting))
		goto out;
	for_each_net(net) {
		for_each_netdev(net, dev) {
			if (dev->rtnl_link_ops && !strcmp(dev->rtnl_link_ops->kind, "ifb")) {
				owner = qdx_tc_owner_create(dev, QDX_TC_EGRESS, NULL);
				if (!IS_ERR(owner))
					qdx_tc_schedule(owner);
				continue;
			}
			key.dev = dev;
			port = qdx_binding_lookup(&key);
			if (IS_ERR_OR_NULL(port))
				continue;
			qdx_tc_owner_create(dev, QDX_TC_INGRESS, port);
			qdx_tc_owner_create(dev, QDX_TC_EGRESS, port);
			qdx_binding_put(port);
		}
	}
out:
	rtnl_unlock();
}

static void qdx_tc_service_changed(void *private, enum qdx_service_kind kind,
				   enum qdx_availability state)
{
	struct qdx_tc_owner *owner;
	int index;

	if (kind != QDX_SERVICE_SHAPER && kind != QDX_SERVICE_IGS &&
	    kind != QDX_SERVICE_MATCH && kind != QDX_SERVICE_MIRROR &&
	    kind != QDX_SERVICE_ETHERNET)
		return;
	index = srcu_read_lock(&qdx_tc_owners_srcu);
	list_for_each_entry_rcu(owner, &qdx_tc_owners, list,
			       srcu_read_lock_held(&qdx_tc_owners_srcu)) {
		if (state == QDX_AVAILABLE)
			WRITE_ONCE(owner->replay_needed, true);
		else
			qdx_tc_invalidate(owner, true, false);
		qdx_tc_schedule(owner);
	}
	srcu_read_unlock(&qdx_tc_owners_srcu, index);
	if (state == QDX_AVAILABLE && READ_ONCE(qdx_tc_admitting))
		queue_work(qdx_tc_wq, &qdx_tc_scan_work);
}

static struct notifier_block qdx_tc_netdev_notifier = { .notifier_call = qdx_tc_netdev_event };
static struct notifier_block qdx_tc_block_notifier = { .notifier_call = qdx_tc_block_event };

static int __init qdx_tc_init(void)
{
	const struct qdx_binding_key key = { .role = QDX_BINDING_TC_PROVIDER };
	const struct qdx_owner registration = { .module = THIS_MODULE };
	int err;

	qdx_tc_wq = alloc_workqueue("qdx_tc", WQ_UNBOUND | WQ_MEM_RECLAIM, 0);
	if (!qdx_tc_wq)
		return -ENOMEM;
	INIT_WORK(&qdx_tc_scan_work, qdx_tc_scan);
	err = tcf_block_register_notifier(&qdx_tc_block_notifier);
	if (err)
		goto free_work;
	err = flow_indr_dev_register(qdx_tc_action_event, (void *)&qdx_tc_provider_ops);
	if (err)
		goto block;
	qdx_tc_listener = qdx_service_listen(&registration, qdx_tc_service_changed);
	if (IS_ERR(qdx_tc_listener)) {
		err = PTR_ERR(qdx_tc_listener);
		qdx_tc_listener = NULL;
		goto action;
	}
	err = register_netdevice_notifier(&qdx_tc_netdev_notifier);
	if (err)
		goto listener;
	qdx_tc_provider = qdx_binding_publish(&key, &registration, &qdx_tc_provider_ops);
	if (IS_ERR(qdx_tc_provider)) {
		err = PTR_ERR(qdx_tc_provider);
		qdx_tc_provider = NULL;
		goto netdev;
	}
	WRITE_ONCE(qdx_tc_admitting, true);
	qdx_binding_available(qdx_tc_provider);
	queue_work(qdx_tc_wq, &qdx_tc_scan_work);
	return 0;
netdev:
	unregister_netdevice_notifier(&qdx_tc_netdev_notifier);
listener:
	qdx_service_unlisten(qdx_tc_listener);
action:
	flow_indr_dev_unregister(qdx_tc_action_event, (void *)&qdx_tc_provider_ops, NULL);
block:
	tcf_block_unregister_notifier(&qdx_tc_block_notifier);
free_work:
	cancel_work_sync(&qdx_tc_scan_work);
	destroy_workqueue(qdx_tc_wq);
	return err;
}

static void __exit qdx_tc_exit(void)
{
	struct qdx_tc_owner *owner;

	WRITE_ONCE(qdx_tc_admitting, false);
	qdx_binding_withdraw(qdx_tc_provider);
	qdx_tc_provider = NULL;
	unregister_netdevice_notifier(&qdx_tc_netdev_notifier);
	tcf_block_unregister_notifier(&qdx_tc_block_notifier);
	flow_indr_dev_unregister(qdx_tc_action_event, (void *)&qdx_tc_provider_ops, NULL);
	qdx_service_unlisten(qdx_tc_listener);
	cancel_work_sync(&qdx_tc_scan_work);
	/* GOING rejects normal module pins. Only this entered exit function owns
	 * subsequent cleanup code; it cannot return before all actual callbacks,
	 * recipients, waits and workers which omit that optional pin have drained.
	 */
	WRITE_ONCE(qdx_tc_exit_draining, true);
	rtnl_lock();
	list_for_each_entry(owner, &qdx_tc_owners, list) {
		WRITE_ONCE(owner->closing, true);
		qdx_tc_invalidate(owner, true, true);
	}
	rtnl_unlock();
	for (;;) {
		bool empty;

		rtnl_lock();
		empty = list_empty(&qdx_tc_owners);
		rtnl_unlock();
		if (empty)
			break;
		wait_event_timeout(qdx_tc_drained, list_empty_careful(&qdx_tc_owners), HZ);
	}
	/* Includes already queued invocations of owners removed from the index. */
	destroy_workqueue(qdx_tc_wq);
	cleanup_srcu_struct(&qdx_tc_owners_srcu);
}

module_init(qdx_tc_init);
module_exit(qdx_tc_exit);
MODULE_DESCRIPTION("NSS native traffic control device stage");
MODULE_LICENSE("GPL");
