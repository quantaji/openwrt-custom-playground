// SPDX-License-Identifier: GPL-2.0-only
#include <linux/rtnetlink.h>
#include "flow.h"

bool qdx_flow_get(void *object)
{
	struct qdx_flow *flow = object;

	return refcount_inc_not_zero(&flow->refs);
}

void qdx_flow_put(void *object)
{
	struct qdx_flow *flow = object;

	if (!refcount_dec_and_test(&flow->refs))
		return;
	qdx_flow_offers_put(flow->offers);
	qdx_flow_domain_put(flow->domain);
	kfree(flow);
}

static void qdx_flow_consumer_put(void *object)
{
	struct qdx_flow *flow = object;

	/* A final old use delivery can make independent path storage reusable. */
	if (READ_ONCE(flow->invalid))
		qdx_flow_queue_retire(flow);
	qdx_flow_put(flow);
}

struct qdx_owner qdx_flow_owner(struct qdx_flow *flow)
{
	return (struct qdx_owner) { .module = THIS_MODULE, .object = flow,
		.get = qdx_flow_get, .put = qdx_flow_consumer_put };
}

void qdx_flow_queue_retire(struct qdx_flow *flow)
{
	if (current_work() == &flow->retire_work.work)
		return;
	qdx_flow_get(flow);
	if (mod_delayed_work(qdx_flow_wq, &flow->retire_work, 0))
		qdx_flow_put(flow);
}

void qdx_flow_queue_prepare(struct qdx_flow *flow)
{
	qdx_flow_get(flow);
	if (!queue_work(qdx_flow_wq, &flow->prepare_work))
		qdx_flow_put(flow);
}

struct qdx_flow *qdx_flow_find(struct qdx_flow_binding *binding,
			       const struct flow_offload *native)
{
	struct qdx_flow_domain *domain = binding->domain;
	struct qdx_flow *flow, *found = NULL;

	spin_lock_bh(&domain->index_lock);
	hash_for_each_possible(domain->associations, flow, association,
			       (unsigned long)native) {
		if (flow->binding == binding && flow->native == native) {
			qdx_flow_get(flow);
			found = flow;
			break;
		}
	}
	spin_unlock_bh(&domain->index_lock);
	return found;
}

static bool qdx_flow_command_get(void *object)
{
	struct qdx_flow_command *command = object;

	return qdx_flow_get(command->flow);
}

static void qdx_flow_command_put(void *object)
{
	struct qdx_flow_command *command = object;

	qdx_flow_put(command->flow);
}

static void qdx_flow_command_done(void *object, const struct qdx_result *result,
				  const void *payload, size_t length)
{
	struct qdx_flow_command *command = object;
	struct qdx_flow *flow = command->flow;

	spin_lock_bh(&flow->data_lock);
	/* The shared request serializes its result deliveries: UNKNOWN can
	 * settle later, but ACK/REJECTED cannot be overwritten by UNKNOWN.
	 */
	if (command->waiting || command->result.outcome == QDX_UNKNOWN) {
		command->result = *result;
		command->waiting = false;
	}
	spin_unlock_bh(&flow->data_lock);
	qdx_flow_queue_retire(flow);
}

static int qdx_flow_submit(struct qdx_flow_command *command, u32 opcode,
			   const void *payload, size_t length,
			   struct qdx_result *result)
{
	struct qdx_flow *flow = command->flow;
	struct qdx_command_recipient recipient = {
		.owner = { .module = THIS_MODULE, .object = command,
			.get = qdx_flow_command_get, .put = qdx_flow_command_put },
		.result = qdx_flow_command_done,
	};
	struct qdx_reply_bounds bounds = { .minimum = 0, .maximum = length,
		.capacity = QDX_FLOW_STATS_CAPACITY };
	int error;

	lockdep_assert_held(&flow->domain->cfg);
	spin_lock_bh(&flow->data_lock);
	command->waiting = true;
	command->result = (struct qdx_result) { .outcome = QDX_NOT_SUBMITTED };
	spin_unlock_bh(&flow->data_lock);
	command->request = qdx_command_submit(flow->collector->endpoint, opcode,
		payload, length, &bounds, &recipient);
	if (IS_ERR(command->request)) {
		error = PTR_ERR(command->request);
		command->request = NULL;
		spin_lock_bh(&flow->data_lock);
		command->waiting = false;
		command->result.error = error;
		spin_unlock_bh(&flow->data_lock);
		*result = (struct qdx_result) { .outcome = QDX_NOT_SUBMITTED,
			.error = error };
		return error;
	}
	return qdx_request_wait(command->request, jiffies + QDX_FLOW_COMMAND_TIMEOUT,
				result, NULL, 0);
}

int qdx_flow_withdraw(struct qdx_flow *flow)
{
	struct qdx_result created, deleted, result = {};
	enum qdx_flow_exposure exposure;
	bool ended, invalid;
	const void *key;
	size_t length;
	int error = 0;

	lockdep_assert_held(&flow->domain->cfg);
	spin_lock_bh(&flow->data_lock);
	flow->invalid = true;
	exposure = flow->exposure;
	created = flow->create.result;
	deleted = flow->destroy.result;
	ended = flow->execution_absent || flow->final_sync || flow->access_ended;
	invalid = flow->invalid || flow->native_dead;
	spin_unlock_bh(&flow->data_lock);
	if (exposure == QDX_FLOW_NONE || ended) {
		if (invalid)
			qdx_flow_queue_retire(flow);
		return 0;
	}
	if (!flow->retire_deadline)
		flow->retire_deadline = jiffies + 2 * QDX_FLOW_COMMAND_TIMEOUT;
	if (!flow->destroy.request &&
	    (created.outcome == QDX_ACK || exposure == QDX_FLOW_LIVE)) {
		if (flow->offers[0].input.family == AF_INET) {
			key = &flow->wire.ipv4.tuple;
			length = sizeof(flow->wire.ipv4.tuple);
		} else {
			key = &flow->wire.ipv6.tuple;
			length = sizeof(flow->wire.ipv6.tuple);
		}
		spin_lock_bh(&flow->data_lock);
		flow->exposure = QDX_FLOW_RETIRING;
		spin_unlock_bh(&flow->data_lock);
		qdx_flow_submit(&flow->destroy, QDX_NSS_IP_DESTROY, key, length, &result);
		deleted = result;
	}
	if (created.outcome == QDX_REJECTED) {
		spin_lock_bh(&flow->data_lock);
		flow->execution_absent = true;
		spin_unlock_bh(&flow->data_lock);
	} else if (deleted.outcome != QDX_ACK) {
		error = qdx_flow_paths_hold(flow);
		if (error)
			error = qdx_stop_execution(flow->collector->service, error);
	}
	qdx_flow_queue_retire(flow);
	return error;
}

int qdx_flow_invalidate(void *object, bool may_sleep)
{
	struct qdx_flow *flow = object;
	int error = 0;

	spin_lock_bh(&flow->data_lock);
	flow->invalid = true;
	spin_unlock_bh(&flow->data_lock);
	if (may_sleep) {
		mutex_lock(&flow->domain->cfg);
		error = qdx_flow_withdraw(flow);
		mutex_unlock(&flow->domain->cfg);
	} else {
		qdx_flow_queue_retire(flow);
	}
	return error;
}

static int qdx_flow_reserve_keys(struct qdx_flow *flow)
{
	struct qdx_flow_domain *domain = flow->domain;
	struct qdx_flow_alias *alias;
	u32 hash[2];
	int i;

	for (i = 0; i < 2; i++) {
		flow->aliases[i].key = flow->offers[i].input;
		flow->aliases[i].flow = flow;
		hash[i] = jhash(&flow->aliases[i].key, sizeof(alias->key), 0);
	}
	spin_lock_bh(&domain->index_lock);
	for (i = 0; i < 2; i++) {
		hash_for_each_possible(domain->wire, alias, node, hash[i]) {
			if (!memcmp(&alias->key, &flow->aliases[i].key, sizeof(alias->key))) {
				spin_unlock_bh(&domain->index_lock);
				return -EEXIST;
			}
		}
	}
	qdx_flow_get(flow);
	for (i = 0; i < 2; i++)
		hash_add(domain->wire, &flow->aliases[i].node, hash[i]);
	flow->keys_reserved = true;
	flow->sync_accepting = true;
	spin_unlock_bh(&domain->index_lock);
	return 0;
}

static void qdx_flow_offers_take(struct qdx_flow *flow,
				 struct qdx_flow_offer offers[2])
{
	int i;

	memcpy(flow->offers, offers, sizeof(flow->offers));
	memset(offers, 0, sizeof(flow->offers));
	for (i = 0; i < 2; i++) {
		struct qdx_flow_offer *offer = &flow->offers[i];

		offer->facts->match.dissector = &offer->match.dissector;
		offer->facts->match.key = &offer->match.key;
		offer->facts->match.mask = &offer->match.mask;
	}
}

int qdx_flow_replace(struct qdx_flow_binding *binding,
		     const struct nf_flow_offload_ctx *context)
{
	struct qdx_flow_domain *domain = binding->domain;
	struct qdx_flow_offer *offers;
	struct qdx_flow *flow;
	struct qdx_result result = {};
	bool valid, installed;
	int error;

	offers = kcalloc(2, sizeof(*offers), GFP_KERNEL);
	if (!offers)
		return -ENOMEM;
	error = qdx_flow_offers_parse(offers, context);
	if (error)
		goto free;
	mutex_lock(&domain->cfg);
	if (!binding->live || !domain->admitting) {
		error = -EOPNOTSUPP;
		goto unlock;
	}
	flow = qdx_flow_find(binding, context->flow);
	if (!flow) {
		struct nf_flow_hw_path *path = nf_flow_hw_path_get(context->flow);

		if (!path) {
			error = -EOPNOTSUPP;
			goto unlock;
		}
		flow = kzalloc(sizeof(*flow), GFP_KERNEL);
		if (!flow) {
			nf_flow_hw_path_put(path);
			error = -ENOMEM;
			goto unlock;
		}
		refcount_set(&flow->refs, 1); /* domain list/native lifetime */
		spin_lock_init(&flow->data_lock);
		INIT_WORK(&flow->prepare_work, qdx_flow_prepare_work);
		INIT_DELAYED_WORK(&flow->retire_work, qdx_flow_retire_work);
		flow->domain = domain;
		refcount_inc(&domain->refs);
		flow->binding = binding;
		refcount_inc(&binding->refs);
		flow->native = context->flow;
		flow->table = binding->table;
		flow->ct = context->ct;
		nf_conntrack_get(&flow->ct->ct_general);
		flow->native_path = path;
		flow->collector = &domain->collectors[offers[0].input.family == AF_INET6];
		flow->create.flow = flow;
		flow->destroy.flow = flow;
		flow->preparation = QDX_FLOW_PREPARING;
		qdx_flow_offers_take(flow, offers);
		spin_lock_bh(&domain->index_lock);
		list_add_tail(&flow->node, &domain->flows);
		hash_add(domain->associations, &flow->association, (unsigned long)flow->native);
		spin_unlock_bh(&domain->index_lock);
		qdx_flow_queue_prepare(flow);
		error = -EAGAIN;
		goto unlock;
	}
	if (!qdx_flow_offers_equal(flow->offers, offers)) {
		if (flow->exposure == QDX_FLOW_NONE && !flow->paths &&
		    flow->preparation != QDX_FLOW_PREPARING) {
			qdx_flow_offers_put(flow->offers);
			qdx_flow_offers_take(flow, offers);
			flow->preparation = QDX_FLOW_EMPTY;
		} else {
			qdx_flow_withdraw(flow);
			error = -EAGAIN;
			goto put;
		}
	}
	if (flow->preparation != QDX_FLOW_READY ||
	    flow->exposure == QDX_FLOW_RETIRING || flow->exposure == QDX_FLOW_UNKNOWN) {
		if (flow->exposure == QDX_FLOW_NONE && !flow->paths)
			qdx_flow_queue_prepare(flow);
		else if (READ_ONCE(flow->invalid))
			qdx_flow_queue_retire(flow);
		error = -EAGAIN;
		goto put;
	}
	error = qdx_flow_paths_nf_check(flow);
	if (error) {
		qdx_flow_withdraw(flow);
		goto put;
	}
	qdx_uses_lock();
	spin_lock_bh(&flow->data_lock);
	flow->counter = READ_ONCE(flow->table->flags) & NF_FLOWTABLE_COUNTER;
	valid = flow->native && !flow->invalid && !flow->final_sync &&
		!flow->access_ended && qdx_flow_paths_available(flow);
	installed = flow->exposure == QDX_FLOW_LIVE;
	spin_unlock_bh(&flow->data_lock);
	qdx_uses_unlock();
	if (!valid) {
		qdx_flow_withdraw(flow);
		error = -EAGAIN;
		goto put;
	}
	if (installed) {
		error = 0;
		goto put;
	}
	if (qdx_service_state(flow->collector->service) != QDX_AVAILABLE) {
		error = -EAGAIN;
		goto put;
	}
	error = qdx_flow_build(flow);
	if (error)
		goto put;
	error = qdx_flow_reserve_keys(flow);
	if (error)
		goto put;
	spin_lock_bh(&flow->data_lock);
	flow->exposure = QDX_FLOW_CREATING;
	spin_unlock_bh(&flow->data_lock);
	error = qdx_flow_submit(&flow->create, QDX_NSS_IP_CREATE, &flow->wire,
				flow->wire_length, &result);
	if (result.outcome == QDX_ACK) {
		qdx_uses_lock();
		spin_lock_bh(&flow->data_lock);
		valid = flow->native && !flow->invalid && !flow->final_sync &&
			!flow->access_ended && qdx_flow_paths_available(flow);
		if (valid)
			flow->exposure = QDX_FLOW_LIVE;
		spin_unlock_bh(&flow->data_lock);
		qdx_uses_unlock();
		if (valid) {
			error = 0;
			goto put;
		}
	} else if (result.outcome == QDX_NOT_SUBMITTED || result.outcome == QDX_REJECTED) {
		spin_lock_bh(&flow->data_lock);
		flow->execution_absent = true;
		spin_unlock_bh(&flow->data_lock);
	} else {
		spin_lock_bh(&flow->data_lock);
		flow->exposure = QDX_FLOW_UNKNOWN;
		spin_unlock_bh(&flow->data_lock);
	}
	qdx_flow_withdraw(flow);
	error = error ?: -EAGAIN;
put:
	qdx_flow_put(flow);
unlock:
	mutex_unlock(&domain->cfg);
	qdx_flow_offers_put(offers);
free:
	kfree(offers);
	return error;
}

void qdx_flow_prepare_work(struct work_struct *work)
{
	struct qdx_flow *flow = container_of(work, struct qdx_flow, prepare_work);
	struct qdx_flow_domain *domain = flow->domain;
	int error;
	bool valid;

	mutex_lock(&domain->cfg);
	if (flow->exposure != QDX_FLOW_NONE)
		goto unlock;
	if (flow->native_dead || !flow->binding || !flow->binding->live) {
		flow->preparation = QDX_FLOW_UNAVAILABLE;
		qdx_flow_queue_retire(flow);
		goto unlock;
	}
	if (flow->paths || flow->create.request || flow->destroy.request || flow->keys_reserved) {
		if (flow->invalid)
			qdx_flow_queue_retire(flow);
		goto unlock;
	}
	spin_lock_bh(&flow->data_lock);
	flow->invalid = false;
	flow->preparation = QDX_FLOW_PREPARING;
	spin_unlock_bh(&flow->data_lock);
	mutex_unlock(&domain->cfg);
	rtnl_lock();
	error = nf_flow_hw_path_validate(flow->native_path);
	if (error == -ESTALE) {
		spin_lock_bh(&flow->data_lock);
		if (flow->native)
			flow_offload_teardown(flow->native);
		spin_unlock_bh(&flow->data_lock);
	}
	if (!error)
		error = qdx_flow_paths_prepare(flow);
	rtnl_unlock();
	mutex_lock(&domain->cfg);
	qdx_uses_lock();
	spin_lock_bh(&flow->data_lock);
	valid = !error && !flow->native_dead && !flow->invalid &&
		qdx_flow_paths_available(flow);
	flow->preparation = valid ? QDX_FLOW_READY : QDX_FLOW_UNAVAILABLE;
	if (!valid)
		flow->invalid = true;
	spin_unlock_bh(&flow->data_lock);
	qdx_uses_unlock();
	if (!valid)
		qdx_flow_queue_retire(flow);
unlock:
	mutex_unlock(&domain->cfg);
	qdx_flow_put(flow);
}

void qdx_flow_destroy(struct qdx_flow_binding *binding,
		      const struct nf_flow_offload_ctx *context)
{
	struct qdx_flow_domain *domain = binding->domain;
	struct qdx_flow *flow;

	if (!context)
		return;
	mutex_lock(&domain->cfg);
	flow = qdx_flow_find(binding, context->flow);
	if (!flow)
		goto out;
	spin_lock_bh(&flow->data_lock);
	flow->counter = READ_ONCE(flow->table->flags) & NF_FLOWTABLE_COUNTER;
	flow->native = NULL;
	flow->table = NULL;
	flow->native_dead = true;
	flow->invalid = true;
	spin_unlock_bh(&flow->data_lock);
	spin_lock_bh(&domain->index_lock);
	hash_del(&flow->association);
	spin_unlock_bh(&domain->index_lock);
	qdx_flow_withdraw(flow);
	qdx_flow_queue_retire(flow);
	qdx_flow_put(flow);
out:
	mutex_unlock(&domain->cfg);
}

void qdx_flow_retire_work(struct work_struct *work)
{
	struct qdx_flow *flow = container_of(to_delayed_work(work), struct qdx_flow, retire_work);
	struct qdx_flow_domain *domain = flow->domain;
	struct qdx_flow_binding *binding;
	struct nf_flow_hw_path *path;
	struct nf_conn *ct;
	bool ended, drained, reserved, dead;
	int i;

	mutex_lock(&domain->cfg);
	if (flow->native_dead && !flow->ct)
		goto unlock;
	spin_lock_bh(&flow->data_lock);
	if (!flow->native_dead && !flow->invalid && !flow->final_sync &&
	    !flow->access_ended && (flow->exposure == QDX_FLOW_NONE ||
		flow->exposure == QDX_FLOW_CREATING || flow->exposure == QDX_FLOW_LIVE)) {
		spin_unlock_bh(&flow->data_lock);
		qdx_flow_paths_account(flow);
		goto unlock;
	}
	if (flow->exposure == QDX_FLOW_NONE && flow->preparation == QDX_FLOW_PREPARING) {
		spin_unlock_bh(&flow->data_lock);
		goto unlock;
	}
	spin_unlock_bh(&flow->data_lock);
	qdx_flow_withdraw(flow);
	spin_lock_bh(&flow->data_lock);
	if (qdx_service_access_ended(flow->collector->service))
		flow->access_ended = true;
	if (!flow->create.waiting && flow->create.result.outcome == QDX_REJECTED)
		flow->execution_absent = true;
	ended = flow->exposure == QDX_FLOW_NONE || flow->execution_absent ||
		flow->final_sync || flow->access_ended;
	drained = !flow->create.waiting && !flow->destroy.waiting &&
		(flow->create.result.outcome != QDX_UNKNOWN || flow->create.result.exposure_ended) &&
		(flow->destroy.result.outcome != QDX_UNKNOWN || flow->destroy.result.exposure_ended);
	spin_unlock_bh(&flow->data_lock);
	if (!ended) {
		if (flow->retire_deadline && time_after_eq(jiffies, flow->retire_deadline)) {
			qdx_stop_execution(flow->collector->service, -ETIMEDOUT);
		} else if (flow->retire_deadline) {
			qdx_flow_get(flow);
			if (mod_delayed_work(qdx_flow_wq, &flow->retire_work,
					     flow->retire_deadline - jiffies))
				qdx_flow_put(flow);
		}
		goto unlock;
	}
	if (!drained)
		goto unlock;
	if (flow->retiring_query) {
		spin_lock_bh(&flow->retiring_query->lock);
		drained = flow->retiring_query->drained;
		spin_unlock_bh(&flow->retiring_query->lock);
		if (!drained)
			goto unlock;
	}
	spin_lock_bh(&domain->index_lock);
	flow->sync_accepting = false;
	drained = !flow->active_receivers;
	spin_unlock_bh(&domain->index_lock);
	if (!drained)
		goto unlock;
	qdx_flow_paths_account(flow);
	if (flow->native_dead)
		qdx_flow_account_retired(flow);
	if (!qdx_flow_paths_release(flow))
		goto unlock;
	qdx_request_put(flow->create.request);
	qdx_request_put(flow->destroy.request);
	flow->create.request = NULL;
	flow->destroy.request = NULL;
	qdx_flow_query_put(flow->retiring_query);
	flow->retiring_query = NULL;
	spin_lock_bh(&domain->index_lock);
	reserved = flow->keys_reserved;
	if (reserved) {
		for (i = 0; i < 2; i++)
			hash_del(&flow->aliases[i].node);
		flow->keys_reserved = false;
	}
	spin_unlock_bh(&domain->index_lock);
	memset(&flow->wire, 0, sizeof(flow->wire));
	memset(flow->forward, 0, sizeof(flow->forward));
	flow->wire_length = 0;
	flow->retire_deadline = 0;
	spin_lock_bh(&flow->data_lock);
	memset(&flow->create.result, 0, sizeof(flow->create.result));
	memset(&flow->destroy.result, 0, sizeof(flow->destroy.result));
	flow->create.waiting = false;
	flow->destroy.waiting = false;
	flow->final_sync = false;
	flow->access_ended = false;
	flow->execution_absent = false;
	flow->exposure = QDX_FLOW_NONE;
	flow->preparation = QDX_FLOW_EMPTY;
	flow->invalid = true;
	dead = flow->native_dead;
	spin_unlock_bh(&flow->data_lock);
	if (reserved)
		qdx_flow_put(flow);
	if (dead) {
		ct = flow->ct;
		path = flow->native_path;
		binding = flow->binding;
		flow->ct = NULL;
		flow->native_path = NULL;
		flow->binding = NULL;
		spin_lock_bh(&domain->index_lock);
		list_del(&flow->node);
		spin_unlock_bh(&domain->index_lock);
		mutex_unlock(&domain->cfg);
		nf_ct_put(ct);
		nf_flow_hw_path_put(path);
		qdx_flow_binding_put(binding);
		qdx_flow_domain_retire(domain);
		qdx_flow_put(flow); /* original domain-list lifetime */
		qdx_flow_put(flow); /* this work */
		return;
	}
	/* A native refresh will request the next preparation/CREATE. Do not spin
	 * on a currently unsupported path by rebuilding from retirement forever.
	 */
unlock:
	mutex_unlock(&domain->cfg);
	qdx_flow_put(flow);
}
