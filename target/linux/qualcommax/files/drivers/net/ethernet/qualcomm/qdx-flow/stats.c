// SPDX-License-Identifier: GPL-2.0-only
#include <linux/overflow.h>
#include <linux/unaligned.h>
#include <net/netfilter/nf_conntrack_acct.h>
#include "flow.h"

static bool qdx_flow_query_get(void *object)
{
	struct qdx_flow_query *query = object;

	return refcount_inc_not_zero(&query->refs);
}

void qdx_flow_query_put(struct qdx_flow_query *query)
{
	if (!query || !refcount_dec_and_test(&query->refs))
		return;
	qdx_flow_domain_put(query->collector->domain);
	kfree(query);
}

static void qdx_flow_query_owner_put(void *object)
{
	qdx_flow_query_put(object);
}

void qdx_flow_sync_receive(struct qdx_flow_collector *collector,
			   const void *payload, size_t length)
{
	struct qdx_flow_domain *domain = collector->domain;
	struct qdx_flow_side_delta delta[2] = {};
	struct qdx_flow_query *query = NULL;
	struct qdx_flow_key key = {};
	struct qdx_flow_alias *alias;
	struct qdx_flow *flow = NULL;
	u32 reason, hash;
	bool final, duplicate = false;
	int i;

	key.family = collector->family;
	if (key.family == AF_INET) {
		const struct qdx_nss_ipv4_sync *sync = payload;

		if (length < sizeof(*sync))
			return;
		key.protocol = sync->protocol;
		key.source.s6_addr32[0] = htonl(le32_to_cpu(sync->flow_ip));
		key.destination.s6_addr32[0] = htonl(le32_to_cpu(sync->return_ip));
		if (le32_to_cpu(sync->flow_ident) > U16_MAX ||
		    le32_to_cpu(sync->return_ident) > U16_MAX)
			return;
		key.source_port = htons(le32_to_cpu(sync->flow_ident));
		key.destination_port = htons(le32_to_cpu(sync->return_ident));
		delta[0].rx.packets = le32_to_cpu(sync->flow_rx_packets);
		delta[0].rx.bytes = le32_to_cpu(sync->flow_rx_bytes);
		delta[0].tx.packets = le32_to_cpu(sync->flow_tx_packets);
		delta[0].tx.bytes = le32_to_cpu(sync->flow_tx_bytes);
		delta[1].rx.packets = le32_to_cpu(sync->return_rx_packets);
		delta[1].rx.bytes = le32_to_cpu(sync->return_rx_bytes);
		delta[1].tx.packets = le32_to_cpu(sync->return_tx_packets);
		delta[1].tx.bytes = le32_to_cpu(sync->return_tx_bytes);
		reason = le32_to_cpu(sync->reason);
	} else {
		const struct qdx_nss_ipv6_sync *sync = payload;

		if (length < sizeof(*sync))
			return;
		key.protocol = sync->protocol;
		for (i = 0; i < 4; i++) {
			key.source.s6_addr32[i] = htonl(le32_to_cpu(sync->flow_ip[i]));
			key.destination.s6_addr32[i] = htonl(le32_to_cpu(sync->return_ip[i]));
		}
		if (le32_to_cpu(sync->flow_ident) > U16_MAX ||
		    le32_to_cpu(sync->return_ident) > U16_MAX)
			return;
		key.source_port = htons(le32_to_cpu(sync->flow_ident));
		key.destination_port = htons(le32_to_cpu(sync->return_ident));
		delta[0].rx.packets = le32_to_cpu(sync->flow_rx_packets);
		delta[0].rx.bytes = le32_to_cpu(sync->flow_rx_bytes);
		delta[0].tx.packets = le32_to_cpu(sync->flow_tx_packets);
		delta[0].tx.bytes = le32_to_cpu(sync->flow_tx_bytes);
		delta[1].rx.packets = le32_to_cpu(sync->return_rx_packets);
		delta[1].rx.bytes = le32_to_cpu(sync->return_rx_bytes);
		delta[1].tx.packets = le32_to_cpu(sync->return_tx_packets);
		delta[1].tx.bytes = le32_to_cpu(sync->return_tx_bytes);
		reason = le32_to_cpu(sync->reason);
	}
	if ((key.protocol != IPPROTO_TCP && key.protocol != IPPROTO_UDP) ||
	    reason > QDX_NSS_SYNC_DESTROY)
		return;
	hash = jhash(&key, sizeof(key), 0);
	spin_lock_bh(&domain->index_lock);
	hash_for_each_possible(domain->wire, alias, node, hash) {
		/* A connection sync names its original control tuple. The reverse
		 * alias reserves packet collisions but is not another statistics key.
		 */
		if (alias != &alias->flow->aliases[0] ||
		    memcmp(&alias->key, &key, sizeof(key)) ||
		    !alias->flow->sync_accepting)
			continue;
		flow = alias->flow;
		qdx_flow_get(flow);
		flow->active_receivers++;
		break;
	}
	spin_unlock_bh(&domain->index_lock);
	if (!flow)
		return;

	final = reason != QDX_NSS_SYNC_STATS;
	if (final) {
		spin_lock_bh(&collector->lock);
		if (collector->query && qdx_flow_query_get(collector->query))
			query = collector->query;
		spin_unlock_bh(&collector->lock);
	}
	spin_lock_bh(&flow->data_lock);
	if (final && flow->final_sync) {
		duplicate = true;
	} else {
		if (final) {
			flow->final_sync = true;
			flow->invalid = true;
			flow->retiring_query = query;
			query = NULL;
		}
		for (i = 0; i < 2; i++) {
			flow->pending_ip[i].packets += delta[i].rx.packets;
			flow->pending_ip[i].bytes += delta[i].rx.bytes;
			flow->pending_ppp[i].rx.packets += delta[i].rx.packets;
			flow->pending_ppp[i].rx.bytes += delta[i].rx.bytes;
			flow->pending_ppp[i].tx.packets += delta[i].tx.packets;
			flow->pending_ppp[i].tx.bytes += delta[i].tx.bytes;
		}
		if (delta[0].rx.packets || delta[1].rx.packets)
			flow->last_activity = jiffies;
		if (final && reason != QDX_NSS_SYNC_DESTROY && flow->native)
			flow_offload_teardown(flow->native);
	}
	spin_unlock_bh(&flow->data_lock);
	qdx_flow_query_put(query);
	spin_lock_bh(&domain->index_lock);
	flow->active_receivers--;
	spin_unlock_bh(&domain->index_lock);
	/* Even a duplicate final receiver may be the last admitted old reader. */
	if (!duplicate || final)
		qdx_flow_queue_retire(flow);
	qdx_flow_put(flow);
}

static void qdx_flow_query_done(void *object, const struct qdx_result *result,
				const void *payload, size_t length)
{
	struct qdx_flow_query *query = object;

	spin_lock_bh(&query->lock);
	query->result = *result;
	query->length = min(length, sizeof(query->payload));
	if (query->length && payload)
		memcpy(query->payload, payload, query->length);
	query->done = true;
	/* Publish the wake before a timer worker can consume and retire this
	 * result. Nothing after releasing the lock may queue an old collector.
	 */
	mod_delayed_work(qdx_flow_wq, &query->collector->work, 0);
	spin_unlock_bh(&query->lock);
}

static void qdx_flow_collector_work(struct work_struct *work)
{
	struct qdx_flow_collector *collector = container_of(to_delayed_work(work),
					struct qdx_flow_collector, work);
	struct qdx_reply_bounds bounds = { .minimum = sizeof(struct qdx_nss_sync_many),
		.maximum = QDX_FLOW_STATS_CAPACITY, .capacity = QDX_FLOW_STATS_CAPACITY };
	struct qdx_flow_query *query;
	struct qdx_command_recipient recipient;
	struct qdx_nss_sync_many request = {};
	struct qdx_flow *flow;
	bool done, settled, waiting;
	bool cleanup_pin;

	if (!READ_ONCE(collector->service))
		return;

	spin_lock_bh(&collector->lock);
	query = collector->query;
	spin_unlock_bh(&collector->lock);
	if (query) {
		spin_lock_bh(&query->lock);
		done = query->done;
		settled = done && (query->result.outcome != QDX_UNKNOWN ||
				  query->result.exposure_ended);
		spin_unlock_bh(&query->lock);
		if (!settled) {
			if (!query->cancelled && time_after_eq(jiffies, query->deadline)) {
				query->cancelled = true;
				qdx_request_cancel(query->request);
			}
			return;
		}
		if (done && query->result.outcome == QDX_ACK) {
			const struct qdx_nss_sync_many *header = (void *)query->payload;
			size_t entry_size = collector->family == AF_INET ?
				sizeof(struct qdx_nss_ipv4_sync) : sizeof(struct qdx_nss_ipv6_sync);
			unsigned int count, i;

			/* D06: 11.4 declares the eight-byte header even with appended
			 * records. Actual received extent bounds their population.
			 */
			if (query->length >= sizeof(*header) &&
			    query->result.declared_len >= sizeof(*header) &&
			    query->result.declared_len <= query->result.received_len) {
				count = le16_to_cpu(header->count);
				if (count <= (query->length - sizeof(*header)) / entry_size) {
					for (i = 0; i < count; i++)
						qdx_flow_sync_receive(collector,
							query->payload + sizeof(*header) + i * entry_size,
							entry_size);
					collector->next = le16_to_cpu(header->next);
				} else {
					collector->next = 0;
				}
			} else {
				collector->next = 0;
			}
		} else {
			collector->next = 0;
		}
		spin_lock_bh(&query->lock);
		query->drained = true;
		spin_unlock_bh(&query->lock);
		spin_lock_bh(&collector->lock);
		collector->query = NULL;
		spin_unlock_bh(&collector->lock);
		/* Wake only records retaining this exact result. A final receiver
		 * that installs its reference after this scan queues its own work.
		 */
		mutex_lock(&collector->domain->cfg);
		list_for_each_entry(flow, &collector->domain->flows, node) {
			spin_lock_bh(&flow->data_lock);
			waiting = flow->retiring_query == query;
			spin_unlock_bh(&flow->data_lock);
			if (waiting)
				qdx_flow_queue_retire(flow);
		}
		mutex_unlock(&collector->domain->cfg);
		qdx_request_put(query->request);
		qdx_flow_query_put(query);
		if (!collector->next && !smp_load_acquire(&collector->stopping) &&
		    !qdx_service_access_ended(collector->service)) {
			mod_delayed_work(qdx_flow_wq, &collector->work, QDX_FLOW_STATS_INTERVAL);
			return;
		}
	}
	if (smp_load_acquire(&collector->stopping)) {
		if (qdx_endpoint_receive_unregister(collector->receiver)) {
			/* The close is already visible in the domain registry. Re-read
			 * after the failed drain to cover a crossing access-end event.
			 */
			if (qdx_service_access_ended(collector->service))
				mod_delayed_work(qdx_flow_wq, &collector->work, 0);
			return;
		}
		collector->receiver = NULL;
		qdx_endpoint_put(collector->endpoint);
		collector->endpoint = NULL;
		qdx_service_put(collector->service);
		WRITE_ONCE(collector->service, NULL);
		cleanup_pin = collector->cleanup_pin;
		collector->cleanup_pin = false;
		complete_all(&collector->stopped);
		qdx_flow_domain_cleanup(collector->domain);
		/* A crossing service callback may have queued one last rerun before
		 * service became NULL. The registry can no longer produce another.
		 */
		cancel_delayed_work(&collector->work);
		qdx_flow_domain_put(collector->domain); /* collector's real storage lifetime */
		/* module_exit synchronizes these same works before freeing text. */
		if (cleanup_pin)
			module_put(THIS_MODULE);
		return;
	}
	if (qdx_service_access_ended(collector->service))
		return;
	if (qdx_service_state(collector->service) != QDX_AVAILABLE)
		return;
	query = kzalloc(sizeof(*query), GFP_KERNEL);
	if (!query) {
		mod_delayed_work(qdx_flow_wq, &collector->work, QDX_FLOW_STATS_INTERVAL);
		return;
	}
	refcount_set(&query->refs, 1);
	spin_lock_init(&query->lock);
	query->collector = collector;
	query->deadline = jiffies + QDX_FLOW_COMMAND_TIMEOUT;
	refcount_inc(&collector->domain->refs);
	recipient.owner = (struct qdx_owner) { .module = THIS_MODULE, .object = query,
		.get = qdx_flow_query_get, .put = qdx_flow_query_owner_put };
	recipient.result = qdx_flow_query_done;
	request.index = cpu_to_le16(collector->next);
	request.size = cpu_to_le16(QDX_FLOW_STATS_CAPACITY);
	spin_lock_bh(&collector->lock);
	collector->query = query;
	spin_unlock_bh(&collector->lock);
	/* Arm before publication. A fast original callback can only bring this
	 * work forward; a later submit-return path cannot postpone that result.
	 */
	mod_delayed_work(qdx_flow_wq, &collector->work, QDX_FLOW_COMMAND_TIMEOUT);
	query->request = qdx_command_submit(collector->endpoint, QDX_NSS_IP_SYNC_MANY,
			&request, sizeof(request), &bounds, &recipient);
	if (IS_ERR(query->request)) {
		spin_lock_bh(&collector->lock);
		collector->query = NULL;
		spin_unlock_bh(&collector->lock);
		spin_lock_bh(&query->lock);
		query->drained = true;
		spin_unlock_bh(&query->lock);
		mutex_lock(&collector->domain->cfg);
		list_for_each_entry(flow, &collector->domain->flows, node) {
			spin_lock_bh(&flow->data_lock);
			waiting = flow->retiring_query == query;
			spin_unlock_bh(&flow->data_lock);
			if (waiting)
				qdx_flow_queue_retire(flow);
		}
		mutex_unlock(&collector->domain->cfg);
		qdx_flow_query_put(query);
		mod_delayed_work(qdx_flow_wq, &collector->work, QDX_FLOW_STATS_INTERVAL);
	}
}

static bool qdx_flow_collector_get(void *object)
{
	struct qdx_flow_collector *collector = object;

	return refcount_inc_not_zero(&collector->domain->refs);
}

static void qdx_flow_collector_put(void *object)
{
	struct qdx_flow_collector *collector = object;

	qdx_flow_domain_put(collector->domain);
}

static void qdx_flow_sync_message(void *object, u32 opcode, u32 response,
				 u32 error, const void *payload,
				 size_t received, size_t declared)
{
	struct qdx_flow_collector *collector = object;
	size_t expected = collector->family == AF_INET ?
		sizeof(struct qdx_nss_ipv4_sync) : sizeof(struct qdx_nss_ipv6_sync);

	if (opcode != QDX_NSS_IP_SYNC || response != QDX_NSS_RESPONSE_NOTIFY ||
	    declared < expected || received < declared)
		return;
	qdx_flow_sync_receive(collector, payload, received);
}

static const struct qdx_receive_ops qdx_flow_receive_ops = {
	.message = qdx_flow_sync_message,
};

int qdx_flow_collector_start(struct qdx_flow_domain *domain, unsigned int index)
{
	struct qdx_flow_collector *collector = &domain->collectors[index];
	struct qdx_owner owner = { .module = THIS_MODULE, .object = collector,
		.get = qdx_flow_collector_get, .put = qdx_flow_collector_put };
	int error;

	collector->domain = domain;
	collector->family = index ? AF_INET6 : AF_INET;
	spin_lock_init(&collector->lock);
	INIT_DELAYED_WORK(&collector->work, qdx_flow_collector_work);
	collector->service = qdx_service_get(domain->dev,
		index ? QDX_SERVICE_IPV6 : QDX_SERVICE_IPV4);
	if (IS_ERR(collector->service)) {
		error = PTR_ERR(collector->service);
		collector->service = NULL;
		return error;
	}
	collector->endpoint = qdx_endpoint_get(collector->service, NULL);
	if (IS_ERR(collector->endpoint)) {
		error = PTR_ERR(collector->endpoint);
		goto put_service;
	}
	collector->receiver = qdx_endpoint_receive_register(collector->endpoint,
		QDX_RECEIVE_MESSAGE, &owner, &qdx_flow_receive_ops);
	if (IS_ERR(collector->receiver)) {
		error = PTR_ERR(collector->receiver);
		goto put_endpoint;
	}
	refcount_inc(&domain->refs);
	reinit_completion(&collector->stopped);
	mod_delayed_work(qdx_flow_wq, &collector->work, QDX_FLOW_STATS_INTERVAL);
	return 0;
put_endpoint:
	qdx_endpoint_put(collector->endpoint);
	collector->endpoint = NULL;
put_service:
	qdx_service_put(collector->service);
	collector->service = NULL;
	return error;
}

void qdx_flow_collector_stop(struct qdx_flow_collector *collector)
{
	bool stop;

	if (!READ_ONCE(collector->service))
		return;
	spin_lock_bh(&collector->lock);
	stop = !collector->stopping;
	if (stop) {
		collector->cleanup_pin = try_module_get(THIS_MODULE);
		smp_store_release(&collector->stopping, true);
	}
	spin_unlock_bh(&collector->lock);
	if (!stop)
		return;
	cancel_delayed_work_sync(&collector->work);
	if (!READ_ONCE(collector->service))
		return;
	/* An exposed query retains its own result and domain. Ordinary module
	 * detachment cannot turn that ownership into a drained result.
	 */
	if (collector->query)
		qdx_request_cancel(collector->query->request);
	mod_delayed_work(qdx_flow_wq, &collector->work, 0);
}

void qdx_flow_stats(struct qdx_flow_binding *binding,
		    const struct nf_flow_offload_ctx *context, struct flow_stats *stats)
{
	struct qdx_flow_delta delta = {};
	struct qdx_flow *flow;
	unsigned long activity = 0;

	if (!context || context->direction > 1)
		return;
	mutex_lock(&binding->domain->cfg);
	flow = qdx_flow_find(binding, context->flow);
	if (!flow)
		goto out;
	spin_lock_bh(&flow->data_lock);
	if (flow->native) {
		flow->counter = READ_ONCE(flow->table->flags) & NF_FLOWTABLE_COUNTER;
		delta = flow->pending_ip[context->direction];
		memset(&flow->pending_ip[context->direction], 0, sizeof(delta));
		activity = flow->last_activity;
	}
	spin_unlock_bh(&flow->data_lock);
	flow_stats_update(stats, delta.bytes, delta.packets, 0, activity,
			  FLOW_ACTION_HW_STATS_DELAYED);
	qdx_flow_put(flow);
out:
	mutex_unlock(&binding->domain->cfg);
}

void qdx_flow_account_retired(struct qdx_flow *flow)
{
	struct qdx_flow_delta delta[2];
	bool counter;
	int i;

	spin_lock_bh(&flow->data_lock);
	memcpy(delta, flow->pending_ip, sizeof(delta));
	memset(flow->pending_ip, 0, sizeof(flow->pending_ip));
	counter = flow->counter;
	spin_unlock_bh(&flow->data_lock);
	if (!counter)
		return;
	for (i = 0; i < 2; i++) {
		while (delta[i].packets || delta[i].bytes) {
			u32 packets = min_t(u64, delta[i].packets, U32_MAX);
			u32 bytes = min_t(u64, delta[i].bytes, U32_MAX);

			nf_ct_acct_add(flow->ct, i, packets, bytes);
			delta[i].packets -= packets;
			delta[i].bytes -= bytes;
		}
	}
}
