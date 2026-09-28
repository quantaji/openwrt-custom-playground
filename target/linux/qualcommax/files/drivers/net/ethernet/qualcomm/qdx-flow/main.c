// SPDX-License-Identifier: GPL-2.0-only
#include <linux/module.h>
#include <linux/qdx/flow.h>
#include <net/pkt_cls.h>
#include "flow.h"

DEFINE_MUTEX(qdx_flow_domains_lock);
LIST_HEAD(qdx_flow_domains);
struct workqueue_struct *qdx_flow_wq;
static struct qdx_binding *qdx_flow_provider;
static struct qdx_listener *qdx_flow_listener;

void qdx_flow_domain_put(struct qdx_flow_domain *domain)
{
	if (!refcount_dec_and_test(&domain->refs))
		return;
	dev_put(domain->dev);
	kfree(domain);
}

void qdx_flow_binding_put(struct qdx_flow_binding *binding)
{
	if (!refcount_dec_and_test(&binding->refs))
		return;
	qdx_binding_put(binding->native);
	qdx_flow_domain_put(binding->domain);
	kfree(binding);
}

void qdx_flow_domain_cleanup(struct qdx_flow_domain *domain)
{
	bool remove;

	mutex_lock(&qdx_flow_domains_lock);
	mutex_lock(&domain->cfg);
	remove = domain->closing && list_empty(&domain->bindings) &&
		list_empty(&domain->flows) && !READ_ONCE(domain->collectors[0].service) &&
		!READ_ONCE(domain->collectors[1].service) && !list_empty(&domain->node);
	if (remove)
		list_del_init(&domain->node);
	mutex_unlock(&domain->cfg);
	mutex_unlock(&qdx_flow_domains_lock);
	if (remove)
		qdx_flow_domain_put(domain); /* registry's real device lifetime */
}

void qdx_flow_domain_retire(struct qdx_flow_domain *domain)
{
	bool retire;

	mutex_lock(&domain->cfg);
	retire = domain->closing && list_empty(&domain->bindings) &&
		list_empty(&domain->flows);
	mutex_unlock(&domain->cfg);
	if (!retire)
		return;
	qdx_flow_collector_stop(&domain->collectors[0]);
	qdx_flow_collector_stop(&domain->collectors[1]);
	qdx_flow_domain_cleanup(domain);
}

static int qdx_flow_bind(void *provider, struct qdx_binding *native_binding,
			 struct nf_flowtable *table, void **attachment)
{
	struct net_device *dev = qdx_binding_dev(native_binding);
	struct qdx_flow_domain *domain, *found = NULL;
	struct qdx_flow_binding *binding;
	bool retire_domain = false;
	int error;

	if (!dev || !table)
		return -EOPNOTSUPP;
	binding = kzalloc(sizeof(*binding), GFP_KERNEL);
	if (!binding)
		return -ENOMEM;
	if (!qdx_binding_hold(native_binding)) {
		kfree(binding);
		return -ENOENT;
	}
	mutex_lock(&qdx_flow_domains_lock);
	list_for_each_entry(domain, &qdx_flow_domains, node) {
		if (domain->dev == dev) {
			found = domain;
			break;
		}
	}
	if (!found) {
		domain = kzalloc(sizeof(*domain), GFP_KERNEL);
		if (!domain) {
			error = -ENOMEM;
			goto fail;
		}
		refcount_set(&domain->refs, 1); /* optional domain registry */
		mutex_init(&domain->cfg);
		spin_lock_init(&domain->index_lock);
		INIT_LIST_HEAD(&domain->flows);
		INIT_LIST_HEAD(&domain->bindings);
		hash_init(domain->associations);
		hash_init(domain->wire);
		domain->dev = dev;
		dev_hold(dev);
		INIT_LIST_HEAD(&domain->node);
		init_completion(&domain->collectors[0].stopped);
		init_completion(&domain->collectors[1].stopped);
		complete_all(&domain->collectors[0].stopped);
		complete_all(&domain->collectors[1].stopped);
		list_add_tail(&domain->node, &qdx_flow_domains);
		error = qdx_flow_collector_start(domain, 0);
		if (error) {
			domain->closing = true;
			refcount_inc(&domain->refs);
			retire_domain = true;
			goto fail;
		}
		error = qdx_flow_collector_start(domain, 1);
		if (error) {
			domain->closing = true;
			refcount_inc(&domain->refs);
			retire_domain = true;
			goto fail;
		}
		domain->admitting = true;
	} else {
		domain = found;
	}
	mutex_lock(&domain->cfg);
	if (domain->closing) {
		mutex_unlock(&domain->cfg);
		error = -EAGAIN;
		goto fail;
	}
	refcount_set(&binding->refs, 1); /* actual dispatcher attachment */
	refcount_inc(&domain->refs);
	binding->domain = domain;
	binding->native = native_binding;
	binding->table = table;
	binding->live = true;
	list_add_tail(&binding->node, &domain->bindings);
	mutex_unlock(&domain->cfg);
	mutex_unlock(&qdx_flow_domains_lock);
	*attachment = binding;
	return 0;
fail:
	mutex_unlock(&qdx_flow_domains_lock);
	if (retire_domain) {
		qdx_flow_domain_retire(domain);
		qdx_flow_domain_put(domain);
	}
	qdx_binding_put(native_binding);
	kfree(binding);
	return error;
}

static int qdx_flow_setup(void *attachment, enum tc_setup_type type, void *data)
{
	struct qdx_flow_binding *binding = attachment;
	struct flow_cls_offload *cls = data;

	if (type != TC_SETUP_CLSFLOWER || !cls->nf_flow_ctx)
		return -EOPNOTSUPP;
	switch (cls->command) {
	case FLOW_CLS_REPLACE:
		return qdx_flow_replace(binding, cls->nf_flow_ctx);
	case FLOW_CLS_DESTROY:
		qdx_flow_destroy(binding, cls->nf_flow_ctx);
		return 0;
	case FLOW_CLS_STATS:
		qdx_flow_stats(binding, cls->nf_flow_ctx, &cls->stats);
		return 0;
	default:
		return -EOPNOTSUPP;
	}
}

static void qdx_flow_unbind(void *attachment)
{
	struct qdx_flow_binding *binding = attachment;
	struct qdx_flow_domain *domain = binding->domain;
	struct nf_flow_offload_ctx context = {};
	struct qdx_flow *flow, *found;

	mutex_lock(&domain->cfg);
	binding->live = false;
	list_del_init(&binding->node);
	if (list_empty(&domain->bindings)) {
		domain->closing = true;
		domain->admitting = false;
	}
	mutex_unlock(&domain->cfg);
	for (;;) {
		found = NULL;
		mutex_lock(&domain->cfg);
		list_for_each_entry(flow, &domain->flows, node) {
			if (flow->binding == binding && !hlist_unhashed(&flow->association)) {
				qdx_flow_get(flow);
				found = flow;
				break;
			}
		}
		if (found) {
			spin_lock_bh(&found->data_lock);
			context.flow = found->native;
			spin_unlock_bh(&found->data_lock);
		}
		mutex_unlock(&domain->cfg);
		if (!found)
			break;
		qdx_flow_destroy(binding, &context);
		qdx_flow_put(found);
	}
	mutex_lock(&domain->cfg);
	binding->table = NULL;
	mutex_unlock(&domain->cfg);
	qdx_flow_domain_retire(domain);
	/* Queued preparation/retirement retain this old storage. Native UNBIND
	 * never waits for RTNL work while still holding its own native locks.
	 */
	qdx_flow_binding_put(binding);
}

static const struct qdx_flow_ops qdx_flow_provider_ops = {
	.bind = qdx_flow_bind,
	.setup = qdx_flow_setup,
	.unbind = qdx_flow_unbind,
};

static struct notifier_block qdx_flow_nf_notifier = {
	.notifier_call = qdx_flow_nf_event,
};
static struct notifier_block qdx_flow_tc_notifier = {
	.notifier_call = qdx_flow_tc_event,
};
static struct notifier_block qdx_flow_netdev_notifier = {
	.notifier_call = qdx_flow_netdev_event,
};

static void qdx_flow_service_changed(void *object, enum qdx_service_kind kind,
				     enum qdx_availability state)
{
	struct qdx_flow_domain *domain;
	struct qdx_flow *flow;
	int i;

	mutex_lock(&qdx_flow_domains_lock);
	list_for_each_entry(domain, &qdx_flow_domains, node) {
		mutex_lock(&domain->cfg);
		if (state == QDX_FAILED)
			domain->admitting = false;
		list_for_each_entry(flow, &domain->flows, node) {
			if (state == QDX_FAILED) {
				spin_lock_bh(&flow->data_lock);
				flow->invalid = true;
				spin_unlock_bh(&flow->data_lock);
				qdx_flow_queue_retire(flow);
			} else if (state == QDX_AVAILABLE) {
				qdx_flow_queue_prepare(flow);
			}
		}
		mutex_unlock(&domain->cfg);
		for (i = 0; i < 2; i++)
			if (READ_ONCE(domain->collectors[i].service))
				mod_delayed_work(qdx_flow_wq, &domain->collectors[i].work, 0);
	}
	mutex_unlock(&qdx_flow_domains_lock);
}

static int __init qdx_flow_init(void)
{
	const struct qdx_binding_key key = { .role = QDX_BINDING_FT_PROVIDER };
	const struct qdx_owner owner = { .module = THIS_MODULE };
	int error;

	qdx_flow_wq = alloc_workqueue("qdx-flow", WQ_UNBOUND | WQ_MEM_RECLAIM, 0);
	if (!qdx_flow_wq)
		return -ENOMEM;
	error = nf_netdev_register_notifier(&qdx_flow_nf_notifier);
	if (error)
		goto destroy_queue;
	error = tcf_block_register_notifier(&qdx_flow_tc_notifier);
	if (error)
		goto unregister_nf;
	error = register_netdevice_notifier(&qdx_flow_netdev_notifier);
	if (error)
		goto unregister_tc;
	qdx_flow_listener = qdx_service_listen(&owner, qdx_flow_service_changed);
	if (IS_ERR(qdx_flow_listener)) {
		error = PTR_ERR(qdx_flow_listener);
		goto unregister_netdev;
	}
	qdx_flow_provider = qdx_binding_publish(&key, &owner, &qdx_flow_provider_ops);
	if (IS_ERR(qdx_flow_provider)) {
		error = PTR_ERR(qdx_flow_provider);
		goto unlisten;
	}
	qdx_binding_available(qdx_flow_provider);
	return 0;
unlisten:
	qdx_service_unlisten(qdx_flow_listener);
unregister_netdev:
	unregister_netdevice_notifier(&qdx_flow_netdev_notifier);
unregister_tc:
	tcf_block_unregister_notifier(&qdx_flow_tc_notifier);
unregister_nf:
	nf_netdev_unregister_notifier(&qdx_flow_nf_notifier);
destroy_queue:
	destroy_workqueue(qdx_flow_wq);
	return error;
}

static void __exit qdx_flow_exit(void)
{
	struct qdx_flow_domain *domain;
	struct qdx_binding_scan scan;
	struct qdx_binding_use *use;
	struct qdx_flow *flow;

	qdx_binding_invalidate(qdx_flow_provider);
	qdx_binding_scan_start(qdx_flow_provider, &scan);
	while ((use = qdx_binding_user_get(qdx_flow_provider, &scan))) {
		use->invalidate(use->consumer.object, true);
		qdx_binding_user_put(use);
	}
	qdx_binding_withdraw(qdx_flow_provider);
	for (;;) {
		mutex_lock(&qdx_flow_domains_lock);
		domain = list_first_entry_or_null(&qdx_flow_domains, struct qdx_flow_domain, node);
		if (domain)
			refcount_inc(&domain->refs);
		mutex_unlock(&qdx_flow_domains_lock);
		if (!domain)
			break;
		mutex_lock(&domain->cfg);
		domain->admitting = false;
		domain->closing = true;
		mutex_unlock(&domain->cfg);
		/* This is outside the actual native UNBIND/source locks. Initial
		 * preparation cannot publish CREATE and may still be waiting for RTNL.
		 */
		for (;;) {
			mutex_lock(&domain->cfg);
			flow = list_first_entry_or_null(&domain->flows, struct qdx_flow, node);
			if (flow)
				qdx_flow_get(flow);
			mutex_unlock(&domain->cfg);
			if (!flow)
				break;
			flush_work(&flow->prepare_work);
			flush_delayed_work(&flow->retire_work);
			qdx_flow_put(flow);
		}
		qdx_flow_domain_retire(domain);
		wait_for_completion(&domain->collectors[0].stopped);
		wait_for_completion(&domain->collectors[1].stopped);
		if (domain->collectors[0].domain)
			cancel_delayed_work_sync(&domain->collectors[0].work);
		if (domain->collectors[1].domain)
			cancel_delayed_work_sync(&domain->collectors[1].work);
		qdx_flow_domain_cleanup(domain);
		qdx_flow_domain_put(domain);
	}
	qdx_service_unlisten(qdx_flow_listener);
	unregister_netdevice_notifier(&qdx_flow_netdev_notifier);
	tcf_block_unregister_notifier(&qdx_flow_tc_notifier);
	nf_netdev_unregister_notifier(&qdx_flow_nf_notifier);
	/* Also drains a last collector that removed its domain before dropping
	 * its code pin. No native/source or peer configuration lock is held.
	 */
	destroy_workqueue(qdx_flow_wq);
}

module_init(qdx_flow_init);
module_exit(qdx_flow_exit);
MODULE_DESCRIPTION("QDX native routed flowtable offload");
MODULE_LICENSE("GPL");
