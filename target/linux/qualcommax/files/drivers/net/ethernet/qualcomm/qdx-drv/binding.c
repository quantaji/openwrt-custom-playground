// SPDX-License-Identifier: GPL-2.0-only
/* Index actual provider objects and retain their real consumer relationships. */
#include <linux/module.h>
#include <linux/slab.h>
#include "qdx.h"

struct qdx_binding {
	struct list_head index;
	struct list_head users;
	struct qdx_binding_key key;
	struct qdx_owner owner;
	const void *ops;
	refcount_t refs;
	u64 last_user;
	bool accepting;
	bool available;
	bool invalid;
};

static LIST_HEAD(qdx_bindings);
static DEFINE_SPINLOCK(qdx_use_lock);

bool qdx_owner_get(const struct qdx_owner *owner)
{
	if (!try_module_get(owner->module))
		return false;
	if (owner->get && !owner->get(owner->object)) {
		module_put(owner->module);
		return false;
	}
	return true;
}

void qdx_owner_put(const struct qdx_owner *owner)
{
	struct module *module = owner->module;

	if (owner->put)
		owner->put(owner->object);
	module_put(module);
}

static void qdx_binding_free(struct qdx_binding *binding)
{
	if (!refcount_dec_and_test(&binding->refs))
		return;
	WARN_ON_ONCE(!list_empty(&binding->users));
	if (binding->key.dev)
		dev_put(binding->key.dev);
	kfree(binding);
}

struct qdx_binding *qdx_binding_publish(const struct qdx_binding_key *key,
		const struct qdx_owner *owner, const void *typed_ops)
{
	struct qdx_binding *binding, *entry;
	int error = -EEXIST;

	if (!owner || (!!owner->get != !!owner->put))
		return ERR_PTR(-EINVAL);
	binding = kzalloc(sizeof(*binding), GFP_KERNEL);
	if (!binding)
		return ERR_PTR(-ENOMEM);
	/* Registration owns storage, but does not prevent idle module exit. */
	if (owner->get && !owner->get(owner->object)) {
		kfree(binding);
		return ERR_PTR(-ESHUTDOWN);
	}
	binding->key = *key;
	binding->owner = *owner;
	binding->ops = typed_ops;
	binding->accepting = true;
	INIT_LIST_HEAD(&binding->users);
	refcount_set(&binding->refs, 1);
	if (key->dev)
		dev_hold(key->dev);
	spin_lock_bh(&qdx_use_lock);
	list_for_each_entry(entry, &qdx_bindings, index) {
		if (entry->key.dev == key->dev && entry->key.identity == key->identity &&
		    entry->key.role == key->role)
			goto duplicate;
	}
	list_add_tail(&binding->index, &qdx_bindings);
	spin_unlock_bh(&qdx_use_lock);
	return binding;
duplicate:
	spin_unlock_bh(&qdx_use_lock);
	if (owner->put)
		owner->put(owner->object);
	qdx_binding_free(binding);
	return ERR_PTR(error);
}
EXPORT_SYMBOL_GPL(qdx_binding_publish);

struct qdx_binding *qdx_binding_lookup(const struct qdx_binding_key *key)
{
	struct qdx_binding *entry, *found = NULL;

	spin_lock_bh(&qdx_use_lock);
	list_for_each_entry(entry, &qdx_bindings, index) {
		if (entry->key.dev != key->dev || entry->key.identity != key->identity ||
		    entry->key.role != key->role || !entry->accepting)
			continue;
		if (qdx_owner_get(&entry->owner)) {
			refcount_inc(&entry->refs);
			found = entry;
		}
		break;
	}
	spin_unlock_bh(&qdx_use_lock);
	return found;
}
EXPORT_SYMBOL_GPL(qdx_binding_lookup);

bool qdx_binding_hold(struct qdx_binding *binding)
{
	if (!qdx_owner_get(&binding->owner))
		return false;
	refcount_inc(&binding->refs);
	return true;
}
EXPORT_SYMBOL_GPL(qdx_binding_hold);

struct net_device *qdx_binding_dev(const struct qdx_binding *binding)
{
	return binding->key.dev;
}
EXPORT_SYMBOL_GPL(qdx_binding_dev);

void qdx_binding_put(struct qdx_binding *binding)
{
	if (!binding)
		return;
	qdx_owner_put(&binding->owner);
	qdx_binding_free(binding);
}
EXPORT_SYMBOL_GPL(qdx_binding_put);

void *qdx_binding_owner(const struct qdx_binding *binding)
{
	return binding->owner.object;
}
EXPORT_SYMBOL_GPL(qdx_binding_owner);

const void *qdx_binding_ops(const struct qdx_binding *binding)
{
	return binding->ops;
}
EXPORT_SYMBOL_GPL(qdx_binding_ops);

int qdx_binding_use(struct qdx_binding *provider, struct qdx_binding_use *use,
		    const struct qdx_owner *consumer,
		    int (*invalidate)(void *consumer, bool may_sleep))
{
	int error = -ESHUTDOWN;

	if (!qdx_owner_get(consumer))
		return error;
	if (!qdx_owner_get(&provider->owner)) {
		qdx_owner_put(consumer);
		return error;
	}
	spin_lock_bh(&qdx_use_lock);
	if (!provider->accepting || provider->last_user == U64_MAX)
		goto closed;
	refcount_inc(&provider->refs);
	use->provider = provider;
	use->consumer = *consumer;
	use->invalidate = invalidate;
	use->serial = ++provider->last_user;
	use->invalid = provider->invalid;
	use->usable = false;
	use->linked = true;
	refcount_set(&use->deliveries, 1);
	list_add_tail(&use->node, &provider->users);
	spin_unlock_bh(&qdx_use_lock);
	return 0;
closed:
	spin_unlock_bh(&qdx_use_lock);
	qdx_owner_put(&provider->owner);
	qdx_owner_put(consumer);
	return error;
}
EXPORT_SYMBOL_GPL(qdx_binding_use);

void qdx_binding_use_put(struct qdx_binding_use *use)
{
	bool detached = false;

	spin_lock_bh(&qdx_use_lock);
	if (use->linked) {
		list_del_init(&use->node);
		use->linked = false;
		use->usable = false;
		smp_store_release(&use->invalid, true);
		detached = true;
	}
	spin_unlock_bh(&qdx_use_lock);
	if (detached)
		qdx_binding_user_put(use);
}
EXPORT_SYMBOL_GPL(qdx_binding_use_put);

void qdx_uses_lock(void)
{
	spin_lock_bh(&qdx_use_lock);
}
EXPORT_SYMBOL_GPL(qdx_uses_lock);

void qdx_uses_unlock(void)
{
	spin_unlock_bh(&qdx_use_lock);
}
EXPORT_SYMBOL_GPL(qdx_uses_unlock);

bool qdx_use_available_locked(const struct qdx_binding_use *use)
{
	lockdep_assert_held(&qdx_use_lock);
	return use->linked && !use->invalid && use->provider->accepting &&
	       use->provider->available;
}
EXPORT_SYMBOL_GPL(qdx_use_available_locked);

void qdx_use_publish_locked(struct qdx_binding_use *use)
{
	lockdep_assert_held(&qdx_use_lock);
	use->usable = qdx_use_available_locked(use);
}
EXPORT_SYMBOL_GPL(qdx_use_publish_locked);

void qdx_use_invalidate_locked(struct qdx_binding_use *use)
{
	lockdep_assert_held(&qdx_use_lock);
	use->usable = false;
	smp_store_release(&use->invalid, true);
}
EXPORT_SYMBOL_GPL(qdx_use_invalidate_locked);

void qdx_binding_prepare(struct qdx_binding *binding)
{
	spin_lock_bh(&qdx_use_lock);
	binding->available = false;
	binding->invalid = false;
	/* Old invalid uses remain invalid; this permits new preparing uses. */
	spin_unlock_bh(&qdx_use_lock);
}
EXPORT_SYMBOL_GPL(qdx_binding_prepare);

void qdx_binding_available(struct qdx_binding *binding)
{
	spin_lock_bh(&qdx_use_lock);
	if (binding->accepting && !binding->invalid)
		binding->available = true;
	spin_unlock_bh(&qdx_use_lock);
}
EXPORT_SYMBOL_GPL(qdx_binding_available);

void qdx_binding_invalidate(struct qdx_binding *binding)
{
	struct qdx_binding_use *use;

	spin_lock_bh(&qdx_use_lock);
	binding->available = false;
	binding->invalid = true;
	list_for_each_entry(use, &binding->users, node) {
		use->usable = false;
		smp_store_release(&use->invalid, true);
	}
	spin_unlock_bh(&qdx_use_lock);
}
EXPORT_SYMBOL_GPL(qdx_binding_invalidate);

void qdx_binding_scan_start(struct qdx_binding *binding, struct qdx_binding_scan *scan)
{
	spin_lock_bh(&qdx_use_lock);
	scan->cursor = 0;
	scan->limit = binding->last_user;
	spin_unlock_bh(&qdx_use_lock);
}
EXPORT_SYMBOL_GPL(qdx_binding_scan_start);

struct qdx_binding_use *qdx_binding_user_get(struct qdx_binding *binding,
					  struct qdx_binding_scan *scan)
{
	struct qdx_binding_use *use, *found = NULL;

	spin_lock_bh(&qdx_use_lock);
	list_for_each_entry(use, &binding->users, node) {
		if (use->serial <= scan->cursor || use->serial > scan->limit)
			continue;
		refcount_inc(&use->deliveries);
		scan->cursor = use->serial;
		found = use;
		break;
	}
	spin_unlock_bh(&qdx_use_lock);
	return found;
}
EXPORT_SYMBOL_GPL(qdx_binding_user_get);

void qdx_binding_user_put(struct qdx_binding_use *use)
{
	struct qdx_binding *provider;
	struct qdx_owner consumer;

	/* Snapshot before the final decrement: zero permits the owner to reuse
	 * its unlinked embedded storage. No access to use is allowed afterward.
	 */
	provider = use->provider;
	consumer = use->consumer;
	if (!refcount_dec_and_test(&use->deliveries))
		return;
	qdx_binding_put(provider);
	qdx_owner_put(&consumer);
}
EXPORT_SYMBOL_GPL(qdx_binding_user_put);

void qdx_binding_withdraw(struct qdx_binding *binding)
{
	struct qdx_binding_use *use;
	struct qdx_owner owner = binding->owner;

	spin_lock_bh(&qdx_use_lock);
	if (!binding->accepting) {
		spin_unlock_bh(&qdx_use_lock);
		return;
	}
	binding->accepting = false;
	binding->available = false;
	binding->invalid = true;
	list_del_init(&binding->index);
	list_for_each_entry(use, &binding->users, node) {
		use->usable = false;
		smp_store_release(&use->invalid, true);
	}
	spin_unlock_bh(&qdx_use_lock);
	/* Each admitted lookup/use separately retains code and storage. The owner
	 * closes its typed entry and stops users before withdrawing registration.
	 */
	if (owner.put)
		owner.put(owner.object);
	qdx_binding_free(binding);
}
EXPORT_SYMBOL_GPL(qdx_binding_withdraw);
