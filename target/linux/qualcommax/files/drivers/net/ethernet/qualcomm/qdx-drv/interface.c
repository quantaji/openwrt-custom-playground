// SPDX-License-Identifier: GPL-2.0-only
#include <linux/etherdevice.h>
#include <linux/rtnetlink.h>
#include <linux/jiffies.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/unaligned.h>
#include "qdx.h"

void qdx_interfaces_init(struct qdx *qdx)
{
	unsigned int i;

	for (i = 0; i < QDX_PHYSICAL_PORTS; i++) {
		struct qdx_port *port = &qdx->ethernet->ports[i];

		port->qdx = qdx;
		port->ifnum = i;
		mutex_init(&port->lock);
		refcount_set(&port->refs, 1);
		init_waitqueue_head(&port->drained);
	}
}

int qdx_interfaces_register(struct qdx *qdx)
{
	struct qdx_ethernet *eth = qdx->ethernet;
	unsigned int i;
	int ret;

	ASSERT_RTNL();
	for (i = 1; i < QDX_PHYSICAL_PORTS; i++) {
		struct qdx_port *port = &eth->ports[i];
		struct qdx_port_state state;

		if (!(eth->ppe->info.ports & BIT(i)) || port->registered)
			continue;
		ret = eth->ppe->info.ops->snapshot(eth->ppe->info.context, i, &state);
		if (ret)
			return ret;
		port->netdev = state.netdev;
		port->conduit = eth->edma->info.conduit;
		dev_hold(port->netdev);
		dev_hold(port->conduit);
		/* One immutable physical table serves either firmware core. */
		smp_store_release(&port->registered, true);
	}
	return 0;
}

void qdx_port_publish(struct qdx_port *port)
{
	if (port->registered && port->opened && port->link_state &&
	    !READ_ONCE(port->changing) &&
	    !atomic_read(&port->qdx->failure))
		smp_store_release(&port->available, true);
}

void qdx_port_withdraw(struct qdx_port *port)
{
	qdx_io_port_close(port);
}

struct qdx_port *qdx_port_get(struct qdx *qdx, unsigned int core, u32 ifnum)
{
	struct qdx_port *port;

	if (core >= 2 || ifnum == 0 || ifnum >= QDX_PHYSICAL_PORTS)
		return NULL;
	port = &qdx->ethernet->ports[ifnum];
	rcu_read_lock();
	if (!smp_load_acquire(&port->registered) ||
	    !smp_load_acquire(&port->available)) {
		rcu_read_unlock();
		return NULL;
	}
	refcount_inc(&port->refs);
	rcu_read_unlock();
	return port;
}

void qdx_port_put(struct qdx_port *port)
{
	unsigned long flags;
	struct qdx *qdx = port->qdx;

	spin_lock_irqsave(&qdx->io_admission, flags);
	refcount_dec(&port->refs);
	wake_up_all(&port->drained);
	spin_unlock_irqrestore(&qdx->io_admission, flags);
}

void qdx_interfaces_unregister(struct qdx *qdx)
{
	unsigned long flags;
	unsigned int i;

	for (i = 1; i < QDX_PHYSICAL_PORTS; i++) {
		struct qdx_port *port = &qdx->ethernet->ports[i];

		qdx_port_withdraw(port);
		smp_store_release(&port->registered, false);
	}
	synchronize_net();
	for (i = 1; i < QDX_PHYSICAL_PORTS; i++) {
		struct qdx_port *port = &qdx->ethernet->ports[i];

		if (!port->netdev)
			continue;
		wait_event(port->drained, refcount_read(&port->refs) == 1);
		spin_lock_irqsave(&qdx->io_admission, flags);
		spin_unlock_irqrestore(&qdx->io_admission, flags);
		dev_put(port->netdev);
		dev_put(port->conduit);
		port->netdev = NULL;
		port->conduit = NULL;
	}
}

/* Endpoint identity is distinct from any peer's policy and producer use. */
static void qdx_endpoint_work(struct work_struct *work);

static struct qdx_endpoint *qdx_endpoint_create(struct qdx_service *service,
					      unsigned int core, u32 type)
{
	struct qdx_endpoint *endpoint = kzalloc(sizeof(*endpoint), GFP_KERNEL);

	if (!endpoint)
		return NULL;
	endpoint->service = service;
	endpoint->core = &service->qdx->cores[core];
	endpoint->dynamic_type = type;
	endpoint->desired = true;
	endpoint->ifnum = U32_MAX;
	endpoint->state = type ? QDX_ENDPOINT_ALLOCATING : QDX_ENDPOINT_OWNED;
	refcount_set(&endpoint->refs, 1);
	mutex_init(&endpoint->cfg);
	spin_lock_init(&endpoint->lock);
	init_completion(&endpoint->ready);
	init_waitqueue_head(&endpoint->drained);
	INIT_WORK(&endpoint->work, qdx_endpoint_work);
	atomic_set(&endpoint->operations, 0);
	qdx_service_hold(service);
	return endpoint;
}

void qdx_endpoint_hold(struct qdx_endpoint *endpoint)
{
	refcount_inc(&endpoint->refs);
}
EXPORT_SYMBOL_GPL(qdx_endpoint_hold);

void qdx_endpoint_put(struct qdx_endpoint *endpoint)
{
	if (!endpoint || !refcount_dec_and_test(&endpoint->refs))
		return;
	WARN_ON_ONCE(endpoint->indexed || atomic_read(&endpoint->operations));
	if (endpoint->port)
		qdx_port_put(endpoint->port);
	qdx_service_put(endpoint->service);
	kfree(endpoint);
}
EXPORT_SYMBOL_GPL(qdx_endpoint_put);

/* The device owns static index entries; callers own references and categories. */
struct qdx_endpoint *qdx_endpoint_static(struct qdx_service *service,
					unsigned int core, u32 ifnum)
{
	struct xarray *index = &service->qdx->cores[core].endpoints;
	struct qdx_endpoint *endpoint, *found;
	unsigned long flags;
	int error;

	endpoint = qdx_endpoint_create(service, core, 0);
	if (!endpoint)
		return ERR_PTR(-ENOMEM);
	endpoint->ifnum = ifnum;
	endpoint->producers_open = true;
	endpoint->dispatch_open = true;
	xa_lock_irqsave(index, flags);
	if (atomic_read(&service->qdx->failure) ||
	    READ_ONCE(service->qdx->io_closing) ||
	    qdx_service_access_ended(service)) {
		xa_unlock_irqrestore(index, flags);
		qdx_endpoint_put(endpoint);
		return ERR_PTR(-ESHUTDOWN);
	}
	found = xa_load(index, ifnum);
	if (found) {
		qdx_endpoint_hold(found);
		xa_unlock_irqrestore(index, flags);
		qdx_endpoint_put(endpoint);
		return found;
	}
	error = __xa_insert(index, ifnum, endpoint, GFP_ATOMIC);
	if (!error) {
		endpoint->indexed = true;
		qdx_endpoint_hold(endpoint);
	}
	xa_unlock_irqrestore(index, flags);
	if (error) {
		qdx_endpoint_put(endpoint);
		return ERR_PTR(error);
	}
	complete_all(&endpoint->ready);
	return endpoint;
}

struct qdx_endpoint *qdx_endpoint_get(struct qdx_service *service,
				    struct net_device *physical)
{
	struct qdx_endpoint *endpoint;
	struct qdx_port *port = NULL;
	unsigned int i;

	if (qdx_service_state(service) != QDX_AVAILABLE)
		return ERR_PTR(-EAGAIN);
	if (!physical)
		return qdx_endpoint_static(service, service->core, service->ifnum);
	rcu_read_lock();
	for (i = 1; i < QDX_PHYSICAL_PORTS; i++) {
		struct qdx_port *candidate = &service->qdx->ethernet->ports[i];

		if (smp_load_acquire(&candidate->registered) && candidate->netdev == physical) {
			refcount_inc(&candidate->refs);
			port = candidate;
			break;
		}
	}
	rcu_read_unlock();
	if (!port)
		return ERR_PTR(-ENODEV);
	endpoint = qdx_endpoint_static(service, service->core, port->ifnum);
	if (IS_ERR(endpoint)) {
		qdx_port_put(port);
		return endpoint;
	}
	mutex_lock(&endpoint->cfg);
	if (!endpoint->port)
		endpoint->port = port;
	else
		qdx_port_put(port);
	mutex_unlock(&endpoint->cfg);
	return endpoint;
}
EXPORT_SYMBOL_GPL(qdx_endpoint_get);

int qdx_endpoint_ifnum(const struct qdx_endpoint *endpoint, u32 *ifnum)
{
	if (!endpoint || READ_ONCE(endpoint->ifnum) == U32_MAX ||
	    smp_load_acquire(&endpoint->state) == QDX_ENDPOINT_RETIRED)
		return -ESTALE;
	*ifnum = READ_ONCE(endpoint->ifnum);
	return 0;
}
EXPORT_SYMBOL_GPL(qdx_endpoint_ifnum);

u32 qdx_endpoint_wire_ifnum(const struct qdx_endpoint *endpoint)
{
	return READ_ONCE(endpoint->ifnum) | ((endpoint->core->id + 1) << 24);
}
EXPORT_SYMBOL_GPL(qdx_endpoint_wire_ifnum);

bool qdx_endpoint_command_ready(struct qdx_endpoint *endpoint)
{
	return smp_load_acquire(&endpoint->producers_open) &&
	       qdx_service_state(endpoint->service) == QDX_AVAILABLE;
}

static bool qdx_endpoint_owner_get(void *object)
{
	struct qdx_endpoint *endpoint = object;

	return refcount_inc_not_zero(&endpoint->refs);
}

static void qdx_endpoint_owner_put(void *object)
{
	qdx_endpoint_put(object);
}

static void qdx_endpoint_result(void *object, const struct qdx_result *result,
				const void *payload, size_t length)
{
	struct qdx_endpoint *endpoint = object;
	unsigned long flags;

	spin_lock_irqsave(&endpoint->lock, flags);
	/* An older transport warning cannot replace a settled callback. */
	if ((endpoint->result.id && result->id < endpoint->result.id) ||
	    (endpoint->result.id == result->id &&
	     endpoint->result.outcome != QDX_UNKNOWN &&
	     result->outcome == QDX_UNKNOWN && !result->exposure_ended)) {
		spin_unlock_irqrestore(&endpoint->lock, flags);
		return;
	}
	endpoint->result = *result;
	endpoint->returned_type = U32_MAX;
	endpoint->returned_ifnum = U32_MAX;
	if (length >= 8) {
		endpoint->returned_type = get_unaligned_le32(payload);
		endpoint->returned_ifnum = get_unaligned_le32(payload + 4);
	}
	endpoint->result_pending = true;
	qdx_endpoint_hold(endpoint);
	if (!queue_work(endpoint->service->qdx->cleanup_queue, &endpoint->work))
		qdx_endpoint_put(endpoint);
	spin_unlock_irqrestore(&endpoint->lock, flags);
}

/* cfg serializes publishing the returned handle with a fast queued callback. */
static int qdx_endpoint_command(struct qdx_endpoint *endpoint, bool deallocate)
{
	struct qdx_command_recipient recipient = {
		.owner = { .module = THIS_MODULE, .object = endpoint,
			.get = qdx_endpoint_owner_get, .put = qdx_endpoint_owner_put },
		.result = qdx_endpoint_result,
	};
	struct qdx_reply_bounds bounds = { .minimum = 8, .maximum = 8, .capacity = 8 };
	struct qdx_endpoint *allocator;
	struct qdx_request *request;
	__le32 body[2] = { cpu_to_le32(endpoint->dynamic_type),
		cpu_to_le32(deallocate ? endpoint->ifnum : U32_MAX) };

	allocator = qdx_endpoint_static(endpoint->service, endpoint->core->id, QDX_IF_DYNAMIC);
	if (IS_ERR(allocator))
		return PTR_ERR(allocator);
	endpoint->deallocation = deallocate;
	request = qdx_command_submit(allocator, deallocate ? 1 : 0, body, sizeof(body),
				     &bounds, &recipient);
	qdx_endpoint_put(allocator);
	if (IS_ERR(request))
		return PTR_ERR(request);
	endpoint->request = request;
	return 0;
}

struct qdx_endpoint *qdx_endpoint_alloc(struct qdx_service *service, u32 type)
{
	struct qdx_endpoint *endpoint;
	bool supported;
	int error;

	supported = (service->kind == QDX_SERVICE_PPPOE && type == 8) ||
		    (service->kind == QDX_SERVICE_VLAN && type == 17) ||
		    (service->kind == QDX_SERVICE_IGS && type == 53) ||
		    (service->kind == QDX_SERVICE_MATCH && type == 58) ||
		    (service->kind == QDX_SERVICE_MIRROR && type == 65);
	if (!supported)
		return ERR_PTR(-EOPNOTSUPP);
	if (qdx_service_state(service) != QDX_AVAILABLE)
		return ERR_PTR(-EAGAIN);
	endpoint = qdx_endpoint_create(service, service->core, type);
	if (!endpoint)
		return ERR_PTR(-ENOMEM);
	mutex_lock(&endpoint->cfg);
	error = qdx_endpoint_command(endpoint, false);
	mutex_unlock(&endpoint->cfg);
	if (error) {
		qdx_endpoint_put(endpoint);
		return ERR_PTR(error);
	}
	return endpoint;
}
EXPORT_SYMBOL_GPL(qdx_endpoint_alloc);

int qdx_endpoint_wait(struct qdx_endpoint *endpoint, unsigned long deadline)
{
	unsigned long now = jiffies;

	if (!wait_for_completion_timeout(&endpoint->ready,
			time_before(now, deadline) ? deadline - now : 0))
		return -ETIMEDOUT;
	if (smp_load_acquire(&endpoint->state) == QDX_ENDPOINT_OWNED)
		return 0;
	return READ_ONCE(endpoint->result.error) ?: -ESHUTDOWN;
}
EXPORT_SYMBOL_GPL(qdx_endpoint_wait);

static void qdx_endpoint_unindex(struct qdx_endpoint *endpoint)
{
	struct xarray *index = &endpoint->core->endpoints;
	unsigned long flags;
	bool removed = false;

	xa_lock_irqsave(index, flags);
	if (endpoint->indexed) {
		__xa_erase(index, endpoint->ifnum);
		endpoint->indexed = false;
		removed = true;
	}
	xa_unlock_irqrestore(index, flags);
	if (removed)
		qdx_endpoint_put(endpoint);
}

static void qdx_endpoint_work(struct work_struct *work)
{
	struct qdx_endpoint *endpoint = container_of(work, struct qdx_endpoint, work);
	struct xarray *index = &endpoint->core->endpoints;
	struct qdx_result result;
	struct qdx_request *request = NULL;
	unsigned long flags;
	u32 type, ifnum;
	bool pending;
	int error = 0;

	mutex_lock(&endpoint->cfg);
	spin_lock_irqsave(&endpoint->lock, flags);
	pending = endpoint->result_pending;
	result = endpoint->result;
	type = endpoint->returned_type;
	ifnum = endpoint->returned_ifnum;
	endpoint->result_pending = false;
	spin_unlock_irqrestore(&endpoint->lock, flags);
	if (pending && (result.outcome != QDX_UNKNOWN || result.exposure_ended)) {
		request = endpoint->request;
		endpoint->request = NULL;
	}
	if (qdx_service_access_ended(endpoint->service))
		goto retired;
	if (pending && result.outcome == QDX_REJECTED) {
		if (result.opcode == 0)
			goto retired;
		error = -EREMOTEIO;
		goto progress;
	}
	if (pending && result.outcome == QDX_ACK) {
		if (type != endpoint->dynamic_type || ifnum < QDX_DYNAMIC_FIRST ||
		    ifnum >= QDX_DYNAMIC_END ||
		    (result.opcode == 1 && ifnum != endpoint->ifnum)) {
			error = -EPROTO;
			goto progress;
		}
		if (result.opcode == 1) {
			error = qdx_io_receive_drain(endpoint->service->qdx);
			if (error)
				goto progress;
			goto retired;
		}
		endpoint->ifnum = ifnum;
		xa_lock_irqsave(index, flags);
		if (atomic_read(&endpoint->service->qdx->failure) ||
		    READ_ONCE(endpoint->service->qdx->io_closing) ||
		    qdx_service_access_ended(endpoint->service))
			error = -ESHUTDOWN;
		else
			error = __xa_insert(index, ifnum, endpoint, GFP_ATOMIC);
		if (!error) {
			endpoint->indexed = true;
			qdx_endpoint_hold(endpoint);
			endpoint->dispatch_open = true;
			smp_store_release(&endpoint->producers_open, endpoint->desired);
			smp_store_release(&endpoint->state, QDX_ENDPOINT_OWNED);
		}
		xa_unlock_irqrestore(index, flags);
		if (error)
			goto progress; /* Collision cannot replace an old wire recipient. */
		complete_all(&endpoint->ready);
	}
	if (pending && result.outcome == QDX_UNKNOWN) {
		error = result.error;
		goto progress;
	}
	if (!endpoint->desired && !endpoint->request && endpoint->ifnum != U32_MAX) {
		xa_lock_irqsave(index, flags);
		if (qdx_service_access_ended(endpoint->service) ||
		    endpoint->state == QDX_ENDPOINT_RETIRED) {
			xa_unlock_irqrestore(index, flags);
			goto retired;
		}
		smp_store_release(&endpoint->producers_open, false);
		smp_store_release(&endpoint->state, QDX_ENDPOINT_RETIRING);
		xa_unlock_irqrestore(index, flags);
		if (!wait_event_timeout(endpoint->drained,
				!atomic_read(&endpoint->operations), msecs_to_jiffies(3000))) {
			error = -ETIMEDOUT;
			goto progress;
		}
		error = qdx_endpoint_command(endpoint, true);
	}
progress:
	if (error)
		qdx_stop_execution(endpoint->service, error);
	goto out;
retired:
	smp_store_release(&endpoint->producers_open, false);
	smp_store_release(&endpoint->dispatch_open, false);
	smp_store_release(&endpoint->state, QDX_ENDPOINT_RETIRED);
	qdx_endpoint_unindex(endpoint);
	complete_all(&endpoint->ready);
	wake_up_all(&endpoint->drained);
out:
	mutex_unlock(&endpoint->cfg);
	qdx_request_put(request);
	qdx_endpoint_put(endpoint); /* This queued worker's storage reference. */
}

int qdx_endpoint_retire(struct qdx_endpoint *endpoint)
{
	/* The peer already withdrew its static producers. Shared physical identity
	 * is device-owned; only this peer's receiver/category is unregistered.
	 */
	if (!endpoint->dynamic_type)
		return qdx_io_receive_drain(endpoint->service->qdx);
	mutex_lock(&endpoint->cfg);
	endpoint->desired = false;
	smp_store_release(&endpoint->producers_open, false);
	qdx_endpoint_hold(endpoint);
	if (!queue_work(endpoint->service->qdx->cleanup_queue, &endpoint->work))
		qdx_endpoint_put(endpoint);
	mutex_unlock(&endpoint->cfg);
	if (wait_event_timeout(endpoint->drained,
			smp_load_acquire(&endpoint->state) == QDX_ENDPOINT_RETIRED,
			msecs_to_jiffies(3000)))
		return 0;
	qdx_stop_execution(endpoint->service, -ETIMEDOUT);
	return -ETIMEDOUT;
}
EXPORT_SYMBOL_GPL(qdx_endpoint_retire);

struct qdx_receiver *qdx_endpoint_receive_register(struct qdx_endpoint *endpoint,
		u8 category, const struct qdx_owner *owner, const struct qdx_receive_ops *ops)
{
	struct qdx_receiver *receiver;
	int error = -EEXIST;

	if (category >= QDX_RX_CATEGORIES || !owner || !ops ||
	    (!!owner->get != !!owner->put) || (!ops->packet && !ops->message))
		return ERR_PTR(-EINVAL);
	receiver = kzalloc(sizeof(*receiver), GFP_KERNEL);
	if (!receiver)
		return ERR_PTR(-ENOMEM);
	if (owner->get && !owner->get(owner->object)) {
		kfree(receiver);
		return ERR_PTR(-ESHUTDOWN);
	}
	receiver->owner = *owner;
	receiver->ops = ops;
	receiver->endpoint = endpoint;
	receiver->category = category;
	receiver->accepting = true;
	refcount_set(&receiver->refs, 1);
	init_waitqueue_head(&receiver->drained);
	qdx_endpoint_hold(endpoint);
	mutex_lock(&endpoint->cfg);
	spin_lock_bh(&endpoint->lock);
	if (!endpoint->dispatch_open) {
		error = -ESHUTDOWN;
	} else if (!rcu_access_pointer(endpoint->receivers[category])) {
		rcu_assign_pointer(endpoint->receivers[category], receiver);
		error = 0;
	}
	spin_unlock_bh(&endpoint->lock);
	mutex_unlock(&endpoint->cfg);
	if (!error)
		return receiver;
	qdx_endpoint_put(endpoint);
	if (owner->put)
		owner->put(owner->object);
	kfree(receiver);
	return ERR_PTR(error);
}
EXPORT_SYMBOL_GPL(qdx_endpoint_receive_register);

static struct qdx_receiver *qdx_receiver_get(struct qdx_core *core, u32 ifnum,
					   u8 category)
{
	struct qdx_endpoint *endpoint;
	struct qdx_receiver *receiver = NULL;
	unsigned long flags;

	if (category >= QDX_RX_CATEGORIES)
		return NULL;
	xa_lock_irqsave(&core->endpoints, flags);
	endpoint = xa_load(&core->endpoints, ifnum);
	if (!endpoint)
		goto out;
	spin_lock(&endpoint->lock);
	if (endpoint->dispatch_open) {
		receiver = rcu_dereference_protected(endpoint->receivers[category],
						   lockdep_is_held(&endpoint->lock));
		if (receiver && receiver->accepting && qdx_owner_get(&receiver->owner))
			refcount_inc(&receiver->refs);
		else
			receiver = NULL;
	}
	spin_unlock(&endpoint->lock);
out:
	xa_unlock_irqrestore(&core->endpoints, flags);
	return receiver;
}

static void qdx_receiver_put(struct qdx_receiver *receiver)
{
	struct qdx_endpoint *endpoint = receiver->endpoint;
	unsigned long flags;

	qdx_owner_put(&receiver->owner);
	spin_lock_irqsave(&endpoint->lock, flags);
	refcount_dec(&receiver->refs);
	wake_up_all(&receiver->drained);
	spin_unlock_irqrestore(&endpoint->lock, flags);
}

void qdx_endpoint_message(struct qdx_core *core, u32 ifnum, u32 opcode,
		u32 response, u32 error, const void *payload, size_t received, size_t declared)
{
	struct qdx_receiver *receiver = qdx_receiver_get(core, ifnum, QDX_RECEIVE_MESSAGE);

	if (!receiver)
		return;
	if (receiver->ops->message)
		receiver->ops->message(receiver->owner.object, opcode, response, error,
				       payload, received, declared);
	qdx_receiver_put(receiver);
}

void qdx_endpoint_packet(struct qdx_core *core, struct sk_buff *skb,
			const struct qdx_rx_meta *metadata, struct napi_struct *napi)
{
	struct qdx_receiver *receiver;
	u8 category = metadata->type;

	/* PACKET is also used by dynamic endpoints; only physical sources use
	 * native Ethernet receive or the physical ingress-shaped category.
	 */
	if (metadata->type == QDX_N2H_PACKET && metadata->ifnum < QDX_PHYSICAL_PORTS) {
		if (!(metadata->flags & QDX_N2H_INGRESS_SHAPED)) {
			qdx_ethernet_receive(core->qdx, core->id, metadata->ifnum, skb, napi);
			return;
		}
		category = QDX_RECEIVE_INGRESS_SHAPED;
	}
	receiver = qdx_receiver_get(core, metadata->ifnum, category);
	if (receiver && receiver->ops->packet)
		receiver->ops->packet(receiver->owner.object, skb, metadata, napi);
	else
		dev_kfree_skb_any(skb);
	if (receiver)
		qdx_receiver_put(receiver);
}

int qdx_endpoint_receive_unregister(struct qdx_receiver *receiver)
{
	struct qdx_endpoint *endpoint;
	int error;

	if (!receiver)
		return 0;
	endpoint = receiver->endpoint;
	/* The owner first withdraws its actual producer. Retain the old recipient
	 * until NAPI has consumed the captured prefix and any crossing fragment.
	 */
	if (smp_load_acquire(&endpoint->state) != QDX_ENDPOINT_RETIRED &&
	    !qdx_service_access_ended(endpoint->service)) {
		error = qdx_io_receive_drain(endpoint->service->qdx);
		if (error)
			qdx_stop_execution(endpoint->service, error);
		/* Without an established prefix/access end the old receiver is still
		 * owned. The caller's retirement resumes after actual stop progress.
		 */
		if (error && !qdx_service_access_ended(endpoint->service))
			return error;
	}
	mutex_lock(&endpoint->cfg);
	spin_lock_bh(&endpoint->lock);
	receiver->accepting = false;
	RCU_INIT_POINTER(endpoint->receivers[receiver->category], NULL);
	spin_unlock_bh(&endpoint->lock);
	mutex_unlock(&endpoint->cfg);
	wait_event(receiver->drained, refcount_read(&receiver->refs) == 1);
	spin_lock_bh(&endpoint->lock);
	spin_unlock_bh(&endpoint->lock);
	if (receiver->owner.put)
		receiver->owner.put(receiver->owner.object);
	qdx_endpoint_put(endpoint);
	kfree(receiver);
	return 0;
}
EXPORT_SYMBOL_GPL(qdx_endpoint_receive_unregister);

void qdx_endpoints_close(struct qdx *qdx)
{
	struct qdx_endpoint *endpoint;
	unsigned long index, flags;
	unsigned int i;

	for (i = 0; i < QDX_CORES; i++) {
		xa_lock_irqsave(&qdx->cores[i].endpoints, flags);
		xa_for_each(&qdx->cores[i].endpoints, index, endpoint)
			smp_store_release(&endpoint->producers_open, false);
		xa_unlock_irqrestore(&qdx->cores[i].endpoints, flags);
	}
}

void qdx_endpoints_access_end(struct qdx *qdx)
{
	struct qdx_endpoint *endpoint;
	unsigned long index, flags;
	unsigned int i;

	for (i = 0; i < QDX_CORES; i++) {
		index = 0;
		for (;;) {
			xa_lock_irqsave(&qdx->cores[i].endpoints, flags);
			endpoint = xa_find(&qdx->cores[i].endpoints, &index, ULONG_MAX, XA_PRESENT);
			if (!endpoint) {
				xa_unlock_irqrestore(&qdx->cores[i].endpoints, flags);
				break;
			}
			__xa_erase(&qdx->cores[i].endpoints, index);
			endpoint->indexed = false;
			smp_store_release(&endpoint->producers_open, false);
			smp_store_release(&endpoint->dispatch_open, false);
			smp_store_release(&endpoint->state, QDX_ENDPOINT_RETIRED);
			xa_unlock_irqrestore(&qdx->cores[i].endpoints, flags);
			complete_all(&endpoint->ready);
			wake_up_all(&endpoint->drained);
			qdx_endpoint_put(endpoint);
		}
	}
}
