// SPDX-License-Identifier: GPL-2.0-only
/* Instance lifetime, dual-core startup, and terminal handback coordination. */
#include <linux/delay.h>
#include <linux/limits.h>
#include <linux/module.h>
#include <linux/srcu.h>
#include <linux/of_address.h>
#include <linux/overflow.h>
#include <linux/platform_device.h>
#include <linux/slab.h>

#include "qdx.h"

/* This module is resident: no ordinary exit can recreate the boot latch. */
static atomic_t qdx_boot_attempted = ATOMIC_INIT(0);

/* Resource choices are fixed before either firmware core can execute. */
static unsigned int native_rx_entries = 2048;
module_param(native_rx_entries, uint, 0444);
MODULE_PARM_DESC(native_rx_entries, "Native EDMA RX ring entries");

static unsigned int tx_slots = 1024;
module_param(tx_slots, uint, 0444);
MODULE_PARM_DESC(tx_slots, "TX carrier slots per NSS core");

static unsigned long rx_dma_limit_mib = 128;
module_param(rx_dma_limit_mib, ulong, 0444);
MODULE_PARM_DESC(rx_dma_limit_mib, "Aggregate NSS RX DMA length limit in MiB");

static unsigned long rx_memory_limit_mib = 256;
module_param(rx_memory_limit_mib, ulong, 0444);
MODULE_PARM_DESC(rx_memory_limit_mib, "QDX-owned RX allocation charge limit in MiB");

static unsigned long host_data_limit_mib = 8;
module_param(host_data_limit_mib, ulong, 0444);
MODULE_PARM_DESC(host_data_limit_mib, "Accepted host packet allocation limit in MiB");

static unsigned long peer_dma_limit_mib = 8;
module_param(peer_dma_limit_mib, ulong, 0444);
MODULE_PARM_DESC(peer_dma_limit_mib, "Persistent peer DMA allocation limit in MiB");

void qdx_schedule(struct qdx *qdx)
{
	schedule_work(&qdx->lifecycle);
}

void qdx_fail(struct qdx *qdx, int error)
{
	if (!error)
		error = -EIO;
	if (error > 0)
		error = -error;
	atomic_cmpxchg(&qdx->failure, 0, error);
	qdx_schedule(qdx);
}

static int qdx_ddr_info(struct qdx *qdx, struct qdx_ddr_info *info)
{
	struct device_node *node;
	struct resource resource;
	u64 start = U64_MAX, end = 0, size = 0, reserved = 0;
	unsigned int banks = 0, i;
	int index;

	/* Report actual DT memory, not free/cached Linux page accounting. */
	for_each_node_by_type(node, "memory") {
		for (index = 0; !of_address_to_resource(node, index, &resource); index++) {
			if (resource.end >= BIT_ULL(32) ||
			    check_add_overflow(size, (u64)resource_size(&resource), &size)) {
				of_node_put(node);
				return -ERANGE;
			}
			start = min_t(u64, start, resource.start);
			end = max_t(u64, end, resource.end + 1);
			banks++;
		}
	}
	/* This firmware envelope describes one contiguous DDR aperture. */
	if (!banks || !size || size > U32_MAX || end - start != size)
		return -EINVAL;
	for (i = 0; i < QDX_CORES; i++) {
		struct qdx_core *core = &qdx->cores[i];

		if (core->image_phys < start || core->image_phys + core->image_size > end)
			return -EINVAL;
		reserved += core->image_size;
	}
	if (reserved > U32_MAX)
		return -ERANGE;
	info->size = cpu_to_le32(size);
	info->start = cpu_to_le32(start);
	info->cores = cpu_to_le32(QDX_CORES);
	info->reserved_size = cpu_to_le32(reserved);
	return 0;
}

static int qdx_common_initialize(struct qdx_core *core, const struct qdx_ddr_info *ddr)
{
	struct qdx_pool_info request = {}, response;
	struct qdx_reply reply = { .max_len = sizeof(*ddr) };
	u32 pool, low, high, opcode;
	int paged, err;

	err = qdx_command(core, QDX_IF_N2H, QDX_N2H_DDR, ddr, sizeof(*ddr), &reply);
	if (err)
		return err;
	for (paged = 0; paged < 2; paged++) {
		opcode = paged ? QDX_N2H_GET_PAGED_POOL : QDX_N2H_GET_POOL;
		reply = (struct qdx_reply) {
			.data = &response,
			.min_len = sizeof(response),
			.max_len = sizeof(response),
		};
		err = qdx_command(core, QDX_IF_N2H, opcode, &request, sizeof(request), &reply);
		if (err)
			return err;
		pool = be32_to_cpu(response.pool);
		low = be32_to_cpu(response.low);
		high = be32_to_cpu(response.high);
		if (low > high)
			return -EPROTO;
		err = qdx_io_set_pool(core, paged, pool, low, high);
		if (err)
			return err;
		dev_info(core->qdx->dev, "core %u %s pool %u, watermarks %u/%u\n",
			 core->id, paged ? "paged" : "ordinary", pool, low, high);
	}
	WRITE_ONCE(core->common_ready, true);
	return 0;
}

static int qdx_wait_maps(struct qdx *qdx)
{
	unsigned long deadline = jiffies + msecs_to_jiffies(5000);
	unsigned int ready, i;
	int err;

	do {
		err = atomic_read(&qdx->failure);
		if (err)
			return err;
		ready = 0;
		for (i = 0; i < QDX_CORES; i++) {
			struct qdx_core *core = &qdx->cores[i];

			if (READ_ONCE(core->map_ready)) {
				ready++;
				continue;
			}
			/* Map publication precedes firmware readiness to accept doorbells.
			 * Its first buffer request is the active startup handshake.
			 */
			if (!smp_load_acquire(&core->boot_signaled))
				continue;
			err = qdx_mem_validate_map(core);
			if (err == -EAGAIN)
				continue;
			if (err)
				return err;
			err = qdx_io_bootstrap(core);
			if (err)
				return err;
			ready++;
		}
		if (ready == QDX_CORES)
			return 0;
		msleep(10);
	} while (time_before(jiffies, deadline));
	return -ETIMEDOUT;
}

static void qdx_frequency_event(void *object, u32 opcode, u32 response, u32 error,
				const void *payload, size_t received, size_t declared)
{
	struct qdx_core *core = object;
	const struct qdx_frequency *event = payload;
	int result = 0;

	if (opcode != QDX_FREQUENCY_ACK)
		return;
	if (declared < sizeof(*event) || received < declared ||
	    (response != QDX_RESPONSE_ACK && response != QDX_RESPONSE_NOTIFY)) {
		result = -EPROTO;
	} else if (le32_to_cpu(event->ack) != READ_ONCE(core->frequency_step)) {
		return; /* A started/duplicate event cannot finish the end step. */
	} else if (le32_to_cpu(event->ack) != 1) {
		return;
	} else if (le32_to_cpu(event->current_frequency) != QDX_CLOCK_RATE) {
		result = -ERANGE;
	}
	WRITE_ONCE(core->frequency_error, result);
	if (!result)
		smp_store_release(&core->frequency_ready, true);
	complete_all(&core->frequency_done);
}

static int qdx_frequency_initialize(struct qdx *qdx)
{
	static const struct qdx_receive_ops ops = { .message = qdx_frequency_event };
	struct qdx_frequency message = { .frequency = cpu_to_le32(QDX_CLOCK_RATE) };
	struct qdx_service *service = &qdx->services[QDX_SERVICE_ETHERNET];
	struct qdx_endpoint *endpoint;
	struct qdx_core *core;
	struct qdx_owner owner = { .module = THIS_MODULE };
	unsigned long deadline;
	unsigned int i, step;
	int error;

	for (i = 0; i < QDX_CORES; i++) {
		core = &qdx->cores[i];
		endpoint = qdx_endpoint_static(service, i, QDX_IF_FREQUENCY);
		if (IS_ERR(endpoint))
			return PTR_ERR(endpoint);
		owner.object = core;
		core->frequency_receiver = qdx_endpoint_receive_register(endpoint,
						QDX_RECEIVE_MESSAGE, &owner, &ops);
		qdx_endpoint_put(endpoint);
		if (IS_ERR(core->frequency_receiver)) {
			error = PTR_ERR(core->frequency_receiver);
			core->frequency_receiver = NULL;
			return error;
		}
		WRITE_ONCE(core->frequency_error, -EINPROGRESS);
	}
	for (step = 0; step < 2; step++) {
		message.step = cpu_to_le32(step);
		for (i = 0; i < QDX_CORES; i++) {
			core = &qdx->cores[i];
			WRITE_ONCE(core->frequency_step, step);
			error = qdx_message_core(core, QDX_IF_FREQUENCY,
						QDX_FREQUENCY_CHANGE, &message, sizeof(message));
			if (error)
				return error;
		}
	}
	deadline = jiffies + msecs_to_jiffies(3000);
	for (i = 0; i < QDX_CORES; i++) {
		core = &qdx->cores[i];
		if (!completion_done(&core->frequency_done) && time_before(jiffies, deadline))
			wait_for_completion_timeout(&core->frequency_done, deadline - jiffies);
		dev_info(qdx->dev, "core %u frequency %u ready=%u error=%d\n", i,
			 QDX_CLOCK_RATE, READ_ONCE(core->frequency_ready),
			 READ_ONCE(core->frequency_error));
	}
	/* Phase 2 services use core0; core1 retains its independently observed
	 * status. Sending a message is never its completion certificate.
	 */
	return smp_load_acquire(&qdx->cores[0].frequency_ready) ? 0 :
		(READ_ONCE(qdx->cores[0].frequency_error) == -EINPROGRESS ?
		 -ETIMEDOUT : READ_ONCE(qdx->cores[0].frequency_error));
}

static void qdx_terminal_stop(struct qdx *qdx)
{
	int hold_error = 0, restore_error, activate_error = 0;
	unsigned int i;

	if (READ_ONCE(qdx->state) == QDX_TERMINAL)
		return;
	WRITE_ONCE(qdx->state, QDX_STOPPING);
	spin_lock_bh(&qdx->io_admission);
	qdx->io_closing = true;
	spin_unlock_bh(&qdx->io_admission);
	qdx_endpoints_close(qdx);
	for (i = 0; i < QDX_CORES; i++)
		qdx_io_close(&qdx->cores[i]);
	for (i = 0; i < QDX_CORES; i++)
		qdx_commands_stop(&qdx->cores[i]);
	if (qdx->execution_possible)
		hold_error = qdx_hw_stop(qdx);
	/* Published carriers have their own ownership. Unpublished preparation
	 * must leave before terminal code can reclaim the carrier arena.
	 */
	wait_event(qdx->io_drained, !atomic_read(&qdx->io_callers));
	spin_lock_bh(&qdx->io_admission);
	spin_unlock_bh(&qdx->io_admission);
	qdx_services_notify(qdx);
	/* Immediate execution hold precedes RTNL-dependent native cleanup. */
	qdx_ethernet_stop(qdx);
	for (i = 0; i < QDX_CORES; i++)
		qdx_io_stop(&qdx->cores[i]);

	/* Native restore performs its real reset/rebuild, never a full PPE probe. */
	restore_error = hold_error ? hold_error : qdx_ethernet_restore(qdx);
	smp_store_release(&qdx->access_ended, !qdx->execution_possible ||
			  (!hold_error && !restore_error));
	if (qdx->access_ended) {
		for (i = 0; i < QDX_CORES; i++)
			qdx_commands_access_end(&qdx->cores[i]);
		qdx_endpoints_access_end(qdx);
		for (i = 0; i < QDX_CORES; i++) {
			qdx_endpoint_receive_unregister(qdx->cores[i].frequency_receiver);
			qdx->cores[i].frequency_receiver = NULL;
		}
		qdx_dma_end_all(qdx);
		qdx_services_notify(qdx);
	}
	mutex_lock(&qdx->receive_drain);
	for (i = 0; i < QDX_CORES; i++)
		qdx_io_release(&qdx->cores[i], qdx->access_ended);
	mutex_unlock(&qdx->receive_drain);
	/* Resolve old accepted charges before native queue activation. */
	if (!restore_error)
		activate_error = qdx_ethernet_activate(qdx);
	/* The bound instance still owns the native port registrations. Their
	 * final reference drain belongs to native/platform removal, not this
	 * progress worker: peers may need a later notification to finish.
	 */
	qdx_mem_release(qdx, qdx->access_ended);
	if (!qdx->execution_possible)
		qdx_hw_unprepare(qdx);
	dev_err(qdx->dev, "NSS terminal: cause %d, hold %d, restore %d, activate %d, storage %s\n",
		atomic_read(&qdx->failure), hold_error, restore_error, activate_error,
		qdx->access_ended ? "released" : "quarantined");
	WRITE_ONCE(qdx->state, QDX_TERMINAL);
	complete_all(&qdx->terminal_done);
}

static void qdx_lifecycle(struct work_struct *work)
{
	struct qdx *qdx = container_of(work, struct qdx, lifecycle);
	struct qdx_ddr_info ddr;
	struct qdx_c2c_map peer;
	struct qdx_reply reply;
	unsigned int i;
	bool coordinated = false;
	int err;

	if (READ_ONCE(qdx->state) == QDX_TERMINAL) {
		qdx_services_notify(qdx);
		return;
	}
	if (atomic_read(&qdx->failure)) {
		qdx_terminal_stop(qdx);
		return;
	}
	if (READ_ONCE(qdx->state) != QDX_WAITING || !qdx_ethernet_ready(qdx))
		return;
	WRITE_ONCE(qdx->state, QDX_STARTING);
	err = qdx_ddr_info(qdx, &ddr);
	if (err)
		goto failed;
	err = qdx_hw_prepare(qdx);
	if (err)
		goto failed;
	err = qdx_mem_prepare(qdx);
	if (err)
		goto failed;
	err = qdx_ethernet_prepare(qdx);
	if (err)
		goto failed;
	coordinated = true;
	for (i = 0; i < QDX_CORES; i++)
		qdx_io_enable(&qdx->cores[i]);
	err = atomic_read(&qdx->failure);
	if (err)
		goto failed;
	if (atomic_cmpxchg(&qdx_boot_attempted, 0, 1)) {
		err = -EALREADY;
		goto failed;
	}
	qdx->execution_possible = true;
	for (i = 0; i < QDX_CORES; i++) {
		err = qdx_hw_start_core(&qdx->cores[i]);
		if (err)
			goto failed;
	}
	err = qdx_wait_maps(qdx);
	if (err)
		goto failed;
	for (i = 0; i < QDX_CORES; i++) {
		err = qdx_common_initialize(&qdx->cores[i], &ddr);
		if (err)
			goto failed;
	}
	for (i = 0; i < QDX_CORES; i++) {
		struct qdx_core *other = &qdx->cores[i ^ 1];

		peer.address = cpu_to_le32(other->c2c_dma);
		peer.interrupt = cpu_to_le32(other->csm_phys + 0x18);
		reply = (struct qdx_reply) { .max_len = sizeof(peer) };
		err = qdx_command(&qdx->cores[i], QDX_IF_C2C_TX, QDX_C2C_MAP,
				  &peer, sizeof(peer), &reply);
		if (err)
			goto failed;
		WRITE_ONCE(qdx->cores[i].peer_ready, true);
	}
	err = atomic_read(&qdx->failure);
	if (err)
		goto failed;
	err = qdx_frequency_initialize(qdx);
	if (err)
		goto failed;
	err = qdx_ethernet_start(qdx); /* Always releases startup coordination. */
	coordinated = false;
	if (err)
		goto failed;
	err = atomic_read(&qdx->failure);
	if (err)
		goto failed;
	smp_store_release(&qdx->state, QDX_READY);
	qdx_services_notify(qdx);
	qdx_ethernet_progress(qdx);
	dev_info(qdx->dev, "both NSS cores ready; native wired transport selected\n");
	return;
failed:
	atomic_cmpxchg(&qdx->failure, 0, err ?: -EIO);
	if (coordinated)
		qdx_ethernet_unlock(qdx);
	qdx_terminal_stop(qdx);
}

static ssize_t state_show(struct device *dev, struct device_attribute *attribute, char *buffer)
{
	static const char * const names[] = { "waiting", "starting", "ready", "stopping", "terminal" };
	struct qdx *qdx = dev_get_drvdata(dev);
	enum qdx_state state = READ_ONCE(qdx->state);

	return sysfs_emit(buffer,
		"%s error=%d attempted=%d execution_possible=%u access_ended=%u "
		"native_rx_entries=%u tx_slots=%u rx_dma_limit_bytes=%lu rx_memory_limit_bytes=%lu "
		"rx_dma_used_bytes=%ld rx_memory_charged_bytes=%ld\n",
		names[state], atomic_read(&qdx->failure), atomic_read(&qdx_boot_attempted),
		READ_ONCE(qdx->execution_possible), READ_ONCE(qdx->access_ended),
		qdx->limits.native_rx_entries, qdx->limits.tx_slots,
		qdx->limits.rx_dma_bytes, qdx->limits.rx_memory_bytes,
		atomic_long_read(&qdx->rx_dma_used),
		atomic_long_read(&qdx->rx_memory_charged));
}
static DEVICE_ATTR_RO(state);

static ssize_t cores_show(struct device *dev, struct device_attribute *attribute, char *buffer)
{
	struct qdx *qdx = dev_get_drvdata(dev);
	unsigned int i;
	ssize_t length = 0;

	for (i = 0; i < QDX_CORES; i++)
		length += sysfs_emit_at(buffer, length, "%u map=%u common=%u peer=%u\n", i,
				       READ_ONCE(qdx->cores[i].map_ready),
				       READ_ONCE(qdx->cores[i].common_ready),
				       READ_ONCE(qdx->cores[i].peer_ready));
	return length;
}
static DEVICE_ATTR_RO(cores);

static struct attribute *qdx_attributes[] = {
	&dev_attr_state.attr,
	&dev_attr_cores.attr,
	NULL,
};

static const struct attribute_group qdx_group = { .attrs = qdx_attributes };
static const struct attribute_group *qdx_groups[] = { &qdx_group, NULL };

/* Flat instance services; readiness does not confer policy authority. */
struct qdx_listener {
	struct list_head node;
	struct qdx_owner owner;
	void (*changed)(void *owner, enum qdx_service_kind kind,
			enum qdx_availability state);
};
static LIST_HEAD(qdx_listeners);
static DEFINE_MUTEX(qdx_listener_lock);
DEFINE_STATIC_SRCU(qdx_listener_srcu);

void qdx_services_init(struct qdx *qdx)
{
	static const u32 interfaces[QDX_SERVICE_COUNT] = {
		[QDX_SERVICE_ETHERNET] = QDX_IF_ETH_RX,
		[QDX_SERVICE_IPV4] = 161,
		[QDX_SERVICE_IPV6] = 163,
		[QDX_SERVICE_PPPOE] = 159,
		[QDX_SERVICE_VLAN] = QDX_IF_DYNAMIC,
		[QDX_SERVICE_SHAPER] = QDX_IF_ETH_RX,
		[QDX_SERVICE_IGS] = QDX_IF_DYNAMIC,
		[QDX_SERVICE_MATCH] = QDX_IF_DYNAMIC,
		[QDX_SERVICE_MIRROR] = QDX_IF_DYNAMIC,
	};
	unsigned int i;

	atomic_set(&qdx->service_users, 0);
	atomic_long_set(&qdx->host_data_used, 0);
	atomic_long_set(&qdx->peer_dma_used, 0);
	init_waitqueue_head(&qdx->services_drained);
	mutex_init(&qdx->receive_drain);
	spin_lock_init(&qdx->io_admission);
	atomic_set(&qdx->io_callers, 0);
	init_waitqueue_head(&qdx->io_drained);
	spin_lock_init(&qdx->resource_lock);
	INIT_LIST_HEAD(&qdx->resource_waits);
	mutex_init(&qdx->region_lock);
	INIT_LIST_HEAD(&qdx->regions);
	for (i = 0; i < QDX_SERVICE_COUNT; i++) {
		qdx->services[i].qdx = qdx;
		qdx->services[i].kind = i;
		qdx->services[i].core = 0;
		qdx->services[i].ifnum = interfaces[i];
	}
	for (i = 0; i < QDX_CORES; i++) {
		xa_init_flags(&qdx->cores[i].endpoints, XA_FLAGS_LOCK_IRQ);
		init_completion(&qdx->cores[i].frequency_done);
	}
}

void qdx_service_hold(struct qdx_service *service)
{
	get_device(service->qdx->dev);
	atomic_inc(&service->qdx->service_users);
}

struct qdx_service *qdx_service_get(struct net_device *dev, enum qdx_service_kind kind)
{
	struct qdx *qdx;

	if (kind >= QDX_SERVICE_COUNT)
		return ERR_PTR(-EOPNOTSUPP);
	qdx = qdx_ethernet_instance_get(dev);
	if (!qdx)
		return ERR_PTR(-ENODEV);
	qdx_service_hold(&qdx->services[kind]);
	qdx_ethernet_instance_put(qdx);
	return &qdx->services[kind];
}
EXPORT_SYMBOL_GPL(qdx_service_get);

void qdx_service_put(struct qdx_service *service)
{
	if (!service)
		return;
	qdx_ethernet_instance_put(service->qdx);
}
EXPORT_SYMBOL_GPL(qdx_service_put);

enum qdx_availability qdx_service_state(const struct qdx_service *service)
{
	struct qdx *qdx = service->qdx;

	if (atomic_read(&qdx->failure))
		return QDX_FAILED;
	if (smp_load_acquire(&qdx->state) != QDX_READY ||
	    !smp_load_acquire(&qdx->cores[service->core].frequency_ready))
		return QDX_NOT_READY;
	return QDX_AVAILABLE;
}
EXPORT_SYMBOL_GPL(qdx_service_state);

bool qdx_service_access_ended(const struct qdx_service *service)
{
	return smp_load_acquire(&service->qdx->access_ended);
}
EXPORT_SYMBOL_GPL(qdx_service_access_ended);

void qdx_services_notify(struct qdx *qdx)
{
	struct qdx_listener *listener;
	unsigned int i;
	int index = srcu_read_lock(&qdx_listener_srcu);

	list_for_each_entry_rcu(listener, &qdx_listeners, node,
			       srcu_read_lock_held(&qdx_listener_srcu)) {
		if (!qdx_owner_get(&listener->owner))
			continue;
		for (i = 0; i < QDX_SERVICE_COUNT; i++)
			listener->changed(listener->owner.object, i,
					  qdx_service_state(&qdx->services[i]));
		qdx_owner_put(&listener->owner);
	}
	srcu_read_unlock(&qdx_listener_srcu, index);
}

struct qdx_listener *qdx_service_listen(const struct qdx_owner *owner,
		void (*changed)(void *owner, enum qdx_service_kind kind,
				enum qdx_availability state))
{
	struct qdx_listener *listener;
	struct qdx *qdx;
	unsigned int i;

	if (!changed || !owner || (!!owner->get != !!owner->put))
		return ERR_PTR(-EINVAL);
	listener = kzalloc(sizeof(*listener), GFP_KERNEL);
	if (!listener)
		return ERR_PTR(-ENOMEM);
	if (owner->get && !owner->get(owner->object)) {
		kfree(listener);
		return ERR_PTR(-ESHUTDOWN);
	}
	listener->owner = *owner;
	listener->changed = changed;
	mutex_lock(&qdx_listener_lock);
	list_add_tail_rcu(&listener->node, &qdx_listeners);
	mutex_unlock(&qdx_listener_lock);
	qdx = qdx_ethernet_instance_get(NULL);
	if (qdx) {
		/* Registration precedes reconciliation. Updates can repeat facts. */
		if (qdx_owner_get(owner)) {
			for (i = 0; i < QDX_SERVICE_COUNT; i++)
				changed(owner->object, i, qdx_service_state(&qdx->services[i]));
			qdx_owner_put(owner);
		}
		qdx_ethernet_instance_put(qdx);
	}
	return listener;
}
EXPORT_SYMBOL_GPL(qdx_service_listen);

void qdx_service_unlisten(struct qdx_listener *listener)
{
	if (!listener)
		return;
	mutex_lock(&qdx_listener_lock);
	list_del_rcu(&listener->node);
	mutex_unlock(&qdx_listener_lock);
	synchronize_srcu(&qdx_listener_srcu);
	if (listener->owner.put)
		listener->owner.put(listener->owner.object);
	kfree(listener);
}
EXPORT_SYMBOL_GPL(qdx_service_unlisten);

void qdx_services_drain(struct qdx *qdx)
{
	unsigned long flags;

	wait_event(qdx->services_drained, !atomic_read(&qdx->service_users));
	spin_lock_irqsave(&qdx->io_admission, flags);
	spin_unlock_irqrestore(&qdx->io_admission, flags);
}

int qdx_stop_execution(struct qdx_service *service, int error)
{
	struct qdx *qdx = service->qdx;
	unsigned int i;

	qdx_fail(qdx, error);
	qdx_endpoints_close(qdx);
	/* The latched failure prevents descriptor publication immediately. The
	 * terminal owner closes/frees IO only after its admitted callers leave.
	 */
	for (i = 0; i < QDX_CORES; i++)
		qdx_commands_stop(&qdx->cores[i]);
	/* Actual hold does not wait for RTNL, another peer or terminal work. */
	return qdx_hw_stop(qdx);
}
EXPORT_SYMBOL_GPL(qdx_stop_execution);

static int qdx_probe(struct platform_device *pdev)
{
	struct qdx_limits limits = {
		.native_rx_entries = native_rx_entries,
		.tx_slots = tx_slots,
	};
	struct qdx *qdx;
	unsigned int i;
	int err;

	if (!limits.native_rx_entries)
		return dev_err_probe(&pdev->dev, -EINVAL, "native_rx_entries must be nonzero\n");
	/* Keep room for control and one initial supply ring of each RX kind. */
	if (!limits.tx_slots ||
	    limits.tx_slots > QDX_SLOTS - QDX_REQUESTS - 2 * (QDX_RING_DEPTH - 1))
		return dev_err_probe(&pdev->dev, -EINVAL, "tx_slots exceeds carrier capacity\n");
	if (!rx_dma_limit_mib ||
	    check_mul_overflow(rx_dma_limit_mib, (unsigned long)SZ_1M,
			       &limits.rx_dma_bytes) || limits.rx_dma_bytes > LONG_MAX)
		return dev_err_probe(&pdev->dev, -EINVAL, "invalid rx_dma_limit_mib\n");
	if (!rx_memory_limit_mib ||
	    check_mul_overflow(rx_memory_limit_mib, (unsigned long)SZ_1M,
			       &limits.rx_memory_bytes) || limits.rx_memory_bytes > LONG_MAX)
		return dev_err_probe(&pdev->dev, -EINVAL, "invalid rx_memory_limit_mib\n");

	if (!host_data_limit_mib ||
	    check_mul_overflow(host_data_limit_mib, (unsigned long)SZ_1M,
			       &limits.host_data_bytes) || limits.host_data_bytes > LONG_MAX)
		return dev_err_probe(&pdev->dev, -EINVAL, "invalid host_data_limit_mib\n");
	if (!peer_dma_limit_mib ||
	    check_mul_overflow(peer_dma_limit_mib, (unsigned long)SZ_1M,
			       &limits.peer_dma_bytes) || limits.peer_dma_bytes > LONG_MAX)
		return dev_err_probe(&pdev->dev, -EINVAL, "invalid peer_dma_limit_mib\n");

	qdx = devm_kzalloc(&pdev->dev, sizeof(*qdx), GFP_KERNEL);
	if (!qdx)
		return -ENOMEM;
	qdx->dev = &pdev->dev;
	qdx->pdev = pdev;
	qdx->state = QDX_WAITING;
	qdx->limits = limits;
	qdx_services_init(qdx);
	atomic_set(&qdx->failure, 0);
	atomic_long_set(&qdx->rx_dma_used, 0);
	atomic_long_set(&qdx->rx_memory_charged, 0);
	init_completion(&qdx->terminal_done);
	INIT_WORK(&qdx->lifecycle, qdx_lifecycle);
	platform_set_drvdata(pdev, qdx);
	for (i = 0; i < QDX_CORES; i++) {
		qdx->cores[i].qdx = qdx;
		qdx->cores[i].id = i;
	}
	err = dma_set_mask_and_coherent(qdx->dev, DMA_BIT_MASK(32));
	if (err)
		return err;
	err = qdx_hw_get(qdx);
	if (err)
		return err;
	qdx->cleanup_queue = alloc_workqueue("qdx-cleanup", WQ_UNBOUND | WQ_MEM_RECLAIM, 0);
	if (!qdx->cleanup_queue)
		return -ENOMEM;
	for (i = 0; i < QDX_CORES; i++) {
		err = qdx_commands_init(&qdx->cores[i]);
		if (err)
			goto release;
		err = qdx_io_init(&qdx->cores[i]);
		if (err)
			goto release;
	}
	err = qdx_ethernet_register(qdx);
	if (err)
		goto release;
	qdx_schedule(qdx);
	return 0;
release:
	for (i = 0; i < QDX_CORES; i++) {
		qdx_io_stop(&qdx->cores[i]);
		qdx_io_release(&qdx->cores[i], true);
		qdx_commands_release(&qdx->cores[i]);
	}
	destroy_workqueue(qdx->cleanup_queue);
	return err;
}

static const struct of_device_id qdx_of_match[] = {
	{ .compatible = "qcom,ipq8074-nss" },
	{}
};
MODULE_DEVICE_TABLE(of, qdx_of_match);

static void qdx_remove(struct platform_device *pdev)
{
	struct qdx *qdx = platform_get_drvdata(pdev);
	unsigned int i;

	qdx_fail(qdx, -ENODEV);
	flush_work(&qdx->lifecycle);
	if (qdx->execution_possible && !qdx->access_ended)
		panic("qdx: platform removal would destroy firmware-accessible resources");
	/* Unpublish native attachments before draining their last schedule request. */
	qdx_ethernet_unregister(qdx);
	cancel_work_sync(&qdx->lifecycle);
	qdx_services_drain(qdx);
	/* A final work item may have released the last endpoint before returning.
	 * Drain the actual executor as well as its retained object references.
	 */
	destroy_workqueue(qdx->cleanup_queue);
	for (i = 0; i < QDX_CORES; i++) {
		qdx_commands_release(&qdx->cores[i]);
		xa_destroy(&qdx->cores[i].endpoints);
	}
	qdx_hw_unprepare(qdx);
}

static struct platform_driver qdx_driver = {
	.probe = qdx_probe,
	.remove = qdx_remove,
	.driver = {
		.name = "qdx-drv",
		.of_match_table = qdx_of_match,
		.suppress_bind_attrs = true,
		.dev_groups = qdx_groups,
	},
};

static int __init qdx_init(void)
{
	return platform_driver_register(&qdx_driver);
}
module_init(qdx_init);

MODULE_DESCRIPTION("Qualcomm NSS execution and wired transport");
MODULE_LICENSE("GPL");
