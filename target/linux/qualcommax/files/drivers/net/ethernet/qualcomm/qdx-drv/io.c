// SPDX-License-Identifier: GPL-2.0-only
/* Shared descriptor transport and host-owned DMA carrier records. */
#include <linux/interrupt.h>
#include <linux/if_vlan.h>
#include <linux/limits.h>
#include <linux/mm.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#include <linux/unaligned.h>
#include <linux/vmalloc.h>

#include "qdx.h"

#define QDX_CHUNK 256U
#define QDX_NO_SLOT U32_MAX
#define QDX_TRANSIT (6 * (QDX_RING_DEPTH - 1))
#define QDX_IRQS 10
#define QDX_EMPTY_RING 0
#define QDX_COMMAND_RING 1
#define QDX_PAGED_RING 2
#define QDX_DATA_RING 3

/* A class reserves capacity; it does not determine the returned wire type. */
enum qdx_carrier_kind { QDX_CONTROL, QDX_TRANSMIT, QDX_LINEAR, QDX_PAGED, QDX_KINDS };
enum qdx_carrier_state { QDX_FREE, QDX_PREPARED, QDX_PUBLISHED, QDX_RETURNING,
			 QDX_QUARANTINED, QDX_RETIRED };

struct qdx_carrier {
	u32 slot;
	u32 generation;
	u32 next;
	enum qdx_carrier_kind kind;
	enum qdx_carrier_state state;
	struct device *dev;
	dma_addr_t dma;
	size_t length;
	unsigned long memory_charge;
	enum dma_data_direction direction;
	bool mapped;
	bool charged;
	bool accepted;
	struct sk_buff *skb;
	struct page *page;
	void *buffer;
	u64 request_id;
	unsigned long host_charge;
	struct qdx_tx_path *path;
	struct qdx_packet_op *operation;
	struct qdx_packet_recipient recipient;
	struct qdx_port *port;
	struct netdev_queue *queue;
	unsigned int bytes;
};

/* One actual completion round. A changed queue flushes the previous run. */
struct qdx_tx_batch {
	struct qdx_port *port;
	struct netdev_queue *queue;
	unsigned int packets;
	unsigned int bytes;
};

struct qdx_supply {
	struct delayed_work work;
	struct qdx_core *core;
	enum qdx_carrier_kind kind;
	u32 target;
	unsigned int backoff;
	atomic_t demand;
	bool pool_known;
};

struct qdx_h2n {
	spinlock_t lock;
	bool closed;
};

struct qdx_irq {
	struct napi_struct napi;
	struct qdx_core *core;
	spinlock_t lock;
	int irq;
	unsigned int purpose;
	bool masked;
	bool active;
	bool drain_requested;
	bool draining;
	u32 drain_remaining;
	struct completion drain_done;
	struct sk_buff *partial;
	struct sk_buff *tail;
	unsigned long partial_charge;
	u8 priority;
};

struct qdx_io {
	struct net_device *napi_dev;
	struct qdx_h2n h2n[QDX_H2N_RINGS];
	struct qdx_irq irq[QDX_IRQS];
	unsigned int irq_count;
	struct mutex allocation_lock;
	spinlock_t carriers_lock;
	struct qdx_carrier *chunks[QDX_SLOTS / QDX_CHUNK];
	u32 slots;
	u32 free_head[QDX_KINDS];
	u32 capacity[QDX_KINDS];
	u32 outstanding[QDX_KINDS];
	struct qdx_supply supply[2];
	unsigned int rx_length;
	unsigned int max_frame;
	bool running;
	bool closed;
	atomic64_t published;
	atomic64_t returned;
	atomic64_t faults;
	atomic64_t dropped;
};

/* Actual calls retain the arena through preparation and producer publication.
 * Endpoint/path refs alone retain the instance, not this arena's allocation.
 */
static bool qdx_io_enter(struct qdx *qdx)
{
	unsigned long flags;
	bool admitted;

	spin_lock_irqsave(&qdx->io_admission, flags);
	admitted = !qdx->io_closing && !atomic_read(&qdx->failure);
	if (admitted)
		atomic_inc(&qdx->io_callers);
	spin_unlock_irqrestore(&qdx->io_admission, flags);
	return admitted;
}

static void qdx_io_leave(struct qdx *qdx)
{
	unsigned long flags;

	spin_lock_irqsave(&qdx->io_admission, flags);
	if (atomic_dec_and_test(&qdx->io_callers))
		wake_up_all(&qdx->io_drained);
	spin_unlock_irqrestore(&qdx->io_admission, flags);
}

/* Chunk pointers never change while the instance can receive a return. */
static struct qdx_carrier *qdx_slot(struct qdx_io *io, u32 slot)
{
	struct qdx_carrier *chunk = READ_ONCE(io->chunks[slot / QDX_CHUNK]);

	return chunk ? &chunk[slot % QDX_CHUNK] : NULL;
}

static int qdx_slots_grow(struct qdx_core *core, enum qdx_carrier_kind kind,
			  unsigned int count)
{
	struct qdx_io *io = core->io;
	struct qdx_carrier *record, *chunk;
	unsigned long flags;
	u32 slot, limit;
	int err = 0;

	mutex_lock(&io->allocation_lock);
	if (count <= io->capacity[kind])
		goto out;
	if (count - io->capacity[kind] > QDX_SLOTS - io->slots) {
		err = -ENOSPC;
		goto out;
	}
	limit = io->slots + count - io->capacity[kind];
	while (io->slots < limit) {
		slot = io->slots;
		if (!io->chunks[slot / QDX_CHUNK]) {
			chunk = kvcalloc(QDX_CHUNK, sizeof(*chunk), GFP_KERNEL);
			if (!chunk) {
				err = -ENOMEM;
				break;
			}
			WRITE_ONCE(io->chunks[slot / QDX_CHUNK], chunk);
		}
		record = qdx_slot(io, slot);
		record->slot = slot;
		record->generation = 1;
		record->kind = kind;
		record->state = QDX_FREE;
		spin_lock_irqsave(&io->carriers_lock, flags);
		record->next = io->free_head[kind];
		io->free_head[kind] = slot;
		io->capacity[kind]++;
		io->slots++;
		spin_unlock_irqrestore(&io->carriers_lock, flags);
	}
 out:
	mutex_unlock(&io->allocation_lock);
	return err;
}

static struct qdx_carrier *qdx_carrier_get(struct qdx_core *core,
					 enum qdx_carrier_kind kind)
{
	struct qdx_io *io = core->io;
	struct qdx_carrier *record = NULL;
	unsigned long flags;
	u32 slot;

	spin_lock_irqsave(&io->carriers_lock, flags);
	slot = io->free_head[kind];
	if (!io->closed && slot != QDX_NO_SLOT) {
		record = qdx_slot(io, slot);
		io->free_head[kind] = record->next;
		record->state = QDX_PREPARED;
		record->dev = core->qdx->dev;
		io->outstanding[kind]++;
	}
	spin_unlock_irqrestore(&io->carriers_lock, flags);
	return record;
}

static void qdx_tx_batch_complete(struct qdx_tx_batch *batch)
{
	struct qdx_edma *edma;

	if (!batch->packets)
		return;
	edma = batch->port->qdx->ethernet->edma;
	edma->info.ops->complete_tx(edma->info.context, batch->queue,
				    batch->packets, batch->bytes);
	qdx_port_put(batch->port);
	*batch = (struct qdx_tx_batch) {};
}

/* Capture the exact accepted observation before releasing its carrier refs. */
static void qdx_tx_batch_add(struct qdx_tx_batch *batch, struct qdx_carrier *record)
{
	if (!record->charged)
		return;
	if (batch->packets && batch->queue != record->queue)
		qdx_tx_batch_complete(batch);
	if (!batch->packets) {
		refcount_inc(&record->port->refs);
		batch->port = record->port;
		batch->queue = record->queue;
	}
	batch->packets++;
	batch->bytes += record->bytes;
	record->charged = false;
}

/* Also used for unsubmitted work: the caller retains its packet/command. */
static void qdx_carrier_put(struct qdx_core *core, struct qdx_carrier *record,
			    bool free_storage)
{
	struct qdx_io *io = core->io;
	enum qdx_carrier_kind kind = record->kind;
	unsigned long flags;

	if (record->mapped) {
		if (kind == QDX_PAGED)
			dma_unmap_page(record->dev, record->dma, record->length,
				       record->direction);
		else
			dma_unmap_single(record->dev, record->dma, record->length,
					 record->direction);
		record->mapped = false;
	}
	WARN_ON_ONCE(record->charged); /* Accepted returns first join their batch. */
	if (record->accepted) {
		/* DMA and the original returned callback ended before this point. */
		spin_lock_irqsave(&core->qdx->io_admission, flags);
		if (record->path)
			record->path->accepted--;
		else
			record->operation->accepted--;
		spin_unlock_irqrestore(&core->qdx->io_admission, flags);
		record->accepted = false;
	}
	if (record->host_charge) {
		atomic_long_sub(record->host_charge, &core->qdx->host_data_used);
		record->host_charge = 0;
	}
	if (record->path) {
		qdx_tx_path_put(record->path);
		record->path = NULL;
	}
	if (record->operation) {
		struct qdx_endpoint *endpoint = record->operation->endpoint;

		/* Rejected preparation has no accepted loan; a published disposal
		 * clears recipient before reaching this common resource release.
		 */
		atomic_dec(&endpoint->operations);
		wake_up_all(&endpoint->drained);
		qdx_owner_put(&record->recipient.owner);
		qdx_packet_op_put(record->operation);
		record->operation = NULL;
	}
	if (record->port) {
		qdx_port_put(record->port);
		record->port = NULL;
	}
	if (free_storage) {
		dev_kfree_skb_any(record->skb);
		if (record->page)
			__free_page(record->page);
		kfree(record->buffer);
	}
	if (kind == QDX_LINEAR || kind == QDX_PAGED)
		atomic_long_sub(record->length, &core->qdx->rx_dma_used);
	atomic_long_sub(record->memory_charge, &core->qdx->rx_memory_charged);
	WRITE_ONCE(record->memory_charge, 0);
	record->skb = NULL;
	record->page = NULL;
	record->buffer = NULL;
	record->queue = NULL;
	record->request_id = 0;
	record->length = 0;
	spin_lock_irqsave(&io->carriers_lock, flags);
	io->outstanding[kind]--;
	if (record->generation == U32_MAX) {
		record->state = QDX_RETIRED;
	} else {
		record->generation++;
		record->state = QDX_FREE;
		record->next = io->free_head[kind];
		io->free_head[kind] = record->slot;
	}
	spin_unlock_irqrestore(&io->carriers_lock, flags);
	if (kind == QDX_TRANSMIT && free_storage)
		qdx_resource_progress(core, QDX_RESOURCE_CARRIER | QDX_RESOURCE_HOST_BYTES);
}

static int qdx_carrier_map(struct qdx_carrier *record)
{
	if (record->kind == QDX_PAGED)
		record->dma = dma_map_page(record->dev, record->page, 0,
					   record->length, record->direction);
	else
		record->dma = dma_map_single(record->dev,
			record->skb ? record->skb->head : record->buffer,
			record->length, record->direction);
	if (dma_mapping_error(record->dev, record->dma))
		return -EIO;
	record->mapped = true;
	if ((u64)record->dma + record->length > BIT_ULL(32))
		return -ERANGE;
	return 0;
}

/* Producer publication is the sole ownership-transfer point. */
static int qdx_publish(struct qdx_core *core, unsigned int ring_id,
		       struct qdx_carrier *record, struct qdx_h2n_desc *desc)
{
	struct qdx_io *io = core->io;
	struct qdx_h2n *ring = &io->h2n[ring_id];
	unsigned long flags;
	u32 producer, consumer;
	int err = 0;

	spin_lock_irqsave(&ring->lock, flags);
	if (ring->closed || atomic_read(&core->qdx->failure) ||
	    !smp_load_acquire(&core->map_ready) ||
	    (record->port && !smp_load_acquire(&record->port->available)) ||
	    (record->path && (!smp_load_acquire(&record->path->open) ||
		!smp_load_acquire(&record->path->endpoint->producers_open))) ||
	    (record->operation && (!smp_load_acquire(&record->operation->open) ||
		!smp_load_acquire(&record->operation->endpoint->producers_open)))) {
		err = -ESHUTDOWN;
		goto unlock;
	}
	producer = le32_to_cpu(READ_ONCE(core->map->h2n_host[ring_id]));
	consumer = le32_to_cpu(READ_ONCE(core->map->h2n_firmware[ring_id]));
	if (producer >= QDX_RING_DEPTH || consumer >= QDX_RING_DEPTH) {
		err = -EPROTO;
		goto unlock;
	}
	if (((producer + 1) & (QDX_RING_DEPTH - 1)) == consumer) {
		err = -ENOSPC;
		goto unlock;
	}
	dma_rmb();
	desc->opaque = cpu_to_le64(((u64)record->generation << 32) |
				 ((u64)core->id << 31) | record->slot);
	desc->buffer = cpu_to_le32(record->dma);
	desc->buffer_len = cpu_to_le16(record->length);
	if (record->kind == QDX_CONTROL) {
		err = qdx_command_publish(core, record->request_id);
		if (err)
			goto unlock;
	}
	if (record->path || record->operation) {
		spin_lock(&core->qdx->io_admission);
		if (core->qdx->io_closing || atomic_read(&core->qdx->failure) ||
		    (record->path && !record->path->open) ||
		    (record->operation && !record->operation->open)) {
			spin_unlock(&core->qdx->io_admission);
			err = -ESHUTDOWN;
			goto unlock;
		}
		if (record->path)
			record->path->accepted++;
		else
			record->operation->accepted++;
		record->accepted = true;
		spin_unlock(&core->qdx->io_admission);
		/* No fallible step remains before producer publication. */
	}
	spin_lock(&io->carriers_lock);
	record->state = QDX_PUBLISHED;
	spin_unlock(&io->carriers_lock);
	if (record->queue) {
		skb_tx_timestamp(record->skb);
		dev_sw_netstats_tx_add(record->port->conduit, 1, record->bytes);
		netdev_tx_sent_queue(record->queue, record->bytes);
		record->charged = true;
	}
	core->h2n_desc[ring_id][producer] = *desc;
	dma_wmb();
	WRITE_ONCE(core->map->h2n_host[ring_id],
		   cpu_to_le32((producer + 1) & (QDX_RING_DEPTH - 1)));
	atomic64_inc(&io->published);
 unlock:
	spin_unlock_irqrestore(&ring->lock, flags);
	if (err == -EPROTO)
		qdx_fail(core->qdx, err);
	if (!err)
		qdx_hw_notify(core, ring_id == QDX_EMPTY_RING ? QDX_DB_EMPTY :
			      ring_id == QDX_PAGED_RING ? QDX_DB_PAGED : QDX_DB_COMMAND);
	/* A return may already have freed record. Never touch it here. */
	return err;
}

int qdx_io_command(struct qdx_core *core, void *buffer, size_t length, u64 id)
{
	struct qdx_h2n_desc desc = { .type = QDX_H2N_CTRL };
	struct qdx_carrier *record;
	int err;

	if (length > QDX_COMMAND_SIZE)
		return -EMSGSIZE;
	if (!qdx_io_enter(core->qdx))
		return -ESHUTDOWN;
	record = qdx_carrier_get(core, QDX_CONTROL);
	if (!record) {
		err = -ENOSPC;
		goto leave;
	}
	record->buffer = buffer;
	record->length = QDX_COMMAND_SIZE;
	record->direction = DMA_BIDIRECTIONAL;
	record->request_id = id;
	desc.flags = cpu_to_le16(QDX_DESC_FIRST | QDX_DESC_LAST | QDX_DESC_REUSABLE);
	desc.payload_len = cpu_to_le16(QDX_COMMAND_SIZE);
	err = qdx_carrier_map(record);
	if (!err)
		err = qdx_publish(core, QDX_COMMAND_RING, record, &desc);
	if (err)
		qdx_carrier_put(core, record, false);
leave:
	qdx_io_leave(core->qdx);
	return err;
}

/* Wait storage belongs to an actual native queue, not a policy registry. */
static DECLARE_WAIT_QUEUE_HEAD(qdx_resource_drained);

static void qdx_resource_wait_put(struct qdx_resource_wait *wait)
{
	struct qdx_owner owner = wait->owner;
	struct qdx_endpoint *endpoint = wait->endpoint;
	struct qdx *qdx = endpoint->service->qdx;
	unsigned long flags;
	bool last;

	/* Final release and rearm serialize over the same actual resource scope.
	 * No embedded storage is touched once zero permits the owner to reuse it.
	 */
	spin_lock_irqsave(&qdx->resource_lock, flags);
	last = refcount_dec_and_test(&wait->calls);
	spin_unlock_irqrestore(&qdx->resource_lock, flags);
	if (!last)
		return;
	qdx_endpoint_put(endpoint);
	qdx_owner_put(&owner);
	wake_up_all(&qdx_resource_drained);
}

static void qdx_resource_wait_arm(struct qdx_endpoint *endpoint,
				  struct qdx_resource_wait *wait, unsigned int resources)
{
	struct qdx *qdx = endpoint->service->qdx;
	unsigned long flags;
	bool notify = false;

	spin_lock_irqsave(&qdx->resource_lock, flags);
	if (wait->armed) {
		notify = (resources & QDX_RESOURCE_DESCRIPTOR) &&
			 !(wait->resources & QDX_RESOURCE_DESCRIPTOR);
		wait->resources = resources;
		goto out;
	}
	if (WARN_ON_ONCE(qdx->last_resource_wait == U64_MAX))
		goto out;
	if (refcount_read(&wait->calls)) {
		/* Credits belong to the core, not the physical endpoint. The held
		 * endpoint only keeps that resource scope alive until calls drain.
		 */
		if (WARN_ON_ONCE(wait->endpoint->core != endpoint->core))
			goto out;
		refcount_inc(&wait->calls);
	} else {
		if (!qdx_owner_get(&wait->owner))
			goto out;
		qdx_endpoint_hold(endpoint);
		wait->endpoint = endpoint;
		refcount_set(&wait->calls, 1);
	}
	wait->resources = resources;
	wait->serial = ++qdx->last_resource_wait;
	wait->armed = true;
	list_add_tail(&wait->node, &qdx->resource_waits);
	notify = resources & QDX_RESOURCE_DESCRIPTOR;
out:
	spin_unlock_irqrestore(&qdx->resource_lock, flags);
	if (notify)
		qdx_hw_notify(endpoint->core, QDX_DB_UNBLOCKED);
}

void qdx_tx_wait_arm(struct qdx_tx_path *path, struct qdx_resource_wait *wait,
		     unsigned int resources)
{
	qdx_resource_wait_arm(path->endpoint, wait, resources);
}
EXPORT_SYMBOL_GPL(qdx_tx_wait_arm);

void qdx_packet_op_wait_arm(struct qdx_packet_op *operation,
			   struct qdx_resource_wait *wait, unsigned int resources)
{
	qdx_resource_wait_arm(operation->endpoint, wait, resources);
}
EXPORT_SYMBOL_GPL(qdx_packet_op_wait_arm);

void qdx_resource_wait_disarm(struct qdx_resource_wait *wait)
{
	struct qdx *qdx;
	unsigned long flags;
	bool detached = false;

	/* The actual queue owner serializes arm/disarm; admitted callbacks have
	 * their own refs. A zero count has no retained endpoint to dereference.
	 */
	if (!READ_ONCE(wait->armed))
		return;
	qdx = wait->endpoint->service->qdx;
	spin_lock_irqsave(&qdx->resource_lock, flags);
	if (wait->armed) {
		list_del_init(&wait->node);
		wait->armed = false;
		detached = true;
	}
	spin_unlock_irqrestore(&qdx->resource_lock, flags);
	if (detached)
		qdx_resource_wait_put(wait);
}
EXPORT_SYMBOL_GPL(qdx_resource_wait_disarm);

void qdx_resource_wait_drain(struct qdx_resource_wait *wait)
{
	qdx_resource_wait_disarm(wait);
	wait_event(qdx_resource_drained, !refcount_read(&wait->calls));
}
EXPORT_SYMBOL_GPL(qdx_resource_wait_drain);

void qdx_resource_progress(struct qdx_core *core, unsigned int resources)
{
	struct qdx *qdx = core->qdx;
	struct qdx_resource_wait *wait, *found;
	unsigned long flags;
	u64 cursor = 0, limit;

	spin_lock_irqsave(&qdx->resource_lock, flags);
	limit = qdx->last_resource_wait;
	spin_unlock_irqrestore(&qdx->resource_lock, flags);
	for (;;) {
		found = NULL;
		spin_lock_irqsave(&qdx->resource_lock, flags);
		list_for_each_entry(wait, &qdx->resource_waits, node) {
			unsigned int relevant = resources;

			if (wait->serial <= cursor || wait->serial > limit)
				continue;
			cursor = wait->serial;
			if (wait->endpoint->core != core)
				relevant &= QDX_RESOURCE_HOST_BYTES;
			if (!(wait->resources & relevant))
				continue;
			refcount_inc(&wait->calls);
			found = wait;
			break;
		}
		spin_unlock_irqrestore(&qdx->resource_lock, flags);
		if (!found)
			return;
		found->progress(found->owner.object);
		qdx_resource_wait_put(found);
	}
}

/* Packet readiness reserves nothing; publication repeats its admission check. */
static struct qdx_ready qdx_data_ready(struct qdx_endpoint *endpoint, size_t charge)
{
	struct qdx_core *core = endpoint->core;
	struct qdx *qdx = core->qdx;
	struct qdx_io *io = READ_ONCE(core->io);
	struct qdx_ready ready = { .status = QDX_CLOSED, .error = -ESHUTDOWN };
	unsigned long flags;
	u32 producer, consumer;

	if (!io || !qdx_endpoint_command_ready(endpoint))
		return ready;
	if (charge > qdx->limits.host_data_bytes)
		return (struct qdx_ready) { .status = QDX_REFUSED, .error = -EMSGSIZE };
	spin_lock_irqsave(&io->h2n[QDX_DATA_RING].lock, flags);
	producer = le32_to_cpu(READ_ONCE(core->map->h2n_host[QDX_DATA_RING]));
	consumer = le32_to_cpu(READ_ONCE(core->map->h2n_firmware[QDX_DATA_RING]));
	if (producer >= QDX_RING_DEPTH || consumer >= QDX_RING_DEPTH) {
		ready.error = -EPROTO;
		goto out;
	}
	if (io->h2n[QDX_DATA_RING].closed)
		goto out;
	if (((producer + 1) & (QDX_RING_DEPTH - 1)) == consumer)
		ready.resources |= QDX_RESOURCE_DESCRIPTOR;
	spin_lock(&io->carriers_lock);
	if (io->free_head[QDX_TRANSMIT] == QDX_NO_SLOT)
		ready.resources |= QDX_RESOURCE_CARRIER;
	spin_unlock(&io->carriers_lock);
	if (charge > qdx->limits.host_data_bytes - atomic_long_read(&qdx->host_data_used))
		ready.resources |= QDX_RESOURCE_HOST_BYTES;
	ready.status = ready.resources ? QDX_RESOURCE_WAIT : QDX_ACCEPTED;
	ready.error = ready.resources ? -ENOSPC : 0;
out:
	spin_unlock_irqrestore(&io->h2n[QDX_DATA_RING].lock, flags);
	if (ready.error == -EPROTO)
		qdx_fail(qdx, ready.error);
	return ready;
}

struct qdx_ready qdx_tx_ready(struct qdx_tx_path *path, size_t charge)
{
	struct qdx *qdx = path->endpoint->service->qdx;
	struct qdx_ready ready = { .status = QDX_CLOSED, .error = -ESHUTDOWN };

	if (!smp_load_acquire(&path->open) || !qdx_io_enter(qdx))
		return ready;
	ready = qdx_data_ready(path->endpoint, charge);
	qdx_io_leave(qdx);
	return ready;
}

EXPORT_SYMBOL_GPL(qdx_tx_ready);

struct qdx_ready qdx_packet_op_ready(struct qdx_packet_op *operation, size_t charge)
{
	struct qdx *qdx = operation->endpoint->service->qdx;
	struct qdx_ready ready = { .status = QDX_CLOSED, .error = -ESHUTDOWN };

	if (!smp_load_acquire(&operation->open) || !qdx_io_enter(qdx))
		return ready;
	ready = qdx_data_ready(operation->endpoint, charge);
	qdx_io_leave(qdx);
	return ready;
}

EXPORT_SYMBOL_GPL(qdx_packet_op_ready);

/* The retained object outlives this query; no IO arena access is required. */
bool qdx_tx_drained(struct qdx_tx_path *path)
{
	struct qdx *qdx = path->endpoint->service->qdx;
	unsigned long flags;
	bool drained;

	spin_lock_irqsave(&qdx->io_admission, flags);
	drained = !path->open && !path->accepted;
	spin_unlock_irqrestore(&qdx->io_admission, flags);
	return drained;
}
EXPORT_SYMBOL_GPL(qdx_tx_drained);

bool qdx_packet_op_drained(struct qdx_packet_op *operation)
{
	struct qdx *qdx = operation->endpoint->service->qdx;
	unsigned long flags;
	bool drained;

	spin_lock_irqsave(&qdx->io_admission, flags);
	drained = !operation->open && !operation->accepted;
	spin_unlock_irqrestore(&qdx->io_admission, flags);
	return drained;
}
EXPORT_SYMBOL_GPL(qdx_packet_op_drained);

static bool qdx_host_reserve(struct qdx *qdx, unsigned long charge)
{
	long used = atomic_long_read(&qdx->host_data_used), old;

	for (;;) {
		if (charge > qdx->limits.host_data_bytes - used)
			return false;
		old = atomic_long_cmpxchg(&qdx->host_data_used, used, used + charge);
		if (old == used)
			return true;
		used = old;
	}
}

static struct qdx_carrier *qdx_packet_prepare(struct qdx_endpoint *endpoint,
					    struct sk_buff *skb, struct qdx_ready *ready)
{
	struct qdx_carrier *record;

	if (skb_is_nonlinear(skb) || skb->len < ETH_HLEN || skb->len > U16_MAX ||
	    skb_headroom(skb) > U16_MAX - skb_headlen(skb)) {
		*ready = (struct qdx_ready) { .status = QDX_REFUSED, .error = -EMSGSIZE };
		return NULL;
	}
	*ready = qdx_data_ready(endpoint, skb->truesize);
	if (ready->status != QDX_ACCEPTED)
		return NULL;
	record = qdx_carrier_get(endpoint->core, QDX_TRANSMIT);
	if (!record) {
		*ready = (struct qdx_ready) { .status = QDX_RESOURCE_WAIT,
			.resources = QDX_RESOURCE_CARRIER, .error = -ENOSPC };
		return NULL;
	}
	if (!qdx_host_reserve(endpoint->service->qdx, skb->truesize)) {
		qdx_carrier_put(endpoint->core, record, false);
		*ready = (struct qdx_ready) { .status = QDX_RESOURCE_WAIT,
			.resources = QDX_RESOURCE_HOST_BYTES, .error = -ENOSPC };
		return NULL;
	}
	record->host_charge = skb->truesize;
	record->skb = skb;
	record->length = skb_headroom(skb) + skb_headlen(skb);
	return record;
}

static struct qdx_ready qdx_packet_publish(struct qdx_endpoint *endpoint,
					   struct qdx_carrier *record, u32 class_tag, u8 type)
{
	struct qdx_h2n_desc desc = {
		.interface = cpu_to_le32(endpoint->ifnum),
		.type = type,
		.qos = cpu_to_le32(class_tag),
		.payload_off = cpu_to_le16(skb_headroom(record->skb)),
		.payload_len = cpu_to_le16(record->skb->len),
		.flags = cpu_to_le16(QDX_DESC_FIRST | QDX_DESC_LAST | QDX_DESC_NO_CSUM),
	};
	int error;

	error = qdx_carrier_map(record);
	if (!error)
		error = qdx_publish(endpoint->core, QDX_DATA_RING, record, &desc);
	if (!error)
		return (struct qdx_ready) { .status = QDX_ACCEPTED };
	qdx_carrier_put(endpoint->core, record, false);
	return (struct qdx_ready) {
		.status = error == -ENOSPC ? QDX_RESOURCE_WAIT :
			error == -ESHUTDOWN ? QDX_CLOSED : QDX_REFUSED,
		.resources = error == -ENOSPC ? QDX_RESOURCE_DESCRIPTOR : 0,
		.error = error,
	};
}

struct qdx_ready qdx_xmit(struct qdx_tx_path *path, struct sk_buff *skb,
		struct qdx_tx_class class, struct netdev_queue *queue, unsigned int bytes)
{
	struct qdx *qdx = path->endpoint->service->qdx;
	struct qdx_carrier *record;
	struct qdx_ready ready;

	if (!smp_load_acquire(&path->open) || class.token != path->class.token ||
	    class.tag != path->class.tag)
		return (struct qdx_ready) { .status = QDX_CLOSED, .error = -ESTALE };
	if (!queue || queue->dev != path->port->conduit)
		return (struct qdx_ready) { .status = QDX_REFUSED, .error = -EINVAL };
	if (!qdx_io_enter(qdx))
		return (struct qdx_ready) { .status = QDX_CLOSED, .error = -ESHUTDOWN };
	record = qdx_packet_prepare(path->endpoint, skb, &ready);
	if (!record)
		goto leave;
	qdx_tx_path_get(path);
	record->path = path;
	refcount_inc(&path->port->refs);
	record->port = path->port;
	record->queue = queue;
	record->bytes = bytes;
	record->direction = DMA_TO_DEVICE;
	ready = qdx_packet_publish(path->endpoint, record, class.tag, QDX_H2N_PACKET);
leave:
	qdx_io_leave(qdx);
	return ready;
}
EXPORT_SYMBOL_GPL(qdx_xmit);

struct qdx_packet_op *qdx_packet_op_prepare(struct qdx_endpoint *endpoint,
					  u32 class_tag, u8 category)
{
	struct qdx_packet_op *operation;

	if (category != QDX_RECEIVE_RETURNED && category != QDX_RECEIVE_BRIDGE_RETURNED)
		return ERR_PTR(-EOPNOTSUPP);
	if (!qdx_endpoint_command_ready(endpoint))
		return ERR_PTR(-ESHUTDOWN);
	operation = kzalloc(sizeof(*operation), GFP_KERNEL);
	if (!operation)
		return ERR_PTR(-ENOMEM);
	qdx_endpoint_hold(endpoint);
	operation->endpoint = endpoint;
	operation->class_tag = class_tag;
	operation->category = category;
	operation->open = true;
	refcount_set(&operation->refs, 1);
	return operation;
}
EXPORT_SYMBOL_GPL(qdx_packet_op_prepare);

void qdx_packet_op_close(struct qdx_packet_op *operation)
{
	struct qdx *qdx = operation->endpoint->service->qdx;
	struct qdx_io *io;
	unsigned long flags;

	if (!qdx_io_enter(qdx)) {
		spin_lock_irqsave(&qdx->io_admission, flags);
		smp_store_release(&operation->open, false);
		spin_unlock_irqrestore(&qdx->io_admission, flags);
		return;
	}
	io = READ_ONCE(operation->endpoint->core->io);
	if (io) {
		spin_lock_irqsave(&io->h2n[QDX_DATA_RING].lock, flags);
		spin_lock(&qdx->io_admission);
		smp_store_release(&operation->open, false);
		spin_unlock(&qdx->io_admission);
		spin_unlock_irqrestore(&io->h2n[QDX_DATA_RING].lock, flags);
	} else {
		spin_lock_irqsave(&qdx->io_admission, flags);
		smp_store_release(&operation->open, false);
		spin_unlock_irqrestore(&qdx->io_admission, flags);
	}
	qdx_io_leave(qdx);
}
EXPORT_SYMBOL_GPL(qdx_packet_op_close);

void qdx_packet_op_put(struct qdx_packet_op *operation)
{
	if (!operation || !refcount_dec_and_test(&operation->refs))
		return;
	qdx_endpoint_put(operation->endpoint);
	kfree(operation);
}
EXPORT_SYMBOL_GPL(qdx_packet_op_put);

struct qdx_ready qdx_packet_op_submit(struct qdx_packet_op *operation,
		struct sk_buff *skb, const struct qdx_packet_recipient *recipient)
{
	struct qdx_endpoint *endpoint = operation->endpoint;
	struct qdx_carrier *record;
	struct qdx_ready ready;
	int error;

	if (!recipient || !recipient->returned || !smp_load_acquire(&operation->open))
		return (struct qdx_ready) { .status = QDX_CLOSED, .error = -ESHUTDOWN };
	if (skb_is_nonlinear(skb))
		return (struct qdx_ready) { .status = QDX_REFUSED, .error = -EMSGSIZE };
	/* The native boundary has already prepared the frame. Only writable DMA
	 * storage is required here; original metadata and ownership are retained.
	 */
	error = skb_unclone(skb, GFP_ATOMIC);
	if (error)
		return (struct qdx_ready) { .status = QDX_REFUSED, .error = error };
	if (!qdx_io_enter(endpoint->service->qdx))
		return (struct qdx_ready) { .status = QDX_CLOSED, .error = -ESHUTDOWN };
	record = qdx_packet_prepare(endpoint, skb, &ready);
	if (!record)
		goto leave;
	if (!qdx_owner_get(&recipient->owner)) {
		qdx_carrier_put(endpoint->core, record, false);
		ready = (struct qdx_ready) { .status = QDX_CLOSED, .error = -ESHUTDOWN };
		goto leave;
	}
	refcount_inc(&operation->refs);
	atomic_inc(&endpoint->operations);
	record->operation = operation;
	record->recipient = *recipient;
	record->direction = DMA_BIDIRECTIONAL;
	ready = qdx_packet_publish(endpoint, record, operation->class_tag,
		operation->category == QDX_RECEIVE_RETURNED ?
		QDX_H2N_RETURNED : QDX_H2N_BRIDGE_RETURNED);
leave:
	qdx_io_leave(endpoint->service->qdx);
	return ready;
}
EXPORT_SYMBOL_GPL(qdx_packet_op_submit);

void qdx_io_tx_close(struct qdx_tx_path *path)
{
	struct qdx *qdx = path->endpoint->service->qdx;
	struct qdx_io *io;
	unsigned long flags;

	if (!qdx_io_enter(qdx)) {
		spin_lock_irqsave(&qdx->io_admission, flags);
		smp_store_release(&path->open, false);
		spin_unlock_irqrestore(&qdx->io_admission, flags);
		return;
	}
	io = READ_ONCE(path->endpoint->core->io);
	if (io) {
		spin_lock_irqsave(&io->h2n[QDX_DATA_RING].lock, flags);
		spin_lock(&qdx->io_admission);
		smp_store_release(&path->open, false);
		spin_unlock(&qdx->io_admission);
		spin_unlock_irqrestore(&io->h2n[QDX_DATA_RING].lock, flags);
	} else {
		spin_lock_irqsave(&qdx->io_admission, flags);
		smp_store_release(&path->open, false);
		spin_unlock_irqrestore(&qdx->io_admission, flags);
	}
	qdx_io_leave(qdx);
}

void qdx_io_port_close(struct qdx_port *port)
{
	struct qdx_io *io;
	unsigned long flags;

	if (!qdx_io_enter(port->qdx)) {
		smp_store_release(&port->available, false);
		return;
	}
	io = READ_ONCE(port->qdx->cores[0].io);
	if (io) {
		spin_lock_irqsave(&io->h2n[QDX_DATA_RING].lock, flags);
		smp_store_release(&port->available, false);
		spin_unlock_irqrestore(&io->h2n[QDX_DATA_RING].lock, flags);
	} else {
		smp_store_release(&port->available, false);
	}
	qdx_io_leave(port->qdx);
}

static void qdx_irq_unmask(struct qdx_irq *ctx)
{
	unsigned long flags;

	spin_lock_irqsave(&ctx->lock, flags);
	if (ctx->active && ctx->masked && READ_ONCE(ctx->core->io->running)) {
		ctx->masked = false;
		enable_irq(ctx->irq);
	}
	spin_unlock_irqrestore(&ctx->lock, flags);
}

/* Match the backing allocation used by alloc_skb(), then reconcile truesize.
 * Small-head caches can differ from kmalloc's estimate; no object is published
 * until its actual charge has also been admitted.
 */
static unsigned long qdx_rx_cost(unsigned int length, enum qdx_carrier_kind kind)
{
	size_t size;

	if (kind == QDX_PAGED)
		return PAGE_SIZE;
	if (length > U16_MAX)
		return 0;
	size = kmalloc_size_roundup(SKB_HEAD_ALIGN(length));
	if (!size || check_add_overflow(size,
			(size_t)SKB_DATA_ALIGN(sizeof(struct sk_buff)), &size) ||
	    size > LONG_MAX)
		return 0;
	return size;
}

static bool qdx_rx_reserve(struct qdx *qdx, unsigned long dma_bytes,
			   unsigned long memory_bytes)
{
	long used = atomic_long_read(&qdx->rx_dma_used);

	do {
		if (used < 0 || used > qdx->limits.rx_dma_bytes ||
		    dma_bytes > qdx->limits.rx_dma_bytes - used)
			return false;
	} while (!atomic_long_try_cmpxchg(&qdx->rx_dma_used, &used,
					 used + dma_bytes));
	used = atomic_long_read(&qdx->rx_memory_charged);
	do {
		if (used < 0 || used > qdx->limits.rx_memory_bytes ||
		    memory_bytes > qdx->limits.rx_memory_bytes - used) {
			atomic_long_sub(dma_bytes, &qdx->rx_dma_used);
			return false;
		}
	} while (!atomic_long_try_cmpxchg(&qdx->rx_memory_charged, &used,
					 used + memory_bytes));
	return true;
}

/* Configuration preflight only: concurrent returns/refill still pass the
 * atomic admission checks. The caller owns lifecycle or native configuration.
 */
static int qdx_rx_project(struct qdx *qdx, struct qdx_supply *changed,
			  u32 target, unsigned int length)
{
	u64 dma = 0, memory = 0, represented = 0;
	unsigned long flags, charged, after, cost;
	unsigned int i, kind, slot, count, extent;

	charged = atomic_long_read(&qdx->rx_memory_charged);
	for (i = 0; i < QDX_CORES; i++) {
		struct qdx_io *io = qdx->cores[i].io;

		if (!io)
			return -EAGAIN;
		spin_lock_irqsave(&io->carriers_lock, flags);
		for (kind = 0; kind < 2; kind++) {
			struct qdx_supply *supply = &io->supply[kind];

			count = supply == changed ? target : READ_ONCE(supply->target);
			count = max(count, io->outstanding[supply->kind]);
			extent = kind ? PAGE_SIZE : max(length, READ_ONCE(io->rx_length));
			cost = qdx_rx_cost(extent, supply->kind);
			if (!cost || count > QDX_SLOTS) {
				spin_unlock_irqrestore(&io->carriers_lock, flags);
				return -ERANGE;
			}
			/* Slot and 16-bit buffer bounds keep both products within u64. */
			dma += (u64)count * extent;
			memory += (u64)count * cost;
		}
		for (slot = 0; slot < io->slots; slot++)
			represented += READ_ONCE(qdx_slot(io, slot)->memory_charge);
		spin_unlock_irqrestore(&io->carriers_lock, flags);
	}
	/* Do not add carrier allocations twice. The remainder includes partial
	 * chains and reservations between admission and assignment to a carrier.
	 * A return during the scan must not preserve a stale higher total.
	 */
	after = atomic_long_read(&qdx->rx_memory_charged);
	charged = min(charged, after);
	if (charged > represented)
		memory += charged - represented;
	if (dma > qdx->limits.rx_dma_bytes || memory > qdx->limits.rx_memory_bytes)
		return -ENOSPC;
	return 0;
}

static void qdx_refill(struct work_struct *work)
{
	struct qdx_supply *supply = container_of(to_delayed_work(work),
						struct qdx_supply, work);
	struct qdx_core *core = supply->core;
	struct qdx_io *io = core->io;
	struct qdx_carrier *record;
	struct qdx_h2n_desc desc;
	unsigned int length, batch, done = 0, delay;
	unsigned long cost, actual;
	bool paged = supply->kind == QDX_PAGED;
	bool shortfall;
	int err = 0;

	/* Acquire the validated map/ring views before supplying firmware. */
	if (READ_ONCE(io->closed) || !smp_load_acquire(&core->map_ready) ||
	    atomic_read(&core->qdx->failure))
		return;
	/* Before the pool reply, firmware demand drives bounded bootstrap growth.
	 * Ring depth limits one batch, not the total number held by firmware.
	 */
	if (atomic_xchg(&supply->demand, 0) && !READ_ONCE(supply->pool_known) &&
	    READ_ONCE(io->outstanding[supply->kind]) >= READ_ONCE(supply->target)) {
		u32 target = READ_ONCE(supply->target) + QDX_RING_DEPTH - 1;

		err = qdx_rx_project(core->qdx, supply, target, 0);
		if (!err)
			err = qdx_slots_grow(core, supply->kind, target);
		if (err) {
			qdx_fail(core->qdx, err);
			return;
		}
		WRITE_ONCE(supply->target, target);
	}
	for (batch = 0; batch < QDX_RING_DEPTH; batch++) {
		if (READ_ONCE(io->outstanding[supply->kind]) >= READ_ONCE(supply->target))
			break;
		record = qdx_carrier_get(core, supply->kind);
		if (!record) {
			err = -ENOSPC;
			break;
		}
		length = paged ? PAGE_SIZE : READ_ONCE(io->rx_length);
		cost = qdx_rx_cost(length, supply->kind);
		if (!cost || !qdx_rx_reserve(core->qdx, length, cost)) {
			qdx_carrier_put(core, record, true);
			err = -ENOMEM;
			break;
		}
		record->length = length;
		WRITE_ONCE(record->memory_charge, cost);
		record->direction = DMA_FROM_DEVICE;
		if (paged)
			record->page = alloc_page(GFP_KERNEL | __GFP_NOMEMALLOC);
		else
			record->skb = alloc_skb(length, GFP_KERNEL | __GFP_NOMEMALLOC);
		if (!record->page && !record->skb) {
			qdx_carrier_put(core, record, true);
			err = -ENOMEM;
			break;
		}
		actual = paged ? PAGE_SIZE : record->skb->truesize;
		if (actual > cost && !qdx_rx_reserve(core->qdx, 0, actual - cost)) {
			qdx_carrier_put(core, record, true);
			err = -ENOMEM;
			break;
		}
		if (actual < cost)
			atomic_long_sub(cost - actual, &core->qdx->rx_memory_charged);
		WRITE_ONCE(record->memory_charge, actual);
		memset(&desc, 0, sizeof(desc));
		desc.type = paged ? QDX_H2N_PAGED_EMPTY : QDX_H2N_EMPTY;
		desc.payload_off = cpu_to_le16(paged ? 0 : NET_SKB_PAD);
		err = qdx_carrier_map(record);
		if (!err)
			err = qdx_publish(core, paged ? QDX_PAGED_RING : QDX_EMPTY_RING,
					  record, &desc);
		if (err) {
			qdx_carrier_put(core, record, true);
			break;
		}
		done++;
	}
	shortfall = READ_ONCE(io->outstanding[supply->kind]) < READ_ONCE(supply->target);
	if (done)
		supply->backoff = 10;
	delay = supply->backoff;
	if (!done && err)
		supply->backoff = min(supply->backoff * 2, 1000U);
	if (done || !shortfall)
		qdx_irq_unmask(&io->irq[paged ? 8 : 0]);
	if (!READ_ONCE(io->closed) && !atomic_read(&core->qdx->failure) && shortfall)
		mod_delayed_work(system_wq, &supply->work, msecs_to_jiffies(delay));
}

int qdx_io_bootstrap(struct qdx_core *core)
{
	struct qdx_io *io = core->io;
	struct qdx_irq *ctx;
	unsigned long flags;
	unsigned int i;
	int err;

	for (i = 0; i < 2; i++) {
		err = qdx_rx_project(core->qdx, &io->supply[i], QDX_RING_DEPTH - 1, 0);
		if (!err)
			err = qdx_slots_grow(core, io->supply[i].kind, QDX_RING_DEPTH - 1);
		if (err)
			return err;
		WRITE_ONCE(io->supply[i].target, QDX_RING_DEPTH - 1);
		mod_delayed_work(system_wq, &io->supply[i].work, 0);
	}
	/* An early event may have completed NAPI while the map was unready. */
	for (i = 0; i < io->irq_count; i++) {
		ctx = &io->irq[i];
		spin_lock_irqsave(&ctx->lock, flags);
		if (ctx->active && ctx->masked && READ_ONCE(io->running))
			napi_schedule_irqoff(&ctx->napi);
		spin_unlock_irqrestore(&ctx->lock, flags);
	}
	return 0;
}

int qdx_io_set_pool(struct qdx_core *core, bool paged, u32 pool, u32 low, u32 high)
{
	struct qdx_io *io = core->io;
	struct qdx_supply *supply = &io->supply[paged];
	u32 target;
	int err;

	/* Pool defaults may set high water above the nominal pool size. */
	if (low > high || check_add_overflow(max(pool, high), (u32)QDX_TRANSIT, &target) ||
	    target > QDX_SLOTS)
		return -ERANGE;
	/* Finish any bootstrap growth before replacing its provisional target. */
	WRITE_ONCE(supply->pool_known, true);
	cancel_delayed_work_sync(&supply->work);
	err = qdx_rx_project(core->qdx, supply, target, 0);
	if (err)
		return err;
	err = qdx_slots_grow(core, supply->kind, target);
	if (err)
		return err;
	WRITE_ONCE(supply->target, target);
	mod_delayed_work(system_wq, &supply->work, 0);
	return 0;
}

int qdx_io_check_mtu(struct qdx *qdx, unsigned int mtu)
{
	unsigned int length;

	if (mtu > U16_MAX - NET_SKB_PAD - ETH_HLEN - VLAN_HLEN)
		return -EMSGSIZE;
	length = max_t(unsigned int, QDX_COMMAND_SIZE + NET_SKB_PAD,
			mtu + NET_SKB_PAD + ETH_HLEN + VLAN_HLEN);
	return qdx_rx_project(qdx, NULL, 0, length);
}

int qdx_io_set_mtu(struct qdx *qdx, unsigned int mtu)
{
	unsigned int length, i;
	int err;

	err = qdx_io_check_mtu(qdx, mtu);
	if (err)
		return err;
	length = max_t(unsigned int, QDX_COMMAND_SIZE + NET_SKB_PAD,
			mtu + NET_SKB_PAD + ETH_HLEN + VLAN_HLEN);
	for (i = 0; i < QDX_CORES; i++) {
		struct qdx_io *io = qdx->cores[i].io;

		/* Old mappings retain their original extent until their own return. */
		WRITE_ONCE(io->rx_length, max(length, io->rx_length));
		WRITE_ONCE(io->max_frame, max(mtu + ETH_HLEN + VLAN_HLEN, io->max_frame));
	}
	return 0;
}

/* Validate identity before looking at any firmware-supplied address. */
static struct qdx_carrier *qdx_return_claim(struct qdx_core *arrival,
					   struct qdx_n2h_desc *desc,
					   struct qdx_core **owner)
{
	struct qdx_carrier *record;
	struct qdx_io *io;
	unsigned long flags;
	u64 cookie = le64_to_cpu(desc->opaque);
	u32 slot = cookie & 0xffff;
	u32 generation = cookie >> 32;

	if (!generation || (cookie & GENMASK_ULL(30, 16)))
		return NULL;
	*owner = &arrival->qdx->cores[(cookie >> 31) & 1];
	io = (*owner)->io;
	spin_lock_irqsave(&io->carriers_lock, flags);
	record = qdx_slot(io, slot);
	if (!record || record->state != QDX_PUBLISHED || record->generation != generation)
		record = NULL;
	else
		record->state = QDX_RETURNING;
	spin_unlock_irqrestore(&io->carriers_lock, flags);
	return record;
}

static bool qdx_return_valid(struct qdx_carrier *record, struct qdx_n2h_desc *desc)
{
	unsigned int offset = le16_to_cpu(desc->payload_off);
	unsigned int length = le16_to_cpu(desc->payload_len);

	if (desc->type == QDX_N2H_EMPTY)
		return true; /* Empty returns do not define payload geometry. */
	if (desc->type == QDX_N2H_COMMAND_RESP)
		return record->kind == QDX_CONTROL && desc->response <= 5;
	if (record->direction == DMA_TO_DEVICE)
		return false;
	return le32_to_cpu(desc->buffer) == record->dma &&
	       le16_to_cpu(desc->buffer_len) <= record->length &&
	       offset <= record->length && length <= record->length - offset;
}

static struct sk_buff *qdx_return_packet(struct qdx *qdx,
					struct qdx_carrier *record,
					struct qdx_n2h_desc *desc,
					unsigned long *memory_charge)
{
	unsigned int offset = le16_to_cpu(desc->payload_off);
	unsigned int length = le16_to_cpu(desc->payload_len);
	unsigned int head_length;
	unsigned long cost, actual;
	struct sk_buff *skb;

	if (!length)
		return NULL;
	if (record->kind == QDX_LINEAR) {
		skb = record->skb;
		record->skb = NULL;
		*memory_charge = record->memory_charge;
		WRITE_ONCE(record->memory_charge, 0);
		skb_reserve(skb, offset);
		skb_put(skb, length);
		return skb;
	}
	head_length = NET_SKB_PAD + (record->kind == QDX_PAGED ? ETH_HLEN : length);
	cost = qdx_rx_cost(head_length, QDX_LINEAR);
	if (!cost || !qdx_rx_reserve(qdx, 0, cost))
		return NULL;
	skb = alloc_skb(head_length, GFP_ATOMIC | __GFP_NOMEMALLOC);
	if (!skb)
		goto release;
	actual = skb->truesize;
	if (actual > cost && !qdx_rx_reserve(qdx, 0, actual - cost))
		goto release;
	if (actual < cost)
		atomic_long_sub(cost - actual, &qdx->rx_memory_charged);
	*memory_charge = actual;
	skb_reserve(skb, NET_SKB_PAD);
	if (record->kind == QDX_PAGED) {
		skb_add_rx_frag(skb, 0, record->page, offset, length, PAGE_SIZE);
		record->page = NULL;
		*memory_charge += record->memory_charge;
		WRITE_ONCE(record->memory_charge, 0);
	} else {
		/* Writable command storage has no skb shared-info area. */
		skb_put_data(skb, record->buffer + offset, length);
	}
	return skb;
release:
	dev_kfree_skb_any(skb);
	atomic_long_sub(cost, &qdx->rx_memory_charged);
	return NULL;
}

static void qdx_packet_assemble(struct qdx_irq *ctx, struct sk_buff *skb,
				struct qdx_n2h_desc *desc,
				unsigned long memory_charge)
{
	struct qdx *qdx = ctx->core->qdx;
	struct qdx_io *io = ctx->core->io;
	u32 interface = le32_to_cpu(desc->interface);
	u16 flags = le16_to_cpu(desc->flags);
	unsigned int target = interface >> 24;
	unsigned int needed, tailroom, old_size;
	struct qdx_rx_meta metadata;
	unsigned long extra = 0, cost, actual;
	bool first = flags & QDX_DESC_FIRST;
	bool last = flags & QDX_DESC_LAST;

	if (first) {
		dev_kfree_skb_any(ctx->partial);
		atomic_long_sub(ctx->partial_charge, &qdx->rx_memory_charged);
		ctx->partial = NULL;
		ctx->tail = NULL;
		WRITE_ONCE(ctx->partial_charge, 0);
	}
	if (!skb || skb->len > READ_ONCE(io->max_frame))
		goto drop;
	if (first) {
		ctx->partial = skb;
		ctx->priority = desc->priority;
	} else {
		if (!ctx->partial ||
		    skb->len > READ_ONCE(io->max_frame) - ctx->partial->len)
			goto drop;
		if (ctx->tail)
			ctx->tail->next = skb;
		else
			skb_shinfo(ctx->partial)->frag_list = skb;
		ctx->tail = skb;
		ctx->partial->len += skb->len;
		ctx->partial->data_len += skb->len;
		ctx->partial->truesize += skb->truesize;
	}
	WRITE_ONCE(ctx->partial_charge, ctx->partial_charge + memory_charge);
	if (!last)
		return;
	skb = ctx->partial;
	memory_charge = ctx->partial_charge;
	ctx->partial = NULL;
	ctx->tail = NULL;
	WRITE_ONCE(ctx->partial_charge, 0);
	/* Priority belongs to FIRST; routing/checksum metadata belongs to LAST. */
	if (target > QDX_CORES || skb->len < ETH_HLEN)
		goto drop;
	if (skb_headlen(skb) < ETH_HLEN) {
		needed = ETH_HLEN - skb_headlen(skb);
		tailroom = skb_end_pointer(skb) - skb_tail_pointer(skb);
		old_size = skb->truesize;
		if (needed > tailroom) {
			/* __pskb_pull_tail adds 128 bytes when it grows this head. */
			cost = qdx_rx_cost(skb_end_offset(skb) + needed - tailroom + 128,
					   QDX_LINEAR);
			if (!cost)
				goto drop;
			extra = cost > SKB_TRUESIZE(skb_end_offset(skb)) ?
				cost - SKB_TRUESIZE(skb_end_offset(skb)) : 0;
			if (!qdx_rx_reserve(qdx, 0, extra))
				goto drop;
			memory_charge += extra;
		}
		/* These freshly returned heads/children have no shared skb owners. */
		if (!pskb_may_pull(skb, ETH_HLEN))
			goto drop;
		actual = skb->truesize - old_size;
		if (actual > extra) {
			if (!qdx_rx_reserve(qdx, 0, actual - extra))
				goto drop;
			memory_charge += actual - extra;
		} else {
			atomic_long_sub(extra - actual, &qdx->rx_memory_charged);
			memory_charge -= extra - actual;
		}
	}
	skb->priority = ctx->priority;
	skb->ip_summed = flags & 2 ? CHECKSUM_UNNECESSARY : CHECKSUM_NONE;
	/* The Linux receive continuation owns the full packet from this point. */
	atomic_long_sub(memory_charge, &qdx->rx_memory_charged);
	metadata = (struct qdx_rx_meta) {
		.ifnum = interface & GENMASK(23, 0),
		.core = target ? target - 1 : ctx->core->id,
		.service_code = desc->service,
		.type = desc->type,
		.flags = flags,
		.priority = ctx->priority,
	};
	qdx_endpoint_packet(&qdx->cores[metadata.core], skb, &metadata, &ctx->napi);
	return;
drop:
	dev_kfree_skb_any(skb);
	atomic_long_sub(memory_charge, &qdx->rx_memory_charged);
	dev_kfree_skb_any(ctx->partial);
	atomic_long_sub(ctx->partial_charge, &qdx->rx_memory_charged);
	ctx->partial = NULL;
	ctx->tail = NULL;
	WRITE_ONCE(ctx->partial_charge, 0);
	atomic64_inc(&io->dropped);
}

static void qdx_operation_return(struct qdx_irq *ctx, struct qdx_carrier *record,
				 const struct qdx_n2h_desc *desc)
{
	struct qdx_rx_meta metadata = {};
	struct sk_buff *original = record->skb, *returned = NULL;
	u32 wire_interface;
	u16 offset, length;

	if (desc) {
		wire_interface = le32_to_cpu(desc->interface);
		metadata.ifnum = wire_interface & GENMASK(23, 0);
		metadata.core = wire_interface >> 24 ? (wire_interface >> 24) - 1 : ctx->core->id;
		metadata.service_code = desc->service;
		metadata.type = desc->type;
		metadata.flags = le16_to_cpu(desc->flags);
		metadata.priority = desc->priority;
		offset = le16_to_cpu(desc->payload_off);
		length = le16_to_cpu(desc->payload_len);
		if (desc->type != QDX_N2H_EMPTY && length >= ETH_HLEN &&
		    (metadata.flags & (QDX_DESC_FIRST | QDX_DESC_LAST)) ==
				      (QDX_DESC_FIRST | QDX_DESC_LAST)) {
			/* This admitted linear mapping already is suitable skb storage.
			 * Keep original host priority, mark, protocol, dst and loan cb;
			 * only the validated frame offsets/length may have moved.
			 */
			skb_headers_offset_update(original, offset - skb_headroom(original));
			original->data = original->head + offset;
			original->len = length;
			original->data_len = 0;
			skb_set_tail_pointer(original, length);
			returned = original;
			record->skb = NULL;
		}
	}
	/* The recipient consumes every returned skb; the carrier still owns an
	 * original which was not transferred. Never reread its cb after this call.
	 */
	record->recipient.returned(record->recipient.owner.object, original, returned,
				   desc ? &metadata : NULL, ctx ? &ctx->napi : NULL);
}

static void qdx_return(struct qdx_irq *ctx, struct qdx_n2h_desc *desc,
		       struct qdx_tx_batch *batch)
{
	struct qdx_core *arrival = ctx->core, *owner = NULL;
	struct qdx_carrier *record;
	struct sk_buff *skb = NULL;
	unsigned long memory_charge = 0;
	u32 interface = le32_to_cpu(desc->interface);
	unsigned int target = interface >> 24;
	void *payload;
	bool fresh = false;

	record = qdx_return_claim(arrival, desc, &owner);
	if (!record || !qdx_return_valid(record, desc)) {
		if (record)
			WRITE_ONCE(record->state, QDX_QUARANTINED);
		atomic64_inc(&arrival->io->faults);
		qdx_fail(arrival->qdx, -EPROTO);
		return;
	}
	if (record->kind == QDX_PAGED)
		dma_unmap_page(record->dev, record->dma, record->length, record->direction);
	else
		dma_unmap_single(record->dev, record->dma, record->length, record->direction);
	record->mapped = false;
	if (record->operation) {
		qdx_operation_return(ctx, record, desc);
		goto reclaimed;
	}
	switch (desc->type) {
	case QDX_N2H_EMPTY:
		break;
	case QDX_N2H_COMMAND_RESP:
		qdx_command_return(owner, record->request_id, desc->response);
		break;
	case QDX_N2H_STATUS:
		payload = record->page ? page_address(record->page) :
			  record->skb ? record->skb->head : record->buffer;
		payload += le16_to_cpu(desc->payload_off);
		/* STATUS names its protocol endpoint in the common header. */
		interface = le16_to_cpu(desc->payload_len) >= sizeof(struct qdx_cmn) ?
			get_unaligned_le32(payload + offsetof(struct qdx_cmn, interface)) : 0;
		if (target <= QDX_CORES)
			qdx_command_receive(&arrival->qdx->cores[target ? target - 1 : arrival->id],
				interface, payload,
				le16_to_cpu(desc->payload_len));
		else
			qdx_fail(arrival->qdx, -EPROTO);
		break;
	case QDX_N2H_PACKET:
	case QDX_N2H_VIRTUAL:
	case QDX_N2H_EXTENDED:
		fresh = true;
		skb = qdx_return_packet(owner->qdx, record, desc, &memory_charge);
		break;
	default:
		atomic64_inc(&arrival->io->dropped);
		break;
	}
reclaimed:
	qdx_tx_batch_add(batch, record);
	qdx_carrier_put(owner, record, true);
	atomic64_inc(&owner->io->returned);
	if (fresh)
		qdx_packet_assemble(ctx, skb, desc, memory_charge);
	if (!READ_ONCE(owner->io->closed)) {
		mod_delayed_work(system_wq, &owner->io->supply[0].work, 0);
		mod_delayed_work(system_wq, &owner->io->supply[1].work, 0);
	}
}

static int qdx_poll(struct napi_struct *napi, int budget)
{
	struct qdx_irq *ctx = container_of(napi, struct qdx_irq, napi);
	struct qdx_core *core = ctx->core;
	struct qdx_io *io = core->io;
	struct qdx_n2h_desc desc;
	struct qdx_tx_batch batch = {};
	u32 producer, consumer;
	unsigned long flags;
	int ring, done = 0;

	if (!budget)
		return 0;
	/* Map validation publishes every ring view before this acquire. */
	if (!smp_load_acquire(&core->map_ready)) {
		napi_complete_done(napi, 0);
		/* First demand stays masked until validated-map bootstrap supplies it. */
		return 0;
	}
	if (ctx->purpose == 1)
		ring = 0;
	else if (ctx->purpose >= 3 && ctx->purpose <= 6)
		ring = ctx->purpose - 2;
	else {
		if (ctx->purpose == 0 || ctx->purpose == 8) {
			struct qdx_supply *supply = &io->supply[ctx->purpose == 8];
			unsigned long delay = 0;

			atomic_set(&supply->demand, 1);

			if (READ_ONCE(io->outstanding[supply->kind]) >= READ_ONCE(supply->target))
				delay = msecs_to_jiffies(10);
			napi_complete_done(napi, 0);
			queue_delayed_work(system_wq, &supply->work, delay);
			return 0;
		}
		if (ctx->purpose == 2)
			qdx_resource_progress(core, QDX_RESOURCE_DESCRIPTOR);
		else if (ctx->purpose == 7)
			qdx_fail(core->qdx, -EIO);
		/* Profiling is disabled in the supplied control allocation. */
		if (napi_complete_done(napi, 0))
			qdx_irq_unmask(ctx);
		return 0;
	}
	consumer = le32_to_cpu(READ_ONCE(core->map->n2h_host[ring]));
	producer = le32_to_cpu(READ_ONCE(core->map->n2h_firmware[ring]));
	if (consumer >= QDX_RING_DEPTH || producer >= QDX_RING_DEPTH) {
		qdx_fail(core->qdx, -EPROTO);
		napi_complete_done(napi, 0);
		return 0;
	}
	/* Only this real NAPI owner captures and advances the prefix. */
	spin_lock_irqsave(&ctx->lock, flags);
	if (ctx->drain_requested) {
		ctx->drain_requested = false;
		ctx->draining = true;
		ctx->drain_remaining = (producer - consumer) & (QDX_RING_DEPTH - 1);
	}
	spin_unlock_irqrestore(&ctx->lock, flags);
	dma_rmb();
	while (consumer != producer && done < budget &&
	       !(ctx->draining && !ctx->drain_remaining)) {
		desc = core->n2h_desc[ring][consumer];
		qdx_return(ctx, &desc, &batch);
		if (ctx->draining && ctx->drain_remaining)
			ctx->drain_remaining--;
		consumer = (consumer + 1) & (QDX_RING_DEPTH - 1);
		done++;
	}
	qdx_tx_batch_complete(&batch);
	dma_wmb();
	WRITE_ONCE(core->map->n2h_host[ring], cpu_to_le32(consumer));
	if (ctx->draining && !ctx->drain_remaining) {
		/* Disposal ends a partial which crosses the captured boundary.
		 * Later non-FIRST fragments encounter an empty assembler and drop.
		 */
		dev_kfree_skb_any(ctx->partial);
		atomic_long_sub(ctx->partial_charge, &core->qdx->rx_memory_charged);
		ctx->partial = NULL;
		ctx->tail = NULL;
		WRITE_ONCE(ctx->partial_charge, 0);
		ctx->draining = false;
		complete_all(&ctx->drain_done);
	}
	qdx_resource_progress(core, QDX_RESOURCE_DESCRIPTOR);
	if (done == budget)
		return budget;
	/* Keep polling for producer progress observed before IRQ rearming. */
	producer = le32_to_cpu(READ_ONCE(core->map->n2h_firmware[ring]));
	if (producer >= QDX_RING_DEPTH) {
		qdx_fail(core->qdx, -EPROTO);
		napi_complete_done(napi, done);
		return done;
	}
	if (producer != consumer)
		return budget;
	spin_lock_irqsave(&ctx->lock, flags);
	/* A request racing the poll tail must retain NAPI ownership. Otherwise
	 * schedule before complete would lose the only requested capture.
	 */
	if (ctx->drain_requested) {
		spin_unlock_irqrestore(&ctx->lock, flags);
		return budget;
	}
	if (napi_complete_done(napi, done) && ctx->active && ctx->masked &&
	    READ_ONCE(io->running)) {
		ctx->masked = false;
		enable_irq(ctx->irq);
	}
	spin_unlock_irqrestore(&ctx->lock, flags);
	return done;
}

static irqreturn_t qdx_interrupt(int irq, void *data)
{
	struct qdx_irq *ctx = data;
	unsigned long flags;

	spin_lock_irqsave(&ctx->lock, flags);
	if (ctx->purpose == 0)
		smp_store_release(&ctx->core->boot_signaled, true);
	if (!ctx->masked) {
		disable_irq_nosync(irq);
		ctx->masked = true;
	}
	if (ctx->active && READ_ONCE(ctx->core->io->running))
		napi_schedule_irqoff(&ctx->napi);
	spin_unlock_irqrestore(&ctx->lock, flags);
	if (ctx->purpose == 7)
		qdx_fail(ctx->core->qdx, -EIO);
	return IRQ_HANDLED;
}

int qdx_io_init(struct qdx_core *core)
{
	static const char * const names[] = {
		"empty-buffer", "empty-return", "tx-unblocked", "data", "data",
		"data", "data", "coredump", "paged-buffer", "profile"
	};
	struct qdx_io *io;
	struct qdx_irq *ctx;
	char name[24];
	unsigned int i;
	int err;

	io = kvzalloc(sizeof(*io), GFP_KERNEL);
	if (!io)
		return -ENOMEM;
	core->io = io;
	mutex_init(&io->allocation_lock);
	spin_lock_init(&io->carriers_lock);
	io->rx_length = QDX_COMMAND_SIZE + NET_SKB_PAD;
	io->max_frame = ETH_DATA_LEN + ETH_HLEN + VLAN_HLEN;
	for (i = 0; i < QDX_KINDS; i++)
		io->free_head[i] = QDX_NO_SLOT;
	for (i = 0; i < QDX_H2N_RINGS; i++)
		spin_lock_init(&io->h2n[i].lock);
	for (i = 0; i < 2; i++) {
		io->supply[i].core = core;
		io->supply[i].kind = i ? QDX_PAGED : QDX_LINEAR;
		io->supply[i].backoff = 10;
		atomic_set(&io->supply[i].demand, 0);
		INIT_DELAYED_WORK(&io->supply[i].work, qdx_refill);
	}
	io->napi_dev = alloc_netdev_dummy(0);
	if (!io->napi_dev)
		return -ENOMEM;
	err = qdx_slots_grow(core, QDX_CONTROL, QDX_REQUESTS);
	if (!err)
		err = qdx_slots_grow(core, QDX_TRANSMIT, core->qdx->limits.tx_slots);
	if (err)
		return err;
	for (i = 0; i < QDX_IRQS; i++) {
		ctx = &io->irq[i];
		ctx->core = core;
		ctx->purpose = i;
		ctx->masked = true;
		spin_lock_init(&ctx->lock);
		init_completion(&ctx->drain_done);
		if (i >= 3 && i <= 6)
			snprintf(name, sizeof(name), "data%u-%u", core->id, i - 3);
		else
			snprintf(name, sizeof(name), "%s%u", names[i], core->id);
		err = platform_get_irq_byname(core->qdx->pdev, name);
		if (err < 0)
			return err;
		ctx->irq = err;
		netif_napi_add(io->napi_dev, &ctx->napi, qdx_poll);
		err = request_irq(ctx->irq, qdx_interrupt, IRQF_NO_AUTOEN,
				  dev_name(core->qdx->dev), ctx);
		if (err) {
			netif_napi_del(&ctx->napi);
			return err;
		}
		io->irq_count++;
	}
	return 0;
}

int qdx_io_receive_drain(struct qdx *qdx)
{
	struct qdx_core *core;
	struct qdx_irq *ctx;
	unsigned long flags, deadline = jiffies + msecs_to_jiffies(3000);
	unsigned int c, i;
	int error = 0;

	mutex_lock(&qdx->receive_drain);
	if (smp_load_acquire(&qdx->access_ended))
		goto out;
	for (c = 0; c < QDX_CORES; c++) {
		core = &qdx->cores[c];
		if (!core->io || !smp_load_acquire(&core->map_ready) ||
		    atomic_read(&qdx->failure)) {
			error = -ESHUTDOWN;
			goto out;
		}
		for (i = 0; i < core->io->irq_count; i++) {
			if (i != 1 && (i < 3 || i > 6))
				continue;
			ctx = &core->io->irq[i];
			spin_lock_irqsave(&ctx->lock, flags);
			if (!ctx->active || !READ_ONCE(core->io->running)) {
				spin_unlock_irqrestore(&ctx->lock, flags);
				error = -ESHUTDOWN;
				goto out;
			}
			reinit_completion(&ctx->drain_done);
			ctx->drain_requested = true;
			if (!ctx->masked) {
				disable_irq_nosync(ctx->irq);
				ctx->masked = true;
			}
			napi_schedule_irqoff(&ctx->napi);
			spin_unlock_irqrestore(&ctx->lock, flags);
		}
	}
	for (c = 0; c < QDX_CORES; c++) {
		core = &qdx->cores[c];
		for (i = 0; i < core->io->irq_count; i++) {
			if (i != 1 && (i < 3 || i > 6))
				continue;
			ctx = &core->io->irq[i];
			if (time_after_eq(jiffies, deadline) ||
			    !wait_for_completion_timeout(&ctx->drain_done, deadline - jiffies)) {
				error = -ETIMEDOUT;
				goto out;
			}
		}
	}
out:
	mutex_unlock(&qdx->receive_drain);
	return error;
}

void qdx_io_enable(struct qdx_core *core)
{
	struct qdx_io *io = core->io;
	unsigned int i;

	WRITE_ONCE(io->running, true);
	for (i = 0; i < io->irq_count; i++) {
		napi_enable(&io->irq[i].napi);
		WRITE_ONCE(io->irq[i].active, true);
		qdx_irq_unmask(&io->irq[i]);
	}
}

void qdx_io_close(struct qdx_core *core)
{
	struct qdx_io *io = core->io;
	unsigned long flags;
	unsigned int i;

	if (!io)
		return;
	spin_lock_irqsave(&io->carriers_lock, flags);
	io->closed = true;
	spin_unlock_irqrestore(&io->carriers_lock, flags);
	for (i = 0; i < QDX_H2N_RINGS; i++) {
		spin_lock_irqsave(&io->h2n[i].lock, flags);
		io->h2n[i].closed = true;
		spin_unlock_irqrestore(&io->h2n[i].lock, flags);
	}
}

void qdx_io_stop(struct qdx_core *core)
{
	struct qdx_io *io = core->io;
	struct qdx_irq *ctx;
	unsigned long flags;
	unsigned int i;
	bool active;

	if (!io)
		return;
	qdx_io_close(core);
	WRITE_ONCE(io->running, false);
	for (i = 0; i < io->irq_count; i++) {
		ctx = &io->irq[i];
		spin_lock_irqsave(&ctx->lock, flags);
		active = ctx->active;
		ctx->active = false;
		if (!ctx->masked) {
			disable_irq_nosync(ctx->irq);
			ctx->masked = true;
		}
		spin_unlock_irqrestore(&ctx->lock, flags);
		synchronize_irq(ctx->irq);
		if (active)
			napi_disable(&ctx->napi);
	}
	/* napi_disable releases ownership before the poll tail has returned. */
	synchronize_net();
	for (i = 0; i < io->irq_count; i++) {
		ctx = &io->irq[i];
		dev_kfree_skb_any(ctx->partial);
		atomic_long_sub(ctx->partial_charge, &core->qdx->rx_memory_charged);
		ctx->partial = NULL;
		ctx->tail = NULL;
		WRITE_ONCE(ctx->partial_charge, 0);
	}
	for (i = 0; i < 2; i++)
		cancel_delayed_work_sync(&io->supply[i].work);
}

void qdx_io_release(struct qdx_core *core, bool access_ended)
{
	struct qdx_io *io = core->io;
	struct qdx_carrier *record;
	struct qdx_tx_batch batch = {};
	unsigned int i;

	if (!io)
		return;
	/* Callers have drained native entries, NAPI, requests and refill workers. */
	for (i = 0; i < io->slots; i++) {
		record = qdx_slot(io, i);
		if (record->state == QDX_FREE || record->state == QDX_RETIRED)
			continue;
		if (access_ended || record->state == QDX_PREPARED) {
			if (record->operation) {
				/* Access end precedes loan disposal and original free. */
				if (record->mapped) {
					dma_unmap_single(record->dev, record->dma, record->length,
							 record->direction);
					record->mapped = false;
				}
				qdx_operation_return(NULL, record, NULL);
			}
			qdx_tx_batch_add(&batch, record);
			qdx_carrier_put(core, record, true);
		} else
			record->state = QDX_QUARANTINED;
	}
	qdx_tx_batch_complete(&batch);
	dev_info(core->qdx->dev, "core %u carriers: published=%lld returned=%lld faults=%lld dropped=%lld%s\n",
		 core->id, atomic64_read(&io->published), atomic64_read(&io->returned),
		 atomic64_read(&io->faults), atomic64_read(&io->dropped),
		 access_ended ? "" : " (device-held memory retained)");
	if (!access_ended)
		return;
	for (i = 0; i < io->irq_count; i++) {
		free_irq(io->irq[i].irq, &io->irq[i]);
		netif_napi_del(&io->irq[i].napi);
	}
	for (i = 0; i < ARRAY_SIZE(io->chunks); i++)
		kvfree(io->chunks[i]);
	if (io->napi_dev)
		free_netdev(io->napi_dev);
	kvfree(io);
	core->io = NULL;
}
