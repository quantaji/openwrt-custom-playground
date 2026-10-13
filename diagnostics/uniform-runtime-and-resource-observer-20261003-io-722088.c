// SPDX-License-Identifier: GPL-2.0-only
/* Shared descriptor transport and host-owned DMA carrier records. */
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/qdx_diag_fq.h>
#include <linux/qdx_diag_bf.h>
#include <linux/qdx_diag_rate.h>
#include <linux/qdx_diag_aqm.h>
#include <linux/qdx_diag_clock.h>
#include <linux/ktime.h>
#include <linux/if_vlan.h>
#include <linux/limits.h>
#include <linux/mm.h>
#include <linux/moduleparam.h>
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

/* Isolated host-FQ diagnostic, disabled unless explicitly selected.  These
 * counters count preparation attempts, including retries, not wire packets.
 */
static unsigned int diag_host_align;
static atomic64_t diag_host_align_mod[4];
static atomic64_t diag_host_align_corrected;
static atomic64_t diag_host_align_refused;
static atomic64_t diag_host_wait_descriptor;
static atomic64_t diag_host_wait_carrier;
static atomic64_t diag_host_wait_bytes;
/* Sample inclusive alignment preparation only, never infer a whole-path cost. */
static bool diag_host_align_timing;
static atomic64_t diag_host_align_timing_attempts;
static atomic64_t diag_host_align_timing_samples;
static atomic64_t diag_host_align_timing_ns;
static atomic64_t diag_host_align_timing_bytes;
module_param_named(diag_host_align_timing, diag_host_align_timing, bool, 0600);
MODULE_PARM_DESC(diag_host_align_timing, "Diagnostic only: sample one in 64 alignment preparations; default off");

static int qdx_diag_host_align_set(const char *value, const struct kernel_param *param)
{
	return param_set_uint_minmax(value, param, 0, 2);
}

static const struct kernel_param_ops qdx_diag_host_align_mode_ops = {
	.set = qdx_diag_host_align_set,
	.get = param_get_uint,
};
module_param_cb(diag_host_align, &qdx_diag_host_align_mode_ops, &diag_host_align, 0600);
MODULE_PARM_DESC(diag_host_align, "Diagnostic only: 0=off, 1=guard, 2=normalize Ethernet data alignment");

static int qdx_diag_host_align_get(char *buffer, const struct kernel_param *param)
{
	return scnprintf(buffer, PAGE_SIZE,
		"mod0=%lld mod1=%lld mod2=%lld mod3=%lld corrected=%lld refused=%lld\n"
		"wait_descriptor=%lld wait_carrier=%lld wait_host_bytes=%lld\n"
		"timing_attempts=%lld timing_samples=%lld timing_ns=%lld timing_bytes=%lld\n",
		(long long)atomic64_read(&diag_host_align_mod[0]),
		(long long)atomic64_read(&diag_host_align_mod[1]),
		(long long)atomic64_read(&diag_host_align_mod[2]),
		(long long)atomic64_read(&diag_host_align_mod[3]),
		(long long)atomic64_read(&diag_host_align_corrected),
		(long long)atomic64_read(&diag_host_align_refused),
		(long long)atomic64_read(&diag_host_wait_descriptor),
		(long long)atomic64_read(&diag_host_wait_carrier),
		(long long)atomic64_read(&diag_host_wait_bytes),
		(long long)atomic64_read(&diag_host_align_timing_attempts),
		(long long)atomic64_read(&diag_host_align_timing_samples),
		(long long)atomic64_read(&diag_host_align_timing_ns),
		(long long)atomic64_read(&diag_host_align_timing_bytes));
}

static const struct kernel_param_ops qdx_diag_host_align_stats_ops = {
	.get = qdx_diag_host_align_get,
};
module_param_cb(diag_host_align_stats, &qdx_diag_host_align_stats_ops, NULL, 0400);

/* Isolated common-cost axes; retain every real publication/return owner. */
/* Owned-buffer MIRROR discriminator; no raw firmware address submission. */
static bool diag_clock_copy;
module_param(diag_clock_copy, bool, 0600);
MODULE_PARM_DESC(diag_clock_copy, "Diagnostic only: fixed readonly NSS clock return; default off");

static bool diag_mirror_copy;
static bool diag_mirror_publish_log;
module_param(diag_mirror_publish_log, bool, 0600);
MODULE_PARM_DESC(diag_mirror_publish_log, "Diagnostic only: log each MIRROR publication; default off");
static bool diag_mirror_table;
module_param(diag_mirror_table, bool, 0600);
MODULE_PARM_DESC(diag_mirror_table, "Diagnostic only: owned two-bin FQ table MIRROR; default off");

int qdx_diag_fq_table_get(struct qdx_service *mirror, struct qdx_dma *handle,
	const struct qdx_owner *owner, dma_addr_t *address);
void qdx_diag_fq_table_put(struct qdx_dma *region);
bool qdx_diag_fq_table_matches(struct qdx_dma *region, const u8 expected[144]);
u32 qdx_diag_fq_table_node(struct qdx_dma *region, u32 derived);
bool qdx_diag_fq_table_physical(struct qdx_dma *region);
bool qdx_diag_fq_table_bf(struct qdx_dma *region, const u32 key[7], bool record);
struct qdx_ready qdx_diag_fq_table_copy(struct qdx_packet_op *operation,
	struct qdx_dma *region, const struct qdx_packet_recipient *recipient);
module_param(diag_mirror_copy, bool, 0600);
MODULE_PARM_DESC(diag_mirror_copy, "Diagnostic only: type65 owned-skb A/B MIRROR copy; default off");

static bool diag_reserve_once, diag_return_tail, diag_io_cost_count;
module_param(diag_reserve_once, bool, 0600);
module_param(diag_return_tail, bool, 0600);
module_param(diag_io_cost_count, bool, 0600);
static atomic64_t diag_ready_scans, diag_ready_skipped;
static atomic64_t diag_return_items, diag_tail_polls;
static atomic64_t diag_progress_calls, diag_supply_schedule, diag_supply_runs;

static int qdx_diag_io_cost_get(char *buffer, const struct kernel_param *param)
{
	return scnprintf(buffer, PAGE_SIZE,
		"ready_scans=%lld ready_skipped=%lld return_items=%lld tail_polls=%lld\n"
		"progress_calls=%lld supply_schedule=%lld supply_runs=%lld\n",
		(long long)atomic64_read(&diag_ready_scans),
		(long long)atomic64_read(&diag_ready_skipped),
		(long long)atomic64_read(&diag_return_items),
		(long long)atomic64_read(&diag_tail_polls),
		(long long)atomic64_read(&diag_progress_calls),
		(long long)atomic64_read(&diag_supply_schedule),
		(long long)atomic64_read(&diag_supply_runs));
}
static const struct kernel_param_ops qdx_diag_io_cost_ops = {
	.get = qdx_diag_io_cost_get,
};
module_param_cb(diag_io_cost_stats, &qdx_diag_io_cost_ops, NULL, 0400);

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
	struct qdx_dma *diag_region;
	struct qdx_diag_clock_sample *diag_clock;
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
	bool diag_clock_busy; /* io_admission: one fixed-range loan */
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
			    bool free_storage, bool notify_progress)
{
	struct qdx_io *io = core->io;
	enum qdx_carrier_kind kind = record->kind;
	struct qdx_diag_clock_sample *clock = record->diag_clock;
	struct qdx_owner clock_owner;
	unsigned long flags;

	if (clock)
		clock_owner = record->recipient.owner;
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
	if (record->diag_region) {
		qdx_diag_fq_table_put(record->diag_region);
		record->diag_region = NULL;
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
		if (!clock)
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
	record->diag_clock = NULL;
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
	if (kind == QDX_TRANSMIT && free_storage && notify_progress)
		qdx_resource_progress(core, QDX_RESOURCE_CARRIER | QDX_RESOURCE_HOST_BYTES);
	if (clock) {
		spin_lock_irqsave(&core->qdx->io_admission, flags);
		io->diag_clock_busy = false;
		spin_unlock_irqrestore(&core->qdx->io_admission, flags);
		clock->retired_ns = ktime_get_ns();
		/* Final storage access precedes wakeup; caller/module remain pinned
		 * by clock_owner until completion has returned to this driver.
		 */
		complete(&clock->done);
		qdx_owner_put(&clock_owner);
	}
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
	if (READ_ONCE(diag_mirror_publish_log) && record->operation &&
	    record->operation->category == QDX_RECEIVE_PACKET && !record->diag_clock)
		pr_info("qdx mirror-copy publish dma=%pad offset=%u length=%u opaque=%016llx\n",
			&record->dma, le16_to_cpu(desc->payload_off),
			le16_to_cpu(desc->payload_len),
			(unsigned long long)le64_to_cpu(desc->opaque));
	core->h2n_desc[ring_id][producer] = *desc;
	if (record->diag_clock)
		record->diag_clock->published_ns = ktime_get_ns();
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
		qdx_carrier_put(core, record, false, true);
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

	if (READ_ONCE(diag_io_cost_count))
		atomic64_inc(&diag_progress_calls);

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

	if (READ_ONCE(diag_io_cost_count))
		atomic64_inc(&diag_ready_scans);
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
	/* Diagnostic readiness checks include repeats; these are not packet drops. */
	if (READ_ONCE(diag_host_align) && ready.resources) {
		if (ready.resources & QDX_RESOURCE_DESCRIPTOR)
			atomic64_inc(&diag_host_wait_descriptor);
		if (ready.resources & QDX_RESOURCE_CARRIER)
			atomic64_inc(&diag_host_wait_carrier);
		if (ready.resources & QDX_RESOURCE_HOST_BYTES)
			atomic64_inc(&diag_host_wait_bytes);
	}
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
	unsigned int mode, alignment, shift, length;
	u64 alignment_start = 0;
	int error;

	if (skb_is_nonlinear(skb) || skb->len < ETH_HLEN || skb->len > U16_MAX ||
	    skb_headroom(skb) > U16_MAX - skb_headlen(skb)) {
		*ready = (struct qdx_ready) { .status = QDX_REFUSED, .error = -EMSGSIZE };
		return NULL;
	}
	mode = READ_ONCE(diag_host_align);
	if (mode) {
		if (READ_ONCE(diag_host_align_timing) &&
		    !(atomic64_inc_return(&diag_host_align_timing_attempts) & 63))
			alignment_start = ktime_get_mono_fast_ns();
		alignment = (unsigned long)skb->data & 3;
		atomic64_inc(&diag_host_align_mod[alignment]);
		if (alignment != 2) {
			error = -EINVAL;
			if (mode == 1)
				goto alignment_refused;
			/* Only the known linear Ethernet test population is normalized.
			 * No hardware or caller has acquired this DMA carrier yet. Keep
			 * the same skb object, including a bounce recipient's identity.
			 */
			if (skb_shared(skb)) {
				error = -EBUSY;
				goto alignment_refused;
			}
			if (skb_cloned(skb) || skb_headroom(skb) < 3) {
				error = pskb_expand_head(skb,
					max_t(int, 3 - (int)skb_headroom(skb), 0),
					0, GFP_ATOMIC);
				if (error)
					goto alignment_refused;
			}
			shift = ((unsigned long)skb->data - 2) & 3;
			length = skb->len;
			skb_push(skb, shift);
			memmove(skb->data, skb->data + shift, length);
			__skb_trim(skb, length);
			skb_headers_offset_update(skb, -(int)shift);
			atomic64_inc(&diag_host_align_corrected);
			if (skb_headroom(skb) > U16_MAX - skb_headlen(skb)) {
				error = -EMSGSIZE;
				goto alignment_refused;
			}
		}
	}
	if (alignment_start) {
		atomic64_add(ktime_get_mono_fast_ns() - alignment_start,
			     &diag_host_align_timing_ns);
		atomic64_add(skb->len, &diag_host_align_timing_bytes);
		atomic64_inc(&diag_host_align_timing_samples);
	}
	if (READ_ONCE(diag_reserve_once)) {
		/* Actual carrier/byte reservations below and final publication remain.
		 * This omits only a non-reserving duplicate capacity traversal.
		 */
		if (READ_ONCE(diag_io_cost_count))
			atomic64_inc(&diag_ready_skipped);
		if (!READ_ONCE(endpoint->core->io) ||
		    READ_ONCE(endpoint->core->io->closed) ||
		    !qdx_endpoint_command_ready(endpoint)) {
			*ready = (struct qdx_ready) { .status = QDX_CLOSED, .error = -ESHUTDOWN };
			return NULL;
		}
		if (skb->truesize > endpoint->service->qdx->limits.host_data_bytes) {
			*ready = (struct qdx_ready) { .status = QDX_REFUSED, .error = -EMSGSIZE };
			return NULL;
		}
	} else {
		*ready = qdx_data_ready(endpoint, skb->truesize);
		if (ready->status != QDX_ACCEPTED)
			return NULL;
	}
	record = qdx_carrier_get(endpoint->core, QDX_TRANSMIT);
	if (!record) {
		*ready = (struct qdx_ready) { .status = QDX_RESOURCE_WAIT,
			.resources = QDX_RESOURCE_CARRIER, .error = -ENOSPC };
		return NULL;
	}
	if (!qdx_host_reserve(endpoint->service->qdx, skb->truesize)) {
		qdx_carrier_put(endpoint->core, record, false, true);
		*ready = (struct qdx_ready) { .status = QDX_RESOURCE_WAIT,
			.resources = QDX_RESOURCE_HOST_BYTES, .error = -ENOSPC };
		return NULL;
	}
	record->host_charge = skb->truesize;
	record->skb = skb;
	record->length = skb_headroom(skb) + skb_headlen(skb);
	return record;
alignment_refused:
	atomic64_inc(&diag_host_align_refused);
	*ready = (struct qdx_ready) { .status = QDX_REFUSED, .error = error };
	return NULL;
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
	qdx_carrier_put(endpoint->core, record, false, true);
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

	if (category == QDX_RECEIVE_PACKET) {
		if ((!READ_ONCE(diag_mirror_copy) || class_tag != 0x4d435059) &&
		    (!READ_ONCE(diag_mirror_table) || class_tag != 0x4d54424c) &&
		    (!READ_ONCE(diag_clock_copy) || class_tag != QDX_DIAG_CLOCK_TAG))
			return ERR_PTR(-EOPNOTSUPP);
		if (endpoint->service->kind != QDX_SERVICE_MIRROR ||
		    endpoint->dynamic_type != 65)
			return ERR_PTR(-EOPNOTSUPP);
	} else if (category != QDX_RECEIVE_RETURNED &&
		   category != QDX_RECEIVE_BRIDGE_RETURNED) {
		return ERR_PTR(-EOPNOTSUPP);
	}
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
	if (operation->category == QDX_RECEIVE_PACKET &&
	    (!READ_ONCE(diag_mirror_copy) ||
	     endpoint->service->kind != QDX_SERVICE_MIRROR ||
	     endpoint->dynamic_type != 65 || operation->class_tag != 0x4d435059 ||
	     !recipient->owner.module || !recipient->owner.object ||
	     strcmp(module_name(recipient->owner.module), "qdx_mirror_copy_diag")))
		return (struct qdx_ready) { .status = QDX_REFUSED, .error = -EPERM };
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
		qdx_carrier_put(endpoint->core, record, false, true);
		ready = (struct qdx_ready) { .status = QDX_CLOSED, .error = -ESHUTDOWN };
		goto leave;
	}
	refcount_inc(&operation->refs);
	atomic_inc(&endpoint->operations);
	record->operation = operation;
	record->recipient = *recipient;
	record->direction = DMA_BIDIRECTIONAL;
	ready = qdx_packet_publish(endpoint, record, operation->class_tag,
		operation->category == QDX_RECEIVE_PACKET ? QDX_H2N_PACKET :
		operation->category == QDX_RECEIVE_RETURNED ?
		QDX_H2N_RETURNED : QDX_H2N_BRIDGE_RETURNED);
leave:
	qdx_io_leave(endpoint->service->qdx);
	return ready;
}
EXPORT_SYMBOL_GPL(qdx_packet_op_submit);

/* Fixed image data only: no user address, no DMA map and no source writes.
 * The published carrier keeps the actual core/endpoint/operation alive.
 */
struct qdx_ready qdx_diag_clock_submit(struct qdx_packet_op *operation,
	struct qdx_diag_clock_sample *sample, const struct qdx_owner *owner)
{
	struct qdx_endpoint *endpoint = operation->endpoint;
	struct qdx_core *core = endpoint->core;
	struct qdx *qdx = core->qdx;
	struct qdx_carrier *record;
	struct qdx_ready ready;
	struct qdx_h2n_desc desc = {
		.interface = cpu_to_le32(endpoint->ifnum), .type = QDX_H2N_PACKET,
		.payload_len = cpu_to_le16(24),
		.flags = cpu_to_le16(QDX_DESC_FIRST | QDX_DESC_LAST | QDX_DESC_NO_CSUM),
	};
	unsigned long flags;
	int error;

	if (!READ_ONCE(diag_clock_copy) || !sample || !owner || !owner->module ||
	    owner->object != sample || owner->get || owner->put ||
	    strcmp(module_name(owner->module), "qdx_clock_diag") ||
	    operation->category != QDX_RECEIVE_PACKET ||
	    operation->class_tag != QDX_DIAG_CLOCK_TAG ||
	    endpoint->service->kind != QDX_SERVICE_MIRROR || endpoint->dynamic_type != 65 ||
	    core->id || core->image_phys != 0x40000000 || !core->image ||
	    core->image_size < 0x301a70)
		return (struct qdx_ready) { .status = QDX_REFUSED, .error = -EPERM };
	if (!smp_load_acquire(&operation->open) || !qdx_io_enter(qdx))
		return (struct qdx_ready) { .status = QDX_CLOSED, .error = -ESHUTDOWN };
	ready = (struct qdx_ready) { .status = QDX_REFUSED, .error = -EBUSY };
	spin_lock_irqsave(&qdx->io_admission, flags);
	if (core->io->diag_clock_busy) {
		spin_unlock_irqrestore(&qdx->io_admission, flags);
		goto leave;
	}
	core->io->diag_clock_busy = true;
	spin_unlock_irqrestore(&qdx->io_admission, flags);
	record = qdx_carrier_get(core, QDX_TRANSMIT);
	if (!record) {
		ready = (struct qdx_ready) { .status = QDX_RESOURCE_WAIT,
			.resources = QDX_RESOURCE_CARRIER, .error = -ENOSPC };
		goto unborrow;
	}
	if (!qdx_owner_get(owner)) {
		qdx_carrier_put(core, record, false, true);
		ready = (struct qdx_ready) { .status = QDX_CLOSED, .error = -ESHUTDOWN };
		goto unborrow;
	}
	refcount_inc(&operation->refs);
	atomic_inc(&endpoint->operations);
	record->operation = operation;
	record->recipient.owner = *owner;
	record->diag_clock = sample;
	record->dma = 0x40301a58;
	record->length = 24;
	record->direction = DMA_BIDIRECTIONAL;
	error = qdx_publish(core, QDX_DATA_RING, record, &desc);
	if (error) {
		sample->error = error;
		qdx_carrier_put(core, record, false, true);
		ready = (struct qdx_ready) { .status = error == -ENOSPC ?
			QDX_RESOURCE_WAIT : QDX_REFUSED, .error = error,
			.resources = error == -ENOSPC ? QDX_RESOURCE_DESCRIPTOR : 0 };
	} else {
		ready = (struct qdx_ready) { .status = QDX_ACCEPTED };
	}
	goto leave;
unborrow:
	spin_lock_irqsave(&qdx->io_admission, flags);
	core->io->diag_clock_busy = false;
	spin_unlock_irqrestore(&qdx->io_admission, flags);
leave:
	qdx_io_leave(qdx);
	return ready;
}
EXPORT_SYMBOL_GPL(qdx_diag_clock_submit);

/* Scratch insertion after qdx_diag_bf_source ancestry checks.
 * Two real groups in the same unpublished owned parent; never user addresses.
 */
static int qdx_diag_bf_pair_source(struct qdx_core *core,
 const struct qdx_diag_fq_view *view, enum qdx_diag_fq_range kind,
 u32 *source, unsigned int *length)
{
 const struct qdx_diag_bf_pair *pair = view->bf_pair;
 const u8 *group = view->bf_group, *parent = view->bf_parent, *aux;
 u32 primary = get_unaligned_le32(view->node + 4);
 u32 parent_address = get_unaligned_le32(group + 4);
 u32 sentinel = parent_address + 188, link, address, header, alignment;

 if (!pair || (view->bf_valid & 3) != 3) return -EPERM;
 link = get_unaligned_le32(group + 204);
 if (link == sentinel) link = get_unaligned_le32(group + 208);
 if (link < 204) return -ERANGE;
 address = link - 204;
 if (address == primary || address < 0x402eb5ac || address >= 0x402f9dac ||
     (address - 0x402eb5ac) % 232) return -EBADMSG;
 if (kind == QDX_DIAG_BF_AUX_GROUP) {
  *source = address; *length = 232; return 0;
 }
 aux = pair->group;
 if (!(pair->valid & 1) || get_unaligned_le32(aux + 8) != 7 ||
     get_unaligned_le32(aux + 16) != 0x6d060000 ||
     get_unaligned_le32(aux + 20) != get_unaligned_le32(group + 20) || !aux[24] ||
     get_unaligned_le32(aux + 4) != parent_address ||
     get_unaligned_le32(aux + 36) != get_unaligned_le32(group + 36) ||
     get_unaligned_le32(aux + 48) != 0x40086980 ||
     get_unaligned_le32(aux + 60) != 0x40086340 ||
     get_unaligned_le32(aux + 212) || aux[228] || aux[229] ||
     get_unaligned_le32(aux + 224) ||
     get_unaligned_le32(aux + 172) != address + 172 ||
     get_unaligned_le32(aux + 176) != address + 172 ||
     get_unaligned_le32(aux + 188) != address + 188 ||
     get_unaligned_le32(aux + 192) != address + 188) return -EBADMSG;
 /* Exactly two structural members, either legal allocation/attachment order. */
 if (get_unaligned_le32(group + 204) == link) {
  if (get_unaligned_le32(group + 208) != sentinel ||
      get_unaligned_le32(aux + 208) != primary + 204 ||
      get_unaligned_le32(aux + 204) != sentinel ||
      get_unaligned_le32(parent + 188) != primary + 204 ||
      get_unaligned_le32(parent + 192) != link) return -EBADMSG;
 } else if (get_unaligned_le32(group + 204) != sentinel ||
      get_unaligned_le32(aux + 204) != primary + 204 ||
      get_unaligned_le32(aux + 208) != sentinel ||
      get_unaligned_le32(parent + 188) != link ||
      get_unaligned_le32(parent + 192) != primary + 204) return -EBADMSG;
 switch (kind) {
 case QDX_DIAG_BF_AUX_ACCOUNT: address = get_unaligned_le32(aux + 168); *length = 312; break;
 case QDX_DIAG_BF_AUX_TIMER: address = get_unaligned_le32(aux + 220); *length = 32; break;
 case QDX_DIAG_BF_AUX_NOTIFIER: address = get_unaligned_le32(aux + 216); *length = 16; break;
 case QDX_DIAG_BF_AUX_HEADER:
  if (!(view->bf_valid & 4)) return -ENODATA;
  alignment = get_unaligned_le32(view->bf_allocator + 12);
  if (alignment < 4 || alignment > 64 || !is_power_of_2(alignment)) return -EBADMSG;
  header = ALIGN(28, alignment); address = get_unaligned_le32(aux + 168);
  if (address < header || (address & (alignment - 1))) return -EBADMSG;
  address -= header; *length = header; break;
 default: return -EINVAL;
 }
 if ((address & 3) || address < core->image_phys ||
     address - core->image_phys > core->image_size ||
     *length > core->image_size - (address - core->image_phys)) return -ERANGE;
 *source = address;
 return 0;
}

/* Read-only BF ancestry for the diagnostic-owned two-bin leaf. The node
 * constructors allocate companions once per pool slot and never replace them.
 * Module lifetime pins the graph; no user pointer or guessed allocation is used.
 */
static int qdx_diag_bf_source(struct qdx_core *core,
 const struct qdx_diag_fq_view *view, u32 node, enum qdx_diag_fq_range kind,
 u32 *source, unsigned int *length)
{
 const u8 *group = view->bf_group, *parent = view->bf_parent;
 u32 address = get_unaligned_le32(view->node + 4), parent_address;
 u32 alignment, quantum, header;

 if (!view->bf || !view->node[24] || address < 0x402eb5ac ||
     address >= 0x402f9dac || (address - 0x402eb5ac) % 232)
  return -EBADMSG;
 if (kind == QDX_DIAG_BF_GROUP) {
  *source = address; *length = 232; return 0;
 }
 if (!(view->bf_valid & 1) || get_unaligned_le32(group + 8) != 7 ||
     get_unaligned_le32(group + 16) != 0x6d030000 ||
     get_unaligned_le32(group + 20) != get_unaligned_le32(view->node + 20) || !group[24] ||
     get_unaligned_le32(group + 36) != get_unaligned_le32(view->node + 36) ||
     get_unaligned_le32(group + 48) != 0x40086980 ||
     get_unaligned_le32(group + 60) != 0x40086340 ||
     get_unaligned_le32(group + 212) != node)
  return -EBADMSG;
 parent_address = get_unaligned_le32(group + 4);
 if (parent_address < 0x402f9dac || parent_address >= 0x402fa3ec ||
     (parent_address - 0x402f9dac) % 200)
  return -ERANGE;
 if (kind == QDX_DIAG_BF_PARENT) {
  *source = parent_address; *length = 200; return 0;
 }
 if (!(view->bf_valid & 2) || get_unaligned_le32(parent + 8) != 6 ||
     get_unaligned_le32(parent + 16) != 0x6d020000 ||
     get_unaligned_le32(parent + 20) != get_unaligned_le32(view->node + 20) || parent[24] ||
     get_unaligned_le32(parent + 4) ||
     get_unaligned_le32(parent + 36) != get_unaligned_le32(group + 36) ||
     get_unaligned_le32(parent + 48) != 0x40087400 ||
     get_unaligned_le32(parent + 60) != 0x400870a0)
  return -EBADMSG;
 if (kind >= QDX_DIAG_BF_AUX_GROUP && kind <= QDX_DIAG_BF_AUX_HEADER)
  return qdx_diag_bf_pair_source(core, view, kind, source, length);
 switch (kind) {
 case QDX_DIAG_BF_ACCOUNT: address = get_unaligned_le32(group + 168); *length = 312; break;
 case QDX_DIAG_BF_ALLOCATOR: address = 0x40298720; *length = 24; break;
 case QDX_DIAG_BF_ACCOUNT_HEADER:
  if (!(view->bf_valid & 4)) return -ENODATA;
  alignment = get_unaligned_le32(view->bf_allocator + 12);
  quantum = get_unaligned_le32(view->bf_allocator + 16);
  if (alignment < 4 || alignment > 64 || !is_power_of_2(alignment) ||
      quantum < 4 || quantum > 1024 || !is_power_of_2(quantum)) return -EBADMSG;
  header = ALIGN(28, alignment);
  address = get_unaligned_le32(group + 168);
  if (address < header || (address & (alignment - 1))) return -EBADMSG;
  address -= header; *length = header; break;
 case QDX_DIAG_BF_TIMER: address = get_unaligned_le32(group + 220); *length = 32; break;
 case QDX_DIAG_BF_NOTIFIER: address = get_unaligned_le32(group + 216); *length = 16; break;
 case QDX_DIAG_BF_EPOCH: address = 0x402d801c; *length = 20; break;
 case QDX_DIAG_BF_FREQUENCY: address = 0x40301a90; *length = 16; break;
 default: return 0; /* Validated frozen ancestry for a normal FQ range. */
 }
 if (address & 3 || address < core->image_phys ||
     address - core->image_phys > core->image_size ||
     *length > core->image_size - (address - core->image_phys))
  return -ERANGE;
 *source = address;
 return 0;
}

/* Fixed two-group BF diagnostic sources. Pool observations are read-only;
 * derived account/timer reads require actual completed object snapshots. */
static int qdx_diag_bf_cycle_source(struct qdx_core *core,
 const struct qdx_diag_fq_view *view, enum qdx_diag_fq_range kind,
 unsigned int index, u32 *source, unsigned int *length)
{
 const struct qdx_diag_bf_cycle *cycle = view->bf_cycle;
 const u8 *group;
 u32 address, alignment, header;

 if (!cycle || index >= 4 || !(cycle->group_valid & BIT(index)) ||
     core->id || core->image_phys != 0x40000000) return -EPERM;
 address = cycle->group_address[index]; group = cycle->group[index];
 /* A completed native FREE invalidates live lookup. The saved companion
  * timer remains allocated with this fixed GROUP slot, provided the caller
  * excludes ALL scheduler allocation until the post-FREE manager join. */
 if (kind == QDX_DIAG_BF_CYCLE_RETIRED_TIMER) {
  if (index != cycle->retired_index || !cycle->retired_valid) return -EPERM;
  address = cycle->retired_address; group = cycle->retired_group;
 }
 if (address < 0x402eb5ac || address >= 0x402f9dac || (address - 0x402eb5ac) % 232 ||
     get_unaligned_le32(group + 8) != 7 || get_unaligned_le32(group + 16) != cycle->group_tag[index] ||
     (cycle->group_tag[index] != 0x6d030000 && cycle->group_tag[index] != 0x6d060000 &&
      cycle->group_tag[index] != 0x6d070000 && cycle->group_tag[index] != 0x6d080000) ||
     get_unaligned_le32(group + 20) != cycle->generation ||
     get_unaligned_le32(group + 36) != cycle->root_pointer ||
     get_unaligned_le32(group + 48) != 0x40086980 ||
     get_unaligned_le32(group + 60) != 0x40086340) return -ESTALE;
 switch (kind) {
 case QDX_DIAG_BF_CYCLE_ACCOUNT: address = get_unaligned_le32(group + 168); *length = 312; break;
 case QDX_DIAG_BF_CYCLE_RETIRED_TIMER:
 case QDX_DIAG_BF_CYCLE_TIMER: address = get_unaligned_le32(group + 220); *length = 32; break;
 case QDX_DIAG_BF_CYCLE_NOTIFIER: address = get_unaligned_le32(group + 216); *length = 16; break;
 case QDX_DIAG_BF_CYCLE_ALLOCATOR: address = 0x40298720; *length = 24; break;
 case QDX_DIAG_BF_CYCLE_EPOCH: address = 0x402d801c; *length = 20; break;
 case QDX_DIAG_BF_CYCLE_CLOCK: address = 0x40301a58; *length = 24; break;
 case QDX_DIAG_BF_CYCLE_HEADER:
  alignment = get_unaligned_le32(view->bf_allocator + 12);
  if (!(view->bf_valid & 4) || alignment < 4 || alignment > 64 ||
      !is_power_of_2(alignment)) return -EBADMSG;
  header = ALIGN(28, alignment); address = get_unaligned_le32(group + 168);
  if (address < header || (address & (alignment - 1))) return -ERANGE;
  address -= header; *length = header; break;
 default: return -EINVAL;
 }
 if ((address & 3) || address < core->image_phys ||
     address - core->image_phys > core->image_size ||
     *length > core->image_size - (address - core->image_phys)) return -ERANGE;
 *source = address;
 return 0;
}

/* Read-only WRR state reached through its actual occupied FQ anchor. The
 * module owns all three children and keeps the outer selection edge detached.
 * Structural list order is independent of active scheduling order.
 */
static int qdx_diag_wrr_source(const struct qdx_diag_fq_view *view, u32 node,
 enum qdx_diag_fq_range kind, unsigned int index, u32 *source, unsigned int *length)
{
 const u8 *anchor = view->wrr_group[0], *root = view->wrr_root, *group;
 u32 address = get_unaligned_le32(view->node + 4), parent, cursor, previous, tag;
 unsigned int n, copied = 0;

 if (!view->wrr || view->bf || !view->node[24] || address < 0x40312878 ||
     address >= 0x40314ec0 || (address - 0x40312878) % 196)
  return -EBADMSG;
 if (kind == QDX_DIAG_WRR_ANCHOR_GROUP) {
  *source = address; *length = 196; return 0;
 }
 if (!(view->wrr_valid & 1) || get_unaligned_le32(anchor + 8) != 10 ||
     get_unaligned_le32(anchor + 16) != 0x6f020000 ||
     get_unaligned_le32(anchor + 20) != get_unaligned_le32(view->node + 20) || !anchor[24] ||
     get_unaligned_le32(anchor + 36) != get_unaligned_le32(view->node + 36) ||
     get_unaligned_le32(anchor + 48) != 0x400a7c80 ||
     get_unaligned_le32(anchor + 60) != 0x400a7a80 ||
     get_unaligned_le32(anchor + 68) != 0x400a7b80 ||
     get_unaligned_le32(anchor + 72) != 0x400a7a40 ||
     get_unaligned_le32(anchor + 188) != node)
  return -EBADMSG;
 parent = get_unaligned_le32(anchor + 4);
 if (parent < 0x40312120 || parent >= 0x40312878 ||
     (parent - 0x40312120) % 188)
  return -ERANGE;
 if (kind == QDX_DIAG_WRR_ROOT) {
  *source = parent; *length = 188; return 0;
 }
 if (!(view->wrr_valid & 2) || get_unaligned_le32(root + 8) != 9 ||
     get_unaligned_le32(root + 16) != 0x6f010000 ||
     get_unaligned_le32(root + 20) != get_unaligned_le32(view->node + 20) || root[24] || get_unaligned_le32(root + 4) ||
     get_unaligned_le32(root + 36) != get_unaligned_le32(anchor + 36) ||
     get_unaligned_le32(root + 48) != 0x400a7660 ||
     get_unaligned_le32(root + 60) != 0x400a7380 ||
     get_unaligned_le32(root + 68) != 0x400a72c0 ||
     get_unaligned_le32(root + 72) != 0x400a7180 ||
     (get_unaligned_le32(root + 184) != 0x400a7060 &&
      get_unaligned_le32(root + 184) != 0x400a7080))
  return -EBADMSG;
 if (kind != QDX_DIAG_WRR_GROUP || index < 1 || index > 2)
  return -EPERM;
 cursor = get_unaligned_le32(root + 172);
 previous = parent + 172;
 for (n = 0; n < 3; n++) {
  if (cursor < 0x40312878 + 180 || cursor >= 0x40314ec0 + 180 ||
      (cursor - 0x40312878 - 180) % 196)
   return -ERANGE;
  if (cursor == address + 180) {
   group = anchor;
  } else {
   copied++;
   if (copied == index) {
    *source = cursor - 180; *length = 196; return 0;
   }
   if (!(view->wrr_valid & BIT(copied + 1))) return -ENODATA;
   group = view->wrr_group[copied];
   tag = get_unaligned_le32(group + 16);
   if (get_unaligned_le32(group + 8) != 10 ||
       (tag != 0x6f030000 && tag != 0x6f040000) ||
       get_unaligned_le32(group + 20) != get_unaligned_le32(view->node + 20) || !group[24] ||
       get_unaligned_le32(group + 4) != parent ||
       get_unaligned_le32(group + 36) != get_unaligned_le32(anchor + 36) ||
       get_unaligned_le32(group + 48) != 0x400a7c80 ||
       get_unaligned_le32(group + 60) != 0x400a7a80 ||
       get_unaligned_le32(group + 68) != 0x400a7b80 ||
       get_unaligned_le32(group + 72) != 0x400a7a40)
    return -EBADMSG;
  }
  if (get_unaligned_le32(group + 184) != previous) return -EBADMSG;
  previous = cursor;
  cursor = get_unaligned_le32(group + 180);
 }
 return -EBADMSG;
}

/* All range identities derive from the actual owned table and completed
 * snapshots. No caller-supplied source address or source length is accepted.
 * The module must keep its graph unreachable and its closed producer alive.
 */
/* One private IGS rate graph. All locations follow its actual occupied anchor;
 * these reads do not grant old diagnostics another private-memory capability.
 */
static int qdx_diag_rate_group(const struct qdx_diag_rate_view *rate, u32 shaper,
 unsigned int index, u32 *address)
{
 const u8 *group = rate->group[0];
 u32 root = get_unaligned_le32(rate->selector + 164), cursor, previous, tag;
 unsigned int i;

 if (!rate->group_mode || index > 3 || root < 0x40298794 ||
     root >= 0x402d7394 || (root - 0x40298794) % 1004)
  return -ERANGE;
 if (!index) { *address = root; return 0; }
 if (!(rate->valid & QDX_RATE_GROUP_VALID(0)) ||
     get_unaligned_le32(group + 8) != 12 ||
     get_unaligned_le32(group + 16) != 0x71010000 ||
     get_unaligned_le32(group + 20) != get_unaligned_le32(rate->selector + 20) || !group[24] ||
     get_unaligned_le32(group + 36) != shaper ||
     get_unaligned_le32(group + 48) != 0x400608e0 ||
     get_unaligned_le32(group + 60) != 0x4005fbc0 ||
     get_unaligned_le32(group + 164))
  return -EBADMSG;
 cursor = get_unaligned_le32(group + 168);
 previous = root + 168;
 for (i = 1; i <= index; i++) {
  if (cursor < 0x40298794 + 964 || cursor >= 0x402d7394 + 964 ||
      (cursor - 0x40298794 - 964) % 1004)
   return -ERANGE;
  if (i == index) { *address = cursor - 964; return 0; }
  if (!(rate->valid & QDX_RATE_GROUP_VALID(i))) return -ENODATA;
  group = rate->group[i];
  tag = get_unaligned_le32(group + 16);
  if (get_unaligned_le32(group + 8) != 12 ||
      tag < 0x71200000 || tag > 0x713f0000 || (tag & 0xffff) ||
      get_unaligned_le32(group + 20) != get_unaligned_le32(rate->selector + 20) || !group[24] ||
      get_unaligned_le32(group + 4) != root ||
      get_unaligned_le32(group + 36) != shaper ||
      get_unaligned_le32(group + 48) != 0x400608e0 ||
      get_unaligned_le32(group + 60) != 0x4005fbc0 ||
      get_unaligned_le32(group + 968) != previous)
   return -EBADMSG;
  previous = cursor;
  cursor = get_unaligned_le32(group + 964);
 }
 return -EBADMSG;
}

static int qdx_diag_rate_source(struct qdx_core *core,
 const struct qdx_diag_fq_view *view, u32 node, enum qdx_diag_fq_range kind,
 unsigned int index, u32 *source, unsigned int *length)
{
 const struct qdx_diag_rate_view *rate = view->rate;
 const u8 *selector, *tbl;
 u32 address, parent = get_unaligned_le32(view->node + 4), shaper;
 u32 alignment, quantum, header, tag;
 int error;

 if (!rate || view->bf || view->wrr || !view->node[24] ||
     parent < 0x402e57ec || parent >= 0x402eb5ac ||
     (parent - 0x402e57ec) % 1200)
  return -EBADMSG;
 if (kind == QDX_DIAG_RATE_SELECTOR) {
  *source = parent; *length = 320; return 0;
 }
 selector = rate->selector;
 shaper = get_unaligned_le32(view->node + 36);
 if (!(rate->valid & QDX_RATE_SELECTOR_VALID) ||
     get_unaligned_le32(selector + 8) != 3 ||
     get_unaligned_le32(selector + 16) != 0x71080000 ||
     get_unaligned_le32(selector + 20) != get_unaligned_le32(view->node + 20) || selector[24] ||
     get_unaligned_le32(selector + 4) ||
     get_unaligned_le32(selector + 36) != shaper ||
     get_unaligned_le32(selector + 48) != 0x40085340 ||
     get_unaligned_le32(selector + 60) != 0x40085100 ||
     get_unaligned_le32(selector + 68) != 0x40084f80 ||
     get_unaligned_le32(selector + 72) != 0x40084e20 ||
     get_unaligned_le32(selector + 168) != node)
  return -EBADMSG;
 switch (kind) {
 case QDX_DIAG_RATE_EPOCH: address = 0x402d801c; *length = 20; goto bounded;
 case QDX_DIAG_RATE_FREQUENCY: address = 0x40301a90; *length = 16; goto bounded;
 case QDX_DIAG_RATE_CLOCK: address = 0x40301a58; *length = 24; goto bounded;
 case QDX_DIAG_RATE_ALLOCATOR: address = 0x40298720; *length = 24; goto bounded;
 case QDX_DIAG_RATE_GROUP_ROOT:
 case QDX_DIAG_RATE_GROUP_CHILD:
  error = qdx_diag_rate_group(rate, shaper,
   kind == QDX_DIAG_RATE_GROUP_ROOT ? 0 : index, &address);
  if (error) return error;
  if (kind == QDX_DIAG_RATE_GROUP_CHILD && !index) return -EINVAL;
  *length = 1004; goto bounded;
 case QDX_DIAG_RATE_SPARE_GROUP:
  if (!rate->group_mode || index >= 32) return -EINVAL;
  address = get_unaligned_le32(selector + 176 + 4 * index);
  if (address < 0x40298794 || address >= 0x402d7394 ||
      (address - 0x40298794) % 1004)
   return -ERANGE;
  *length = 1004; goto bounded;
 default: break;
 }
 if (kind == QDX_DIAG_RATE_CLOCK_TBL || kind == QDX_DIAG_RATE_CLOCK_ACCOUNT) {
  address = get_unaligned_le32(selector + 172);
  tbl = rate->clock_tbl; tag = 0x71020000;
  if (kind != QDX_DIAG_RATE_CLOCK_TBL && !(rate->valid & QDX_RATE_CLOCK_VALID))
   return -ENODATA;
 } else {
  if (rate->group_mode) return -EPERM;
  address = get_unaligned_le32(selector + 164);
  tbl = rate->tbl; tag = 0x71010000;
  if (kind != QDX_DIAG_RATE_TBL && !(rate->valid & QDX_RATE_TBL_VALID))
   return -ENODATA;
 }
 if (address < 0x402fd0e4 || address >= 0x40301a54 ||
     (address - 0x402fd0e4) % 188)
  return -ERANGE;
 if (kind == QDX_DIAG_RATE_TBL || kind == QDX_DIAG_RATE_CLOCK_TBL) {
  *length = 188; goto bounded;
 }
 if (get_unaligned_le32(tbl + 8) != 5 || get_unaligned_le32(tbl + 16) != tag ||
     get_unaligned_le32(tbl + 20) != get_unaligned_le32(view->node + 20) || !tbl[24] ||
     get_unaligned_le32(tbl + 4) != parent ||
     get_unaligned_le32(tbl + 36) != shaper ||
     get_unaligned_le32(tbl + 48) != 0x400898e0 ||
     get_unaligned_le32(tbl + 60) != 0x40089500 ||
     get_unaligned_le32(tbl + 68) != 0x400892c0 ||
     get_unaligned_le32(tbl + 72) != 0x40089280 ||
     (tag == 0x71020000 && get_unaligned_le32(tbl + 172)))
  return -EBADMSG;
 switch (kind) {
 case QDX_DIAG_RATE_ACCOUNT:
 case QDX_DIAG_RATE_CLOCK_ACCOUNT:
  address = get_unaligned_le32(tbl + 164); *length = 312; break;
 case QDX_DIAG_RATE_TIMER:
  address = get_unaligned_le32(tbl + 176); *length = 32; break;
 case QDX_DIAG_RATE_NOTIFIER:
  address = get_unaligned_le32(tbl + 168); *length = 16; break;
 case QDX_DIAG_RATE_ACCOUNT_HEADER:
  if (!(rate->valid & QDX_RATE_ALLOCATOR_VALID)) return -ENODATA;
  alignment = get_unaligned_le32(rate->allocator + 12);
  quantum = get_unaligned_le32(rate->allocator + 16);
  if (alignment < 4 || alignment > 64 || !is_power_of_2(alignment) ||
      quantum < 4 || quantum > 1024 || !is_power_of_2(quantum))
   return -EBADMSG;
  header = ALIGN(28, alignment);
  address = get_unaligned_le32(tbl + 164);
  if (address < header || address & (alignment - 1)) return -EBADMSG;
  address -= header; *length = header; break;
 default: return -EPERM;
 }
bounded:
 if ((address & 3) || address < core->image_phys ||
     address - core->image_phys > core->image_size ||
     *length > core->image_size - (address - core->image_phys))
  return -ERANGE;
 *source = address;
 return 0;
}

/* Only the separately owned AQM graph grants these fixed-image ranges. */
/* Physical endpoint identity is shared by core/ifnum, regardless of which
 * service first created that static endpoint. Validate static physical identity
 * below; its creating service may legitimately be ETHERNET, not SHAPER.
 */
static int qdx_diag_aqm_source(struct qdx_endpoint *mirror,
 const struct qdx_diag_fq_view *view, u32 anchor, enum qdx_diag_fq_range kind,
 unsigned int index, bool physical, u32 *source, unsigned int *length)
{
 const struct qdx_diag_aqm_view *aqm = view->aqm;
 const struct qdx_packet_op *data_op;
 struct qdx_core *core = mirror->core;
 struct qdx_io *io = core->io;
 struct qdx_carrier *record;
 const u8 *node, *carrier, *metadata;
 u32 parent, shaper, address, count, head, tail, stride, meta, slot, buffer, data;
 u32 packet_length, buffer_length, base, size;
 unsigned long flags;
 unsigned int i;
 u64 cookie;
 bool valid;

 if (!aqm || view->bf || view->wrr || view->rate ||
     (!physical && (view->physical_rebuild || aqm->physical_rebuild)) ||
     (physical && aqm->data) || !view->node[24]) return -EPERM;
 parent = get_unaligned_le32(view->node + 4);
 shaper = get_unaligned_le32(view->node + 36);
 if (parent < 0x402e57ec || parent >= 0x402eb5ac ||
     (parent - 0x402e57ec) % 1200) return -ERANGE;
 if (kind == QDX_DIAG_AQM_SELECTOR) {
  *source = parent; *length = 320; return 0;
 }
 if (!(aqm->valid & QDX_AQM_SELECTOR_VALID) ||
     get_unaligned_le32(aqm->selector + 8) != 3 ||
     get_unaligned_le32(aqm->selector + 16) != QDX_AQM_PARENT_TAG ||
     get_unaligned_le32(aqm->selector + 20) != get_unaligned_le32(view->node + 20) || aqm->selector[24] ||
     get_unaligned_le32(aqm->selector + 4) ||
     get_unaligned_le32(aqm->selector + 36) != shaper ||
     get_unaligned_le32(aqm->selector + 48) != 0x40085340 ||
     get_unaligned_le32(aqm->selector + 60) != 0x40085100 ||
     get_unaligned_le32(aqm->selector + 68) != 0x40084f80 ||
     get_unaligned_le32(aqm->selector + 72) != 0x40084e20 ||
     get_unaligned_le32(aqm->selector + 168) != anchor)
  return -EBADMSG;
 for (i = 172; i < 320; i += 4)
  if (get_unaligned_le32(aqm->selector + i)) return -EBADMSG;
 address = get_unaligned_le32(aqm->selector + 164);
 base = aqm->plain ? 0x4027b62c : 0x40301d20;
 size = aqm->plain ? 280 : 520;
 if (address < base || address >= (aqm->plain ? 0x4028ce2c : 0x40312120) ||
     (address - base) % size || address == anchor) return -ERANGE;
 if (kind == QDX_DIAG_AQM_NODE) {
  *source = address; *length = size; return 0;
 }
 node = aqm->node;
 if (!(aqm->valid & QDX_AQM_NODE_VALID) || get_unaligned_le32(node) ||
     get_unaligned_le32(node + 8) != (aqm->plain ? 1 : 13) ||
     (get_unaligned_le32(node + 16) != QDX_AQM_LEAF_A_TAG &&
      get_unaligned_le32(node + 16) != QDX_AQM_LEAF_B_TAG &&
      get_unaligned_le32(node + 16) != QDX_AQM_LEAF_C_TAG &&
      get_unaligned_le32(node + 16) != QDX_AQM_LEAF_D_TAG) ||
     get_unaligned_le32(node + 20) != get_unaligned_le32(view->node + 20) || !node[24] ||
     get_unaligned_le32(node + 4) != parent ||
     get_unaligned_le32(node + 36) != shaper ||
     get_unaligned_le32(node + 48) != (aqm->plain ? 0x40052000 : 0x400a6ea0) ||
     get_unaligned_le32(node + 52) != (aqm->plain ? 0x40051f80 : 0x400a6e20) ||
     get_unaligned_le32(node + 56) != (aqm->plain ? 0x40052160 : 0x400a6d80) ||
     get_unaligned_le32(node + 60) != (aqm->plain ? 0x40051ce0 : 0x400a6a80) ||
     get_unaligned_le32(node + 64) != (aqm->plain ? 0x40051aa0 : 0x400a6800) ||
     (aqm->plain && get_unaligned_le32(node + 264))) return -EBADMSG;
 if (kind == QDX_DIAG_AQM_CLOCK) {
  *source = 0x40301a58; *length = 24; return 0;
 }
 count = get_unaligned_le32(node + (aqm->plain ? 180 : 172));
 head = get_unaligned_le32(node + (aqm->plain ? 172 : 164));
 tail = get_unaligned_le32(node + (aqm->plain ? 176 : 168));
 data_op = aqm->data;
 if (!physical && (!data_op || data_op->endpoint->core != core ||
     data_op->endpoint->service->qdx != mirror->service->qdx ||
     data_op->endpoint->service->kind != QDX_SERVICE_IGS ||
     data_op->endpoint->dynamic_type != 53 ||
     data_op->category != QDX_RECEIVE_RETURNED ||
     data_op->class_tag != get_unaligned_le32(node + 16) ||
     smp_load_acquire(&data_op->open) || READ_ONCE(data_op->accepted) != count))
  return -EPERM;
 if (count > 16 || !count || index >= count || !head || !tail) return -EPERM;
 if (index && !(aqm->carrier_valid & BIT(index - 1))) return -ENODATA;
 address = index ? get_unaligned_le32(aqm->carrier[index - 1]) : head;
 if (address >= 0x3f0120a8 && address < 0x3f0120a8 + 1736 * 56 &&
     !((address - 0x3f0120a8) % 56)) {
  slot = (address - 0x3f0120a8) / 56;
  meta = 0x40168ac0 + slot * 96; stride = 56;
 } else if (address >= 0x400ccac0 && address < 0x400ccac0 + 9984 * 64 &&
            !((address - 0x400ccac0) % 64)) {
  slot = (address - 0x400ccac0) / 64;
  meta = 0x401915c0 + slot * 96; stride = 64;
 } else return -ERANGE;
 for (i = 0; i < index; i++)
  if ((aqm->carrier_valid & BIT(i)) && aqm->carrier_address[i] == address) return -ELOOP;
 if (index == count - 1 && address != tail) return -EBADMSG;
 if (kind == QDX_DIAG_AQM_CARRIER) { *source = address; *length = stride; return 0; }
 carrier = aqm->carrier[index];
 if (!(aqm->carrier_valid & BIT(index)) || aqm->carrier_address[index] != address ||
     get_unaligned_le32(carrier + 36) != meta ||
     (index == count - 1 && get_unaligned_le32(carrier))) return -EBADMSG;
 if (kind == QDX_DIAG_AQM_METADATA) { *source = meta; *length = 96; return 0; }
 if (kind != QDX_DIAG_AQM_PAYLOAD || !(aqm->metadata_valid & BIT(index))) return -EPERM;
 metadata = aqm->metadata[index];
 cookie = get_unaligned_le64(metadata + 4);
 if (!(cookie >> 32) || (cookie & GENMASK_ULL(30, 16)) ||
     ((cookie >> 31) & 1) != core->id) return -EBADMSG;
 buffer = get_unaligned_le32(carrier + 8);
 data = get_unaligned_le32(carrier + 24);
 packet_length = get_unaligned_le16(carrier + 46);
 buffer_length = get_unaligned_le16(carrier + 44);
 spin_lock_irqsave(&io->carriers_lock, flags);
 record = qdx_slot(io, cookie & 0xffff);
 valid = record && record->state == QDX_PUBLISHED && record->generation == cookie >> 32 &&
  record->mapped && record->dma == buffer && buffer_length <= record->length &&
  data >= buffer && data - buffer <= buffer_length && packet_length >= 64 &&
  packet_length <= 1514 && packet_length <= buffer_length - (data - buffer);
 if (valid && physical) {
  if (!aqm->physical_rebuild) {
   valid = !record->operation && !record->accepted &&
    record->direction == DMA_FROM_DEVICE &&
    ((record->kind == QDX_LINEAR && record->skb && !record->page) ||
     (record->kind == QDX_PAGED && record->page && !record->skb));
  } else {
   valid = record->kind == QDX_TRANSMIT && record->accepted && !record->operation &&
    record->path && record->path == aqm->physical_rebuild && record->skb &&
    record->direction == DMA_TO_DEVICE && record->path->endpoint->core == core &&
    record->path->endpoint->service->qdx == mirror->service->qdx &&
    !record->path->endpoint->dynamic_type &&
    record->path->endpoint->ifnum == 4 &&
    record->path->class.tag == get_unaligned_le32(node + 16) &&
    !smp_load_acquire(&record->path->open) && READ_ONCE(record->path->accepted) == count &&
    record->length == buffer_length && record->skb->len == packet_length &&
    data - buffer == skb_headroom(record->skb);
  }
 } else if (valid) {
  valid = record->kind == QDX_TRANSMIT && record->accepted && record->operation == data_op &&
   record->skb && record->direction == DMA_BIDIRECTIONAL && record->recipient.owner.module &&
   !strcmp(module_name(record->recipient.owner.module), "qdx_aqm_handover_diag") &&
   record->length == buffer_length && record->skb->len == packet_length &&
   data - buffer == skb_headroom(record->skb);
 }
 spin_unlock_irqrestore(&io->carriers_lock, flags);
 if (!valid) return -ESTALE;
 *source = data; *length = packet_length;
 return 0;
}

/* Two private physical anchor packets prove a closed SHAPER owner. Their
 * carrier/metadata copies come from this registered table; no supplied path
 * is dereferenced until it matches the actual live carrier's retained path.
 */
static int qdx_diag_physical_anchor(struct qdx_endpoint *mirror,
 const struct qdx_diag_fq_view *view)
{
 struct qdx_core *core = mirror->core;
 struct qdx_io *io = core->io;
 struct qdx_carrier *record;
 const u8 *bin, *carrier;
 unsigned long flags;
 u64 cookie[2];
 u32 address, metadata, buffer[2], data[2], extent[2];
 unsigned int i;
 bool valid = true;

 if (!view->physical_rebuild || view->bf || view->aqm ||
     (!!view->rate == !!view->wrr) || view->carrier_valid != 3 ||
     view->metadata_valid != 3 || !view->node_valid || !view->node[24])
  return -EPERM;
 for (i = 0; i < 2; i++) {
  bin = view->table + i * 72;
  carrier = view->carrier[i];
  address = view->carrier_address[i];
  if (get_unaligned_le32(bin + 24) != 1 ||
      get_unaligned_le32(bin + 64) != 128 ||
      get_unaligned_le32(bin + 16) != address ||
      get_unaligned_le32(bin + 20) != address ||
      get_unaligned_le32(carrier) ||
      (i && address == view->carrier_address[0])) return -EBADMSG;
  if (address >= 0x3f0120a8 && address < 0x3f0120a8 + 1736 * 56 &&
      !((address - 0x3f0120a8) % 56))
   metadata = 0x40168ac0 + ((address - 0x3f0120a8) / 56) * 96;
  else if (address >= 0x400ccac0 && address < 0x400ccac0 + 9984 * 64 &&
           !((address - 0x400ccac0) % 64))
   metadata = 0x401915c0 + ((address - 0x400ccac0) / 64) * 96;
  else return -ERANGE;
  if (get_unaligned_le32(carrier + 36) != metadata ||
      get_unaligned_le16(carrier + 46) != 128) return -EBADMSG;
  cookie[i] = get_unaligned_le64(view->metadata[i] + 4);
  if (!(cookie[i] >> 32) || (cookie[i] & GENMASK_ULL(30, 16)) ||
      ((cookie[i] >> 31) & 1) != core->id || (i && cookie[i] == cookie[0]))
   return -EBADMSG;
  buffer[i] = get_unaligned_le32(carrier + 8);
  data[i] = get_unaligned_le32(carrier + 24);
  extent[i] = get_unaligned_le16(carrier + 44);
  if (data[i] < buffer[i] || data[i] - buffer[i] > extent[i] ||
      128 > extent[i] - (data[i] - buffer[i])) return -ERANGE;
 }
 spin_lock_irqsave(&io->carriers_lock, flags);
 for (i = 0; i < 2 && valid; i++) {
  record = qdx_slot(io, cookie[i] & 0xffff);
  valid = record && record->state == QDX_PUBLISHED &&
   record->generation == cookie[i] >> 32 && record->kind == QDX_TRANSMIT &&
   record->mapped && record->accepted && !record->operation &&
   record->direction == DMA_TO_DEVICE && record->dma == buffer[i] &&
   record->length == extent[i] && record->skb && record->skb->len == 128 &&
   data[i] - buffer[i] == skb_headroom(record->skb) &&
   record->path && record->path == view->physical_rebuild &&
   record->path->endpoint->core == core &&
   record->path->endpoint->service->qdx == mirror->service->qdx &&
   !record->path->endpoint->dynamic_type &&
   record->path->endpoint->ifnum == 4 && record->path->class.tag == 0x6d010000 &&
   !smp_load_acquire(&record->path->open) && READ_ONCE(record->path->accepted) == 2;
 }
 spin_unlock_irqrestore(&io->carriers_lock, flags);
 return valid ? 0 : -ESTALE;
}

/* Called only with io->carriers_lock held. Witness pointers are compared to
 * actual published records before any path dereference. The two real closed
 * producer populations remain distinct until their own completions.
 */
static bool qdx_diag_fq_staging_paths_locked(struct qdx_core *core,
 const struct qdx_diag_fq_view *view, unsigned int total)
{
 const struct qdx_tx_path *actual[2] = {};
 struct qdx_io *io = core->io;
 struct qdx_carrier *record;
 unsigned int count[2] = {}, i, path;
 u64 cookie, seen[16];
 u32 buffer, data;
 unsigned int length, extent, j;

 if (!view->physical_rebuild ||
     view->physical_rebuild_next == view->physical_rebuild ||
     total > 16 || view->carrier_valid != GENMASK(total - 1, 0) ||
     view->metadata_valid != GENMASK(total - 1, 0)) return false;
 for (i = 0; i < total; i++) {
  cookie = get_unaligned_le64(view->metadata[i] + 4);
  if (!(cookie >> 32) || (cookie & GENMASK_ULL(30, 16)) ||
      ((cookie >> 31) & 1) != core->id) return false;
  for (j = 0; j < i; j++) if (seen[j] == cookie) return false;
  seen[i] = cookie;
  record = qdx_slot(io, cookie & 0xffff);
  buffer = get_unaligned_le32(view->carrier[i] + 8);
  data = get_unaligned_le32(view->carrier[i] + 24);
  length = get_unaligned_le16(view->carrier[i] + 46);
  extent = get_unaligned_le16(view->carrier[i] + 44);
  if (!record || record->state != QDX_PUBLISHED ||
      record->generation != cookie >> 32 || record->kind != QDX_TRANSMIT ||
      !record->mapped || !record->accepted || record->operation || !record->skb ||
      !record->path || record->direction != DMA_TO_DEVICE || record->dma != buffer ||
      record->length != extent || !length || length > 2048 ||
      data < buffer || data - buffer > extent || length > extent - (data - buffer) ||
      record->skb->len != length || data - buffer != skb_headroom(record->skb)) return false;
  if (record->path == view->physical_rebuild) path = 0;
  else if (record->path == view->physical_rebuild_next) path = 1;
  else return false;
  actual[path] = record->path;
  if (record->path->endpoint->core != core ||
      record->path->endpoint->service->qdx != core->qdx ||
      record->path->endpoint->dynamic_type || record->path->endpoint->ifnum != 4 ||
      record->path->class.tag != 0x6d010000 ||
      smp_load_acquire(&record->path->open)) return false;
  count[path]++;
 }
 if (!actual[0] || READ_ONCE(actual[0]->accepted) != count[0]) return false;
 if (view->physical_rebuild_next &&
     (!actual[1] || READ_ONCE(actual[1]->accepted) != count[1])) return false;
 return true;
}

static int qdx_diag_fq_source(struct qdx_endpoint *mirror,
 struct qdx_packet_op *loans, const struct qdx_diag_fq_view *view,
 enum qdx_diag_fq_range kind, unsigned int index, u32 table_address,
 u32 registered_node, bool physical, u32 *source, unsigned int *length)
{
 struct qdx_core *core = mirror->core;
 struct qdx_carrier *record;
 struct qdx_io *io = core->io;
 const u8 *bin, *carrier, *metadata;
 unsigned long flags;
 u64 cookie;
 u32 node, address, meta_address, pool_index, stride, data, buffer, first, total;
 u32 second, previous, cursor, sentinel, mask, seen, slot, next;
 unsigned int list, n;
 unsigned int i, packet_length, buffer_length;
 int error;
 bool valid;

 if (!view || core->id || core->image_phys != 0x40000000)
  return -EPERM;
 if ((view->physical_staging && (!physical || !view->physical_rebuild ||
      view->bf || view->rate || view->wrr || view->aqm)) ||
     (!view->physical_staging && view->physical_rebuild_next)) return -EPERM;
 if (physical) {
  /* This mode is selected by the registered SHAPER table, never by NULL
   * alone. The module has detached and fenced its real physical subtree.
   */
  if (loans)
   return -EPERM;
 } else if (!loans || loans->endpoint->core != core ||
     loans->endpoint->service->qdx != mirror->service->qdx ||
     loans->endpoint->service->kind != QDX_SERVICE_IGS ||
     loans->endpoint->dynamic_type != 53 || loans->category != QDX_RECEIVE_RETURNED ||
     loans->class_tag != 0x6d010000 || smp_load_acquire(&loans->open)) {
  return -EPERM;
 }
 first = get_unaligned_le32(view->table + 24);
 second = get_unaligned_le32(view->table + 96);
 total = first + second;
 if (physical) {
  if (first > 16 || second > 16 || !total || total > 16)
   return -EPERM;
  if ((view->rate || view->wrr) &&
      (first != 1 || second != 1 || !view->physical_rebuild || view->aqm ||
       (!!view->rate == !!view->wrr))) return -EPERM;
 } else if (!first || first >= 16 || total <= first || total > 16 ||
            READ_ONCE(loans->accepted) != total || view->physical_rebuild) {
  return -EPERM;
 }
 node = registered_node;
 if (!node && !physical) node = get_unaligned_le32(view->table + 4) - 228;
 if (!node && physical) {
  /* At least one nonempty bin belongs to a real new/old list. The first
   * entry's prev is its node sentinel, not a guessed fixed bin ordering.
   */
  for (i = 0; i < 2; i++) {
   bin = view->table + i * 72;
   previous = get_unaligned_le32(bin + 4);
   if (previous == table_address || previous == table_address + 72) continue;
   node = previous - (bin[68] ? 228 : 236);
   break;
  }
 }
 if (node < 0x4027b62c || node >= 0x4027b62c + 256 * 280 ||
     (node - 0x4027b62c) % 280)
  return -EBADMSG;
 if (!physical && !registered_node && (get_unaligned_le32(view->table) != table_address + 72 ||
     get_unaligned_le32(view->table + 72) != node + 228 ||
     get_unaligned_le32(view->table + 76) != table_address))
  return -EBADMSG;
 if (physical) {
  mask = 0;
  for (i = 0; i < 2; i++) {
   bin = view->table + i * 72;
   next = get_unaligned_le32(bin); previous = get_unaligned_le32(bin + 4);
   if (next == table_address + i * 72 && previous == next) {
    if (get_unaligned_le32(bin + 24)) return -EBADMSG;
   } else {
    mask |= BIT(i);
   }
  }
  seen = 0;
  for (list = 0; list < 2; list++) {
   sentinel = node + (list ? 236 : 228);
   cursor = sentinel;
   for (i = 0; i < 2; i++) {
    bin = view->table + i * 72;
    if ((mask & BIT(i)) && get_unaligned_le32(bin + 4) == sentinel) {
     if (cursor != sentinel || !!bin[68] != !list) return -EBADMSG;
     cursor = table_address + i * 72;
    }
   }
   previous = sentinel;
   for (n = 0; cursor != sentinel && n < 2; n++) {
    if (cursor != table_address && cursor != table_address + 72) return -EBADMSG;
    slot = cursor == table_address ? 0 : 1;
    bin = view->table + slot * 72;
    if (!(mask & BIT(slot)) || (seen & BIT(slot)) || !!bin[68] != !list ||
        get_unaligned_le32(bin + 4) != previous) return -EBADMSG;
    seen |= BIT(slot); previous = cursor; cursor = get_unaligned_le32(bin);
   }
   if (cursor != sentinel) return -EBADMSG;
  }
  if (seen != mask || !seen) return -EBADMSG;
 }
 if (kind == QDX_DIAG_FQ_NODE) {
  *source = node;
  *length = 280;
  return 0;
 }
 /* Node+20 is the shaper generation, not a required constant. The registered
  * table and retained graph pin this node; ancestors compare the same generation.
  */
 if (!view->node_valid || get_unaligned_le32(view->node + 8) != 1 ||
     get_unaligned_le32(view->node + 16) != 0x6d010000 ||
     (!view->bf && !view->bf_cycle && !view->wrr && !view->rate && !view->aqm && view->node[24]) ||
     get_unaligned_le32(view->node + 220) != table_address ||
     get_unaligned_le16(view->node + 264) != 2 ||
     (get_unaligned_le16(view->node + 266) != 1 &&
      (!view->physical_staging || get_unaligned_le16(view->node + 266))))
  return -EBADMSG;
 if (view->aqm)
  return qdx_diag_aqm_source(mirror, view, node, kind, index, physical, source, length);
 if (physical && (view->rate || view->wrr)) {
  if (kind != QDX_DIAG_FQ_CARRIER && kind != QDX_DIAG_FQ_METADATA) {
   error = qdx_diag_physical_anchor(mirror, view);
   if (error) return error;
   if (view->rate)
    return qdx_diag_rate_source(core, view, node, kind, index, source, length);
   return qdx_diag_wrr_source(view, node, kind, index, source, length);
  }
 } else {
  if (view->rate)
   return qdx_diag_rate_source(core, view, node, kind, index, source, length);
  if (view->bf && view->wrr) return -EPERM;
  if (view->wrr)
   return qdx_diag_wrr_source(view, node, kind, index, source, length);
 }
 if (view->bf) {
  if (kind > QDX_DIAG_BF_FREQUENCY &&
      (kind < QDX_DIAG_BF_AUX_GROUP || kind > QDX_DIAG_BF_AUX_HEADER)) return -EPERM;
  error = qdx_diag_bf_source(core, view, node, kind, source, length);
  if (error || kind >= QDX_DIAG_BF_GROUP)
   return error;
 } else if (kind >= QDX_DIAG_BF_GROUP) {
  return -EPERM;
 }
 if (kind == QDX_DIAG_FQ_CLOCK) {
  *source = 0x40301a58;
  *length = 24;
  return 0;
 }
 if (index >= total)
  return -EINVAL;
 bin = view->table + (index >= first ? 72 : 0);
 if (index && index != first && !(view->carrier_valid & BIT(index - 1)))
  return -ENODATA;
 address = index && index != first ? get_unaligned_le32(view->carrier[index - 1]) :
  get_unaligned_le32(bin + 16);
 if (address >= 0x3f0120a8 && address < 0x3f0120a8 + 1736 * 56 &&
     !((address - 0x3f0120a8) % 56)) {
  pool_index = (address - 0x3f0120a8) / 56;
  meta_address = 0x40168ac0 + pool_index * 96;
  stride = 56;
 } else if (address >= 0x400ccac0 && address < 0x400ccac0 + 9984 * 64 &&
     !((address - 0x400ccac0) % 64)) {
  pool_index = (address - 0x400ccac0) / 64;
  meta_address = 0x401915c0 + pool_index * 96;
  stride = 64;
 } else {
  return -ERANGE;
 }
 for (i = 0; i < index; i++)
  if ((view->carrier_valid & BIT(i)) && view->carrier_address[i] == address)
   return -ELOOP;
 if ((index == first - 1 || index == total - 1) &&
     address != get_unaligned_le32(bin + 20))
  return -EBADMSG;
 if (kind == QDX_DIAG_FQ_CARRIER) {
  *source = address;
  *length = stride;
  return 0;
 }
 carrier = view->carrier[index];
 if (!(view->carrier_valid & BIT(index)) || view->carrier_address[index] != address ||
     get_unaligned_le32(carrier + 36) != meta_address)
  return -EBADMSG;
 if (kind == QDX_DIAG_FQ_METADATA) {
  *source = meta_address;
  *length = 96;
  return 0;
 }
 if (kind != QDX_DIAG_FQ_PAYLOAD || !(view->metadata_valid & BIT(index)))
  return -EINVAL;
 metadata = view->metadata[index];
 cookie = get_unaligned_le64(metadata + 4);
 if (!(cookie >> 32) || (cookie & GENMASK_ULL(30, 16)) ||
     ((cookie >> 31) & 1) != core->id)
  return -EBADMSG;
 buffer = get_unaligned_le32(carrier + 8);
 data = get_unaligned_le32(carrier + 24);
 packet_length = get_unaligned_le16(carrier + 46);
 buffer_length = get_unaligned_le16(carrier + 44);
 spin_lock_irqsave(&io->carriers_lock, flags);
 record = qdx_slot(io, cookie & 0xffff);
 valid = record && record->state == QDX_PUBLISHED && record->generation == cookie >> 32 &&
  record->mapped && record->dma == buffer && buffer_length <= record->length &&
  data >= buffer && data - buffer <= buffer_length && packet_length &&
  packet_length <= buffer_length - (data - buffer);
 if (valid && physical) {
  /* A pool supply is not an accepted host transmit operation. Its backing
   * stays firmware-owned: copy never claims, unmaps or steals this slot.
   */
  if (!view->physical_rebuild) {
   valid = !record->operation && !record->accepted &&
    record->direction == DMA_FROM_DEVICE && packet_length <= 2048 &&
    ((record->kind == QDX_LINEAR && record->skb && !record->page) ||
     (record->kind == QDX_PAGED && record->page && !record->skb));
  } else if (view->physical_staging) {
   valid = qdx_diag_fq_staging_paths_locked(core, view, total);
  } else {
   /* Compare only; the supplied witness is never dereferenced. This actual
    * published record holds its path and skb until the real completion.
    */
   valid = record->kind == QDX_TRANSMIT && record->accepted && !record->operation &&
    record->path && record->path == view->physical_rebuild && record->skb &&
    record->direction == DMA_TO_DEVICE && packet_length <= 2048 &&
    record->path->endpoint->core == core &&
    record->path->endpoint->service->qdx == mirror->service->qdx &&
    !record->path->endpoint->dynamic_type &&
    record->path->endpoint->ifnum == 4 && record->path->class.tag == 0x6d010000 &&
    !smp_load_acquire(&record->path->open) && READ_ONCE(record->path->accepted) == total &&
    record->length == buffer_length && record->skb->len == packet_length &&
    data - buffer == skb_headroom(record->skb);
  }
 } else if (valid) {
  valid = record->kind == QDX_TRANSMIT && record->accepted && record->operation == loans &&
   record->skb && record->recipient.owner.module &&
   !strcmp(module_name(record->recipient.owner.module), "qdx_mirror_state_diag") &&
   record->length == buffer_length && packet_length == 64 &&
   data - buffer == skb_headroom(record->skb) && record->skb->len == 64;
 }
 spin_unlock_irqrestore(&io->carriers_lock, flags);
 if (!valid)
  return -ESTALE;
 *source = data;
 *length = packet_length;
 return 0;
}

/* Continue exact graph observation after its last actual packet returns.
 * Payload/carrier access and all writes retain the occupied-owner guards.
 */
static int qdx_diag_bf_empty_source(struct qdx_endpoint *mirror,
 struct qdx_dma *region, struct qdx_packet_op *loans,
 const struct qdx_diag_fq_view *view, enum qdx_diag_fq_range kind,
 u32 table_address, u32 *source, unsigned int *length)
{
 u32 node = qdx_diag_fq_table_node(region, 0);
 u32 key[7] = { node, get_unaligned_le32(view->node + 36),
  get_unaligned_le32(view->node + 4), get_unaligned_le32(view->bf_group + 4),
  get_unaligned_le32(view->bf_group + 168), get_unaligned_le32(view->bf_group + 220),
  get_unaligned_le32(view->bf_group + 216) };
 bool physical = qdx_diag_fq_table_physical(region);
 int error;

 if (!view->bf || view->wrr || view->rate || view->aqm ||
     mirror->core->id || mirror->core->image_phys != 0x40000000)
  return -EPERM;
 if (physical) {
  /* No path dereference is needed after actual payload closure. The exact
   * physical caller keeps its registered graph and path until timer join.
   */
  if (loans) return -EPERM;
 } else if (!loans || view->physical_rebuild ||
     loans->endpoint->core != mirror->core ||
     loans->endpoint->service->qdx != mirror->service->qdx ||
     loans->endpoint->service->kind != QDX_SERVICE_IGS || loans->endpoint->dynamic_type != 53 ||
     loans->category != QDX_RECEIVE_RETURNED || loans->class_tag != 0x6d010000 ||
     smp_load_acquire(&loans->open) || READ_ONCE(loans->accepted) ||
     !qdx_packet_op_drained(loans)) return -EPERM;
 if (get_unaligned_le32(view->table + 24) ||
     get_unaligned_le32(view->table + 96) || get_unaligned_le32(view->table + 64) ||
     get_unaligned_le32(view->table + 136) || !view->node_valid ||
     get_unaligned_le32(view->node + 8) != 1 ||
     get_unaligned_le32(view->node + 16) != 0x6d010000 ||
     get_unaligned_le32(view->node + 20) != get_unaligned_le32(view->bf_group + 20) ||
     !view->node[24] ||
     get_unaligned_le32(view->node + 220) != table_address ||
     get_unaligned_le16(view->node + 264) != 2 ||
     get_unaligned_le16(view->node + 266) != 1 ||
     !qdx_diag_fq_table_bf(region, key, false)) return -EPERM;
 if (kind == QDX_DIAG_FQ_NODE) {
  *source = node; *length = 280; return 0;
 }
 if (kind != QDX_DIAG_FQ_CLOCK &&
     (kind < QDX_DIAG_BF_GROUP || kind > QDX_DIAG_BF_FREQUENCY)) return -EPERM;
 error = qdx_diag_bf_source(mirror->core, view, node, kind, source, length);
 if (error) return error;
 if (kind == QDX_DIAG_FQ_CLOCK) { *source = 0x40301a58; *length = 24; }
 return 0;
}

static struct qdx_ready qdx_diag_fq_copy(struct qdx_packet_op *operation,
	struct qdx_dma *region, struct qdx_packet_op *loans,
	const struct qdx_diag_fq_view *view, enum qdx_diag_fq_range kind,
	unsigned int index, const struct qdx_packet_recipient *recipient)
{
	struct qdx_endpoint *endpoint = operation->endpoint;
	struct qdx_carrier *record;
	struct qdx_ready ready;
	struct qdx_h2n_desc desc = {
		.interface = cpu_to_le32(endpoint->ifnum), .type = QDX_H2N_PACKET,
		.payload_off = 0, .payload_len = cpu_to_le16(144),
		.flags = cpu_to_le16(QDX_DESC_FIRST | QDX_DESC_LAST | QDX_DESC_NO_CSUM),
	};
	dma_addr_t address;
	u32 source;
	unsigned int length = 144;
	bool physical_rate, physical_wrr, physical_aqm;
	int error;

	if (!READ_ONCE(diag_mirror_table) ||
	    operation->category != QDX_RECEIVE_PACKET ||
	    operation->class_tag != 0x4d54424c ||
	    endpoint->service->kind != QDX_SERVICE_MIRROR || endpoint->dynamic_type != 65 ||
	    !recipient || !recipient->returned || !recipient->owner.module ||
	    !recipient->owner.object || recipient->owner.get || recipient->owner.put ||
	    (strcmp(module_name(recipient->owner.module), "qdx_mirror_state_diag") &&
	     strcmp(module_name(recipient->owner.module), "qdx_wrr_handover_diag") &&
	     strcmp(module_name(recipient->owner.module), "qdx_rate_handover_diag") &&
	     strcmp(module_name(recipient->owner.module), "qdx_aqm_handover_diag") &&
	     strcmp(module_name(recipient->owner.module), "qdx_physical_aqm_diag") &&
	     strcmp(module_name(recipient->owner.module), "qdx_physical_rate_diag") &&
	     strcmp(module_name(recipient->owner.module), "qdx_physical_wrr_diag") &&
	     strcmp(module_name(recipient->owner.module), "qdx_physical_fq_diag")))
		return (struct qdx_ready) { .status = QDX_REFUSED, .error = -EPERM };
	if (view && view->physical_staging &&
	    strcmp(module_name(recipient->owner.module), "qdx_physical_fq_diag"))
		return (struct qdx_ready) { .status = QDX_REFUSED, .error = -EPERM };
	physical_rate = !strcmp(module_name(recipient->owner.module), "qdx_physical_rate_diag");
	physical_wrr = !strcmp(module_name(recipient->owner.module), "qdx_physical_wrr_diag");
	physical_aqm = !strcmp(module_name(recipient->owner.module), "qdx_physical_aqm_diag");
	if ((physical_rate || physical_wrr || physical_aqm) && loans)
		return (struct qdx_ready) { .status = QDX_REFUSED, .error = -EPERM };
	if (physical_rate && view && (!view->rate || view->bf || view->wrr || view->aqm ||
	    (kind > QDX_DIAG_FQ_METADATA &&
	     (kind < QDX_DIAG_RATE_SELECTOR || kind > QDX_DIAG_RATE_CLOCK))))
		return (struct qdx_ready) { .status = QDX_REFUSED, .error = -EPERM };
	if (physical_wrr && view && (!view->wrr || view->bf || view->rate || view->aqm ||
	    (kind > QDX_DIAG_FQ_METADATA &&
	     (kind < QDX_DIAG_WRR_ANCHOR_GROUP || kind > QDX_DIAG_WRR_GROUP))))
		return (struct qdx_ready) { .status = QDX_REFUSED, .error = -EPERM };
	if (view && view->aqm && !physical_aqm &&
	    strcmp(module_name(recipient->owner.module), "qdx_aqm_handover_diag"))
		return (struct qdx_ready) { .status = QDX_REFUSED, .error = -EPERM };
	if ((physical_aqm || !strcmp(module_name(recipient->owner.module), "qdx_aqm_handover_diag")) &&
	    view && (!view->aqm || view->bf || view->wrr || view->rate ||
	     (kind != QDX_DIAG_FQ_NODE && kind < QDX_DIAG_AQM_SELECTOR)))
		return (struct qdx_ready) { .status = QDX_REFUSED, .error = -EPERM };
	if (view && view->rate && !physical_rate &&
	    strcmp(module_name(recipient->owner.module), "qdx_rate_handover_diag"))
		return (struct qdx_ready) { .status = QDX_REFUSED, .error = -EPERM };
	if (!strcmp(module_name(recipient->owner.module), "qdx_rate_handover_diag") &&
	    view && (!view->rate || view->bf || view->wrr || view->aqm ||
	     (kind != QDX_DIAG_FQ_NODE && kind < QDX_DIAG_RATE_SELECTOR)))
		return (struct qdx_ready) { .status = QDX_REFUSED, .error = -EPERM };
	if (!strcmp(module_name(recipient->owner.module), "qdx_wrr_handover_diag") &&
	    view && (!view->wrr || view->bf ||
	     (kind != QDX_DIAG_FQ_NODE && kind < QDX_DIAG_WRR_ANCHOR_GROUP)))
		return (struct qdx_ready) { .status = QDX_REFUSED, .error = -EPERM };
	if (view && view->wrr && !physical_wrr &&
	    strcmp(module_name(recipient->owner.module), "qdx_wrr_handover_diag"))
		return (struct qdx_ready) { .status = QDX_REFUSED, .error = -EPERM };
	if (!smp_load_acquire(&operation->open) || !qdx_io_enter(endpoint->service->qdx))
		return (struct qdx_ready) { .status = QDX_CLOSED, .error = -ESHUTDOWN };
	ready = qdx_data_ready(endpoint, 0);
	if (ready.status != QDX_ACCEPTED)
		goto leave;
	error = qdx_diag_fq_table_get(endpoint->service, region, &recipient->owner, &address);
	if (error) {
		ready = (struct qdx_ready) { .status = QDX_REFUSED, .error = error };
		goto leave;
	}
	if ((!strcmp(module_name(recipient->owner.module), "qdx_wrr_handover_diag") ||
	     !strcmp(module_name(recipient->owner.module), "qdx_rate_handover_diag") ||
	     !strcmp(module_name(recipient->owner.module), "qdx_aqm_handover_diag")) &&
	    qdx_diag_fq_table_physical(region)) {
		qdx_diag_fq_table_put(region);
		ready = (struct qdx_ready) { .status = QDX_REFUSED, .error = -EPERM };
		goto leave;
	}
	if ((physical_rate || physical_wrr || physical_aqm) && !qdx_diag_fq_table_physical(region)) {
		qdx_diag_fq_table_put(region);
		ready = (struct qdx_ready) { .status = QDX_REFUSED, .error = -EPERM };
		goto leave;
	}
	if ((view && view->bf && qdx_diag_fq_table_physical(region) &&
	     strcmp(module_name(recipient->owner.module), "qdx_physical_fq_diag")) ||
	    (!strcmp(module_name(recipient->owner.module), "qdx_physical_fq_diag") &&
	     (!qdx_diag_fq_table_physical(region) || (view && (view->wrr || view->rate || view->aqm))))) {
		qdx_diag_fq_table_put(region);
		ready = (struct qdx_ready) { .status = QDX_REFUSED, .error = -EPERM };
		goto leave;
	}
	if (!view && (kind == QDX_DIAG_BF_POOL_GROUP || kind == QDX_DIAG_BF_POOL_PARENT)) {
		unsigned int slots = kind == QDX_DIAG_BF_POOL_GROUP ? 256 : 8;

		length = kind == QDX_DIAG_BF_POOL_GROUP ? 232 : 200;
		if (index >= slots || endpoint->core->id || endpoint->core->image_phys != 0x40000000 ||
		    !endpoint->core->image || endpoint->core->image_size < 0x2fa3ec) {
			qdx_diag_fq_table_put(region);
			ready = (struct qdx_ready) { .status = QDX_REFUSED, .error = -ERANGE };
			goto leave;
		}
		address = (kind == QDX_DIAG_BF_POOL_GROUP ? 0x402eb5ac : 0x402f9dac) + index * length;
	}
	if (view) {
		if (!qdx_diag_fq_table_matches(region, view->table))
			error = -ESTALE;
		else if (view->bf_cycle && kind >= QDX_DIAG_BF_CYCLE_ACCOUNT &&
			 kind <= QDX_DIAG_BF_CYCLE_RETIRED_TIMER)
			error = qdx_diag_bf_cycle_source(endpoint->core, view, kind, index, &source, &length);
		else if (view->bf && !get_unaligned_le32(view->table + 24) &&
			 !get_unaligned_le32(view->table + 96) &&
			 ((!strcmp(module_name(recipient->owner.module), "qdx_mirror_state_diag") &&
			   !qdx_diag_fq_table_physical(region)) ||
			  (!strcmp(module_name(recipient->owner.module), "qdx_physical_fq_diag") &&
			   qdx_diag_fq_table_physical(region))))
			error = qdx_diag_bf_empty_source(endpoint, region, loans, view, kind,
				address, &source, &length);
		else
			error = qdx_diag_fq_source(endpoint, loans, view, kind, index,
				address, qdx_diag_fq_table_node(region, 0),
				qdx_diag_fq_table_physical(region), &source, &length);
		if (error) {
			qdx_diag_fq_table_put(region);
			ready = (struct qdx_ready) { .status = QDX_REFUSED, .error = error };
			goto leave;
		}
		if (kind == QDX_DIAG_FQ_NODE)
			qdx_diag_fq_table_node(region, source);
		address = source;
	}
	desc.payload_len = cpu_to_le16(length);
	record = qdx_carrier_get(endpoint->core, QDX_TRANSMIT);
	if (!record) {
		qdx_diag_fq_table_put(region);
		ready = (struct qdx_ready) { .status = QDX_RESOURCE_WAIT,
			.resources = QDX_RESOURCE_CARRIER, .error = -ENOSPC };
		goto leave;
	}
	record->diag_region = region;
	record->dma = address;
	record->length = length;
	record->direction = DMA_BIDIRECTIONAL;
	if (!qdx_owner_get(&recipient->owner)) {
		qdx_carrier_put(endpoint->core, record, false, true);
		ready = (struct qdx_ready) { .status = QDX_CLOSED, .error = -ESHUTDOWN };
		goto leave;
	}
	refcount_inc(&operation->refs);
	atomic_inc(&endpoint->operations);
	record->operation = operation;
	record->recipient = *recipient;
	error = qdx_publish(endpoint->core, QDX_DATA_RING, record, &desc);
	if (error) {
		qdx_carrier_put(endpoint->core, record, false, true);
		ready = (struct qdx_ready) { .status = error == -ENOSPC ?
			QDX_RESOURCE_WAIT : QDX_REFUSED, .error = error,
			.resources = error == -ENOSPC ? QDX_RESOURCE_DESCRIPTOR : 0 };
	} else {
		ready = (struct qdx_ready) { .status = QDX_ACCEPTED };
	}
leave:
	qdx_io_leave(endpoint->service->qdx);
	return ready;
}
struct qdx_ready qdx_diag_bf_pool_copy(struct qdx_packet_op *operation,
 struct qdx_dma *region, bool parent, unsigned int slot,
 const struct qdx_packet_recipient *recipient)
{
 return qdx_diag_fq_copy(operation, region, NULL, NULL,
  parent ? QDX_DIAG_BF_POOL_PARENT : QDX_DIAG_BF_POOL_GROUP, slot, recipient);
}
EXPORT_SYMBOL_GPL(qdx_diag_bf_pool_copy);

struct qdx_ready qdx_diag_fq_table_copy(struct qdx_packet_op *operation,
 struct qdx_dma *region, const struct qdx_packet_recipient *recipient)
{
 return qdx_diag_fq_copy(operation, region, NULL, NULL, QDX_DIAG_FQ_NODE, 0, recipient);
}
EXPORT_SYMBOL_GPL(qdx_diag_fq_table_copy);

struct qdx_ready qdx_diag_fq_owned_copy(struct qdx_packet_op *operation,
 struct qdx_dma *region, struct qdx_packet_op *loans,
 const struct qdx_diag_fq_view *view, enum qdx_diag_fq_range kind,
 unsigned int index, const struct qdx_packet_recipient *recipient)
{
 if (!view)
  return (struct qdx_ready) { .status = QDX_REFUSED, .error = -EINVAL };
 return qdx_diag_fq_copy(operation, region, loans, view, kind, index, recipient);
}
EXPORT_SYMBOL_GPL(qdx_diag_fq_owned_copy);

/* Remember only the graph witnessed through real occupied loans and this
 * registered table exposure. The exact caller keeps allocations and service
 * references until timer join; this is not a firmware allocation-generation API.
 */
int qdx_diag_bf_pin(struct qdx_packet_op *operation, struct qdx_dma *region,
 struct qdx_packet_op *loans, const struct qdx_diag_fq_view *view,
 const struct qdx_owner *owner)
{
 struct qdx_endpoint *endpoint = operation->endpoint;
 dma_addr_t table_address;
 u32 source, node, key[7], payload;
 unsigned int length, i, total;
 bool physical;
 int error;

 if (!READ_ONCE(diag_mirror_table) || !view || !view->bf || view->wrr ||
     view->rate || view->aqm || !owner || !owner->module ||
     (strcmp(module_name(owner->module), "qdx_mirror_state_diag") &&
      strcmp(module_name(owner->module), "qdx_physical_fq_diag")) ||
     operation->category != QDX_RECEIVE_PACKET || operation->class_tag != 0x4d54424c ||
     endpoint->service->kind != QDX_SERVICE_MIRROR || endpoint->dynamic_type != 65 ||
     !qdx_packet_op_drained(operation))
  return -EPERM;
 if (!qdx_io_enter(endpoint->service->qdx)) return -ESHUTDOWN;
 error = qdx_diag_fq_table_get(endpoint->service, region, owner, &table_address);
 if (error) goto leave;
 physical = qdx_diag_fq_table_physical(region);
 if ((physical && (loans || strcmp(module_name(owner->module), "qdx_physical_fq_diag"))) ||
     (!physical && (view->physical_rebuild ||
      strcmp(module_name(owner->module), "qdx_mirror_state_diag")))) {
  error = -EPERM; goto put;
 }
 if (!qdx_diag_fq_table_matches(region, view->table)) {
  error = -ESTALE; goto put;
 }
 node = qdx_diag_fq_table_node(region, 0);
 error = qdx_diag_fq_source(endpoint, loans, view, QDX_DIAG_BF_ACCOUNT, 0,
  table_address, node, physical, &source, &length);
 if (error) goto put;
 if (physical) {
  total = get_unaligned_le32(view->table + 24) + get_unaligned_le32(view->table + 96);
  for (i = 0; i < total; i++) {
   error = qdx_diag_fq_source(endpoint, NULL, view, QDX_DIAG_FQ_PAYLOAD, i,
    table_address, node, true, &payload, &length);
   if (error) goto put;
  }
 }
 key[0] = node; key[1] = get_unaligned_le32(view->node + 36);
 key[2] = get_unaligned_le32(view->node + 4);
 key[3] = get_unaligned_le32(view->bf_group + 4);
 key[4] = source; key[5] = get_unaligned_le32(view->bf_group + 220);
 key[6] = get_unaligned_le32(view->bf_group + 216);
 error = qdx_diag_fq_table_bf(region, key, true) ? 0 : -ESTALE;
put:
 qdx_diag_fq_table_put(region);
leave:
 qdx_io_leave(endpoint->service->qdx);
 return error;
}
EXPORT_SYMBOL_GPL(qdx_diag_bf_pin);

/* Only joined BF credit/reference and interior deficit words are imported.
 * The caller has detached selection, closed producers/configuration, joined
 * this timer and frequency writer, and completed MIRROR source release.
 * Local wait/queued observations followed by manager inactivity join this
 * callback. Unrelated global timer generations do not invalidate that join.
 */
int qdx_diag_bf_import(struct qdx_packet_op *operation, struct qdx_dma *region,
 struct qdx_packet_op *loans, const struct qdx_diag_fq_view *view,
 const struct qdx_diag_bf_state *state, const struct qdx_owner *owner)
{
 struct qdx_endpoint *endpoint = operation->endpoint;
 struct qdx_core *core = endpoint->core;
 dma_addr_t table_address;
 const u8 *group, *parent;
 u32 node, account, source, start, extent, header, address, key[7], frequency, payload;
 unsigned int length, i, total, quantum, control;
 bool physical;
 int error;

 if (!READ_ONCE(diag_mirror_table) || !view || !view->bf || view->wrr || view->rate ||
     view->aqm || !state || !owner || !owner->module ||
     (strcmp(module_name(owner->module), "qdx_mirror_state_diag") &&
      strcmp(module_name(owner->module), "qdx_physical_fq_diag")) ||
     operation->category != QDX_RECEIVE_PACKET || operation->class_tag != 0x4d54424c ||
     endpoint->service->kind != QDX_SERVICE_MIRROR || endpoint->dynamic_type != 65 ||
     !qdx_packet_op_drained(operation) || (view->bf_valid & 15) != 15)
  return -EPERM;
 group = view->bf_group; parent = view->bf_parent;
 if (!state->timer_joined || (get_unaligned_le32(state->epoch[0]) & 1) ||
     (get_unaligned_le32(state->epoch[0] + 16) & 1)) return -EBUSY;
 for (i = 0; i < 2; i++)
  if (get_unaligned_le32(state->frequency[i]) & 1) return -EBUSY;
 if (get_unaligned_le32(state->frequency[0] + 4) !=
      get_unaligned_le32(state->frequency[1] + 4) ||
     state->clock_ms[1] < state->clock_ms[0] ||
     state->clock_ms[1] - state->clock_ms[0] >= 32768) return -ESTALE;
 frequency = get_unaligned_le32(state->frequency[1] + 4);
 if (!qdx_io_enter(endpoint->service->qdx)) return -ESHUTDOWN;
 error = qdx_diag_fq_table_get(endpoint->service, region, owner, &table_address);
 if (error) goto leave;
 physical = qdx_diag_fq_table_physical(region);
 if ((physical && (loans || strcmp(module_name(owner->module), "qdx_physical_fq_diag"))) ||
     (!physical && (view->physical_rebuild ||
      strcmp(module_name(owner->module), "qdx_mirror_state_diag")))) {
  error = -EPERM; goto put;
 }
 if (!qdx_diag_fq_table_matches(region, view->table)) {
  error = -ESTALE; goto put;
 }
 node = qdx_diag_fq_table_node(region, 0);
 error = qdx_diag_fq_source(endpoint, loans, view, QDX_DIAG_BF_ACCOUNT, 0,
  table_address, node, physical, &account, &length);
 if (error) goto put;
 if (physical) {
  total = get_unaligned_le32(view->table + 24) + get_unaligned_le32(view->table + 96);
  for (i = 0; i < total; i++) {
   error = qdx_diag_fq_source(endpoint, NULL, view, QDX_DIAG_FQ_PAYLOAD, i,
    table_address, node, true, &payload, &length);
   if (error) goto put;
  }
 }
 address = get_unaligned_le32(view->node + 4);
 key[0] = node; key[1] = get_unaligned_le32(view->node + 36);
 key[2] = address; key[3] = get_unaligned_le32(group + 4);
 key[4] = account; key[5] = get_unaligned_le32(group + 220);
 key[6] = get_unaligned_le32(group + 216);
 if (!qdx_diag_fq_table_bf(region, key, false)) { error = -ESTALE; goto put; }
 error = qdx_diag_fq_source(endpoint, loans, view, QDX_DIAG_BF_ACCOUNT_HEADER, 0,
  table_address, node, physical, &source, &length);
 if (error) goto put;
 quantum = physical ? 256 : 128;
 control = physical ? 128 : 64;
 if ((get_unaligned_le32(group) & 1) || (get_unaligned_le32(parent) & 1) ||
     group[229] || (get_unaligned_le32(state->timer + 24) & 2) ||
     get_unaligned_le32(state->notifier + 4) != 0x40086900 ||
     get_unaligned_le32(state->notifier + 8) != address ||
     get_unaligned_le32(state->notifier + 12) != frequency ||
     get_unaligned_le32(group + 180) != quantum ||
     get_unaligned_le32(group + 196) != quantum ||
     (physical && get_unaligned_le32(state->current_account + 8) != 128) ||
     get_unaligned_le32(view->bf_header) != account ||
     get_unaligned_le16(view->bf_header + 12) != 121 || (view->bf_header[15] & 8)) {
  error = -EBADMSG; goto put;
 }
 start = source; header = length; extent = get_unaligned_le32(view->bf_header + 4);
 if (extent < header + 312 || start < core->image_phys ||
     start - core->image_phys > core->image_size ||
     extent > core->image_size - (start - core->image_phys) ||
     ((account + 292) & ~31U) < start || ((account + 307) | 31U) >= start + extent ||
     ((address + 184) & ~31U) < address ||
     ((address + 203) | 31U) >= address + 232 ||
     !state->credit || state->credit <= -(1LL << 62) ||
     state->reference > get_unaligned_le64(state->current_account + 300) ||
     state->deficit[0] < -(s32)quantum || state->deficit[0] > (s32)quantum) {
  error = -ERANGE; goto put;
 }
 if (state->credit > 0) {
  /* The carried CPU event already became eligible. Real child activation
   * creates P/E membership; no private packet or deficit compensation.
   */
  if ((s64)get_unaligned_le64(state->current_account + 284) < state->credit ||
      state->deficit[1] < -(s32)quantum || state->deficit[1] > (s32)quantum) {
   error = -ERANGE; goto put;
  }
 } else if (state->deficit[1] < 0 ||
            state->deficit[1] > (s32)(quantum + control)) {
  /* Negative-debt rearm still requires the single private L-byte event. */
  error = -ERANGE; goto put;
 }
 /* No writes precede the complete validation. The cache lines belong to
  * these exact frozen allocations; no timer/list/control field is changed.
  */
 writel(lower_32_bits(state->credit), core->image + account - core->image_phys + 292);
 writel(upper_32_bits(state->credit), core->image + account - core->image_phys + 296);
 writel(lower_32_bits(state->reference), core->image + account - core->image_phys + 300);
 writel(upper_32_bits(state->reference), core->image + account - core->image_phys + 304);
 writel(state->deficit[0], core->image + address - core->image_phys + 184);
 writel(state->deficit[1], core->image + address - core->image_phys + 200);
 wmb(); error = 0;
put:
 qdx_diag_fq_table_put(region);
leave:
 qdx_io_leave(endpoint->service->qdx);
 return error;
}
EXPORT_SYMBOL_GPL(qdx_diag_bf_import);

/* Bounded two-group inherited-event publication. The caller seals the root,
 * joins activation, excludes configuration/frequency, and holds every object.
 * No host write touches a firmware lock, P link or native timer. Sibling native
 * callbacks may continue: they write P, never E or the target's private account.
 */
int qdx_diag_bf_cycle_write(struct qdx_packet_op *operation, struct qdx_dma *region,
 const struct qdx_diag_fq_view *view, const struct qdx_diag_bf_cycle_update *update,
 const struct qdx_owner *owner)
{
 const struct qdx_diag_bf_cycle *cycle;
 struct qdx_endpoint *endpoint = operation->endpoint;
 struct qdx_core *core = endpoint->core;
 const u8 *a, *b, *parent, *guard;
 dma_addr_t table_address;
 u32 ga, gb, pa, next, source, length, header, extent, account, first, second;
 unsigned int i;
 int error;

 if (!READ_ONCE(diag_mirror_table) || !view || !view->bf_cycle || !update ||
     !owner || !owner->module || strcmp(module_name(owner->module), "qdx_mirror_state_diag") ||
     operation->category != QDX_RECEIVE_PACKET || operation->class_tag != 0x4d54424c ||
     endpoint->service->kind != QDX_SERVICE_MIRROR || endpoint->dynamic_type != 65 ||
     !qdx_packet_op_drained(operation)) return -EPERM;
 cycle = view->bf_cycle;
 if (cycle->group_valid != 15 || cycle->parent_valid != 3 ||
     (cycle->timer_valid & 13) != 13 || (cycle->account_valid & 5) != 5 ||
     !(cycle->header_valid & 1)) return -ENODATA;
 if (!qdx_io_enter(endpoint->service->qdx)) return -ESHUTDOWN;
 error = qdx_diag_fq_table_get(endpoint->service, region, owner, &table_address);
 if (error) goto leave;
 if (qdx_diag_fq_table_physical(region) || !qdx_diag_fq_table_matches(region, view->table)) {
  error = -ESTALE; goto put;
 }
 for (i = 0; i < 4; i++) {
  error = qdx_diag_bf_cycle_source(core, view, QDX_DIAG_BF_CYCLE_TIMER, i, &source, &length);
  if (error) goto put;
  if ((get_unaligned_le32(cycle->group[i]) & 1) || cycle->group[i][160]) {
   error = -EBUSY; goto put;
  }
 }
 a = cycle->group[0]; b = cycle->group[1]; parent = cycle->parent[0]; guard = cycle->parent[1];
 ga = cycle->group_address[0]; gb = cycle->group_address[1]; pa = cycle->parent_address[0];
 next = ga + 232;
 /* Both target wait-line spill and E-line neighbors have actual owners. */
 if ((ga & 31) != 12 || (gb & 31) != 4 || (pa & 31) != 12 ||
     cycle->group_address[3] != next || cycle->parent_address[1] != pa + 200 ||
     pa < 0x402f9dac || pa >= 0x402fa3ec - 200 || (pa - 0x402f9dac) % 200 ||
     get_unaligned_le32(a + 4) != pa || get_unaligned_le32(b + 4) != pa ||
     !a[24] || !b[24] || (get_unaligned_le32(parent) & 1) ||
     get_unaligned_le32(parent + 8) != 6 || get_unaligned_le32(parent + 16) != cycle->parent_tag[0] ||
     get_unaligned_le32(parent + 20) != get_unaligned_le32(a + 20) || parent[24] ||
     get_unaligned_le32(parent + 4) ||
     get_unaligned_le32(parent + 36) != get_unaligned_le32(a + 36) ||
     get_unaligned_le32(parent + 48) != 0x40087400 || parent[160] ||
     (get_unaligned_le32(guard) & 1) || get_unaligned_le32(guard + 8) != 6 ||
     get_unaligned_le32(guard + 16) != cycle->parent_tag[1] ||
     get_unaligned_le32(guard + 20) != get_unaligned_le32(a + 20) ||
     get_unaligned_le32(guard + 36) != get_unaligned_le32(a + 36) ||
     guard[24] || guard[160] || get_unaligned_le32(guard + 4) ||
     get_unaligned_le32(guard + 196) ||
     (get_unaligned_le32(cycle->timer[0] + 24) & 2)) { error = -EBADMSG; goto put; }
 for (i = 0; i < 2; i++)
  if (get_unaligned_le32(cycle->group[i] + 180) != 128 ||
      get_unaligned_le32(cycle->group[i] + 196) != 128) { error = -EBADMSG; goto put; }
 for (i = 2; i < 4; i++) {
  const u8 *g = cycle->group[i];
  u32 address = cycle->group_address[i];

  if (g[24] || g[228] || g[229] || get_unaligned_le32(g + 4) ||
      get_unaligned_le32(g + 212) || get_unaligned_le32(g + 224) ||
      get_unaligned_le32(g + 172) != address + 172 ||
      get_unaligned_le32(g + 176) != address + 172 ||
      get_unaligned_le32(g + 188) != address + 188 ||
      get_unaligned_le32(g + 192) != address + 188 ||
      (get_unaligned_le32(cycle->timer[i] + 24) & 2)) { error = -EBUSY; goto put; }
 }
 error = qdx_diag_bf_cycle_source(core, view, QDX_DIAG_BF_CYCLE_HEADER, 0, &source, &header);
 if (error) goto put;
 account = get_unaligned_le32(a + 168); extent = get_unaligned_le32(cycle->header[0] + 4);
 if (get_unaligned_le32(cycle->header[0]) != account ||
     get_unaligned_le16(cycle->header[0] + 12) != 121 || (cycle->header[0][15] & 8) ||
     extent < header + 312 || source < core->image_phys ||
     source - core->image_phys > core->image_size || extent > core->image_size - (source - core->image_phys) ||
     ((account + 292) & ~31U) < source || ((account + 307) | 31U) >= source + extent) {
  error = -ERANGE; goto put;
 }
 if (update->action == QDX_DIAG_BF_CYCLE_ACCOUNT_INIT) {
  if (a[228] || a[229] || get_unaligned_le32(a + 212) || get_unaligned_le32(a + 224) ||
      get_unaligned_le32(a + 172) != ga + 172 || get_unaligned_le32(a + 176) != ga + 172 ||
      get_unaligned_le32(a + 188) != ga + 188 || get_unaligned_le32(a + 192) != ga + 188 ||
      update->credit <= -(1LL << 62) ||
      update->credit > (s64)get_unaligned_le64(cycle->account[0] + 284) ||
      get_unaligned_le32(cycle->account[2] + 280) != get_unaligned_le32(cycle->account[0] + 280) ||
      get_unaligned_le32(cycle->account[2] + 276) != get_unaligned_le32(cycle->account[0] + 276) ||
      update->reference > get_unaligned_le64(cycle->account[2] + 300) ||
      update->deficit[0] < -128 || update->deficit[0] > 128 ||
      update->deficit[1] < -128 || update->deficit[1] > 128) { error = -ERANGE; goto put; }
  writel(lower_32_bits(update->credit), core->image + account - core->image_phys + 292);
  writel(upper_32_bits(update->credit), core->image + account - core->image_phys + 296);
  writel(lower_32_bits(update->reference), core->image + account - core->image_phys + 300);
  writel(upper_32_bits(update->reference), core->image + account - core->image_phys + 304);
  writel(update->deficit[0], core->image + ga - core->image_phys + 184);
  writel(update->deficit[1], core->image + ga - core->image_phys + 200);
  writeb(1, core->image + ga - core->image_phys + 229);
 } else if (update->action == QDX_DIAG_BF_CYCLE_E_RESTORE) {
  if (update->excess_first > 1 || !a[228] || !b[228] || !a[229] ||
      get_unaligned_le32(parent + 196) != 2 ||
      get_unaligned_le32(a + 212) != qdx_diag_fq_table_node(region, 0)) {
   error = -EBADMSG; goto put;
  }
  /* Validate the actual complete two-node E ring before restoring its order.
   * P membership/credit may legitimately disagree and are not rewritten. */
  first = get_unaligned_le32(parent + 180); second = first == ga + 188 ? gb + 188 : ga + 188;
  if ((first != ga + 188 && first != gb + 188) || get_unaligned_le32(parent + 184) != second ||
      get_unaligned_le32(cycle->group[first == ga + 188 ? 0 : 1] + 188) != second ||
      get_unaligned_le32(cycle->group[first == ga + 188 ? 0 : 1] + 192) != pa + 180 ||
      get_unaligned_le32(cycle->group[second == ga + 188 ? 0 : 1] + 188) != pa + 180 ||
      get_unaligned_le32(cycle->group[second == ga + 188 ? 0 : 1] + 192) != first) {
   error = -EBADMSG; goto put;
  }
  first = cycle->group_address[update->excess_first] + 188;
  second = cycle->group_address[update->excess_first ^ 1] + 188;
  writel(first, core->image + pa - core->image_phys + 180);
  writel(second, core->image + pa - core->image_phys + 184);
  writel(second, core->image + first - core->image_phys);
  writel(pa + 180, core->image + first - core->image_phys + 4);
  writel(pa + 180, core->image + second - core->image_phys);
  writel(first, core->image + second - core->image_phys + 4);
 } else if (update->action == QDX_DIAG_BF_CYCLE_EVENT_END) {
  if (!a[229] || (s64)get_unaligned_le64(cycle->account[0] + 292) <= 0 ||
      (a[228] && !get_unaligned_le32(a + 224))) { error = -EBADMSG; goto put; }
  writeb(0, core->image + ga - core->image_phys + 229);
 } else { error = -EINVAL; goto put; }
 wmb(); error = 0;
put:
 qdx_diag_fq_table_put(region);
leave:
 qdx_io_leave(endpoint->service->qdx);
 return error;
}
EXPORT_SYMBOL_GPL(qdx_diag_bf_cycle_write);

/* The old cycle writer deliberately permits B's independent callback. This
 * different operation requires both real callbacks joined and owns every
 * complete line of both groups, parent and accounts before any store. */
int qdx_diag_bf_multigroup_write(struct qdx_packet_op *operation,
 struct qdx_dma *region, const struct qdx_diag_fq_view *view,
 const struct qdx_diag_bf_multigroup_update *update, const struct qdx_owner *owner)
{
 const struct qdx_diag_bf_cycle *cycle;
 struct qdx_endpoint *endpoint = operation->endpoint;
 struct qdx_core *core = endpoint->core;
 const u8 *parent, *guard, *g;
 dma_addr_t table_address;
 u32 ga, gb, pa, source, length, header, extent, account[2], address, first, second;
 unsigned int i, ring, count;
 int error;

 if (!READ_ONCE(diag_mirror_table) || !view || !view->bf_cycle || !update ||
     !owner || !owner->module || strcmp(module_name(owner->module), "qdx_mirror_state_diag") ||
     operation->category != QDX_RECEIVE_PACKET || operation->class_tag != 0x4d54424c ||
     endpoint->service->kind != QDX_SERVICE_MIRROR || endpoint->dynamic_type != 65 ||
     !qdx_packet_op_drained(operation)) return -EPERM;
 cycle = view->bf_cycle;
 if (cycle->group_valid != 15 || cycle->parent_valid != 3 || cycle->timer_valid != 15 ||
     cycle->account_valid != 7 || cycle->header_valid != 3) return -ENODATA;
 if ((get_unaligned_le32(update->manager) & 1) ||
     (get_unaligned_le32(update->manager + 16) & 1) || !update->due) return -EBUSY;
 if (!qdx_io_enter(endpoint->service->qdx)) return -ESHUTDOWN;
 error = qdx_diag_fq_table_get(endpoint->service, region, owner, &table_address);
 if (error) goto leave;
 if (qdx_diag_fq_table_physical(region) || !qdx_diag_fq_table_matches(region, view->table)) {
  error = -ESTALE; goto put;
 }
 for (i = 0; i < 4; i++) {
  error = qdx_diag_bf_cycle_source(core, view, QDX_DIAG_BF_CYCLE_TIMER, i, &source, &length);
  if (error) goto put;
  g = cycle->group[i];
  if ((get_unaligned_le32(g) & 1) || g[160] ||
      (get_unaligned_le32(cycle->timer[i] + 24) & 2)) { error = -EBUSY; goto put; }
 }
 ga = cycle->group_address[0]; gb = cycle->group_address[1]; pa = cycle->parent_address[0];
 parent = cycle->parent[0]; guard = cycle->parent[1];
 /* A tail shares B's quiet header; B tail shares the genuinely allocated
  * inactive next GROUP header. Parent tail likewise has a real next owner. */
 if ((ga & 31) != 12 || gb != ga + 232 || (gb & 31) != 20 ||
     cycle->group_address[3] != gb + 232 || (pa & 31) != 12 ||
     cycle->parent_address[1] != pa + 200 ||
     pa < 0x402f9dac || pa >= 0x402fa3ec - 200 || (pa - 0x402f9dac) % 200 ||
     (get_unaligned_le32(parent) & 1) || get_unaligned_le32(parent + 8) != 6 ||
     get_unaligned_le32(parent + 16) != cycle->parent_tag[0] ||
     get_unaligned_le32(parent + 20) != cycle->generation || parent[24] ||
     get_unaligned_le32(parent + 4) || get_unaligned_le32(parent + 36) != cycle->root_pointer ||
     get_unaligned_le32(parent + 48) != 0x40087400 || parent[160] ||
     get_unaligned_le32(parent + 196) != 2 ||
     (get_unaligned_le32(guard) & 1) || get_unaligned_le32(guard + 8) != 6 ||
     get_unaligned_le32(guard + 16) != cycle->parent_tag[1] ||
     get_unaligned_le32(guard + 20) != cycle->generation || guard[24] || guard[160] ||
     get_unaligned_le32(guard + 4) || get_unaligned_le32(guard + 196) ||
     get_unaligned_le32(guard + 36) != cycle->root_pointer) { error = -ESTALE; goto put; }
 for (i = 0; i < 4; i++) {
  g = cycle->group[i]; address = cycle->group_address[i];
  if (i < 2) {
   if (get_unaligned_le32(g + 4) != pa || !g[24] || !g[228] ||
       !get_unaligned_le32(g + 212) || get_unaligned_le32(g + 180) != 128 ||
       get_unaligned_le32(g + 196) != 128 || get_unaligned_le32(g + 164) != 748800000 ||
       get_unaligned_le32(g + 224) > 1 || g[229] > 1) { error = -EBADMSG; goto put; }
  } else if (g[24] || g[228] || g[229] || get_unaligned_le32(g + 4) ||
      get_unaligned_le32(g + 212) || get_unaligned_le32(g + 224) ||
      get_unaligned_le32(g + 172) != address + 172 || get_unaligned_le32(g + 176) != address + 172 ||
      get_unaligned_le32(g + 188) != address + 188 || get_unaligned_le32(g + 192) != address + 188) {
   error = -EBUSY; goto put;
  }
 }
 if (get_unaligned_le32(cycle->group[0] + 212) != qdx_diag_fq_table_node(region, 0)) {
  error = -ESTALE; goto put;
 }
 /* Walk each actual current ring, accepting either order and zero/one/two P
  * entries. Membership follows the real flags; it is not inferred from debt. */
 for (ring = 0; ring < 2; ring++) {
  u32 offset = ring ? 188 : 172, sentinel = pa + (ring ? 180 : 172), previous = sentinel;
  u32 seen = 0;
  first = get_unaligned_le32(parent + (ring ? 180 : 172)); count = 0;
  while (first != sentinel) {
   if (first == ga + offset) i = 0;
   else if (first == gb + offset) i = 1;
   else { error = -EBADMSG; goto put; }
   if ((seen & BIT(i)) || count == 2 ||
       get_unaligned_le32(cycle->group[i] + offset + 4) != previous) { error = -EBADMSG; goto put; }
   seen |= BIT(i); count++; previous = first;
   first = get_unaligned_le32(cycle->group[i] + offset);
  }
  if (get_unaligned_le32(parent + (ring ? 184 : 176)) != previous ||
      (ring && seen != 3)) { error = -EBADMSG; goto put; }
  for (i = 0; i < 2; i++) {
   if (!ring && !!(seen & BIT(i)) != !!get_unaligned_le32(cycle->group[i] + 224)) { error = -EBADMSG; goto put; }
   if (!(seen & BIT(i)) && (get_unaligned_le32(cycle->group[i] + offset) != cycle->group_address[i] + offset ||
       get_unaligned_le32(cycle->group[i] + offset + 4) != cycle->group_address[i] + offset)) { error = -EBADMSG; goto put; }
  }
 }
 for (i = 0; i < 2; i++) {
  error = qdx_diag_bf_cycle_source(core, view, QDX_DIAG_BF_CYCLE_HEADER, i, &source, &header);
  if (error) goto put;
  account[i] = get_unaligned_le32(cycle->group[i] + 168);
  extent = get_unaligned_le32(cycle->header[i] + 4);
  if (get_unaligned_le32(cycle->header[i]) != account[i] ||
      get_unaligned_le16(cycle->header[i] + 12) != 121 || (cycle->header[i][15] & 8) ||
      extent < header + 312 || source < core->image_phys ||
      source - core->image_phys > core->image_size || extent > core->image_size - (source - core->image_phys) ||
      ((account[i] + 292) & ~31U) < source || ((account[i] + 307) | 31U) >= source + extent ||
      update->credit[i] <= -(1LL << 62) || update->credit[i] > (s64)get_unaligned_le64(cycle->account[i] + 284) ||
      get_unaligned_le32(cycle->account[i] + 280) || get_unaligned_le32(cycle->account[i] + 272) ||
      get_unaligned_le32(cycle->account[2] + 280) ||
      update->reference[i] > get_unaligned_le64(cycle->account[2] + 300)) { error = -ERANGE; goto put; }
 }
 if (account[0] == account[1] || update->credit[0] <= 0 || update->credit[1] >= 0) {
  error = -EBADMSG; goto put;
 }
 /* No allocation, native command or rejection after the first store. */
 for (i = 0; i < 2; i++) {
  writel(lower_32_bits(update->credit[i]), core->image + account[i] - core->image_phys + 292);
  writel(upper_32_bits(update->credit[i]), core->image + account[i] - core->image_phys + 296);
  writel(lower_32_bits(update->reference[i]), core->image + account[i] - core->image_phys + 300);
  writel(upper_32_bits(update->reference[i]), core->image + account[i] - core->image_phys + 304);
  address = cycle->group_address[i];
  writel(i ? -64 : 64, core->image + address - core->image_phys + 184);
  writel(0, core->image + address - core->image_phys + 200);
  writel(i ? 0 : 1, core->image + address - core->image_phys + 224);
  writeb(1, core->image + address - core->image_phys + 228);
  writeb(i, core->image + address - core->image_phys + 229);
 }
 first = ga + 172; second = gb + 172;
 writel(first, core->image + pa - core->image_phys + 172);
 writel(first, core->image + pa - core->image_phys + 176);
 writel(pa + 172, core->image + first - core->image_phys);
 writel(pa + 172, core->image + first - core->image_phys + 4);
 writel(second, core->image + second - core->image_phys);
 writel(second, core->image + second - core->image_phys + 4);
 first = ga + 188; second = gb + 188;
 writel(first, core->image + pa - core->image_phys + 180);
 writel(second, core->image + pa - core->image_phys + 184);
 writel(second, core->image + first - core->image_phys);
 writel(pa + 180, core->image + first - core->image_phys + 4);
 writel(pa + 180, core->image + second - core->image_phys);
 writel(first, core->image + second - core->image_phys + 4);
 writel(2, core->image + pa - core->image_phys + 196);
 wmb(); error = 0;
put:
 qdx_diag_fq_table_put(region);
leave:
 qdx_io_leave(endpoint->service->qdx);
 return error;
}
EXPORT_SYMBOL_GPL(qdx_diag_bf_multigroup_write);


/* Scratch insertion after qdx_diag_bf_import. No arbitrary address API.
 * prepare writes only a joined idle account; publish swaps one aligned pointer.
 * The caller closes all other writers and performs NSS source release before
 * each write and consequential source reads afterward. A callback may capture
 * either complete account, so both allocations stay owned until real join.
 */
int qdx_diag_bf_pair_write(struct qdx_packet_op *operation, struct qdx_dma *region,
 struct qdx_packet_op *loans, const struct qdx_diag_fq_view *view,
 const struct qdx_diag_bf_state *observed, const struct qdx_diag_bf_pair_update *update,
 const struct qdx_owner *owner)
{
 struct qdx_endpoint *endpoint = operation->endpoint;
 struct qdx_core *core = endpoint->core;
 const struct qdx_diag_bf_pair *pair;
 const u8 *group, *parent;
 dma_addr_t table_address;
 u32 source, length, primary, aux, original, replacement, key[7], header, extent, frequency;
 unsigned int i, alignment;
 int error;

 if (!READ_ONCE(diag_mirror_table) || !view || !view->bf || view->wrr ||
     view->rate || view->aqm || !view->bf_pair || !observed || !update ||
     !owner || !owner->module || strcmp(module_name(owner->module), "qdx_mirror_state_diag") ||
     operation->category != QDX_RECEIVE_PACKET || operation->class_tag != 0x4d54424c ||
     endpoint->service->kind != QDX_SERVICE_MIRROR || endpoint->dynamic_type != 65 ||
     !qdx_packet_op_drained(operation) || (view->bf_valid & 15) != 15)
  return -EPERM;
 pair = view->bf_pair; group = view->bf_group; parent = view->bf_parent;
 if (pair->valid != 31 || update->action < QDX_DIAG_BF_PAIR_PREPARE ||
     update->action > QDX_DIAG_BF_PAIR_RESTORE) return -EPERM;
 /* The caller collected either after this callback's permanent join, or
  * entirely before the same queued event's absolute deadline. Auxiliary wait
  * and queued state were read before this inactive-manager observation. */
 if ((get_unaligned_le32(observed->epoch[0]) & 1) ||
     (get_unaligned_le32(observed->epoch[0] + 16) & 1)) return -EBUSY;
 for (i = 0; i < 2; i++)
  if (get_unaligned_le32(observed->frequency[i]) & 1) return -EBUSY;
 if (get_unaligned_le32(observed->frequency[0] + 4) != get_unaligned_le32(observed->frequency[1] + 4) ||
     observed->clock_ms[1] < observed->clock_ms[0] ||
     observed->clock_ms[1] - observed->clock_ms[0] >= 32768) return -ESTALE;
 if (!observed->timer_joined &&
     (!(get_unaligned_le32(observed->timer + 24) & 2) ||
      get_unaligned_le64(observed->timer + 16) <= observed->clock_ms[1])) return -ESTALE;
 frequency = get_unaligned_le32(observed->frequency[1] + 4);
 if (!qdx_io_enter(endpoint->service->qdx)) return -ESHUTDOWN;
 error = qdx_diag_fq_table_get(endpoint->service, region, owner, &table_address);
 if (error) goto leave;
 if (qdx_diag_fq_table_physical(region) || !qdx_diag_fq_table_matches(region, view->table)) {
  error = -EPERM; goto put;
 }
 error = qdx_diag_fq_source(endpoint, loans, view, QDX_DIAG_BF_AUX_ACCOUNT, 0,
  table_address, qdx_diag_fq_table_node(region, 0), false, &replacement, &length);
 if (error) goto put;
 primary = get_unaligned_le32(view->node + 4);
 source = get_unaligned_le32(group + 204);
 if (source == get_unaligned_le32(group + 4) + 188) source = get_unaligned_le32(group + 208);
 aux = source - 204;
 original = update->original_account;
 key[0] = qdx_diag_fq_table_node(region, 0); key[1] = get_unaligned_le32(view->node + 36);
 key[2] = primary; key[3] = get_unaligned_le32(group + 4);
 key[4] = original; key[5] = get_unaligned_le32(group + 220);
 key[6] = get_unaligned_le32(group + 216);
 if (!qdx_diag_fq_table_bf(region, key, false)) { error = -ESTALE; goto put; }
 /* The original allocation remains pinned after the pointer moves. Its
  * header is the pre-publication source copy, tied to the retained BF key.
  */
 alignment = get_unaligned_le32(view->bf_allocator + 12);
 if (alignment < 4 || alignment > 64 || !is_power_of_2(alignment)) { error = -EBADMSG; goto put; }
 header = ALIGN(28, alignment);
 source = original - header; extent = get_unaligned_le32(view->bf_header + 4);
 if (original < header || get_unaligned_le32(view->bf_header) != original ||
     get_unaligned_le16(view->bf_header + 12) != 121 || (view->bf_header[15] & 8) ||
     extent < header + 312 || source < core->image_phys ||
     source - core->image_phys > core->image_size ||
     extent > core->image_size - (source - core->image_phys)) { error = -ERANGE; goto put; }
 /* The validated 232-byte GROUP pool has residues4/12/20/28. Pointer168
  * and deficit184 occupy complete relative lines140..211 across these four
  * layouts, always inside this object and away from lock0/activity228/wait229.
  * They can share P/E links and structural links204/208. None has a writer
  * here: producers/selection/configuration/frequency are joined, the auxiliary
  * is inactive, and this sole P1 group's positive timer callback returns
  * before parent list stores; its negative callback never calls the parent.
  * Keep the complete one-active-P1 and ownership proof below for all actions.
  */
 if ((primary & 7) != 4 ||
     (get_unaligned_le32(group) & 1) ||
     (get_unaligned_le32(parent) & 1) || (get_unaligned_le32(pair->group) & 1) ||
     group[160] || pair->group[160] || !group[228] ||
     get_unaligned_le32(group + 224) != 1 ||
     get_unaligned_le32(parent + 196) != 1 ||
     get_unaligned_le32(group + 180) != 128 ||
     get_unaligned_le32(group + 196) != 128 ||
     get_unaligned_le32(pair->group + 180) != 128 ||
     get_unaligned_le32(pair->group + 196) != 128 ||
     get_unaligned_le32(group + 172) != key[3] + 172 ||
     get_unaligned_le32(group + 176) != key[3] + 172 ||
     get_unaligned_le32(parent + 172) != primary + 172 ||
     get_unaligned_le32(parent + 176) != primary + 172 ||
     get_unaligned_le32(group + 188) != key[3] + 180 ||
     get_unaligned_le32(group + 192) != key[3] + 180 ||
     get_unaligned_le32(parent + 180) != primary + 188 ||
     get_unaligned_le32(parent + 184) != primary + 188 ||
     get_unaligned_le32(observed->timer + 8) != 0x40086600 ||
     get_unaligned_le32(observed->timer + 12) != primary ||
     pair->group[229] || (get_unaligned_le32(pair->timer + 24) & 2) ||
     get_unaligned_le32(observed->notifier + 4) != 0x40086900 ||
     get_unaligned_le32(observed->notifier + 8) != primary ||
     get_unaligned_le32(pair->notifier + 4) != 0x40086900 ||
     get_unaligned_le32(pair->notifier + 8) != aux ||
     get_unaligned_le32(observed->notifier + 12) != frequency ||
     get_unaligned_le32(pair->notifier + 12) != frequency || original == replacement) {
  error = -EBADMSG; goto put;
 }
 error = qdx_diag_bf_pair_source(core, view, QDX_DIAG_BF_AUX_HEADER, &source, &length);
 if (error) goto put;
 header = length; extent = get_unaligned_le32(pair->header + 4);
 if (get_unaligned_le32(pair->header) != replacement ||
     get_unaligned_le16(pair->header + 12) != 121 || (pair->header[15] & 8) ||
     extent < header + 312 || source - core->image_phys > core->image_size ||
     extent > core->image_size - (source - core->image_phys) ||
     ((replacement + 292) & ~31U) < source ||
     ((replacement + 307) | 31U) >= source + extent) { error = -ERANGE; goto put; }
 if (update->action == QDX_DIAG_BF_PAIR_RESTORE) {
  if (!observed->timer_joined || get_unaligned_le32(group + 168) != replacement || group[229] ||
      (get_unaligned_le32(observed->timer + 24) & 2)) { error = -EBUSY; goto put; }
  writel(original, core->image + primary - core->image_phys + 168);
 } else {
  if (get_unaligned_le32(group + 168) != original || !group[229] ||
      !(get_unaligned_le32(observed->timer + 24) & 2) ||
      memcmp(observed->current_account, pair->account, 292) ||
      get_unaligned_le32(pair->account + 308) != get_unaligned_le32(observed->current_account + 308) ||
      update->credit >= 0 || update->credit <= -(1LL << 62) ||
      update->deficit < -128 || update->deficit > 128) { error = -EBADMSG; goto put; }
  if (update->action == QDX_DIAG_BF_PAIR_PREPARE) {
   if (update->reference != get_unaligned_le64(pair->account + 300)) { error = -ESTALE; goto put; }
   writel(lower_32_bits(update->credit), core->image + replacement - core->image_phys + 292);
   writel(upper_32_bits(update->credit), core->image + replacement - core->image_phys + 296);
   /* Reference already comes from actual native CONFIG on this idle account. */
  } else {
   if ((s64)get_unaligned_le64(pair->account + 292) != update->credit ||
       get_unaligned_le64(pair->account + 300) != update->reference) { error = -ESTALE; goto put; }
   /* This one-active-group P1 callback cannot change this line: positive
    *40087064..74 returns before list stores; negative40086728 skips parent.
    * No other group can append a tail, and ordinary selection is detached.
    */
   writel(update->deficit, core->image + primary - core->image_phys + 184);
   writel(replacement, core->image + primary - core->image_phys + 168);
  }
 }
 wmb(); error = 0;
put:
 qdx_diag_fq_table_put(region);
leave:
 qdx_io_leave(endpoint->service->qdx);
 return error;
}
EXPORT_SYMBOL_GPL(qdx_diag_bf_pair_write);


/* Typed, finite IGS continuation. The module has joined every selected timer
 * and configuration writer, and completed source-release for these copies.
 * State contains semantic indices, never an arbitrary target pointer/offset.
 */
int qdx_diag_rate_import(struct qdx_packet_op *operation, struct qdx_dma *region,
 struct qdx_packet_op *loans, const struct qdx_diag_fq_view *view,
 const struct qdx_diag_rate_state *state, const struct qdx_owner *owner)
{
 struct qdx_endpoint *endpoint = operation->endpoint;
 struct qdx_core *core = endpoint->core;
 const struct qdx_diag_rate_view *rate;
 const u8 *object, *account;
 dma_addr_t table_address;
 u32 address[4], source, node, start, extent, header, alignment, frequency;
 u32 seen, preferred_mask = 0, shaper, parent, tag, sentinel, before, after;
 unsigned int length, i, j, count, child, offset, order;
 bool physical;
 int error;

 if (!READ_ONCE(diag_mirror_table) || !view || !view->rate || !state ||
     !owner || !owner->module ||
     (strcmp(module_name(owner->module), "qdx_rate_handover_diag") &&
      strcmp(module_name(owner->module), "qdx_physical_rate_diag")) ||
     operation->category != QDX_RECEIVE_PACKET || operation->class_tag != 0x4d54424c ||
     endpoint->service->kind != QDX_SERVICE_MIRROR || endpoint->dynamic_type != 65 ||
     !qdx_packet_op_drained(operation) || view->bf || view->wrr || view->aqm)
  return -EPERM;
 physical = !strcmp(module_name(owner->module), "qdx_physical_rate_diag");
 if ((physical && (loans || !view->physical_rebuild)) ||
     (!physical && view->physical_rebuild)) return -EPERM;
 rate = view->rate;
 if (!(rate->valid & QDX_RATE_CLOCK_ACCOUNT_VALID) ||
     !(rate->valid & QDX_RATE_TIMERS_JOINED)) return -ENODATA;
 /* epoch[0] follows every owned timer's unqueued observation. Its inactive
  * bit joins callbacks already removed from the timer list. The caller then
  * recopied all policy fields, with no producer/selector/config/frequency
  * writer able to rearm these one-shot timers. Later unrelated timer-manager
  * activity does not invalidate the joined objects. */
 if ((get_unaligned_le32(rate->epoch[0]) & 1) ||
     (get_unaligned_le32(rate->epoch[0] + 16) & 1)) return -EBUSY;
 for (i = 0; i < 2; i++)
  if (get_unaligned_le32(rate->frequency[i]) & 1) return -EBUSY;
 if (get_unaligned_le32(rate->frequency[0] + 4) !=
      get_unaligned_le32(rate->frequency[1] + 4) ||
     rate->clock_ms[1] < rate->clock_ms[0] ||
     rate->clock_ms[1] - rate->clock_ms[0] >= 32768)
  return -ESTALE;
 frequency = get_unaligned_le32(rate->frequency[1] + 4);
 if (!qdx_io_enter(endpoint->service->qdx)) return -ESHUTDOWN;
 error = qdx_diag_fq_table_get(endpoint->service, region, owner, &table_address);
 if (error) goto leave;
 if (qdx_diag_fq_table_physical(region) != physical ||
     !qdx_diag_fq_table_matches(region, view->table)) {
  error = -ESTALE; goto put;
 }
 node = qdx_diag_fq_table_node(region, 0);
 error = qdx_diag_fq_source(endpoint, loans, view, QDX_DIAG_RATE_SELECTOR,
  0, table_address, node, physical, &source, &length);
 if (error) goto put;
 parent = source;
 if (!rate->group_mode) {
  error = qdx_diag_fq_source(endpoint, loans, view, QDX_DIAG_RATE_ACCOUNT,
   0, table_address, node, physical, &source, &length);
  if (error) goto put;
  address[0] = source;
  error = qdx_diag_fq_source(endpoint, loans, view, QDX_DIAG_RATE_ACCOUNT_HEADER,
   0, table_address, node, physical, &source, &length);
  if (error) goto put;
  if (!(rate->valid & QDX_RATE_HEADER_VALID) ||
      !(rate->valid & QDX_RATE_ACCOUNT_VALID) ||
      get_unaligned_le32(rate->account_header) != address[0] ||
      get_unaligned_le16(rate->account_header + 12) != 121 ||
      (rate->account_header[15] & 8) ||
      (get_unaligned_le32(rate->timer + 24) & 2) ||
      get_unaligned_le32(rate->timer + 8) != 0x40089400 ||
      get_unaligned_le32(rate->timer + 12) != get_unaligned_le32(rate->selector + 164) ||
      get_unaligned_le32(rate->notifier + 12) != frequency) {
   error = -EBADMSG; goto put;
  }
  alignment = get_unaligned_le32(rate->allocator + 12);
  header = ALIGN(28, alignment);
  start = source;
  extent = get_unaligned_le32(rate->account_header + 4);
  if (extent < header + 312 || start < core->image_phys ||
      extent > core->image_size - (start - core->image_phys) ||
      ((address[0] + 292) & ~31U) < start ||
      ((address[0] + 307) | 31U) >= start + extent ||
      state->credit[0][0] >= 0 || state->credit[0][0] <= -(1LL << 62) ||
      state->reference[0][0] > get_unaligned_le64(rate->clock_account + 300) ||
      get_unaligned_le32(rate->account + 280) ||
      get_unaligned_le32(rate->clock_account + 280)) {
   error = -ERANGE; goto put;
  }
  writel(lower_32_bits(state->credit[0][0]), core->image + address[0] - core->image_phys + 292);
  writel(upper_32_bits(state->credit[0][0]), core->image + address[0] - core->image_phys + 296);
  writel(lower_32_bits(state->reference[0][0]), core->image + address[0] - core->image_phys + 300);
  writel(upper_32_bits(state->reference[0][0]), core->image + address[0] - core->image_phys + 304);
  wmb(); error = 0; goto put;
 }
 shaper = get_unaligned_le32(view->node + 36);
 for (i = 0; i < 4; i++) {
  error = qdx_diag_fq_source(endpoint, loans, view,
   i ? QDX_DIAG_RATE_GROUP_CHILD : QDX_DIAG_RATE_GROUP_ROOT,
   i, table_address, node, physical, &source, &length);
  if (error) goto put;
  address[i] = source;
  object = rate->group[i];
  tag = get_unaligned_le32(object + 16);
  if (!(rate->valid & QDX_RATE_GROUP_VALID(i)) ||
      get_unaligned_le32(object + 8) != 12 ||
      (!i && tag != 0x71010000) ||
      (i && (tag < 0x71200000 || tag > 0x713f0000 || (tag & 0xffff))) ||
      get_unaligned_le32(object + 20) != get_unaligned_le32(view->node + 20) || !object[24] ||
      get_unaligned_le32(object + 4) != (i ? address[0] : parent) ||
      get_unaligned_le32(object + 36) != shaper ||
      get_unaligned_le32(object + 48) != 0x400608e0 ||
      get_unaligned_le32(object + 60) != 0x4005fbc0 ||
      get_unaligned_le32(object + 68) != 0x40061060 ||
      get_unaligned_le32(object + 72) != 0x40060e20 ||
      get_unaligned_le32(object + 276) || get_unaligned_le32(object + 280) ||
      (get_unaligned_le32(object + 952) & 2) ||
      get_unaligned_le32(object + 924) != frequency ||
      (i && ((source + 1004) & 31))) {
   error = -EBADMSG; goto put;
  }
  /* Constructor clears only callback and flags. A recreated GROUP can
   * remain never armed while the outer selector is detached. Context and
   * deadline are not defined until arm; the joined-writer checks above still
   * apply. A registered callback must belong to this exact GROUP. */
  if (!get_unaligned_le32(object + 936)) {
   if (get_unaligned_le32(object + 952)) {
    error = -EBADMSG; goto put;
   }
  } else if (get_unaligned_le32(object + 936) != 0x4005f8c0 ||
             get_unaligned_le32(object + 940) != source) {
   error = -EBADMSG; goto put;
  }
  if (i && (get_unaligned_le32(object + 968) !=
             (i == 1 ? address[0] + 168 : address[i - 1] + 964) ||
            !get_unaligned_le32(object + 164))) {
   error = -EBADMSG; goto put;
  }
  for (j = 0; j < i; j++)
   if (address[j] == source) { error = -ELOOP; goto put; }
  for (j = 0; j < 2; j++) {
   account = object + (j ? 600 : 288);
   if (get_unaligned_le32(account + 280) ||
       state->credit[i][j] <= -(1LL << 62) ||
       state->credit[i][j] > (s64)get_unaligned_le64(account + 284) ||
       state->reference[i][j] > get_unaligned_le64(rate->clock_account + 300) ||
       (i && j && state->credit[i][j] <= 0)) {
    error = -ERANGE; goto put;
   }
  }
 }
 if (get_unaligned_le32(rate->group[3] + 964) != address[0] + 168 ||
     get_unaligned_le32(rate->group[0] + 172) != address[3] + 964 ||
     (rate->group[0][960] & 1) || get_unaligned_le32(rate->group[0] + 272) != 3 ||
     (state->preferred_count < 2 || state->preferred_count > 3) || state->credit[0][1] >= 0 ||
     get_unaligned_le32(rate->clock_account + 280)) {
  error = -EBADMSG; goto put;
 }
 for (order = 0; order < 2; order++) {
  count = order ? 3 : state->preferred_count;
  seen = 0;
  for (i = 0; i < count; i++) {
   child = order ? state->borrowing[i] : state->preferred[i];
   if (child >= 3 || (seen & BIT(child))) { error = -EINVAL; goto put; }
   seen |= BIT(child);
  }
  if (order && seen != 7) { error = -EINVAL; goto put; }
  if (!order) preferred_mask = seen;
 }
 /* B/C stay entitled in this finite fixture. A is indebted but can still
  * be preferred: native membership is decided from pre-debit credit after
  * selecting a packet, not reconstructed from the newly debited account.
  * Preserve either actual A phase, with unchanged identity/writer checks. */
 if ((preferred_mask & 6) != 6 || state->credit[1][0] >= 0 ||
     state->credit[2][0] <= 0 || state->credit[3][0] <= 0) {
  error = -EBADMSG; goto put;
 }
 for (i = 0; i < 3; i++) {
  if (get_unaligned_le32(rate->group[i + 1] + 272) != 1 ||
      (get_unaligned_le32(rate->group[i + 1] + 960) & 1)) {
   error = -EBADMSG; goto put;
  }
 }
 /* Every check precedes any write. The outer selector remains detached and
  * timers/frequency/configuration have been joined by the pinned caller.
  */
 for (i = 0; i < 4; i++)
  for (j = 0; j < 2; j++) {
   offset = j ? 892 : 580;
   writel(lower_32_bits(state->credit[i][j]), core->image + address[i] - core->image_phys + offset);
   writel(upper_32_bits(state->credit[i][j]), core->image + address[i] - core->image_phys + offset + 4);
   writel(lower_32_bits(state->reference[i][j]), core->image + address[i] - core->image_phys + offset + 8);
   writel(upper_32_bits(state->reference[i][j]), core->image + address[i] - core->image_phys + offset + 12);
  }
 for (order = 0; order < 2; order++) {
  offset = order ? 208 : 176;
  sentinel = address[0] + offset;
  count = order ? 3 : state->preferred_count;
  for (j = 0; j < 4; j++) {
   writel(sentinel + j * 8, core->image + address[0] - core->image_phys + offset + j * 8);
   writel(sentinel + j * 8, core->image + address[0] - core->image_phys + offset + j * 8 + 4);
   writel(j ? 0 : count, core->image + address[0] - core->image_phys + (order ? 256 : 240) + j * 4);
  }
  for (i = 0; i < 3; i++) {
   source = address[i + 1] + (order ? 988 : 972);
   writel(source, core->image + source - core->image_phys);
   writel(source, core->image + source - core->image_phys + 4);
   writel(state->deficit[i][order], core->image + source - core->image_phys + 12);
  }
  for (i = 0; i < count; i++) {
   child = order ? state->borrowing[i] : state->preferred[i];
   source = address[child + 1] + (order ? 988 : 972);
   before = i ? address[(order ? state->borrowing[i - 1] : state->preferred[i - 1]) + 1] +
                (order ? 988 : 972) : sentinel;
   after = i + 1 < count ?
    address[(order ? state->borrowing[i + 1] : state->preferred[i + 1]) + 1] +
     (order ? 988 : 972) : sentinel;
   writel(after, core->image + source - core->image_phys);
   writel(before, core->image + source - core->image_phys + 4);
   if (!i) writel(source, core->image + sentinel - core->image_phys);
   if (i + 1 == count) writel(source, core->image + sentinel - core->image_phys + 4);
  }
 }
 writel(3, core->image + address[0] - core->image_phys + 272);
 wmb(); error = 0;
put:
 qdx_diag_fq_table_put(region);
leave:
 qdx_io_leave(endpoint->service->qdx);
 return error;
}
EXPORT_SYMBOL_GPL(qdx_diag_rate_import);

/* No graph, timer, lock or function pointer is imported. The actual MIRROR
 * release has completed; every byte lies in the selected owned allocation. */
static int qdx_diag_aqm_write(struct qdx_packet_op *operation, struct qdx_dma *region,
 struct qdx_packet_op *anchor, const struct qdx_diag_fq_view *view,
 const struct qdx_diag_aqm_state *state, unsigned int index, u64 age,
 const struct qdx_owner *owner)
{
 struct qdx_endpoint *endpoint = operation->endpoint;
 struct qdx_core *core = endpoint->core;
 const struct qdx_diag_aqm_view *aqm;
 dma_addr_t table_address;
 u32 node, source, count, classes = 0, occupancy[7] = {}, class, begin, end;
 unsigned int length, i;
 int error;

 if (!READ_ONCE(diag_mirror_table) || !view || !view->aqm || !owner ||
     !owner->module || (strcmp(module_name(owner->module), "qdx_aqm_handover_diag") &&
      strcmp(module_name(owner->module), "qdx_physical_aqm_diag")) ||
     operation->category != QDX_RECEIVE_PACKET || operation->class_tag != 0x4d54424c ||
     endpoint->service->kind != QDX_SERVICE_MIRROR || endpoint->dynamic_type != 65 ||
     !qdx_packet_op_drained(operation)) return -EPERM;
 aqm = view->aqm;
 if (!state && !aqm->plain) return -EPERM;
 if (!qdx_io_enter(endpoint->service->qdx)) return -ESHUTDOWN;
 error = qdx_diag_fq_table_get(endpoint->service, region, owner, &table_address);
 if (error) goto leave;
 if ((!strcmp(module_name(owner->module), "qdx_physical_aqm_diag") &&
      (!qdx_diag_fq_table_physical(region) || anchor)) ||
     (!strcmp(module_name(owner->module), "qdx_aqm_handover_diag") &&
      qdx_diag_fq_table_physical(region))) {
  error = -EPERM; goto put;
 }
 if (!qdx_diag_fq_table_matches(region, view->table)) {
  error = -ESTALE; goto put;
 }
 /* Clock range checks the complete node identity even when its FIFO is empty. */
 error = qdx_diag_fq_source(endpoint, anchor, view, QDX_DIAG_AQM_CLOCK, 0,
  table_address, qdx_diag_fq_table_node(region, 0), qdx_diag_fq_table_physical(region),
  &source, &length);
 if (error) goto put;
 node = get_unaligned_le32(aqm->selector + 164);
 count = get_unaligned_le32(aqm->node + (aqm->plain ? 180 : 172));
 if (!count) {
  if (!state || state->count || state->active ||
      get_unaligned_le32(aqm->node + (aqm->plain ? 172 : 164)) ||
      get_unaligned_le32(aqm->node + (aqm->plain ? 176 : 168))) {
   error = -EBADMSG; goto put;
  }
  if (!qdx_diag_fq_table_physical(region)) {
   if (!aqm->data || aqm->data->endpoint->core != core ||
       aqm->data->endpoint->service->qdx != endpoint->service->qdx ||
       aqm->data->endpoint->service->kind != QDX_SERVICE_IGS ||
       aqm->data->endpoint->dynamic_type != 53 ||
       aqm->data->category != QDX_RECEIVE_RETURNED ||
       aqm->data->class_tag != get_unaligned_le32(aqm->node + 16) ||
       smp_load_acquire(&aqm->data->open) || READ_ONCE(aqm->data->accepted) ||
       !qdx_packet_op_drained(aqm->data)) { error = -EPERM; goto put; }
  } else if (aqm->physical_rebuild &&
      (aqm->physical_rebuild->endpoint->core != core ||
       aqm->physical_rebuild->endpoint->service->qdx != endpoint->service->qdx ||
       aqm->physical_rebuild->endpoint->dynamic_type ||
       aqm->physical_rebuild->endpoint->ifnum != 4 ||
       aqm->physical_rebuild->class.tag != get_unaligned_le32(aqm->node + 16) ||
       smp_load_acquire(&aqm->physical_rebuild->open) ||
       READ_ONCE(aqm->physical_rebuild->accepted))) { error = -EPERM; goto put; }
 } else {
  error = qdx_diag_fq_source(endpoint, anchor, view, QDX_DIAG_AQM_PAYLOAD, index,
   table_address, qdx_diag_fq_table_node(region, 0), qdx_diag_fq_table_physical(region),
   &source, &length);
  if (error) goto put;
 }
 if (state) {
  if (state->count != count || state->active > 1 || state->dropping > 1) {
   error = -EINVAL; goto put;
  }
  if (aqm->plain) {
   begin = (node + 188) & ~31U; end = (node + 219) | 31U;
   if (begin < node || end >= node + 280) { error = -EXDEV; goto put; }
  } else {
   classes = get_unaligned_le32(aqm->node + 488);
   if (classes > 6 || aqm->node[497] > 1 ||
       (aqm->node[497] && !classes) || (node & 31) == 8 || (node & 31) == 16) {
    error = -EBADMSG; goto put;
   }
   for (i = 0; i < count; i++) {
    error = qdx_diag_fq_source(endpoint, anchor, view, QDX_DIAG_AQM_PAYLOAD, i,
     table_address, qdx_diag_fq_table_node(region, 0), qdx_diag_fq_table_physical(region), &source, &length);
    if (error) goto put;
    class = get_unaligned_le32(aqm->metadata[i] + 80);
    if (class > classes || (!class && aqm->node[497])) { error = -EBADMSG; goto put; }
    occupancy[class] += length;
   }
   for (i = 0; i <= classes; i++)
    if (state->occupancy[i] != occupancy[i] ||
        get_unaligned_le32(aqm->node + 216 + 44 * i) != occupancy[i]) {
     error = -EBADMSG; goto put;
    }
  }
  if (aqm->plain) {
   for (i = 0; i < count; i++) {
    error = qdx_diag_fq_source(endpoint, anchor, view, QDX_DIAG_AQM_PAYLOAD, i,
     table_address, qdx_diag_fq_table_node(region, 0), qdx_diag_fq_table_physical(region),
     &source, &length);
    if (error) goto put;
   }
  }
  /* Every check precedes all writes, including full real FIFO identity. */
  if (aqm->plain) {
   writel(state->codel_count, core->image + node - core->image_phys + 188);
   writel(lower_32_bits(state->first_above), core->image + node - core->image_phys + 192);
   writel(upper_32_bits(state->first_above), core->image + node - core->image_phys + 196);
   writel(lower_32_bits(state->drop_next), core->image + node - core->image_phys + 200);
   writel(upper_32_bits(state->drop_next), core->image + node - core->image_phys + 204);
   writel(state->delay_max, core->image + node - core->image_phys + 208);
   writel(state->delay_min, core->image + node - core->image_phys + 212);
   writeb(state->dropping, core->image + node - core->image_phys + 218);
  } else {
   for (i = 0; i <= classes; i++)
    writel(state->average[i], core->image + node - core->image_phys + 184 + 44 * i);
   writel(lower_32_bits(state->idle), core->image + node - core->image_phys + 500);
   writel(upper_32_bits(state->idle), core->image + node - core->image_phys + 504);
   writeb(state->active, core->image + node - core->image_phys + 508);
  }
 } else {
  source = get_unaligned_le32(aqm->carrier[index] + 36);
  if ((source & 31) || source < core->image_phys ||
      source + 96 > core->image_phys + core->image_size) { error = -ERANGE; goto put; }
  writel(lower_32_bits(age), core->image + source - core->image_phys + 72);
  writel(upper_32_bits(age), core->image + source - core->image_phys + 76);
 }
 wmb(); error = 0;
put:
 qdx_diag_fq_table_put(region);
leave:
 qdx_io_leave(endpoint->service->qdx);
 return error;
}

int qdx_diag_aqm_import(struct qdx_packet_op *operation, struct qdx_dma *region,
 struct qdx_packet_op *anchor, const struct qdx_diag_fq_view *view,
 const struct qdx_diag_aqm_state *state, const struct qdx_owner *owner)
{
 if (!state) return -EINVAL;
 return qdx_diag_aqm_write(operation, region, anchor, view, state, 0, 0, owner);
}
EXPORT_SYMBOL_GPL(qdx_diag_aqm_import);
int qdx_diag_aqm_age_import(struct qdx_packet_op *operation, struct qdx_dma *region,
 struct qdx_packet_op *anchor, const struct qdx_diag_fq_view *view,
 unsigned int index, u64 age, const struct qdx_owner *owner)
{
 return qdx_diag_aqm_write(operation, region, anchor, view, NULL, index, age, owner);
}
EXPORT_SYMBOL_GPL(qdx_diag_aqm_age_import);

/* Only DDR data owned by this frozen fixture is writable. The caller has
 * completed its real MIRROR source release; cached shared boundary lines are
 * refused rather than assumed harmless. No local carrier or code write.
 */
static int qdx_diag_fq_import(struct qdx_packet_op *operation, struct qdx_dma *region,
 struct qdx_packet_op *loans, const struct qdx_diag_fq_view *view,
 unsigned int index, u64 age, const u32 *values, const struct qdx_owner *owner)
{
 static const u16 offsets[8] = { 224, 228, 232, 236, 240, 252, 256, 260 };
 struct qdx_endpoint *endpoint = operation->endpoint;
 struct qdx_core *core = endpoint->core;
 dma_addr_t table_address;
 u32 source, node, begin, end, pointer, previous, sentinel, seen = 0, expected_active = 3;
 unsigned int length, i;
 int error;

 if (!READ_ONCE(diag_mirror_table) || !view || !owner || !owner->module ||
     (strcmp(module_name(owner->module), "qdx_mirror_state_diag") &&
      strcmp(module_name(owner->module), "qdx_physical_fq_diag")) ||
     operation->category != QDX_RECEIVE_PACKET || operation->class_tag != 0x4d54424c ||
     endpoint->service->kind != QDX_SERVICE_MIRROR || endpoint->dynamic_type != 65 ||
     !qdx_packet_op_drained(operation))
  return -EPERM;
 if (!qdx_io_enter(endpoint->service->qdx))
  return -ESHUTDOWN;
 error = qdx_diag_fq_table_get(endpoint->service, region, owner, &table_address);
 if (error)
  goto leave;
 if ((view->bf && qdx_diag_fq_table_physical(region) &&
      strcmp(module_name(owner->module), "qdx_physical_fq_diag")) ||
     (!strcmp(module_name(owner->module), "qdx_physical_fq_diag") &&
      (!qdx_diag_fq_table_physical(region) || view->wrr || view->rate || view->aqm))) {
  error = -EPERM;
  goto put;
 }
 if (!qdx_diag_fq_table_matches(region, view->table)) {
  error = -ESTALE;
  goto put;
 }
 /* PAYLOAD also proves the selected actual packet-loan identity. */
 error = qdx_diag_fq_source(endpoint, loans, view, QDX_DIAG_FQ_PAYLOAD,
  index, table_address, qdx_diag_fq_table_node(region, 0),
  qdx_diag_fq_table_physical(region), &source, &length);
 if (error)
  goto put;
 if (values) {
  if (qdx_diag_fq_table_physical(region)) {
   expected_active = 0;
   for (i = 0; i < 2; i++)
    if (get_unaligned_le32(view->table + i * 72) != table_address + i * 72 ||
        get_unaligned_le32(view->table + i * 72 + 4) != table_address + i * 72)
     expected_active |= BIT(i);
  }
  node = qdx_diag_fq_table_node(region, 0);
  for (i = 0; i < 8; i++) {
   begin = (node + offsets[i]) & ~31U;
   end = (node + offsets[i] + 3) | 31U;
   if (begin < node || end >= node + 280) {
    error = -EXDEV;
    goto put;
   }
  }
  if ((values[0] && values[0] != table_address && values[0] != table_address + 72) ||
      values[5] > 2 || values[6] > 2 || values[5] + values[6] != hweight32(expected_active) ||
      !values[7] || values[7] > U16_MAX) {
   error = -EINVAL;
   goto put;
  }
  /* The firmware field at node+260 is the largest observed packet length,
   * not a queue count. Retained history may exceed today's queued maximum;
   * every actual live packet must still fit within the imported value.
   */
  for (i = 0; i < get_unaligned_le32(view->table + 24) +
                    get_unaligned_le32(view->table + 96); i++) {
   error = qdx_diag_fq_source(endpoint, loans, view, QDX_DIAG_FQ_PAYLOAD,
    i, table_address, node, qdx_diag_fq_table_physical(region), &source, &length);
   if (error)
    goto put;
   if (length > values[7]) {
    error = -EINVAL;
    goto put;
   }
  }
  for (i = 1; i <= 4; i++) {
   pointer = values[i];
   if (pointer != table_address && pointer != table_address + 72 &&
       pointer != node + (i <= 2 ? 228 : 236)) {
    error = -EINVAL;
    goto put;
   }
  }
  /* The already released table must encode precisely these two lists.
   * This rejects duplicates, cycles and node pointers not backed by bins.
   */
  for (i = 0; i < 2; i++) {
   unsigned int n, bin;
   const u8 *flow;
   sentinel = node + (i ? 236 : 228);
   pointer = values[i ? 3 : 1];
   previous = sentinel;
   for (n = 0; n < values[i ? 6 : 5]; n++) {
    if (pointer != table_address && pointer != table_address + 72) {
     error = -EINVAL; goto put;
    }
    bin = pointer == table_address ? 0 : 1;
    flow = view->table + bin * 72;
    if ((seen & BIT(bin)) || get_unaligned_le32(flow + 4) != previous ||
        !!flow[68] != !i) {
     error = -EINVAL; goto put;
    }
    seen |= BIT(bin);
    previous = pointer;
    pointer = get_unaligned_le32(flow);
   }
   if (pointer != sentinel || previous != values[i ? 4 : 2]) {
    error = -EINVAL; goto put;
   }
  }
  if (seen != expected_active) { error = -EINVAL; goto put; }
  for (i = 0; i < 8; i++)
   writel(values[i], core->image + node - core->image_phys + offsets[i]);
 } else {
  source = get_unaligned_le32(view->carrier[index] + 36);
  if ((source & 31) || source < core->image_phys ||
      source + 96 > core->image_phys + core->image_size) {
   error = -ERANGE;
   goto put;
  }
  writel(lower_32_bits(age), core->image + source - core->image_phys + 72);
  writel(upper_32_bits(age), core->image + source - core->image_phys + 76);
 }
 wmb();
 error = 0;
put:
 qdx_diag_fq_table_put(region);
leave:
 qdx_io_leave(endpoint->service->qdx);
 return error;
}

/* Fixed two-bin diagnostic data operation. No address, length, instruction
 * or arbitrary mask is accepted. Caller keeps its physical subtree detached.
 */
int qdx_diag_fq_staging_mask(struct qdx_packet_op *operation, struct qdx_dma *region,
 const struct qdx_diag_fq_view *view, bool staging, const struct qdx_owner *owner)
{
 struct qdx_endpoint *endpoint = operation->endpoint;
 struct qdx_core *core = endpoint->core;
 dma_addr_t table_address;
 u32 node, source, begin, end;
 unsigned int length, total, i;
 u16 expected = staging ? 1 : 0, replacement = staging ? 0 : 1;
 int error;

 if (!READ_ONCE(diag_mirror_table) || !view || !view->physical_staging ||
     !owner || !owner->module || strcmp(module_name(owner->module), "qdx_physical_fq_diag") ||
     operation->category != QDX_RECEIVE_PACKET || operation->class_tag != 0x4d54424c ||
     endpoint->service->kind != QDX_SERVICE_MIRROR || endpoint->dynamic_type != 65 ||
     !qdx_packet_op_drained(operation) || !view->node_valid ||
     get_unaligned_le16(view->node + 264) != 2 ||
     get_unaligned_le16(view->node + 266) != expected) return -EPERM;
 if (!qdx_io_enter(endpoint->service->qdx)) return -ESHUTDOWN;
 error = qdx_diag_fq_table_get(endpoint->service, region, owner, &table_address);
 if (error) goto leave;
 if (!qdx_diag_fq_table_physical(region) ||
     !qdx_diag_fq_table_matches(region, view->table)) { error = -ESTALE; goto put; }
 total = get_unaligned_le32(view->table + 24) + get_unaligned_le32(view->table + 96);
 if (!total || total > 16) { error = -ERANGE; goto put; }
 node = qdx_diag_fq_table_node(region, 0);
 for (i = 0; i < total; i++) {
  error = qdx_diag_fq_source(endpoint, NULL, view, QDX_DIAG_FQ_PAYLOAD,
   i, table_address, node, true, &source, &length);
  if (error) goto put;
 }
 if (node < core->image_phys || node + 280 > core->image_phys + core->image_size) { error = -ERANGE; goto put; }
 begin = (node + 266) & ~31U;
 end = (node + 267) | 31U;
 if (begin < node || end >= node + 280) { error = -EXDEV; goto put; }
 if (readw(core->image + node - core->image_phys + 264) != 2 ||
     readw(core->image + node - core->image_phys + 266) != expected) {
  error = -ESTALE; goto put;
 }
 writew(replacement, core->image + node - core->image_phys + 266);
 wmb();
 error = 0;
put:
 qdx_diag_fq_table_put(region);
leave:
 qdx_io_leave(endpoint->service->qdx);
 return error;
}
EXPORT_SYMBOL_GPL(qdx_diag_fq_staging_mask);

int qdx_diag_fq_age_import(struct qdx_packet_op *operation, struct qdx_dma *region,
 struct qdx_packet_op *loans, const struct qdx_diag_fq_view *view,
 unsigned int index, u64 age, const struct qdx_owner *owner)
{
 return qdx_diag_fq_import(operation, region, loans, view, index, age, NULL, owner);
}
EXPORT_SYMBOL_GPL(qdx_diag_fq_age_import);

int qdx_diag_fq_node_import(struct qdx_packet_op *operation, struct qdx_dma *region,
 struct qdx_packet_op *loans, const struct qdx_diag_fq_view *view,
 const u32 values[8], const struct qdx_owner *owner)
{
 if (!values)
  return -EINVAL;
 return qdx_diag_fq_import(operation, region, loans, view, 0, 0, values, owner);
}
EXPORT_SYMBOL_GPL(qdx_diag_fq_node_import);

/* Exact known DDR data, through the actual reserved-image mapping. This
 * performs six read-only32-bit loads; it is NOT an atomic six-word snapshot,
 * an inferred local-I/O alias, an ARM cache flush or a timestamp conversion.
 */
int qdx_diag_fq_clock_host(struct qdx_packet_op *operation, struct qdx_dma *region,
 struct qdx_packet_op *loans, const struct qdx_diag_fq_view *view,
 const struct qdx_owner *owner, u32 words[6])
{
 struct qdx_endpoint *endpoint = operation->endpoint;
 struct qdx_core *core = endpoint->core;
 dma_addr_t table_address;
 u32 source;
 unsigned int length, i;
 int error;

 if (!READ_ONCE(diag_mirror_table) || !view || !owner || !owner->module || !words ||
     (strcmp(module_name(owner->module), "qdx_mirror_state_diag") &&
      strcmp(module_name(owner->module), "qdx_physical_fq_diag")) ||
     operation->category != QDX_RECEIVE_PACKET || operation->class_tag != 0x4d54424c ||
     endpoint->service->kind != QDX_SERVICE_MIRROR || endpoint->dynamic_type != 65 ||
     !qdx_packet_op_drained(operation))
  return -EPERM;
 if (!qdx_io_enter(endpoint->service->qdx))
  return -ESHUTDOWN;
 error = qdx_diag_fq_table_get(endpoint->service, region, owner, &table_address);
 if (error)
  goto leave;
 if ((view->bf && qdx_diag_fq_table_physical(region)) ||
     (!strcmp(module_name(owner->module), "qdx_physical_fq_diag") &&
      (!qdx_diag_fq_table_physical(region) || view->wrr))) {
  error = -EPERM;
  goto put;
 }
 if (!qdx_diag_fq_table_matches(region, view->table)) {
  error = -ESTALE;
  goto put;
 }
 error = qdx_diag_fq_source(endpoint, loans, view, QDX_DIAG_FQ_CLOCK,
  0, table_address, qdx_diag_fq_table_node(region, 0),
  qdx_diag_fq_table_physical(region), &source, &length);
 if (error)
  goto put;
 if (!core->image || source < core->image_phys ||
     source + length > core->image_phys + core->image_size) {
  error = -ERANGE;
  goto put;
 }
 for (i = 0; i < 6; i++)
  words[i] = readl(core->image + source - core->image_phys + i * 4);
put:
 qdx_diag_fq_table_put(region);
leave:
 qdx_io_leave(endpoint->service->qdx);
 return error;
}
EXPORT_SYMBOL_GPL(qdx_diag_fq_clock_host);

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

	if (READ_ONCE(diag_io_cost_count))
		atomic64_inc(&diag_supply_runs);

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
			qdx_carrier_put(core, record, true, true);
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
			qdx_carrier_put(core, record, true, true);
			err = -ENOMEM;
			break;
		}
		actual = paged ? PAGE_SIZE : record->skb->truesize;
		if (actual > cost && !qdx_rx_reserve(core->qdx, 0, actual - cost)) {
			qdx_carrier_put(core, record, true, true);
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
			qdx_carrier_put(core, record, true, true);
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
	if (record->diag_region || record->diag_clock)
		return desc->type == QDX_N2H_PACKET &&
		       le32_to_cpu(desc->buffer) == record->dma &&
		       le16_to_cpu(desc->buffer_len) == record->length && offset == 0 &&
		       length == record->length &&
		       (le32_to_cpu(desc->interface) & GENMASK(23, 0)) ==
				record->operation->endpoint->ifnum &&
		       (le16_to_cpu(desc->flags) & (QDX_DESC_FIRST | QDX_DESC_LAST)) ==
				(QDX_DESC_FIRST | QDX_DESC_LAST);
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

	if (record->diag_clock) {
		struct qdx_diag_clock_sample *clock = record->diag_clock;
		struct qdx_core *core = record->operation->endpoint->core;
		unsigned int i;

		clock->returned_ns = ktime_get_ns();
		clock->type = desc ? desc->type : U32_MAX;
		clock->ifnum = desc ? le32_to_cpu(desc->interface) & GENMASK(23, 0) : U32_MAX;
		clock->error = desc ? 0 : -ESHUTDOWN;
		if (desc) {
			clock->read_begin_ns = ktime_get_ns();
			for (i = 0; i < ARRAY_SIZE(clock->words); i++)
				clock->words[i] = readl(core->image + 0x301a58 + 4 * i);
			clock->read_end_ns = ktime_get_ns();
		}
		/* No skb owns this fixed firmware allocation. The actual carrier
		 * release completes clock->done after all loan bookkeeping ends.
		 */
		return;
	}
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
		if (record->diag_region) {
			/* Metadata completion only: this coherent table is not skb storage. */
			record->recipient.returned(record->recipient.owner.object, NULL, NULL,
					   &metadata, ctx ? &ctx->napi : NULL);
			return;
		}
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
		       struct qdx_tx_batch *batch,
		       unsigned int *progress, unsigned int *returned_kinds)
{
	struct qdx_core *arrival = ctx->core, *owner = NULL;
	struct qdx_carrier *record;
	struct sk_buff *skb = NULL;
	unsigned long memory_charge = 0;
	u32 interface = le32_to_cpu(desc->interface);
	unsigned int target = interface >> 24;
	void *payload;
	bool fresh = false;
	enum qdx_carrier_kind kind;

	record = qdx_return_claim(arrival, desc, &owner);
	if (!record || !qdx_return_valid(record, desc)) {
		if (record)
			WRITE_ONCE(record->state, QDX_QUARANTINED);
		atomic64_inc(&arrival->io->faults);
		qdx_fail(arrival->qdx, -EPROTO);
		return;
	}
	kind = record->kind;
	if (READ_ONCE(diag_io_cost_count))
		atomic64_inc(&diag_return_items);
	if (record->mapped) {
		if (record->kind == QDX_PAGED)
			dma_unmap_page(record->dev, record->dma, record->length, record->direction);
		else
			dma_unmap_single(record->dev, record->dma, record->length, record->direction);
		record->mapped = false;
	}
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
	qdx_carrier_put(owner, record, true, !progress);
	if (progress) {
		if (kind == QDX_TRANSMIT)
			progress[owner->id] |= QDX_RESOURCE_CARRIER | QDX_RESOURCE_HOST_BYTES;
		returned_kinds[owner->id] |= BIT(kind);
	}
	atomic64_inc(&owner->io->returned);
	if (fresh)
		qdx_packet_assemble(ctx, skb, desc, memory_charge);
	if (!progress && !READ_ONCE(owner->io->closed)) {
		if (READ_ONCE(diag_io_cost_count))
			atomic64_add(2, &diag_supply_schedule);
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
	unsigned int progress[QDX_CORES] = {}, returned_kinds[QDX_CORES] = {};
	bool tail_events = READ_ONCE(diag_return_tail);
	u32 producer, consumer;
	unsigned long flags;
	int ring, done = 0;
	unsigned int c, k;

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
		qdx_return(ctx, &desc, &batch,
			tail_events ? progress : NULL,
			tail_events ? returned_kinds : NULL);
		if (ctx->draining && ctx->drain_remaining)
			ctx->drain_remaining--;
		consumer = (consumer + 1) & (QDX_RING_DEPTH - 1);
		done++;
	}
	qdx_tx_batch_complete(&batch);
	dma_wmb();
	WRITE_ONCE(core->map->n2h_host[ring], cpu_to_le32(consumer));
	if (tail_events) {
		if (READ_ONCE(diag_io_cost_count))
			atomic64_inc(&diag_tail_polls);
		for (c = 0; c < QDX_CORES; c++) {
			struct qdx_core *owner = &core->qdx->cores[c];
			struct qdx_io *owned = owner->io;

			if (progress[c])
				qdx_resource_progress(owner, progress[c]);
			if (!returned_kinds[c] || !owned || READ_ONCE(owned->closed))
				continue;
			for (k = 0; k < 2; k++) {
				struct qdx_supply *supply = &owned->supply[k];

				if (READ_ONCE(owned->outstanding[supply->kind]) >=
				    READ_ONCE(supply->target) && !atomic_read(&supply->demand))
					continue;
				if (READ_ONCE(diag_io_cost_count))
					atomic64_inc(&diag_supply_schedule);
				mod_delayed_work(system_wq, &supply->work, 0);
			}
		}
	}
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
			qdx_carrier_put(core, record, true, true);
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
