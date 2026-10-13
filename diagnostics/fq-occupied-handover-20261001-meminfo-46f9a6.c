// SPDX-License-Identifier: GPL-2.0-only
/* Validate local firmware and own all persistent firmware-visible memory. */
#include <crypto/sha2.h>
#include <linux/dma-mapping.h>
#include <linux/firmware.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#include <linux/sizes.h>
#include <linux/unaligned.h>
#include <linux/vmalloc.h>

#include "qdx.h"

#define QDX_MEM_RECORDS	62

enum qdx_memory_type {
	QDX_MEMORY_IMEM,
	QDX_MEMORY_SDRAM,
	QDX_MEMORY_UTCM,
	QDX_MEMORY_INFO,
};

struct qdx_allocation {
	void *base;
	dma_addr_t base_dma;
	size_t allocation_size;
	void *cpu;
	dma_addr_t dma;
	size_t size;
	u16 type;
	char name[48];
};

struct qdx_mem {
	struct qdx_allocation allocation[QDX_MEM_RECORDS];
	unsigned int count;
	size_t imem_used;
	dma_addr_t h2n_dma;
	dma_addr_t n2h_dma;
};

static const struct {
	const char *name;
	size_t size;
	u8 sha256[SHA256_DIGEST_SIZE];
	unsigned int requests;
} qdx_images[QDX_CORES] = {
	{
		.name = "qdx/11.4/retail_router0.bin",
		.size = 835960,
		.sha256 = { 0x1c, 0x3b, 0xad, 0xac, 0x46, 0x94, 0x55, 0x4a,
			    0x89, 0xf5, 0x56, 0xd7, 0xa9, 0xc2, 0x23, 0x10,
			    0xcb, 0x8c, 0xab, 0x8e, 0x9d, 0x26, 0x3a, 0x12,
			    0xe9, 0x9e, 0x19, 0xed, 0x73, 0x4e, 0x26, 0xcd },
		.requests = 25,
	}, {
		.name = "qdx/11.4/retail_router1.bin",
		.size = 292296,
		.sha256 = { 0x67, 0xab, 0x46, 0xb2, 0x9b, 0x62, 0x44, 0x1e,
			    0x8d, 0xe8, 0xbe, 0x89, 0x13, 0x7d, 0xba, 0x32,
			    0x3a, 0xb4, 0xe9, 0xc4, 0xf1, 0x52, 0xf8, 0x75,
			    0x05, 0x5b, 0x82, 0x2a, 0x81, 0x34, 0x8c, 0x6a },
		.requests = 15,
	}
};

/* Each allocation records the real allocator base, even after alignment. */
static int qdx_mem_allocate(struct qdx_core *core, u16 type, const char *name,
			    size_t size, size_t alignment, struct qdx_allocation **result)
{
	struct qdx_mem *mem = core->mem;
	struct qdx_allocation *allocation;
	size_t total, offset;
	u64 address, end;
	unsigned int i;

	if (!size || size > SZ_8M || !is_power_of_2(alignment) ||
	    alignment > SZ_1M || mem->count >= QDX_MEM_RECORDS)
		return -EINVAL;
	for (i = 0; i < mem->count; i++)
		if (!strcmp(mem->allocation[i].name, name))
			return -EINVAL;
	allocation = &mem->allocation[mem->count];
	allocation->type = type;
	allocation->size = size;
	strscpy(allocation->name, name, sizeof(allocation->name));

	switch (type) {
	case QDX_MEMORY_IMEM:
		address = ALIGN((u64)core->imem_phys + mem->imem_used, alignment);
		if (check_add_overflow(address, (u64)size, &end) ||
		    end > (u64)core->imem_phys + core->imem_size || end > BIT_ULL(32))
			return -ENOSPC;
		offset = address - core->imem_phys;
		allocation->dma = address;
		memset_io(core->imem + offset, 0, size);
		mem->imem_used = offset + size;
		break;
	case QDX_MEMORY_SDRAM:
		if (check_add_overflow(size, alignment - 1, &total))
			return -EOVERFLOW;
		allocation->base = dma_alloc_coherent(core->qdx->dev, total,
						      &allocation->base_dma, GFP_KERNEL);
		if (!allocation->base)
			return -ENOMEM;
		allocation->allocation_size = total;
		address = ALIGN((u64)allocation->base_dma, alignment);
		offset = address - allocation->base_dma;
		if ((u64)allocation->base_dma + total > BIT_ULL(32) ||
		    address + size > BIT_ULL(32)) {
			dma_free_coherent(core->qdx->dev, total, allocation->base,
					  allocation->base_dma);
			memset(allocation, 0, sizeof(*allocation));
			return -ERANGE;
		}
		allocation->cpu = allocation->base + offset;
		allocation->dma = address;
		memset(allocation->cpu, 0, size);
		break;
	default:
		/* The selected IPQ807x images have no UTCM request. */
		return -EOPNOTSUPP;
	}
	mem->count++;
	*result = allocation;
	return 0;
}

static int qdx_mem_image(struct qdx_core *core, const struct firmware *firmware)
{
	struct qdx_allocation *allocation;
	struct qdx_mem_request request;
	struct qdx_mem *mem;
	u8 *image;
	u32 linked_map;
	size_t map_offset, map_limit, offset;
	unsigned int count = 0, special = 0, i;
	int err = -EINVAL;
	u16 type;

	image = kvmalloc(firmware->size, GFP_KERNEL);
	if (!image)
		return -ENOMEM;
	memcpy(image, firmware->data, firmware->size);
	if (get_unaligned_le16(image + 8) != QDX_MEM_RESERVE_MAGIC)
		goto out;
	linked_map = get_unaligned_le32(image + 12);
	if (linked_map < core->image_phys)
		goto out;
	map_offset = linked_map - core->image_phys;
	if (!IS_ALIGNED(map_offset, sizeof(u32)) ||
	    map_offset > firmware->size - QDX_MEM_MAP_SIZE ||
	    get_unaligned_le16(image + map_offset) != QDX_MEM_MAP_MAGIC)
		goto out;
	map_limit = map_offset + QDX_MEM_MAP_SIZE;
	mem = kzalloc(sizeof(*mem), GFP_KERNEL);
	if (!mem) {
		err = -ENOMEM;
		goto out;
	}
	core->mem = mem;
	offset = map_offset + sizeof(u32);
	while (offset + sizeof(u16) <= map_limit &&
	       get_unaligned_le16(image + offset) == QDX_MEM_REQUEST_MAGIC) {
		if (sizeof(request) > map_limit - offset || count >= QDX_MEM_RECORDS - 2) {
			err = -EINVAL;
			goto out;
		}
		memcpy(&request, image + offset, sizeof(request));
		if (!memchr(request.name, '\0', sizeof(request.name)) || !request.name[0]) {
			err = -EINVAL;
			goto out;
		}
		for (i = 0; request.name[i]; i++) {
			if ((u8)request.name[i] < 0x21 || (u8)request.name[i] > 0x7e) {
				err = -EINVAL;
				goto out;
			}
		}
		type = le16_to_cpu(request.type);
		if (type == QDX_MEMORY_INFO) {
			if (strcmp(request.name, "heap_ddr_size")) {
				err = -EOPNOTSUPP;
				goto out;
			}
			/* INFO describes the whole linked image/heap window, not an allocation. */
			request.size = cpu_to_le32(core->image_size);
			request.address = cpu_to_le32(core->image_phys);
		} else {
			err = qdx_mem_allocate(core, type, request.name,
					       le32_to_cpu(request.size),
					       le32_to_cpu(request.alignment), &allocation);
			if (err)
				goto out;
			request.address = cpu_to_le32(allocation->dma);
			if (!strcmp(request.name, "nss_if_mem_map_inst")) {
				if (type != QDX_MEMORY_SDRAM || allocation->size != sizeof(*core->map)) {
					err = -EINVAL;
					goto out;
				}
				core->map = allocation->cpu;
				special |= BIT(0);
			} else if (!strcmp(request.name, "c2c_descs_if_mem_map")) {
				if (type != QDX_MEMORY_IMEM || allocation->size != 8256) {
					err = -EINVAL;
					goto out;
				}
				core->c2c_dma = allocation->dma;
				special |= BIT(1);
			} else if (!strcmp(request.name, "debug_boot_log_desc")) {
				if (type != QDX_MEMORY_SDRAM || allocation->size != 5152) {
					err = -EINVAL;
					goto out;
				}
				/* Firmware initializes its log header in this zeroed allocation. */
				special |= BIT(2);
			} else if (!strcmp(request.name, "profile_dma_ctrl")) {
				if (type != QDX_MEMORY_SDRAM || allocation->size != 256) {
					err = -EINVAL;
					goto out;
				}
				/* No host profile ring or callback is registered in Phase 1. */
				special |= BIT(3);
			}
		}
		request.selected_type = request.type;
		memcpy(image + offset, &request, sizeof(request));
		offset += sizeof(request);
		count++;
	}
	if (offset + sizeof(u16) > map_limit ||
	    get_unaligned_le16(image + offset) != QDX_MEM_END_MAGIC ||
	    count != qdx_images[core->id].requests || special != GENMASK(3, 0)) {
		err = -EINVAL;
		goto out;
	}

	err = qdx_mem_allocate(core, QDX_MEMORY_SDRAM, "h2n_rings",
			       QDX_H2N_RINGS * QDX_RING_STRIDE, 128, &allocation);
	if (err)
		goto out;
	mem->h2n_dma = allocation->dma;
	for (i = 0; i < QDX_H2N_RINGS; i++) {
		core->h2n_desc[i] = allocation->cpu + i * QDX_RING_STRIDE;
		core->map->h2n[i].address = cpu_to_le32(allocation->dma + i * QDX_RING_STRIDE);
		core->map->h2n[i].size = cpu_to_le16(QDX_RING_DEPTH);
	}
	err = qdx_mem_allocate(core, QDX_MEMORY_SDRAM, "n2h_rings",
			       QDX_N2H_RINGS * QDX_RING_STRIDE, 128, &allocation);
	if (err)
		goto out;
	mem->n2h_dma = allocation->dma;
	for (i = 0; i < QDX_N2H_RINGS; i++) {
		core->n2h_desc[i] = allocation->cpu + i * QDX_RING_STRIDE;
		core->map->n2h[i].address = cpu_to_le32(allocation->dma + i * QDX_RING_STRIDE);
		core->map->n2h[i].size = cpu_to_le16(QDX_RING_DEPTH);
	}
	core->map->h2n_count = QDX_H2N_RINGS;
	core->map->n2h_count = QDX_N2H_RINGS;
	/* Magic/version stay zero until firmware publishes its initialized map. */
	memset_io(core->image, 0, core->image_size);
	memcpy_toio(core->image, image, firmware->size);
	dma_wmb();
	wmb();
	readl(core->image);
	dev_info(core->qdx->dev, "core %u: loaded local 11.4 image, %u requests, %zu IMEM bytes\n",
		 core->id, count, mem->imem_used);
out:
	kvfree(image);
	return err;
}

int qdx_mem_prepare(struct qdx *qdx)
{
	const struct firmware *firmware[QDX_CORES] = {};
	u8 digest[SHA256_DIGEST_SIZE];
	int i, err;

	/* Verify both originals before preparing either core for execution. */
	for (i = 0; i < QDX_CORES; i++) {
		err = request_firmware_direct(&firmware[i], qdx_images[i].name, qdx->dev);
		if (err)
			goto out;
		if (firmware[i]->size != qdx_images[i].size ||
		    firmware[i]->size > qdx->cores[i].image_size) {
			err = -EINVAL;
			goto out;
		}
		sha256(firmware[i]->data, firmware[i]->size, digest);
		if (memcmp(digest, qdx_images[i].sha256, sizeof(digest))) {
			err = -EBADMSG;
			goto out;
		}
	}
	for (i = 0; i < QDX_CORES; i++) {
		err = qdx_mem_image(&qdx->cores[i], firmware[i]);
		if (err)
			goto out;
	}
out:
	for (i = 0; i < QDX_CORES; i++)
		release_firmware(firmware[i]);
	if (err)
		qdx_mem_release(qdx, true); /* No core has been released by this operation. */
	return err;
}

int qdx_mem_validate_map(struct qdx_core *core)
{
	struct qdx_ifmap *map = core->map;
	struct qdx_mem *mem = core->mem;
	u32 magic;
	unsigned int i;

	if (!map || !mem)
		return -EINVAL;
	if (READ_ONCE(core->map_ready))
		return 0;
	magic = le32_to_cpu(READ_ONCE(map->magic));
	if (!magic)
		return -EAGAIN;
	dma_rmb();
	if (magic != QDX_MAP_MAGIC || le16_to_cpu(READ_ONCE(map->version)) != QDX_MAP_VERSION ||
	    READ_ONCE(map->h2n_count) != QDX_H2N_RINGS ||
	    READ_ONCE(map->n2h_count) != QDX_N2H_RINGS)
		return -EPROTO;
	for (i = 0; i < QDX_H2N_RINGS; i++) {
		if (le32_to_cpu(READ_ONCE(map->h2n[i].address)) != mem->h2n_dma + i * QDX_RING_STRIDE ||
		    le16_to_cpu(READ_ONCE(map->h2n[i].size)) != QDX_RING_DEPTH ||
		    le32_to_cpu(READ_ONCE(map->h2n_firmware[i])) >= QDX_RING_DEPTH ||
		    le32_to_cpu(READ_ONCE(map->h2n_host[i])) >= QDX_RING_DEPTH)
			return -EPROTO;
	}
	for (i = 0; i < QDX_N2H_RINGS; i++) {
		if (le32_to_cpu(READ_ONCE(map->n2h[i].address)) != mem->n2h_dma + i * QDX_RING_STRIDE ||
		    le16_to_cpu(READ_ONCE(map->n2h[i].size)) != QDX_RING_DEPTH ||
		    le32_to_cpu(READ_ONCE(map->n2h_firmware[i])) >= QDX_RING_DEPTH ||
		    le32_to_cpu(READ_ONCE(map->n2h_host[i])) >= QDX_RING_DEPTH)
			return -EPROTO;
	}
	smp_store_release(&core->map_ready, true);
	return 0;
}

void qdx_mem_release(struct qdx *qdx, bool access_ended)
{
	struct qdx_allocation *allocation;
	struct qdx_mem *mem;
	int i;

	/* These records remain reachable for terminal diagnostics and quarantine. */
	if (!access_ended)
		return;
	for (i = 0; i < QDX_CORES; i++) {
		struct qdx_core *core = &qdx->cores[i];

		mem = core->mem;
		if (!mem)
			continue;
		while (mem->count) {
			allocation = &mem->allocation[--mem->count];
			if (allocation->base)
				dma_free_coherent(qdx->dev, allocation->allocation_size,
						  allocation->base, allocation->base_dma);
		}
		core->mem = NULL;
		core->map = NULL;
		core->map_ready = false;
		core->c2c_dma = 0;
		memset(core->h2n_desc, 0, sizeof(core->h2n_desc));
		memset(core->n2h_desc, 0, sizeof(core->n2h_desc));
		kfree(mem);
	}
}

/* Feature regions are accounted separately from boot memory and RX supplies. */
struct qdx_dma {
	struct list_head node;
	struct qdx_service *service;
	void *base;
	void *cpu;
	dma_addr_t base_dma;
	dma_addr_t dma;
	size_t allocation;
	size_t length;
	enum dma_data_direction direction;
	bool exposed;
	bool release_pending;
};

static void qdx_dma_free(struct qdx_dma *region)
{
	struct qdx_service *service = region->service;

	dma_free_coherent(service->qdx->dev, region->allocation, region->base,
			  region->base_dma);
	atomic_long_sub(region->allocation, &service->qdx->peer_dma_used);
	kfree(region);
	qdx_service_put(service);
}

struct qdx_dma *qdx_dma_alloc(struct qdx_service *service, size_t length,
			     size_t alignment, enum dma_data_direction direction)
{
	struct qdx *qdx = service->qdx;
	struct qdx_dma *region;
	size_t allocation, offset, extra;
	long used;
	int error = -ENOMEM;

	if (!length || !is_power_of_2(alignment) || alignment > SZ_1M ||
	    direction == DMA_NONE)
		return ERR_PTR(-EINVAL);
	/* Coherent allocations are already page aligned; charge all real pages. */
	extra = alignment > PAGE_SIZE ? alignment - PAGE_SIZE : 0;
	if (check_add_overflow(length, extra, &allocation) ||
	    allocation > LONG_MAX - (PAGE_SIZE - 1))
		return ERR_PTR(-EOVERFLOW);
	allocation = PAGE_ALIGN(allocation);
	if (qdx_service_state(service) != QDX_AVAILABLE)
		return ERR_PTR(-EAGAIN);
	used = atomic_long_read(&qdx->peer_dma_used);
	do {
		if (used < 0 || used > qdx->limits.peer_dma_bytes ||
		    allocation > qdx->limits.peer_dma_bytes - used)
			return ERR_PTR(-ENOSPC);
	} while (!atomic_long_try_cmpxchg(&qdx->peer_dma_used, &used, used + allocation));
	region = kzalloc(sizeof(*region), GFP_KERNEL);
	if (!region)
		goto uncharge;
	region->base = dma_alloc_coherent(qdx->dev, allocation, &region->base_dma, GFP_KERNEL);
	if (!region->base)
		goto free_region;
	region->dma = ALIGN(region->base_dma, alignment);
	offset = region->dma - region->base_dma;
	if ((u64)region->base_dma + allocation > BIT_ULL(32) ||
	    (u64)region->dma + length > BIT_ULL(32)) {
		error = -ERANGE;
		goto free_dma;
	}
	region->cpu = region->base + offset;
	region->length = length;
	region->allocation = allocation;
	region->direction = direction;
	region->service = service;
	qdx_service_hold(service);
	mutex_lock(&qdx->region_lock);
	list_add_tail(&region->node, &qdx->regions);
	mutex_unlock(&qdx->region_lock);
	return region;
free_dma:
	dma_free_coherent(qdx->dev, allocation, region->base, region->base_dma);
free_region:
	kfree(region);
uncharge:
	atomic_long_sub(allocation, &qdx->peer_dma_used);
	return ERR_PTR(error);
}
EXPORT_SYMBOL_GPL(qdx_dma_alloc);

void *qdx_dma_cpu(struct qdx_dma *region)
{
	return region->cpu;
}
EXPORT_SYMBOL_GPL(qdx_dma_cpu);

dma_addr_t qdx_dma_address(const struct qdx_dma *region)
{
	return region->dma;
}
EXPORT_SYMBOL_GPL(qdx_dma_address);

void qdx_dma_expose(struct qdx_dma *region)
{
	WRITE_ONCE(region->exposed, true);
}
EXPORT_SYMBOL_GPL(qdx_dma_expose);

void qdx_dma_access_end(struct qdx_dma *region)
{
	WRITE_ONCE(region->exposed, false);
}
EXPORT_SYMBOL_GPL(qdx_dma_access_end);

void qdx_dma_release(struct qdx_dma *region)
{
	struct qdx *qdx;
	bool release;

	if (!region)
		return;
	qdx = region->service->qdx;
	mutex_lock(&qdx->region_lock);
	release = !READ_ONCE(region->exposed) || smp_load_acquire(&qdx->access_ended);
	if (release)
		list_del(&region->node);
	else
		region->release_pending = true;
	mutex_unlock(&qdx->region_lock);
	if (release)
		qdx_dma_free(region);
}
EXPORT_SYMBOL_GPL(qdx_dma_release);

void qdx_dma_end_all(struct qdx *qdx)
{
	struct qdx_dma *region, *next;
	LIST_HEAD(release);

	mutex_lock(&qdx->region_lock);
	list_for_each_entry_safe(region, next, &qdx->regions, node) {
		WRITE_ONCE(region->exposed, false);
		if (region->release_pending)
			list_move_tail(&region->node, &release);
	}
	mutex_unlock(&qdx->region_lock);
	list_for_each_entry_safe(region, next, &release, node) {
		list_del(&region->node);
		qdx_dma_free(region);
	}
}

MODULE_FIRMWARE("qdx/11.4/retail_router0.bin");
MODULE_FIRMWARE("qdx/11.4/retail_router1.bin");
