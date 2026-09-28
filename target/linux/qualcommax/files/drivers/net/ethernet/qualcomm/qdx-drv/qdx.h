/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _QDX_H
#define _QDX_H

#include <linux/atomic.h>
#include <linux/completion.h>
#include <linux/dma-mapping.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/notifier.h>
#include <linux/platform_device.h>
#include <linux/qdx.h>
#include <linux/refcount.h>
#include <linux/sizes.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/xarray.h>

#include "abi.h"

#define QDX_PHYSICAL_PORTS 8
#define QDX_REQUESTS 64
#define QDX_SLOTS 65536U

struct qdx;
struct qdx_hw;
struct qdx_mem;
struct qdx_io;
struct qdx_commands;

enum qdx_state {
	QDX_WAITING, QDX_STARTING, QDX_READY, QDX_STOPPING, QDX_TERMINAL,
};

bool qdx_owner_get(const struct qdx_owner *owner);
void qdx_owner_put(const struct qdx_owner *owner);

/* Shared drv storage; to be inserted into the existing private qdx.h. */
#define QDX_RX_CATEGORIES 32
#define QDX_IF_DYNAMIC 176
#define QDX_IF_FREQUENCY 175
#define QDX_DYNAMIC_FIRST 28
#define QDX_DYNAMIC_END 156

struct qdx_service {
	struct qdx *qdx;
	enum qdx_service_kind kind;
	u32 ifnum;
	u8 core;
};

enum qdx_endpoint_state {
	QDX_ENDPOINT_ALLOCATING, QDX_ENDPOINT_OWNED,
	QDX_ENDPOINT_RETIRING, QDX_ENDPOINT_RETIRED,
};

struct qdx_endpoint {
	struct qdx_core *core;
	struct qdx_service *service;
	struct qdx_port *port;
	refcount_t refs;
	struct mutex cfg;
	spinlock_t lock;
	struct completion ready;
	wait_queue_head_t drained;
	struct work_struct work;
	struct qdx_request *request;
	struct qdx_result result;
	struct qdx_receiver __rcu *receivers[QDX_RX_CATEGORIES];
	atomic_t operations;
	u32 ifnum;
	u32 dynamic_type;
	u32 returned_type;
	u32 returned_ifnum;
	enum qdx_endpoint_state state;
	bool desired;
	bool indexed;
	bool result_pending;
	bool deallocation;
	bool producers_open;
	bool dispatch_open;
};

struct qdx_receiver {
	struct qdx_endpoint *endpoint;
	struct qdx_owner owner;
	const struct qdx_receive_ops *ops;
	refcount_t refs;
	wait_queue_head_t drained;
	u8 category;
	bool accepting;
};

void qdx_service_hold(struct qdx_service *service);
void qdx_services_init(struct qdx *qdx);
void qdx_services_notify(struct qdx *qdx);
void qdx_services_drain(struct qdx *qdx);
struct qdx *qdx_ethernet_instance_get(struct net_device *dev);
void qdx_ethernet_instance_put(struct qdx *qdx);
bool qdx_endpoint_command_ready(struct qdx_endpoint *endpoint);
struct qdx_endpoint *qdx_endpoint_static(struct qdx_service *service,
					unsigned int core, u32 ifnum);
void qdx_endpoint_message(struct qdx_core *core, u32 ifnum, u32 opcode,
		u32 response, u32 error, const void *payload, size_t received, size_t declared);
void qdx_endpoint_packet(struct qdx_core *core, struct sk_buff *skb,
			const struct qdx_rx_meta *metadata, struct napi_struct *napi);
void qdx_endpoints_close(struct qdx *qdx);
void qdx_endpoints_access_end(struct qdx *qdx);
int qdx_io_receive_drain(struct qdx *qdx);
int qdx_command_publish(struct qdx_core *core, u64 id);
void qdx_commands_access_end(struct qdx_core *core);
int qdx_message_core(struct qdx_core *core, u32 ifnum, u32 opcode,
		     const void *payload, size_t length);

struct qdx_reply {
	enum qdx_outcome outcome;
	void *data;
	u16 min_len;
	u16 max_len;
	u16 len;
	u32 firmware_error;
};

struct qdx_core {
	struct qdx *qdx;
	unsigned int id;
	struct qdx_mem *mem;
	struct qdx_io *io;
	struct qdx_commands *commands;
	struct xarray endpoints;
	struct completion frequency_done;
	u32 frequency_step;
	int frequency_error;
	struct qdx_receiver *frequency_receiver;
	bool frequency_ready;
	void __iomem *csm;
	phys_addr_t csm_phys;
	void __iomem *imem;
	phys_addr_t imem_phys;
	size_t imem_size;
	void __iomem *image;
	phys_addr_t image_phys;
	size_t image_size;
	struct qdx_ifmap *map;
	struct qdx_h2n_desc *h2n_desc[QDX_H2N_RINGS];
	struct qdx_n2h_desc *n2h_desc[QDX_N2H_RINGS];
	dma_addr_t c2c_dma;
	bool boot_signaled;
	bool map_ready;
	bool common_ready;
	bool peer_ready;
};

struct qdx_vsi {
	struct work_struct release_work;
	struct qdx_endpoint *physical;
	struct qdx_port *port;
	struct qdx_ppe *ppe;
	struct module *native_owner;
	u32 wire;
};

struct qdx_rx_use {
	struct qdx_endpoint *endpoint;
	struct qdx_port *port;
	struct qdx_ppe *ppe;
	struct qdx_ppe_rx *scope;
};

struct qdx_tx_path {
	struct work_struct release_work;
	struct qdx_endpoint *endpoint;
	struct qdx_port *port;
	refcount_t refs;
	struct qdx_tx_class class;
	struct qdx_ppe *ppe;
	struct qdx_ppe_tx *scope;
	enum qdx_disposition disposition;
	u16 queue;
	bool open;
	unsigned int accepted; /* io_admission: published packet completions. */
};

struct qdx_packet_op {
	struct qdx_endpoint *endpoint;
	refcount_t refs;
	u32 class_tag;
	u8 category;
	bool open;
	unsigned int accepted; /* io_admission: published packet completions. */
};

void qdx_tx_path_get(struct qdx_tx_path *path);
void qdx_tx_path_put(struct qdx_tx_path *path);
void qdx_io_tx_close(struct qdx_tx_path *path);
void qdx_resource_progress(struct qdx_core *core, unsigned int resources);

struct qdx_edma {
	struct qdx_edma_info info;
	struct qdx *qdx;
	bool detaching;
};

struct qdx_ppe {
	struct qdx_ppe_info info;
	struct qdx *qdx;
	bool detaching;
};

struct qdx_port {
	struct qdx *qdx;
	struct net_device *netdev;
	struct net_device *conduit;
	struct mutex lock;
	refcount_t refs;
	wait_queue_head_t drained;
	u32 ifnum;
	bool registered;
	bool available;
	bool configured;
	bool opened;
	bool changing;
	u32 link_state;
	struct qdx_port_state confirmed;
};

struct qdx_ethernet {
	struct qdx_edma *edma;
	struct qdx_ppe *ppe;
	struct qdx_port ports[QDX_PHYSICAL_PORTS];
	bool prepared;
	bool native_touched;
	bool native_restored;
	struct notifier_block netdev_notifier;
	struct work_struct mac_work;
};

struct qdx_limits {
	u32 native_rx_entries;
	u32 tx_slots;
	unsigned long rx_dma_bytes;
	unsigned long rx_memory_bytes;
	unsigned long host_data_bytes;
	unsigned long peer_dma_bytes;
};

struct qdx {
	struct device *dev;
	struct platform_device *pdev;
	struct qdx_hw *hw;
	struct qdx_service services[QDX_SERVICE_COUNT];
	atomic_t service_users;
	wait_queue_head_t services_drained;
	struct mutex receive_drain;
	spinlock_t io_admission;
	atomic_t io_callers;
	wait_queue_head_t io_drained;
	bool io_closing;
	spinlock_t resource_lock;
	struct list_head resource_waits;
	u64 last_resource_wait;
	struct mutex region_lock;
	struct list_head regions;
	atomic_long_t host_data_used;
	atomic_long_t peer_dma_used;
	struct qdx_core cores[QDX_CORES];
	struct qdx_ethernet *ethernet;
	enum qdx_state state;
	atomic_t failure;
	struct workqueue_struct *cleanup_queue;
	struct work_struct lifecycle;
	struct completion terminal_done;
	struct qdx_limits limits;
	atomic_long_t rx_dma_used;
	atomic_long_t rx_memory_charged;
	bool execution_possible;
	bool access_ended;
};

void qdx_fail(struct qdx *qdx, int error);
void qdx_schedule(struct qdx *qdx);
int qdx_hw_get(struct qdx *qdx);
int qdx_hw_prepare(struct qdx *qdx);
int qdx_hw_start_core(struct qdx_core *core);
int qdx_hw_stop(struct qdx *qdx);
int qdx_hw_notify(struct qdx_core *core, unsigned int channel);
void qdx_hw_unprepare(struct qdx *qdx);
int qdx_mem_prepare(struct qdx *qdx);
int qdx_mem_validate_map(struct qdx_core *core);
void qdx_mem_release(struct qdx *qdx, bool access_ended);
void qdx_dma_end_all(struct qdx *qdx);

int qdx_io_init(struct qdx_core *core);
void qdx_io_enable(struct qdx_core *core);
void qdx_io_close(struct qdx_core *core);
void qdx_io_stop(struct qdx_core *core);
void qdx_io_release(struct qdx_core *core, bool access_ended);
int qdx_io_bootstrap(struct qdx_core *core);
int qdx_io_set_pool(struct qdx_core *core, bool paged, u32 pool, u32 low, u32 high);
int qdx_io_check_mtu(struct qdx *qdx, unsigned int mtu);
int qdx_io_set_mtu(struct qdx *qdx, unsigned int mtu);
void qdx_io_port_close(struct qdx_port *port);
int qdx_io_command(struct qdx_core *core, void *buffer, size_t length, u64 id);

int qdx_commands_init(struct qdx_core *core);
void qdx_commands_stop(struct qdx_core *core);
void qdx_commands_release(struct qdx_core *core);
int qdx_command(struct qdx_core *core, u32 ifnum, u32 opcode,
		const void *body, size_t length, struct qdx_reply *reply);
void qdx_command_receive(struct qdx_core *core, u32 ifnum,
			 const void *buffer, size_t length);
void qdx_command_return(struct qdx_core *core, u64 id, u32 response);

int qdx_ethernet_register(struct qdx *qdx);
void qdx_ethernet_unregister(struct qdx *qdx);
bool qdx_ethernet_ready(struct qdx *qdx);
int qdx_ethernet_prepare(struct qdx *qdx);
int qdx_ethernet_start(struct qdx *qdx);
void qdx_ethernet_unlock(struct qdx *qdx);
void qdx_ethernet_stop(struct qdx *qdx);
int qdx_ethernet_restore(struct qdx *qdx);
int qdx_ethernet_activate(struct qdx *qdx);
void qdx_ethernet_receive(struct qdx *qdx, unsigned int core, u32 ifnum,
			  struct sk_buff *skb, struct napi_struct *napi);
void qdx_ethernet_progress(struct qdx *qdx);
void qdx_port_publish(struct qdx_port *port);
void qdx_port_withdraw(struct qdx_port *port);
struct qdx_port *qdx_port_get(struct qdx *qdx, unsigned int core, u32 ifnum);
void qdx_port_put(struct qdx_port *port);
void qdx_interfaces_init(struct qdx *qdx);
int qdx_interfaces_register(struct qdx *qdx);
void qdx_interfaces_unregister(struct qdx *qdx);

#endif
