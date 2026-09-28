/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_QDX_H
#define _LINUX_QDX_H

#include <linux/err.h>
#include <linux/if_ether.h>
#include <linux/kconfig.h>
#include <linux/dma-direction.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/refcount.h>
#include <linux/wait.h>

struct qdx_service;
struct qdx_endpoint;
struct qdx_request;
struct qdx_receiver;
struct qdx_listener;
struct qdx_dma;
struct qdx_binding;
struct qdx_rx_use;
struct qdx_vsi;
struct qdx_tx_path;
struct qdx_packet_op;

/* Storage operations never take another owner's configuration lock. */
struct qdx_owner {
	struct module *module;
	void *object;
	bool (*get)(void *object);
	void (*put)(void *object);
};

enum qdx_service_kind {
	QDX_SERVICE_ETHERNET,
	QDX_SERVICE_IPV4,
	QDX_SERVICE_IPV6,
	QDX_SERVICE_PPPOE,
	QDX_SERVICE_VLAN,
	QDX_SERVICE_SHAPER,
	QDX_SERVICE_IGS,
	QDX_SERVICE_MATCH,
	QDX_SERVICE_MIRROR,
	QDX_SERVICE_COUNT,
};

enum qdx_availability { QDX_NOT_READY, QDX_AVAILABLE, QDX_FAILED };

struct qdx_service *qdx_service_get(struct net_device *dev,
				  enum qdx_service_kind kind);
void qdx_service_put(struct qdx_service *service);
bool qdx_service_access_ended(const struct qdx_service *service);
enum qdx_availability qdx_service_state(const struct qdx_service *service);
struct qdx_listener *qdx_service_listen(const struct qdx_owner *owner,
		void (*changed)(void *owner, enum qdx_service_kind kind,
				enum qdx_availability state));
void qdx_service_unlisten(struct qdx_listener *listener);
int qdx_stop_execution(struct qdx_service *service, int error);

/* Static identity is native; dynamic type is the checked 11.4 ABI value.
 * A pending allocation remains a held attempt; wait cannot recycle its identity.
 */
struct qdx_endpoint *qdx_endpoint_get(struct qdx_service *service,
				    struct net_device *physical);
struct qdx_endpoint *qdx_endpoint_alloc(struct qdx_service *service, u32 type);
int qdx_endpoint_wait(struct qdx_endpoint *endpoint, unsigned long deadline);
void qdx_endpoint_hold(struct qdx_endpoint *endpoint);
void qdx_endpoint_put(struct qdx_endpoint *endpoint);
int qdx_endpoint_retire(struct qdx_endpoint *endpoint);
int qdx_endpoint_ifnum(const struct qdx_endpoint *endpoint, u32 *ifnum);
u32 qdx_endpoint_wire_ifnum(const struct qdx_endpoint *endpoint);

/* Control outcome is independent of waiter status and DMA access. */
enum qdx_outcome { QDX_NOT_SUBMITTED, QDX_ACK, QDX_REJECTED, QDX_UNKNOWN };
struct qdx_result {
	u64 id;
	u32 opcode;
	u32 ifnum;
	enum qdx_outcome outcome;
	int error;
	u32 firmware_error;
	size_t received_len;
	size_t declared_len;
	bool published;
	bool exposure_ended;
};
struct qdx_reply_bounds { size_t minimum, maximum, capacity; };
struct qdx_command_recipient {
	struct qdx_owner owner;
	/* NAPI-safe: copy the result and queue existing owner work. */
	void (*result)(void *owner, const struct qdx_result *result,
		       const void *payload, size_t length);
};
struct qdx_request *qdx_command_submit(struct qdx_endpoint *endpoint, u32 opcode,
		const void *payload, size_t length,
		const struct qdx_reply_bounds *bounds,
		const struct qdx_command_recipient *recipient);
int qdx_request_wait(struct qdx_request *request, unsigned long deadline,
		    struct qdx_result *result, void *payload, size_t capacity);
void qdx_request_cancel(struct qdx_request *request);
void qdx_request_put(struct qdx_request *request);
int qdx_message_send(struct qdx_endpoint *endpoint, u32 opcode,
		     const void *payload, size_t length);

enum qdx_receive_category {
	QDX_RECEIVE_MESSAGE = 0,
	QDX_RECEIVE_PACKET = 3,
	QDX_RECEIVE_VIRTUAL = 10,
	QDX_RECEIVE_RETURNED = 11,
	QDX_RECEIVE_BRIDGE_RETURNED = 12,
	QDX_RECEIVE_EXTENDED = 13,
	/* Fresh physical PACKET with the actual INGRESS_SHAPED flag. */
	QDX_RECEIVE_INGRESS_SHAPED = 16,
};

struct qdx_rx_meta {
	u32 ifnum;
	u32 service_code;
	u16 flags;
	u8 core;
	u8 type;
	u8 priority;
};
struct qdx_receive_ops {
	/* Consumes skb. No native policy query or sleeping work here. */
	void (*packet)(void *owner, struct sk_buff *skb,
		       const struct qdx_rx_meta *metadata, struct napi_struct *napi);
	void (*message)(void *owner, u32 opcode, u32 response, u32 error,
			const void *payload, size_t received, size_t declared);
};
struct qdx_receiver *qdx_endpoint_receive_register(struct qdx_endpoint *endpoint,
		u8 category, const struct qdx_owner *owner,
		const struct qdx_receive_ops *ops);
int qdx_endpoint_receive_unregister(struct qdx_receiver *receiver);

struct qdx_dma *qdx_dma_alloc(struct qdx_service *service, size_t length,
			     size_t alignment, enum dma_data_direction direction);
void *qdx_dma_cpu(struct qdx_dma *region);
dma_addr_t qdx_dma_address(const struct qdx_dma *region);
void qdx_dma_expose(struct qdx_dma *region);
/* Called only on proven unsubmitted access or actual feature access end. */
void qdx_dma_access_end(struct qdx_dma *region);
void qdx_dma_release(struct qdx_dma *region);

enum qdx_disposition { QDX_NATIVE, QDX_OPTIONAL, QDX_REQUIRED };
enum qdx_submit_status { QDX_ACCEPTED, QDX_RESOURCE_WAIT, QDX_CLOSED, QDX_REFUSED };
enum qdx_resource {
	QDX_RESOURCE_DESCRIPTOR = BIT(0),
	QDX_RESOURCE_CARRIER = BIT(1),
	QDX_RESOURCE_HOST_BYTES = BIT(2),
};
struct qdx_ready {
	enum qdx_submit_status status;
	unsigned int resources;
	int error;
};
struct qdx_tx_class { u32 tag; u64 token; };
#if IS_REACHABLE(CONFIG_QDX)
struct qdx_tx_path *qdx_tx_prepare(struct qdx_endpoint *endpoint,
		struct net_device *port, u16 queue, struct qdx_tx_class class,
		enum qdx_disposition disposition);
/* Storage references do not stop or resume execution. */
void qdx_tx_path_get(struct qdx_tx_path *path);
void qdx_tx_path_put(struct qdx_tx_path *path);
int qdx_tx_hold(struct qdx_tx_path *path);
/* Closed admission plus all accepted DMA/recipient completion, not HW hold. */
bool qdx_tx_drained(struct qdx_tx_path *path);
void qdx_tx_release(struct qdx_tx_path *path);
struct qdx_ready qdx_tx_ready(struct qdx_tx_path *path, size_t charge);
struct qdx_ready qdx_xmit(struct qdx_tx_path *path, struct sk_buff *skb,
		struct qdx_tx_class class, struct netdev_queue *queue,
		unsigned int bytes);
#else
static inline struct qdx_tx_path *qdx_tx_prepare(struct qdx_endpoint *endpoint,
		struct net_device *port, u16 queue, struct qdx_tx_class class,
		enum qdx_disposition disposition)
{
	return ERR_PTR(-EOPNOTSUPP);
}
static inline void qdx_tx_path_get(struct qdx_tx_path *path) {}
static inline void qdx_tx_path_put(struct qdx_tx_path *path) {}
static inline int qdx_tx_hold(struct qdx_tx_path *path)
{
	return -EOPNOTSUPP;
}
static inline bool qdx_tx_drained(struct qdx_tx_path *path) { return true; }
static inline void qdx_tx_release(struct qdx_tx_path *path) {}
static inline struct qdx_ready qdx_tx_ready(struct qdx_tx_path *path, size_t charge)
{
	return (struct qdx_ready) { .status = QDX_CLOSED, .error = -EOPNOTSUPP };
}
static inline struct qdx_ready qdx_xmit(struct qdx_tx_path *path, struct sk_buff *skb,
		struct qdx_tx_class class, struct netdev_queue *queue, unsigned int bytes)
{
	return (struct qdx_ready) { .status = QDX_CLOSED, .error = -EOPNOTSUPP };
}
#endif
struct qdx_rx_use *qdx_rx_acquire(struct qdx_endpoint *endpoint,
				struct net_device *port);
int qdx_rx_hold(struct qdx_rx_use *use);
int qdx_rx_release(struct qdx_rx_use *use);

/* RTNL-only allocation before peer cfg; the physical endpoint supplies the
 * native port. Release consumes the handle after firmware attachment, endpoint
 * and recipient access have ended; final native clear runs asynchronously.
 */
struct qdx_vsi *qdx_vsi_alloc(struct qdx_endpoint *physical, u32 *wire_vsi);
void qdx_vsi_release(struct qdx_vsi *vsi);

struct qdx_packet_recipient {
	struct qdx_owner owner;
	/* Original metadata is valid throughout this callback. Consumes returned
	 * skb when non-NULL; NULL means disposal, never a fabricated match verdict.
	 */
	void (*returned)(void *owner, struct sk_buff *original,
			 struct sk_buff *returned, const struct qdx_rx_meta *metadata,
			 struct napi_struct *napi);
};
struct qdx_packet_op *qdx_packet_op_prepare(struct qdx_endpoint *endpoint,
					  u32 class_tag, u8 category);
void qdx_packet_op_close(struct qdx_packet_op *operation);
bool qdx_packet_op_drained(struct qdx_packet_op *operation);
void qdx_packet_op_put(struct qdx_packet_op *operation);
struct qdx_ready qdx_packet_op_ready(struct qdx_packet_op *operation, size_t charge);
struct qdx_ready qdx_packet_op_submit(struct qdx_packet_op *operation,
		struct sk_buff *skb, const struct qdx_packet_recipient *recipient);

/* A held result of the concrete PPE lookup. The owner keeps the immutable
 * path/class and original retiring queue identity alive through this call.
 */
enum qdx_tx_selection_status {
	QDX_TX_NATIVE, QDX_TX_READY, QDX_TX_HELD, QDX_TX_RETIRED, QDX_TX_REFUSED,
};
struct qdx_tx_selection {
	struct qdx_owner owner;
	struct qdx_tx_path *path;
	struct qdx_tx_class class;
	enum qdx_tx_selection_status status;
	enum qdx_disposition disposition;
};
#if IS_REACHABLE(CONFIG_QDX)
void qdx_tx_selection_put(struct qdx_tx_selection *selection);
#else
static inline void qdx_tx_selection_put(struct qdx_tx_selection *selection) {}
#endif

/* One embedded wait per real waiting queue; no skb or independent policy hold. */
struct qdx_resource_wait {
	struct list_head node;
	struct qdx_owner owner;
	void (*progress)(void *owner);
	unsigned int resources;
	struct qdx_endpoint *endpoint;
	u64 serial;
	refcount_t calls;
	bool armed;
};
#if IS_REACHABLE(CONFIG_QDX)
void qdx_tx_wait_arm(struct qdx_tx_path *path, struct qdx_resource_wait *wait,
		     unsigned int resources);
void qdx_packet_op_wait_arm(struct qdx_packet_op *operation,
			   struct qdx_resource_wait *wait, unsigned int resources);
void qdx_resource_wait_disarm(struct qdx_resource_wait *wait);
void qdx_resource_wait_drain(struct qdx_resource_wait *wait);
#else
static inline void qdx_tx_wait_arm(struct qdx_tx_path *path,
		struct qdx_resource_wait *wait, unsigned int resources) {}
static inline void qdx_packet_op_wait_arm(struct qdx_packet_op *operation,
		struct qdx_resource_wait *wait, unsigned int resources) {}
static inline void qdx_resource_wait_disarm(struct qdx_resource_wait *wait) {}
static inline void qdx_resource_wait_drain(struct qdx_resource_wait *wait) {}
#endif

enum qdx_binding_role {
	QDX_BINDING_FT_PROVIDER,
	QDX_BINDING_FT,
	QDX_BINDING_TC_PROVIDER,
	QDX_BINDING_TC_PORT,
	QDX_BINDING_TC,
	QDX_BINDING_BRIDGE_PATH,
	QDX_BINDING_VLAN_PATH,
	QDX_BINDING_VLAN_ENDPOINT,
	QDX_BINDING_PPPOE_SESSION,
};
struct qdx_binding_key {
	struct net_device *dev;
	const void *identity;
	enum qdx_binding_role role;
};
struct qdx_binding_use {
	struct list_head node;
	struct qdx_binding *provider;
	struct qdx_owner consumer;
	int (*invalidate)(void *consumer, bool may_sleep);
	refcount_t deliveries;
	u64 serial;
	bool invalid;
	bool usable;
	bool linked;
};
struct qdx_binding_scan { u64 cursor, limit; };

#if IS_REACHABLE(CONFIG_QDX)
struct qdx_binding *qdx_binding_publish(const struct qdx_binding_key *key,
		const struct qdx_owner *owner, const void *typed_ops);
struct qdx_binding *qdx_binding_lookup(const struct qdx_binding_key *key);
bool qdx_binding_hold(struct qdx_binding *binding);
void qdx_binding_put(struct qdx_binding *binding);
struct net_device *qdx_binding_dev(const struct qdx_binding *binding);
void *qdx_binding_owner(const struct qdx_binding *binding);
const void *qdx_binding_ops(const struct qdx_binding *binding);
int qdx_binding_use(struct qdx_binding *provider, struct qdx_binding_use *use,
		    const struct qdx_owner *consumer,
		    int (*invalidate)(void *consumer, bool may_sleep));
void qdx_binding_use_put(struct qdx_binding_use *use);
/* Caller owns its cfg; short common lock precedes its data lock. */
void qdx_uses_lock(void);
void qdx_uses_unlock(void);
bool qdx_use_available_locked(const struct qdx_binding_use *use);
void qdx_use_publish_locked(struct qdx_binding_use *use);
void qdx_use_invalidate_locked(struct qdx_binding_use *use);
void qdx_binding_prepare(struct qdx_binding *binding);
void qdx_binding_available(struct qdx_binding *binding);
/* Mark all real uses invalid before their owner-specific withdrawal. */
void qdx_binding_invalidate(struct qdx_binding *binding);
/* Temporary, retained consumer iteration; caller invokes its typed entry only
 * after releasing common/provider locks. Repeated events still confirm stops.
 */
void qdx_binding_scan_start(struct qdx_binding *binding, struct qdx_binding_scan *scan);
struct qdx_binding_use *qdx_binding_user_get(struct qdx_binding *binding,
					  struct qdx_binding_scan *scan);
void qdx_binding_user_put(struct qdx_binding_use *use);
/* Consumes the publish registration; admitted lookup/use refs are separate. */
void qdx_binding_withdraw(struct qdx_binding *binding);
#else
static inline struct qdx_binding *qdx_binding_publish(const struct qdx_binding_key *key,
		const struct qdx_owner *owner, const void *typed_ops)
{
	return ERR_PTR(-EOPNOTSUPP);
}
static inline struct qdx_binding *qdx_binding_lookup(const struct qdx_binding_key *key)
{
	return NULL;
}
static inline bool qdx_binding_hold(struct qdx_binding *binding) { return false; }
static inline void qdx_binding_put(struct qdx_binding *binding) {}
static inline struct net_device *qdx_binding_dev(const struct qdx_binding *binding)
{
	return NULL;
}
static inline void *qdx_binding_owner(const struct qdx_binding *binding) { return NULL; }
static inline const void *qdx_binding_ops(const struct qdx_binding *binding) { return NULL; }
static inline int qdx_binding_use(struct qdx_binding *provider,
		struct qdx_binding_use *use, const struct qdx_owner *consumer,
		int (*invalidate)(void *consumer, bool may_sleep))
{
	return -EOPNOTSUPP;
}
static inline void qdx_binding_use_put(struct qdx_binding_use *use) {}
static inline void qdx_uses_lock(void) {}
static inline void qdx_uses_unlock(void) {}
static inline bool qdx_use_available_locked(const struct qdx_binding_use *use)
{
	return false;
}
static inline void qdx_use_publish_locked(struct qdx_binding_use *use) {}
static inline void qdx_use_invalidate_locked(struct qdx_binding_use *use) {}
static inline void qdx_binding_prepare(struct qdx_binding *binding) {}
static inline void qdx_binding_available(struct qdx_binding *binding) {}
static inline void qdx_binding_invalidate(struct qdx_binding *binding) {}
static inline void qdx_binding_scan_start(struct qdx_binding *binding,
		struct qdx_binding_scan *scan)
{
	*scan = (struct qdx_binding_scan) {};
}
static inline struct qdx_binding_use *qdx_binding_user_get(struct qdx_binding *binding,
		struct qdx_binding_scan *scan)
{
	return NULL;
}
static inline void qdx_binding_user_put(struct qdx_binding_use *use) {}
static inline void qdx_binding_withdraw(struct qdx_binding *binding) {}
#endif

struct qdx_edma;
struct qdx_ppe;
struct qdx_ppe_rx;
struct qdx_ppe_tx;

struct qdx_port_state {
	struct net_device *netdev;
	u32 mtu;
	u32 link_state;
	u8 mac[ETH_ALEN];
	bool admin;
};

struct qdx_edma_ops {
	int (*activate)(void *context);
	int (*quiesce)(void *context, u32 native_rx_entries);
	int (*resume_shared)(void *context);
	int (*map_rx_queue)(void *context, u16 queue, bool firmware);
	void (*resource_progress)(void *context);
	void (*tx_gate)(void *context, bool hold);
	void (*complete_tx)(void *context, struct netdev_queue *queue,
			    unsigned int packets, unsigned int bytes);
	int (*restore)(void *context);
	void (*receive)(void *context, unsigned int port, struct sk_buff *skb,
			struct napi_struct *napi);
};

struct qdx_edma_info {
	struct device *dev;
	struct net_device *conduit;
	const struct qdx_edma_ops *ops;
	void *context;
	unsigned int max_frame;
	unsigned int tx_min_size;
};

struct qdx_ppe_ops {
	void (*lock)(void *context, unsigned int port);
	void (*unlock)(void *context, unsigned int port);
	int (*snapshot)(void *context, unsigned int port,
			struct qdx_port_state *state);
	int (*reapply)(void *context, unsigned int port);
	int (*restore)(void *context);
	/* Sleepable actual resource calls, never a Linux policy callback. */
	struct qdx_ppe_rx *(*rx_acquire)(void *context, unsigned int port);
	int (*rx_hold)(void *context, struct qdx_ppe_rx *scope);
	int (*rx_release)(void *context, struct qdx_ppe_rx *scope);
	struct qdx_ppe_tx *(*tx_prepare)(void *context, unsigned int port, u16 queue);
	int (*tx_hold)(void *context, struct qdx_ppe_tx *scope);
	void (*tx_release)(void *context, struct qdx_ppe_tx *scope);
	/* RTNL -> native resource lock; no firmware waits or peer callbacks. */
	int (*vsi_alloc)(void *context, unsigned int port, u32 *wire_vsi);
	int (*vsi_release)(void *context, u32 wire_vsi);
	/* Short selection read; retains result.owner before returning. */
	void (*resolve_tx)(void *context, unsigned int port, u16 queue, u64 token,
			   enum qdx_disposition disposition,
			   struct qdx_tx_selection *selection);
};

struct qdx_ppe_info {
	struct device *dev;
	struct net_device *conduit;
	const struct qdx_ppe_ops *ops;
	void *context;
	unsigned long ports;
};

#if IS_REACHABLE(CONFIG_QDX)
struct qdx_edma *qdx_edma_attach(const struct qdx_edma_info *info);
struct qdx_ppe *qdx_ppe_attach(const struct qdx_ppe_info *info);
/* Sleepable; caller retains the native registration. Zero refuses allocation. */
u64 qdx_ppe_next_tx_token(struct qdx_ppe *ppe);
void qdx_edma_detach(struct qdx_edma *edma);
void qdx_ppe_detach(struct qdx_ppe *ppe);
void qdx_edma_resolve(struct qdx_edma *edma, unsigned int port, u16 queue,
		      u64 token, enum qdx_disposition disposition,
		      struct qdx_tx_selection *selection);
int qdx_ppe_map_rx_queue(struct qdx_ppe *ppe, u16 queue, bool firmware);
void qdx_ppe_tx_gate(struct qdx_ppe *ppe, bool hold);
void qdx_ppe_tx_progress(struct qdx_ppe *ppe);
int qdx_port_open(struct qdx_ppe *ppe, unsigned int port);
int qdx_port_close(struct qdx_ppe *ppe, unsigned int port);
int qdx_port_check_mtu(struct qdx_ppe *ppe, unsigned int port, unsigned int mtu);
int qdx_port_mtu(struct qdx_ppe *ppe, unsigned int port, unsigned int mtu);
/* A successful prepare holds port serialization until finish. */
int qdx_port_prepare(struct qdx_ppe *ppe, unsigned int port);
int qdx_port_finish(struct qdx_ppe *ppe, unsigned int port);
void qdx_port_failed(struct qdx_ppe *ppe, unsigned int port, int error);
#else
static inline struct qdx_edma *qdx_edma_attach(const struct qdx_edma_info *info)
{
	return NULL;
}
static inline struct qdx_ppe *qdx_ppe_attach(const struct qdx_ppe_info *info)
{
	return NULL;
}
static inline void qdx_edma_detach(struct qdx_edma *edma) {}
static inline void qdx_ppe_detach(struct qdx_ppe *ppe) {}
static inline u64 qdx_ppe_next_tx_token(struct qdx_ppe *ppe) { return 0; }
static inline void qdx_edma_resolve(struct qdx_edma *edma, unsigned int port,
		u16 queue, u64 token, enum qdx_disposition disposition,
		struct qdx_tx_selection *selection)
{
	*selection = (struct qdx_tx_selection) {
		.status = token || disposition != QDX_NATIVE ?
			  QDX_TX_REFUSED : QDX_TX_NATIVE,
		.disposition = disposition,
	};
}
static inline int qdx_ppe_map_rx_queue(struct qdx_ppe *ppe, u16 queue, bool firmware)
{
	return -EOPNOTSUPP;
}
static inline void qdx_ppe_tx_gate(struct qdx_ppe *ppe, bool hold) {}
static inline void qdx_ppe_tx_progress(struct qdx_ppe *ppe) {}
static inline int qdx_port_open(struct qdx_ppe *ppe, unsigned int port)
{
	return 0;
}
static inline int qdx_port_close(struct qdx_ppe *ppe, unsigned int port)
{
	return 0;
}
static inline int qdx_port_prepare(struct qdx_ppe *ppe, unsigned int port)
{
	return 0;
}
static inline int qdx_port_finish(struct qdx_ppe *ppe, unsigned int port)
{
	return 0;
}
static inline int qdx_port_check_mtu(struct qdx_ppe *ppe, unsigned int port,
				     unsigned int mtu)
{
	return 0;
}
static inline int qdx_port_mtu(struct qdx_ppe *ppe, unsigned int port, unsigned int mtu)
{
	return 0;
}
static inline void qdx_port_failed(struct qdx_ppe *ppe, unsigned int port, int error) {}
#endif
#endif
