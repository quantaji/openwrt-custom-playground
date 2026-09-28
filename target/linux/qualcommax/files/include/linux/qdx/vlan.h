/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_QDX_VLAN_H
#define _LINUX_QDX_VLAN_H

#include <linux/err.h>
#include <linux/if_vlan.h>
#include <linux/qdx.h>

#define QDX_VLAN_DEPTH NET_DEVICE_PATH_VLAN_MAX

enum qdx_vlan_location {
	QDX_VLAN_METADATA,
	QDX_VLAN_IN_FRAME,
	QDX_VLAN_SAVED_MAC,
};

struct qdx_vlan_tag {
	__be16 protocol;
	u16 tci;
	u16 known_tci;
	enum qdx_vlan_location location;
};

enum qdx_geometry_known {
	QDX_GEOMETRY_PRIORITY = BIT(0),
	QDX_GEOMETRY_PROTOCOL = BIT(1),
	QDX_GEOMETRY_FRAME_PROTOCOL = BIT(2),
	QDX_GEOMETRY_SOURCE = BIT(3),
	QDX_GEOMETRY_DESTINATION = BIT(4),
	QDX_GEOMETRY_PACKET_TYPE = BIT(5),
	QDX_GEOMETRY_VLAN_PAYLOAD_PROTOCOL = BIT(6),
};

/* Actual native position. Length = network/PPP payload length + overhead;
 * saved MAC and metadata are not part of data_overhead. wire_overhead excludes
 * FCS/padding/preamble/IFG. A bit missing from known_tci is not a known zero.
 */
struct qdx_packet_geometry {
	s32 data_overhead;
	u16 saved_mac_len;
	u16 wire_overhead;
	u16 mtu;
	u32 priority;
	u32 known;
	__be16 protocol;
	__be16 frame_protocol;
	/* Inside the innermost visible VLAN tag; with no visible tag, the
	 * protocol a later tag will wrap. Saved RX MAC tags are not visible.
	 * Valid only with QDX_GEOMETRY_VLAN_PAYLOAD_PROTOCOL in known.
	 */
	__be16 vlan_payload_protocol;
	u8 source[ETH_ALEN];
	u8 destination[ETH_ALEN];
	u8 packet_type;
	u8 tag_count;
	struct qdx_vlan_tag tags[QDX_VLAN_DEPTH];
};

enum qdx_vlan_position {
	QDX_VLAN_RX,
	QDX_VLAN_HEADER,
	QDX_VLAN_TX,
};

struct qdx_vlan_request {
	struct net_device *dev;
	struct net_device *immediate_lower;
	enum qdx_vlan_position position;
	struct qdx_packet_geometry input;
	bool source_from_device;
};

struct qdx_vlan_path {
	struct qdx_binding_use use;
	struct list_head node;
	struct qdx_vlan_request request;
	struct qdx_packet_geometry output;
	struct net_device *dependencies[QDX_VLAN_DEPTH + 1];
	u8 dependency_count;
};

struct qdx_vlan_ops {
	int (*get)(struct qdx_binding *provider,
		   const struct qdx_vlan_request *request,
		   const struct qdx_owner *consumer,
		   int (*invalidate)(void *consumer, bool may_sleep),
		   struct qdx_vlan_path *path);
	void (*put)(struct qdx_vlan_path *path);
};

/* Caller holds RTNL. Result storage belongs to the retained consumer. */
static inline int qdx_vlan_path_get(const struct qdx_vlan_request *request,
		const struct qdx_owner *consumer,
		int (*invalidate)(void *consumer, bool may_sleep),
		struct qdx_vlan_path *path)
{
	const struct qdx_binding_key key = { .role = QDX_BINDING_VLAN_PATH };
	struct qdx_binding *provider = qdx_binding_lookup(&key);
	const struct qdx_vlan_ops *ops;
	int err;

	if (IS_ERR(provider))
		return PTR_ERR(provider);
	if (!provider)
		return -EOPNOTSUPP;
	ops = qdx_binding_ops(provider);
	err = ops->get(provider, request, consumer, invalidate, path);
	qdx_binding_put(provider);
	return err;
}

static inline void qdx_vlan_path_put(struct qdx_vlan_path *path)
{
	const struct qdx_vlan_ops *ops = qdx_binding_ops(path->use.provider);

	ops->put(path);
	qdx_binding_use_put(&path->use);
}

/* Borrowed during preparation. A dynamic VLAN lower is represented by its
 * actual preparation binding; a physical lower has vlan_binding == NULL.
 */
struct qdx_lower_path {
	struct net_device *physical_dev;
	struct qdx_endpoint *physical;
	struct qdx_endpoint *execution;
	struct qdx_binding *vlan_binding;
};

struct qdx_vlan_endpoint_request {
	struct qdx_vlan_request path;
	struct qdx_lower_path lower;
	struct qdx_vlan_tag tag;
};

struct qdx_vlan_endpoint_use {
	struct qdx_binding_use use;
	struct qdx_endpoint *execution;
	struct qdx_endpoint *physical;
};

struct qdx_vlan_endpoint_ops {
	struct qdx_binding *(*prepare)(const struct qdx_vlan_endpoint_request *request);
	void (*prepare_put)(struct qdx_binding *preparation);
	int (*get)(struct qdx_binding *preparation,
		   const struct qdx_owner *consumer,
		   int (*invalidate)(void *consumer, bool may_sleep),
		   struct qdx_vlan_endpoint_use *use);
	void (*put)(struct qdx_vlan_endpoint_use *use);
};

/* RTNL held. The returned binding is the real retained preparation, including
 * when configuration remains pending. Release through the typed prepare_put.
 */
static inline struct qdx_binding *
qdx_vlan_endpoint_prepare(const struct qdx_vlan_endpoint_request *request)
{
	const struct qdx_binding_key key = { .role = QDX_BINDING_VLAN_ENDPOINT };
	struct qdx_binding *provider = qdx_binding_lookup(&key), *preparation;
	const struct qdx_vlan_endpoint_ops *ops;

	if (IS_ERR(provider))
		return provider;
	if (!provider)
		return ERR_PTR(-EOPNOTSUPP);
	ops = qdx_binding_ops(provider);
	preparation = ops->prepare(request);
	qdx_binding_put(provider);
	return preparation;
}

static inline void qdx_vlan_endpoint_prepare_put(struct qdx_binding *preparation)
{
	const struct qdx_vlan_endpoint_ops *ops = qdx_binding_ops(preparation);

	ops->prepare_put(preparation);
	qdx_binding_put(preparation);
}

static inline int qdx_vlan_endpoint_get(struct qdx_binding *preparation,
		const struct qdx_owner *consumer,
		int (*invalidate)(void *consumer, bool may_sleep),
		struct qdx_vlan_endpoint_use *use)
{
	const struct qdx_vlan_endpoint_ops *ops = qdx_binding_ops(preparation);

	return ops->get(preparation, consumer, invalidate, use);
}

static inline void qdx_vlan_endpoint_put(struct qdx_vlan_endpoint_use *use)
{
	const struct qdx_vlan_endpoint_ops *ops = qdx_binding_ops(use->use.provider);

	ops->put(use);
	qdx_binding_use_put(&use->use);
}

#endif
