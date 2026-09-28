/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_QDX_TUNNEL_H
#define _LINUX_QDX_TUNNEL_H

#include <linux/ppp_channel.h>
#include <linux/qdx/vlan.h>

struct qdx_pppoe_request {
	struct net_device *dev;
	struct net_device_path native_path;
	struct qdx_lower_path lower;
	struct qdx_packet_geometry transmit;
	__be16 protocol;
};

struct qdx_pppoe_use {
	struct qdx_binding_use use;
	struct qdx_endpoint *execution;
	struct qdx_endpoint *physical;
	struct qdx_packet_geometry transmit;
	u16 session_id;
	u16 mtu;
	u8 local[ETH_ALEN];
	u8 remote[ETH_ALEN];
};

struct qdx_pppoe_ops {
	struct qdx_binding *(*prepare)(const struct qdx_pppoe_request *request);
	void (*prepare_put)(struct qdx_binding *preparation);
	int (*get)(struct qdx_binding *preparation, __be16 protocol,
		   const struct qdx_owner *consumer,
		   int (*invalidate)(void *consumer, bool may_sleep),
		   struct qdx_pppoe_use *use);
	void (*account)(const struct qdx_pppoe_use *use,
			const struct ppp_offload_stats *delta);
	void (*put)(struct qdx_pppoe_use *use);
};

/* Caller holds RTNL for prepare and get, without a consumer cfg lock.
 * The preparation has an actual common binding reference, released through
 * typed prepare_put. Get never creates or reconfigures an execution object.
 */
static inline struct qdx_binding *
qdx_pppoe_session_prepare(const struct qdx_pppoe_request *request)
{
	const struct qdx_binding_key key = { .role = QDX_BINDING_PPPOE_SESSION };
	struct qdx_binding *provider = qdx_binding_lookup(&key), *preparation;
	const struct qdx_pppoe_ops *ops;

	if (IS_ERR(provider))
		return provider;
	if (!provider)
		return ERR_PTR(-EOPNOTSUPP);
	ops = qdx_binding_ops(provider);
	preparation = ops->prepare(request);
	qdx_binding_put(provider);
	return preparation;
}

static inline void qdx_pppoe_session_prepare_put(struct qdx_binding *preparation)
{
	const struct qdx_pppoe_ops *ops = qdx_binding_ops(preparation);

	ops->prepare_put(preparation);
	qdx_binding_put(preparation);
}

static inline int qdx_pppoe_session_get(struct qdx_binding *preparation,
		__be16 protocol, const struct qdx_owner *consumer,
		int (*invalidate)(void *consumer, bool may_sleep),
		struct qdx_pppoe_use *use)
{
	const struct qdx_pppoe_ops *ops = qdx_binding_ops(preparation);

	return ops->get(preparation, protocol, consumer, invalidate, use);
}

static inline void qdx_pppoe_account(const struct qdx_pppoe_use *use,
				     const struct ppp_offload_stats *delta)
{
	const struct qdx_pppoe_ops *ops = qdx_binding_ops(use->use.provider);

	ops->account(use, delta);
}

static inline void qdx_pppoe_session_put(struct qdx_pppoe_use *use)
{
	const struct qdx_pppoe_ops *ops = qdx_binding_ops(use->use.provider);

	ops->put(use);
	qdx_binding_use_put(&use->use);
}

#endif
