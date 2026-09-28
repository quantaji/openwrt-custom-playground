/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_QDX_BRIDGE_H
#define _LINUX_QDX_BRIDGE_H

#include <linux/err.h>
#include <linux/if_bridge.h>
#include <linux/qdx.h>

struct qdx_bridge_request {
	struct net_device *master;
	struct net_device *port;
	struct net_device *position_dev;
	u8 destination[ETH_ALEN];
	u16 vid;
	u8 vlan_mode;
	bool rx;
	bool tx;
};

/* Embedded in the consumer retained by use.consumer. Do not reuse this
 * storage until its previous delivery references have ended.
 */
struct qdx_bridge_path {
	struct qdx_binding_use use;
	struct list_head node;
	struct qdx_bridge_request request;
};

struct qdx_bridge_ops {
	int (*get)(struct qdx_binding *provider,
		   const struct qdx_bridge_request *request,
		   const struct qdx_owner *consumer,
		   int (*invalidate)(void *consumer, bool may_sleep),
		   struct qdx_bridge_path *path);
	void (*put)(struct qdx_bridge_path *path);
};

/* Caller holds RTNL, before taking its configuration lock. */
static inline int qdx_bridge_path_get(const struct qdx_bridge_request *request,
		const struct qdx_owner *consumer,
		int (*invalidate)(void *consumer, bool may_sleep),
		struct qdx_bridge_path *path)
{
	const struct qdx_binding_key key = { .role = QDX_BINDING_BRIDGE_PATH };
	struct qdx_binding *provider = qdx_binding_lookup(&key);
	const struct qdx_bridge_ops *ops;
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

static inline void qdx_bridge_path_put(struct qdx_bridge_path *path)
{
	const struct qdx_bridge_ops *ops = qdx_binding_ops(path->use.provider);

	/* End the peer call before releasing its last possible code reference. */
	ops->put(path);
	qdx_binding_use_put(&path->use);
}

#endif
