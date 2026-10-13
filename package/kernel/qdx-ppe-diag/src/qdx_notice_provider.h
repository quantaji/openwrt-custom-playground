/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef QDX_NOTICE_PROVIDER_H
#define QDX_NOTICE_PROVIDER_H
#include "qdx.h"

/* Version-bound diagnostic access to io.c:215. No arena pointer is retained. */
struct qdx_notice_io_prefix { struct net_device *napi_dev; };
struct qdx_notice_provider {
    struct qdx_service *service;
    u32 ids[32];
    unsigned int count;
};

static int qdx_notice_bind(struct qdx_notice_provider *provider,
                           struct net_device *conduit)
{
    struct qdx_service *service;
    struct qdx *qdx;
    unsigned int core;
    int error = 0;

    service = qdx_service_get(conduit, QDX_SERVICE_ETHERNET);
    if (IS_ERR(service))
        return PTR_ERR(service);
    qdx = service->qdx;
    /* terminal_stop releases the io arena under this mutex BEFORE service
     * users drain. A service ref alone is explicitly insufficient. */
    mutex_lock(&qdx->receive_drain);
    if (qdx_service_state(service) != QDX_AVAILABLE) {
        error = -ESHUTDOWN;
        goto out;
    }
    for (core = 0; core < QDX_CORES && !error; core++) {
        struct qdx_notice_io_prefix *io = (void *)qdx->cores[core].io;
        struct napi_struct *napi;
        struct net_device *dev;

        if (!io || !(dev = READ_ONCE(io->napi_dev))) {
            error = -ENODEV;
            break;
        }
        netdev_lock(dev);
        list_for_each_entry(napi, &dev->napi_list, dev_list) {
            u32 id = READ_ONCE(napi->napi_id);

            /* Zero means no usable busy-poll identity, not a corrupt object. */
            if (!id)
                continue;
            if (provider->count == ARRAY_SIZE(provider->ids)) {
                error = -EOVERFLOW;
                break;
            }
            provider->ids[provider->count++] = id;
        }
        netdev_unlock(dev);
    }
    if (!error && !provider->count)
        error = -ENODATA;
    if (!error && qdx_service_state(service) != QDX_AVAILABLE)
        error = -ESHUTDOWN;
 out:
    mutex_unlock(&qdx->receive_drain);
    if (error) {
        provider->count = 0;
        qdx_service_put(service);
        return error;
    }
    provider->service = service;
    return 0;
}

static bool qdx_notice_owns(const struct qdx_notice_provider *provider,
                            const struct sk_buff *skb)
{
    unsigned int i;
    u32 id = skb_napi_id(skb);

    for (i = 0; i < provider->count; i++)
        if (provider->ids[i] == id)
            return true;
    return false;
}

/* Caller has removed its packet tap and joined synchronize_net first. */
static void qdx_notice_unbind(struct qdx_notice_provider *provider)
{
    qdx_service_put(provider->service);
    provider->service = NULL;
    provider->count = 0;
}
#endif
