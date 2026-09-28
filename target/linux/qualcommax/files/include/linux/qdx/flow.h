/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_QDX_FLOW_H
#define _LINUX_QDX_FLOW_H

#include <linux/netdevice.h>

struct nf_flowtable;
struct qdx_binding;

/* The concrete FT dispatcher owns native binding and callback lifetimes. */
struct qdx_flow_ops {
	int (*bind)(void *provider, struct qdx_binding *native_binding,
		    struct nf_flowtable *flowtable, void **attachment);
	int (*setup)(void *attachment, enum tc_setup_type type, void *data);
	void (*unbind)(void *attachment);
};

#endif
