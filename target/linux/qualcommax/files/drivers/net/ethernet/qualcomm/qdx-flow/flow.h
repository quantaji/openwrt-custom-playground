/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _QDX_FLOW_PRIVATE_H
#define _QDX_FLOW_PRIVATE_H

#include <linux/completion.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/mutex.h>
#include <linux/netfilter.h>
#include <linux/qdx.h>
#include <linux/refcount.h>
#include <linux/workqueue.h>
#include <net/netfilter/nf_flow_table.h>
#include <net/netfilter/nf_conntrack.h>
#include "nss.h"

#define QDX_FLOW_HASH_BITS 8
#define QDX_FLOW_COMMAND_TIMEOUT msecs_to_jiffies(1000)
#define QDX_FLOW_STATS_INTERVAL msecs_to_jiffies(1000)
#define QDX_FLOW_STATS_CAPACITY 4096

struct qdx_flow;
struct qdx_flow_paths;
struct qdx_flow_domain;

/* Zero initialized, service-local packet identity. Namespace/zone is not a
 * firmware key extension. Both packet directions reserve their actual keys.
 */
struct qdx_flow_key {
	struct in6_addr source;
	struct in6_addr destination;
	__be16 source_port;
	__be16 destination_port;
	u8 family;
	u8 protocol;
	u8 reserved[2];
};

struct qdx_flow_offer {
	struct nf_flow_match match;
	struct flow_rule *facts;
	struct qdx_flow_key input;
	struct qdx_flow_key output;
	struct net_device *redirect;
	u8 source[ETH_ALEN];
	u8 destination[ETH_ALEN];
	u8 vlan_pop;
	u8 vlan_push;
	struct { __be16 protocol; u16 tci; } tags[2];
	u16 pppoe_sid;
	bool pppoe_push;
};

struct qdx_flow_alias {
	struct hlist_node node;
	struct qdx_flow_key key;
	struct qdx_flow *flow;
};

enum qdx_flow_preparation { QDX_FLOW_EMPTY, QDX_FLOW_PREPARING,
	QDX_FLOW_READY, QDX_FLOW_UNAVAILABLE };
enum qdx_flow_exposure { QDX_FLOW_NONE, QDX_FLOW_CREATING,
	QDX_FLOW_LIVE, QDX_FLOW_RETIRING, QDX_FLOW_UNKNOWN };

/* Request recipient state is copied only by its original completion. */
struct qdx_flow_command {
	struct qdx_flow *flow;
	struct qdx_request *request;
	struct qdx_result result;
	bool waiting;
};

struct qdx_flow_delta { u64 packets, bytes; };
struct qdx_flow_side_delta { struct qdx_flow_delta rx, tx; };

struct qdx_flow_wire_path {
	u32 physical_ifnum;
	u32 execution_ifnum;
	u32 session_ifnum;
	u32 class_tag;
	u32 vlan[2];
	u16 mtu;
	u16 igs_tag;
	bool pppoe;
	bool has_class;
	bool has_igs;
};

struct qdx_flow_query {
	refcount_t refs;
	spinlock_t lock;
	struct qdx_flow_collector *collector;
	struct qdx_request *request;
	struct qdx_result result;
	size_t length;
	bool done;
	bool drained;
	bool cancelled;
	unsigned long deadline;
	u8 payload[QDX_FLOW_STATS_CAPACITY];
};

struct qdx_flow_collector {
	struct qdx_flow_domain *domain;
	struct qdx_service *service;
	struct qdx_endpoint *endpoint;
	struct qdx_receiver *receiver;
	spinlock_t lock;
	struct qdx_flow_query *query;
	struct delayed_work work;
	struct completion stopped;
	u16 next;
	u8 family;
	bool stopping;
	bool cleanup_pin;
};

struct qdx_flow_binding {
	refcount_t refs;
	struct list_head node;
	struct qdx_flow_domain *domain;
	struct qdx_binding *native;
	struct nf_flowtable *table;
	bool live;
};

struct qdx_flow_domain {
	refcount_t refs;
	struct list_head node;
	struct net_device *dev;
	struct mutex cfg;
	spinlock_t index_lock;
	DECLARE_HASHTABLE(associations, QDX_FLOW_HASH_BITS);
	DECLARE_HASHTABLE(wire, QDX_FLOW_HASH_BITS);
	struct list_head flows;
	struct list_head bindings;
	struct qdx_flow_collector collectors[2];
	bool admitting;
	bool closing;
};

struct qdx_flow {
	refcount_t refs;
	struct list_head node;
	struct hlist_node association;
	struct qdx_flow_alias aliases[2];
	struct qdx_flow_domain *domain;
	struct qdx_flow_binding *binding;
	spinlock_t data_lock;
	struct flow_offload *native;
	struct nf_flowtable *table;
	struct nf_conn *ct;
	struct nf_flow_hw_path *native_path;
	struct qdx_flow_offer offers[2];
	struct qdx_flow_paths *paths;
	struct qdx_flow_wire_path forward[2];
	struct qdx_flow_collector *collector;
	struct qdx_flow_command create;
	struct qdx_flow_command destroy;
	struct qdx_flow_query *retiring_query;
	union { struct qdx_nss_ipv4_create ipv4; struct qdx_nss_ipv6_create ipv6; } wire;
	size_t wire_length;
	struct qdx_flow_delta pending_ip[2];
	struct qdx_flow_side_delta pending_ppp[2];
	unsigned long last_activity;
	struct work_struct prepare_work;
	struct delayed_work retire_work;
	unsigned long retire_deadline;
	enum qdx_flow_preparation preparation;
	enum qdx_flow_exposure exposure;
	unsigned int active_receivers;
	bool sync_accepting;
	bool keys_reserved;
	bool invalid;
	bool native_dead;
	bool counter;
	bool final_sync;
	bool access_ended;
	bool execution_absent;
};

bool qdx_flow_get(void *object);
void qdx_flow_put(void *object);
struct qdx_owner qdx_flow_owner(struct qdx_flow *flow);
void qdx_flow_queue_retire(struct qdx_flow *flow);
void qdx_flow_queue_prepare(struct qdx_flow *flow);
int qdx_flow_invalidate(void *object, bool may_sleep);
int qdx_flow_withdraw(struct qdx_flow *flow);
void qdx_flow_retire_work(struct work_struct *work);
void qdx_flow_prepare_work(struct work_struct *work);
int qdx_flow_replace(struct qdx_flow_binding *binding,
		     const struct nf_flow_offload_ctx *context);
void qdx_flow_destroy(struct qdx_flow_binding *binding,
		      const struct nf_flow_offload_ctx *context);
void qdx_flow_stats(struct qdx_flow_binding *binding,
		    const struct nf_flow_offload_ctx *context,
		    struct flow_stats *stats);
struct qdx_flow *qdx_flow_find(struct qdx_flow_binding *binding,
			       const struct flow_offload *native);
void qdx_flow_binding_put(struct qdx_flow_binding *binding);
void qdx_flow_domain_put(struct qdx_flow_domain *domain);
void qdx_flow_domain_retire(struct qdx_flow_domain *domain);
void qdx_flow_domain_cleanup(struct qdx_flow_domain *domain);

int qdx_flow_offers_parse(struct qdx_flow_offer offers[2],
			 const struct nf_flow_offload_ctx *context);
void qdx_flow_offers_put(struct qdx_flow_offer offers[2]);
bool qdx_flow_offers_equal(const struct qdx_flow_offer a[2],
			   const struct qdx_flow_offer b[2]);
int qdx_flow_build(struct qdx_flow *flow);

int qdx_flow_paths_prepare(struct qdx_flow *flow);
bool qdx_flow_paths_release(struct qdx_flow *flow);
bool qdx_flow_paths_available(struct qdx_flow *flow);
int qdx_flow_paths_nf_check(struct qdx_flow *flow);
int qdx_flow_paths_hold(struct qdx_flow *flow);
void qdx_flow_paths_account(struct qdx_flow *flow);
int qdx_flow_paths_encode(struct qdx_flow *flow, void *wire);
int qdx_flow_nf_event(struct notifier_block *nb, unsigned long event, void *data);
int qdx_flow_netdev_event(struct notifier_block *nb, unsigned long event, void *data);
int qdx_flow_tc_event(struct notifier_block *nb, unsigned long event, void *data);

int qdx_flow_collector_start(struct qdx_flow_domain *domain, unsigned int index);
void qdx_flow_collector_stop(struct qdx_flow_collector *collector);
void qdx_flow_query_put(struct qdx_flow_query *query);
void qdx_flow_account_retired(struct qdx_flow *flow);
void qdx_flow_sync_receive(struct qdx_flow_collector *collector,
			   const void *payload, size_t length);

extern struct mutex qdx_flow_domains_lock;
extern struct list_head qdx_flow_domains;
extern struct workqueue_struct *qdx_flow_wq;

#endif
