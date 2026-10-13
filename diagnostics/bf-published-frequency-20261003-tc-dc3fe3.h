/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _QDX_TC_PRIVATE_H
#define _QDX_TC_PRIVATE_H

#include <linux/idr.h>
#include <linux/jiffies.h>
#include <linux/completion.h>
#include <linux/mutex.h>
#include <linux/qdx/tc.h>
#include <linux/refcount.h>
#include <linux/workqueue.h>
#include <net/gen_stats.h>
#include <net/ifb.h>
#include <net/pkt_cls.h>
#include <net/sch_generic.h>
#include "wire.h"

#define QDX_TC_COMMAND_TIMEOUT msecs_to_jiffies(3000)

struct qdx_tc_owner;
struct qdx_tc_tree;
struct qdx_tc_node;
struct qdx_tc_rule;
struct qdx_tc_igs;
struct qdx_tc_match;
struct qdx_tc_block;
struct qdx_tc_ifb;

/* One original operation and its reply, embedded in its real feature object.
 * Callback lifetime holds that object. A timeout does not reset this record.
 */
struct qdx_tc_command {
	struct qdx_owner holder;
	struct qdx_tc_owner *owner;
	struct qdx_request *request;
	spinlock_t lock;
	struct qdx_result result;
	u8 reply[sizeof(struct qdx_shaper_message)];
	size_t reply_length;
	bool replied;
	bool malformed_reply;
	struct completion recipient_done;
};

enum qdx_tc_node_operation {
	QDX_TC_NODE_ALLOC,
	QDX_TC_NODE_MEMORY,
	QDX_TC_NODE_CONFIG,
	QDX_TC_NODE_ATTACH,
	QDX_TC_NODE_DETACH,
	QDX_TC_NODE_FREE,
	QDX_TC_NODE_OPERATIONS,
};

/* Closing controls new queries; the original request/recipient still drains
 * independently after CLOSED. Reset only for a new hardware allocation.
 */
enum qdx_tc_stats_close {
	QDX_TC_STATS_OPEN,
	QDX_TC_STATS_CLOSING,
	QDX_TC_STATS_CLOSED,
};

struct qdx_tc_collector {
	struct qdx_tc_command command;
	struct gnet_stats_hw_source *source;
	struct gnet_stats_hw_source *query_source;
	unsigned long next_query;
	enum qdx_tc_stats_close close;
	bool requested;
	bool stale;
	bool detached;
};

struct qdx_tc_node {
	struct list_head list;
	refcount_t refs;
	struct qdx_tc_tree *tree;
	struct qdx_tc_node *parent;
	/* Borrowed from this tree: optional execution-only TBF peak GROUP. */
	struct qdx_tc_node *tbf_peak;
	struct qdx_endpoint *endpoint;
	/* Identities only after the current native callback/traversal ends. */
	struct Qdisc *native;
	unsigned long native_class;
	u32 handle;
	u32 classid;
	u32 tag;
	enum qdx_shaper_kind kind;
	union qdx_shaper_parameters parameters;
	struct qdx_tc_command command[QDX_TC_NODE_OPERATIONS];
	struct qdx_tc_collector stats;
	struct qdx_dma *flows_memory;
	size_t flows_memory_size;
	struct qdx_tc_queue *queue;
	struct qdx_tc_queue_owner queue_owner;
	struct qdx_tx_path *path;
	struct qdx_resource_wait drain_wait;
	u16 qid;
	u16 band;
	u16 bands;
	u8 priomap[TC_PRIO_MAX + 1];
	struct tcf_block *native_block; /* Identity only in an immutable view. */
	u64 token;
	bool fq;
	bool allocated;
	bool configured;
	bool linked;
	bool retiring;
	bool access_ended;
	bool probability_reported;
	bool memory_queried;
	u32 memory_per_flow;
	bool native_leaf;
	bool native_dead;
	bool restore_config;
	union qdx_shaper_parameters attempted;
};

struct qdx_tc_leaf {
	u16 minor;
	u16 qid;
	struct qdx_tc_node *node;
};

/* Only actual explicit HTB native queue assignments, not a scheduler copy. */
struct qdx_tc_selection {
	u16 major;
	u16 default_minor;
	u16 count;
	struct qdx_tc_leaf leaves[];
};

struct qdx_tc_tree {
	struct list_head list;
	refcount_t refs;
	struct qdx_tc_owner *owner;
	struct list_head nodes;
	struct qdx_tc_node *root;
	struct qdx_tc_node *htb_parent; /* Borrowed from the actual node list. */
	/* The native request identifies this tree's single output budget.
	 * The concrete provider owns its encoded row and gate; this node is a
	 * borrow from nodes, not a second native class or statistics sink.
	 */
	struct qdx_tc_node *peak_node;
	struct qdx_tc_peak_params peak_parameters;
	struct qdx_tc_peak *peak;
	struct qdx_endpoint *endpoint;
	struct qdx_tc_command root_command;
	struct qdx_tc_command default_command;
	struct qdx_tc_tree *previous_root;
	struct qdx_tc_selection __rcu *selection;
	struct qdx_tc_selection *selection_storage[2];
	struct qdx_tc_node **packet_nodes;
	u16 packet_queues;
	u32 root_handle;
	u32 default_class;
	u16 normal_direct_count;
	u16 class_capacity;
	bool explicit_htb;
	bool ingress;
	bool rooted;
	bool defaulted;
	bool retiring;
	bool native_dead;
	bool held;
	int hold_error;
	bool cancelled;
	bool prospective;
};

/* Fixed, bounded match facts. A zero mask is unknown, never a guessed value. */
struct qdx_tc_fields {
	u8 source_mac[ETH_ALEN];
	u8 destination_mac[ETH_ALEN];
	__be16 classifier_protocol;
	__be16 protocol;
	__be32 source_ipv4;
	__be32 destination_ipv4;
	struct in6_addr source_ipv6;
	struct in6_addr destination_ipv6;
	__be16 source_port;
	__be16 destination_port;
	u32 priority;
	u32 ingress_ifindex;
	u16 vlan_tci[2];
	__be16 vlan_protocol[2];
	__be16 vlan_payload_protocol[2];
	u8 ip_protocol;
	u8 ip_tos;
	u16 address_type;
	u8 vlan_depth;
};

enum qdx_tc_action_kind {
	QDX_TC_PASS,
	QDX_TC_DROP,
	QDX_TC_SET_PRIORITY,
	QDX_TC_REDIRECT_IFB,
	QDX_TC_MIRROR,
};

struct qdx_tc_action {
	unsigned long identity;
	enum flow_action_id id;
	int control;
	u32 flags;
	u8 hw_stats;
	struct net_device *target;
	u32 priority;
};

struct qdx_tc_rule {
	struct list_head list;
	refcount_t refs;
	struct qdx_tc_owner *owner;
	struct qdx_tc_block *block;
	struct tcf_block *native_block;
	unsigned long cookie;
	unsigned long replace_cookie;
	struct qdx_tc_action actions[TCA_ACT_MAX_PRIO];
	unsigned int nr_actions;
	struct net_device *target;
	struct qdx_tc_fields key;
	struct qdx_tc_fields mask;
	enum qdx_tc_action_kind action;
	u32 priority_after;
	u32 classid;
	u32 chain;
	u32 filter_priority;
	__be16 protocol;
	u32 flags;
	u32 action_flags;
	u8 hw_stats;
	bool matchall;
	bool native_count;
	bool memo_only;
	bool release_igs;
	bool installed;
	bool configured;
	bool continued;
	bool attached;
	bool retiring;
	bool native_current;
	u64 member_sequence;
	struct qdx_endpoint *endpoint;
	struct qdx_service *service;
	u16 rule_slot;
	u16 mask_slot;
	bool slot_reserved;
	struct qdx_rx_use *rx;
	struct qdx_rx_use *resume_rx;
	struct qdx_endpoint *source_endpoint;
	bool held;
	struct qdx_receiver *receiver;
	struct qdx_tc_igs *igs;
	struct qdx_tc_match *table;
	struct qdx_tc_rule *old;
	struct qdx_tc_rule *replacement;
	struct qdx_match_config profile;
	union {
		struct qdx_match_vow vow;
		struct qdx_match_l2 l2;
		struct qdx_mirror_config mirror;
	} wire;
	struct qdx_tc_command configure;
	struct qdx_tc_command install;
	struct qdx_tc_command remove;
	struct qdx_tc_command source_attach;
	struct qdx_tc_command source_detach;
};

/* One real MATCH table, its two mask slots and actual source attachment. */
struct qdx_tc_match {
	struct qdx_service *service;
	struct qdx_endpoint *endpoint;
	struct qdx_receiver *receiver;
	struct qdx_rx_use *rx;
	struct qdx_rx_use *resume_rx;
	struct qdx_endpoint *source_endpoint;
	bool held;
	struct qdx_match_config profile;
	unsigned long rules;
	u16 mask_users[QDX_MATCH_MASKS];
	struct qdx_tc_command configure;
	struct qdx_tc_command attach;
	struct qdx_tc_command detach;
	bool configured;
	bool attached;
	bool retiring;
};

struct qdx_tc_view {
	struct list_head list;
	refcount_t refs;
	struct qdx_tc_owner *owner;
	struct qdx_tc_tree *tree;
	struct qdx_tc_rule **rules;
	unsigned int nr_rules;
	struct qdx_tc_view_block *blocks;
	unsigned int nr_blocks;
	bool neutral;
	bool members_ready;
	bool available;
	bool invalid;
};

struct qdx_tc_block {
	struct list_head list;
	refcount_t refs;
	struct qdx_tc_owner *owner;
	struct tcf_block *native;
	enum flow_block_binder_type binder;
	bool dead;
	bool replay_needed;
};

struct qdx_tc_view_block {
	struct qdx_tc_block *block;
	struct tcf_block *native;
	u64 sequence;
};

struct qdx_tc_owner {
	struct list_head list;
	refcount_t refs;
	struct net_device *dev;
	struct qdx_service *service;
	struct qdx_endpoint *endpoint;
	struct qdx_tc_command assign;
	struct qdx_tc_command unassign;
	/* Borrowed from its owner-list node: first actual ALLOC, including its
	 * pending request and full retirement. SET_ROOT never changes this.
	 */
	struct qdx_tc_node *root_allocation;
	u32 shaper;
	bool assigned;
	struct qdx_binding *port;
	struct qdx_binding *binding;
	const struct qdx_tc_port_ops *port_ops;
	enum qdx_tc_direction direction;
	struct mutex cfg;
	spinlock_t data_lock;
	struct delayed_work work;
	/* One RTNL synchronous retire waiter, signalled by existing node waits. */
	struct completion drain_progress;
	struct list_head trees;
	struct list_head blocks;
	struct list_head rules;
	struct list_head associations;
	struct list_head views;
	struct qdx_binding_use port_use;
	struct qdx_tc_view *pending;
	struct qdx_tc_view *available;
	struct ifb_binding *ifb;
	struct qdx_tc_ifb *ifb_state;
	struct qdx_tc_match match;
	struct ida tags;
	bool closing;
	bool native_dead;
	bool replay_needed;
};

extern bool qdx_tc_exit_draining;

bool qdx_tc_owner_get(void *object);
void qdx_tc_owner_put(void *object);
void qdx_tc_schedule(struct qdx_tc_owner *owner);
int qdx_tc_invalidate(struct qdx_tc_owner *owner, bool pending, bool may_sleep);
int qdx_tc_setup(struct qdx_tc_owner *owner, enum tc_setup_type type, void *data);
int qdx_tc_setup_block(struct qdx_tc_owner *owner, struct tcf_block *block,
		       enum flow_block_binder_type binder, enum tc_setup_type type,
		       void *data);
int qdx_tc_view_acquire(struct net_device *dev, enum qdx_tc_direction direction,
			struct qdx_binding_use *use, const struct qdx_owner *consumer,
			int (*invalidate)(void *consumer, bool may_sleep),
			struct qdx_tc_view **result);
void qdx_tc_view_put(struct qdx_tc_view *view);
int qdx_tc_view_observe(struct qdx_tc_view *view, struct tcf_block *block,
			u64 sequence);
void qdx_tc_command_init(struct qdx_tc_command *command,
			 struct qdx_tc_owner *owner, const struct qdx_owner *holder);
int qdx_tc_command_start(struct qdx_tc_command *command,
			 struct qdx_endpoint *endpoint, u32 opcode,
			 const void *payload, size_t length,
			 const struct qdx_reply_bounds *bounds);
int qdx_tc_command_wait(struct qdx_tc_command *command);
void qdx_tc_command_clear(struct qdx_tc_command *command);

bool qdx_tc_node_get(void *object);
void qdx_tc_node_put(void *object);
struct qdx_tc_node *qdx_tc_enqueue_node(struct qdx_tc_node *node);
bool qdx_tc_tree_get(void *object);
void qdx_tc_tree_put(void *object);
int qdx_tc_tree_prepare(struct qdx_tc_owner *owner, struct qdx_tc_view *view);
int qdx_tc_tree_retire(struct qdx_tc_tree *tree, bool synchronous);
int qdx_tc_tree_publish(struct qdx_tc_tree *tree);
int qdx_tc_qdisc_setup(struct qdx_tc_owner *owner, enum tc_setup_type type, void *data);
int qdx_tc_htb_setup(struct qdx_tc_owner *owner,
		     struct tc_htb_qopt_offload *offload);
bool qdx_tc_select_queue(struct qdx_tc_owner *owner,
			 const struct sk_buff *skb, u16 *queue);
void qdx_tc_stats_request(struct qdx_tc_node *node);
void qdx_tc_stats_collect(struct qdx_tc_node *node);
void qdx_tc_stats_detach(struct qdx_tc_node *node);
bool qdx_tc_stats_drained(struct qdx_tc_node *node);

int qdx_tc_block_setup(struct qdx_tc_block *block,
		       enum tc_setup_type type, void *data);
int qdx_tc_members_prepare(struct qdx_tc_owner *owner,
			   struct qdx_tc_view *view);
int qdx_tc_project(struct qdx_binding *provider,
		   const struct qdx_tc_position *position,
		   const struct flow_rule *facts,
		   const struct qdx_packet_geometry *geometry,
		   struct qdx_binding_use *use, const struct qdx_owner *consumer,
		   int (*invalidate)(void *consumer, bool may_sleep),
		   struct qdx_tc_ref **result);
void qdx_tc_projection_put(struct qdx_tc_ref *reference);
void qdx_tc_rule_put(void *object);
void qdx_tc_rules_retire(struct qdx_tc_owner *owner);
int qdx_tc_rules_activate(struct qdx_tc_owner *owner, struct qdx_tc_view *view);
int qdx_tc_ifb_bind(struct qdx_tc_owner *owner);
int qdx_tc_ifb_prepare(struct qdx_tc_owner *owner);
int qdx_tc_ifb_retire(struct qdx_tc_owner *owner);
int qdx_tc_ifb_tree_prepare(struct qdx_tc_tree *tree);
void qdx_tc_ifb_tree_close(struct qdx_tc_tree *tree);
int qdx_tc_ifb_tree_drained(struct qdx_tc_tree *tree);
int qdx_tc_ifb_node_drained(struct qdx_tc_node *node);
void qdx_tc_ifb_progress(struct qdx_tc_owner *owner);
void qdx_tc_ifb_native(struct qdx_tc_owner *owner);
int qdx_tc_igs_prepare(struct qdx_tc_rule *rule);
int qdx_tc_igs_retire(struct qdx_tc_igs *association);
bool qdx_tc_igs_available_locked(const struct qdx_tc_igs *association);
const struct qdx_tc_view *qdx_tc_igs_view(const struct qdx_tc_igs *association);

#endif
