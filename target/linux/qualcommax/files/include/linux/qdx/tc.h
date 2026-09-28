/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_QDX_TC_H
#define _LINUX_QDX_TC_H

#include <linux/err.h>
#include <linux/qdx.h>
#include <linux/qdx/vlan.h>
#include <net/flow_offload.h>

struct Qdisc;
struct tcf_block;
struct qdx_tc_queue;
struct qdx_tc_peak;

enum qdx_tc_direction { QDX_TC_INGRESS, QDX_TC_EGRESS };

struct qdx_tc_position {
	struct net_device *dev;
	enum qdx_tc_direction direction;
};

enum qdx_tc_effect {
	QDX_TC_CLASS = BIT(0),
	QDX_TC_IGS = BIT(1),
	QDX_TC_PRIORITY = BIT(2),
};

struct qdx_tc_ops;
/* Immutable while the actual consumer use is retained. A zero effects mask
 * denotes a proven neutral position, not a missing provider. Priority is a
 * native-visible obligation: the flow encoder must represent its complete
 * effect, including all subsequent class and VLAN decisions.
 */
struct qdx_tc_ref {
	struct qdx_binding_use *use;
	const struct qdx_tc_ops *ops;
	unsigned int effects;
	struct qdx_endpoint *class_endpoint;
	u32 class_tag; /* Complete node tag used by egress packet/flow execution. */
	struct qdx_endpoint *igs_endpoint;
	u32 igs_tag; /* Compact 16-bit ingress-flow tag, not the full node tag. */
	u32 priority_after;
	/* Actual projection proofs, never inferred merely from CLASS/IGS bits.
	 * A fixed class uses neither value. output_priority_used requires this
	 * position's PRIORITY effect; input refers to the supplied geometry.
	 */
	bool input_priority_used;
	bool output_priority_used;
};

struct qdx_tc_ops {
	/* RTNL, except select_queue. The concrete native port registration is
	 * retained by the caller. Setup routes removal before feature admission.
	 * Block identities remain borrowed until this exact native UNBIND.
	 */
	int (*setup_tc)(struct qdx_binding *provider,
			struct qdx_binding *port, enum tc_setup_type type, void *data);
	int (*setup_block)(struct qdx_binding *provider,
			   struct qdx_binding *port, struct tcf_block *block,
			   enum flow_block_binder_type binder,
			   enum tc_setup_type type, void *data);
	/* A live explicit root retains its actual provider lifetime. False means
	 * regular/direct selection, not permission to bypass a scope hold.
	 */
	bool (*select_queue)(struct qdx_binding *provider,
			     struct net_device *dev, const struct sk_buff *skb,
			     u16 *queue);
	int (*get)(struct qdx_binding *provider,
		   const struct qdx_tc_position *position,
		   const struct flow_rule *facts,
		   const struct qdx_packet_geometry *geometry,
		   struct qdx_binding_use *use,
		   const struct qdx_owner *consumer,
		   int (*invalidate)(void *consumer, bool may_sleep),
		   struct qdx_tc_ref **result);
	/* Frees the reference while the caller still retains its consumer use. */
	void (*put)(struct qdx_tc_ref *reference);
};

/* Concrete native port service, published at QDX_BINDING_TC_PORT with the
 * actual user netdevice and identity NULL. It owns hardware resources and
 * fixed queue identities; it does not classify packets or interpret policy.
 * The registration has no permanent qdx-tc module reference.
 */
struct qdx_tc_queue_owner {
	struct Qdisc *root;
	unsigned long class;
};

struct qdx_tc_queue_ops {
	/* RTNL + the TC owner's cfg, then the concrete resource mutex. Native
	 * identities are borrowed for these calls, never dereferenced afterwards.
	 * U16_MAX selects any free class slot; an exact qid must really be free.
	 * Success returns one owned slot and its fixed real user queue number.
	 */
	int (*reserve)(struct qdx_binding *port,
		       const struct qdx_tc_queue_owner *owner, u16 requested,
		       struct qdx_tc_queue **slot, u16 *queue);
	/* Change only the actual native claim after a successful native queue
	 * operation. NULL ends that claim. Execution retirement never calls this
	 * implicitly; transfer preserves the same qid and requires old users ended.
	 */
	int (*claim)(struct qdx_tc_queue *slot,
		     const struct qdx_tc_queue_owner *owner);
	/* RTNL, outside TC cfg: activate the real prefix before native publication.
	 * Shrinking is internal to release and cannot cross any live/retiring slot.
	 */
	int (*activate)(struct qdx_tc_queue *slot);
	/* Generates a new boot-unique token and prepares this actual slot's path
	 * through qdx_tx_prepare. No execution selection is published yet. Caller
	 * owns the returned path; a failed attempt cannot recycle an exposed token.
	 */
	int (*execution_prepare)(struct qdx_tc_queue *slot,
				 struct qdx_endpoint *endpoint, u32 tag,
				 enum qdx_disposition disposition,
				 struct qdx_tx_path **path, u64 *token);
	/* Retains its own path reference. Requires the already activated qid and
	 * the exact prepared slot/token; no lookup of a replacement association.
	 */
	int (*publish)(struct qdx_tc_queue *slot, struct qdx_tx_path *path);
	/* Sleepable; no RTNL acquisition or callback into TC cfg. A repeated hold
	 * confirms actual stopping. Retirement irreversibly closes the old token,
	 * while a still-live native claim remains usable for queue selection.
	 */
	int (*hold)(struct qdx_tc_queue *slot);
	int (*retire)(struct qdx_tc_queue *slot);
	/* RTNL, outside TC cfg. current_root is a current operation borrow, or
	 * NULL after real unlink/reset. Checks public native caches, native claim,
	 * readers and accepted users. -EINPROGRESS retains the owned slot; zero
	 * consumes it. A queue cannot be reused merely because hardware detached.
	 */
	int (*release)(struct qdx_tc_queue *slot, struct Qdisc *current_root);
};

/* One common physical-output budget, charged by the actual port meter.
 * Rate is bytes/second from the native offer; burst is not timer-expanded.
 */
struct qdx_tc_peak_params {
	u64 rate_bytes_ps;
	u32 burst_bytes;
};

struct qdx_tc_port_ops {
	u16 normal_direct_count;
	const struct qdx_tc_queue_ops *queues;
	/* RTNL + TC cfg, then native port configuration/resource locks. The
	 * caller retains this provider's binding use through final release.
	 * Prepare owns an output hold and never publishes an execution token.
	 * Even on error, a non-NULL result owns an unfinished rollback and must
	 * be released. A NULL result means no remaining acquired resource.
	 */
	int (*peak_prepare)(struct qdx_binding *port,
			    const struct qdx_tc_peak_params *parameters,
			    struct qdx_tc_peak **peak);
	/* After complete graph/queue preparation, drop only this resource's
	 * preparation hold. Failure retains the resource and its output hold.
	 */
	int (*peak_publish)(struct qdx_tc_peak *peak);
	/* After producer/firmware/accepted retirement, restore the owned row
	 * while original path holds still prevent CPU handback. Zero consumes
	 * the handle; failure retains it and the hold for explicit cleanup.
	 */
	int (*peak_release)(struct qdx_tc_peak *peak);
	/* RTNL. Uses this exact native block/binder callback, preserving native
	 * counts and replay error unwind. It never manufactures a binding.
	 */
	int (*replay)(struct qdx_binding *port, struct tcf_block *block,
		      enum flow_block_binder_type binder, bool add,
		      struct netlink_ext_ack *extack);
};

/* Prepared-view lookup only: no RTNL, native policy walk or TC cfg lock.
 * The facts' actions are ignored. Unknown match bits remain unknown.
 * On success, the caller owns exactly one populated use and one reference.
 */
static inline int qdx_tc_position_get(const struct qdx_tc_position *position,
		const struct flow_rule *facts,
		const struct qdx_packet_geometry *geometry,
		struct qdx_binding_use *use, const struct qdx_owner *consumer,
		int (*invalidate)(void *consumer, bool may_sleep),
		struct qdx_tc_ref **result)
{
	const struct qdx_binding_key key = { .role = QDX_BINDING_TC_PROVIDER };
	struct qdx_binding *provider = qdx_binding_lookup(&key);
	const struct qdx_tc_ops *ops;
	int err;

	*result = NULL;
	if (IS_ERR(provider))
		return PTR_ERR(provider);
	if (!provider)
		return -EOPNOTSUPP;
	ops = qdx_binding_ops(provider);
	err = ops->get(provider, position, facts, geometry, use, consumer,
		       invalidate, result);
	qdx_binding_put(provider);
	return err;
}

static inline void qdx_tc_ref_put(struct qdx_tc_ref *reference)
{
	struct qdx_binding_use *use = reference->use;

	reference->ops->put(reference);
	qdx_binding_use_put(use);
}

#endif
