// SPDX-License-Identifier: GPL-2.0-only
#include <linux/etherdevice.h>
#include <linux/if_vlan.h>
#include <linux/overflow.h>
#include <linux/qdx/bridge.h>
#include <linux/qdx/tc.h>
#include <linux/qdx/tunnel.h>
#include <linux/rtnetlink.h>
#include <net/pkt_cls.h>
#include <net/sch_generic.h>
#include <net/tcx.h>
#include "flow.h"

struct qdx_flow_position {
	struct list_head node;
	struct net_device *dev;
	unsigned int hooknum;
	bool anchor;
	struct tcf_block *block;
	u64 sequence;
	struct qdx_binding_use tc_use;
	struct qdx_tc_ref *tc;
	bool released;
};

struct qdx_flow_vlan_view {
	struct list_head node;
	struct qdx_vlan_path path;
	bool released;
};

struct qdx_flow_bridge_view {
	struct list_head node;
	struct qdx_bridge_path path;
	bool released;
};

struct qdx_flow_side {
	struct net_device *dev;
	struct qdx_endpoint *physical;
	struct qdx_endpoint *execution;
	struct qdx_rx_use *rx;
	struct qdx_pppoe_use session;
	struct qdx_binding *preparation;
	struct qdx_binding *vlan_preparation[QDX_VLAN_DEPTH];
	struct qdx_vlan_endpoint_use vlan_lower[QDX_VLAN_DEPTH];
	struct qdx_endpoint *class_endpoint;
	struct qdx_endpoint *igs_endpoint;
	struct qdx_packet_geometry transmit;
	u32 class_tag;
	u16 igs_tag;
	u16 mtu;
	bool has_class;
	bool has_igs;
	bool released;
};

struct qdx_flow_paths {
	struct list_head positions;
	struct list_head vlans;
	struct list_head bridges;
	struct qdx_flow_side side[2];
};

static int qdx_flow_any_filter(struct tcf_proto *tp, void *node,
			       struct tcf_walker *walker)
{
	walker->nonempty = true;
	walker->stop = 1;
	return 0;
}

bool qdx_flow_paths_available(struct qdx_flow *flow)
{
	struct qdx_flow_paths *paths = flow->paths;
	struct qdx_flow_position *position;
	struct qdx_flow_vlan_view *vlan;
	struct qdx_flow_bridge_view *bridge;
	int i, j;

	/* Caller holds the common use lock and the flow data lock. */
	if (!paths)
		return false;
	list_for_each_entry(position, &paths->positions, node)
		if (position->tc && !qdx_use_available_locked(&position->tc_use))
			return false;
	list_for_each_entry(vlan, &paths->vlans, node)
		if (!qdx_use_available_locked(&vlan->path.use))
			return false;
	list_for_each_entry(bridge, &paths->bridges, node)
		if (!qdx_use_available_locked(&bridge->path.use))
			return false;
	for (i = 0; i < 2; i++) {
		if (paths->side[i].session.use.linked &&
		    !qdx_use_available_locked(&paths->side[i].session.use))
			return false;
		for (j = 0; j < QDX_VLAN_DEPTH; j++)
			if (paths->side[i].vlan_lower[j].use.linked &&
			    !qdx_use_available_locked(&paths->side[i].vlan_lower[j].use))
				return false;
	}
	return true;
}

int qdx_flow_paths_nf_check(struct qdx_flow *flow)
{
	struct qdx_flow_position *position;
	struct nf_netdev_hook_position hooks;
	int error;

	lockdep_assert_held(&flow->domain->cfg);
	if (!flow->paths || !flow->table || !flow->native)
		return -ENOENT;
	list_for_each_entry(position, &flow->paths->positions, node) {
		error = nf_netdev_hook_position(position->dev, position->hooknum,
			position->anchor ? flow->table : NULL, &hooks);
		if (error)
			return error;
		if (position->anchor ? hooks.anchor_index != 0 : hooks.live_count != 0)
			return -EOPNOTSUPP;
	}
	return 0;
}

int qdx_flow_paths_hold(struct qdx_flow *flow)
{
	int i, error = 0, result;

	if (!flow->paths)
		return -EINVAL;
	for (i = 0; i < 2; i++) {
		if (!flow->paths->side[i].rx)
			continue;
		result = qdx_rx_hold(flow->paths->side[i].rx);
		if (result && !error)
			error = result;
	}
	return error;
}

void qdx_flow_paths_account(struct qdx_flow *flow)
{
	struct qdx_flow_side_delta pending[2];
	int i;

	lockdep_assert_held(&flow->domain->cfg);
	spin_lock_bh(&flow->data_lock);
	memcpy(pending, flow->pending_ppp, sizeof(pending));
	memset(flow->pending_ppp, 0, sizeof(flow->pending_ppp));
	spin_unlock_bh(&flow->data_lock);
	if (!memchr_inv(pending, 0, sizeof(pending)))
		return;
	if (!flow->paths)
		return;
	for (i = 0; i < 2; i++) {
		struct qdx_flow_side *side = &flow->paths->side[i];
		struct ppp_offload_stats delta;
		u64 overhead;

		if (!side->session.use.linked)
			continue;
		if (check_mul_overflow(pending[i].tx.packets,
			(u64)(ETH_HLEN + side->transmit.tag_count * VLAN_HLEN + PPPOE_SES_HLEN),
			&overhead) || pending[i].tx.bytes < overhead) {
			pr_warn_ratelimited("qdx-flow: PPP frame byte accounting outside captured geometry\n");
			continue;
		}
		delta = (struct ppp_offload_stats) {
			.rx_packets = pending[i].rx.packets, .rx_bytes = pending[i].rx.bytes,
			.tx_packets = pending[i].tx.packets, .tx_bytes = pending[i].tx.bytes - overhead,
		};
		qdx_pppoe_account(&side->session, &delta);
	}
}

bool qdx_flow_paths_release(struct qdx_flow *flow)
{
	struct qdx_flow_paths *paths = flow->paths;
	struct qdx_flow_position *position, *next_position;
	struct qdx_flow_vlan_view *vlan, *next_vlan;
	struct qdx_flow_bridge_view *bridge, *next_bridge;
	bool drained = true;
	int i, j;

	lockdep_assert_held(&flow->domain->cfg);
	if (!paths)
		return true;
	list_for_each_entry(position, &paths->positions, node) {
		if (!position->released) {
			if (position->tc)
				qdx_tc_ref_put(position->tc);
			position->tc = NULL;
			position->released = true;
		}
		drained &= !refcount_read(&position->tc_use.deliveries);
	}
	list_for_each_entry(vlan, &paths->vlans, node) {
		if (!vlan->released) {
			qdx_vlan_path_put(&vlan->path);
			vlan->released = true;
		}
		drained &= !refcount_read(&vlan->path.use.deliveries);
	}
	list_for_each_entry(bridge, &paths->bridges, node) {
		if (!bridge->released) {
			qdx_bridge_path_put(&bridge->path);
			bridge->released = true;
		}
		drained &= !refcount_read(&bridge->path.use.deliveries);
	}
	for (i = 0; i < 2; i++) {
		struct qdx_flow_side *side = &paths->side[i];

		if (!side->released) {
			if (side->session.use.linked)
				qdx_pppoe_session_put(&side->session);
			if (side->preparation)
				qdx_pppoe_session_prepare_put(side->preparation);
			side->preparation = NULL;
			for (j = QDX_VLAN_DEPTH - 1; j >= 0; j--) {
				if (side->vlan_lower[j].use.linked)
					qdx_vlan_endpoint_put(&side->vlan_lower[j]);
				if (side->vlan_preparation[j])
					qdx_vlan_endpoint_prepare_put(side->vlan_preparation[j]);
				side->vlan_preparation[j] = NULL;
			}
			side->released = true;
		}
		drained &= !refcount_read(&side->session.use.deliveries);
		for (j = 0; j < QDX_VLAN_DEPTH; j++)
			drained &= !refcount_read(&side->vlan_lower[j].use.deliveries);
		if (side->rx) {
			if (qdx_rx_release(side->rx))
				drained = false;
			else
				side->rx = NULL;
		}
	}
	if (!drained)
		return false;
	/* No old shared delivery may touch these embedded use addresses now. */
	spin_lock_bh(&flow->domain->index_lock);
	flow->paths = NULL;
	spin_unlock_bh(&flow->domain->index_lock);
	list_for_each_entry_safe(position, next_position, &paths->positions, node) {
		dev_put(position->dev);
		kfree(position);
	}
	list_for_each_entry_safe(vlan, next_vlan, &paths->vlans, node)
		kfree(vlan);
	list_for_each_entry_safe(bridge, next_bridge, &paths->bridges, node)
		kfree(bridge);
	for (i = 0; i < 2; i++)
		qdx_endpoint_put(paths->side[i].physical);
	kfree(paths);
	return true;
}

int qdx_flow_nf_event(struct notifier_block *nb, unsigned long event, void *data)
{
	const struct nf_netdev_hook_change *change = data;
	struct qdx_flow_domain *domain;
	struct qdx_flow_position *position;
	struct qdx_flow *flow;
	bool matches;

	mutex_lock(&qdx_flow_domains_lock);
	list_for_each_entry(domain, &qdx_flow_domains, node) {
		mutex_lock(&domain->cfg);
		list_for_each_entry(flow, &domain->flows, node) {
			matches = false;
			spin_lock_bh(&domain->index_lock);
			if (flow->paths)
				list_for_each_entry(position, &flow->paths->positions, node)
					matches |= position->dev == change->dev && position->hooknum == change->hooknum;
			spin_unlock_bh(&domain->index_lock);
			if (matches && qdx_flow_paths_nf_check(flow))
				qdx_flow_withdraw(flow);
		}
		mutex_unlock(&domain->cfg);
	}
	mutex_unlock(&qdx_flow_domains_lock);
	return NOTIFY_DONE;
}

int qdx_flow_tc_event(struct notifier_block *nb, unsigned long event, void *data)
{
	const struct tcf_block_event *change = data;
	struct qdx_flow_domain *domain;
	struct qdx_flow_position *position;
	struct qdx_flow *flow;
	bool matches;

	mutex_lock(&qdx_flow_domains_lock);
	list_for_each_entry(domain, &qdx_flow_domains, node) {
		mutex_lock(&domain->cfg);
		list_for_each_entry(flow, &domain->flows, node) {
			matches = false;
			spin_lock_bh(&domain->index_lock);
			if (flow->paths)
				list_for_each_entry(position, &flow->paths->positions, node)
					matches |= position->block == change->block && position->sequence != change->sequence;
			spin_unlock_bh(&domain->index_lock);
			if (matches)
				qdx_flow_withdraw(flow);
		}
		mutex_unlock(&domain->cfg);
	}
	mutex_unlock(&qdx_flow_domains_lock);
	return NOTIFY_DONE;
}

int qdx_flow_netdev_event(struct notifier_block *nb, unsigned long event, void *data)
{
	struct net_device *dev = netdev_notifier_info_to_dev(data);
	struct qdx_flow_domain *domain;
	struct qdx_flow_position *position;
	struct qdx_flow *flow;
	bool matches;

	switch (event) {
	case NETDEV_UNREGISTER:
	case NETDEV_DOWN:
	case NETDEV_CHANGEMTU:
	case NETDEV_CHANGEADDR:
	case NETDEV_CHANGEUPPER:
	case NETDEV_CHANGE_TC:
	case NETDEV_FEAT_CHANGE:
		break;
	default:
		return NOTIFY_DONE;
	}
	mutex_lock(&qdx_flow_domains_lock);
	list_for_each_entry(domain, &qdx_flow_domains, node) {
		mutex_lock(&domain->cfg);
		list_for_each_entry(flow, &domain->flows, node) {
			matches = false;
			spin_lock_bh(&domain->index_lock);
			if (flow->paths)
				list_for_each_entry(position, &flow->paths->positions, node)
					matches |= position->dev == dev;
			spin_unlock_bh(&domain->index_lock);
			if (matches)
				qdx_flow_withdraw(flow);
		}
		mutex_unlock(&domain->cfg);
	}
	mutex_unlock(&qdx_flow_domains_lock);
	return NOTIFY_DONE;
}

static int qdx_flow_neutral_tc(struct qdx_flow *flow,
			       struct qdx_flow_position *position)
{
	struct net_device *dev = position->dev;
	struct tcf_block_state before, after;
	struct netdev_queue *queue;
	struct tcf_chain *chain;
	struct tcf_proto *proto;
	struct Qdisc *qdisc;
	struct tcf_block *block = NULL;
	bool ingress = position->hooknum == NF_NETDEV_INGRESS;
	bool nonempty = false;
	unsigned int i;

	ASSERT_RTNL();
	if (!ingress) {
		qdisc = rtnl_dereference(dev->qdisc);
		if (qdisc->handle)
			return -EOPNOTSUPP;
		for (i = 0; i < dev->num_tx_queues; i++) {
			queue = netdev_get_tx_queue(dev, i);
			qdisc = rtnl_dereference(queue->qdisc_sleeping);
			if (qdisc->handle)
				return -EOPNOTSUPP;
		}
	}
	queue = dev_ingress_queue(dev);
	if (!queue)
		return 0;
	qdisc = rtnl_dereference(queue->qdisc_sleeping);
	if (qdisc->ops->cl_ops && qdisc->ops->cl_ops->tcf_block)
		block = qdisc->ops->cl_ops->tcf_block(qdisc,
			TC_H_MIN(ingress ? TC_H_MIN_INGRESS : TC_H_MIN_EGRESS), NULL);
	if (!block)
		return 0;
	/* Link the borrowed identity before the first native membership read.
	 * RTNL protects this actual attachment, not concurrent unlocked filters.
	 */
	spin_lock_bh(&flow->domain->index_lock);
	position->block = block;
	spin_unlock_bh(&flow->domain->index_lock);
	tcf_block_read_state(block, &before);
	for (chain = tcf_get_next_chain(block, NULL); chain;
	     chain = tcf_get_next_chain(block, chain)) {
		for (proto = tcf_get_next_proto(chain, NULL); proto;
		     proto = tcf_get_next_proto(chain, proto)) {
			struct tcf_walker walker = { .fn = qdx_flow_any_filter };

			if (!proto->ops->walk) {
				nonempty = true;
				continue;
			}
			proto->ops->walk(proto, &walker, true);
			nonempty |= walker.nonempty || walker.count;
		}
	}
	tcf_block_read_state(block, &after);
	if (nonempty || before.active || after.active || before.sequence != after.sequence)
		return -EOPNOTSUPP;
	spin_lock_bh(&flow->domain->index_lock);
	position->sequence = after.sequence;
	spin_unlock_bh(&flow->domain->index_lock);
	return 0;
}

static int qdx_flow_position_add(struct qdx_flow *flow, struct net_device *dev,
		unsigned int hooknum, bool anchor, struct flow_rule *facts,
		struct qdx_packet_geometry *geometry, unsigned int side,
		bool *priority_pending)
{
	struct qdx_tc_position tc_position = { .dev = dev,
		.direction = hooknum == NF_NETDEV_INGRESS ? QDX_TC_INGRESS : QDX_TC_EGRESS };
	struct qdx_flow_position *position;
	struct qdx_owner owner = qdx_flow_owner(flow);
	struct nf_netdev_hook_position nf;
#if IS_ENABLED(CONFIG_NET_XGRESS)
	struct bpf_mprog_entry *entry;
#endif
	struct qdx_flow_side *output = &flow->paths->side[side];
	struct nf_flow_key *fact_key = facts->match.key, *fact_mask = facts->match.mask;
	unsigned int i, count = 0;
	int error;

	position = kzalloc(sizeof(*position), GFP_KERNEL);
	if (!position)
		return -ENOMEM;
	position->dev = dev;
	position->hooknum = hooknum;
	position->anchor = anchor;
	dev_hold(dev);
	mutex_lock(&flow->domain->cfg);
	spin_lock_bh(&flow->domain->index_lock);
	list_add_tail(&position->node, &flow->paths->positions);
	spin_unlock_bh(&flow->domain->index_lock);
	if (!flow->native || !flow->table) {
		error = -ENOENT;
	} else {
		error = nf_netdev_hook_position(dev, hooknum, anchor ? flow->table : NULL, &nf);
		if (!error && (anchor ? nf.anchor_index != 0 : nf.live_count != 0))
			error = -EOPNOTSUPP;
	}
	mutex_unlock(&flow->domain->cfg);
	if (error)
		return error;
#if IS_ENABLED(CONFIG_NET_XGRESS)
	entry = tcx_entry_fetch(dev, hooknum == NF_NETDEV_INGRESS);
	if (entry && bpf_mprog_total(entry))
		return -EOPNOTSUPP;
#endif
	/* These buffers are owned by this walk. Preserve the earlier position's
	 * snapshot in its TC reference; later native representation is new input.
	 */
	facts->match.dissector->used_keys &= ~(BIT_ULL(FLOW_DISSECTOR_KEY_VLAN) |
						 BIT_ULL(FLOW_DISSECTOR_KEY_CVLAN));
	memset(&fact_key->vlan, 0, sizeof(fact_key->vlan));
	memset(&fact_key->cvlan, 0, sizeof(fact_key->cvlan));
	memset(&fact_mask->vlan, 0, sizeof(fact_mask->vlan));
	memset(&fact_mask->cvlan, 0, sizeof(fact_mask->cvlan));
	for (i = 0; i < geometry->tag_count; i++) {
		struct flow_dissector_key_vlan *key, *mask;
		const struct qdx_vlan_tag *tag = &geometry->tags[i];
		enum flow_dissector_key_id id;

		if (tag->location == QDX_VLAN_SAVED_MAC)
			continue;
		if (count == QDX_VLAN_DEPTH)
			return -EOPNOTSUPP;
		key = count ? &fact_key->cvlan : &fact_key->vlan;
		mask = count ? &fact_mask->cvlan : &fact_mask->vlan;
		id = count ? FLOW_DISSECTOR_KEY_CVLAN : FLOW_DISSECTOR_KEY_VLAN;
		key->vlan_id = tag->tci & VLAN_VID_MASK;
		mask->vlan_id = tag->known_tci & VLAN_VID_MASK;
		key->vlan_priority = tag->tci >> VLAN_PRIO_SHIFT;
		mask->vlan_priority = tag->known_tci >> VLAN_PRIO_SHIFT;
		key->vlan_dei = !!(tag->tci & VLAN_CFI_MASK);
		mask->vlan_dei = !!(tag->known_tci & VLAN_CFI_MASK);
		key->vlan_tpid = tag->protocol;
		mask->vlan_tpid = cpu_to_be16(U16_MAX);
		facts->match.dissector->offset[id] = count ? offsetof(struct nf_flow_key, cvlan) :
			offsetof(struct nf_flow_key, vlan);
		facts->match.dissector->used_keys |= BIT_ULL(id);
		count++;
	}
	error = qdx_tc_position_get(&tc_position, facts, geometry, &position->tc_use,
		&owner, qdx_flow_invalidate, &position->tc);
	if (error == -EOPNOTSUPP || error == -ENOENT || error == -EAGAIN)
		return qdx_flow_neutral_tc(flow, position);
	if (error)
		return error;
	if (position->tc->input_priority_used)
		*priority_pending = false;
	if (position->tc->effects & QDX_TC_CLASS) {
		if (output->has_class && output->class_tag != position->tc->class_tag)
			return -EOPNOTSUPP;
		output->has_class = true;
		output->class_tag = position->tc->class_tag;
		output->class_endpoint = position->tc->class_endpoint;
	}
	if (position->tc->effects & QDX_TC_IGS) {
		if (position->tc->igs_tag > U16_MAX || output->has_igs)
			return -EOPNOTSUPP;
		output->has_igs = true;
		output->igs_tag = position->tc->igs_tag;
		output->igs_endpoint = position->tc->igs_endpoint;
	}
	if (position->tc->effects & QDX_TC_PRIORITY) {
		geometry->priority = position->tc->priority_after;
		geometry->known |= QDX_GEOMETRY_PRIORITY;
		*priority_pending = !position->tc->output_priority_used;
	}
	return 0;
}

static int qdx_flow_vlan_view(struct qdx_flow *flow, struct net_device *dev,
		struct net_device *lower, enum qdx_vlan_position position,
		struct qdx_packet_geometry *geometry, bool source_from_device)
{
	struct qdx_flow_vlan_view *view;
	struct qdx_owner owner = qdx_flow_owner(flow);
	struct qdx_vlan_request request = { .dev = dev, .immediate_lower = lower,
		.position = position, .input = *geometry,
		.source_from_device = source_from_device };
	int error;

	view = kzalloc(sizeof(*view), GFP_KERNEL);
	if (!view)
		return -ENOMEM;
	list_add_tail(&view->node, &flow->paths->vlans);
	error = qdx_vlan_path_get(&request, &owner, qdx_flow_invalidate, &view->path);
	if (error) {
		/* Get has unwound its ownership, but an admitted invalidation may
		 * still refer to this embedded use. Retirement waits for delivery.
		 */
		view->released = true;
		return error;
	}
	*geometry = view->path.output;
	return 0;
}

static int qdx_flow_bridge_view(struct qdx_flow *flow,
		const struct net_device_path *step, struct net_device *port,
		const u8 *destination)
{
	struct qdx_flow_bridge_view *view;
	struct qdx_owner owner = qdx_flow_owner(flow);
	struct qdx_bridge_request request = {
		.master = (struct net_device *)step->dev,
		.port = port,
		.vid = step->bridge.vlan_id, .vlan_mode = step->bridge.vlan_mode,
		.tx = true,
	};
	int position, error;

	ether_addr_copy(request.destination, destination);
	/* Native forwarding depends on both the local bridge position and the
	 * selected port's effective forwarding state. FDB lookup alone checks
	 * neither the port's STP/MST state nor its per-VID transmit permission.
	 */
	for (position = 0; position < 2; position++) {
		request.position_dev = position ? port : request.master;
		view = kzalloc(sizeof(*view), GFP_KERNEL);
		if (!view)
			return -ENOMEM;
		list_add_tail(&view->node, &flow->paths->bridges);
		error = qdx_bridge_path_get(&request, &owner, qdx_flow_invalidate,
					    &view->path);
		if (error) {
			view->released = true;
			return error;
		}
	}
	return 0;
}

static int qdx_flow_header(struct qdx_flow *flow, struct net_device *dev,
		struct net_device *lower, struct qdx_packet_geometry *geometry,
		bool source_from_device)
{
	if (is_vlan_dev(dev))
		return qdx_flow_vlan_view(flow, dev, lower, QDX_VLAN_HEADER,
					  geometry, source_from_device);
	/* The caller reached only the retained physical or bridge Ethernet
	 * terminal. No arbitrary third-party header_ops is invoked or inferred.
	 */
	geometry->data_overhead += ETH_HLEN;
	geometry->wire_overhead += ETH_HLEN;
	geometry->saved_mac_len = 0;
	geometry->frame_protocol = geometry->protocol;
	geometry->known |= QDX_GEOMETRY_FRAME_PROTOCOL;
	if (source_from_device) {
		ether_addr_copy(geometry->source, dev->dev_addr);
		geometry->known |= QDX_GEOMETRY_SOURCE;
	}
	return 0;
}

int qdx_flow_paths_prepare(struct qdx_flow *flow)
{
	struct qdx_flow_paths *paths;
	struct qdx_owner owner = qdx_flow_owner(flow);
	int terminal[2], i, dir, error;

	ASSERT_RTNL();
	paths = kzalloc(sizeof(*paths), GFP_KERNEL);
	if (!paths)
		return -ENOMEM;
	INIT_LIST_HEAD(&paths->positions);
	INIT_LIST_HEAD(&paths->vlans);
	INIT_LIST_HEAD(&paths->bridges);
	spin_lock_bh(&flow->domain->index_lock);
	flow->paths = paths;
	spin_unlock_bh(&flow->domain->index_lock);
	for (dir = 0; dir < 2; dir++) {
		const struct net_device_path_stack *stack = &flow->native_path->dir[!dir].stack;
		struct qdx_flow_side *side = &paths->side[dir];

		terminal[dir] = -1;
		for (i = 0; i < stack->num_paths; i++) {
			if (stack->path[i].type == DEV_PATH_DSA || stack->path[i].type == DEV_PATH_ETHERNET) {
				terminal[dir] = i;
				break;
			}
		}
		if (terminal[dir] < 0)
			return -EOPNOTSUPP;
		side->dev = (struct net_device *)stack->path[terminal[dir]].dev;
		side->physical = qdx_endpoint_get(flow->collector->service, side->dev);
		if (IS_ERR(side->physical)) {
			error = PTR_ERR(side->physical);
			side->physical = NULL;
			return error;
		}
		side->execution = side->physical;
		side->mtu = flow->native_path->dir[!dir].mtu;
	}
	for (dir = 0; dir < 2; dir++) {
		const struct nf_flow_hw_path_dir *native = &flow->native_path->dir[dir];
		const struct net_device_path_stack *stack = &native->stack;
		const struct qdx_flow_offer *offer = &flow->offers[dir];
		struct qdx_flow_side *output = &paths->side[!dir];
		struct qdx_packet_geometry geometry = {
			.protocol = offer->match.key.basic.n_proto,
			.vlan_payload_protocol = offer->match.key.basic.n_proto,
			.known = QDX_GEOMETRY_PROTOCOL | QDX_GEOMETRY_VLAN_PAYLOAD_PROTOCOL,
			.mtu = native->mtu,
			.saved_mac_len = ETH_HLEN, .wire_overhead = ETH_HLEN,
		};
		struct nf_flow_match facts_match = offer->match;
		struct flow_rule *facts = flow_rule_alloc(0);
		struct net_device *dev, *lower;
		const struct net_device_path *ppp = NULL;
		bool priority_pending = false;
		int start = -1;

		if (!facts)
			return -ENOMEM;
		facts->match = (struct flow_match) { .dissector = &facts_match.dissector,
			.key = &facts_match.key, .mask = &facts_match.mask };
		/* The captured native HW table lookup is on its flattened ingress.
		 * Do not reintroduce VLAN/PPP upper receive rounds already bypassed
		 * by that same native software flowtable.
		 */
		if (native->route.in.ifindex != paths->side[dir].dev->ifindex) {
			error = -EOPNOTSUPP;
			goto free_facts;
		}
		for (i = native->route.in.num_encaps - 1; i >= 0; i--) {
			if (native->route.in.ingress_vlans & BIT(i))
				continue;
			if (native->route.in.encap[i].proto == htons(ETH_P_PPP_SES)) {
				geometry.data_overhead += PPPOE_SES_HLEN;
				geometry.wire_overhead += PPPOE_SES_HLEN;
				geometry.protocol = htons(ETH_P_PPP_SES);
				geometry.vlan_payload_protocol = htons(ETH_P_PPP_SES);
				continue;
			}
			if (geometry.tag_count == QDX_VLAN_DEPTH) {
				error = -EOPNOTSUPP;
				goto free_facts;
			}
			geometry.tags[geometry.tag_count] = (struct qdx_vlan_tag) {
				.protocol = native->route.in.encap[i].proto,
				.tci = native->route.in.encap[i].id,
				.known_tci = VLAN_VID_MASK,
				.location = geometry.tag_count ? QDX_VLAN_IN_FRAME : QDX_VLAN_METADATA,
			};
			geometry.tag_count++;
			geometry.wire_overhead += VLAN_HLEN;
		}
		if (geometry.tag_count) {
			geometry.tags[0].location = QDX_VLAN_METADATA;
			geometry.data_overhead += (geometry.tag_count - 1) * VLAN_HLEN;
			if (geometry.tag_count > 1)
				geometry.protocol = geometry.tags[1].protocol;
		}
		error = qdx_flow_position_add(flow, paths->side[dir].dev, NF_NETDEV_INGRESS,
			true, facts, &geometry, dir, &priority_pending);
		if (error)
			goto free_facts;

		/* Native FT decapsulation and NAT precede its selected output. */
		geometry.data_overhead = 0;
		geometry.wire_overhead = 0;
		geometry.saved_mac_len = 0;
		geometry.tag_count = 0;
		geometry.protocol = offer->match.key.basic.n_proto;
		geometry.vlan_payload_protocol = offer->match.key.basic.n_proto;
		ether_addr_copy(geometry.source, offer->source);
		ether_addr_copy(geometry.destination, offer->destination);
		geometry.known |= QDX_GEOMETRY_SOURCE | QDX_GEOMETRY_DESTINATION;
		facts_match.dissector.used_keys &= ~(BIT_ULL(FLOW_DISSECTOR_KEY_VLAN) |
							 BIT_ULL(FLOW_DISSECTOR_KEY_CVLAN));
		if (offer->input.family == AF_INET) {
			facts_match.key.ipv4.src = offer->output.source.s6_addr32[0];
			facts_match.key.ipv4.dst = offer->output.destination.s6_addr32[0];
		} else {
			facts_match.key.ipv6.src = offer->output.source;
			facts_match.key.ipv6.dst = offer->output.destination;
		}
		facts_match.key.tp.src = offer->output.source_port;
		facts_match.key.tp.dst = offer->output.destination_port;
		for (i = 0; i <= terminal[!dir]; i++) {
			const struct net_device_path *step = &stack->path[i];

			if (step->type == DEV_PATH_BRIDGE) {
				if (i == terminal[!dir]) {
					error = -EOPNOTSUPP;
					goto free_facts;
				}
				error = qdx_flow_bridge_view(flow, step,
					(struct net_device *)stack->path[i + 1].dev,
					offer->destination);
				if (error)
					goto free_facts;
			}
			if (step->dev->ifindex == (native->route.xmit_type == FLOW_OFFLOAD_XMIT_DIRECT ?
				native->route.out.ifindex : native->route.dst->dev->ifindex))
				start = i;
		}
		if (start < 0 || offer->redirect != output->dev) {
			error = -EOPNOTSUPP;
			goto free_facts;
		}
		dev = (struct net_device *)stack->path[start].dev;
		lower = start < terminal[!dir] ? (struct net_device *)stack->path[start + 1].dev : NULL;
		if (stack->path[start].type != DEV_PATH_PPPOE) {
			unsigned int before_tags = geometry.tag_count;

			error = qdx_flow_header(flow, dev, lower, &geometry, false);
			if (error)
				goto free_facts;
			if (is_vlan_dev(dev) && geometry.tag_count > before_tags &&
			    (geometry.known & QDX_GEOMETRY_PRIORITY))
				priority_pending = false;
		}
		for (i = start; i <= terminal[!dir]; i++) {
			const struct net_device_path *step = &stack->path[i];
			unsigned int tag;

			dev = (struct net_device *)step->dev;
			lower = i < terminal[!dir] ? (struct net_device *)stack->path[i + 1].dev : NULL;
			error = qdx_flow_position_add(flow, dev, NF_NETDEV_EGRESS, false,
				facts, &geometry, !dir, &priority_pending);
			if (error)
				goto free_facts;
			/* validate_xmit_vlan runs before this device's ndo. */
			for (tag = 0; tag < geometry.tag_count; tag++) {
				struct qdx_vlan_tag *vlan = &geometry.tags[tag];
				netdev_features_t feature = vlan->protocol == htons(ETH_P_8021AD) ?
					NETIF_F_HW_VLAN_STAG_TX : NETIF_F_HW_VLAN_CTAG_TX;

				if (vlan->location == QDX_VLAN_METADATA && !(dev->features & feature)) {
					vlan->location = QDX_VLAN_IN_FRAME;
					geometry.data_overhead += VLAN_HLEN;
					geometry.frame_protocol = vlan->protocol;
					geometry.protocol = vlan->protocol;
					geometry.known |= QDX_GEOMETRY_FRAME_PROTOCOL | QDX_GEOMETRY_PROTOCOL;
				}
			}
			if (step->type == DEV_PATH_VLAN) {
				unsigned int before_tags = geometry.tag_count;

				error = qdx_flow_vlan_view(flow, dev, lower, QDX_VLAN_TX, &geometry, false);
				if (error)
					goto free_facts;
				if (geometry.tag_count > before_tags &&
				    (geometry.known & QDX_GEOMETRY_PRIORITY))
					priority_pending = false;
			} else if (step->type == DEV_PATH_PPPOE) {
				unsigned int before_tags = geometry.tag_count;

				if (!lower || ppp) {
					error = -EOPNOTSUPP;
					goto free_facts;
				}
				ppp = step;
				geometry.data_overhead += PPPOE_SES_HLEN;
				geometry.wire_overhead += PPPOE_SES_HLEN;
				geometry.protocol = htons(ETH_P_PPP_SES);
				geometry.vlan_payload_protocol = htons(ETH_P_PPP_SES);
				ether_addr_copy(geometry.destination, step->encap.h_dest);
				error = qdx_flow_header(flow, lower,
					i + 1 < terminal[!dir] ? (struct net_device *)stack->path[i + 2].dev : NULL,
					&geometry, true);
				if (error)
					goto free_facts;
				if (is_vlan_dev(lower) && geometry.tag_count > before_tags &&
				    (geometry.known & QDX_GEOMETRY_PRIORITY))
					priority_pending = false;
			}
		}
		/* All actual native continuations have been checked in order. A
		 * remaining metadata effect has no selected NSS wire representation.
		 */
		if (priority_pending) {
			error = -EOPNOTSUPP;
			goto free_facts;
		}
		/* Native bridge port VLAN changes can occur after the last device's
		 * TC position. Use the retained flattened wire tag identities here,
		 * without fabricating a VLAN device/ndo or moving them before TC.
		 */
		{
			const struct nf_flow_route_tuple *reverse = &flow->native_path->dir[!dir].route;
			struct qdx_vlan_tag emitted[QDX_VLAN_DEPTH] = {};
			unsigned int used = 0, count = 0, tag;

			for (i = reverse->in.num_encaps - 1; i >= 0; i--) {
				bool found = false;

				if (reverse->in.encap[i].proto == htons(ETH_P_PPP_SES) ||
				    (reverse->in.ingress_vlans & BIT(i)))
					continue;
				if (count == QDX_VLAN_DEPTH) {
					error = -EOPNOTSUPP;
					goto free_facts;
				}
				for (tag = 0; tag < geometry.tag_count; tag++) {
					if ((used & BIT(tag)) || geometry.tags[tag].protocol != reverse->in.encap[i].proto ||
					    (geometry.tags[tag].tci & VLAN_VID_MASK) != reverse->in.encap[i].id)
						continue;
					emitted[count] = geometry.tags[tag];
					used |= BIT(tag);
					found = true;
					break;
				}
				if (!found) {
					for (tag = 0; tag < offer->vlan_push; tag++) {
						if (offer->tags[tag].protocol != reverse->in.encap[i].proto ||
						    (offer->tags[tag].tci & VLAN_VID_MASK) != reverse->in.encap[i].id)
							continue;
						emitted[count] = (struct qdx_vlan_tag) {
							.protocol = offer->tags[tag].protocol,
							.tci = offer->tags[tag].tci, .known_tci = U16_MAX,
							.location = QDX_VLAN_IN_FRAME };
						found = true;
						break;
					}
				}
				if (!found) {
					error = -EOPNOTSUPP;
					goto free_facts;
				}
				count++;
			}
			geometry.wire_overhead = ETH_HLEN + count * VLAN_HLEN +
				(ppp ? PPPOE_SES_HLEN : 0);
			geometry.tag_count = count;
			memcpy(geometry.tags, emitted, sizeof(emitted));
		}
		output->transmit = geometry;
		if (ppp) {
			struct qdx_pppoe_request request = { .dev = (struct net_device *)ppp->dev,
				.native_path = *ppp, .transmit = geometry,
				.protocol = offer->match.key.basic.n_proto,
				.lower = { .physical_dev = output->dev,
					.physical = output->physical, .execution = output->physical } };
			unsigned int lower_count = 0;

			/* A persistent PPP session owns the actual lower execution chain.
			 * Create only VLAN lower objects present below that PPP path.
			 * Plain per-flow VLAN output continues using the physical endpoint.
			 */
			for (i = terminal[!dir] - 1; i >= start; i--) {
				const struct net_device_path *step = &stack->path[i];
				struct qdx_vlan_endpoint_request vlan_request = {};
				struct qdx_flow_vlan_view *view;
				bool found = false;

				if (step->type == DEV_PATH_PPPOE)
					break;
				if (step->type != DEV_PATH_VLAN)
					continue;
				if (lower_count == QDX_VLAN_DEPTH) {
					error = -EOPNOTSUPP;
					goto free_facts;
				}
				list_for_each_entry(view, &paths->vlans, node) {
					if (view->path.request.dev == step->dev &&
					    view->path.request.position == QDX_VLAN_TX) {
						vlan_request.path = view->path.request;
						found = true;
						break;
					}
				}
				if (!found) {
					error = -EOPNOTSUPP;
					goto free_facts;
				}
				found = false;
				for (unsigned int tag = 0; tag < geometry.tag_count; tag++) {
					if (geometry.tags[tag].protocol == step->encap.proto &&
					    (geometry.tags[tag].tci & VLAN_VID_MASK) == step->encap.id) {
						vlan_request.tag = geometry.tags[tag];
						found = true;
						break;
					}
				}
				if (!found || vlan_request.tag.known_tci != U16_MAX) {
					error = -EOPNOTSUPP;
					goto free_facts;
				}
				vlan_request.lower = request.lower;
				output->vlan_preparation[lower_count] = qdx_vlan_endpoint_prepare(&vlan_request);
				if (IS_ERR(output->vlan_preparation[lower_count])) {
					error = PTR_ERR(output->vlan_preparation[lower_count]);
					output->vlan_preparation[lower_count] = NULL;
					goto free_facts;
				}
				error = qdx_vlan_endpoint_get(output->vlan_preparation[lower_count],
					&owner, qdx_flow_invalidate, &output->vlan_lower[lower_count]);
				if (error)
					goto free_facts;
				request.lower.execution = output->vlan_lower[lower_count].execution;
				request.lower.vlan_binding = output->vlan_preparation[lower_count];
				lower_count++;
			}

			output->preparation = qdx_pppoe_session_prepare(&request);
			if (IS_ERR(output->preparation)) {
				error = PTR_ERR(output->preparation);
				output->preparation = NULL;
				goto free_facts;
			}
			error = qdx_pppoe_session_get(output->preparation, request.protocol,
				&owner, qdx_flow_invalidate, &output->session);
			if (error)
				goto free_facts;
			output->execution = output->session.execution;
			if (!offer->pppoe_push || output->session.session_id != offer->pppoe_sid) {
				error = -EOPNOTSUPP;
				goto free_facts;
			}
			/* The actual session now owns its lower. The flow keeps only its
			 * session use; old embedded delivery storage is still not reused.
			 */
			for (i = (int)lower_count - 1; i >= 0; i--) {
				qdx_vlan_endpoint_put(&output->vlan_lower[i]);
				qdx_vlan_endpoint_prepare_put(output->vlan_preparation[i]);
				output->vlan_preparation[i] = NULL;
			}
		} else if (offer->pppoe_push) {
			error = -EOPNOTSUPP;
			goto free_facts;
		}
		error = 0;
free_facts:
		kfree(facts);
		if (error)
			return error;
	}
	/* PPP control does not require RTNL. Link the actual session uses first,
	 * then compare the retained native path again before enabling RX or
	 * making this flow ready. Later changes invalidate those same uses.
	 */
	if (paths->side[0].session.use.linked || paths->side[1].session.use.linked) {
		error = nf_flow_hw_path_validate(flow->native_path);
		if (error == -ESTALE) {
			spin_lock_bh(&flow->data_lock);
			if (flow->native)
				flow_offload_teardown(flow->native);
			spin_unlock_bh(&flow->data_lock);
		}
		if (error)
			return error;
	}
	for (i = 0; i < 2; i++) {
		struct qdx_flow_side *side = &paths->side[i];
		struct qdx_flow_wire_path *forward = &flow->forward[i];
		u32 ifnum;
		unsigned int tag;

		error = qdx_endpoint_ifnum(side->physical, &forward->physical_ifnum);
		if (error)
			return error;
		error = qdx_endpoint_ifnum(side->execution, &forward->execution_ifnum);
		if (error)
			return error;
		forward->pppoe = side->session.use.linked;
		forward->session_ifnum = forward->pppoe ? forward->execution_ifnum : 0;
		forward->mtu = side->mtu;
		forward->class_tag = side->class_tag;
		forward->igs_tag = side->igs_tag;
		forward->has_class = side->has_class;
		forward->has_igs = side->has_igs;
		if (side->has_class) {
			error = qdx_endpoint_ifnum(side->class_endpoint, &ifnum);
			if (error || (ifnum != forward->physical_ifnum && ifnum != forward->execution_ifnum))
				return error ?: -EOPNOTSUPP;
		}
		/* Session lowers retain topology; the IP rule still supplies the
		 * complete wire tags consumed by the firmware header writer.
		 */
		for (tag = 0; tag < QDX_VLAN_DEPTH; tag++) {
			forward->vlan[tag] = QDX_NSS_UNTAGGED;
			if (tag >= side->transmit.tag_count)
				continue;
			if (side->transmit.tags[tag].known_tci != U16_MAX)
				return -EOPNOTSUPP;
			forward->vlan[tag] = (ntohs(side->transmit.tags[tag].protocol) << 16) |
				side->transmit.tags[tag].tci;
		}
		paths->side[i].rx = qdx_rx_acquire(paths->side[i].physical, paths->side[i].dev);
		if (IS_ERR(paths->side[i].rx)) {
			error = PTR_ERR(paths->side[i].rx);
			paths->side[i].rx = NULL;
			return error;
		}
	}
	return 0;
}
