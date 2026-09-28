// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bitfield.h>
#include <linux/etherdevice.h>
#include <linux/if_arp.h>
#include <linux/if_vlan.h>
#include <linux/jiffies.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/unaligned.h>
#include <net/rtnetlink.h>
#include "tc.h"

#define QDX_TC_RULE_TIMEOUT msecs_to_jiffies(3000)

struct qdx_tc_projection {
	struct qdx_tc_ref reference;
	struct qdx_tc_view *view;
};

struct qdx_tc_member_walk {
	struct tcf_walker walk;
	struct qdx_tc_view *view;
	struct qdx_tc_rule **memos;
	unsigned int nr_memos;
	struct tcf_block *block;
	bool *seen;
	int error;
};

/* A filter's unexpressed mask is a rejection. Extra knowledge in the input
 * connection is harmless; only the shared fixed fields are needed there.
 */
static int qdx_tc_fields_copy(const struct flow_rule *rule,
			     struct qdx_tc_fields *key,
			     struct qdx_tc_fields *mask, bool predicate)
{
	u64 supported = BIT_ULL(FLOW_DISSECTOR_KEY_CONTROL) |
		BIT_ULL(FLOW_DISSECTOR_KEY_BASIC) | BIT_ULL(FLOW_DISSECTOR_KEY_ETH_ADDRS) |
		BIT_ULL(FLOW_DISSECTOR_KEY_IPV4_ADDRS) | BIT_ULL(FLOW_DISSECTOR_KEY_IPV6_ADDRS) |
		BIT_ULL(FLOW_DISSECTOR_KEY_PORTS) | BIT_ULL(FLOW_DISSECTOR_KEY_IP) |
		BIT_ULL(FLOW_DISSECTOR_KEY_META) | BIT_ULL(FLOW_DISSECTOR_KEY_VLAN) |
		BIT_ULL(FLOW_DISSECTOR_KEY_CVLAN) | BIT_ULL(FLOW_DISSECTOR_KEY_NUM_OF_VLANS);

	memset(key, 0, sizeof(*key));
	memset(mask, 0, sizeof(*mask));
	if (predicate && (rule->match.dissector->used_keys & ~supported))
		return -EOPNOTSUPP;
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_CONTROL)) {
		struct flow_match_control match;

		flow_rule_match_control(rule, &match);
		if (predicate && (match.mask->flags || match.mask->thoff))
			return -EOPNOTSUPP;
		key->address_type = match.key->addr_type;
		mask->address_type = match.mask->addr_type;
	}
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_BASIC)) {
		struct flow_match_basic match;

		flow_rule_match_basic(rule, &match);
		key->protocol = match.key->n_proto;
		mask->protocol = match.mask->n_proto;
		key->ip_protocol = match.key->ip_proto;
		mask->ip_protocol = match.mask->ip_proto;
	}
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ETH_ADDRS)) {
		struct flow_match_eth_addrs match;

		flow_rule_match_eth_addrs(rule, &match);
		ether_addr_copy(key->source_mac, match.key->src);
		ether_addr_copy(mask->source_mac, match.mask->src);
		ether_addr_copy(key->destination_mac, match.key->dst);
		ether_addr_copy(mask->destination_mac, match.mask->dst);
	}
	/* Address keys can share storage; control selects the active family. */
	if (key->address_type == FLOW_DISSECTOR_KEY_IPV4_ADDRS &&
	    flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_IPV4_ADDRS)) {
		struct flow_match_ipv4_addrs match;

		flow_rule_match_ipv4_addrs(rule, &match);
		key->source_ipv4 = match.key->src;
		key->destination_ipv4 = match.key->dst;
		mask->source_ipv4 = match.mask->src;
		mask->destination_ipv4 = match.mask->dst;
	} else if (key->address_type == FLOW_DISSECTOR_KEY_IPV6_ADDRS &&
		   flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_IPV6_ADDRS)) {
		struct flow_match_ipv6_addrs match;

		flow_rule_match_ipv6_addrs(rule, &match);
		key->source_ipv6 = match.key->src;
		key->destination_ipv6 = match.key->dst;
		mask->source_ipv6 = match.mask->src;
		mask->destination_ipv6 = match.mask->dst;
	}
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_PORTS)) {
		struct flow_match_ports match;

		flow_rule_match_ports(rule, &match);
		key->source_port = match.key->src;
		key->destination_port = match.key->dst;
		mask->source_port = match.mask->src;
		mask->destination_port = match.mask->dst;
	}
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_IP)) {
		struct flow_match_ip match;

		flow_rule_match_ip(rule, &match);
		if (predicate && match.mask->ttl)
			return -EOPNOTSUPP;
		key->ip_tos = match.key->tos;
		mask->ip_tos = match.mask->tos;
	}
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_META)) {
		struct flow_match_meta match;

		flow_rule_match_meta(rule, &match);
		if (predicate && (match.mask->ingress_iftype || match.mask->l2_miss))
			return -EOPNOTSUPP;
		key->ingress_ifindex = match.key->ingress_ifindex;
		mask->ingress_ifindex = match.mask->ingress_ifindex;
	}
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_VLAN)) {
		struct flow_match_vlan match;

		flow_rule_match_vlan(rule, &match);
		key->vlan_tci[0] = match.key->vlan_id | (match.key->vlan_dei << 12) |
			(match.key->vlan_priority << VLAN_PRIO_SHIFT);
		mask->vlan_tci[0] = match.mask->vlan_id | (match.mask->vlan_dei << 12) |
			(match.mask->vlan_priority << VLAN_PRIO_SHIFT);
		key->vlan_protocol[0] = match.key->vlan_tpid;
		mask->vlan_protocol[0] = match.mask->vlan_tpid;
		key->vlan_payload_protocol[0] = match.key->vlan_eth_type;
		mask->vlan_payload_protocol[0] = match.mask->vlan_eth_type;
	}
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_CVLAN)) {
		struct flow_match_vlan match;

		flow_rule_match_cvlan(rule, &match);
		key->vlan_tci[1] = match.key->vlan_id | (match.key->vlan_dei << 12) |
			(match.key->vlan_priority << VLAN_PRIO_SHIFT);
		mask->vlan_tci[1] = match.mask->vlan_id | (match.mask->vlan_dei << 12) |
			(match.mask->vlan_priority << VLAN_PRIO_SHIFT);
		key->vlan_protocol[1] = match.key->vlan_tpid;
		mask->vlan_protocol[1] = match.mask->vlan_tpid;
		key->vlan_payload_protocol[1] = match.key->vlan_eth_type;
		mask->vlan_payload_protocol[1] = match.mask->vlan_eth_type;
	}
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_NUM_OF_VLANS)) {
		const struct flow_dissector_key_num_of_vlans *value, *bits;

		value = skb_flow_dissector_target(rule->match.dissector,
			FLOW_DISSECTOR_KEY_NUM_OF_VLANS, rule->match.key);
		bits = skb_flow_dissector_target(rule->match.dissector,
			FLOW_DISSECTOR_KEY_NUM_OF_VLANS, rule->match.mask);
		key->vlan_depth = value->num_of_vlans;
		mask->vlan_depth = bits->num_of_vlans;
	}
	return 0;
}

static bool qdx_tc_disjoint(const struct qdx_tc_fields *left,
			    const struct qdx_tc_fields *left_mask,
			    const struct qdx_tc_fields *right,
			    const struct qdx_tc_fields *right_mask)
{
	const u8 *a = (const u8 *)left, *am = (const u8 *)left_mask;
	const u8 *b = (const u8 *)right, *bm = (const u8 *)right_mask;
	unsigned int byte;

	/* Padding is zeroed with the complete owned field record. Bytewise masks
	 * preserve both network-order fields and host-order metadata exactly.
	 */
	for (byte = 0; byte < sizeof(*left); byte++)
		if ((a[byte] ^ b[byte]) & am[byte] & bm[byte])
			return true;
	return false;
}

static bool qdx_tc_implies(const struct qdx_tc_fields *facts,
			  const struct qdx_tc_fields *known,
			  const struct qdx_tc_fields *key,
			  const struct qdx_tc_fields *mask)
{
	const u8 *v = (const u8 *)facts, *k = (const u8 *)known;
	const u8 *want = (const u8 *)key, *need = (const u8 *)mask;
	unsigned int byte;

	for (byte = 0; byte < sizeof(*facts); byte++)
		if ((k[byte] & need[byte]) != need[byte] ||
		    ((v[byte] ^ want[byte]) & need[byte]))
			return false;
	return true;
}

static bool qdx_tc_rule_get(void *object)
{
	struct qdx_tc_rule *rule = object;

	return refcount_inc_not_zero(&rule->refs);
}

void qdx_tc_rule_put(void *object)
{
	struct qdx_tc_rule *rule = object;
	struct qdx_tc_owner *owner = rule->owner;
	unsigned int action;

	if (!refcount_dec_and_test(&rule->refs))
		return;
	WARN_ON_ONCE(rule->installed || rule->receiver || rule->rx || rule->resume_rx ||
		     rule->source_endpoint || rule->igs || rule->native_count ||
		     rule->endpoint || rule->configure.request || rule->install.request ||
		     rule->remove.request || rule->source_attach.request ||
		     rule->source_detach.request);
	for (action = 0; action < rule->nr_actions; action++)
		if (rule->actions[action].target)
			dev_put(rule->actions[action].target);
	if (rule->service)
		qdx_service_put(rule->service);
	if (rule->old)
		qdx_tc_rule_put(rule->old);
	if (rule->block && refcount_dec_and_test(&rule->block->refs)) {
		qdx_tc_owner_put(rule->block->owner);
		kfree(rule->block);
	}
	kfree(rule);
	qdx_tc_owner_put(owner);
}

static struct qdx_tc_rule *qdx_tc_copy_offer(struct qdx_tc_block *block,
			const struct flow_cls_common_offload *common,
			const struct flow_rule *native, unsigned long cookie,
			unsigned long replace_cookie, u32 classid, bool matchall)
{
	struct qdx_tc_rule *rule;
	const struct flow_action_entry *entry;
	struct qdx_owner holder;
	unsigned int i;
	int error;

	if (!native || native->action.num_entries > TCA_ACT_MAX_PRIO)
		return ERR_PTR(-EOPNOTSUPP);
	rule = kzalloc(sizeof(*rule), GFP_KERNEL);
	if (!rule)
		return ERR_PTR(-ENOMEM);
	INIT_LIST_HEAD(&rule->list);
	refcount_set(&rule->refs, 1);
	qdx_tc_owner_get(block->owner);
	rule->owner = block->owner;
	refcount_inc(&block->refs);
	rule->block = block;
	rule->native_block = block->native;
	rule->cookie = cookie;
	rule->replace_cookie = replace_cookie;
	rule->chain = common->chain_index;
	rule->filter_priority = common->prio;
	rule->protocol = common->protocol;
	rule->flags = common->skip_sw ? TCA_CLS_FLAGS_SKIP_SW : 0;
	rule->classid = classid;
	rule->matchall = matchall;
	rule->action = QDX_TC_PASS;
	if (!matchall) {
		error = qdx_tc_fields_copy(native, &rule->key, &rule->mask, true);
		if (error)
			goto fail;
	}
	if (common->protocol != htons(ETH_P_ALL)) {
		rule->key.classifier_protocol = common->protocol;
		rule->mask.classifier_protocol = htons(U16_MAX);
	}
	flow_action_for_each(i, entry, &native->action) {
		struct qdx_tc_action *action = &rule->actions[i];

		action->identity = entry->cookie;
		action->id = entry->id;
		action->control = entry->control_action;
		action->flags = entry->action_flags;
		action->hw_stats = entry->hw_stats;
		if (entry->id == FLOW_ACTION_MIRRED || entry->id == FLOW_ACTION_REDIRECT) {
			action->target = entry->dev;
			if (!action->target) {
				error = -EINVAL;
				goto fail;
			}
			dev_hold(action->target);
		}
		if (entry->id == FLOW_ACTION_PRIORITY)
			action->priority = entry->priority;
		rule->nr_actions++;
	}
	holder = (struct qdx_owner) {
		.module = THIS_MODULE, .object = rule,
		.get = qdx_tc_rule_get, .put = qdx_tc_rule_put,
	};
	qdx_tc_command_init(&rule->configure, rule->owner, &holder);
	qdx_tc_command_init(&rule->install, rule->owner, &holder);
	qdx_tc_command_init(&rule->remove, rule->owner, &holder);
	qdx_tc_command_init(&rule->source_attach, rule->owner, &holder);
	qdx_tc_command_init(&rule->source_detach, rule->owner, &holder);
	return rule;
fail:
	qdx_tc_rule_put(rule);
	return ERR_PTR(error);
}

static int qdx_tc_actions_admit(struct qdx_tc_rule *rule)
{
	unsigned int i;
	bool terminal = false;

	for (i = 0; i < rule->nr_actions; i++) {
		struct qdx_tc_action *action = &rule->actions[i];
		bool last = i + 1 == rule->nr_actions;

		if (terminal || action->flags & TCA_ACT_FLAGS_SKIP_HW ||
		    action->hw_stats != FLOW_ACTION_HW_STATS_DISABLED)
			return -EOPNOTSUPP;
		switch (action->id) {
		case FLOW_ACTION_ACCEPT:
			if (action->control != TC_ACT_OK || !last)
				return -EOPNOTSUPP;
			terminal = true;
			break;
		case FLOW_ACTION_DROP:
			if (action->control != TC_ACT_SHOT || !last || i)
				return -EOPNOTSUPP;
			rule->action = QDX_TC_DROP;
			terminal = true;
			break;
		case FLOW_ACTION_PRIORITY:
			if (rule->action != QDX_TC_PASS ||
			    (action->control != TC_ACT_PIPE && action->control != TC_ACT_OK) ||
			    (action->control == TC_ACT_OK && !last))
				return -EOPNOTSUPP;
			rule->action = QDX_TC_SET_PRIORITY;
			rule->priority_after = action->priority;
			terminal = action->control == TC_ACT_OK;
			break;
		case FLOW_ACTION_REDIRECT:
			if (i || !last || action->control != TC_ACT_STOLEN ||
			    (!action->target->rtnl_link_ops ||
			     strcmp(action->target->rtnl_link_ops->kind, "ifb")))
				return -EOPNOTSUPP;
			rule->action = QDX_TC_REDIRECT_IFB;
			rule->target = action->target;
			terminal = true;
			break;
		case FLOW_ACTION_MIRRED:
			if (i || !last || action->control != TC_ACT_PIPE)
				return -EOPNOTSUPP;
			rule->action = QDX_TC_MIRROR;
			rule->target = action->target;
			/* MIRROR's original continues native ingress; this is deliberately
			 * not a terminal flow-projection permission.
			 */
			break;
		default:
			return -EOPNOTSUPP;
		}
	}
	if (rule->nr_actions && !terminal && rule->action != QDX_TC_MIRROR)
		return -EOPNOTSUPP;
	if (rule->chain || (rule->classid && TC_H_MIN(rule->classid) == 0))
		return -EOPNOTSUPP;
	return 0;
}

static int qdx_tc_member_visit(struct tcf_proto *tp, void *member,
			       struct tcf_walker *walk)
{
	struct qdx_tc_member_walk *scan = container_of(walk, typeof(*scan), walk);
	unsigned int i;
	bool represented = false;

	for (i = 0; i < scan->nr_memos; i++) {
		struct qdx_tc_rule *rule = scan->memos[i];

		if (rule->native_block != scan->block || rule->cookie != (unsigned long)member ||
		    rule->chain != tp->chain->index || rule->filter_priority != (tp->prio >> 16) ||
		    rule->protocol != tp->protocol)
			continue;
		scan->seen[i] = true;
		represented |= !rule->retiring;
	}
	/* Continue the real native walk: an unknown/skip_hw member does not hide
	 * later members or erase their actual retirement identities.
	 */
	if (!represented)
		scan->error = -EOPNOTSUPP;
	return 0;
}

int qdx_tc_members_prepare(struct qdx_tc_owner *owner, struct qdx_tc_view *view)
{
	struct qdx_tc_member_walk scan = { .view = view };
	struct qdx_tc_rule *rule;
	struct qdx_tc_block *binding;
	struct tcf_block **blocks = NULL;
	struct qdx_tc_rule **current_rules = NULL;
	unsigned int nr_blocks = 0, n = 0;
	unsigned int i, j, count = 0, current_count = 0;
	int error = 0;

	ASSERT_RTNL();
	lockdep_assert_not_held(&owner->cfg);
	mutex_lock(&owner->cfg);
	list_for_each_entry(rule, &owner->rules, list)
		count++;
	scan.memos = kmalloc_array(count, sizeof(*scan.memos), GFP_KERNEL);
	scan.seen = kcalloc(count, sizeof(*scan.seen), GFP_KERNEL);
	if (count && (!scan.memos || !scan.seen)) {
		error = -ENOMEM;
		goto unlock;
	}
	list_for_each_entry(rule, &owner->rules, list) {
		qdx_tc_rule_get(rule);
		scan.memos[scan.nr_memos++] = rule;
	}
	list_for_each_entry(binding, &owner->blocks, list)
		if (!binding->dead && binding->native)
			nr_blocks++;
	blocks = kmalloc_array(nr_blocks, sizeof(*blocks), GFP_KERNEL);
	if (nr_blocks && !blocks) {
		error = -ENOMEM;
		goto unlock;
	}
	list_for_each_entry(binding, &owner->blocks, list)
		if (!binding->dead && binding->native)
			blocks[n++] = binding->native;
unlock:
	mutex_unlock(&owner->cfg);
	if (error)
		goto out;
	/* RTNL keeps these actual native attachment borrows alive; cfg is not
	 * held while taking the native block lock or walking native members.
	 */
	for (i = 0; i < nr_blocks; i++) {
		struct tcf_block_state state;

		tcf_block_read_state(blocks[i], &state);
		error = state.active ? -EAGAIN :
			qdx_tc_view_observe(view, blocks[i], state.sequence);
		if (error)
			goto out;
	}
	for (i = 0; i < view->nr_blocks; i++) {
		struct tcf_block_state before, after;
		struct tcf_chain *chain = NULL;

		scan.block = view->blocks[i].native;
		tcf_block_read_state(scan.block, &before);
		if (before.active || before.sequence != view->blocks[i].sequence) {
			error = -EAGAIN;
			goto out;
		}
		while ((chain = tcf_get_next_chain(scan.block, chain))) {
			struct tcf_proto *tp = NULL;

			while ((tp = tcf_get_next_proto(chain, tp))) {
				if (!tp->ops->walk) {
					scan.error = -EOPNOTSUPP;
					continue;
				}
				scan.walk = (struct tcf_walker) { .fn = qdx_tc_member_visit };
				tp->ops->walk(tp, &scan.walk, true);
			}
		}
		tcf_block_read_state(scan.block, &after);
		if (after.active || after.sequence != before.sequence) {
			error = -EAGAIN;
			goto out;
		}
	}
	for (i = 0; i < scan.nr_memos; i++) {
		if (!scan.seen[i] || scan.memos[i]->retiring)
			continue;
		current_count++;
		for (j = 0; j < i; j++) {
			if (!scan.seen[j] || scan.memos[j]->retiring || scan.memos[j]->native_block != scan.memos[i]->native_block)
				continue;
			if (!qdx_tc_disjoint(&scan.memos[i]->key, &scan.memos[i]->mask,
					     &scan.memos[j]->key, &scan.memos[j]->mask))
				scan.error = -EOPNOTSUPP;
		}
	}
	current_rules = kmalloc_array(current_count, sizeof(*current_rules), GFP_KERNEL);
	if (current_count && !current_rules) {
		error = -ENOMEM;
		goto out;
	}
	mutex_lock(&owner->cfg);
	n = 0;
	for (i = 0; i < scan.nr_memos; i++) {
		rule = scan.memos[i];
		/* Only a complete coherent scope grants execution. A current member
		 * of an incomplete scope stays held; it is not silently deleted here.
		 */
		rule->native_current = scan.seen[i];
		if (!scan.seen[i] || rule->retiring)
			continue;
		qdx_tc_rule_get(rule);
		current_rules[n++] = rule;
		for (j = 0; j < view->nr_blocks; j++)
			if (view->blocks[j].native == rule->native_block)
				rule->member_sequence = view->blocks[j].sequence;
	}
	spin_lock_bh(&owner->data_lock);
	view->rules = current_rules;
	view->nr_rules = n;
	if (n)
		view->neutral = false;
	spin_unlock_bh(&owner->data_lock);
	mutex_unlock(&owner->cfg);
	error = scan.error;
out:
	kfree(blocks);
	for (i = 0; i < scan.nr_memos; i++)
		qdx_tc_rule_put(scan.memos[i]);
	kfree(scan.memos);
	kfree(scan.seen);
	return error;
}

/* Return one whole predicate, no recreated classifier ordering. */
static int qdx_tc_select_member(const struct qdx_tc_view *view,
			       const struct tcf_block *block,
			       const struct qdx_tc_fields *facts,
			       const struct qdx_tc_fields *known,
			       struct qdx_tc_rule **result)
{
	unsigned int i;

	*result = NULL;
	for (i = 0; i < view->nr_rules; i++) {
		struct qdx_tc_rule *rule = view->rules[i];

		if (rule->native_block != block)
			continue;
		if (qdx_tc_disjoint(facts, known, &rule->key, &rule->mask))
			continue;
		if (!qdx_tc_implies(facts, known, &rule->key, &rule->mask) || *result)
			return -EOPNOTSUPP;
		*result = rule;
	}
	return 0;
}

static int qdx_tc_project_tree(const struct qdx_tc_view *view,
			      struct qdx_tc_tree *tree,
			      struct qdx_tc_fields *facts,
			      struct qdx_tc_fields *known,
			      struct qdx_tc_ref *result,
			      struct qdx_tc_node **selected)
{
	struct qdx_tc_node *node = tree->root, *child;
	unsigned int remaining = 0;
	bool priority_output = result->effects & QDX_TC_PRIORITY;

	list_for_each_entry(child, &tree->nodes, list)
		remaining++;
	while (node && remaining--) {
		struct qdx_tc_rule *rule = NULL;
		struct qdx_tc_node *choice = NULL;
		u32 classid = 0, band = 0;
		bool priority_used = false, classify = true;
		int error;

		if (!node->allocated || !node->configured || node->retiring)
			return -EAGAIN;
		if (node->kind == QDX_SHAPER_PRIO) {
			if (known->priority != U32_MAX || !node->bands)
				return -EOPNOTSUPP;
			classify = TC_H_MAJ(facts->priority) != node->handle;
		}
		if (node->kind == QDX_SHAPER_HTB) {
			if (known->priority != U32_MAX || facts->priority == tree->root_handle)
				return -EOPNOTSUPP; /* Native direct bypass has no shaped class tag. */
			list_for_each_entry(child, &tree->nodes, list)
				if (child->native && child->kind == QDX_SHAPER_HTB_GROUP &&
				    TC_H_MAKE(TC_H_MAJ(child->handle), child->classid) == facts->priority) {
					choice = child;
					priority_used = true;
					classify = false;
					break;
				}
		}
		if (classify && node->native) {
			error = qdx_tc_select_member(view, node->native_block, facts, known, &rule);
			if (error)
				return error;
		}
		if (rule) {
			if (rule->action != QDX_TC_PASS && rule->action != QDX_TC_SET_PRIORITY)
				return -EOPNOTSUPP;
			if (rule->action == QDX_TC_SET_PRIORITY) {
				facts->priority = rule->priority_after;
				known->priority = U32_MAX;
				result->effects |= QDX_TC_PRIORITY;
				result->priority_after = rule->priority_after;
				priority_output = true;
			}
			classid = rule->classid;
		}
		if (node->kind == QDX_SHAPER_HTB ||
		    (node->kind == QDX_SHAPER_HTB_GROUP && node->native)) {
			if (!choice && classid)
				list_for_each_entry(child, &tree->nodes, list)
					if (child->native && child->kind == QDX_SHAPER_HTB_GROUP &&
					    TC_H_MAKE(TC_H_MAJ(child->handle), child->classid) == classid) {
						choice = child;
						break;
					}
			if (!choice) {
				classid = TC_H_MAKE(TC_H_MAJ(tree->root_handle), tree->default_class);
				list_for_each_entry(child, &tree->nodes, list)
					if (child->native && child->kind == QDX_SHAPER_HTB_GROUP &&
					    TC_H_MAKE(TC_H_MAJ(child->handle), child->classid) == classid &&
					    child->native_leaf) {
						choice = child;
						break;
					}
			}
			if (!choice || choice == node || choice->retiring || !choice->configured)
				return -EOPNOTSUPP;
			if (priority_used) {
				result->input_priority_used |= !priority_output;
				result->output_priority_used |= priority_output;
			}
			if (!choice->native_leaf) {
				node = choice;
				continue;
			}
			node = choice;
			/* Follow the leaf's actual child, including further PRIO choices.
			 * The selected enqueue leaf retains its linked ancestor budgets.
			 */
		} else if (node->kind == QDX_SHAPER_PRIO) {
			if (!classify) {
				band = TC_H_MIN(facts->priority) - 1;
				priority_used = true;
			} else if (classid) {
				band = TC_H_MIN(classid) - 1;
			} else {
				u32 priority = TC_H_MAJ(facts->priority) ? 0 : facts->priority;
				unsigned int p;

				band = node->priomap[priority & TC_PRIO_MAX];
				if (!TC_H_MAJ(facts->priority))
					for (p = 1; p <= TC_PRIO_MAX; p++)
						priority_used |= node->priomap[p] != node->priomap[0];
			}
			if (band >= node->bands)
				band = node->priomap[0];
			if (priority_used) {
				result->input_priority_used |= !priority_output;
				result->output_priority_used |= priority_output;
			}
			band++;
		}
		child = NULL;
		{
			struct qdx_tc_node *candidate;

			list_for_each_entry(candidate, &tree->nodes, list) {
				if (candidate->parent != node ||
				    (candidate->kind == QDX_SHAPER_HTB_GROUP &&
				     candidate->native) ||
				    (node->kind == QDX_SHAPER_PRIO && candidate->band != band) ||
				    candidate->retiring)
					continue;
				if (child)
					return -EOPNOTSUPP;
				child = candidate;
			}
		}
		if (!child) {
			node = qdx_tc_enqueue_node(node);
			if (IS_ERR(node))
				return PTR_ERR(node);
			*selected = node;
			return 0;
		}
		node = child;
	}
	return -EOPNOTSUPP;
}

int qdx_tc_project(struct qdx_binding *provider,
		   const struct qdx_tc_position *position,
		   const struct flow_rule *native_facts,
		   const struct qdx_packet_geometry *geometry,
		   struct qdx_binding_use *use, const struct qdx_owner *consumer,
		   int (*invalidate)(void *consumer, bool may_sleep),
		   struct qdx_tc_ref **result)
{
	struct qdx_tc_projection *projection;
	struct qdx_tc_fields facts, known;
	struct qdx_tc_node *selected = NULL;
	struct qdx_tc_rule *igs_rule = NULL;
	struct qdx_tc_view *view;
	struct qdx_tc_owner *owner;
	unsigned int i, visible = 0;
	int error;

	*result = NULL;
	error = qdx_tc_fields_copy(native_facts, &facts, &known, false);
	if (error)
		return error;
	facts.priority = geometry->priority;
	known.priority = geometry->known & QDX_GEOMETRY_PRIORITY ? U32_MAX : 0;
	facts.classifier_protocol = geometry->protocol;
	known.classifier_protocol = geometry->known & QDX_GEOMETRY_PROTOCOL ? htons(U16_MAX) : 0;
	for (i = 0; i < geometry->tag_count; i++)
		if (geometry->tags[i].location == QDX_VLAN_METADATA) {
			facts.classifier_protocol = geometry->tags[i].protocol;
			known.classifier_protocol = htons(U16_MAX);
			break;
		}
	ether_addr_copy(facts.source_mac, geometry->source);
	ether_addr_copy(facts.destination_mac, geometry->destination);
	memset(known.source_mac, geometry->known & QDX_GEOMETRY_SOURCE ? 0xff : 0, ETH_ALEN);
	memset(known.destination_mac, geometry->known & QDX_GEOMETRY_DESTINATION ? 0xff : 0, ETH_ALEN);
	memset(facts.vlan_tci, 0, sizeof(facts.vlan_tci));
	memset(facts.vlan_protocol, 0, sizeof(facts.vlan_protocol));
	memset(facts.vlan_payload_protocol, 0, sizeof(facts.vlan_payload_protocol));
	/* A missing VLAN key is zero in the native dissector. Present tags below
	 * replace that fact with their actual known bits, including unknown PCP.
	 */
	memset(known.vlan_tci, 0xff, sizeof(known.vlan_tci));
	memset(known.vlan_protocol, 0xff, sizeof(known.vlan_protocol));
	memset(known.vlan_payload_protocol, 0xff, sizeof(known.vlan_payload_protocol));
	for (i = 0; i < geometry->tag_count; i++) {
		if (geometry->tags[i].location == QDX_VLAN_SAVED_MAC)
			continue;
		if (visible == ARRAY_SIZE(facts.vlan_tci))
			return -EOPNOTSUPP;
		facts.vlan_tci[visible] = geometry->tags[i].tci;
		known.vlan_tci[visible] = geometry->tags[i].known_tci;
		facts.vlan_protocol[visible] = geometry->tags[i].protocol;
		known.vlan_protocol[visible] = htons(U16_MAX);
		visible++;
	}
	for (i = 0; i < visible; i++) {
		if (i + 1 < visible) {
			facts.vlan_payload_protocol[i] = facts.vlan_protocol[i + 1];
		} else if (geometry->known & QDX_GEOMETRY_VLAN_PAYLOAD_PROTOCOL) {
			facts.vlan_payload_protocol[i] = geometry->vlan_payload_protocol;
		} else {
			known.vlan_payload_protocol[i] = 0;
		}
	}
	facts.vlan_depth = visible;
	known.vlan_depth = U8_MAX;
	projection = kzalloc(sizeof(*projection), GFP_KERNEL);
	if (!projection)
		return -ENOMEM;
	error = qdx_tc_view_acquire(position->dev, position->direction, use,
				    consumer, invalidate, &view);
	if (error)
		goto free;
	projection->view = view;
	projection->reference.use = use;
	projection->reference.ops = qdx_binding_ops(provider);
	owner = view->owner;
	/* Owned values only. Keep the publication lock through the calculation:
	 * an in-place native HTB update invalidates this same view before mutation.
	 */
	qdx_uses_lock();
	spin_lock_bh(&owner->data_lock);
	if (!view->available || view->invalid || !qdx_use_available_locked(use)) {
		error = -EAGAIN;
		goto unlock;
	}
	if (view->neutral)
		goto publish;
	if (position->direction == QDX_TC_INGRESS) {
		for (i = 0; i < view->nr_blocks; i++) {
			struct qdx_tc_rule *rule;

			error = qdx_tc_select_member(view, view->blocks[i].native, &facts, &known, &rule);
			if (error)
				goto unlock;
			if (!rule)
				continue;
			if (rule->action == QDX_TC_DROP || rule->action == QDX_TC_MIRROR || rule->classid) {
				error = -EOPNOTSUPP;
				goto unlock;
			}
			if (rule->action == QDX_TC_SET_PRIORITY) {
				facts.priority = rule->priority_after;
				known.priority = U32_MAX;
				projection->reference.effects |= QDX_TC_PRIORITY;
				projection->reference.priority_after = rule->priority_after;
			}
			if (rule->action == QDX_TC_REDIRECT_IFB) {
				if (igs_rule || !rule->igs || !qdx_tc_igs_available_locked(rule->igs)) {
					error = -EAGAIN;
					goto unlock;
				}
				igs_rule = rule;
				{
					const struct qdx_tc_view *target = qdx_tc_igs_view(rule->igs);

					/* Source is a physical ingress owner; the target is IFB.
					 * IFB projection never takes the source owner lock back.
					 */
					spin_lock_bh(&target->owner->data_lock);
					if (!target->available || target->invalid || !target->tree)
						error = -ESTALE;
					else
						error = qdx_tc_project_tree(target, target->tree,
							&facts, &known, &projection->reference, &selected);
					spin_unlock_bh(&target->owner->data_lock);
				}
				if (error)
					goto unlock;
				projection->reference.effects |= QDX_TC_IGS;
				projection->reference.igs_endpoint = selected->endpoint;
				projection->reference.igs_tag = selected->tag >> QDX_SHAPER_TAG_SHIFT;
			}
		}
	} else if (view->tree) {
		error = qdx_tc_project_tree(view, view->tree, &facts, &known,
					    &projection->reference, &selected);
		if (error)
			goto unlock;
		projection->reference.effects |= QDX_TC_CLASS;
		projection->reference.class_endpoint = selected->endpoint;
		projection->reference.class_tag = selected->tag;
	}
publish:
	if (!view->available || view->invalid || !qdx_use_available_locked(use) ||
	    (igs_rule && !qdx_tc_igs_available_locked(igs_rule->igs))) {
		error = -EAGAIN;
		goto unlock;
	}
	*result = &projection->reference;
	error = 0;
unlock:
	spin_unlock_bh(&owner->data_lock);
	qdx_uses_unlock();
	if (!error)
		return 0;
	qdx_tc_view_put(view);
	qdx_binding_use_put(use);
free:
	kfree(projection);
	return error;
}

void qdx_tc_projection_put(struct qdx_tc_ref *reference)
{
	struct qdx_tc_projection *projection = container_of(reference, typeof(*projection), reference);

	qdx_tc_view_put(projection->view);
	kfree(projection);
}

/* One settled wire operation. Original UNKNOWN recipients are never replaced
 * or cleared; callers record the real ACK in their own operation state.
 */
static int qdx_tc_rule_command(struct qdx_tc_command *command,
			       struct qdx_endpoint *endpoint, u32 opcode,
			       const void *payload, size_t length)
{
	struct qdx_reply_bounds bounds = {
		.minimum = 0, .maximum = length,
		.capacity = sizeof(command->reply),
	};
	struct qdx_result result;
	int error;

	if (!command->request) {
		error = qdx_tc_command_start(command, endpoint, opcode, payload, length, &bounds);
		if (error)
			return error;
	}
	error = qdx_tc_command_wait(command);
	spin_lock_bh(&command->lock);
	result = command->result;
	spin_unlock_bh(&command->lock);
	if (result.outcome == QDX_UNKNOWN && !result.exposure_ended)
		return error ?: -EINPROGRESS;
	qdx_tc_command_clear(command);
	if (result.outcome == QDX_ACK)
		return 0;
	return result.error ?: error ?: -EIO;
}

static int qdx_tc_match_encode(struct qdx_tc_rule *rule, u32 source)
{
	struct qdx_tc_fields remaining = rule->mask;
	struct qdx_match_action action = { };
	u32 mask[QDX_MATCH_MASK_WORDS] = { U16_MAX, 0, 0, 0 };
	unsigned int i;
	bool l2;

	if (source > U16_MAX ||
	    ((rule->key.ingress_ifindex ^ rule->owner->dev->ifindex) & remaining.ingress_ifindex))
		return -EOPNOTSUPP;
	remaining.ingress_ifindex = 0;
	/* Basic protocol is the dissector result, while the native dispatcher
	 * compares skb_protocol(skb, false). Only an exact non-encapsulated
	 * dispatcher EtherType proves that these two conditions are identical.
	 */
	if (remaining.protocol) {
		if (remaining.classifier_protocol != htons(U16_MAX) ||
		    eth_type_vlan(rule->key.classifier_protocol) ||
		    rule->key.classifier_protocol == htons(ETH_P_PPP_SES) ||
		    ((rule->key.protocol ^ rule->key.classifier_protocol) & remaining.protocol))
			return -EOPNOTSUPP;
		remaining.protocol = 0;
	}
	l2 = !is_zero_ether_addr(remaining.source_mac) ||
		!is_zero_ether_addr(remaining.destination_mac) || remaining.classifier_protocol;
	memset(&rule->profile, 0, sizeof(rule->profile));
	memset(&rule->wire, 0, sizeof(rule->wire));
	if (rule->action == QDX_TC_DROP) {
		action.effects = cpu_to_le32(QDX_MATCH_DROP);
	} else {
		if (rule->priority_after > U16_MAX)
			return -EOPNOTSUPP;
		action.effects = cpu_to_le32(QDX_MATCH_SET_PRIORITY);
		action.priority = cpu_to_le16(rule->priority_after);
	}
	if (l2) {
		u16 d0 = get_unaligned_be16(&remaining.destination_mac[0]);
		u16 d1 = get_unaligned_be16(&remaining.destination_mac[2]);
		u16 d2 = get_unaligned_be16(&remaining.destination_mac[4]);
		u16 s0 = get_unaligned_be16(&remaining.source_mac[0]);
		u16 s1 = get_unaligned_be16(&remaining.source_mac[2]);
		u16 s2 = get_unaligned_be16(&remaining.source_mac[4]);

		mask[0] |= (u32)d0 << 16;
		mask[1] = d1 | ((u32)d2 << 16);
		mask[2] = s0 | ((u32)s1 << 16);
		mask[3] = s2 | ((u32)be16_to_cpu(remaining.classifier_protocol) << 16);
		rule->wire.l2.action = action;
		rule->wire.l2.source_ifnum = cpu_to_le32(source);
		/* MATCH encodes each numeric MAC halfword in little-endian order. */
		for (i = 0; i < ARRAY_SIZE(rule->wire.l2.source); i++) {
			rule->wire.l2.destination[i] = cpu_to_le16(
				get_unaligned_be16(&rule->key.destination_mac[2 * i]));
			rule->wire.l2.source[i] = cpu_to_le16(
				get_unaligned_be16(&rule->key.source_mac[2 * i]));
		}
		rule->wire.l2.protocol = cpu_to_le16(be16_to_cpu(rule->key.classifier_protocol));
		memset(remaining.source_mac, 0, ETH_ALEN);
		memset(remaining.destination_mac, 0, ETH_ALEN);
		remaining.classifier_protocol = 0;
		rule->profile.profile = cpu_to_le32(QDX_MATCH_L2);
	} else {
		if ((remaining.ip_tos & 3) ||
		    (remaining.vlan_tci[0] & ~VLAN_PRIO_MASK) ||
		    (remaining.vlan_tci[1] & ~VLAN_PRIO_MASK))
			return -EOPNOTSUPP;
		mask[0] |= ((u32)(remaining.ip_tos >> 2) << 16) |
			((u32)(remaining.vlan_tci[1] >> VLAN_PRIO_SHIFT) << 22) |
			((u32)(remaining.vlan_tci[0] >> VLAN_PRIO_SHIFT) << 25);
		rule->wire.vow.action = action;
		rule->wire.vow.source_ifnum = cpu_to_le32(source);
		rule->wire.vow.dscp = rule->key.ip_tos >> 2;
		rule->wire.vow.outer_pcp = rule->key.vlan_tci[0] >> VLAN_PRIO_SHIFT;
		rule->wire.vow.inner_pcp = rule->key.vlan_tci[1] >> VLAN_PRIO_SHIFT;
		remaining.ip_tos = 0;
		remaining.vlan_tci[0] = 0;
		remaining.vlan_tci[1] = 0;
		rule->profile.profile = cpu_to_le32(QDX_MATCH_VOW);
	}
	/* Neither profile expresses protocol-family, address, transport, tag
	 * presence/VID/TPID or other discarded predicates. Never install a subset.
	 */
	if (memchr_inv(&remaining, 0, sizeof(remaining)))
		return -EOPNOTSUPP;
	rule->profile.valid_masks = cpu_to_le32(1);
	for (i = 0; i < QDX_MATCH_MASK_WORDS; i++)
		rule->profile.masks[0][i] = cpu_to_le32(mask[i]);
	return 0;
}

static int qdx_tc_match_rule(struct qdx_tc_rule *rule, bool add)
{
	bool l2 = rule->profile.profile == cpu_to_le32(QDX_MATCH_L2);
	struct qdx_tc_command *command = add ? &rule->install : &rule->remove;
	int error;

	if (qdx_service_access_ended(rule->table->service)) {
		rule->installed = false;
		if (command->request) {
			qdx_tc_command_wait(command);
			qdx_tc_command_clear(command);
		}
		return add ? -ESHUTDOWN : 0;
	}
	if (l2) {
		rule->wire.l2.rule = cpu_to_le16(rule->rule_slot + 1);
		rule->wire.l2.mask = cpu_to_le16(rule->mask_slot + 1);
		error = qdx_tc_rule_command(command, rule->table->endpoint,
			add ? QDX_MATCH_L2_ADD : QDX_MATCH_L2_DELETE,
			&rule->wire.l2, sizeof(rule->wire.l2));
	} else {
		rule->wire.vow.rule = cpu_to_le16(rule->rule_slot + 1);
		rule->wire.vow.mask = cpu_to_le16(rule->mask_slot + 1);
		error = qdx_tc_rule_command(command, rule->table->endpoint,
			add ? QDX_MATCH_VOW_ADD : QDX_MATCH_VOW_DELETE,
			&rule->wire.vow, sizeof(rule->wire.vow));
	}
	if (!error)
		rule->installed = add;
	return error;
}

static void qdx_tc_mirror_packet(void *object, struct sk_buff *skb,
				 const struct qdx_rx_meta *metadata,
				 struct napi_struct *napi)
{
	struct qdx_tc_rule *rule = object;
	struct net_device *target = rule->target;
	struct net_device *source = rule->owner->dev;

	if (unlikely(!(READ_ONCE(target->flags) & IFF_UP) || !netif_carrier_ok(target) ||
		     READ_ONCE(target->reg_state) != NETREG_REGISTERED ||
		     READ_ONCE(source->reg_state) != NETREG_REGISTERED ||
		     !pskb_may_pull(skb, ETH_HLEN))) {
		kfree_skb(skb);
		return;
	}
	/* Recreate the physical ingress position's packet geometry, using the
	 * same Ethernet pull and one VLAN untag as native ingress before TC.
	 * This fresh clone never executes the source's RX or classification again.
	 */
	skb->protocol = eth_type_trans(skb, source);
	skb_reset_network_header(skb);
	skb_reset_transport_header(skb);
	skb_reset_mac_len(skb);
	if (eth_type_vlan(skb->protocol)) {
		skb = skb_vlan_untag(skb);
		if (!skb)
			return;
	}
	nf_reset_ct(skb);
	if (dev_is_mac_header_xmit(target))
		skb_push_rcsum(skb, skb->mac_len);
	skb->skb_iif = source->ifindex;
	skb->dev = target;
	skb->priority = metadata->priority;
	skb_set_queue_mapping(skb, 0);
	/* Ordinary target TX owns its egress TC/qdisc and any target encapsulation. */
	dev_queue_xmit(skb);
}

static const struct qdx_receive_ops qdx_tc_mirror_receive = {
	.packet = qdx_tc_mirror_packet,
};

static int qdx_tc_match_close(struct qdx_tc_owner *owner)
{
	struct qdx_tc_match *table = &owner->match;
	struct qdx_tc_rule *rule;
	__le32 empty = 0;
	int error;

	if (table->rx) {
		error = qdx_rx_hold(table->rx);
		if (error)
			return error;
		table->held = true;
	}
	if (table->configure.request) {
		error = qdx_tc_rule_command(&table->configure, table->endpoint,
			QDX_MATCH_CONFIG, &table->profile, sizeof(table->profile));
		if (table->configure.request)
			return error;
		table->configured = !error;
	}
	if (table->attach.request) {
		u32 ifnum;
		__le32 next;

		error = qdx_endpoint_ifnum(table->endpoint, &ifnum);
		if (error && !qdx_service_access_ended(table->service))
			return error;
		next = cpu_to_le32(error ? 0 : ifnum);

		error = qdx_tc_rule_command(&table->attach, table->source_endpoint,
			QDX_TC_SET_NEXTHOP, &next, sizeof(next));
		if (table->attach.request)
			return error;
		table->attached = !error;
	}
	if (qdx_service_access_ended(table->service))
		table->attached = false;
	if (table->attached || table->detach.request) {
		error = qdx_tc_rule_command(&table->detach, table->source_endpoint,
			QDX_TC_RESET_NEXTHOP, &empty, sizeof(empty));
		if (error)
			return error;
		table->attached = false;
	}
	list_for_each_entry(rule, &owner->rules, list) {
		if (rule->table != table)
			continue;
		if (rule->install.request) {
			error = qdx_tc_match_rule(rule, true);
			if (rule->install.request)
				return error;
		}
		if (rule->installed || rule->remove.request) {
			error = qdx_tc_match_rule(rule, false);
			if (error)
				return error;
		}
	}
	if (table->endpoint) {
		error = qdx_endpoint_retire(table->endpoint);
		if (error)
			return error;
		qdx_endpoint_put(table->endpoint);
		table->endpoint = NULL;
	}
	table->configured = false;
	return 0;
}

static int qdx_tc_match_prepare(struct qdx_tc_rule *rule)
{
	struct qdx_tc_owner *owner = rule->owner;
	struct qdx_tc_match *table = &owner->match;
	struct qdx_match_config profile;
	struct qdx_tc_rule *other;
	struct qdx_owner holder = {
		.module = THIS_MODULE, .object = owner,
		.get = qdx_tc_owner_get, .put = qdx_tc_owner_put,
	};
	struct qdx_endpoint *endpoint;
	unsigned int slot, free_mask = QDX_MATCH_MASKS;
	u32 source;
	__le32 next;
	int error;

	if (!table->service) {
		table->service = qdx_service_get(owner->dev, QDX_SERVICE_MATCH);
		if (IS_ERR(table->service)) {
			error = PTR_ERR(table->service);
			table->service = NULL;
			return error;
		}
		qdx_tc_command_init(&table->configure, owner, &holder);
		qdx_tc_command_init(&table->attach, owner, &holder);
		qdx_tc_command_init(&table->detach, owner, &holder);
	}
	if (!table->source_endpoint) {
		endpoint = qdx_endpoint_get(table->service, owner->dev);
		if (IS_ERR(endpoint))
			return PTR_ERR(endpoint);
		table->source_endpoint = endpoint;
	}
	error = qdx_endpoint_ifnum(table->source_endpoint, &source);
	if (error)
		return error;
	error = qdx_tc_match_encode(rule, source);
	if (error)
		return error;
	if (!table->rx) {
		table->rx = qdx_rx_acquire(table->source_endpoint, owner->dev);
		if (IS_ERR(table->rx)) {
			error = PTR_ERR(table->rx);
			table->rx = NULL;
			return error;
		}
	}
	error = qdx_rx_hold(table->rx);
	if (error)
		return error;
	table->held = true;
	profile = table->profile;
	if (profile.profile && profile.profile != rule->profile.profile) {
		list_for_each_entry(other, &owner->rules, list)
			if (other != rule && other != rule->old && other->table == table &&
			    other->native_current && !other->retiring)
				return -EOPNOTSUPP;
		memset(&profile, 0, sizeof(profile));
	}
	profile.profile = rule->profile.profile;
	if (rule->slot_reserved) {
		slot = rule->mask_slot;
		memcpy(profile.masks[slot], rule->profile.masks[0], sizeof(profile.masks[slot]));
		profile.valid_masks |= cpu_to_le32(BIT(slot));
		goto have_mask;
	}
	for (slot = 0; slot < QDX_MATCH_MASKS; slot++) {
		if (!memcmp(profile.masks[slot], rule->profile.masks[0], sizeof(profile.masks[slot])) &&
		    (le32_to_cpu(profile.valid_masks) & BIT(slot)))
			break;
		if (!table->mask_users[slot] && free_mask == QDX_MATCH_MASKS)
			free_mask = slot;
	}
	if (slot == QDX_MATCH_MASKS) {
		if (free_mask == QDX_MATCH_MASKS)
			return -ENOSPC;
		slot = free_mask;
		memcpy(profile.masks[slot], rule->profile.masks[0], sizeof(profile.masks[slot]));
		profile.valid_masks |= cpu_to_le32(BIT(slot));
	}
have_mask:
	if (!rule->slot_reserved) {
		unsigned int id = find_first_zero_bit(&table->rules, QDX_MATCH_RULES);

		if (id == QDX_MATCH_RULES)
			return -ENOSPC;
		rule->rule_slot = id;
		rule->mask_slot = slot;
		rule->slot_reserved = true;
		rule->table = table;
		__set_bit(id, &table->rules);
		table->mask_users[slot]++;
	}
	if (table->configured && memcmp(&profile, &table->profile, sizeof(profile))) {
		/* A configured table is a real firmware object. Rebuild it under the
		 * same source hold; old rule encodings/identities remain owned below.
		 */
		error = qdx_tc_match_close(owner);
		if (error)
			return error;
	}
	if (table->configure.request && memcmp(&profile, &table->profile, sizeof(profile)))
		return -EBUSY;
	if (!table->endpoint) {
		endpoint = qdx_endpoint_alloc(table->service, QDX_TC_DYNAMIC_MATCH);
		if (IS_ERR(endpoint))
			return PTR_ERR(endpoint);
		table->endpoint = endpoint;
	}
	error = qdx_endpoint_wait(table->endpoint, jiffies + QDX_TC_RULE_TIMEOUT);
	if (error)
		return error;
	if (!table->configured) {
		table->profile = profile; /* Original CONFIG input, not an ACK assertion. */
		error = qdx_tc_rule_command(&table->configure, table->endpoint,
			QDX_MATCH_CONFIG, &table->profile, sizeof(table->profile));
		if (error)
			return error;
		table->configured = true;
	}
	list_for_each_entry(other, &owner->rules, list) {
		if (other == rule || other->table != table || other->retiring || !other->native_current ||
		    other->installed || other->profile.profile != table->profile.profile)
			continue;
		error = qdx_tc_match_rule(other, true);
		if (error)
			return error;
	}
	if (!rule->installed) {
		error = qdx_tc_match_rule(rule, true);
		if (error)
			return error;
	}
	if (!table->attached) {
		error = qdx_endpoint_ifnum(table->endpoint, &source);
		if (error)
			return error;
		next = cpu_to_le32(source);
		error = qdx_tc_rule_command(&table->attach, table->source_endpoint,
			QDX_TC_SET_NEXTHOP, &next, sizeof(next));
		if (error)
			return error;
		table->attached = true;
	}
	return 0;
}

static int qdx_tc_mirror_prepare(struct qdx_tc_rule *rule)
{
	struct qdx_tc_owner *owner = rule->owner;
	struct qdx_owner holder = {
		.module = THIS_MODULE, .object = rule,
		.get = qdx_tc_rule_get, .put = qdx_tc_rule_put,
	};
	struct qdx_endpoint *endpoint;
	u32 ifnum;
	__le32 next;
	int error;

	if (!rule->service) {
		rule->service = qdx_service_get(owner->dev, QDX_SERVICE_MIRROR);
		if (IS_ERR(rule->service)) {
			error = PTR_ERR(rule->service);
			rule->service = NULL;
			return error;
		}
	}
	if (!rule->source_endpoint) {
		endpoint = qdx_endpoint_get(rule->service, owner->dev);
		if (IS_ERR(endpoint))
			return PTR_ERR(endpoint);
		rule->source_endpoint = endpoint;
	}
	if (!rule->rx) {
		rule->rx = qdx_rx_acquire(rule->source_endpoint, owner->dev);
		if (IS_ERR(rule->rx)) {
			error = PTR_ERR(rule->rx);
			rule->rx = NULL;
			return error;
		}
	}
	error = qdx_rx_hold(rule->rx);
	if (error)
		return error;
	rule->held = true;
	if (!rule->endpoint) {
		endpoint = qdx_endpoint_alloc(rule->service, QDX_TC_DYNAMIC_MIRROR);
		if (IS_ERR(endpoint))
			return PTR_ERR(endpoint);
		rule->endpoint = endpoint;
	}
	error = qdx_endpoint_wait(rule->endpoint, jiffies + QDX_TC_RULE_TIMEOUT);
	if (error)
		return error;
	if (!rule->receiver) {
		rule->receiver = qdx_endpoint_receive_register(rule->endpoint,
			QDX_RECEIVE_PACKET, &holder, &qdx_tc_mirror_receive);
		if (IS_ERR(rule->receiver)) {
			error = PTR_ERR(rule->receiver);
			rule->receiver = NULL;
			return error;
		}
	}
	if (!rule->configured) {
		rule->wire.mirror.clone_point = cpu_to_le32(1);
		error = qdx_tc_rule_command(&rule->configure, rule->endpoint,
			QDX_MIRROR_CONFIG, &rule->wire.mirror, sizeof(rule->wire.mirror));
		if (error)
			return error;
		rule->configured = true;
	}
	if (!rule->continued) {
		next = cpu_to_le32(QDX_TC_ETH_RX_IFNUM);
		error = qdx_tc_rule_command(&rule->configure, rule->endpoint,
			QDX_MIRROR_SET_NEXTHOP, &next, sizeof(next));
		if (error)
			return error;
		rule->continued = true;
	}
	if (!rule->installed) {
		error = qdx_tc_rule_command(&rule->install, rule->endpoint, QDX_MIRROR_ENABLE, NULL, 0);
		if (error)
			return error;
		rule->installed = true;
	}
	if (!rule->attached) {
		error = qdx_endpoint_ifnum(rule->endpoint, &ifnum);
		if (error)
			return error;
		next = cpu_to_le32(ifnum);
		error = qdx_tc_rule_command(&rule->source_attach, rule->source_endpoint,
			QDX_TC_SET_NEXTHOP, &next, sizeof(next));
		if (error)
			return error;
		rule->attached = true;
	}
	return 0;
}

static int qdx_tc_mirror_retire(struct qdx_tc_rule *rule)
{
	__le32 payload = 0;
	u32 opcode;
	int error;

	if (rule->rx) {
		error = qdx_rx_hold(rule->rx);
		if (error)
			return error;
		rule->held = true;
	}
	/* Settle original construction operations before issuing their inverses.
	 * The configure slot is reused only after its previous recipient ended.
	 */
	if (rule->configure.request) {
		spin_lock_bh(&rule->configure.lock);
		opcode = rule->configure.result.opcode;
		spin_unlock_bh(&rule->configure.lock);
		payload = cpu_to_le32(QDX_TC_ETH_RX_IFNUM);
		if (opcode == QDX_MIRROR_CONFIG)
			error = qdx_tc_rule_command(&rule->configure, rule->endpoint, opcode,
				&rule->wire.mirror, sizeof(rule->wire.mirror));
		else
			error = qdx_tc_rule_command(&rule->configure, rule->endpoint, opcode,
				opcode == QDX_MIRROR_SET_NEXTHOP ? &payload : NULL,
				opcode == QDX_MIRROR_SET_NEXTHOP ? sizeof(payload) : 0);
		if (rule->configure.request)
			return error;
		if (!error) {
			if (opcode == QDX_MIRROR_CONFIG)
				rule->configured = true;
			else
				rule->continued = opcode == QDX_MIRROR_SET_NEXTHOP;
		}
	}
	if (rule->install.request) {
		error = qdx_tc_rule_command(&rule->install, rule->endpoint,
			QDX_MIRROR_ENABLE, NULL, 0);
		if (rule->install.request)
			return error;
		rule->installed = !error;
	}
	if (rule->source_attach.request) {
		u32 ifnum;

		error = qdx_endpoint_ifnum(rule->endpoint, &ifnum);
		if (error && !qdx_service_access_ended(rule->service))
			return error;
		payload = cpu_to_le32(error ? 0 : ifnum);
		error = qdx_tc_rule_command(&rule->source_attach, rule->source_endpoint,
			QDX_TC_SET_NEXTHOP, &payload, sizeof(payload));
		if (rule->source_attach.request)
			return error;
		rule->attached = !error;
	}
	if (qdx_service_access_ended(rule->service)) {
		rule->attached = false;
		rule->installed = false;
		rule->continued = false;
	}
	if (rule->attached || rule->source_detach.request) {
		payload = 0;
		error = qdx_tc_rule_command(&rule->source_detach, rule->source_endpoint,
			QDX_TC_RESET_NEXTHOP, &payload, sizeof(payload));
		if (error)
			return error;
		rule->attached = false;
	}
	if (rule->installed || rule->remove.request) {
		error = qdx_tc_rule_command(&rule->remove, rule->endpoint,
			QDX_MIRROR_DISABLE, NULL, 0);
		if (error)
			return error;
		rule->installed = false;
	}
	if (rule->continued) {
		error = qdx_tc_rule_command(&rule->configure, rule->endpoint,
			QDX_MIRROR_RESET_NEXTHOP, NULL, 0);
		if (error)
			return error;
		rule->continued = false;
	}
	if (rule->endpoint) {
		error = qdx_endpoint_retire(rule->endpoint);
		if (error)
			return error;
	}
	if (rule->receiver) {
		error = qdx_endpoint_receive_unregister(rule->receiver);
		if (error)
			return error;
		rule->receiver = NULL;
	}
	if (rule->endpoint) {
		qdx_endpoint_put(rule->endpoint);
		rule->endpoint = NULL;
	}
	rule->configured = false;
	if ((rule->flags & TCA_CLS_FLAGS_SKIP_SW) && rule->native_current &&
	    !rule->owner->native_dead && rule->rx)
		return -EINPROGRESS;
	if (rule->resume_rx) {
		error = qdx_rx_release(rule->resume_rx);
		if (error)
			return error;
		rule->resume_rx = NULL;
	}
	if (rule->rx) {
		error = qdx_rx_release(rule->rx);
		if (error)
			return error;
		rule->rx = NULL;
	}
	if (rule->source_endpoint) {
		qdx_endpoint_put(rule->source_endpoint);
		rule->source_endpoint = NULL;
	}
	rule->configured = false;
	rule->held = false;
	return 0;
}

void qdx_tc_rules_retire(struct qdx_tc_owner *owner)
{
	struct qdx_tc_match *table = &owner->match;
	struct qdx_tc_rule *rule, *next;
	struct qdx_tc_block *block;
	bool table_used = false, igs_ended = false;
	int error;

	lockdep_assert_held(&owner->cfg);
	list_for_each_entry_safe(rule, next, &owner->rules, list) {
		bool required = (rule->flags & TCA_CLS_FLAGS_SKIP_SW) && rule->native_current &&
			!owner->native_dead;
		struct qdx_tc_view *view;
		bool consumers = false;
		unsigned int member;
		if (owner->closing || owner->native_dead ||
		    qdx_service_state(owner->service) == QDX_FAILED)
			rule->retiring = true;
		if (!rule->retiring && !rule->release_igs) {
			table_used |= rule->table != NULL;
			continue;
		}
		if (rule->replacement && rule->replacement->native_count &&
		    rule->replacement->installed && !rule->replacement->retiring &&
		    ((rule->replacement->table && !rule->replacement->table->held) ||
		     (rule->replacement->rx && !rule->replacement->held)))
			required = false;
		spin_lock_bh(&owner->data_lock);
		list_for_each_entry(view, &owner->views, list) {
			if (refcount_read(&view->refs) <= 1)
				continue;
			for (member = 0; member < view->nr_rules; member++)
				consumers |= view->rules[member] == rule;
		}
		spin_unlock_bh(&owner->data_lock);
		if (consumers) {
			table_used |= rule->table != NULL;
			continue;
		}
		/* Immutable views still hold the original rule and its association.
		 * Closing publication precedes this check; no new view can acquire it.
		 */
		if (rule->igs) {
			error = qdx_tc_igs_retire(rule->igs);
			if (error)
				continue;
			rule->igs = NULL;
			igs_ended = true;
		}
		rule->release_igs = false;
		if (!rule->retiring) {
			table_used |= rule->table != NULL;
			continue; /* The native redirect memo still exists. */
		}
		if (rule->action == QDX_TC_MIRROR && rule->service) {
			error = qdx_tc_mirror_retire(rule);
			if (error)
				continue;
		}
		if (rule->table) {
			if (rule->install.request) {
				error = qdx_tc_match_rule(rule, true);
				if (rule->install.request) {
					table_used = true;
					continue;
				}
			}
			if (rule->installed || rule->remove.request) {
				error = qdx_tc_match_rule(rule, false);
				if (error) {
					table_used = true;
					continue;
				}
			}
		}
		if (rule->configure.request || rule->install.request || rule->remove.request ||
		    rule->source_attach.request || rule->source_detach.request ||
		    !completion_done(&rule->configure.recipient_done) ||
		    !completion_done(&rule->install.recipient_done) ||
		    !completion_done(&rule->remove.recipient_done) ||
		    !completion_done(&rule->source_attach.recipient_done) ||
		    !completion_done(&rule->source_detach.recipient_done)) {
			table_used |= rule->table != NULL;
			continue;
		}
		if (rule->slot_reserved) {
			__clear_bit(rule->rule_slot, &table->rules);
			table->mask_users[rule->mask_slot]--;
			rule->slot_reserved = false;
			rule->table = NULL;
		}
		/* A real native count obligation survives resource failure until the
		 * native callback actually withdraws that original contribution.
		 */
		if (rule->native_count || required) {
			if (rule->action == QDX_TC_DROP || rule->action == QDX_TC_SET_PRIORITY)
				table_used = true;
			continue;
		}
		if (rule->old && rule->old->replacement == rule)
			rule->old->replacement = NULL;
		if (rule->replacement && rule->replacement->old == rule) {
			rule->replacement->old = NULL;
			rule->replacement = NULL;
			qdx_tc_rule_put(rule); /* The settled successor's rollback backup. */
		}
		list_del_init(&rule->list);
		qdx_tc_rule_put(rule);
	}
	/* Only the actual end of the old source route reopens callbacks which
	 * waited for it. A returned optional offer did not acquire a native count.
	 */
	if (igs_ended && list_empty(&owner->associations)) {
		list_for_each_entry(block, &owner->blocks, list) {
			if (block->dead || !block->native || !block->replay_needed)
				continue;
			WRITE_ONCE(owner->replay_needed, true);
			qdx_tc_schedule(owner);
			break;
		}
	}
	if (table_used || !table->service)
		return;
	error = qdx_tc_match_close(owner);
	if (error)
		return;
	if (table->resume_rx) {
		error = qdx_rx_release(table->resume_rx);
		if (error)
			return;
		table->resume_rx = NULL;
	}
	if (table->rx) {
		error = qdx_rx_release(table->rx);
		if (error)
			return;
		table->rx = NULL;
	}
	if (!completion_done(&table->configure.recipient_done) ||
	    !completion_done(&table->attach.recipient_done) ||
	    !completion_done(&table->detach.recipient_done))
		return;
	if (table->source_endpoint)
		qdx_endpoint_put(table->source_endpoint);
	qdx_service_put(table->service);
	memset(table, 0, sizeof(*table));
}

int qdx_tc_rules_activate(struct qdx_tc_owner *owner, struct qdx_tc_view *view)
{
	struct qdx_tc_match *table = &owner->match;
	struct qdx_tc_rule *other;
	bool source_route = table->rx || table->endpoint || table->attach.request;
	unsigned int i;
	int error;

	ASSERT_RTNL();
	lockdep_assert_held(&owner->cfg);
	if (view->invalid || owner->closing || owner->native_dead)
		return -ESTALE;
	list_for_each_entry(other, &owner->rules, list) {
		if (other->release_igs && other->igs)
			return -EINPROGRESS;
		if (other->action == QDX_TC_MIRROR &&
		    (other->rx || other->endpoint || other->source_attach.request))
			source_route = true;
	}
	for (i = 0; i < view->nr_rules; i++) {
		struct qdx_tc_rule *rule = view->rules[i];

		if (!rule->native_current || rule->retiring)
			return -ESTALE;
		if (rule->action == QDX_TC_REDIRECT_IFB) {
			/* The same physical interface has one selected next-hop field.
			 * Keep this native memo, including its precedence proof; only a
			 * flow selecting it requires an available IGS association.
			 */
			if (source_route)
				continue;
			error = qdx_tc_igs_prepare(rule);
		} else if (rule->memo_only) {
			error = 0;
		} else if (!rule->native_count) {
			return -EOPNOTSUPP; /* A failed callback did not gain authority later. */
		} else if (rule->action == QDX_TC_MIRROR) {
			error = qdx_tc_mirror_prepare(rule);
		} else {
			error = qdx_tc_match_prepare(rule);
		}
		if (error)
			return error;
	}
	/* A replacing MIRROR has acquired its own real held reservation before
	 * this point. Retire only the old reservation, while the new one still
	 * holds this source and the complete current native view is established.
	 */
	for (i = 0; i < view->nr_rules; i++) {
		struct qdx_tc_rule *rule = view->rules[i];
		struct qdx_tc_rule *old = rule->old;

		if (!old || !old->rx || old->installed || old->attached ||
		    !((rule->rx && rule->held) || (rule->table && rule->table->rx && rule->table->held)))
			continue;
		error = qdx_rx_release(old->rx);
		if (error)
			return error;
		old->rx = NULL;
		old->held = false;
	}
	/* The owner checks the same pending view under common use/data locks
	 * before and after this sleepable publication step. A concurrent native
	 * mutation invalidates first, then waits for cfg and takes the real hold.
	 */
	qdx_uses_lock();
	spin_lock_bh(&owner->data_lock);
	error = view->invalid || owner->closing ? -ESTALE : 0;
	spin_unlock_bh(&owner->data_lock);
	qdx_uses_unlock();
	if (error)
		return error;
	if (table->rx && table->held) {
		if (!table->resume_rx) {
			table->resume_rx = qdx_rx_acquire(table->source_endpoint, owner->dev);
			if (IS_ERR(table->resume_rx)) {
				error = PTR_ERR(table->resume_rx);
				table->resume_rx = NULL;
				return error;
			}
		}
		error = qdx_rx_release(table->rx);
		if (error)
			return error;
		table->rx = table->resume_rx;
		table->resume_rx = NULL;
		table->held = false;
	}
	for (i = 0; i < view->nr_rules; i++) {
		struct qdx_tc_rule *rule = view->rules[i];

		if (!rule->rx || !rule->held)
			continue;
		if (!rule->resume_rx) {
			rule->resume_rx = qdx_rx_acquire(rule->source_endpoint, owner->dev);
			if (IS_ERR(rule->resume_rx)) {
				error = PTR_ERR(rule->resume_rx);
				rule->resume_rx = NULL;
				return error;
			}
		}
		error = qdx_rx_release(rule->rx);
		if (error)
			return error;
		rule->rx = rule->resume_rx;
		rule->resume_rx = NULL;
		rule->held = false;
	}
	return 0;
}

int qdx_tc_block_setup(struct qdx_tc_block *block, enum tc_setup_type type, void *data)
{
	struct qdx_tc_owner *owner = block->owner;
	struct flow_cls_common_offload *common;
	struct flow_rule *native;
	struct qdx_tc_rule *rule, *other, *old = NULL;
	unsigned long cookie, replace_cookie = 0;
	u32 classid = 0;
	bool destroy, stats, matchall = type == TC_SETUP_CLSMATCHALL;
	int error;

	lockdep_assert_not_held(&owner->cfg);
	if (type == TC_SETUP_CLSFLOWER) {
		struct flow_cls_offload *offer = data;

		common = &offer->common;
		native = offer->rule;
		cookie = offer->cookie;
		replace_cookie = offer->replace_cookie;
		classid = offer->classid;
		destroy = offer->command == FLOW_CLS_DESTROY;
		stats = offer->command == FLOW_CLS_STATS;
		if (!destroy && !stats && offer->command != FLOW_CLS_REPLACE)
			return -EOPNOTSUPP;
	} else if (matchall) {
		struct tc_cls_matchall_offload *offer = data;

		common = &offer->common;
		native = offer->rule;
		cookie = offer->cookie;
		classid = offer->classid;
		destroy = offer->command == TC_CLSMATCHALL_DESTROY;
		stats = offer->command == TC_CLSMATCHALL_STATS;
		if (!destroy && !stats && offer->command != TC_CLSMATCHALL_REPLACE)
			return -EOPNOTSUPP;
	} else {
		return -EOPNOTSUPP;
	}
	if (stats)
		return -EOPNOTSUPP; /* No selected source supplies per-action byte deltas. */
	if (destroy) {
		error = qdx_tc_invalidate(owner, false, true);
		mutex_lock(&owner->cfg);
		list_for_each_entry(rule, &owner->rules, list) {
			if (rule->native_block != block->native || rule->cookie != cookie ||
			    (rule->retiring && !rule->native_count))
				continue;
			rule->retiring = true;
			/* The native count must be returned once even when physical
			 * cleanup has to retain an UNKNOWN operation under its real hold.
			 */
			error = rule->native_count ? 0 : -EOPNOTSUPP;
			if (rule->native_count) {
				rule->native_count = false;
				module_put(THIS_MODULE);
			}
			goto removed;
		}
		error = -EOPNOTSUPP;
removed:
		mutex_unlock(&owner->cfg);
		qdx_tc_schedule(owner);
		return error;
	}
	if (!tc_can_offload(owner->dev))
		return -EOPNOTSUPP;
	rule = qdx_tc_copy_offer(block, common, native, cookie, replace_cookie, classid, matchall);
	if (IS_ERR(rule))
		return PTR_ERR(rule);
	error = qdx_tc_actions_admit(rule);
	if (error)
		goto put;
	error = qdx_tc_invalidate(owner, false, true);
	if (error)
		goto put;
	mutex_lock(&owner->cfg);
	if (block->dead || !block->native || owner->closing || !tc_can_offload(owner->dev)) {
		error = -EOPNOTSUPP;
		goto unlock;
	}
	list_for_each_entry(other, &owner->rules, list) {
		if (other->native_block == block->native && other->cookie == cookie) {
			if (!other->retiring) {
				if (other->native_count) {
					error = -EALREADY;
					goto unlock;
				}
				/* A real replay may keep the filter cookie while a shared
				 * action changed. Keep old execution references, not its old
				 * action values as the new native membership's authority.
				 */
				other->retiring = true;
			}
			old = other;
		}
		if (replace_cookie && other->native_block == block->native && other->cookie == replace_cookie)
			old = other;
	}
	list_for_each_entry(other, &owner->rules, list) {
		if (other == old || !other->retiring || other->action != QDX_TC_MIRROR)
			continue;
		if (other->attached || other->source_attach.request || other->source_detach.request) {
			error = -EINPROGRESS;
			goto unlock;
		}
	}
	if (old) {
		qdx_tc_rule_get(old);
		rule->old = old;
		old->replacement = rule;
	}
	rule->memo_only = !(rule->flags & TCA_CLS_FLAGS_SKIP_SW) &&
		(rule->action == QDX_TC_PASS || rule->action == QDX_TC_SET_PRIORITY ||
		 rule->action == QDX_TC_REDIRECT_IFB);
	if (rule->memo_only) {
		list_add_tail(&rule->list, &owner->rules);
		mutex_unlock(&owner->cfg);
		qdx_tc_schedule(owner);
		return -EOPNOTSUPP;
	}
	if (owner->direction != QDX_TC_INGRESS || rule->classid ||
	    (rule->action != QDX_TC_DROP && rule->action != QDX_TC_SET_PRIORITY &&
	     rule->action != QDX_TC_MIRROR)) {
		error = -EOPNOTSUPP;
		goto unlock;
	}
	if (rule->action == QDX_TC_MIRROR && (!matchall ||
	    rule->protocol != htons(ETH_P_ALL) || !(rule->flags & TCA_CLS_FLAGS_SKIP_SW))) {
		error = -EOPNOTSUPP;
		goto unlock;
	}
	list_for_each_entry(other, &owner->rules, list) {
		if (other == old || other->retiring)
			continue;
		if (other->action == QDX_TC_MIRROR || rule->action == QDX_TC_MIRROR ||
		    !qdx_tc_disjoint(&rule->key, &rule->mask, &other->key, &other->mask)) {
			error = -EOPNOTSUPP;
			goto unlock;
		}
	}
	/* The list retains every exposed original, even when this callback later
	 * returns timeout. No async recipient points into provisional stack data.
	 */
	list_add_tail(&rule->list, &owner->rules);
	if (!list_empty(&owner->associations)) {
		/* Native callbacks may hold RTNL. Close the published flow uses now,
		 * then let their actual puts and the existing worker retire IGS.
		 * A later real replay, never this failed offer, grants in_hw.
		 */
		list_for_each_entry(other, &owner->rules, list)
			if (other->igs)
				other->release_igs = true;
		block->replay_needed = true;
		error = -EINPROGRESS;
		goto retained;
	}
	if (old && old->action == QDX_TC_MIRROR) {
		error = qdx_tc_mirror_retire(old);
		if (error && (error != -EINPROGRESS || old->endpoint || old->installed ||
			      old->attached || !old->rx || !old->held))
			goto retained;
	}
	if (rule->action == QDX_TC_MIRROR && owner->match.service) {
		error = qdx_tc_match_close(owner);
		if (error)
			goto retained;
	}
	if (rule->action == QDX_TC_MIRROR)
		error = qdx_tc_mirror_prepare(rule);
	else
		error = qdx_tc_match_prepare(rule);
retained:
	if (error)
		rule->retiring = true;
	else if (try_module_get(THIS_MODULE))
		rule->native_count = true;
	else {
		rule->retiring = true;
		error = -ESHUTDOWN;
	}
	mutex_unlock(&owner->cfg);
	qdx_tc_schedule(owner);
	return error;
unlock:
	if (old && old->replacement == rule)
		old->replacement = NULL;
	mutex_unlock(&owner->cfg);
put:
	qdx_tc_rule_put(rule);
	return error;
}
