// SPDX-License-Identifier: GPL-2.0-only
#include <linux/etherdevice.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/unaligned.h>
#include <linux/tc_act/tc_csum.h>
#include <linux/netfilter/nf_conntrack_tcp.h>
#include "flow.h"

static int qdx_flow_match_copy(struct qdx_flow_offer *offer,
			       const struct flow_rule *rule)
{
	struct nf_flow_match *dst = &offer->match;
	struct flow_dissector *dissector = &dst->dissector;
	struct nf_flow_key expected = {};
	struct flow_match_meta meta;
	struct flow_match_control control;
	struct flow_match_basic basic;
	struct flow_match_ports ports;
	u64 allowed, required;

	required = BIT_ULL(FLOW_DISSECTOR_KEY_META) |
		   BIT_ULL(FLOW_DISSECTOR_KEY_CONTROL) |
		   BIT_ULL(FLOW_DISSECTOR_KEY_BASIC) |
		   BIT_ULL(FLOW_DISSECTOR_KEY_PORTS);
	allowed = required | BIT_ULL(FLOW_DISSECTOR_KEY_IPV4_ADDRS) |
		  BIT_ULL(FLOW_DISSECTOR_KEY_IPV6_ADDRS) |
		  BIT_ULL(FLOW_DISSECTOR_KEY_TCP) |
		  BIT_ULL(FLOW_DISSECTOR_KEY_VLAN) |
		  BIT_ULL(FLOW_DISSECTOR_KEY_CVLAN);
	if ((rule->match.dissector->used_keys & required) != required ||
	    rule->match.dissector->used_keys & ~allowed)
		return -EOPNOTSUPP;

	flow_rule_match_meta(rule, &meta);
	flow_rule_match_control(rule, &control);
	flow_rule_match_basic(rule, &basic);
	flow_rule_match_ports(rule, &ports);
	dst->key.meta = *meta.key;
	dst->mask.meta = *meta.mask;
	dst->key.control = *control.key;
	dst->mask.control = *control.mask;
	dst->key.basic = *basic.key;
	dst->mask.basic = *basic.mask;
	dst->key.tp = *ports.key;
	dst->mask.tp = *ports.mask;
	expected.meta.ingress_ifindex = U32_MAX;
	expected.control.addr_type = U16_MAX;
	expected.basic.n_proto = cpu_to_be16(U16_MAX);
	expected.basic.ip_proto = U8_MAX;
	expected.tp.src = cpu_to_be16(U16_MAX);
	expected.tp.dst = cpu_to_be16(U16_MAX);
	dissector->offset[FLOW_DISSECTOR_KEY_META] = offsetof(struct nf_flow_key, meta);
	dissector->offset[FLOW_DISSECTOR_KEY_CONTROL] = offsetof(struct nf_flow_key, control);
	dissector->offset[FLOW_DISSECTOR_KEY_BASIC] = offsetof(struct nf_flow_key, basic);
	dissector->offset[FLOW_DISSECTOR_KEY_PORTS] = offsetof(struct nf_flow_key, tp);

	if (basic.key->n_proto == htons(ETH_P_IP) &&
	    control.key->addr_type == FLOW_DISSECTOR_KEY_IPV4_ADDRS &&
	    flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_IPV4_ADDRS) &&
	    !flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_IPV6_ADDRS)) {
		struct flow_match_ipv4_addrs ip;

		flow_rule_match_ipv4_addrs(rule, &ip);
		dst->key.ipv4 = *ip.key;
		dst->mask.ipv4 = *ip.mask;
		memset(&expected.ipv4, 0xff, sizeof(expected.ipv4));
		dissector->offset[FLOW_DISSECTOR_KEY_IPV4_ADDRS] = offsetof(struct nf_flow_key, ipv4);
		offer->input.family = AF_INET;
		offer->input.source.s6_addr32[0] = ip.key->src;
		offer->input.destination.s6_addr32[0] = ip.key->dst;
	} else if (basic.key->n_proto == htons(ETH_P_IPV6) &&
		   control.key->addr_type == FLOW_DISSECTOR_KEY_IPV6_ADDRS &&
		   flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_IPV6_ADDRS) &&
		   !flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_IPV4_ADDRS)) {
		struct flow_match_ipv6_addrs ip;

		flow_rule_match_ipv6_addrs(rule, &ip);
		dst->key.ipv6 = *ip.key;
		dst->mask.ipv6 = *ip.mask;
		memset(&expected.ipv6, 0xff, sizeof(expected.ipv6));
		dissector->offset[FLOW_DISSECTOR_KEY_IPV6_ADDRS] = offsetof(struct nf_flow_key, ipv6);
		offer->input.family = AF_INET6;
		offer->input.source = ip.key->src;
		offer->input.destination = ip.key->dst;
	} else {
		return -EOPNOTSUPP;
	}

	if (basic.key->ip_proto == IPPROTO_TCP) {
		struct flow_match_tcp tcp;

		if (!flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_TCP))
			return -EOPNOTSUPP;
		flow_rule_match_tcp(rule, &tcp);
		dst->key.tcp = *tcp.key;
		dst->mask.tcp = *tcp.mask;
		expected.tcp.flags = htons(be32_to_cpu(TCP_FLAG_FIN | TCP_FLAG_RST) >> 16);
		if (tcp.key->flags)
			return -EOPNOTSUPP;
		dissector->offset[FLOW_DISSECTOR_KEY_TCP] = offsetof(struct nf_flow_key, tcp);
	} else if (basic.key->ip_proto != IPPROTO_UDP ||
		   flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_TCP)) {
		return -EOPNOTSUPP;
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_VLAN)) {
		struct flow_match_vlan vlan;

		flow_rule_match_vlan(rule, &vlan);
		dst->key.vlan = *vlan.key;
		dst->mask.vlan = *vlan.mask;
		expected.vlan.vlan_id = VLAN_VID_MASK;
		expected.vlan.vlan_tpid = cpu_to_be16(U16_MAX);
		dissector->offset[FLOW_DISSECTOR_KEY_VLAN] = offsetof(struct nf_flow_key, vlan);
	}
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_CVLAN)) {
		struct flow_match_vlan vlan;

		if (!flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_VLAN))
			return -EOPNOTSUPP;
		flow_rule_match_cvlan(rule, &vlan);
		dst->key.cvlan = *vlan.key;
		dst->mask.cvlan = *vlan.mask;
		expected.cvlan.vlan_id = VLAN_VID_MASK;
		expected.cvlan.vlan_tpid = cpu_to_be16(U16_MAX);
		dissector->offset[FLOW_DISSECTOR_KEY_CVLAN] = offsetof(struct nf_flow_key, cvlan);
	}
	/* Only fields proven by the native producer are exact. In particular,
	 * its VLAN match does not make PCP or DEI known packet facts.
	 */
	if (memcmp(&dst->mask, &expected, sizeof(expected)))
		return -EOPNOTSUPP;
	dissector->used_keys = rule->match.dissector->used_keys;
	offer->input.protocol = basic.key->ip_proto;
	offer->input.source_port = ports.key->src;
	offer->input.destination_port = ports.key->dst;
	offer->output = offer->input;
	offer->facts = flow_rule_alloc(0);
	if (!offer->facts)
		return -ENOMEM;
	offer->facts->match.dissector = dissector;
	offer->facts->match.key = &dst->key;
	offer->facts->match.mask = &dst->mask;
	return 0;
}

static int qdx_flow_mangle(struct qdx_flow_offer *offer,
			   const struct flow_action_entry *entry,
			   u8 mac[12], u8 known[12], bool *nat)
{
	u8 bytes[sizeof(struct in6_addr) * 2];
	u32 value, offset = entry->mangle.offset;
	u8 *target;
	unsigned int size;

	switch (entry->mangle.htype) {
	case FLOW_ACT_MANGLE_HDR_TYPE_ETH:
		target = mac;
		size = 12;
		break;
	case FLOW_ACT_MANGLE_HDR_TYPE_IP4:
		if (offer->input.family != AF_INET || offset < offsetof(struct iphdr, saddr))
			return -EOPNOTSUPP;
		offset -= offsetof(struct iphdr, saddr);
		memcpy(bytes, &offer->output.source.s6_addr32[0], 4);
		memcpy(bytes + 4, &offer->output.destination.s6_addr32[0], 4);
		target = bytes;
		size = 8;
		*nat = true;
		break;
	case FLOW_ACT_MANGLE_HDR_TYPE_IP6:
		if (offer->input.family != AF_INET6 || offset < offsetof(struct ipv6hdr, saddr))
			return -EOPNOTSUPP;
		offset -= offsetof(struct ipv6hdr, saddr);
		memcpy(bytes, &offer->output.source, 16);
		memcpy(bytes + 16, &offer->output.destination, 16);
		target = bytes;
		size = 32;
		*nat = true;
		break;
	case FLOW_ACT_MANGLE_HDR_TYPE_TCP:
	case FLOW_ACT_MANGLE_HDR_TYPE_UDP:
		if ((entry->mangle.htype == FLOW_ACT_MANGLE_HDR_TYPE_TCP) !=
		    (offer->input.protocol == IPPROTO_TCP))
			return -EOPNOTSUPP;
		memcpy(bytes, &offer->output.source_port, 2);
		memcpy(bytes + 2, &offer->output.destination_port, 2);
		target = bytes;
		size = 4;
		*nat = true;
		break;
	default:
		return -EOPNOTSUPP;
	}
	if (offset > size - sizeof(value))
		return -EOPNOTSUPP;
	/* The native action contains raw host-endian words copied from the packet
	 * edit. Its mask preserves bits; unaligned access preserves that meaning.
	 */
	value = get_unaligned((u32 *)(target + offset));
	value = (value & entry->mangle.mask) | entry->mangle.val;
	put_unaligned(value, (u32 *)(target + offset));
	switch (entry->mangle.htype) {
	case FLOW_ACT_MANGLE_HDR_TYPE_ETH:
		value = get_unaligned((u32 *)(known + offset));
		value |= ~entry->mangle.mask;
		put_unaligned(value, (u32 *)(known + offset));
		break;
	case FLOW_ACT_MANGLE_HDR_TYPE_IP4:
		memcpy(&offer->output.source.s6_addr32[0], bytes, 4);
		memcpy(&offer->output.destination.s6_addr32[0], bytes + 4, 4);
		break;
	case FLOW_ACT_MANGLE_HDR_TYPE_IP6:
		memcpy(&offer->output.source, bytes, 16);
		memcpy(&offer->output.destination, bytes + 16, 16);
		break;
	default:
		memcpy(&offer->output.source_port, bytes, 2);
		memcpy(&offer->output.destination_port, bytes + 2, 2);
	}
	return 0;
}

static int qdx_flow_offer_parse(struct qdx_flow_offer *offer,
				const struct flow_rule *rule)
{
	const struct flow_action_entry *entry;
	u8 mac[12] = {}, known[12] = {};
	u32 checksum = 0, required_csum;
	bool nat = false, redirected = false;
	int i, error;

	error = qdx_flow_match_copy(offer, rule);
	if (error)
		return error;
	flow_action_for_each(i, entry, &rule->action) {
		if (redirected)
			return -EOPNOTSUPP;
		switch (entry->id) {
		case FLOW_ACTION_MANGLE:
			error = qdx_flow_mangle(offer, entry, mac, known, &nat);
			if (error)
				return error;
			break;
		case FLOW_ACTION_CSUM:
			checksum |= entry->csum_flags;
			break;
		case FLOW_ACTION_VLAN_POP:
			if (offer->vlan_push || offer->vlan_pop == 2)
				return -EOPNOTSUPP;
			offer->vlan_pop++;
			break;
		case FLOW_ACTION_VLAN_PUSH:
			if (offer->vlan_push == 2 || entry->vlan.vid > VLAN_VID_MASK ||
			    entry->vlan.prio > 7 ||
			    (entry->vlan.proto != htons(ETH_P_8021Q) &&
			     entry->vlan.proto != htons(ETH_P_8021AD)))
				return -EOPNOTSUPP;
			offer->tags[offer->vlan_push].protocol = entry->vlan.proto;
			offer->tags[offer->vlan_push].tci = entry->vlan.vid |
				(entry->vlan.prio << VLAN_PRIO_SHIFT);
			offer->vlan_push++;
			break;
		case FLOW_ACTION_PPPOE_PUSH:
			if (offer->pppoe_push || !entry->pppoe.sid)
				return -EOPNOTSUPP;
			offer->pppoe_push = true;
			offer->pppoe_sid = entry->pppoe.sid;
			break;
		case FLOW_ACTION_REDIRECT:
			if (!entry->dev)
				return -EOPNOTSUPP;
			offer->redirect = entry->dev;
			dev_hold(offer->redirect);
			redirected = true;
			break;
		default:
			return -EOPNOTSUPP;
		}
	}
	if (!redirected || memchr_inv(known, 0xff, sizeof(known)))
		return -EOPNOTSUPP;
	ether_addr_copy(offer->destination, mac);
	ether_addr_copy(offer->source, mac + ETH_ALEN);
	required_csum = offer->input.protocol == IPPROTO_TCP ?
		TCA_CSUM_UPDATE_FLAG_TCP : TCA_CSUM_UPDATE_FLAG_UDP;
	if (offer->input.family == AF_INET)
		required_csum |= TCA_CSUM_UPDATE_FLAG_IPV4HDR;
	if ((checksum && (!nat || checksum != required_csum)) ||
	    (nat && offer->input.family == AF_INET && checksum != required_csum))
		return -EOPNOTSUPP;
	return 0;
}

void qdx_flow_offers_put(struct qdx_flow_offer offers[2])
{
	int i;

	for (i = 0; i < 2; i++) {
		dev_put(offers[i].redirect);
		kfree(offers[i].facts);
		memset(&offers[i], 0, sizeof(offers[i]));
	}
}

int qdx_flow_offers_parse(struct qdx_flow_offer offers[2],
			 const struct nf_flow_offload_ctx *context)
{
	struct qdx_flow_key reverse;
	int i, error;

	if (!context || !context->flow || !context->ct ||
	    context->authorized_directions != (BIT(0) | BIT(1)) ||
	    !context->rules[0] || !context->rules[1])
		return -EOPNOTSUPP;
	memset(offers, 0, sizeof(*offers) * 2);
	for (i = 0; i < 2; i++) {
		error = qdx_flow_offer_parse(&offers[i], context->rules[i]);
		if (error)
			goto fail;
	}
	for (i = 0; i < 2; i++) {
		reverse = offers[!i].input;
		reverse.source = offers[!i].input.destination;
		reverse.destination = offers[!i].input.source;
		reverse.source_port = offers[!i].input.destination_port;
		reverse.destination_port = offers[!i].input.source_port;
		if (memcmp(&reverse, &offers[i].output, sizeof(reverse))) {
			error = -EOPNOTSUPP;
			goto fail;
		}
		if (offers[i].input.family == AF_INET6 &&
		    memcmp(&offers[i].input, &offers[i].output, sizeof(reverse))) {
			error = -EOPNOTSUPP;
			goto fail;
		}
	}
	return 0;
fail:
	qdx_flow_offers_put(offers);
	return error;
}

bool qdx_flow_offers_equal(const struct qdx_flow_offer a[2],
			   const struct qdx_flow_offer b[2])
{
	int i;

	for (i = 0; i < 2; i++) {
		if (memcmp(&a[i].match, &b[i].match, sizeof(a[i].match)) ||
		    memcmp(&a[i].input, &b[i].input, sizeof(a[i].input)) ||
		    memcmp(&a[i].output, &b[i].output, sizeof(a[i].output)) ||
		    a[i].redirect != b[i].redirect ||
		    !ether_addr_equal(a[i].source, b[i].source) ||
		    !ether_addr_equal(a[i].destination, b[i].destination) ||
		    a[i].vlan_pop != b[i].vlan_pop || a[i].vlan_push != b[i].vlan_push ||
		    memcmp(a[i].tags, b[i].tags, sizeof(a[i].tags)) ||
		    a[i].pppoe_push != b[i].pppoe_push || a[i].pppoe_sid != b[i].pppoe_sid)
			return false;
	}
	return true;
}

int qdx_flow_paths_encode(struct qdx_flow *flow, void *payload)
{
	const struct qdx_flow_wire_path *from = &flow->forward[0];
	const struct qdx_flow_wire_path *to = &flow->forward[1];
	struct qdx_nss_pppoe *ppp;
	struct qdx_nss_qos *qos;
	struct qdx_nss_igs *igs;
	struct qdx_nss_vlan *primary, *secondary;
	struct qdx_nss_nexthop *next;
	struct qdx_nss_source_mac *source;
	__le16 *valid;
	u16 flags;

	if (flow->offers[0].input.family == AF_INET) {
		struct qdx_nss_ipv4_create *wire = payload;

		wire->conn_rule.flow_interface_num = cpu_to_le32(from->physical_ifnum);
		wire->conn_rule.return_interface_num = cpu_to_le32(to->physical_ifnum);
		wire->conn_rule.flow_mtu = cpu_to_le32(from->mtu);
		wire->conn_rule.return_mtu = cpu_to_le32(to->mtu);
		ether_addr_copy(wire->conn_rule.flow_mac, flow->offers[1].destination);
		ether_addr_copy(wire->conn_rule.return_mac, flow->offers[0].destination);
		ppp = &wire->pppoe_rule;
		qos = &wire->qos_rule;
		igs = &wire->igs_rule;
		primary = &wire->vlan_primary_rule;
		secondary = &wire->vlan_secondary_rule;
		next = &wire->nexthop_rule;
		source = &wire->src_mac_rule;
		valid = &wire->valid_flags;
	} else {
		struct qdx_nss_ipv6_create *wire = payload;

		wire->conn_rule.flow_interface_num = cpu_to_le32(from->physical_ifnum);
		wire->conn_rule.return_interface_num = cpu_to_le32(to->physical_ifnum);
		wire->conn_rule.flow_mtu = cpu_to_le32(from->mtu);
		wire->conn_rule.return_mtu = cpu_to_le32(to->mtu);
		ether_addr_copy(wire->conn_rule.flow_mac, flow->offers[1].destination);
		ether_addr_copy(wire->conn_rule.return_mac, flow->offers[0].destination);
		ppp = &wire->pppoe_rule;
		qos = &wire->qos_rule;
		igs = &wire->igs_rule;
		primary = &wire->vlan_primary_rule;
		secondary = &wire->vlan_secondary_rule;
		next = &wire->nexthop_rule;
		source = &wire->src_mac_rule;
		valid = &wire->valid_flags;
	}
	flags = le16_to_cpu(*valid) | QDX_NSS_NEXTHOP_VALID |
		QDX_NSS_SRC_MAC_VALID | QDX_NSS_VLAN_VALID;
	next->flow_nexthop = cpu_to_le32(from->execution_ifnum);
	next->return_nexthop = cpu_to_le32(to->execution_ifnum);
	source->mac_valid_flags = cpu_to_le32(3);
	ether_addr_copy(source->flow_src_mac, flow->offers[1].source);
	ether_addr_copy(source->return_src_mac, flow->offers[0].source);
	primary->ingress_vlan_tag = cpu_to_le32(from->vlan[0]);
	primary->egress_vlan_tag = cpu_to_le32(to->vlan[0]);
	secondary->ingress_vlan_tag = cpu_to_le32(from->vlan[1]);
	secondary->egress_vlan_tag = cpu_to_le32(to->vlan[1]);
	if (from->pppoe || to->pppoe) {
		flags |= QDX_NSS_PPPOE_VALID;
		ppp->flow_if_exist = cpu_to_le32(from->pppoe);
		ppp->flow_if_num = cpu_to_le32(from->session_ifnum);
		ppp->return_if_exist = cpu_to_le32(to->pppoe);
		ppp->return_if_num = cpu_to_le32(to->session_ifnum);
	}
	if (from->has_class || to->has_class) {
		flags |= QDX_NSS_QOS_VALID;
		qos->flow_qos_tag = cpu_to_le32(to->class_tag);
		qos->return_qos_tag = cpu_to_le32(from->class_tag);
	}
	if (from->has_igs || to->has_igs) {
		flags |= QDX_NSS_IGS_VALID;
		igs->flow_qos_tag = cpu_to_le16(from->igs_tag);
		igs->return_qos_tag = cpu_to_le16(to->igs_tag);
	}
	*valid = cpu_to_le16(flags);
	return 0;
}

static void qdx_flow_build_ipv4(struct qdx_flow *flow,
		const struct ip_ct_tcp_state tcp[2], u16 flags, u16 valid)
{
	const struct qdx_flow_key *o = &flow->offers[0].input;
	const struct qdx_flow_key *r = &flow->offers[1].input;
	struct qdx_nss_ipv4_create *wire = &flow->wire.ipv4;

	wire->tuple.flow_ip = cpu_to_le32(ntohl(o->source.s6_addr32[0]));
	wire->tuple.return_ip = cpu_to_le32(ntohl(o->destination.s6_addr32[0]));
	wire->tuple.flow_ident = cpu_to_le32(ntohs(o->source_port));
	wire->tuple.return_ident = cpu_to_le32(ntohs(o->destination_port));
	wire->tuple.protocol = o->protocol;
	wire->conn_rule.flow_ip_xlate = cpu_to_le32(ntohl(r->destination.s6_addr32[0]));
	wire->conn_rule.return_ip_xlate = cpu_to_le32(ntohl(r->source.s6_addr32[0]));
	wire->conn_rule.flow_ident_xlate = cpu_to_le32(ntohs(r->destination_port));
	wire->conn_rule.return_ident_xlate = cpu_to_le32(ntohs(r->source_port));
	wire->tcp_rule.flow_max_window = cpu_to_le32(tcp[0].td_maxwin);
	wire->tcp_rule.return_max_window = cpu_to_le32(tcp[1].td_maxwin);
	wire->tcp_rule.flow_end = cpu_to_le32(tcp[0].td_end);
	wire->tcp_rule.return_end = cpu_to_le32(tcp[1].td_end);
	wire->tcp_rule.flow_max_end = cpu_to_le32(tcp[0].td_maxend);
	wire->tcp_rule.return_max_end = cpu_to_le32(tcp[1].td_maxend);
	wire->tcp_rule.flow_window_scale = tcp[0].td_scale;
	wire->tcp_rule.return_window_scale = tcp[1].td_scale;
	wire->valid_flags = cpu_to_le16(valid);
	wire->rule_flags = cpu_to_le16(flags);
	flow->wire_length = sizeof(*wire);
}

static void qdx_flow_build_ipv6(struct qdx_flow *flow,
		const struct ip_ct_tcp_state tcp[2], u16 flags, u16 valid)
{
	const struct qdx_flow_key *o = &flow->offers[0].input;
	struct qdx_nss_ipv6_create *wire = &flow->wire.ipv6;
	int i;

	for (i = 0; i < 4; i++) {
		wire->tuple.flow_ip[i] = cpu_to_le32(ntohl(o->source.s6_addr32[i]));
		wire->tuple.return_ip[i] = cpu_to_le32(ntohl(o->destination.s6_addr32[i]));
	}
	wire->tuple.flow_ident = cpu_to_le32(ntohs(o->source_port));
	wire->tuple.return_ident = cpu_to_le32(ntohs(o->destination_port));
	wire->tuple.protocol = o->protocol;
	wire->tcp_rule.flow_max_window = cpu_to_le32(tcp[0].td_maxwin);
	wire->tcp_rule.return_max_window = cpu_to_le32(tcp[1].td_maxwin);
	wire->tcp_rule.flow_end = cpu_to_le32(tcp[0].td_end);
	wire->tcp_rule.return_end = cpu_to_le32(tcp[1].td_end);
	wire->tcp_rule.flow_max_end = cpu_to_le32(tcp[0].td_maxend);
	wire->tcp_rule.return_max_end = cpu_to_le32(tcp[1].td_maxend);
	wire->tcp_rule.flow_window_scale = tcp[0].td_scale;
	wire->tcp_rule.return_window_scale = tcp[1].td_scale;
	wire->valid_flags = cpu_to_le16(valid);
	wire->rule_flags = cpu_to_le16(flags);
	flow->wire_length = sizeof(*wire);
}

int qdx_flow_build(struct qdx_flow *flow)
{
	const struct qdx_flow_key *o = &flow->offers[0].input;
	struct ip_ct_tcp_state tcp[2] = {};
	u16 flags = QDX_NSS_ROUTED | QDX_NSS_SOURCE_CHECK;
	u16 valid = QDX_NSS_CONN_VALID;
	int error;

	if (o->protocol == IPPROTO_TCP) {
		spin_lock_bh(&flow->ct->lock);
		tcp[0] = flow->ct->proto.tcp.seen[0];
		tcp[1] = flow->ct->proto.tcp.seen[1];
		spin_unlock_bh(&flow->ct->lock);
		valid |= QDX_NSS_TCP_VALID;
		if ((tcp[0].flags | tcp[1].flags) & IP_CT_TCP_FLAG_BE_LIBERAL)
			flags |= QDX_NSS_NO_SEQ_CHECK;
	}
	memset(&flow->wire, 0, sizeof(flow->wire));
	if (o->family == AF_INET)
		qdx_flow_build_ipv4(flow, tcp, flags, valid);
	else
		qdx_flow_build_ipv6(flow, tcp, flags, valid);
	error = qdx_flow_paths_encode(flow, &flow->wire);
	return error;
}
