// SPDX-License-Identifier: GPL-2.0-only
/* Isolated 114368 cost discriminator, not a production offload interface.
 * Default: one UDP tuple. Explicit four_flow_fq: .144 -> .115 server ports
 * 5991..5994, TCP/UDP, bypass the lan2 TBF/FQ root once per selected packet.
 * Explicit four_flow_red adds endpoint ICMP and uses a real TBF/RED leaf whose
 * NSS parameters were separately configured; the conduit must be noqueue.
 * Explicit two_flow_fairness uses ingress priorities 1:10/1:20 and their
 * actual native class queues. No IP routing is bypassed in a routed fixture.
 * The native DSA/EDMA path supplies its real existing NSS queue identity.
 */
#include <linux/capability.h>
#include <linux/debugfs.h>
#include <linux/etherdevice.h>
#include <linux/if_vlan.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/percpu.h>
#include <linux/qdx.h>
#include <linux/qdx/tc.h>
#include <linux/refcount.h>
#include <linux/rtnetlink.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/tcp.h>
#include <linux/uaccess.h>
#include <linux/udp.h>
#include <net/ip.h>
#include <net/net_namespace.h>
#include <net/pkt_sched.h>

#define HANDOFF_SOURCE "lan3"
#define HANDOFF_TARGET "lan2"
#define HANDOFF_CONDUIT "eth0"
#define HANDOFF_SOURCE_IP 0xc0a80190U
#define HANDOFF_TARGET_IP 0xc0a80173U

static bool allow_writes;
module_param(allow_writes, bool, 0400);
MODULE_PARM_DESC(allow_writes, "Permit explicit fixed RX handoff enable");
static ushort source_port = 5987;
module_param(source_port, ushort, 0400);
static ushort destination_port = 45987;
module_param(destination_port, ushort, 0400);
static bool four_flow_fq;
module_param(four_flow_fq, bool, 0400);
MODULE_PARM_DESC(four_flow_fq, "Use fixed TCP/UDP server ports 5991..5994 and TBF/FQ fixture");
static bool four_flow_red;
module_param(four_flow_red, bool, 0400);
MODULE_PARM_DESC(four_flow_red, "Use fixed TCP/UDP server ports 5991..5994 plus endpoint ICMP with TBF/RED and noqueue conduit");

static bool two_flow_fairness;
module_param(two_flow_fairness, bool, 0400);
MODULE_PARM_DESC(two_flow_fairness, "Use fixed UDP destinations 5001/5002, actual priorities 1:10/1:20 and HTB/PFIFO256 class queues");

struct handoff_context {
	refcount_t refs;
	struct qdx_binding_use use;
	struct qdx_tc_ref *reference;
	struct qdx_binding_use fair_use;
	struct qdx_tc_ref *fair_reference;
	u16 fair_queue[2];
	struct qdx_service *service;
	struct qdx_endpoint *source_endpoint, *target_endpoint;
	struct net_device *source, *target, *conduit;
	bool admitting;
	bool invalid;
};

struct handoff_counts {
	u64 attempts, bytes, consumed, busy, xmit_drop, shape_refused;
	u64 shared_headers, allocation_failed, passed;
	u64 tcp_attempts, udp_attempts, icmp_validated, server_attempts[4];
	u64 priority_refused;
	u64 fair_attempts[2], fair_bytes[2], fair_consumed[2];
	u64 fair_busy[2], fair_xmit_drop[2];
};
static DEFINE_PER_CPU(struct handoff_counts, handoff_counts);
static DEFINE_MUTEX(handoff_lock);
static struct handoff_context *handoff;
static struct dentry *handoff_debugfs;
static int last_error;

static bool handoff_get(void *object)
{
	struct handoff_context *context = object;

	return refcount_inc_not_zero(&context->refs);
}

static void handoff_put(void *object)
{
	struct handoff_context *context = object;

	if (refcount_dec_and_test(&context->refs))
		kfree(context);
}

static int handoff_invalid(void *object, bool may_sleep)
{
	struct handoff_context *context = object;

	WRITE_ONCE(context->invalid, true);
	smp_store_release(&context->admitting, false);
	if (!may_sleep)
		return -EWOULDBLOCK;
	/* Prior handlers can only finish native transmit, never await firmware. */
	synchronize_net();
	return 0;
}

static rx_handler_result_t handoff_receive(struct sk_buff **pskb)
{
	struct sk_buff *skb = *pskb;
	struct handoff_context *context = rcu_dereference(skb->dev->rx_handler_data);
	struct handoff_counts *counts = this_cpu_ptr(&handoff_counts);
	struct iphdr ip_buffer;
	struct udphdr udp_buffer;
	struct tcphdr tcp_buffer;
	const struct iphdr *ip;
	const struct udphdr *udp = NULL;
	const struct tcphdr *tcp = NULL;
	__be16 packet_source_port = 0, packet_destination_port = 0;
	bool four_flow = four_flow_fq || four_flow_red;
	unsigned int ip_length, ip_total_length, frame_length, transport_length;
	int result, fair_index = -1;
	u16 queue = 0;

	if (!smp_load_acquire(&context->admitting) || skb->protocol != htons(ETH_P_IP))
		goto pass;
	ip = skb_header_pointer(skb, 0, sizeof(ip_buffer), &ip_buffer);
	if (!ip || ip->version != 4 || ip->ihl < 5 ||
	    (ip->protocol != IPPROTO_UDP &&
	     (!four_flow || ip->protocol != IPPROTO_TCP) &&
	     (!four_flow_red || ip->protocol != IPPROTO_ICMP)) ||
	    ip->saddr != htonl(HANDOFF_SOURCE_IP) ||
	    ip->daddr != htonl(HANDOFF_TARGET_IP) || ip_is_fragment(ip))
		goto pass;
	ip_length = ip->ihl * 4;
	ip_total_length = ntohs(ip->tot_len);
	if (ip->protocol == IPPROTO_UDP) {
		udp = skb_header_pointer(skb, ip_length, sizeof(udp_buffer), &udp_buffer);
		if (!udp)
			goto pass;
		packet_source_port = udp->source;
		packet_destination_port = udp->dest;
		transport_length = sizeof(*udp);
	} else if (ip->protocol == IPPROTO_TCP) {
		tcp = skb_header_pointer(skb, ip_length, sizeof(tcp_buffer), &tcp_buffer);
		if (!tcp)
			goto pass;
		packet_source_port = tcp->source;
		packet_destination_port = tcp->dest;
		transport_length = tcp->doff * 4;
	} else {
		transport_length = sizeof(struct icmphdr);
	}
	if (two_flow_fairness) {
		if (packet_destination_port == htons(5001))
			fair_index = 0;
		else if (packet_destination_port == htons(5002))
			fair_index = 1;
		else
			goto pass;
		counts->fair_attempts[fair_index]++;
		counts->fair_bytes[fair_index] += skb->len + ETH_HLEN;
		queue = context->fair_queue[fair_index];
	} else if (four_flow) {
		if (ip->protocol != IPPROTO_ICMP) {
			if (ntohs(packet_source_port) < 5991 || ntohs(packet_source_port) > 5994)
				goto pass;
			counts->server_attempts[ntohs(packet_source_port) - 5991]++;
		}
	} else if (packet_source_port != htons(source_port) ||
		   packet_destination_port != htons(destination_port)) {
		goto pass;
	}
	counts->attempts++;
	if (tcp)
		counts->tcp_attempts++;
	else if (udp)
		counts->udp_attempts++;
	frame_length = skb->len + ETH_HLEN;
	counts->bytes += frame_length;
	if (fair_index >= 0 && skb->priority != (fair_index ? 0x10020U : 0x10010U)) {
		counts->priority_refused++;
		kfree_skb(skb);
		*pskb = NULL;
		return RX_HANDLER_CONSUMED;
	}
	if (ip_length != sizeof(*ip) || skb_is_nonlinear(skb) || skb_is_gso(skb) ||
	    skb_vlan_tag_present(skb) || skb->ip_summed == CHECKSUM_PARTIAL ||
	    skb_network_header(skb) != skb->data || !skb_mac_header_was_set(skb) ||
	    skb_headroom(skb) < ETH_HLEN ||
	    skb_mac_header(skb) != skb->data - ETH_HLEN ||
	    eth_hdr(skb)->h_proto != htons(ETH_P_IP) ||
	    (tcp && tcp->doff < 5) ||
	    ip_total_length < ip_length + transport_length ||
	    ip_total_length > skb->len ||
	    (ip_total_length != skb->len && frame_length != ETH_ZLEN) ||
	    (udp && ntohs(udp->len) != ip_total_length - ip_length)) {
		counts->shape_refused++;
		kfree_skb(skb);
		*pskb = NULL;
		return RX_HANDLER_CONSUMED;
	}
	if (ip->protocol == IPPROTO_ICMP)
		counts->icmp_validated++;
	if (skb_shared(skb))
		counts->shared_headers++;
	skb = skb_share_check(skb, GFP_ATOMIC);
	*pskb = NULL;
	if (!skb) {
		counts->allocation_failed++;
		return RX_HANDLER_CONSUMED;
	}
	/* Restore existing bytes, not a synthetic header or a new packet. */
	skb_push(skb, ETH_HLEN);
	skb->dev = context->target;
	skb->pkt_type = PACKET_OUTGOING;
	result = dev_direct_xmit(skb, queue);
	/* The wrapper consumes even BUSY. Never access or free skb here. */
	if (result == NETDEV_TX_OK)
		counts->consumed++;
	else if (!dev_xmit_complete(result))
		counts->busy++;
	else
		counts->xmit_drop++;
	if (fair_index >= 0) {
		if (result == NETDEV_TX_OK)
			counts->fair_consumed[fair_index]++;
		else if (!dev_xmit_complete(result))
			counts->fair_busy[fair_index]++;
		else
			counts->fair_xmit_drop[fair_index]++;
	}
	return RX_HANDLER_CONSUMED;
pass:
	counts->passed++;
	return RX_HANDLER_PASS;
}

/* Caller has unregistered the handler or has not published one yet. */
static void handoff_release(struct handoff_context *context)
{
	if (context->fair_reference)
		qdx_tc_ref_put(context->fair_reference);
	if (context->reference)
		qdx_tc_ref_put(context->reference);
	if (context->target_endpoint)
		qdx_endpoint_put(context->target_endpoint);
	if (context->source_endpoint)
		qdx_endpoint_put(context->source_endpoint);
	if (context->service)
		qdx_service_put(context->service);
	if (context->conduit)
		dev_put(context->conduit);
	if (context->target)
		dev_put(context->target);
	if (context->source)
		dev_put(context->source);
	handoff_put(context);
}

static int handoff_enable(void)
{
	struct qdx_tc_position position = { .direction = QDX_TC_EGRESS };
	struct qdx_packet_geometry geometry = {};
	struct flow_dissector dissector = {};
	struct flow_rule facts = { .match.dissector = &dissector };
	struct qdx_owner consumer = { .module = THIS_MODULE,
		.get = handoff_get, .put = handoff_put };
	struct handoff_context *context;
	struct Qdisc *root, *leaf;
	struct sk_buff *queue_probe = NULL;
	struct qdx_tc_ref *reference;
	struct qdx_binding_use *use;
	unsigned long native_class;
	const netdev_features_t aggregation = NETIF_F_GRO | NETIF_F_GRO_HW | NETIF_F_LRO;
	u32 source_ifnum, target_ifnum;
	int error, i;

	ASSERT_RTNL();
	if (handoff)
		return -EBUSY;
	if (!two_flow_fairness && !four_flow_fq && !four_flow_red && (!source_port || !destination_port))
		return -EINVAL;
	context = kzalloc(sizeof(*context), GFP_KERNEL);
	if (!context)
		return -ENOMEM;
	refcount_set(&context->refs, 1);
	INIT_LIST_HEAD(&context->use.node);
	INIT_LIST_HEAD(&context->fair_use.node);
	context->source = dev_get_by_name(&init_net, HANDOFF_SOURCE);
	context->target = dev_get_by_name(&init_net, HANDOFF_TARGET);
	context->conduit = dev_get_by_name(&init_net, HANDOFF_CONDUIT);
	if (!context->source || !context->target || !context->conduit) {
		error = -ENODEV;
		goto fail;
	}
	if (!netif_running(context->source) || !netif_carrier_ok(context->source) ||
	    !netif_running(context->target) || !netif_carrier_ok(context->target) ||
	    !netif_running(context->conduit) || !netif_carrier_ok(context->conduit)) {
		error = -ENETDOWN;
		goto fail;
	}
	if (netdev_master_upper_dev_get(context->source) ||
	    netdev_is_rx_handler_busy(context->source)) {
		error = -EBUSY;
		goto fail;
	}
	if ((context->source->features | context->conduit->features) & aggregation ||
	    !(context->target->features & NETIF_F_HW_TC)) {
		error = -EOPNOTSUPP;
		goto fail;
	}
	root = rtnl_dereference(context->conduit->qdisc);
	if (strcmp(root->ops->id, four_flow_red || two_flow_fairness ? "noqueue" : "fq_codel")) {
		error = -EOPNOTSUPP;
		goto fail;
	}
	root = rtnl_dereference(context->target->qdisc);
	leaf = root;
	if (two_flow_fairness) {
		if (strcmp(root->ops->id, "htb") || !root->ops->cl_ops ||
		    !root->ops->cl_ops->find || !root->ops->cl_ops->leaf ||
		    !context->target->netdev_ops->ndo_select_queue) {
			error = -EOPNOTSUPP;
			goto fail;
		}
		for (i = 0; i < 2; i++) {
			native_class = root->ops->cl_ops->find(root, i ? 0x10020 : 0x10010);
			leaf = native_class ? root->ops->cl_ops->leaf(root, native_class) : NULL;
			if (!leaf || strcmp(leaf->ops->id, "pfifo") || leaf->limit != 256) {
				error = -EOPNOTSUPP;
				goto fail;
			}
		}
	} else if (!strcmp(root->ops->id, "tbf")) {
		if (!root->ops->cl_ops || !root->ops->cl_ops->leaf) {
			error = -EOPNOTSUPP;
			goto fail;
		}
		leaf = root->ops->cl_ops->leaf(root, 1);
	} else if (four_flow_fq || four_flow_red || strcmp(root->ops->id, "pfifo")) {
		error = -EOPNOTSUPP;
		goto fail;
	}
	if (!leaf) {
		error = -EOPNOTSUPP;
		goto fail;
	}
	if (two_flow_fairness) {
		/* Both actual native children were checked above. */
	} else if (four_flow_red) {
		if (strcmp(leaf->ops->id, "red")) {
			error = -EOPNOTSUPP;
			goto fail;
		}
	} else if (four_flow_fq) {
		if (strcmp(leaf->ops->id, "fq_codel") ||
		    (leaf->limit != 128 && leaf->limit != 1024)) {
			error = -EOPNOTSUPP;
			goto fail;
		}
	} else if (strcmp(leaf->ops->id, "pfifo") || leaf->limit != 128) {
		error = -EOPNOTSUPP;
		goto fail;
	}
	context->service = qdx_service_get(context->source, QDX_SERVICE_ETHERNET);
	if (IS_ERR(context->service)) {
		error = PTR_ERR(context->service);
		context->service = NULL;
		goto fail;
	}
	context->source_endpoint = qdx_endpoint_get(context->service, context->source);
	if (IS_ERR(context->source_endpoint)) {
		error = PTR_ERR(context->source_endpoint);
		context->source_endpoint = NULL;
		goto fail;
	}
	context->target_endpoint = qdx_endpoint_get(context->service, context->target);
	if (IS_ERR(context->target_endpoint)) {
		error = PTR_ERR(context->target_endpoint);
		context->target_endpoint = NULL;
		goto fail;
	}
	error = qdx_endpoint_ifnum(context->source_endpoint, &source_ifnum);
	if (!error)
		error = qdx_endpoint_ifnum(context->target_endpoint, &target_ifnum);
	if (error || source_ifnum != 3 || target_ifnum != 4) {
		error = error ?: -EXDEV;
		goto fail;
	}
	position.dev = context->target;
	consumer.object = context;
	if (two_flow_fairness) {
		queue_probe = alloc_skb(ETH_HLEN, GFP_KERNEL);
		if (!queue_probe) {
			error = -ENOMEM;
			goto fail;
		}
		queue_probe->dev = context->target;
		queue_probe->protocol = htons(ETH_P_IP);
		geometry.known = QDX_GEOMETRY_PRIORITY;
	}
	for (i = 0; i < (two_flow_fairness ? 2 : 1); i++) {
		use = i ? &context->fair_use : &context->use;
		if (two_flow_fairness)
			geometry.priority = i ? 0x10020 : 0x10010;
		error = qdx_tc_position_get(&position, &facts, &geometry, use,
			&consumer, handoff_invalid,
			i ? &context->fair_reference : &context->reference);
		if (error)
			goto fail;
		reference = i ? context->fair_reference : context->reference;
		if (reference->effects != QDX_TC_CLASS ||
		    reference->input_priority_used != two_flow_fairness || reference->output_priority_used ||
		    !reference->class_endpoint || !reference->class_tag ||
		    (!two_flow_fairness && (reference->class_tag & 0xffff))) {
			error = -EOPNOTSUPP;
			goto fail;
		}
		error = qdx_endpoint_ifnum(reference->class_endpoint, &target_ifnum);
		if (error || target_ifnum != 4) {
			error = error ?: -EXDEV;
			goto fail;
		}
		if (two_flow_fairness) {
			qdx_uses_lock();
			if (!qdx_use_available_locked(use) || READ_ONCE(context->invalid))
				error = -ESTALE;
			qdx_uses_unlock();
			if (error)
				goto fail;
			/* RTNL freezes the graph; no QDX lock surrounds native selection. */
			queue_probe->priority = geometry.priority;
			context->fair_queue[i] = context->target->netdev_ops->ndo_select_queue(
				context->target, queue_probe, context->source);
			/* This diagnostic driver has one normal direct queue (qid0).
			 * Its native selector returns that queue when no class was selected.
			 */
			if (!context->fair_queue[i] ||
			    context->fair_queue[i] >= context->target->real_num_tx_queues) {
				error = -ERANGE;
				goto fail;
			}
		}
	}
	if (two_flow_fairness &&
	    (context->reference->class_tag == context->fair_reference->class_tag ||
	     context->fair_queue[0] == context->fair_queue[1])) {
		error = -EOPNOTSUPP;
		goto fail;
	}
	kfree_skb(queue_probe);
	queue_probe = NULL;
	qdx_uses_lock();
	if (!qdx_use_available_locked(&context->use) ||
	    (two_flow_fairness && !qdx_use_available_locked(&context->fair_use)) ||
	    READ_ONCE(context->invalid))
		error = -ESTALE;
	else
		smp_store_release(&context->admitting, true);
	qdx_uses_unlock();
	if (error)
		goto fail;
	error = netdev_rx_handler_register(context->source, handoff_receive, context);
	if (error)
		goto fail;
	handoff = context;
	return 0;
fail:
	kfree_skb(queue_probe);
	smp_store_release(&context->admitting, false);
	handoff_release(context);
	return error;
}

static void handoff_disable(void)
{
	struct handoff_context *context = handoff;

	ASSERT_RTNL();
	if (!context)
		return;
	smp_store_release(&context->admitting, false);
	netdev_rx_handler_unregister(context->source);
	handoff = NULL;
	handoff_release(context);
}

static int handoff_status_show(struct seq_file *seq, void *unused)
{
	struct handoff_counts total = {}, *counts;
	int cpu, i;

	mutex_lock(&handoff_lock);
	seq_printf(seq, "fixture=%s four_flow_fq=%u four_flow_red=%u selected_server_ports=%s selected_protocols=%s destination_port_fixed=%u\n",
		two_flow_fairness ? "two-flow-fairness" :
		four_flow_red ? "four-flow-red" : four_flow_fq ? "four-flow-fq" : "single-udp-pfifo",
		four_flow_fq, four_flow_red,
		four_flow_fq || four_flow_red ? "5991-5994" : "parameter",
		four_flow_red ? "tcp,udp,icmp" : four_flow_fq ? "tcp,udp" : "udp",
		!four_flow_fq && !four_flow_red && !two_flow_fairness);
	seq_printf(seq, "source=%s target=%s conduit=%s verified_conduit_qdisc=%s source_ip=192.168.1.144 source_port=%u target_ip=192.168.1.115 destination_port=%u\n",
		HANDOFF_SOURCE, HANDOFF_TARGET, HANDOFF_CONDUIT,
		four_flow_red || two_flow_fairness ? "noqueue" : "fq_codel", source_port, destination_port);
	seq_printf(seq, "allow_writes=%u registered=%u admitting=%u invalid=%u class_tag=%#x last_error=%d\n",
		allow_writes, !!handoff, handoff ? READ_ONCE(handoff->admitting) : false,
		handoff ? READ_ONCE(handoff->invalid) : false,
		handoff ? handoff->reference->class_tag : 0, last_error);
	seq_printf(seq, "two_flow_fairness=%u selected_destination_ports=%s\n",
		two_flow_fairness, two_flow_fairness ? "5001,5002" : "legacy");
	if (two_flow_fairness) {
		for (i = 0; i < 2; i++) {
			struct qdx_tc_ref *reference = handoff ?
				(i ? handoff->fair_reference : handoff->reference) : NULL;

			seq_printf(seq, "fair_class%d classid=%#x tag=%#x qid=%u reference=%u input_priority_used=%u\n",
				i, i ? 0x10020 : 0x10010, reference ? reference->class_tag : 0,
				handoff ? handoff->fair_queue[i] : 0, !!reference,
				reference ? reference->input_priority_used : false);
		}
	}
	mutex_unlock(&handoff_lock);
	for_each_possible_cpu(cpu) {
		counts = per_cpu_ptr(&handoff_counts, cpu);
		total.attempts += READ_ONCE(counts->attempts);
		total.bytes += READ_ONCE(counts->bytes);
		total.consumed += READ_ONCE(counts->consumed);
		total.busy += READ_ONCE(counts->busy);
		total.xmit_drop += READ_ONCE(counts->xmit_drop);
		total.shape_refused += READ_ONCE(counts->shape_refused);
		total.shared_headers += READ_ONCE(counts->shared_headers);
		total.allocation_failed += READ_ONCE(counts->allocation_failed);
		total.passed += READ_ONCE(counts->passed);
		total.priority_refused += READ_ONCE(counts->priority_refused);
		for (i = 0; i < 2; i++) {
			total.fair_attempts[i] += READ_ONCE(counts->fair_attempts[i]);
			total.fair_bytes[i] += READ_ONCE(counts->fair_bytes[i]);
			total.fair_consumed[i] += READ_ONCE(counts->fair_consumed[i]);
			total.fair_busy[i] += READ_ONCE(counts->fair_busy[i]);
			total.fair_xmit_drop[i] += READ_ONCE(counts->fair_xmit_drop[i]);
		}
		total.tcp_attempts += READ_ONCE(counts->tcp_attempts);
		total.udp_attempts += READ_ONCE(counts->udp_attempts);
		total.icmp_validated += READ_ONCE(counts->icmp_validated);
		for (i = 0; i < ARRAY_SIZE(total.server_attempts); i++)
			total.server_attempts[i] += READ_ONCE(counts->server_attempts[i]);
	}
	seq_printf(seq, "attempts=%llu bytes=%llu xmit_consumed=%llu busy=%llu xmit_drop=%llu shape_refused=%llu shared_headers=%llu allocation_failed=%llu passed=%llu\n",
		total.attempts, total.bytes, total.consumed, total.busy, total.xmit_drop,
		total.shape_refused, total.shared_headers, total.allocation_failed, total.passed);
	seq_printf(seq, "tcp_attempts=%llu udp_attempts=%llu icmp_validated=%llu server5991=%llu server5992=%llu server5993=%llu server5994=%llu\n",
		total.tcp_attempts, total.udp_attempts, total.icmp_validated, total.server_attempts[0],
		total.server_attempts[1], total.server_attempts[2], total.server_attempts[3]);
	seq_printf(seq, "priority_refused=%llu\n", total.priority_refused);
	if (two_flow_fairness)
		for (i = 0; i < 2; i++)
			seq_printf(seq, "fair_count%d attempts=%llu bytes=%llu consumed=%llu busy=%llu xmit_drop=%llu\n",
				i, total.fair_attempts[i], total.fair_bytes[i], total.fair_consumed[i],
				total.fair_busy[i], total.fair_xmit_drop[i]);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(handoff_status);

static ssize_t handoff_control_write(struct file *file, const char __user *buffer,
				     size_t length, loff_t *offset)
{
	char command[16];
	int error;

	if (!allow_writes || !capable(CAP_NET_ADMIN))
		return -EPERM;
	if (!length || length >= sizeof(command))
		return -EINVAL;
	if (copy_from_user(command, buffer, length))
		return -EFAULT;
	command[length] = '\0';
	strim(command);
	rtnl_lock();
	mutex_lock(&handoff_lock);
	if (!strcmp(command, "enable"))
		error = handoff_enable();
	else if (!strcmp(command, "disable")) {
		handoff_disable();
		error = 0;
	} else {
		error = -EINVAL;
	}
	last_error = error;
	mutex_unlock(&handoff_lock);
	rtnl_unlock();
	return error ?: length;
}

static const struct file_operations handoff_control_fops = {
	.owner = THIS_MODULE,
	.write = handoff_control_write,
};

static int __init handoff_init(void)
{
	struct dentry *entry;
	int error;

	if ((four_flow_fq && four_flow_red) ||
	    (two_flow_fairness && (four_flow_fq || four_flow_red)))
		return -EINVAL;
	handoff_debugfs = debugfs_create_dir("qdx_rx_handoff_diag", NULL);
	if (IS_ERR(handoff_debugfs))
		return PTR_ERR(handoff_debugfs);
	entry = debugfs_create_file("status", 0400, handoff_debugfs, NULL, &handoff_status_fops);
	if (IS_ERR(entry)) {
		error = PTR_ERR(entry);
		goto remove;
	}
	entry = debugfs_create_file("control", 0200, handoff_debugfs, NULL, &handoff_control_fops);
	if (IS_ERR(entry)) {
		error = PTR_ERR(entry);
		goto remove;
	}
	return 0;
remove:
	debugfs_remove_recursive(handoff_debugfs);
	return error;
}

static void __exit handoff_exit(void)
{
	debugfs_remove_recursive(handoff_debugfs);
	rtnl_lock();
	mutex_lock(&handoff_lock);
	handoff_disable();
	mutex_unlock(&handoff_lock);
	rtnl_unlock();
}
module_init(handoff_init);
module_exit(handoff_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fixed native RX to existing NSS queue diagnostic");
