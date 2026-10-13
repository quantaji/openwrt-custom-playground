// SPDX-License-Identifier: GPL-2.0-only
/* Isolated charged-carrier BF/packet-WRR/byte-WRR diagnostic.
 * Retains routed originals and resumes the remaining real POST_ROUTING hooks.
 * No PPE proxy, register writes, physical shaper or firmware restart.
 */
#include <linux/build_bug.h>
#include <linux/debugfs.h>
#include <linux/etherdevice.h>
#include <linux/if_vlan.h>
#include <linux/inet.h>
#include <linux/ip.h>
#include <linux/jiffies.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/qdx.h>
#include <linux/refcount.h>
#include <linux/seq_file.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/udp.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>
#include <net/dst.h>
#include <net/ip.h>
#include <net/net_namespace.h>

#define WAIT_MS 3000
#define NODES 6
#define HEADROOM 130
#define TAG(i) ((0x7210U + (i)) << 16)

/* Selected NSS ABI. Layout provenance: Qualcomm exports/nss_shaper.h,
 * nss_if.h and nss_virt_if.h, reproduced only for the used wire records.
 * Copyright (c) 2014, 2017-2018 The Linux Foundation. All rights reserved.
 * Copyright (c) 2014-2021, The Linux Foundation. All rights reserved.
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
struct charge_wire {
	__le32 request, response, value[27];
};
struct charge_redirect {
	__le32 flags, sibling, next;
	u8 mac[ETH_ALEN], pad[2];
};
static_assert(sizeof(struct charge_wire) == 116);
static_assert(sizeof(struct charge_redirect) == 20);

struct charge_node {
	bool allocated, attached, configured;
	u32 gauge_bytes, gauge_packets;
	u64 enqueued_bytes, enqueued_packets, enqueue_drop_bytes, enqueue_drop_packets;
	u64 dequeued_bytes, dequeued_packets, dequeue_drop_bytes, dequeue_drop_packets;
	u64 overruns;
};
struct charge_item {
	refcount_t refs;
	struct list_head output;
	struct sk_buff *original, *carrier;
	void *original_head;
	unsigned int carrier_offset;
	__be16 original_protocol;
	u8 prefix, saved_prefix[17];
	bool reused;
	struct nf_hook_state state;
	u32 charge, original_bytes, original_memory, carrier_memory;
	u8 class;
	u64 id;
};
struct charge_counts {
	atomic64_t inputs, accepted, returned, disposal, firmware_empty, access_end;
	atomic64_t refusal, invalid, forwarded, continuation_error;
	atomic64_t charged_bytes, basis_bytes;
	atomic64_t reuse_prepared, reuse_accepted, reuse_returned, reuse_disposal;
	atomic64_t reuse_refused, reuse_restored, reuse_moved;
	atomic64_t fallback_shared, fallback_cloned, fallback_geometry;
};

static bool allow_writes, reuse_original, wrr_unshaped;
static unsigned int flavor = 1, rate = 12500000, burst = 65536;
static unsigned int overhead = 64, limit = 256, max_live = 4096;
module_param(allow_writes, bool, 0400);
module_param(reuse_original, bool, 0400);
module_param(wrr_unshaped, bool, 0400);
MODULE_PARM_DESC(wrr_unshaped, "WRR only: first PRIO root, band0 arbiter; require rate=0 burst=0; default retains TBL");
MODULE_PARM_DESC(reuse_original, "Use exclusive linear original backing for the charged bounce; otherwise retain separate carrier");
module_param(flavor, uint, 0400);
module_param(rate, uint, 0400);
module_param(burst, uint, 0400);
module_param(overhead, uint, 0400);
module_param(limit, uint, 0400);
module_param(max_live, uint, 0400);
MODULE_PARM_DESC(flavor, "1=BF, 2=packet WRR, 3=byte WRR; distinct firmware laws");
MODULE_PARM_DESC(rate, "Common NSS TBL charged bytes/second; BF entitlements each rate/5");
MODULE_PARM_DESC(overhead, "Added charge beyond IPv4 skb length plus14 in this untagged fixture");

static DEFINE_MUTEX(control_lock);
static DEFINE_SPINLOCK(output_lock);
static LIST_HEAD(output_queue);
static struct work_struct output_work;
static struct dentry *directory;
static struct net_device *physical, *outdev;
static struct qdx_service *service;
static struct qdx_endpoint *endpoint, *sibling;
static struct qdx_packet_op *operations[2];
static struct qdx_request *request;
static struct qdx_result last_result;
static struct charge_node nodes[NODES];
static struct charge_counts counts[2];
static u32 ifnum = U32_MAX, sibling_ifnum = U32_MAX, shaper_id;
static u32 pending_opcode, pending_request, pending_node, pending_child;
static u32 last_response;
static bool n2h_configured, h2n_configured, assigned, rooted;
static bool endpoint_retired, sibling_retired, pinned, prepared;
static bool armed, ever_armed, sealed, hook_registered, fault, draining;
static int last_error;
static atomic_t live_items = ATOMIC_INIT(0), publishers = ATOMIC_INIT(0);
static atomic_t output_pending = ATOMIC_INIT(0), reused_live = ATOMIC_INIT(0);
static atomic64_t identities = ATOMIC64_INIT(0);
static atomic64_t original_bytes = ATOMIC64_INIT(0), charge_bytes = ATOMIC64_INIT(0);
static atomic64_t original_memory = ATOMIC64_INIT(0), carrier_memory = ATOMIC64_INIT(0);
static unsigned int charge_hook(void *priv, struct sk_buff *skb,
		const struct nf_hook_state *state);
static struct nf_hook_ops hook = {
	.hook = charge_hook, .priv = &hook,
	.pf = NFPROTO_IPV4, .hooknum = NF_INET_POST_ROUTING,
	.priority = NF_IP_PRI_LAST,
};

static bool charge_item_get(void *object)
{
	struct charge_item *item = object;

	return refcount_inc_not_zero(&item->refs);
}

static void charge_item_put(void *object)
{
	struct charge_item *item = object;

	if (!refcount_dec_and_test(&item->refs))
		return;
	WARN_ON(item->original || item->carrier || !list_empty(&item->output));
	dev_put(item->state.out);
	if (item->state.in)
		dev_put(item->state.in);
	put_net(item->state.net);
	atomic_dec(&live_items);
	kfree(item);
}

static void charge_original_end(struct charge_item *item, bool free_packet)
{
	struct sk_buff *skb = item->original;

	item->original = NULL;
	atomic64_sub(item->original_bytes, &original_bytes);
	atomic64_sub(item->original_memory, &original_memory);
	if (free_packet)
		dev_kfree_skb_any(skb);
}

/* QDX preserves host metadata and adjusts all header offsets if firmware moves
 * the returned frame. Restore relative to that frame, never an old data address.
 * Called only for this item's validated reused skb, after DMA access has ended.
 */
static void charge_original_restore(struct charge_item *item)
{
	struct sk_buff *skb = item->original;

	if (skb_headroom(skb) != item->carrier_offset)
		atomic64_inc(&counts[item->class].reuse_moved);
	memcpy(skb->data, item->saved_prefix, item->prefix);
	skb_pull(skb, item->prefix);
	__skb_trim(skb, item->original_bytes - ETH_HLEN);
	skb->protocol = item->original_protocol;
	atomic64_inc(&counts[item->class].reuse_restored);
}

/* Only one drainer invokes native continuation, including when callbacks arrive
 * on different CPUs. The remaining hook chain consumes skb unless it returns1.
 */
static void charge_drain(void)
{
	struct nf_hook_entries *entries;
	struct charge_item *item;
	struct sk_buff *skb;
	unsigned long flags;
	unsigned int i, done = 0;
	int result;

	spin_lock_irqsave(&output_lock, flags);
	if (draining) {
		spin_unlock_irqrestore(&output_lock, flags);
		return;
	}
	draining = true;
	while (!list_empty(&output_queue) && done++ < 64) {
		item = list_first_entry(&output_queue, struct charge_item, output);
		list_del_init(&item->output);
		spin_unlock_irqrestore(&output_lock, flags);
		skb = item->original;
		local_bh_disable();
		rcu_read_lock();
		entries = rcu_dereference(item->state.net->nf.hooks_ipv4[NF_INET_POST_ROUTING]);
		for (i = 0; entries && i < entries->num_hook_entries; i++)
			if (entries->hooks[i].hook == charge_hook && entries->hooks[i].priv == &hook)
				break;
		if (!entries || i == entries->num_hook_entries) {
			WRITE_ONCE(fault, true);
			atomic64_inc(&counts[item->class].continuation_error);
			charge_original_end(item, true);
		} else {
			/* Transfer ownership once before calling consuming native code. */
			charge_original_end(item, false);
			result = nf_hook_slow(skb, &item->state, entries, i + 1);
			if (result == 1) {
				result = item->state.okfn(item->state.net, NULL, skb);
				atomic64_inc(&counts[item->class].forwarded);
			}
			if (result < 0)
				atomic64_inc(&counts[item->class].continuation_error);
		}
		rcu_read_unlock();
		local_bh_enable();
		atomic_dec(&output_pending);
		charge_item_put(item);
		spin_lock_irqsave(&output_lock, flags);
	}
	draining = false;
	if (!list_empty(&output_queue))
		schedule_work(&output_work);
	spin_unlock_irqrestore(&output_lock, flags);
}

static void charge_output_work(struct work_struct *work)
{
	charge_drain();
}

static void charge_returned(void *owner, struct sk_buff *submitted,
		struct sk_buff *returned, const struct qdx_rx_meta *meta,
		struct napi_struct *napi)
{
	struct charge_item *item = owner;
	unsigned long flags;
	bool valid = returned && returned == submitted && submitted == item->carrier &&
		meta && meta->ifnum == READ_ONCE(ifnum) &&
		meta->type == QDX_RECEIVE_BRIDGE_RETURNED && returned->len == item->charge &&
		(!item->reused || (returned == item->original &&
		 returned->head == item->original_head && !skb_is_nonlinear(returned)));

	/* QDX has ended DMA before this callback. On NULL it still frees its own
	 * submitted carrier after this callback; only a returned carrier is ours.
	 */
	item->carrier = NULL;
	atomic64_sub(item->charge, &charge_bytes);
	atomic64_sub(item->carrier_memory, &carrier_memory);
	if (item->reused)
		atomic_dec(&reused_live);
	if (!returned) {
		atomic64_inc(&counts[item->class].disposal);
		if (!meta)
			atomic64_inc(&counts[item->class].access_end);
		else if (meta->type == 1) /* selected ABI QDX_N2H_EMPTY */
			atomic64_inc(&counts[item->class].firmware_empty);
		else {
			WRITE_ONCE(fault, true);
			atomic64_inc(&counts[item->class].invalid);
		}
		if (item->reused) {
			/* The submitted original still belongs to QDX on NULL. */
			charge_original_restore(item);
			atomic64_inc(&counts[item->class].reuse_disposal);
		}
		charge_original_end(item, !item->reused);
		return;
	}
	if (!item->reused)
		dev_kfree_skb_any(returned);
	if (!valid) {
		WRITE_ONCE(fault, true);
		atomic64_inc(&counts[item->class].invalid);
		charge_original_end(item, true);
		return;
	}
	if (item->reused) {
		charge_original_restore(item);
		atomic64_inc(&counts[item->class].reuse_returned);
	}
	atomic64_inc(&counts[item->class].returned);
	refcount_inc(&item->refs); /* ordered continuation outlives the QDX callback */
	atomic_inc(&output_pending);
	spin_lock_irqsave(&output_lock, flags);
	list_add_tail(&item->output, &output_queue);
	spin_unlock_irqrestore(&output_lock, flags);
	charge_drain();
}

static unsigned int charge_hook(void *priv, struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	struct qdx_packet_recipient recipient;
	struct charge_item *item;
	struct qdx_ready ready;
	struct iphdr *ip;
	struct udphdr *udp;
	struct sk_buff *carrier;
	unsigned int class, length, ihl, original_length, prefix, suffix;

	if (state->out != READ_ONCE(outdev) || skb->protocol != htons(ETH_P_IP))
		return NF_ACCEPT;
	if (!pskb_may_pull(skb, sizeof(*ip)))
		return NF_ACCEPT;
	ip = ip_hdr(skb);
	if (ip->saddr != htonl(0xc0a84802) || ip->daddr != htonl(0xc0a80173) ||
	    ip->protocol != IPPROTO_UDP)
		return NF_ACCEPT;
	ihl = ip->ihl * 4;
	if (ihl < sizeof(*ip) || !pskb_may_pull(skb, ihl + sizeof(*udp)))
		return NF_ACCEPT;
	ip = ip_hdr(skb);
	udp = (struct udphdr *)((u8 *)ip + ihl);
	if (udp->dest != htons(5001) && udp->dest != htons(5002))
		return NF_ACCEPT;
	class = udp->dest == htons(5001) ? 0 : 1;
	if (!READ_ONCE(armed)) {
		if (!READ_ONCE(ever_armed))
			return NF_ACCEPT;
		atomic64_inc(&counts[class].refusal);
		return NF_DROP;
	}
	atomic_inc(&publishers);
	/* stop clears armed then synchronizes hook readers before closing ops. */
	if (!READ_ONCE(armed) || READ_ONCE(fault))
		goto refuse;
	atomic64_inc(&counts[class].inputs);
	length = skb->len + ETH_HLEN + overhead;
	if (state->sk || !state->okfn || ip_is_fragment(ip) || skb_is_gso(skb) ||
	    length < ETH_HLEN || length > U16_MAX - HEADROOM ||
	    !skb_dst(skb) || skb_vlan_tag_present(skb) || skb->len > 1500 ||
	    ip->ihl != 5 || ntohs(ip->tot_len) != skb->len) {
		atomic64_inc(&counts[class].invalid);
		goto refuse;
	}
	if (!skb_dst_force(skb))
		goto refuse;
	if (atomic_inc_return(&live_items) > max_live) {
		atomic_dec(&live_items);
		goto refuse;
	}
	item = kzalloc(sizeof(*item), GFP_ATOMIC);
	if (!item) {
		atomic_dec(&live_items);
		goto refuse;
	}
	original_length = skb->len;
	prefix = ETH_HLEN + (((unsigned long)skb->data - ETH_HLEN - 2) & 3);
	suffix = overhead + ETH_HLEN - prefix;
	if (reuse_original) {
		if (skb_shared(skb))
			atomic64_inc(&counts[class].fallback_shared);
		else if (skb_cloned(skb))
			atomic64_inc(&counts[class].fallback_cloned);
		else if (skb_is_nonlinear(skb) || overhead + ETH_HLEN < prefix ||
			 skb_headroom(skb) < prefix || skb_tailroom(skb) < suffix ||
			 skb_headroom(skb) - prefix > U16_MAX - length)
			atomic64_inc(&counts[class].fallback_geometry);
		else
			item->reused = true;
	}
	if (item->reused) {
		carrier = skb;
		item->prefix = prefix;
		item->original_protocol = skb->protocol;
		item->original_head = skb->head;
		memcpy(item->saved_prefix, skb->data - prefix, prefix);
		memset(skb_push(skb, prefix), 0, prefix);
		skb_put_zero(skb, suffix);
		item->carrier_offset = skb_headroom(skb);
		atomic64_inc(&counts[class].reuse_prepared);
		atomic_inc(&reused_live);
	} else {
		carrier = alloc_skb(HEADROOM + length, GFP_ATOMIC);
		if (!carrier) {
			atomic_dec(&live_items);
			kfree(item);
			goto refuse;
		}
		skb_reserve(carrier, HEADROOM);
		skb_put_zero(carrier, length);
	}
	ether_addr_copy(carrier->data, physical->dev_addr);
	ether_addr_copy(carrier->data + ETH_ALEN, physical->dev_addr);
	carrier->data[12] = 0x88;
	carrier->data[13] = 0xb5;
	carrier->protocol = htons(0x88b5);
	if (!item->reused) {
		carrier->dev = physical;
		skb_reset_mac_header(carrier);
	}
	refcount_set(&item->refs, 1); /* submitter survives an immediate callback */
	INIT_LIST_HEAD(&item->output);
	item->state = *state;
	get_net(item->state.net);
	dev_hold(item->state.out);
	if (item->state.in)
		dev_hold(item->state.in);
	item->original = skb;
	item->carrier = carrier;
	item->class = class;
	item->charge = length;
	item->original_bytes = original_length + ETH_HLEN;
	item->original_memory = skb->truesize;
	item->carrier_memory = item->reused ? 0 : carrier->truesize;
	item->id = atomic64_inc_return(&identities);
	atomic64_add(item->original_bytes, &original_bytes);
	atomic64_add(item->original_memory, &original_memory);
	atomic64_add(length, &charge_bytes);
	atomic64_add(item->carrier_memory, &carrier_memory);
	recipient = (struct qdx_packet_recipient) {
		.owner = { .module = THIS_MODULE, .object = item,
			.get = charge_item_get, .put = charge_item_put },
		.returned = charge_returned,
	};
	ready = qdx_packet_op_submit(operations[class], carrier, &recipient);
	if (ready.status != QDX_ACCEPTED) {
		item->carrier = NULL;
		atomic64_sub(length, &charge_bytes);
		atomic64_sub(item->carrier_memory, &carrier_memory);
		if (item->reused) {
			charge_original_restore(item);
			atomic_dec(&reused_live);
			atomic64_inc(&counts[class].reuse_refused);
		} else {
			dev_kfree_skb_any(carrier);
		}
		charge_original_end(item, false); /* NF_DROP below owns original */
		charge_item_put(item);
		goto refuse;
	}
	if (item->reused)
		atomic64_inc(&counts[class].reuse_accepted);
	atomic64_inc(&counts[class].accepted);
	atomic64_add(length, &counts[class].charged_bytes);
	atomic64_add(item->original_bytes, &counts[class].basis_bytes);
	charge_item_put(item);
	atomic_dec(&publishers);
	return NF_STOLEN;
refuse:
	atomic64_inc(&counts[class].refusal);
	atomic_dec(&publishers);
	return NF_DROP;
}

/* One retained request describes its exact effect across timeout. No later
 * command replaces it, and ACK validation precedes the corresponding state.
 */
static int charge_command(u32 opcode, u32 subcommand, u32 node, u32 child,
		bool submit, unsigned int wait_ms)
{
	struct charge_wire msg = {};
	struct charge_redirect redirect = {};
	struct qdx_reply_bounds bounds;
	struct qdx_endpoint *target = endpoint;
	__le32 assignment[2] = {};
	u8 reply[sizeof(msg)] = {};
	void *payload;
	u32 quantum, type, value;
	size_t length;
	int error;

	if (fault)
		return -EPROTO;
	if (request && (pending_opcode != opcode || pending_request != subcommand ||
	    pending_node != node || pending_child != child))
		return -EBUSY;
	if (opcode == 10000) {
		redirect.sibling = cpu_to_le32(node ? ifnum : sibling_ifnum);
		redirect.next = cpu_to_le32(node ? 158 : 156);
		ether_addr_copy(redirect.mac, physical->dev_addr);
		target = node ? sibling : endpoint;
		payload = &redirect;
		length = sizeof(redirect);
	} else if (opcode == 7 || opcode == 9) {
		assignment[0] = cpu_to_le32(opcode == 7 ? 0 : shaper_id);
		payload = assignment;
		length = opcode == 7 ? 8 : 4;
	} else if (opcode == 11 && node < NODES) {
		msg.request = cpu_to_le32(subcommand);
		msg.value[0] = cpu_to_le32(TAG(node));
		if (subcommand == 0) {
			type = node == 0 ? (wrr_unshaped ? 3 : 5) : node == 1 ? (flavor == 1 ? 6 : 9) :
				node < 4 ? (flavor == 1 ? 7 : 10) : 4;
			msg.value[0] = cpu_to_le32(type);
			msg.value[1] = cpu_to_le32(TAG(node));
		} else if (subcommand == 5 || subcommand == 6) {
			/* PRIO detaches its band, while the other parents name a child tag. */
			msg.value[1] = cpu_to_le32(wrr_unshaped && node == 0 &&
				subcommand == 6 ? 0 : TAG(child));
			/* value[2] stays zero: the sole PRIO child occupies band0. */
		} else if (subcommand == 7) {
			if (node == 0) {
				if (wrr_unshaped)
					return -EINVAL; /* PRIO has no TBL CONFIG. */
				msg.value[1] = cpu_to_le32(rate);
				msg.value[2] = cpu_to_le32(burst);
				msg.value[3] = cpu_to_le32(31);
			} else if (node == 1) {
				msg.value[1] = cpu_to_le32(flavor == 3 ? 1 : 0);
			} else if (node < 4) {
				quantum = (flavor == 2 ? 1 : 1514) * (node - 1);
				msg.value[1] = cpu_to_le32(quantum);
				if (flavor == 1) {
					msg.value[2] = cpu_to_le32(rate / 5);
					msg.value[3] = cpu_to_le32(burst);
					msg.value[4] = cpu_to_le32(31);
				}
			} else {
				msg.value[1] = cpu_to_le32(limit);
				msg.value[2] = cpu_to_le32(1);
			}
		}
		payload = &msg;
		length = sizeof(msg);
	} else {
		return -EINVAL;
	}
	if (!request) {
		if (!submit)
			return 0;
		bounds = (struct qdx_reply_bounds) { length, length, length };
		request = qdx_command_submit(target, opcode, payload, length, &bounds, NULL);
		if (IS_ERR(request)) {
			error = PTR_ERR(request);
			request = NULL;
			return error;
		}
		pending_opcode = opcode;
		pending_request = subcommand;
		pending_node = node;
		pending_child = child;
	}
	error = qdx_request_wait(request, jiffies + msecs_to_jiffies(wait_ms),
		&last_result, reply, sizeof(reply));
	if (last_result.outcome == QDX_UNKNOWN && !last_result.exposure_ended)
		return error ?: -EINPROGRESS;
	if (last_result.outcome == QDX_ACK) {
		if (last_result.received_len < length || last_result.declared_len != length) {
			fault = true;
			return -EPROTO;
		}
		if (opcode == 11) {
			memcpy(&msg, reply, length);
			if (le32_to_cpu(msg.request) != subcommand) {
				fault = true;
				return -EPROTO;
			}
			last_response = le32_to_cpu(msg.response);
			error = last_response ? -EREMOTEIO : 0;
		} else if (opcode == 7) {
			memcpy(assignment, reply, length);
			shaper_id = le32_to_cpu(assignment[1]);
			error = shaper_id ? 0 : -EPROTO;
			if (error)
				fault = true;
		} else {
			error = 0;
		}
		if (!error) {
			if (opcode == 10000) {
				if (node)
					h2n_configured = true;
				else
					n2h_configured = true;
			} else if (opcode == 7) {
				assigned = true;
			} else if (opcode == 9) {
				assigned = false;
			} else if (subcommand == 0) {
				nodes[node].allocated = true;
			} else if (subcommand == 1) {
				nodes[node].allocated = nodes[node].configured = false;
			} else if (subcommand == 3) {
				rooted = true;
			} else if (subcommand == 5 || subcommand == 6) {
				nodes[child].attached = subcommand == 5;
			} else if (subcommand == 7) {
				nodes[node].configured = true;
			} else if (subcommand == 4) {
				nodes[node].gauge_bytes = le32_to_cpu(msg.value[1]);
				nodes[node].gauge_packets = le32_to_cpu(msg.value[2]);
				nodes[node].enqueued_bytes += le32_to_cpu(msg.value[7]);
				nodes[node].enqueued_packets += le32_to_cpu(msg.value[8]);
				nodes[node].enqueue_drop_bytes += le32_to_cpu(msg.value[9]);
				nodes[node].enqueue_drop_packets += le32_to_cpu(msg.value[10]);
				nodes[node].dequeued_bytes += le32_to_cpu(msg.value[11]);
				nodes[node].dequeued_packets += le32_to_cpu(msg.value[12]);
				nodes[node].dequeue_drop_bytes += le32_to_cpu(msg.value[13]);
				nodes[node].dequeue_drop_packets += le32_to_cpu(msg.value[14]);
				value = le32_to_cpu(msg.value[15]);
				nodes[node].overruns += value;
			}
		}
	} else {
		error = last_result.error ?: error ?: -EIO;
	}
	qdx_request_put(request);
	request = NULL;
	return error;
}

static int charge_prepare(void)
{
	unsigned int i, parent;
	int error;

	if (sealed || fault)
		return -EPERM;
	if (!pinned) {
		if (!try_module_get(THIS_MODULE))
			return -ENODEV;
		pinned = true;
		physical = dev_get_by_name(&init_net, "lan3");
		outdev = dev_get_by_name(&init_net, "br-lan");
		if (!physical || !outdev || !netif_running(physical) || !netif_running(outdev))
			return -ENODEV;
		service = qdx_service_get(physical, QDX_SERVICE_SHAPER);
		if (IS_ERR(service)) {
			error = PTR_ERR(service);
			service = NULL;
			return error;
		}
	}
	if (!service || qdx_service_state(service) != QDX_AVAILABLE)
		return -ENODEV;
	if (!endpoint) {
		endpoint = qdx_endpoint_alloc(service, 32);
		if (IS_ERR(endpoint)) {
			error = PTR_ERR(endpoint);
			endpoint = NULL;
			return error;
		}
	}
	error = qdx_endpoint_wait(endpoint, jiffies + msecs_to_jiffies(WAIT_MS));
	if (error)
		return error;
	error = qdx_endpoint_ifnum(endpoint, &ifnum);
	if (error)
		return error;
	if (!sibling) {
		sibling = qdx_endpoint_alloc(service, 33);
		if (IS_ERR(sibling)) {
			error = PTR_ERR(sibling);
			sibling = NULL;
			return error;
		}
	}
	error = qdx_endpoint_wait(sibling, jiffies + msecs_to_jiffies(WAIT_MS));
	if (error)
		return error;
	error = qdx_endpoint_ifnum(sibling, &sibling_ifnum);
	if (error || ifnum == sibling_ifnum)
		return error ?: -EPROTO;
	if (request) {
		error = charge_command(pending_opcode, pending_request, pending_node,
			pending_child, false, WAIT_MS);
		if (error)
			return error;
	}
	for (i = 0; i < 2; i++) {
		if (i ? h2n_configured : n2h_configured)
			continue;
		error = charge_command(10000, 0, i, 0, true, WAIT_MS);
		if (error)
			return error;
	}
	if (!assigned) {
		error = charge_command(7, 0, 0, 0, true, WAIT_MS);
		if (error)
			return error;
	}
	for (i = 0; i < NODES; i++) {
		if (nodes[i].allocated)
			continue;
		error = charge_command(11, 0, i, 0, true, WAIT_MS);
		if (error)
			return error;
	}
	if (!rooted) {
		error = charge_command(11, 3, 0, 0, true, WAIT_MS);
		if (error)
			return error;
	}
	for (i = 1; i < NODES; i++) {
		if (nodes[i].attached)
			continue;
		parent = i == 1 ? 0 : i < 4 ? 1 : i - 2;
		error = charge_command(11, 5, parent, i, true, WAIT_MS);
		if (error)
			return error;
	}
	for (i = 0; i < NODES; i++) {
		if (nodes[i].configured || (i == 1 && flavor == 1) ||
		    (i == 0 && wrr_unshaped))
			continue;
		error = charge_command(11, 7, i, 0, true, WAIT_MS);
		if (error)
			return error;
	}
	for (i = 0; i < 2; i++) {
		if (operations[i])
			continue;
		operations[i] = qdx_packet_op_prepare(endpoint, TAG(i + 4),
			QDX_RECEIVE_BRIDGE_RETURNED);
		if (IS_ERR(operations[i])) {
			error = PTR_ERR(operations[i]);
			operations[i] = NULL;
			return error;
		}
	}
	if (!hook_registered) {
		error = nf_register_net_hook(&init_net, &hook);
		if (error)
			return error;
		hook_registered = true;
	}
	prepared = true;
	return 0;
}

static int charge_stop(void)
{
	unsigned int i;

	WRITE_ONCE(armed, false);
	sealed = true;
	synchronize_net();
	if (atomic_read(&publishers))
		return -EINPROGRESS;
	for (i = 0; i < 2; i++)
		if (operations[i])
			qdx_packet_op_close(operations[i]);
	return 0;
}

static int charge_restore(void)
{
	unsigned int i, parent;
	int error;
	bool access_ended;

	if (!pinned)
		return 0;
	error = charge_stop();
	if (error)
		return error;
	for (i = 0; i < 2; i++)
		if (operations[i] && !qdx_packet_op_drained(operations[i]))
			return -EINPROGRESS;
	flush_work(&output_work);
	if (atomic_read(&live_items) || atomic_read(&reused_live) || atomic_read(&output_pending))
		return -EINPROGRESS;
	if (hook_registered) {
		nf_unregister_net_hook(&init_net, &hook);
		hook_registered = false;
	}
	access_ended = service && qdx_service_access_ended(service);
	if (access_ended) {
		if (request)
			qdx_request_put(request);
		request = NULL;
		for (i = 0; i < NODES; i++)
			nodes[i].allocated = nodes[i].attached = nodes[i].configured = false;
		assigned = rooted = prepared = false;
	} else {
		if (request) {
			error = charge_command(pending_opcode, pending_request, pending_node,
				pending_child, false, WAIT_MS);
			if (error)
				return error;
		}
		for (i = NODES; i-- > 1;) {
			if (!nodes[i].attached)
				continue;
			parent = i < 4 ? 1 : i - 2;
			if (i == 1)
				parent = 0;
			error = charge_command(11, 6, parent, i, true, WAIT_MS);
			if (error)
				return error;
		}
		for (i = NODES; i-- > 0;) {
			if (!nodes[i].allocated)
				continue;
			error = charge_command(11, 1, i, 0, true, WAIT_MS);
			if (error)
				return error;
		}
		if (assigned) {
			error = charge_command(9, 0, 0, 0, true, WAIT_MS);
			if (error)
				return error;
		}
	}
	if (endpoint && !endpoint_retired) {
		if (!access_ended && qdx_endpoint_wait(endpoint, jiffies) == -ETIMEDOUT)
			return -EINPROGRESS;
		error = qdx_endpoint_retire(endpoint);
		if (error)
			return error;
		endpoint_retired = true;
	}
	if (sibling && !sibling_retired) {
		if (!access_ended && qdx_endpoint_wait(sibling, jiffies) == -ETIMEDOUT)
			return -EINPROGRESS;
		error = qdx_endpoint_retire(sibling);
		if (error)
			return error;
		sibling_retired = true;
	}
	for (i = 0; i < 2; i++) {
		qdx_packet_op_put(operations[i]);
		operations[i] = NULL;
	}
	qdx_endpoint_put(endpoint);
	endpoint = NULL;
	qdx_endpoint_put(sibling);
	sibling = NULL;
	qdx_service_put(service);
	service = NULL;
	if (physical)
		dev_put(physical);
	physical = NULL;
	if (outdev)
		dev_put(outdev);
	outdev = NULL;
	prepared = rooted = false;
	pinned = false;
	module_put(THIS_MODULE);
	return 0;
}

static int charge_status_show(struct seq_file *seq, void *unused)
{
	unsigned int i;
	struct charge_counts *c;
	struct charge_node *n;

	mutex_lock(&control_lock);
	seq_printf(seq, "allow_writes=%u reuse_original=%u flavor=%u wrr_unshaped=%u root_type=%u rate=%u burst=%u overhead=%u limit=%u max_live=%u pinned=%u prepared=%u armed=%u ever_armed=%u sealed=%u fault=%u hook=%u assigned=%u rooted=%u error=%d\n",
		allow_writes, reuse_original, flavor, wrr_unshaped, wrr_unshaped ? 3 : 5,
		rate, burst, overhead, limit, max_live, pinned,
		prepared, armed, ever_armed, sealed, fault, hook_registered, assigned, rooted, last_error);
	seq_printf(seq, "n2h=%u h2n=%u shaper=%u request=%u opcode=%u command=%u node=%u child=%u outcome=%u published=%u exposure_ended=%u reply=%u\n",
		ifnum, sibling_ifnum, shaper_id, !!request, pending_opcode, pending_request,
		pending_node, pending_child, last_result.outcome, last_result.published,
		last_result.exposure_ended, last_response);
	seq_printf(seq, "live=%d reused_live=%d publishers=%d output_pending=%d original_bytes=%lld charge_bytes=%lld original_memory=%lld carrier_memory=%lld op0_drained=%u op1_drained=%u\n",
		atomic_read(&live_items), atomic_read(&reused_live), atomic_read(&publishers), atomic_read(&output_pending),
		atomic64_read(&original_bytes), atomic64_read(&charge_bytes),
		atomic64_read(&original_memory), atomic64_read(&carrier_memory),
		operations[0] ? qdx_packet_op_drained(operations[0]) : true,
		operations[1] ? qdx_packet_op_drained(operations[1]) : true);
	for (i = 0; i < 2; i++) {
		c = &counts[i];
		seq_printf(seq, "class=%u inputs=%lld accepted=%lld returned=%lld disposal=%lld firmware_empty=%lld access_end=%lld refusal=%lld invalid=%lld forwarded=%lld continuation_error=%lld charged_bytes=%lld basis_bytes=%lld "
			"reuse_prepared=%lld reuse_accepted=%lld reuse_returned=%lld reuse_disposal=%lld reuse_refused=%lld reuse_restored=%lld reuse_moved=%lld fallback_shared=%lld fallback_cloned=%lld fallback_geometry=%lld\n",
			i, atomic64_read(&c->inputs), atomic64_read(&c->accepted),
			atomic64_read(&c->returned), atomic64_read(&c->disposal),
			atomic64_read(&c->firmware_empty), atomic64_read(&c->access_end), atomic64_read(&c->refusal),
			atomic64_read(&c->invalid), atomic64_read(&c->forwarded),
			atomic64_read(&c->continuation_error), atomic64_read(&c->charged_bytes),
			atomic64_read(&c->basis_bytes),
			atomic64_read(&c->reuse_prepared), atomic64_read(&c->reuse_accepted),
			atomic64_read(&c->reuse_returned), atomic64_read(&c->reuse_disposal),
			atomic64_read(&c->reuse_refused), atomic64_read(&c->reuse_restored),
			atomic64_read(&c->reuse_moved), atomic64_read(&c->fallback_shared),
			atomic64_read(&c->fallback_cloned), atomic64_read(&c->fallback_geometry));
	}
	for (i = 0; i < NODES; i++) {
		n = &nodes[i];
		seq_printf(seq, "node=%u tag=%08x allocated=%u attached=%u configured=%u qlen=%u backlog=%u enq=%llu enq_bytes=%llu drop=%llu drop_bytes=%llu deq=%llu deq_bytes=%llu dq_drop=%llu dq_drop_bytes=%llu overruns=%llu\n",
			i, TAG(i), n->allocated, n->attached, n->configured,
			n->gauge_packets, n->gauge_bytes, n->enqueued_packets, n->enqueued_bytes,
			n->enqueue_drop_packets, n->enqueue_drop_bytes, n->dequeued_packets,
			n->dequeued_bytes, n->dequeue_drop_packets, n->dequeue_drop_bytes, n->overruns);
	}
	mutex_unlock(&control_lock);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(charge_status);

static ssize_t charge_control_write(struct file *file, const char __user *buffer,
		size_t count, loff_t *position)
{
	char command[24];
	unsigned int i;
	int error = 0;

	if (!allow_writes)
		return -EPERM;
	if (!count || count >= sizeof(command))
		return -EINVAL;
	if (copy_from_user(command, buffer, count))
		return -EFAULT;
	command[count] = 0;
	strim(command);
	mutex_lock(&control_lock);
	if (!strcmp(command, "prepare")) {
		error = charge_prepare();
	} else if (!strcmp(command, "arm")) {
		if (!prepared || sealed || fault || request)
			error = -EINVAL;
		else {
			ever_armed = true;
			WRITE_ONCE(armed, true);
		}
	} else if (!strcmp(command, "stop")) {
		error = charge_stop();
	} else if (!strcmp(command, "restore")) {
		error = charge_restore();
	} else if (!strcmp(command, "poll")) {
		if (request)
			error = charge_command(pending_opcode, pending_request, pending_node,
				pending_child, false, 0);
	} else if (!strcmp(command, "stats")) {
		if (!prepared || request || fault)
			error = -EBUSY;
		else
			for (i = 0; i < NODES; i++) {
				error = charge_command(11, 4, i, 0, true, WAIT_MS);
				if (error)
					break;
			}
	} else {
		error = -EINVAL;
	}
	last_error = error;
	mutex_unlock(&control_lock);
	return error ?: count;
}
static const struct file_operations charge_control_fops = {
	.owner = THIS_MODULE, .write = charge_control_write,
};

static int __init charge_init(void)
{
	struct dentry *entry;

	if (flavor < 1 || flavor > 3 ||
	    (wrr_unshaped ? (flavor == 1 || rate || burst) :
	     (rate < 5 || rate > INT_MAX || burst < 31 || burst > INT_MAX ||
	      burst < DIV_ROUND_UP(rate, 1000))) ||
	    overhead > 4096 || !limit || limit > 65535 || !max_live || max_live > 65535)
		return -EINVAL;
	INIT_WORK(&output_work, charge_output_work);
	directory = debugfs_create_dir("qdx_charge_diag", NULL);
	if (IS_ERR_OR_NULL(directory))
		return -ENOMEM;
	entry = debugfs_create_file("control", 0200, directory, NULL, &charge_control_fops);
	if (IS_ERR_OR_NULL(entry))
		goto fail;
	entry = debugfs_create_file("status", 0400, directory, NULL, &charge_status_fops);
	if (IS_ERR_OR_NULL(entry))
		goto fail;
	return 0;
fail:
	debugfs_remove_recursive(directory);
	return -ENOMEM;
}
static void __exit charge_exit(void)
{
	WARN_ON(pinned || request || endpoint || sibling || operations[0] || operations[1] ||
		hook_registered || atomic_read(&live_items) || atomic_read(&reused_live) || atomic_read(&output_pending));
	cancel_work_sync(&output_work);
	debugfs_remove_recursive(directory);
}
module_init(charge_init);
module_exit(charge_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Isolated backed-charge carriers with real routed original continuation");
