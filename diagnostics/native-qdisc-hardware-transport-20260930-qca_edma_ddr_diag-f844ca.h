/* SPDX-License-Identifier: GPL-2.0-only */
/* Isolated RAM diagnostic, included once by qca_edma.c. Not a product API.
 * CoDel state transitions below adapt Linux 6.18.44 codel_impl.h to real
 * page records. Its original notice follows. FQ-CoDel list/overflow rules
 * derive from sch_fq_codel.c, Copyright (C) 2012,2015 Eric Dumazet.
 */
/*
 * Codel - The Controlled-Delay Active Queue Management algorithm
 *
 *  Copyright (C) 2011-2012 Kathleen Nichols <nichols@pollere.com>
 *  Copyright (C) 2011-2012 Van Jacobson <van@pollere.net>
 *  Copyright (C) 2012 Michael D. Taht <dave.taht@bufferbloat.net>
 *  Copyright (C) 2012,2015 Eric Dumazet <edumazet@google.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The names of the authors may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * Alternatively, provided that this notice is retained in full, this
 * software may be distributed under the terms of the GNU General
 * Public License ("GPL") version 2, in which case the provisions of the
 * GPL apply INSTEAD OF those given above.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 */
#ifndef QCA_EDMA_DDR_DIAG_H
#define QCA_EDMA_DDR_DIAG_H

#include <linux/hrtimer.h>
#include <linux/ip.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/udp.h>
#include <linux/uaccess.h>
#include <net/codel.h>
#include <net/dsa.h>
#include <net/inet_ecn.h>
#include <net/ip.h>
#include <net/sch_generic.h>

#define EDMA_DDR_FLOWS 4
#define EDMA_DDR_PORT_BASE 45987
#define EDMA_DDR_MAX_LIMIT 4096

enum edma_ddr_mode {
	EDMA_DDR_FIFO = 1,
	EDMA_DDR_CODEL,
	EDMA_DDR_FQ_CODEL,
};

struct edma_ddr_item {
	struct edma_ddr_item *next;
	struct page *page;
	u32 len;
	u32 memory;
	codel_time_t enqueue_time;
	u8 bin;
};

struct edma_ddr_flow {
	struct edma_ddr_item *head, *tail;
	struct list_head active;
	struct codel_vars codel;
	u32 bytes;
	s32 deficit;
};

struct edma_ddr_stats {
	u64 seen, seen_bytes, enqueued, overlimit, overmemory, aqm_drop;
	u64 ecn_mark, oversize, record_refused, alloc_failed, shape_refused;
	u64 handed, handed_bytes, handoff_error, waits, aborted;
	u64 service_due_skipped;
	u64 service_entry_calls, service_arrival_probes, service_arrival_early;
	u64 service_arrival_calls, service_tail_calls;
	u64 deadline_count, deadline_sum_ns, deadline_max_ns;
	u64 deadline_busy_count, deadline_busy_sum_ns, deadline_busy_max_ns;
	u64 ready_without_wait;
	u64 bypass_selected, bypass_sent, bypass_requeued;
	u64 arrivals[EDMA_DDR_FLOWS], departures[EDMA_DDR_FLOWS];
	u64 marks[EDMA_DDR_FLOWS], drops[EDMA_DDR_FLOWS];
};

struct edma_ddr_diag {
	struct edma_priv *priv;
	struct proc_dir_entry *proc;
	struct mutex control;
	spinlock_t lock;
	struct hrtimer timer;
	struct net_device *source, *target;
	struct Qdisc *target_root, *conduit_root;
	struct edma_ddr_item *items, *free, *cached;
	struct edma_ddr_flow flows[EDMA_DDR_FLOWS];
	struct list_head new_flows, old_flows;
	struct codel_params cparams;
	struct psched_ratecfg rate;
	struct edma_ddr_stats stats;
	u64 rate_bps;
	s64 buffer, tokens, token_time, due_time;
	s64 head_due; /* First credit deadline of this cached head; timer cannot erase it. */
	bool head_had_busy;
	atomic64_t timer_fired;
	u32 mode, limit, memory_limit, quantum, drop_batch, burst;
	u32 qlen, backlog, memory, publishing, maxpacket;
	u32 target_mtu, invalid;
	bool active, transport_raw, bounded_sync, due_guard, empty_bypass, service_first;
};

/* Called under the queue lock. A changed fixture stops taking new pages.
 * A hard mismatch retains its old pages until the actual driver reset/removal;
 * this diagnostic does not invent a policy transition for native objects.
 */
static bool edma_ddr_fixture_valid(struct edma_ddr_diag *d)
{
	if (d->invalid)
		return false;
	if (rcu_access_pointer(d->target->qdisc) != d->target_root ||
	    rcu_access_pointer(d->priv->netdev->qdisc) != d->conduit_root)
		d->invalid = 1;
	else if (d->empty_bypass &&
		 !(READ_ONCE(d->target_root->flags) & TCQ_F_CAN_BYPASS))
		d->invalid = 6;
	else if (d->target->features & NETIF_F_HW_TC)
		d->invalid = 2;
	else if (READ_ONCE(d->target->mtu) != d->target_mtu)
		d->invalid = 3;
	else if (!netif_running(d->source) || !netif_running(d->target) ||
		 !netif_carrier_ok(d->source) || !netif_carrier_ok(d->target))
		d->invalid = 4;
	return !d->invalid;
}

/* Called in RX NAPI, except for explicit driver destruction/pool replacement. */
static void edma_ddr_release(struct edma_ddr_diag *d,
			     struct edma_ddr_item *item, bool direct)
{
	if (item->page) {
		u64 started = edma_diag_begin(d->priv, EDMA_TIME_DDR_RECYCLE);
		u32 sync_len = d->bounded_sync ? EDMA_RX_PREHDR_SIZE + item->len : ~0U;

		page_pool_put_page(d->priv->page_pool, item->page, sync_len, direct);
		edma_diag_end(d->priv, EDMA_TIME_DDR_RECYCLE, started, item->len);
	}
	item->page = NULL;
	item->next = d->free;
	d->free = item;
}

static struct edma_ddr_item *edma_ddr_pop(struct edma_ddr_diag *d,
					struct edma_ddr_flow *flow)
{
	struct edma_ddr_item *item = flow->head;

	if (!item)
		return NULL;
	flow->head = item->next;
	if (!flow->head)
		flow->tail = NULL;
	item->next = NULL;
	flow->bytes -= item->len;
	d->qlen--;
	d->backlog -= item->len;
	d->memory -= item->memory;
	return item;
}

static void edma_ddr_newton(struct codel_vars *vars)
{
	u32 invsqrt = (u32)vars->rec_inv_sqrt << REC_INV_SQRT_SHIFT;
	u32 invsqrt2 = ((u64)invsqrt * invsqrt) >> 32;
	u64 value = (3LL << 32) - (u64)vars->count * invsqrt2;

	value >>= 2;
	value = (value * invsqrt) >> (32 - 2 + 1);
	vars->rec_inv_sqrt = value >> REC_INV_SQRT_SHIFT;
}

static codel_time_t edma_ddr_control_law(codel_time_t time,
					struct edma_ddr_diag *d,
					struct codel_vars *vars)
{
	return time + reciprocal_scale(d->cparams.interval,
			(u32)vars->rec_inv_sqrt << REC_INV_SQRT_SHIFT);
}

static bool edma_ddr_should_drop(struct edma_ddr_diag *d,
				 struct codel_vars *vars,
				 struct edma_ddr_item *item, codel_time_t now)
{
	if (!item) {
		vars->first_above_time = 0;
		return false;
	}
	vars->ldelay = now - item->enqueue_time;
	d->maxpacket = max(d->maxpacket, item->len);
	if (codel_time_before(vars->ldelay, d->cparams.target) ||
	    d->backlog <= d->cparams.mtu) {
		vars->first_above_time = 0;
		return false;
	}
	if (!vars->first_above_time)
		vars->first_above_time = now + d->cparams.interval;
	else if (codel_time_after(now, vars->first_above_time))
		return true;
	return false;
}

static bool edma_ddr_mark(struct edma_ddr_diag *d, struct edma_ddr_item *item)
{
	struct iphdr *ip = page_address(item->page) + NET_SKB_PAD +
			   EDMA_RX_PREHDR_SIZE + ETH_HLEN;

	if (!d->cparams.ecn || !IP_ECN_set_ce(ip))
		return false;
	d->stats.ecn_mark++;
	d->stats.marks[item->bin]++;
	return true;
}

static struct edma_ddr_item *edma_ddr_codel(struct edma_ddr_diag *d,
					  struct edma_ddr_flow *flow)
{
	struct codel_vars *vars = &flow->codel;
	struct edma_ddr_item *item = edma_ddr_pop(d, flow);
	codel_time_t now;
	bool drop;

	if (!item) {
		vars->dropping = false;
		return NULL;
	}
	now = codel_get_time();
	drop = edma_ddr_should_drop(d, vars, item, now);
	if (vars->dropping) {
		if (!drop) {
			vars->dropping = false;
		} else if (codel_time_after_eq(now, vars->drop_next)) {
			while (vars->dropping &&
			       codel_time_after_eq(now, vars->drop_next)) {
				vars->count++;
				edma_ddr_newton(vars);
				if (edma_ddr_mark(d, item)) {
					vars->drop_next = edma_ddr_control_law(
						vars->drop_next, d, vars);
					return item;
				}
				d->stats.aqm_drop++;
				d->stats.drops[item->bin]++;
				edma_ddr_release(d, item, true);
				item = edma_ddr_pop(d, flow);
				if (!edma_ddr_should_drop(d, vars, item, now))
					vars->dropping = false;
				else
					vars->drop_next = edma_ddr_control_law(
						vars->drop_next, d, vars);
			}
		}
	} else if (drop) {
		u32 delta;

		if (!edma_ddr_mark(d, item)) {
			d->stats.aqm_drop++;
			d->stats.drops[item->bin]++;
			edma_ddr_release(d, item, true);
			item = edma_ddr_pop(d, flow);
			edma_ddr_should_drop(d, vars, item, now);
		}
		vars->dropping = true;
		delta = vars->count - vars->lastcount;
		if (delta > 1 && codel_time_before(now - vars->drop_next,
						16 * d->cparams.interval)) {
			vars->count = delta;
			edma_ddr_newton(vars);
		} else {
			vars->count = 1;
			vars->rec_inv_sqrt = ~0U >> REC_INV_SQRT_SHIFT;
		}
		vars->lastcount = vars->count;
		vars->drop_next = edma_ddr_control_law(now, d, vars);
	}
	/* ce_threshold is deliberately disabled in this fixed diagnostic. */
	return item;
}

static struct edma_ddr_item *edma_ddr_select(struct edma_ddr_diag *d)
{
	struct edma_ddr_item *item;
	struct edma_ddr_flow *flow;
	struct list_head *head;

	if (d->mode == EDMA_DDR_FIFO)
		return edma_ddr_pop(d, &d->flows[0]);
	if (d->mode == EDMA_DDR_CODEL)
		return edma_ddr_codel(d, &d->flows[0]);
	for (;;) {
		head = &d->new_flows;
		if (list_empty(head)) {
			head = &d->old_flows;
			if (list_empty(head))
				return NULL;
		}
		flow = list_first_entry(head, struct edma_ddr_flow, active);
		if (flow->deficit <= 0) {
			flow->deficit += d->quantum;
			list_move_tail(&flow->active, &d->old_flows);
			continue;
		}
		item = edma_ddr_codel(d, flow);
		if (!item) {
			if (head == &d->new_flows && !list_empty(&d->old_flows))
				list_move_tail(&flow->active, &d->old_flows);
			else
				list_del_init(&flow->active);
			continue;
		}
		flow->deficit -= item->len;
		return item;
	}
}

/* This is after-append largest-bin eviction, not a global tail drop. */
static void edma_ddr_overflow(struct edma_ddr_diag *d, bool memory_limited)
{
	struct edma_ddr_flow *flow;
	struct edma_ddr_item *item;
	u32 maximum = 0, index = 0, bytes = 0, count = 0, i;

	for (i = 0; i < EDMA_DDR_FLOWS; i++) {
		if (d->flows[i].bytes > maximum) {
			maximum = d->flows[i].bytes;
			index = i;
		}
	}
	flow = &d->flows[index];
	do {
		item = edma_ddr_pop(d, flow);
		if (WARN_ON_ONCE(!item))
			break;
		bytes += item->len;
		d->stats.drops[item->bin]++;
		edma_ddr_release(d, item, true);
	} while (++count < d->drop_batch && bytes < (maximum >> 1));
	flow->codel.count += count;
	d->stats.overlimit += count;
	if (memory_limited)
		d->stats.overmemory += count;
}

/* True transfers this exact page; false preserves the driver's normal path. */
static bool edma_ddr_receive(struct edma_priv *priv, struct page *page,
			     u32 source_port, u32 len)
{
	struct edma_ddr_diag *d = priv->ddr_diag;
	struct edma_ddr_item *item;
	struct edma_ddr_flow *flow;
	struct ethhdr *eth;
	struct iphdr *ip;
	struct udphdr *udp;
	u32 ip_len, bin, memory;
	u64 output_started;
	int result;
	bool limited;

	if (!d || !READ_ONCE(d->active) || source_port != 3 ||
	    len < ETH_HLEN + sizeof(*ip) + sizeof(*udp) ||
	    len > priv->rx_buffer_size - EDMA_RX_PREHDR_SIZE)
		return false;
	eth = page_address(page) + NET_SKB_PAD + EDMA_RX_PREHDR_SIZE;
	if (eth->h_proto != htons(ETH_P_IP))
		return false;
	ip = (void *)(eth + 1);
	if (ip->saddr != htonl(0xc0a80190) || ip->daddr != htonl(0xc0a80173) ||
	    ip->protocol != IPPROTO_UDP)
		return false;
	if (ip->version != 4 || ip->ihl != 5 ||
	    ip->frag_off & htons(IP_MF | IP_OFFSET))
		goto shape;
	udp = (void *)(ip + 1);
	bin = ntohs(udp->dest) - EDMA_DDR_PORT_BASE;
	if (bin >= EDMA_DDR_FLOWS)
		return false;
	ip_len = ntohs(ip->tot_len);
	if (ip_len < sizeof(*ip) + sizeof(*udp) || ip_len > len - ETH_HLEN ||
	    (ip_len != len - ETH_HLEN && len != ETH_ZLEN) ||
	    ntohs(udp->len) != ip_len - sizeof(*ip))
		goto shape;

	spin_lock_bh(&d->lock);
	if (!d->active || !edma_ddr_fixture_valid(d)) {
		spin_unlock_bh(&d->lock);
		return false;
	}
	dev_sw_netstats_rx_add(priv->netdev, len);
	d->stats.seen++;
	d->stats.seen_bytes += len;
	d->stats.arrivals[bin]++;
	/* Native root CAN_BYPASS skips policy history, not prior actions or
	 * actual output ownership. RX NAPI and this lock serialize the whole
	 * diagnostic population; accepted TX descriptors preserve prior order.
	 */
	if (d->empty_bypass && !d->qlen && !d->cached && !d->publishing) {
		item = d->free;
		if (unlikely(!item)) {
			d->stats.record_refused++;
			goto reject;
		}
		d->stats.bypass_selected++;
		output_started = edma_diag_begin(priv, EDMA_TIME_DDR_OUTPUT);
		result = edma_diag_raw_xmit(priv, &page, len, d->bounded_sync);
		edma_diag_end(priv, EDMA_TIME_DDR_OUTPUT, output_started, len);
		if (!result) {
			d->stats.bypass_sent++;
			d->stats.handed++;
			d->stats.handed_bytes += len;
			d->stats.departures[bin]++;
			spin_unlock_bh(&d->lock);
			return true;
		}
		if (result != -EAGAIN) {
			d->invalid = 5;
			/* A failed publication may already have transferred the page
			 * to its TX slot. Do not invent a second backlog owner.
			 */
			if (!page) {
				spin_unlock_bh(&d->lock);
				return true;
			}
		}
		/* Native BUSY requeue is already selected: no bin membership,
		 * timestamp, memory charge, deficit or CoDel history update.
		 * Retry this head before any later ordinary queued packet.
		 */
		d->free = item->next;
		*item = (struct edma_ddr_item) { .page = page, .len = len, .bin = bin };
		d->cached = item;
		d->qlen = 1;
		d->backlog = len;
		if (result == -EAGAIN)
			d->stats.bypass_requeued++;
		spin_unlock_bh(&d->lock);
		return true;
	}
	if (d->rate_bps && len > d->burst) {
		d->stats.oversize++;
		goto reject;
	}
	if (d->mode != EDMA_DDR_FQ_CODEL && d->qlen >= d->limit) {
		d->stats.overlimit++;
		goto reject;
	}
	item = d->free;
	if (unlikely(!item)) {
		d->stats.record_refused++;
		goto reject;
	}
	d->free = item->next;
	memory = page_size(page) + SKB_DATA_ALIGN(sizeof(struct sk_buff));
	*item = (struct edma_ddr_item) {
		.page = page, .len = len, .memory = memory, .bin = bin,
		.enqueue_time = codel_get_time(),
	};
	flow = &d->flows[d->mode == EDMA_DDR_FQ_CODEL ? bin : 0];
	if (flow->tail)
		flow->tail->next = item;
	else
		flow->head = item;
	flow->tail = item;
	flow->bytes += len;
	d->qlen++;
	d->backlog += len;
	d->memory += memory;
	d->stats.enqueued++;
	if (d->mode == EDMA_DDR_FQ_CODEL) {
		if (list_empty(&flow->active)) {
			list_add_tail(&flow->active, &d->new_flows);
			flow->deficit = d->quantum;
		}
		limited = d->memory > d->memory_limit;
		if (d->qlen > d->limit || limited)
			edma_ddr_overflow(d, limited);
	}
	spin_unlock_bh(&d->lock);
	return true;
reject:
	d->stats.drops[bin]++;
	spin_unlock_bh(&d->lock);
	page_pool_put_page(priv->page_pool, page,
		d->bounded_sync ? EDMA_RX_PREHDR_SIZE + len : ~0U, true);
	return true;
shape:
	spin_lock_bh(&d->lock);
	d->stats.shape_refused++;
	spin_unlock_bh(&d->lock);
	return false;
}

/* No record pointer is put into the skb: native output owns it independently. */
static bool edma_ddr_output(struct edma_ddr_diag *d, struct edma_ddr_item *item,
			    int *result)
{
	struct sk_buff *skb;
	struct dsa_oob_tag_info *tag;

	skb = napi_build_skb(page_address(item->page), page_size(item->page));
	if (!skb)
		return false;
	skb_mark_for_recycle(skb);
	item->page = NULL;
	skb_reserve(skb, NET_SKB_PAD + EDMA_RX_PREHDR_SIZE);
	skb_put(skb, item->len);
	skb_reset_mac_header(skb);
	skb_set_network_header(skb, ETH_HLEN);
	skb_set_transport_header(skb, ETH_HLEN + sizeof(struct iphdr));
	skb->protocol = htons(ETH_P_IP);
	skb->ip_summed = CHECKSUM_NONE;
	skb->dev = d->priv->netdev;
	skb->skb_iif = d->source->ifindex;
	skb_set_queue_mapping(skb, 0);
	tag = skb_ext_add(skb, SKB_EXT_DSA_OOB);
	if (!tag) {
		dev_kfree_skb_any(skb);
		return false;
	}
	*tag = (struct dsa_oob_tag_info) { .port = 4 };
	/* dev_queue_xmit consumes skb on every return, including a drop. */
	*result = dev_queue_xmit(skb);
	return true;
}

static enum hrtimer_restart edma_ddr_timer(struct hrtimer *timer)
{
	struct edma_ddr_diag *d = container_of(timer, struct edma_ddr_diag, timer);

	atomic64_inc(&d->timer_fired);
	WRITE_ONCE(d->due_time, 0);
	if (READ_ONCE(d->active) && READ_ONCE(d->priv->napi_active))
		napi_schedule(&d->priv->rx_napi);
	return HRTIMER_NORESTART;
}

static int edma_ddr_service(struct edma_priv *priv, int budget)
{
	struct edma_ddr_diag *d = priv->ddr_diag;
	struct edma_ddr_item *item;
	s64 now = 0, tokens = 0, due;
	u64 started, output_started;
	int done = 0, result;
	bool handed;

	if (!d || !READ_ONCE(d->active))
		return 0;
	/* The same RX NAPI owns the cached head. A later arrival cannot remove
	 * it from a flow bin. Timer/configuration clears this optional hint.
	 */
	due = READ_ONCE(d->due_time);
	if (d->due_guard && due && ktime_get_ns() < due) {
		d->stats.service_due_skipped++;
		return 0;
	}
	while (done < budget) {
		started = edma_diag_begin(priv, EDMA_TIME_DDR_DECISION);
		spin_lock_bh(&d->lock);
		if (!d->active || !READ_ONCE(priv->napi_active) ||
		    !edma_ddr_fixture_valid(d)) {
			edma_diag_end(priv, EDMA_TIME_DDR_DECISION, started, 0);
			spin_unlock_bh(&d->lock);
			break;
		}
		if (!d->cached) {
			d->head_due = 0;
			d->head_had_busy = false;
			d->cached = edma_ddr_select(d);
			if (d->cached) {
				/* Generic native peek restores only qlen/global bytes. */
				d->qlen++;
				d->backlog += d->cached->len;
			}
		}
		item = d->cached;
		if (!item) {
			edma_diag_end(priv, EDMA_TIME_DDR_DECISION, started, 0);
			spin_unlock_bh(&d->lock);
			break;
		}
		WRITE_ONCE(d->due_time, 0);
		if (d->rate_bps) {
			now = ktime_get_ns();
			tokens = min_t(s64, now - d->token_time, d->buffer);
			tokens = min_t(s64, tokens + d->tokens, d->buffer);
			tokens -= (s64)psched_l2t_ns(&d->rate, item->len);
			if (tokens < 0) {
				u64 wake = now - tokens;

				d->stats.waits++;
				if (!d->head_due)
					d->head_due = wake;
				if (d->due_guard)
					WRITE_ONCE(d->due_time, wake);
				if (!hrtimer_active(&d->timer) ||
				    ktime_to_ns(hrtimer_get_expires(&d->timer)) != wake)
					hrtimer_start(&d->timer, ns_to_ktime(wake),
						      HRTIMER_MODE_ABS);
				edma_diag_end(priv, EDMA_TIME_DDR_DECISION, started, item->len);
				spin_unlock_bh(&d->lock);
				break;
			}
		}
		if (d->transport_raw) {
			output_started = edma_diag_begin(priv, EDMA_TIME_DDR_OUTPUT);
			result = edma_diag_raw_xmit(priv, &item->page, item->len,
						   d->bounded_sync);
			edma_diag_end(priv, EDMA_TIME_DDR_OUTPUT, output_started, item->len);
			if (result) {
				/* BUSY owns no descriptor: retain cached head and credit.
				 * A real fault closes this diagnostic without disposal.
				 */
				if (result == -EAGAIN)
					d->head_had_busy = true;
				else
					d->invalid = 5;
				edma_diag_end(priv, EDMA_TIME_DDR_DECISION, started, item->len);
				spin_unlock_bh(&d->lock);
				break;
			}
		}
		if (d->rate_bps) {
			d->tokens = tokens;
			d->token_time = now;
			if (d->transport_raw && d->head_due) {
				u64 late = max_t(s64, ktime_get_ns() - d->head_due, 0);

				/* Successful publication-return witness, not wire time. */
				if (d->head_had_busy) {
					d->stats.deadline_busy_count++;
					d->stats.deadline_busy_sum_ns += late;
					d->stats.deadline_busy_max_ns =
						max(d->stats.deadline_busy_max_ns, late);
				} else {
					d->stats.deadline_count++;
					d->stats.deadline_sum_ns += late;
					d->stats.deadline_max_ns =
						max(d->stats.deadline_max_ns, late);
				}
			} else if (d->transport_raw) {
				d->stats.ready_without_wait++;
			}
		}
		d->head_due = 0;
		d->head_had_busy = false;
		d->cached = NULL;
		d->qlen--;
		d->backlog -= item->len;
		if (d->transport_raw) {
			d->stats.handed++;
			d->stats.handed_bytes += item->len;
			d->stats.departures[item->bin]++;
			edma_diag_end(priv, EDMA_TIME_DDR_DECISION, started, item->len);
			edma_ddr_release(d, item, true); /* page already belongs to TX */
			spin_unlock_bh(&d->lock);
			done++;
			continue;
		}
		d->publishing++;
		edma_diag_end(priv, EDMA_TIME_DDR_DECISION, started, item->len);
		spin_unlock_bh(&d->lock);

		output_started = edma_diag_begin(priv, EDMA_TIME_DDR_OUTPUT);
		handed = edma_ddr_output(d, item, &result);
		edma_diag_end(priv, EDMA_TIME_DDR_OUTPUT, output_started, item->len);
		spin_lock_bh(&d->lock);
		if (!handed) {
			d->stats.alloc_failed++;
			d->stats.drops[item->bin]++;
		} else {
			d->stats.handed++;
			d->stats.handed_bytes += item->len;
			d->stats.departures[item->bin]++;
			if (net_xmit_eval(result))
				d->stats.handoff_error++;
		}
		edma_ddr_release(d, item, true);
		d->publishing--;
		spin_unlock_bh(&d->lock);
		done++;
	}
	return done;
}

static int edma_ddr_status(struct seq_file *seq, void *unused)
{
	static const char * const stage_names[EDMA_TIME_COUNT] = {
		"rx_sync_take", "rx_dispatch", "rx_fill", "compact_decision",
		"survivor_output", "tx_completion", "compact_recycle",
	};
	struct edma_ddr_diag *d = seq->private;
	struct edma_priv *priv = d->priv;
	struct edma_ddr_stats stats;
	struct edma_ddr_flow flows[EDMA_DDR_FLOWS];
	u32 i, qlen, backlog, memory, cached, publishing, maxpacket, invalid;
	u32 tx_hw_count = 0, completion_hw_count = 0;
	u32 tx_mod_timer = 0, tx_mod_control = 0, bql_inflight = 0;
	u64 clean_calls, clean_zero;
	struct netdev_queue *txq = netdev_get_tx_queue(priv->netdev, 0);
	int tx_read, completion_read, timer_read, control_read;
	s64 tokens;

	mutex_lock(&d->control);
	spin_lock_bh(&d->lock);
	stats = d->stats;
	memcpy(flows, d->flows, sizeof(flows));
	qlen = d->qlen;
	backlog = d->backlog;
	memory = d->memory;
	cached = !!d->cached;
	publishing = d->publishing;
	maxpacket = d->maxpacket;
	invalid = d->invalid;
	tokens = d->tokens;
	spin_unlock_bh(&d->lock);
	seq_printf(seq, "transport_raw=%u bounded_sync=%u pool_dma_dir=%u timing_every=%u due_guard=%u empty_bypass=%u service_first=%u\n",
		d->transport_raw, d->bounded_sync, page_pool_get_dma_dir(priv->page_pool),
		READ_ONCE(diag_timing_every), d->due_guard, d->empty_bypass, d->service_first);
	tx_read = regmap_read(priv->regmap,
		EDMA_REG_TXDESC_RING_SIZE(priv->soc->txdesc_ring), &tx_hw_count);
	completion_read = regmap_read(priv->regmap,
		EDMA_REG_TXCMPL_RING_SIZE(priv->soc->txcmpl_base, priv->soc->txcmpl_ring),
		&completion_hw_count);
	seq_printf(seq, "tx_entries_config=%u tx_entries_allocated=%u completion_entries_allocated=%u tx_entries_hardware=%u completion_entries_hardware=%u tx_size_read_error=%d completion_size_read_error=%d\n",
		diag_tx_entries, priv->txdesc_ring.count, priv->txcmpl_ring.count,
		tx_hw_count & EDMA_TXDESC_RING_SIZE_MASK,
		completion_hw_count & EDMA_TXDESC_RING_SIZE_MASK, tx_read, completion_read);
	seq_printf(seq, "native_ring_stops=%lld tx_ring_highwater=%u tx_drv_stopped=%u tx_stack_stopped=%u\n",
		(long long)atomic64_read(&priv->diag_native_ring_stops),
		READ_ONCE(priv->diag_tx_ring_highwater), netif_tx_queue_stopped(txq),
		test_bit(__QUEUE_STATE_STACK_XOFF, &txq->state));
	timer_read = regmap_read(priv->regmap,
		EDMA_REG_TX_MOD_TIMER(priv->soc->tx_int_base, priv->soc->txcmpl_ring),
		&tx_mod_timer);
	control_read = regmap_read(priv->regmap,
		EDMA_REG_TX_INT_CTRL(priv->soc->tx_int_base, priv->soc->txcmpl_ring),
		&tx_mod_control);
#ifdef CONFIG_BQL
	spin_lock_bh(&priv->completion_lock);
	bql_inflight = READ_ONCE(txq->dql.num_queued) - READ_ONCE(txq->dql.num_completed);
	spin_unlock_bh(&priv->completion_lock);
#endif
	seq_printf(seq, "tx_mod_config=%u tx_mod_register=%u tx_mod_raw=%u tx_mod_control=%u tx_mod_read_error=%d tx_mod_control_read_error=%d tx_mod_error=%d tx_mod_restore_error=%d tx_bql_inflight=%u native_ready=%u tx_admin=%u\n",
		priv->diag_tx_mod_timer, tx_mod_timer, tx_mod_timer & EDMA_TX_MOD_TIMER_MASK,
		tx_mod_control, timer_read, control_read, priv->diag_tx_mod_error,
		priv->diag_tx_mod_restore_error, bql_inflight,
		READ_ONCE(priv->native_ready), READ_ONCE(priv->tx_admin));
	clean_calls = READ_ONCE(priv->diag_tx_clean_calls);
	clean_zero = READ_ONCE(priv->diag_tx_clean_zero);
	seq_printf(seq, "tx_irq_handled=%lld tx_clean_calls=%llu tx_clean_zero=%llu tx_clean_nonzero=%llu tx_clean_entries=%llu tx_clean_max=%u\n",
		(long long)atomic64_read(&priv->diag_tx_irq_handled), clean_calls, clean_zero,
		clean_calls - min(clean_calls, clean_zero),
		READ_ONCE(priv->diag_tx_clean_entries), READ_ONCE(priv->diag_tx_clean_max));
	seq_printf(seq, "bypass_selected=%llu bypass_sent=%llu bypass_requeued=%llu\n",
		stats.bypass_selected, stats.bypass_sent, stats.bypass_requeued);
	seq_printf(seq, "raw_published=%lld raw_completed=%lld raw_inflight=%d raw_busy=%lld raw_error=%lld raw_aborted=%lld\n",
		(long long)atomic64_read(&priv->diag_raw_published),
		(long long)atomic64_read(&priv->diag_raw_completed),
		atomic_read(&priv->diag_raw_inflight),
		(long long)atomic64_read(&priv->diag_raw_busy),
		(long long)atomic64_read(&priv->diag_raw_error),
		(long long)atomic64_read(&priv->diag_raw_aborted));
	seq_printf(seq, "native_tx_busy=%lld native_tx_drop=%lld timer_fired=%lld service_due_skipped=%llu\n",
		(long long)atomic64_read(&priv->diag_native_tx_busy),
		(long long)atomic64_read(&priv->diag_native_tx_drop),
		(long long)atomic64_read(&d->timer_fired), stats.service_due_skipped);
	seq_printf(seq, "service_entry_calls=%llu service_arrival_probes=%llu service_arrival_early=%llu service_arrival_calls=%llu service_tail_calls=%llu\n",
		stats.service_entry_calls, stats.service_arrival_probes,
		stats.service_arrival_early, stats.service_arrival_calls, stats.service_tail_calls);
	seq_printf(seq, "deadline_count=%llu deadline_sum_ns=%llu deadline_max_ns=%llu deadline_busy_count=%llu deadline_busy_sum_ns=%llu deadline_busy_max_ns=%llu ready_without_wait=%llu\n",
		stats.deadline_count, stats.deadline_sum_ns, stats.deadline_max_ns,
		stats.deadline_busy_count, stats.deadline_busy_sum_ns,
		stats.deadline_busy_max_ns, stats.ready_without_wait);
	for (i = 0; i < EDMA_TIME_COUNT; i++) {
		const struct edma_diag_time *t = &priv->diag_time[i];

		seq_printf(seq, "stage=%s calls=%llu samples=%llu units=%llu sampled_units=%llu total_ns=%llu max_ns=%llu\n",
			stage_names[i], READ_ONCE(t->calls), READ_ONCE(t->samples),
			READ_ONCE(t->units), READ_ONCE(t->sampled_units),
			READ_ONCE(t->total_ns), READ_ONCE(t->max_ns));
	}
	seq_printf(seq, "active=%u mode=%u qlen=%u backlog=%u memory=%u cached=%u publishing=%u maxpacket=%u invalid=%u\n",
		d->active, d->mode, qlen, backlog, memory, cached, publishing,
		maxpacket, invalid);
	seq_printf(seq, "rate_bps=%llu burst=%u buffer_ns=%lld tokens_ns=%lld limit=%u memory_limit=%u quantum=%u drop_batch=%u overhead=%u mpu=%u\n",
		d->rate_bps, d->burst, d->buffer, tokens, d->limit,
		d->memory_limit, d->quantum, d->drop_batch, d->rate.overhead,
		d->rate.mpu);
	seq_printf(seq, "target_us=%u interval_us=%u ecn=%u mtu=%u page_order=%u napi_active=%u\n",
		codel_time_to_us(d->cparams.target),
		codel_time_to_us(d->cparams.interval), d->cparams.ecn,
		d->cparams.mtu, d->priv->rx_page_order,
		READ_ONCE(d->priv->napi_active));
	seq_puts(seq, "source=lan3/3 target=lan2/4 conduit=eth0 source_ip=192.168.1.144 destination_ip=192.168.1.115 udp_source=any destination_ports=45987-45990 bins=0-3 ce_threshold=disabled\n");
	seq_printf(seq, "seen=%llu seen_bytes=%llu enqueued=%llu overlimit=%llu overmemory=%llu aqm_drop=%llu ecn_mark=%llu oversize=%llu record_refused=%llu alloc_failed=%llu shape_refused=%llu\n",
		stats.seen, stats.seen_bytes, stats.enqueued, stats.overlimit,
		stats.overmemory, stats.aqm_drop, stats.ecn_mark, stats.oversize,
		stats.record_refused, stats.alloc_failed, stats.shape_refused);
	seq_printf(seq, "handed=%llu handed_bytes=%llu handoff_error=%llu tbf_waits=%llu aborted_by_driver=%llu\n",
		stats.handed, stats.handed_bytes, stats.handoff_error,
		stats.waits, stats.aborted);
	for (i = 0; i < EDMA_DDR_FLOWS; i++)
		seq_printf(seq, "bin%u arrivals=%llu handed=%llu drops=%llu marks=%llu queued_bytes=%u deficit=%d codel_count=%u dropping=%u ldelay_us=%u\n",
			i, stats.arrivals[i], stats.departures[i], stats.drops[i],
			stats.marks[i], flows[i].bytes, flows[i].deficit,
			flows[i].codel.count, flows[i].codel.dropping,
			codel_time_to_us(flows[i].codel.ldelay));
	mutex_unlock(&d->control);
	return 0;
}

static int edma_ddr_open(struct inode *inode, struct file *file)
{
	return single_open(file, edma_ddr_status, pde_data(inode));
}

/* RTNL + control mutex; no packet record survives a successful stop. */
static int edma_ddr_stop(struct edma_ddr_diag *d)
{
	spin_lock_bh(&d->lock);
	if (d->qlen || d->publishing || atomic_read(&d->priv->diag_raw_inflight)) {
		spin_unlock_bh(&d->lock);
		return -EBUSY;
	}
	d->active = false;
	d->head_due = 0;
	d->head_had_busy = false;
	WRITE_ONCE(d->due_time, 0);
	spin_unlock_bh(&d->lock);
	hrtimer_cancel(&d->timer);
	if (d->target_root) {
		qdisc_put(d->target_root);
		d->target_root = NULL;
	}
	if (d->conduit_root) {
		qdisc_put(d->conduit_root);
		d->conduit_root = NULL;
	}
	if (d->source) {
		dev_put(d->source);
		d->source = NULL;
	}
	if (d->target) {
		dev_put(d->target);
		d->target = NULL;
	}
	return 0;
}

static ssize_t edma_ddr_write(struct file *file, const char __user *user,
			      size_t count, loff_t *position)
{
	struct edma_ddr_diag *d = pde_data(file_inode(file));
	struct net_device *source = NULL, *target = NULL;
	struct edma_ddr_item *items = NULL;
	struct tc_ratespec spec = {};
	struct psched_ratecfg rate = {};
	struct dsa_port *source_port, *target_port;
	struct Qdisc *qdisc, *conduit_root;
	unsigned long long rate_bps;
	u32 mode, burst, limit, memory, quantum, batch, target_us, interval_us;
	u32 ecn, overhead, mpu, i, raw, narrow, every, guard;
	char input[256], *command;
	int used = 0, ret = 0;

	if (!count || count >= sizeof(input))
		return -EINVAL;
	if (copy_from_user(input, user, count))
		return -EFAULT;
	input[count] = 0;
	command = strim(input);
	rtnl_lock();
	mutex_lock(&d->control);
	if (!strcmp(command, "stop")) {
		ret = edma_ddr_stop(d);
		goto out;
	}
	if (!strncmp(command, "transport ", 10)) {
		if (sscanf(command, "transport %u %u %n", &raw, &narrow, &used) != 2 ||
		    command[used] || raw > 1 || narrow > 1) {
			ret = -EINVAL;
			goto out;
		}
		if (READ_ONCE(d->active) || atomic_read(&d->priv->diag_raw_inflight)) {
			ret = -EBUSY;
			goto out;
		}
		if (raw && page_pool_get_dma_dir(d->priv->page_pool) != DMA_BIDIRECTIONAL) {
			ret = -EOPNOTSUPP;
			goto out;
		}
		d->transport_raw = raw;
		d->bounded_sync = narrow;
		goto out;
	}
	if (!strncmp(command, "timing ", 7)) {
		if (sscanf(command, "timing %u %n", &every, &used) != 1 || command[used] ||
		    (every && (!is_power_of_2(every) || every > BIT(20)))) {
			ret = -EINVAL;
			goto out;
		}
		if (READ_ONCE(d->active) || atomic_read(&d->priv->diag_raw_inflight)) {
			ret = -EBUSY;
			goto out;
		}
		WRITE_ONCE(diag_timing_every, every);
		goto out;
	}
	if (!strncmp(command, "due_guard ", 10)) {
		if (sscanf(command, "due_guard %u %n", &guard, &used) != 1 ||
		    command[used] || guard > 1) {
			ret = -EINVAL;
			goto out;
		}
		if (READ_ONCE(d->active) || atomic_read(&d->priv->diag_raw_inflight)) {
			ret = -EBUSY;
			goto out;
		}
		d->due_guard = guard;
		goto out;
	}
	if (!strncmp(command, "empty_bypass ", 13)) {
		if (sscanf(command, "empty_bypass %u %n", &guard, &used) != 1 ||
		    command[used] || guard > 1) {
			ret = -EINVAL;
			goto out;
		}
		if (READ_ONCE(d->active) || atomic_read(&d->priv->diag_raw_inflight)) {
			ret = -EBUSY;
			goto out;
		}
		d->empty_bypass = guard;
		goto out;
	}
	if (!strncmp(command, "service_first ", 14)) {
		if (sscanf(command, "service_first %u %n", &guard, &used) != 1 ||
		    command[used] || guard > 1) {
			ret = -EINVAL;
			goto out;
		}
		if (READ_ONCE(d->active) || atomic_read(&d->priv->diag_raw_inflight)) {
			ret = -EBUSY;
			goto out;
		}
		d->service_first = guard;
		goto out;
	}
	if (!strncmp(command, "tx_moderation ", 14)) {
		if (sscanf(command, "tx_moderation %u %n", &raw, &used) != 1 ||
		    command[used] || !raw || raw > EDMA_TX_MOD_TIMER_MASK) {
			ret = -EINVAL;
			goto out;
		}
		if (READ_ONCE(d->active) || d->qlen || d->cached || d->publishing ||
		    atomic_read(&d->priv->diag_raw_inflight)) {
			ret = -EBUSY;
			goto out;
		}
		ret = edma_diag_tx_moderation(d->priv, raw);
		goto out;
	}
	if (!strcmp(command, "reset_stats")) {
		if (READ_ONCE(d->active) || atomic_read(&d->priv->diag_raw_inflight)) {
			ret = -EBUSY;
			goto out;
		}
		edma_diag_reset(d->priv);
		memset(&d->stats, 0, sizeof(d->stats));
		atomic64_set(&d->timer_fired, 0);
		goto out;
	}
	if (sscanf(command, "start %u %llu %u %u %u %u %u %u %u %u %u %u %n",
		   &mode, &rate_bps, &burst, &limit, &memory, &quantum, &batch,
		   &target_us, &interval_us, &ecn, &overhead, &mpu, &used) != 12 ||
	    command[used] || mode < EDMA_DDR_FIFO || mode > EDMA_DDR_FQ_CODEL ||
	    !limit || limit > EDMA_DDR_MAX_LIMIT || !memory ||
	    !quantum || quantum > 65536 || !batch || batch > EDMA_DDR_MAX_LIMIT ||
	    !target_us || target_us > 10000000 || !interval_us ||
	    interval_us > 10000000 || ecn > 1 || overhead > 256 || mpu > 65535 ||
	    rate_bps > 10000000000ULL || (rate_bps && (rate_bps < 8 || rate_bps % 8 ||
	    !burst || burst > 1048576))) {
		ret = -EINVAL;
		goto out;
	}
	if (READ_ONCE(d->active)) {
		ret = -EBUSY;
		goto out;
	}
	if (d->transport_raw && (!d->priv->shared || !d->priv->qdx ||
	    d->priv->soc->txdesc_ring != 23 || d->priv->soc->txcmpl_ring != 7 ||
	    page_pool_get_dma_dir(d->priv->page_pool) != DMA_BIDIRECTIONAL)) {
		ret = -EOPNOTSUPP;
		goto out;
	}
	if (!d->priv->native_ready || !d->priv->napi_active ||
	    strcmp(d->priv->netdev->name, "eth0")) {
		ret = -ENETDOWN;
		goto out;
	}
	source = dev_get_by_name(&init_net, "lan3");
	target = dev_get_by_name(&init_net, "lan2");
	if (!source || !target) {
		ret = -ENODEV;
		goto out;
	}
	source_port = dsa_port_from_netdev(source);
	target_port = dsa_port_from_netdev(target);
	if (IS_ERR(source_port) || IS_ERR(target_port) ||
	    source_port->index != 3 || target_port->index != 4 ||
	    dsa_port_to_conduit(source_port) != d->priv->netdev ||
	    dsa_port_to_conduit(target_port) != d->priv->netdev ||
	    !netif_running(source) || !netif_carrier_ok(source) ||
	    !netif_running(target) || !netif_carrier_ok(target) ||
	    (target->features & NETIF_F_HW_TC)) {
		ret = -EINVAL;
		goto out;
	}
	conduit_root = rtnl_dereference(d->priv->netdev->qdisc);
	if ((strcmp(conduit_root->ops->id, "fq_codel") &&
	     strcmp(conduit_root->ops->id, "noqueue")) ||
	    (d->transport_raw && strcmp(conduit_root->ops->id, "noqueue"))) {
		ret = -EOPNOTSUPP;
		goto out;
	}
	qdisc = rtnl_dereference(target->qdisc);
	if (d->empty_bypass && (!d->transport_raw || rate_bps ||
	    !(qdisc->flags & TCQ_F_CAN_BYPASS) ||
	    (mode != EDMA_DDR_CODEL && mode != EDMA_DDR_FQ_CODEL) ||
	    (mode == EDMA_DDR_CODEL && strcmp(qdisc->ops->id, "codel")) ||
	    (mode == EDMA_DDR_FQ_CODEL && strcmp(qdisc->ops->id, "fq_codel")))) {
		ret = -EOPNOTSUPP;
		goto out;
	}
	items = kcalloc(limit + 2, sizeof(*items), GFP_KERNEL);
	if (!items) {
		ret = -ENOMEM;
		goto out;
	}
	if (rate_bps) {
		spec.rate = min_t(u64, rate_bps / 8, U32_MAX);
		spec.linklayer = TC_LINKLAYER_ETHERNET;
		spec.overhead = overhead;
		spec.mpu = mpu;
		psched_ratecfg_precompute(&rate, &spec, rate_bps / 8);
	}
	qdisc_refcount_inc(qdisc);
	qdisc_refcount_inc(conduit_root);
	spin_lock_bh(&d->lock);
	kfree(d->items);
	d->items = items;
	items = NULL;
	d->free = NULL;
	for (i = 0; i < limit + 2; i++) {
		d->items[i].next = d->free;
		d->free = &d->items[i];
	}
	memset(&d->stats, 0, sizeof(d->stats));
	memset(d->flows, 0, sizeof(d->flows));
	INIT_LIST_HEAD(&d->new_flows);
	INIT_LIST_HEAD(&d->old_flows);
	for (i = 0; i < EDMA_DDR_FLOWS; i++)
		INIT_LIST_HEAD(&d->flows[i].active);
	d->cached = NULL;
	d->qlen = d->backlog = d->memory = d->publishing = d->maxpacket = 0;
	d->mode = mode;
	d->limit = limit;
	d->memory_limit = memory;
	d->quantum = quantum;
	d->drop_batch = batch;
	d->burst = burst;
	d->rate = rate;
	d->rate_bps = rate_bps;
	d->buffer = rate_bps ? psched_l2t_ns(&rate, burst) : 0;
	d->tokens = d->buffer;
	d->token_time = ktime_get_ns();
	d->head_due = 0;
	d->head_had_busy = false;
	WRITE_ONCE(d->due_time, 0);
	atomic64_set(&d->timer_fired, 0);
	d->cparams = (struct codel_params) {
		.target = ((u64)target_us * NSEC_PER_USEC) >> CODEL_SHIFT,
		.interval = ((u64)interval_us * NSEC_PER_USEC) >> CODEL_SHIFT,
		.mtu = psched_mtu(target), .ecn = ecn,
		.ce_threshold = CODEL_DISABLED_THRESHOLD,
	};
	d->source = source;
	d->target = target;
	d->target_root = qdisc;
	d->conduit_root = conduit_root;
	d->target_mtu = target->mtu;
	d->invalid = 0;
	d->active = true;
	spin_unlock_bh(&d->lock);
	source = target = NULL;
out:
	kfree(items);
	if (source)
		dev_put(source);
	if (target)
		dev_put(target);
	mutex_unlock(&d->control);
	rtnl_unlock();
	return ret ? ret : count;
}

static const struct proc_ops edma_ddr_proc_ops = {
	.proc_open = edma_ddr_open,
	.proc_read = seq_read,
	.proc_write = edma_ddr_write,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static int edma_ddr_init(struct edma_priv *priv)
{
	struct edma_ddr_diag *d;

	d = kzalloc(sizeof(*d), GFP_KERNEL);
	if (!d)
		return -ENOMEM;
	d->priv = priv;
	spin_lock_init(&d->lock);
	mutex_init(&d->control);
	hrtimer_setup(&d->timer, edma_ddr_timer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS);
	d->proc = proc_create_data("qdx_edma_ddr", 0600, NULL, &edma_ddr_proc_ops, d);
	if (!d->proc) {
		kfree(d);
		return -ENOMEM;
	}
	priv->ddr_diag = d;
	return 0;
}

/* RTNL held, NAPI stopped. Only real driver reset/removal calls this. */
static void edma_ddr_purge(struct edma_priv *priv)
{
	struct edma_ddr_diag *d = priv->ddr_diag;
	u32 i;

	if (!d)
		return;
	hrtimer_cancel(&d->timer);
	mutex_lock(&d->control);
	spin_lock_bh(&d->lock);
	d->active = false;
	for (i = 0; d->items && i < d->limit + 2; i++) {
		if (d->items[i].page) {
			d->stats.aborted++;
			page_pool_put_full_page(priv->page_pool, d->items[i].page, false);
			d->items[i].page = NULL;
		}
	}
	d->cached = NULL;
	d->qlen = d->backlog = d->memory = d->publishing = 0;
	memset(d->flows, 0, sizeof(d->flows));
	spin_unlock_bh(&d->lock);
	/* The caller holds RTNL, including qdisc reference destruction. */
	edma_ddr_stop(d);
	mutex_unlock(&d->control);
}

static void edma_ddr_remove(struct edma_priv *priv)
{
	struct edma_ddr_diag *d = priv->ddr_diag;

	if (!d)
		return;
	if (d->proc) {
		proc_remove(d->proc);
		d->proc = NULL;
	}
}

static void edma_ddr_destroy(struct edma_priv *priv)
{
	struct edma_ddr_diag *d = priv->ddr_diag;

	if (!d)
		return;
	/* proc users have ended; caller already stopped NAPI and purged. */
	WARN_ON(d->proc || d->active || d->source || d->target || d->publishing ||
		atomic_read(&priv->diag_raw_inflight));
	priv->ddr_diag = NULL;
	kfree(d->items);
	kfree(d);
}

#endif /* QCA_EDMA_DDR_DIAG_H */
