// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2016-2021, The Linux Foundation. All rights reserved.
 * Copyright (c) 2023-2024, Qualcomm Innovation Center, Inc. All rights reserved.
 */

#include <linux/clk.h>
#include <linux/ethtool.h>
#include <linux/if_vlan.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_net.h>
#include <linux/of_platform.h>
#include <linux/property.h>
#include <linux/regmap.h>
#include <linux/reset.h>
#include <linux/qdx/flow.h>
#include <linux/refcount.h>
#include <linux/rtnetlink.h>
#include <linux/version.h>
#include <net/netfilter/nf_flow_table.h>
#include <net/pkt_cls.h>
#include "qca_edma.h"

static void edma_tx_retry(void *context);
static void edma_txdesc_drain(struct edma_priv *priv, struct edma_ring *ring);

static void edma_irq_disable_all(struct edma_priv *priv)
{
	const struct edma_soc_data *soc = priv->soc;
	int i;

	for (i = 0; i <= soc->txdesc_ring; i++)
		regmap_write(priv->regmap,
			     EDMA_REG_TX_INT_MASK(soc->tx_int_base, i),
			     0);

	for (i = 0; i <= soc->rxfill_ring; i++)
		regmap_write(priv->regmap, EDMA_REG_RXFILL_INT_MASK(i), 0);

	for (i = 0; i <= soc->rxdesc_ring; i++) {
		regmap_write(priv->regmap, EDMA_REG_RXDESC_INT_MASK(i), 0);
		regmap_write(priv->regmap, EDMA_REG_RX_INT_CTRL(i), 0);
	}
}

static void edma_tx_irq_mask(struct edma_priv *priv)
{
	const struct edma_soc_data *soc = priv->soc;

	regmap_write(priv->regmap,
		     EDMA_REG_TX_INT_MASK(soc->tx_int_base, soc->txcmpl_ring),
		     0);
}

static void edma_tx_irq_unmask(struct edma_priv *priv)
{
	const struct edma_soc_data *soc = priv->soc;

	regmap_write(priv->regmap,
		     EDMA_REG_TX_INT_MASK(soc->tx_int_base, soc->txcmpl_ring),
		     EDMA_TX_INT_MASK);
}

static void edma_rx_irq_mask(struct edma_priv *priv)
{
	const struct edma_soc_data *soc = priv->soc;

	regmap_write(priv->regmap,
		     EDMA_REG_RXFILL_INT_MASK(soc->rxfill_ring), 0);
	regmap_write(priv->regmap,
		     EDMA_REG_RXDESC_INT_MASK(soc->rxdesc_ring), 0);
}

static void edma_rx_irq_unmask(struct edma_priv *priv)
{
	const struct edma_soc_data *soc = priv->soc;

	regmap_write(priv->regmap,
		     EDMA_REG_RXFILL_INT_MASK(soc->rxfill_ring),
		     EDMA_RXFILL_INT_MASK);
	regmap_write(priv->regmap,
		     EDMA_REG_RXDESC_INT_MASK(soc->rxdesc_ring),
		     EDMA_RXDESC_INT_MASK_PKT_INT);
}

static irqreturn_t edma_tx_irq_handle(int irq, void *ctx)
{
	const struct edma_soc_data *soc;
	struct edma_priv *priv = ctx;
	u32 val;

	soc = priv->soc;

	regmap_read(priv->regmap,
		    EDMA_REG_TX_INT_STAT(soc->tx_int_base,
					 soc->txcmpl_ring), &val);
	if (!val)
		return IRQ_NONE;

	edma_tx_irq_mask(priv);

	if (likely(napi_schedule_prep(&priv->tx_napi)))
		__napi_schedule(&priv->tx_napi);

	return IRQ_HANDLED;
}

static irqreturn_t edma_rx_irq_handle(int irq, void *ctx)
{
	const struct edma_soc_data *soc;
	struct edma_priv *priv = ctx;
	u32 val, status = 0;

	soc = priv->soc;

	regmap_read(priv->regmap,
		    EDMA_REG_RXDESC_INT_STAT(soc->rxdesc_ring),
		    &val);
	status |= val;
	regmap_read(priv->regmap,
		    EDMA_REG_RXFILL_INT_STAT(soc->rxfill_ring),
		    &val);
	status |= val;

	if (!status)
		return IRQ_NONE;

	edma_rx_irq_mask(priv);

	if (likely(napi_schedule_prep(&priv->rx_napi)))
		__napi_schedule(&priv->rx_napi);

	return IRQ_HANDLED;
}

static irqreturn_t edma_misc_irq_handle(int irq, void *ctx)
{
	struct edma_priv *priv = ctx;
	u32 val;

	regmap_read(priv->regmap, EDMA_REG_MISC_INT_STAT, &val);
	if (!val)
		return IRQ_NONE;

	return IRQ_HANDLED;
}

static int edma_ring_alloc(struct edma_priv *priv, struct edma_ring *ring, int count,
			   int desc_size)
{
	struct device *dev = &priv->pdev->dev;

	ring->count = count;
	ring->desc = dma_alloc_coherent(dev, count * desc_size, &ring->dma,
					GFP_KERNEL);
	if (!ring->desc)
		return -ENOMEM;

	return 0;
}

static int edma_tx_ring_alloc(struct edma_priv *priv, struct edma_ring *ring,
			      int count, int desc_size)
{
	int ret;

	ret = edma_ring_alloc(priv, ring, count, desc_size);
	if (ret)
		return ret;

	ring->tx = kcalloc(count, sizeof(*ring->tx), GFP_KERNEL);
	if (!ring->tx) {
		dma_free_coherent(&priv->pdev->dev, count * desc_size,
				  ring->desc, ring->dma);
		ring->desc = NULL;
		return -ENOMEM;
	}

	return 0;
}

static int edma_rx_ring_alloc(struct edma_priv *priv, struct edma_ring *ring,
			      int count, int desc_size)
{
	int ret;

	ret = edma_ring_alloc(priv, ring, count, desc_size);
	if (ret)
		return ret;

	ring->page_store = kcalloc(count, sizeof(*ring->page_store),
				   GFP_KERNEL);
	if (!ring->page_store) {
		dma_free_coherent(&priv->pdev->dev, count * desc_size,
				  ring->desc, ring->dma);
		ring->desc = NULL;
		return -ENOMEM;
	}

	return 0;
}

static void edma_ring_free(struct edma_priv *priv, struct edma_ring *ring,
			   int desc_size)
{
	if (ring->desc) {
		dma_free_coherent(&priv->pdev->dev, ring->count * desc_size,
				  ring->desc, ring->dma);
		ring->desc = NULL;
	}
}

static void edma_tx_ring_free(struct edma_priv *priv, struct edma_ring *ring,
			      int desc_size)
{
	edma_txdesc_drain(priv, ring);
	kfree(ring->tx);
	ring->tx = NULL;

	edma_ring_free(priv, ring, desc_size);
}

static int edma_rx_fill(struct edma_priv *priv, struct edma_ring *rxfill_ring)
{
	const struct edma_soc_data *soc = priv->soc;
	struct edma_rxfill_desc *rxfill_desc;
	struct edma_rx_preheader *rxph;
	u16 prod, cons, next;
	struct page *page;
	u16 filled = 0;
	dma_addr_t dma;
	u32 val;

	regmap_read(priv->regmap, EDMA_REG_RXFILL_PROD_IDX(soc->rxfill_ring),
		    &val);
	prod = val & EDMA_RXFILL_PROD_IDX_MASK & (rxfill_ring->count - 1);

	regmap_read(priv->regmap, EDMA_REG_RXFILL_CONS_IDX(soc->rxfill_ring),
		    &val);
	cons = val & EDMA_RXFILL_CONS_IDX_MASK & (rxfill_ring->count - 1);

	while (1) {
		next = prod + 1;
		if (next == rxfill_ring->count)
			next = 0;

		if (next == cons)
			break;
		/* The page may still be prefetched inside EDMA. */
		if (unlikely(rxfill_ring->page_store[prod]))
			break;

		page = page_pool_dev_alloc_pages(priv->page_pool);
		if (unlikely(!page))
			break;

		rxfill_desc = EDMA_RXFILL_DESC(rxfill_ring, prod);

		dma = page_pool_get_dma_addr(page) + NET_SKB_PAD;
		rxph = page_address(page) + NET_SKB_PAD;
		rxph->opaque = cpu_to_le32(prod);
		dma_sync_single_for_device(&priv->pdev->dev, dma,
					   sizeof(rxph->opaque), DMA_FROM_DEVICE);
		rxfill_ring->page_store[prod] = page;
		rxfill_desc->buffer_addr = cpu_to_le32(dma);
		rxfill_desc->word1 = cpu_to_le32(priv->rx_buffer_size &
						 EDMA_RXFILL_BUF_SIZE_MASK);

		filled++;
		prod = next;
	}

	if (filled) {
		wmb();
		regmap_write(priv->regmap,
			     EDMA_REG_RXFILL_PROD_IDX(soc->rxfill_ring),
			     prod & EDMA_RXFILL_PROD_IDX_MASK);
	}

	return filled;
}

static bool edma_rx_page_take(struct edma_priv *priv, struct page *page,
			      u32 store_idx)
{
	struct edma_ring *ring = &priv->rxfill_ring;
	int i;

	if (likely(store_idx < ring->count &&
		   ring->page_store[store_idx] == page)) {
		ring->page_store[store_idx] = NULL;
		return true;
	}

	for (i = 0; i < ring->count; i++) {
		if (ring->page_store[i] != page)
			continue;

		ring->page_store[i] = NULL;
		dev_warn_ratelimited(&priv->pdev->dev,
				     "rx page has invalid store index %u, expected %d\n",
				     store_idx, i);
		return true;
	}

	/* The page may already belong to an skb, so it cannot be freed safely. */
	dev_warn_ratelimited(&priv->pdev->dev,
			     "rx page with store index %u is not tracked\n",
			     store_idx);
	return false;
}

/* Native and firmware returns share one completion side of conduit BQL. */
static void edma_tx_complete(void *context, struct netdev_queue *queue,
			     unsigned int packets,
			     unsigned int bytes)
{
	struct edma_priv *priv = context;

	spin_lock_bh(&priv->completion_lock);
	if (packets)
		netdev_tx_completed_queue(queue, packets, bytes);
	spin_unlock_bh(&priv->completion_lock);
	edma_tx_retry(priv);
}

static u32 edma_clean_tx(struct edma_priv *priv, struct edma_ring *txcmpl_ring,
			 int budget)
{
	const struct edma_soc_data *soc = priv->soc;
	struct platform_device *pdev = priv->pdev;
	struct edma_txcmpl *txcmpl;
	u32 cleaned = 0, packets = 0, bytes = 0;
	u16 prod, cons;
	struct edma_tx_slot slot;
	struct netdev_queue *queue = NULL;
	u32 val, idx;

	regmap_read(priv->regmap,
		    EDMA_REG_TXCMPL_PROD_IDX(soc->txcmpl_base,
					     soc->txcmpl_ring),
		    &val);
	prod = val & EDMA_TXCMPL_PROD_IDX_MASK;

	regmap_read(priv->regmap,
		    EDMA_REG_TXCMPL_CONS_IDX(soc->txcmpl_base,
					     soc->txcmpl_ring),
		    &val);
	cons = val & EDMA_TXCMPL_CONS_IDX_MASK;
	/* Observe descriptor contents after the device's producer publication. */
	dma_rmb();

	while (cons != prod && cleaned < budget) {
		txcmpl = EDMA_TXCMPL_DESC(txcmpl_ring, cons);

		idx = le32_to_cpu(txcmpl->buffer_addr);
		if (unlikely(idx >= priv->txdesc_ring.count)) {
			netdev_warn(priv->netdev, "invalid TX completion index %u\n", idx);
			goto next;
		}
		spin_lock_bh(&priv->tx_lock);
		slot = priv->txdesc_ring.tx[idx];
		memset(&priv->txdesc_ring.tx[idx], 0, sizeof(slot));
		spin_unlock_bh(&priv->tx_lock);

		if (unlikely(!slot.skb)) {
			dev_warn(&pdev->dev,
				 "invalid skb: cons:%u prod:%u status %x\n",
				 cons, prod, txcmpl->status);
			goto next;
		}

		dma_unmap_single(&pdev->dev, slot.dma, slot.mapped, DMA_TO_DEVICE);
		if (queue && queue != slot.queue) {
			edma_tx_complete(priv, queue, packets, bytes);
			packets = 0;
			bytes = 0;
		}
		queue = slot.queue;
		packets++;
		bytes += slot.bytes;
		napi_consume_skb(slot.skb, budget);

next:
		if (++cons == txcmpl_ring->count)
			cons = 0;

		cleaned++;
	}

	if (cleaned == 0)
		return 0;

	/* Ensure all TX completions are processed before updating cons idx */
	wmb();
	regmap_write(priv->regmap,
		     EDMA_REG_TXCMPL_CONS_IDX(soc->txcmpl_base,
					      soc->txcmpl_ring),
			     cons);
	edma_tx_complete(priv, queue, packets, bytes);

	return cleaned;
}

static void edma_receive(void *context, unsigned int port, struct sk_buff *skb,
			 struct napi_struct *napi)
{
	struct edma_priv *priv = context;
	struct dsa_oob_tag_info *tag;
	unsigned int len = skb->len;

	tag = skb_ext_add(skb, SKB_EXT_DSA_OOB);
	if (!tag) {
		priv->netdev->stats.rx_dropped++;
		dev_kfree_skb_any(skb);
		return;
	}
	*tag = (struct dsa_oob_tag_info) { .port = port };
	skb->protocol = eth_type_trans(skb, priv->netdev);
	dev_sw_netstats_rx_add(priv->netdev, len);
	napi_gro_receive(napi, skb);
}

static u32 edma_clean_rx(struct edma_priv *priv, int budget,
			 struct edma_ring *rxdesc_ring)
{
	const struct edma_soc_data *soc = priv->soc;
	struct platform_device *pdev = priv->pdev;
	struct edma_rx_preheader *rxph;
	struct edma_rxdesc *rxdesc;
	struct sk_buff *skb;
	u16 prod, cons;
	struct page *page;
	u32 done = 0;
	u32 src_port;
	int pkt_len;
	u32 val;

	regmap_read(priv->regmap, EDMA_REG_RXDESC_PROD_IDX(soc->rxdesc_ring),
		    &val);
	prod = val & EDMA_RXDESC_PROD_IDX_MASK;

	regmap_read(priv->regmap, EDMA_REG_RXDESC_CONS_IDX(soc->rxdesc_ring),
		    &val);
	cons = val & EDMA_RXDESC_CONS_IDX_MASK;

	while (cons != prod && done < budget) {
		u32 desc_addr, desc_status;
		u32 store_idx;

		rxdesc = EDMA_RXDESC_DESC(rxdesc_ring, cons);
		desc_addr = le32_to_cpu(rxdesc->buffer_addr);
		desc_status = le32_to_cpu(rxdesc->status);
		rxph = phys_to_virt(desc_addr);
		page = virt_to_head_page(rxph);

		pkt_len = desc_status & EDMA_RXDESC_PACKET_LEN_MASK;

		page_pool_dma_sync_for_cpu(priv->page_pool, page, 0,
					   EDMA_RX_PREHDR_SIZE + pkt_len);
		store_idx = le32_to_cpu(rxph->opaque);
		if (unlikely(!edma_rx_page_take(priv, page, store_idx)))
			goto next;

		if (EDMA_RXPH_SRC_INFO_TYPE_GET(rxph) !=
		    EDMA_PREHDR_DSTINFO_PORTID_IND) {
			dev_warn_ratelimited(&pdev->dev,
					     "rx drop: src_info_type=%#x src_info=%#06x dst_info=%#06x\n",
					     EDMA_RXPH_SRC_INFO_TYPE_GET(rxph),
					     le16_to_cpu(rxph->src_info),
					     le16_to_cpu(rxph->dst_info));
			page_pool_put_full_page(priv->page_pool, page, true);
			goto next;
		}

		src_port = rxph->src_info & EDMA_SRC_PORT_MASK;

		skb = napi_build_skb(page_address(page), page_size(page));
		if (unlikely(!skb)) {
			page_pool_put_full_page(priv->page_pool, page, true);
			goto next;
		}

		skb_mark_for_recycle(skb);
		skb_reserve(skb, NET_SKB_PAD + EDMA_RX_PREHDR_SIZE);
		skb_put(skb, pkt_len);

		edma_receive(priv, src_port, skb, &priv->rx_napi);

next:
		if (++cons == rxdesc_ring->count)
			cons = 0;

		done++;
	}

	edma_rx_fill(priv, &priv->rxfill_ring);

	wmb();
	regmap_write(priv->regmap,
		     EDMA_REG_RXDESC_CONS_IDX(soc->rxdesc_ring),
		     cons);
	return done;
}

/* completion_lock is the sole conduit TX-state lock. Native publication takes
 * tx_lock below it; PPE selection publication crosses it through tx_gate.
 */
static bool edma_native_tx_ready(struct edma_priv *priv, u16 slots)
{
	const struct edma_soc_data *soc = priv->soc;
	u32 prod, cons;
	int ret;

	spin_lock(&priv->tx_lock);
	ret = regmap_read(priv->regmap,
			  EDMA_REG_TXDESC_PROD_IDX(soc->txdesc_ring), &prod);
	if (ret)
		goto out;
	ret = regmap_read(priv->regmap,
			  EDMA_REG_TXDESC_CONS_IDX(soc->txdesc_ring), &cons);
	if (ret)
		goto out;
	prod &= EDMA_TXDESC_PROD_IDX_MASK;
	cons &= EDMA_TXDESC_CONS_IDX_MASK;
	if (prod >= priv->txdesc_ring.count || cons >= priv->txdesc_ring.count) {
		ret = -EIO;
		goto out;
	}
	ret = ((cons - prod - 1) & (priv->txdesc_ring.count - 1)) >= slots &&
	      !priv->txdesc_ring.tx[prod].skb;
out:
	spin_unlock(&priv->tx_lock);
	return ret > 0;
}

static bool edma_tx_can_run_locked(struct edma_priv *priv,
				   struct qdx_tx_selection *selection)
{
	struct edma_tx_wait *wait = &priv->wait;
	struct qdx_ready ready;

	if (!priv->tx_admin || priv->detaching || priv->tx_transitions ||
	    !READ_ONCE(priv->native_ready) || !priv->napi_active ||
	    !netif_running(priv->netdev) ||
	    !netif_carrier_ok(priv->netdev))
		return false;
	if (wait->reason == EDMA_TX_WAIT_NONE)
		return true;
	selection->status = QDX_TX_NATIVE;
	if (wait->tagged)
		qdx_edma_resolve(priv->qdx, wait->port, wait->user_queue,
				 wait->token, wait->disposition, selection);
	if (selection->status == QDX_TX_HELD)
		return false;
	if (selection->status == QDX_TX_RETIRED ||
	    selection->status == QDX_TX_REFUSED)
		return true; /* Let ndo_xmit consume this permanently refused packet. */
	if (selection->status == QDX_TX_READY) {
		ready = qdx_tx_ready(selection->path, wait->charge);
		if (ready.status == QDX_CLOSED)
			return false;
		if (wait->reason == EDMA_TX_WAIT_DISPOSITION)
			return true;
		return ready.status == QDX_ACCEPTED || ready.status == QDX_REFUSED;
	}
	if (wait->reason == EDMA_TX_WAIT_DISPOSITION)
		return true;
	/* A real native handback makes an old firmware-resource wait irrelevant. */
	if (wait->status != QDX_TX_NATIVE)
		return true;
	return edma_native_tx_ready(priv, wait->native_slots);
}

static void edma_tx_wait_clear_locked(struct edma_priv *priv)
{
	qdx_resource_wait_disarm(&priv->wait.resource);
	priv->wait.status = QDX_TX_NATIVE;
	priv->wait.reason = EDMA_TX_WAIT_NONE;
}

static void edma_tx_retry(void *context)
{
	struct edma_priv *priv = context;
	struct qdx_tx_selection checked = {};
	struct netdev_queue *queue;

	spin_lock_bh(&priv->completion_lock);
	queue = priv->wait.queue;
	if (edma_tx_can_run_locked(priv, &checked)) {
		edma_tx_wait_clear_locked(priv);
		netif_tx_wake_queue(queue);
	}
	spin_unlock_bh(&priv->completion_lock);
	qdx_tx_selection_put(&checked);
}

static void edma_tx_gate(void *context, bool hold)
{
	struct edma_priv *priv = context;

	spin_lock_bh(&priv->completion_lock);
	if (hold) {
		priv->tx_transitions++;
		netif_tx_stop_queue(priv->wait.queue);
	} else if (!WARN_ON_ONCE(!priv->tx_transitions)) {
		priv->tx_transitions--;
	}
	spin_unlock_bh(&priv->completion_lock);
	if (!hold)
		edma_tx_retry(priv);
}

static bool edma_wait_get(void *context)
{
	struct edma_priv *priv = context;

	dev_hold(priv->netdev);
	return true;
}

static void edma_wait_put(void *context)
{
	struct edma_priv *priv = context;

	dev_put(priv->netdev);
}

/* The failed submission owns no skb or DMA. Stop, then recheck after installing
 * the actual queue's retained scope. Only one inline retry is permitted.
 */
static bool edma_tx_maybe_stop(struct edma_priv *priv,
		const struct dsa_oob_tag_info *tag, size_t charge,
		enum edma_tx_wait_reason reason, u16 native_slots, bool inline_retry)
{
	struct qdx_tx_selection selected = { .status = QDX_TX_NATIVE }, checked = {};
	struct edma_tx_wait *wait = &priv->wait;
	struct qdx_ready ready;
	bool runnable;

	spin_lock_bh(&priv->completion_lock);
	edma_tx_wait_clear_locked(priv);
	wait->reason = reason;
	wait->tagged = !!tag;
	wait->charge = charge;
	wait->native_slots = native_slots;
	if (tag) {
		wait->port = tag->port;
		wait->user_queue = tag->user_queue;
		wait->token = tag->token;
		wait->disposition = tag->disposition;
		qdx_edma_resolve(priv->qdx, wait->port, wait->user_queue,
				 wait->token, wait->disposition, &selected);
	}
	/* Retain queue identity and resource notification, not the execution.
	 * A saved path reference would prevent its own pending handback.
	 */
	wait->status = selected.status;
	if (reason == EDMA_TX_WAIT_RESOURCE && selected.status == QDX_TX_READY) {
		ready = qdx_tx_ready(selected.path, charge);
		if (ready.status == QDX_RESOURCE_WAIT)
			qdx_tx_wait_arm(selected.path, &wait->resource, ready.resources);
	}
	netif_tx_stop_queue(wait->queue);
	runnable = edma_tx_can_run_locked(priv, &checked);
	if (runnable) {
		/* Retain the installed scope until retry drops it; no pointer to the
		 * rejected skb is retained. A scheduled retry must remain scheduled.
		 */
		if (inline_retry)
			netif_tx_start_queue(wait->queue);
		else
			netif_tx_wake_queue(wait->queue);
	}
	spin_unlock_bh(&priv->completion_lock);
	qdx_tx_selection_put(&checked);
	qdx_tx_selection_put(&selected);
	return runnable && inline_retry;
}

static int edma_tx_napi(struct napi_struct *napi, int budget)
{
	struct edma_priv *priv = container_of(napi, struct edma_priv, tx_napi);
	int work = edma_clean_tx(priv, &priv->txcmpl_ring, budget);
	const struct edma_soc_data *soc = priv->soc;
	u32 val;

	edma_tx_retry(priv);

	if (work < budget) {
		regmap_read(priv->regmap,
			    EDMA_REG_TX_INT_STAT(soc->tx_int_base,
						 soc->txcmpl_ring),
			    &val);
		if (val)
			return budget;

		if (napi_complete_done(napi, work))
			edma_tx_irq_unmask(priv);
	}

	return work;
}

static int edma_rx_napi(struct napi_struct *napi, int budget)
{
	struct edma_priv *priv = container_of(napi, struct edma_priv, rx_napi);
	const struct edma_soc_data *soc = priv->soc;
	int done;
	u16 prod, cons;

	done = edma_clean_rx(priv, budget, &priv->rxdesc_ring);

	if (done < budget) {
		u32 val;

		regmap_read(priv->regmap,
			    EDMA_REG_RXDESC_INT_STAT(soc->rxdesc_ring),
			    &val);
		prod = val;
		regmap_read(priv->regmap,
			    EDMA_REG_RXFILL_INT_STAT(soc->rxfill_ring),
			    &val);
		cons = val;
		if (prod || cons)
			return budget;

		regmap_read(priv->regmap,
			    EDMA_REG_RXFILL_PROD_IDX(soc->rxfill_ring),
			    &val);
		prod = val & (priv->rxfill_ring.count - 1);
		regmap_read(priv->regmap,
			    EDMA_REG_RXFILL_CONS_IDX(soc->rxfill_ring),
			    &val);
		cons = val & (priv->rxfill_ring.count - 1);
		if (prod == cons) {
			dev_warn_ratelimited(&priv->pdev->dev,
					     "RXFILL ring starved\n");
			edma_rx_fill(priv, &priv->rxfill_ring);
			return budget;
		}

		if (napi_complete_done(napi, done))
			edma_rx_irq_unmask(priv);
	}

	return done;
}

static netdev_tx_t edma_ring_xmit(struct edma_priv *priv, struct net_device *netdev,
				  struct sk_buff *skb, struct netdev_queue *queue)
{
	const struct edma_soc_data *soc = priv->soc;
	struct edma_ring *ring = &priv->txdesc_ring;
	struct edma_tx_preheader *txph;
	struct dsa_oob_tag_info *tag;
	struct edma_txdesc *desc;
	struct edma_tx_slot *slot;
	u16 prod, cons, next;
	u32 value, bytes;
	dma_addr_t dma;

	spin_lock_bh(&priv->tx_lock);
	if (regmap_read(priv->regmap, EDMA_REG_TXDESC_PROD_IDX(soc->txdesc_ring), &value))
		goto drop;
	prod = value & EDMA_TXDESC_PROD_IDX_MASK;
	if (regmap_read(priv->regmap, EDMA_REG_TXDESC_CONS_IDX(soc->txdesc_ring), &value))
		goto drop;
	cons = value & EDMA_TXDESC_CONS_IDX_MASK;
	if (prod >= ring->count || cons >= ring->count)
		goto drop;
	next = (prod + 1) & (ring->count - 1);
	slot = &ring->tx[prod & (ring->count - 1)];
	if (next == cons || slot->skb) {
		spin_unlock_bh(&priv->tx_lock);
		return NETDEV_TX_BUSY;
	}

	/* Capacity is now reserved by this ring lock. No later branch returns
	 * BUSY after modifying the caller's frame or its storage.
	 */
	if (skb_is_nonlinear(skb) && skb_linearize(skb))
		goto drop;
	if (soc->tx_min_size && skb->len < soc->tx_min_size) {
		if (skb_padto(skb, soc->tx_min_size)) {
			netdev->stats.tx_dropped++;
			spin_unlock_bh(&priv->tx_lock);
			return NETDEV_TX_OK;
		}
		skb_put(skb, soc->tx_min_size - skb->len);
	}
	if ((skb_cloned(skb) || skb_headroom(skb) < netdev->needed_headroom ||
	     skb_tailroom(skb) < netdev->needed_tailroom) &&
	    pskb_expand_head(skb, netdev->needed_headroom, netdev->needed_tailroom, GFP_ATOMIC))
		goto drop;
	bytes = skb->len;
	if (bytes > EDMA_TXDESC_DATA_LENGTH_MASK)
		goto drop;
	tag = skb_ext_find(skb, SKB_EXT_DSA_OOB);
	txph = (struct edma_tx_preheader *)skb_push(skb, EDMA_TX_PREHDR_SIZE);
	memset(txph, 0, sizeof(*txph));
	if (tag)
		txph->dst_info = cpu_to_le16((EDMA_DST_PORT_TYPE << 8) |
					   (tag->port & EDMA_DST_PORT_ID_MASK));
	txph->opaque = cpu_to_le32(prod);
	dma = dma_map_single(&priv->pdev->dev, skb->data,
			     bytes + EDMA_TX_PREHDR_SIZE, DMA_TO_DEVICE);
	if (dma_mapping_error(&priv->pdev->dev, dma))
		goto drop;
	*slot = (struct edma_tx_slot) {
		.skb = skb, .dma = dma, .mapped = bytes + EDMA_TX_PREHDR_SIZE,
		.bytes = bytes, .queue = queue,
	};
	desc = EDMA_TXDESC_DESC(ring, prod);
	desc->buffer_addr = cpu_to_le32(dma);
	desc->word1 = cpu_to_le32((1 << EDMA_TXDESC_PREHEADER_SHIFT) |
				(EDMA_TX_PREHDR_SIZE << EDMA_TXDESC_DATA_OFFSET_SHIFT) |
				bytes);
	skb_tx_timestamp(skb);
	dev_sw_netstats_tx_add(netdev, 1, bytes);
	netdev_tx_sent_queue(queue, bytes);
	/* Publish the initialized descriptor only after its retained TX record. */
	wmb();
	regmap_write(priv->regmap, EDMA_REG_TXDESC_PROD_IDX(soc->txdesc_ring), next);
	spin_unlock_bh(&priv->tx_lock);
	return NETDEV_TX_OK;
drop:
	netdev->stats.tx_dropped++;
	dev_kfree_skb_any(skb);
	spin_unlock_bh(&priv->tx_lock);
	return NETDEV_TX_OK;
}

static void edma_rx_ring_free(struct edma_priv *priv, struct edma_ring *ring,
			      int desc_size)
{
	int i;

	if (ring->page_store) {
		/* Hardware indices do not account for prefetched RX pages. */
		for (i = 0; i < ring->count; i++) {
			if (!ring->page_store[i])
				continue;

			page_pool_put_full_page(priv->page_pool,
						ring->page_store[i], false);
			ring->page_store[i] = NULL;
		}

		kfree(ring->page_store);
		ring->page_store = NULL;
	}

	edma_ring_free(priv, ring, desc_size);
}

/* Reset/stop has ended native access. Indices omit prefetched TX packets. */
static void edma_txdesc_drain(struct edma_priv *priv, struct edma_ring *ring)
{
	struct netdev_queue *queue = NULL;
	u32 bytes = 0, packets = 0;
	unsigned int i;

	if (!ring->tx)
		return;
	for (i = 0; i < ring->count; i++) {
		struct edma_tx_slot slot;

		spin_lock_bh(&priv->tx_lock);
		slot = ring->tx[i];
		memset(&ring->tx[i], 0, sizeof(slot));
		spin_unlock_bh(&priv->tx_lock);
		if (!slot.skb)
			continue;
		dma_unmap_single(&priv->pdev->dev, slot.dma, slot.mapped, DMA_TO_DEVICE);
		if (queue && queue != slot.queue) {
			edma_tx_complete(priv, queue, packets, bytes);
			packets = 0;
			bytes = 0;
		}
		queue = slot.queue;
		bytes += slot.bytes;
		packets++;
		dev_kfree_skb_any(slot.skb);
	}
	if (packets)
		edma_tx_complete(priv, queue, packets, bytes);
}

static int edma_rings_alloc(struct edma_priv *priv)
{
	int ret;

	ret = edma_tx_ring_alloc(priv, &priv->txdesc_ring, EDMA_TX_RING_SIZE,
				 sizeof(struct edma_txdesc));
	if (ret)
		return ret;

	ret = edma_ring_alloc(priv, &priv->txcmpl_ring, EDMA_TX_RING_SIZE,
			      sizeof(struct edma_txcmpl));
	if (ret)
		goto err_txcmpl;

	ret = edma_rx_ring_alloc(priv, &priv->rxfill_ring, priv->rx_entries,
				 sizeof(struct edma_rxfill_desc));
	if (ret)
		goto err_rxfill;

	ret = edma_ring_alloc(priv, &priv->rxdesc_ring, priv->rx_entries,
			      sizeof(struct edma_rxdesc));
	if (ret)
		goto err_rxdesc;

	return 0;

err_rxdesc:
	edma_rx_ring_free(priv, &priv->rxfill_ring,
			  sizeof(struct edma_rxfill_desc));
err_rxfill:
	edma_ring_free(priv, &priv->txcmpl_ring, sizeof(struct edma_txcmpl));
err_txcmpl:
	edma_tx_ring_free(priv, &priv->txdesc_ring, sizeof(struct edma_txdesc));
	return ret;
}

static void edma_rings_drain(struct edma_priv *priv)
{
	edma_tx_ring_free(priv, &priv->txdesc_ring, sizeof(struct edma_txdesc));
	edma_ring_free(priv, &priv->txcmpl_ring, sizeof(struct edma_txcmpl));
	edma_rx_ring_free(priv, &priv->rxfill_ring,
			  sizeof(struct edma_rxfill_desc));
	edma_ring_free(priv, &priv->rxdesc_ring, sizeof(struct edma_rxdesc));
}

static void edma_configure_txdesc_ring(struct edma_priv *priv,
				       struct edma_ring *txdesc_ring)
{
	const struct edma_soc_data *soc = priv->soc;
	u32 val;

	regmap_write(priv->regmap, EDMA_REG_TXDESC_BA(soc->txdesc_ring),
		    (u32)txdesc_ring->dma);

	regmap_write(priv->regmap,
		     EDMA_REG_TXDESC_RING_SIZE(soc->txdesc_ring),
		     txdesc_ring->count & EDMA_TXDESC_RING_SIZE_MASK);

	regmap_read(priv->regmap, EDMA_REG_TXDESC_CONS_IDX(soc->txdesc_ring),
		    &val);
	val &= ~EDMA_TXDESC_CONS_IDX_MASK;

	regmap_update_bits(priv->regmap,
			   EDMA_REG_TXDESC_PROD_IDX(soc->txdesc_ring),
			   EDMA_TXDESC_PROD_IDX_MASK, val);
}

static void edma_configure_txcmpl_ring(struct edma_priv *priv,
				       struct edma_ring *txcmpl_ring)
{
	const struct edma_soc_data *soc = priv->soc;

	regmap_write(priv->regmap,
		     EDMA_REG_TXCMPL_BA(soc->txcmpl_base, soc->txcmpl_ring),
		     (u32)txcmpl_ring->dma);
	regmap_write(priv->regmap,
		     EDMA_REG_TXCMPL_RING_SIZE(soc->txcmpl_base,
					       soc->txcmpl_ring),
		     txcmpl_ring->count & EDMA_TXDESC_RING_SIZE_MASK);

	regmap_write(priv->regmap,
		     EDMA_REG_TXCMPL_CTRL(soc->txcmpl_base,
					  soc->txcmpl_ring),
		     EDMA_TXCMPL_RETMODE_OPAQUE);

	regmap_write(priv->regmap,
		     EDMA_REG_TX_MOD_TIMER(soc->tx_int_base,
					   soc->txcmpl_ring),
		     EDMA_TX_MOD_TIMER);

	regmap_write(priv->regmap,
		     EDMA_REG_TX_INT_CTRL(soc->tx_int_base,
					  soc->txcmpl_ring),
		     0x2);
}

static void edma_configure_rxdesc_ring(struct edma_priv *priv,
				       struct edma_ring *rxdesc_ring)
{
	const struct edma_soc_data *soc = priv->soc;
	u32 val;

	regmap_write(priv->regmap,
		     EDMA_REG_RXDESC_BA(soc->rxdesc_ring),
		     (u32)rxdesc_ring->dma);

	val = rxdesc_ring->count & EDMA_RXDESC_RING_SIZE_MASK;
	val |= (EDMA_RX_PREHDR_SIZE & EDMA_RXDESC_PL_OFFSET_MASK)
	       << EDMA_RXDESC_PL_OFFSET_SHIFT;
	regmap_write(priv->regmap,
		     EDMA_REG_RXDESC_RING_SIZE(soc->rxdesc_ring),
		     val);

	regmap_write(priv->regmap,
		     EDMA_REG_RX_MOD_TIMER(soc->rxdesc_ring),
		     EDMA_RX_MOD_TIMER_INIT);

	regmap_write(priv->regmap,
		     EDMA_REG_RX_INT_CTRL(soc->rxdesc_ring),
		     0x2);
}

static void edma_configure_rxfill_ring(struct edma_priv *priv,
				       struct edma_ring *rxfill_ring)
{
	const struct edma_soc_data *soc = priv->soc;

	regmap_write(priv->regmap,
		     EDMA_REG_RXFILL_BA(soc->rxfill_ring),
		     (u32)rxfill_ring->dma);

	regmap_write(priv->regmap,
		     EDMA_REG_RXFILL_RING_SIZE(soc->rxfill_ring),
		     rxfill_ring->count & EDMA_RXFILL_RING_SIZE_MASK);

	edma_rx_fill(priv, rxfill_ring);
}

static void edma_configure_rings(struct edma_priv *priv)
{
	edma_configure_txdesc_ring(priv, &priv->txdesc_ring);
	edma_configure_txcmpl_ring(priv, &priv->txcmpl_ring);
	edma_configure_rxfill_ring(priv, &priv->rxfill_ring);
	edma_configure_rxdesc_ring(priv, &priv->rxdesc_ring);
}

static void edma_rings_disable(struct edma_priv *priv)
{
	const struct edma_soc_data *soc = priv->soc;
	int i;

	for (i = 0; i <= soc->rxdesc_ring; i++)
		regmap_clear_bits(priv->regmap, EDMA_REG_RXDESC_CTRL(i),
				  EDMA_RXDESC_RX_EN);

	for (i = 0; i <= soc->rxfill_ring; i++)
		regmap_clear_bits(priv->regmap, EDMA_REG_RXFILL_RING_EN(i),
				  EDMA_RXFILL_RING_EN);

	for (i = 0; i <= soc->txdesc_ring; i++)
		regmap_clear_bits(priv->regmap, EDMA_REG_TXDESC_CTRL(i),
				  EDMA_TXDESC_TX_EN);
}

static void edma_rings_enable(struct edma_priv *priv)
{
	const struct edma_soc_data *soc = priv->soc;

	regmap_set_bits(priv->regmap,
			EDMA_REG_RXDESC_CTRL(soc->rxdesc_ring),
			EDMA_RXDESC_RX_EN);

	regmap_set_bits(priv->regmap,
			EDMA_REG_RXFILL_RING_EN(soc->rxfill_ring),
			EDMA_RXFILL_RING_EN);

	regmap_set_bits(priv->regmap,
			EDMA_REG_TXDESC_CTRL(soc->txdesc_ring),
			EDMA_TXDESC_TX_EN);
}

static void edma_hw_stop(struct edma_priv *priv)
{
	WRITE_ONCE(priv->native_ready, false);
	edma_irq_disable_all(priv);
	edma_rings_disable(priv);
	regmap_write(priv->regmap, EDMA_REG_PORT_CTRL, 0);
}

static int edma_hw_reset(struct edma_priv *priv)
{
	int ret;

	ret = reset_control_assert(priv->rst);
	if (ret)
		return ret;
	udelay(100);
	ret = reset_control_deassert(priv->rst);
	if (ret)
		return ret;
	udelay(100);
	return 0;
}

static int edma_hw_init(struct edma_priv *priv)
{
	const struct edma_soc_data *soc = priv->soc;
	int ret;
	u32 val;

	ret = edma_hw_reset(priv);
	if (ret)
		return ret;
	edma_hw_stop(priv);

	regmap_write(priv->regmap, EDMA_QID2RID_TABLE_MEM(0),
		     soc->rxdesc_ring & 0xF);

	ret = edma_rings_alloc(priv);
	if (ret)
		return ret;

	edma_configure_rings(priv);

	regmap_write(priv->regmap, EDMA_REG_RXDESC2FILL_MAP_0, 0);
	regmap_write(priv->regmap, EDMA_REG_RXDESC2FILL_MAP_1,
		     (soc->rxfill_ring & 0x7)
			<< ((soc->rxdesc_ring % 10) * 3));

	if (soc->txcmpl_ring != soc->txdesc_ring) {
		int map_idx, bit_pos;
		int i;

		for (i = 0; i < 3; i++)
			regmap_write(priv->regmap, EDMA_REG_TXDESC2CMPL_MAP(i), 0);

		map_idx = soc->txdesc_ring / 10;
		bit_pos = (soc->txdesc_ring % 10) * 3;
		regmap_set_bits(priv->regmap, EDMA_REG_TXDESC2CMPL_MAP(map_idx),
				(soc->txcmpl_ring & 0x7) << bit_pos);
	}

	val = EDMA_DMAR_BURST_LEN_SET(soc->burst_enable) |
	      EDMA_DMAR_REQ_PRI_SET(0) | EDMA_DMAR_TXDATA_NUM_SET(31) |
	      EDMA_DMAR_TXDESC_NUM_SET(7) | EDMA_DMAR_RXFILL_NUM_SET(7);
	regmap_write(priv->regmap, EDMA_REG_DMAR_CTRL, val);

	if (soc->axiw_enable)
		regmap_set_bits(priv->regmap, EDMA_REG_AXIW_CTRL,
				EDMA_AXIW_MAX_WR_SIZE_EN);

	regmap_write(priv->regmap, EDMA_REG_MISC_INT_MASK, soc->misc_int_mask);

	regmap_write(priv->regmap, EDMA_REG_PORT_CTRL,
		     EDMA_PORT_PAD_EN | EDMA_PORT_EDMA_EN);

	edma_rings_enable(priv);
	WRITE_ONCE(priv->native_ready, true);

	return 0;
}

static void edma_get_drvinfo(struct net_device *netdev,
			     struct ethtool_drvinfo *info)
{
	strscpy(info->driver, "qca-edma", sizeof(info->driver));
	strscpy(info->bus_info, dev_name(netdev->dev.parent),
		sizeof(info->bus_info));
}

static void edma_get_ringparam(struct net_device *netdev,
			       struct ethtool_ringparam *ring,
			       struct kernel_ethtool_ringparam *kernel_ring,
			       struct netlink_ext_ack *extack)
{
	struct edma_priv *priv = netdev_priv(netdev);

	ring->tx_max_pending = EDMA_TX_RING_SIZE;
	ring->rx_max_pending = EDMA_RX_RING_MAX;
	ring->tx_pending = priv->txdesc_ring.count;
	ring->rx_pending = priv->rx_entries;
}

static const struct ethtool_ops edma_ethtool_ops = {
	.get_drvinfo = edma_get_drvinfo,
	.get_link = ethtool_op_get_link,
	.get_ringparam = edma_get_ringparam,
};

static int edma_ndo_open(struct net_device *netdev)
{
	struct edma_priv *priv = netdev_priv(netdev);

	if (!priv->native_ready)
		return -EIO;
	/* Both owners may complete earlier submissions in either live mode. */
	if (priv->native_ready && !priv->napi_active) {
		priv->napi_active = true;
		napi_enable(&priv->tx_napi);
		napi_enable(&priv->rx_napi);
		edma_tx_irq_unmask(priv);
		edma_rx_irq_unmask(priv);
	}
	/* Administrative cycles retain outstanding packets and their BQL charges. */
	spin_lock_bh(&priv->completion_lock);
	priv->tx_admin = true;
	spin_unlock_bh(&priv->completion_lock);
	edma_tx_retry(priv);
	return 0;
}

static int edma_ndo_stop(struct net_device *netdev)
{
	struct edma_priv *priv = netdev_priv(netdev);
	bool active;

	spin_lock_bh(&priv->completion_lock);
	active = priv->napi_active;
	WRITE_ONCE(priv->napi_active, false);
	priv->tx_admin = false;
	netif_tx_stop_queue(priv->wait.queue);
	spin_unlock_bh(&priv->completion_lock);
	netif_tx_disable(netdev);
	if (!active)
		return 0;
	edma_tx_irq_mask(priv);
	edma_rx_irq_mask(priv);
	synchronize_irq(priv->txcmpl_irq);
	synchronize_irq(priv->rxfill_irq);
	synchronize_irq(priv->rxdesc_irq);
	napi_disable(&priv->tx_napi);
	napi_disable(&priv->rx_napi);
	synchronize_net();
	/* Both poll tails have exited before the final interrupt masks. */
	edma_tx_irq_mask(priv);
	edma_rx_irq_mask(priv);

	return 0;
}

static int edma_ndo_change_mtu(struct net_device *netdev, int new_mtu);

static netdev_tx_t edma_ndo_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	struct edma_priv *priv = netdev_priv(netdev);
	struct dsa_oob_tag_info *tag = skb_ext_find(skb, SKB_EXT_DSA_OOB);
	struct dsa_oob_tag_info saved_tag;
	struct netdev_queue *queue = netdev_get_tx_queue(netdev, skb_get_queue_mapping(skb));
	struct qdx_tx_selection selection;
	enum edma_tx_wait_reason reason;
	struct qdx_ready ready;
	struct sk_buff *packet;
	size_t charge;
	bool retried = false;
	bool stop;
	u16 native_slots;
	netdev_tx_t ret;

	if (tag) {
		saved_tag = *tag;
		tag = &saved_tag;
	}
retry:
	packet = skb;
	charge = skb->truesize;
	memset(&selection, 0, sizeof(selection));
	selection.status = QDX_TX_NATIVE;
	reason = EDMA_TX_WAIT_DISPOSITION;
	spin_lock_bh(&priv->completion_lock);
	if (!priv->tx_admin || priv->detaching || priv->tx_transitions ||
	    !priv->native_ready || !priv->napi_active ||
	    !netif_running(netdev) || !netif_carrier_ok(netdev))
		goto stopped;
	edma_tx_wait_clear_locked(priv);
	if (tag)
		qdx_edma_resolve(priv->qdx, tag->port, tag->user_queue,
				 tag->token, tag->disposition, &selection);
	if (selection.status == QDX_TX_HELD)
		goto stopped;
	if (selection.status == QDX_TX_RETIRED ||
	    selection.status == QDX_TX_REFUSED || skb->len < ETH_HLEN)
		goto drop;
	if (selection.status == QDX_TX_NATIVE) {
		ret = edma_ring_xmit(priv, netdev, skb, queue);
		if (ret == NETDEV_TX_OK)
			goto accepted;
		reason = EDMA_TX_WAIT_RESOURCE;
		goto stopped;
	}
	/* This SoC requires a complete frame of at least tx_min_size bytes.
	 * A rejected NSS submission must leave the qdisc's original skb intact.
	 */
	if (skb_is_nonlinear(skb) || skb_cloned(skb) ||
	    skb->len < priv->soc->tx_min_size) {
		packet = skb_copy_expand(skb, skb_headroom(skb),
			max_t(unsigned int, skb_tailroom(skb),
			      priv->soc->tx_min_size > skb->len ?
			      priv->soc->tx_min_size - skb->len : 0), GFP_ATOMIC);
		if (!packet)
			goto drop;
		if (skb_put_padto(packet, priv->soc->tx_min_size)) {
			packet = skb; /* skb_put_padto consumed only the temporary copy. */
			goto drop;
		}
		charge = packet->truesize;
	}
	ready = qdx_tx_ready(selection.path, charge);
	if (ready.status == QDX_ACCEPTED)
		ready = qdx_xmit(selection.path, packet, selection.class, queue, packet->len);
	if (ready.status == QDX_ACCEPTED) {
		if (packet != skb)
			dev_consume_skb_any(skb);
		goto accepted;
	}
	if (packet != skb)
		dev_kfree_skb_any(packet);
	packet = skb;
	if (ready.status == QDX_REFUSED)
		goto drop;
	if (ready.status == QDX_RESOURCE_WAIT)
		reason = EDMA_TX_WAIT_RESOURCE;
stopped:
	spin_unlock_bh(&priv->completion_lock);
	qdx_tx_selection_put(&selection);
	if (edma_tx_maybe_stop(priv, tag, charge, reason, 1, !retried)) {
		retried = true;
		goto retry;
	}
	return NETDEV_TX_BUSY;
drop:
	netdev->stats.tx_dropped++;
	dev_kfree_skb_any(skb);
accepted:
	/* Check fixed descriptor/carrier needs after publication. The next skb's
	 * unknown allocation is not guessed; its real byte shortage is recorded
	 * only if that later submission cannot be admitted.
	 */
	reason = EDMA_TX_WAIT_RESOURCE;
	native_slots = EDMA_TX_RING_THRESH + 1;
	stop = false;
	if (selection.status == QDX_TX_NATIVE) {
		stop = !edma_native_tx_ready(priv, native_slots);
	} else if (selection.status == QDX_TX_READY) {
		ready = qdx_tx_ready(selection.path, 0);
		stop = ready.status == QDX_RESOURCE_WAIT || ready.status == QDX_CLOSED;
		if (ready.status == QDX_CLOSED)
			reason = EDMA_TX_WAIT_DISPOSITION;
	}
	spin_unlock_bh(&priv->completion_lock);
	qdx_tx_selection_put(&selection);
	if (stop)
		edma_tx_maybe_stop(priv, tag, 0, reason, native_slots, false);
	return NETDEV_TX_OK;
}

/* One entry per actual FT block and conduit. The native FT lock protects the
 * callback's table borrow; cfg serializes optional provider attach and detach.
 */
struct edma_ft {
	refcount_t refs;
	struct mutex cfg;
	struct net_device *dev;
	struct nf_flowtable *table;
	struct qdx_binding *native;
	struct qdx_binding *provider;
	void *attachment;
	bool closed;
};

static bool edma_ft_get(void *object)
{
	struct edma_ft *entry = object;

	return refcount_inc_not_zero(&entry->refs);
}

static void edma_ft_put(void *object)
{
	struct edma_ft *entry = object;

	if (!refcount_dec_and_test(&entry->refs))
		return;
	dev_put(entry->dev);
	kfree(entry);
}

static int edma_ft_setup(enum tc_setup_type type, void *data, void *object)
{
	struct edma_ft *entry = object;
	const struct qdx_binding_key key = { .role = QDX_BINDING_FT_PROVIDER };
	struct flow_cls_offload *cls = data;
	const struct qdx_flow_ops *ops;
	struct qdx_binding *provider;
	int ret = -EOPNOTSUPP;

	mutex_lock(&entry->cfg);
	if (entry->closed)
		goto out;
	if (!entry->provider) {
		/* CPU refresh naturally retries REPLACE after a missing peer loads.
		 * Cleanup/statistics for an unoffloaded entry need no new attachment.
		 */
		if (type != TC_SETUP_CLSFLOWER || cls->command != FLOW_CLS_REPLACE)
			goto out;
		provider = qdx_binding_lookup(&key);
		if (IS_ERR(provider)) {
			ret = PTR_ERR(provider);
			goto out;
		}
		if (!provider)
			goto out;
		ops = qdx_binding_ops(provider);
		ret = ops->bind(qdx_binding_owner(provider), entry->native,
				entry->table, &entry->attachment);
		if (ret) {
			qdx_binding_put(provider);
			goto out;
		}
		entry->provider = provider;
	}
	ops = qdx_binding_ops(entry->provider);
	ret = ops->setup(entry->attachment, type, data);
out:
	mutex_unlock(&entry->cfg);
	return ret;
}

static void edma_ft_release(void *object)
{
	struct edma_ft *entry = object;
	const struct qdx_flow_ops *ops;

	/* Native flow_block write lock excludes every old callback. No wait for
	 * RTNL-dependent preparation or final hardware retirement is allowed here.
	 */
	mutex_lock(&entry->cfg);
	entry->closed = true;
	if (entry->provider) {
		ops = qdx_binding_ops(entry->provider);
		ops->unbind(entry->attachment);
		entry->attachment = NULL;
		qdx_binding_put(entry->provider);
		entry->provider = NULL;
	}
	entry->table = NULL;
	qdx_binding_withdraw(entry->native);
	mutex_unlock(&entry->cfg);
	edma_ft_put(entry); /* Native callback storage; old peer refs may remain. */
}

static int edma_ndo_setup_tc(struct net_device *netdev, enum tc_setup_type type,
			     void *data)
{
	struct edma_priv *priv = netdev_priv(netdev);
	struct flow_block_offload *offload = data;
	struct qdx_binding_key key;
	struct qdx_owner owner;
	struct flow_block_cb *cb;
	struct edma_ft *entry;
	int ret;

	if (type != TC_SETUP_FT || !offload->nf_flowtable ||
	    offload->binder_type != FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS)
		return -EOPNOTSUPP;
	cb = flow_block_cb_lookup(offload->block, edma_ft_setup, netdev);
	switch (offload->command) {
	case FLOW_BLOCK_BIND:
		if (cb) {
			flow_block_cb_incref(cb);
			return 0;
		}
		entry = kzalloc_obj(*entry);
		if (!entry)
			return -ENOMEM;
		refcount_set(&entry->refs, 1);
		mutex_init(&entry->cfg);
		entry->dev = netdev;
		dev_hold(netdev);
		entry->table = offload->nf_flowtable;
		key = (struct qdx_binding_key) {
			.dev = netdev, .identity = offload->block, .role = QDX_BINDING_FT,
		};
		owner = (struct qdx_owner) {
			.module = THIS_MODULE, .object = entry,
			.get = edma_ft_get, .put = edma_ft_put,
		};
		entry->native = qdx_binding_publish(&key, &owner, NULL);
		if (IS_ERR(entry->native)) {
			ret = PTR_ERR(entry->native);
			edma_ft_put(entry);
			return ret;
		}
		cb = flow_block_cb_alloc(edma_ft_setup, netdev, entry, edma_ft_release);
		if (IS_ERR(cb)) {
			qdx_binding_withdraw(entry->native);
			edma_ft_put(entry);
			return PTR_ERR(cb);
		}
		flow_block_cb_incref(cb);
		flow_block_cb_add(cb, offload);
		list_add_tail(&cb->driver_list, &priv->ft_bindings);
		qdx_binding_available(entry->native);
		return 0;
	case FLOW_BLOCK_UNBIND:
		if (!cb)
			return -ENOENT;
		if (flow_block_cb_decref(cb))
			return 0;
		flow_block_cb_remove(cb, offload);
		list_del(&cb->driver_list);
		return 0;
	default:
		return -EOPNOTSUPP;
	}
}

static const struct net_device_ops edma_netdev_ops = {
	.ndo_open = edma_ndo_open,
	.ndo_stop = edma_ndo_stop,
	.ndo_start_xmit = edma_ndo_xmit,
	.ndo_change_mtu = edma_ndo_change_mtu,
	.ndo_setup_tc = edma_ndo_setup_tc,
	.ndo_set_mac_address = eth_mac_addr,
	.ndo_validate_addr = eth_validate_addr,
	.ndo_get_stats64 = dev_get_tstats64,
};

static int edma_irq_init(struct edma_priv *priv)
{
	struct platform_device *pdev = priv->pdev;
	struct device *dev = &pdev->dev;
	int ret;

	priv->txcmpl_irq = platform_get_irq(pdev, 0);
	if (priv->txcmpl_irq < 0)
		return priv->txcmpl_irq;

	priv->rxfill_irq = platform_get_irq(pdev, 1);
	if (priv->rxfill_irq < 0)
		return priv->rxfill_irq;

	priv->rxdesc_irq = platform_get_irq(pdev, 2);
	if (priv->rxdesc_irq < 0)
		return priv->rxdesc_irq;

	priv->misc_irq = platform_get_irq(pdev, 3);
	if (priv->misc_irq < 0)
		return priv->misc_irq;

	ret = devm_request_irq(dev, priv->txcmpl_irq, edma_tx_irq_handle, 0,
			       "edma_txcmpl", priv);
	if (ret)
		return ret;

	ret = devm_request_irq(dev, priv->rxfill_irq, edma_rx_irq_handle, 0,
			       "edma_rxfill", priv);
	if (ret)
		return ret;

	ret = devm_request_irq(dev, priv->rxdesc_irq, edma_rx_irq_handle, 0,
			       "edma_rxdesc", priv);
	if (ret)
		return ret;

	ret = devm_request_irq(dev, priv->misc_irq, edma_misc_irq_handle, 0,
			       "edma_misc", priv);
	if (ret)
		return ret;

	return 0;
}

static u8 edma_rx_page_order(int mtu)
{
	size_t size = NET_SKB_PAD + EDMA_RX_PREHDR_SIZE + mtu + ETH_HLEN +
		      2 * VLAN_HLEN +
		      SKB_DATA_ALIGN(sizeof(struct skb_shared_info));

	return get_order(size);
}

static u32 edma_rx_buffer_size(u8 order)
{
	return (PAGE_SIZE << order) - NET_SKB_PAD -
	       SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
}

static struct page_pool *edma_page_pool_create(struct edma_priv *priv,
					       u8 order, u32 entries)
{
	struct page_pool_params pp = {
		.order     = order,
		.pool_size = entries,
		.nid       = NUMA_NO_NODE,
		.dev       = &priv->pdev->dev,
		.dma_dir   = DMA_FROM_DEVICE,
		.offset    = NET_SKB_PAD,
		.max_len   = edma_rx_buffer_size(order),
		.flags     = PP_FLAG_DMA_MAP | PP_FLAG_DMA_SYNC_DEV,
	};

	return page_pool_create(&pp);
}

static int edma_ndo_change_mtu(struct net_device *netdev, int new_mtu)
{
	struct edma_priv *priv = netdev_priv(netdev);
	struct page_pool *old_pool, *new_pool;
	u8 old_order, new_order;
	bool running;
	int ret;

	if (READ_ONCE(priv->shared)) {
		WRITE_ONCE(netdev->mtu, new_mtu);
		return 0;
	}
	if (!priv->native_ready)
		return -EIO;
	new_order = edma_rx_page_order(new_mtu);
	if (new_order == priv->rx_page_order) {
		WRITE_ONCE(netdev->mtu, new_mtu);
		return 0;
	}

	new_pool = edma_page_pool_create(priv, new_order, priv->rx_entries);
	if (IS_ERR(new_pool))
		return PTR_ERR(new_pool);

	running = netif_running(netdev);
	if (running) {
		netif_tx_disable(netdev);
		edma_ndo_stop(netdev);
	}

	WRITE_ONCE(priv->native_ready, false);
	ret = reset_control_assert(priv->rst);
	if (ret) {
		/* Old descriptors and mappings may still be accessible. */
		page_pool_destroy(new_pool);
		netdev_err(netdev, "failed to stop DMA for MTU change: %d\n", ret);
		return ret;
	}
	udelay(100);
	edma_rings_drain(priv);

	old_pool = priv->page_pool;
	old_order = priv->rx_page_order;
	priv->page_pool = new_pool;
	priv->rx_page_order = new_order;
	priv->rx_buffer_size = edma_rx_buffer_size(new_order);

	ret = edma_hw_init(priv);
	if (ret) {
		int restore_ret;

		priv->page_pool = old_pool;
		priv->rx_page_order = old_order;
		priv->rx_buffer_size = edma_rx_buffer_size(old_order);
		page_pool_destroy(new_pool);

		restore_ret = edma_hw_init(priv);
		if (restore_ret) {
			netdev_err(netdev,
				   "failed to restore receive buffers after MTU change: %d\n",
				   restore_ret);
			netif_device_detach(netdev);
			return restore_ret;
		}
	} else {
		page_pool_destroy(old_pool);
		WRITE_ONCE(netdev->mtu, new_mtu);
	}

	if (running)
		edma_ndo_open(netdev);

	return ret;
}

static int edma_qdx_quiesce(void *context, u32 native_rx_entries)
{
	struct edma_priv *priv = context;
	const struct edma_soc_data *soc = priv->soc;
	struct page_pool *pool = NULL;
	u8 order = edma_rx_page_order(EDMA_MAX_MTU);
	int ret;

	if (native_rx_entries < 2 || native_rx_entries > EDMA_RX_RING_MAX ||
	    !is_power_of_2(native_rx_entries)) {
		dev_err(&priv->pdev->dev, "invalid native_rx_entries: %u\n",
			native_rx_entries);
		return -EINVAL;
	}
	if (priv->shared)
		return -EBUSY;
	if (priv->rx_page_order < order || priv->rx_entries != native_rx_entries) {
		pool = edma_page_pool_create(priv, order, native_rx_entries);
		if (IS_ERR(pool))
			return PTR_ERR(pool);
	}

	netif_tx_disable(priv->netdev);
	edma_ndo_stop(priv->netdev);
	synchronize_irq(priv->txcmpl_irq);
	synchronize_irq(priv->rxfill_irq);
	synchronize_irq(priv->rxdesc_irq);
	WRITE_ONCE(priv->native_ready, false);
	if (pool) {
		/* NSS is still held: a reset may safely end old native DMA here. */
		ret = reset_control_assert(priv->rst);
		if (ret) {
			page_pool_destroy(pool);
			return ret;
		}
		udelay(100);
		edma_rings_drain(priv);
		page_pool_destroy(priv->page_pool);
		priv->page_pool = pool;
		priv->rx_entries = native_rx_entries;
		priv->rx_page_order = order;
		priv->rx_buffer_size = edma_rx_buffer_size(order);
		ret = edma_hw_init(priv);
		if (ret)
			return ret;
		WRITE_ONCE(priv->native_ready, false);
	}

	ret = regmap_clear_bits(priv->regmap,
			EDMA_REG_TXDESC_CTRL(soc->txdesc_ring), EDMA_TXDESC_TX_EN);
	if (ret)
		return ret;
	ret = regmap_clear_bits(priv->regmap,
			EDMA_REG_RXDESC_CTRL(soc->rxdesc_ring), EDMA_RXDESC_RX_EN);
	if (ret)
		return ret;
	ret = regmap_clear_bits(priv->regmap,
			EDMA_REG_RXFILL_RING_EN(soc->rxfill_ring), EDMA_RXFILL_RING_EN);
	if (ret)
		return ret;
	ret = regmap_set_bits(priv->regmap, EDMA_REG_PORT_CTRL,
			      EDMA_PORT_EDMA_EN | EDMA_PORT_PAD_EN);
	if (!ret)
		WRITE_ONCE(priv->shared, true);
	return ret;
}

static int edma_qdx_resume_shared(void *context)
{
	struct edma_priv *priv = context;
	const struct edma_soc_data *soc = priv->soc;
	u32 values[4], route, shift, expected;
	int ret;

	if (!priv->shared || priv->native_ready ||
	    !priv->txdesc_ring.desc || !priv->txcmpl_ring.desc ||
	    !priv->rxfill_ring.desc || !priv->rxdesc_ring.desc)
		return -EINVAL;

	/* Each block is base, producer, consumer, size. Never reset an index. */
	ret = regmap_bulk_read(priv->regmap, EDMA_REG_TXDESC_BA(soc->txdesc_ring),
			       values, ARRAY_SIZE(values));
	if (ret)
		return ret;
	if (values[0] != lower_32_bits(priv->txdesc_ring.dma) ||
	    (values[1] & EDMA_TXDESC_PROD_IDX_MASK) >= priv->txdesc_ring.count ||
	    (values[2] & EDMA_TXDESC_CONS_IDX_MASK) >= priv->txdesc_ring.count ||
	    (values[3] & EDMA_TXDESC_RING_SIZE_MASK) != priv->txdesc_ring.count)
		return -EIO;

	ret = regmap_bulk_read(priv->regmap,
			       EDMA_REG_TXCMPL_BA(soc->txcmpl_base, soc->txcmpl_ring),
			       values, ARRAY_SIZE(values));
	if (ret)
		return ret;
	if (values[0] != lower_32_bits(priv->txcmpl_ring.dma) ||
	    (values[1] & EDMA_TXCMPL_PROD_IDX_MASK) >= priv->txcmpl_ring.count ||
	    (values[2] & EDMA_TXCMPL_CONS_IDX_MASK) >= priv->txcmpl_ring.count ||
	    (values[3] & EDMA_TXDESC_RING_SIZE_MASK) != priv->txcmpl_ring.count)
		return -EIO;

	ret = regmap_bulk_read(priv->regmap, EDMA_REG_RXFILL_BA(soc->rxfill_ring),
			       values, ARRAY_SIZE(values));
	if (ret)
		return ret;
	if (values[0] != lower_32_bits(priv->rxfill_ring.dma) ||
	    (values[1] & EDMA_RXFILL_PROD_IDX_MASK) >= priv->rxfill_ring.count ||
	    (values[2] & EDMA_RXFILL_CONS_IDX_MASK) >= priv->rxfill_ring.count ||
	    (values[3] & EDMA_RXFILL_RING_SIZE_MASK) != priv->rxfill_ring.count)
		return -EIO;

	ret = regmap_bulk_read(priv->regmap, EDMA_REG_RXDESC_BA(soc->rxdesc_ring),
			       values, ARRAY_SIZE(values));
	if (ret)
		return ret;
	expected = priv->rxdesc_ring.count |
		   (EDMA_RX_PREHDR_SIZE << EDMA_RXDESC_PL_OFFSET_SHIFT);
	if (values[0] != lower_32_bits(priv->rxdesc_ring.dma) ||
	    (values[1] & EDMA_RXDESC_PROD_IDX_MASK) >= priv->rxdesc_ring.count ||
	    (values[2] & EDMA_RXDESC_CONS_IDX_MASK) >= priv->rxdesc_ring.count ||
	    (values[3] & (EDMA_RXDESC_RING_SIZE_MASK |
			  (EDMA_RXDESC_PL_OFFSET_MASK << EDMA_RXDESC_PL_OFFSET_SHIFT))) !=
	    expected)
		return -EIO;

	ret = regmap_read(priv->regmap, EDMA_QID2RID_TABLE_MEM(0), &route);
	if (ret)
		return ret;
	route &= EDMA_QID2RID_QUEUE0_MASK;
	if (route == soc->rxdesc_ring)
		return -EIO;
	priv->firmware_rx_ring = route;

	shift = (soc->txdesc_ring % EDMA_RING_MAP_ENTRIES) * EDMA_RING_MAP_BITS;
	ret = regmap_update_bits(priv->regmap,
			EDMA_REG_TXDESC2CMPL_MAP(soc->txdesc_ring / EDMA_RING_MAP_ENTRIES),
			EDMA_RING_MAP_MASK << shift, soc->txcmpl_ring << shift);
	if (ret)
		return ret;
	shift = (soc->rxdesc_ring % EDMA_RING_MAP_ENTRIES) * EDMA_RING_MAP_BITS;
	ret = regmap_update_bits(priv->regmap,
			EDMA_REG_RXDESC2FILL_MAP_0 +
			4 * (soc->rxdesc_ring / EDMA_RING_MAP_ENTRIES),
			EDMA_RING_MAP_MASK << shift, soc->rxfill_ring << shift);
	if (ret)
		return ret;
	ret = regmap_set_bits(priv->regmap,
			      EDMA_REG_TXDESC_CTRL(soc->txdesc_ring), EDMA_TXDESC_TX_EN);
	if (ret)
		return ret;
	ret = regmap_set_bits(priv->regmap,
			      EDMA_REG_RXFILL_RING_EN(soc->rxfill_ring), EDMA_RXFILL_RING_EN);
	if (ret)
		return ret;
	ret = regmap_set_bits(priv->regmap,
			      EDMA_REG_RXDESC_CTRL(soc->rxdesc_ring), EDMA_RXDESC_RX_EN);
	if (ret)
		return ret;
	if (netif_running(priv->netdev)) {
		napi_enable(&priv->tx_napi);
		napi_enable(&priv->rx_napi);
		priv->napi_active = true;
		ret = regmap_write(priv->regmap,
			EDMA_REG_TX_INT_MASK(soc->tx_int_base, soc->txcmpl_ring),
			EDMA_TX_INT_MASK);
		if (!ret)
			ret = regmap_write(priv->regmap,
				EDMA_REG_RXFILL_INT_MASK(soc->rxfill_ring),
				EDMA_RXFILL_INT_MASK);
		if (!ret)
			ret = regmap_write(priv->regmap,
				EDMA_REG_RXDESC_INT_MASK(soc->rxdesc_ring),
				EDMA_RXDESC_INT_MASK_PKT_INT);
		if (ret) {
			edma_ndo_stop(priv->netdev);
			return ret;
		}
	}
	WRITE_ONCE(priv->native_ready, true);
	spin_lock_bh(&priv->completion_lock);
	priv->tx_admin = netif_running(priv->netdev);
	spin_unlock_bh(&priv->completion_lock);
	edma_tx_retry(priv);
	return 0;
}

static int edma_qdx_map_rx_queue(void *context, u16 queue, bool firmware)
{
	struct edma_priv *priv = context;
	u32 route, value, reg, shift, mask;
	int ret;

	if (!priv->native_ready || (firmware && !priv->shared))
		return -EIO;
	if (queue >= EDMA_QID2RID_UNICAST_QUEUES)
		return -ERANGE;
	/* PPE owns allocation and its affected dequeue hold. EDMA writes only
	 * this actual queue's four-bit ring field, then verifies the same field.
	 */
	reg = EDMA_QID2RID_TABLE_MEM(queue / EDMA_QID2RID_QUEUES_PER_WORD);
	shift = (queue % EDMA_QID2RID_QUEUES_PER_WORD) * 4;
	mask = EDMA_QID2RID_QUEUE0_MASK << shift;
	route = firmware ? priv->firmware_rx_ring : priv->soc->rxdesc_ring;
	route <<= shift;
	ret = regmap_update_bits(priv->regmap, reg, mask, route);
	if (ret)
		return ret;
	ret = regmap_read(priv->regmap, reg, &value);
	if (ret)
		return ret;
	return (value & mask) == route ? 0 : -EIO;
}

static int edma_qdx_restore(void *context)
{
	struct edma_priv *priv = context;
	struct page_pool *pool;
	u8 order = edma_rx_page_order(priv->netdev->mtu);
	int ret;

	WRITE_ONCE(priv->native_ready, false);
	netif_tx_disable(priv->netdev);
	edma_ndo_stop(priv->netdev);
	ret = reset_control_assert(priv->rst);
	if (ret)
		return ret;
	udelay(100);
	edma_rings_drain(priv);
	page_pool_destroy(priv->page_pool);
	priv->page_pool = NULL;
	pool = edma_page_pool_create(priv, order, priv->rx_entries);
	if (IS_ERR(pool))
		return PTR_ERR(pool);
	priv->page_pool = pool;
	priv->rx_page_order = order;
	priv->rx_buffer_size = edma_rx_buffer_size(order);
	ret = edma_hw_init(priv);
	if (ret)
		return ret;
	WRITE_ONCE(priv->shared, false);
	return 0;
}

static int edma_qdx_activate(void *context)
{
	struct edma_priv *priv = context;
	const struct edma_soc_data *soc = priv->soc;
	int ret;

	if (!netif_running(priv->netdev))
		return 0;
	napi_enable(&priv->tx_napi);
	napi_enable(&priv->rx_napi);
	priv->napi_active = true;
	ret = regmap_write(priv->regmap,
		EDMA_REG_TX_INT_MASK(soc->tx_int_base, soc->txcmpl_ring), EDMA_TX_INT_MASK);
	if (!ret)
		ret = regmap_write(priv->regmap,
			EDMA_REG_RXFILL_INT_MASK(soc->rxfill_ring),
				EDMA_RXFILL_INT_MASK);
	if (!ret)
		ret = regmap_write(priv->regmap, EDMA_REG_RXDESC_INT_MASK(soc->rxdesc_ring),
			EDMA_RXDESC_INT_MASK_PKT_INT);
	if (ret) {
		edma_ndo_stop(priv->netdev);
		WRITE_ONCE(priv->native_ready, false);
	} else {
		spin_lock_bh(&priv->completion_lock);
		priv->tx_admin = true;
		spin_unlock_bh(&priv->completion_lock);
		edma_tx_retry(priv);
	}
	return ret;
}

static const struct qdx_edma_ops edma_qdx_ops = {
	.activate = edma_qdx_activate,
	.quiesce = edma_qdx_quiesce,
	.resume_shared = edma_qdx_resume_shared,
	.map_rx_queue = edma_qdx_map_rx_queue,
	.resource_progress = edma_tx_retry,
	.tx_gate = edma_tx_gate,
	.complete_tx = edma_tx_complete,
	.restore = edma_qdx_restore,
	.receive = edma_receive,
};

static const struct regmap_config edma_regmap_cfg = {
	.reg_bits = 32,
	.reg_stride = 4,
	.val_bits = 32,
};

/*
 * The conduit is a DMA engine behind the switch and has no address of its
 * own, so boards describe none: fall back to the switch this conduit serves,
 * whose ports carry the board's addresses either from DT or patched in by
 * the bootloader. DSA user ports without one of their own inherit whatever
 * ends up here.
 */
static int edma_get_mac_address(struct net_device *netdev,
				struct device_node *np)
{
	struct device_node *cpu_port;
	int ret;

	ret = of_get_ethdev_address(np, netdev);
	if (!ret || ret == -EPROBE_DEFER)
		return ret;

	for_each_node_with_property(cpu_port, "ethernet") {
		struct device_node *conduit __free(device_node) =
			of_parse_phandle(cpu_port, "ethernet", 0);

		if (conduit != np)
			continue;

		for_each_available_child_of_node_scoped(cpu_port->parent, port) {
			ret = of_get_ethdev_address(port, netdev);
			if (!ret || ret == -EPROBE_DEFER) {
				of_node_put(cpu_port);
				return ret;
			}
		}
	}

	return -ENODEV;
}

static int edma_probe(struct platform_device *pdev)
{
	struct clk_bulk_data *clks;
	struct device *dev = &pdev->dev;
	struct reset_control *rst;
	struct net_device *netdev;
	struct edma_priv *priv;
	struct regmap *regmap;
	void __iomem *base;
	int ret;

	ret = devm_clk_bulk_get_all_enabled(dev, &clks);
	if (ret < 0)
		return ret;

	rst = devm_reset_control_get(dev, EDMA_HW_RESET_ID);
	if (IS_ERR(rst))
		return PTR_ERR(rst);

	base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(base))
		return dev_err_probe(dev, PTR_ERR(base), "failed to ioremap resource");

	regmap = devm_regmap_init_mmio(dev, base, &edma_regmap_cfg);
	if (IS_ERR(regmap))
		return dev_err_probe(dev, PTR_ERR(regmap), "failed to init regmap");

	ret = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(32));
	if (ret)
		return ret;

	netdev = devm_alloc_etherdev(dev, sizeof(*priv));
	if (!netdev)
		return -ENOMEM;

	priv = netdev_priv(netdev);
	priv->netdev = netdev;
	priv->regmap = regmap;
	priv->rst = rst;
	spin_lock_init(&priv->tx_lock);
	spin_lock_init(&priv->completion_lock);
	INIT_LIST_HEAD(&priv->ft_bindings);
	INIT_LIST_HEAD(&priv->wait.resource.node);
	refcount_set(&priv->wait.resource.calls, 0);
	priv->wait.queue = netdev_get_tx_queue(netdev, 0);
	priv->wait.resource.owner = (struct qdx_owner) {
		.module = THIS_MODULE, .object = priv,
		.get = edma_wait_get, .put = edma_wait_put,
	};
	priv->wait.resource.progress = edma_tx_retry;
	priv->rx_entries = EDMA_RX_RING_SIZE;
	priv->pdev = pdev;
	priv->soc = device_get_match_data(dev);

	ret = edma_get_mac_address(netdev, dev->of_node);
	if (ret == -EPROBE_DEFER)
		return dev_err_probe(dev, ret, "failed to get MAC address\n");
	if (ret)
		eth_hw_addr_random(netdev);

	priv->rx_page_order = edma_rx_page_order(netdev->mtu);
	priv->rx_buffer_size = edma_rx_buffer_size(priv->rx_page_order);
	priv->page_pool = edma_page_pool_create(priv, priv->rx_page_order,
					       priv->rx_entries);
	if (IS_ERR(priv->page_pool))
		return PTR_ERR(priv->page_pool);

	ret = edma_hw_init(priv);
	if (ret)
		goto err_page_pool;

	SET_NETDEV_DEV(netdev, dev);
	netdev->dev.of_node = dev->of_node;
	netdev->netdev_ops = &edma_netdev_ops;
	netdev->features = NETIF_F_GRO;
	netdev->pcpu_stat_type = NETDEV_PCPU_STAT_TSTATS;
	netdev->watchdog_timeo = 5 * HZ;
	netdev->max_mtu = EDMA_MAX_MTU;
	netdev->needed_headroom = EDMA_TX_PREHDR_SIZE;
	netdev->ethtool_ops = &edma_ethtool_ops;

	priv->netdev = netdev;

	netif_napi_add(netdev, &priv->tx_napi, edma_tx_napi);
	netif_napi_add(netdev, &priv->rx_napi, edma_rx_napi);

	ret = edma_irq_init(priv);
	if (ret)
		goto err_irq;

	ret = register_netdev(netdev);
	if (ret) {
		dev_warn(dev, "failed to register conduit netdevice\n");
		goto err_irq;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
	ret = dev_set_threaded(netdev, NETDEV_NAPI_THREADED_ENABLED);
#else
	ret = dev_set_threaded(netdev, true);
#endif
	if (ret)
		dev_warn(dev, "failed to enable threaded NAPI: %d\n", ret);

	platform_set_drvdata(pdev, priv);
	if (of_device_is_compatible(dev->of_node, "qualcomm,ipq8074-edma")) {
		struct qdx_edma_info info = {
			.dev = dev,
			.conduit = netdev,
			.ops = &edma_qdx_ops,
			.context = priv,
			.max_frame = EDMA_MAX_FRAME_SIZE,
			.tx_min_size = priv->soc->tx_min_size,
		};

		/* Native preparation takes RTNL before using this backpointer. */
		rtnl_lock();
		priv->qdx = qdx_edma_attach(&info);
		ret = PTR_ERR_OR_ZERO(priv->qdx);
		if (ret)
			priv->qdx = NULL;
		rtnl_unlock();
		if (ret) {
			unregister_netdev(netdev);
			goto err_irq;
		}
	}
	return 0;

err_irq:
	netif_napi_del(&priv->tx_napi);
	netif_napi_del(&priv->rx_napi);
	edma_hw_stop(priv);
	edma_rings_drain(priv);
err_page_pool:
	page_pool_destroy(priv->page_pool);
	return ret;
}

static void edma_remove(struct platform_device *pdev)
{
	struct edma_priv *priv = platform_get_drvdata(pdev);

	spin_lock_bh(&priv->completion_lock);
	priv->detaching = true;
	netif_tx_stop_queue(priv->wait.queue);
	edma_tx_wait_clear_locked(priv);
	spin_unlock_bh(&priv->completion_lock);
	netif_tx_disable(priv->netdev);
	qdx_resource_wait_drain(&priv->wait.resource);
	qdx_edma_detach(priv->qdx);
	priv->qdx = NULL;
	unregister_netdev(priv->netdev);
	netif_napi_del(&priv->tx_napi);
	netif_napi_del(&priv->rx_napi);
	edma_hw_stop(priv);
	edma_rings_drain(priv);
	page_pool_destroy(priv->page_pool);
}

static const struct edma_soc_data ipq60xx_data = {
	.txcmpl_base = 0x79000,
	.tx_int_base = 0x91000,
	.misc_int_mask = 0xff,
	.txdesc_ring = 23,
	.txcmpl_ring = 23,
	.rxfill_ring = 7,
	.rxdesc_ring = 15,
	.burst_enable = true,
	.axiw_enable = true,
};

static const struct edma_soc_data ipq807x_data = {
	.txcmpl_base = 0x19000,
	.tx_int_base = 0x21000,
	.misc_int_mask = 0x1ff,
	.txdesc_ring = 23,
	.txcmpl_ring = 7,
	.rxfill_ring = 7,
	.rxdesc_ring = 15,
	.tx_min_size = 33,
};

static const struct of_device_id edma_of_match[] = {
	{ .compatible = "qualcomm,ipq6018-edma", .data = &ipq60xx_data },
	{ .compatible = "qualcomm,ipq8074-edma", .data = &ipq807x_data },
	{},
};

static struct platform_driver edma_driver = {
	.driver = {
		.name = "qca-edma",
		.of_match_table = edma_of_match,
	},
	.probe = edma_probe,
	.remove = edma_remove,
};

module_platform_driver(edma_driver);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Qualcomm IPQ EDMA Ethernet driver");
