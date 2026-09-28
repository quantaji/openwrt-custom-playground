// SPDX-License-Identifier: GPL-2.0-or-later OR MIT

#include "qca_ppe.h"
#include <linux/clk.h>
#include <linux/math64.h>
#include <linux/overflow.h>
#include <linux/qdx/tc.h>
#include <linux/rtnetlink.h>
#include <linux/slab.h>

#define PPE_QDX_RX_PROFILES	3
#define PPE_QDX_PROFILE_ENTRIES	(3 * PPE_MAX_VPORT)
#define PPE_QDX_QUEUE_WAIT_US	10000

struct qca_ppe_rx_resource {
	unsigned int port;
	unsigned int users;
	unsigned int holds;
	u8 profile;
	u8 queue;
	u8 priority;
	u8 native_profile;
	bool restored;
	bool closing;
	u32 flow;
	u32 committed_sp;
	u32 excess_sp;
	u32 enqueue;
	u32 dequeue;
	u32 saved[PPE_QDX_PROFILE_ENTRIES];
	u32 selected[PPE_QDX_PROFILE_ENTRIES];
};

struct qdx_ppe_rx {
	struct qca_ppe_rx_resource *resource;
	bool held;
};

struct qdx_ppe_tx {
	struct list_head list;
	unsigned int port;
	u16 queue;
	bool held;
	bool orphan;
};

struct psch_tdm_entry {
	u8 en_port;
	u8 de_port;
};

struct bm_tdm_entry {
	u8 port;
	u8 dir;
};

enum psch_tdm_port {
	TDM_PORT_CPU = 0,
	TDM_PORT_PHY_1,
	TDM_PORT_PHY_2,
	TDM_PORT_PHY_3,
	TDM_PORT_PHY_4,
	TDM_PORT_FAB_0,
	TDM_PORT_FAB_1,
	TDM_PORT_PHY_7,
};

enum bm_tdm_dir {
	TDM_DIR_INGRESS = 0,
	TDM_DIR_EGRESS,
};

/* CPPE (IPQ60xx) port scheduler TDM -- 50 entries */
const struct psch_tdm_entry cppe_psch_tdm[] = {
	{ TDM_PORT_CPU, TDM_PORT_FAB_1 },
	{ TDM_PORT_PHY_3, TDM_PORT_CPU },
	{ TDM_PORT_FAB_1, TDM_PORT_FAB_0 },
	{ TDM_PORT_CPU, TDM_PORT_PHY_1 },
	{ TDM_PORT_FAB_0, TDM_PORT_FAB_1 },
	{ TDM_PORT_PHY_1, TDM_PORT_CPU },
	{ TDM_PORT_FAB_1, TDM_PORT_PHY_4 },
	{ TDM_PORT_CPU, TDM_PORT_FAB_0 },
	{ TDM_PORT_PHY_4, TDM_PORT_FAB_1 },
	{ TDM_PORT_FAB_0, TDM_PORT_CPU },
	{ TDM_PORT_FAB_1, TDM_PORT_PHY_7 },
	{ TDM_PORT_CPU, TDM_PORT_FAB_0 },
	{ TDM_PORT_PHY_7, TDM_PORT_FAB_1 },
	{ TDM_PORT_FAB_0, TDM_PORT_CPU },
	{ TDM_PORT_FAB_1, TDM_PORT_PHY_2 },
	{ TDM_PORT_CPU, TDM_PORT_FAB_1 },
	{ TDM_PORT_PHY_2, TDM_PORT_FAB_0 },
	{ TDM_PORT_FAB_1, TDM_PORT_PHY_4 },
	{ TDM_PORT_FAB_0, TDM_PORT_CPU },
	{ TDM_PORT_PHY_4, TDM_PORT_FAB_1 },
	{ TDM_PORT_CPU, TDM_PORT_PHY_7 },
	{ TDM_PORT_FAB_1, TDM_PORT_FAB_0 },
	{ TDM_PORT_PHY_7, TDM_PORT_CPU },
	{ TDM_PORT_FAB_0, TDM_PORT_FAB_1 },
	{ TDM_PORT_CPU, TDM_PORT_PHY_3 },
	{ TDM_PORT_FAB_1, TDM_PORT_PHY_4 },
	{ TDM_PORT_PHY_3, TDM_PORT_CPU },
	{ TDM_PORT_PHY_4, TDM_PORT_FAB_1 },
	{ TDM_PORT_CPU, TDM_PORT_FAB_0 },
	{ TDM_PORT_FAB_1, TDM_PORT_PHY_1 },
	{ TDM_PORT_FAB_0, TDM_PORT_CPU },
	{ TDM_PORT_PHY_1, TDM_PORT_FAB_1 },
	{ TDM_PORT_CPU, TDM_PORT_FAB_0 },
	{ TDM_PORT_FAB_1, TDM_PORT_PHY_7 },
	{ TDM_PORT_FAB_0, TDM_PORT_CPU },
	{ TDM_PORT_PHY_7, TDM_PORT_FAB_1 },
	{ TDM_PORT_CPU, TDM_PORT_PHY_4 },
	{ TDM_PORT_FAB_1, TDM_PORT_FAB_0 },
	{ TDM_PORT_PHY_4, TDM_PORT_FAB_1 },
	{ TDM_PORT_FAB_0, TDM_PORT_CPU },
	{ TDM_PORT_FAB_1, TDM_PORT_PHY_2 },
	{ TDM_PORT_CPU, TDM_PORT_FAB_0 },
	{ TDM_PORT_PHY_2, TDM_PORT_FAB_1 },
	{ TDM_PORT_FAB_0, TDM_PORT_CPU },
	{ TDM_PORT_FAB_1, TDM_PORT_PHY_7 },
	{ TDM_PORT_CPU, TDM_PORT_PHY_4 },
	{ TDM_PORT_PHY_7, TDM_PORT_FAB_1 },
	{ TDM_PORT_PHY_4, TDM_PORT_FAB_0 },
	{ TDM_PORT_FAB_1, TDM_PORT_CPU },
	{ TDM_PORT_FAB_0, TDM_PORT_PHY_3 },
};

/* HPPE (IPQ807x) port scheduler TDM -- 50 entries
 * Source: ssdk_hppe.c port_schedulerTDM_PORT_CPU_tbl[] */
const struct psch_tdm_entry hppe_psch_tdm[] = {
	{ TDM_PORT_FAB_1, TDM_PORT_CPU },
	{ TDM_PORT_PHY_4, TDM_PORT_FAB_0 },
	{ TDM_PORT_CPU, TDM_PORT_FAB_1 },
	{ TDM_PORT_FAB_0, TDM_PORT_CPU },
	{ TDM_PORT_FAB_1, TDM_PORT_PHY_7 },
	{ TDM_PORT_CPU, TDM_PORT_FAB_0 },
	{ TDM_PORT_PHY_7, TDM_PORT_FAB_1 },
	{ TDM_PORT_FAB_0, TDM_PORT_CPU },
	{ TDM_PORT_FAB_1, TDM_PORT_PHY_1 },
	{ TDM_PORT_CPU, TDM_PORT_FAB_0 },
	{ TDM_PORT_PHY_1, TDM_PORT_CPU },
	{ TDM_PORT_FAB_0, TDM_PORT_FAB_1 },
	{ TDM_PORT_CPU, TDM_PORT_PHY_2 },
	{ TDM_PORT_FAB_1, TDM_PORT_FAB_0 },
	{ TDM_PORT_PHY_2, TDM_PORT_CPU },
	{ TDM_PORT_FAB_0, TDM_PORT_FAB_1 },
	{ TDM_PORT_CPU, TDM_PORT_PHY_7 },
	{ TDM_PORT_FAB_1, TDM_PORT_CPU },
	{ TDM_PORT_PHY_7, TDM_PORT_FAB_0 },
	{ TDM_PORT_CPU, TDM_PORT_FAB_1 },
	{ TDM_PORT_FAB_0, TDM_PORT_PHY_3 },
	{ TDM_PORT_FAB_1, TDM_PORT_CPU },
	{ TDM_PORT_PHY_3, TDM_PORT_FAB_0 },
	{ TDM_PORT_CPU, TDM_PORT_FAB_1 },
	{ TDM_PORT_FAB_0, TDM_PORT_CPU },
	{ TDM_PORT_FAB_1, TDM_PORT_PHY_4 },
	{ TDM_PORT_CPU, TDM_PORT_FAB_0 },
	{ TDM_PORT_PHY_4, TDM_PORT_FAB_1 },
	{ TDM_PORT_FAB_0, TDM_PORT_CPU },
	{ TDM_PORT_FAB_1, TDM_PORT_PHY_7 },
	{ TDM_PORT_CPU, TDM_PORT_FAB_0 },
	{ TDM_PORT_PHY_7, TDM_PORT_CPU },
	{ TDM_PORT_FAB_0, TDM_PORT_FAB_1 },
	{ TDM_PORT_CPU, TDM_PORT_PHY_1 },
	{ TDM_PORT_FAB_1, TDM_PORT_FAB_0 },
	{ TDM_PORT_PHY_1, TDM_PORT_CPU },
	{ TDM_PORT_FAB_0, TDM_PORT_FAB_1 },
	{ TDM_PORT_CPU, TDM_PORT_PHY_2 },
	{ TDM_PORT_FAB_1, TDM_PORT_CPU },
	{ TDM_PORT_PHY_2, TDM_PORT_FAB_0 },
	{ TDM_PORT_CPU, TDM_PORT_FAB_1 },
	{ TDM_PORT_FAB_0, TDM_PORT_PHY_7 },
	{ TDM_PORT_FAB_1, TDM_PORT_CPU },
	{ TDM_PORT_PHY_7, TDM_PORT_FAB_0 },
	{ TDM_PORT_CPU, TDM_PORT_FAB_1 },
	{ TDM_PORT_FAB_0, TDM_PORT_PHY_3 },
	{ TDM_PORT_FAB_1, TDM_PORT_CPU },
	{ TDM_PORT_PHY_3, TDM_PORT_FAB_0 },
	{ TDM_PORT_CPU, TDM_PORT_FAB_1 },
	{ TDM_PORT_FAB_0, TDM_PORT_PHY_4 },
};

/* CPPE buffer manager TDM -- 98 entries */
const struct bm_tdm_entry cppe_bm_tdm[] = {
	{ TDM_PORT_CPU, TDM_DIR_INGRESS },
	{ TDM_PORT_CPU, TDM_DIR_EGRESS },
	{ TDM_PORT_FAB_0, TDM_DIR_INGRESS },
	{ TDM_PORT_PHY_4, TDM_DIR_EGRESS },
	{ TDM_PORT_PHY_1, TDM_DIR_INGRESS },
	{ TDM_PORT_FAB_0, TDM_DIR_EGRESS },
	{ TDM_PORT_FAB_1, TDM_DIR_INGRESS },
	{ TDM_PORT_FAB_1, TDM_DIR_EGRESS },
	{ TDM_PORT_CPU, TDM_DIR_INGRESS },
	{ TDM_PORT_CPU, TDM_DIR_EGRESS },
	{ TDM_PORT_PHY_7, TDM_DIR_INGRESS },
	{ TDM_PORT_PHY_7, TDM_DIR_EGRESS },
	{ TDM_PORT_PHY_4, TDM_DIR_INGRESS },
	{ TDM_PORT_CPU, TDM_DIR_EGRESS },
	{ TDM_PORT_FAB_1, TDM_DIR_INGRESS },
	{ TDM_PORT_FAB_0, TDM_DIR_EGRESS },
	{ TDM_PORT_CPU, TDM_DIR_INGRESS },
	{ TDM_PORT_CPU, TDM_DIR_EGRESS },
	{ TDM_PORT_PHY_2, TDM_DIR_INGRESS },
	{ TDM_PORT_FAB_1, TDM_DIR_EGRESS },
	{ TDM_PORT_PHY_7, TDM_DIR_INGRESS },
	{ TDM_PORT_PHY_7, TDM_DIR_EGRESS },
	{ TDM_PORT_FAB_0, TDM_DIR_INGRESS },
	{ TDM_PORT_FAB_0, TDM_DIR_EGRESS },
	{ TDM_PORT_CPU, TDM_DIR_INGRESS },
	{ TDM_PORT_CPU, TDM_DIR_EGRESS },
	{ TDM_PORT_FAB_1, TDM_DIR_INGRESS },
	{ TDM_PORT_FAB_1, TDM_DIR_EGRESS },
	{ TDM_PORT_PHY_7, TDM_DIR_INGRESS },
	{ TDM_PORT_PHY_3, TDM_DIR_EGRESS },
	{ TDM_PORT_FAB_0, TDM_DIR_INGRESS },
	{ TDM_PORT_PHY_7, TDM_DIR_EGRESS },
	{ TDM_PORT_CPU, TDM_DIR_INGRESS },
	{ TDM_PORT_CPU, TDM_DIR_EGRESS },
	{ TDM_PORT_FAB_1, TDM_DIR_INGRESS },
	{ TDM_PORT_FAB_0, TDM_DIR_EGRESS },
	{ TDM_PORT_CPU, TDM_DIR_INGRESS },
	{ TDM_PORT_FAB_1, TDM_DIR_EGRESS },
	{ TDM_PORT_PHY_7, TDM_DIR_INGRESS },
	{ TDM_PORT_PHY_7, TDM_DIR_EGRESS },
	{ TDM_PORT_CPU, TDM_DIR_INGRESS },
	{ TDM_PORT_CPU, TDM_DIR_EGRESS },
	{ TDM_PORT_FAB_0, TDM_DIR_INGRESS },
	{ TDM_PORT_PHY_4, TDM_DIR_EGRESS },
	{ TDM_PORT_FAB_1, TDM_DIR_INGRESS },
	{ TDM_PORT_FAB_1, TDM_DIR_EGRESS },
	{ TDM_PORT_PHY_7, TDM_DIR_INGRESS },
	{ TDM_PORT_PHY_7, TDM_DIR_EGRESS },
	{ TDM_PORT_CPU, TDM_DIR_INGRESS },
	{ TDM_PORT_CPU, TDM_DIR_EGRESS },
	{ TDM_PORT_PHY_4, TDM_DIR_INGRESS },
	{ TDM_PORT_FAB_0, TDM_DIR_EGRESS },
	{ TDM_PORT_FAB_0, TDM_DIR_INGRESS },
	{ TDM_PORT_PHY_1, TDM_DIR_EGRESS },
	{ TDM_PORT_FAB_1, TDM_DIR_INGRESS },
	{ TDM_PORT_FAB_1, TDM_DIR_EGRESS },
	{ TDM_PORT_CPU, TDM_DIR_INGRESS },
	{ TDM_PORT_CPU, TDM_DIR_EGRESS },
	{ TDM_PORT_PHY_7, TDM_DIR_INGRESS },
	{ TDM_PORT_PHY_7, TDM_DIR_EGRESS },
	{ TDM_PORT_CPU, TDM_DIR_INGRESS },
	{ TDM_PORT_PHY_4, TDM_DIR_EGRESS },
	{ TDM_PORT_FAB_0, TDM_DIR_INGRESS },
	{ TDM_PORT_FAB_1, TDM_DIR_EGRESS },
	{ TDM_PORT_CPU, TDM_DIR_INGRESS },
	{ TDM_PORT_CPU, TDM_DIR_EGRESS },
	{ TDM_PORT_FAB_1, TDM_DIR_INGRESS },
	{ TDM_PORT_PHY_2, TDM_DIR_EGRESS },
	{ TDM_PORT_PHY_7, TDM_DIR_INGRESS },
	{ TDM_PORT_PHY_7, TDM_DIR_EGRESS },
	{ TDM_PORT_FAB_0, TDM_DIR_INGRESS },
	{ TDM_PORT_FAB_0, TDM_DIR_EGRESS },
	{ TDM_PORT_CPU, TDM_DIR_INGRESS },
	{ TDM_PORT_CPU, TDM_DIR_EGRESS },
	{ TDM_PORT_FAB_1, TDM_DIR_INGRESS },
	{ TDM_PORT_FAB_1, TDM_DIR_EGRESS },
	{ TDM_PORT_PHY_3, TDM_DIR_INGRESS },
	{ TDM_PORT_PHY_7, TDM_DIR_EGRESS },
	{ TDM_PORT_PHY_7, TDM_DIR_INGRESS },
	{ TDM_PORT_FAB_0, TDM_DIR_EGRESS },
	{ TDM_PORT_CPU, TDM_DIR_INGRESS },
	{ TDM_PORT_CPU, TDM_DIR_EGRESS },
	{ TDM_PORT_FAB_0, TDM_DIR_INGRESS },
	{ TDM_PORT_FAB_1, TDM_DIR_EGRESS },
	{ TDM_PORT_FAB_1, TDM_DIR_INGRESS },
	{ TDM_PORT_CPU, TDM_DIR_EGRESS },
	{ TDM_PORT_PHY_7, TDM_DIR_INGRESS },
	{ TDM_PORT_PHY_7, TDM_DIR_EGRESS },
	{ TDM_PORT_CPU, TDM_DIR_INGRESS },
	{ TDM_PORT_CPU, TDM_DIR_EGRESS },
	{ TDM_PORT_PHY_4, TDM_DIR_INGRESS },
	{ TDM_PORT_FAB_0, TDM_DIR_EGRESS },
	{ TDM_PORT_FAB_1, TDM_DIR_INGRESS },
	{ TDM_PORT_FAB_1, TDM_DIR_EGRESS },
	{ TDM_PORT_PHY_7, TDM_DIR_INGRESS },
	{ TDM_PORT_PHY_7, TDM_DIR_EGRESS },
	{ TDM_PORT_CPU, TDM_DIR_INGRESS },
	{ TDM_PORT_CPU, TDM_DIR_EGRESS },
};

/* HPPE buffer manager TDM -- 96 entries
 * Source: ssdk_hppe.c port_tdmTDM_PORT_CPU_tbl[] */
const struct bm_tdm_entry hppe_bm_tdm[] = {
	{ TDM_PORT_CPU, TDM_DIR_INGRESS },
	{ TDM_PORT_FAB_0, TDM_DIR_EGRESS },
	{ TDM_PORT_FAB_0, TDM_DIR_INGRESS },
	{ TDM_PORT_PHY_7, TDM_DIR_EGRESS },
	{ TDM_PORT_PHY_1, TDM_DIR_INGRESS },
	{ TDM_PORT_FAB_1, TDM_DIR_EGRESS },
	{ TDM_PORT_FAB_1, TDM_DIR_INGRESS },
	{ TDM_PORT_CPU, TDM_DIR_EGRESS },
	{ TDM_PORT_CPU, TDM_DIR_INGRESS },
	{ TDM_PORT_PHY_7, TDM_DIR_EGRESS },
	{ TDM_PORT_PHY_7, TDM_DIR_INGRESS },
	{ TDM_PORT_FAB_0, TDM_DIR_EGRESS },
	{ TDM_PORT_FAB_0, TDM_DIR_INGRESS },
	{ TDM_PORT_CPU, TDM_DIR_EGRESS },
	{ TDM_PORT_FAB_1, TDM_DIR_INGRESS },
	{ TDM_PORT_FAB_1, TDM_DIR_EGRESS },
	{ TDM_PORT_CPU, TDM_DIR_INGRESS },
	{ TDM_PORT_PHY_3, TDM_DIR_EGRESS },
	{ TDM_PORT_PHY_2, TDM_DIR_INGRESS },
	{ TDM_PORT_PHY_7, TDM_DIR_EGRESS },
	{ TDM_PORT_PHY_7, TDM_DIR_INGRESS },
	{ TDM_PORT_FAB_0, TDM_DIR_EGRESS },
	{ TDM_PORT_FAB_0, TDM_DIR_INGRESS },
	{ TDM_PORT_CPU, TDM_DIR_EGRESS },
	{ TDM_PORT_CPU, TDM_DIR_INGRESS },
	{ TDM_PORT_FAB_1, TDM_DIR_EGRESS },
	{ TDM_PORT_FAB_1, TDM_DIR_INGRESS },
	{ TDM_PORT_CPU, TDM_DIR_EGRESS },
	{ TDM_PORT_PHY_7, TDM_DIR_INGRESS },
	{ TDM_PORT_PHY_7, TDM_DIR_EGRESS },
	{ TDM_PORT_FAB_0, TDM_DIR_INGRESS },
	{ TDM_PORT_FAB_0, TDM_DIR_EGRESS },
	{ TDM_PORT_CPU, TDM_DIR_INGRESS },
	{ TDM_PORT_CPU, TDM_DIR_EGRESS },
	{ TDM_PORT_FAB_1, TDM_DIR_INGRESS },
	{ TDM_PORT_FAB_1, TDM_DIR_EGRESS },
	{ TDM_PORT_CPU, TDM_DIR_INGRESS },
	{ TDM_PORT_CPU, TDM_DIR_EGRESS },
	{ TDM_PORT_PHY_7, TDM_DIR_INGRESS },
	{ TDM_PORT_PHY_7, TDM_DIR_EGRESS },
	{ TDM_PORT_CPU, TDM_DIR_INGRESS },
	{ TDM_PORT_FAB_0, TDM_DIR_EGRESS },
	{ TDM_PORT_FAB_0, TDM_DIR_INGRESS },
	{ TDM_PORT_PHY_4, TDM_DIR_EGRESS },
	{ TDM_PORT_FAB_1, TDM_DIR_INGRESS },
	{ TDM_PORT_FAB_1, TDM_DIR_EGRESS },
	{ TDM_PORT_PHY_7, TDM_DIR_INGRESS },
	{ TDM_PORT_CPU, TDM_DIR_EGRESS },
	{ TDM_PORT_CPU, TDM_DIR_INGRESS },
	{ TDM_PORT_PHY_7, TDM_DIR_EGRESS },
	{ TDM_PORT_PHY_4, TDM_DIR_INGRESS },
	{ TDM_PORT_FAB_0, TDM_DIR_EGRESS },
	{ TDM_PORT_FAB_0, TDM_DIR_INGRESS },
	{ TDM_PORT_CPU, TDM_DIR_EGRESS },
	{ TDM_PORT_FAB_1, TDM_DIR_INGRESS },
	{ TDM_PORT_FAB_1, TDM_DIR_EGRESS },
	{ TDM_PORT_CPU, TDM_DIR_INGRESS },
	{ TDM_PORT_PHY_1, TDM_DIR_EGRESS },
	{ TDM_PORT_PHY_7, TDM_DIR_INGRESS },
	{ TDM_PORT_PHY_7, TDM_DIR_EGRESS },
	{ TDM_PORT_CPU, TDM_DIR_INGRESS },
	{ TDM_PORT_FAB_0, TDM_DIR_EGRESS },
	{ TDM_PORT_FAB_0, TDM_DIR_INGRESS },
	{ TDM_PORT_CPU, TDM_DIR_EGRESS },
	{ TDM_PORT_CPU, TDM_DIR_INGRESS },
	{ TDM_PORT_FAB_1, TDM_DIR_EGRESS },
	{ TDM_PORT_FAB_1, TDM_DIR_INGRESS },
	{ TDM_PORT_CPU, TDM_DIR_EGRESS },
	{ TDM_PORT_PHY_7, TDM_DIR_INGRESS },
	{ TDM_PORT_PHY_7, TDM_DIR_EGRESS },
	{ TDM_PORT_FAB_0, TDM_DIR_INGRESS },
	{ TDM_PORT_FAB_0, TDM_DIR_EGRESS },
	{ TDM_PORT_CPU, TDM_DIR_INGRESS },
	{ TDM_PORT_CPU, TDM_DIR_EGRESS },
	{ TDM_PORT_FAB_1, TDM_DIR_INGRESS },
	{ TDM_PORT_FAB_1, TDM_DIR_EGRESS },
	{ TDM_PORT_PHY_3, TDM_DIR_INGRESS },
	{ TDM_PORT_CPU, TDM_DIR_EGRESS },
	{ TDM_PORT_PHY_7, TDM_DIR_INGRESS },
	{ TDM_PORT_PHY_7, TDM_DIR_EGRESS },
	{ TDM_PORT_CPU, TDM_DIR_INGRESS },
	{ TDM_PORT_FAB_0, TDM_DIR_EGRESS },
	{ TDM_PORT_FAB_0, TDM_DIR_INGRESS },
	{ TDM_PORT_CPU, TDM_DIR_EGRESS },
	{ TDM_PORT_FAB_1, TDM_DIR_INGRESS },
	{ TDM_PORT_FAB_1, TDM_DIR_EGRESS },
	{ TDM_PORT_PHY_7, TDM_DIR_INGRESS },
	{ TDM_PORT_PHY_2, TDM_DIR_EGRESS },
	{ TDM_PORT_CPU, TDM_DIR_INGRESS },
	{ TDM_PORT_PHY_7, TDM_DIR_EGRESS },
	{ TDM_PORT_FAB_0, TDM_DIR_INGRESS },
	{ TDM_PORT_FAB_0, TDM_DIR_EGRESS },
	{ TDM_PORT_FAB_1, TDM_DIR_INGRESS },
	{ TDM_PORT_CPU, TDM_DIR_EGRESS },
	{ TDM_PORT_PHY_7, TDM_DIR_INGRESS },
	{ TDM_PORT_FAB_1, TDM_DIR_EGRESS },
};

static void ppe_tdm_init(struct qca_ppe_priv *priv)
{
	const struct ppe_data *data = priv->data;
	const struct psch_tdm_entry *psch;
	const struct bm_tdm_entry *bm;
	int psch_num, bm_num;
	u8 prev_de_port;
	int i;

	psch = data->psch_tdm->entries;
	psch_num = data->psch_tdm->num;

	bm = data->bm_tdm->entries;
	bm_num = data->bm_tdm->num;

	/*
	 * The port scheduler TDM is circular with the bitmap
	 * composed of the
	 * NOT (dequeue port (de_port) OR the previous dequeue port)
	 * Each bit correspond to a port from 0 to 7.
	 *
	 * For the first element, we refer to the last dequeue port
	 * (since it's circular).
	 *
	 * Taking an example for the first element:
	 * We dequeue port 6 and the last element dequeue port 3
	 * So the bitmap will be ~(BIT(6) | BIT(3)) = 0xb7
	 *
	 * Example for the second element:
	 * We dequeque port 0 and previously we dequeued port 6
	 * So the bitmap will be ~(BIT(0) | BIT(6)) = 0xbe
	 */
	prev_de_port = psch[psch_num - 1].de_port;
	for (i = 0; i < psch_num; i++) {
		u8 bmp = ~(BIT(prev_de_port) | BIT(psch[i].de_port));

		regmap_write(priv->regmap, PPE_TM_PSCH_TDM(i),
			     FIELD_PREP(PPE_PSCH_ENS_PORT_BMP, bmp) |
			     FIELD_PREP(PPE_PSCH_ENS_PORT, psch[i].en_port) |
			     FIELD_PREP(PPE_PSCH_DES_PORT, psch[i].de_port));

		prev_de_port = psch[i].de_port;
	}

	regmap_write(priv->regmap, PPE_TM_TDM_DEPTH,
		     FIELD_PREP(PPE_TM_TDM_DEPTH_MASK, psch_num));

	for (i = 0; i < bm_num; i++)
		regmap_write(priv->regmap, PPE_PRX_TDM_CFG(i),
			     FIELD_PREP(PPE_TDM_PORT_NUM, bm[i].port) |
			     FIELD_PREP(PPE_TDM_DIR, bm[i].dir) |
			     PPE_TDM_VALID);

	regmap_write(priv->regmap, PPE_PRX_TDM_CTRL,
		     FIELD_PREP(PPE_TDM_DEPTH, bm_num) |
		     PPE_TDM_EN);
}

static void ppe_bm_init(struct qca_ppe_priv *priv)
{
	const struct ppe_data *d = priv->data;
	int i;

	for (i = 0; i < PPE_BM_PORTS; i++) {
		bool fc_en = (i < PPE_BM_PHY_START || i > d->bm_phy_end);

		regmap_write(priv->regmap, PPE_BM_FC_MODE(i),
			     fc_en ? PPE_BM_FC_EN : 0);
		regmap_write(priv->regmap, PPE_BM_GROUP_ID(i), 0);
	}

	regmap_write(priv->regmap, PPE_BM_SHARED_GRP(0),
		     FIELD_PREP(PPE_BM_SHARED_LIMIT, d->bm_group_buf));

	for (i = 0; i < PPE_BM_PORTS; i++) {
		u16 react;
		u32 w0, w1;

		if (i < PPE_BM_PHY_START)
			react = 100;
		else if (i >= d->bm_internal_start)
			react = 40;
		else
			react = 128;

		w0 = FIELD_PREP(PPE_BM_REACT_LIMIT, react) |
		     FIELD_PREP(PPE_BM_RESUME_OFF, 36) |
		     FIELD_PREP(PPE_BM_CEILING_LO, d->bm_ceiling & 0x7);
		w1 = FIELD_PREP(PPE_BM_CEILING_HI, d->bm_ceiling >> 3) |
		     FIELD_PREP(PPE_BM_WEIGHT, 4) |
		     PPE_BM_DYNAMIC;

		regmap_write(priv->regmap, PPE_BM_PORT_FC_W0(i), w0);
		regmap_write(priv->regmap, PPE_BM_PORT_FC_W1(i), w1);
	}
}

static void ppe_qm_map_set(struct qca_ppe_priv *priv, u32 index,
			    u8 queue_base, u8 profile)
{
	regmap_write(priv->regmap, PPE_QM_UCAST_MAP(index),
		     FIELD_PREP(PPE_QM_PROFILE_ID, profile) |
		     FIELD_PREP(PPE_QM_QUEUE_ID, queue_base));
}

static const u8 port_queue_base[PPE_NUM_PORTS] = {
	0, 144, 160, 176, 192, 208, 224, 240,
};

static const u8 port_l0_cdrr_num[PPE_NUM_PORTS] = {
	48, 16, 16, 16, 16, 16, 16, 16,
};

static void ppe_qm_init(struct qca_ppe_priv *priv)
{
	const struct ppe_data *d = priv->data;
	int i, pri;

	ppe_qm_map_set(priv, QM_SERVICE_CODE_OFFSET + 2, 8, 0);
	ppe_qm_map_set(priv, QM_SERVICE_CODE_OFFSET + 3, 128, 8);
	ppe_qm_map_set(priv, QM_SERVICE_CODE_OFFSET + 4, 128, 8);
	ppe_qm_map_set(priv, QM_SERVICE_CODE_OFFSET + 5, 0, 0);
	ppe_qm_map_set(priv, QM_SERVICE_CODE_OFFSET + 6, 8, 0);
	ppe_qm_map_set(priv, QM_SERVICE_CODE_OFFSET + 7, 240, 0);

	for (i = 0; i < PPE_NUM_PORTS; i++)
		ppe_qm_map_set(priv, QM_VP_PORT_OFFSET + i,
				port_queue_base[i], i);

	for (i = 0; i < PPE_NUM_PORTS; i++) {
		u8 max_pri = port_l0_cdrr_num[i];
		u8 profile;

		if (max_pri > 16)
			max_pri = 1;

		for (pri = 0; pri < 16; pri++) {
			u8 cls = (pri >= max_pri) ? max_pri - 1 : pri;

			if (i == 0) {
				profile = 0;
				regmap_write(priv->regmap,
					     PPE_QM_UCAST_PRI_MAP(profile * 16 + pri),
					     FIELD_PREP(PPE_QM_PRI_CLASS, cls));
				profile = 15;
				regmap_write(priv->regmap,
					     PPE_QM_UCAST_PRI_MAP(profile * 16 + pri),
					     FIELD_PREP(PPE_QM_PRI_CLASS, cls));
			} else {
				regmap_write(priv->regmap,
					     PPE_QM_UCAST_PRI_MAP(i * 16 + pri),
					     FIELD_PREP(PPE_QM_PRI_CLASS, cls));
			}
		}
	}

	for (i = 0; i < 256; i++) {
		regmap_write(priv->regmap, PPE_QM_UCAST_HASH_MAP(15 * 256 + i), 0);
		regmap_write(priv->regmap, PPE_QM_UCAST_HASH_MAP(14 * 256 + i), 0);
	}

	ppe_qm_map_set(priv, QM_CPU_CODE_OFFSET + 101,
			port_queue_base[0] + 0, 0);

	for (i = 0; i < PPE_MAX_SERVICE_CODES; i++) {
		u32 idx = QM_SERVICE_CODE_OFFSET + (1 << 8) + i;

		if (i == 2 || i == 6)
			ppe_qm_map_set(priv, idx, 8, 0);
		else if (i == 3 || i == 4)
			ppe_qm_map_set(priv, idx, 128, 8);
		else
			ppe_qm_map_set(priv, idx, 4, 0);
	}

	for (i = 0; i < PPE_MAX_CPU_CODES; i++)
		ppe_qm_map_set(priv, QM_CPU_CODE_OFFSET + (1 << 8) + i, 4, 0);

	for (i = 0; i < PPE_NUM_PORTS; i++)
		ppe_qm_map_set(priv, QM_VP_PORT_OFFSET + (1 << 8) + i,
				port_queue_base[i], i);

	for (i = PPE_NUM_PORTS; i < PPE_MAX_VPORT; i++)
		ppe_qm_map_set(priv, QM_VP_PORT_OFFSET + (1 << 8) + i, 4, 0);

	for (i = 0; i < PPE_L0_UCAST_QUEUES; i++) {
		regmap_write(priv->regmap, PPE_QM_AC_UNI_W0(i),
			     PPE_AC_EN |
			     PPE_AC_SHARED_DYNAMIC |
			     FIELD_PREP(PPE_AC_SHARED_WEIGHT, 4) |
			     FIELD_PREP(PPE_AC_SHARED_CEILING, d->qm_ceiling));
		regmap_write(priv->regmap, PPE_QM_AC_UNI_W1(i), 0);
		regmap_write(priv->regmap, PPE_QM_AC_UNI_W2(i), 0);
		regmap_write(priv->regmap, PPE_QM_AC_UNI_W3(i),
			     FIELD_PREP(PPE_AC_GRN_RESUME_OFF, 36));
	}

	for (i = 0; i < PPE_L0_QUEUES - PPE_L0_UCAST_QUEUES; i++) {
		regmap_write(priv->regmap, PPE_QM_AC_MUL_W0(i),
			     PPE_AC_MUL_EN |
			     FIELD_PREP(PPE_AC_MUL_CEILING, d->qm_ceiling) |
			     FIELD_PREP(PPE_AC_MUL_GRN_MAX_LO, d->qm_green_max & 0x1f));
		regmap_write(priv->regmap, PPE_QM_AC_MUL_W1(i),
			     FIELD_PREP(PPE_AC_MUL_GRN_MAX_HI, d->qm_green_max >> 5));
		regmap_write(priv->regmap, PPE_QM_AC_MUL_W2(i),
			     FIELD_PREP(PPE_AC_MUL_GRN_RESUME_HI, 36));
	}

	regmap_write(priv->regmap, PPE_QM_AC_GRP_W0(0), 0);
	regmap_write(priv->regmap, PPE_QM_AC_GRP_W1(0),
		     FIELD_PREP(PPE_AC_GRP_LIMIT, d->qm_total_buf));
	regmap_write(priv->regmap, PPE_QM_AC_GRP_W2(0), 0);

	regmap_update_bits(priv->regmap, PPE_EG_BRIDGE_CONFIG,
			   PPE_EG_QUEUE_CNT_EN, PPE_EG_QUEUE_CNT_EN);
}

struct l1_cfg {
	u8 index;
	u8 port;
	u8 pri;
	u8 drr;
};

static const struct l1_cfg l1_cfg[] = {
	{  0, 0, 0,  0 },
	{  1, 0, 0,  0 },
	{ 36, 1, 0,  8 },
	{ 37, 1, 1,  9 },
	{ 40, 2, 0, 12 },
	{ 41, 2, 1, 13 },
	{ 44, 3, 0, 16 },
	{ 45, 3, 1, 17 },
	{ 48, 4, 0, 20 },
	{ 49, 4, 1, 21 },
	{ 52, 5, 0, 24 },
	{ 53, 5, 1, 25 },
	{ 56, 6, 0, 28 },
	{ 57, 6, 1, 29 },
	{ 60, 7, 0, 32 },
	{ 61, 7, 1, 33 },
};

static void ppe_l1_scheduler_init(struct qca_ppe_priv *priv)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(l1_cfg); i++) {
		const struct l1_cfg *c = &l1_cfg[i];
		u32 sp_idx;

		regmap_write(priv->regmap, PPE_TM_L1_FLOW_MAP(c->index),
			     FIELD_PREP(PPE_L1_SP_ID, c->port) |
			     FIELD_PREP(PPE_L1_C_PRI, c->pri) |
			     FIELD_PREP(PPE_L1_E_PRI, c->pri) |
			     FIELD_PREP(PPE_L1_C_DRR_WT, 1) |
			     FIELD_PREP(PPE_L1_E_DRR_WT, 1));

		sp_idx = c->port * 8 + c->pri;
		regmap_write(priv->regmap, PPE_TM_L1_C_SP(sp_idx),
			     FIELD_PREP(PPE_L1_SP_DRR_ID, c->drr));

		regmap_write(priv->regmap, PPE_TM_L1_E_SP(sp_idx),
			     FIELD_PREP(PPE_L1_SP_DRR_ID, c->drr));

		regmap_write(priv->regmap, PPE_TM_L1_PORT_MAP(c->index),
			     FIELD_PREP(PPE_L1_PORT_NUM, c->port));
	}
}

struct l0_cfg {
	u16 queue;
	u8 port;
	u8 sp;
	u8 cpri;
	u8 cdrr;
	u8 epri;
	u8 edrr;
};

static const struct l0_cfg l0_port0[] = {
	{   0, 0, 0, 0, 0, 0, 0 }, {   4, 0, 0, 0, 0, 0, 0 },
	{   8, 0, 0, 0, 0, 0, 0 }, { 256, 0, 0, 0, 0, 0, 0 },
	{ 260, 0, 0, 0, 0, 0, 0 },
	{   1, 0, 0, 1, 1, 1, 1 }, {   5, 0, 0, 1, 1, 1, 1 },
	{   9, 0, 0, 1, 1, 1, 1 }, { 257, 0, 0, 1, 1, 1, 1 },
	{ 261, 0, 0, 1, 1, 1, 1 },
	{   2, 0, 0, 2, 2, 2, 2 }, {   6, 0, 0, 2, 2, 2, 2 },
	{  10, 0, 0, 2, 2, 2, 2 }, { 258, 0, 0, 2, 2, 2, 2 },
	{ 262, 0, 0, 2, 2, 2, 2 },
	{   3, 0, 0, 3, 3, 3, 3 }, {   7, 0, 0, 3, 3, 3, 3 },
	{  11, 0, 0, 3, 3, 3, 3 }, { 259, 0, 0, 3, 3, 3, 3 },
	{ 263, 0, 0, 3, 3, 3, 3 },
};

static void ppe_l0_entry_write(struct qca_ppe_priv *priv, const struct l0_cfg *c)
{
	u32 sp_idx;

	regmap_write(priv->regmap, PPE_TM_L0_FLOW_MAP(c->queue),
		     FIELD_PREP(PPE_L0_SP_ID, c->sp) |
		     FIELD_PREP(PPE_L0_C_PRI, c->cpri) |
		     FIELD_PREP(PPE_L0_E_PRI, c->epri) |
		     FIELD_PREP(PPE_L0_C_DRR_WT, 1) |
		     FIELD_PREP(PPE_L0_E_DRR_WT, 1));

	sp_idx = c->sp * 8 + c->cpri;
	regmap_write(priv->regmap, PPE_TM_L0_C_SP(sp_idx),
		     FIELD_PREP(PPE_L0_SP_DRR_ID, c->cdrr));

	sp_idx = c->sp * 8 + c->epri;
	regmap_write(priv->regmap, PPE_TM_L0_E_SP(sp_idx),
		     FIELD_PREP(PPE_L0_SP_DRR_ID, c->edrr));

	regmap_write(priv->regmap, PPE_TM_L0_PORT_MAP(c->queue),
		     FIELD_PREP(PPE_L0_PORT_NUM, c->port));
}

struct port_l0_params {
	u16 ucast_base;
	u8 ucast_count;
	u16 mcast_base;
	u8 mcast_count;
	u8 sp_base;
	u8 cdrr_base;
	u8 port;
};

static const struct port_l0_params port_l0[] = {
	{ 144, 16, 272, 4, 36,  48, 1 },
	{ 160, 16, 276, 4, 40,  64, 2 },
	{ 176, 16, 280, 4, 44,  80, 3 },
	{ 192, 16, 284, 4, 48,  96, 4 },
	{ 208, 16, 288, 4, 52, 112, 5 },
	{ 224, 16, 292, 4, 56, 128, 6 },
	{ 240, 16, 296, 1, 60, 144, 7 },
};

static void ppe_l0_scheduler_init(struct qca_ppe_priv *priv)
{
	int i, j;

	for (i = 0; i < ARRAY_SIZE(l0_port0); i++)
		ppe_l0_entry_write(priv, &l0_port0[i]);

	for (i = 0; i < ARRAY_SIZE(port_l0); i++) {
		const struct port_l0_params *p = &port_l0[i];
		u16 bases[] = { p->ucast_base, p->mcast_base };
		u8 counts[] = { p->ucast_count, p->mcast_count };
		int k;

		/* Multicast queues take the port's top unicast slots, not
		 * 0..mcast_count-1: sharing a slot puts two queues on one DRR
		 * node, whose credit rotation can latch and freeze both until
		 * the node is rebuilt. The top slots idle unless skb->priority
		 * selects them, at the cost of sitting on the port's second SP,
		 * which puts flooding above best-effort unicast.
		 */
		for (k = 0; k < 2; k++) {
			for (j = 0; j < counts[k]; j++) {
				int slot = k ? p->ucast_count - counts[k] + j : j;
				struct l0_cfg c = {
					.queue = bases[k] + j,
					.port = p->port,
					.sp = p->sp_base + slot / PPE_MAX_SP_PRI,
					.cpri = slot % PPE_MAX_SP_PRI,
					.cdrr = p->cdrr_base + slot,
					.epri = slot % PPE_MAX_SP_PRI,
					.edrr = p->cdrr_base + slot,
				};

				ppe_l0_entry_write(priv, &c);
			}
		}
	}
}

static void ppe_edma_ring_map_init(struct qca_ppe_priv *priv)
{
	int i;

	regmap_write(priv->regmap, PPE_TM_RING_Q_MAP(0), 0xf);
	for (i = 1; i < 10; i++)
		regmap_write(priv->regmap, PPE_TM_RING_Q_MAP(0) + i * 4, 0);

	regmap_write(priv->regmap, PPE_TM_RING_Q_MAP(3), 0xf0);
	for (i = 1; i < 10; i++)
		regmap_write(priv->regmap, PPE_TM_RING_Q_MAP(3) + i * 4, 0);

	regmap_write(priv->regmap, PPE_TM_RING_Q_MAP(1), 0xf00);
	for (i = 1; i < 10; i++)
		regmap_write(priv->regmap, PPE_TM_RING_Q_MAP(1) + i * 4, 0);

	for (i = 0; i < 10; i++)
		regmap_write(priv->regmap, PPE_TM_RING_Q_MAP(2) + i * 4, 0);
	regmap_write(priv->regmap, PPE_TM_RING_Q_MAP(2) + 4 * 4, 0xffff);
}

static void ppe_qos_init(struct qca_ppe_priv *priv)
{
	int i;
	u32 qos_bits;

	qos_bits = FIELD_PREP(PPE_QOS_PREHEADER_PREC, 3) |
		   FIELD_PREP(PPE_QOS_DSCP_PREC, 1) |
		   FIELD_PREP(PPE_QOS_FLOW_PREC, 4) |
		   FIELD_PREP(PPE_QOS_ACL_PREC, 2);

	for (i = 0; i < PPE_NUM_PORTS; i++)
		regmap_update_bits(priv->regmap, PPE_PRX_MRU_MTU_W1(i),
				   PPE_QOS_PCP_GRP | PPE_QOS_DSCP_GRP |
				   PPE_QOS_PREHEADER_PREC | PPE_QOS_PCP_PREC |
				   PPE_QOS_DSCP_PREC | PPE_QOS_FLOW_PREC |
				   PPE_QOS_ACL_PREC,
				   qos_bits);
}

const struct psch_tdm_data cppe_psch_tdm_data = {
	.entries = cppe_psch_tdm,
	.num = ARRAY_SIZE(cppe_psch_tdm),
};

const struct psch_tdm_data hppe_psch_tdm_data = {
	.entries = hppe_psch_tdm,
	.num = ARRAY_SIZE(hppe_psch_tdm),
};

const struct bm_tdm_data cppe_bm_tdm_data = {
	.entries = cppe_bm_tdm,
	.num = ARRAY_SIZE(cppe_bm_tdm),
};

const struct bm_tdm_data hppe_bm_tdm_data = {
	.entries = hppe_bm_tdm,
	.num = ARRAY_SIZE(hppe_bm_tdm),
};

void ppe_scheduler_init(struct qca_ppe_priv *priv)
{
	ppe_tdm_init(priv);
	ppe_bm_init(priv);
	ppe_qm_init(priv);
	ppe_l1_scheduler_init(priv);
	ppe_l0_scheduler_init(priv);
	ppe_edma_ring_map_init(priv);
	ppe_qos_init(priv);
}

/* Resource writes report the hardware result, including a partial prefix. */
static int ppe_qdx_write(struct qca_ppe_priv *priv, u32 reg, u32 value, u32 mask)
{
	u32 actual;
	int ret;

	ret = regmap_write(priv->regmap, reg, value);
	if (ret)
		return ret;
	ret = regmap_read(priv->regmap, reg, &actual);
	if (ret)
		return ret;
	return (actual & mask) == (value & mask) ? 0 : -EIO;
}

static int ppe_qdx_source_set(struct qca_ppe_priv *priv, unsigned int port,
			    unsigned int profile)
{
	u32 reg = PPE_MRU_MTU_CTRL(port, priv->data->mru_mtu_ctrl_stride);
	u32 row[2];
	int ret;

	lockdep_assert_held(&priv->resource_lock);
	ret = regmap_bulk_read(priv->regmap, reg, row, ARRAY_SIZE(row));
	if (ret)
		return ret;
	row[1] &= ~PPE_MRU_MTU_CTRL_SRC_PROFILE;
	row[1] |= FIELD_PREP(PPE_MRU_MTU_CTRL_SRC_PROFILE, profile);
	/* The final word commits the row; keep current native MTU/counters. */
	ret = regmap_bulk_write(priv->regmap, reg, row, ARRAY_SIZE(row));
	if (ret)
		return ret;
	ret = regmap_bulk_read(priv->regmap, reg, row, ARRAY_SIZE(row));
	if (ret)
		return ret;
	return FIELD_GET(PPE_MRU_MTU_CTRL_SRC_PROFILE, row[1]) == profile ? 0 : -EIO;
}

static u32 ppe_qdx_profile_reg(unsigned int profile, unsigned int entry)
{
	unsigned int index = (entry / PPE_MAX_VPORT) * 1024;

	return PPE_QM_UCAST_MAP(index + profile * PPE_MAX_VPORT + entry % PPE_MAX_VPORT);
}

static int ppe_qdx_profile_write(struct qca_ppe_priv *priv, unsigned int profile,
				 const u32 *values)
{
	unsigned int i;
	int ret;

	for (i = 0; i < PPE_QDX_PROFILE_ENTRIES; i++) {
		ret = ppe_qdx_write(priv, ppe_qdx_profile_reg(profile, i), values[i],
				    PPE_QM_PROFILE_ID | PPE_QM_QUEUE_ID);
		if (ret)
			return ret;
	}
	return 0;
}

/* Check real current selectors, including inactive physical/virtual sources.
 * The selected baseline keeps CPU queue 0 independent of class/RSS offsets.
 * Do not steal q1..3 from an existing non-default QoS/RSS allocation.
 */
static int ppe_qdx_selectors_check(struct qca_ppe_priv *priv, u8 *profiles)
{
	struct {
		s16 min_hash;
		s16 max_hash;
		u8 max_class;
		bool read;
	} offsets[16] = {};
	unsigned int source, entry, profile, queue, i;
	u32 row[2], value, active = 0;
	int ret;

	for (source = 0; source < PPE_MAX_VPORT; source++) {
		ret = regmap_bulk_read(priv->regmap,
			PPE_MRU_MTU_CTRL(source, priv->data->mru_mtu_ctrl_stride),
			row, ARRAY_SIZE(row));
		if (ret)
			return ret;
		active |= BIT(FIELD_GET(PPE_MRU_MTU_CTRL_SRC_PROFILE, row[1]));
	}
	*profiles = active;
	ret = regmap_read(priv->regmap, PPE_QM_DEFAULT_HASH, &value);
	if (ret)
		return ret;
	if (value & PPE_QM_HASH_OFFSET)
		return -EBUSY;
	for (source = 0; source <= PPE_QDX_RX_PROFILES; source++) {
		if (!(active & BIT(source)))
			continue;
		for (entry = 0; entry < PPE_QDX_PROFILE_ENTRIES; entry++) {
			ret = regmap_read(priv->regmap, ppe_qdx_profile_reg(source, entry),
					  &value);
			if (ret)
				return ret;
			profile = FIELD_GET(PPE_QM_PROFILE_ID, value);
			queue = FIELD_GET(PPE_QM_QUEUE_ID, value);
			if (!offsets[profile].read) {
				for (i = 0; i < 16; i++) {
					ret = regmap_read(priv->regmap,
						PPE_QM_UCAST_PRI_MAP(profile * 16 + i), &value);
					if (ret)
						return ret;
					offsets[profile].max_class = max_t(u8,
						offsets[profile].max_class,
						FIELD_GET(PPE_QM_PRI_CLASS, value));
				}
				for (i = 0; i < 256; i++) {
					s8 hash;

					ret = regmap_read(priv->regmap,
						PPE_QM_UCAST_HASH_MAP(profile * 256 + i), &value);
					if (ret)
						return ret;
					hash = FIELD_GET(PPE_QM_HASH_OFFSET, value);
					offsets[profile].min_hash = min_t(s16,
						offsets[profile].min_hash, hash);
					offsets[profile].max_hash = max_t(s16,
						offsets[profile].max_hash, hash);
				}
				offsets[profile].read = true;
			}
			if (queue <= PPE_QDX_RX_PROFILES) {
				bool owned = !queue;

				for (i = 1; i < priv->data->num_ports; i++) {
					struct qca_ppe_rx_resource *rx = priv->rx_resources[i];

					if (rx && !rx->restored && rx->profile == source &&
					    rx->queue == queue)
						owned = true;
				}
				if (!owned || offsets[profile].max_class ||
				    offsets[profile].min_hash || offsets[profile].max_hash)
					return -EBUSY;
			} else if (offsets[profile].min_hash < 0 ||
				   queue + offsets[profile].max_class +
				   offsets[profile].max_hash >= PPE_L0_UCAST_QUEUES) {
				/* A negative or wrapping offset needs a different allocation. */
				return -EBUSY;
			}
		}
	}
	return 0;
}

/* No other queue may use either selected SP slot or DRR identifier. Checking
 * all L0 rows includes the CPU multicast aliases of the old q1..3 settings.
 */
static int ppe_qdx_scheduler_check(struct qca_ppe_priv *priv,
				 struct qca_ppe_rx_resource *rx)
{
	unsigned int queue, sp, cslot, eslot;
	u32 flow, value;
	int ret;

	for (queue = 0; queue < PPE_L0_QUEUES; queue++) {
		ret = regmap_read(priv->regmap, PPE_TM_L0_FLOW_MAP(queue), &flow);
		if (ret)
			return ret;
		if (queue == rx->queue)
			continue;
		sp = FIELD_GET(PPE_L0_SP_ID, flow);
		cslot = sp * PPE_MAX_SP_PRI + FIELD_GET(PPE_L0_C_PRI, flow);
		eslot = sp * PPE_MAX_SP_PRI + FIELD_GET(PPE_L0_E_PRI, flow);
		if (cslot == rx->priority || eslot == rx->priority)
			return -EBUSY;
		ret = regmap_read(priv->regmap, PPE_TM_L0_C_SP(cslot), &value);
		if (ret)
			return ret;
		if (FIELD_GET(PPE_L0_SP_DRR_ID, value) == rx->priority)
			return -EBUSY;
		ret = regmap_read(priv->regmap, PPE_TM_L0_E_SP(eslot), &value);
		if (ret)
			return ret;
		if (FIELD_GET(PPE_L0_SP_DRR_ID, value) == rx->priority)
			return -EBUSY;
	}
	ret = regmap_read(priv->regmap, PPE_TM_L0_PORT_MAP(rx->queue), &value);
	if (ret)
		return ret;
	if (FIELD_GET(PPE_L0_PORT_NUM, value) != QCA_PPE_CPU_PORT)
		return -EBUSY;
	ret = regmap_read(priv->regmap, PPE_QM_PENDING_BUFFERS(rx->queue), &value);
	if (ret)
		return ret;
	return value & PPE_QM_PENDING_COUNT ? -EBUSY : 0;
}

static int ppe_qdx_queue_flush(struct qca_ppe_priv *priv, unsigned int queue,
			     unsigned int port)
{
	u32 value;
	int ret;

	ret = regmap_read_poll_timeout(priv->regmap, PPE_QM_FLUSH, value,
				      !(value & PPE_QM_FLUSH_BUSY), 10,
				      PPE_QDX_QUEUE_WAIT_US);
	if (ret)
		return ret;
	value &= ~(PPE_QM_FLUSH_QUEUE | PPE_QM_FLUSH_PORT | PPE_QM_FLUSH_ALL |
		   PPE_QM_FLUSH_STATUS);
	value |= FIELD_PREP(PPE_QM_FLUSH_QUEUE, queue) |
		 FIELD_PREP(PPE_QM_FLUSH_PORT, port) | PPE_QM_FLUSH_BUSY;
	ret = regmap_write(priv->regmap, PPE_QM_FLUSH, value);
	if (ret)
		return ret;
	ret = regmap_read_poll_timeout(priv->regmap, PPE_QM_FLUSH, value,
				      !(value & PPE_QM_FLUSH_BUSY), 10,
				      PPE_QDX_QUEUE_WAIT_US);
	if (ret)
		return ret;
	return value & PPE_QM_FLUSH_STATUS ? 0 : -EIO;
}

/* This is a PPE queue fence, not the end of drv DMA/N2H ownership. */
static int ppe_qdx_rx_restore(struct qca_ppe_priv *priv,
			      struct qca_ppe_rx_resource *rx)
{
	u32 pending;
	int ret;

	if (rx->restored)
		return 0;
	rx->closing = true;
	ret = ppe_qdx_source_set(priv, rx->port, rx->native_profile);
	if (ret)
		return ret;
	ret = ppe_qdx_write(priv, PPE_QM_ENQUEUE_DISABLE(rx->queue),
			    rx->enqueue | PPE_QUEUE_DISABLED, PPE_QUEUE_DISABLED);
	if (ret)
		return ret;
	ret = qdx_ppe_map_rx_queue(priv->qdx, rx->queue, false);
	if (ret)
		return ret;
	ret = ppe_qdx_write(priv, PPE_TM_DEQUEUE_DISABLE(rx->queue),
			    rx->dequeue & ~PPE_QUEUE_DISABLED, PPE_QUEUE_DISABLED);
	if (ret)
		return ret;
	ret = regmap_read_poll_timeout(priv->regmap, PPE_QM_PENDING_BUFFERS(rx->queue),
				      pending, !(pending & PPE_QM_PENDING_COUNT), 10,
				      PPE_QDX_QUEUE_WAIT_US);
	if (ret && ret != -ETIMEDOUT)
		return ret;
	/* A finite old prefix may be disposed if native draining did not finish. */
	ret = ppe_qdx_write(priv, PPE_TM_DEQUEUE_DISABLE(rx->queue),
			    rx->dequeue | PPE_QUEUE_DISABLED, PPE_QUEUE_DISABLED);
	if (ret)
		return ret;
	ret = ppe_qdx_queue_flush(priv, rx->queue, QCA_PPE_CPU_PORT);
	if (ret)
		return ret;
	ret = ppe_qdx_profile_write(priv, rx->profile, rx->saved);
	if (ret)
		return ret;
	ret = ppe_qdx_write(priv, PPE_TM_L0_FLOW_MAP(rx->queue), rx->flow, U32_MAX);
	if (ret)
		return ret;
	ret = ppe_qdx_write(priv, PPE_TM_L0_C_SP(rx->priority), rx->committed_sp,
			    PPE_L0_SP_DRR_ID);
	if (ret)
		return ret;
	ret = ppe_qdx_write(priv, PPE_TM_L0_E_SP(rx->priority), rx->excess_sp,
			    PPE_L0_SP_DRR_ID);
	if (ret)
		return ret;
	ret = ppe_qdx_write(priv, PPE_TM_DEQUEUE_DISABLE(rx->queue), rx->dequeue,
			    PPE_QUEUE_DISABLED);
	if (ret)
		return ret;
	ret = ppe_qdx_write(priv, PPE_QM_ENQUEUE_DISABLE(rx->queue), rx->enqueue,
			    PPE_QUEUE_DISABLED);
	if (!ret)
		rx->restored = true;
	return ret;
}

static int ppe_qdx_rx_apply(struct qca_ppe_priv *priv,
			    struct qca_ppe_rx_resource *rx)
{
	u32 flow = rx->flow & ~(PPE_L0_SP_ID | PPE_L0_C_PRI | PPE_L0_E_PRI |
			       PPE_L0_C_DRR_WT | PPE_L0_E_DRR_WT);
	int ret;

	ret = ppe_qdx_write(priv, PPE_TM_DEQUEUE_DISABLE(rx->queue),
			    rx->dequeue | PPE_QUEUE_DISABLED, PPE_QUEUE_DISABLED);
	if (ret)
		return ret;
	flow |= FIELD_PREP(PPE_L0_C_PRI, rx->priority) |
		FIELD_PREP(PPE_L0_E_PRI, rx->priority) |
		FIELD_PREP(PPE_L0_C_DRR_WT, 1) | FIELD_PREP(PPE_L0_E_DRR_WT, 1);
	ret = ppe_qdx_write(priv, PPE_TM_L0_C_SP(rx->priority),
			    (rx->committed_sp & ~PPE_L0_SP_DRR_ID) | rx->priority,
			    PPE_L0_SP_DRR_ID);
	if (ret)
		return ret;
	ret = ppe_qdx_write(priv, PPE_TM_L0_E_SP(rx->priority),
			    (rx->excess_sp & ~PPE_L0_SP_DRR_ID) | rx->priority,
			    PPE_L0_SP_DRR_ID);
	if (ret)
		return ret;
	ret = ppe_qdx_write(priv, PPE_TM_L0_FLOW_MAP(rx->queue), flow, U32_MAX);
	if (ret)
		return ret;
	ret = ppe_qdx_profile_write(priv, rx->profile, rx->selected);
	if (ret)
		return ret;
	ret = qdx_ppe_map_rx_queue(priv->qdx, rx->queue, true);
	if (ret)
		return ret;
	ret = ppe_qdx_write(priv, PPE_QM_ENQUEUE_DISABLE(rx->queue),
			    rx->enqueue & ~PPE_QUEUE_DISABLED, PPE_QUEUE_DISABLED);
	if (ret)
		return ret;
	ret = ppe_qdx_source_set(priv, rx->port, rx->profile);
	if (ret)
		return ret;
	return ppe_qdx_write(priv, PPE_TM_DEQUEUE_DISABLE(rx->queue),
			     rx->holds ? rx->dequeue | PPE_QUEUE_DISABLED :
			     rx->dequeue & ~PPE_QUEUE_DISABLED, PPE_QUEUE_DISABLED);
}

struct qdx_ppe_rx *ppe_qdx_rx_acquire(void *context, unsigned int port)
{
	struct qca_ppe_priv *priv = context;
	struct qca_ppe_rx_resource *rx;
	struct qdx_ppe_rx *use;
	unsigned int profile, entry, i;
	u32 row[2], value;
	u8 profiles;
	int ret, undo = 0;

	if (!port || port >= priv->data->num_ports ||
	    priv->data->type != PPE_TYPE_IPQ8074)
		return ERR_PTR(-EOPNOTSUPP);
	use = kzalloc_obj(*use);
	if (!use)
		return ERR_PTR(-ENOMEM);
	mutex_lock(&priv->resource_lock);
	if (priv->resources_terminal) {
		ret = -ESHUTDOWN;
		goto free_use;
	}
	rx = priv->rx_resources[port];
	if (rx) {
		if (rx->closing) {
			ret = -ESHUTDOWN;
			goto free_use;
		}
		rx->users++;
		use->resource = rx;
		mutex_unlock(&priv->resource_lock);
		return use;
	}
	ret = ppe_qdx_selectors_check(priv, &profiles);
	if (ret)
		goto free_use;
	for (i = 1; i < priv->data->num_ports; i++)
		if (priv->rx_resources[i])
			profiles |= BIT(priv->rx_resources[i]->profile);
	rx = kvzalloc_obj(*rx);
	if (!rx) {
		ret = -ENOMEM;
		goto free_use;
	}
	rx->port = port;
	ret = regmap_bulk_read(priv->regmap,
		PPE_MRU_MTU_CTRL(port, priv->data->mru_mtu_ctrl_stride),
		row, ARRAY_SIZE(row));
	if (ret)
		goto free_resource;
	rx->native_profile = FIELD_GET(PPE_MRU_MTU_CTRL_SRC_PROFILE, row[1]);
	if (rx->native_profile) {
		/* A foreign source selector is an existing resource owner. */
		ret = -EBUSY;
		goto free_resource;
	}
	for (profile = 1; profile <= PPE_QDX_RX_PROFILES; profile++) {
		if (profiles & BIT(profile))
			continue;
		rx->profile = profile;
		rx->queue = profile;
		rx->priority = profile + 3;
		ret = ppe_qdx_scheduler_check(priv, rx);
		if (ret == -EBUSY)
			continue;
		if (ret)
			goto free_resource;
		ret = regmap_read(priv->regmap, PPE_QM_ENQUEUE_DISABLE(rx->queue),
				  &rx->enqueue);
		if (ret)
			goto free_resource;
		ret = regmap_read(priv->regmap, PPE_TM_DEQUEUE_DISABLE(rx->queue),
				  &rx->dequeue);
		if (ret)
			goto free_resource;
		if (!((rx->enqueue | rx->dequeue) & PPE_QUEUE_DISABLED))
			break;
	}
	if (profile > PPE_QDX_RX_PROFILES) {
		ret = -ENOSPC;
		goto free_resource;
	}
	ret = regmap_read(priv->regmap, PPE_TM_L0_FLOW_MAP(rx->queue), &rx->flow);
	if (ret)
		goto free_resource;
	ret = regmap_read(priv->regmap, PPE_TM_L0_C_SP(rx->priority), &rx->committed_sp);
	if (ret)
		goto free_resource;
	ret = regmap_read(priv->regmap, PPE_TM_L0_E_SP(rx->priority), &rx->excess_sp);
	if (ret)
		goto free_resource;
	for (entry = 0; entry < PPE_QDX_PROFILE_ENTRIES; entry++) {
		ret = regmap_read(priv->regmap, ppe_qdx_profile_reg(profile, entry),
				  &rx->saved[entry]);
		if (ret)
			goto free_resource;
		ret = regmap_read(priv->regmap,
				  ppe_qdx_profile_reg(rx->native_profile, entry), &value);
		if (ret)
			goto free_resource;
		/* Keep current physical destinations and special CPU/service queues. */
		if (!FIELD_GET(PPE_QM_QUEUE_ID, value))
			value |= FIELD_PREP(PPE_QM_QUEUE_ID, rx->queue);
		rx->selected[entry] = value;
	}
	/* Publish actual ownership before the first hardware mutation. */
	priv->rx_resources[port] = rx;
	ret = ppe_qdx_rx_apply(priv, rx);
	if (ret) {
		undo = ppe_qdx_rx_restore(priv, rx);
		if (undo)
			goto free_use;
		priv->rx_resources[port] = NULL;
		goto free_resource;
	}
	rx->users = 1;
	use->resource = rx;
	mutex_unlock(&priv->resource_lock);
	return use;
free_resource:
	kvfree(rx);
free_use:
	mutex_unlock(&priv->resource_lock);
	kfree(use);
	if (undo)
		qdx_port_failed(priv->qdx, port, undo);
	return ERR_PTR(ret);
}

int ppe_qdx_rx_hold(void *context, struct qdx_ppe_rx *scope)
{
	struct qca_ppe_priv *priv = context;
	struct qca_ppe_rx_resource *rx = scope->resource;
	int ret = 0;

	mutex_lock(&priv->resource_lock);
	if (!scope->held) {
		scope->held = true;
		rx->holds++;
	}
	if (!rx->restored)
		ret = ppe_qdx_write(priv, PPE_TM_DEQUEUE_DISABLE(rx->queue),
				    rx->dequeue | PPE_QUEUE_DISABLED, PPE_QUEUE_DISABLED);
	mutex_unlock(&priv->resource_lock);
	return ret;
}

int ppe_qdx_rx_release(void *context, struct qdx_ppe_rx *scope)
{
	struct qca_ppe_priv *priv = context;
	struct qca_ppe_rx_resource *rx = scope->resource;
	int ret = 0;

	mutex_lock(&priv->resource_lock);
	if (rx->users == 1 || priv->resources_terminal || rx->closing) {
		ret = ppe_qdx_rx_restore(priv, rx);
	} else if (scope->held && rx->holds == 1) {
		ret = ppe_qdx_write(priv, PPE_TM_DEQUEUE_DISABLE(rx->queue),
				    rx->dequeue & ~PPE_QUEUE_DISABLED, PPE_QUEUE_DISABLED);
	}
	if (ret)
		goto out;
	if (scope->held)
		rx->holds--;
	if (!--rx->users) {
		priv->rx_resources[rx->port] = NULL;
		kvfree(rx);
	}
	kfree(scope);
out:
	mutex_unlock(&priv->resource_lock);
	return ret;
}

/* These are actual native output queues, not NSS qos_tag or user queue IDs. */
static int ppe_qdx_tx_gates(struct qca_ppe_priv *priv, unsigned int port,
			    bool hold, bool dispose)
{
	const struct port_l0_params *layout = &port_l0[port - 1];
	unsigned int i, queue, count = layout->ucast_count + layout->mcast_count;
	u32 value;
	int ret;

	if (!priv->tx_saved[port]) {
		for (i = 0; i < count; i++) {
			queue = i < layout->ucast_count ? layout->ucast_base + i :
				layout->mcast_base + i - layout->ucast_count;
			ret = regmap_read(priv->regmap, PPE_TM_DEQUEUE_DISABLE(queue),
					  &priv->tx_dequeue[port][i]);
			if (ret)
				return ret;
			ret = regmap_read(priv->regmap, PPE_QM_ENQUEUE_DISABLE(queue),
					  &priv->tx_enqueue[port][i]);
			if (ret)
				return ret;
		}
		priv->tx_saved[port] = true;
	}
	for (i = 0; i < count; i++) {
		queue = i < layout->ucast_count ? layout->ucast_base + i :
			layout->mcast_base + i - layout->ucast_count;
		value = priv->tx_dequeue[port][i];
		if (hold || dispose)
			value |= PPE_QUEUE_DISABLED;
		ret = ppe_qdx_write(priv, PPE_TM_DEQUEUE_DISABLE(queue), value,
				    PPE_QUEUE_DISABLED);
		if (ret)
			return ret;
		if (!dispose)
			continue;
		ret = ppe_qdx_write(priv, PPE_QM_ENQUEUE_DISABLE(queue),
				    priv->tx_enqueue[port][i] | PPE_QUEUE_DISABLED,
				    PPE_QUEUE_DISABLED);
		if (ret)
			return ret;
		ret = ppe_qdx_queue_flush(priv, queue, port);
		if (ret)
			return ret;
		ret = ppe_qdx_write(priv, PPE_QM_ENQUEUE_DISABLE(queue),
				    priv->tx_enqueue[port][i],
				    PPE_QUEUE_DISABLED);
		if (ret)
			return ret;
	}
	if (dispose) {
		/* All old queues are disposed before any output gate is reopened. */
		for (i = 0; i < count; i++) {
			queue = i < layout->ucast_count ? layout->ucast_base + i :
				layout->mcast_base + i - layout->ucast_count;
			ret = ppe_qdx_write(priv, PPE_TM_DEQUEUE_DISABLE(queue),
					    priv->tx_dequeue[port][i], PPE_QUEUE_DISABLED);
			if (ret)
				return ret;
		}
	}
	return 0;
}

struct qdx_ppe_tx *ppe_qdx_tx_prepare(void *context, unsigned int port, u16 queue)
{
	struct qca_ppe_priv *priv = context;
	const struct port_l0_params *layout;
	struct qdx_ppe_tx *use;
	unsigned int q;
	u32 value;
	int ret = 0;

	if (!port || port >= priv->data->num_ports ||
	    priv->data->type != PPE_TYPE_IPQ8074)
		return ERR_PTR(-EOPNOTSUPP);
	use = kzalloc_obj(*use);
	if (!use)
		return ERR_PTR(-ENOMEM);
	layout = &port_l0[port - 1];
	mutex_lock(&priv->resource_lock);
	if (priv->resources_terminal) {
		ret = -ESHUTDOWN;
		goto out;
	}
	for (q = 0; q < PPE_L0_QUEUES; q++) {
		bool belongs = (q >= layout->ucast_base &&
				q < layout->ucast_base + layout->ucast_count) ||
			       (q >= layout->mcast_base &&
				q < layout->mcast_base + layout->mcast_count);

		ret = regmap_read(priv->regmap, PPE_TM_L0_PORT_MAP(q), &value);
		if (ret)
			goto out;
		if (belongs != (FIELD_GET(PPE_L0_PORT_NUM, value) == port)) {
			ret = -EBUSY;
			goto out;
		}
	}
	use->port = port;
	use->queue = queue;
	list_add_tail(&use->list, &priv->tx_uses);
out:
	mutex_unlock(&priv->resource_lock);
	if (ret) {
		kfree(use);
		return ERR_PTR(ret);
	}
	return use;
}

int ppe_qdx_tx_hold(void *context, struct qdx_ppe_tx *scope)
{
	struct qca_ppe_priv *priv = context;
	int ret;

	qdx_ppe_tx_gate(priv->qdx, true);
	mutex_lock(&priv->resource_lock);
	if (!scope->held) {
		scope->held = true;
		WRITE_ONCE(priv->tx_holds[scope->port], priv->tx_holds[scope->port] + 1);
	}
	ret = ppe_qdx_tx_gates(priv, scope->port, true, false);
	mutex_unlock(&priv->resource_lock);
	qdx_ppe_tx_gate(priv->qdx, false);
	return ret;
}

/* A peak may restore its row before older paths release their holds. Keep
 * its bridge obligation with the native port until the last share ends.
 */
static int ppe_qdx_tx_bridge_restore(struct qca_ppe_priv *priv, unsigned int port)
{
	u32 bridge;
	int ret, error;

	lockdep_assert_held(&priv->resource_lock);
	if (!priv->tx_bridge_owned[port])
		return 0;
	ret = regmap_read(priv->regmap, PPE_PORT_BRIDGE_CTRL(port), &bridge);
	if (ret)
		return ret;
	bridge &= ~PPE_PORT_BRIDGE_CTRL_TXMAC_EN;
	if (priv->tx_bridge_enabled[port])
		bridge |= PPE_PORT_BRIDGE_CTRL_TXMAC_EN;
	ret = ppe_qdx_write(priv, PPE_PORT_BRIDGE_CTRL(port), bridge,
			    PPE_PORT_BRIDGE_CTRL_TXMAC_EN);
	if (!ret) {
		priv->tx_bridge_owned[port] = false;
		return 0;
	}
	/* A failed readback may follow a real enable. Keep the native share
	 * and close the attempted output prefix before reporting that failure.
	 */
	error = regmap_read(priv->regmap, PPE_PORT_BRIDGE_CTRL(port), &bridge);
	if (!error)
		ppe_qdx_write(priv, PPE_PORT_BRIDGE_CTRL(port),
			bridge & ~PPE_PORT_BRIDGE_CTRL_TXMAC_EN, PPE_PORT_BRIDGE_CTRL_TXMAC_EN);
	ppe_qdx_tx_gates(priv, port, true, false);
	return ret;
}

static int ppe_qdx_tx_use_release(struct qca_ppe_priv *priv, struct qdx_ppe_tx *scope)
{
	unsigned int port = scope->port;
	int ret = 0;

	lockdep_assert_held(&priv->resource_lock);
	if (scope->held && priv->tx_holds[port] == 1) {
		ret = ppe_qdx_tx_gates(priv, port, false, true);
		if (!ret)
			ret = ppe_qdx_tx_bridge_restore(priv, port);
	}
	if (ret)
		return ret;
	if (scope->held)
		WRITE_ONCE(priv->tx_holds[port], priv->tx_holds[port] - 1);
	if (!priv->tx_holds[port])
		priv->tx_saved[port] = false;
	list_del(&scope->list);
	kfree(scope);
	return 0;
}

void ppe_qdx_tx_release(void *context, struct qdx_ppe_tx *scope)
{
	struct qca_ppe_priv *priv = context;
	unsigned int port = scope->port;
	int ret;

	qdx_ppe_tx_gate(priv->qdx, true);
	mutex_lock(&priv->resource_lock);
	ret = ppe_qdx_tx_use_release(priv, scope);
	if (ret)
		/* Existing native identity retirement retries this failed prefix. */
		scope->orphan = true;
	mutex_unlock(&priv->resource_lock);
	qdx_ppe_tx_gate(priv->qdx, false);
	if (ret)
		qdx_port_failed(priv->qdx, port, ret);
}

bool ppe_qdx_port_tx_held(struct qca_ppe_priv *priv, unsigned int port)
{
	return port < QCA_PPE_MAX_PORTS && READ_ONCE(priv->tx_holds[port]);
}

/* Called by the actual native identity retirement on real owner progress.
 * A failure remains visible and retained; it does not schedule a retry loop.
 */
int ppe_qdx_tx_queue_retry(struct qca_ppe_priv *priv, unsigned int port, u16 queue)
{
	struct qdx_ppe_tx *use, *next;
	int ret = 0;

	qdx_ppe_tx_gate(priv->qdx, true);
	mutex_lock(&priv->resource_lock);
	list_for_each_entry_safe(use, next, &priv->tx_uses, list) {
		if (!use->orphan || use->port != port || use->queue != queue)
			continue;
		ret = ppe_qdx_tx_use_release(priv, use);
		if (ret)
			break;
	}
	mutex_unlock(&priv->resource_lock);
	qdx_ppe_tx_gate(priv->qdx, false);
	return ret;
}

bool ppe_qdx_tx_queue_busy(struct qca_ppe_priv *priv, unsigned int port, u16 queue)
{
	struct qdx_ppe_tx *use;
	bool busy = false;

	mutex_lock(&priv->resource_lock);
	list_for_each_entry(use, &priv->tx_uses, list) {
		if (use->port == port && use->queue == queue) {
			busy = true;
			break;
		}
	}
	mutex_unlock(&priv->resource_lock);
	return busy;
}

/* The rate is in bytes/s at the typed boundary and bits/s in this equation.
 * The physical meter charges FRAME_CRC; it is not an NSS dequeue statistic.
 */
static int ppe_qdx_peak_encode(struct qdx_tc_peak *peak,
			       const struct qdx_tc_peak_params *params)
{
	static const u32 units[] = { 16384, 4096, 1024, 256, 64, 16, 4, 1 };
	u32 slot = FIELD_GET(PPE_PORT_SHAPER_SLOT, peak->slot);
	u64 bps, numerator, refresh, depth;
	unsigned int i;

	if (!params->rate_bytes_ps || !params->burst_bytes || !peak->hz || !slot ||
	    check_mul_overflow(params->rate_bytes_ps, 8ULL, &bps))
		return -ERANGE;
	for (i = 0; i < ARRAY_SIZE(units); i++) {
		if (check_mul_overflow(bps, (u64)slot * units[i], &numerator))
			continue;
		refresh = div64_u64(numerator, peak->hz);
		depth = DIV_ROUND_UP_ULL((u64)params->burst_bytes, 65536 / units[i]);
		if (!refresh || refresh > FIELD_MAX(PPE_PORT_SHAPER_REFRESH) ||
		    !depth || depth > FIELD_MAX(PPE_PORT_SHAPER_DEPTH))
			continue;
		peak->config[0] = FIELD_PREP(PPE_PORT_SHAPER_REFRESH, refresh) |
				  FIELD_PREP(PPE_PORT_SHAPER_DEPTH, depth);
		peak->config[1] = (peak->original_cfg[1] &
			~(PPE_PORT_SHAPER_UNIT | PPE_PORT_SHAPER_PACKETS)) |
			FIELD_PREP(PPE_PORT_SHAPER_UNIT, i) | PPE_PORT_SHAPER_ENABLE;
		peak->meter = (peak->original_meter & ~PPE_PORT_SHAPER_LENGTH) |
			FIELD_PREP(PPE_PORT_SHAPER_LENGTH, PPE_PORT_SHAPER_FRAME_CRC);
		return 0;
	}
	return -ERANGE;
}

/* HPPE commits the complete entry. Finish its one or two word writes before
 * readback, including an error prefix whose actual write is uncertain.
 */
static int ppe_qdx_peak_write(struct qca_ppe_priv *priv, u32 reg,
			      const u32 *values, unsigned int count)
{
	u32 actual[2] = {};
	unsigned int i;
	int ret = 0, error;

	for (i = 0; i < count; i++) {
		error = regmap_write(priv->regmap, reg + i * sizeof(u32), values[i]);
		if (error && !ret)
			ret = error;
	}
	for (i = 0; i < count; i++) {
		error = regmap_read(priv->regmap, reg + i * sizeof(u32), &actual[i]);
		if (error && !ret)
			ret = error;
	}
	if (!ret && memcmp(actual, values, count * sizeof(u32)))
		ret = -EIO;
	return ret;
}

/* This share is independent of any qid/path and never becomes a void-release
 * orphan. Its owner retains it if any gate write cannot be confirmed.
 */
static int ppe_qdx_peak_gate(struct qdx_tc_peak *peak, bool hold)
{
	struct qca_ppe_priv *priv = peak->priv;
	unsigned int port = peak->port;
	u32 bridge;
	int ret = 0, error;

	lockdep_assert_held(&priv->resource_lock);
	if (!hold) {
		if (!peak->held)
			return 0;
		if (priv->tx_holds[port] > 1) {
			WRITE_ONCE(priv->tx_holds[port], priv->tx_holds[port] - 1);
			peak->held = false;
			return 0;
		}
		/* Keep the bridge closed until every saved dequeue gate is restored.
		 * Publishing this resource never disposes already queued packets.
		 */
		ret = ppe_qdx_tx_gates(priv, port, false, false);
		if (!ret)
			ret = ppe_qdx_tx_bridge_restore(priv, port);
		if (!ret) {
			WRITE_ONCE(priv->tx_holds[port], priv->tx_holds[port] - 1);
			peak->held = false;
			priv->tx_saved[port] = false;
			return 0;
		}
		/* An incomplete reopen must retain and reclose this same share. */
	}
	if (!peak->held) {
		peak->held = true;
		WRITE_ONCE(priv->tx_holds[port], priv->tx_holds[port] + 1);
	}
	priv->tx_bridge_owned[port] = true;
	error = regmap_read(priv->regmap, PPE_PORT_BRIDGE_CTRL(port), &bridge);
	if (!error)
		error = ppe_qdx_write(priv, PPE_PORT_BRIDGE_CTRL(port),
			bridge & ~PPE_PORT_BRIDGE_CTRL_TXMAC_EN, PPE_PORT_BRIDGE_CTRL_TXMAC_EN);
	if (error && !ret)
		ret = error;
	error = ppe_qdx_tx_gates(priv, port, true, false);
	return ret ? ret : error;
}

static int ppe_qdx_peak_verify(struct qdx_tc_peak *peak)
{
	struct qca_ppe_priv *priv = peak->priv;
	u32 config[2], meter, slot, expected = peak->config[1];
	int ret;

	if (peak->error)
		return peak->error;
	if (!peak->prepared || peak->retiring || peak->restored)
		return -ESHUTDOWN;
	if (!peak->published)
		expected &= ~PPE_PORT_SHAPER_ENABLE;
	ret = regmap_bulk_read(priv->regmap, PPE_TM_PORT_SHAPER_CFG(peak->port),
			       config, ARRAY_SIZE(config));
	if (!ret)
		ret = regmap_read(priv->regmap, PPE_TM_PORT_SHAPER_METER(peak->port), &meter);
	if (!ret)
		ret = regmap_read(priv->regmap, PPE_TM_PORT_SHAPER_SLOT, &slot);
	if (ret)
		return ret;
	if (config[0] != peak->config[0] || config[1] != expected ||
	    meter != peak->meter || slot != peak->slot ||
	    clk_get_rate(peak->clock) != peak->hz)
		return -ESTALE;
	return 0;
}

static int ppe_qdx_peak_restore(struct qdx_tc_peak *peak)
{
	struct qca_ppe_priv *priv = peak->priv;
	unsigned int port = peak->port;
	int ret;

	peak->retiring = true;
	ret = ppe_qdx_peak_gate(peak, true);
	if (ret || peak->restored)
		return ret;
	/* Acquisition rejected an enabled original limiter. Restore its entire
	 * disabled entry before credit/sign, even after an uncertain enable.
	 */
	ret = ppe_qdx_peak_write(priv, PPE_TM_PORT_SHAPER_CFG(port),
				 peak->original_cfg, ARRAY_SIZE(peak->original_cfg));
	if (!ret)
		ret = ppe_qdx_peak_write(priv, PPE_TM_PORT_SHAPER_CREDIT(port),
					 &peak->original_credit, 1);
	if (!ret)
		ret = ppe_qdx_peak_write(priv, PPE_TM_PORT_SHAPER_SIGN(port),
					 &peak->original_sign, 1);
	if (!ret)
		ret = ppe_qdx_peak_write(priv, PPE_TM_PORT_SHAPER_METER(port),
					 &peak->original_meter, 1);
	if (!ret)
		peak->restored = true;
	return ret;
}

int ppe_qdx_peak_prepare(struct qca_ppe_priv *priv, unsigned int port,
			 const struct qdx_tc_peak_params *params,
			 struct qdx_tc_peak **result)
{
	struct qdx_tc_peak *peak;
	u32 config[2], value;
	bool gate;
	int ret, undo;

	ASSERT_RTNL();
	*result = NULL;
	if (!params || !priv->qdx || priv->data->type != PPE_TYPE_IPQ8074 ||
	    !port || port >= priv->data->num_ports || port == priv->data->loopback_port)
		return -EOPNOTSUPP;
	peak = kzalloc(sizeof(*peak), GFP_KERNEL);
	if (!peak)
		return -ENOMEM;
	peak->priv = priv;
	peak->port = port;
	peak->clock = clk_get(priv->ds.dev, "nss_ppe_clk");
	if (IS_ERR(peak->clock)) {
		ret = PTR_ERR(peak->clock);
		kfree(peak);
		return ret;
	}
	/* Terminal restore precedes attachment removal; native storage lives
	 * through this handle even when that attachment no longer does.
	 */
	gate = !READ_ONCE(priv->resources_terminal);
	if (gate)
		qdx_ppe_tx_gate(priv->qdx, true);
	mutex_lock(&priv->port_config[port].lock);
	mutex_lock(&priv->resource_lock);
	ret = -ESHUTDOWN;
	if (priv->resources_terminal)
		goto out;
	ret = -EBUSY;
	if (priv->peak_resources[port])
		goto out;
	ret = regmap_bulk_read(priv->regmap, PPE_TM_PORT_SHAPER_CFG(port),
			       peak->original_cfg, ARRAY_SIZE(peak->original_cfg));
	if (ret)
		goto out;
	if (peak->original_cfg[1] & PPE_PORT_SHAPER_ENABLE) {
		ret = -EBUSY;
		goto out;
	}
	ret = regmap_read(priv->regmap, PPE_TM_PORT_SHAPER_CREDIT(port),
			   &peak->original_credit);
	if (!ret)
		ret = regmap_read(priv->regmap, PPE_TM_PORT_SHAPER_SIGN(port),
				   &peak->original_sign);
	if (!ret)
		ret = regmap_read(priv->regmap, PPE_TM_PORT_SHAPER_METER(port),
				   &peak->original_meter);
	if (!ret)
		ret = regmap_read(priv->regmap, PPE_TM_PORT_SHAPER_SLOT, &peak->slot);
	if (ret)
		goto out;
	peak->hz = clk_get_rate(peak->clock);
	ret = ppe_qdx_peak_encode(peak, params);
	if (ret)
		goto out;
	/* Retain exact ownership before the first possibly partial mutation. */
	priv->peak_resources[port] = peak;
	*result = peak;
	ret = ppe_qdx_peak_gate(peak, true);
	config[0] = peak->config[0];
	config[1] = peak->config[1] & ~PPE_PORT_SHAPER_ENABLE;
	if (!ret)
		ret = ppe_qdx_peak_write(priv, PPE_TM_PORT_SHAPER_CFG(port),
					 config, ARRAY_SIZE(config));
	value = peak->original_credit & ~PPE_PORT_SHAPER_CREDIT;
	if (!ret)
		ret = ppe_qdx_peak_write(priv, PPE_TM_PORT_SHAPER_CREDIT(port), &value, 1);
	value = peak->original_sign & ~PPE_PORT_SHAPER_NEGATIVE;
	if (!ret)
		ret = ppe_qdx_peak_write(priv, PPE_TM_PORT_SHAPER_SIGN(port), &value, 1);
	if (!ret)
		ret = ppe_qdx_peak_write(priv, PPE_TM_PORT_SHAPER_METER(port), &peak->meter, 1);
	peak->prepared = !ret;
	peak->error = ret;
out:
	mutex_unlock(&priv->resource_lock);
	mutex_unlock(&priv->port_config[port].lock);
	if (gate)
		qdx_ppe_tx_gate(priv->qdx, false);
	if (!ret)
		return 0;
	if (*result) {
		undo = ppe_qdx_peak_release(peak);
		if (!undo)
			*result = NULL;
		return ret;
	}
	clk_put(peak->clock);
	kfree(peak);
	return ret;
}

int ppe_qdx_peak_publish(struct qdx_tc_peak *peak)
{
	struct qca_ppe_priv *priv = peak->priv;
	unsigned int port = peak->port;
	bool gate;
	int ret;

	ASSERT_RTNL();
	/* Terminal restore precedes attachment removal; native storage lives
	 * through this handle even when that attachment no longer does.
	 */
	gate = !READ_ONCE(priv->resources_terminal);
	if (gate)
		qdx_ppe_tx_gate(priv->qdx, true);
	mutex_lock(&priv->port_config[port].lock);
	mutex_lock(&priv->resource_lock);
	ret = priv->resources_terminal ? -ESHUTDOWN : ppe_qdx_peak_verify(peak);
	if (!ret && !peak->published) {
		/* The attempted enable is retained even if its write is uncertain. */
		peak->published = true;
		ret = ppe_qdx_peak_write(priv, PPE_TM_PORT_SHAPER_CFG(port),
					 peak->config, ARRAY_SIZE(peak->config));
	}
	if (!ret)
		ret = ppe_qdx_peak_gate(peak, false);
	if (ret) {
		peak->error = ret;
		ppe_qdx_peak_gate(peak, true);
	}
	mutex_unlock(&priv->resource_lock);
	mutex_unlock(&priv->port_config[port].lock);
	if (gate)
		qdx_ppe_tx_gate(priv->qdx, false);
	return ret;
}

int ppe_qdx_peak_release(struct qdx_tc_peak *peak)
{
	struct qca_ppe_priv *priv = peak->priv;
	unsigned int port = peak->port;
	bool gate;
	int ret;

	ASSERT_RTNL();
	/* Terminal restore precedes attachment removal; native storage lives
	 * through this handle even when that attachment no longer does.
	 */
	gate = !READ_ONCE(priv->resources_terminal);
	if (gate)
		qdx_ppe_tx_gate(priv->qdx, true);
	mutex_lock(&priv->port_config[port].lock);
	mutex_lock(&priv->resource_lock);
	/* Existing ownership can be restored after access end or native close. */
	ret = ppe_qdx_peak_restore(peak);
	if (!ret)
		ret = ppe_qdx_peak_gate(peak, false);
	if (!ret)
		priv->peak_resources[port] = NULL;
	mutex_unlock(&priv->resource_lock);
	mutex_unlock(&priv->port_config[port].lock);
	if (gate)
		qdx_ppe_tx_gate(priv->qdx, false);
	if (ret)
		return ret;
	clk_put(peak->clock);
	kfree(peak);
	return 0;
}

int ppe_qdx_resources_reapply(struct qca_ppe_priv *priv, unsigned int port)
{
	struct qca_ppe_rx_resource *rx;
	struct qdx_tc_peak *peak;
	unsigned int priority;
	int ret = 0;

	qdx_ppe_tx_gate(priv->qdx, true);
	mutex_lock(&priv->resource_lock);
	peak = priv->peak_resources[port];
	if (peak) {
		if (priv->resources_terminal || peak->retiring)
			ret = ppe_qdx_peak_restore(peak);
		else
			ret = ppe_qdx_peak_verify(peak);
		if (ret) {
			peak->error = ret;
			ppe_qdx_peak_gate(peak, true);
			goto out;
		}
	}
	/* Restore the native CPU queue baseline after firmware port commands.
	 * Class offsets must not spread queue 0 traffic into reserved RX queues.
	 */
	for (priority = 0; priority < 16; priority++) {
		ret = ppe_qdx_write(priv, PPE_QM_UCAST_PRI_MAP(priority), 0,
				    PPE_QM_PRI_CLASS);
		if (ret)
			goto out;
	}
	rx = priv->rx_resources[port];
	if (rx && !rx->restored) {
		if (rx->closing || priv->resources_terminal)
			ret = ppe_qdx_rx_restore(priv, rx);
		else
			ret = ppe_qdx_rx_apply(priv, rx);
	}
	if (!ret && priv->tx_holds[port])
		ret = ppe_qdx_tx_gates(priv, port, true, false);
out:
	mutex_unlock(&priv->resource_lock);
	qdx_ppe_tx_gate(priv->qdx, false);
	return ret;
}

int ppe_qdx_resources_restore(struct qca_ppe_priv *priv)
{
	struct qdx_ppe_tx *use, *next;
	unsigned int port;
	int ret = 0;

	qdx_ppe_tx_gate(priv->qdx, true);
	mutex_lock(&priv->resource_lock);
	priv->resources_terminal = true;
	/* Restore native row state but keep each live TC handle and its hold.
	 * The original consumer releases it before its native queue identities.
	 */
	for (port = 1; port < priv->data->num_ports; port++) {
		if (!priv->peak_resources[port])
			continue;
		ret = ppe_qdx_peak_restore(priv->peak_resources[port]);
		if (ret)
			goto out;
	}
	for (port = 1; port < priv->data->num_ports; port++) {
		struct qca_ppe_rx_resource *rx = priv->rx_resources[port];

		if (!rx)
			continue;
		ret = ppe_qdx_rx_restore(priv, rx);
		if (ret)
			goto out;
		if (!rx->users) {
			priv->rx_resources[port] = NULL;
			kvfree(rx);
		}
	}
	list_for_each_entry_safe(use, next, &priv->tx_uses, list) {
		if (!use->orphan)
			continue;
		ret = ppe_qdx_tx_use_release(priv, use);
		if (ret)
			goto out;
	}
	/* Live required scopes still own their hold through terminal recovery. */
	for (port = 1; port < priv->data->num_ports; port++) {
		if (!priv->tx_holds[port])
			continue;
		ret = ppe_qdx_tx_gates(priv, port, true, false);
		if (ret)
			goto out;
	}
out:
	mutex_unlock(&priv->resource_lock);
	qdx_ppe_tx_gate(priv->qdx, false);
	return ret;
}

void ppe_qdx_resources_init(struct qca_ppe_priv *priv)
{
	mutex_init(&priv->resource_lock);
	INIT_LIST_HEAD(&priv->tx_uses);
}
