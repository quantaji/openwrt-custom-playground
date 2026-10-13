/* SPDX-License-Identifier: GPL-2.0-only */
/* Bounded fixed-image AQM continuation diagnostic, not a product interface. */
#ifndef _LINUX_QDX_DIAG_AQM_H
#define _LINUX_QDX_DIAG_AQM_H
#include <linux/qdx_diag_fq.h>
/* Normal packet lookup clears the low16 bits; each leaf needs its own key. */
#define QDX_AQM_PARENT_TAG 0x710d0000U
#define QDX_AQM_LEAF_A_TAG 0x710e0000U
#define QDX_AQM_LEAF_B_TAG 0x710f0000U
#define QDX_AQM_LEAF_C_TAG 0x71100000U
#define QDX_AQM_LEAF_D_TAG 0x71110000U
#define QDX_AQM_SELECTOR_VALID BIT(0)
#define QDX_AQM_NODE_VALID BIT(1)
struct qdx_diag_aqm_view {
 bool plain;
 u8 valid;
 /* Held closed operation for actual data, distinct from the discovery anchor. */
 struct qdx_packet_op *data;
 const struct qdx_tx_path *physical_rebuild;
 u8 selector[320], node[520], carrier[16][64], metadata[16][96];
 u32 carrier_address[16];
 u16 carrier_valid, metadata_valid;
};
struct qdx_diag_aqm_state {
 u32 average[7], occupancy[7], count;
 u64 idle, first_above, drop_next;
 u32 codel_count, delay_max, delay_min;
 u8 active, dropping;
};
int qdx_diag_aqm_import(struct qdx_packet_op *operation, struct qdx_dma *region,
 struct qdx_packet_op *anchor, const struct qdx_diag_fq_view *view,
 const struct qdx_diag_aqm_state *state, const struct qdx_owner *owner);
int qdx_diag_aqm_age_import(struct qdx_packet_op *operation, struct qdx_dma *region,
 struct qdx_packet_op *anchor, const struct qdx_diag_fq_view *view,
 unsigned int index, u64 age, const struct qdx_owner *owner);
#endif
