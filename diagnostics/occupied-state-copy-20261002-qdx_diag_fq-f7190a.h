/* SPDX-License-Identifier: GPL-2.0-only */
/* Isolated fixed-firmware diagnostic, not a product QDX interface. */
#ifndef _LINUX_QDX_DIAG_FQ_H
#define _LINUX_QDX_DIAG_FQ_H
#include <linux/qdx.h>
#define QDX_DIAG_FQ_PACKETS 16
struct qdx_diag_rate_view;
struct qdx_diag_aqm_view;
#define QDX_DIAG_FQ_NODE_BYTES 280
enum qdx_diag_fq_range {
 QDX_DIAG_FQ_NODE, QDX_DIAG_FQ_CARRIER, QDX_DIAG_FQ_METADATA,
 QDX_DIAG_FQ_PAYLOAD, QDX_DIAG_FQ_CLOCK,
 QDX_DIAG_BF_GROUP, QDX_DIAG_BF_PARENT, QDX_DIAG_BF_ACCOUNT,
 QDX_DIAG_BF_TIMER, QDX_DIAG_BF_NOTIFIER, QDX_DIAG_BF_ALLOCATOR,
 QDX_DIAG_BF_ACCOUNT_HEADER, QDX_DIAG_BF_EPOCH, QDX_DIAG_BF_FREQUENCY,
 QDX_DIAG_WRR_ANCHOR_GROUP, QDX_DIAG_WRR_ROOT, QDX_DIAG_WRR_GROUP,
 QDX_DIAG_RATE_SELECTOR, QDX_DIAG_RATE_TBL, QDX_DIAG_RATE_ACCOUNT,
 QDX_DIAG_RATE_TIMER, QDX_DIAG_RATE_NOTIFIER, QDX_DIAG_RATE_CLOCK_TBL,
 QDX_DIAG_RATE_CLOCK_ACCOUNT, QDX_DIAG_RATE_ALLOCATOR, QDX_DIAG_RATE_ACCOUNT_HEADER,
 QDX_DIAG_RATE_GROUP_ROOT, QDX_DIAG_RATE_GROUP_CHILD, QDX_DIAG_RATE_SPARE_GROUP,
 QDX_DIAG_RATE_EPOCH, QDX_DIAG_RATE_FREQUENCY, QDX_DIAG_RATE_CLOCK,
 QDX_DIAG_AQM_SELECTOR, QDX_DIAG_AQM_NODE, QDX_DIAG_AQM_CARRIER,
 QDX_DIAG_AQM_METADATA, QDX_DIAG_AQM_PAYLOAD, QDX_DIAG_AQM_CLOCK,
};
/* Filled only by completed MIRROR callbacks in the pinned diagnostic. The
 * module seals the unpublished graph; the driver validates actual loans.
 */
struct qdx_diag_fq_view {
 u8 table[144], node[280];
 u8 carrier[16][64], metadata[16][96];
 u32 carrier_address[16];
 u16 carrier_valid, metadata_valid;
 bool node_valid;
 /* Optional closed physical rebuild path; only compared against a real carrier. */
 const struct qdx_tx_path *physical_rebuild;
 /* Explicit BF fixture; every address derives from this actual leaf. */
 bool bf;
 u8 bf_valid, bf_group[232], bf_parent[200], bf_allocator[24], bf_header[64];
 const struct qdx_diag_rate_view *rate;
 const struct qdx_diag_aqm_view *aqm;
 bool wrr;
 u8 wrr_valid, wrr_root[188], wrr_group[3][196];
};
struct qdx_ready qdx_diag_fq_owned_copy(struct qdx_packet_op *operation,
 struct qdx_dma *region, struct qdx_packet_op *loans,
 const struct qdx_diag_fq_view *view, enum qdx_diag_fq_range kind,
 unsigned int index, const struct qdx_packet_recipient *recipient);
int qdx_diag_fq_age_import(struct qdx_packet_op *operation, struct qdx_dma *region,
 struct qdx_packet_op *loans, const struct qdx_diag_fq_view *view,
 unsigned int index, u64 age, const struct qdx_owner *owner);
int qdx_diag_fq_node_import(struct qdx_packet_op *operation, struct qdx_dma *region,
 struct qdx_packet_op *loans, const struct qdx_diag_fq_view *view,
 const u32 values[8], const struct qdx_owner *owner);
int qdx_diag_fq_clock_host(struct qdx_packet_op *operation, struct qdx_dma *region,
 struct qdx_packet_op *loans, const struct qdx_diag_fq_view *view,
 const struct qdx_owner *owner, u32 words[6]);
#endif
