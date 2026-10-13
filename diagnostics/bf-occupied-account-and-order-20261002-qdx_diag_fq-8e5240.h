/* SPDX-License-Identifier: GPL-2.0-only */
/* Isolated fixed-firmware diagnostic, not a product QDX interface. */
#ifndef _LINUX_QDX_DIAG_FQ_H
#define _LINUX_QDX_DIAG_FQ_H
#include <linux/qdx.h>
#define QDX_DIAG_FQ_PACKETS 16
#define QDX_DIAG_FQ_NODE_BYTES 280
enum qdx_diag_fq_range {
 QDX_DIAG_FQ_NODE, QDX_DIAG_FQ_CARRIER, QDX_DIAG_FQ_METADATA,
 QDX_DIAG_FQ_PAYLOAD, QDX_DIAG_FQ_CLOCK,
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
