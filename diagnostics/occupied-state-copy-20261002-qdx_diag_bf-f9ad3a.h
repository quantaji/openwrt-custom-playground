/* SPDX-License-Identifier: GPL-2.0-only */
/* Fixed, isolated BF continuation diagnostic; not a product interface. */
#ifndef _LINUX_QDX_DIAG_BF_H
#define _LINUX_QDX_DIAG_BF_H
#include <linux/qdx_diag_fq.h>
struct qdx_diag_bf_state {
 u8 current_account[312], timer[32], notifier[16];
 u8 epoch[2][20], frequency[2][8];
 u64 clock_ms[2];
 s64 credit;
 u64 reference;
 s32 deficit[2];
};
int qdx_diag_bf_pin(struct qdx_packet_op *operation, struct qdx_dma *region,
 struct qdx_packet_op *loans, const struct qdx_diag_fq_view *view,
 const struct qdx_owner *owner);
int qdx_diag_bf_import(struct qdx_packet_op *operation, struct qdx_dma *region,
 struct qdx_packet_op *loans, const struct qdx_diag_fq_view *view,
 const struct qdx_diag_bf_state *state, const struct qdx_owner *owner);
#endif
