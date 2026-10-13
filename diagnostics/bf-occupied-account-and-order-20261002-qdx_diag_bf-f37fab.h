/* SPDX-License-Identifier: GPL-2.0-only */
/* Fixed, isolated BF continuation diagnostic; not a product interface. */
#ifndef _LINUX_QDX_DIAG_BF_H
#define _LINUX_QDX_DIAG_BF_H
#include <linux/qdx_diag_fq.h>
struct qdx_diag_bf_state {
 u8 current_account[312], timer[32], notifier[16];
 u8 epoch[2][20], frequency[2][8];
 u64 clock_ms[2];
 bool timer_joined; /* Own wait/queued clear, then manager inactive, then reread. */
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
/* Owned spare account, reached through the actual two-member BF parent. */
struct qdx_diag_bf_pair {
 u8 valid, group[232], account[312], timer[32], notifier[16], header[64];
};
enum qdx_diag_bf_pair_action {
 QDX_DIAG_BF_PAIR_PREPARE, QDX_DIAG_BF_PAIR_PUBLISH, QDX_DIAG_BF_PAIR_RESTORE,
};
struct qdx_diag_bf_pair_update {
 enum qdx_diag_bf_pair_action action;
 u32 original_account;
 s64 credit;
 u64 reference;
 s32 deficit;
};
int qdx_diag_bf_pair_write(struct qdx_packet_op *operation, struct qdx_dma *region,
 struct qdx_packet_op *loans, const struct qdx_diag_fq_view *view,
 const struct qdx_diag_bf_state *observed, const struct qdx_diag_bf_pair_update *update,
 const struct qdx_owner *owner);
#endif
