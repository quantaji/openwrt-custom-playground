/* SPDX-License-Identifier: GPL-2.0-only */
/* Isolated fixed-firmware rate-history experiment; not a product interface. */
#ifndef _LINUX_QDX_DIAG_RATE_H
#define _LINUX_QDX_DIAG_RATE_H
#include <linux/qdx_diag_fq.h>
#define QDX_RATE_SELECTOR_VALID BIT(0)
#define QDX_RATE_TBL_VALID BIT(1)
#define QDX_RATE_CLOCK_VALID BIT(2)
#define QDX_RATE_ALLOCATOR_VALID BIT(3)
#define QDX_RATE_HEADER_VALID BIT(4)
#define QDX_RATE_ACCOUNT_VALID BIT(5)
#define QDX_RATE_GROUP_VALID(i) BIT(6 + (i))
#define QDX_RATE_CLOCK_ACCOUNT_VALID BIT(10)
/* epoch[0] is an actual inactive-manager observation after all owned timers
 * were unqueued; policy fields are copied again after that join. */
#define QDX_RATE_TIMERS_JOINED BIT(11)
struct qdx_diag_rate_view {
 bool group_mode;
 u32 valid;
 u8 selector[320], tbl[188], clock_tbl[188];
 u8 allocator[24], account_header[64], account[312], clock_account[312];
 u8 group[4][1004], spare[1004];
 u8 timer[32], notifier[16], epoch[2][20], frequency[2][8];
 u64 clock_ms[2];
};
/* List entries are three semantic child indices0..2; no raw pointers. */
struct qdx_diag_rate_state {
 s64 credit[4][2];
 u64 reference[4][2];
 s32 deficit[3][2];
 u8 preferred[3], borrowing[3], preferred_count;
};
int qdx_diag_rate_import(struct qdx_packet_op *operation, struct qdx_dma *region,
 struct qdx_packet_op *loans, const struct qdx_diag_fq_view *view,
 const struct qdx_diag_rate_state *state, const struct qdx_owner *owner);
#endif
