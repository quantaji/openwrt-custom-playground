/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef QDX_FINITE_FIFO_DIAG_H
#define QDX_FINITE_FIFO_DIAG_H
#include <linux/types.h>
struct qdx_endpoint;
int qdx_finite_fifo_acquire(struct qdx_endpoint **bound, u32 *tag);
void qdx_finite_fifo_put(struct qdx_endpoint *bound);
#endif
