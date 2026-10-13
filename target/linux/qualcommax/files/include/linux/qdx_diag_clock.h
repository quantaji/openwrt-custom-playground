/* SPDX-License-Identifier: GPL-2.0-only */
/* Fixed-firmware isolated diagnostic; not a product interface. */
#ifndef _LINUX_QDX_DIAG_CLOCK_H
#define _LINUX_QDX_DIAG_CLOCK_H
#include <linux/completion.h>
#include <linux/qdx.h>
#define QDX_DIAG_CLOCK_TAG 0x434c4f4bU
struct qdx_diag_clock_sample {
	struct completion done;
	u64 published_ns, returned_ns, read_begin_ns, read_end_ns, retired_ns;
	u32 words[6], type, ifnum;
	int error;
};
/* Caller keeps sample and module alive until actual done, including timeout.
 * Source is always core0 fixed DDR 40301a58, extent24, no caller address.
 */
struct qdx_ready qdx_diag_clock_submit(struct qdx_packet_op *operation,
	struct qdx_diag_clock_sample *sample, const struct qdx_owner *owner);
#endif
