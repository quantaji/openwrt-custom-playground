/* SPDX-License-Identifier: GPL-2.0-only */
/* NSS 11.4 wire facts from Qualcomm exports/nss_if.h, nss_shaper.h,
 * nss_match.h, nss_mirror.h and nss_dynamic_interface.h. The driver transport
 * owns the common message header. Only payloads consumed by qdx-tc are here.
 *
 * The source ABI declarations carry the following permission:
 * Copyright (c) 2014, 2017-2018 The Linux Foundation. All rights reserved.
 * Copyright (c) 2014-2021, The Linux Foundation. All rights reserved.
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#ifndef _QDX_TC_WIRE_H
#define _QDX_TC_WIRE_H

#include <linux/build_bug.h>
#include <linux/types.h>

#define QDX_TC_ETH_RX_IFNUM 158
/* Node/control and packet tags use the upper half; flow IGS uses that u16. */
#define QDX_SHAPER_TAG_SHIFT 16

enum qdx_tc_interface_command {
	QDX_TC_ISHAPER_ASSIGN = 6,
	QDX_TC_ISHAPER_UNASSIGN = 8,
	QDX_TC_ISHAPER_CONFIG = 10,
	QDX_TC_SET_NEXTHOP = 15,
	QDX_TC_SET_IGS = 16,
	QDX_TC_CLEAR_IGS = 17,
	QDX_TC_RESET_NEXTHOP = 18,
};

enum qdx_tc_dynamic_type {
	QDX_TC_DYNAMIC_IGS = 53,
	QDX_TC_DYNAMIC_MATCH = 58,
	QDX_TC_DYNAMIC_MIRROR = 65,
};

enum qdx_shaper_kind {
	QDX_SHAPER_CODEL = 1,
	QDX_SHAPER_PRIO = 3,
	QDX_SHAPER_FIFO = 4,
	QDX_SHAPER_TBL = 5,
	QDX_SHAPER_HTB = 11,
	QDX_SHAPER_HTB_GROUP = 12,
	QDX_SHAPER_RED = 13,
};

enum qdx_shaper_command {
	QDX_SHAPER_ALLOC = 0,
	QDX_SHAPER_FREE = 1,
	QDX_SHAPER_SET_DEFAULT = 2,
	QDX_SHAPER_SET_ROOT = 3,
	QDX_SHAPER_STATS = 4,
	QDX_SHAPER_ATTACH = 5,
	QDX_SHAPER_DETACH = 6,
	QDX_SHAPER_CONFIG = 7,
	QDX_SHAPER_MEMORY = 10,
};

struct qdx_shaper_rate {
	__le32 rate_bytes_ps;
	__le32 burst_bytes;
	__le32 max_size;
	u8 short_circuit;
	u8 reserved[3];
};

struct qdx_shaper_codel {
	__le32 limit_packets;
	__le16 interval_ms;
	__le16 target_ms;
	__le16 mtu;
	__le16 reserved;
	__le32 flows;
	__le32 flows_memory;
	__le32 flows_memory_size;
	__le32 quantum;
	__le32 ecn;
};

struct qdx_shaper_tbf {
	struct qdx_shaper_rate rate;
	struct qdx_shaper_rate peak;
};

struct qdx_shaper_htb {
	__le32 quantum;
	__le32 priority;
	__le32 overhead;
	struct qdx_shaper_rate rate;
	struct qdx_shaper_rate ceil;
};

struct qdx_shaper_red {
	__le32 limit_bytes;
	__le32 weight_mode;
	__le32 traffic_classes;
	__le32 default_class;
	__le32 traffic_id;
	__le32 weight_value;
	__le32 minimum;
	__le32 maximum;
	__le32 probability;
	__le32 ewma_log;
	u8 ecn;
	u8 reserved[3];
};

union qdx_shaper_parameters {
	struct qdx_shaper_codel codel;
	struct qdx_shaper_tbf tbf;
	struct qdx_shaper_htb htb;
	struct qdx_shaper_red red;
	struct { __le32 limit_packets, drop_mode; } fifo;
	struct { __le32 child, priority; } attach;
	__le32 memory_per_flow;
	__le32 reserved[11];
};

struct qdx_shaper_stats {
	__le32 qlen_bytes;
	__le32 qlen_packets;
	__le32 reserved[4];
	__le32 enqueue_bytes;
	__le32 enqueue_packets;
	__le32 enqueue_drop_bytes;
	__le32 enqueue_drop_packets;
	__le32 dequeue_bytes;
	__le32 dequeue_packets;
	__le32 dequeue_drop_bytes;
	__le32 dequeue_drop_packets;
	__le32 overruns;
	__le32 delta_reserved[4];
	__le32 peak_dequeue_ms;
	__le32 peak_drop_ms;
	__le32 new_flows;
	__le32 ecn_marks;
	__le32 new_list_length;
	__le32 old_list_length;
	__le32 max_packet;
};

struct qdx_shaper_message {
	__le32 command;
	__le32 response;
	union {
		struct { __le32 kind, tag; } allocate;
		__le32 tag;
		struct {
			__le32 tag;
			union qdx_shaper_parameters parameters;
		} node;
		struct {
			__le32 tag;
			struct qdx_shaper_stats values;
		} stats;
	} data;
};

struct qdx_shaper_assignment {
	__le32 shaper;
	__le32 assigned;
};

#define QDX_MATCH_RULES 32
#define QDX_MATCH_MASKS 2
#define QDX_MATCH_MASK_WORDS 4

enum qdx_match_command {
	QDX_MATCH_CONFIG = 1,
	QDX_MATCH_VOW_ADD = 2,
	QDX_MATCH_L2_ADD = 3,
	QDX_MATCH_VOW_DELETE = 4,
	QDX_MATCH_L2_DELETE = 5,
};

enum qdx_match_profile { QDX_MATCH_VOW = 1, QDX_MATCH_L2 = 2 };
enum qdx_match_effect { QDX_MATCH_SET_PRIORITY = 1, QDX_MATCH_DROP = 4 };

struct qdx_match_config {
	__le32 profile;
	__le32 valid_masks;
	__le32 masks[QDX_MATCH_MASKS][QDX_MATCH_MASK_WORDS];
};

struct qdx_match_action {
	__le32 effects;
	__le32 forward_ifnum;
	__le16 priority;
	__le16 reserved;
};

struct qdx_match_vow {
	__le16 rule;
	__le16 mask;
	struct qdx_match_action action;
	__le32 source_ifnum;
	u8 dscp;
	u8 outer_pcp;
	u8 inner_pcp;
	u8 reserved;
};

struct qdx_match_l2 {
	__le16 rule;
	__le16 mask;
	struct qdx_match_action action;
	__le32 source_ifnum;
	__le16 destination[3];
	__le16 source[3];
	__le16 protocol;
	__le16 reserved;
};

enum qdx_mirror_command {
	QDX_MIRROR_CONFIG = 0,
	QDX_MIRROR_ENABLE = 1,
	QDX_MIRROR_DISABLE = 2,
	QDX_MIRROR_SET_NEXTHOP = 3,
	QDX_MIRROR_RESET_NEXTHOP = 4,
};

struct qdx_mirror_config {
	__le32 clone_point;
	__le16 clone_size;
	__le16 clone_offset;
};

static_assert(sizeof(struct qdx_shaper_rate) == 16);
static_assert(sizeof(struct qdx_shaper_codel) == 32);
static_assert(sizeof(struct qdx_shaper_htb) == 44);
static_assert(sizeof(struct qdx_shaper_stats) == 104);
static_assert(sizeof(struct qdx_shaper_message) == 116);
static_assert(sizeof(struct qdx_match_config) == 40);
static_assert(sizeof(struct qdx_match_vow) == 24);
static_assert(sizeof(struct qdx_match_l2) == 36);

#endif
