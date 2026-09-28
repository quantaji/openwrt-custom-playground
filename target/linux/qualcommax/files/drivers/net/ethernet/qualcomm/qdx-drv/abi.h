/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _QDX_ABI_H
#define _QDX_ABI_H

#include <linux/build_bug.h>
#include <linux/stddef.h>
#include <linux/types.h>

/* NSS.HK.11.4.0.5-6-R wire ABI; no host pointer crosses this boundary. */
#define QDX_CORES		2
#define QDX_H2N_RINGS		11
#define QDX_N2H_RINGS		5
#define QDX_RING_DEPTH		128
#define QDX_RING_STRIDE		((QDX_RING_DEPTH + 2) * 32)
#define QDX_COMMAND_SIZE		1984
#define QDX_MAP_MAGIC		0x4e52522e
#define QDX_MAP_VERSION		1
#define QDX_MESSAGE_VERSION	1
#define QDX_MEM_RESERVE_MAGIC	0x9526
#define QDX_MEM_MAP_MAGIC		0x9527
#define QDX_MEM_REQUEST_MAGIC	0x9528
#define QDX_MEM_END_MAGIC		0x9529
#define QDX_MEM_MAP_SIZE		4096

#define QDX_H2N_EMPTY		0
#define QDX_H2N_PAGED_EMPTY	1
#define QDX_H2N_PACKET		2
#define QDX_H2N_CTRL		4
#define QDX_H2N_RETURNED		9
#define QDX_H2N_BRIDGE_RETURNED	10
#define QDX_N2H_EMPTY		1
#define QDX_N2H_PACKET		3
#define QDX_N2H_COMMAND_RESP	5
#define QDX_N2H_STATUS		6
#define QDX_N2H_VIRTUAL		10
#define QDX_N2H_RETURNED		11
#define QDX_N2H_BRIDGE_RETURNED	12
#define QDX_N2H_EXTENDED		13
#define QDX_N2H_INGRESS_SHAPED	0x0010
#define QDX_DESC_FIRST		0x0004
#define QDX_DESC_LAST		0x0008
#define QDX_DESC_NO_CSUM		0x0010
#define QDX_DESC_REUSABLE		0x8000
#define QDX_RESPONSE_ACK		0
#define QDX_RESPONSE_NOTIFY	5
#define QDX_RESPONSE_MAX		6

#define QDX_IF_N2H		156
#define QDX_IF_ETH_RX		158
#define QDX_IF_OPEN		0
#define QDX_IF_CLOSE		1
#define QDX_IF_LINK		2
#define QDX_IF_MTU		3
#define QDX_IF_MAC		4
#define QDX_IF_C2C_TX		168
#define QDX_N2H_GET_POOL		7
#define QDX_N2H_DDR		9
#define QDX_N2H_GET_PAGED_POOL	13
#define QDX_C2C_MAP		1

#define QDX_CLOCK_RATE 748800000U
#define QDX_FREQUENCY_CHANGE 1
#define QDX_FREQUENCY_ACK 2
struct qdx_frequency {
	__le32 frequency;
	__le32 step;
	__le32 stats_enable;
	__le32 current_frequency;
	__le32 ack;
};

struct qdx_ddr_info {
	__le32 size;
	__le32 start;
	__le32 cores;
	__le32 reserved_size;
};

struct qdx_pool_info {
	__be32 pool;
	__be32 low;
	__be32 high;
};

struct qdx_c2c_map {
	__le32 address;
	__le32 interrupt;
};

/* Host mailbox channel purpose, independent of descriptor queue number. */
enum qdx_doorbell {
	QDX_DB_EMPTY,
	QDX_DB_COMMAND,
	QDX_DB_UNBLOCKED,
	QDX_DB_COREDUMP,
	QDX_DB_PAGED,
	QDX_DOORBELLS,
};

struct qdx_h2n_desc {
	__le32 interface;
	__le32 buffer;
	__le32 qos;
	__le16 buffer_len;
	__le16 payload_len;
	__le16 mss;
	__le16 payload_off;
	__le16 flags;
	u8 type;
	u8 reserved;
	__le64 opaque;
};

struct qdx_n2h_desc {
	__le32 interface;
	__le32 buffer;
	__le16 buffer_len;
	__le16 payload_len;
	__le16 payload_off;
	__le16 flags;
	u8 type;
	u8 response;
	u8 priority;
	u8 service;
	__le32 reserved;
	__le64 opaque;
};

struct qdx_ring_meta {
	__le32 address;
	__le16 size;
	__le16 reserved;
};

struct qdx_ifmap {
	struct qdx_ring_meta h2n[16];
	struct qdx_ring_meta n2h[15];
	__le32 magic;
	__le16 version;
	u8 h2n_count;
	u8 n2h_count;
	__le32 h2n_firmware[16];
	__le32 n2h_firmware[15];
	u8 physical_ports;
	u8 reserved1[3];
	__le32 h2n_host[16];
	__le32 n2h_host[15];
	__le32 reserved2;
};

struct qdx_cmn {
	__le16 version;
	__le16 length;
	__le32 interface;
	__le32 response;
	__le32 type;
	__le32 error;
	__le32 reserved;
	__le64 host_tag;
	__le64 request_id;
};

struct qdx_mem_request {
	__le16 magic;
	char name[48];
	__le16 type;
	__le16 selected_type;
	__le16 reserved;
	__le32 alignment;
	__le32 size;
	__le32 address;
};

static_assert(sizeof(struct qdx_h2n_desc) == 32);
static_assert(sizeof(struct qdx_n2h_desc) == 32);
static_assert(offsetof(struct qdx_h2n_desc, opaque) == 24);
static_assert(offsetof(struct qdx_n2h_desc, opaque) == 24);
static_assert(sizeof(struct qdx_ifmap) == 512);
static_assert(offsetof(struct qdx_ifmap, magic) == 248);
static_assert(offsetof(struct qdx_ifmap, h2n_firmware) == 256);
static_assert(offsetof(struct qdx_ifmap, h2n_host) == 384);
static_assert(sizeof(struct qdx_cmn) == 40);
static_assert(offsetof(struct qdx_cmn, host_tag) == 24);
static_assert(sizeof(struct qdx_mem_request) == 68);
static_assert(offsetof(struct qdx_mem_request, alignment) == 56);
static_assert(offsetof(struct qdx_mem_request, address) == 64);

#endif
