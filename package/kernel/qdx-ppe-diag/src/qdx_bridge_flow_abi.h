/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _QDX_FLOW_NSS_H
#define _QDX_FLOW_NSS_H

#include <linux/build_bug.h>
#include <linux/types.h>

/* NSS 11.4 wire layouts, from nss-drv/exports/nss_ipv4.h and nss_ipv6.h.
 * Scalars use the IPQ807x firmware's little-endian host representation.
 * IP address words are numeric host-order words, not network-order bytes;
 * IPv6 keeps network word order. MAC fields contain the six raw address bytes.
 * These are protocol definitions, without the vendor's driver/policy objects.
 */
enum qdx_nss_ip_message {
	QDX_NSS_IP_CREATE = 0,
	QDX_NSS_IP_DESTROY = 1,
	QDX_NSS_IP_SYNC = 3,
	QDX_NSS_IP_SYNC_MANY = 7,
};

enum qdx_nss_sync_reason {
	QDX_NSS_SYNC_STATS,
	QDX_NSS_SYNC_FLUSH,
	QDX_NSS_SYNC_EVICT,
	QDX_NSS_SYNC_DESTROY,
};

#define QDX_NSS_CONN_VALID	0x0001
#define QDX_NSS_TCP_VALID		0x0002
#define QDX_NSS_PPPOE_VALID	0x0004
#define QDX_NSS_QOS_VALID		0x0008
#define QDX_NSS_VLAN_VALID	0x0010
#define QDX_NSS_SRC_MAC_VALID	0x0080
#define QDX_NSS_NEXTHOP_VALID	0x0100
#define QDX_NSS_IGS_VALID		0x0800
#define QDX_NSS_NO_SEQ_CHECK	0x0001
#define QDX_NSS_ROUTED		0x0004
#define QDX_NSS_SOURCE_CHECK	0x0400
#define QDX_NSS_UNTAGGED		0x0fff
#define QDX_NSS_RESPONSE_NOTIFY	5

struct qdx_nss_ipv4_tuple {
	__le32 flow_ip;
	__le32 flow_ident;
	__le32 return_ip;
	__le32 return_ident;
	u8 protocol;
	u8 reserved[3];
};

struct qdx_nss_ipv6_tuple {
	__le32 flow_ip[4];
	__le32 flow_ident;
	__le32 return_ip[4];
	__le32 return_ident;
	u8 protocol;
	u8 reserved[3];
};

struct qdx_nss_ipv4_connection {
	u8 flow_mac[6];
	u8 return_mac[6];
	__le32 flow_interface_num;
	__le32 return_interface_num;
	__le32 flow_mtu;
	__le32 return_mtu;
	__le32 flow_ip_xlate;
	__le32 return_ip_xlate;
	__le32 flow_ident_xlate;
	__le32 return_ident_xlate;
};

struct qdx_nss_ipv6_connection {
	u8 flow_mac[6];
	u8 return_mac[6];
	__le32 flow_interface_num;
	__le32 return_interface_num;
	__le32 flow_mtu;
	__le32 return_mtu;
};

/* The two TCP layouts differ in field order in the actual firmware ABI. */
struct qdx_nss_ipv4_tcp {
	__le32 flow_max_window;
	__le32 return_max_window;
	__le32 flow_end;
	__le32 return_end;
	__le32 flow_max_end;
	__le32 return_max_end;
	u8 flow_window_scale;
	u8 return_window_scale;
	__le16 reserved;
};

struct qdx_nss_ipv6_tcp {
	__le32 flow_max_window;
	__le32 flow_end;
	__le32 flow_max_end;
	__le32 return_max_window;
	__le32 return_end;
	__le32 return_max_end;
	u8 flow_window_scale;
	u8 return_window_scale;
	__le16 reserved;
};

struct qdx_nss_pppoe {
	__le32 flow_if_exist;
	__le32 flow_if_num;
	__le32 return_if_exist;
	__le32 return_if_num;
};

struct qdx_nss_qos {
	__le32 flow_qos_tag;
	__le32 return_qos_tag;
};

struct qdx_nss_dscp {
	u8 flow_dscp;
	u8 return_dscp;
	u8 reserved[2];
};

struct qdx_nss_vlan {
	__le32 ingress_vlan_tag;
	__le32 egress_vlan_tag;
};

struct qdx_nss_source_mac {
	__le32 mac_valid_flags;
	u8 flow_src_mac[6];
	u8 return_src_mac[6];
};

struct qdx_nss_nexthop {
	__le32 flow_nexthop;
	__le32 return_nexthop;
};

struct qdx_nss_rps {
	u8 flow_rps;
	u8 return_rps;
	u8 reserved[2];
};

struct qdx_nss_igs {
	__le16 flow_qos_tag;
	__le16 return_qos_tag;
};

struct qdx_nss_identifier {
	__le32 valid;
	__le32 flow;
	__le32 reply;
};

struct qdx_nss_mirror {
	__le32 valid;
	__le32 flow_ifnum;
	__le32 return_ifnum;
};

struct qdx_nss_ipv4_create {
	__le16 valid_flags;
	__le16 rule_flags;
	struct qdx_nss_ipv4_tuple tuple;
	struct qdx_nss_ipv4_connection conn_rule;
	struct qdx_nss_ipv4_tcp tcp_rule;
	struct qdx_nss_pppoe pppoe_rule;
	struct qdx_nss_qos qos_rule;
	struct qdx_nss_dscp dscp_rule;
	struct qdx_nss_vlan vlan_primary_rule;
	struct qdx_nss_vlan vlan_secondary_rule;
	struct qdx_nss_source_mac src_mac_rule;
	struct qdx_nss_nexthop nexthop_rule;
	struct qdx_nss_rps rps_rule;
	struct qdx_nss_igs igs_rule;
	struct qdx_nss_identifier identifier;
	struct qdx_nss_mirror mirror_rule;
};

struct qdx_nss_ipv6_create {
	__le16 valid_flags;
	__le16 rule_flags;
	struct qdx_nss_ipv6_tuple tuple;
	struct qdx_nss_ipv6_connection conn_rule;
	struct qdx_nss_ipv6_tcp tcp_rule;
	struct qdx_nss_pppoe pppoe_rule;
	struct qdx_nss_qos qos_rule;
	struct qdx_nss_dscp dscp_rule;
	struct qdx_nss_vlan vlan_primary_rule;
	struct qdx_nss_vlan vlan_secondary_rule;
	struct qdx_nss_source_mac src_mac_rule;
	struct qdx_nss_nexthop nexthop_rule;
	struct qdx_nss_rps rps_rule;
	struct qdx_nss_igs igs_rule;
	struct qdx_nss_identifier identifier;
	struct qdx_nss_mirror mirror_rule;
};

struct qdx_nss_ipv4_sync {
	__le32 reserved;
	u8 protocol;
	u8 padding[3];
	__le32 flow_ip;
	__le32 flow_ip_xlate;
	__le32 flow_ident;
	__le32 flow_ident_xlate;
	__le32 flow_max_window;
	__le32 flow_end;
	__le32 flow_max_end;
	__le32 flow_rx_packets;
	__le32 flow_rx_bytes;
	__le32 flow_tx_packets;
	__le32 flow_tx_bytes;
	__le32 return_ip;
	__le32 return_ip_xlate;
	__le32 return_ident;
	__le32 return_ident_xlate;
	__le32 return_max_window;
	__le32 return_end;
	__le32 return_max_end;
	__le32 return_rx_packets;
	__le32 return_rx_bytes;
	__le32 return_tx_packets;
	__le32 return_tx_bytes;
	__le32 inc_ticks;
	__le32 reason;
	u8 flags;
	u8 padding2[3];
	__le32 qos_tag;
	__le32 cause;
};

struct qdx_nss_ipv6_sync {
	__le32 reserved;
	u8 protocol;
	u8 padding[3];
	__le32 flow_ip[4];
	__le32 flow_ident;
	__le32 flow_max_window;
	__le32 flow_end;
	__le32 flow_max_end;
	__le32 flow_rx_packets;
	__le32 flow_rx_bytes;
	__le32 flow_tx_packets;
	__le32 flow_tx_bytes;
	__le32 return_ip[4];
	__le32 return_ident;
	__le32 return_max_window;
	__le32 return_end;
	__le32 return_max_end;
	__le32 return_rx_packets;
	__le32 return_rx_bytes;
	__le32 return_tx_packets;
	__le32 return_tx_bytes;
	__le32 inc_ticks;
	__le32 reason;
	u8 flags;
	u8 padding2[3];
	__le32 qos_tag;
	__le32 cause;
};

struct qdx_nss_sync_many {
	__le16 index;
	__le16 size;
	__le16 next;
	__le16 count;
};

static_assert(sizeof(struct qdx_nss_ipv4_tuple) == 20);
static_assert(sizeof(struct qdx_nss_ipv6_tuple) == 44);
static_assert(sizeof(struct qdx_nss_ipv4_create) == 196);
static_assert(sizeof(struct qdx_nss_ipv6_create) == 204);
static_assert(sizeof(struct qdx_nss_ipv4_sync) == 116);
static_assert(sizeof(struct qdx_nss_ipv6_sync) == 124);
static_assert(sizeof(struct qdx_nss_sync_many) == 8);

#endif
