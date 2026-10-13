// SPDX-License-Identifier: GPL-2.0-only
/* Isolated fixed IPv4 UDP/TCP bridge-flow witness. No ordinary ARM packet path.
 * External fixture: raw relay restored, no other IPv4 writer/collector, no input
 * during preparation, actual peer MACs supplied, native target qdisc unchanged.
 * This diagnostic retains historical QDX calls; it is not a Phase 2.5 API.
 */
#include <linux/debugfs.h>
#include <linux/etherdevice.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/jiffies.h>
#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/qdx.h>
#include <linux/qdx/tc.h>
#include <linux/rtnetlink.h>
#include <linux/seq_file.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <net/net_namespace.h>
#include <net/pkt_sched.h>
#include "qdx_bridge_flow_abi.h"

#define FLOW_SLOTS 4
#define WAIT_MS 3000
#define STATS_BYTES 4096
#define SOURCE_IFNUM 3
#define TARGET_IFNUM 4
#define IPV4_MODE 8
#define RESET_NEXTHOP 18
#define BRIDGE_FLOW 0x0002

enum command_step { STEP_NONE, STEP_NORMAL, STEP_MODE, STEP_QUERY,
                    STEP_CREATE, STEP_DESTROY };
struct flow_slot {
        struct qdx_nss_ipv4_create wire;
        bool key_valid, created, destroy_acked, final_seen;
        u32 final_reason;
        u64 rx_packets[2], rx_bytes[2], tx_packets[2], tx_bytes[2];
        u64 syncs, duplicate_final;
};

static bool allow_writes, fixture_reserved, scalar_membership;
static bool scalar_leaf_leased;
extern int qdx_physical_fq_membership_get(struct net_device *, u32 *);
extern void qdx_physical_fq_membership_put(void);
static int (*scalar_get)(struct net_device *, u32 *);
static void (*scalar_put)(void);
static char *source_mac, *target_mac;
module_param(allow_writes, bool, 0400);
module_param(fixture_reserved, bool, 0400);
module_param(scalar_membership, bool, 0400);
module_param(source_mac, charp, 0400);
module_param(target_mac, charp, 0400);
MODULE_PARM_DESC(fixture_reserved, "Operator confirms exclusive IPv4 fixture, raw relay restored and no preparation input");
MODULE_PARM_DESC(source_mac, "Actual peer MAC on LAN3, for fixed192.168.1.144");
MODULE_PARM_DESC(target_mac, "Actual peer MAC on LAN2, for fixed192.168.1.115");

static DEFINE_MUTEX(control_lock);
static DEFINE_SPINLOCK(stats_lock);
static struct dentry *directory;
static struct net_device *source_dev, *target_dev;
static struct qdx_service *ethernet_service, *ip_service;
static struct qdx_endpoint *source_endpoint, *target_endpoint, *ip_endpoint;
static struct qdx_rx_use *source_rx, *resume_rx;
static struct qdx_receiver *receiver;
static struct qdx_binding_use tc_use;
static struct qdx_tc_ref *tc_reference;
static struct qdx_request *request;
static struct qdx_result last_result;
static struct flow_slot slots[FLOW_SLOTS];
static enum command_step pending_step;
static unsigned int pending_slot;
static u16 query_next;
static u32 class_tag;
static u64 foreign_records, bad_messages, round_records;
static bool pinned, prepared_once, held, running, normal_acked, mode_acked;
static bool initial_empty, invalid, protocol_fault, native_warmup;
static u64 warmup_opened_ns, cut_started_ns, cut_held_ns, armed_ns;
static int last_error;
static u8 reply[STATS_BYTES], peer_source[ETH_ALEN], peer_target[ETH_ALEN];

/* Called with stats_lock; record lifetime extends through receiver drain. */
static void account_sync(const struct qdx_nss_ipv4_sync *sync)
{
        struct flow_slot *slot = NULL;
        unsigned int i;
        u32 reason = le32_to_cpu(sync->reason);

        if (reason > QDX_NSS_SYNC_DESTROY) {
                bad_messages++;
                return;
        }
        for (i = 0; i < FLOW_SLOTS; i++) {
                const struct qdx_nss_ipv4_tuple *key = &slots[i].wire.tuple;

                if (slots[i].key_valid && sync->protocol == key->protocol &&
                    sync->flow_ip == key->flow_ip && sync->return_ip == key->return_ip &&
                    sync->flow_ident == key->flow_ident && sync->return_ident == key->return_ident) {
                        slot = &slots[i];
                        break;
                }
        }
        if (!slot) {
                foreign_records++;
                return;
        }
        if (reason && slot->final_seen) {
                slot->duplicate_final++;
                return;
        }
        slot->rx_packets[0] += le32_to_cpu(sync->flow_rx_packets);
        slot->rx_bytes[0] += le32_to_cpu(sync->flow_rx_bytes);
        slot->tx_packets[0] += le32_to_cpu(sync->flow_tx_packets);
        slot->tx_bytes[0] += le32_to_cpu(sync->flow_tx_bytes);
        slot->rx_packets[1] += le32_to_cpu(sync->return_rx_packets);
        slot->rx_bytes[1] += le32_to_cpu(sync->return_rx_bytes);
        slot->tx_packets[1] += le32_to_cpu(sync->return_tx_packets);
        slot->tx_bytes[1] += le32_to_cpu(sync->return_tx_bytes);
        slot->syncs++;
        if (reason) {
                slot->final_seen = true;
                slot->final_reason = reason;
        }
}

static void flow_message(void *owner, u32 opcode, u32 response, u32 error,
                         const void *payload, size_t received, size_t declared)
{
        unsigned long flags;

        if (opcode != QDX_NSS_IP_SYNC || response != QDX_NSS_RESPONSE_NOTIFY)
                return;
        spin_lock_irqsave(&stats_lock, flags);
        /* 11.4 NOTIFY serialization does not initialize common-header error.
         * It is a command-reply field, not a validity condition for this event.
         */
        if (declared < sizeof(struct qdx_nss_ipv4_sync) || received < declared)
                bad_messages++;
        else
                account_sync(payload);
        spin_unlock_irqrestore(&stats_lock, flags);
}

static const struct qdx_receive_ops receive_ops = { .message = flow_message };

static int flow_hold(void)
{
        int error;

        if (!source_rx)
                return 0;
        error = qdx_rx_hold(source_rx);
        if (!error) {
                held = true;
                running = false;
        }
        return error;
}

static int tc_invalid(void *owner, bool may_sleep)
{
        int error;

        WRITE_ONCE(invalid, true);
        if (!may_sleep)
                return -EWOULDBLOCK;
        mutex_lock(&control_lock);
        error = flow_hold();
        mutex_unlock(&control_lock);
        return error;
}

/* One immutable qdx_request survives timeout. The explicit module pin protects
 * these controls; callbacks own only the registered, drained receiver above. */
static int command_run(enum command_step step, unsigned int slot, bool submit,
                       unsigned int wait_ms)
{
        struct qdx_nss_sync_many query = { .index = cpu_to_le16(query_next),
                                         .size = cpu_to_le16(STATS_BYTES) };
        struct qdx_reply_bounds bounds = {};
        struct qdx_endpoint *endpoint = ip_endpoint;
        __be32 mode = 0;
        const void *payload = NULL;
        unsigned long flags;
        size_t length = 0;
        u32 opcode;
        int error;

        if (protocol_fault)
                return -EPROTO;
        if (request && (pending_step != step || pending_slot != slot))
                return -EBUSY;
        switch (step) {
        case STEP_NORMAL:
                opcode = RESET_NEXTHOP;
                endpoint = source_endpoint;
                break;
        case STEP_MODE:
                opcode = IPV4_MODE;
                payload = &mode;
                length = sizeof(mode);
                break;
        case STEP_QUERY:
                opcode = QDX_NSS_IP_SYNC_MANY;
                payload = &query;
                length = sizeof(query);
                break;
        case STEP_CREATE:
                opcode = QDX_NSS_IP_CREATE;
                payload = &slots[slot].wire;
                length = sizeof(slots[slot].wire);
                break;
        case STEP_DESTROY:
                opcode = QDX_NSS_IP_DESTROY;
                payload = &slots[slot].wire.tuple;
                length = sizeof(slots[slot].wire.tuple);
                break;
        default:
                return -EINVAL;
        }
        if (!request) {
                if (!submit)
                        return 0;
                bounds.minimum = step == STEP_QUERY ? sizeof(query) : 0;
                bounds.maximum = step == STEP_QUERY ? STATS_BYTES : length;
                bounds.capacity = STATS_BYTES;
                request = qdx_command_submit(endpoint, opcode, payload, length,
                                             &bounds, NULL);
                if (IS_ERR(request)) {
                        error = PTR_ERR(request);
                        request = NULL;
                        return error;
                }
                pending_step = step;
                pending_slot = slot;
        }
        memset(reply, 0, sizeof(reply));
        error = qdx_request_wait(request, jiffies + msecs_to_jiffies(wait_ms),
                                 &last_result, reply, sizeof(reply));
        if (last_result.outcome == QDX_UNKNOWN && !last_result.exposure_ended)
                return error ?: -EINPROGRESS;
        if (last_result.outcome == QDX_ACK) {
                if (step == STEP_QUERY) {
                        const struct qdx_nss_sync_many *header = (void *)reply;
                        unsigned int count = le16_to_cpu(header->count), i;

                        if (last_result.declared_len < sizeof(*header) ||
                            last_result.declared_len > last_result.received_len ||
                            last_result.received_len > sizeof(reply) ||
                            last_result.received_len < sizeof(*header) ||
                            count > (last_result.received_len - sizeof(*header)) /
                                    sizeof(struct qdx_nss_ipv4_sync)) {
                                protocol_fault = true;
                                return -EPROTO;
                        }
                        spin_lock_irqsave(&stats_lock, flags);
                        if (!query_next)
                                round_records = 0;
                        round_records += count;
                        for (i = 0; i < count; i++)
                                account_sync((void *)(reply + sizeof(*header) +
                                    i * sizeof(struct qdx_nss_ipv4_sync)));
                        query_next = le16_to_cpu(header->next);
                        if (!query_next && !round_records && !foreign_records)
                                initial_empty = true;
                        spin_unlock_irqrestore(&stats_lock, flags);
                } else if (step == STEP_NORMAL) {
                        normal_acked = true;
                } else if (step == STEP_MODE) {
                        mode_acked = true;
                } else {
                        spin_lock_irqsave(&stats_lock, flags);
                        if (step == STEP_CREATE)
                                slots[slot].created = true;
                        else
                                slots[slot].destroy_acked = true;
                        spin_unlock_irqrestore(&stats_lock, flags);
                }
                error = 0;
        } else {
                error = last_result.error ?: error ?: -EIO;
        }
        qdx_request_put(request);
        request = NULL;
        pending_step = STEP_NONE;
        return error;
}

static int flow_prepare(void)
{
        struct qdx_owner owner = { .module = THIS_MODULE };
        struct qdx_tc_position position = { .direction = QDX_TC_EGRESS };
        struct qdx_packet_geometry geometry = {};
        struct flow_dissector dissector = {};
        struct flow_rule facts = { .match.dissector = &dissector };
        u32 source, target;
        int error;

        if (!fixture_reserved || prepared_once || pinned || request)
                return -EBUSY;
        if (!source_mac || !target_mac || !mac_pton(source_mac, peer_source) ||
            !mac_pton(target_mac, peer_target) ||
            !is_valid_ether_addr(peer_source) || !is_valid_ether_addr(peer_target) ||
            ether_addr_equal(peer_source, peer_target))
                return -EINVAL;
        if (!try_module_get(THIS_MODULE))
                return -ENODEV;
        pinned = true;
        prepared_once = true;
        source_dev = dev_get_by_name(&init_net, "lan3");
        target_dev = dev_get_by_name(&init_net, "lan2");
        if (!source_dev || !target_dev || !netif_running(source_dev) ||
            !netif_running(target_dev) || !netif_carrier_ok(source_dev) ||
            !netif_carrier_ok(target_dev))
                return -ENETDOWN;
        ethernet_service = qdx_service_get(source_dev, QDX_SERVICE_ETHERNET);
        if (IS_ERR(ethernet_service)) {
                error = PTR_ERR(ethernet_service);
                ethernet_service = NULL;
                return error;
        }
        ip_service = qdx_service_get(source_dev, QDX_SERVICE_IPV4);
        if (IS_ERR(ip_service)) {
                error = PTR_ERR(ip_service);
                ip_service = NULL;
                return error;
        }
        source_endpoint = qdx_endpoint_get(ethernet_service, source_dev);
        if (IS_ERR(source_endpoint)) {
                error = PTR_ERR(source_endpoint);
                source_endpoint = NULL;
                return error;
        }
        target_endpoint = qdx_endpoint_get(ethernet_service, target_dev);
        if (IS_ERR(target_endpoint)) {
                error = PTR_ERR(target_endpoint);
                target_endpoint = NULL;
                return error;
        }
        error = qdx_endpoint_ifnum(source_endpoint, &source);
        if (!error)
                error = qdx_endpoint_ifnum(target_endpoint, &target);
        if (error || source != SOURCE_IFNUM || target != TARGET_IFNUM)
                return error ?: -EXDEV;
        ip_endpoint = qdx_endpoint_get(ip_service, NULL);
        if (IS_ERR(ip_endpoint)) {
                error = PTR_ERR(ip_endpoint);
                ip_endpoint = NULL;
                return error;
        }
        receiver = qdx_endpoint_receive_register(ip_endpoint, QDX_RECEIVE_MESSAGE,
                                                &owner, &receive_ops);
        if (IS_ERR(receiver)) {
                error = PTR_ERR(receiver);
                receiver = NULL;
                return error;
        }
        source_rx = qdx_rx_acquire(source_endpoint, source_dev);
        if (IS_ERR(source_rx)) {
                error = PTR_ERR(source_rx);
                source_rx = NULL;
                return error;
        }
        error = flow_hold();
        if (error)
                return error;
        if (scalar_membership) {
                scalar_get = symbol_get(qdx_physical_fq_membership_get);
                scalar_put = symbol_get(qdx_physical_fq_membership_put);
                if (!scalar_get || !scalar_put)
                        return -ENODEV;
                error = scalar_get(target_dev, &class_tag);
                if (!error)
                        scalar_leaf_leased = true;
                return error;
        }
        INIT_LIST_HEAD(&tc_use.node);
        position.dev = target_dev;
        error = qdx_tc_position_get(&position, &facts, &geometry, &tc_use,
                                   &owner, tc_invalid, &tc_reference);
        if (error)
                return error;
        if (tc_reference->effects != QDX_TC_CLASS ||
            tc_reference->input_priority_used || tc_reference->output_priority_used ||
            !tc_reference->class_endpoint || !tc_reference->class_tag ||
            (tc_reference->class_tag & 0xffff))
                return -EOPNOTSUPP;
        error = qdx_endpoint_ifnum(tc_reference->class_endpoint, &target);
        if (error || target != TARGET_IFNUM)
                return error ?: -EXDEV;
        class_tag = tc_reference->class_tag;
        return 0;
}

/* No rule exists yet. Restore actual native ingress for TCP/UDP setup;
 * keep the independently owned endpoints, receiver and native TC reference.
 */
static int flow_native_warmup(void)
{
        unsigned int i;
        int error;

        if (!pinned || !source_rx || !held || running || resume_rx || request ||
            !normal_acked || !mode_acked || !initial_empty || query_next ||
            !tc_reference || READ_ONCE(invalid) || protocol_fault || native_warmup)
                return -EINVAL;
        for (i = 0; i < FLOW_SLOTS; i++)
                if (slots[i].key_valid)
                        return -EBUSY;
        error = qdx_rx_release(source_rx);
        if (error)
                return error;
        source_rx = NULL;
        held = false;
        native_warmup = true;
        warmup_opened_ns = ktime_get_mono_fast_ns();
        return 0;
}

/* Re-establish the real input hold only after all four native connections are
 * known. No whole-table scan occurs under this short cut. Failed acquisition
 * or hold retains every acquired resource; the ordinary release path owns it.
 */
static int flow_cut_warmup(void)
{
        unsigned int i;
        int error;

        if (!pinned || !native_warmup || source_rx || resume_rx || request ||
            !normal_acked || !mode_acked || !initial_empty || !tc_reference ||
            READ_ONCE(invalid) || protocol_fault)
                return -EINVAL;
        for (i = 0; i < FLOW_SLOTS; i++)
                if (slots[i].key_valid)
                        return -EBUSY;
        cut_started_ns = ktime_get_mono_fast_ns();
        source_rx = qdx_rx_acquire(source_endpoint, source_dev);
        if (IS_ERR(source_rx)) {
                error = PTR_ERR(source_rx);
                source_rx = NULL;
                return error;
        }
        native_warmup = false;
        error = flow_hold();
        if (!error)
                cut_held_ns = ktime_get_mono_fast_ns();
        return error;
}

static int flow_create(unsigned int slot, unsigned int sport, unsigned int dport,
                       u8 protocol)
{
        struct qdx_nss_ipv4_create wire = {};
        unsigned long flags;
        unsigned int i;

        if (!source_rx || !held || (!tc_reference && !scalar_leaf_leased) || !normal_acked || !mode_acked ||
            !initial_empty || READ_ONCE(invalid) || request || protocol_fault ||
            slot >= FLOW_SLOTS || sport < 1024 || sport > 65535 ||
            dport < 1024 || dport > 65535 ||
            (protocol != IPPROTO_UDP && protocol != IPPROTO_TCP))
                return -EINVAL;
        if (scalar_membership &&
            (slot > 1 || protocol != IPPROTO_UDP ||
             sport != (slot ? 5994 : 5993) || dport != (slot ? 45990 : 45989)))
                return -EINVAL;
        wire.valid_flags = cpu_to_le16(QDX_NSS_CONN_VALID | QDX_NSS_VLAN_VALID |
                                      QDX_NSS_QOS_VALID | QDX_NSS_NEXTHOP_VALID);
        wire.rule_flags = cpu_to_le16(BRIDGE_FLOW | QDX_NSS_SOURCE_CHECK);
        wire.tuple.flow_ip = cpu_to_le32(0xc0a80190);
        wire.tuple.return_ip = cpu_to_le32(0xc0a80173);
        wire.tuple.flow_ident = cpu_to_le32(sport);
        wire.tuple.return_ident = cpu_to_le32(dport);
        wire.tuple.protocol = protocol;
        if (protocol == IPPROTO_TCP) {
                /* The exclusive transparent fixture has no conntrack policy.
                 * Keep its existing no-sequence-check behavior explicit;
                 * this is not permission to relax product TCP authorization.
                 */
                wire.valid_flags |= cpu_to_le16(QDX_NSS_TCP_VALID);
                wire.rule_flags |= cpu_to_le16(QDX_NSS_NO_SEQ_CHECK);
                wire.tcp_rule.flow_max_window = cpu_to_le32(1);
                wire.tcp_rule.return_max_window = cpu_to_le32(1);
        }
        ether_addr_copy(wire.conn_rule.flow_mac, peer_source);
        ether_addr_copy(wire.conn_rule.return_mac, peer_target);
        wire.conn_rule.flow_interface_num = cpu_to_le32(SOURCE_IFNUM);
        wire.conn_rule.return_interface_num = cpu_to_le32(TARGET_IFNUM);
        wire.conn_rule.flow_mtu = cpu_to_le32(source_dev->mtu);
        wire.conn_rule.return_mtu = cpu_to_le32(target_dev->mtu);
        wire.conn_rule.flow_ip_xlate = wire.tuple.flow_ip;
        wire.conn_rule.return_ip_xlate = wire.tuple.return_ip;
        wire.conn_rule.flow_ident_xlate = wire.tuple.flow_ident;
        wire.conn_rule.return_ident_xlate = wire.tuple.return_ident;
        wire.qos_rule.flow_qos_tag = cpu_to_le32(class_tag);
        wire.nexthop_rule.flow_nexthop = cpu_to_le32(SOURCE_IFNUM);
        wire.nexthop_rule.return_nexthop = cpu_to_le32(TARGET_IFNUM);
        wire.vlan_primary_rule.ingress_vlan_tag = cpu_to_le32(QDX_NSS_UNTAGGED);
        wire.vlan_primary_rule.egress_vlan_tag = cpu_to_le32(QDX_NSS_UNTAGGED);
        wire.vlan_secondary_rule = wire.vlan_primary_rule;
        spin_lock_irqsave(&stats_lock, flags);
        if (slots[slot].key_valid || foreign_records || bad_messages) {
                spin_unlock_irqrestore(&stats_lock, flags);
                return -EBUSY;
        }
        for (i = 0; i < FLOW_SLOTS; i++) {
                if (slots[i].key_valid &&
                    !memcmp(&slots[i].wire.tuple, &wire.tuple, sizeof(wire.tuple))) {
                        spin_unlock_irqrestore(&stats_lock, flags);
                        return -EEXIST;
                }
        }
        slots[slot].wire = wire;
        slots[slot].key_valid = true;
        spin_unlock_irqrestore(&stats_lock, flags);
        return command_run(STEP_CREATE, slot, true, WAIT_MS);
}

static int flow_arm(void)
{
        unsigned long flags;
        unsigned int i, live = 0;
        bool bad;
        int error;

        if (!source_rx || !held || request || !normal_acked || !mode_acked ||
            (!tc_reference && !scalar_leaf_leased) || READ_ONCE(invalid) || protocol_fault)
                return -EINVAL;
        spin_lock_irqsave(&stats_lock, flags);
        bad = foreign_records || bad_messages;
        for (i = 0; i < FLOW_SLOTS; i++)
                live += slots[i].created && !slots[i].final_seen && !slots[i].destroy_acked;
        spin_unlock_irqrestore(&stats_lock, flags);
        if (bad || !live)
                return -ESTALE;
        if (!resume_rx) {
                resume_rx = qdx_rx_acquire(source_endpoint, source_dev);
                if (IS_ERR(resume_rx)) {
                        error = PTR_ERR(resume_rx);
                        resume_rx = NULL;
                        return error;
                }
        }
        error = qdx_rx_release(source_rx);
        if (error)
                return error;
        source_rx = resume_rx;
        resume_rx = NULL;
        held = false;
        running = true;
        armed_ns = ktime_get_mono_fast_ns();
        return 0;
}

/* Control references only. Operator separately proves old output queues drained
 * before removing their native qdisc; this function never claims wire delivery. */
static int flow_release(void)
{
        unsigned long flags;
        unsigned int i;
        bool live = false;
        int error;

        if (!pinned)
                return 0;
        error = flow_hold();
        if (error)
                return error;
        if (request)
                return -EINPROGRESS;
        spin_lock_irqsave(&stats_lock, flags);
        /* A matching final FLUSH/EVICT also ends firmware flow execution.
         * An outstanding command above still owns its request independently.
         */
        for (i = 0; i < FLOW_SLOTS; i++)
                live |= slots[i].created && !slots[i].final_seen;
        spin_unlock_irqrestore(&stats_lock, flags);
        if (live || protocol_fault)
                return -EBUSY;
        if (receiver) {
                error = qdx_endpoint_receive_unregister(receiver);
                if (error)
                        return error;
                receiver = NULL;
        }
        if (scalar_leaf_leased) {
                scalar_put();
                scalar_leaf_leased = false;
        }
        if (scalar_get) {
                symbol_put(qdx_physical_fq_membership_get);
                scalar_get = NULL;
        }
        if (scalar_put) {
                symbol_put(qdx_physical_fq_membership_put);
                scalar_put = NULL;
        }
        if (tc_reference) {
                qdx_tc_ref_put(tc_reference);
                tc_reference = NULL;
        }
        if (resume_rx) {
                error = qdx_rx_release(resume_rx);
                if (error)
                        return error;
                resume_rx = NULL;
        }
        if (source_rx) {
                error = qdx_rx_release(source_rx);
                if (error)
                        return error;
                source_rx = NULL;
        }
        qdx_endpoint_put(ip_endpoint);
        qdx_endpoint_put(target_endpoint);
        qdx_endpoint_put(source_endpoint);
        ip_endpoint = target_endpoint = source_endpoint = NULL;
        qdx_service_put(ip_service);
        qdx_service_put(ethernet_service);
        ip_service = ethernet_service = NULL;
        if (target_dev)
                dev_put(target_dev);
        if (source_dev)
                dev_put(source_dev);
        target_dev = source_dev = NULL;
        held = running = native_warmup = false;
        pinned = false;
        module_put(THIS_MODULE);
        return 0;
}

static int status_show(struct seq_file *seq, void *unused)
{
        struct flow_slot snapshot[FLOW_SLOTS];
        unsigned long flags;
        unsigned int i;
        u64 foreign, bad, records;

        mutex_lock(&control_lock);
        spin_lock_irqsave(&stats_lock, flags);
        memcpy(snapshot, slots, sizeof(snapshot));
        foreign = foreign_records;
        bad = bad_messages;
        records = round_records;
        spin_unlock_irqrestore(&stats_lock, flags);
        seq_printf(seq, "scalar_membership=%u scalar_leaf_leased=%u\n", scalar_membership, scalar_leaf_leased);
        seq_printf(seq, "pinned=%u source_rx=%u resume_rx=%u held=%u running=%u receiver=%u tc=%u invalid=%u class_tag=%#x\n",
                   pinned, !!source_rx, !!resume_rx, held, running, !!receiver,
                   !!tc_reference, READ_ONCE(invalid), class_tag);
        seq_printf(seq, "native_warmup=%u warmup_opened_ns=%llu cut_started_ns=%llu cut_held_ns=%llu armed_ns=%llu\n",
                   native_warmup, warmup_opened_ns, cut_started_ns, cut_held_ns, armed_ns);
        seq_printf(seq, "normal=%u mode0=%u initial_empty=%u query_next=%u round_records=%llu foreign=%llu bad=%llu protocol_fault=%u\n",
                   normal_acked, mode_acked, initial_empty, query_next,
                   records, foreign, bad, protocol_fault);
        seq_printf(seq, "pending=%u step=%u slot=%u last_error=%d id=%llu opcode=%u ifnum=%u outcome=%u error=%d firmware_error=%u published=%u exposure_ended=%u received=%zu declared=%zu\n",
                   !!request, pending_step, pending_slot, last_error,
                   last_result.id, last_result.opcode, last_result.ifnum,
                   last_result.outcome, last_result.error, last_result.firmware_error,
                   last_result.published, last_result.exposure_ended,
                   last_result.received_len, last_result.declared_len);
        for (i = 0; i < FLOW_SLOTS; i++) {
                const struct flow_slot *s = &snapshot[i];
                seq_printf(seq, "slot=%u key=%u sport=%u dport=%u protocol=%u created=%u destroy=%u final=%u reason=%u syncs=%llu duplicate_final=%llu rx=%llu/%llu rx_bytes=%llu/%llu tx=%llu/%llu tx_bytes=%llu/%llu\n",
                           i, s->key_valid, le32_to_cpu(s->wire.tuple.flow_ident),
                           le32_to_cpu(s->wire.tuple.return_ident), s->wire.tuple.protocol,
                           s->created,
                           s->destroy_acked, s->final_seen, s->final_reason, s->syncs,
                           s->duplicate_final, s->rx_packets[0], s->rx_packets[1],
                           s->rx_bytes[0], s->rx_bytes[1], s->tx_packets[0],
                           s->tx_packets[1], s->tx_bytes[0], s->tx_bytes[1]);
        }
        mutex_unlock(&control_lock);
        return 0;
}
DEFINE_SHOW_ATTRIBUTE(status);

static ssize_t control_write(struct file *file, const char __user *buffer,
                             size_t count, loff_t *position)
{
        char command[80], *text, extra;
        unsigned int slot, sport, dport;
        int error = -EINVAL;

        if (!allow_writes)
                return -EPERM;
        if (!count || count >= sizeof(command))
                return -EINVAL;
        if (copy_from_user(command, buffer, count))
                return -EFAULT;
        command[count] = '\0';
        text = strim(command);
        rtnl_lock();
        mutex_lock(&control_lock);
        if (!strcmp(text, "prepare"))
                error = flow_prepare();
        else if (!strcmp(text, "release"))
                error = flow_release();
        else if (!strcmp(text, "hold"))
                error = flow_hold();
        else if (!strcmp(text, "poll"))
                error = request ? command_run(pending_step, pending_slot, false, 0) : 0;
        else if (!strcmp(text, "native-warmup"))
                error = flow_native_warmup();
        else if (!strcmp(text, "cut-warmup"))
                error = flow_cut_warmup();
        else if (!pinned || !source_rx || !ip_endpoint || (!tc_reference && !scalar_leaf_leased))
                error = -ENODEV;
        else if (!strcmp(text, "normal"))
                error = held ? command_run(STEP_NORMAL, 0, true, WAIT_MS) : -EBUSY;
        else if (!strcmp(text, "mode0"))
                error = held && initial_empty ?
                        command_run(STEP_MODE, 0, true, WAIT_MS) : -EBUSY;
        else if (!strcmp(text, "query"))
                error = command_run(STEP_QUERY, 0, true, WAIT_MS);
        else if (!strcmp(text, "arm"))
                error = flow_arm();
        else if (sscanf(text, "create %u %u %u %c", &slot, &sport, &dport, &extra) == 3)
                error = flow_create(slot, sport, dport, IPPROTO_UDP);
        else if (sscanf(text, "create_tcp %u %u %u %c", &slot, &sport, &dport, &extra) == 3)
                error = flow_create(slot, sport, dport, IPPROTO_TCP);
        else if (sscanf(text, "destroy %u %c", &slot, &extra) == 1 &&
                 slot < FLOW_SLOTS && held && slots[slot].created &&
                 !slots[slot].destroy_acked)
                error = command_run(STEP_DESTROY, slot, true, WAIT_MS);
        last_error = error;
        mutex_unlock(&control_lock);
        rtnl_unlock();
        return error ?: count;
}

static const struct file_operations control_fops = {
        .owner = THIS_MODULE, .write = control_write,
};

static int __init diagnostic_init(void)
{
        struct dentry *entry;

        directory = debugfs_create_dir("qdx_bridge_flow_diag", NULL);
        if (IS_ERR_OR_NULL(directory))
                return directory ? PTR_ERR(directory) : -ENOMEM;
        entry = debugfs_create_file("control", 0200, directory, NULL, &control_fops);
        if (IS_ERR_OR_NULL(entry))
                goto fail;
        entry = debugfs_create_file("status", 0400, directory, NULL, &status_fops);
        if (IS_ERR_OR_NULL(entry))
                goto fail;
        return 0;
fail:
        debugfs_remove_recursive(directory);
        return entry ? PTR_ERR(entry) : -ENOMEM;
}

static void __exit diagnostic_exit(void)
{
        WARN_ON(pinned || request || receiver || source_rx || resume_rx || tc_reference ||
                scalar_leaf_leased || scalar_get || scalar_put);
        debugfs_remove_recursive(directory);
}
module_init(diagnostic_init);
module_exit(diagnostic_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Isolated NSS IPv4 scalar bridge-flow admission witness");
