// SPDX-License-Identifier: GPL-2.0-only
/* Command-only final-notification witness. No data producer or receiver. */
#include <linux/debugfs.h>
#include <linux/etherdevice.h>
#include <linux/in.h>
#include <linux/jiffies.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/qdx.h>
#include <linux/rtnetlink.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <net/net_namespace.h>
#include "qdx_bridge_flow_abi.h"

#define CAPACITY 4096
#define WAIT_MS 3000
enum step { WITNESS_NONE, WITNESS_QUERY, WITNESS_CREATE, WITNESS_DESTROY };
static bool allow_writes, held_fixture;
static char *source_mac, *target_mac;
module_param(allow_writes, bool, 0400);
module_param(held_fixture, bool, 0400);
module_param(source_mac, charp, 0400);
module_param(target_mac, charp, 0400);
MODULE_PARM_DESC(held_fixture, "Operator confirms no traffic, exclusive IPv4 writer, source3 held, normal next-hop and mode0");
static DEFINE_MUTEX(control_lock);
static struct dentry *directory;
static struct net_device *source_dev, *target_dev;
static struct qdx_service *ethernet_service, *ip_service;
static struct qdx_endpoint *source_endpoint, *target_endpoint, *ip_endpoint;
static struct qdx_rx_use *source_rx;
static struct qdx_request *request;
static struct qdx_result result;
static struct qdx_nss_ipv4_create wire;
static enum step pending_step;
static u8 reply[CAPACITY];
static u16 cursor;
static u64 round_records, foreign_records, traffic_records;
static bool pinned, prepared_once, prepared, fault, initial_empty, empty_verified;
static bool create_sent, create_settled, created, destroyed;
static int last_error;

static int command_run(enum step step, bool submit)
{
        struct qdx_nss_sync_many query = { .index = cpu_to_le16(cursor),
                                         .size = cpu_to_le16(CAPACITY) };
        struct qdx_reply_bounds bounds = { .capacity = CAPACITY };
        const void *payload;
        size_t length;
        u32 opcode;
        int error;

        if (fault || (request && pending_step != step))
                return -EBUSY;
        if (step == WITNESS_QUERY) {
                payload = &query;
                length = sizeof(query);
                opcode = QDX_NSS_IP_SYNC_MANY;
                bounds.minimum = sizeof(query);
                bounds.maximum = CAPACITY;
        } else if (step == WITNESS_CREATE) {
                payload = &wire;
                length = sizeof(wire);
                opcode = QDX_NSS_IP_CREATE;
                bounds.maximum = length;
        } else if (step == WITNESS_DESTROY) {
                payload = &wire.tuple;
                length = sizeof(wire.tuple);
                opcode = QDX_NSS_IP_DESTROY;
                bounds.maximum = length;
        } else {
                return -EINVAL;
        }
        if (!request) {
                if (!submit)
                        return 0;
                request = qdx_command_submit(ip_endpoint, opcode, payload, length,
                                             &bounds, NULL);
                if (IS_ERR(request)) {
                        error = PTR_ERR(request);
                        request = NULL;
                        return error;
                }
                pending_step = step;
                empty_verified = false;
                if (step == WITNESS_CREATE)
                        create_sent = true;
        }
        memset(reply, 0, sizeof(reply));
        error = qdx_request_wait(request, jiffies + msecs_to_jiffies(WAIT_MS),
                                 &result, reply, sizeof(reply));
        if (result.outcome == QDX_UNKNOWN && !result.exposure_ended)
                return error ?: -EINPROGRESS;
        if (result.outcome == QDX_ACK) {
                if (step == WITNESS_QUERY) {
                        const struct qdx_nss_sync_many *header = (void *)reply;
                        unsigned int count, i;
                        u16 next;

                        if (result.declared_len < sizeof(*header) ||
                            result.declared_len > result.received_len ||
                            result.received_len < sizeof(*header) ||
                            result.received_len > sizeof(reply)) {
                                fault = true;
                                return -EPROTO;
                        }
                        count = le16_to_cpu(header->count);
                        next = le16_to_cpu(header->next);
                        if (count > (result.received_len - sizeof(*header)) /
                                    sizeof(struct qdx_nss_ipv4_sync) ||
                            (next && next <= cursor)) {
                                fault = true;
                                return -EPROTO;
                        }
                        if (!cursor)
                                round_records = 0;
                        round_records += count;
                        for (i = 0; i < count; i++) {
                                const struct qdx_nss_ipv4_sync *sync =
                                        (void *)(reply + sizeof(*header) + i * sizeof(*sync));

                                if (!create_sent || sync->protocol != wire.tuple.protocol ||
                                    sync->flow_ip != wire.tuple.flow_ip ||
                                    sync->return_ip != wire.tuple.return_ip ||
                                    sync->flow_ident != wire.tuple.flow_ident ||
                                    sync->return_ident != wire.tuple.return_ident)
                                        foreign_records++;
                                if (sync->flow_rx_packets || sync->flow_rx_bytes ||
                                    sync->flow_tx_packets || sync->flow_tx_bytes ||
                                    sync->return_rx_packets || sync->return_rx_bytes ||
                                    sync->return_tx_packets || sync->return_tx_bytes)
                                        traffic_records++;
                        }
                        cursor = next;
                        if (!cursor && !round_records && !foreign_records) {
                                empty_verified = true;
                                if (!create_sent)
                                        initial_empty = true;
                        }
                } else if (step == WITNESS_CREATE) {
                        created = true;
                        create_settled = true;
                } else {
                        destroyed = true;
                }
                error = 0;
        } else {
                if (step == WITNESS_CREATE)
                        create_settled = true;
                error = result.error ?: error ?: -EIO;
        }
        qdx_request_put(request);
        request = NULL;
        pending_step = WITNESS_NONE;
        return error;
}

static int prepare(void)
{
        u8 smac[ETH_ALEN], tmac[ETH_ALEN];
        u32 source, target;
        int error;

        if (!held_fixture || prepared_once || !source_mac || !target_mac ||
            !mac_pton(source_mac, smac) || !mac_pton(target_mac, tmac) ||
            !is_valid_ether_addr(smac) || !is_valid_ether_addr(tmac) ||
            ether_addr_equal(smac, tmac))
                return -EINVAL;
        if (!try_module_get(THIS_MODULE))
                return -ENODEV;
        pinned = prepared_once = true;
        source_dev = dev_get_by_name(&init_net, "lan3");
        target_dev = dev_get_by_name(&init_net, "lan2");
        if (!source_dev || !target_dev || !netif_running(source_dev) ||
            !netif_running(target_dev))
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
        if (error || source != 3 || target != 4)
                return error ?: -EXDEV;
        ip_endpoint = qdx_endpoint_get(ip_service, NULL);
        if (IS_ERR(ip_endpoint)) {
                error = PTR_ERR(ip_endpoint);
                ip_endpoint = NULL;
                return error;
        }
        source_rx = qdx_rx_acquire(source_endpoint, source_dev);
        if (IS_ERR(source_rx)) {
                error = PTR_ERR(source_rx);
                source_rx = NULL;
                return error;
        }
        error = qdx_rx_hold(source_rx);
        if (error)
                return error;
        wire.valid_flags = cpu_to_le16(QDX_NSS_CONN_VALID | QDX_NSS_VLAN_VALID |
                                      QDX_NSS_NEXTHOP_VALID);
        wire.rule_flags = cpu_to_le16(0x0002 | QDX_NSS_SOURCE_CHECK);
        wire.tuple.flow_ip = cpu_to_le32(0xc0a80190);
        wire.tuple.return_ip = cpu_to_le32(0xc0a80173);
        wire.tuple.flow_ident = cpu_to_le32(62001);
        wire.tuple.return_ident = cpu_to_le32(46201);
        wire.tuple.protocol = IPPROTO_UDP;
        ether_addr_copy(wire.conn_rule.flow_mac, smac);
        ether_addr_copy(wire.conn_rule.return_mac, tmac);
        wire.conn_rule.flow_interface_num = cpu_to_le32(3);
        wire.conn_rule.return_interface_num = cpu_to_le32(4);
        wire.conn_rule.flow_mtu = cpu_to_le32(source_dev->mtu);
        wire.conn_rule.return_mtu = cpu_to_le32(target_dev->mtu);
        wire.conn_rule.flow_ip_xlate = wire.tuple.flow_ip;
        wire.conn_rule.return_ip_xlate = wire.tuple.return_ip;
        wire.conn_rule.flow_ident_xlate = wire.tuple.flow_ident;
        wire.conn_rule.return_ident_xlate = wire.tuple.return_ident;
        wire.nexthop_rule.flow_nexthop = cpu_to_le32(3);
        wire.nexthop_rule.return_nexthop = cpu_to_le32(4);
        wire.vlan_primary_rule.ingress_vlan_tag = cpu_to_le32(QDX_NSS_UNTAGGED);
        wire.vlan_primary_rule.egress_vlan_tag = cpu_to_le32(QDX_NSS_UNTAGGED);
        wire.vlan_secondary_rule = wire.vlan_primary_rule;
        prepared = true;
        return 0;
}

static int release(void)
{
        int error;

        if (!pinned)
                return 0;
        if (request || fault || (create_sent && (foreign_records || traffic_records)))
                return -EBUSY;
        if (create_sent && (!create_settled || (created && !destroyed) ||
                            !empty_verified || cursor || round_records))
                return -EBUSY;
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
        source_dev = target_dev = NULL;
        prepared = pinned = false;
        module_put(THIS_MODULE);
        return 0;
}

static int status_show(struct seq_file *seq, void *unused)
{
        mutex_lock(&control_lock);
        seq_printf(seq, "pinned=%u prepared=%u source_rx=%u initial_empty=%u empty_verified=%u cursor=%u round_records=%llu foreign=%llu traffic=%llu fault=%u\n",
                   pinned, prepared, !!source_rx, initial_empty, empty_verified,
                   cursor, round_records, foreign_records, traffic_records, fault);
        seq_printf(seq, "sent=%u settled=%u created=%u destroyed=%u sport=62001 dport=46201 protocol=17\n",
                   create_sent, create_settled, created, destroyed);
        seq_printf(seq, "pending=%u step=%u last_error=%d id=%llu opcode=%u outcome=%u error=%d firmware_error=%u published=%u exposure_ended=%u received=%zu declared=%zu\n",
                   !!request, pending_step, last_error, result.id, result.opcode,
                   result.outcome, result.error, result.firmware_error,
                   result.published, result.exposure_ended, result.received_len,
                   result.declared_len);
        mutex_unlock(&control_lock);
        return 0;
}
DEFINE_SHOW_ATTRIBUTE(status);

static ssize_t control_write(struct file *file, const char __user *buffer,
                             size_t count, loff_t *position)
{
        char command[24], *text;
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
                error = prepare();
        else if (!strcmp(text, "release"))
                error = release();
        else if (!strcmp(text, "poll"))
                error = request ? command_run(pending_step, false) : 0;
        else if (!prepared || request || fault)
                error = -EBUSY;
        else if (!strcmp(text, "query"))
                error = command_run(WITNESS_QUERY, true);
        else if (!strcmp(text, "create") && initial_empty && empty_verified &&
                 !create_sent && !cursor && !foreign_records && !traffic_records)
                error = command_run(WITNESS_CREATE, true);
        else if (!strcmp(text, "destroy") && created && !destroyed)
                error = command_run(WITNESS_DESTROY, true);
        last_error = error;
        mutex_unlock(&control_lock);
        rtnl_unlock();
        return error ?: count;
}
static const struct file_operations control_fops = {
        .owner = THIS_MODULE, .write = control_write,
};

static int __init witness_init(void)
{
        struct dentry *entry;

        directory = debugfs_create_dir("qdx_ipv4_notify_diag", NULL);
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
static void __exit witness_exit(void)
{
        WARN_ON(pinned || request || source_rx);
        debugfs_remove_recursive(directory);
}
module_init(witness_init);
module_exit(witness_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Command-only held IPv4 final notification witness");
