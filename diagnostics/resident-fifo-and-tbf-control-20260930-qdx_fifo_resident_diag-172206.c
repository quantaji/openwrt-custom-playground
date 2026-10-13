// SPDX-License-Identifier: GPL-2.0-only
/* Isolated resident native-byte FIFO and ready-prefix diagnostic.
 * No rate/AQM law, no batch-fill delay, no descriptor/link mutation.
 * Physical staging is not the native byte limit. Source3 .144 -> .115 UDP
 * dports45987/45988. Root freezes writers and owns the original-drop guard.
 */
#include <linux/module.h>
#include <linux/capability.h>
#include <linux/of_address.h>
#include <linux/wait.h>
#include <linux/io.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/kthread.h>
#include <linux/hrtimer.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/if_vlan.h>
#include <linux/unaligned.h>
#include <linux/slab.h>
#include <linux/crc32.h>
#include <net/net_namespace.h>

#define Q 193
#define STAGE_CELLS 512
#define RECORDS 1024
#define LEDGER 4096
#define CPU_SAMPLES 262144
#define ROUTE193 0x5a060
#define QUANTUM (1U << 21)
#define HEAD (0x86c000 + 16 * Q)
#define USED (0x84e000 + 16 * Q)
#define DEQ (0x430000 + 16 * Q)
#define ENQ (0x85c000 + 16 * Q)
#define DROP (0x864000 + 16 * Q)
#define CFG (0x41c000 + 16 * Q)
#define CREDIT (0x41a000 + 16 * Q)
#define AC (0x848000 + 16 * Q)
#define TX (0x024000 + 16 * Q)
#define RULE(i) (0x0b0000 + 16 * (i))
#define MASK(i) (0x0b2000 + 16 * (i))
#define ACTION(i) (0x068000 + 32 * (i))
#define COUNT(i) (0x174000 + 16 * (i))
#define CONTROL_PRIORITY(i) (0x842000 + 16 * (4 * 16 + (i)))
#define EXT(k, l) (0x0b4000 + 0x100 * (k) + 4 * (l))
#define IDLE_NS 100000ULL
#define COMPLETION_RETRY_NS 8000ULL /* one scan is a polling hint, not a completion fence */
#define FLIGHT_NS 100000000ULL /* diagnostic hold deadline, far below8.38s credit recovery */

struct acl_row { u32 rule[3], mask[2], action[5], count[3]; };
struct private_row { u32 off, saved[3], expected[3]; u8 words; bool touched; };
enum private_row_id { P_CFG, P_CREDIT, P_MAP, P_PORT, P_LENGTH,
    P_L1C, P_L1E, P_L0C, P_L0E, P_CPUC, P_CPUE, P_ROWS };
/* serial is a queue generation, not a hardware packet cookie. Reused numeric
 * descriptor IDs become new records only after the old grant has settled. */
struct item { u64 serial, observed; u32 backlog_after; u16 id, length; bool accepted, selected; };
struct cpu_sample { u64 serial, time; u32 crc; u16 length, copied; u8 data[106]; };
static struct item items[RECORDS], ledger[LEDGER];
static struct cpu_sample *cpu_samples;
static bool ids[2048];
static void __iomem *ppe, *edma;
static struct private_row private_rows[P_ROWS];
static unsigned int private_l1, private_c, private_e;
static u32 physical_map, cpu_map, expected_map, expected_port;
static bool qmap_touched, cpu_mapping, route_touched, tap_on, cpu_consent;
static u32 saved_route, expected_route, cpu_parent_cfg[3], cpu_port_cfg[2];
static struct net_device *tap_dev;
static DEFINE_SPINLOCK(cpu_lock);
static u64 cpu_received, cpu_generation_hits, cpu_start;
static u32 cpu_count;
static bool cpu_expected;
static int cpu_fault;
static u32 leaf_maps[300], leaf_ports[300], parent_maps[64], parent_ports[64];
static struct dentry *dir;
static DEFINE_MUTEX(lock);
static struct task_struct *worker;
static DECLARE_WAIT_QUEUE_HEAD(stop_wait);
static struct acl_row saved_acl[8], rules[8];
static u32 saved_ext[3], saved_cfg[3], saved_credit[2], saved_ac[4];
static u32 saved_gate, saved_enq, saved_drop, saved_map, saved_port, group_row[3];
static u32 saved_parent[3], saved_port_cfg[2], ac_expected[4];
static u8 touched_rule, touched_mask, touched_action, touched_ext;
static u32 saved_priority[16];
static u16 touched_priority;
static const char *reject_kind;
static u32 reject_offset, reject_value;
static int reject_profile = -1, reject_class = -1, reject_hash = -256;
static bool used_once, ever_armed, restoring, large;
static u32 drop_before[6][3], acl_list, last_tx, tx_start;
static u32 byte_limit = 16384, batch_cap = 8, backlog, backlog_max, pending_max, cells_max;
static u64 arrived, retired, accepted, rejected, accepted_bytes, rejected_bytes;
static u64 selected, completed, sent, disposed, sent_bytes, disposed_bytes, selected_bytes;
static u64 issued_allowances, grants, histogram[17], reason_cap, reason_tail, reason_change;
static u64 length_count[4], visits, visit_ns, max_visit_ns, max_gap_ns, previous_visit;
static u64 mmio_reads, mmio_writes, worker_reads, worker_writes, metadata_reads;
static u64 prepare_calls, prepare_ns, grant_ns, finish_checks, finish_ns;
static u64 settle_sum_ns, settle_max_ns, settle_min_ns = U64_MAX;
static u64 wakes, idle_waits, completion_waits, discovery_calls, discovery_ns;
static u64 started, end_time, issue_time, stop_time, next_ownership_check, next_check;
static u32 flight_count, flight_credit;
static bool flight_cpu;
static u64 frozen_time, partial_stops, partial_settlements, partial_completed;
static u32 fault_offset, fault_expected, fault_observed;
static int failure, last_result;
static bool reserved, armed, running, stopping, in_flight, sealed, terminal, collecting, frozen;
static bool allow_writes;
module_param(allow_writes, bool, 0400);

static u32 rd(u32 off) { mmio_reads++; return readl(ppe + off); }
static void read_row(u32 off, u32 *data, unsigned int words)
{
	unsigned int i;
	for (i = 0; i < words; i++)
		data[i] = rd(off + 4 * i);
}
static int write_row(u32 off, const u32 *data, unsigned int words)
{
	unsigned int i;
	int err = 0;
	for (i = 0; i < words; i++) {
		writel(data[i], ppe + off + 4 * i);
		mmio_writes++;
	}
	for (i = 0; i < words; i++) {
		u32 value = rd(off + 4 * i);
		if (value != data[i]) {
			if (!failure && !fault_offset) {
				fault_offset = off + 4 * i;
				fault_expected = data[i];
				fault_observed = value;
			}
			err = -EIO;
		}
	}
	return err;
}
static int write_one(u32 off, u32 data) { return write_row(off, &data, 1); }
static void field(u32 *data, unsigned int bit, unsigned int width, u32 value)
{
	unsigned int i;
	for (i = 0; i < width; i++) {
		u32 mask = BIT((bit + i) % 32);
		data[(bit + i) / 32] &= ~mask;
		if (value & BIT(i))
			data[(bit + i) / 32] |= mask;
	}
}

/* Keep the first rejected condition visible even when setup changed nothing. */
static int reject_preflight(const char *kind, u32 offset, u32 value, int error)
{
	if (!reject_kind) {
		reject_kind = kind;
		reject_offset = offset;
		reject_value = value;
	}
	return error;
}

/* Map source-profile/destination, CPU code or service code to base+class+hash.
 * Profile4 is evaluated with its explicitly reserved control-band class0;
 * all other profiles retain their actual class and signed hash offsets.
 * No packet classification or per-packet work occurs in this setup audit.
 */
static int audit_selectors(void)
{
	u32 hashes[16][8] = {}, checked[16][8] = {};
	u16 classes[16] = {}, loaded = 0;
	unsigned int row, profile, base, i, cls, h;
	u32 value, offset, mapped;
	int hash, queue;
	/* Native resource checks likewise require the default hash offset zero. */
	value = rd(0x800060);
	if (value & 255)
		return reject_preflight("default_hash", 0x800060, value, -EXDEV);
	for (row = 0; row < 3072; row++) {
		offset = 0x810000 + 16 * row;
		mapped = rd(offset);
		profile = mapped & 15;
		base = (mapped >> 4) & 255;
		if (profile == 4 && base != 192) {
			if (!reject_kind)
				reject_profile = profile;
			return reject_preflight("control_profile_base", offset, mapped, -EXDEV);
		}
		if (!(loaded & BIT(profile))) {
			for (i = 0; i < 16; i++) {
				value = rd(0x842000 + 16 * (profile * 16 + i));
				classes[profile] |= BIT(profile == 4 ? 0 : value & 15);
			}
			for (i = 0; i < 256; i++) {
				u32 hash_offset = 0x830000 + 16 * (profile * 256 + i);
				value = rd(hash_offset);
				h = value & 255;
				if (profile == 4 && h) {
					if (!reject_kind) {
						reject_profile = profile;
						reject_hash = (s8)h;
					}
					return reject_preflight("control_profile_hash", hash_offset, value, -EXDEV);
				}
				hashes[profile][h / 32] |= BIT(h % 32);
			}
			loaded |= BIT(profile);
		}
		if (checked[profile][base / 32] & BIT(base % 32))
			continue;
		checked[profile][base / 32] |= BIT(base % 32);
		for (cls = 0; cls < 16; cls++) {
			if (!(classes[profile] & BIT(cls)))
				continue;
			for (h = 0; h < 256; h++) {
				if (!(hashes[profile][h / 32] & BIT(h % 32)))
					continue;
				hash = (s8)h;
				queue = (int)base + (int)cls + hash;
				if (queue != Q && queue >= 0 && queue < 256)
					continue;
				if (!reject_kind) {
					reject_profile = profile;
					reject_class = cls;
					reject_hash = hash;
				}
				return reject_preflight(queue == Q ? "queue_alias" : "queue_offset_range",
					offset, mapped, queue == Q ? -EADDRINUSE : -ERANGE);
			}
		}
	}
	/* The sixteen rows we will change must really be an active base192 profile. */
	if (!(loaded & BIT(4)))
		return reject_preflight("control_profile_absent", 0x810000, 0, -EXDEV);
	return 0;
}

/* Configuration ownership only; mutable credit/counters are checked at their
 * actual completion boundary. Partial setup accepts only old or our own words.
 */
static int owned_row(u32 offset, const u32 *expected, const u32 *saved,
                     unsigned int words, bool partial)
{
	u32 observed[5];
	unsigned int i;
	read_row(offset, observed, words);
	for (i = 0; i < words; i++)
		if (observed[i] != expected[i] && (!partial || observed[i] != saved[i]))
			return reject_preflight("ownership", offset + 4 * i, observed[i], -ESTALE);
	return 0;
}

static int private_write(unsigned int index, const u32 *values)
{
	struct private_row *row = &private_rows[index];
	if (values != row->expected)
		memcpy(row->expected, values, row->words * sizeof(u32));
	row->touched = true;
	return write_row(row->off, values, row->words);
}

/* Tap clones prove returned geometry/order and retain identity for the external
 * source/capture audit. The protocol-ALL ingress guard owns actual originals. */
static int cpu_receive(struct sk_buff *skb, struct net_device *dev,
                       struct packet_type *type, struct net_device *original)
{
    u8 data[1514];
    unsigned long flags;
    unsigned int length, copied;
    int offset;
    u16 dport;
    struct item *entry;
    struct cpu_sample *sample;

    if (!skb_mac_header_was_set(skb))
        goto done;
    offset = skb_mac_offset(skb);
    if (offset < -(int)skb_headroom(skb) || offset > (int)skb->len)
        goto done;
    length = skb->len - offset;
    if (length < 42 || skb_copy_bits(skb, offset, data, min_t(unsigned int, length, 42)))
        goto done;
    dport = get_unaligned_be16(data + 36);
    if (get_unaligned_be16(data + 12) != ETH_P_IP || data[14] != 0x45 ||
        data[23] != IPPROTO_UDP || get_unaligned_be32(data + 26) != 0xc0a80190 ||
        get_unaligned_be32(data + 30) != 0xc0a80173 ||
        (dport != 45987 && dport != 45988))
        goto done;
    spin_lock_irqsave(&cpu_lock, flags);
    if (!cpu_expected || cpu_generation_hits >= cpu_count ||
        skb->pkt_type == PACKET_OUTGOING || skb_vlan_tag_present(skb) ||
        length > sizeof(data) || cpu_received >= CPU_SAMPLES) {
        if (!cpu_fault)
            cpu_fault = -EPROTO;
        goto unlock;
    }
    entry = &items[(cpu_start + cpu_generation_hits) % RECORDS];
    if (entry->serial != cpu_start + cpu_generation_hits || entry->accepted ||
        !entry->selected || length != entry->length ||
        max_t(u32, get_unaligned_be16(data + 16) + 14, 60) != length ||
        skb_copy_bits(skb, offset, data, length)) {
        if (!cpu_fault)
            cpu_fault = -EPROTO;
        goto unlock;
    }
    sample = &cpu_samples[cpu_received];
    sample->serial = entry->serial;
    sample->time = ktime_get_ns();
    sample->length = length;
    sample->crc = crc32_le(~0U, data, length) ^ ~0U;
    copied = min_t(unsigned int, length, sizeof(sample->data));
    sample->copied = copied;
    memcpy(sample->data, data, copied);
    cpu_generation_hits++;
    cpu_received++;
 unlock:
    spin_unlock_irqrestore(&cpu_lock, flags);
 done:
    consume_skb(skb);
    return NET_RX_SUCCESS;
}
static struct packet_type cpu_tap = {
    .type = cpu_to_be16(ETH_P_ALL), .func = cpu_receive,
};

/* No writes: allocate only real unused rows and audit moved DRR identities. */
static int private_preflight(void)
{
	bool referenced[64] = {}, c_used[36] = {}, e_used[36] = {};
	u32 map, c, e, original_c, original_e, data[3], parent_map;
	unsigned int i, n, cp, ep;
	if (!edma || !cpu_consent)
		return reject_preflight("cpu_consent_or_edma", 0, 0, -EPERM);
	if (rd(0x400014) != 64 || rd(0x400018) != 8)
		return reject_preflight("shared_slots", 0x400014, rd(0x400014), -EXDEV);
	read_row(0x45e000, cpu_parent_cfg, 3);
	read_row(0x474000, cpu_port_cfg, 2);
	if ((rd(0x440000) & 15) || (rd(0x446000) & 15) ||
	    (cpu_parent_cfg[2] & 0x30) || (cpu_port_cfg[1] & 0x10) ||
	    !(readl(edma + 0x48018) & 1))
		return reject_preflight("native_cpu_parent", 0x440000, rd(0x440000), -EXDEV);
	original_c = rd(0x404000 + 16 * (48 * 8 + ((saved_map >> 6) & 7)));
	original_e = rd(0x406000 + 16 * (48 * 8 + ((saved_map >> 9) & 7)));
	if ((original_c & 255) >= 160 || (original_e & 255) >= 160)
		return reject_preflight("l0_drr_range", 0x402000 + 16 * Q, saved_map, -ERANGE);
	for (i = 0; i < 300; i++) {
		map = leaf_maps[i] = rd(0x402000 + 16 * i);
		leaf_ports[i] = rd(0x408000 + 16 * i);
		n = map & 63; cp = (map >> 6) & 7; ep = (map >> 9) & 7;
		referenced[n] = true;
		if (i == Q)
			continue;
		if (!n && (cp == 7 || ep == 7))
			return reject_preflight("cpu_priority_busy", 0x402000 + 16 * i, map, -EBUSY);
		c = rd(0x404000 + 16 * (n * 8 + cp));
		e = rd(0x406000 + 16 * (n * 8 + ep));
		if ((c & 255) == (original_c & 255) || (e & 255) == (original_e & 255))
			return reject_preflight("leaf_drr_alias", 0x402000 + 16 * i, map, -EBUSY);
	}
	private_l1 = 64;
	for (i = 64; i-- > 0;) {
		read_row(0x45e000 + 16 * i, data, 3);
		if (!referenced[i] && !(data[2] & 0x30) && !(rd(0x466000 + 16 * i) & 7)) {
			private_l1 = i;
			break;
		}
	}
	if (private_l1 == 64)
		return reject_preflight("no_private_l1", 0, 0, -ENOSPC);
	for (i = 0; i < 64; i++) {
		parent_maps[i] = rd(0x440000 + 16 * i);
		parent_ports[i] = rd(0x446000 + 16 * i);
		if (i == private_l1)
			continue;
		map = rd(0x440000 + 16 * i);
		n = map & 15; cp = (map >> 4) & 7; ep = (map >> 7) & 7;
		if (n >= 8)
			return reject_preflight("l1_port_range", 0x440000 + 16 * i, map, -ERANGE);
		if (n == 4 && (cp == 7 || ep == 7))
			return reject_preflight("port4_priority7_busy", 0x440000 + 16 * i, map, -EBUSY);
		c = rd(0x442000 + 16 * (n * 8 + cp)) & 63;
		e = rd(0x444000 + 16 * (n * 8 + ep)) & 63;
		if (c >= 36 || e >= 36)
			return reject_preflight("l1_drr_range", 0x440000 + 16 * i, map, -ERANGE);
		c_used[c] = true; e_used[e] = true;
	}
	private_c = private_e = 36;
	for (i = 0; i < 36; i++) {
		read_row(0x448000 + 16 * i, data, 2);
		if (private_c == 36 && !c_used[i] && !(data[0] & (BIT(12) | BIT(30))))
			private_c = i;
		read_row(0x44a000 + 16 * i, data, 2);
		if (private_e == 36 && !e_used[i] && !(data[0] & (BIT(12) | BIT(30))))
			private_e = i;
	}
	if (private_c == 36 || private_e == 36)
		return reject_preflight("no_private_l1_drr", 0, 0, -ENOSPC);
	parent_map = rd(0x440000 + 16 * 48);
	if (!(parent_map & GENMASK(19, 10)) || !(parent_map & GENMASK(29, 20)))
		return reject_preflight("parent_weights", 0x440000 + 16 * 48, parent_map, -EXDEV);
	private_rows[P_CFG] = (struct private_row){ .off = 0x45e000 + 16 * private_l1, .words = 3 };
	private_rows[P_CREDIT] = (struct private_row){ .off = 0x45c000 + 16 * private_l1, .words = 2 };
	private_rows[P_MAP] = (struct private_row){ .off = 0x440000 + 16 * private_l1, .words = 1 };
	private_rows[P_PORT] = (struct private_row){ .off = 0x446000 + 16 * private_l1, .words = 1 };
	private_rows[P_LENGTH] = (struct private_row){ .off = 0x46a000 + 16 * private_l1, .words = 1 };
	private_rows[P_L1C] = (struct private_row){ .off = 0x442000 + 16 * 39, .words = 1 };
	private_rows[P_L1E] = (struct private_row){ .off = 0x444000 + 16 * 39, .words = 1 };
	private_rows[P_L0C] = (struct private_row){ .off = 0x404000 + 16 * (private_l1 * 8), .words = 1 };
	private_rows[P_L0E] = (struct private_row){ .off = 0x406000 + 16 * (private_l1 * 8), .words = 1 };
	private_rows[P_CPUC] = (struct private_row){ .off = 0x404070, .words = 1 };
	private_rows[P_CPUE] = (struct private_row){ .off = 0x406070, .words = 1 };
	for (i = 0; i < P_ROWS; i++) {
		struct private_row *row = &private_rows[i];
		read_row(row->off, row->saved, row->words);
		memcpy(row->expected, row->saved, sizeof(row->saved));
	}
	private_rows[P_MAP].expected[0] = (parent_map & ~0x3ffU) | 4 | (7 << 4) | (7 << 7);
	private_rows[P_PORT].expected[0] = (private_rows[P_PORT].saved[0] & ~15U) | 4;
	private_rows[P_LENGTH].expected[0] = (private_rows[P_LENGTH].saved[0] & ~3U) | 1;
	c = rd(0x442000 + 16 * (4 * 8 + ((parent_map >> 4) & 7)));
	e = rd(0x444000 + 16 * (4 * 8 + ((parent_map >> 7) & 7)));
	private_rows[P_L1C].expected[0] = (c & ~63U) | private_c;
	private_rows[P_L1E].expected[0] = (e & ~63U) | private_e;
	private_rows[P_L0C].expected[0] = private_rows[P_CPUC].expected[0] = original_c;
	private_rows[P_L0E].expected[0] = private_rows[P_CPUE].expected[0] = original_e;
	physical_map = (saved_map & ~0xfffU) | private_l1;
	cpu_map = (saved_map & ~0xfffU) | (7 << 6) | (7 << 9);
	expected_map = saved_map; expected_port = saved_port;
	saved_route = readl(edma + ROUTE193);
	expected_route = (saved_route & ~(15U << 4)) | (15U << 4);
	tap_dev = dev_get_by_name(&init_net, "eth0");
	if (!tap_dev)
		return -ENODEV;
	return 0;
}

static int private_install(void)
{
    u32 cfg[3] = {}, credit[2] = {};
    unsigned int i;
    int err = private_write(P_CFG, cfg);
    if (!err)
        err = private_write(P_CREDIT, credit);
    for (i = P_MAP; i < P_ROWS && !err; i++)
        err = private_write(i, private_rows[i].expected);
    if (!err) {
        route_touched = true;
        writel(expected_route, edma + ROUTE193);
        if (readl(edma + ROUTE193) != expected_route)
            err = -EIO;
    }
    if (!err) {
        qmap_touched = true;
        expected_map = physical_map;
        err = write_one(0x402000 + 16 * Q, expected_map);
    }
    if (!err) {
        cpu_tap.dev = tap_dev;
        dev_add_pack(&cpu_tap);
        tap_on = true;
    }
    return err;
}

/* Exact borrowed rows stay frozen. The hardware-owned credits are not frozen. */
static int private_ownership(bool partial)
{
	u32 data[3];
	unsigned int i;
	int err;
	if (rd(0x400010) != 300 || rd(0x400014) != 64 || rd(0x400018) != 8)
		return -ESTALE;
	read_row(0x45e000, data, 3);
	if (memcmp(data, cpu_parent_cfg, sizeof(cpu_parent_cfg)))
		return -ESTALE;
	read_row(0x474000, data, 2);
	if (memcmp(data, cpu_port_cfg, sizeof(cpu_port_cfg)) || !(readl(edma + 0x48018) & 1))
		return -ESTALE;
	for (i = 0; i < 300; i++)
		if (i != Q && (rd(0x402000 + 16 * i) != leaf_maps[i] ||
			      rd(0x408000 + 16 * i) != leaf_ports[i]))
			return -ESTALE;
	for (i = 0; i < 64; i++)
		if (i != private_l1 && (rd(0x440000 + 16 * i) != parent_maps[i] ||
				       rd(0x446000 + 16 * i) != parent_ports[i]))
			return -ESTALE;
	for (i = 0; i < P_ROWS; i++) {
		struct private_row *row = &private_rows[i];
		if (!row->touched || i == P_CREDIT)
			continue;
		err = owned_row(row->off, row->expected, row->saved, row->words, partial);
		if (err)
			return err;
	}
	if (route_touched && readl(edma + ROUTE193) != expected_route &&
	    !(partial && readl(edma + ROUTE193) == saved_route))
		return -ESTALE;
	return 0;
}

/* Called held, with no unresolved ordinary grant. Only actual CPU reception
 * permits the reverse mapping. Prior physical port-map consumption is a test
 * obligation: finite alternation must qualify it before continuous disposal.
 */
static int map_cpu(bool to_cpu)
{
	int err;
	if (in_flight || !(rd(DEQ) & 1))
		return -EBUSY;
	expected_map = to_cpu ? cpu_map : physical_map;
	expected_port = to_cpu ? (saved_port & ~15U) : saved_port;
	qmap_touched = true;
	err = write_one(0x402000 + 16 * Q, expected_map);
	if (!err)
		err = write_one(0x408000 + 16 * Q, expected_port);
	if (!err)
		cpu_mapping = to_cpu;
	return err;
}

static int private_restore(void)
{
	u32 cfg[3];
	unsigned int i;
	int err = 0;
	if (private_rows[P_CFG].touched) {
		memcpy(cfg, private_rows[P_CFG].expected, sizeof(cfg));
		cfg[2] &= ~0x30U;
		err = private_write(P_CFG, cfg);
	}
	if (!err && qmap_touched) {
		err = write_one(0x402000 + 16 * Q, saved_map);
		if (!err)
			err = write_one(0x408000 + 16 * Q, saved_port);
	}
	for (i = P_MAP; i < P_ROWS && !err; i++)
		if (private_rows[i].touched)
			err = write_row(private_rows[i].off, private_rows[i].saved, private_rows[i].words);
	if (!err && private_rows[P_CREDIT].touched)
		err = write_row(private_rows[P_CREDIT].off, private_rows[P_CREDIT].saved, 2);
	if (!err && private_rows[P_CFG].touched)
		err = write_row(private_rows[P_CFG].off, private_rows[P_CFG].saved, 3);
	if (!err && route_touched) {
		writel(saved_route, edma + ROUTE193);
		if (readl(edma + ROUTE193) != saved_route)
			err = -EIO;
	}
	if (!err && tap_on) {
		dev_remove_pack(&cpu_tap);
		synchronize_net();
		tap_on = false;
	}
	if (!err && tap_dev) {
		dev_put(tap_dev);
		tap_dev = NULL;
	}
	return err;
}

static int check_ownership(bool partial)
{
	u32 cfg[3], live[3], expected;
	unsigned int i;
	int err;
	if (rd(DROP) != saved_drop)
		return -ESTALE;
	expected = expected_map;
	err = owned_row(0x402000 + 16 * Q, &expected, &saved_map, 1, partial);
	if (err)
		return err;
	expected = expected_port;
	err = owned_row(0x408000 + 16 * Q, &expected, &saved_port, 1, partial);
	if (err)
		return err;
	err = private_ownership(partial);
	if (err)
		return err;
	read_row(0x45e000 + 16 * 48, live, 3);
	if (memcmp(live, saved_parent, sizeof(live)))
		return -ESTALE;
	read_row(0x474000 + 16 * 4, live, 2);
	if (memcmp(live, saved_port_cfg, sizeof(saved_port_cfg)))
		return -ESTALE;
	read_row(CFG, cfg, 3);
	if (memcmp(cfg, saved_cfg, sizeof(cfg)) &&
	    ((cfg[0] != 0xfffc0000 && cfg[0] != 0xfffc0001) ||
	     cfg[1] != 0xfffc0000 || (cfg[2] != 8 && cfg[2] != 0x38)))
		return -ESTALE;
	err = owned_row(AC, ac_expected, saved_ac, 4, partial);
	if (err)
		return err;
	for (i = 0; i < 16; i++) {
		expected = saved_priority[i];
		if (touched_priority & BIT(i))
			expected &= ~15U;
		err = owned_row(CONTROL_PRIORITY(i), &expected, &saved_priority[i], 1, partial);
		if (err)
			return err;
	}
	for (i = 0; i < 8; i++) {
		if (touched_rule & BIT(i)) {
			err = owned_row(RULE(8 * acl_list + i), rules[i].rule, saved_acl[i].rule, 3, partial);
			if (err)
				return err;
		}
		if (touched_mask & BIT(i)) {
			err = owned_row(MASK(8 * acl_list + i), rules[i].mask, saved_acl[i].mask, 2, partial);
			if (err)
				return err;
		}
		if (touched_action & BIT(i)) {
			err = owned_row(ACTION(8 * acl_list + i), rules[i].action, saved_acl[i].action, 5, partial);
			if (err)
				return err;
		}
	}
	for (i = 0; i < 3; i++) {
		if (!(touched_ext & BIT(i)))
			continue;
		expected = i == 0 ? 15 : i == 1 ? 3 : 0;
		err = owned_row(EXT(i, acl_list), &expected, &saved_ext[i], 1, partial);
		if (err)
			return err;
	}
	return 0;
}

static int bind_rule(bool enable)
{
	unsigned int i;
	int err;
	for (i = 0; i < 8; i++) {
		if (!(touched_rule & BIT(i)))
			continue;
		field(rules[i].rule, 61, 8, enable ? BIT(3) : 0);
		err = write_row(RULE(8 * acl_list + i), rules[i].rule, 3);
		if (err)
			return err;
	}
	armed = enable;
	if (enable)
		ever_armed = true;
	return 0;
}

/* Called only by the single owner. Closing input is not a pipeline fence. */
static int seal_input(void)
{
	int err = write_one(ENQ, saved_enq | 1);
	if (!err)
		err = check_ownership(!ever_armed);
	if (!err)
		err = bind_rule(false);
	if (!err) {
		sealed = true;
		stop_time = ktime_get_ns();
	}
	return err;
}

/* Observe only while service is held and no selected packet can disappear.
 * If an unserved suffix exists, its final record is a live append anchor.
 * Otherwise begin at the new HEAD; never follow a retired tail or require
 * that the next generation have a different numeric descriptor ID. */
static int discover(void)
{
    u64 begin = ktime_get_ns(), cursor = arrived;
    u32 snapshot = rd(HEAD), id, tail, lo, hi, length, h;
    struct item *entry;
    unsigned int added = 0;

    discovery_calls++;
    if (in_flight || !(rd(DEQ) & 1))
        return -EBUSY;
    if (snapshot & 1) {
        if (arrived != retired)
            return -ESTALE;
        return 0;
    }
    id = (snapshot >> 12) & 0x7ff;
    tail = (snapshot >> 1) & 0x7ff;
    if (arrived != retired) {
        if (items[retired % RECORDS].id != id)
            return -ESTALE;
        entry = &items[(arrived - 1) % RECORDS];
        if (entry->id == tail)
            return 0;
        id = rd(0x890000 + 16 * entry->id) & 0x7ff;
    }
    for (;;) {
        if (cursor - retired >= RECORDS || ids[id])
            return -EOVERFLOW;
        lo = rd(0x9c0000 + 64 * id);
        hi = rd(0x9c0004 + 64 * id);
        metadata_reads += 2;
        length = (lo >> 24) | ((hi & 63) << 8);
        if ((lo & 0xfff) != 3 || (length != 60 && length != 67 &&
            length != 106 && !(large && length == 1514)))
            return -EPROTO;
        entry = &items[cursor % RECORDS];
        memset(entry, 0, sizeof(*entry));
        entry->serial = cursor;
        entry->id = id;
        entry->length = length;
        entry->observed = begin;
        /* The native logical enqueue event occurs here, in FIFO order.
         * Cells occupied before this event remain transport staging. */
        entry->accepted = length <= byte_limit - backlog;
        if (entry->accepted) {
            backlog += length;
            accepted++;
            accepted_bytes += length;
        } else {
            rejected++;
            rejected_bytes += length;
        }
        entry->backlog_after = backlog;
        if (cursor < LEDGER)
            ledger[cursor] = *entry;
        ids[id] = true;
        cursor++;
        arrived = cursor; /* preserve every completed admission even on failure */
        added++;
        backlog_max = max(backlog_max, backlog);
        pending_max = max_t(u32, pending_max, arrived - retired);
        if (id == tail)
            break;
        id = rd(0x890000 + 16 * id) & 0x7ff;
    }
    h = rd(HEAD);
    /* Appends can change tail. The retained starting head cannot disappear. */
    if ((h & 0x7ff001) != (snapshot & 0x7ff001))
        return -ESTALE;
    cells_max = max(cells_max, rd(USED) & 0xfff);
    discovery_ns += ktime_get_ns() - begin;
    return added;
}

/* All selected entries have one disposition. Previously selected survivors
 * of an explicit partial stop retain their output reservation and are never
 * admitted again or charged to native backlog twice. */
static int grant_prefix(void)
{
    struct item *first = &items[retired % RECORDS], *entry;
    u32 cfg[3] = { 0xfffc0000, 0xfffc0000, 8 }, credit[2];
    u32 h, count = 0;
    u64 begin = ktime_get_ns(), prepared_at;
    unsigned long flags;
    unsigned int i;
    bool was_selected;
    int err;

    if (arrived == retired || in_flight || frozen || collecting)
        return -EBUSY;
    h = rd(HEAD);
    if ((h & 1) || ((h >> 12) & 0x7ff) != first->id || !(rd(DEQ) & 1))
        return -ESTALE;
    was_selected = first->selected;
    while (retired + count < arrived && count < batch_cap) {
        entry = &items[(retired + count) % RECORDS];
        if (entry->accepted != first->accepted || entry->selected != was_selected)
            break;
        count++;
    }
    if (!count)
        return -EINVAL;
    if (!first->accepted && READ_ONCE(cpu_received) + count > CPU_SAMPLES)
        return -ENOSPC; /* refuse before publishing an unrecordable return */
    if (cpu_mapping != !first->accepted) {
        err = map_cpu(!first->accepted);
        if (err)
            return err;
    }
    flight_credit = count * QUANTUM - QUANTUM / 2;
    credit[0] = flight_credit;
    credit[1] = 0x20400000;
    err = write_row(CFG, cfg, 3);
    if (!err)
        err = write_row(CREDIT, credit, 2);
    prepared_at = ktime_get_ns();
    cfg[0] |= 1;
    cfg[2] = 0x38;
    if (!err)
        err = write_row(CFG, cfg, 3);
    prepare_calls++;
    prepare_ns += ktime_get_ns() - begin;
    if (err)
        return err;
    h = rd(HEAD);
    if ((h & 1) || ((h >> 12) & 0x7ff) != first->id || !(rd(DEQ) & 1))
        return -ESTALE;
    last_tx = rd(TX);
    issue_time = ktime_get_ns();
    if (issue_time - prepared_at > FLIGHT_NS)
        return -ETIMEDOUT;
    flight_count = count;
    flight_cpu = !first->accepted;
    if (flight_cpu) {
        spin_lock_irqsave(&cpu_lock, flags);
        if (cpu_fault || cpu_expected) {
            spin_unlock_irqrestore(&cpu_lock, flags);
            return -EPROTO;
        }
        cpu_start = retired;
        cpu_count = count;
        cpu_generation_hits = 0;
        cpu_expected = true;
        spin_unlock_irqrestore(&cpu_lock, flags);
    }
    /* These FIFO dequeues are legal now. No waiting for an artificial batch;
     * no rate parent or AQM permission is inferred from this transport grant. */
    for (i = 0; i < count; i++) {
        entry = &items[(retired + i) % RECORDS];
        if (!entry->selected) {
            entry->selected = true;
            selected++;
            if (entry->accepted) {
                backlog -= entry->length;
                selected_bytes += entry->length;
            }
        }
    }
    if (count == batch_cap)
        reason_cap++;
    else if (retired + count == arrived)
        reason_tail++;
    else
        reason_change++;
    in_flight = true;
    issued_allowances += count;
    histogram[count]++;
    grants++;
    err = write_one(DEQ, saved_gate & ~1);
    grant_ns += ktime_get_ns() - issue_time;
    next_check = issue_time + COMPLETION_RETRY_NS;
    return err;
}

/* Called only after the actual count and CPU witnesses prove this prefix.
 * No old descriptor is read after retirement. The next discovery starts from
 * a retained unserved suffix or the actual new HEAD, including numeric reuse. */
static void retire_prefix(unsigned int count)
{
    struct item *entry;
    unsigned long flags;
    unsigned int i;
    for (i = 0; i < count; i++) {
        entry = &items[(retired + i) % RECORDS];
        if (entry->accepted) {
            sent++;
            sent_bytes += entry->length;
        } else {
            disposed++;
            disposed_bytes += entry->length;
        }
        length_count[entry->length == 60 ? 0 : entry->length == 67 ? 1 :
                     entry->length == 106 ? 2 : 3]++;
        ids[entry->id] = false;
    }
    retired += count;
    completed += count;
    if (flight_cpu) {
        spin_lock_irqsave(&cpu_lock, flags);
        cpu_expected = false;
        spin_unlock_irqrestore(&cpu_lock, flags);
    }
    in_flight = false;
    flight_count = 0;
}

static int finish_prefix(void)
{
    u32 credit[2], tx, cfg[3] = { 0xfffc0000, 0xfffc0000, 8 };
    u64 begin = ktime_get_ns(), observed, elapsed, hits = 0;
    unsigned long flags;
    int err = 0;
    read_row(CREDIT, credit, 2);
    tx = rd(TX);
    observed = ktime_get_ns();
    finish_checks++;
    if (flight_cpu) {
        spin_lock_irqsave(&cpu_lock, flags);
        err = cpu_fault;
        hits = cpu_generation_hits;
        spin_unlock_irqrestore(&cpu_lock, flags);
    }
    if ((u32)(tx - last_tx) > flight_count || (flight_cpu && hits > flight_count))
        err = -EOVERFLOW;
    if (!err && (credit[0] & BIT(30)) && (credit[0] & 0x3fffffff) &&
        (u32)(tx - last_tx) == flight_count && (!flight_cpu || hits == flight_count)) {
        err = write_one(DEQ, saved_gate | 1);
        if (!err)
            err = write_row(CFG, cfg, 3);
        if (!err) {
            elapsed = observed - issue_time;
            settle_sum_ns += elapsed;
            settle_max_ns = max(settle_max_ns, elapsed);
            settle_min_ns = min(settle_min_ns, elapsed);
            retire_prefix(flight_count);
        }
    } else if (!err && observed - issue_time > FLIGHT_NS) {
        err = -ETIMEDOUT;
    } else {
        next_check = observed + COMPLETION_RETRY_NS;
    }
    finish_ns += ktime_get_ns() - begin;
    return err;
}

/* Holds/freeze are an operation boundary, not a fabricated completion fence.
 * A partial in-flight grant keeps its records and mapping until settle N. */
static int freeze_probe(void)
{
    u32 cfg[3] = { 0xfffc0000, 0xfffc0000, 8 };
    int err = write_one(DEQ, saved_gate | 1);
    if (!err)
        err = write_row(CFG, cfg, 3);
    if (!err && !sealed)
        err = seal_input();
    frozen_time = ktime_get_ns();
    frozen = true;
    running = false;
    partial_stops++;
    return err;
}

/* Explicit diagnostic consent: root has stopped the source and independently
 * witnessed N terminal originals (wire or CPU guard). Equal idle snapshots do
 * not supply that witness. Count credit, PTX and the remaining HEAD must agree.
 * The unissued selected suffix retains its original output reservation. */
static int settle_partial(unsigned int count)
{
    u32 credit[2], cfg[3], tx, h;
    s64 signed_credit, consumed, error;
    u64 hits = 0;
    unsigned long flags;
    int err;
    if (!reserved || running || !frozen || !sealed || !in_flight || count > flight_count)
        return -EBUSY;
    err = check_ownership(false);
    if (err)
        return err;
    read_row(CFG, cfg, 3);
    read_row(CREDIT, credit, 2);
    tx = rd(TX);
    h = rd(HEAD);
    if (!(rd(DEQ) & 1) || !(rd(ENQ) & 1) || cfg[0] != 0xfffc0000 || cfg[2] != 8)
        return -ESTALE;
    signed_credit = credit[0] & 0x3fffffff;
    if (credit[0] & BIT(30))
        signed_credit = -signed_credit;
    consumed = (s64)flight_credit - signed_credit;
    error = consumed - (s64)count * QUANTUM;
    /* Refresh only adds: allow a bounded100ms history plus guard-read time.
     * A long/descheduled lease cannot be reinterpreted as a finite grant. */
    if (frozen_time - issue_time > FLIGHT_NS || error > 0 || error < -20000 ||
        (u32)(tx - last_tx) != count)
        return -EAGAIN;
    if (retired + count < arrived && ((h & 1) ||
        ((h >> 12) & 0x7ff) != items[(retired + count) % RECORDS].id))
        return -ESTALE;
    if (flight_cpu) {
        spin_lock_irqsave(&cpu_lock, flags);
        err = cpu_fault;
        hits = cpu_generation_hits;
        spin_unlock_irqrestore(&cpu_lock, flags);
        if (err || hits != count)
            return err ? err : -EAGAIN;
    }
    retire_prefix(count);
    partial_settlements++;
    partial_completed += count;
    return 0;
}

static bool parked;
static int run_probe(void *unused)
{
    while (!kthread_should_stop()) {
        u64 begin = ktime_get_ns(), elapsed, wake_at, reads, writes;
        ktime_t delay;
        int err = 0;
        mutex_lock(&lock);
        if (!running)
            goto stop_locked;
        reads = mmio_reads;
        writes = mmio_writes;
        if (previous_visit)
            max_gap_ns = max(max_gap_ns, begin - previous_visit);
        previous_visit = begin;
        if (begin >= next_ownership_check) {
            err = check_ownership(false);
            next_ownership_check = begin + 10 * NSEC_PER_MSEC;
        }
        if (!err && READ_ONCE(cpu_fault))
            err = READ_ONCE(cpu_fault);
        if (!err && !sealed && (stopping || begin >= end_time))
            err = seal_input();
        if (!err && in_flight)
            err = finish_prefix();
        if (!err && !in_flight) {
            err = discover();
            if (err > 0)
                err = 0;
        }
        if (!err && !in_flight && !collecting && arrived != retired)
            err = grant_prefix();
        visits++;
        elapsed = ktime_get_ns() - begin;
        visit_ns += elapsed;
        max_visit_ns = max(max_visit_ns, elapsed);
        if (err) {
            if (!failure)
                failure = err;
            freeze_probe();
        } else if (sealed && !in_flight && (collecting || (arrived == retired && (rd(HEAD) & 1)))) {
            if (!collecting && cpu_mapping)
                err = map_cpu(false);
            if (err && !failure)
                failure = err;
            running = false;
        }
        worker_reads += mmio_reads - reads;
        worker_writes += mmio_writes - writes;
        if (!running)
            goto stop_locked;
        if (in_flight) {
            wake_at = next_check;
            completion_waits++;
        } else {
            wake_at = ktime_get_ns() + IDLE_NS;
            idle_waits++;
        }
        if (!sealed)
            wake_at = min(wake_at, end_time);
        wake_at = min(wake_at, next_ownership_check);
        elapsed = ktime_get_ns();
        delay = ns_to_ktime(wake_at > elapsed ? wake_at - elapsed : 1);
        wakes++;
        mutex_unlock(&lock);
        set_current_state(TASK_INTERRUPTIBLE);
        schedule_hrtimeout(&delay, HRTIMER_MODE_REL);
    }
    mutex_lock(&lock);
 stop_locked:
    parked = true;
    mutex_unlock(&lock);
    __set_current_state(TASK_RUNNING);
    wait_event_interruptible(stop_wait, kthread_should_stop());
    return 0;
}

static int reserve_probe(unsigned int list)
{
	u32 data[5], parent[3], port_cfg[2], ext, value;
	u32 cfg[3] = { 0xfffc0000, 0xfffc0000, 8 };
	u32 credit[2] = { BIT(30) | QUANTUM / 2, 0x20400000 };
	u32 ac[4];
	unsigned int i, j;
	int err;
	if (!allow_writes || reserved || used_once || list >= 64)
		return -EPERM;
	value = rd(HEAD);
	if (!(value & 1))
		return reject_preflight("queue_not_empty", HEAD, value, -EBUSY);
	value = rd(USED);
	if (value & 0xfff)
		return reject_preflight("queue_cells", USED, value, -EBUSY);
	value = rd(ENQ);
	if (value & 1)
		return reject_preflight("enqueue_closed", ENQ, value, -EBUSY);
	value = rd(DROP);
	if (value & 1)
		return reject_preflight("dequeue_drop", DROP, value, -EBUSY);
	saved_map = rd(0x402000 + 16 * Q);
	saved_port = rd(0x408000 + 16 * Q);
	read_row(CFG, saved_cfg, 3);
	read_row(0x45e000 + 16 * 48, parent, 3);
	read_row(0x474000 + 16 * 4, port_cfg, 2);
	memcpy(saved_parent, parent, sizeof(parent));
	memcpy(saved_port_cfg, port_cfg, sizeof(port_cfg));
	if ((saved_map & 0x3f) != 48)
		return reject_preflight("queue_parent", 0x402000 + 16 * Q, saved_map, -EXDEV);
	if ((saved_port & 15) != 4)
		return reject_preflight("queue_port", 0x408000 + 16 * Q, saved_port, -EXDEV);
	value = rd(0x446000 + 16 * 48);
	if ((value & 15) != 4)
		return reject_preflight("parent_port", 0x446000 + 16 * 48, value, -EXDEV);
	if (saved_cfg[2] & 0x30)
		return reject_preflight("leaf_shaper", CFG + 8, saved_cfg[2], -EXDEV);
	if (parent[2] & 0x30)
		return reject_preflight("parent_shaper", 0x45e008 + 16 * 48, parent[2], -EXDEV);
	if (port_cfg[1] & 0x10)
		return reject_preflight("port_shaper", 0x474004 + 16 * 4, port_cfg[1], -EXDEV);
	value = rd(0x400010);
	if (value != 300)
		return reject_preflight("l0_slot", 0x400010, value, -EXDEV);
	for (i = 0; i < 16; i++)
		saved_priority[i] = rd(CONTROL_PRIORITY(i));
	err = audit_selectors();
	if (err)
		return err;
	for (i = 0; i < 512; i++) {
		read_row(ACTION(i), data, 5);
		if ((data[3] & BIT(21)) && ((data[3] >> 22) & 255) == Q)
			return reject_preflight("acl_queue_alias", ACTION(i) + 12, data[3], -EADDRINUSE);
	}
	for (i = 0; i < 8; i++) {
		struct acl_row *a = &saved_acl[i];
		read_row(RULE(8 * list + i), a->rule, 3);
		if ((a->rule[1] >> 27) & 31)
			return reject_preflight("acl_list_bound", RULE(8 * list + i) + 4, a->rule[1], -EBUSY);
		if (a->rule[2] & 31)
			return reject_preflight("acl_list_bound", RULE(8 * list + i) + 8, a->rule[2], -EBUSY);
		read_row(MASK(8 * list + i), a->mask, 2);
		read_row(ACTION(8 * list + i), a->action, 5);
		read_row(COUNT(8 * list + i), a->count, 3);
	}
	for (i = 0; i < 3; i++)
		saved_ext[i] = rd(EXT(i, list));
	read_row(AC, saved_ac, 4);
	read_row(0x84c000 + 16 * ((saved_ac[0] >> 4) & 3), group_row, 3);
	/* Require the shared group admission disabled; never change another queue
	 * population's group budget merely to make this fixture run.
	 */
	if (group_row[0] & 3)
		return reject_preflight("shared_admission", 0x84c000 + 16 * ((saved_ac[0] >> 4) & 3), group_row[0], -EXDEV);
	read_row(CREDIT, saved_credit, 2);
	saved_gate = rd(DEQ);
	saved_enq = rd(ENQ);
	saved_drop = rd(DROP);
	for (i = 0; i < 6; i++)
		read_row(0x9e0000 + 0x60 * Q + 12 * i, drop_before[i], 3);
	err = private_preflight();
	if (err)
		return err;
	acl_list = list;
	reserved = true;
	used_once = true;
	__module_get(THIS_MODULE);
	err = write_one(DEQ, saved_gate | 1);
	if (!err)
		err = write_one(ENQ, saved_enq | 1);
	if (!err && (!(rd(HEAD) & 1) || (rd(USED) & 0xfff)))
		err = reject_preflight("queue_changed_before_hold", HEAD, rd(HEAD), -EBUSY);
	/* Explicit diagnostic PRIO policy: every non-test priority is controlband0.
	 * The exact test ACL later overrides its queue to193 without an ARM visit.
	 */
	for (i = 0; i < 16 && !err; i++) {
		value = rd(CONTROL_PRIORITY(i));
		if (value != saved_priority[i]) {
			err = reject_preflight("control_priority_changed", CONTROL_PRIORITY(i), value, -ESTALE);
			break;
		}
		touched_priority |= BIT(i);
		err = write_one(CONTROL_PRIORITY(i), saved_priority[i] & ~15U);
	}
	if (!err)
		err = write_row(CFG, cfg, 3);
	if (!err)
		err = write_row(CREDIT, credit, 2);
	ac[0] = 5 | (saved_ac[0] & 0x30) | (STAGE_CELLS << 21);
	ac[1] = ac[2] = 0;
	ac[3] = saved_ac[3] & 0xff000000;
	memcpy(ac_expected, ac, sizeof(ac));
	if (!err)
		err = private_install();
	if (!err)
		err = write_row(AC, ac, 4);
	memset(rules, 0, sizeof(rules));
	for (i = 0; i < 8 && !err; i++) {
		u64 value, mask;
		u32 type, bypass = BIT(0) | BIT(1) | GENMASK(19, 8) | BIT(21) | BIT(22) | BIT(23);
        if ((i & 3) < 2) {
            bool dest = i & 1;
            type = dest ? 4 : 5;
            value = ((u64)(dest ? 0xc0a80173 : 0xc0a80190) << 16) |
                (dest ? (i < 4 ? 45987 : 45988) : 0) | BIT_ULL(49) | BIT_ULL(52);
            mask = GENMASK_ULL(52, dest ? 0 : 16);
        } else if ((i & 3) == 2) {
            type = 2;
            value = BIT_ULL(36);
            mask = 7ULL << 36;
        } else {
            type = 12;
            value = 17ULL << 16;
            mask = (255ULL << 16) | BIT_ULL(48) | BIT_ULL(49);
        }
		rules[i].rule[0] = value;
		rules[i].rule[1] = value >> 32;
		field(rules[i].rule, 55, 4, type);
		rules[i].mask[0] = mask;
		rules[i].mask[1] = mask >> 32;
		field(rules[i].action, 0, 1, 1);
		field(rules[i].action, 3, 14, (2 << 12) | 4);
		field(rules[i].action, 18, 32, bypass);
		field(rules[i].action, 117, 1, 1);
		field(rules[i].action, 118, 8, Q);
		touched_mask |= BIT(i);
		err = write_row(MASK(8 * list + i), rules[i].mask, 2);
		if (!err) {
			touched_action |= BIT(i);
			err = write_row(ACTION(8 * list + i), rules[i].action, 5);
		}
		if (!err) {
			touched_rule |= BIT(i);
			err = write_row(RULE(8 * list + i), rules[i].rule, 3);
		}
	}
	for (j = 0; j < 3 && !err; j++) {
		ext = j == 0 ? 15 : j == 1 ? 3 : 0; /* independent compounds0..3 and4..7 */
		touched_ext |= BIT(j);
		err = write_one(EXT(j, list), ext);
	}
	if (err)
		failure = err;
	tx_start = rd(TX);
	return err;
}

static int restore_probe(void)
{
	u32 cfg[3] = { 0xfffc0000, 0xfffc0000, 8 };
	unsigned int i;
	int err;
	if (!reserved || running || in_flight || !terminal || !(rd(HEAD) & 1) ||
	    (rd(USED) & 0xfff) || selected != completed || arrived != retired || backlog || !sealed ||
        (worker && !parked) || READ_ONCE(cpu_fault))
		return -EBUSY;
	err = check_ownership(!ever_armed || restoring);
	if (!err) {
		restoring = true;
		err = write_one(DEQ, saved_gate | 1);
	}
	if (!err)
		err = bind_rule(false);
	if (!err)
		err = write_row(CFG, cfg, 3);
	if (!err)
		err = private_restore();
	if (!err)
		err = write_row(CREDIT, saved_credit, 2);
	if (!err)
		err = write_row(AC, saved_ac, 4);
	for (i = 0; i < 8 && !err; i++) {
		if (touched_mask & BIT(i))
			err = write_row(MASK(8 * acl_list + i), saved_acl[i].mask, 2);
		if (!err && (touched_action & BIT(i)))
			err = write_row(ACTION(8 * acl_list + i), saved_acl[i].action, 5);
		if (!err && (touched_rule & BIT(i))) {
			err = write_row(COUNT(8 * acl_list + i), saved_acl[i].count, 3);
			if (!err)
				err = write_row(RULE(8 * acl_list + i), saved_acl[i].rule, 3);
		}
	}
	for (i = 0; i < 3 && !err; i++)
		if (touched_ext & BIT(i))
			err = write_one(EXT(i, acl_list), saved_ext[i]);
	/* Only after actual accepted work is retired and the test ACL is unbound. */
	for (i = 0; i < 16 && !err; i++)
		if (touched_priority & BIT(i))
			err = write_one(CONTROL_PRIORITY(i), saved_priority[i]);
	if (!err)
		err = write_one(DROP, saved_drop);
	if (!err)
		err = write_row(CFG, saved_cfg, 3);
	if (!err)
		err = write_one(ENQ, saved_enq);
	if (!err)
		err = write_one(DEQ, saved_gate);
	if (!err) {
		if (worker) {
			kthread_stop(worker);
			worker = NULL;
		}
		reserved = false;
		module_put(THIS_MODULE);
	}
	return err;
}

static int status_show(struct seq_file *s, void *unused)
{
    u32 cfg[3], credit[2], data[3];
    u64 received, hits;
    unsigned long flags;
    unsigned int i;
    int rx_fault;
    mutex_lock(&lock);
    read_row(CFG, cfg, 3);
    read_row(CREDIT, credit, 2);
    spin_lock_irqsave(&cpu_lock, flags);
    received = cpu_received; hits = cpu_generation_hits; rx_fault = cpu_fault;
    spin_unlock_irqrestore(&cpu_lock, flags);
    seq_printf(s, "reserved=%u running=%u parked=%u armed=%u sealed=%u terminal=%u collecting=%u frozen=%u failure=%d last=%d\n",
        reserved,running,parked,armed,sealed,terminal,collecting,frozen,failure,last_result);
    seq_printf(s, "queue=193 acl_list=%u byte_limit=%u batch=%u large=%u stage_cells=512 records=1024 head=%08x cells=%u deq=%08x enq=%08x drop=%08x map=%08x port=%08x\n",
        acl_list,byte_limit,batch_cap,large,rd(HEAD),rd(USED)&0xfff,rd(DEQ),rd(ENQ),rd(DROP),
        rd(0x402000+16*Q),rd(0x408000+16*Q));
    seq_printf(s, "cfg=%08x,%08x,%08x credit=%08x,%08x group=%08x,%08x,%08x\n",
        cfg[0],cfg[1],cfg[2],credit[0],credit[1],group_row[0],group_row[1],group_row[2]);
    seq_printf(s, "arrived=%llu retired=%llu pending=%llu backlog=%u backlog_max=%u pending_max=%u cells_max=%u accepted=%llu rejected=%llu accepted_bytes=%llu rejected_bytes=%llu\n",
        arrived,retired,arrived-retired,backlog,backlog_max,pending_max,cells_max,accepted,rejected,accepted_bytes,rejected_bytes);
    seq_printf(s, "selected=%llu completed=%llu sent=%llu disposed=%llu sent_bytes=%llu disposed_bytes=%llu selected_bytes=%llu issued_allowances=%llu grants=%llu in_flight=%u flight_count=%u flight_cpu=%u flight_credit=%u tx_start=%u tx=%u\n",
        selected,completed,sent,disposed,sent_bytes,disposed_bytes,selected_bytes,issued_allowances,grants,in_flight,flight_count,flight_cpu,flight_credit,tx_start,rd(TX));
    seq_printf(s, "length60=%llu length67=%llu length106=%llu length1514=%llu private_l1=%u c_drr=%u e_drr=%u\n",
        length_count[0],length_count[1],length_count[2],length_count[3],private_l1,private_c,private_e);
    seq_printf(s, "cpu_consent=%u cpu_mapping=%u tap_on=%u cpu_received=%llu cpu_generation_hits=%llu cpu_fault=%d cpu_start=%llu cpu_count=%u cpu_samples_limit=%u route=%08x\n",
        cpu_consent,cpu_mapping,tap_on,received,hits,rx_fault,cpu_start,cpu_count,CPU_SAMPLES,edma?readl(edma+ROUTE193):0);
    seq_printf(s, "partial_stops=%llu partial_settlements=%llu partial_completed=%llu frozen_time=%llu reason_cap=%llu reason_tail=%llu reason_change=%llu\n",
        partial_stops,partial_settlements,partial_completed,frozen_time,reason_cap,reason_tail,reason_change);
    seq_printf(s, "visits=%llu visit_ns=%llu max_visit_ns=%llu max_gap_ns=%llu wakes=%llu idle_waits=%llu completion_waits=%llu discovery_calls=%llu discovery_ns=%llu\n",
        visits,visit_ns,max_visit_ns,max_gap_ns,wakes,idle_waits,completion_waits,discovery_calls,discovery_ns);
    seq_printf(s, "worker_reads=%llu worker_writes=%llu metadata_reads=%llu total_reads=%llu total_writes=%llu prepare_calls=%llu prepare_ns=%llu grant_ns=%llu finish_checks=%llu finish_ns=%llu\n",
        worker_reads,worker_writes,metadata_reads,mmio_reads,mmio_writes,prepare_calls,prepare_ns,grant_ns,finish_checks,finish_ns);
    seq_printf(s, "settle_min_ns=%llu settle_sum_ns=%llu settle_max_ns=%llu started=%llu end=%llu stop=%llu issue_time=%llu next_check=%llu\n",
        settle_min_ns==U64_MAX?0:settle_min_ns,settle_sum_ns,settle_max_ns,started,end_time,stop_time,issue_time,next_check);
    seq_printf(s, "mmio_failure=%06x expected=%08x observed=%08x reject_kind=%s reject_offset=%06x reject_value=%08x reject_profile=%d reject_class=%d reject_hash=%d touched_priority=%04x\n",
        fault_offset,fault_expected,fault_observed,reject_kind?reject_kind:"none",reject_offset,reject_value,reject_profile,reject_class,reject_hash,touched_priority);
    for(i=1;i<=16;i++)
        seq_printf(s,"batch%u=%llu\n",i,histogram[i]);
    if (reserved) {
        for(i=0;i<P_ROWS;i++) {
            struct private_row *row=&private_rows[i];
            memset(data,0,sizeof(data));
            read_row(row->off,data,row->words);
            seq_printf(s,"private_row%u off=%06x touched=%u live=%08x,%08x,%08x saved=%08x,%08x,%08x\n",
                i,row->off,row->touched,data[0],data[1],data[2],row->saved[0],row->saved[1],row->saved[2]);
        }
        for(i=0;i<8;i++) {
            read_row(COUNT(8*acl_list+i),data,3);
            seq_printf(s,"acl%u=%08x,%08x,%08x before=%08x,%08x,%08x\n",i,data[0],data[1],data[2],saved_acl[i].count[0],saved_acl[i].count[1],saved_acl[i].count[2]);
        }
        for(i=0;i<6;i++) {
            read_row(0x9e0000+0x60*Q+12*i,data,3);
            seq_printf(s,"drop%u=%08x,%08x,%08x before=%08x,%08x,%08x\n",i,data[0],data[1],data[2],drop_before[i][0],drop_before[i][1],drop_before[i][2]);
        }
    }
    mutex_unlock(&lock);
    return 0;
}
DEFINE_SHOW_ATTRIBUTE(status);

/* Prefix-only finite ledger; continuous aggregate counts remain complete.
 * Admission serials reconstruct A/R against captured source FIFO order. */
static int ledger_show(struct seq_file *s, void *unused)
{
    u64 count, i;
    mutex_lock(&lock);
    count=min_t(u64,arrived,LEDGER);
    seq_printf(s,"retained=%llu arrived=%llu truncated=%u\n",count,arrived,arrived>LEDGER);
    for(i=0;i<count;i++) {
        const struct item *entry=&ledger[i];
        seq_printf(s,"serial=%llu id=%u length=%u accepted=%u backlog_after=%u observed=%llu\n",
            entry->serial,entry->id,entry->length,entry->accepted,entry->backlog_after,entry->observed);
    }
    mutex_unlock(&lock);
    return 0;
}
DEFINE_SHOW_ATTRIBUTE(ledger);

static int returns_show(struct seq_file *s, void *unused)
{
    unsigned long flags;
    u64 count, i;
    spin_lock_irqsave(&cpu_lock,flags);
    count=cpu_received;
    spin_unlock_irqrestore(&cpu_lock,flags);
    for(i=0;i<count;i++) {
        const struct cpu_sample *sample=&cpu_samples[i];
        unsigned int first=min_t(u16,sample->copied,64);
        seq_printf(s,"serial=%llu time=%llu length=%u crc32=%08x prefix=",sample->serial,sample->time,sample->length,sample->crc);
        seq_printf(s,"%*phN",first,sample->data);
        if(sample->copied>first)
            seq_printf(s,"%*phN",sample->copied-first,sample->data+first);
        seq_putc(s,'\n');
    }
    return 0;
}
DEFINE_SHOW_ATTRIBUTE(returns);

static ssize_t control_write(struct file *file, const char __user *buf, size_t len, loff_t *ppos)
{
    char text[96],cmd[24],extra;
    unsigned int a=0;
    int n,err=-EINVAL;
    if(!capable(CAP_SYS_ADMIN)||!allow_writes)
        return -EPERM;
    if(!len||len>=sizeof(text)||copy_from_user(text,buf,len))
        return -EINVAL;
    text[len]=0;
    n=sscanf(text,"%23s %u %c",cmd,&a,&extra);
    if(n<1)
        return -EINVAL;
    mutex_lock(&lock);
    if(!strcmp(cmd,"limit")&&n==2&&!reserved&&!used_once&&a>=60&&a<=65536) {
        byte_limit=a; err=0;
    } else if(!strcmp(cmd,"batch")&&n==2&&!reserved&&!used_once&&(a==1||a==8||a==16)) {
        batch_cap=a; err=0;
    } else if(!strcmp(cmd,"large")&&n==2&&!reserved&&!used_once&&a<=1) {
        large=a; err=0;
    } else if(!strcmp(cmd,"cpu-consent")&&n==2&&!reserved&&!used_once&&a==1) {
        /* Root attests native protocol-ALL exact original-drop guard installed. */
        cpu_consent=true; err=0;
    } else if(!strcmp(cmd,"reserve")&&n==2) {
        err=reserve_probe(a);
    } else if((!strcmp(cmd,"start")||!strcmp(cmd,"collect"))&&n==2&&a>=1&&a<=20&&
              reserved&&!failure&&!worker&&!armed&&!sealed&&touched_rule==255&&
              touched_mask==255&&touched_action==255&&touched_ext==7&&touched_priority==0xffff) {
        collecting=!strcmp(cmd,"collect");
        started=ktime_get_ns(); end_time=started+(u64)a*NSEC_PER_SEC;
        err=write_one(ENQ,saved_enq);
        if(!err)
            err=bind_rule(true);
        if(!err) {
            running=true; parked=false;
            worker=kthread_run(run_probe,NULL,"qdx-fifo-probe");
            if(IS_ERR(worker)) { err=PTR_ERR(worker); worker=NULL; }
        }
        if(err) { running=false; seal_input(); }
    } else if(!strcmp(cmd,"release")&&n==2&&a==1&&reserved&&!failure&&!frozen&&collecting) {
        if(worker&&!running&&!parked) {
            err=-EAGAIN;
        } else {
            collecting=false;
            if(worker&&parked) { kthread_stop(worker); worker=NULL; }
            if(!worker) {
                running=true; parked=false;
                worker=kthread_run(run_probe,NULL,"qdx-fifo-drain");
                if(IS_ERR(worker)) { err=PTR_ERR(worker); worker=NULL; running=false; }
                else err=0;
            } else { wake_up_process(worker); err=0; }
        }
    } else if(!strcmp(cmd,"stop")&&n==2&&a==1&&reserved) {
        stopping=true;
        if(worker&&running) { wake_up_process(worker); err=0; }
        else err=seal_input();
    } else if(!strcmp(cmd,"freeze")&&n==2&&a==1&&reserved&&!frozen) {
        err=freeze_probe();
        if(worker) wake_up_process(worker);
    } else if(!strcmp(cmd,"settle")&&n==2) {
        err=settle_partial(a);
    } else if(!strcmp(cmd,"resume")&&n==2&&a==1&&reserved&&sealed&&frozen&&!in_flight&&
              !READ_ONCE(cpu_fault)&&(!worker||parked)) {
        err=check_ownership(false);
        if(!err) {
            if(worker) { kthread_stop(worker); worker=NULL; }
            frozen=false; collecting=false; running=true; parked=false;
            worker=kthread_run(run_probe,NULL,"qdx-fifo-resume");
            if(IS_ERR(worker)) { err=PTR_ERR(worker); worker=NULL; running=false; frozen=true; }
        }
    } else if(!strcmp(cmd,"complete")&&n==2&&a==1&&reserved&&!running&&sealed&&
              !in_flight&&arrived==retired&&!backlog&&selected==completed&&
              !READ_ONCE(cpu_fault)&&READ_ONCE(cpu_received)==disposed&&
              (rd(HEAD)&1)&&!(rd(USED)&0xfff)&&(!worker||parked)) {
        /* Root attests source end, actual A/R packet identities, native guard,
         * physical terminals and separate staging-drop accounting. */
        err=0;
        if(cpu_mapping) err=map_cpu(false);
        if(!err) terminal=true;
    } else if(!strcmp(cmd,"restore")&&n==1) {
        err=restore_probe();
    }
    last_result=err;
    mutex_unlock(&lock);
    return err?err:len;
}
static const struct file_operations control_fops={.owner=THIS_MODULE,.write=control_write};

static int __init probe_init(void)
{
    struct device_node *np;
    struct resource res;
    int err;
    np=of_find_compatible_node(NULL,NULL,"qualcomm,ipq8074-ppe");
    if(!np) return -ENODEV;
    err=of_address_to_resource(np,0,&res);
    of_node_put(np);
    if(err||res.start!=0x3a000000||resource_size(&res)<0x900000) return -ENODEV;
    ppe=ioremap(res.start,0xa00000);
    if(!ppe) return -ENOMEM;
    np=of_find_compatible_node(NULL,NULL,"qualcomm,ipq8074-edma");
    if(np) {
        err=of_address_to_resource(np,0,&res);
        of_node_put(np);
        if(!err&&res.start==0x3ab00000&&resource_size(&res)>=0x60000)
            edma=ioremap(res.start,resource_size(&res));
    }
    cpu_samples=kvcalloc(CPU_SAMPLES,sizeof(*cpu_samples),GFP_KERNEL);
    if(!cpu_samples) { err=-ENOMEM; goto fail; }
    dir=debugfs_create_dir("qdx_fifo_resident_diag",NULL);
    if(IS_ERR_OR_NULL(dir)) { err=dir?PTR_ERR(dir):-ENOMEM; dir=NULL; goto fail; }
    if(IS_ERR_OR_NULL(debugfs_create_file("status",0400,dir,NULL,&status_fops))||
       IS_ERR_OR_NULL(debugfs_create_file("control",0200,dir,NULL,&control_fops))||
       IS_ERR_OR_NULL(debugfs_create_file("ledger",0400,dir,NULL,&ledger_fops))||
       IS_ERR_OR_NULL(debugfs_create_file("returns",0400,dir,NULL,&returns_fops))) {
        err=-ENOMEM; debugfs_remove_recursive(dir); goto fail;
    }
    return 0;
 fail:
    kvfree(cpu_samples);
    if(edma) iounmap(edma);
    iounmap(ppe);
    return err;
}
static void __exit probe_exit(void)
{
    if(worker) kthread_stop(worker);
    debugfs_remove_recursive(dir);
    kvfree(cpu_samples);
    if(edma) iounmap(edma);
    iounmap(ppe);
}
module_init(probe_init);
module_exit(probe_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Bounded resident native-byte FIFO ready-prefix comparison");
