// SPDX-License-Identifier: GPL-2.0-only
/* Isolated fixed-population experiment, not a production qdisc or API.
 * HPPE: qca-ssdk 446db12b1fd3bca2e61e45cb01c4ad52cfddd95b.
 * CoDel: the build's native Linux6.18.44 codel_impl.h, without modification.
 * Root must freeze other writers. Native profile4 priorities temporarily map
 * all non-test traffic to q192, matching the native PRIO control band.
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
#include <net/net_namespace.h>
#include <net/pkt_sched.h>
#include <net/codel.h>
#include <net/codel_impl.h>

#define Q 193
#define LIMIT 128
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
#define PERIOD_NS 53600ULL /* fixed67B,10Mbit/s,one-packet bucket */
#define POLL_NS 25000ULL
#define FLIGHT_NS 100000000ULL /* < 8.38s half-quantum refill */

enum disposition { QUEUED, DISCARD, SEND };
struct item {
	struct sk_buff *proxy;
	u64 serial;
	u16 id;
	u8 disposition;
	codel_time_t arrival;
};
struct acl_row { u32 rule[3], mask[2], action[5], count[3]; };
static void __iomem *ppe, *edma;
#define ROUTE193 0x5a060
#define CPU_SAMPLES 16384
/* Saved configuration rows have one owner and explicit partial-write state.
 * Credit is mutable hardware state: checked only at completion, not as config.
 */
enum paced_row_id { P_CFG, P_CREDIT, P_MAP, P_PORT, P_LENGTH,
	P_L1C, P_L1E, P_L0C, P_L0E, P_CPUC, P_CPUE, P_ROWS };
struct paced_row { u32 off, saved[3], expected[3]; u8 words; bool touched; };
static struct paced_row paced_rows[P_ROWS];
static bool paced, cpu_consent, tap_on, cpu_mapping, route_touched, qmap_touched;
static unsigned int private_l1, private_c, private_e, alternate_count;
static unsigned int pacing_refresh = 567; /* 18-bit CIR field, diagnostic range480..640 */
static u32 physical_map, cpu_map, expected_map, expected_port;
static u32 saved_route, expected_route, cpu_parent_cfg[3], cpu_port_cfg[2];
static u32 leaf_maps[300], leaf_ports[300], parent_maps[64], parent_ports[64];
static u16 higher_queues[300];
static unsigned int higher_count;
static u64 priority_waits, forced_drops, cpu_completed;
static struct net_device *tap_dev;
static DEFINE_SPINLOCK(cpu_lock);
static bool cpu_expected;
static u64 cpu_serial, cpu_received, cpu_generation_hits;
static int cpu_fault;
struct cpu_sample { u64 serial, time; u8 data[67]; };
static struct cpu_sample *cpu_samples;
static struct dentry *dir;
static DEFINE_MUTEX(lock);
static struct task_struct *worker;
static DECLARE_WAIT_QUEUE_HEAD(stop_wait);
static struct item items[LIMIT];
static bool ids[2048];
static struct codel_params params;
static struct codel_vars vars;
static struct codel_stats stats;
static struct acl_row saved_acl[8], rules[4];
static u32 saved_ext[3], saved_cfg[3], saved_credit[2], saved_ac[4];
static u32 saved_gate, saved_enq, saved_drop, saved_map, saved_port, group_row[3];
static u32 saved_parent[3], saved_port_cfg[2], ac_expected[4];
static u8 touched_rule, touched_mask, touched_action, touched_ext;
static u32 saved_priority[16];
static u16 touched_priority;
static const char *reject_kind;
static u32 reject_offset, reject_value;
static int reject_profile = -1, reject_class = -1, reject_hash = -256;
static bool used_once, ever_armed, recovery, restoring;
static u64 recovery_sent, recovery_dropped, next_ownership_check;
static u32 drop_before[6][3], acl_list, tos, mtu, backlog, last_tx;
static u64 seen, selected, completed, sent, discarded, issued, marked;
static u64 visits, visit_ns, max_visit_ns, max_gap_ns, previous_scan, next_send;
static u64 started, end_time, issue_time, stop_time;
static u32 last_tail, fault_offset, fault_expected, fault_observed;
static int failure, last_result;
static bool reserved, armed, running, stopping, in_flight, sealed, terminal;
static bool allow_writes;
module_param(allow_writes, bool, 0400);

static u32 rd(u32 off) { return readl(ppe + off); }
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
	for (i = 0; i < words; i++)
		writel(data[i], ppe + off + 4 * i);
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

/* The observer owns only its clone. Root must install the native ingress
 * drop before cpu-consent1; the actual TC drop counter is an external witness.
 * Tuple/generation and raw packet identity are retained for offline comparison.
 */
static int cpu_receive(struct sk_buff *skb, struct net_device *dev,
		       struct packet_type *type, struct net_device *original)
{
	u8 data[67];
	unsigned long flags;
	int offset;
	unsigned int length;
	if (!skb_mac_header_was_set(skb))
		goto done;
	offset = skb_mac_offset(skb);
	if (offset < -(int)skb_headroom(skb) || offset > (int)skb->len)
		goto done;
	length = skb->len - offset;
	if (length < 42 || skb_copy_bits(skb, offset, data, min_t(unsigned int, length, 67)))
		goto done;
	if (get_unaligned_be16(data + 12) != ETH_P_IP || data[14] != 0x45 ||
	    data[23] != IPPROTO_UDP || get_unaligned_be32(data + 26) != 0xc0a80190 ||
	    get_unaligned_be32(data + 30) != 0xc0a80173 ||
	    get_unaligned_be16(data + 34) != 5987 || get_unaligned_be16(data + 36) != 45987 ||
	    get_unaligned_be16(data + 16) != 53)
		goto done;
	spin_lock_irqsave(&cpu_lock, flags);
	if (!cpu_expected || length != 67 || data[15] != tos || skb_vlan_tag_present(skb)) {
		if (!cpu_fault)
			cpu_fault = -EPROTO;
	} else if (++cpu_generation_hits != 1 || cpu_received == CPU_SAMPLES) {
		if (!cpu_fault)
			cpu_fault = -EOVERFLOW;
	} else {
		struct cpu_sample *sample = &cpu_samples[cpu_received++];
		sample->serial = cpu_serial;
		sample->time = ktime_get_ns();
		memcpy(sample->data, data, sizeof(data));
	}
	spin_unlock_irqrestore(&cpu_lock, flags);
 done:
	consume_skb(skb);
	return NET_RX_SUCCESS;
}
static struct packet_type cpu_tap = {
	.type = cpu_to_be16(ETH_P_ALL), .func = cpu_receive,
};

static int paced_write(unsigned int index, const u32 *values)
{
	struct paced_row *row = &paced_rows[index];
	if (values != row->expected)
		memcpy(row->expected, values, row->words * sizeof(u32));
	row->touched = true;
	return write_row(row->off, values, row->words);
}

/* No writes: allocate only real unused rows and audit moved DRR identities. */
static int paced_preflight(void)
{
	bool referenced[64] = {}, c_used[36] = {}, e_used[36] = {};
	u32 map, c, e, original_c, original_e, data[3], parent_map;
	unsigned int i, n, cp, ep;
	higher_count = 0;
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
		if ((leaf_ports[i] & 15) == 4)
			higher_queues[higher_count++] = i;
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
	paced_rows[P_CFG] = (struct paced_row){ .off = 0x45e000 + 16 * private_l1, .words = 3 };
	paced_rows[P_CREDIT] = (struct paced_row){ .off = 0x45c000 + 16 * private_l1, .words = 2 };
	paced_rows[P_MAP] = (struct paced_row){ .off = 0x440000 + 16 * private_l1, .words = 1 };
	paced_rows[P_PORT] = (struct paced_row){ .off = 0x446000 + 16 * private_l1, .words = 1 };
	paced_rows[P_LENGTH] = (struct paced_row){ .off = 0x46a000 + 16 * private_l1, .words = 1 };
	paced_rows[P_L1C] = (struct paced_row){ .off = 0x442000 + 16 * 39, .words = 1 };
	paced_rows[P_L1E] = (struct paced_row){ .off = 0x444000 + 16 * 39, .words = 1 };
	paced_rows[P_L0C] = (struct paced_row){ .off = 0x404000 + 16 * (private_l1 * 8), .words = 1 };
	paced_rows[P_L0E] = (struct paced_row){ .off = 0x406000 + 16 * (private_l1 * 8), .words = 1 };
	paced_rows[P_CPUC] = (struct paced_row){ .off = 0x404070, .words = 1 };
	paced_rows[P_CPUE] = (struct paced_row){ .off = 0x406070, .words = 1 };
	for (i = 0; i < P_ROWS; i++) {
		struct paced_row *row = &paced_rows[i];
		read_row(row->off, row->saved, row->words);
		memcpy(row->expected, row->saved, sizeof(row->saved));
	}
	paced_rows[P_MAP].expected[0] = (parent_map & ~0x3ffU) | 4 | (7 << 4) | (7 << 7);
	paced_rows[P_PORT].expected[0] = (paced_rows[P_PORT].saved[0] & ~15U) | 4;
	paced_rows[P_LENGTH].expected[0] = (paced_rows[P_LENGTH].saved[0] & ~3U) | 1;
	c = rd(0x442000 + 16 * (4 * 8 + ((parent_map >> 4) & 7)));
	e = rd(0x444000 + 16 * (4 * 8 + ((parent_map >> 7) & 7)));
	paced_rows[P_L1C].expected[0] = (c & ~63U) | private_c;
	paced_rows[P_L1E].expected[0] = (e & ~63U) | private_e;
	paced_rows[P_L0C].expected[0] = paced_rows[P_CPUC].expected[0] = original_c;
	paced_rows[P_L0E].expected[0] = paced_rows[P_CPUE].expected[0] = original_e;
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

static int paced_install(void)
{
	u32 cfg[3] = { pacing_refresh, 0, 3 }, credit[2] = { 0, 0x20020000 };
	unsigned int i;
	int err = paced_write(P_CFG, cfg);
	if (!err)
		err = paced_write(P_CREDIT, credit);
	for (i = P_MAP; i < P_ROWS && !err; i++)
		err = paced_write(i, paced_rows[i].expected);
	if (!err) {
		route_touched = true;
		writel(expected_route, edma + ROUTE193);
		if (readl(edma + ROUTE193) != expected_route)
			err = reject_preflight("edma_route_write", 0xb00000 + ROUTE193, readl(edma + ROUTE193), -EIO);
	}
	if (!err) {
		qmap_touched = true;
		expected_map = physical_map;
		err = write_one(0x402000 + 16 * Q, expected_map);
	}
	cfg[2] = 0x33;
	if (!err)
		err = paced_write(P_CFG, cfg);
	if (!err) {
		cpu_tap.dev = tap_dev;
		dev_add_pack(&cpu_tap);
		tap_on = true;
	}
	return err;
}

/* Exact borrowed rows stay frozen. The hardware-owned credits are not frozen. */
static int paced_ownership(bool partial)
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
		struct paced_row *row = &paced_rows[i];
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
 * obligation: finite alternation must qualify it before continuous AQM.
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

/* A fresh lower-band selection must wait for the actual higher-band leaves.
 * No gate or credit of those queues is changed. Later high-priority arrivals
 * may postpone an already prepared head, just as native cached peek can.
 */
static bool higher_ready(void)
{
	unsigned int i, q;
	for (i = 0; i < higher_count; i++) {
		q = higher_queues[i];
		if (!(rd(q < 256 ? 0x86c000 + 16 * q : 0x874000 + 16 * (q - 256)) &
		      (q < 256 ? 1U : 8U))) {
			priority_waits++;
			return false;
		}
	}
	return true;
}

static int paced_restore(void)
{
	u32 cfg[3];
	unsigned int i;
	int err = 0;
	if (paced_rows[P_CFG].touched) {
		memcpy(cfg, paced_rows[P_CFG].expected, sizeof(cfg));
		cfg[2] &= ~0x30U;
		err = paced_write(P_CFG, cfg);
	}
	if (!err && qmap_touched) {
		err = write_one(0x402000 + 16 * Q, saved_map);
		if (!err)
			err = write_one(0x408000 + 16 * Q, saved_port);
	}
	for (i = P_MAP; i < P_ROWS && !err; i++)
		if (paced_rows[i].touched)
			err = write_row(paced_rows[i].off, paced_rows[i].saved, paced_rows[i].words);
	if (!err && paced_rows[P_CREDIT].touched)
		err = write_row(paced_rows[P_CREDIT].off, paced_rows[P_CREDIT].saved, 2);
	if (!err && paced_rows[P_CFG].touched)
		err = write_row(paced_rows[P_CFG].off, paced_rows[P_CFG].saved, 3);
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
	expected = paced ? expected_map : saved_map;
	err = owned_row(0x402000 + 16 * Q, &expected, &saved_map, 1, partial);
	if (err)
		return err;
	expected = paced ? expected_port : saved_port;
	err = owned_row(0x408000 + 16 * Q, &expected, &saved_port, 1, partial);
	if (err)
		return err;
	if (paced) {
		err = paced_ownership(partial);
		if (err)
			return err;
	}
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
	for (i = 0; i < 4; i++) {
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
		expected = i == 0 ? 3 : i == 1 ? 1 : 0;
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
	for (i = 0; i < 4; i++) {
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

static u32 item_length(const struct sk_buff *skb) { return 67; }
static codel_time_t item_time(const struct sk_buff *skb)
{
	struct item *entry;
	memcpy(&entry, skb->cb, sizeof(entry));
	return entry->arrival;
}
static void item_drop(struct sk_buff *skb, void *ctx)
{
	struct item *entry;
	memcpy(&entry, skb->cb, sizeof(entry));
	entry->disposition = DISCARD; /* keep the physical victim until confirmed */
}
static struct sk_buff *item_dequeue(struct codel_vars *v, void *ctx)
{
	struct item *entry;
	if (selected == seen)
		return NULL;
	entry = &items[selected % LIMIT];
	selected++;
	backlog -= 67;
	return entry->proxy;
}

static int discover(void)
{
	u64 now;
	u32 h = rd(HEAD), id, tail, lo, hi, next;
	unsigned int count = 0;
	now = ktime_get_ns(); /* upper timestamp bound after this tail snapshot */
	if (previous_scan && now - previous_scan > max_gap_ns)
		max_gap_ns = now - previous_scan;
	previous_scan = now;
	if (h & 1)
		return seen == completed ? 0 : -ESTALE;
	tail = (h >> 1) & 0x7ff;
	if (seen != completed) {
		if (tail == last_tail)
			return 0;
		id = rd(0x890000 + 16 * last_tail) & 0x7ff;
	} else {
		id = (h >> 12) & 0x7ff;
	}
	for (;;) {
		struct item *entry;
		struct iphdr *ip;
		if (++count > LIMIT || seen - completed >= LIMIT || ids[id])
			return -EOVERFLOW;
		lo = rd(0x9c0000 + 64 * id);
		hi = rd(0x9c0004 + 64 * id);
		next = rd(0x890000 + 16 * id) & 0x7ff;
		if (((lo >> 24) | ((hi & 0x3f) << 8)) != 67)
			return -EPROTO;
		entry = &items[seen % LIMIT];
		entry->id = id;
		entry->serial = seen++;
		entry->arrival = now >> CODEL_SHIFT;
		entry->disposition = QUEUED;
		ip = ip_hdr(entry->proxy);
		ip->tos = tos;
		ip->check = 0;
		ids[id] = true;
		backlog += 67;
		last_tail = id;
		if (id == tail)
			break;
		id = next;
	}
	return 0;
}

/* Only an unissued owned head may be edited. No packet links or payload access. */
static int mark_head(struct item *entry)
{
	u32 before[13], after[13], observed[13], h = rd(HEAD), offset;
	int err;
	if (in_flight || !(rd(DEQ) & 1) || (h & 1) ||
	    ((h >> 12) & 0x7ff) != entry->id)
		return -ESTALE;
	offset = 0x9c0000 + 64 * entry->id;
	read_row(offset, before, 13);
	read_row(offset, observed, 13);
	if (memcmp(before, observed, sizeof(before)) ||
	    (rd(HEAD) & 0x7ff001) != (h & 0x7ff001))
		return -EAGAIN;
	/* Same ordinary IPv4/no pending L3 operation population as qualified1618. */
	if ((before[0] & 0xfff) != 3 || (before[2] & BIT(30)) ||
	    (before[3] & 0x3f) || (before[4] & (BIT(30) | BIT(31))) ||
	    (before[5] & 7) || (before[6] & BIT(28)) ||
	    ((before[8] >> 24) & 3) != 1 || ((before[9] >> 2) & 7) != 2 ||
	    ((before[9] >> 5) & 0xff) != IPPROTO_UDP ||
	    ((before[6] >> 20) & 0xff) != tos)
		return -EPROTONOSUPPORT;
	memcpy(after, before, sizeof(after));
	field(after, 211, 1, 1);
	field(after, 212, 8, tos | 3);
	field(after, 304, 1, 0);
	err = write_row(offset, after, 13);
	if (!err && (rd(HEAD) & 0x7ff001) != (h & 0x7ff001))
		err = -ESTALE;
	if (!err)
		marked++;
	return err;
}

static int grant_head(struct item *entry)
{
	u32 cfg[3] = { 0xfffc0000, 0xfffc0000, 8 };
	u32 credit[2] = { QUANTUM / 2, 0x20400000 };
	u32 h = rd(HEAD);
	unsigned long flags;
	int err;
	if ((h & 1) || ((h >> 12) & 0x7ff) != entry->id || !(rd(DEQ) & 1))
		return -ESTALE;
	if (entry->disposition == SEND && !recovery && ip_hdr(entry->proxy)->tos != tos) {
		err = mark_head(entry);
		if (err)
			return err;
	}
	if (paced && entry->disposition == DISCARD) {
		if (!cpu_consent || !tap_on)
			return -EPERM;
		err = map_cpu(true);
		if (err)
			return err;
		spin_lock_irqsave(&cpu_lock, flags);
		cpu_expected = true;
		cpu_serial = entry->serial;
		cpu_generation_hits = 0;
		spin_unlock_irqrestore(&cpu_lock, flags);
	}
	/* Disable while held, write both credits, enable refresh-dependent eligibility. */
	err = write_row(CFG, cfg, 3);
	if (!err)
		err = write_row(CREDIT, credit, 2);
	if (!err)
		err = write_one(DROP, (saved_drop & ~1) | (!paced && entry->disposition == DISCARD));
	cfg[0] |= 1;
	cfg[2] = 0x38;
	if (!err)
		err = write_row(CFG, cfg, 3);
	if (err)
		return err;
	last_tx = rd(TX);
	issue_time = ktime_get_ns();
	in_flight = true;
	issued++;
	err = write_one(DEQ, saved_gate & ~1);
	if (!err && !paced && entry->disposition == SEND)
		next_send = issue_time + PERIOD_NS; /* no more than one packet accumulated */
	return err;
}

static int finish_head(u64 now)
{
	struct item *entry = &items[completed % LIMIT];
	u32 credit[2], h, tx, cfg[3] = { 0xfffc0000, 0xfffc0000, 8 };
	bool changed, cpu_done = false;
	unsigned long flags;
	int err;
	read_row(CREDIT, credit, 2);
	h = rd(HEAD);
	tx = rd(TX);
	changed = (h & 1) || ((h >> 12) & 0x7ff) != entry->id;
	if (paced) {
		spin_lock_irqsave(&cpu_lock, flags);
		err = cpu_fault;
		cpu_done = cpu_expected && cpu_serial == entry->serial && cpu_generation_hits == 1;
		spin_unlock_irqrestore(&cpu_lock, flags);
		if (err)
			return err;
	}
	if ((u32)(tx - last_tx) > (paced || entry->disposition == SEND ? 1 : 0))
		return -EOVERFLOW;
	/* PTX1 plus exhausted finite credit proves the selected head was released.
	 * A newly appended packet may already reuse its numeric descriptor ID.
	 * Never read that row as the old packet; CPU disposal additionally needs
	 * the actual tuple/generation reception, and its raw ID is audited offline.
	 */
	if ((credit[0] & BIT(30)) && (credit[0] & 0x3fffffff) &&
	    ((entry->disposition == SEND && (u32)(tx - last_tx) == 1) ||
	     (entry->disposition == DISCARD &&
	      (paced ? ((u32)(tx - last_tx) == 1 && cpu_done) : changed)))) {
		err = write_one(DEQ, saved_gate | 1);
		if (!err)
			err = write_row(CFG, cfg, 3);
		if (err)
			return err;
		if (paced && entry->disposition == DISCARD) {
			/* Clear the completed grant before reversing the mapping. If reverse
			 * setup fails, retain the known retired identity and the reservation.
			 */
			in_flight = false;
			err = map_cpu(false);
			if (err) {
				in_flight = true;
				return err;
			}
			spin_lock_irqsave(&cpu_lock, flags);
			cpu_expected = false;
			spin_unlock_irqrestore(&cpu_lock, flags);
			cpu_completed++;
		}
		if (entry->disposition == SEND) {
			sent++;
			if (recovery)
				recovery_sent++;
		} else {
			discarded++;
			if (recovery)
				recovery_dropped++;
		}
		ids[entry->id] = false;
		completed++;
		in_flight = false;
		return 0;
	}
	return now - issue_time > FLIGHT_NS ? -ETIMEDOUT : 0;
}

static int run_probe(void *unused)
{
	while (!kthread_should_stop()) {
		u64 begin = ktime_get_ns(), elapsed;
		ktime_t delay;
		int err = 0;
		mutex_lock(&lock);
		if (paced)
			err = READ_ONCE(cpu_fault);
		if (!err && begin >= next_ownership_check) {
			err = check_ownership(false);
			next_ownership_check = begin + 10 * NSEC_PER_MSEC;
		}
		if (!err && !sealed && (stopping || begin >= end_time))
			err = seal_input();
		if (!err && in_flight)
			err = finish_head(begin);
		if (!err && !in_flight)
			err = discover();
		if (!err && recovery) {
			while (selected != seen) {
				items[selected++ % LIMIT].disposition = SEND;
				backlog -= 67;
			}
		}
		if (!err && !recovery && !in_flight && completed == selected &&
		    (!paced || higher_ready())) {
			struct sk_buff *skb;
			if (alternate_count && selected != seen) {
				if (selected >= alternate_count) {
					err = -EOVERFLOW;
					skb = NULL;
				} else {
					skb = item_dequeue(&vars, NULL);
					if ((selected - 1) & 1) {
						item_drop(skb, NULL);
						forced_drops++;
						skb = NULL;
					}
				}
			} else if (alternate_count) {
				skb = NULL;
			} else {
				skb = codel_dequeue(NULL, &backlog, &params, &vars,
				&stats, item_length, item_time, item_drop, item_dequeue);
			}
			if (skb) {
				struct item *entry;
				memcpy(&entry, skb->cb, sizeof(entry));
				entry->disposition = SEND;
			}
		}
		if (!err && !in_flight && completed != selected) {
			struct item *entry = &items[completed % LIMIT];
			if (paced || entry->disposition == DISCARD || recovery || begin >= next_send)
				err = grant_head(entry);
		}
		visits++;
		elapsed = ktime_get_ns() - begin;
		visit_ns += elapsed;
		max_visit_ns = max(max_visit_ns, elapsed);
		if (err) {
			if (!failure)
				failure = err;
			write_one(DEQ, saved_gate | 1);
			if (!sealed)
				seal_input();
			running = false;
			mutex_unlock(&lock);
			goto stopped;
		}
		if (sealed && !in_flight && completed == seen && (rd(HEAD) & 1)) {
			running = false;
			mutex_unlock(&lock);
			goto stopped;
		}
		delay = ns_to_ktime(POLL_NS);
		elapsed = ktime_get_ns();
		if (in_flight)
			delay = ns_to_ktime(4000);
		else if (!paced && completed != selected && next_send > elapsed)
			delay = ns_to_ktime(min_t(u64, POLL_NS, next_send - elapsed));
		mutex_unlock(&lock);
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_hrtimeout(&delay, HRTIMER_MODE_REL);
	}
	__set_current_state(TASK_RUNNING);
stopped:
	/* Keep task lifetime explicit until restore joins it; no stale task pointer. */
	wait_event_interruptible(stop_wait, kthread_should_stop());
	return 0;
}

static int reserve_probe(unsigned int list, unsigned int ds)
{
	u32 data[5], parent[3], port_cfg[2], ext, value;
	u32 cfg[3] = { 0xfffc0000, 0xfffc0000, 8 };
	u32 credit[2] = { BIT(30) | QUANTUM / 2, 0x20400000 };
	u32 ac[4];
	unsigned int i, j;
	int err;
	if (!allow_writes || reserved || used_once || list >= 64 || (ds != 40 && ds != 42))
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
	if (paced) {
		err = paced_preflight();
		if (err)
			return err;
	}
	acl_list = list;
	tos = ds;
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
	ac[0] = 5 | (saved_ac[0] & 0x30) | (LIMIT << 21);
	ac[1] = ac[2] = 0;
	ac[3] = saved_ac[3] & 0xff000000;
	memcpy(ac_expected, ac, sizeof(ac));
	if (!err && paced)
		err = paced_install();
	if (!err)
		err = write_row(AC, ac, 4);
	memset(rules, 0, sizeof(rules));
	for (i = 0; i < 4 && !err; i++) {
		u64 value, mask;
		u32 type, bypass = BIT(0) | BIT(1) | GENMASK(19, 8) | BIT(21) | BIT(22) | BIT(23);
		if (i < 2) {
			type = i ? 4 : 5;
			value = ((u64)(i ? 0xc0a80173 : 0xc0a80190) << 16) |
				(i ? 45987 : 5987) | BIT_ULL(49) | BIT_ULL(52);
			mask = GENMASK_ULL(52, 0);
		} else if (i == 2) {
			type = 2;
			value = BIT_ULL(36); /* actual untagged encoding1 */
			mask = 7ULL << 36;
		} else {
			type = 12;
			value = 53 | (17ULL << 16) | ((u64)tos << 24);
			mask = U32_MAX | BIT_ULL(48) | BIT_ULL(49);
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
		ext = j == 0 ? 3 : j == 1 ? 1 : 0; /* combine rows0+1,2+3,then0..3 */
		touched_ext |= BIT(j);
		err = write_one(EXT(j, list), ext);
	}
	if (err)
		failure = err;
	return err;
}

static int restore_probe(void)
{
	u32 cfg[3] = { 0xfffc0000, 0xfffc0000, 8 };
	unsigned int i;
	int err;
	if (!reserved || running || in_flight || !terminal || !(rd(HEAD) & 1) ||
	    (rd(USED) & 0xfff) || seen != completed || !sealed)
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
	if (!err && paced)
		err = paced_restore();
	if (!err)
		err = write_row(CREDIT, saved_credit, 2);
	if (!err)
		err = write_row(AC, saved_ac, 4);
	for (i = 0; i < 4 && !err; i++) {
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
	unsigned int i;
	unsigned long flags;
	u64 received, hits;
	int rx_fault;
	mutex_lock(&lock);
	read_row(CFG, cfg, 3);
	read_row(CREDIT, credit, 2);
	seq_printf(s, "reserved=%u running=%u armed=%u sealed=%u terminal=%u failure=%d last=%d\n",
		reserved, running, armed, sealed, terminal, failure, last_result);
	seq_printf(s, "queue=193 acl_list=%u tos=%u mtu=%u head=%08x cells=%u deq=%08x enq=%08x drop=%08x map=%08x port=%08x\n",
		acl_list, tos, mtu, rd(HEAD), rd(USED) & 0xfff, rd(DEQ), rd(ENQ), rd(DROP),
		rd(0x402000 + 16 * Q), rd(0x408000 + 16 * Q));
	seq_printf(s, "cfg=%08x,%08x,%08x credit=%08x,%08x group=%08x,%08x,%08x\n",
		cfg[0], cfg[1], cfg[2], credit[0], credit[1], group_row[0], group_row[1], group_row[2]);
	seq_printf(s, "seen=%llu selected=%llu completed=%llu sent=%llu aqm_drop=%llu issued=%llu marked=%llu backlog=%u in_flight=%u tx=%u\n",
		seen, selected, completed, sent, discarded, issued, marked, backlog, in_flight, rd(TX));
	seq_printf(s, "ecn_mark=%u ce_mark=%u drop_count=%u drop_len=%u count=%u dropping=%u ldelay_us=%u first_above=%u drop_next=%u\n",
		stats.ecn_mark, stats.ce_mark, stats.drop_count, stats.drop_len, vars.count,
		vars.dropping, codel_time_to_us(vars.ldelay), vars.first_above_time, vars.drop_next);
	seq_printf(s, "recovery=%u recovery_sent=%llu recovery_drop=%llu\n", recovery, recovery_sent, recovery_dropped);
	seq_printf(s, "visits=%llu visit_ns=%llu max_visit_ns=%llu max_gap_ns=%llu started=%llu end=%llu stop=%llu\n",
		visits, visit_ns, max_visit_ns, max_gap_ns, started, end_time, stop_time);
	seq_printf(s, "mmio_failure=%06x expected=%08x observed=%08x\n", fault_offset, fault_expected, fault_observed);
	seq_printf(s, "reject_kind=%s reject_offset=%06x reject_value=%08x reject_profile=%d reject_class=%d reject_hash=%d touched_priority=%04x\n",
		reject_kind ? reject_kind : "none", reject_offset, reject_value,
		reject_profile, reject_class, reject_hash, touched_priority);
	spin_lock_irqsave(&cpu_lock, flags);
	received = cpu_received; hits = cpu_generation_hits; rx_fault = cpu_fault;
	spin_unlock_irqrestore(&cpu_lock, flags);
	seq_printf(s, "paced=%u refresh=%u l1_slot=64 unit=256 cap=0 cpu_consent=%u alternate=%u forced_drop=%llu private_l1=%u c_drr=%u e_drr=%u higher_count=%u priority_waits=%llu\n",
		paced, pacing_refresh, cpu_consent, alternate_count, forced_drops, private_l1, private_c, private_e, higher_count, priority_waits);
	seq_printf(s, "cpu_mapping=%u cpu_received=%llu cpu_completed=%llu cpu_generation_hits=%llu cpu_fault=%d route=%08x cached_or_disposal=%llu admission_items=%llu\n",
		cpu_mapping, received, cpu_completed, hits, rx_fault, edma ? readl(edma + ROUTE193) : 0,
		selected - completed, seen - completed);
	if (paced && reserved) {
		for (i = 0; i < P_ROWS; i++) {
			struct paced_row *row = &paced_rows[i];
			memset(data, 0, sizeof(data));
			read_row(row->off, data, row->words);
			seq_printf(s, "paced_row%u off=%06x touched=%u live=%08x,%08x,%08x saved=%08x,%08x,%08x\n",
				i, row->off, row->touched, data[0], data[1], data[2], row->saved[0], row->saved[1], row->saved[2]);
		}
	}
	if (reserved) {
		for (i = 0; i < 16; i++)
			seq_printf(s, "control_priority%u live=%08x saved=%08x\n", i,
				rd(CONTROL_PRIORITY(i)), saved_priority[i]);
		for (i = 0; i < 4; i++) {
			read_row(COUNT(8 * acl_list + i), data, 3);
			seq_printf(s, "acl%u=%08x,%08x,%08x\n", i, data[0], data[1], data[2]);
		}
		for (i = 0; i < 6; i++) {
			read_row(0x9e0000 + 0x60 * Q + 12 * i, data, 3);
			seq_printf(s, "drop%u=%08x,%08x,%08x before=%08x,%08x,%08x\n", i,
				data[0], data[1], data[2], drop_before[i][0], drop_before[i][1], drop_before[i][2]);
		}
	}
	mutex_unlock(&lock);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(status);

/* Immutable samples are printed outside cpu_lock; publication is protected.
 * This separate read-only file keeps the fast status path bounded.
 */
static int returns_show(struct seq_file *s, void *unused)
{
	unsigned long flags;
	u64 count, i;
	spin_lock_irqsave(&cpu_lock, flags);
	count = cpu_received;
	spin_unlock_irqrestore(&cpu_lock, flags);
	for (i = 0; i < count; i++)
		seq_printf(s, "serial=%llu time=%llu frame=%*phN%*phN\n", cpu_samples[i].serial,
			cpu_samples[i].time, 64, cpu_samples[i].data, 3, cpu_samples[i].data + 64);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(returns);

/* Explicit recovery for a failed diagnostic. It never authorizes unknown
 * packets or cancels an unresolved hardware grant. The original failure stays.
 */
static int drain_probe(void)
{
	u32 h, id, tail, raw[13];
	unsigned int n = 0;
	int err;
	if (!reserved || running || !sealed || terminal)
		return -EBUSY;
	err = check_ownership(false);
	if (!err && in_flight)
		err = finish_head(ktime_get_ns());
	if (err || in_flight)
		return err ? err : -EBUSY;
	h = rd(HEAD);
	id = (h >> 12) & 0x7ff;
	tail = (h >> 1) & 0x7ff;
	while (!(h & 1)) {
		read_row(0x9c0000 + 64 * id, raw, 13);
		if (++n > LIMIT || ((raw[0] >> 24) | ((raw[1] & 63) << 8)) != 67 ||
		    (raw[0] & 0xfff) != 3 || (raw[2] & BIT(30)) ||
		    (raw[3] & 63) || (raw[4] & (BIT(30) | BIT(31))) || (raw[5] & 7) ||
		    ((raw[6] >> 20) & 0xfc) != 40 || ((raw[8] >> 24) & 3) != 1 ||
		    ((raw[9] >> 5) & 255) != IPPROTO_UDP)
			return -EPROTO;
		if (id == tail)
			break;
		id = rd(0x890000 + 16 * id) & 0x7ff;
	}
	if (rd(HEAD) != h)
		return -EAGAIN;
	if (worker) {
		kthread_stop(worker);
		worker = NULL;
	}
	recovery = true;
	running = true;
	worker = kthread_run(run_probe, NULL, "qdx-codel-drain");
	if (IS_ERR(worker)) {
		err = PTR_ERR(worker);
		worker = NULL;
		running = false;
		return err;
	}
	return 0;
}

static ssize_t control_write(struct file *file, const char __user *buf, size_t len, loff_t *ppos)
{
	char text[96], cmd[24], extra;
	unsigned int a = 0, b = 0;
	int n, err = -EINVAL;
	if (!capable(CAP_SYS_ADMIN) || !allow_writes)
		return -EPERM;
	if (!len || len >= sizeof(text) || copy_from_user(text, buf, len))
		return -EINVAL;
	text[len] = 0;
	n = sscanf(text, "%23s %u %u %c", cmd, &a, &b, &extra);
	mutex_lock(&lock);
	if (!strcmp(cmd, "paced") && n == 2 && a <= 1 && !reserved && !used_once) {
		paced = a;
		if (!a)
			alternate_count = 0;
		err = 0;
	} else if (!strcmp(cmd, "refresh") && n == 2 && a >= 480 && a <= 640 &&
		   paced && !reserved && !used_once) {
		pacing_refresh = a;
		err = 0;
	} else if (!strcmp(cmd, "cpu-consent") && n == 2 && a == 1 && !reserved && !used_once) {
		/* Operator attests actual native ingress software-drop installation. */
		cpu_consent = true;
		err = 0;
	} else if (!strcmp(cmd, "alternate") && n == 2 && a <= LIMIT && !(a & 1) &&
		   paced && !reserved && !used_once) {
		alternate_count = a;
		err = 0;
	} else if (!strcmp(cmd, "reserve") && n == 3) {
		err = reserve_probe(a, b);
	} else if (!strcmp(cmd, "start") && n == 2 && a >= 1 && a <= 20 &&
		   reserved && !failure && !worker && !armed && !sealed &&
		   touched_rule == 15 && touched_mask == 15 && touched_action == 15 && touched_ext == 7 &&
		   touched_priority == 0xffff) {
		memset(ids, 0, sizeof(ids));
		codel_vars_init(&vars);
		codel_stats_init(&stats);
		started = ktime_get_ns();
		previous_scan = started;
		end_time = started + (u64)a * NSEC_PER_SEC;
		next_send = started;
		err = write_one(ENQ, saved_enq);
		if (!err)
			err = bind_rule(true);
		if (!err) {
			running = true;
			worker = kthread_run(run_probe, NULL, "qdx-codel-probe");
			if (IS_ERR(worker)) {
				err = PTR_ERR(worker);
				worker = NULL;
				running = false;
				seal_input();
			}
		}
	} else if (!strcmp(cmd, "stop") && n == 2 && a == 1 && reserved) {
		stopping = true;
		if (worker && running) {
			wake_up_process(worker);
			err = 0;
		} else {
			err = seal_input();
		}
	} else if (!strcmp(cmd, "drain") && n == 2 && a == 1) {
		err = drain_probe();
	} else if (!strcmp(cmd, "complete") && n == 2 && a == 1 && reserved &&
		   !running && sealed && !in_flight && seen == completed && (rd(HEAD) & 1) &&
		   !(rd(USED) & 0xfff) && (!paced || (!READ_ONCE(cpu_fault) && !cpu_mapping))) {
		/* External finite source finished and every actual output/disposal accounted. */
		terminal = true;
		err = 0;
	} else if (!strcmp(cmd, "restore") && n == 1) {
		err = restore_probe();
	}
	last_result = err;
	mutex_unlock(&lock);
	return err ? err : len;
}
static const struct file_operations control_fops = { .owner = THIS_MODULE, .write = control_write };

static int __init probe_init(void)
{
	struct device_node *np;
	struct resource res;
	struct net_device *dev;
	unsigned int i;
	int err;
	np = of_find_compatible_node(NULL, NULL, "qualcomm,ipq8074-ppe");
	if (!np)
		return -ENODEV;
	err = of_address_to_resource(np, 0, &res);
	of_node_put(np);
	if (err || res.start != 0x3a000000 || resource_size(&res) < 0x900000)
		return -ENODEV;
	/* Actual HPPE QM descriptor/counter tables extend beyond native DT's9MiB. */
	ppe = ioremap(res.start, 0xa00000);
	if (!ppe)
		return -ENOMEM;
	np = of_find_compatible_node(NULL, NULL, "qualcomm,ipq8074-edma");
	if (np) {
		err = of_address_to_resource(np, 0, &res);
		of_node_put(np);
		if (!err && res.start == 0x3ab00000 && resource_size(&res) >= 0x60000)
			edma = ioremap(res.start, resource_size(&res));
	}
	cpu_samples = kvcalloc(CPU_SAMPLES, sizeof(*cpu_samples), GFP_KERNEL);
	if (!cpu_samples) { err = -ENOMEM; goto fail; }
	dev = dev_get_by_name(&init_net, "lan2");
	if (!dev) { err = -ENODEV; goto fail; }
	mtu = psched_mtu(dev);
	dev_put(dev);
	codel_params_init(&params);
	params.ecn = true;
	params.mtu = mtu;
	for (i = 0; i < LIMIT; i++) {
		struct item *entry = &items[i];
		struct iphdr *ip;
		entry->proxy = alloc_skb(64, GFP_KERNEL);
		if (!entry->proxy) { err = -ENOMEM; goto fail; }
		skb_put_zero(entry->proxy, sizeof(*ip));
		skb_reset_network_header(entry->proxy);
		entry->proxy->protocol = htons(ETH_P_IP);
		ip = ip_hdr(entry->proxy);
		ip->version = 4;
		ip->ihl = 5;
		ip->tot_len = htons(53);
		ip->protocol = IPPROTO_UDP;
		memcpy(entry->proxy->cb, &entry, sizeof(entry));
	}
	dir = debugfs_create_dir("qdx_codel_diag", NULL);
	if (IS_ERR_OR_NULL(dir)) { err = dir ? PTR_ERR(dir) : -ENOMEM; dir = NULL; goto fail; }
	if (IS_ERR_OR_NULL(debugfs_create_file("status", 0400, dir, NULL, &status_fops)) ||
	    IS_ERR_OR_NULL(debugfs_create_file("control", 0200, dir, NULL, &control_fops)) ||
	    IS_ERR_OR_NULL(debugfs_create_file("returns", 0400, dir, NULL, &returns_fops))) {
		err = -ENOMEM;
		debugfs_remove_recursive(dir);
		goto fail;
	}
	return 0;
fail:
	for (i = 0; i < LIMIT; i++)
		kfree_skb(items[i].proxy);
	kvfree(cpu_samples);
	if (edma)
		iounmap(edma);
	iounmap(ppe);
	return err;
}
static void __exit probe_exit(void)
{
	if (worker)
		kthread_stop(worker);
	debugfs_remove_recursive(dir);
	for (unsigned int i = 0; i < LIMIT; i++)
		kfree_skb(items[i].proxy);
	kvfree(cpu_samples);
	if (edma)
		iounmap(edma);
	iounmap(ppe);
}
module_init(probe_init);
module_exit(probe_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Bounded fixed-population PPE-resident CoDel CPU comparison");
