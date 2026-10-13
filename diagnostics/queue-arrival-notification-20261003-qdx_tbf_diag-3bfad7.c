// SPDX-License-Identifier: GPL-2.0-only
/* Isolated native-time-credit TBF/PFIFO experiment, not a production API.
 * Derived from qualified014/qdx_codel_diag.paced-frozen.c; source diff retained.
 * Same-cell ordinary IPv4 UDP, source3/.144 -> .115:45987 or45988.
 * Default lengths60/67/106B retain the measured fixture; parameters describe
 * other same-cell populations, not arbitrary mixed-cell packet admission.
 * Root freezes other writers. Non-test profile4 priorities map to controlq192.
 * CPU owns actual head credit, PPE owns tail admission/payload/output.
 * Grant->completion observation is measured, not the actual pop timestamp.
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
#include <net/pkt_sched.h>
#include <linux/delay.h>
#include <linux/dsa/oob.h>
#include <linux/rtnetlink.h>
#include <linux/skbuff.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/unaligned.h>
#include <net/net_namespace.h>
#include "qdx_notice_provider.h"

#define Q 193
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
#define COMPLETION_CHECK_NS 250000ULL
#define PREPARE_NS 100000000ULL /* < half-quantum refill; only known held heads */
#define FLIGHT_NS 100000000ULL /* diagnostic hold deadline, far below8.38s credit recovery */

struct acl_row { u32 rule[3], mask[2], action[5], count[3]; };
struct private_row { u32 off, saved[3], expected[3]; u8 words; bool touched; };
enum private_row_id { P_CFG, P_CREDIT, P_MAP, P_PORT, P_LENGTH,
    P_L1C, P_L1E, P_L0C, P_L0E, P_ROWS };
static void __iomem *ppe;
static struct private_row private_rows[P_ROWS];
static unsigned int private_l1, private_c, private_e;
static u32 physical_map, expected_map;
static bool qmap_touched;
static u32 leaf_maps[300], leaf_ports[300], parent_maps[64], parent_ports[64];
static struct dentry *dir;
static DEFINE_MUTEX(lock);
static struct task_struct *worker;
static DECLARE_WAIT_QUEUE_HEAD(stop_wait);
static DECLARE_WAIT_QUEUE_HEAD(notice_wait);
static atomic64_t notice_generation = ATOMIC64_INIT(0);
static atomic64_t notice_bytes = ATOMIC64_INIT(0);
static struct qdx_notice_provider notice_provider;
static struct net_device *notice_dev;
static bool notice_tap_on, idle_event, exact_port_range;
static unsigned int idle_watchdog_us = 100;
static bool event_copy_on, event_actions_valid = true;
static u64 event_seen, event_watchdog_at, event_retry_at;
static u64 empty_episodes, copy_action_writes, notice_wakes, empty_notices;
static u64 publication_retries, watchdog_wakes, watchdog_nonempty, arm_nonempty;
static int notice_fault;
module_param(idle_event, bool, 0400);
module_param(idle_watchdog_us, uint, 0400);
module_param(exact_port_range, bool, 0400);
MODULE_PARM_DESC(idle_event, "Use real NSS COPY hints only while the native TBF head is empty");
MODULE_PARM_DESC(idle_watchdog_us, "Absolute missing-notice HEAD check:100 or1000us; not a batching timer");
MODULE_PARM_DESC(exact_port_range, "Four-slice exact45987..45988 range; default keeps eight slices");
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
static bool used_once, ever_armed, restoring, head_valid, prepared;
static u32 drop_before[6][3], acl_list, last_tx, tx_start;
static u16 head_id, head_length;
static u64 heads, selected, completed, sent, issued, sent_bytes, selected_bytes;
static u64 length_count[3], visits, visit_ns, max_visit_ns, max_gap_ns, previous_visit;
static u64 mmio_reads, mmio_writes, worker_reads, worker_writes, head_reads;
static u64 prepare_calls, prepare_ns, prepared_time, max_prepare_age_ns;
static u64 grant_calls, grant_ns, finish_checks, finish_ns, max_finish_ns;
static u64 settle_sum_ns, settle_max_ns, settle_min_ns = U64_MAX;
static u64 wakes, credit_waits, idle_waits, completion_waits, due_misses, max_due_late_ns;
static u64 started, end_time, issue_time, stop_time, next_ownership_check, next_check, next_due;
static u32 fault_offset, fault_expected, fault_observed;
static int failure, last_result;
static bool reserved, armed, running, stopping, in_flight, sealed, terminal, recovery;
static u64 recovery_runs, recovery_sent, recovery_bytes;
static bool allow_writes;
static unsigned int completion_lead_ns, deadline_spin_ns;
/* Mode0 retains the measured old controller. Mode1 removes only redundant
 * work under the same explicitly exclusive diagnostic writer reservation.
 */
static bool control_fast, mechanical_disabled;
static unsigned int rate_bps = 10000000, burst_bytes = 106;
static unsigned int packet_limit = 128, data_length_a = 67, data_length_b = 106;
static bool accept_handshake = true;
static unsigned int cell_cost, min_length, max_length;
static u64 head_cost, head_peak_cost, min_rate_cost, min_peak_cost;
static u64 data_count[3], topology_checks, audit_reads, audit_ns, audit_max_ns;
module_param(control_fast, bool, 0400);
module_param(rate_bps, uint, 0400);
module_param(burst_bytes, uint, 0400);
module_param(packet_limit, uint, 0400);
module_param(data_length_a, uint, 0400);
module_param(data_length_b, uint, 0400);
module_param(accept_handshake, bool, 0400);
MODULE_PARM_DESC(control_fast, "Exclusive-writer control reduction; default retains old controller");
MODULE_PARM_DESC(accept_handshake, "Accept padded60B handshake only within same-cell geometry");
/* Zero keeps the original finite TBF matcher. Nonzero selects only the
 * autonomous blackhole diagnostic: fixed UDP source port, dynamic destination.
 */
static unsigned int blackhole_sport;
static u64 spins, spin_ns, grant_late_count, grant_late_ns, grant_late_max_ns;
static struct psched_ratecfg rate, peak;
static u64 peak_burst;
static s64 buffer_ns, peak_buffer_ns, tokens, ptokens, credit_time;
module_param(allow_writes, bool, 0400);
module_param(completion_lead_ns, uint, 0400);
module_param(deadline_spin_ns, uint, 0400);
module_param(blackhole_sport, uint, 0400);
MODULE_PARM_DESC(blackhole_sport, "Autonomous blackhole source port; zero keeps TBF diagnostics");

#include "qdx_tbf_handover_diag.h"

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

/* No writes: allocate only real unused rows and audit moved DRR identities. */
static int private_preflight(void)
{
	bool referenced[64] = {}, c_used[36] = {}, e_used[36] = {};
	u32 map, c, e, original_c, original_e, data[3], parent_map;
	unsigned int i, n, cp, ep;
	if (rd(0x400014) != 64 || rd(0x400018) != 8)
		return reject_preflight("shared_slots", 0x400014, rd(0x400014), -EXDEV);
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
	private_rows[P_L0C].expected[0] = original_c;
	private_rows[P_L0E].expected[0] = original_e;
	physical_map = (saved_map & ~0xfffU) | private_l1;
	expected_map = saved_map;
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
        qmap_touched = true;
        expected_map = physical_map;
        err = write_one(0x402000 + 16 * Q, expected_map);
    }
    return err;
}

/* Exact borrowed rows stay frozen. The hardware-owned credits are not frozen. */
static int private_ownership(bool partial)
{
	unsigned int i;
	int err;
	if (rd(0x400010) != 300 || rd(0x400014) != 64 || rd(0x400018) != 8)
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
	return 0;
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
	return err;
}

static int check_ownership_rows(bool partial)
{
	u32 cfg[3], live[3], expected;
	unsigned int i;
	int err;
	err = handover_owned_rows();
	if (err) return err;
	expected = handover.active && handover.map_touched ? handover.expected_map : expected_map;
	err = owned_row(0x402000 + 16 * Q, &expected, &saved_map, 1, partial);
	if (err)
		return err;
	expected = handover.active && handover.port_touched ? handover.expected_port : saved_port;
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
		if (handover.active && (handover.priority_touched & BIT(i)))
			expected |= 1;
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
		expected = i == 0 ? (exact_port_range ? 3 : 15) :
            i == 1 ? (exact_port_range ? 1 : 3) : 0;
		err = owned_row(EXT(i, acl_list), &expected, &saved_ext[i], 1, partial);
		if (err)
			return err;
	}
	return 0;
}

/* Diagnostic audit cost is inclusive elapsed time, not exclusive CPU time.
 * Keep the same instrumentation in both modes; never subtract it from the
 * whole-machine measurement. All callers already serialize with lock.
 */
static int check_ownership(bool partial)
{
    u64 begin = ktime_get_ns(), before_reads = mmio_reads, elapsed;
    int err = check_ownership_rows(partial);

    elapsed = ktime_get_ns() - begin;
    topology_checks++;
    audit_reads += mmio_reads - before_reads;
    audit_ns += elapsed;
    audit_max_ns = max(audit_max_ns, elapsed);
    return err;
}

static int bind_rule(bool enable)
{
	unsigned int i;
	int err;
	for (i = 0; i < 8; i++) {
		if (!(touched_rule & BIT(i)))
			continue;
		/* In source-port mode only compound0..3 matches. Do not count the
		 * same packet through two identical matching compounds.
		 */
		field(rules[i].rule, 61, 8,
		      enable && (!blackhole_sport || i < 4) ? BIT(3) : 0);
		err = write_row(RULE(8 * acl_list + i), rules[i].rule, 3);
		if (err)
			return err;
	}
	armed = enable;
	if (enable)
		ever_armed = true;
	return 0;
}

/* The packet tap owns only its skb reference. Exact eth0 ingress guards
 * own the actual NSS COPY and remain installed after this tap is removed.
 * Native recall/reimport originals are a different producer, never notices.
 * No payload copy, CRC, skb retention, credit debit or grant occurs here.
 */
static int notice_receive(struct sk_buff *skb, struct net_device *dev,
                          struct packet_type *type, struct net_device *original)
{
    u8 bytes[42];
    unsigned int length;
    int offset;
    u16 dport;

    if (!qdx_notice_owns(&notice_provider, skb) || !skb_mac_header_was_set(skb))
        goto done;
    offset = skb_mac_offset(skb);
    if (offset < -(int)skb_headroom(skb) || offset > (int)skb->len)
        goto done;
    length = skb->len - offset;
    if (length < sizeof(bytes) || skb_copy_bits(skb, offset, bytes, sizeof(bytes)))
        goto done;
    dport = get_unaligned_be16(bytes + 36);
    if (get_unaligned_be16(bytes + 12) != ETH_P_IP || bytes[14] != 0x45 ||
        bytes[23] != IPPROTO_UDP || get_unaligned_be32(bytes + 26) != 0xc0a80190 ||
        get_unaligned_be32(bytes + 30) != 0xc0a80173 ||
        (dport != 45987 && dport != 45988))
        goto done;
    if (skb->pkt_type == PACKET_OUTGOING || skb_vlan_tag_present(skb) ||
        length > 1514 || max_t(u32, get_unaligned_be16(bytes + 16) + 14, 60) != length) {
        WRITE_ONCE(notice_fault, -EPROTO);
        wake_up_interruptible(&notice_wait);
        goto done;
    }
    atomic64_add(length, &notice_bytes);
    atomic64_inc(&notice_generation);
    wake_up_interruptible(&notice_wait);
 done:
    consume_skb(skb);
    return NET_RX_SUCCESS;
}
static struct packet_type notice_tap = {
    .type = cpu_to_be16(ETH_P_ALL),
    .func = notice_receive,
};

/* Bind before publishing any COPY action. Failed binding changes no hardware. */
static int notice_subscribe(void)
{
    int err;

    if (!idle_event)
        return 0;
    notice_dev = dev_get_by_name(&init_net, "eth0");
    if (!notice_dev)
        return -ENODEV;
    err = qdx_notice_bind(&notice_provider, notice_dev);
    if (err) {
        dev_put(notice_dev);
        notice_dev = NULL;
        return err;
    }
    notice_tap.dev = notice_dev;
    dev_add_pack(&notice_tap);
    notice_tap_on = true;
    return 0;
}

/* Late COPYs remain guarded even after the recipient has been detached.
 * synchronize_net joins tap callbacks; it is not an NSS/pipeline drain fence.
 */
static void notice_release(void)
{
    if (notice_tap_on) {
        dev_remove_pack(&notice_tap);
        synchronize_net();
        notice_tap_on = false;
    }
    if (notice_provider.service)
        qdx_notice_unbind(&notice_provider);
    if (notice_dev) {
        dev_put(notice_dev);
        notice_dev = NULL;
    }
}

/* COPY changes only the duplicate action, not original destination or QID.
 * A failed readback invalidates the whole action cache. A retry rewrites every
 * owned row rather than skipping the possibly-unpublished expected value.
 */
static int set_idle_copy(bool enable)
{
    bool known = event_actions_valid;
    unsigned int i;
    int err;

    if (!idle_event || (event_actions_valid && event_copy_on == enable))
        return 0;
    event_actions_valid = false;
    for (i = 0; i < ARRAY_SIZE(rules); i++) {
        u32 value;

        if (!(touched_action & BIT(i)))
            continue;
        value = enable ? rules[i].action[0] | BIT(2) :
                         rules[i].action[0] & ~BIT(2);
        if (known && value == rules[i].action[0])
            continue;
        /* Publish the complete action row, as reserve/restore do. A single
         * low-word write did not update COPY on the actual HPPE table. */
        rules[i].action[0] = value;
        copy_action_writes += ARRAY_SIZE(rules[i].action);
        err = write_row(ACTION(8 * acl_list + i), rules[i].action, 5);
        if (err)
            return err;
    }
    event_actions_valid = true;
    event_copy_on = enable;
    if (!enable) {
        event_retry_at = 0;
        event_watchdog_at = 0;
    }
    return 0;
}

/* Called only by the single owner. Closing input is not a pipeline fence. */
static int seal_input(void)
{
	int err = set_idle_copy(false);
	if (!err)
		err = write_one(ENQ, saved_enq | 1);
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

/* Only inspect the actual held head: no admission timestamp or tail walk. */
static int load_head(void)
{
    u32 h, lo, hi, id, len;
    /* No actor can replace this cached head while DEQ is held and no grant
     * is in flight. Recheck actual HEAD/DEQ at the publication boundary.
     */
    if (control_fast && head_valid && !in_flight)
        return 0;
    h = rd(HEAD);
    if (!(rd(DEQ) & 1) || in_flight)
        return -EBUSY;
    if (h & 1)
        return head_valid ? -ESTALE : 0;
    id = (h >> 12) & 0x7ff;
    if (head_valid)
        return id == head_id ? 0 : -ESTALE;
    lo = rd(0x9c0000 + 64 * id);
    hi = rd(0x9c0004 + 64 * id);
    head_reads += 2;
    len = (lo >> 24) | ((hi & 0x3f) << 8);
    if (((lo & 0xfff) != 3 && !(handover_mode && handover.recalled &&
          handover.maps_restored && handover.queued == 2 && (lo & 0xfff) == 0)) ||
        (len != data_length_a && len != data_length_b &&
         !(accept_handshake && len == 60)))
        return -EPROTO;
    if ((rd(HEAD) & 0x7ff001) != (h & 0x7ff001))
        return -ESTALE;
    head_id = id;
    head_length = len;
    head_valid = true;
    if (control_fast) {
        head_cost = psched_l2t_ns(&rate, head_length);
        head_peak_cost = peak.rate_bytes_ps ? psched_l2t_ns(&peak, head_length) : 0;
    }
    heads++;
    return 0;
}

/* Native6.18.44 tbf_dequeue time-credit arithmetic, including its common
 * elapsed cap for the optional peak account. No next-head reordering.
 * commit occurs immediately before publishing one real hardware grant.
 */
static bool fund_head(u64 now, bool commit)
{
    s64 elapsed = min_t(s64, now - credit_time, buffer_ns);
    s64 t = min_t(s64, elapsed + tokens, buffer_ns);
    s64 p = 0, wait;
    t -= control_fast ? head_cost : psched_l2t_ns(&rate, head_length);
    if (peak.rate_bytes_ps) {
        p = min_t(s64, elapsed + ptokens, peak_buffer_ns);
        p -= control_fast ? head_peak_cost : psched_l2t_ns(&peak, head_length);
    }
    if ((t | p) < 0) {
        wait = max_t(s64, -t, -p);
        next_due = now + wait;
        return false;
    }
    if (commit) {
        tokens = t;
        ptokens = p;
        credit_time = now;
        next_due = 0;
    }
    return true;
}

/* Program the mechanical allowance while the real head remains gated.
 * A known pending head never waits here more than100ms before publication:
 * at1raw/8us its half-quantum positive credit remains below one packet.
 */
static int prepare_head(void)
{
    u32 cfg[3] = { 0xfffc0000, 0xfffc0000, 8 };
    u32 credit[2] = { QUANTUM / 2, 0x20400000 };
    u32 h;
    u64 begin = ktime_get_ns();
    int err = 0;

    if (!head_valid || in_flight)
        return -ESTALE;
    if (!control_fast) {
        h = rd(HEAD);
        if ((h & 1) || ((h >> 12) & 0x7ff) != head_id || !(rd(DEQ) & 1))
            return -ESTALE;
    }
    prepared = false;
    /* reserve/finish already disabled this mechanical grant. A cached
     * successful write is valid only while this single owner keeps the row.
     */
    if (!control_fast || !mechanical_disabled) {
        mechanical_disabled = false;
        err = write_row(CFG, cfg, 3);
        if (!err)
            mechanical_disabled = true;
    }
    if (!err)
        err = write_row(CREDIT, credit, 2);
    prepared_time = ktime_get_ns();
    cfg[0] |= 1;
    cfg[2] = 0x38;
    if (!err) {
        mechanical_disabled = false;
        err = write_row(CFG, cfg, 3);
    }
    prepare_calls++;
    prepare_ns += ktime_get_ns() - begin;
    if (!err)
        prepared = true;
    return err;
}

static int grant_head(void)
{
    u32 h;
    s64 wait, p_wait = 0;
    u64 begin = ktime_get_ns();
    int err;

    if (!prepared || begin - prepared_time > PREPARE_NS) {
        err = prepare_head();
        if (err)
            return err;
    }
    h = rd(HEAD);
    if (!head_valid || in_flight || (h & 1) ||
        ((h >> 12) & 0x7ff) != head_id || !(rd(DEQ) & 1))
        return -ESTALE;
    if (!control_fast)
        last_tx = rd(TX);
    issue_time = ktime_get_ns();
    if (issue_time - prepared_time > PREPARE_NS)
        return -ETIMEDOUT; /* retain the held head after a long scheduling gap */
    max_prepare_age_ns = max(max_prepare_age_ns, issue_time - prepared_time);
    if (next_due) {
        u64 late = issue_time > next_due ? issue_time - next_due : 0;
        grant_late_count++;
        grant_late_ns += late;
        grant_late_max_ns = max(grant_late_max_ns, late);
    }
    if (!fund_head(issue_time, true))
        return -EAGAIN; /* impossible with monotone time and the same held head */
    in_flight = true;
    issued++;
    selected++;
    selected_bytes += head_length;
    err = write_one(DEQ, saved_gate & ~1);
    grant_calls++;
    grant_ns += ktime_get_ns() - begin;
    /* Earliest possible next native item uses the configured admitted minimum.
     * No latest-completion or actual next-head cost is inferred from it.
     */
    wait = (s64)(control_fast ? min_rate_cost :
                 psched_l2t_ns(&rate, min_length)) - tokens;
    if (peak.rate_bytes_ps)
        p_wait = (s64)(control_fast ? min_peak_cost :
                      psched_l2t_ns(&peak, min_length)) - ptokens;
    wait = max_t(s64, wait, p_wait);
    /* Observe completion early enough to prepare the next held head. This
     * changes only the wake hint: fund_head still uses actual publication time.
     * Zero preserves the measured original diagnostic for comparison.
     */
    if (completion_lead_ns && wait > 0)
        wait = max_t(s64, COMPLETION_RETRY_NS,
                     min_t(s64, wait, COMPLETION_CHECK_NS) -
                     min_t(unsigned int, completion_lead_ns, 32000));
    next_check = issue_time + (wait > 0 ? min_t(u64, wait, COMPLETION_CHECK_NS) : COMPLETION_RETRY_NS);
    return err;
}

static int finish_head(void)
{
    u32 credit[2], tx, cfg[3] = { 0xfffc0000, 0xfffc0000, 8 };
    u64 begin = ktime_get_ns(), elapsed, observed;
    int err = 0;
    read_row(CREDIT, credit, 2);
    tx = rd(TX);
    observed = ktime_get_ns();
    finish_checks++;
    if ((u32)(tx - last_tx) > 1)
        err = -EOVERFLOW;
    else if ((credit[0] & BIT(30)) && (credit[0] & 0x3fffffff) &&
             (u32)(tx - last_tx) == 1) {
        err = write_one(DEQ, saved_gate | 1);
        if (!err) {
            mechanical_disabled = false;
            err = write_row(CFG, cfg, 3);
            if (!err)
                mechanical_disabled = true;
        }
        if (!err) {
            if (control_fast)
                last_tx = tx;
            elapsed = observed - issue_time;
            settle_sum_ns += elapsed;
            settle_max_ns = max(settle_max_ns, elapsed);
            settle_min_ns = min(settle_min_ns, elapsed);
            completed++;
            sent++;
            sent_bytes += head_length;
            if (recovery) {
                recovery_sent++;
                recovery_bytes += head_length;
            }
            if (head_length == 60 || head_length == 67 || head_length == 106)
                length_count[head_length == 60 ? 0 : head_length == 67 ? 1 : 2]++;
            data_count[accept_handshake && head_length == 60 ? 0 :
                       head_length == data_length_a ? 1 : 2]++;
            in_flight = false;
            head_valid = false;
            prepared = false;
        }
    } else if (observed - issue_time > FLIGHT_NS)
        err = -ETIMEDOUT;
    else
        next_check = observed + COMPLETION_RETRY_NS;
    elapsed = ktime_get_ns() - begin;
    finish_ns += elapsed;
    max_finish_ns = max(max_finish_ns, elapsed);
    return err;
}

static int run_probe(void *unused)
{
    DEFINE_WAIT(wait);
    while (!kthread_should_stop()) {
        u64 begin = ktime_get_ns(), elapsed, wake_at;
        u64 reads, writes, generation = idle_event ? atomic64_read(&notice_generation) : 0;
        bool notified = false, watchdog_due = false, event_waiting = false;
        ktime_t delay;
        int err = 0;
        mutex_lock(&lock);
        reads = mmio_reads;
        writes = mmio_writes;
        if (previous_visit)
            max_gap_ns = max(max_gap_ns, begin - previous_visit);
        previous_visit = begin;
        if (idle_event) {
            notified = generation != event_seen;
            event_seen = generation;
            if (notified)
                notice_wakes++;
            watchdog_due = event_copy_on && begin >= event_watchdog_at;
            if (watchdog_due) {
                watchdog_wakes++;
                event_watchdog_at = begin + (u64)idle_watchdog_us * NSEC_PER_USEC;
            }
            if (event_retry_at && begin >= event_retry_at) {
                publication_retries++;
                event_retry_at = 0;
            }
        }
        if (notice_provider.service &&
            qdx_service_state(notice_provider.service) != QDX_AVAILABLE)
            err = -ESHUTDOWN;
        if (!err && READ_ONCE(notice_fault))
            err = READ_ONCE(notice_fault);
        if (!err && !control_fast && begin >= next_ownership_check) {
            err = check_ownership(false);
            next_ownership_check = begin + 10 * NSEC_PER_MSEC;
        }
        if (!err && !sealed && (stopping || begin >= end_time))
            err = seal_input();
        if (!err && in_flight)
            err = finish_head();
        if (!err && !in_flight)
            err = load_head();
        if (!err && idle_event && !in_flight && !head_valid && !sealed) {
            if (!event_copy_on) {
                /* The later wait compares this pre-publication generation.
                 * A post-arm HEAD read covers arrivals before COPY was active. */
                generation = atomic64_read(&notice_generation);
                event_seen = generation;
                event_watchdog_at = ktime_get_ns() +
                    (u64)idle_watchdog_us * NSEC_PER_USEC;
                empty_episodes++;
                err = set_idle_copy(true);
                if (!err) {
                    err = load_head();
                    if (!err && head_valid)
                        arm_nonempty++;
                }
            }
            if (!err && !head_valid &&
                (notified || atomic64_read(&notice_generation) != generation)) {
                empty_notices++;
                /* One bounded recheck per observed notice. Stale/refused
                 * copies never postpone the absolute missing-notice deadline. */
                if (!event_retry_at)
                    event_retry_at = ktime_get_ns() + COMPLETION_RETRY_NS;
            }
        }
        if (!err && idle_event && !in_flight && head_valid) {
            if (watchdog_due)
                watchdog_nonempty++;
            err = set_idle_copy(false);
        }
        if (!err && !in_flight && head_valid && !prepared)
            err = prepare_head();
        if (!err && !in_flight && head_valid) {
            u64 now = ktime_get_ns();
            bool ready;
            if (next_due && now > next_due) {
                due_misses++;
                max_due_late_ns = max(max_due_late_ns, now - next_due);
            }
            ready = fund_head(now, false);
            if (!ready && deadline_spin_ns) {
                u64 spin_begin = ktime_get_ns();
                u64 bound = min_t(unsigned int, deadline_spin_ns, 16000);
                now = spin_begin;
                if (now < next_due && next_due - now <= bound) {
                    do {
                        cpu_relax();
                        now = ktime_get_ns();
                    } while (now < next_due);
                    spins++;
                    spin_ns += now - spin_begin;
                }
                if (now >= next_due)
                    ready = fund_head(now, false);
            }
            if (ready)
                err = grant_head();
            else
                credit_waits++;
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
        } else if (sealed && !in_flight && !head_valid && (rd(HEAD) & 1)) {
            running = false;
        }
        worker_reads += mmio_reads - reads;
        worker_writes += mmio_writes - writes;
        if (!running) {
            mutex_unlock(&lock);
            goto stopped;
        }
        if (in_flight) {
            wake_at = next_check;
            completion_waits++;
        } else if (head_valid && next_due) {
            u64 lead = min_t(unsigned int, deadline_spin_ns, 16000);
            wake_at = next_due > lead ? next_due - lead : 0;
        } else if (idle_event && event_copy_on) {
            wake_at = event_watchdog_at;
            if (event_retry_at)
                wake_at = min(wake_at, event_retry_at);
            event_waiting = true;
            idle_waits++;
        } else {
            wake_at = ktime_get_ns() + IDLE_NS;
            idle_waits++;
        }
        if (!sealed)
            wake_at = min(wake_at, end_time);
        if (!control_fast)
            wake_at = min(wake_at, next_ownership_check);
        elapsed = ktime_get_ns();
        delay = ns_to_ktime(wake_at > elapsed ? wake_at - elapsed : 1);
        wakes++;
        if (event_waiting)
            prepare_to_wait(&notice_wait, &wait, TASK_INTERRUPTIBLE);
        else
            set_current_state(TASK_INTERRUPTIBLE);
        mutex_unlock(&lock);
        if (!kthread_should_stop() && READ_ONCE(running) &&
            (!READ_ONCE(stopping) || READ_ONCE(sealed)) &&
            (!event_waiting || (atomic64_read(&notice_generation) == generation &&
                                !READ_ONCE(notice_fault))))
            schedule_hrtimeout(&delay, HRTIMER_MODE_REL);
        if (event_waiting)
            finish_wait(&notice_wait, &wait);
        else
            __set_current_state(TASK_RUNNING);
    }
    __set_current_state(TASK_RUNNING);
stopped:
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
	if (!err)
		err = notice_subscribe();
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
	if (!err) {
		mechanical_disabled = false;
		err = write_row(CFG, cfg, 3);
		if (!err)
			mechanical_disabled = true;
	}
	if (!err)
		err = write_row(CREDIT, credit, 2);
	ac[0] = 5 | (saved_ac[0] & 0x30) | ((packet_limit * cell_cost) << 21);
	ac[1] = ac[2] = 0;
	ac[3] = saved_ac[3] & 0xff000000;
	memcpy(ac_expected, ac, sizeof(ac));
	if (!err)
		err = private_install();
	if (!err)
		err = write_row(AC, ac, 4);
	memset(rules, 0, sizeof(rules));
	for (i = 0; i < (exact_port_range ? 4 : 8) && !err; i++) {
		u64 value, mask;
		u32 type, bypass = BIT(0) | BIT(1) | GENMASK(19, 8) | BIT(21) | BIT(22) | BIT(23);
        if ((i & 3) < 2) {
            /* The HPPE range comparator occupies even destination slice0.
             * The default retains both existing independent compounds. */
            bool dest = exact_port_range ? i == 0 : i & 1;
            type = dest ? 4 : 5;
            value = ((u64)(dest ? 0xc0a80173 : 0xc0a80190) << 16) |
                (blackhole_sport ? (dest ? 0 : blackhole_sport) :
                 (dest ? (i < 4 ? 45987 : 45988) : 0)) | BIT_ULL(49) | BIT_ULL(52);
            mask = GENMASK_ULL(52, blackhole_sport ? (dest ? 16 : 0) : (dest ? 0 : 16));
            if (exact_port_range && dest) {
                value |= BIT_ULL(53);
                mask = (mask & ~0xffffULL) | 45988;
            }
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
		ext = j == 0 ? (exact_port_range ? 3 : 15) :
            j == 1 ? (exact_port_range ? 1 : 3) : 0;
		touched_ext |= BIT(j);
		err = write_one(EXT(j, list), ext);
	}
	if (err)
		failure = err;
	tx_start = rd(TX);
	last_tx = tx_start;
	return err;
}

static int restore_probe(void)
{
	u32 cfg[3] = { 0xfffc0000, 0xfffc0000, 8 };
	unsigned int i;
	int err;
	if (!reserved || running || in_flight || !terminal || !(rd(HEAD) & 1) ||
	    (rd(USED) & 0xfff) || selected != completed || head_valid || !sealed ||
        (idle_event && (!event_actions_valid || event_copy_on)))
		return -EBUSY;
	err = check_ownership(!ever_armed || restoring);
	if (!err) {
		restoring = true;
		err = write_one(DEQ, saved_gate | 1);
	}
	if (!err)
		err = set_idle_copy(false);
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
	if (!err) {
		mechanical_disabled = false;
		err = write_row(CFG, saved_cfg, 3);
	}
	if (!err)
		err = write_one(ENQ, saved_enq);
	if (!err)
		err = write_one(DEQ, saved_gate);
	if (!err) {
		if (worker) {
			kthread_stop(worker);
			worker = NULL;
		}
		err = handover_release();
		if (err) return err;
		notice_release();
		reserved = false;
		module_put(THIS_MODULE);
	}
	return err;
}

static int status_show(struct seq_file *s, void *unused)
{
    u32 cfg[3], credit[2], data[3];
    unsigned int i;
    mutex_lock(&lock);
    read_row(CFG, cfg, 3);
    read_row(CREDIT, credit, 2);
    seq_printf(s, "reserved=%u running=%u armed=%u sealed=%u terminal=%u failure=%d last=%d\n",
        reserved, running, armed, sealed, terminal, failure, last_result);
    seq_printf(s, "blackhole_sport=%u worker_present=%u\n", blackhole_sport, worker != NULL);
    seq_printf(s, "queue=193 acl_list=%u head=%08x cells=%u deq=%08x enq=%08x drop=%08x map=%08x port=%08x\n",
        acl_list, rd(HEAD), rd(USED)&0xfff, rd(DEQ), rd(ENQ), rd(DROP),
        rd(0x402000+16*Q), rd(0x408000+16*Q));
    seq_printf(s, "cfg=%08x,%08x,%08x credit=%08x,%08x group=%08x,%08x,%08x\n",
        cfg[0],cfg[1],cfg[2],credit[0],credit[1],group_row[0],group_row[1],group_row[2]);
    seq_printf(s, "rate=%llu burst=%u peak_rate=%llu peak_burst=%llu buffer_ns=%lld peak_buffer_ns=%lld tokens=%lld ptokens=%lld credit_time=%lld next_due=%llu\n",
        rate.rate_bytes_ps,burst_bytes,peak.rate_bytes_ps,peak_burst,buffer_ns,peak_buffer_ns,tokens,ptokens,credit_time,next_due);
    seq_printf(s, "control_fast=%u mechanical_disabled=%u topology_checks=%llu packet_limit=%u cell_cost=%u data_length_a=%u data_length_b=%u accept_handshake=%u min_length=%u max_length=%u length_handshake=%llu length_a=%llu length_b=%llu\n",
        control_fast,mechanical_disabled,topology_checks,packet_limit,cell_cost,data_length_a,data_length_b,accept_handshake,min_length,max_length,data_count[0],data_count[1],data_count[2]);
    seq_printf(s, "heads=%llu selected=%llu completed=%llu sent=%llu issued=%llu selected_bytes=%llu sent_bytes=%llu in_flight=%u head_valid=%u cached_id=%u cached_length=%u tx_start=%u tx=%u\n",
        heads,selected,completed,sent,issued,selected_bytes,sent_bytes,in_flight,head_valid,head_id,head_length,tx_start,rd(TX));
    seq_printf(s, "length60=%llu length67=%llu length106=%llu cached_or_selected=%u private_l1=%u c_drr=%u e_drr=%u\n",
        length_count[0],length_count[1],length_count[2],head_valid,private_l1,private_c,private_e);
    seq_printf(s, "recovery=%u recovery_runs=%llu recovery_sent=%llu recovery_bytes=%llu\n",
        recovery, recovery_runs, recovery_sent, recovery_bytes);
    seq_printf(s, "visits=%llu visit_ns=%llu max_visit_ns=%llu max_gap_ns=%llu wakes=%llu credit_waits=%llu idle_waits=%llu completion_waits=%llu due_misses=%llu max_due_late_ns=%llu\n",
        visits,visit_ns,max_visit_ns,max_gap_ns,wakes,credit_waits,idle_waits,completion_waits,due_misses,max_due_late_ns);
    seq_printf(s, "idle_event=%u idle_watchdog_us=%u exact_port_range=%u notice_tap=%u provider_ids=%u notice_fault=%d notices=%llu notice_bytes=%llu\n",
        idle_event,idle_watchdog_us,exact_port_range,notice_tap_on,notice_provider.count,
        READ_ONCE(notice_fault),(u64)atomic64_read(&notice_generation),(u64)atomic64_read(&notice_bytes));
    seq_printf(s, "event_copy_on=%u event_actions_valid=%u empty_episodes=%llu copy_action_writes=%llu notice_wakes=%llu empty_notices=%llu publication_retries=%llu watchdog_wakes=%llu watchdog_nonempty=%llu arm_nonempty=%llu event_watchdog_at=%llu event_retry_at=%llu\n",
        event_copy_on,event_actions_valid,empty_episodes,copy_action_writes,notice_wakes,
        empty_notices,publication_retries,watchdog_wakes,watchdog_nonempty,arm_nonempty,
        event_watchdog_at,event_retry_at);
    seq_printf(s, "audit_reads=%llu audit_ns=%llu audit_max_ns=%llu\n",
        audit_reads,audit_ns,audit_max_ns);
    seq_printf(s, "worker_reads=%llu worker_writes=%llu head_reads=%llu total_reads=%llu total_writes=%llu grant_calls=%llu grant_ns=%llu finish_checks=%llu finish_ns=%llu max_finish_ns=%llu\n",
        worker_reads,worker_writes,head_reads,mmio_reads,mmio_writes,grant_calls,grant_ns,finish_checks,finish_ns,max_finish_ns);
    seq_printf(s, "completion_lead_ns=%u deadline_spin_ns=%u spins=%llu spin_ns=%llu grant_late_count=%llu grant_late_ns=%llu grant_late_max_ns=%llu\n",
        completion_lead_ns,deadline_spin_ns,spins,spin_ns,grant_late_count,grant_late_ns,grant_late_max_ns);
    seq_printf(s, "prepared=%u prepare_calls=%llu prepare_ns=%llu prepared_time=%llu max_prepare_age_ns=%llu\n",
        prepared, prepare_calls, prepare_ns, prepared_time, max_prepare_age_ns);
    seq_printf(s, "settle_min_ns=%llu settle_sum_ns=%llu settle_max_ns=%llu started=%llu end=%llu stop=%llu issue_time=%llu next_check=%llu\n",
        settle_min_ns == U64_MAX ? 0 : settle_min_ns,settle_sum_ns,settle_max_ns,started,end_time,stop_time,issue_time,next_check);
    seq_printf(s, "mmio_failure=%06x expected=%08x observed=%08x reject_kind=%s reject_offset=%06x reject_value=%08x reject_profile=%d reject_class=%d reject_hash=%d touched_priority=%04x\n",
        fault_offset,fault_expected,fault_observed,reject_kind?reject_kind:"none",reject_offset,reject_value,reject_profile,reject_class,reject_hash,touched_priority);
    if (reserved) {
        for (i=0;i<P_ROWS;i++) {
            struct private_row *row=&private_rows[i];
            memset(data,0,sizeof(data));
            read_row(row->off,data,row->words);
            seq_printf(s,"private_row%u off=%06x touched=%u live=%08x,%08x,%08x saved=%08x,%08x,%08x\n",
                i,row->off,row->touched,data[0],data[1],data[2],row->saved[0],row->saved[1],row->saved[2]);
        }
        for(i=0;i<16;i++)
            seq_printf(s,"control_priority%u live=%08x saved=%08x\n",i,rd(CONTROL_PRIORITY(i)),saved_priority[i]);
        for(i=0;i<8;i++) {
            read_row(COUNT(8*acl_list+i),data,3);
            seq_printf(s,"acl%u=%08x,%08x,%08x before=%08x,%08x,%08x\n",i,data[0],data[1],data[2],saved_acl[i].count[0],saved_acl[i].count[1],saved_acl[i].count[2]);
        }
        for(i=0;i<6;i++) {
            read_row(0x9e0000+0x60*Q+12*i,data,3);
            seq_printf(s,"drop%u=%08x,%08x,%08x before=%08x,%08x,%08x\n",i,data[0],data[1],data[2],drop_before[i][0],drop_before[i][1],drop_before[i][2]);
        }
    }
    handover_status(s);
    mutex_unlock(&lock);
    return 0;
}
DEFINE_SHOW_ATTRIBUTE(status);

/* Explicit retry only after source-finished consent, a stable known queue,
 * intact configuration and real settlement of any earlier grant. No purge,
 * credit reset, forced head-drop or concealed fault success.
 */
static int drain_probe(void)
{
    u32 h, id, tail, lo, hi, len;
    unsigned int n = 0;
    int err;

    if (!reserved || running || !sealed || terminal || blackhole_sport || handover.active)
        return -EBUSY;
    err = check_ownership(false);
    if (!err && in_flight)
        err = finish_head();
    if (err || in_flight)
        return err ? err : -EBUSY;
    h = rd(HEAD);
    id = (h >> 12) & 0x7ff;
    tail = (h >> 1) & 0x7ff;
    while (!(h & 1)) {
        lo = rd(0x9c0000 + 64 * id);
        hi = rd(0x9c0004 + 64 * id);
        len = (lo >> 24) | ((hi & 63) << 8);
        if (++n > packet_limit || (lo & 0xfff) != 3 ||
            (len != data_length_a && len != data_length_b &&
             !(accept_handshake && len == 60)))
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
    recovery_runs++;
    running = true;
    worker = kthread_run(run_probe, NULL, "qdx-tbf-drain");
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
    struct tc_ratespec spec = { .linklayer = TC_LINKLAYER_ETHERNET };
    int n, err = -EINVAL;

    if (!capable(CAP_SYS_ADMIN) || !allow_writes)
        return -EPERM;
    if (!len || len >= sizeof(text) || copy_from_user(text, buf, len))
        return -EINVAL;
    text[len] = 0;
    n = sscanf(text, "%23s %u %u %c", cmd, &a, &b, &extra);
    if (n < 1)
        return -EINVAL;
    mutex_lock(&lock);
    if (!strcmp(cmd, "peak") && n == 3 && !reserved && !used_once &&
        ((a == 0 && b == 0) || (a > rate.rate_bytes_ps &&
          b >= max_length && b <= 1048576))) {
        peak_burst = b;
        memset(&peak, 0, sizeof(peak));
        if (a) {
            spec.rate = a;
            psched_ratecfg_precompute(&peak, &spec, 0);
        }
        peak_buffer_ns = a ? psched_l2t_ns(&peak, b) : 0;
        min_peak_cost = a ? psched_l2t_ns(&peak, min_length) : 0;
        err = 0;
    } else if (!strcmp(cmd, "h-arm") && n == 1) {
        err = handover_prepare();
    } else if (!strcmp(cmd, "h-run") && n == 2 && a == 1) {
        /* a=1 attests that the exact external finite source has ended. */
        err = handover_start(false);
    } else if (!strcmp(cmd, "h-continue") && n == 1) {
        err = handover_start(true);
    } else if (!strcmp(cmd, "h-empty-abort") && n == 2 && a == 1 &&
               handover.active && handover.phase <= 1 && !running &&
               !in_flight && !head_valid && !selected && !handover.returned &&
               !handover.recall_issued && (rd(HEAD) & 1) && !(rd(USED) & 0xfff) &&
               skb_queue_empty(&handover.quarantine)) {
        /* Explicit source-ended/no-original attestation after preparation
         * failed. This is an empty recovery, never a successful H result. */
        err = seal_input();
        if (!err) { handover.empty_abort = true; terminal = true; }
    } else if (!strcmp(cmd, "h-complete") && n == 2 && a == 4 &&
               handover.active && handover.phase == 8 && !handover.error &&
               !handover.bad && !handover.transport_error &&
               !running && !in_flight && !head_valid && sealed &&
               handover.returned == 3 && handover.cpu_done && handover.queued == 2 &&
               selected == 3 && completed == 3 && (rd(HEAD) & 1) &&
               !(rd(USED) & 0xfff) && !handover.priority_touched &&
               !handover.item[1].skb && !handover.item[2].skb && !handover.item[3].skb &&
               skb_queue_empty(&handover.quarantine) &&
               (u32)(rd(TX) - handover.source_tx) == 6) {
        /* Host attests exact four original wire identities/order/checksums,
         * not merely an empty queue or this internal counter relation. */
        handover.complete = true;
        terminal = true;
        err = 0;
    } else if (!strcmp(cmd, "reserve") && n == 2) {
        err = reserve_probe(a);
    } else if (!strcmp(cmd, "blackhole") && n == 2 && a == 1 && blackhole_sport &&
               reserved && !failure && !worker && !running && !ever_armed &&
               !armed && !sealed && touched_rule == 255 && touched_mask == 255 &&
               touched_action == 255 && touched_ext == 7 && touched_priority == 0xffff) {
        /* q193 remains enqueue-closed and dequeue-held for the whole epoch.
         * Only the scoped classifier becomes active. No worker, head read,
         * finite credit grant, timer or per-packet ARM decision is installed.
         * The bounded external actor stops the classifier and retains all
         * counters before attesting complete; MMIO readback is not a fence.
         */
        err = check_ownership(false);
        if (!err && (!(rd(ENQ) & 1) || !(rd(DEQ) & 1) ||
                     (rd(DROP) & 1) || !(rd(HEAD) & 1) || (rd(USED) & 0xfff) ||
                     in_flight || head_valid || issued || selected || completed))
            err = -EBUSY;
        if (!err) {
            started = ktime_get_ns();
            err = bind_rule(true);
        }
        if (err) {
            failure = err;
            seal_input();
        }
    } else if (!strcmp(cmd, "start") && n == 2 && a >= 1 && a <= 120 && reserved &&
               !blackhole_sport && !handover_mode && !failure && !worker && !armed && !sealed &&
               touched_rule == (exact_port_range ? 15 : 255) &&
               touched_mask == (exact_port_range ? 15 : 255) &&
               touched_action == (exact_port_range ? 15 : 255) && touched_ext == 7 &&
               touched_priority == 0xffff) {
        started = ktime_get_ns();
        end_time = started + (u64)a * NSEC_PER_SEC;
        tokens = buffer_ns;
        ptokens = peak_buffer_ns;
        credit_time = started;
        err = check_ownership(false);
        if (!err)
            err = write_one(ENQ, saved_enq);
        if (!err)
            err = bind_rule(true);
        if (!err) {
            running = true;
            worker = kthread_run(run_probe, NULL, "qdx-tbf-probe");
            if (IS_ERR(worker)) {
                err = PTR_ERR(worker);
                worker = NULL;
            }
        }
        if (err) {
            running = false;
            seal_input();
        }
    } else if (!strcmp(cmd, "stop") && n == 2 && a == 1 && reserved && !handover.active) {
        stopping = true;
        if (worker && running) {
            wake_up_process(worker);
            err = 0;
        } else {
            err = seal_input();
        }
    } else if (!strcmp(cmd, "drain") && n == 2 && a == 1) {
        err = drain_probe();
    } else if (!strcmp(cmd, "complete") && n == 2 && a == 1 && reserved && !handover.active && !running &&
               sealed && !in_flight && !head_valid && selected == completed &&
               (rd(HEAD) & 1) && !(rd(USED) & 0xfff)) {
        /* Root attests finite-source termination plus actual terminal ledger. */
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
    struct tc_ratespec spec = { .linklayer = TC_LINKLAYER_ETHERNET };
    int err;

    if (!rate_bps || rate_bps % 8 || !packet_limit ||
        data_length_a < 60 || data_length_a > 1514 ||
        data_length_b < 60 || data_length_b > 1514)
        return -ERANGE;
    cell_cost = DIV_ROUND_UP(data_length_a, 256);
    min_length = min(data_length_a, data_length_b);
    max_length = max(data_length_a, data_length_b);
    /* Packet-count admission is exact only when EVERY selected item uses
     * the same number of PPE cells. A small handshake must not steal only
     * one of a six-cell packet's accounting units.
     */
    if (DIV_ROUND_UP(data_length_b, 256) != cell_cost ||
        (accept_handshake && cell_cost != 1) ||
        packet_limit > 2047 / cell_cost || burst_bytes < max_length ||
        burst_bytes > 1048576)
        return -ERANGE;
    if (accept_handshake)
        min_length = min(min_length, 60U);
    spec.rate = rate_bps / 8;
    if (blackhole_sport > 65535 ||
        (blackhole_sport && (idle_event || exact_port_range)) ||
        (idle_watchdog_us != 100 && idle_watchdog_us != 1000))
        return -ERANGE;
    np = of_find_compatible_node(NULL, NULL, "qualcomm,ipq8074-ppe");
    if (!np)
        return -ENODEV;
    err = of_address_to_resource(np, 0, &res);
    of_node_put(np);
    if (err || res.start != 0x3a000000 || resource_size(&res) < 0x900000)
        return -ENODEV;
    ppe = ioremap(res.start, 0xa00000);
    if (!ppe)
        return -ENOMEM;
    psched_ratecfg_precompute(&rate, &spec, 0);
    buffer_ns = psched_l2t_ns(&rate, burst_bytes);
    min_rate_cost = psched_l2t_ns(&rate, min_length);
    dir = debugfs_create_dir("qdx_tbf_diag", NULL);
    if (IS_ERR_OR_NULL(dir)) {
        err = dir ? PTR_ERR(dir) : -ENOMEM;
        dir = NULL;
        goto fail;
    }
    if (IS_ERR_OR_NULL(debugfs_create_file("status", 0400, dir, NULL, &status_fops)) ||
        IS_ERR_OR_NULL(debugfs_create_file("control", 0200, dir, NULL, &control_fops))) {
        err = -ENOMEM;
        debugfs_remove_recursive(dir);
        goto fail;
    }
    return 0;
fail:
    iounmap(ppe);
    return err;
}

static void __exit probe_exit(void)
{
    if (worker)
        kthread_stop(worker);
    notice_release();
    debugfs_remove_recursive(dir);
    iounmap(ppe);
}
module_init(probe_init);
module_exit(probe_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Bounded PPE resident native-time-credit TBF PFIFO comparison");
