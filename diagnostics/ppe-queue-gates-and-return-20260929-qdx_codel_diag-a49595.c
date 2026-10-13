// SPDX-License-Identifier: GPL-2.0-only
/* Isolated fixed-population experiment, not a production qdisc or API.
 * HPPE: qca-ssdk 446db12b1fd3bca2e61e45cb01c4ad52cfddd95b.
 * CoDel: the build's native Linux6.18.44 codel_impl.h, without modification.
 * Root must stop other configuration writers and verify this queue is unused.
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
static void __iomem *ppe;
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
			return -ESTALE;
	return 0;
}

static int check_ownership(bool partial)
{
	u32 cfg[3], live[3], expected;
	unsigned int i;
	int err;
	if (rd(0x402000 + 16 * Q) != saved_map || rd(0x408000 + 16 * Q) != saved_port)
		return -ESTALE;
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
	int err;
	if ((h & 1) || ((h >> 12) & 0x7ff) != entry->id || !(rd(DEQ) & 1))
		return -ESTALE;
	if (entry->disposition == SEND && !recovery && ip_hdr(entry->proxy)->tos != tos) {
		err = mark_head(entry);
		if (err)
			return err;
	}
	/* Disable while held, write both credits, enable refresh-dependent eligibility. */
	err = write_row(CFG, cfg, 3);
	if (!err)
		err = write_row(CREDIT, credit, 2);
	if (!err)
		err = write_one(DROP, (saved_drop & ~1) | (entry->disposition == DISCARD));
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
	if (!err && entry->disposition == SEND)
		next_send = issue_time + PERIOD_NS; /* no more than one packet accumulated */
	return err;
}

static int finish_head(u64 now)
{
	struct item *entry = &items[completed % LIMIT];
	u32 credit[2], h, tx, cfg[3] = { 0xfffc0000, 0xfffc0000, 8 };
	bool changed;
	int err;
	read_row(CREDIT, credit, 2);
	h = rd(HEAD);
	tx = rd(TX);
	changed = (h & 1) || ((h >> 12) & 0x7ff) != entry->id;
	if ((u32)(tx - last_tx) > (entry->disposition == SEND ? 1 : 0))
		return -EOVERFLOW;
	if ((credit[0] & BIT(30)) && (credit[0] & 0x3fffffff) &&
	    ((entry->disposition == SEND && (u32)(tx - last_tx) == 1) ||
	     (entry->disposition == DISCARD && changed))) {
		err = write_one(DEQ, saved_gate | 1);
		if (!err)
			err = write_row(CFG, cfg, 3);
		if (err)
			return err;
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
		if (begin >= next_ownership_check) {
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
		if (!err && !recovery && !in_flight && completed == selected) {
			struct sk_buff *skb = codel_dequeue(NULL, &backlog, &params, &vars,
				&stats, item_length, item_time, item_drop, item_dequeue);
			if (skb) {
				struct item *entry;
				memcpy(&entry, skb->cb, sizeof(entry));
				entry->disposition = SEND;
			}
		}
		if (!err && !in_flight && completed != selected) {
			struct item *entry = &items[completed % LIMIT];
			if (entry->disposition == DISCARD || recovery || begin >= next_send)
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
		else if (completed != selected && next_send > elapsed)
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
	u32 data[5], parent[3], port_cfg[2], ext, qmap;
	u32 cfg[3] = { 0xfffc0000, 0xfffc0000, 8 };
	u32 credit[2] = { BIT(30) | QUANTUM / 2, 0x20400000 };
	u32 ac[4];
	unsigned int i, j;
	int err;
	if (!allow_writes || reserved || used_once || list >= 64 || (ds != 40 && ds != 42))
		return -EPERM;
	if (!(rd(HEAD) & 1) || (rd(USED) & 0xfff) || (rd(ENQ) & 1) || (rd(DROP) & 1))
		return -EBUSY;
	saved_map = rd(0x402000 + 16 * Q);
	saved_port = rd(0x408000 + 16 * Q);
	read_row(CFG, saved_cfg, 3);
	read_row(0x45e000 + 16 * 48, parent, 3);
	read_row(0x474000 + 16 * 4, port_cfg, 2);
	memcpy(saved_parent, parent, sizeof(parent));
	memcpy(saved_port_cfg, port_cfg, sizeof(port_cfg));
	if ((saved_map & 0x3f) != 48 || (saved_port & 15) != 4 ||
	    (rd(0x446000 + 16 * 48) & 15) != 4 ||
	    (saved_cfg[2] & 0x30) || (parent[2] & 0x30) || (port_cfg[1] & 0x10) ||
	    rd(0x400010) != 300)
		return -EXDEV;
	/* Bounded selector audit. Reject any route, even inactive, naming this queue.
	 * The fixture additionally requires all offset tables zero, so a base cannot
	 * reach it through a hidden hash/priority offset. No selector is rewritten.
	 */
	for (i = 0; i < 3072; i++) {
		qmap = rd(0x810000 + 16 * i);
		if (((qmap >> 4) & 255) == Q)
			return -EADDRINUSE;
	}
	for (i = 0; i < 256; i++)
		if (rd(0x842000 + 16 * i) & 15)
			return -EXDEV;
	for (i = 0; i < 4096; i++)
		if (rd(0x830000 + 16 * i) & 255)
			return -EXDEV;
	for (i = 0; i < 512; i++) {
		read_row(ACTION(i), data, 5);
		if ((data[3] & BIT(21)) && ((data[3] >> 22) & 255) == Q)
			return -EADDRINUSE;
	}
	for (i = 0; i < 8; i++) {
		struct acl_row *a = &saved_acl[i];
		read_row(RULE(8 * list + i), a->rule, 3);
		if (((a->rule[1] >> 27) & 31) || (a->rule[2] & 31))
			return -EBUSY;
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
		return -EXDEV;
	read_row(CREDIT, saved_credit, 2);
	saved_gate = rd(DEQ);
	saved_enq = rd(ENQ);
	saved_drop = rd(DROP);
	for (i = 0; i < 6; i++)
		read_row(0x9e0000 + 0x60 * Q + 12 * i, drop_before[i], 3);
	acl_list = list;
	tos = ds;
	reserved = true;
	used_once = true;
	__module_get(THIS_MODULE);
	err = write_one(DEQ, saved_gate | 1);
	if (!err)
		err = write_one(ENQ, saved_enq | 1);
	if (!err && (!(rd(HEAD) & 1) || (rd(USED) & 0xfff)))
		err = -EBUSY;
	if (!err)
		err = write_row(CFG, cfg, 3);
	if (!err)
		err = write_row(CREDIT, credit, 2);
	ac[0] = 5 | (saved_ac[0] & 0x30) | (LIMIT << 21);
	ac[1] = ac[2] = 0;
	ac[3] = saved_ac[3] & 0xff000000;
	memcpy(ac_expected, ac, sizeof(ac));
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
			value = 53 | (17ULL << 16) | ((u64)tos << 24) | BIT_ULL(49);
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
	if (reserved) {
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
	if (!strcmp(cmd, "reserve") && n == 3) {
		err = reserve_probe(a, b);
	} else if (!strcmp(cmd, "start") && n == 2 && a >= 1 && a <= 20 &&
		   reserved && !failure && !worker && !armed && !sealed &&
		   touched_rule == 15 && touched_mask == 15 && touched_action == 15 && touched_ext == 7) {
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
		   !(rd(USED) & 0xfff)) {
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
	    IS_ERR_OR_NULL(debugfs_create_file("control", 0200, dir, NULL, &control_fops))) {
		err = -ENOMEM;
		debugfs_remove_recursive(dir);
		goto fail;
	}
	return 0;
fail:
	for (i = 0; i < LIMIT; i++)
		kfree_skb(items[i].proxy);
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
	iounmap(ppe);
}
module_init(probe_init);
module_exit(probe_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Bounded fixed-population PPE-resident CoDel CPU comparison");
