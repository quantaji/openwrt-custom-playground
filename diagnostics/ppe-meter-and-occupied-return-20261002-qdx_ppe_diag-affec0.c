// SPDX-License-Identifier: GPL-2.0-only
/* Isolated IPQ8074 HPPE diagnostic. No production driver interface is proposed.
 * Register evidence: qca-ssdk 446db12b1fd3bca2e61e45cb01c4ad52cfddd95b.
 * The operator must isolate the selected physical port and stop other writers.
 */
#include <linux/bitmap.h>
#include <linux/capability.h>
#include <linux/debugfs.h>
#include <linux/hrtimer.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/unaligned.h>
#include <net/net_namespace.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of_address.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>

#define TM 0x400000
#define QM 0x800000
#define PTX 0x020000
#define HEAD(q) (QM + ((q) < 256 ? 0x6c000 + 16 * (q) : \
                      0x74000 + 16 * ((q) - 256)))
#define HEAD_EMPTY(q) ((q) < 256 ? 1U : 8U)
#define PPE_PHYS 0x3a000000
#define PPE_SPAN 0xa00000
#define QUEUES 300
#define L1S 64
#define DIAG_PREFIX_MAX 64
#define L0_MAP(q) (TM + 0x2000 + 16 * (q))
#define L1_MAP(l) (TM + 0x40000 + 16 * (l))
#define L0_PORT(q) (TM + 0x8000 + 16 * (q))
#define L1_PORT(l) (TM + 0x46000 + 16 * (l))
#define DEQ(q) (TM + 0x30000 + 16 * (q))
#define PENDING(q) (QM + ((q) < 256 ? 0x4e000 + 16 * (q) : \
                         0x52000 + 16 * ((q) - 256)))

enum { L0_CFG, L0_CREDIT, L0_LENGTH, L1_CFG, L1_CREDIT, L1_LENGTH,
       PORT_CFG, PORT_CREDIT, PORT_SIGN, PORT_LENGTH, ENQUEUE, DROP, ADMISSION_CFG, ROWS };

struct diag_row {
	const char *name;
	u32 offset, words, mask[4], saved[4];
};

static struct diag_row rows[ROWS] = {
	[L0_CFG] = { "l0_cfg", 0, 3, { U32_MAX, U32_MAX, 0x7f } },
	[L0_CREDIT] = { "l0_credit", 0, 2, { U32_MAX, 0x3fffffff } },
	[L0_LENGTH] = { "l0_length", 0, 1, { 3 } },
	[L1_CFG] = { "l1_cfg", 0, 3, { U32_MAX, U32_MAX, 0x7f } },
	[L1_CREDIT] = { "l1_credit", 0, 2, { U32_MAX, 0x3fffffff } },
	[L1_LENGTH] = { "l1_length", 0, 1, { 3 } },
	[PORT_CFG] = { "port_cfg", 0, 2, { U32_MAX, 0x1f } },
	[PORT_CREDIT] = { "port_credit", 0, 1, { 0x3fffffff } },
	[PORT_SIGN] = { "port_sign", 0, 1, { 1 } },
	[PORT_LENGTH] = { "port_length", 0, 1, { 3 } },
	[ENQUEUE] = { "enqueue", 0, 1, { 1 } },
	[DROP] = { "drop", 0, 1, { 1 } },
	/* Dedicated bounded admission commands only; generic set cannot write it. */
	[ADMISSION_CFG] = { "admission_cfg", 0, 4, { 0 } },
};

static void __iomem *ppe;
static struct dentry *directory;
static DEFINE_MUTEX(diag_lock);
static DEFINE_SPINLOCK(window_lock);
static struct hrtimer close_timer;
static bool allow_writes;
module_param(allow_writes, bool, 0400);
MODULE_PARM_DESC(allow_writes, "Allow explicit reservation and bounded MMIO experiments");
static int port = -1, queue = -1, l1 = -1, window_queue = -1;
static unsigned int prefix_count = 16;
static bool reserved, window_open, fault, drain_active, reservation_opened;
static bool head_edit_recorded, head_edit_valid, head_edit_undone;
static u32 head_edit_id, head_edit_head, head_edit_before[13], head_edit_after[13];
static u64 head_edit_ns;
static u32 l0_map[QUEUES], l1_map[L1S], gate_saved[QUEUES];
static u32 l0_port[QUEUES], l1_port[L1S];
static DECLARE_BITMAP(port_queues, QUEUES);
static u64 opened_ns, closed_ns;
static int last_result;
static unsigned int cost_count;
static u64 cost_ns;
static u32 cost_sum, cost_head_before, cost_head_after, cost_gate_after;
static DEFINE_SPINLOCK(mmio_error_lock);
static bool mmio_failed;
static u32 mmio_failed_offset, mmio_expected, mmio_observed;
static u64 mmio_failed_ns;
static struct {
	bool active, installed, opened, complete, maps_restored;
	bool destination_edited, destination_restored;
	u32 head, descriptor[13], descriptor_expected[13], map_saved, port_saved, map_expected, port_expected;
	u32 c_saved, e_saved, c_expected, e_expected, route_saved, route_expected;
} cpu_remap;
static struct {
	bool active, source_closed, complete, restored;
	u32 prealloc, shared, group, expected[4], group_saved[3], enqueue_expected;
} admission;

struct fixture_acl {
	u32 rule[3], mask[2], action[5], counter[3];
};

/* The existing q192 reservation owns the pin and output gates. These two
 * otherwise inactive lists only classify the finite selected source. */
static struct {
	bool active, armed, endpoint_pair;
	u32 lists[2], ext[2][3];
	struct fixture_acl saved[16], expected[16];
} admission_color;
static int admission_color_check(void);
static int admission_color_restore(void);

static u32 rd(u32 offset)
{
	return readl(ppe + offset);
}

/* Table reads start with word0, as hppe_reg_tbl_get does. Never interleave
 * different entries or depend on C function-argument evaluation order.
 */
static void rd_row(u32 offset, u32 *values, unsigned int words)
{
	unsigned int i;

	for (i = 0; i < words; i++)
		values[i] = rd(offset + 4 * i);
}

/* Preserve the first mismatch until the next reservation. Timer failures use
 * the same record; later cleanup must not replace the original evidence.
 */
static int mmio_error(u32 offset, u32 expected, u32 observed)
{
	unsigned long flags;
	bool first;

	spin_lock_irqsave(&mmio_error_lock, flags);
	first = !mmio_failed;
	if (first) {
		mmio_failed_offset = offset;
		mmio_expected = expected;
		mmio_observed = observed;
		mmio_failed_ns = ktime_get_ns();
		smp_store_release(&mmio_failed, true);
	}
	spin_unlock_irqrestore(&mmio_error_lock, flags);
	if (first)
		pr_err("qdx_ppe_diag: MMIO off=%06x expected=%08x observed=%08x\n",
		       offset, expected, observed);
	return -EIO;
}

/* Call only for allowlisted offsets. A readback is not a pipeline drain fence. */
static int wr(u32 offset, u32 value)
{
	u32 observed;

	writel(value, ppe + offset);
	observed = rd(offset);
	return observed == value ? 0 : mmio_error(offset, value, observed);
}

/* HPPE latches whole entries: finish all words before any readback. */
static int wr_row(u32 offset, const u32 *values, unsigned int words)
{
	unsigned int i;
	int err = 0;

	for (i = 0; i < words; i++)
		writel(values[i], ppe + offset + 4 * i);
	for (i = 0; i < words; i++) {
		u32 observed = rd(offset + 4 * i);

		if (observed != values[i])
			err = mmio_error(offset + 4 * i, values[i], observed);
	}
	return err;
}

/* After the chosen leaf is held, return cleanup drain to a stopped finite
 * actuator. An already selected frame still requires external packet evidence.
 */
static int finish_drain(void)
{
	u32 config[2] = { 0xfffc0000, 0x18 };
	int err;

	if (!drain_active)
		return 0;
	err = wr(rows[PORT_CREDIT].offset, 1);
	if (!err)
		err = wr(rows[PORT_SIGN].offset, 1);
	if (!err)
		err = wr_row(rows[PORT_CFG].offset, config, 2);
	if (!err)
		drain_active = false;
	return err;
}

static int close_window(void)
{
	unsigned long flags;
	int err = 0;

	hrtimer_cancel(&close_timer);
	spin_lock_irqsave(&window_lock, flags);
	if (reserved) {
		err = wr(DEQ(window_queue), gate_saved[window_queue] | 1);
		if (!err)
			err = finish_drain();
		closed_ns = ktime_get_ns();
		if (err)
			fault = true;
	}
	window_open = false;
	spin_unlock_irqrestore(&window_lock, flags);
	return err;
}

static enum hrtimer_restart close_expired(struct hrtimer *timer)
{
	unsigned long flags;

	spin_lock_irqsave(&window_lock, flags);
	if (wr(DEQ(window_queue), gate_saved[window_queue] | 1) || finish_drain())
		fault = true;
	closed_ns = ktime_get_ns();
	window_open = false;
	spin_unlock_irqrestore(&window_lock, flags);
	return HRTIMER_NORESTART;
}

/* Reject a concurrent driver/FW scheduler remap; there is no shared native lock. */
static int check_maps(void)
{
	u32 observed[4];
	unsigned int i;

	for (i = 0; i < QUEUES; i++) {
		u32 map = l0_map[i], destination = l0_port[i];

		if (cpu_remap.active && !cpu_remap.maps_restored && i == 192) {
			map = cpu_remap.map_expected;
			destination = cpu_remap.port_expected;
		}
		if (rd(L0_MAP(i)) != map || rd(L0_PORT(i)) != destination)
			return -ESTALE;
	}
	for (i = 0; i < L1S; i++)
		if (rd(L1_MAP(i)) != l1_map[i] || rd(L1_PORT(i)) != l1_port[i])
			return -ESTALE;
	if (admission.active) {
		rd_row(rows[ADMISSION_CFG].offset, observed, 4);
		if (memcmp(observed, admission.expected, sizeof(admission.expected)))
			return -ESTALE;
		rd_row(QM + 0x4c000 + 16 * admission.group, observed, 3);
		if (memcmp(observed, admission.group_saved, sizeof(admission.group_saved)) ||
		    rd(rows[ENQUEUE].offset) != admission.enqueue_expected)
			return -ESTALE;
	}
	return admission_color.active ? admission_color_check() : 0;
}

static int select_path(unsigned int p, unsigned int q, unsigned int s)
{
	if (reserved)
		return -EBUSY;
	/* CPU0 and virtual ports remain excluded. Port7 is an explicit fixture. */
	if (p < 1 || p > 7 || q >= 256 || s >= L1S)
		return -ERANGE;
	if ((rd(L0_MAP(q)) & 0x3f) != s || (rd(L1_MAP(s)) & 0xf) != p ||
	    (rd(L0_PORT(q)) & 0xf) != p || (rd(L1_PORT(s)) & 0xf) != p)
		return -EXDEV;
	port = p;
	queue = q;
	window_queue = q;
	l1 = s;
	rows[L0_CFG].offset = TM + 0x1c000 + 16 * q;
	rows[L0_CREDIT].offset = TM + 0x1a000 + 16 * q;
	rows[L0_LENGTH].offset = TM + 0x28000 + 16 * q;
	rows[L1_CFG].offset = TM + 0x5e000 + 16 * s;
	rows[L1_CREDIT].offset = TM + 0x5c000 + 16 * s;
	rows[L1_LENGTH].offset = TM + 0x6a000 + 16 * s;
	rows[PORT_CFG].offset = TM + 0x74000 + 16 * p;
	rows[PORT_CREDIT].offset = TM + 0x72000 + 16 * p;
	rows[PORT_SIGN].offset = TM + 0x70000 + 16 * p;
	rows[PORT_LENGTH].offset = TM + 0x78000 + 16 * p;
	rows[ENQUEUE].offset = QM + 0x5c000 + 16 * q;
	rows[DROP].offset = QM + 0x64000 + 16 * q;
	rows[ADMISSION_CFG].offset = QM + 0x48000 + 16 * q;
	fault = false;
	return 0;
}

/* Freeze refresh under closed gates; restore uses the saved caps/unit/enables. */
static int freeze_refresh(bool original)
{
	const unsigned int configs[] = { L0_CFG, L1_CFG, PORT_CFG };
	u32 values[3];
	unsigned int i, j, n;
	int err;

	for (i = 0; i < ARRAY_SIZE(configs); i++) {
		n = configs[i];
		for (j = 0; j < rows[n].words; j++)
			values[j] = original ? rows[n].saved[j] : rd(rows[n].offset + 4 * j);
		values[0] &= ~0x3ffff;
		if (n != PORT_CFG)
			values[1] &= ~0x3ffff;
		err = wr_row(rows[n].offset, values, rows[n].words);
		if (err)
			return err;
	}
	return 0;
}

static int reserve_path(void)
{
	unsigned int i, j;
	int err;

	if (!allow_writes)
		return -EPERM;
	if (reserved || queue < 0)
		return -EINVAL;
	mmio_failed = false;
	bitmap_zero(port_queues, QUEUES);
	for (i = 0; i < L1S; i++) {
		l1_map[i] = rd(L1_MAP(i));
		l1_port[i] = rd(L1_PORT(i));
	}
	for (i = 0; i < QUEUES; i++) {
		l0_map[i] = rd(L0_MAP(i));
		l0_port[i] = rd(L0_PORT(i));
		if ((l0_port[i] & 0xf) != port)
			continue;
		__set_bit(i, port_queues);
		gate_saved[i] = rd(DEQ(i));
		/* Start from an idle test port; later fill/gate tests are separate. */
		if (rd(PENDING(i)) & (i < 256 ? 0xfff : 0x1fff))
			return -EBUSY;
	}
	if (!test_bit(queue, port_queues) || (l0_map[queue] & 0x3f) != l1 ||
	    (l1_port[l1] & 0xf) != port || (l1_map[l1] & 0xf) != port)
		return -EXDEV;
	for (i = 0; i < ROWS; i++)
		for (j = 0; j < rows[i].words; j++)
			rows[i].saved[j] = rd(rows[i].offset + 4 * j);
	/* A failed restoration must not permit unload to discard the saved rows. */
	__module_get(THIS_MODULE);
	reserved = true;
	reservation_opened = false;
	head_edit_valid = false;
	for_each_set_bit(i, port_queues, QUEUES) {
		err = wr(DEQ(i), gate_saved[i] | 1);
		if (err)
			goto fail;
	}
	err = check_maps();
	if (err)
		goto fail;
	err = freeze_refresh(false);
	if (err)
		goto fail;
	/* Capture credit after refresh freeze, while the externally idle port is held.
	 * This is the saved credit epoch; elapsed test time is not added on restore.
	 */
	for (i = 0; i < ROWS; i++) {
		if (i != L0_CREDIT && i != L1_CREDIT &&
		    i != PORT_CREDIT && i != PORT_SIGN)
			continue;
		for (j = 0; j < rows[i].words; j++)
			rows[i].saved[j] = rd(rows[i].offset + 4 * j);
	}
	return 0;
fail:
	fault = true;
	for_each_set_bit(i, port_queues, QUEUES)
		wr(DEQ(i), gate_saved[i] | 1);
	return err;
}

static int restore_path(void)
{
	unsigned int i;
	int err;

	if (!reserved)
		return -EINVAL;
	/* Never publish an ungranted trial edit merely by reopening saved gates.
	 * Undo on the same held head first; after a real grant no stale-ID write.
	 */
	if (head_edit_valid && !reservation_opened)
		return -EBUSY;
	err = close_window();
	if (err)
		return err;
	for_each_set_bit(i, port_queues, QUEUES) {
		err = wr(DEQ(i), gate_saved[i] | 1);
		if (err)
			goto fail;
	}
	err = check_maps();
	if (err)
		goto fail;
	if (admission.active && !admission.restored) {
		/* Zero occupancy is not terminal evidence: the operator must close
		 * the finite source and account every emitted or dropped probe.
		 */
		if (!admission.source_closed || !admission.complete ||
		    !(rd(HEAD(queue)) & 1) || (rd(PENDING(queue)) & 0xfff))
			return -EBUSY;
		if (admission_color.active) {
			err = admission_color_restore();
			if (err)
				goto fail;
		}
		err = wr_row(rows[ADMISSION_CFG].offset, rows[ADMISSION_CFG].saved, 4);
		if (err)
			goto fail;
		memcpy(admission.expected, rows[ADMISSION_CFG].saved, sizeof(admission.expected));
		admission.restored = true;
	}
	err = freeze_refresh(true);
	if (err)
		goto fail;
	/* Credits and sign are checked before the original refresh is resumed. */
	for (i = 0; i < ROWS; i++) {
		if (i == L0_CFG || i == L1_CFG || i == PORT_CFG || i == ADMISSION_CFG)
			continue;
		err = wr_row(rows[i].offset, rows[i].saved, rows[i].words);
		if (err)
			goto fail;
		if (admission.active && i == ENQUEUE)
			admission.enqueue_expected = rows[ENQUEUE].saved[0];
	}
	for (i = 0; i < ROWS; i++) {
		if (i != L0_CFG && i != L1_CFG && i != PORT_CFG)
			continue;
		err = wr_row(rows[i].offset, rows[i].saved, rows[i].words);
		if (err)
			goto fail;
	}
	for_each_set_bit(i, port_queues, QUEUES) {
		err = wr(DEQ(i), gate_saved[i]);
		if (err)
			goto fail;
	}
	reserved = false;
	admission.active = false;
	fault = false;
	module_put(THIS_MODULE);
	return 0;
fail:
	fault = true;
	/* Re-hold every reserved leaf if partial restore or gate release failed. */
	for_each_set_bit(i, port_queues, QUEUES)
		wr(DEQ(i), gate_saved[i] | 1);
	return err;
}

static int set_row(const char *name, u32 *values, unsigned int count)
{
	unsigned int i, j, cfg;
	u32 row[4];
	int err;

	if (!reserved || fault)
		return -EPERM;
	err = close_window();
	if (err)
		return err;
	err = check_maps();
	if (err)
		goto fail;
	for_each_set_bit(i, port_queues, QUEUES)
		if (!(rd(DEQ(i)) & 1)) {
			err = -EBUSY;
			goto fail;
		}
	for (i = 0; i < ROWS; i++)
		if (!strcmp(name, rows[i].name))
			break;
	if (i == ROWS || count != rows[i].words)
		return -EINVAL;
	if (i == ADMISSION_CFG || (admission.active && i == ENQUEUE))
		return -EPERM;
	for (j = 0; j < count; j++)
		if (values[j] & ~rows[i].mask[j])
			return -ERANGE;
	if (i == L0_CREDIT || i == L1_CREDIT ||
	    i == PORT_CREDIT || i == PORT_SIGN) {
		cfg = i == L0_CREDIT ? L0_CFG : i == L1_CREDIT ? L1_CFG : PORT_CFG;
		if ((rd(rows[cfg].offset) & 0x3ffff) ||
		    (cfg != PORT_CFG && (rd(rows[cfg].offset + 4) & 0x3ffff)))
			return -EBUSY;
	}
	for (j = 0; j < count; j++) {
		u32 old = rd(rows[i].offset + 4 * j);

		row[j] = (old & ~rows[i].mask[j]) | values[j];
	}
	err = wr_row(rows[i].offset, row, count);
	if (err)
		goto fail;
	return 0;
fail:
	fault = true;
	return err;
}

static int open_window_on(unsigned int q, unsigned int usec, bool drain)
{
	unsigned long flags;
	unsigned int i;
	int err;

	if (!reserved || fault || usec < 1 ||
	    usec > (admission_color.active && !drain ? 60000000 : 1000000) ||
	    q >= QUEUES || !test_bit(q, port_queues))
		return -EINVAL;
	err = close_window();
	if (err)
		return err;
	err = check_maps();
	if (err)
		return err;
	for_each_set_bit(i, port_queues, QUEUES)
		if (!(rd(DEQ(i)) & 1))
			return -EBUSY;
	spin_lock_irqsave(&window_lock, flags);
	window_queue = q;
	drain_active = drain;
	opened_ns = ktime_get_ns();
	reservation_opened = true;
	err = wr(DEQ(q), gate_saved[q] & ~1);
	if (!err) {
		window_open = true;
		hrtimer_start(&close_timer, ns_to_ktime((u64)usec * 1000), HRTIMER_MODE_REL);
	} else {
		fault = true;
		wr(DEQ(q), gate_saved[q] | 1);
	}
	spin_unlock_irqrestore(&window_lock, flags);
	return err;
}

/* Three MMIO reads per iteration: two packet-length words and one next ID.
 * Wall time includes interrupts/preemption. It is not a CPU-cycle benchmark.
 */
static int measure_cost(unsigned int count)
{
	u32 id, first, tail, lo, hi, next, sum = 0;
	unsigned int i;
	u64 start;

	if (!reserved || fault || !count || count > 10000)
		return -EINVAL;
	if (!(rd(DEQ(queue)) & 1))
		return -EBUSY;
	cost_head_before = rd(QM + 0x6c000 + 16 * queue);
	if (cost_head_before & 1)
		return -ENODATA;
	first = (cost_head_before >> 12) & 0x7ff;
	tail = (cost_head_before >> 1) & 0x7ff;
	id = first;
	start = ktime_get_ns();
	for (i = 0; i < count; i++) {
		lo = rd(QM + 0x1c0000 + 64 * id);
		hi = rd(QM + 0x1c0000 + 64 * id + 4);
		next = rd(QM + 0x90000 + 16 * id) & 0x7ff;
		sum += (lo >> 24) | ((hi & 0x3f) << 8);
		id = id == tail ? first : next;
	}
	cost_ns = ktime_get_ns() - start;
	cost_count = count;
	cost_sum = sum;
	cost_head_after = rd(QM + 0x6c000 + 16 * queue);
	cost_gate_after = rd(DEQ(queue));
	return cost_head_before == cost_head_after && (cost_gate_after & 1) ? 0 : -EAGAIN;
}

/* The fixture owns only two complete inactive ACL lists and the named idle
 * queues. External configuration must remain stopped; this is not an allocator.
 */
#define IPO 0x0b0000
#define ACL_RULE(i) (IPO + 16 * (i))
#define ACL_MASK(i) (IPO + 0x2000 + 16 * (i))
/* ACL actions are in IPE_L2; hit counters are in ingress policer.
 * hppe_acl.c accessors use different banks from rule/mask/extension rows.
 */
#define ACL_ACTION(i) (0x068000 + 32 * (i))
#define ACL_COUNT(i) (0x174000 + 16 * (i))
#define ACL_EXT(k, i) (IPO + 0x4000 + 0x100 * (k) + 4 * (i))
#define METER_CFG(i) (0x104000 + 16 * (i))
#define METER_CREDIT(i) (0x108000 + 16 * (i))
#define METER_COUNT(i, c) (0x110000 + 16 * (3 * (i) + (c)))
#define EDMA_ROUTE(q) (0x5a000 + 4 * ((q) / 8))
#define BRIDGE_CTRL(p) (0x60300 + 4 * (p))
/* IPQ8074 has two-word MRU/MTU rows, unlike the IPQ6018 stride. */
#define MRU_MTU(p) (0x63000 + 8 * (p))
#define FIX_SAMPLES 64
#define FIX_BYTES 128

struct fixture_sample {
	u64 time;
	u32 length, copied;
	u16 vlan_proto, vlan_tci;
	bool vlan_present;
	u8 inline_tags;
	u8 data[FIX_BYTES];
};

static struct {
	bool configured, active, armed, tap_on, meter_on, inventory, installed, restoring;
	bool relay_opened, relay_complete;
	u32 sip, dip, sport, dport, tos, vida, vidb;
	u32 lists[2], cpuq, meter, mode, cpu_gate, cpu_route, second_drop;
	u32 untag, tagged, tagmask, status, match_tos, direct, relay;
	u32 bridge7_saved, bridge7_expected, relay_route, relay_gate, relay_mru[2];
	u32 service1_saved[5], service1_expected[5];
	u32 return_post, return_tagmask, return_vidmask, return_sources;
	u32 ext[2][3], meter_cfg[4], meter_credit[2], meter_count[3][3];
	struct fixture_acl saved[16], expected[16];
	struct net_device *dev;
	u64 received;
	struct fixture_sample samples[FIX_SAMPLES];
} fixture;
static DEFINE_SPINLOCK(tap_lock);
static void __iomem *edma;

/* Register fields are at most32 bits; never shifts a32-bit value by32. */
static void put_field(u32 *row, unsigned int bit, unsigned int width, u32 value)
{
	unsigned int i;

	for (i = 0; i < width; i++) {
		u32 mask = BIT((bit + i) % 32);
		u32 *word = &row[(bit + i) / 32];

		*word = (*word & ~mask) | ((value & BIT(i)) ? mask : 0);
	}
}

/* Only an ordinary, externally finished TOS42 UDP probe may use this command.
 * The port was idle when reserved and no dequeue gate has opened since then.
 * This is a diagnostic test of late metadata consumption, not a production
 * ownership claim. No packet link, length, buffer identity or reference changes.
 */
static int head_ce(unsigned int id, bool undo)
{
	u32 observed[13], repeat[13], next[13], config[2], head, offset;
	unsigned int i;
	int err;

	if (!allow_writes || !reserved || fault || fixture.active ||
	    port != 4 || queue != 192 || l1 != 48 || id >= 2048 ||
	    reservation_opened || window_open || drain_active)
		return -EPERM;
	err = check_maps();
	if (err)
		return err;
	for_each_set_bit(i, port_queues, QUEUES)
		if (!(rd(DEQ(i)) & 1))
			return -EBUSY;
	rd_row(rows[PORT_CFG].offset, config, 2);
	if ((config[0] & 0x3ffff) || (config[1] & 0x1f) != 0x18 ||
	    !(rd(rows[PORT_SIGN].offset) & 1) ||
	    !(rd(rows[PORT_CREDIT].offset) & 0x3fffffff))
		return -EBUSY;
	head = rd(QM + 0x6c000 + 16 * queue);
	if ((head & 1) || ((head >> 12) & 0x7ff) != id)
		return -ESTALE;
	offset = QM + 0x1c0000 + 64 * id;
	rd_row(offset, observed, 13);
	rd_row(offset, repeat, 13);
	if (memcmp(observed, repeat, sizeof(observed)) ||
	    rd(QM + 0x6c000 + 16 * queue) != head)
		return -EAGAIN;
	if (undo) {
		if (!head_edit_valid || id != head_edit_id || head != head_edit_head ||
		    memcmp(observed, head_edit_after, sizeof(observed)))
			return -ESTALE;
		memcpy(next, head_edit_before, sizeof(next));
	} else {
		if (head_edit_valid)
			return -EALREADY;
		/* Physical source3, no NSS proxy/service, ordinary IPv4 UDP, no
		 * route/NAT/TTL/PPPoE-strip or timestamp update pending.
		 */
		if ((observed[0] & 0xfff) != 3 || ((observed[0] >> 12) & 0xfff) != 3 ||
		    (observed[1] & (BIT(7) | BIT(8))) || (observed[2] >> 30) ||
		    (observed[3] & 0x3f) || (observed[4] & (BIT(30) | BIT(31))) ||
		    (observed[5] & 7) || (observed[6] & BIT(28)) ||
		    ((observed[8] >> 24) & 3) != 1 || ((observed[9] >> 2) & 7) != 2 ||
		    ((observed[9] >> 5) & 0xff) != IPPROTO_UDP ||
		    ((observed[6] & BIT(19)) && ((observed[6] >> 20) & 0xff) != 42))
			return -EPROTONOSUPPORT;
		memcpy(next, observed, sizeof(next));
		put_field(next, 211, 1, 1);
		put_field(next, 212, 8, 43); /* known DSCP10/ECT0 -> DSCP10/CE */
		put_field(next, 304, 1, 0);
		head_edit_recorded = true;
		head_edit_undone = false;
		head_edit_valid = true; /* retain recovery snapshot even on readback failure */
		head_edit_id = id;
		head_edit_head = head;
		memcpy(head_edit_before, observed, sizeof(observed));
		memcpy(head_edit_after, next, sizeof(next));
	}
	head_edit_ns = ktime_get_ns();
	err = wr_row(offset, next, 13);
	rd_row(offset, repeat, 13);
	/* A refused allowed-field edit can be undone on the same held head.
	 * Any unrelated mutation or head change invalidates that ownership proof.
	 */
	for (i = 0; i < 13; i++) {
		u32 allowed = i == 6 ? GENMASK(27, 19) : i == 9 ? BIT(16) : 0;

		if ((repeat[i] ^ observed[i]) & ~allowed) {
			fault = true;
			err = -ESTALE;
		}
	}
	if (rd(QM + 0x6c000 + 16 * queue) != head) {
		fault = true;
		err = -ESTALE;
	}
	memcpy(head_edit_after, repeat, sizeof(repeat));
	if (err)
		return err;
	if (undo) {
		head_edit_valid = false;
		head_edit_undone = true;
	}
	return 0;
}

static unsigned int fixture_index(unsigned int row)
{
	return fixture.lists[row / 8] * 8 + row % 8;
}

static int fixture_receive(struct sk_buff *skb, struct net_device *dev,
			   struct packet_type *type, struct net_device *original)
{
	u8 data[FIX_BYTES];
	unsigned long flags;
	unsigned int length, copied, network = ETH_HLEN, tags;
	u16 protocol;
	int offset;

	if (!skb_mac_header_was_set(skb))
		goto done;
	offset = skb_mac_offset(skb);
	if (offset < -(int)skb_headroom(skb) || offset > (int)skb->len)
		goto done;
	length = skb->len - offset;
	copied = min_t(unsigned int, length, sizeof(data));
	if (copied < 42 || skb_copy_bits(skb, offset, data, copied))
		goto done;
	/* Match the tuple independently of the strip action's outcome. Walk
	 * at most two actual tags in this copied header; never alter the skb.
	 * An outer tag may instead already be present in skb VLAN metadata.
	 */
	protocol = get_unaligned_be16(data + 12);
	for (tags = 0; tags < 2; tags++) {
		if (protocol != ETH_P_8021Q && protocol != ETH_P_8021AD)
			break;
		if (copied < network + VLAN_HLEN)
			goto done;
		protocol = get_unaligned_be16(data + network + 2);
		network += VLAN_HLEN;
	}
	if (protocol != ETH_P_IP || copied < network + 28 || data[network] != 0x45 ||
	    data[network + 9] != IPPROTO_UDP ||
	    get_unaligned_be32(data + network + 12) != fixture.sip ||
	    get_unaligned_be32(data + network + 16) != fixture.dip ||
	    get_unaligned_be16(data + network + 20) != fixture.sport ||
	    get_unaligned_be16(data + network + 22) != fixture.dport)
		goto done;
	spin_lock_irqsave(&tap_lock, flags);
	if (fixture.received < FIX_SAMPLES) {
		struct fixture_sample *sample = &fixture.samples[fixture.received];

		sample->time = ktime_get_ns();
		sample->length = length;
		sample->copied = copied;
		sample->vlan_present = skb_vlan_tag_present(skb);
		sample->vlan_proto = be16_to_cpu(skb->vlan_proto);
		sample->vlan_tci = skb_vlan_tag_get(skb);
		sample->inline_tags = tags;
		memcpy(sample->data, data, copied);
	}
	fixture.received++;
	spin_unlock_irqrestore(&tap_lock, flags);
done:
	consume_skb(skb);
	return NET_RX_SUCCESS;
}

static struct packet_type fixture_tap = {
	.type = cpu_to_be16(ETH_P_ALL), .func = fixture_receive,
};

/* Reparent one ordinary held UC192 packet to the existing CPU0/L1 node0.
 * No CPU parent, shared port shaper, packet metadata or link is modified.
 */
static int cpu_remap_begin(unsigned int id, const char *name)
{
	u32 head, data[13], repeat[13], cfg[3], c, e, map, value;
	unsigned int i;
	int err;

	if (!allow_writes || !reserved || fault || fixture.active || cpu_remap.active ||
	    !fixture.configured || !edma || port != 4 || queue != 192 || l1 != 48 ||
	    id >= 2048 || reservation_opened || window_open || drain_active || head_edit_valid)
		return -EPERM;
	err = check_maps();
	if (err)
		return err;
	for_each_set_bit(i, port_queues, QUEUES) {
		if (!(rd(DEQ(i)) & 1))
			return -EBUSY;
		if (i != 192 && ((rd(PENDING(i)) & (i < 256 ? 0xfff : 0x1fff)) ||
		    !(rd(HEAD(i)) & HEAD_EMPTY(i))))
			return -EBUSY;
	}
	head = rd(HEAD(192));
	if ((head & 1) || ((head >> 12) & 0x7ff) != id || ((head >> 1) & 0x7ff) != id)
		return -ENODATA;
	rd_row(QM + 0x1c0000 + 64 * id, data, 13);
	rd_row(QM + 0x1c0000 + 64 * id, repeat, 13);
	if (memcmp(data, repeat, sizeof(data)) || rd(HEAD(192)) != head)
		return -EAGAIN;
	/* Ordinary physical source3 -> destination4, service0 IPv4 UDP. */
	if ((data[0] & 0xfff) != 3 || ((data[0] >> 12) & 0xfff) != 3 ||
	    (data[2] >> 30) || (data[3] & 0x3f) ||
	    ((data[8] >> 24) & 3) != 1 || ((data[9] >> 2) & 7) != 2 ||
	    ((data[9] >> 5) & 0xff) != IPPROTO_UDP || ((data[10] >> 12) & 0xfff) != 4)
		return -EPROTONOSUPPORT;
	rd_row(rows[PORT_CFG].offset, cfg, 2);
	if ((cfg[0] & 0x3ffff) || (cfg[1] & 0x1f) != 0x18 ||
	    !(rd(rows[PORT_SIGN].offset) & 1) || !rd(rows[PORT_CREDIT].offset))
		return -EBUSY;
	/* Parent0 and its port are native. This trial will not repair/configure them. */
	if ((rd(L1_MAP(0)) & 0xf) || (rd(L1_PORT(0)) & 0xf) ||
	    !(readl(edma + 0x48018) & 1))
		return -EXDEV;
	rd_row(TM + 0x5e000, cfg, 3);
	if (cfg[2] & 0x30)
		return -EBUSY;
	rd_row(TM + 0x74000, cfg, 2);
	if (cfg[1] & 0x10)
		return -EBUSY;
	rd_row(rows[L0_CFG].offset, cfg, 3);
	if (cfg[2] & 0x30)
		return -EBUSY;
	map = l0_map[192];
	c = rd(TM + 0x4000 + 16 * ((map & 0x3f) * 8 + ((map >> 6) & 7)));
	e = rd(TM + 0x6000 + 16 * ((map & 0x3f) * 8 + ((map >> 9) & 7)));
	/* No other queue may use CPU parent0 priority7 or either moved DRR ID. */
	for (i = 0; i < QUEUES; i++) {
		if (i == 192)
			continue;
		value = rd(L0_MAP(i));
		if (!(value & 0x3f) && (((value >> 6) & 7) == 7 || ((value >> 9) & 7) == 7))
			return -EBUSY;
		if ((rd(TM + 0x4000 + 16 * ((value & 0x3f) * 8 + ((value >> 6) & 7))) & 0xff) == (c & 0xff) ||
		    (rd(TM + 0x6000 + 16 * ((value & 0x3f) * 8 + ((value >> 9) & 7))) & 0xff) == (e & 0xff))
			return -EBUSY;
	}
	fixture.dev = dev_get_by_name(&init_net, name);
	if (!fixture.dev)
		return -ENODEV;
	memset(&cpu_remap, 0, sizeof(cpu_remap));
	cpu_remap.head = head;
	memcpy(cpu_remap.descriptor, data, sizeof(data));
	memcpy(cpu_remap.descriptor_expected, data, sizeof(data));
	cpu_remap.map_saved = map;
	cpu_remap.port_saved = l0_port[192];
	cpu_remap.map_expected = (map & ~0xfffU) | (7 << 6) | (7 << 9);
	cpu_remap.port_expected = l0_port[192] & ~0xfU;
	cpu_remap.c_saved = rd(TM + 0x4000 + 16 * 7);
	cpu_remap.e_saved = rd(TM + 0x6000 + 16 * 7);
	cpu_remap.c_expected = c;
	cpu_remap.e_expected = e;
	cpu_remap.route_saved = readl(edma + EDMA_ROUTE(192));
	cpu_remap.route_expected = (cpu_remap.route_saved & ~15U) | 15;
	cpu_remap.active = true; /* original reservation keeps the module pinned */
	fixture.received = 0;
	memset(fixture.samples, 0, sizeof(fixture.samples));
	fixture_tap.dev = fixture.dev;
	dev_add_pack(&fixture_tap);
	fixture.tap_on = true;
	err = wr(TM + 0x4000 + 16 * 7, c);
	if (!err)
		err = wr(TM + 0x6000 + 16 * 7, e);
	if (!err) {
		writel(cpu_remap.route_expected, edma + EDMA_ROUTE(192));
		value = readl(edma + EDMA_ROUTE(192));
		if (value != cpu_remap.route_expected)
			err = mmio_error(0xb00000 + EDMA_ROUTE(192), cpu_remap.route_expected, value);
	}
	if (!err)
		err = wr(L0_MAP(192), cpu_remap.map_expected);
	if (!err)
		err = wr(L0_PORT(192), cpu_remap.port_expected);
	if (!err)
		err = check_maps();
	if (err)
		fault = true;
	else
		cpu_remap.installed = true;
	return err;
}

/* Optional field-level discriminator, separate from default scheduler-only
 * remap. Pinned hppe_qm.c7216 has this exact whole-row field setter. Whether
 * CHG_PORT_VP controls transmission or only editing is the trial's question.
 */
static int cpu_remap_destination(void)
{
	u32 observed[13], repeat[13], expected[13], offset;
	unsigned int i;
	int err;

	if (!cpu_remap.active || !cpu_remap.installed || cpu_remap.destination_edited ||
	    cpu_remap.opened || reservation_opened || window_open || fault)
		return -EPERM;
	err = check_maps();
	if (err)
		return err;
	for_each_set_bit(i, port_queues, QUEUES)
		if (!(rd(DEQ(i)) & 1))
			return -EBUSY;
	if (rd(HEAD(192)) != cpu_remap.head)
		return -ESTALE;
	offset = QM + 0x1c0000 + 64 * ((cpu_remap.head >> 12) & 0x7ff);
	rd_row(offset, observed, 13);
	rd_row(offset, repeat, 13);
	if (memcmp(observed, repeat, sizeof(observed)) ||
	    memcmp(observed, cpu_remap.descriptor_expected, sizeof(observed)) ||
	    rd(HEAD(192)) != cpu_remap.head || ((observed[10] >> 12) & 0xfff) != 4)
		return -ESTALE;
	memcpy(expected, observed, sizeof(expected));
	put_field(expected, 332, 12, 0); /* only known physical destination4 -> CPU0 */
	cpu_remap.destination_edited = true; /* preserve recovery on a refused write */
	memcpy(cpu_remap.descriptor_expected, expected, sizeof(expected));
	err = wr_row(offset, expected, 13);
	rd_row(offset, repeat, 13);
	for (i = 0; i < 13; i++) {
		u32 allowed = i == 10 ? GENMASK(23, 12) : 0;

		if ((repeat[i] ^ observed[i]) & ~allowed) {
			fault = true;
			return -ESTALE;
		}
		if (repeat[i] != expected[i])
			err = mmio_error(offset + 4 * i, expected[i], repeat[i]);
	}
	if (rd(HEAD(192)) != cpu_remap.head) {
		fault = true;
		return -ESTALE;
	}
	memcpy(cpu_remap.descriptor_expected, repeat, sizeof(repeat));
	if (err)
		fault = true;
	return err;
}

/* Explicit consent1 means the operator has installed and checked the exact
 * tuple's software-only CPU ingress drop and stopped the finite producer.
 */
static int cpu_remap_open(unsigned int consent, unsigned int usec)
{
	u32 data[13], id;
	unsigned int i;
	int err;

	if (!cpu_remap.active || !cpu_remap.installed || cpu_remap.opened ||
	    fault || consent != 1 || !usec || usec > 100000)
		return -EPERM;
	err = check_maps();
	if (err)
		return err;
	if (rd(TM + 0x4000 + 16 * 7) != cpu_remap.c_expected ||
	    rd(TM + 0x6000 + 16 * 7) != cpu_remap.e_expected ||
	    readl(edma + EDMA_ROUTE(192)) != cpu_remap.route_expected)
		return -ESTALE;
	for_each_set_bit(i, port_queues, QUEUES)
		if (!(rd(DEQ(i)) & 1) || (i != 192 &&
		    ((rd(PENDING(i)) & (i < 256 ? 0xfff : 0x1fff)) ||
		     !(rd(HEAD(i)) & HEAD_EMPTY(i)))))
			return -EBUSY;
	if (rd(HEAD(192)) != cpu_remap.head)
		return -ESTALE;
	id = (cpu_remap.head >> 12) & 0x7ff;
	rd_row(QM + 0x1c0000 + 64 * id, data, 13);
	if (memcmp(data, cpu_remap.descriptor_expected, sizeof(data)) || rd(HEAD(192)) != cpu_remap.head)
		return -ESTALE;
	cpu_remap.opened = true; /* one attempt; a failed opening does not allow a retry */
	return open_window_on(192, usec, false);
}

static int cpu_remap_end(void)
{
	u32 head, data[13], repeat[13], value, offset;
	unsigned int i;
	int err;

	if (!cpu_remap.active)
		return -EINVAL;
	err = close_window();
	if (err)
		return err;
	for_each_set_bit(i, port_queues, QUEUES)
		if (!(rd(DEQ(i)) & 1))
			return -EBUSY;
	head = rd(HEAD(192));
	if (head & 1) {
		if (rd(PENDING(192)) & 0xfff)
			return -EBUSY;
		/* Empty storage alone does not fence the late EDMA route lookup. */
		if (!cpu_remap.opened ||
		    (READ_ONCE(fixture.received) != 1 && !cpu_remap.complete))
			return -EINPROGRESS;
	} else {
		if (head != cpu_remap.head)
			return -ESTALE;
		offset = QM + 0x1c0000 + 64 * ((head >> 12) & 0x7ff);
		rd_row(offset, data, 13);
		rd_row(offset, repeat, 13);
		if (memcmp(data, repeat, sizeof(data)) ||
		    memcmp(data, cpu_remap.descriptor_expected, sizeof(data)) || rd(HEAD(192)) != head)
			return -ESTALE;
	}
	/* Partial preparation/restore may leave either our old or new values.
	 * Foreign values are not overwritten. Other scheduler mappings must match.
	 */
	for (i = 0; i < QUEUES; i++) {
		value = rd(L0_MAP(i));
		if (value != l0_map[i] && (i != 192 || value != cpu_remap.map_expected))
			return -ESTALE;
		value = rd(L0_PORT(i));
		if (value != l0_port[i] && (i != 192 || value != cpu_remap.port_expected))
			return -ESTALE;
	}
	for (i = 0; i < L1S; i++)
		if (rd(L1_MAP(i)) != l1_map[i] || rd(L1_PORT(i)) != l1_port[i])
			return -ESTALE;
	value = rd(TM + 0x4000 + 16 * 7);
	if (value != cpu_remap.c_saved && value != cpu_remap.c_expected)
		return -ESTALE;
	value = rd(TM + 0x6000 + 16 * 7);
	if (value != cpu_remap.e_saved && value != cpu_remap.e_expected)
		return -ESTALE;
	value = readl(edma + EDMA_ROUTE(192));
	if (value != cpu_remap.route_saved && value != cpu_remap.route_expected)
		return -ESTALE;
	/* Only the known original unreleased head can be undone. Empty storage
	 * follows terminal-witness handling above and never writes a recycled ID.
	 */
	if (!(head & 1) && cpu_remap.destination_edited && !cpu_remap.destination_restored) {
		rd_row(offset, repeat, 13);
		if (memcmp(repeat, data, sizeof(data)) || rd(HEAD(192)) != head)
			return -ESTALE;
		err = wr_row(offset, cpu_remap.descriptor, 13);
		rd_row(offset, repeat, 13);
		for (i = 0; i < 13; i++) {
			u32 allowed = i == 10 ? GENMASK(23, 12) : 0;

			if ((repeat[i] ^ data[i]) & ~allowed) {
				fault = true;
				return -ESTALE;
			}
			if (repeat[i] != cpu_remap.descriptor[i])
				err = mmio_error(offset + 4 * i, cpu_remap.descriptor[i], repeat[i]);
		}
		if (rd(HEAD(192)) != head) {
			fault = true;
			return -ESTALE;
		}
		memcpy(cpu_remap.descriptor_expected, repeat, sizeof(repeat));
		if (err) {
			fault = true;
			return err;
		}
		cpu_remap.destination_restored = true;
	}
	err = wr(L0_MAP(192), cpu_remap.map_saved);
	if (!err)
		err = wr(L0_PORT(192), cpu_remap.port_saved);
	if (!err)
		err = wr(TM + 0x4000 + 16 * 7, cpu_remap.c_saved);
	if (!err)
		err = wr(TM + 0x6000 + 16 * 7, cpu_remap.e_saved);
	if (!err) {
		writel(cpu_remap.route_saved, edma + EDMA_ROUTE(192));
		value = readl(edma + EDMA_ROUTE(192));
		if (value != cpu_remap.route_saved)
			err = mmio_error(0xb00000 + EDMA_ROUTE(192), cpu_remap.route_saved, value);
	}
	if (err) {
		fault = true;
		return err;
	}
	cpu_remap.maps_restored = true;
	if (fixture.tap_on) {
		dev_remove_pack(&fixture_tap);
		fixture.tap_on = false;
	}
	err = restore_path();
	if (err)
		return err;
	dev_put(fixture.dev);
	fixture.dev = NULL;
	cpu_remap.active = false;
	cpu_remap.installed = false;
	return 0;
}

static void fixture_action(unsigned int group, u32 *action)
{
	u32 dest = group < 2 ? 7 : 4;
	u32 q = group == 0 ? 240 : group == 1 ? 241 : 192;
	u32 bypass = BIT(0) | BIT(1) | GENMASK(19, 8) | BIT(21) | BIT(22) | BIT(23);

	memset(action, 0, 5 * sizeof(u32));
	put_field(action, 0, 1, 1);
	put_field(action, 18, 32, bypass);
	if (group == 3) {
		put_field(action, 1, 2, 1);
		return;
	}
	if (!group && fixture.direct) {
		dest = 4;
		q = 192;
	}
	if (fixture.relay && !group) {
		/* External RX acquisition owns this profile/queue and its ring. */
		dest = 0;
		q = fixture.relay;
	}
	if (fixture.relay && group == 2) {
		dest = 0;
		q = fixture.cpuq;
	}
	if (group == 2 && fixture.mode == 2) {
		dest = 0;
		q = fixture.cpuq;
		/* Explicit physical CPU destination plus exact queue, not the
		 * default trap queue currently owned by NSS.
		 */
	}
	put_field(action, 3, 14, (2 << 12) | dest);
	if (group == 2 && fixture.mode == 1)
		bypass &= ~BIT(21);
	if (!group && fixture.meter_on) {
		bypass &= ~BIT(19);
		put_field(action, 107, 1, 1);
		put_field(action, 108, 9, fixture.meter);
	}
	put_field(action, 18, 32, bypass);
	if (group || !fixture.direct) {
		put_field(action, 64, 1, 1);
		put_field(action, 65, 1, group < 2);
		put_field(action, 66, 12, group == 0 ? fixture.vida : group == 1 ? fixture.vidb : 0);
	}
	if (group == 2 && fixture.mode == 1) {
		put_field(action, 78, 1, 1);
		put_field(action, 79, 8, (fixture.tos & 0xfc) | 3);
	}
	put_field(action, 117, 1, 1);
	put_field(action, 118, 8, q);
}

/* Four ANDed slices, with two independent four-slice groups per list. */
static void fixture_construct(void)
{
	unsigned int group, slice, row, type;
	u64 value, mask;
	bool inverse;

	memset(fixture.expected, 0, sizeof(fixture.expected));
	for (group = 0; group < 4; group++) {
		for (slice = 0; slice < 4; slice++) {
			struct fixture_acl *entry;

			row = 4 * group + slice;
			entry = &fixture.expected[row];
			inverse = false;
			if (slice < 2) {
				type = slice ? 4 : 5;
				value = (u64)(slice ? fixture.dip : fixture.sip) << 16;
				value |= slice ? fixture.dport : fixture.sport;
				value |= BIT_ULL(49) | BIT_ULL(52); /* UDP, IP, nonfragment */
				mask = GENMASK_ULL(47, 0); /* exact address and port always */
				if (fixture.status & 1)
					mask |= BIT_ULL(52);
				if (fixture.status & 2)
					mask |= BIT_ULL(48);
				if (fixture.status & 4)
					mask |= GENMASK_ULL(51, 49);
			} else if (slice == 2 || group == 3) {
				type = 2;
				value = (u64)fixture.untag << 36;
				mask = (u64)fixture.tagmask << 36;
				if (group || slice == 3) {
					value = (u64)fixture.tagged << 36 | (group == 1 ||
						(group == 3 && slice == 2) ? fixture.vida : fixture.vidb);
					mask |= 0xfff;
					if (fixture.relay && group == 2) {
						value = (u64)fixture.tagged << 36 | fixture.vida;
						mask = (u64)fixture.return_tagmask << 36 | fixture.return_vidmask;
					}
				}
				inverse = group == 3;
			} else {
				type = 12;
				value = (u64)fixture.tos << 24 | (u64)IPPROTO_UDP << 16;
				mask = (u64)0xff << 16; /* protocol17 remains mandatory */
				if (!group && fixture.match_tos)
					mask |= (u64)0xff << 24;
				if (fixture.status & 1)
					mask |= BIT_ULL(49); /* IPv4 */
				if (fixture.status & 2)
					mask |= BIT_ULL(48); /* nonfragment */
			}
			entry->rule[0] = value;
			entry->rule[1] = value >> 32;
			put_field(entry->rule, 54, 1, inverse);
			put_field(entry->rule, 55, 4, type);
			if (fixture.relay && group == 2)
				put_field(entry->rule, 79, 1, fixture.return_post);
			entry->mask[0] = mask;
			entry->mask[1] = mask >> 32;
			fixture_action(group, entry->action);
		}
	}
}

static int fixture_bind(unsigned int group, bool enable)
{
	unsigned int i;
	int err;

	for (i = 4 * group; i < 4 * group + 4; i++) {
		put_field(fixture.expected[i].rule, 61, 8,
			enable ? (fixture.relay && group == 2 ? fixture.return_sources : BIT(group ? 7 : 3)) : 0);
		err = wr_row(ACL_RULE(fixture_index(i)), fixture.expected[i].rule, 3);
		if (err) {
			fault = true;
			return err;
		}
	}
	if (!group) {
		fixture.armed = enable;
		if (enable && fixture.relay) {
			fixture.relay_opened = true;
			fixture.relay_complete = false;
		}
	}
	return 0;
}

/* Valid words of ingress(2), L2(1), and egress(2) SC1 rows. Padding is not
 * part of these documented entries. Keep every unrelated field unchanged.
 */
static int fixture_service1_check(void)
{
	u32 observed[5];

	if (!fixture.relay)
		return 0;
	rd_row(0x15010, observed, 2);
	observed[2] = rd(0x64010);
	rd_row(0x2c008, observed + 3, 2);
	return memcmp(observed, fixture.service1_expected, sizeof(observed)) ? -ESTALE : 0;
}

static int fixture_check(void)
{
	u32 mru[2];
	unsigned int i, j, index;
	int err = check_maps();

	if (!err)
		err = fixture_service1_check();
	if (err)
		return err;
	if (rd(BRIDGE_CTRL(7)) != fixture.bridge7_expected)
		return -ESTALE;
	if (fixture.relay) {
		rd_row(MRU_MTU(3), mru, 2);
		if (((mru[1] >> 2) & 3) != fixture.relay ||
		    ((readl(edma + EDMA_ROUTE(fixture.relay)) >>
		      (4 * (fixture.relay % 8))) & 15) != fixture.relay_route)
			return -ESTALE;
		/* The external relay may open its own queue after this reservation. */
	}
	if (rd(rows[PORT_CFG].offset) != 0xfffc0000 ||
	    (rd(rows[PORT_CFG].offset + 4) & 0x1f) != (READ_ONCE(drain_active) ? 0x08 : 0x18) ||
	    ((readl(edma + EDMA_ROUTE(fixture.cpuq)) >> (4 * (fixture.cpuq % 8))) & 15) != 15)
		return -ESTALE;
	for (i = 0; i < 2; i++)
		if (rd(ACL_EXT(0, fixture.lists[i])) != 15 ||
		    rd(ACL_EXT(1, fixture.lists[i])) != 3 ||
		    rd(ACL_EXT(2, fixture.lists[i])) != 0)
			return -ESTALE;
	for (i = 0; i < 16; i++) {
		index = fixture_index(i);
		for (j = 0; j < 3; j++)
			if (rd(ACL_RULE(index) + 4 * j) != fixture.expected[i].rule[j])
				return -ESTALE;
		for (j = 0; j < 2; j++)
			if (rd(ACL_MASK(index) + 4 * j) != fixture.expected[i].mask[j])
				return -ESTALE;
		for (j = 0; j < 5; j++)
			if (rd(ACL_ACTION(index) + 4 * j) != fixture.expected[i].action[j])
				return -ESTALE;
	}
	return 0;
}

static int fixture_begin(u32 list0, u32 list1, u32 cpuq, u32 meter, const char *name)
{
	unsigned int i, j, k, index, shift;
	u32 source, action[5], live[3], cfg[2] = { 0xfffc0000, 0x08 };
	int err;

	if (!allow_writes || !fixture.configured || reserved || fixture.active)
		return -EPERM;
	if (list0 >= 64 || list1 >= 64 || list0 == list1 || cpuq < 1 || cpuq > 3 || meter > 512)
		return -ERANGE;
	if (!edma || !(readl(edma + 0x39018 + 0x1000 * 15) & 1))
		return -ENODEV;
	if (fixture.relay) {
		if (fixture.relay == cpuq)
			return -EINVAL;
		rd_row(MRU_MTU(3), fixture.relay_mru, 2);
		fixture.relay_route = (readl(edma + EDMA_ROUTE(fixture.relay)) >>
			(4 * (fixture.relay % 8))) & 15;
		fixture.relay_gate = rd(DEQ(fixture.relay));
		if (((fixture.relay_mru[1] >> 2) & 3) != fixture.relay ||
		    (rd(L0_PORT(fixture.relay)) & 0xf) ||
		    (rd(L1_PORT(rd(L0_MAP(fixture.relay)) & 0x3f)) & 0xf) ||
		    fixture.relay_route == 15)
			return -EXDEV;
		if (!(fixture.relay_gate & 1) || (rd(PENDING(fixture.relay)) & 0xfff) ||
		    !(rd(HEAD(fixture.relay)) & 1))
			return -EBUSY;
	}
	if ((rd(L0_MAP(240)) & 0x3f) != 60 || (rd(L0_MAP(241)) & 0x3f) != 60 ||
	    (rd(L0_PORT(241)) & 0xf) != 7 || (rd(L0_PORT(cpuq)) & 0xf) ||
	    (rd(L1_PORT(rd(L0_MAP(cpuq)) & 0x3f)) & 0xf))
		return -EXDEV;
	for (i = 240; i <= 241; i++) {
		rd_row(TM + 0x1c000 + 16 * i, live, 3);
		if (live[2] & 0x30)
			return -EBUSY;
	}
	rd_row(TM + 0x5e000 + 16 * 60, live, 3);
	if (live[2] & 0x30)
		return -EBUSY;
	rd_row(TM + 0x74000 + 16 * 7, live, 2);
	if ((live[1] & 0x10) ||
	    (rd(PENDING(cpuq)) & 0xfff) ||
	    !(rd(QM + 0x6c000 + 16 * cpuq) & 1) ||
	    (rd(QM + 0x5c000 + 16 * cpuq) & 1) ||
	    (rd(QM + 0x64000 + 16 * cpuq) & 1) ||
	    (rd(QM + 0x5c000 + 16 * 240) & 1) ||
	    (rd(QM + 0x5c000 + 16 * 241) & 1) ||
	    (rd(QM + 0x64000 + 16 * 240) & 1) ||
	    (rd(QM + 0x64000 + 16 * 241) & 1))
		return -EBUSY;
	fixture.lists[0] = list0;
	fixture.lists[1] = list1;
	fixture.cpuq = cpuq;
	fixture.meter = meter;
	fixture.mode = 0;
	fixture.meter_on = false;
	fixture.relay_opened = false;
	fixture.relay_complete = false;
	fixture.installed = false;
	fixture.restoring = false;
	for (i = 0; i < 16; i++) {
		struct fixture_acl *entry = &fixture.saved[i];

		index = fixture_index(i);
		rd_row(ACL_RULE(index), entry->rule, 3);
		rd_row(ACL_COUNT(index), entry->counter, 3);
		source = (entry->rule[1] >> 27) & 0x1f;
		if (source || (entry->rule[2] & 0x1f))
			return -EBUSY; /* source type0 AND empty physical bitmap only */
		for (j = 0; j < 2; j++)
			entry->mask[j] = rd(ACL_MASK(index) + 4 * j);
		for (j = 0; j < 5; j++)
			entry->action[j] = rd(ACL_ACTION(index) + 4 * j);
	}
	for (i = 0; i < 2; i++)
		for (j = 0; j < 3; j++)
			fixture.ext[i][j] = rd(ACL_EXT(j, fixture.lists[i]));
	if (meter < 512) {
		if (rd(METER_CFG(meter)) & 1)
			return -EBUSY;
		for (i = 0; i < 512; i++) {
			for (j = 0; j < 5; j++)
				action[j] = rd(ACL_ACTION(i) + 4 * j);
			if ((action[3] & BIT(11)) && ((action[3] >> 12) & 0x1ff) == meter)
				return -EBUSY; /* reject even inactive foreign references */
		}
		for (j = 0; j < 4; j++)
			fixture.meter_cfg[j] = rd(METER_CFG(meter) + 4 * j);
		for (j = 0; j < 2; j++)
			fixture.meter_credit[j] = rd(METER_CREDIT(meter) + 4 * j);
		for (j = 0; j < 3; j++)
			for (k = 0; k < 3; k++)
				fixture.meter_count[j][k] = rd(METER_COUNT(meter, j) + 4 * k);
	}
	fixture.dev = dev_get_by_name(&init_net, name);
	if (!fixture.dev)
		return -ENODEV;
	fixture.cpu_gate = rd(DEQ(cpuq));
	shift = 4 * (cpuq % 8);
	fixture.cpu_route = (readl(edma + EDMA_ROUTE(cpuq)) >> shift) & 15;
	fixture.second_drop = rd(QM + 0x64000 + 16 * 241);
	fixture.bridge7_saved = rd(BRIDGE_CTRL(7));
	fixture.bridge7_expected = fixture.bridge7_saved;
	if (fixture.relay) {
		rd_row(0x15010, fixture.service1_saved, 2);
		fixture.service1_saved[2] = rd(0x64010);
		rd_row(0x2c008, fixture.service1_saved + 3, 2);
		memcpy(fixture.service1_expected, fixture.service1_saved,
		       sizeof(fixture.service1_saved));
	}
	err = select_path(7, 240, 60);
	if (!err)
		err = reserve_path();
	if (err && !reserved) {
		dev_put(fixture.dev);
		fixture.dev = NULL;
		return err;
	}
	fixture.active = true;
	fixture_construct();
	if (err)
		goto fail;
	err = wr(DEQ(cpuq), fixture.cpu_gate | 1);
	if (err)
		goto fail;
	writel((readl(edma + EDMA_ROUTE(cpuq)) & ~(15 << shift)) | (15 << shift),
	       edma + EDMA_ROUTE(cpuq));
	source = readl(edma + EDMA_ROUTE(cpuq));
	if (((source >> shift) & 15) != 15) {
		err = mmio_error(0xb00000 + EDMA_ROUTE(cpuq),
				 (source & ~(15 << shift)) | (15 << shift), source);
		goto fail;
	}
	/* Construct the independent credit/sign registers while disabled. All
	 * queues must still be held and empty; readbacks are not a drain fence.
	 */
	for_each_set_bit(i, port_queues, QUEUES) {
		if (!(rd(DEQ(i)) & 1) ||
		    (rd(PENDING(i)) & (i < 256 ? 0xfff : 0x1fff)) ||
		    !(rd(HEAD(i)) & HEAD_EMPTY(i))) {
			err = -EBUSY;
			goto fail;
		}
	}
	err = wr_row(rows[PORT_CFG].offset, cfg, 2);
	if (!err)
		err = wr(rows[PORT_CREDIT].offset, 1);
	if (!err)
		err = wr(rows[PORT_SIGN].offset, 1);
	cfg[1] = 0x18;
	if (!err)
		err = wr_row(rows[PORT_CFG].offset, cfg, 2);
	/* Three read-only observations, no write retry or guessed sleep/fence. */
	for (i = 0; !err && i < 3; i++) {
		rd_row(rows[PORT_CFG].offset, live, 2);
		for (j = 0; j < 2; j++)
			if (live[j] != cfg[j])
				err = mmio_error(rows[PORT_CFG].offset + 4 * j, cfg[j], live[j]);
		live[0] = rd(rows[PORT_CREDIT].offset);
		live[1] = rd(rows[PORT_SIGN].offset);
		if (live[0] != 1)
			err = mmio_error(rows[PORT_CREDIT].offset, 1, live[0]);
		if (live[1] != 1)
			err = mmio_error(rows[PORT_SIGN].offset, 1, live[1]);
	}
	if (err)
		goto fail;
	for (i = 0; i < 16; i++) {
		index = fixture_index(i);
		err = wr_row(ACL_ACTION(index), fixture.expected[i].action, 5);
		if (!err)
			err = wr_row(ACL_MASK(index), fixture.expected[i].mask, 2);
		if (!err)
			err = wr_row(ACL_RULE(index), fixture.expected[i].rule, 3);
		if (err)
			goto fail;
	}
	for (i = 0; i < 2; i++) {
		err = wr(ACL_EXT(0, fixture.lists[i]), 15);
		if (!err)
			err = wr(ACL_EXT(1, fixture.lists[i]), 3);
		if (!err)
			err = wr(ACL_EXT(2, fixture.lists[i]), 0);
		if (err)
			goto fail;
	}
	fixture.received = 0;
	memset(fixture.samples, 0, sizeof(fixture.samples));
	fixture_tap.dev = fixture.dev;
	dev_add_pack(&fixture_tap);
	fixture.tap_on = true;
	if (fixture.relay) {
		err = fixture_bind(2, true);
	} else if (!fixture.direct) {
		err = fixture_bind(3, true);
		if (!err)
			err = fixture_bind(2, true);
		if (!err)
			err = fixture_bind(1, true);
	}
	if (!err)
		err = wr(DEQ(cpuq), fixture.cpu_gate & ~1);
	if (!err) {
		fixture.installed = true;
		return 0;
	}
fail:
	fault = true;
	return err;
}

/* Only the documented TXMAC enable bit is changed. This is a diagnostic
 * discriminator for the native init/DSA-setup ordering, not a port initializer.
 */
static int fixture_enable7(unsigned int consent)
{
	unsigned int i;
	u32 observed;
	int err;

	if (!fixture.active || !fixture.installed || fixture.armed || fixture.direct ||
	    fixture.relay || fault || window_open || consent != 1)
		return -EPERM;
	err = fixture_check();
	if (err)
		return err;
	if (fixture.bridge7_expected & BIT(16))
		return -EALREADY;
	for_each_set_bit(i, port_queues, QUEUES)
		if (!(rd(DEQ(i)) & 1) ||
		    (rd(PENDING(i)) & (i < 256 ? 0xfff : 0x1fff)) ||
		    !(rd(HEAD(i)) & HEAD_EMPTY(i)))
			return -EBUSY;
	fixture.bridge7_expected = fixture.bridge7_saved | BIT(16);
	err = wr(BRIDGE_CTRL(7), fixture.bridge7_expected);
	if (err) {
		observed = rd(BRIDGE_CTRL(7));
		if (observed == fixture.bridge7_saved)
			fixture.bridge7_expected = fixture.bridge7_saved;
		fault = true;
	}
	return err;
}

/* Consent means all other SC1 producers are isolated by the operator. The
 * module can verify only its reserved external NSS queue and finite witness.
 */
static int fixture_service1(unsigned int consent, unsigned int tag_edit)
{
	u32 previous[5], observed[2];
	int err;

	if (!fixture.active || !fixture.installed || !fixture.relay || fixture.armed ||
	    fault || window_open || consent != 1 || tag_edit > 1 ||
	    (fixture.relay_opened && !fixture.relay_complete))
		return -EPERM;
	err = fixture_check();
	if (err)
		return err;
	if (!(rd(DEQ(fixture.relay)) & 1) || (rd(PENDING(fixture.relay)) & 0xfff) ||
	    !(rd(HEAD(fixture.relay)) & 1))
		return -EBUSY;
	memcpy(previous, fixture.service1_expected, sizeof(previous));
	fixture.service1_expected[0] = fixture.service1_saved[0] & ~BIT(7);
	err = wr_row(0x15010, fixture.service1_expected, 2);
	if (err) {
		rd_row(0x15010, observed, 2);
		if (observed[0] == previous[0] && observed[1] == previous[1])
			fixture.service1_expected[0] = previous[0];
		goto fail;
	}
	/* IN_L2_SERVICE bypass bitmap starts at bit6; logical editor bit12. */
	fixture.service1_expected[2] = fixture.service1_saved[2];
	if (tag_edit)
		fixture.service1_expected[2] &= ~BIT(18);
	err = wr(0x64010, fixture.service1_expected[2]);
	if (err && rd(0x64010) == previous[2])
		fixture.service1_expected[2] = previous[2];
	if (!err)
		err = fixture_service1_check();
	if (!err)
		return 0;
fail:
	fault = true;
	return err;
}

static int fixture_mode(unsigned int mode)
{
	unsigned int i;
	int err;

	if (!fixture.active || fixture.direct || fixture.relay || fault || mode > 2)
		return -EINVAL;
	err = close_window();
	if (!err)
		err = fixture_check();
	if (err)
		return err;
	if (!(rd(DEQ(240)) & 1) || !(rd(DEQ(241)) & 1))
		return -EBUSY;
	/* Caller has established no outstanding traversal by finite packet evidence. */
	err = fixture_bind(2, false);
	fixture.mode = mode;
	for (i = 8; !err && i < 12; i++) {
		fixture_action(2, fixture.expected[i].action);
		err = wr_row(ACL_ACTION(fixture_index(i)), fixture.expected[i].action, 5);
	}
	if (!err)
		err = fixture_bind(2, true);
	if (err)
		fault = true;
	return err;
}

static int fixture_meter(const u32 *v)
{
	u32 config[4] = { 0 }, credit[2] = { v[4], v[5] };
	unsigned int i;
	int err;

	if (!fixture.active || fault || fixture.armed || fixture.meter >= 512 ||
	    v[0] > 1 || v[1] > 1 || v[2] > 1 || v[3] > 7)
		return -EINVAL;
	err = fixture_check();
	if (err)
		return err;
	put_field(config, 0, 1, 1);
	put_field(config, 2, 1, v[1]);
	put_field(config, 3, 1, v[0]);
	put_field(config, 4, 3, v[3]);
	put_field(config, 7, 1, v[2]);
	put_field(config, 8, 16, 65535);
	put_field(config, 42, 16, 65535);
	put_field(config, 90, 1, 1); /* forward red; yellow has no drop command */
	err = wr_row(METER_CFG(fixture.meter), config, 4);
	if (!err)
		err = wr_row(METER_CREDIT(fixture.meter), credit, 2);
	fixture.meter_on = true;
	for (i = 0; !err && i < 4; i++) {
		fixture_action(0, fixture.expected[i].action);
		err = wr_row(ACL_ACTION(fixture_index(i)), fixture.expected[i].action, 5);
	}
	if (err)
		fault = true;
	return err;
}

static int fixture_grant(unsigned int q, unsigned int packets, unsigned int drop,
			 unsigned int usec)
{
	u32 value, config[2] = { 0xfffc0000, 0x18 };
	int err;

	if (!fixture.active || fixture.direct || fixture.relay || fault || (q != 240 && q != 241) ||
	    !packets || packets > 64 || drop > 1 || !usec || usec > 1000000)
		return -EINVAL;
	err = close_window();
	if (!err)
		err = fixture_check();
	if (err)
		return err;
	if (!(rd(DEQ(240)) & 1) || !(rd(DEQ(241)) & 1))
		return -EBUSY;
	value = packets * (1U << 21) - 1;
	err = wr_row(rows[PORT_CFG].offset, config, 2);
	if (!err)
		err = wr(rows[PORT_CREDIT].offset, value);
	if (!err)
		err = wr(rows[PORT_SIGN].offset, 0);
	if (!err)
		err = wr(QM + 0x64000 + 16 * q,
			(rd(QM + 0x64000 + 16 * q) & ~1) | drop);
	if (!err)
		err = open_window_on(q, usec, false);
	if (err)
		fault = true;
	return err;
}

/* Explicit bounded cleanup when a finite-grant mechanism fails qualification.
 * No source3 admission and no unseen population may be introduced here.
 */
static int fixture_drain(unsigned int q, unsigned int drop, unsigned int usec)
{
	u32 h, id, tail, config[2] = { 0xfffc0000, 0x08 };
	unsigned int i;
	int err;

	if (!fixture.active || fixture.relay || fault || fixture.armed || (q != 240 && q != 241) ||
	    drop > 1 || !usec || usec > 1000000)
		return -EINVAL;
	err = close_window();
	if (!err)
		err = fixture_check();
	if (err)
		return err;
	h = rd(QM + 0x6c000 + 16 * q);
	if (h & 1)
		return -ENODATA;
	id = (h >> 12) & 0x7ff;
	tail = (h >> 1) & 0x7ff;
	for (i = 0; i < 64 && id != tail; i++)
		id = rd(QM + 0x90000 + 16 * id) & 0x7ff;
	if (i >= 64 || rd(QM + 0x6c000 + 16 * q) != h)
		return -EAGAIN;
	err = wr_row(rows[PORT_CFG].offset, config, 2);
	if (!err)
		err = wr(rows[PORT_CREDIT].offset, 0);
	if (!err)
		err = wr(rows[PORT_SIGN].offset, 0);
	if (!err) {
		err = wr(QM + 0x64000 + 16 * q,
			(rd(QM + 0x64000 + 16 * q) & ~1) | drop);
	}
	if (!err)
		err = open_window_on(q, usec, true);
	if (err)
		fault = true;
	return err;
}

static int fixture_end(void)
{
	unsigned int i, j, index, shift;
	int err;
	u32 value;

	if (!fixture.active)
		return -EINVAL;
	err = close_window();
	if (!err)
		err = fixture_service1_check();
	if (!err && rd(BRIDGE_CTRL(7)) != fixture.bridge7_expected)
		err = -ESTALE;
	if (!err && fixture.installed && !fixture.restoring)
		err = fixture_check();
	if (!err)
		err = fixture_bind(0, false);
	if (err)
		goto fail;
	/* The caller must retain the final capture while any NSS relay carrier
	 * could still return. Empty port7/native CPU storage is not that fence.
	 */
	if (fixture.relay && fixture.relay_opened && !fixture.relay_complete)
		return -EINPROGRESS;
	if (fixture.relay && (!(rd(DEQ(fixture.relay)) & 1) ||
	    (rd(PENDING(fixture.relay)) & 0xfff) || !(rd(HEAD(fixture.relay)) & 1)))
		return -EBUSY;
	for_each_set_bit(i, port_queues, QUEUES)
		if (rd(PENDING(i)) & (i < 256 ? 0xfff : 0x1fff))
			return -EBUSY;
	if ((rd(PENDING(fixture.cpuq)) & 0xfff) ||
	    !(rd(QM + 0x6c000 + 16 * 240) & 1) ||
	    !(rd(QM + 0x6c000 + 16 * 241) & 1))
		return -EBUSY;
	fixture.restoring = true;
	err = wr(DEQ(fixture.cpuq), fixture.cpu_gate | 1);
	for (i = 1; !err && i < 4; i++)
		err = fixture_bind(i, false);
	if (err)
		goto fail;
	/* The external NSS producer is held and its old finite population has
	 * terminal witnesses. Restore SC1 before releasing any fixture resource.
	 */
	if (fixture.relay) {
		err = fixture_service1_check();
		if (err)
			goto fail;
		value = fixture.service1_expected[0];
		fixture.service1_expected[0] = fixture.service1_saved[0];
		err = wr_row(0x15010, fixture.service1_expected, 2);
		if (err) {
			u32 observed[2];

			rd_row(0x15010, observed, 2);
			if (observed[0] == value && observed[1] == fixture.service1_saved[1])
				fixture.service1_expected[0] = value;
			goto fail;
		}
		value = fixture.service1_expected[2];
		fixture.service1_expected[2] = fixture.service1_saved[2];
		err = wr(0x64010, fixture.service1_expected[2]);
		if (err && rd(0x64010) == value)
			fixture.service1_expected[2] = value;
		if (!err)
			err = fixture_service1_check();
		if (err)
			goto fail;
	}
	if (fixture.tap_on) {
		dev_remove_pack(&fixture_tap); /* includes synchronize_net */
		fixture.tap_on = false;
	}
	for (i = 0; i < 16; i++) {
		index = fixture_index(i);
		err = wr_row(ACL_ACTION(index), fixture.saved[i].action, 5);
		if (!err)
			err = wr_row(ACL_MASK(index), fixture.saved[i].mask, 2);
		if (!err)
			err = wr_row(ACL_RULE(index), fixture.saved[i].rule, 3);
		if (!err)
			err = wr_row(ACL_COUNT(index), fixture.saved[i].counter, 3);
		if (err)
			goto fail;
	}
	for (i = 0; i < 2; i++)
		for (j = 0; j < 3; j++) {
			err = wr(ACL_EXT(j, fixture.lists[i]), fixture.ext[i][j]);
			if (err)
				goto fail;
		}
	if (fixture.meter < 512) {
		err = wr_row(METER_CFG(fixture.meter), fixture.meter_cfg, 4);
		if (!err)
			err = wr_row(METER_CREDIT(fixture.meter), fixture.meter_credit, 2);
		for (i = 0; !err && i < 3; i++)
			err = wr_row(METER_COUNT(fixture.meter, i), fixture.meter_count[i], 3);
		if (err)
			goto fail;
	}
	shift = 4 * (fixture.cpuq % 8);
	value = readl(edma + EDMA_ROUTE(fixture.cpuq));
	value = (value & ~(15 << shift)) | (fixture.cpu_route << shift);
	writel(value, edma + EDMA_ROUTE(fixture.cpuq));
	index = readl(edma + EDMA_ROUTE(fixture.cpuq));
	if (((index >> shift) & 15) != fixture.cpu_route) {
		err = mmio_error(0xb00000 + EDMA_ROUTE(fixture.cpuq), value, index);
		goto fail;
	}
	/* All fixture sources are unbound and the stores are empty. Restore the
	 * owned bit before any original port7 gate can reopen; never overwrite a
	 * foreign change elsewhere in the saved bridge row.
	 */
	value = rd(BRIDGE_CTRL(7));
	if (value != fixture.bridge7_expected) {
		err = -ESTALE;
		goto fail;
	}
	if (value != fixture.bridge7_saved) {
		fixture.bridge7_expected = fixture.bridge7_saved;
		err = wr(BRIDGE_CTRL(7), fixture.bridge7_saved);
		if (err) {
			if (rd(BRIDGE_CTRL(7)) == value)
				fixture.bridge7_expected = value;
			goto fail;
		}
	}
	err = wr(QM + 0x64000 + 16 * 241, fixture.second_drop);
	if (!err)
		err = wr(DEQ(fixture.cpuq), fixture.cpu_gate);
	if (!err)
		err = restore_path();
	if (err)
		goto fail;
	dev_put(fixture.dev);
	fixture.dev = NULL;
	fixture.active = false;
	fixture.armed = false;
	fixture.installed = false;
	fixture.restoring = false;
	return 0;
fail:
	fault = true;
	return err;
}

static void show_tap_samples(struct seq_file *s)
{
	struct fixture_sample sample;
	unsigned long flags;
	u64 count;
	unsigned int i, j;

	/* Both callers hold diag_lock; inactive/failed cleanup has no device. */
	if (!fixture.dev)
		return;
	spin_lock_irqsave(&tap_lock, flags);
	count = fixture.received;
	spin_unlock_irqrestore(&tap_lock, flags);
	seq_printf(s, "fixture_cpu_received=%llu dev=%s\n", count, fixture.dev->name);
	for (i = 0; i < min_t(u64, count, FIX_SAMPLES); i++) {
		spin_lock_irqsave(&tap_lock, flags);
		sample = fixture.samples[i];
		spin_unlock_irqrestore(&tap_lock, flags);
		seq_printf(s, "fixture_cpu[%u] ns=%llu len=%u vlan_present=%u vlan_proto=%04x vlan_tci=%04x inline_tags=%u header=",
			i, sample.time, sample.length, sample.vlan_present,
			sample.vlan_proto, sample.vlan_tci, sample.inline_tags);
		for (j = 0; j < sample.copied; j += 32)
			seq_printf(s, "%*phN", min_t(u32, 32, sample.copied - j), sample.data + j);
		seq_putc(s, '\n');
	}
}

static void fixture_status(struct seq_file *s)
{
	u32 h, id, tail, index, active, row[5], credit[2];
	unsigned int i, j, q;

	seq_printf(s, "fixture configured=%u active=%u armed=%u mode=%u lists=%u,%u cpuq=%u meter=%u meter_on=%u tap=%u\n",
		fixture.configured, fixture.active, fixture.armed, fixture.mode,
		fixture.lists[0], fixture.lists[1], fixture.cpuq, fixture.meter,
		fixture.meter_on, fixture.tap_on);
	seq_printf(s, "fixture_match untag=%u tag=%u tagmask=%u status=%u tos=%u direct=%u relay=%u\n",
		fixture.untag, fixture.tagged, fixture.tagmask, fixture.status,
		fixture.match_tos, fixture.direct, fixture.relay);
	seq_printf(s, "fixture_return post=%u tagmask=%u vidmask=%03x sources=%02x\n",
		fixture.return_post, fixture.return_tagmask, fixture.return_vidmask, fixture.return_sources);
	seq_printf(s, "fixture_relay opened=%u complete=%u saved_route=%u saved_gate=%08x saved_mru=%08x,%08x\n",
		fixture.relay_opened, fixture.relay_complete, fixture.relay_route,
		fixture.relay_gate, fixture.relay_mru[0], fixture.relay_mru[1]);
	if (fixture.relay && fixture.active) {
		rd_row(0x15010, row, 2);
		row[2] = rd(0x64010);
		rd_row(0x2c008, row + 3, 2);
		seq_printf(s, "fixture_service1 saved=%08x,%08x,%08x,%08x,%08x expected=%08x,%08x,%08x,%08x,%08x live=%08x,%08x,%08x,%08x,%08x\n",
			fixture.service1_saved[0], fixture.service1_saved[1], fixture.service1_saved[2],
			fixture.service1_saved[3], fixture.service1_saved[4],
			fixture.service1_expected[0], fixture.service1_expected[1], fixture.service1_expected[2],
			fixture.service1_expected[3], fixture.service1_expected[4],
			row[0], row[1], row[2], row[3], row[4]);
	}
	if (fixture.inventory || fixture.active) {
		for (i = 4; i <= 7; i += 3) {
			rd_row(MRU_MTU(i), row, 2);
			seq_printf(s, "fixture_port=%u bridge=%08x mru=%08x,%08x profile=%u\n",
				i, rd(BRIDGE_CTRL(i)), row[0], row[1], (row[1] >> 2) & 3);
		}
		rd_row(MRU_MTU(3), row, 2);
		seq_printf(s, "fixture_source3 mru=%08x,%08x profile=%u bridge7_saved=%08x bridge7_expected=%08x\n",
			row[0], row[1], (row[1] >> 2) & 3,
			fixture.bridge7_saved, fixture.bridge7_expected);
		if (fixture.relay && edma) {
			q = fixture.relay;
			seq_printf(s, "fixture_nss_queue=%u l0=%08x port=%08x gate=%08x pending=%08x head=%08x route=%u\n",
				q, rd(L0_MAP(q)), rd(L0_PORT(q)), rd(DEQ(q)), rd(PENDING(q)),
				rd(HEAD(q)), (readl(edma + EDMA_ROUTE(q)) >> (4 * (q % 8))) & 15);
		}
	}
	seq_printf(s, "ipo_global hit=%08x miss=%08x bypass=%08x parser3=%08x\n",
		rd(IPO + 0x430c), rd(IPO + 0x4310), rd(IPO + 0x4314), rd(0x200c));
	if (fixture.inventory) {
		for (i = 0; i < 64; i++) {
			active = 0;
			for (j = 0; j < 8; j++) {
				rd_row(ACL_RULE(8 * i + j), row, 3);
				if (((row[1] >> 27) & 0x1f) || (row[2] & 0x1f))
					active |= BIT(j);
			}
			seq_printf(s, "acl_list=%u active=%02x ext=%08x,%08x,%08x\n", i, active,
				rd(ACL_EXT(0, i)), rd(ACL_EXT(1, i)), rd(ACL_EXT(2, i)));
		}
		rd_row(0x2c008, row, 2);
		seq_printf(s, "service1 ingress=%08x l2=%08x egress=%08x,%08x eg_bridge=%08x\n",
			rd(0x15010), rd(0x64010), row[0], row[1], rd(PTX + 0x6000));
		for (i = 504; i < 512; i++) {
			rd_row(METER_CFG(i), row, 4);
			rd_row(METER_CREDIT(i), credit, 2);
			seq_printf(s, "meter_candidate=%u cfg=%08x,%08x,%08x,%08x credit=%08x,%08x\n",
				i, row[0], row[1], row[2], row[3], credit[0], credit[1]);
		}
		/* These are the native driver's extrapolated port7 MAC offsets.
		 * A zero read does not establish whether the internal path loops.
		 */
		seq_printf(s, "loop7 enable=%08x pps=%08x parser=%08x vlan_tpid=%08x egress_tpid=%08x\n",
			rd(0x1c00), rd(0x1c0c), rd(0x201c), rd(0x2020), rd(PTX + 0x440));
		/* Read-only source-input ledger; no CPU-port selection or gate write. */
		for (q = 1; q <= 3; q++) {
			seq_printf(s, "cpu_candidate=%u l0=%08x port=%08x gate=%08x pending=%08x route=%08x head=%08x ns=%llu\n",
				q, rd(L0_MAP(q)), rd(L0_PORT(q)), rd(DEQ(q)), rd(PENDING(q)),
				edma ? readl(edma + EDMA_ROUTE(q)) : 0,
				rd(HEAD(q)), ktime_get_ns());
			rd_row(PTX + 0x4000 + 16 * q, row, 3);
			seq_printf(s, "cpu_queue_tx=%u raw=%08x,%08x,%08x\n",
				q, row[0], row[1], row[2]);
			for (i = 0; i < 6; i++) {
				rd_row(QM + 0x1e0000 + 96 * q + 16 * i, row, 3);
				seq_printf(s, "cpu_queue_drop=%u reason=%u raw=%08x,%08x,%08x\n",
					q, i, row[0], row[1], row[2]);
			}
		}
	}
	if (!fixture.active)
		return;
	seq_printf(s, "fixture_cpu_queue=%u head=%08x gate=%08x pending=%08x tx=%08x route=%08x rx15=%08x,%08x,%08x,%08x,%08x\n",
		fixture.cpuq, rd(QM + 0x6c000 + 16 * fixture.cpuq), rd(DEQ(fixture.cpuq)),
		rd(PENDING(fixture.cpuq)), rd(PTX + 0x4000 + 16 * fixture.cpuq),
		readl(edma + EDMA_ROUTE(fixture.cpuq)), readl(edma + 0x48000),
		readl(edma + 0x48004), readl(edma + 0x48008), readl(edma + 0x4800c),
		readl(edma + 0x48018));
	for (q = 240; q <= 241; q++) {
		h = rd(QM + 0x6c000 + 16 * q);
		seq_printf(s, "fixture_queue=%u head=%08x gate=%08x pending=%08x tx=%08x credit=%08x sign=%08x\n",
			q, h, rd(DEQ(q)), rd(PENDING(q)), rd(PTX + 0x4000 + 16 * q),
			rd(rows[PORT_CREDIT].offset), rd(rows[PORT_SIGN].offset));
		id = (h >> 12) & 0x7ff;
		tail = (h >> 1) & 0x7ff;
		for (i = 0; !(h & 1) && i < prefix_count; i++) {
			seq_printf(s, "fixture_packet q=%u position=%u id=%u raw", q, i, id);
			for (j = 0; j < 13; j++)
				seq_printf(s, " %08x", rd(QM + 0x1c0000 + 64 * id + 4 * j));
			seq_putc(s, '\n');
			if (id == tail)
				break;
			id = rd(QM + 0x90000 + 16 * id) & 0x7ff;
		}
	}
	for (i = 0; i < 16; i++) {
		index = fixture_index(i);
		seq_printf(s, "fixture_acl=%u rule", index);
		for (j = 0; j < 3; j++)
			seq_printf(s, " %08x", rd(ACL_RULE(index) + 4 * j));
		seq_puts(s, " action");
		for (j = 0; j < 5; j++)
			seq_printf(s, " %08x", rd(ACL_ACTION(index) + 4 * j));
		seq_puts(s, " counters");
		for (j = 0; j < 3; j++)
			seq_printf(s, " %08x", rd(ACL_COUNT(index) + 4 * j));
		seq_putc(s, '\n');
	}
	if (fixture.meter < 512) {
		seq_puts(s, "fixture_meter cfg");
		for (j = 0; j < 4; j++)
			seq_printf(s, " %08x", rd(METER_CFG(fixture.meter) + 4 * j));
		rd_row(METER_CREDIT(fixture.meter), credit, 2);
		seq_printf(s, " credits %08x %08x\n", credit[0], credit[1]);
		for (i = 0; i < 3; i++) {
			seq_printf(s, "fixture_color=%u", i);
			for (j = 0; j < 3; j++)
				seq_printf(s, " %08x", rd(METER_COUNT(fixture.meter, i) + 4 * j));
			seq_putc(s, '\n');
		}
	}
	show_tap_samples(s);
}

/* Bounded AC experiment on the already qualified ordinary physical queue.
 * The operator stops unrelated producers before reserve. No classifier, group
 * threshold, counter, packet link or buffer ownership is changed here.
 */
static int admission_begin(unsigned int prealloc, unsigned int shared, bool colored)
{
	u32 observed_cfg[4];
	unsigned int i;
	int err;

	if (!reserved || fault || reservation_opened || window_open ||
	    port != 4 || queue != 192 || l1 != 48 || fixture.active ||
	    cpu_remap.active || head_edit_valid || admission.active)
		return -EPERM;
	if (colored) {
		if (prealloc || shared < 6 || shared > 256)
			return -ERANGE;
	} else if (prealloc > 16 || shared > 16 || (!prealloc && !shared) ||
		   prealloc + shared > 16) {
		return -ERANGE;
	}
	err = check_maps();
	if (err)
		return err;
	for_each_set_bit(i, port_queues, QUEUES)
		if (!(rd(DEQ(i)) & 1) ||
		    (rd(PENDING(i)) & (i < 256 ? 0xfff : 0x1fff)))
			return -EBUSY;
	if (!(rd(HEAD(queue)) & 1) || (rows[ENQUEUE].saved[0] & 1) ||
	    rd(rows[ENQUEUE].offset) != rows[ENQUEUE].saved[0] ||
	    (rd(rows[DROP].offset) & 1))
		return -EBUSY;
	rd_row(rows[ADMISSION_CFG].offset, observed_cfg, 4);
	if (memcmp(observed_cfg, rows[ADMISSION_CFG].saved, sizeof(observed_cfg)))
		return -ESTALE;
	memset(&admission, 0, sizeof(admission));
	admission.prealloc = prealloc;
	admission.shared = shared;
	admission.group = (observed_cfg[0] >> 4) & 3;
	memcpy(admission.expected, observed_cfg, sizeof(observed_cfg));
	rd_row(QM + 0x4c000 + 16 * admission.group, admission.group_saved, 3);
	admission.enqueue_expected = rows[ENQUEUE].saved[0] | 1;
	admission.active = true;
	err = wr(rows[ENQUEUE].offset, admission.enqueue_expected);
	if (err)
		goto fail;
	if (!(rd(HEAD(queue)) & 1) || (rd(PENDING(queue)) & 0xfff)) {
		err = -EBUSY;
		goto fail;
	}
	/* Retain the measured static color-blind base and group/reserved bits.
	 * The optional colored trial changes only color enable and two max gaps.
	 */
	admission.expected[0] = 5 | (observed_cfg[0] & 0x30) |
		(prealloc << 6) | (shared << 21);
	admission.expected[1] = 0;
	admission.expected[2] = 0;
	admission.expected[3] = observed_cfg[3] & 0xff000000;
	if (colored) {
		/* One actual occupancy; incoming costs1/5/6 select H/H-4/H-5. */
		put_field(admission.expected, 3, 1, 1);
		put_field(admission.expected, 43, 11, 4);
		put_field(admission.expected, 65, 11, 5);
	}
	err = wr_row(rows[ADMISSION_CFG].offset, admission.expected, 4);
	if (err)
		goto fail;
	err = check_maps();
	if (err)
		goto fail;
	admission.enqueue_expected = rows[ENQUEUE].saved[0];
	err = wr(rows[ENQUEUE].offset, admission.enqueue_expected);
	if (err)
		goto fail;
	return 0;
fail:
	fault = true;
	return err;
}

/* The caller holds diag_lock. Check only configuration, never live counters. */
static int admission_color_check(void)
{
	const u32 extensions[3] = { 15, 3, 0 };
	unsigned int i, j, index;
	u32 observed[5];

	for (i = 0; i < 2; i++)
		for (j = 0; j < 3; j++)
			if (rd(ACL_EXT(j, admission_color.lists[i])) != extensions[j])
				return -ESTALE;
	for (i = 0; i < 16; i++) {
		index = admission_color.lists[i / 8] * 8 + i % 8;
		rd_row(ACL_RULE(index), observed, 3);
		if (memcmp(observed, admission_color.expected[i].rule, 3 * sizeof(u32)))
			return -ESTALE;
		rd_row(ACL_MASK(index), observed, 2);
		if (memcmp(observed, admission_color.expected[i].mask, 2 * sizeof(u32)))
			return -ESTALE;
		rd_row(ACL_ACTION(index), observed, 5);
		if (memcmp(observed, admission_color.expected[i].action, 5 * sizeof(u32)))
			return -ESTALE;
	}
	return 0;
}

static int admission_color_bind(bool enable)
{
	unsigned int i, index;
	int err;

	if (!admission.active || !admission_color.active || admission.restored ||
	    (enable && (admission.source_closed || admission_color.armed || fault)))
		return -EPERM;
	err = close_window();
	if (!err)
		err = check_maps();
	if (err)
		return err;
	for_each_set_bit(i, port_queues, QUEUES)
		if (!(rd(DEQ(i)) & 1))
			return -EBUSY;
	/* A partial enable remains owned; restoration never assumes no source. */
	if (enable)
		admission_color.armed = true;
	for (i = 0; i < 12; i++) {
		index = admission_color.lists[i / 8] * 8 + i % 8;
		put_field(admission_color.expected[i].rule, 61, 8, enable ? BIT(3) : 0);
		err = wr_row(ACL_RULE(index), admission_color.expected[i].rule, 3);
		if (err) {
			fault = true;
			return err;
		}
	}
	admission_color.armed = enable;
	return 0;
}

/* Untagged IPv4 exact UDP tuple or explicit endpoint pair, three length
 * bands, one queue. No group threshold, storage migration or counter writes. */
static int admission_color_begin(u32 list0, u32 list1, unsigned int shared,
				 bool endpoint_pair)
{
	const u32 low[3] = { 0, 243, 1267 }, high[3] = { 242, 1266, 1500 };
	const u32 extensions[3] = { 15, 3, 0 };
	u64 value, mask;
	unsigned int i, j, index, group, slice, type;
	int err;

	if (!reserved || fault || admission.active || admission_color.active ||
	    !fixture.configured || fixture.active || fixture.relay ||
	    fixture.untag != 1 || fixture.tagmask != 7 || fixture.status != 7 ||
	    list0 >= 64 || list1 >= 64 || list0 == list1 || shared < 6 || shared > 256)
		return -EPERM;
	memset(&admission_color, 0, sizeof(admission_color));
	admission_color.endpoint_pair = endpoint_pair;
	admission_color.lists[0] = list0;
	admission_color.lists[1] = list1;
	for (i = 0; i < 16; i++) {
		struct fixture_acl *entry = &admission_color.saved[i];

		index = admission_color.lists[i / 8] * 8 + i % 8;
		rd_row(ACL_RULE(index), entry->rule, 3);
		if (((entry->rule[1] >> 27) & 0x1f) || (entry->rule[2] & 0x1f))
			return -EBUSY;
		rd_row(ACL_MASK(index), entry->mask, 2);
		rd_row(ACL_ACTION(index), entry->action, 5);
		/* Preserve the unused fourth group byte-for-byte, including priority. */
		admission_color.expected[i] = *entry;
	}
	for (i = 0; i < 2; i++)
		for (j = 0; j < 3; j++)
			admission_color.ext[i][j] = rd(ACL_EXT(j, admission_color.lists[i]));
	err = admission_begin(0, shared, true);
	if (err)
		return err;
	/* The queue reservation already pins this recovery snapshot. */
	admission_color.active = true;
	for (i = 0; i < 12; i++) {
		struct fixture_acl *entry = &admission_color.expected[i];

		group = i / 4;
		slice = i % 4;
		memset(entry, 0, sizeof(*entry));
		if (slice < 2) {
			type = slice ? 4 : 5;
			value = (u64)(slice ? fixture.dip : fixture.sip) << 16;
			value |= BIT_ULL(52);
			mask = GENMASK_ULL(48, 16) | BIT_ULL(52);
			if (!endpoint_pair) {
				value |= (slice ? fixture.dport : fixture.sport) | BIT_ULL(49);
				mask = GENMASK_ULL(52, 0);
			}
		} else if (slice == 3) {
			type = 2;
			value = (u64)fixture.untag << 36;
			mask = (u64)7 << 36; /* measured untagged encoding1 */
		} else {
			type = 12;
			value = low[group];
			mask = high[group] | BIT_ULL(48) | BIT_ULL(49);
			if (!endpoint_pair) {
				value |= (u64)IPPROTO_UDP << 16;
				mask |= (u64)0xff << 16;
			}
		}
		entry->rule[0] = value;
		entry->rule[1] = value >> 32;
		put_field(entry->rule, 55, 4, type);
		/* HPPE range comparators exist only on even ACL entries. */
		if (slice == 2)
			put_field(entry->rule, 53, 1, 1);
		entry->mask[0] = mask;
		entry->mask[1] = mask >> 32;
		put_field(entry->action, 0, 1, 1);
		put_field(entry->action, 3, 14, (2 << 12) | 4);
		put_field(entry->action, 18, 32,
			  BIT(0) | BIT(1) | GENMASK(19, 8) | BIT(21) | BIT(22) | BIT(23));
		put_field(entry->action, 104, 1, 1);
		put_field(entry->action, 105, 2, group);
		put_field(entry->action, 117, 1, 1);
		put_field(entry->action, 118, 8, 192);
	}
	for (i = 0; i < 16; i++) {
		index = admission_color.lists[i / 8] * 8 + i % 8;
		err = wr_row(ACL_ACTION(index), admission_color.expected[i].action, 5);
		if (!err)
			err = wr_row(ACL_MASK(index), admission_color.expected[i].mask, 2);
		if (!err)
			err = wr_row(ACL_RULE(index), admission_color.expected[i].rule, 3);
		if (err)
			goto fail;
	}
	for (i = 0; i < 2; i++)
		for (j = 0; j < 3; j++) {
			err = wr(ACL_EXT(j, admission_color.lists[i]), extensions[j]);
			if (err)
				goto fail;
		}
	err = check_maps();
	if (!err)
		return 0;
fail:
	fault = true;
	return err;
}

static int admission_color_restore(void)
{
	unsigned int i, j, index;
	int err;

	if (admission_color.armed || !admission.source_closed || !admission.complete)
		return -EBUSY;
	err = admission_color_check();
	if (err)
		return err;
	for (i = 0; i < 16; i++) {
		index = admission_color.lists[i / 8] * 8 + i % 8;
		err = wr_row(ACL_ACTION(index), admission_color.saved[i].action, 5);
		if (!err)
			err = wr_row(ACL_MASK(index), admission_color.saved[i].mask, 2);
		if (!err)
			err = wr_row(ACL_RULE(index), admission_color.saved[i].rule, 3);
		if (err)
			return err;
	}
	for (i = 0; i < 2; i++)
		for (j = 0; j < 3; j++) {
			err = wr(ACL_EXT(j, admission_color.lists[i]), admission_color.ext[i][j]);
			if (err)
				return err;
		}
	admission_color.active = false;
	return 0;
}

/* This acknowledgement means the external finite source has finished. The
 * enqueue gate prevents later admissions; it is not an ingress pipeline fence.
 */
static int admission_stop(unsigned int acknowledged)
{
	int err;

	if (!admission.active || acknowledged != 1 || admission.restored)
		return -EPERM;
	if (admission_color.active) {
		err = admission_color_bind(false);
		if (err)
			return err;
	}
	err = close_window();
	if (err)
		return err;
	err = check_maps();
	if (err)
		goto fail;
	admission.enqueue_expected = rows[ENQUEUE].saved[0] | 1;
	err = wr(rows[ENQUEUE].offset, admission.enqueue_expected);
	if (err)
		goto fail;
	admission.source_closed = true;
	return 0;
fail:
	fault = true;
	return err;
}

static int show_status(struct seq_file *s, void *unused)
{
	DECLARE_BITMAP(seen, 2048);
	u32 d[13], h0, h1, next, id, tail, offset;
	unsigned int i, j;

	mutex_lock(&diag_lock);
	if (smp_load_acquire(&mmio_failed))
		seq_printf(s, "mmio_failure off=%06x expected=%08x observed=%08x ns=%llu\n",
			mmio_failed_offset, mmio_expected, mmio_observed, mmio_failed_ns);
	seq_printf(s, "cpu_remap active=%u installed=%u opened=%u complete=%u maps_restored=%u original_head=%08x\n",
		cpu_remap.active, cpu_remap.installed, cpu_remap.opened, cpu_remap.complete,
		cpu_remap.maps_restored, cpu_remap.head);
	if (cpu_remap.destination_edited)
		seq_printf(s, "cpu_remap_destination edited=1 restored=%u original_word10=%08x expected_word10=%08x\n",
			cpu_remap.destination_restored, cpu_remap.descriptor[10],
			cpu_remap.descriptor_expected[10]);
	if (cpu_remap.active) {
		seq_printf(s, "cpu_remap_map saved=%08x expected=%08x live=%08x port_saved=%08x port_expected=%08x port_live=%08x\n",
			cpu_remap.map_saved, cpu_remap.map_expected, rd(L0_MAP(192)),
			cpu_remap.port_saved, cpu_remap.port_expected, rd(L0_PORT(192)));
		seq_printf(s, "cpu_remap_saved c=%08x e=%08x route=%08x expected_c=%08x expected_e=%08x expected_route=%08x\n",
			cpu_remap.c_saved, cpu_remap.e_saved, cpu_remap.route_saved,
			cpu_remap.c_expected, cpu_remap.e_expected, cpu_remap.route_expected);
		seq_printf(s, "cpu_remap_select c=%08x e=%08x route=%08x rx15=%08x,%08x,%08x,%08x,%08x\n",
			rd(TM + 0x4000 + 16 * 7), rd(TM + 0x6000 + 16 * 7),
			readl(edma + EDMA_ROUTE(192)), readl(edma + 0x48000),
			readl(edma + 0x48004), readl(edma + 0x48008),
			readl(edma + 0x4800c), readl(edma + 0x48018));
		show_tap_samples(s);
	}
	if (head_edit_recorded) {
		seq_printf(s, "head_ce id=%u head=%08x valid=%u undone=%u ns=%llu reservation_opened=%u\n",
			head_edit_id, head_edit_head, head_edit_valid, head_edit_undone,
			head_edit_ns, reservation_opened);
		if (head_edit_valid && !reservation_opened)
			seq_printf(s, "restore requires head-ce-undo %u before reopening gates\n", head_edit_id);
		seq_puts(s, "head_ce_before");
		for (j = 0; j < 13; j++)
			seq_printf(s, " %08x", head_edit_before[j]);
		seq_puts(s, "\nhead_ce_after");
		for (j = 0; j < 13; j++)
			seq_printf(s, " %08x", head_edit_after[j]);
		seq_putc(s, '\n');
	}
	fixture_status(s);
	seq_printf(s, "admission_color active=%u armed=%u lists=%u,%u bands_l3=0:242,243:1266,1267:1500 dp=0,1,2 gaps=0,4,5 endpoint_pair=%u max_window_us=60000000\n",
		admission_color.active, admission_color.armed,
		admission_color.lists[0], admission_color.lists[1], admission_color.endpoint_pair);
	if (admission_color.active) {
		for (i = 0; i < 16; i++) {
			id = admission_color.lists[i / 8] * 8 + i % 8;
			seq_printf(s, "admission_acl=%u rule", id);
			for (j = 0; j < 3; j++)
				seq_printf(s, " %08x", rd(ACL_RULE(id) + 4 * j));
			seq_puts(s, " mask");
			for (j = 0; j < 2; j++)
				seq_printf(s, " %08x", rd(ACL_MASK(id) + 4 * j));
			seq_puts(s, " action");
			for (j = 0; j < 5; j++)
				seq_printf(s, " %08x", rd(ACL_ACTION(id) + 4 * j));
			rd_row(ACL_COUNT(id), d, 3);
			seq_printf(s, " counters %08x %08x %08x\n", d[0], d[1], d[2]);
		}
	}
	seq_printf(s, "admission active=%u source_closed=%u complete=%u restored=%u prealloc=%u shared=%u group=%u enqueue_expected=%08x\n",
		admission.active, admission.source_closed, admission.complete,
		admission.restored, admission.prealloc, admission.shared,
		admission.group, admission.enqueue_expected);
	/* Sequential, read-only occupancy; not a pipeline-idle acknowledgement. */
	seq_puts(s, "bm_port_used");
	for (i = 0; i < 15; i++)
		seq_printf(s, " %u:%u", i, rd(0x6001c0 + 4 * i) & 0x7ff);
	seq_putc(s, '\n');
	h0 = rd(PTX + 0x6054);
	h1 = rd(PTX + 0x6070);
	seq_printf(s, "epe_debug in=%08x out=%08x\n", h0, h1);
	seq_printf(s, "allow_writes=%u selected=%u reserved=%u fault=%u window=%u last=%d\n",
		allow_writes, queue >= 0, reserved, READ_ONCE(fault),
		READ_ONCE(window_open), last_result);
	seq_printf(s, "port=%d queue=%d l1=%d prefix=%u opened_ns=%llu closed_ns=%llu\n",
		port, queue, l1, prefix_count, opened_ns, closed_ns);
	seq_puts(s, "Snapshot reads are sequential; equal heads do not prove no in-flight packet.\n");
	if (queue < 0) {
		seq_puts(s, "Use map <physical-port> or inspect <unicast-queue>, then read status.\n");
		if (port < 1 || port > 7)
			goto out;
		for (i = 0; i < L1S; i++)
			if ((rd(L1_PORT(i)) & 0xf) == port)
				seq_printf(s, "l1_map[%u]=%08x port_map=%08x\n",
					i, rd(L1_MAP(i)), rd(L1_PORT(i)));
		for (i = 0; i < QUEUES; i++) {
			u32 map = rd(L0_MAP(i));

			if ((rd(L0_PORT(i)) & 0xf) == port)
				seq_printf(s, "queue[%u] l0_map=%08x port_map=%08x gate=%08x pending=%08x\n",
					i, map, rd(L0_PORT(i)), rd(DEQ(i)), rd(PENDING(i)));
		}
		goto out;
	}
	seq_printf(s, "cost_iterations=%u cost_reads=%u cost_ns=%llu sum=%u head_before=%08x head_after=%08x gate_after=%08x\n",
		cost_count, 3 * cost_count, cost_ns, cost_sum,
		cost_head_before, cost_head_after, cost_gate_after);
	seq_printf(s, "time_begin_ns=%llu l0_map=%08x l1_map=%08x deq=%08x pending=%08x\n",
		ktime_get_ns(), rd(L0_MAP(queue)), rd(L1_MAP(l1)),
		rd(DEQ(queue)), rd(PENDING(queue)));
	seq_printf(s, "slot_l0=%08x slot_l1=%08x slot_port=%08x ipg=%08x minmax=%08x\n",
		rd(TM + 0x10), rd(TM + 0x14), rd(TM + 0x18), rd(TM + 8), rd(TM + 4));
	seq_printf(s, "l0_port=%08x l1_port=%08x\n", rd(L0_PORT(queue)), rd(L1_PORT(l1)));
	seq_printf(s, "eligibility_l0=%08x eligibility_l1=%08x\n",
		rd(TM + 0x24000 + 16 * queue), rd(TM + 0x66000 + 16 * l1));
	h0 = rd(L0_MAP(queue));
	h1 = rd(L1_MAP(l1));
	seq_printf(s, "sp_l0_c=%08x sp_l0_e=%08x sp_l1_c=%08x sp_l1_e=%08x\n",
		rd(TM + 0x4000 + 16 * ((h0 & 0x3f) * 8 + ((h0 >> 6) & 7))),
		rd(TM + 0x6000 + 16 * ((h0 & 0x3f) * 8 + ((h0 >> 9) & 7))),
		rd(TM + 0x42000 + 16 * ((h1 & 7) * 8 + ((h1 >> 4) & 7))),
		rd(TM + 0x44000 + 16 * ((h1 & 7) * 8 + ((h1 >> 7) & 7))));
	for (i = 0; i < ROWS; i++) {
		seq_printf(s, "%s off=%06x live", rows[i].name, rows[i].offset);
		for (j = 0; j < rows[i].words; j++)
			seq_printf(s, " %08x", rd(rows[i].offset + 4 * j));
		if (reserved) {
			seq_puts(s, " saved");
			for (j = 0; j < rows[i].words; j++)
				seq_printf(s, " %08x", rows[i].saved[j]);
		}
		seq_putc(s, '\n');
	}
	/* Read word0 first even when only later group fields are needed. */
	rd_row(rows[ADMISSION_CFG].offset, d, 4);
	i = (d[0] >> 4) & 3;
	rd_row(QM + 0x4c000 + 16 * i, d, 3);
	seq_printf(s, "admission_group[%u] cfg=%08x,%08x,%08x count=%08x",
		i, d[0], d[1], d[2], rd(QM + 0x54000 + 16 * i));
	if (admission.active)
		seq_printf(s, " saved=%08x,%08x,%08x", admission.group_saved[0],
			admission.group_saved[1], admission.group_saved[2]);
	rd_row(QM + 0x56000 + 16 * queue, d, 2);
	seq_printf(s, " queue_drop_state=%08x,%08x\n", d[0], d[1]);
	seq_puts(s, "tx_raw");
	for (j = 0; j < 3; j++)
		seq_printf(s, " %08x", rd(PTX + 0x4000 + 16 * queue + 4 * j));
	seq_putc(s, '\n');
	for (i = 0; i < 6; i++) {
		seq_printf(s, "drop_raw[%u]", i);
		for (j = 0; j < 3; j++)
			seq_printf(s, " %08x", rd(QM + 0x1e0000 + 96 * queue + 16 * i + 4 * j));
		seq_putc(s, '\n');
	}
	if (reserved)
		for_each_set_bit(i, port_queues, QUEUES)
			seq_printf(s, "held_queue=%u gate=%08x saved=%08x pending=%08x head=%08x\n",
				i, rd(DEQ(i)), gate_saved[i], rd(PENDING(i)), rd(HEAD(i)));
	h0 = rd(QM + 0x6c000 + 16 * queue);
	seq_printf(s, "head_before=%08x\n", h0);
	bitmap_zero(seen, 2048);
	id = (h0 >> 12) & 0x7ff;
	tail = (h0 >> 1) & 0x7ff;
	for (i = 0; !(h0 & 1) && i < prefix_count; i++) {
		if (test_and_set_bit(id, seen)) {
			seq_printf(s, "cycle_at=%u\n", id);
			break;
		}
		offset = QM + 0x1c0000 + 64 * id;
		for (j = 0; j < ARRAY_SIZE(d); j++)
			d[j] = rd(offset + 4 * j);
		next = rd(QM + 0x90000 + 16 * id) & 0x7ff;
		seq_printf(s, "packet[%u] id=%u next=%u len=%u raw", i, id, next,
			(d[0] >> 24) | ((d[1] & 0x3f) << 8));
		for (j = 0; j < ARRAY_SIZE(d); j++)
			seq_printf(s, " %08x", d[j]);
		seq_putc(s, '\n');
		if (id == tail)
			break;
		id = next;
	}
	h1 = rd(QM + 0x6c000 + 16 * queue);
	seq_printf(s, "head_after=%08x deq_after=%08x time_end_ns=%llu\n",
		h1, rd(DEQ(queue)), ktime_get_ns());
out:
	mutex_unlock(&diag_lock);
	return 0;
}

static int status_open(struct inode *inode, struct file *file)
{
	return single_open(file, show_status, NULL);
}

static const struct file_operations status_fops = {
	.owner = THIS_MODULE, .open = status_open, .read = seq_read,
	.llseek = seq_lseek, .release = single_release,
};

static ssize_t command_write(struct file *file, const char __user *user,
			     size_t count, loff_t *position)
{
	char text[256], *cursor, *arg[10], *word;
	u32 v[8];
	unsigned int n = 0, i;
	int err = 0;

	if (!capable(CAP_SYS_RAWIO))
		return -EPERM;
	if (!count || count >= sizeof(text))
		return -E2BIG;
	if (copy_from_user(text, user, count))
		return -EFAULT;
	if (memchr(text, '\0', count))
		return -EINVAL;
	text[count] = '\0';
	cursor = strim(text);
	while ((word = strsep(&cursor, " \t\r\n"))) {
		if (!*word)
			continue;
		if (n == ARRAY_SIZE(arg))
			return -E2BIG;
		arg[n++] = word;
	}
	if (!n)
		return -EINVAL;
	mutex_lock(&diag_lock);
	if (cpu_remap.active && strcmp(arg[0], "cpu-remap-open") &&
	    strcmp(arg[0], "cpu-remap-complete") && strcmp(arg[0], "cpu-remap-destination") &&
	    strcmp(arg[0], "hold") && strcmp(arg[0], "restore")) {
		err = -EBUSY;
		goto done;
	}
	if (admission.active && strcmp(arg[0], "color-arm") &&
	    strcmp(arg[0], "admission-stop") &&
	    strcmp(arg[0], "admission-complete") && strcmp(arg[0], "set") &&
	    strcmp(arg[0], "window") && strcmp(arg[0], "hold") &&
	    strcmp(arg[0], "prefix") && strcmp(arg[0], "cost") &&
	    strcmp(arg[0], "restore")) {
		err = -EBUSY;
		goto done;
	}
	if ((!strcmp(arg[0], "color-admission") ||
	     !strcmp(arg[0], "color-endpoints")) && n == 4) {
		for (i = 0; i < 3; i++) {
			err = kstrtou32(arg[i + 1], 0, &v[i]);
			if (err)
				goto done;
		}
		err = admission_color_begin(v[0], v[1], v[2],
					    !strcmp(arg[0], "color-endpoints"));
	} else if (!strcmp(arg[0], "color-arm") && n == 1) {
		err = admission_color_bind(true);
	} else if (!strcmp(arg[0], "admission") && n == 3) {
		err = kstrtou32(arg[1], 0, &v[0]);
		if (!err)
			err = kstrtou32(arg[2], 0, &v[1]);
		if (!err)
			err = admission_begin(v[0], v[1], false);
	} else if (!strcmp(arg[0], "admission-stop") && n == 2) {
		err = kstrtou32(arg[1], 0, &v[0]);
		if (!err)
			err = admission_stop(v[0]);
	} else if (!strcmp(arg[0], "admission-complete") && n == 2) {
		err = kstrtou32(arg[1], 0, &v[0]);
		if (!err && (!admission.active || !admission.source_closed ||
		    admission.restored || window_open || v[0] != 1 ||
		    !(rd(HEAD(queue)) & 1) || (rd(PENDING(queue)) & 0xfff)))
			err = -EPERM;
		if (!err)
			err = check_maps();
		if (!err)
			admission.complete = true;
	} else if (!strcmp(arg[0], "cpu-remap") && n == 3) {
		err = kstrtou32(arg[1], 0, &v[0]);
		if (!err)
			err = cpu_remap_begin(v[0], arg[2]);
	} else if (!strcmp(arg[0], "cpu-remap-destination") && n == 1) {
		err = cpu_remap_destination();
	} else if (!strcmp(arg[0], "cpu-remap-open") && n == 3) {
		err = kstrtou32(arg[1], 0, &v[0]);
		if (!err)
			err = kstrtou32(arg[2], 0, &v[1]);
		if (!err)
			err = cpu_remap_open(v[0], v[1]);
	} else if (!strcmp(arg[0], "cpu-remap-complete") && n == 2) {
		err = kstrtou32(arg[1], 0, &v[0]);
		if (!err && (!cpu_remap.active || !cpu_remap.opened ||
		    window_open || v[0] != 1 || !(rd(HEAD(192)) & 1) ||
		    (rd(PENDING(192)) & 0xfff)))
			err = -EPERM;
		if (!err)
			cpu_remap.complete = true;
	} else if (!strcmp(arg[0], "fixture-inventory") && n == 1) {
		fixture.inventory = true;
	} else if (!strcmp(arg[0], "fixture-config") && n == 8) {
		if (reserved || fixture.active) {
			err = -EBUSY;
			goto done;
		}
		for (i = 0; i < 7; i++) {
			err = kstrtou32(arg[i + 1], 0, &v[i]);
			if (err)
				goto done;
		}
		if (!v[2] || v[2] > 65535 || !v[3] || v[3] > 65535 ||
		    v[4] > 255 || (v[4] & 3) == 0 || !v[5] || v[5] > 4094 ||
		    !v[6] || v[6] > 4094 || v[5] == v[6]) {
			err = -ERANGE;
			goto done;
		}
		fixture.sip = v[0];
		fixture.dip = v[1];
		fixture.sport = v[2];
		fixture.dport = v[3];
		fixture.tos = v[4];
		fixture.vida = v[5];
		fixture.vidb = v[6];
		fixture.untag = 0;
		fixture.tagged = 1;
		fixture.tagmask = 7;
		fixture.status = 7;
		fixture.match_tos = 1;
		fixture.direct = 0;
		fixture.relay = 0;
		fixture.return_post = 1;
		fixture.return_tagmask = 7;
		fixture.return_vidmask = 0xfff;
		fixture.return_sources = 0xff;
		fixture.configured = true;
	} else if (!strcmp(arg[0], "fixture-match") && n == 7) {
		if (!fixture.configured || reserved || fixture.active) {
			err = -EBUSY;
			goto done;
		}
		for (i = 0; i < 6; i++) {
			err = kstrtou32(arg[i + 1], 0, &v[i]);
			if (err)
				goto done;
		}
		if (v[0] > 7 || v[1] > 7 || v[2] > 7 || v[3] > 7 || v[4] > 1 || v[5] > 1 || (v[5] && fixture.relay)) {
			err = -ERANGE;
			goto done;
		}
		fixture.untag = v[0];
		fixture.tagged = v[1];
		fixture.tagmask = v[2];
		fixture.status = v[3];
		fixture.match_tos = v[4];
		fixture.direct = v[5];
	} else if (!strcmp(arg[0], "fixture-relay") && n == 2) {
		if (!fixture.configured || reserved || fixture.active || fixture.direct) {
			err = -EBUSY;
			goto done;
		}
		err = kstrtou32(arg[1], 0, &v[0]);
		if (!err && (v[0] < 1 || v[0] > 3))
			err = -ERANGE;
		if (!err)
			fixture.relay = v[0];
	} else if (!strcmp(arg[0], "fixture-return") && n == 5) {
		if (!fixture.configured || !fixture.relay || reserved || fixture.active) {
			err = -EBUSY;
			goto done;
		}
		for (i = 0; i < 4; i++) {
			err = kstrtou32(arg[i + 1], 0, &v[i]);
			if (err)
				goto done;
		}
		if (v[0] > 1 || v[1] > 7 || v[2] > 0xfff || !v[3] || v[3] > 0xff ||
		    (!v[1] && !v[2] && (v[3] & BIT(3)))) {
			err = -ERANGE;
			goto done;
		}
		fixture.return_post = v[0];
		fixture.return_tagmask = v[1];
		fixture.return_vidmask = v[2];
		fixture.return_sources = v[3];
	} else if (!strcmp(arg[0], "fixture-relay-complete") && n == 2) {
		err = kstrtou32(arg[1], 0, &v[0]);
		if (!err && (!fixture.active || !fixture.relay || !fixture.relay_opened ||
		    fixture.armed || window_open || v[0] != 1 ||
		    (rd(PENDING(fixture.cpuq)) & 0xfff)))
			err = -EPERM;
		if (!err)
			fixture.relay_complete = true;
	} else if (!strcmp(arg[0], "head-ce") && n == 2) {
		err = kstrtou32(arg[1], 0, &v[0]);
		if (!err)
			err = head_ce(v[0], false);
	} else if (!strcmp(arg[0], "head-ce-undo") && n == 2) {
		err = kstrtou32(arg[1], 0, &v[0]);
		if (!err)
			err = head_ce(v[0], true);
	} else if (!strcmp(arg[0], "fixture-reserve") && n == 6) {
		for (i = 0; i < 4; i++) {
			err = kstrtou32(arg[i + 1], 0, &v[i]);
			if (err)
				goto done;
		}
		err = fixture_begin(v[0], v[1], v[2], v[3], arg[5]);
	} else if (!strcmp(arg[0], "fixture-service1") && n == 3) {
		err = kstrtou32(arg[1], 0, &v[0]);
		if (!err)
			err = kstrtou32(arg[2], 0, &v[1]);
		if (!err)
			err = fixture_service1(v[0], v[1]);
	} else if (!strcmp(arg[0], "fixture-enable7") && n == 2) {
		err = kstrtou32(arg[1], 0, &v[0]);
		if (!err)
			err = fixture_enable7(v[0]);
	} else if (!strcmp(arg[0], "fixture-arm") && n == 1) {
		err = fixture.active && !fault ? close_window() : -EPERM;
		if (!err)
			err = fixture_check();
		if (!err)
			err = fixture_bind(0, true);
	} else if (!strcmp(arg[0], "fixture-stop") && n == 1) {
		err = fixture.active ? close_window() : -EINVAL;
		if (!err)
			err = fixture_bind(0, false);
	} else if (!strcmp(arg[0], "fixture-mode") && n == 2) {
		err = kstrtou32(arg[1], 0, &v[0]);
		if (!err)
			err = fixture_mode(v[0]);
	} else if (!strcmp(arg[0], "fixture-meter") && n == 7) {
		for (i = 0; i < 6; i++) {
			err = kstrtou32(arg[i + 1], 0, &v[i]);
			if (err)
				goto done;
		}
		err = fixture_meter(v);
	} else if (!strcmp(arg[0], "fixture-drain") && n == 4) {
		for (i = 0; i < 3; i++) {
			err = kstrtou32(arg[i + 1], 0, &v[i]);
			if (err)
				goto done;
		}
		err = fixture_drain(v[0], v[1], v[2]);
	} else if (!strcmp(arg[0], "fixture-grant") && n == 5) {
		for (i = 0; i < 4; i++) {
			err = kstrtou32(arg[i + 1], 0, &v[i]);
			if (err)
				goto done;
		}
		err = fixture_grant(v[0], v[1], v[2], v[3]);
	} else if (!strcmp(arg[0], "map") && n == 2) {
		err = kstrtou32(arg[1], 0, &v[0]);
		if (reserved)
			err = -EBUSY;
		if (!err && (v[0] < 1 || v[0] > 7))
			err = -ERANGE;
		if (!err) {
			port = v[0];
			queue = -1;
			l1 = -1;
		}
	} else if (!strcmp(arg[0], "inspect") && n == 2) {
		err = kstrtou32(arg[1], 0, &v[0]);
		if (!err && v[0] >= 256)
			err = -ERANGE;
		if (!err) {
			v[1] = rd(L0_MAP(v[0])) & 0x3f;
			v[2] = rd(L0_PORT(v[0])) & 0xf;
			err = select_path(v[2], v[0], v[1]);
		}
	} else if (!strcmp(arg[0], "select") && n == 4) {
		for (i = 0; i < 3; i++) {
			err = kstrtou32(arg[i + 1], 0, &v[i]);
			if (err)
				goto done;
		}
		err = select_path(v[0], v[1], v[2]);
	} else if (!strcmp(arg[0], "prefix") && n == 2) {
		err = kstrtou32(arg[1], 0, &v[0]);
		if (!err && v[0] <= DIAG_PREFIX_MAX)
			prefix_count = v[0];
		else
			err = -EINVAL;
	} else if (!strcmp(arg[0], "reserve") && n == 1) {
		err = reserve_path();
	} else if (!strcmp(arg[0], "hold") && n == 1) {
		err = reserved ? close_window() : -EINVAL;
	} else if (!strcmp(arg[0], "restore") && n == 1) {
		if (cpu_remap.active)
			err = cpu_remap_end();
		else
			err = fixture.active ? fixture_end() : restore_path();
	} else if (!strcmp(arg[0], "cost") && n == 2) {
		err = kstrtou32(arg[1], 0, &v[0]);
		if (!err)
			err = measure_cost(v[0]);
	} else if (!strcmp(arg[0], "window") && n == 2) {
		err = kstrtou32(arg[1], 0, &v[0]);
		if (!err)
			err = fixture.active ? -EBUSY : open_window_on(queue, v[0], false);
	} else if (!strcmp(arg[0], "set") && n >= 3 && n <= 5) {
		if (fixture.active) {
			err = -EBUSY;
			goto done;
		}
		for (i = 0; i < n - 2; i++) {
			err = kstrtou32(arg[i + 2], 0, &v[i]);
			if (err)
				goto done;
		}
		err = set_row(arg[1], v, n - 2);
	} else {
		err = -EINVAL;
	}
done:
	last_result = err;
	mutex_unlock(&diag_lock);
	return err ? err : count;
}

static const struct file_operations command_fops = {
	.owner = THIS_MODULE, .write = command_write,
};

static int __init diag_init(void)
{
	struct device_node *node;
	struct resource resource;
	struct dentry *entry;
	int err;

	node = of_find_compatible_node(NULL, NULL, "qualcomm,ipq8074-ppe");
	if (!node)
		return -ENODEV;
	err = of_address_to_resource(node, 0, &resource);
	of_node_put(node);
	if (err)
		return err;
	if (resource.start != PPE_PHYS || resource_size(&resource) < 0x900000)
		return -ENODEV;
	/* Native driver already owns this resource. This is an explicit diagnostic
	 * alias, not a second driver or request_mem_region ownership claim.
	 * Native DT maps 9 MiB. Pinned HPPE QM packet metadata/drop tables
	 * explicitly occupy offsets 0x9c0000..0x9f7fff, so this diagnostic
	 * maps their documented 10 MiB aperture without changing the DT.
	 */
	ppe = ioremap(resource.start, PPE_SPAN);
	if (!ppe)
		return -ENOMEM;
	node = of_find_compatible_node(NULL, NULL, "qualcomm,ipq8074-edma");
	if (node) {
		err = of_address_to_resource(node, 0, &resource);
		of_node_put(node);
		if (!err && resource.start == PPE_PHYS + 0xb00000 &&
		    resource_size(&resource) >= 0x60000)
			edma = ioremap(resource.start, resource_size(&resource));
	}
	hrtimer_setup(&close_timer, close_expired, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	directory = debugfs_create_dir("qdx_ppe_diag", NULL);
	if (IS_ERR_OR_NULL(directory)) {
		err = directory ? PTR_ERR(directory) : -ENOMEM;
		goto unmap;
	}
	entry = debugfs_create_file("status", 0400, directory, NULL, &status_fops);
	if (IS_ERR_OR_NULL(entry)) {
		err = entry ? PTR_ERR(entry) : -ENOMEM;
		goto remove;
	}
	entry = debugfs_create_file("command", 0200, directory, NULL, &command_fops);
	if (IS_ERR_OR_NULL(entry)) {
		err = entry ? PTR_ERR(entry) : -ENOMEM;
		goto remove;
	}
	pr_info("qdx_ppe_diag: read-only until explicit select/reserve; allow_writes=%u\n", allow_writes);
	return 0;
remove:
	debugfs_remove_recursive(directory);
unmap:
	if (edma)
		iounmap(edma);
	iounmap(ppe);
	return err;
}

static void __exit diag_exit(void)
{
	/* Successful reserve pins the module until explicit successful restore. */
	debugfs_remove_recursive(directory);
	hrtimer_cancel(&close_timer);
	if (edma)
		iounmap(edma);
	iounmap(ppe);
}
module_init(diag_init);
module_exit(diag_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Isolated bounded HPPE queue/shaper diagnostic for QDX exploration");
