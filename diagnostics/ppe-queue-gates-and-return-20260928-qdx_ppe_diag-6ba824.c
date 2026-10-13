// SPDX-License-Identifier: GPL-2.0-only
/* Isolated IPQ8074 HPPE diagnostic. No production driver interface is proposed.
 * Register evidence: qca-ssdk 446db12b1fd3bca2e61e45cb01c4ad52cfddd95b.
 * The operator must isolate the selected physical port and stop other writers.
 */
#include <linux/bitmap.h>
#include <linux/capability.h>
#include <linux/debugfs.h>
#include <linux/hrtimer.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of_address.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>

#define TM 0x400000
#define QM 0x800000
#define PTX 0x020000
#define PPE_PHYS 0x3a000000
#define PPE_SPAN 0xa00000
#define QUEUES 300
#define L1S 64
#define PREFIX_MAX 64
#define L0_MAP(q) (TM + 0x2000 + 16 * (q))
#define L1_MAP(l) (TM + 0x40000 + 16 * (l))
#define L0_PORT(q) (TM + 0x8000 + 16 * (q))
#define L1_PORT(l) (TM + 0x46000 + 16 * (l))
#define DEQ(q) (TM + 0x30000 + 16 * (q))
#define PENDING(q) (QM + ((q) < 256 ? 0x4e000 + 16 * (q) : \
                         0x52000 + 16 * ((q) - 256)))

enum { L0_CFG, L0_CREDIT, L0_LENGTH, L1_CFG, L1_CREDIT, L1_LENGTH,
       PORT_CFG, PORT_CREDIT, PORT_SIGN, PORT_LENGTH, ENQUEUE, DROP, ROWS };

struct diag_row {
	const char *name;
	u32 offset, words, mask[3], saved[3];
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
};

static void __iomem *ppe;
static struct dentry *directory;
static DEFINE_MUTEX(diag_lock);
static DEFINE_SPINLOCK(window_lock);
static struct hrtimer close_timer;
static bool allow_writes;
module_param(allow_writes, bool, 0400);
MODULE_PARM_DESC(allow_writes, "Allow explicit reservation and bounded MMIO experiments");
static int port = -1, queue = -1, l1 = -1;
static unsigned int prefix_count = 16;
static bool reserved, window_open, fault;
static u32 l0_map[QUEUES], l1_map[L1S], gate_saved[QUEUES];
static u32 l0_port[QUEUES], l1_port[L1S];
static DECLARE_BITMAP(port_queues, QUEUES);
static u64 opened_ns, closed_ns;
static int last_result;
static unsigned int cost_count;
static u64 cost_ns;
static u32 cost_sum, cost_head_before, cost_head_after, cost_gate_after;

static u32 rd(u32 offset)
{
	return readl(ppe + offset);
}

/* Call only for allowlisted offsets. A readback is not a pipeline drain fence. */
static int wr(u32 offset, u32 value)
{
	writel(value, ppe + offset);
	return rd(offset) == value ? 0 : -EIO;
}

/* HPPE latches whole entries: finish all words before any readback. */
static int wr_row(u32 offset, const u32 *values, unsigned int words)
{
	unsigned int i;
	int err = 0;

	for (i = 0; i < words; i++)
		writel(values[i], ppe + offset + 4 * i);
	for (i = 0; i < words; i++)
		if (rd(offset + 4 * i) != values[i])
			err = -EIO;
	return err;
}

static int close_window(void)
{
	unsigned long flags;
	int err = 0;

	hrtimer_cancel(&close_timer);
	spin_lock_irqsave(&window_lock, flags);
	if (reserved) {
		err = wr(DEQ(queue), gate_saved[queue] | 1);
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
	if (wr(DEQ(queue), gate_saved[queue] | 1))
		fault = true;
	closed_ns = ktime_get_ns();
	window_open = false;
	spin_unlock_irqrestore(&window_lock, flags);
	return HRTIMER_NORESTART;
}

/* Reject a concurrent driver/FW scheduler remap; there is no shared native lock. */
static int check_maps(void)
{
	unsigned int i;

	for (i = 0; i < QUEUES; i++)
		if (rd(L0_MAP(i)) != l0_map[i] || rd(L0_PORT(i)) != l0_port[i])
			return -ESTALE;
	for (i = 0; i < L1S; i++)
		if (rd(L1_MAP(i)) != l1_map[i] || rd(L1_PORT(i)) != l1_port[i])
			return -ESTALE;
	return 0;
}

static int select_path(unsigned int p, unsigned int q, unsigned int s)
{
	if (reserved)
		return -EBUSY;
	/* Do not gate CPU0, internal loopback7, or an arbitrary virtual port. */
	if (p < 1 || p > 6 || q >= 256 || s >= L1S)
		return -ERANGE;
	if ((rd(L0_MAP(q)) & 0x3f) != s || (rd(L1_MAP(s)) & 0xf) != p ||
	    (rd(L0_PORT(q)) & 0xf) != p || (rd(L1_PORT(s)) & 0xf) != p)
		return -EXDEV;
	port = p;
	queue = q;
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
	err = freeze_refresh(true);
	if (err)
		goto fail;
	/* Credits and sign are checked before the original refresh is resumed. */
	for (i = 0; i < ROWS; i++) {
		if (i == L0_CFG || i == L1_CFG || i == PORT_CFG)
			continue;
		err = wr_row(rows[i].offset, rows[i].saved, rows[i].words);
		if (err)
			goto fail;
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
	u32 row[3];
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

static int open_window(unsigned int usec)
{
	unsigned long flags;
	unsigned int i;
	int err;

	if (!reserved || fault || usec < 1 || usec > 1000000)
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
	opened_ns = ktime_get_ns();
	err = wr(DEQ(queue), gate_saved[queue] & ~1);
	if (!err) {
		window_open = true;
		hrtimer_start(&close_timer, ns_to_ktime((u64)usec * 1000), HRTIMER_MODE_REL);
	} else {
		fault = true;
		wr(DEQ(queue), gate_saved[queue] | 1);
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

static int show_status(struct seq_file *s, void *unused)
{
	DECLARE_BITMAP(seen, 2048);
	u32 d[13], h0, h1, next, id, tail, offset;
	unsigned int i, j;

	mutex_lock(&diag_lock);
	seq_printf(s, "allow_writes=%u selected=%u reserved=%u fault=%u window=%u last=%d\n",
		allow_writes, queue >= 0, reserved, READ_ONCE(fault),
		READ_ONCE(window_open), last_result);
	seq_printf(s, "port=%d queue=%d l1=%d prefix=%u opened_ns=%llu closed_ns=%llu\n",
		port, queue, l1, prefix_count, opened_ns, closed_ns);
	seq_puts(s, "Snapshot reads are sequential; equal heads do not prove no in-flight packet.\n");
	if (queue < 0) {
		seq_puts(s, "Use map <physical-port> or inspect <unicast-queue>, then read status.\n");
		if (port < 1 || port > 6)
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
			seq_printf(s, "held_queue=%u gate=%08x saved=%08x pending=%08x\n",
				i, rd(DEQ(i)), gate_saved[i], rd(PENDING(i)));
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
	char text[192], *cursor, *arg[6], *word;
	u32 v[3];
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
	if (!strcmp(arg[0], "map") && n == 2) {
		err = kstrtou32(arg[1], 0, &v[0]);
		if (reserved)
			err = -EBUSY;
		if (!err && (v[0] < 1 || v[0] > 6))
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
		if (!err && v[0] <= PREFIX_MAX)
			prefix_count = v[0];
		else
			err = -EINVAL;
	} else if (!strcmp(arg[0], "reserve") && n == 1) {
		err = reserve_path();
	} else if (!strcmp(arg[0], "hold") && n == 1) {
		err = reserved ? close_window() : -EINVAL;
	} else if (!strcmp(arg[0], "restore") && n == 1) {
		err = restore_path();
	} else if (!strcmp(arg[0], "cost") && n == 2) {
		err = kstrtou32(arg[1], 0, &v[0]);
		if (!err)
			err = measure_cost(v[0]);
	} else if (!strcmp(arg[0], "window") && n == 2) {
		err = kstrtou32(arg[1], 0, &v[0]);
		if (!err)
			err = open_window(v[0]);
	} else if (!strcmp(arg[0], "set") && n >= 3 && n <= 5) {
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
	iounmap(ppe);
	return err;
}

static void __exit diag_exit(void)
{
	/* Successful reserve pins the module until explicit successful restore. */
	debugfs_remove_recursive(directory);
	hrtimer_cancel(&close_timer);
	iounmap(ppe);
}
module_init(diag_init);
module_exit(diag_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Isolated bounded HPPE queue/shaper diagnostic for QDX exploration");
