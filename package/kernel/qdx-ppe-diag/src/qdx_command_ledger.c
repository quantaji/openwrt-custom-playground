// SPDX-License-Identifier: GPL-2.0-only
/* Isolated bounded control ledger; observes, never edits commands. */
#include <linux/debugfs.h>
#include <linux/kprobes.h>
#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/spinlock.h>
#include <linux/vmalloc.h>
#include <linux/unaligned.h>
#include <asm/ptrace.h>

#define LEDGER_RECORDS 8192
#define LEDGER_BYTES 2048
struct ledger_record {
	u64 when;
	unsigned long core;
	u32 accessible;
	u16 copied;
	u8 direction;
	u8 bytes[LEDGER_BYTES];
};
static struct ledger_record *records;
static DEFINE_SPINLOCK(ledger_lock);
static u32 used;
static u64 overflow, truncated;
static bool enabled;
static struct dentry *directory;

static int ledger_capture(struct kprobe *probe, struct pt_regs *regs)
{
	struct ledger_record *record;
	const void *data;
	unsigned long flags;
	size_t accessible;
	bool incoming = !strcmp(probe->symbol_name, "qdx_command_receive");
	bool ipv4_notify = false;

	data = (const void *)regs->regs[incoming ? 2 : 1];
	accessible = regs->regs[incoming ? 3 : 2];
	/* Keep all requests/replies, physical ports, PPE and EDMA real ports/rings.
	 * Unrelated periodic virtual-port reports are not this experiment's ledger.
	 */
	if (incoming && accessible >= 40 && get_unaligned_le32(data + 8) == 5) {
		u32 interface = get_unaligned_le32(data + 4);

		if (interface != 3 && interface != 4 && interface != 197 &&
		    interface != 196 && interface != 156 && interface != 161)
			return 0;
		ipv4_notify = interface == 161;
		if (interface == 197 && get_unaligned_le32(data + 12) == 0 &&
		    accessible >= 44 && get_unaligned_le16(data + 40) >= 8)
			return 0;
	}
	/* IPv4 notifications retain the actual received extent so a short/stale
	 * declared length cannot hide bytes needed to diagnose the header.
	 * All other traffic keeps the previous bounded declared-length capture.
	 */
	if (accessible >= 40 && !ipv4_notify)
		accessible = min_t(size_t, accessible, 40 + get_unaligned_le16(data + 2));
	spin_lock_irqsave(&ledger_lock, flags);
	if (!READ_ONCE(enabled))
		goto out;
	if (used == LEDGER_RECORDS) {
		overflow++;
		goto out;
	}
	record = &records[used];
	record->when = ktime_get_mono_fast_ns();
	record->core = regs->regs[0];
	record->accessible = accessible;
	record->copied = min_t(size_t, accessible, LEDGER_BYTES);
	record->direction = incoming;
	if (accessible > LEDGER_BYTES)
		truncated++;
	memcpy(record->bytes, data, record->copied);
	used++;
out:
	spin_unlock_irqrestore(&ledger_lock, flags);
	return 0;
}
NOKPROBE_SYMBOL(ledger_capture);

static struct kprobe probes[] = {
	{ .symbol_name = "qdx_io_command", .pre_handler = ledger_capture },
	{ .symbol_name = "qdx_command_receive", .pre_handler = ledger_capture },
};

static int ledger_show(struct seq_file *seq, void *unused)
{
	unsigned long flags;
	u32 count, i;
	u64 lost, clipped;

	spin_lock_irqsave(&ledger_lock, flags);
	if (READ_ONCE(enabled)) {
		spin_unlock_irqrestore(&ledger_lock, flags);
		return -EBUSY;
	}
	count = used;
	lost = overflow;
	clipped = truncated;
	spin_unlock_irqrestore(&ledger_lock, flags);
	seq_printf(seq, "records=%u overflow=%llu truncated=%llu\n", count, lost, clipped);
	for (i = 0; i < count; i++) {
		struct ledger_record *r = &records[i];
		u32 j;

		seq_printf(seq, "%llu %u %lx %u %u ", r->when, r->direction,
			   r->core, r->accessible, r->copied);
		for (j = 0; j < r->copied; j++)
			seq_printf(seq, "%02x", r->bytes[j]);
		seq_putc(seq, '\n');
	}
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(ledger);

static int __init ledger_init(void)
{
	int error;

	records = vzalloc(array_size(LEDGER_RECORDS, sizeof(*records)));
	if (!records)
		return -ENOMEM;
	error = register_kprobe(&probes[0]);
	if (error)
		goto free_records;
	error = register_kprobe(&probes[1]);
	if (error)
		goto remove_first;
	directory = debugfs_create_dir("qdx_command_ledger", NULL);
	if (IS_ERR(directory)) {
		error = PTR_ERR(directory);
		goto remove_second;
	}
	debugfs_create_bool("enabled", 0600, directory, &enabled);
	debugfs_create_file("records", 0400, directory, NULL, &ledger_fops);
	return 0;
remove_second:
	unregister_kprobe(&probes[1]);
remove_first:
	unregister_kprobe(&probes[0]);
free_records:
	vfree(records);
	return error;
}

static void __exit ledger_exit(void)
{
	debugfs_remove_recursive(directory);
	unregister_kprobe(&probes[1]);
	unregister_kprobe(&probes[0]);
	vfree(records);
}
module_init(ledger_init);
module_exit(ledger_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Read-only control ledger for isolated QDX diagnostics");
