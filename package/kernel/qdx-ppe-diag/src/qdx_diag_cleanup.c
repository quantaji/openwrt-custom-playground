// SPDX-License-Identifier: GPL-2.0-only
/* One-shot recovery of RUN1619's retained CPU-remap reservation.
 * No packet memory is mapped or freed. The existing diagnostic remains owner.
 * Keep enqueue closed until that owner's explicit completion/restore.
 */
#include <linux/module.h>
#include <linux/io.h>
#include <linux/iopoll.h>

static bool allow_cleanup;
module_param(allow_cleanup, bool, 0400);
static int cleanup_result = -EINPROGRESS;
module_param(cleanup_result, int, 0400);

static int __init cleanup_init(void)
{
	void __iomem *ppe;
	u32 value;
	unsigned int q;
	int error;

	if (!allow_cleanup)
		return -EPERM;
	ppe = ioremap(0x3a000000, 0xa00000);
	if (!ppe)
		return -ENOMEM;
	if (readl(ppe + 0x402c00) != 0x00401fc0 ||
	    readl(ppe + 0x408c00) != 0 ||
	    readl(ppe + 0x404070) != 0x60 ||
	    readl(ppe + 0x406070) != 0x60 ||
	    readl(ppe + 0x85cc00) != 0) {
		error = -ESTALE;
		goto out;
	}
	for (q = 192; q < 208; q++)
		if (!(readl(ppe + 0x430000 + 16 * q) & 1)) {
			error = -EBUSY;
			goto out;
		}
	/* Native ppe_qdx_queue_flush uses this exact command and busy/status
	 * contract after moving a reserved queue onto the CPU0 scheduler.
	 */
	error = readl_poll_timeout(ppe + 0x800000, value,
		!(value & BIT(31)), 10, 100000);
	if (error)
		goto out;
	writel(1, ppe + 0x85cc00);
	if (readl(ppe + 0x85cc00) != 1) {
		error = -EIO;
		goto out;
	}
	value &= ~(GENMASK(8, 0) | BIT(10) | GENMASK(23, 21) | BIT(24));
	writel(value | 192 | BIT(31), ppe + 0x800000);
	error = readl_poll_timeout(ppe + 0x800000, value,
		!(value & BIT(31)), 10, 100000);
	if (!error && (!(value & BIT(10)) ||
	    (readl(ppe + 0x85cc00) != 1) ||
	    (readl(ppe + 0x84ec00) & 0xfff)))
		error = -EIO;
out:
	cleanup_result = error;
	pr_info("qdx_diag_cleanup result=%d; owner must inspect and restore retained reservation\n", error);
	iounmap(ppe);
	return 0;
}
static void __exit cleanup_exit(void) {}
module_init(cleanup_init);
module_exit(cleanup_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("One-shot guarded cleanup of retained RUN1619 queue");
