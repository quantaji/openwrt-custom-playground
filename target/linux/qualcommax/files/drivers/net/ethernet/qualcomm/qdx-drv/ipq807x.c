// SPDX-License-Identifier: GPL-2.0-only
/* IPQ807x hardware operations for the two NSS cores. */
#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/mailbox_client.h>
#include <linux/of_address.h>
#include <linux/of_reserved_mem.h>
#include <linux/platform_device.h>
#include <linux/regulator/consumer.h>
#include <linux/reset.h>
#include <linux/sizes.h>
#include <linux/slab.h>

#include "qdx.h"

#define QDX_CSM_RESET	0x04
#define QDX_CSM_BAR	0x08
#define QDX_CSM_AMC	0x0c
#define QDX_CSM_BOOT	0x10
#define QDX_CSM_INT2	0x40
#define QDX_CSM_INT3	0x44
#define QDX_CSM_FETCH	0x48
#define QDX_CORE_RATE	748800000UL
#define QDX_CORE_UV	912000
#define QDX_IMAGE_WINDOW	SZ_8M

struct qdx_mailbox {
	struct mbox_client client;
	struct mbox_chan *channel;
	spinlock_t lock;
	u32 token;
	bool done;
	bool pending;
	bool frozen;
	int result;
};

struct qdx_hw {
	struct mutex operation_lock;
	struct clk_bulk_data clocks[27];
	struct regulator *supply;
	struct reset_control *core_reset[QDX_CORES][5];
	struct reset_control *master_reset[6];
	struct qdx_mailbox mailbox[QDX_CORES][QDX_DOORBELLS];
	bool powered;
	bool clocked;
	bool executed;
};

/* Only owned support rates are changed; shared Ethernet fabric keeps its rate. */
static const struct {
	const char *name;
	unsigned long rate;
} qdx_clocks[] = {
	{ "noc", 0 }, { "ptp-ref", 0 }, { "csr", 0 },
	{ "cfg", 100000000 }, { "imem", 400000000 }, { "qosgen", 0 },
	{ "mem-noc", 0 }, { "snoc", 0 }, { "timeout", 0 },
	{ "ce-axi", 200000000 }, { "ce-apb", 200000000 },
	{ "noc-ce-axi", 200000000 }, { "noc-ce-apb", 200000000 },
	{ "crypto", 0 }, { "noc-crypto", 0 },
	{ "core0", QDX_CORE_RATE }, { "noc-ahb0", 200000000 },
	{ "ahb0", 200000000 }, { "axi0", 0 }, { "mpt0", 25000000 },
	{ "nc-axi0", 0 },
	{ "core1", QDX_CORE_RATE }, { "noc-ahb1", 200000000 },
	{ "ahb1", 200000000 }, { "axi1", 0 }, { "mpt1", 25000000 },
	{ "nc-axi1", 0 },
};

static void qdx_mailbox_done(struct mbox_client *client, void *message, int result)
{
	struct qdx_mailbox *mailbox = container_of(client, struct qdx_mailbox, client);

	/* The caller holds mailbox->lock; do not acquire it from this callback. */
	if (message != &mailbox->token || !READ_ONCE(mailbox->pending)) {
		WRITE_ONCE(mailbox->frozen, true);
		return;
	}
	WRITE_ONCE(mailbox->result, result);
	WRITE_ONCE(mailbox->done, true);
}

static void qdx_mailbox_free(void *data)
{
	mbox_free_channel(data);
}

int qdx_hw_get(struct qdx *qdx)
{
	static const char * const reset_names[] = { "clkrst", "axi", "ahb", "nc-axi", "core" };
	static const char * const master_names[] = {
		"ce-axi", "ce-apb", "noc-ce-axi", "noc-ce-apb", "crypto", "noc-crypto"
	};
	static const char * const mailbox_names[] = {
		"empty", "command", "unblocked", "coredump", "paged"
	};
	struct platform_device *pdev = to_platform_device(qdx->dev);
	struct device_node *node;
	struct reserved_mem *reserved;
	struct qdx_hw *hw;
	void __iomem *image;
	struct resource *resource;
	char name[24];
	int i, j, err;

	hw = devm_kzalloc(qdx->dev, sizeof(*hw), GFP_KERNEL);
	if (!hw)
		return -ENOMEM;
	qdx->hw = hw;
	mutex_init(&hw->operation_lock);
	for (i = 0; i < ARRAY_SIZE(qdx_clocks); i++)
		hw->clocks[i].id = qdx_clocks[i].name;
	err = devm_clk_bulk_get(qdx->dev, ARRAY_SIZE(hw->clocks), hw->clocks);
	if (err)
		return dev_err_probe(qdx->dev, err, "NSS clocks unavailable\n");
	hw->supply = devm_regulator_get(qdx->dev, "npu");
	if (IS_ERR(hw->supply))
		return dev_err_probe(qdx->dev, PTR_ERR(hw->supply), "NSS supply unavailable\n");

	node = of_parse_phandle(qdx->dev->of_node, "memory-region", 0);
	if (!node)
		return -EINVAL;
	reserved = of_property_read_bool(node, "no-map") ? of_reserved_mem_lookup(node) : NULL;
	of_node_put(node);
	if (!reserved || reserved->base != 0x40000000 || reserved->size != SZ_16M)
		return dev_err_probe(qdx->dev, -EINVAL, "invalid NSS firmware reservation\n");
	image = devm_ioremap(qdx->dev, reserved->base, reserved->size);
	if (!image)
		return -ENOMEM;

	for (i = 0; i < QDX_CORES; i++) {
		struct qdx_core *core = &qdx->cores[i];

		snprintf(name, sizeof(name), "csm%d", i);
		resource = platform_get_resource_byname(pdev, IORESOURCE_MEM, name);
		if (!resource || resource_size(resource) != SZ_4K ||
		    resource->start != 0x39000000 + i * 0x400000)
			return -EINVAL;
		core->csm_phys = resource->start;
		core->csm = devm_ioremap_resource(qdx->dev, resource);
		if (IS_ERR(core->csm))
			return PTR_ERR(core->csm);
		snprintf(name, sizeof(name), "imem%d", i);
		resource = platform_get_resource_byname(pdev, IORESOURCE_MEM, name);
		if (!resource || resource_size(resource) != 0x30000 ||
		    resource->start != 0x38000000 + i * 0x30000)
			return -EINVAL;
		core->imem_phys = resource->start;
		core->imem_size = resource_size(resource);
		core->imem = devm_ioremap_resource(qdx->dev, resource);
		if (IS_ERR(core->imem))
			return PTR_ERR(core->imem);
		core->image = image + i * QDX_IMAGE_WINDOW;
		core->image_phys = reserved->base + i * QDX_IMAGE_WINDOW;
		core->image_size = QDX_IMAGE_WINDOW;

		for (j = 0; j < ARRAY_SIZE(reset_names); j++) {
			snprintf(name, sizeof(name), "%s%d", reset_names[j], i);
			hw->core_reset[i][j] = devm_reset_control_get_exclusive(qdx->dev, name);
			if (IS_ERR(hw->core_reset[i][j]))
				return dev_err_probe(qdx->dev, PTR_ERR(hw->core_reset[i][j]),
						     "reset %s unavailable\n", name);
		}
		for (j = 0; j < QDX_DOORBELLS; j++) {
			struct qdx_mailbox *mailbox = &hw->mailbox[i][j];

			spin_lock_init(&mailbox->lock);
			mailbox->client.dev = qdx->dev;
			mailbox->client.knows_txdone = true;
			mailbox->client.tx_done = qdx_mailbox_done;
			snprintf(name, sizeof(name), "%s%d", mailbox_names[j], i);
			mailbox->channel = mbox_request_channel_byname(&mailbox->client, name);
			if (IS_ERR(mailbox->channel))
				return dev_err_probe(qdx->dev, PTR_ERR(mailbox->channel),
						     "mailbox %s unavailable\n", name);
			err = devm_add_action_or_reset(qdx->dev, qdx_mailbox_free, mailbox->channel);
			if (err)
				return err;
		}
	}
	for (i = 0; i < ARRAY_SIZE(master_names); i++) {
		hw->master_reset[i] = devm_reset_control_get_exclusive(qdx->dev, master_names[i]);
		if (IS_ERR(hw->master_reset[i]))
			return dev_err_probe(qdx->dev, PTR_ERR(hw->master_reset[i]),
					     "reset %s unavailable\n", master_names[i]);
	}
	return 0;
}

int qdx_hw_stop(struct qdx *qdx)
{
	/* Hold AXI, AHB and NC_AXI before the core and clock/reset clamps. */
	static const u8 core_order[] = { 1, 2, 3, 4, 0 };
	struct qdx_hw *hw = qdx->hw;
	int i, j, index, err, first = 0;

	mutex_lock(&hw->operation_lock);
	/* Provider success records the hold operation, not a measured DMA drain. */
	if (hw->clocked) {
		for (i = 0; i < QDX_CORES; i++) {
			writel(1, qdx->cores[i].csm + QDX_CSM_RESET);
			/* Complete the write; this register is not a DMA-idle test. */
			readl(qdx->cores[i].csm + QDX_CSM_RESET);
		}
	}
	for (i = 0; i < QDX_CORES; i++) {
		for (j = 0; j < ARRAY_SIZE(core_order); j++) {
			index = core_order[j];
			err = reset_control_assert(hw->core_reset[i][index]);
			if (err) {
				dev_err(qdx->dev, "core %d hold %d failed: %d\n", i, index, err);
				if (!first)
					first = err;
			}
		}
	}
	for (i = 0; i < ARRAY_SIZE(hw->master_reset); i++) {
		err = reset_control_assert(hw->master_reset[i]);
		if (err) {
			dev_err(qdx->dev, "NSS master hold %d failed: %d\n", i, err);
			if (!first)
				first = err;
		}
	}
	mutex_unlock(&hw->operation_lock);
	return first;
}

void qdx_hw_unprepare(struct qdx *qdx)
{
	struct qdx_hw *hw = qdx->hw;
	int err;

	/* Keep references until the terminal access boundary has completed. */
	if (!hw || (hw->executed && !qdx->access_ended))
		return;
	if (hw->clocked) {
		clk_bulk_disable_unprepare(ARRAY_SIZE(hw->clocks), hw->clocks);
		hw->clocked = false;
	}
	if (hw->powered) {
		err = regulator_disable(hw->supply);
		if (err)
			dev_err(qdx->dev, "cannot release NSS supply reference: %d\n", err);
		else
			hw->powered = false;
	}
	if (!hw->powered) {
		err = regulator_set_voltage(hw->supply, 0, INT_MAX);
		if (err)
			dev_err(qdx->dev, "cannot release NSS voltage vote: %d\n", err);
	}
}

int qdx_hw_prepare(struct qdx *qdx)
{
	struct qdx_hw *hw = qdx->hw;
	int i, err;

	err = qdx_hw_stop(qdx);
	if (err)
		return err;
	err = regulator_set_voltage(hw->supply, QDX_CORE_UV, QDX_CORE_UV);
	if (err)
		return err;
	err = regulator_enable(hw->supply);
	if (err)
		goto unwind;
	hw->powered = true;
	for (i = 0; i < ARRAY_SIZE(qdx_clocks); i++) {
		if (!qdx_clocks[i].rate)
			continue;
		err = clk_set_rate(hw->clocks[i].clk, qdx_clocks[i].rate);
		if (err)
			goto unwind;
	}
	/* CE/crypto ARES holds also block their clock branch status.
	 * Release those peripheral holds before enabling clocks; both
	 * processor cores remain clamped until qdx_hw_start_core().
	 */
	for (i = 0; i < ARRAY_SIZE(hw->master_reset); i++) {
		err = reset_control_deassert(hw->master_reset[i]);
		if (err)
			goto hold;
	}
	err = clk_bulk_prepare_enable(ARRAY_SIZE(hw->clocks), hw->clocks);
	if (err)
		goto hold;
	hw->clocked = true;
	if (clk_get_rate(hw->clocks[15].clk) != QDX_CORE_RATE ||
	    clk_get_rate(hw->clocks[21].clk) != QDX_CORE_RATE) {
		err = -ERANGE;
		goto hold;
	}
	dev_info(qdx->dev, "both NSS cores prepared at %lu Hz, S4 vote %u uV\n",
		 QDX_CORE_RATE, QDX_CORE_UV);
	return 0;
hold:
	qdx_hw_stop(qdx);
unwind:
	qdx_hw_unprepare(qdx);
	return err;
}

int qdx_hw_start_core(struct qdx_core *core)
{
	struct qdx_hw *hw = core->qdx->hw;
	int i, err = 0;

	mutex_lock(&hw->operation_lock);
	if (atomic_read(&core->qdx->failure)) {
		err = -ESHUTDOWN;
		goto out;
	}
	if (!hw->clocked || !core->map) {
		err = -EINVAL;
		goto out;
	}
	/* A provider failure cannot prove that its hardware write had no effect. */
	hw->executed = true;
	err = reset_control_deassert(hw->core_reset[core->id][0]);
	if (err)
		goto out;
	usleep_range(10, 20);
	for (i = 1; i < 5; i++) {
		err = reset_control_deassert(hw->core_reset[core->id][i]);
		if (err)
			goto out;
	}
	writel(1, core->csm + QDX_CSM_RESET);
	writel(1, core->csm + QDX_CSM_AMC);
	writel(0x3c000000, core->csm + QDX_CSM_BAR);
	writel(lower_32_bits(core->image_phys), core->csm + QDX_CSM_BOOT);
	writel(0xffff, core->csm + QDX_CSM_INT2);
	writel(0xff, core->csm + QDX_CSM_INT3);
	writel(0xbf004001, core->csm + QDX_CSM_FETCH);
	readl(core->csm + QDX_CSM_FETCH);
	writel(0, core->csm + QDX_CSM_RESET);
	readl(core->csm + QDX_CSM_RESET);
out:
	mutex_unlock(&hw->operation_lock);
	return err;
}

int qdx_hw_notify(struct qdx_core *core, unsigned int channel)
{
	struct qdx_mailbox *mailbox;
	unsigned long flags;
	int err;

	if (channel >= QDX_DOORBELLS)
		return -EINVAL;
	mailbox = &core->qdx->hw->mailbox[core->id][channel];
	spin_lock_irqsave(&mailbox->lock, flags);
	if (mailbox->frozen || mailbox->pending) {
		err = -EIO;
		goto freeze;
	}
	mailbox->done = false;
	mailbox->pending = true;
	mailbox->result = -EINPROGRESS;
	err = mbox_send_message(mailbox->channel, &mailbox->token);
	if (err < 0)
		goto freeze;
	mbox_client_txdone(mailbox->channel, 0);
	if (!READ_ONCE(mailbox->done)) {
		err = -EIO;
		goto freeze;
	}
	err = READ_ONCE(mailbox->result);
	if (err || READ_ONCE(mailbox->frozen)) {
		err = err ?: -EIO;
		goto freeze;
	}
	mailbox->pending = false;
	spin_unlock_irqrestore(&mailbox->lock, flags);
	return 0;
freeze:
	mailbox->frozen = true;
	spin_unlock_irqrestore(&mailbox->lock, flags);
	qdx_fail(core->qdx, err);
	return err;
}
