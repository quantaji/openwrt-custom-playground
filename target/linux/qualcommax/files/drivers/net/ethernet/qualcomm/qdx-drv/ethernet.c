// SPDX-License-Identifier: GPL-2.0-only
#include <linux/etherdevice.h>
#include <linux/if_vlan.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/reboot.h>
#include <linux/rtnetlink.h>
#include "qdx.h"

/* The two native providers can probe before the NSS platform device. */
static DEFINE_MUTEX(attachment_lock);
static DEFINE_MUTEX(detachment_lock);
static struct qdx *ethernet_instance;
static struct qdx_edma *native_edma;
static struct qdx_ppe *native_ppe;
/* qdx-drv remains resident; native PPE detach must not recycle old OOB tokens. */
static u64 last_tx_token;

struct qdx *qdx_ethernet_instance_get(struct net_device *dev)
{
	struct qdx *qdx = NULL;
	unsigned int i;

	mutex_lock(&attachment_lock);
	if (!ethernet_instance)
		goto out;
	if (!dev || (native_edma && native_edma->info.conduit == dev)) {
		qdx = ethernet_instance;
	} else {
		for (i = 1; i < QDX_PHYSICAL_PORTS; i++) {
			if (ethernet_instance->ethernet->ports[i].netdev == dev &&
			    ethernet_instance->ethernet->ports[i].registered) {
				qdx = ethernet_instance;
				break;
			}
		}
	}
	if (qdx) {
		get_device(qdx->dev);
		atomic_inc(&qdx->service_users);
	}
out:
	mutex_unlock(&attachment_lock);
	return qdx;
}

void qdx_ethernet_instance_put(struct qdx *qdx)
{
	struct device *dev = qdx->dev;
	unsigned long flags;

	spin_lock_irqsave(&qdx->io_admission, flags);
	if (atomic_dec_and_test(&qdx->service_users))
		wake_up_all(&qdx->services_drained);
	spin_unlock_irqrestore(&qdx->io_admission, flags);
	put_device(dev);
}

static int qdx_port_command(struct qdx_port *port, u32 opcode,
			    const void *body, size_t size)
{
	struct qdx_reply reply = { .min_len = 0, .max_len = size };
	int ret;

	ret = qdx_command(&port->qdx->cores[0], port->ifnum, opcode, body, size,
			  &reply);
	if (reply.outcome == QDX_UNKNOWN)
		qdx_fail(port->qdx, ret);
	return ret;
}

/* The port mutex and native configuration lock cover this entire sequence. */
static int qdx_port_apply(struct qdx_port *port,
			  const struct qdx_port_state *state)
{
	struct qdx_ethernet *eth = port->qdx->ethernet;
	struct qdx_port_state old = port->confirmed;
	__le32 open[4] = { 0, 0, cpu_to_le32(QDX_IF_ETH_RX), 0 };
	bool mac_done = false, mtu_done = false;
	bool admin_done = false, link_done = false;
	bool old_opened = port->opened;
	u32 old_link = port->link_state;
	__le32 word;
	__le16 mtu;
	int ret, undo = 0;

	qdx_port_withdraw(port);
	if (!port->configured || !ether_addr_equal(old.mac, state->mac)) {
		ret = qdx_port_command(port, QDX_IF_MAC, state->mac, ETH_ALEN);
		if (ret)
			goto rollback;
		mac_done = true;
	}
	if (!port->configured || old.mtu != state->mtu) {
		ret = qdx_io_set_mtu(port->qdx, state->mtu);
		if (ret)
			goto rollback;
		mtu = cpu_to_le16(state->mtu);
		ret = qdx_port_command(port, QDX_IF_MTU, &mtu, sizeof(mtu));
		if (ret)
			goto rollback;
		mtu_done = true;
	}
	if (state->admin != old_opened) {
		word = 0;
		ret = state->admin ? qdx_port_command(port, QDX_IF_OPEN, open, sizeof(open)) :
			qdx_port_command(port, QDX_IF_CLOSE, &word, sizeof(word));
		if (ret)
			goto rollback;
		admin_done = true;
		port->opened = state->admin;
	}
	if (state->admin && (old_link != state->link_state || admin_done)) {
		word = cpu_to_le32(state->link_state);
		ret = qdx_port_command(port, QDX_IF_LINK, &word, sizeof(word));
		if (ret)
			goto rollback;
		link_done = true;
	}
	ret = eth->ppe->info.ops->reapply(eth->ppe->info.context, port->ifnum);
	if (ret)
		goto rollback;
	port->confirmed = *state;
	port->configured = true;
	port->link_state = state->admin ? state->link_state : 0;
	qdx_port_publish(port);
	return 0;

rollback:
	/* A command with unknown execution cannot be safely reversed. */
	if (atomic_read(&port->qdx->failure))
		return ret;
	if (!port->configured) {
		/* Initial partial state is closed before terminal ownership recovery. */
		word = 0;
		if (port->opened)
			qdx_port_command(port, QDX_IF_CLOSE, &word, sizeof(word));
		qdx_fail(port->qdx, ret);
		return ret;
	}
	if (link_done) {
		word = cpu_to_le32(old_link);
		undo = qdx_port_command(port, QDX_IF_LINK, &word, sizeof(word));
	}
	if (admin_done && !undo) {
		word = 0;
		undo = old_opened ? qdx_port_command(port, QDX_IF_OPEN, open, sizeof(open)) :
			qdx_port_command(port, QDX_IF_CLOSE, &word, sizeof(word));
	}
	if (mtu_done && !undo) {
		mtu = cpu_to_le16(old.mtu);
		undo = qdx_port_command(port, QDX_IF_MTU, &mtu, sizeof(mtu));
	}
	if (mac_done && !undo)
		undo = qdx_port_command(port, QDX_IF_MAC, old.mac, ETH_ALEN);
	if (!undo)
		undo = eth->ppe->info.ops->reapply(eth->ppe->info.context, port->ifnum);
	if (undo) {
		qdx_fail(port->qdx, undo);
		return ret;
	}
	port->opened = old_opened;
	port->link_state = old_link;
	return ret;
}

static void qdx_ports_lock(struct qdx_ethernet *eth)
{
	unsigned int i;

	for (i = 1; i < QDX_PHYSICAL_PORTS; i++) {
		if (!(eth->ppe->info.ports & BIT(i)))
			continue;
		eth->ppe->info.ops->lock(eth->ppe->info.context, i);
		mutex_lock(&eth->ports[i].lock);
	}
}

static void qdx_ports_unlock(struct qdx_ethernet *eth)
{
	int i;

	for (i = QDX_PHYSICAL_PORTS - 1; i > 0; i--) {
		if (!(eth->ppe->info.ports & BIT(i)))
			continue;
		mutex_unlock(&eth->ports[i].lock);
		eth->ppe->info.ops->unlock(eth->ppe->info.context, i);
	}
}

static void qdx_mac_work(struct work_struct *work)
{
	struct qdx_ethernet *eth = container_of(work, struct qdx_ethernet, mac_work);
	unsigned int i;

	rtnl_lock();
	if (!eth->ppe || eth->ppe->detaching || !eth->native_touched ||
	    READ_ONCE(eth->ppe->qdx->state) != QDX_READY ||
	    atomic_read(&eth->ppe->qdx->failure))
		goto out;
	for (i = 1; i < QDX_PHYSICAL_PORTS; i++) {
		struct qdx_port *port = &eth->ports[i];
		struct qdx_port_state state;
		int ret;

		if (!port->registered)
			continue;
		eth->ppe->info.ops->lock(eth->ppe->info.context, i);
		mutex_lock(&port->lock);
		ret = eth->ppe->info.ops->snapshot(eth->ppe->info.context, i, &state);
		if (!ret)
			ret = qdx_port_apply(port, &state);
		if (ret) {
			qdx_port_withdraw(port);
			qdx_fail(port->qdx, ret);
		}
		mutex_unlock(&port->lock);
		eth->ppe->info.ops->unlock(eth->ppe->info.context, i);
	}
	qdx_ethernet_progress(eth->edma->qdx);
out:
	rtnl_unlock();
}

static int qdx_netdev_event(struct notifier_block *nb, unsigned long event,
			    void *data)
{
	struct qdx_ethernet *eth = container_of(nb, struct qdx_ethernet, netdev_notifier);
	struct net_device *dev = netdev_notifier_info_to_dev(data);
	unsigned int i;

	if (event != NETDEV_CHANGEADDR)
		return NOTIFY_DONE;
	for (i = 1; i < QDX_PHYSICAL_PORTS; i++) {
		if (eth->ports[i].registered && eth->ports[i].netdev == dev) {
			schedule_work(&eth->mac_work);
			break;
		}
	}
	return NOTIFY_DONE;
}

int qdx_ethernet_register(struct qdx *qdx)
{
	struct qdx_ethernet *eth;
	int ret;

	eth = kzalloc(sizeof(*eth), GFP_KERNEL);
	if (!eth)
		return -ENOMEM;
	qdx->ethernet = eth;
	qdx_interfaces_init(qdx);
	INIT_WORK(&eth->mac_work, qdx_mac_work);
	eth->netdev_notifier.notifier_call = qdx_netdev_event;
	ret = register_netdevice_notifier(&eth->netdev_notifier);
	if (ret)
		goto free;
	mutex_lock(&attachment_lock);
	if (ethernet_instance) {
		mutex_unlock(&attachment_lock);
		unregister_netdevice_notifier(&eth->netdev_notifier);
		ret = -EBUSY;
		goto free;
	}
	ethernet_instance = qdx;
	mutex_unlock(&attachment_lock);
	qdx_schedule(qdx);
	return 0;
free:
	kfree(eth);
	qdx->ethernet = NULL;
	return ret;
}

bool qdx_ethernet_ready(struct qdx *qdx)
{
	struct device_node *edma, *ppe;
	bool ready = false;

	edma = of_parse_phandle(qdx->dev->of_node, "qcom,edma", 0);
	ppe = of_parse_phandle(qdx->dev->of_node, "qcom,ppe", 0);
	mutex_lock(&attachment_lock);
	if (native_edma && native_ppe && !native_edma->detaching &&
	    !native_ppe->detaching && native_edma->info.dev->of_node == edma &&
	    native_ppe->info.dev->of_node == ppe &&
	    native_edma->info.conduit == native_ppe->info.conduit) {
		qdx->ethernet->edma = native_edma;
		qdx->ethernet->ppe = native_ppe;
		native_edma->qdx = qdx;
		native_ppe->qdx = qdx;
		ready = true;
	}
	mutex_unlock(&attachment_lock);
	of_node_put(edma);
	of_node_put(ppe);
	return ready;
}

struct qdx_edma *qdx_edma_attach(const struct qdx_edma_info *info)
{
	struct qdx_edma *edma;

	if (!info->dev || !info->conduit || !info->ops || !info->ops->quiesce ||
	    !info->ops->restore || !info->ops->receive || !info->ops->activate ||
	    !info->ops->resume_shared || !info->ops->map_rx_queue ||
	    !info->ops->complete_tx || !info->ops->resource_progress || !info->ops->tx_gate)
		return ERR_PTR(-EINVAL);
	edma = kzalloc(sizeof(*edma), GFP_KERNEL);
	if (!edma)
		return ERR_PTR(-ENOMEM);
	edma->info = *info;
	mutex_lock(&attachment_lock);
	if (native_edma) {
		mutex_unlock(&attachment_lock);
		kfree(edma);
		return ERR_PTR(-EBUSY);
	}
	get_device(info->dev);
	dev_hold(info->conduit);
	native_edma = edma;
	if (ethernet_instance)
		qdx_schedule(ethernet_instance);
	mutex_unlock(&attachment_lock);
	return edma;
}
EXPORT_SYMBOL_GPL(qdx_edma_attach);

struct qdx_ppe *qdx_ppe_attach(const struct qdx_ppe_info *info)
{
	struct qdx_ppe *ppe;

	if (!info->dev || !info->conduit || !info->ops || !info->ops->snapshot ||
	    !info->ops->reapply || !info->ops->restore || !info->ops->lock ||
	    !info->ops->unlock || !info->ops->rx_acquire || !info->ops->rx_hold ||
	    !info->ops->rx_release || !info->ops->tx_prepare || !info->ops->tx_hold ||
	    !info->ops->tx_release || !info->ops->resolve_tx || !info->ops->vsi_alloc ||
	    !info->ops->vsi_release || !info->ports || info->ports & ~GENMASK(6, 1))
		return ERR_PTR(-EINVAL);
	ppe = kzalloc(sizeof(*ppe), GFP_KERNEL);
	if (!ppe)
		return ERR_PTR(-ENOMEM);
	ppe->info = *info;
	mutex_lock(&attachment_lock);
	if (native_ppe) {
		mutex_unlock(&attachment_lock);
		kfree(ppe);
		return ERR_PTR(-EBUSY);
	}
	get_device(info->dev);
	dev_hold(info->conduit);
	native_ppe = ppe;
	if (ethernet_instance)
		qdx_schedule(ethernet_instance);
	mutex_unlock(&attachment_lock);
	return ppe;
}
EXPORT_SYMBOL_GPL(qdx_ppe_attach);

u64 qdx_ppe_next_tx_token(struct qdx_ppe *ppe)
{
	u64 token = 0;

	mutex_lock(&attachment_lock);
	if (ppe && native_ppe == ppe && !ppe->detaching && ppe->qdx &&
	    READ_ONCE(ppe->qdx->state) == QDX_READY &&
	    !atomic_read(&ppe->qdx->failure) && last_tx_token != U64_MAX)
		token = ++last_tx_token;
	mutex_unlock(&attachment_lock);
	return token;
}
EXPORT_SYMBOL_GPL(qdx_ppe_next_tx_token);

/* Called without native locks, before the native driver's first destruction. */
static void qdx_native_drain(struct qdx *qdx)
{
	if (!qdx)
		return;
	qdx_fail(qdx, -ENODEV);
	wait_for_completion(&qdx->terminal_done);
	flush_work(&qdx->lifecycle);
	cancel_work_sync(&qdx->ethernet->mac_work);
	if (qdx->execution_possible && !qdx->access_ended)
		panic("qdx: native detach cannot release firmware-accessible resources");
	qdx_interfaces_unregister(qdx);
}

void qdx_edma_detach(struct qdx_edma *edma)
{
	if (!edma)
		return;
	mutex_lock(&detachment_lock);
	mutex_lock(&attachment_lock);
	edma->detaching = true;
	mutex_unlock(&attachment_lock);
	qdx_native_drain(edma->qdx);
	mutex_lock(&attachment_lock);
	if (edma->qdx)
		edma->qdx->ethernet->edma = NULL;
	native_edma = NULL;
	mutex_unlock(&attachment_lock);
	synchronize_net();
	dev_put(edma->info.conduit);
	put_device(edma->info.dev);
	kfree(edma);
	mutex_unlock(&detachment_lock);
}
EXPORT_SYMBOL_GPL(qdx_edma_detach);

void qdx_ppe_detach(struct qdx_ppe *ppe)
{
	if (!ppe)
		return;
	mutex_lock(&detachment_lock);
	mutex_lock(&attachment_lock);
	ppe->detaching = true;
	mutex_unlock(&attachment_lock);
	qdx_native_drain(ppe->qdx);
	mutex_lock(&attachment_lock);
	if (ppe->qdx)
		ppe->qdx->ethernet->ppe = NULL;
	native_ppe = NULL;
	mutex_unlock(&attachment_lock);
	synchronize_net();
	dev_put(ppe->info.conduit);
	put_device(ppe->info.dev);
	kfree(ppe);
	mutex_unlock(&detachment_lock);
}
EXPORT_SYMBOL_GPL(qdx_ppe_detach);

void qdx_ethernet_unregister(struct qdx *qdx)
{
	struct qdx_ethernet *eth;

	mutex_lock(&detachment_lock);
	eth = qdx->ethernet;
	if (!eth) {
		mutex_unlock(&detachment_lock);
		return;
	}
	unregister_netdevice_notifier(&eth->netdev_notifier);
	cancel_work_sync(&eth->mac_work);
	qdx_interfaces_unregister(qdx);
	/* Native configuration readers hold these locks before using QDX. */
	rtnl_lock();
	if (eth->ppe)
		qdx_ports_lock(eth);
	mutex_lock(&attachment_lock);
	if (eth->edma)
		eth->edma->qdx = NULL;
	if (eth->ppe)
		eth->ppe->qdx = NULL;
	ethernet_instance = NULL;
	mutex_unlock(&attachment_lock);
	if (eth->ppe)
		qdx_ports_unlock(eth);
	rtnl_unlock();
	synchronize_net();
	kfree(eth);
	qdx->ethernet = NULL;
	mutex_unlock(&detachment_lock);
}

int qdx_ethernet_prepare(struct qdx *qdx)
{
	struct qdx_ethernet *eth = qdx->ethernet;
	int ret;

	rtnl_lock();
	qdx_ports_lock(eth);
	if (eth->edma->detaching || eth->ppe->detaching || atomic_read(&qdx->failure)) {
		ret = -ENODEV;
		goto out;
	}
	ret = qdx_interfaces_register(qdx);
	if (ret)
		goto out;
	eth->native_touched = true;
	ret = eth->edma->info.ops->quiesce(eth->edma->info.context,
					    qdx->limits.native_rx_entries);
	if (ret)
		goto out;
	eth->prepared = true;
	return 0;
out:
	qdx_ports_unlock(eth);
	rtnl_unlock();
	return ret;
}

void qdx_ethernet_unlock(struct qdx *qdx)
{
	struct qdx_ethernet *eth = qdx->ethernet;

	if (!eth->prepared)
		return;
	eth->prepared = false;
	qdx_ports_unlock(eth);
	rtnl_unlock();
}

int qdx_ethernet_start(struct qdx *qdx)
{
	struct qdx_ethernet *eth = qdx->ethernet;
	unsigned int i;
	int ret = 0;

	for (i = 1; i < QDX_PHYSICAL_PORTS; i++) {
		struct qdx_port_state state;

		if (!eth->ports[i].registered)
			continue;
		ret = eth->ppe->info.ops->snapshot(eth->ppe->info.context, i, &state);
		if (!ret)
			ret = qdx_port_apply(&eth->ports[i], &state);
		if (ret)
			break;
	}
	if (!ret)
		ret = eth->edma->info.ops->resume_shared(eth->edma->info.context);
	/* Both receive rings are live. Unclaimed traffic belongs to native
	 * queue 0; peers acquire separate queues after READY is published.
	 */
	if (!ret)
		ret = eth->edma->info.ops->map_rx_queue(eth->edma->info.context,
						    0, false);
	if (!ret)
		qdx_ethernet_progress(qdx);
	qdx_ethernet_unlock(qdx);
	return ret;
}

void qdx_ethernet_stop(struct qdx *qdx)
{
	struct qdx_ethernet *eth = qdx->ethernet;
	unsigned int i;

	cancel_work_sync(&eth->mac_work);
	for (i = 1; i < QDX_PHYSICAL_PORTS; i++)
		qdx_port_withdraw(&eth->ports[i]);
	if (eth->edma && eth->native_touched)
		netif_tx_disable(eth->edma->info.conduit);
	/* Finish native writes already in progress before hardware holds. New
	 * destructive changes now fail prepare while retaining desired state.
	 */
	if (eth->ppe && eth->native_touched) {
		rtnl_lock();
		qdx_ports_lock(eth);
		qdx_ports_unlock(eth);
		rtnl_unlock();
	}
}

int qdx_ethernet_restore(struct qdx *qdx)
{
	struct qdx_ethernet *eth = qdx->ethernet;
	int ret;

	if (!eth->native_touched)
		return 0;
	if (!eth->edma || !eth->ppe)
		return -ENODEV;
	rtnl_lock();
	qdx_ports_lock(eth);
	ret = eth->edma->info.ops->restore(eth->edma->info.context);
	if (!ret)
		ret = eth->ppe->info.ops->restore(eth->ppe->info.context);
	if (!ret)
		eth->native_restored = true;
	qdx_ports_unlock(eth);
	rtnl_unlock();
	return ret;
}

int qdx_ethernet_activate(struct qdx *qdx)
{
	struct qdx_ethernet *eth = qdx->ethernet;
	int ret;

	if (!eth->native_touched || !eth->native_restored)
		return 0;
	rtnl_lock();
	ret = eth->edma->info.ops->activate(eth->edma->info.context);
	if (ret) {
		rtnl_unlock();
		return ret;
	}
	eth->native_touched = false;
	qdx_ethernet_progress(qdx);
	rtnl_unlock();
	return 0;
}

int qdx_port_prepare(struct qdx_ppe *ppe, unsigned int number)
{
	struct qdx_port *port;
	__le32 down = 0;
	int ret;

	if (!ppe || !ppe->qdx || number == 0)
		return 0;
	if (number >= QDX_PHYSICAL_PORTS)
		return -EINVAL;
	port = &ppe->qdx->ethernet->ports[number];
	mutex_lock(&port->lock);
	if (!ppe->qdx->ethernet->native_touched)
		return 0;
	if (atomic_read(&ppe->qdx->failure)) {
		mutex_unlock(&port->lock);
		return -EIO;
	}
	WRITE_ONCE(port->changing, true);
	qdx_port_withdraw(port);
	if (!port->opened || !port->link_state)
		return 0;
	ret = qdx_port_command(port, QDX_IF_LINK, &down, sizeof(down));
	if (ret) {
		/* A rejected/unsubmitted command leaves the confirmed link intact. */
		if (!atomic_read(&ppe->qdx->failure)) {
			WRITE_ONCE(port->changing, false);
			qdx_port_publish(port);
		}
		mutex_unlock(&port->lock);
		if (!atomic_read(&ppe->qdx->failure))
			qdx_ethernet_progress(ppe->qdx);
		return ret;
	}
	port->link_state = 0;
	return 0;
}
EXPORT_SYMBOL_GPL(qdx_port_prepare);

int qdx_port_finish(struct qdx_ppe *ppe, unsigned int number)
{
	struct qdx_port_state state;
	struct qdx_port *port;
	int ret = 0;

	if (!ppe || !ppe->qdx || number == 0)
		return 0;
	port = &ppe->qdx->ethernet->ports[number];
	if (atomic_read(&ppe->qdx->failure) &&
	    ppe->qdx->ethernet->native_touched) {
		ret = -EIO;
	} else if (ppe->qdx->ethernet->native_touched) {
		ret = ppe->info.ops->snapshot(ppe->info.context, number, &state);
		if (!ret)
			ret = qdx_port_apply(port, &state);
	}
	WRITE_ONCE(port->changing, false);
	if (!ret)
		qdx_port_publish(port);
	mutex_unlock(&port->lock);
	qdx_ethernet_progress(ppe->qdx);
	return ret;
}
EXPORT_SYMBOL_GPL(qdx_port_finish);

int qdx_port_check_mtu(struct qdx_ppe *ppe, unsigned int number, unsigned int mtu)
{
	struct qdx_port *port;
	int ret = 0;

	if (!ppe || !ppe->qdx || !number)
		return 0;
	if (number >= QDX_PHYSICAL_PORTS)
		return -EINVAL;
	port = &ppe->qdx->ethernet->ports[number];
	mutex_lock(&port->lock);
	if (ppe->qdx->ethernet->native_touched) {
		ret = atomic_read(&ppe->qdx->failure);
		if (!ret)
			ret = qdx_io_check_mtu(ppe->qdx, mtu);
	}
	mutex_unlock(&port->lock);
	return ret;
}
EXPORT_SYMBOL_GPL(qdx_port_check_mtu);

int qdx_port_mtu(struct qdx_ppe *ppe, unsigned int number, unsigned int mtu)
{
	struct qdx_port *port;
	__le16 wire_mtu = cpu_to_le16(mtu);
	int ret;

	if (!ppe || !ppe->qdx || number == 0 ||
	    !ppe->qdx->ethernet->native_touched)
		return 0;
	port = &ppe->qdx->ethernet->ports[number];
	lockdep_assert_held(&port->lock);
	ret = qdx_io_set_mtu(ppe->qdx, mtu);
	if (!ret)
		ret = qdx_port_command(port, QDX_IF_MTU, &wire_mtu, sizeof(wire_mtu));
	if (!ret)
		port->confirmed.mtu = mtu;
	return ret;
}
EXPORT_SYMBOL_GPL(qdx_port_mtu);

void qdx_port_failed(struct qdx_ppe *ppe, unsigned int number, int error)
{
	if (!ppe || !ppe->qdx || number >= QDX_PHYSICAL_PORTS)
		return;
	qdx_port_withdraw(&ppe->qdx->ethernet->ports[number]);
	qdx_fail(ppe->qdx, error);
}
EXPORT_SYMBOL_GPL(qdx_port_failed);

int qdx_port_open(struct qdx_ppe *ppe, unsigned int number)
{
	int ret = qdx_port_prepare(ppe, number);

	if (ret)
		return ret;
	return qdx_port_finish(ppe, number);
}
EXPORT_SYMBOL_GPL(qdx_port_open);

int qdx_port_close(struct qdx_ppe *ppe, unsigned int number)
{
	int ret = qdx_port_prepare(ppe, number);

	if (!ret)
		ret = qdx_port_finish(ppe, number);
	if (ret && ppe && ppe->qdx)
		qdx_fail(ppe->qdx, ret);
	return ret;
}
EXPORT_SYMBOL_GPL(qdx_port_close);

void qdx_ethernet_progress(struct qdx *qdx)
{
	struct qdx_edma *edma;

	rcu_read_lock();
	edma = READ_ONCE(qdx->ethernet->edma);
	if (edma && !READ_ONCE(edma->detaching))
		edma->info.ops->resource_progress(edma->info.context);
	rcu_read_unlock();
}

void qdx_ethernet_receive(struct qdx *qdx, unsigned int core, u32 ifnum,
			struct sk_buff *skb, struct napi_struct *napi)
{
	struct qdx_port *port = qdx_port_get(qdx, core, ifnum);
	struct qdx_edma *edma = qdx->ethernet->edma;

	if (!port || !edma || edma->detaching || !netif_running(port->netdev)) {
		if (port)
			qdx_port_put(port);
		dev_kfree_skb_any(skb);
		return;
	}
	edma->info.ops->receive(edma->info.context, ifnum, skb, napi);
	qdx_port_put(port);
}

static void qdx_vsi_free(struct work_struct *work)
{
	struct qdx_vsi *vsi = container_of(work, struct qdx_vsi, release_work);
	int error;

	/* Peer cfg never waits for RTNL. The retained port prevents native detach
	 * from destroying regmap/priv before this actual resource release ends.
	 */
	rtnl_lock();
	error = vsi->ppe->info.ops->vsi_release(vsi->ppe->info.context, vsi->wire);
	rtnl_unlock();
	if (error) {
		dev_err(vsi->ppe->info.dev, "VSI %u release failed: %d; reservation retained\n",
			vsi->wire, error);
		qdx_stop_execution(vsi->physical->service, error);
		return;
	}
	module_put(vsi->native_owner);
	qdx_endpoint_put(vsi->physical);
	qdx_port_put(vsi->port);
	kfree(vsi);
}

struct qdx_vsi *qdx_vsi_alloc(struct qdx_endpoint *physical, u32 *wire_vsi)
{
	struct qdx_vsi *vsi;
	struct qdx_port *port;
	struct qdx_ppe *ppe;
	struct qdx *qdx;
	struct module *owner;
	int error;

	ASSERT_RTNL();
	if (!physical || !physical->port || !wire_vsi)
		return ERR_PTR(-EINVAL);
	if (!qdx_endpoint_command_ready(physical))
		return ERR_PTR(-ESHUTDOWN);
	qdx = physical->service->qdx;
	port = qdx_port_get(qdx, physical->core->id, physical->ifnum);
	if (!port)
		return ERR_PTR(-ENODEV);
	ppe = READ_ONCE(qdx->ethernet->ppe);
	if (!ppe || READ_ONCE(ppe->detaching) || atomic_read(&qdx->failure)) {
		error = -ESHUTDOWN;
		goto put_port;
	}
	vsi = kzalloc(sizeof(*vsi), GFP_KERNEL);
	if (!vsi) {
		error = -ENOMEM;
		goto put_port;
	}
	/* Native remove waits for port references before returning. A module
	 * reference additionally excludes starting its unload while leased.
	 */
	owner = ppe->info.dev->driver->owner;
	if (!try_module_get(owner)) {
		error = -ENODEV;
		goto free;
	}
	error = ppe->info.ops->vsi_alloc(ppe->info.context, port->ifnum, &vsi->wire);
	if (error)
		goto put_module;
	vsi->physical = physical;
	qdx_endpoint_hold(physical);
	vsi->port = port;
	vsi->ppe = ppe;
	vsi->native_owner = owner;
	INIT_WORK(&vsi->release_work, qdx_vsi_free);
	*wire_vsi = vsi->wire;
	return vsi;
put_module:
	module_put(owner);
free:
	kfree(vsi);
put_port:
	qdx_port_put(port);
	return ERR_PTR(error);
}
EXPORT_SYMBOL_GPL(qdx_vsi_alloc);

void qdx_vsi_release(struct qdx_vsi *vsi)
{
	if (vsi)
		queue_work(vsi->physical->service->qdx->cleanup_queue, &vsi->release_work);
}
EXPORT_SYMBOL_GPL(qdx_vsi_release);

/* Prepared RX and output uses retain native resources independently. */
struct qdx_rx_use *qdx_rx_acquire(struct qdx_endpoint *endpoint,
				struct net_device *dev)
{
	struct qdx *qdx = endpoint->service->qdx;
	struct qdx_rx_use *use;
	struct qdx_port *port;
	struct qdx_ppe *ppe;
	int error;

	if (!qdx_endpoint_command_ready(endpoint))
		return ERR_PTR(-ESHUTDOWN);
	port = qdx_port_get(qdx, endpoint->core->id, endpoint->ifnum);
	if (!port)
		return ERR_PTR(-ENODEV);
	if (port->netdev != dev) {
		error = -EINVAL;
		goto put_port;
	}
	use = kzalloc(sizeof(*use), GFP_KERNEL);
	if (!use) {
		error = -ENOMEM;
		goto put_port;
	}
	/* The physical port reference prevents the native provider from passing
	 * its detach drain. Resource operations never acquire port policy locks.
	 */
	ppe = READ_ONCE(qdx->ethernet->ppe);
	if (!ppe || READ_ONCE(ppe->detaching) || atomic_read(&qdx->failure)) {
		error = -ESHUTDOWN;
		goto free;
	}
	use->scope = ppe->info.ops->rx_acquire(ppe->info.context, port->ifnum);
	if (IS_ERR(use->scope)) {
		error = PTR_ERR(use->scope);
		goto free;
	}
	qdx_endpoint_hold(endpoint);
	use->endpoint = endpoint;
	use->port = port;
	use->ppe = ppe;
	return use;
free:
	kfree(use);
put_port:
	qdx_port_put(port);
	return ERR_PTR(error);
}
EXPORT_SYMBOL_GPL(qdx_rx_acquire);

int qdx_rx_hold(struct qdx_rx_use *use)
{
	int error;

	if (qdx_service_access_ended(use->endpoint->service))
		return 0;
	error = use->ppe->info.ops->rx_hold(use->ppe->info.context, use->scope);
	if (error)
		qdx_stop_execution(use->endpoint->service, error);
	return error;
}
EXPORT_SYMBOL_GPL(qdx_rx_hold);

int qdx_rx_release(struct qdx_rx_use *use)
{
	int error;

	if (!use)
		return 0;
	error = use->ppe->info.ops->rx_release(use->ppe->info.context, use->scope);
	if (error) {
		qdx_stop_execution(use->endpoint->service, error);
		return error; /* The exact old reservation and references remain held. */
	}
	qdx_endpoint_put(use->endpoint);
	qdx_port_put(use->port);
	kfree(use);
	return 0;
}
EXPORT_SYMBOL_GPL(qdx_rx_release);

static void qdx_tx_path_free(struct work_struct *work)
{
	struct qdx_tx_path *path = container_of(work, struct qdx_tx_path, release_work);

	/* A last DMA return can run in NAPI. The actual hardware-resource release
	 * is sleepable and precedes ending the native provider's detach reference.
	 */
	path->ppe->info.ops->tx_release(path->ppe->info.context, path->scope);
	/* The last carrier can precede this sleepable native scope cleanup.
	 * Retiring owners recheck their real queue state after this progress.
	 */
	qdx_resource_progress(path->endpoint->core, QDX_RESOURCE_CARRIER);
	qdx_endpoint_put(path->endpoint);
	qdx_port_put(path->port);
	kfree(path);
}

struct qdx_tx_path *qdx_tx_prepare(struct qdx_endpoint *endpoint,
		struct net_device *dev, u16 queue, struct qdx_tx_class class,
		enum qdx_disposition disposition)
{
	struct qdx *qdx = endpoint->service->qdx;
	struct qdx_tx_path *path;
	struct qdx_port *port;
	struct qdx_ppe *ppe;
	int error;

	if (!class.token || disposition == QDX_NATIVE || disposition > QDX_REQUIRED ||
	    queue >= dev->num_tx_queues)
		return ERR_PTR(-EINVAL);
	if (!qdx_endpoint_command_ready(endpoint))
		return ERR_PTR(-ESHUTDOWN);
	port = qdx_port_get(qdx, endpoint->core->id, endpoint->ifnum);
	if (!port)
		return ERR_PTR(-ENODEV);
	if (port->netdev != dev) {
		error = -EINVAL;
		goto put_port;
	}
	path = kzalloc(sizeof(*path), GFP_KERNEL);
	if (!path) {
		error = -ENOMEM;
		goto put_port;
	}
	ppe = READ_ONCE(qdx->ethernet->ppe);
	if (!ppe || READ_ONCE(ppe->detaching) || atomic_read(&qdx->failure)) {
		error = -ESHUTDOWN;
		goto free;
	}
	path->scope = ppe->info.ops->tx_prepare(ppe->info.context, port->ifnum, queue);
	if (IS_ERR(path->scope)) {
		error = PTR_ERR(path->scope);
		goto free;
	}
	qdx_endpoint_hold(endpoint);
	path->endpoint = endpoint;
	path->port = port;
	path->ppe = ppe;
	path->queue = queue;
	path->class = class;
	path->disposition = disposition;
	INIT_WORK(&path->release_work, qdx_tx_path_free);
	refcount_set(&path->refs, 1);
	smp_store_release(&path->open, true);
	return path;
free:
	kfree(path);
put_port:
	qdx_port_put(port);
	return ERR_PTR(error);
}
EXPORT_SYMBOL_GPL(qdx_tx_prepare);

void qdx_tx_path_get(struct qdx_tx_path *path)
{
	refcount_inc(&path->refs);
}
EXPORT_SYMBOL_GPL(qdx_tx_path_get);

void qdx_tx_path_put(struct qdx_tx_path *path)
{
	if (refcount_dec_and_test(&path->refs))
		queue_work(path->endpoint->service->qdx->cleanup_queue, &path->release_work);
}
EXPORT_SYMBOL_GPL(qdx_tx_path_put);

int qdx_tx_hold(struct qdx_tx_path *path)
{
	int error;

	qdx_io_tx_close(path);
	if (qdx_service_access_ended(path->endpoint->service))
		return 0;
	error = path->ppe->info.ops->tx_hold(path->ppe->info.context, path->scope);
	if (error)
		qdx_stop_execution(path->endpoint->service, error);
	return error;
}
EXPORT_SYMBOL_GPL(qdx_tx_hold);

void qdx_tx_release(struct qdx_tx_path *path)
{
	if (!path)
		return;
	qdx_io_tx_close(path);
	qdx_tx_path_put(path);
}
EXPORT_SYMBOL_GPL(qdx_tx_release);

void qdx_edma_resolve(struct qdx_edma *edma, unsigned int port, u16 queue,
		      u64 token, enum qdx_disposition disposition,
		      struct qdx_tx_selection *selection)
{
	struct qdx_ppe *ppe;
	struct qdx *qdx;

	*selection = (struct qdx_tx_selection) {
		.status = token || disposition != QDX_NATIVE ?
			  QDX_TX_REFUSED : QDX_TX_NATIVE,
		.disposition = disposition,
	};
	if (!edma)
		return;
	rcu_read_lock();
	qdx = READ_ONCE(edma->qdx);
	if (!qdx)
		goto out;
	ppe = READ_ONCE(qdx->ethernet->ppe);
	if (ppe && !READ_ONCE(ppe->detaching))
		ppe->info.ops->resolve_tx(ppe->info.context, port, queue, token,
					 disposition, selection);
out:
	rcu_read_unlock();
}
EXPORT_SYMBOL_GPL(qdx_edma_resolve);

void qdx_tx_selection_put(struct qdx_tx_selection *selection)
{
	if (selection->owner.object)
		qdx_owner_put(&selection->owner);
	memset(selection, 0, sizeof(*selection));
}
EXPORT_SYMBOL_GPL(qdx_tx_selection_put);

int qdx_ppe_map_rx_queue(struct qdx_ppe *ppe, u16 queue, bool firmware)
{
	struct qdx_edma *edma;

	if (!ppe || !ppe->qdx)
		return -ENODEV;
	/* The caller's real RX reservation retains the physical/native provider.
	 * Native hardware control is process context, never a fast-path lock.
	 */
	edma = READ_ONCE(ppe->qdx->ethernet->edma);
	if (!edma || (firmware && READ_ONCE(edma->detaching)))
		return -ENODEV;
	return edma->info.ops->map_rx_queue(edma->info.context, queue, firmware);
}
EXPORT_SYMBOL_GPL(qdx_ppe_map_rx_queue);

void qdx_ppe_tx_gate(struct qdx_ppe *ppe, bool hold)
{
	struct qdx_edma *edma;

	if (!ppe || !ppe->qdx)
		return;
	rcu_read_lock();
	edma = READ_ONCE(ppe->qdx->ethernet->edma);
	if (edma && !READ_ONCE(edma->detaching))
		edma->info.ops->tx_gate(edma->info.context, hold);
	rcu_read_unlock();
}
EXPORT_SYMBOL_GPL(qdx_ppe_tx_gate);

void qdx_ppe_tx_progress(struct qdx_ppe *ppe)
{
	if (ppe && ppe->qdx)
		qdx_ethernet_progress(ppe->qdx);
}
EXPORT_SYMBOL_GPL(qdx_ppe_tx_progress);
