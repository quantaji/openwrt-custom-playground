// SPDX-License-Identifier: GPL-2.0-only
#include <linux/etherdevice.h>
#include <linux/module.h>
#include <linux/qdx/bridge.h>
#include <linux/rtnetlink.h>
#include <linux/workqueue.h>
#include <net/switchdev.h>

static LIST_HEAD(qdx_bridge_paths);
static struct qdx_binding *qdx_bridge_provider;

static void qdx_bridge_invalidate(bool may_sleep)
{
	struct qdx_binding_scan scan;
	struct qdx_binding_use *use;
	bool invalid;

	if (!READ_ONCE(qdx_bridge_provider))
		return;
	qdx_binding_scan_start(qdx_bridge_provider, &scan);
	while ((use = qdx_binding_user_get(qdx_bridge_provider, &scan))) {
		qdx_uses_lock();
		invalid = use->invalid;
		qdx_uses_unlock();
		if (invalid)
			use->invalidate(use->consumer.object, may_sleep);
		qdx_binding_user_put(use);
	}
}

static void qdx_bridge_retire_work(struct work_struct *work)
{
	qdx_bridge_invalidate(true);
}

static DECLARE_WORK(qdx_bridge_work, qdx_bridge_retire_work);

static void qdx_bridge_path_release(struct qdx_bridge_path *path)
{
	qdx_uses_lock();
	list_del_init(&path->node);
	qdx_uses_unlock();
	dev_put(path->request.port);
	dev_put(path->request.master);
}

static int qdx_bridge_path_acquire(struct qdx_binding *provider,
		const struct qdx_bridge_request *request,
		const struct qdx_owner *consumer,
		int (*invalidate)(void *consumer, bool may_sleep),
		struct qdx_bridge_path *path)
{
	struct bridge_vlan_info vlan;
	struct br_path_state state;
	bool untagged;
	int err;

	ASSERT_RTNL();
	if (!request->master || !request->port ||
	    (request->position_dev != request->master &&
	     request->position_dev != request->port) ||
	    (!request->rx && !request->tx) ||
	    request->vlan_mode > DEV_PATH_BR_VLAN_UNTAG_HW)
		return -EINVAL;
	path->request = *request;
	INIT_LIST_HEAD(&path->node);
	dev_hold(request->master);
	dev_hold(request->port);
	err = qdx_binding_use(provider, &path->use, consumer, invalidate);
	if (err)
		goto put_devices;
	qdx_uses_lock();
	list_add_tail(&path->node, &qdx_bridge_paths);
	qdx_uses_unlock();

	err = -EOPNOTSUPP;
	if (!netif_is_bridge_master(request->master) ||
	    netdev_master_upper_dev_get(request->port) != request->master ||
	    !(request->position_dev->flags & IFF_UP))
		goto failed;
	/* Locked-port admission depends on a source authorization lookup which
	 * a routed offload path does not supply. Do not replace it with STP state.
	 */
	if (request->rx && request->position_dev == request->port &&
	    br_port_flag_is_set(request->port, BR_PORT_LOCKED))
		goto failed;
	if (request->tx && br_fdb_find_port(request->master,
			request->destination, request->vid) != request->port)
		goto failed;
	if (br_vlan_enabled(request->master)) {
		err = br_vlan_get_info(request->port, request->vid, &vlan);
		if (err)
			goto failed;
		untagged = vlan.flags & BRIDGE_VLAN_INFO_UNTAGGED;
		if ((request->vlan_mode == DEV_PATH_BR_VLAN_TAG && untagged) ||
		    ((request->vlan_mode == DEV_PATH_BR_VLAN_UNTAG ||
		      request->vlan_mode == DEV_PATH_BR_VLAN_UNTAG_HW) && !untagged)) {
			err = -ESTALE;
			goto failed;
		}
	}
	err = br_path_state(request->position_dev, request->vid, &state);
	if (err)
		goto failed;
	if ((request->rx && !state.rx) || (request->tx && !state.tx)) {
		err = -EOPNOTSUPP;
		goto failed;
	}
	qdx_uses_lock();
	qdx_use_publish_locked(&path->use);
	err = qdx_use_available_locked(&path->use) ? 0 : -ESTALE;
	qdx_uses_unlock();
	if (!err)
		return 0;
failed:
	qdx_bridge_path_release(path);
	qdx_binding_use_put(&path->use);
	return err;
put_devices:
	dev_put(request->port);
	dev_put(request->master);
	return err;
}

static const struct qdx_bridge_ops qdx_bridge_ops = {
	.get = qdx_bridge_path_acquire,
	.put = qdx_bridge_path_release,
};

static int qdx_bridge_netdev_event(struct notifier_block *nb,
				   unsigned long event, void *data)
{
	struct net_device *dev = netdev_notifier_info_to_dev(data);
	struct qdx_bridge_path *path;

	switch (event) {
	case NETDEV_DOWN:
	case NETDEV_GOING_DOWN:
	case NETDEV_UNREGISTER:
	case NETDEV_CHANGE:
	case NETDEV_CHANGEADDR:
	case NETDEV_CHANGEMTU:
	case NETDEV_CHANGEUPPER:
	case NETDEV_CHANGELOWERSTATE:
	case NETDEV_FEAT_CHANGE:
		break;
	default:
		return NOTIFY_DONE;
	}
	qdx_uses_lock();
	list_for_each_entry(path, &qdx_bridge_paths, node)
		if (path->request.master == dev || path->request.port == dev)
			qdx_use_invalidate_locked(&path->use);
	qdx_uses_unlock();
	qdx_bridge_invalidate(true);
	return NOTIFY_DONE;
}

static int qdx_bridge_switchdev_event(struct notifier_block *nb,
				      unsigned long event, void *data)
{
	struct switchdev_notifier_info *info = data;
	struct switchdev_notifier_fdb_info *fdb = data;
	struct qdx_bridge_path *path;

	if (event != SWITCHDEV_FDB_CHANGED && event != SWITCHDEV_PORT_ATTR_SET)
		return NOTIFY_DONE;
	qdx_uses_lock();
	list_for_each_entry(path, &qdx_bridge_paths, node) {
		if (event == SWITCHDEV_FDB_CHANGED) {
			if (path->request.master != info->dev || !path->request.tx ||
			    path->request.vid != fdb->vid ||
			    !ether_addr_equal(path->request.destination, fdb->addr))
				continue;
		} else if (path->request.master != info->dev &&
			   path->request.port != info->dev) {
			continue;
		}
		qdx_use_invalidate_locked(&path->use);
	}
	qdx_uses_unlock();
	qdx_bridge_invalidate(false);
	schedule_work(&qdx_bridge_work);
	return NOTIFY_DONE;
}

static int qdx_bridge_switchdev_blocking_event(struct notifier_block *nb,
					       unsigned long event, void *data)
{
	struct switchdev_notifier_vlan_info *info = data;
	struct qdx_bridge_path *path;

	/* Attr callbacks can precede their owner commit even on this chain. */
	if (event == SWITCHDEV_PORT_ATTR_SET)
		return qdx_bridge_switchdev_event(nb, event, data);
	if (event != SWITCHDEV_VLAN_CHANGED)
		return NOTIFY_DONE;
	qdx_uses_lock();
	list_for_each_entry(path, &qdx_bridge_paths, node) {
		if (path->request.master != info->info.dev ||
		    (info->port && path->request.port != info->port))
			continue;
		if (info->scope == SWITCHDEV_VLAN_CHANGE_RANGE &&
		    (path->request.vid < info->vid_begin ||
		     path->request.vid > info->vid_end))
			continue;
		qdx_use_invalidate_locked(&path->use);
	}
	qdx_uses_unlock();
	qdx_bridge_invalidate(true);
	return NOTIFY_DONE;
}

static struct notifier_block qdx_bridge_netdev_nb = {
	.notifier_call = qdx_bridge_netdev_event,
};
static struct notifier_block qdx_bridge_switchdev_nb = {
	.notifier_call = qdx_bridge_switchdev_event,
};
static struct notifier_block qdx_bridge_blocking_nb = {
	.notifier_call = qdx_bridge_switchdev_blocking_event,
};

static int __init qdx_bridge_init(void)
{
	const struct qdx_binding_key key = { .role = QDX_BINDING_BRIDGE_PATH };
	const struct qdx_owner owner = { .module = THIS_MODULE };
	int err;

	err = register_netdevice_notifier(&qdx_bridge_netdev_nb);
	if (err)
		return err;
	err = register_switchdev_notifier(&qdx_bridge_switchdev_nb);
	if (err)
		goto netdev;
	err = register_switchdev_blocking_notifier(&qdx_bridge_blocking_nb);
	if (err)
		goto switchdev;
	qdx_bridge_provider = qdx_binding_publish(&key, &owner, &qdx_bridge_ops);
	if (IS_ERR(qdx_bridge_provider)) {
		err = PTR_ERR(qdx_bridge_provider);
		qdx_bridge_provider = NULL;
		goto blocking;
	}
	qdx_binding_available(qdx_bridge_provider);
	return 0;
blocking:
	unregister_switchdev_blocking_notifier(&qdx_bridge_blocking_nb);
switchdev:
	unregister_switchdev_notifier(&qdx_bridge_switchdev_nb);
netdev:
	unregister_netdevice_notifier(&qdx_bridge_netdev_nb);
	cancel_work_sync(&qdx_bridge_work);
	return err;
}

static void __exit qdx_bridge_exit(void)
{
	qdx_binding_invalidate(qdx_bridge_provider);
	qdx_bridge_invalidate(true);
	unregister_switchdev_blocking_notifier(&qdx_bridge_blocking_nb);
	unregister_switchdev_notifier(&qdx_bridge_switchdev_nb);
	unregister_netdevice_notifier(&qdx_bridge_netdev_nb);
	cancel_work_sync(&qdx_bridge_work);
	qdx_binding_withdraw(qdx_bridge_provider);
}

module_init(qdx_bridge_init);
module_exit(qdx_bridge_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("QDX bridge path dependencies");
