// SPDX-License-Identifier: GPL-2.0-only
#include <linux/etherdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/ppp-ioctl.h>
#include <linux/qdx/bridge.h>
#include <linux/qdx/tunnel.h>
#include <linux/rtnetlink.h>
#include <linux/slab.h>
#include <linux/workqueue.h>

#define QDX_PPPOE_DYNAMIC_TYPE 8
#define QDX_PPPOE_CREATE 0
#define QDX_PPPOE_DESTROY 1
#define QDX_PPPOE_COMMAND_TIMEOUT msecs_to_jiffies(3000)

struct qdx_pppoe_create {
	s32 base;
	u32 mtu;
	u8 remote[ETH_ALEN];
	u8 local[ETH_ALEN];
	u16 session_id;
	u16 reserved;
};

struct qdx_pppoe_destroy {
	u16 session_id;
	u8 remote[ETH_ALEN];
	u8 local[ETH_ALEN];
};

struct qdx_pppoe_session {
	struct list_head node;
	refcount_t refs;
	struct mutex cfg;
	struct delayed_work work;
	struct qdx_binding *binding;
	struct qdx_service *service;
	struct qdx_endpoint *endpoint;
	struct qdx_receiver *receiver;
	struct qdx_request *create_request;
	struct qdx_request *destroy_request;
	struct qdx_result create_result;
	struct qdx_result destroy_result;
	struct qdx_pppoe_request prepared;
	struct ppp_offload_ref *native;
	struct ppp_offload_snapshot snapshot;
	struct qdx_vlan_endpoint_use lower;
	struct qdx_bridge_path bridge[NET_DEVICE_PATH_STACK_MAX * 2];
	struct qdx_pppoe_create create;
	u64 serial;
	unsigned int bridge_count;
	unsigned int preparations;
	unsigned int users;
	bool lower_held;
	bool assembling;
	bool invalid;
	bool available;
	bool cleaned;
};

static LIST_HEAD(qdx_pppoe_sessions);
static u64 qdx_pppoe_serial;
static struct qdx_binding *qdx_pppoe_provider;
static const struct qdx_pppoe_ops qdx_pppoe_ops;

static bool qdx_pppoe_ref(void *object)
{
	struct qdx_pppoe_session *session = object;

	return refcount_inc_not_zero(&session->refs);
}

static void qdx_pppoe_unref(void *object)
{
	struct qdx_pppoe_session *session = object;

	if (!refcount_dec_and_test(&session->refs))
		return;
	/* Old native accounting deliberately outlives endpoint/lower retirement. */
	if (session->native)
		ppp_offload_ref_put(session->native);
	kfree(session);
}

static void qdx_pppoe_queue(struct qdx_pppoe_session *session)
{
	qdx_pppoe_ref(session);
	__module_get(THIS_MODULE);
	if (!schedule_delayed_work(&session->work, msecs_to_jiffies(20))) {
		qdx_pppoe_unref(session);
		module_put(THIS_MODULE);
	}
}

static void qdx_pppoe_command_done(void *object, const struct qdx_result *result,
				   const void *payload, size_t length)
{
	qdx_pppoe_queue(object);
}

static void qdx_pppoe_message(void *object, u32 opcode, u32 response, u32 error,
			      const void *payload, size_t received, size_t declared)
{
	/* Mixed CPU/session totals do not enter the hardware-only flow collector. */
}

static const struct qdx_receive_ops qdx_pppoe_receive_ops = {
	.message = qdx_pppoe_message,
};

static int qdx_pppoe_retire(struct qdx_pppoe_session *session)
{
	const struct qdx_owner owner = {
		.module = THIS_MODULE, .object = session,
		.get = qdx_pppoe_ref, .put = qdx_pppoe_unref,
	};
	const struct qdx_command_recipient recipient = {
		.owner = owner, .result = qdx_pppoe_command_done,
	};
	const struct qdx_reply_bounds bounds = {
		.maximum = sizeof(struct qdx_pppoe_destroy),
		.capacity = sizeof(struct qdx_pppoe_destroy),
	};
	struct qdx_pppoe_destroy destroy;
	struct qdx_binding_scan scan;
	struct qdx_binding_use *use;
	struct qdx_binding *binding;
	unsigned int users;
	int err = 0, result;

	qdx_uses_lock();
	if (session->cleaned || !qdx_binding_hold(session->binding)) {
		qdx_uses_unlock();
		return 0;
	}
	binding = session->binding;
	session->invalid = true;
	session->available = false;
	qdx_uses_unlock();
	qdx_binding_invalidate(binding);
	qdx_binding_scan_start(binding, &scan);
	while ((use = qdx_binding_user_get(binding, &scan))) {
		result = use->invalidate(use->consumer.object, true);
		if (result && !err)
			err = result;
		qdx_binding_user_put(use);
	}
	if (err)
		err = qdx_stop_execution(session->service, err);
	mutex_lock(&session->cfg);
	if (session->cleaned)
		goto out;
	if (session->assembling)
		goto pending;
	qdx_uses_lock();
	users = session->users;
	qdx_uses_unlock();
	if (users && !qdx_service_access_ended(session->service))
		goto pending;
	if (session->create_request)
		qdx_request_wait(session->create_request, jiffies,
				 &session->create_result, NULL, 0);
	if (session->create_result.outcome == QDX_UNKNOWN &&
	    !session->create_result.exposure_ended &&
	    !qdx_service_access_ended(session->service)) {
		qdx_stop_execution(session->service, -ETIMEDOUT);
		goto pending;
	}
	if (session->create_result.outcome == QDX_ACK &&
	    !qdx_service_access_ended(session->service)) {
		if (!session->destroy_request) {
			if (session->destroy_result.error)
				goto pending;
			destroy.session_id = session->create.session_id;
			ether_addr_copy(destroy.remote, session->create.remote);
			ether_addr_copy(destroy.local, session->create.local);
			session->destroy_request = qdx_command_submit(session->endpoint,
				QDX_PPPOE_DESTROY, &destroy, sizeof(destroy), &bounds, &recipient);
			if (IS_ERR(session->destroy_request)) {
				err = PTR_ERR(session->destroy_request);
				session->destroy_result.error = err;
				session->destroy_request = NULL;
				qdx_stop_execution(session->service, err);
				goto pending;
			}
		}
		qdx_request_wait(session->destroy_request, jiffies + QDX_PPPOE_COMMAND_TIMEOUT,
				 &session->destroy_result, NULL, 0);
		if (session->destroy_result.outcome != QDX_ACK) {
			qdx_stop_execution(session->service, -EIO);
			goto pending;
		}
	}
	if (session->endpoint && qdx_endpoint_retire(session->endpoint) &&
	    !qdx_service_access_ended(session->service))
		goto pending;
	if (session->receiver) {
		if (qdx_endpoint_receive_unregister(session->receiver))
			goto pending;
		session->receiver = NULL;
	}
	qdx_request_put(session->create_request);
	qdx_request_put(session->destroy_request);
	session->create_request = NULL;
	session->destroy_request = NULL;
	qdx_endpoint_put(session->endpoint);
	session->endpoint = NULL;
	if (session->lower_held) {
		qdx_vlan_endpoint_put(&session->lower);
		session->lower_held = false;
	}
	while (session->bridge_count)
		qdx_bridge_path_put(&session->bridge[--session->bridge_count]);
	qdx_endpoint_put(session->prepared.lower.execution);
	qdx_endpoint_put(session->prepared.lower.physical);
	dev_put(session->prepared.lower.physical_dev);
	if (session->snapshot.lower_dev)
		dev_put(session->snapshot.lower_dev);
	session->snapshot.lower_dev = NULL;
	qdx_service_put(session->service);
	qdx_uses_lock();
	session->cleaned = true;
	list_del_init(&session->node);
	qdx_uses_unlock();
	qdx_binding_withdraw(binding);
	qdx_pppoe_unref(session); /* Actual session index reference. */
	goto out;
pending:
	qdx_pppoe_queue(session);
out:
	mutex_unlock(&session->cfg);
	qdx_binding_put(binding);
	return err;
}

static int qdx_pppoe_lower_changed(void *object, bool may_sleep)
{
	struct qdx_pppoe_session *session = object;
	struct qdx_binding *binding;

	qdx_uses_lock();
	if (session->cleaned || !qdx_binding_hold(session->binding)) {
		qdx_uses_unlock();
		return 0;
	}
	binding = session->binding;
	session->invalid = true;
	session->available = false;
	qdx_uses_unlock();
	qdx_binding_invalidate(binding);
	qdx_binding_put(binding);
	if (may_sleep)
		return qdx_pppoe_retire(session);
	qdx_pppoe_queue(session);
	return 0;
}

static bool qdx_pppoe_dependencies(struct qdx_pppoe_session *session)
{
	unsigned int i;

	if (session->invalid ||
	    (session->lower_held && !qdx_use_available_locked(&session->lower.use)))
		return false;
	for (i = 0; i < session->bridge_count; i++)
		if (!qdx_use_available_locked(&session->bridge[i].use))
			return false;
	return true;
}

static void qdx_pppoe_configure(struct qdx_pppoe_session *session)
{
	const struct qdx_owner owner = {
		.module = THIS_MODULE, .object = session,
		.get = qdx_pppoe_ref, .put = qdx_pppoe_unref,
	};
	const struct qdx_command_recipient recipient = {
		.owner = owner, .result = qdx_pppoe_command_done,
	};
	const struct qdx_reply_bounds bounds = {
		.maximum = sizeof(struct qdx_pppoe_create),
		.capacity = sizeof(struct qdx_pppoe_create),
	};
	bool valid;
	int err;

	mutex_lock(&session->cfg);
	if (session->cleaned)
		goto out;
	qdx_uses_lock();
	valid = qdx_pppoe_dependencies(session);
	qdx_uses_unlock();
	if (!valid)
		goto retire;
	if (!session->endpoint) {
		session->endpoint = qdx_endpoint_alloc(session->service, QDX_PPPOE_DYNAMIC_TYPE);
		if (IS_ERR(session->endpoint)) {
			session->endpoint = NULL;
			goto retire;
		}
	}
	err = qdx_endpoint_wait(session->endpoint, jiffies + QDX_PPPOE_COMMAND_TIMEOUT);
	if (err)
		goto retire;
	if (!session->receiver) {
		session->receiver = qdx_endpoint_receive_register(session->endpoint,
			QDX_RECEIVE_MESSAGE, &owner, &qdx_pppoe_receive_ops);
		if (IS_ERR(session->receiver)) {
			session->receiver = NULL;
			goto retire;
		}
	}
	if (!session->create_request) {
		qdx_uses_lock();
		valid = qdx_pppoe_dependencies(session);
		qdx_uses_unlock();
		if (!valid)
			goto retire;
		session->create_request = qdx_command_submit(session->endpoint, QDX_PPPOE_CREATE,
			&session->create, sizeof(session->create), &bounds, &recipient);
		if (IS_ERR(session->create_request)) {
			session->create_request = NULL;
			goto retire;
		}
	}
	qdx_request_wait(session->create_request, jiffies + QDX_PPPOE_COMMAND_TIMEOUT,
			 &session->create_result, NULL, 0);
	if (session->create_result.outcome != QDX_ACK)
		goto retire;
	qdx_uses_lock();
	valid = qdx_pppoe_dependencies(session);
	session->available = valid;
	qdx_uses_unlock();
	if (!valid)
		goto retire;
	qdx_binding_available(session->binding);
	goto out;
retire:
	qdx_uses_lock();
	session->invalid = true;
	session->available = false;
	qdx_uses_unlock();
	qdx_binding_invalidate(session->binding);
	qdx_pppoe_queue(session);
out:
	mutex_unlock(&session->cfg);
}

static void qdx_pppoe_work(struct work_struct *work)
{
	struct qdx_pppoe_session *session =
		container_of(to_delayed_work(work), struct qdx_pppoe_session, work);

	if (READ_ONCE(session->invalid))
		qdx_pppoe_retire(session);
	else
		qdx_pppoe_configure(session);
	qdx_pppoe_unref(session);
	module_put(THIS_MODULE);
}

static bool qdx_pppoe_protocol(const struct ppp_offload_snapshot *snapshot,
			       __be16 protocol)
{
	if (protocol == htons(ETH_P_IP))
		return snapshot->ipv4_mode == NPMODE_PASS;
	if (protocol == htons(ETH_P_IPV6))
		return snapshot->ipv6_mode == NPMODE_PASS;
	return false;
}

static struct qdx_binding *
qdx_pppoe_prepare_record(const struct qdx_pppoe_request *request)
{
	struct qdx_binding_key key = { .role = QDX_BINDING_PPPOE_SESSION };
	struct qdx_pppoe_session *session;
	struct qdx_pppoe_session *other;
	struct net_device_path_stack stack = {};
	struct qdx_bridge_request bridge = {};
	struct ppp_offload_snapshot *snapshot;
	struct ppp_offload_snapshot captured = {};
	struct ppp_offload_ref *native;
	struct qdx_binding *binding;
	struct qdx_owner owner;
	u32 base;
	unsigned int i;
	bool valid, terminal = false, vlan = false;
	int err;

	ASSERT_RTNL();
	if (!request->dev || request->native_path.type != DEV_PATH_PPPOE ||
	    request->native_path.dev != request->dev ||
	    !request->lower.physical_dev || !request->lower.physical ||
	    !request->lower.execution)
		return ERR_PTR(-EINVAL);
	qdx_uses_lock();
	list_for_each_entry(session, &qdx_pppoe_sessions, node) {
		if (session->prepared.dev != request->dev ||
		    session->prepared.lower.execution != request->lower.execution)
			continue;
		if (session->invalid || !qdx_binding_hold(session->binding)) {
			qdx_uses_unlock();
			return ERR_PTR(-EAGAIN);
		}
		binding = session->binding;
		session->preparations++;
		qdx_uses_unlock();
		if (READ_ONCE(session->assembling))
			return binding;
		valid = ppp_offload_ref_valid(session->native);
		if (!valid) {
			qdx_pppoe_lower_changed(session, false);
			qdx_pppoe_session_prepare_put(binding);
			return ERR_PTR(-ESTALE);
		}
		if (!qdx_pppoe_protocol(&session->snapshot, request->protocol)) {
			qdx_pppoe_session_prepare_put(binding);
			return ERR_PTR(-EOPNOTSUPP);
		}
		return binding;
	}
	if (qdx_pppoe_serial == U64_MAX) {
		qdx_uses_unlock();
		return ERR_PTR(-EOVERFLOW);
	}
	qdx_uses_unlock();
	session = kzalloc_obj(*session);
	if (!session)
		return ERR_PTR(-ENOMEM);
	refcount_set(&session->refs, 1);
	mutex_init(&session->cfg);
	INIT_LIST_HEAD(&session->node);
	INIT_DELAYED_WORK(&session->work, qdx_pppoe_work);
	session->prepared = *request;
	session->assembling = true;
	session->service = qdx_service_get(request->lower.physical_dev, QDX_SERVICE_PPPOE);
	if (IS_ERR(session->service)) {
		err = PTR_ERR(session->service);
		kfree(session);
		return ERR_PTR(err);
	}
	dev_hold(request->lower.physical_dev);
	qdx_endpoint_hold(request->lower.physical);
	qdx_endpoint_hold(request->lower.execution);
	owner = (struct qdx_owner) {
		.module = THIS_MODULE, .object = session,
		.get = qdx_pppoe_ref, .put = qdx_pppoe_unref,
	};
	key.dev = request->dev;
	key.identity = session;
	session->binding = qdx_binding_publish(&key, &owner, &qdx_pppoe_ops);
	if (IS_ERR(session->binding)) {
		err = PTR_ERR(session->binding);
		qdx_endpoint_put(request->lower.execution);
		qdx_endpoint_put(request->lower.physical);
		dev_put(request->lower.physical_dev);
		qdx_service_put(session->service);
		kfree(session);
		return ERR_PTR(err);
	}
	qdx_uses_lock();
	session->serial = ++qdx_pppoe_serial;
	list_add_tail(&session->node, &qdx_pppoe_sessions);
	qdx_uses_unlock();
	snapshot = &session->snapshot;
	/* Published before native get: earlier mutation is caught by generation;
	 * later mutation finds this actual session after its reference is installed.
	 */
	native = ppp_offload_ref_get(request->dev, &captured);
	if (IS_ERR(native)) {
		err = PTR_ERR(native);
		goto failed;
	}
	qdx_uses_lock();
	session->snapshot = captured;
	session->native = native;
	qdx_uses_unlock();
	valid = ppp_offload_ref_valid(session->native);
	if (!valid) {
		err = -ESTALE;
		goto failed;
	}
	if (snapshot->channel_count != 1 || snapshot->path.type != DEV_PATH_PPPOE ||
	    snapshot->pass_filter || snapshot->active_filter || snapshot->vj ||
	    snapshot->tx_compression || snapshot->rx_compression ||
	    (snapshot->flags & (SC_MULTILINK | SC_LOOP_TRAFFIC | SC_COMP_TCP | SC_MUST_COMP)) ||
	    !qdx_pppoe_protocol(snapshot, request->protocol) ||
	    snapshot->path.encap.id != request->native_path.encap.id ||
	    snapshot->path.encap.proto != request->native_path.encap.proto ||
	    !ether_addr_equal(snapshot->path.encap.h_dest, request->native_path.encap.h_dest) ||
	    snapshot->mtu <= 0 || snapshot->mtu > U16_MAX) {
		err = -EOPNOTSUPP;
		goto failed;
	}
	err = dev_fill_forward_path(snapshot->lower_dev, snapshot->path.encap.h_dest, &stack);
	if (err)
		goto failed;
	for (i = 0; i < stack.num_paths; i++) {
		const struct net_device_path *path = &stack.path[i];

		if (path->type == DEV_PATH_VLAN) {
			if (!request->lower.vlan_binding) {
				err = -EOPNOTSUPP;
				goto failed;
			}
			if (path->dev != qdx_binding_dev(request->lower.vlan_binding)) {
				err = -ESTALE;
				goto failed;
			}
			vlan = true;
			continue;
		}
		if (path->type == DEV_PATH_DSA || path->type == DEV_PATH_ETHERNET) {
			if (path->dev != request->lower.physical_dev) {
				err = -ESTALE;
				goto failed;
			}
			terminal = true;
			break;
		}
		if (path->type != DEV_PATH_BRIDGE) {
			err = -EOPNOTSUPP;
			goto failed;
		}
		if (i + 1 == stack.num_paths) {
			err = -ESTALE;
			goto failed;
		}
		bridge.master = (struct net_device *)path->dev;
		bridge.port = (struct net_device *)stack.path[i + 1].dev;
		bridge.position_dev = bridge.master;
		bridge.vid = path->bridge.vlan_id;
		bridge.vlan_mode = path->bridge.vlan_mode;
		bridge.tx = true;
		ether_addr_copy(bridge.destination, snapshot->path.encap.h_dest);
		err = qdx_bridge_path_get(&bridge, &owner, qdx_pppoe_lower_changed,
					  &session->bridge[session->bridge_count]);
		if (err)
			goto failed;
		session->bridge_count++;
		bridge.position_dev = bridge.port;
		err = qdx_bridge_path_get(&bridge, &owner, qdx_pppoe_lower_changed,
					  &session->bridge[session->bridge_count]);
		if (err)
			goto failed;
		session->bridge_count++;
	}
	/* PPP association changes do not all hold RTNL. Match the current native
	 * lower to this actual request before CREATE can expose its base/SID/MAC.
	 * The retained flow path is validated again after its session use exists.
	 */
	if (!terminal || (!!request->lower.vlan_binding != vlan)) {
		err = -ESTALE;
		goto failed;
	}
	if (request->lower.vlan_binding) {
		err = qdx_vlan_endpoint_get(request->lower.vlan_binding, &owner,
					    qdx_pppoe_lower_changed, &session->lower);
		if (err)
			goto failed;
		session->lower_held = true;
		if (session->lower.execution != request->lower.execution) {
			err = -ESTALE;
			goto failed;
		}
	}
	err = qdx_endpoint_ifnum(request->lower.execution, &base);
	if (err)
		goto failed;
	session->create.base = base;
	session->create.mtu = snapshot->mtu;
	session->create.session_id = snapshot->path.encap.id;
	ether_addr_copy(session->create.remote, snapshot->path.encap.h_dest);
	ether_addr_copy(session->create.local, snapshot->lower_dev->dev_addr);
	valid = ppp_offload_ref_valid(session->native);
	qdx_uses_lock();
	/* DESTROY identifies this actual wire key without a lower interface.
	 * Do not create an alias against another live or retiring representation.
	 */
	list_for_each_entry(other, &qdx_pppoe_sessions, node) {
		if (other != session && other->create.session_id == session->create.session_id &&
		    ether_addr_equal(other->create.local, session->create.local) &&
		    ether_addr_equal(other->create.remote, session->create.remote)) {
			valid = false;
			break;
		}
	}
	if (!valid || !qdx_pppoe_dependencies(session) || !qdx_binding_hold(session->binding)) {
		qdx_uses_unlock();
		err = -ESTALE;
		goto failed;
	}
	session->preparations++;
	qdx_uses_unlock();
	mutex_lock(&session->cfg);
	session->assembling = false;
	mutex_unlock(&session->cfg);
	qdx_pppoe_configure(session);
	return session->binding;
failed:
	mutex_lock(&session->cfg);
	session->assembling = false;
	mutex_unlock(&session->cfg);
	qdx_pppoe_lower_changed(session, false);
	return ERR_PTR(err);
}

static void qdx_pppoe_prepare_release(struct qdx_binding *preparation)
{
	struct qdx_pppoe_session *session = qdx_binding_owner(preparation);
	bool retire;

	qdx_uses_lock();
	session->preparations--;
	retire = !session->preparations && !session->users;
	if (retire)
		session->invalid = true;
	qdx_uses_unlock();
	if (retire)
		qdx_pppoe_queue(session);
}

static int qdx_pppoe_acquire(struct qdx_binding *preparation, __be16 protocol,
		const struct qdx_owner *consumer,
		int (*invalidate)(void *consumer, bool may_sleep), struct qdx_pppoe_use *use)
{
	struct qdx_pppoe_session *session = qdx_binding_owner(preparation);
	bool valid;
	int err;

	ASSERT_RTNL();
	if (READ_ONCE(session->assembling) || !session->native)
		return -EAGAIN;
	if (!qdx_pppoe_protocol(&session->snapshot, protocol))
		return -EOPNOTSUPP;
	valid = ppp_offload_ref_valid(session->native);
	if (!valid) {
		qdx_pppoe_lower_changed(session, false);
		return -ESTALE;
	}
	err = qdx_binding_use(preparation, &use->use, consumer, invalidate);
	if (err)
		return err;
	qdx_uses_lock();
	if (!session->available || !qdx_pppoe_dependencies(session) ||
	    qdx_service_state(session->service) != QDX_AVAILABLE) {
		err = -EAGAIN;
	} else {
		qdx_use_publish_locked(&use->use);
		err = qdx_use_available_locked(&use->use) ? 0 : -ESTALE;
		if (!err) {
			session->users++;
			use->execution = session->endpoint;
			use->physical = session->prepared.lower.physical;
			use->transmit = session->prepared.transmit;
			use->session_id = session->create.session_id;
			use->mtu = session->create.mtu;
			ether_addr_copy(use->local, session->create.local);
			ether_addr_copy(use->remote, session->create.remote);
		}
	}
	qdx_uses_unlock();
	if (err)
		qdx_binding_use_put(&use->use);
	return err;
}

static void qdx_pppoe_account_delta(const struct qdx_pppoe_use *use,
				    const struct ppp_offload_stats *delta)
{
	const struct qdx_pppoe_session *session = qdx_binding_owner(use->use.provider);

	ppp_offload_account(session->native, delta);
}

static void qdx_pppoe_release(struct qdx_pppoe_use *use)
{
	struct qdx_pppoe_session *session = qdx_binding_owner(use->use.provider);
	bool retire;

	qdx_uses_lock();
	session->users--;
	retire = !session->users && !session->preparations;
	if (retire)
		session->invalid = true;
	qdx_uses_unlock();
	if (retire)
		qdx_pppoe_queue(session);
}

static const struct qdx_pppoe_ops qdx_pppoe_ops = {
	.prepare = qdx_pppoe_prepare_record,
	.prepare_put = qdx_pppoe_prepare_release,
	.get = qdx_pppoe_acquire,
	.account = qdx_pppoe_account_delta,
	.put = qdx_pppoe_release,
};

static void qdx_pppoe_invalidate(const struct ppp_offload_event *event,
				struct net_device *dev)
{
	struct qdx_pppoe_session *session, *next;
	u64 cursor = 0, limit;
	bool affected;

	qdx_uses_lock();
	limit = qdx_pppoe_serial;
	qdx_uses_unlock();
	for (;;) {
		next = NULL;
		qdx_uses_lock();
		list_for_each_entry(session, &qdx_pppoe_sessions, node) {
			if (session->serial <= cursor || session->serial > limit)
				continue;
			cursor = session->serial;
			if (event)
				affected = session->native &&
					ppp_offload_ref_affected(session->native, event);
			else
				affected = session->prepared.dev == dev ||
					session->snapshot.lower_dev == dev ||
					session->prepared.lower.physical_dev == dev;
			if (affected && qdx_pppoe_ref(session)) {
				next = session;
				break;
			}
		}
		qdx_uses_unlock();
		if (!next)
			break;
		qdx_pppoe_retire(next);
		qdx_pppoe_unref(next);
	}
}

static int qdx_pppoe_change(struct notifier_block *nb,
			    unsigned long action, void *event)
{
	qdx_pppoe_invalidate(event, NULL);
	return NOTIFY_DONE;
}

static int qdx_pppoe_netdev_event(struct notifier_block *nb,
				  unsigned long event, void *data)
{
	switch (event) {
	case NETDEV_DOWN:
	case NETDEV_GOING_DOWN:
	case NETDEV_UNREGISTER:
	case NETDEV_CHANGE:
	case NETDEV_CHANGEADDR:
	case NETDEV_CHANGEMTU:
	case NETDEV_CHANGEUPPER:
	case NETDEV_CHANGELOWERSTATE:
		qdx_pppoe_invalidate(NULL, netdev_notifier_info_to_dev(data));
		break;
	}
	return NOTIFY_DONE;
}

static struct notifier_block qdx_pppoe_native_nb = {
	.notifier_call = qdx_pppoe_change,
};
static struct notifier_block qdx_pppoe_netdev_nb = {
	.notifier_call = qdx_pppoe_netdev_event,
};

static int __init qdx_pppoe_init(void)
{
	const struct qdx_binding_key key = { .role = QDX_BINDING_PPPOE_SESSION };
	const struct qdx_owner owner = { .module = THIS_MODULE };
	int err;

	err = ppp_offload_register_notifier(&qdx_pppoe_native_nb);
	if (err)
		return err;
	err = register_netdevice_notifier(&qdx_pppoe_netdev_nb);
	if (err)
		goto native;
	qdx_pppoe_provider = qdx_binding_publish(&key, &owner, &qdx_pppoe_ops);
	if (IS_ERR(qdx_pppoe_provider)) {
		err = PTR_ERR(qdx_pppoe_provider);
		unregister_netdevice_notifier(&qdx_pppoe_netdev_nb);
		goto native;
	}
	qdx_binding_available(qdx_pppoe_provider);
	return 0;
native:
	ppp_offload_unregister_notifier(&qdx_pppoe_native_nb);
	return err;
}

static void __exit qdx_pppoe_exit(void)
{
	qdx_binding_withdraw(qdx_pppoe_provider);
	unregister_netdevice_notifier(&qdx_pppoe_netdev_nb);
	ppp_offload_unregister_notifier(&qdx_pppoe_native_nb);
}

module_init(qdx_pppoe_init);
module_exit(qdx_pppoe_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("QDX PPPoE session execution and native lifetime");
