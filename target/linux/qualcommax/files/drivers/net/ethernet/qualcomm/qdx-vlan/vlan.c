// SPDX-License-Identifier: GPL-2.0-only
#include <linux/etherdevice.h>
#include <linux/if_arp.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/overflow.h>
#include <linux/qdx/vlan.h>
#include <linux/rtnetlink.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/unaligned.h>
#include <linux/workqueue.h>

static LIST_HEAD(qdx_vlan_paths);
static struct qdx_binding *qdx_vlan_provider;
static struct qdx_binding *qdx_vlan_endpoint_provider;
static LIST_HEAD(qdx_vlan_endpoints);

#define QDX_VLAN_DYNAMIC_TYPE 17
#define QDX_VLAN_ADD_TAG 10000
#define QDX_IF_MTU_CHANGE 3
#define QDX_IF_MAC_ADDR_SET 4
#define QDX_IF_VSI_ASSIGN 13
#define QDX_IF_VSI_UNASSIGN 14
#define QDX_VLAN_COMMAND_TIMEOUT msecs_to_jiffies(3000)

struct qdx_vlan_endpoint {
	struct list_head node;
	refcount_t refs;
	struct mutex cfg;
	struct delayed_work work;
	struct qdx_binding *binding;
	struct qdx_service *service;
	struct qdx_endpoint *endpoint;
	struct qdx_receiver *receiver;
	struct qdx_vlan_endpoint_request prepared;
	struct qdx_vlan_endpoint_use lower;
	struct qdx_vlan_path path;
	struct qdx_vsi *vsi;
	u32 wire_vsi;
	/* ASSIGN, MAC, MTU, ADD_TAG, in firmware prerequisite order. */
	struct qdx_request *commands[4];
	struct qdx_result results[4];
	struct qdx_request *unassign;
	struct qdx_result unassign_result;
	u8 mac[ETH_ALEN];
	u16 mtu;
	unsigned int preparations;
	unsigned int users;
	bool path_held;
	bool lower_held;
	bool invalid;
	bool available;
	bool cleaned;
	bool assembling;
};

static const struct qdx_vlan_endpoint_ops qdx_vlan_endpoint_ops;

static bool qdx_vlan_endpoint_ref(void *object)
{
	struct qdx_vlan_endpoint *endpoint = object;

	return refcount_inc_not_zero(&endpoint->refs);
}

static void qdx_vlan_endpoint_unref(void *object)
{
	struct qdx_vlan_endpoint *endpoint = object;

	if (refcount_dec_and_test(&endpoint->refs))
		kfree(endpoint);
}

static void qdx_vlan_queue(struct qdx_vlan_endpoint *endpoint)
{
	qdx_vlan_endpoint_ref(endpoint);
	__module_get(THIS_MODULE);
	if (!schedule_delayed_work(&endpoint->work, msecs_to_jiffies(20))) {
		qdx_vlan_endpoint_unref(endpoint);
		module_put(THIS_MODULE);
	}
}

static void qdx_vlan_command_done(void *object, const struct qdx_result *result,
				 const void *payload, size_t length);

static int qdx_vlan_retire(struct qdx_vlan_endpoint *endpoint)
{
	const struct qdx_command_recipient recipient = {
		.owner = {
			.module = THIS_MODULE, .object = endpoint,
			.get = qdx_vlan_endpoint_ref, .put = qdx_vlan_endpoint_unref,
		},
		.result = qdx_vlan_command_done,
	};
	const struct qdx_reply_bounds bounds = {
		.maximum = sizeof(__le32), .capacity = sizeof(__le32),
	};
	__le32 wire_vsi;
	struct qdx_binding *binding;
	struct qdx_binding_scan scan;
	struct qdx_binding_use *use;
	unsigned int i, users;
	int err = 0, result;

	qdx_uses_lock();
	if (endpoint->cleaned || !qdx_binding_hold(endpoint->binding)) {
		qdx_uses_unlock();
		return 0;
	}
	binding = endpoint->binding;
	endpoint->invalid = true;
	endpoint->available = false;
	qdx_uses_unlock();
	qdx_binding_invalidate(endpoint->binding);
	qdx_binding_scan_start(endpoint->binding, &scan);
	while ((use = qdx_binding_user_get(endpoint->binding, &scan))) {
		result = use->invalidate(use->consumer.object, true);
		if (result && !err)
			err = result;
		qdx_binding_user_put(use);
	}
	if (err)
		err = qdx_stop_execution(endpoint->service, err);
	mutex_lock(&endpoint->cfg);
	if (endpoint->cleaned)
		goto out;
	if (endpoint->assembling)
		goto pending;
	qdx_uses_lock();
	users = endpoint->users;
	qdx_uses_unlock();
	if (users && !qdx_service_access_ended(endpoint->service))
		goto pending;
	for (i = 0; i < ARRAY_SIZE(endpoint->commands); i++) {
		if (!endpoint->commands[i])
			continue;
		qdx_request_wait(endpoint->commands[i], jiffies,
				 &endpoint->results[i], NULL, 0);
		if (endpoint->results[i].outcome == QDX_UNKNOWN &&
		    !endpoint->results[i].exposure_ended &&
		    !qdx_service_access_ended(endpoint->service)) {
			qdx_stop_execution(endpoint->service, -ETIMEDOUT);
			goto pending;
		}
	}
	/* UNASSIGN needs command admission, before endpoint retirement closes it.
	 * An unknown ASSIGN cannot reach here until its exposure or service ends.
	 */
	if (endpoint->vsi && endpoint->results[0].outcome == QDX_ACK &&
	    !qdx_service_access_ended(endpoint->service)) {
		if (!endpoint->unassign) {
			wire_vsi = cpu_to_le32(endpoint->wire_vsi);
			endpoint->unassign = qdx_command_submit(endpoint->endpoint,
				QDX_IF_VSI_UNASSIGN, &wire_vsi, sizeof(wire_vsi),
				&bounds, &recipient);
			if (IS_ERR(endpoint->unassign)) {
				result = PTR_ERR(endpoint->unassign);
				endpoint->unassign = NULL;
				qdx_stop_execution(endpoint->service, result);
				goto pending;
			}
		}
		qdx_request_wait(endpoint->unassign, jiffies + QDX_VLAN_COMMAND_TIMEOUT,
				 &endpoint->unassign_result, NULL, 0);
		if (endpoint->unassign_result.outcome != QDX_ACK &&
		    !qdx_service_access_ended(endpoint->service)) {
			result = endpoint->unassign_result.error;
			qdx_stop_execution(endpoint->service, result ?: -EREMOTEIO);
			goto pending;
		}
	}
	if (endpoint->endpoint && qdx_endpoint_retire(endpoint->endpoint) &&
	    !qdx_service_access_ended(endpoint->service))
		goto pending;
	if (endpoint->receiver) {
		if (qdx_endpoint_receive_unregister(endpoint->receiver))
			goto pending;
		endpoint->receiver = NULL;
	}
	for (i = 0; i < ARRAY_SIZE(endpoint->commands); i++) {
		qdx_request_put(endpoint->commands[i]);
		endpoint->commands[i] = NULL;
	}
	qdx_request_put(endpoint->unassign);
	endpoint->unassign = NULL;
	qdx_endpoint_put(endpoint->endpoint);
	endpoint->endpoint = NULL;
	qdx_vsi_release(endpoint->vsi);
	endpoint->vsi = NULL;
	if (endpoint->path_held) {
		qdx_vlan_path_put(&endpoint->path);
		endpoint->path_held = false;
	}
	if (endpoint->lower_held) {
		qdx_vlan_endpoint_put(&endpoint->lower);
		endpoint->lower_held = false;
	}
	qdx_endpoint_put(endpoint->prepared.lower.execution);
	qdx_endpoint_put(endpoint->prepared.lower.physical);
	dev_put(endpoint->prepared.lower.physical_dev);
	qdx_service_put(endpoint->service);
	qdx_uses_lock();
	endpoint->cleaned = true;
	list_del_init(&endpoint->node);
	qdx_uses_unlock();
	qdx_binding_withdraw(endpoint->binding);
	qdx_vlan_endpoint_unref(endpoint); /* Actual index reference. */
	goto out;
pending:
	qdx_vlan_queue(endpoint);
out:
	mutex_unlock(&endpoint->cfg);
	qdx_binding_put(binding);
	return err;
}

static int qdx_vlan_lower_changed(void *object, bool may_sleep)
{
	struct qdx_vlan_endpoint *endpoint = object;
	struct qdx_binding *binding;

	qdx_uses_lock();
	if (endpoint->cleaned || !qdx_binding_hold(endpoint->binding)) {
		qdx_uses_unlock();
		return 0;
	}
	binding = endpoint->binding;
	endpoint->invalid = true;
	endpoint->available = false;
	qdx_uses_unlock();
	qdx_binding_invalidate(binding);
	qdx_binding_put(binding);
	if (!may_sleep) {
		qdx_vlan_queue(endpoint);
		return 0;
	}
	return qdx_vlan_retire(endpoint);
}

static void qdx_vlan_command_done(void *object, const struct qdx_result *result,
				  const void *payload, size_t length)
{
	/* The retained request owns the immutable correlated result. */
	qdx_vlan_queue(object);
}

static void qdx_vlan_message(void *object, u32 opcode, u32 response, u32 error,
			     const void *payload, size_t received, size_t declared)
{
	/* Interface totals include CPU traffic and are not flow-only accounting. */
}

static const struct qdx_receive_ops qdx_vlan_receive_ops = {
	.message = qdx_vlan_message,
};

static void qdx_vlan_configure(struct qdx_vlan_endpoint *endpoint)
{
	const struct qdx_owner owner = {
		.module = THIS_MODULE, .object = endpoint,
		.get = qdx_vlan_endpoint_ref, .put = qdx_vlan_endpoint_unref,
	};
	const struct qdx_command_recipient recipient = {
		.owner = owner, .result = qdx_vlan_command_done,
	};
	struct { u32 tag, next_hop, physical; } add_tag;
	const struct qdx_reply_bounds bounds = {
		.maximum = sizeof(add_tag), .capacity = sizeof(add_tag),
	};
	__le32 wire_vsi = cpu_to_le32(endpoint->wire_vsi);
	const void *payload;
	u32 opcode;
	size_t length;
	unsigned int i;
	bool valid;
	int err;

	mutex_lock(&endpoint->cfg);
	if (endpoint->cleaned)
		goto out;
	qdx_uses_lock();
	valid = !endpoint->invalid && qdx_use_available_locked(&endpoint->path.use) &&
		(!endpoint->lower_held || qdx_use_available_locked(&endpoint->lower.use));
	qdx_uses_unlock();
	if (!valid)
		goto retire;
	if (!endpoint->endpoint) {
		endpoint->endpoint = qdx_endpoint_alloc(endpoint->service, QDX_VLAN_DYNAMIC_TYPE);
		if (IS_ERR(endpoint->endpoint)) {
			endpoint->endpoint = NULL;
			goto retire;
		}
	}
	err = qdx_endpoint_wait(endpoint->endpoint, jiffies + QDX_VLAN_COMMAND_TIMEOUT);
	if (err)
		goto retire;
	if (!endpoint->receiver) {
		endpoint->receiver = qdx_endpoint_receive_register(endpoint->endpoint,
			QDX_RECEIVE_MESSAGE, &owner, &qdx_vlan_receive_ops);
		if (IS_ERR(endpoint->receiver)) {
			endpoint->receiver = NULL;
			goto retire;
		}
	}
	add_tag.tag = (ntohs(endpoint->prepared.tag.protocol) << 16) |
		      endpoint->prepared.tag.tci;
	err = qdx_endpoint_ifnum(endpoint->prepared.lower.execution, &add_tag.next_hop);
	if (err)
		goto retire;
	err = qdx_endpoint_ifnum(endpoint->prepared.lower.physical, &add_tag.physical);
	if (err)
		goto retire;
	for (i = 0; i < ARRAY_SIZE(endpoint->commands); i++) {
		if (endpoint->results[i].outcome == QDX_ACK)
			continue;
		qdx_uses_lock();
		valid = !endpoint->invalid && qdx_use_available_locked(&endpoint->path.use) &&
			(!endpoint->lower_held || qdx_use_available_locked(&endpoint->lower.use));
		qdx_uses_unlock();
		if (!valid)
			goto retire;
		if (!endpoint->commands[i]) {
			switch (i) {
			case 0:
				opcode = QDX_IF_VSI_ASSIGN;
				payload = &wire_vsi;
				length = sizeof(wire_vsi);
				break;
			case 1:
				opcode = QDX_IF_MAC_ADDR_SET;
				payload = endpoint->mac;
				length = sizeof(endpoint->mac);
				break;
			case 2:
				opcode = QDX_IF_MTU_CHANGE;
				payload = &endpoint->mtu;
				length = sizeof(endpoint->mtu);
				break;
			default:
				opcode = QDX_VLAN_ADD_TAG;
				payload = &add_tag;
				length = sizeof(add_tag);
				break;
			}
			endpoint->commands[i] = qdx_command_submit(endpoint->endpoint, opcode,
				payload, length, &bounds, &recipient);
			if (IS_ERR(endpoint->commands[i])) {
				endpoint->commands[i] = NULL;
				goto retire;
			}
		}
		qdx_request_wait(endpoint->commands[i], jiffies + QDX_VLAN_COMMAND_TIMEOUT,
				 &endpoint->results[i], NULL, 0);
		if (endpoint->results[i].outcome != QDX_ACK)
			goto retire;
	}
	qdx_uses_lock();
	valid = !endpoint->invalid && qdx_use_available_locked(&endpoint->path.use) &&
		(!endpoint->lower_held || qdx_use_available_locked(&endpoint->lower.use));
	endpoint->available = valid;
	qdx_uses_unlock();
	if (!valid)
		goto retire;
	qdx_binding_available(endpoint->binding);
	goto out;
retire:
	qdx_uses_lock();
	endpoint->invalid = true;
	endpoint->available = false;
	qdx_uses_unlock();
	qdx_binding_invalidate(endpoint->binding);
	qdx_vlan_queue(endpoint);
out:
	mutex_unlock(&endpoint->cfg);
}

static void qdx_vlan_endpoint_work(struct work_struct *work)
{
	struct qdx_vlan_endpoint *endpoint =
		container_of(to_delayed_work(work), struct qdx_vlan_endpoint, work);

	if (READ_ONCE(endpoint->invalid))
		qdx_vlan_retire(endpoint);
	else
		qdx_vlan_configure(endpoint);
	qdx_vlan_endpoint_unref(endpoint);
	module_put(THIS_MODULE);
}

static void qdx_vlan_path_release(struct qdx_vlan_path *path)
{
	qdx_uses_lock();
	list_del_init(&path->node);
	qdx_uses_unlock();
	while (path->dependency_count)
		dev_put(path->dependencies[--path->dependency_count]);
}

static int qdx_vlan_receive(struct qdx_vlan_path *path)
{
	struct net_device *dev = path->request.dev;
	struct qdx_packet_geometry *out = &path->output;
	struct qdx_vlan_tag tag;
	u32 priority;
	unsigned int i, slot;

	for (slot = 0; slot < out->tag_count; slot++)
		if (out->tags[slot].location == QDX_VLAN_METADATA)
			break;
	if (slot == out->tag_count)
		return -EOPNOTSUPP;
	tag = out->tags[slot];
	if (tag.protocol != vlan_dev_vlan_proto(dev) ||
	    (tag.known_tci & VLAN_VID_MASK) != VLAN_VID_MASK ||
	    (tag.tci & VLAN_VID_MASK) != vlan_dev_vlan_id(dev))
		return -ESTALE;
	if ((tag.known_tci & VLAN_PRIO_MASK) == VLAN_PRIO_MASK) {
		priority = vlan_get_ingress_priority(dev, tag.tci);
	} else {
		/* D05: prove a constant mapping, without guessing the input PCP. */
		priority = vlan_get_ingress_priority(dev, 0);
		for (i = 1; i < 8; i++)
			if (vlan_get_ingress_priority(dev, i << VLAN_PRIO_SHIFT) != priority)
				return -EOPNOTSUPP;
	}
	out->priority = priority;
	out->known |= QDX_GEOMETRY_PRIORITY;
	/* Consuming the outer tag preserves the inner payload protocol fact,
	 * including its unknown state and the saved-MAC reinsertion case.
	 */
	memmove(&out->tags[slot], &out->tags[slot + 1],
		(out->tag_count - slot - 1) * sizeof(tag));
	out->tag_count--;
	if (!(vlan_dev_flags(dev) & VLAN_FLAG_REORDER_HDR) &&
	    !netif_is_bridge_port(dev) && !netif_is_macvlan_port(dev)) {
		/* The native insertion is after existing saved MAC tags. */
		for (slot = 0; slot < out->tag_count; slot++)
			if (out->tags[slot].location != QDX_VLAN_SAVED_MAC)
				break;
		memmove(&out->tags[slot + 1], &out->tags[slot],
			(out->tag_count - slot) * sizeof(tag));
		tag.location = QDX_VLAN_SAVED_MAC;
		out->tags[slot] = tag;
		out->tag_count++;
		if (check_add_overflow(out->saved_mac_len, (u16)VLAN_HLEN,
				       &out->saved_mac_len))
			return -EOVERFLOW;
	}
	if (out->known & QDX_GEOMETRY_PACKET_TYPE) {
		if (out->packet_type == PACKET_OTHERHOST) {
			if (!(out->known & QDX_GEOMETRY_DESTINATION))
				return -EOPNOTSUPP;
			if (ether_addr_equal(out->destination, dev->dev_addr))
				out->packet_type = PACKET_HOST;
		}
	}
	return 0;
}

static int qdx_vlan_header(struct qdx_vlan_path *path)
{
	const struct qdx_vlan_request *request = &path->request;
	struct qdx_packet_geometry *out = &path->output;
	struct net_device *dev = request->dev;
	struct sk_buff *skb;
	struct ethhdr *eth;
	__be16 protocol;
	unsigned int room, cursor;
	int length, err = -EOPNOTSUPP;
	u32 needed = QDX_GEOMETRY_PROTOCOL | QDX_GEOMETRY_PRIORITY |
		     QDX_GEOMETRY_DESTINATION;

	if (!request->source_from_device)
		needed |= QDX_GEOMETRY_SOURCE;
	if ((out->known & needed) != needed || out->tag_count ||
	    out->protocol == htons(ETH_P_802_3) ||
	    out->protocol == htons(ETH_P_802_2) || eth_type_vlan(out->protocol))
		return -EOPNOTSUPP;
	room = max_t(unsigned int, LL_RESERVED_SPACE(dev),
		     ETH_HLEN + VLAN_HLEN * (path->dependency_count - 1));
	/* LL_RESERVED_SPACE is unsigned-short based, with this checked bound. */
	if (room > U16_MAX)
		return -EOVERFLOW;
	skb = alloc_skb(room, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;
	skb_reserve(skb, room);
	skb->priority = out->priority;
	skb->protocol = out->protocol;
	length = dev_hard_header(skb, dev, ntohs(out->protocol), out->destination,
		request->source_from_device ? NULL : out->source, 0);
	if (length < ETH_HLEN || length != skb->len || length > room)
		goto done;
	eth = (struct ethhdr *)skb->data;
	protocol = eth->h_proto;
	out->frame_protocol = protocol;
	ether_addr_copy(out->source, eth->h_source);
	ether_addr_copy(out->destination, eth->h_dest);
	cursor = ETH_HLEN;
	while (eth_type_vlan(protocol)) {
		struct qdx_vlan_tag *tag;

		if (cursor + VLAN_HLEN > length || out->tag_count == QDX_VLAN_DEPTH)
			goto done;
		tag = &out->tags[out->tag_count++];
		tag->protocol = protocol;
		tag->tci = get_unaligned_be16(skb->data + cursor);
		tag->known_tci = U16_MAX;
		tag->location = QDX_VLAN_IN_FRAME;
		protocol = get_unaligned((__be16 *)(skb->data + cursor + sizeof(u16)));
		cursor += VLAN_HLEN;
	}
	if (cursor != length || protocol != request->input.protocol)
		goto done;
	if (check_add_overflow(out->data_overhead, length, &out->data_overhead) ||
	    check_add_overflow(out->wire_overhead, (u16)length, &out->wire_overhead)) {
		err = -EOVERFLOW;
		goto done;
	}
	out->protocol = skb->protocol;
	out->vlan_payload_protocol = protocol;
	out->known |= QDX_GEOMETRY_SOURCE | QDX_GEOMETRY_DESTINATION |
		      QDX_GEOMETRY_FRAME_PROTOCOL | QDX_GEOMETRY_VLAN_PAYLOAD_PROTOCOL;
	err = 0;
done:
	kfree_skb(skb);
	return err;
}

static int qdx_vlan_transmit(struct qdx_vlan_path *path)
{
	struct net_device *dev = path->request.dev;
	struct qdx_packet_geometry *out = &path->output;
	struct qdx_vlan_tag *tag;
	unsigned int slot;

	if (!(vlan_dev_flags(dev) & VLAN_FLAG_REORDER_HDR)) {
		if (!(out->known & QDX_GEOMETRY_FRAME_PROTOCOL))
			return -EOPNOTSUPP;
		if (out->frame_protocol == vlan_dev_vlan_proto(dev))
			return 0;
	}
	if (!(out->known & QDX_GEOMETRY_PRIORITY))
		return -EOPNOTSUPP;
	for (slot = 0; slot < out->tag_count; slot++)
		if (out->tags[slot].location == QDX_VLAN_METADATA)
			break;
	if (slot == out->tag_count) {
		if (out->tag_count == QDX_VLAN_DEPTH)
			return -EOPNOTSUPP;
		memmove(&out->tags[1], &out->tags[0],
			out->tag_count * sizeof(*tag));
		out->tag_count++;
		slot = 0;
		if (check_add_overflow(out->wire_overhead, (u16)VLAN_HLEN,
				       &out->wire_overhead))
			return -EOVERFLOW;
	}
	/* Adding/replacing this outer metadata tag does not change its payload. */
	tag = &out->tags[slot];
	tag->protocol = vlan_dev_vlan_proto(dev);
	tag->tci = vlan_dev_vlan_id(dev) |
		   vlan_dev_get_egress_qos_mask(dev, out->priority);
	tag->known_tci = U16_MAX;
	tag->location = QDX_VLAN_METADATA;
	return 0;
}

static int qdx_vlan_path_acquire(struct qdx_binding *provider,
		const struct qdx_vlan_request *request,
		const struct qdx_owner *consumer,
		int (*invalidate)(void *consumer, bool may_sleep),
		struct qdx_vlan_path *path)
{
	struct net_device *dev = request->dev, *lower, *next;
	struct list_head *iter;
	int err;

	ASSERT_RTNL();
	if (!dev || request->input.tag_count > QDX_VLAN_DEPTH ||
	    request->position > QDX_VLAN_TX ||
	    (request->position != QDX_VLAN_HEADER && !is_vlan_dev(dev)))
		return -EINVAL;
	path->request = *request;
	path->output = request->input;
	path->output.mtu = dev->mtu;
	path->dependency_count = 0;
	INIT_LIST_HEAD(&path->node);
	/* Follow real native adjacency, never the flattened VLAN real-dev helper. */
	for (;;) {
		if (path->dependency_count == ARRAY_SIZE(path->dependencies)) {
			err = -E2BIG;
			goto put_devices;
		}
		dev_hold(dev);
		path->dependencies[path->dependency_count++] = dev;
		if (!is_vlan_dev(dev))
			break;
		next = NULL;
		netdev_for_each_lower_dev(dev, lower, iter) {
			if (next) {
				err = -EOPNOTSUPP;
				goto put_devices;
			}
			next = lower;
		}
		if (!next || (dev == request->dev && request->immediate_lower &&
			     next != request->immediate_lower)) {
			err = -ESTALE;
			goto put_devices;
		}
		dev = next;
	}
	if (dev->type != ARPHRD_ETHER || dev->addr_len != ETH_ALEN) {
		err = -EOPNOTSUPP;
		goto put_devices;
	}
	err = qdx_binding_use(provider, &path->use, consumer, invalidate);
	if (err)
		goto put_devices;
	qdx_uses_lock();
	list_add_tail(&path->node, &qdx_vlan_paths);
	qdx_uses_unlock();
	if (!(request->dev->flags & IFF_UP)) {
		err = -ENETDOWN;
		goto failed;
	}
	switch (request->position) {
	case QDX_VLAN_RX:
		err = qdx_vlan_receive(path);
		break;
	case QDX_VLAN_HEADER:
		err = qdx_vlan_header(path);
		break;
	case QDX_VLAN_TX:
		err = qdx_vlan_transmit(path);
		break;
	}
	if (err)
		goto failed;
	qdx_uses_lock();
	qdx_use_publish_locked(&path->use);
	err = qdx_use_available_locked(&path->use) ? 0 : -ESTALE;
	qdx_uses_unlock();
	if (!err)
		return 0;
failed:
	qdx_vlan_path_release(path);
	qdx_binding_use_put(&path->use);
	return err;
put_devices:
	while (path->dependency_count)
		dev_put(path->dependencies[--path->dependency_count]);
	return err;
}

static const struct qdx_vlan_ops qdx_vlan_ops = {
	.get = qdx_vlan_path_acquire,
	.put = qdx_vlan_path_release,
};

static struct qdx_binding *
qdx_vlan_endpoint_prepare_record(const struct qdx_vlan_endpoint_request *request)
{
	struct qdx_binding_key key = { .role = QDX_BINDING_VLAN_ENDPOINT };
	struct qdx_vlan_endpoint *endpoint;
	struct qdx_owner owner;
	struct qdx_binding *binding;
	unsigned int i;
	bool tag_found = false;
	int err;

	ASSERT_RTNL();
	if (!request->path.dev || !is_vlan_dev(request->path.dev) ||
	    !request->lower.physical_dev || !request->lower.physical ||
	    !request->lower.execution || request->tag.known_tci != U16_MAX ||
	    request->tag.location == QDX_VLAN_SAVED_MAC)
		return ERR_PTR(-EINVAL);
	qdx_uses_lock();
	list_for_each_entry(endpoint, &qdx_vlan_endpoints, node) {
		if (endpoint->prepared.path.dev != request->path.dev ||
		    endpoint->prepared.lower.execution != request->lower.execution ||
		    endpoint->prepared.tag.protocol != request->tag.protocol ||
		    endpoint->prepared.tag.tci != request->tag.tci)
			continue;
		if (endpoint->invalid || !qdx_binding_hold(endpoint->binding)) {
			qdx_uses_unlock();
			return ERR_PTR(-EAGAIN);
		}
		endpoint->preparations++;
		binding = endpoint->binding;
		qdx_uses_unlock();
		return binding;
	}
	qdx_uses_unlock();
	endpoint = kzalloc_obj(*endpoint);
	if (!endpoint)
		return ERR_PTR(-ENOMEM);
	refcount_set(&endpoint->refs, 1);
	mutex_init(&endpoint->cfg);
	INIT_LIST_HEAD(&endpoint->node);
	INIT_DELAYED_WORK(&endpoint->work, qdx_vlan_endpoint_work);
	endpoint->prepared = *request;
	endpoint->assembling = true;
	endpoint->service = qdx_service_get(request->lower.physical_dev, QDX_SERVICE_VLAN);
	if (IS_ERR(endpoint->service)) {
		err = PTR_ERR(endpoint->service);
		kfree(endpoint);
		return ERR_PTR(err);
	}
	dev_hold(request->lower.physical_dev);
	qdx_endpoint_hold(request->lower.physical);
	qdx_endpoint_hold(request->lower.execution);
	owner = (struct qdx_owner) {
		.module = THIS_MODULE, .object = endpoint,
		.get = qdx_vlan_endpoint_ref, .put = qdx_vlan_endpoint_unref,
	};
	key.dev = request->path.dev;
	key.identity = endpoint;
	endpoint->binding = qdx_binding_publish(&key, &owner, &qdx_vlan_endpoint_ops);
	if (IS_ERR(endpoint->binding)) {
		err = PTR_ERR(endpoint->binding);
		qdx_endpoint_put(request->lower.execution);
		qdx_endpoint_put(request->lower.physical);
		dev_put(request->lower.physical_dev);
		qdx_service_put(endpoint->service);
		kfree(endpoint);
		return ERR_PTR(err);
	}
	qdx_uses_lock();
	list_add_tail(&endpoint->node, &qdx_vlan_endpoints);
	qdx_uses_unlock();
	if (request->lower.vlan_binding) {
		err = qdx_vlan_endpoint_get(request->lower.vlan_binding, &owner,
					    qdx_vlan_lower_changed, &endpoint->lower);
		if (err)
			goto failed;
		endpoint->lower_held = true;
		if (endpoint->lower.execution != request->lower.execution) {
			err = -ESTALE;
			goto failed;
		}
	}
	err = qdx_vlan_path_get(&request->path, &owner, qdx_vlan_lower_changed,
				&endpoint->path);
	if (err)
		goto failed;
	endpoint->path_held = true;
	for (i = 0; i < endpoint->path.output.tag_count; i++) {
		const struct qdx_vlan_tag *tag = &endpoint->path.output.tags[i];

		if (tag->location != QDX_VLAN_SAVED_MAC && tag->known_tci == U16_MAX &&
		    tag->protocol == request->tag.protocol && tag->tci == request->tag.tci)
			tag_found = true;
	}
	if (!tag_found) {
		err = -EOPNOTSUPP;
		goto failed;
	}
	/* RTNL is already held; never allocate from configure under cfg. */
	endpoint->vsi = qdx_vsi_alloc(request->lower.physical, &endpoint->wire_vsi);
	if (IS_ERR(endpoint->vsi)) {
		err = PTR_ERR(endpoint->vsi);
		endpoint->vsi = NULL;
		goto failed;
	}
	ether_addr_copy(endpoint->mac, request->path.dev->dev_addr);
	endpoint->mtu = request->path.dev->mtu;
	qdx_uses_lock();
	if (endpoint->invalid || !qdx_binding_hold(endpoint->binding)) {
		qdx_uses_unlock();
		err = -ESTALE;
		goto failed;
	}
	endpoint->preparations++;
	qdx_uses_unlock();
	mutex_lock(&endpoint->cfg);
	endpoint->assembling = false;
	mutex_unlock(&endpoint->cfg);
	qdx_vlan_configure(endpoint);
	return endpoint->binding;
failed:
	mutex_lock(&endpoint->cfg);
	endpoint->assembling = false;
	mutex_unlock(&endpoint->cfg);
	qdx_vlan_lower_changed(endpoint, false);
	return ERR_PTR(err);
}

static void qdx_vlan_endpoint_prepare_release(struct qdx_binding *preparation)
{
	struct qdx_vlan_endpoint *endpoint = qdx_binding_owner(preparation);
	bool retire;

	qdx_uses_lock();
	endpoint->preparations--;
	retire = !endpoint->preparations && !endpoint->users;
	if (retire)
		endpoint->invalid = true;
	qdx_uses_unlock();
	if (retire)
		qdx_vlan_queue(endpoint);
}

static int qdx_vlan_endpoint_acquire(struct qdx_binding *preparation,
		const struct qdx_owner *consumer,
		int (*invalidate)(void *consumer, bool may_sleep),
		struct qdx_vlan_endpoint_use *use)
{
	struct qdx_vlan_endpoint *endpoint = qdx_binding_owner(preparation);
	int err;

	ASSERT_RTNL();
	err = qdx_binding_use(preparation, &use->use, consumer, invalidate);
	if (err)
		return err;
	qdx_uses_lock();
	if (endpoint->invalid || !endpoint->available ||
	    qdx_service_state(endpoint->service) != QDX_AVAILABLE ||
	    !qdx_use_available_locked(&endpoint->path.use) ||
	    (endpoint->lower_held && !qdx_use_available_locked(&endpoint->lower.use))) {
		err = -EAGAIN;
	} else {
		qdx_use_publish_locked(&use->use);
		err = qdx_use_available_locked(&use->use) ? 0 : -ESTALE;
		if (!err) {
			endpoint->users++;
			use->execution = endpoint->endpoint;
			use->physical = endpoint->prepared.lower.physical;
		}
	}
	qdx_uses_unlock();
	if (err)
		qdx_binding_use_put(&use->use);
	return err;
}

static void qdx_vlan_endpoint_release(struct qdx_vlan_endpoint_use *use)
{
	struct qdx_vlan_endpoint *endpoint = qdx_binding_owner(use->use.provider);
	bool retire;

	qdx_uses_lock();
	endpoint->users--;
	retire = !endpoint->users && !endpoint->preparations;
	if (retire)
		endpoint->invalid = true;
	qdx_uses_unlock();
	if (retire)
		qdx_vlan_queue(endpoint);
}

static const struct qdx_vlan_endpoint_ops qdx_vlan_endpoint_ops = {
	.prepare = qdx_vlan_endpoint_prepare_record,
	.prepare_put = qdx_vlan_endpoint_prepare_release,
	.get = qdx_vlan_endpoint_acquire,
	.put = qdx_vlan_endpoint_release,
};

static int qdx_vlan_event(struct notifier_block *nb,
			  unsigned long event, void *data)
{
	struct net_device *dev = netdev_notifier_info_to_dev(data);
	struct qdx_binding_scan scan;
	struct qdx_binding_use *use;
	struct qdx_vlan_path *path;
	unsigned int i;
	bool invalid;

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
	list_for_each_entry(path, &qdx_vlan_paths, node)
		for (i = 0; i < path->dependency_count; i++)
			if (path->dependencies[i] == dev)
				qdx_use_invalidate_locked(&path->use);
	qdx_uses_unlock();
	if (!qdx_vlan_provider)
		return NOTIFY_DONE;
	qdx_binding_scan_start(qdx_vlan_provider, &scan);
	while ((use = qdx_binding_user_get(qdx_vlan_provider, &scan))) {
		qdx_uses_lock();
		invalid = use->invalid;
		qdx_uses_unlock();
		if (invalid)
			use->invalidate(use->consumer.object, true);
		qdx_binding_user_put(use);
	}
	return NOTIFY_DONE;
}

static struct notifier_block qdx_vlan_nb = {
	.notifier_call = qdx_vlan_event,
};

static int __init qdx_vlan_init(void)
{
	struct qdx_binding_key key = { .role = QDX_BINDING_VLAN_PATH };
	const struct qdx_owner owner = { .module = THIS_MODULE };
	int err;

	err = register_netdevice_notifier(&qdx_vlan_nb);
	if (err)
		return err;
	qdx_vlan_provider = qdx_binding_publish(&key, &owner, &qdx_vlan_ops);
	if (IS_ERR(qdx_vlan_provider)) {
		err = PTR_ERR(qdx_vlan_provider);
		qdx_vlan_provider = NULL;
		unregister_netdevice_notifier(&qdx_vlan_nb);
		return err;
	}
	qdx_binding_available(qdx_vlan_provider);
	key.role = QDX_BINDING_VLAN_ENDPOINT;
	qdx_vlan_endpoint_provider = qdx_binding_publish(&key, &owner,
						       &qdx_vlan_endpoint_ops);
	if (IS_ERR(qdx_vlan_endpoint_provider)) {
		err = PTR_ERR(qdx_vlan_endpoint_provider);
		qdx_binding_withdraw(qdx_vlan_provider);
		qdx_vlan_provider = NULL;
		unregister_netdevice_notifier(&qdx_vlan_nb);
		return err;
	}
	qdx_binding_available(qdx_vlan_endpoint_provider);
	return 0;
}

static void __exit qdx_vlan_exit(void)
{
	qdx_binding_withdraw(qdx_vlan_endpoint_provider);
	qdx_binding_invalidate(qdx_vlan_provider);
	unregister_netdevice_notifier(&qdx_vlan_nb);
	qdx_binding_withdraw(qdx_vlan_provider);
}

module_init(qdx_vlan_init);
module_exit(qdx_vlan_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("QDX native VLAN path interpretation and endpoints");
