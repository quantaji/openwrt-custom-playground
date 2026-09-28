// SPDX-License-Identifier: GPL-2.0-only
/* A published command remains owned independently of its waiter and carrier. */
#include <linux/jiffies.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/unaligned.h>
#include <linux/xarray.h>
#include "qdx.h"

#define QDX_HOST_TAG 0x514458434f4d4d31ULL
#define QDX_COMMAND_PAYLOAD (QDX_COMMAND_SIZE - sizeof(struct qdx_cmn))
#define QDX_COMMAND_TIMEOUT msecs_to_jiffies(3000)

struct qdx_request {
	refcount_t refs;
	spinlock_t lock;
	struct completion done;
	struct qdx_core *core;
	struct qdx_endpoint *endpoint;
	struct qdx_command_recipient recipient;
	struct qdx_result result;
	struct qdx_reply_bounds bounds;
	u64 id;
	u32 ifnum;
	u32 opcode;
	bool cancelled;
	bool reported_error;
	bool delivering;
	bool delivery_pending;
	u8 data[];
};

struct qdx_commands {
	struct xarray pending;
	wait_queue_head_t drained;
	atomic_t objects;
	atomic_t callers;
	unsigned int reserved;
	bool closed;
	atomic64_t notifications;
	atomic64_t malformed;
	atomic64_t late;
};

static atomic64_t qdx_command_id = ATOMIC64_INIT(0);

void qdx_request_put(struct qdx_request *request)
{
	struct qdx_commands *commands;
	unsigned long flags;

	if (!request || !refcount_dec_and_test(&request->refs))
		return;
	commands = request->core->commands;
	if (request->recipient.result)
		qdx_owner_put(&request->recipient.owner);
	qdx_endpoint_put(request->endpoint);
	kfree(request);
	xa_lock_irqsave(&commands->pending, flags);
	if (atomic_dec_and_test(&commands->objects))
		wake_up_all(&commands->drained);
	xa_unlock_irqrestore(&commands->pending, flags);
}
EXPORT_SYMBOL_GPL(qdx_request_put);

/* One original recipient observes monotonic results, outside drv locks. A
 * concurrent final response supersedes a warning not yet delivered. The active
 * delivery reference also keeps a queued final result alive after index removal.
 */
static void qdx_request_deliver(struct qdx_request *request)
{
	struct qdx_result result;
	unsigned long flags;
	size_t length;

	spin_lock_irqsave(&request->lock, flags);
	if (request->delivering) {
		spin_unlock_irqrestore(&request->lock, flags);
		return;
	}
	request->delivering = true;
	while (request->delivery_pending) {
		request->delivery_pending = false;
		result = request->result;
		length = result.outcome == QDX_UNKNOWN ? 0 :
			 min(result.received_len, request->bounds.capacity);
		spin_unlock_irqrestore(&request->lock, flags);
		if (request->recipient.result)
			request->recipient.result(request->recipient.owner.object, &result,
						  length ? request->data : NULL, length);
		spin_lock_irqsave(&request->lock, flags);
	}
	request->delivering = false;
	spin_unlock_irqrestore(&request->lock, flags);
}

int qdx_commands_init(struct qdx_core *core)
{
	struct qdx_commands *commands = kzalloc(sizeof(*commands), GFP_KERNEL);

	if (!commands)
		return -ENOMEM;
	xa_init_flags(&commands->pending, XA_FLAGS_LOCK_IRQ);
	init_waitqueue_head(&commands->drained);
	atomic_set(&commands->objects, 0);
	atomic_set(&commands->callers, 0);
	core->commands = commands;
	return 0;
}

/* Called with the data/control ring locked, immediately before publication.
 * No path holding pending/request locks enters the producer ring lock.
 */
int qdx_command_publish(struct qdx_core *core, u64 id)
{
	struct qdx_commands *commands = core->commands;
	struct qdx_request *request;
	unsigned long flags;
	int error = 0;

	if (!id)
		return 0;
	xa_lock_irqsave(&commands->pending, flags);
	request = xa_load(&commands->pending, id);
	if (!request || commands->closed) {
		error = -ESHUTDOWN;
	} else {
		spin_lock(&request->lock);
		request->result.published = true;
		spin_unlock(&request->lock);
	}
	xa_unlock_irqrestore(&commands->pending, flags);
	return error;
}

static struct qdx_request *qdx_submit(struct qdx_core *core,
		struct qdx_endpoint *endpoint, u32 ifnum, u32 opcode,
		const void *body, size_t length, const struct qdx_reply_bounds *bounds,
		const struct qdx_command_recipient *recipient)
{
	struct qdx_commands *commands = core->commands;
	struct qdx_request *request;
	struct qdx_cmn *message;
	unsigned long flags;
	s64 previous;
	bool reserved = true, removed;
	int error;

	if (!commands)
		return ERR_PTR(-ENODEV);
	if (!bounds || (length && !body) || length > QDX_COMMAND_PAYLOAD ||
	    bounds->minimum > bounds->maximum || bounds->maximum > bounds->capacity ||
	    bounds->capacity > U16_MAX || ifnum > 0xffffff)
		return ERR_PTR(-EINVAL);
	xa_lock_irqsave(&commands->pending, flags);
	if (commands->closed)
		error = -ESHUTDOWN;
	else if (commands->reserved >= QDX_REQUESTS)
		error = -EAGAIN;
	else {
		commands->reserved++;
		atomic_inc(&commands->callers);
		error = 0;
	}
	xa_unlock_irqrestore(&commands->pending, flags);
	if (error)
		return ERR_PTR(error);
	request = kzalloc(struct_size(request, data, bounds->capacity), GFP_KERNEL);
	if (!request) {
		error = -ENOMEM;
		goto unreserve;
	}
	refcount_set(&request->refs, 1);
	spin_lock_init(&request->lock);
	init_completion(&request->done);
	request->core = core;
	request->bounds = *bounds;
	request->ifnum = ifnum;
	request->opcode = opcode;
	request->result.outcome = QDX_UNKNOWN;
	request->result.error = -EINPROGRESS;
	atomic_inc(&commands->objects);
	if (endpoint) {
		qdx_endpoint_hold(endpoint);
		request->endpoint = endpoint;
	}
	if (recipient && recipient->result) {
		if (!qdx_owner_get(&recipient->owner)) {
			error = -ESHUTDOWN;
			goto put;
		}
		request->recipient = *recipient;
	}
	previous = atomic64_read(&qdx_command_id);
	do {
		if ((u64)previous == U64_MAX) {
			error = -EOVERFLOW;
			goto put;
		}
	} while (!atomic64_try_cmpxchg(&qdx_command_id, &previous, (u64)previous + 1));
	request->id = (u64)previous + 1;
	request->result.id = request->id;
	request->result.opcode = opcode;
	request->result.ifnum = ifnum;
	message = kzalloc(QDX_COMMAND_SIZE, GFP_KERNEL);
	if (!message) {
		error = -ENOMEM;
		goto put;
	}
	message->version = cpu_to_le16(QDX_MESSAGE_VERSION);
	message->length = cpu_to_le16(length);
	message->interface = cpu_to_le32(ifnum);
	message->type = cpu_to_le32(opcode);
	message->host_tag = cpu_to_le64(QDX_HOST_TAG);
	message->request_id = cpu_to_le64(request->id);
	if (length)
		memcpy(message + 1, body, length);
	xa_lock_irqsave(&commands->pending, flags);
	if (commands->closed)
		error = -ESHUTDOWN;
	else
		error = __xa_insert(&commands->pending, request->id, request, GFP_ATOMIC);
	if (!error) {
		refcount_inc(&request->refs);
		reserved = false; /* The index now owns both reference and reservation. */
	}
	xa_unlock_irqrestore(&commands->pending, flags);
	if (error)
		goto free_message;
	error = qdx_io_command(core, message, sizeof(*message) + length, request->id);
	if (!error) {
		xa_lock_irqsave(&commands->pending, flags);
		if (atomic_dec_and_test(&commands->callers))
			wake_up_all(&commands->drained);
		xa_unlock_irqrestore(&commands->pending, flags);
		return request; /* Carrier and response may already have returned. */
	}
	xa_lock_irqsave(&commands->pending, flags);
	removed = __xa_erase(&commands->pending, request->id) == request;
	if (removed)
		commands->reserved--;
	xa_unlock_irqrestore(&commands->pending, flags);
	if (removed)
		qdx_request_put(request); /* Only the actual remover owns this put. */
free_message:
	kfree(message);
put:
	qdx_request_put(request);
unreserve:
	xa_lock_irqsave(&commands->pending, flags);
	if (reserved)
		commands->reserved--;
	if (atomic_dec_and_test(&commands->callers))
		wake_up_all(&commands->drained);
	xa_unlock_irqrestore(&commands->pending, flags);
	return ERR_PTR(error);
}

struct qdx_request *qdx_command_submit(struct qdx_endpoint *endpoint, u32 opcode,
		const void *payload, size_t length, const struct qdx_reply_bounds *bounds,
		const struct qdx_command_recipient *recipient)
{
	u32 ifnum;
	int error = qdx_endpoint_ifnum(endpoint, &ifnum);

	if (error)
		return ERR_PTR(error);
	if (!qdx_endpoint_command_ready(endpoint))
		return ERR_PTR(-ESHUTDOWN);
	return qdx_submit(endpoint->core, endpoint, ifnum, opcode, payload, length,
			  bounds, recipient);
}
EXPORT_SYMBOL_GPL(qdx_command_submit);

int qdx_request_wait(struct qdx_request *request, unsigned long deadline,
		    struct qdx_result *result, void *payload, size_t capacity)
{
	unsigned long flags, now = jiffies;
	size_t copied;
	bool completed;
	int error;

	completed = wait_for_completion_timeout(&request->done,
			time_before(now, deadline) ? deadline - now : 0);
	spin_lock_irqsave(&request->lock, flags);
	*result = request->result;
	if (!completed && result->error == -EINPROGRESS)
		result->error = -ETIMEDOUT; /* This wait, not the exposed request. */
	copied = min(result->received_len, request->bounds.capacity);
	error = result->error;
	if (payload && copied > capacity)
		error = -EMSGSIZE;
	else if (payload && copied)
		memcpy(payload, request->data, copied);
	spin_unlock_irqrestore(&request->lock, flags);
	return error;
}
EXPORT_SYMBOL_GPL(qdx_request_wait);

void qdx_request_cancel(struct qdx_request *request)
{
	unsigned long flags;

	spin_lock_irqsave(&request->lock, flags);
	request->cancelled = true;
	if (request->result.outcome == QDX_UNKNOWN &&
	    !request->result.exposure_ended)
		request->result.error = -ECANCELED;
	spin_unlock_irqrestore(&request->lock, flags);
	complete_all(&request->done);
}
EXPORT_SYMBOL_GPL(qdx_request_cancel);

/* Existing boot/physical callers share the same owned request engine. */
int qdx_command(struct qdx_core *core, u32 ifnum, u32 opcode,
		const void *body, size_t length, struct qdx_reply *reply)
{
	struct qdx_reply_bounds bounds = {
		.minimum = reply->min_len, .maximum = reply->max_len,
		.capacity = max_t(size_t, length, reply->max_len),
	};
	struct qdx_result result;
	struct qdx_request *request;
	unsigned long deadline = jiffies + QDX_COMMAND_TIMEOUT;
	int error;

	reply->outcome = QDX_NOT_SUBMITTED;
	reply->len = 0;
	reply->firmware_error = 0;
	request = qdx_submit(core, NULL, ifnum, opcode, body, length, &bounds, NULL);
	if (IS_ERR(request))
		return PTR_ERR(request);
	error = qdx_request_wait(request, deadline, &result, reply->data, reply->max_len);
	reply->outcome = result.outcome;
	reply->len = min_t(size_t, result.declared_len, reply->max_len);
	reply->firmware_error = result.firmware_error;
	qdx_request_put(request);
	return error;
}

void qdx_command_receive(struct qdx_core *core, u32 ifnum, const void *data,
			 size_t accessible)
{
	struct qdx_commands *commands = core->commands;
	struct qdx_request *request;
	struct qdx_cmn header;
	unsigned long flags;
	size_t received, declared, copied;
	u32 opcode, response;
	u64 id;
	bool settled = false, report = false;

	if (!commands || accessible < sizeof(header))
		goto corrupt;
	memcpy(&header, data, sizeof(header));
	if (le16_to_cpu(header.version) != QDX_MESSAGE_VERSION ||
	    le32_to_cpu(header.interface) != ifnum || ifnum > 0xffffff)
		goto corrupt;
	declared = le16_to_cpu(header.length);
	received = accessible - sizeof(header);
	opcode = le32_to_cpu(header.type);
	response = le32_to_cpu(header.response);
	if (response >= QDX_RESPONSE_MAX)
		goto corrupt;
	if (response == QDX_RESPONSE_NOTIFY) {
		atomic64_inc(&commands->notifications);
		qdx_endpoint_message(core, ifnum, opcode, response,
			le32_to_cpu(header.error), data + sizeof(header), received, declared);
		return;
	}
	if (le64_to_cpu(header.host_tag) != QDX_HOST_TAG)
		goto corrupt;
	id = le64_to_cpu(header.request_id);
	xa_lock_irqsave(&commands->pending, flags);
	request = xa_load(&commands->pending, id);
	if (!request) {
		atomic64_inc(&commands->late);
		xa_unlock_irqrestore(&commands->pending, flags);
		return;
	}
	spin_lock(&request->lock);
	if (request->ifnum != ifnum || request->opcode != opcode ||
	    !request->result.published) {
		spin_unlock(&request->lock);
		xa_unlock_irqrestore(&commands->pending, flags);
		goto corrupt;
	}
	refcount_inc(&request->refs); /* Delivery survives index removal. */
	if (declared > received || declared > request->bounds.capacity ||
	    (response == QDX_RESPONSE_ACK &&
	     (declared < request->bounds.minimum || declared > request->bounds.maximum))) {
		request->result.error = -EPROTO;
		atomic64_inc(&commands->malformed);
		if (!request->reported_error) {
			request->reported_error = true;
			report = true;
		}
		copied = 0; /* Unsettled storage may later receive a real response. */
	} else {
		request->result.outcome = response == QDX_RESPONSE_ACK ? QDX_ACK : QDX_REJECTED;
		request->result.error = response == QDX_RESPONSE_ACK ? 0 : -EREMOTEIO;
		request->result.firmware_error = le32_to_cpu(header.error);
		request->result.received_len = received;
		request->result.declared_len = declared;
		copied = min(received, request->bounds.capacity);
		if (copied)
			memcpy(request->data, data + sizeof(header), copied);
		__xa_erase(&commands->pending, id);
		commands->reserved--;
		settled = true;
		report = true;
	}
	if (report)
		request->delivery_pending = true;
	spin_unlock(&request->lock);
	xa_unlock_irqrestore(&commands->pending, flags);
	complete_all(&request->done);
	qdx_request_deliver(request);
	if (settled)
		qdx_request_put(request); /* Exposure ended by actual ACK/NACK. */
	qdx_request_put(request);
	return;
corrupt:
	qdx_fail(core->qdx, -EPROTO);
}

void qdx_command_return(struct qdx_core *core, u64 id, u32 status)
{
	struct qdx_commands *commands = core->commands;
	struct qdx_request *request;
	unsigned long flags;

	if (!status || !id || !commands)
		return;
	if (status > 5) {
		qdx_fail(core->qdx, -EPROTO);
		return;
	}
	xa_lock_irqsave(&commands->pending, flags);
	request = xa_load(&commands->pending, id);
	if (!request) {
		xa_unlock_irqrestore(&commands->pending, flags);
		return;
	}
	refcount_inc(&request->refs);
	spin_lock(&request->lock);
	request->result.error = -EIO;
	if (!request->reported_error)
		request->delivery_pending = true;
	request->reported_error = true;
	spin_unlock(&request->lock);
	xa_unlock_irqrestore(&commands->pending, flags);
	complete_all(&request->done);
	qdx_request_deliver(request);
	qdx_request_put(request);
}

int qdx_message_core(struct qdx_core *core, u32 ifnum, u32 opcode,
		     const void *payload, size_t length)
{
	struct qdx_cmn *message;
	int error;

	if (length > QDX_COMMAND_PAYLOAD || (length && !payload) || ifnum > 0xffffff)
		return -EINVAL;
	if (!core->commands || READ_ONCE(core->commands->closed))
		return -ESHUTDOWN;
	message = kzalloc(QDX_COMMAND_SIZE, GFP_KERNEL);
	if (!message)
		return -ENOMEM;
	message->version = cpu_to_le16(QDX_MESSAGE_VERSION);
	message->length = cpu_to_le16(length);
	message->interface = cpu_to_le32(ifnum);
	message->type = cpu_to_le32(opcode);
	if (length)
		memcpy(message + 1, payload, length);
	error = qdx_io_command(core, message, sizeof(*message) + length, 0);
	if (error)
		kfree(message);
	return error;
}

int qdx_message_send(struct qdx_endpoint *endpoint, u32 opcode,
		     const void *payload, size_t length)
{
	u32 ifnum;
	int error = qdx_endpoint_ifnum(endpoint, &ifnum);

	if (error)
		return error;
	if (!qdx_endpoint_command_ready(endpoint))
		return -ESHUTDOWN;
	return qdx_message_core(endpoint->core, ifnum, opcode, payload, length);
}
EXPORT_SYMBOL_GPL(qdx_message_send);

void qdx_commands_stop(struct qdx_core *core)
{
	struct qdx_commands *commands = core->commands;
	struct qdx_request *request;
	unsigned long index, flags;

	if (!commands)
		return;
	xa_lock_irqsave(&commands->pending, flags);
	commands->closed = true;
	xa_for_each(&commands->pending, index, request) {
		spin_lock(&request->lock);
		request->result.error = -ESHUTDOWN;
		spin_unlock(&request->lock);
		complete_all(&request->done);
	}
	xa_unlock_irqrestore(&commands->pending, flags);
}

/* Receive is drained and actual firmware/DMA access has ended. */
void qdx_commands_access_end(struct qdx_core *core)
{
	struct qdx_commands *commands = core->commands;
	struct qdx_request *request;
	unsigned long flags, index = 0;

	if (!commands)
		return;
	for (;;) {
		xa_lock_irqsave(&commands->pending, flags);
		request = xa_find(&commands->pending, &index, ULONG_MAX, XA_PRESENT);
		if (!request) {
			xa_unlock_irqrestore(&commands->pending, flags);
			break;
		}
		spin_lock(&request->lock);
		request->result.error = -ESHUTDOWN;
		if (!request->result.published)
			request->result.outcome = QDX_NOT_SUBMITTED;
		request->result.exposure_ended = true;
		request->delivery_pending = true;
		__xa_erase(&commands->pending, index);
		commands->reserved--;
		spin_unlock(&request->lock);
		xa_unlock_irqrestore(&commands->pending, flags);
		complete_all(&request->done);
		qdx_request_deliver(request);
		qdx_request_put(request); /* Retained exposure reference. */
	}
}

void qdx_commands_release(struct qdx_core *core)
{
	struct qdx_commands *commands = core->commands;
	unsigned long flags;

	if (!commands)
		return;
	qdx_commands_stop(core);
	if (!xa_empty(&commands->pending))
		return; /* Unended remote exposure is quarantined, never erased here. */
	wait_event(commands->drained, !atomic_read(&commands->callers) &&
		   !atomic_read(&commands->objects));
	xa_lock_irqsave(&commands->pending, flags);
	xa_unlock_irqrestore(&commands->pending, flags);
	xa_destroy(&commands->pending);
	kfree(commands);
	core->commands = NULL;
}
