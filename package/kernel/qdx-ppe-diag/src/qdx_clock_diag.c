// SPDX-License-Identifier: GPL-2.0-only
/* Isolated fixed NSS clock: enabled clone reference versus disabled EMPTY. */
#include <linux/completion.h>
#include <linux/debugfs.h>
#include <linux/delay.h>
#include <linux/jiffies.h>
#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/qdx_diag_clock.h>
#include <linux/seq_file.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/unaligned.h>
#include <net/net_namespace.h>

#define WAIT_MS 3000
#define PAIRS_MAX 32
#define ROWS_MAX (PAIRS_MAX * 3)
#define CLOCK_EMPTY 1
/* MIRROR wire ABI, identical to the already qualified size24 source copy. */
struct clock_config { __le32 point; __le16 size, offset; };
struct clock_endpoint {
	struct qdx_endpoint *endpoint;
	struct qdx_receiver *receiver;
	struct qdx_packet_op *operation;
	struct qdx_request *request;
	struct qdx_result result;
	u32 ifnum, opcode, active, unexpected;
	bool configured, next, enabled, disabled, retired;
};
struct clock_row {
	struct qdx_diag_clock_sample sample;
	struct completion clone_done;
	u64 begin_ns, submit_end_ns, end_ns, clone_ns;
	u32 clone_words[6], clones, clone_ifnum, clone_type, clone_length, clone_mod4;
	u32 endpoint, pair;
	bool submitted, clone_valid, checked, probe;
	bool sample_waited, clone_waited;
};
static bool allow_writes;
module_param(allow_writes, bool, 0400);
static DEFINE_MUTEX(clock_lock);
static DEFINE_SPINLOCK(clone_lock);
static struct dentry *directory;
static struct net_device *port;
static struct qdx_service *service;
static struct clock_endpoint endpoints[2]; /* 0: enabled reference; 1: disabled */
static struct clock_row rows[ROWS_MAX];
static u32 used, pairs, verified, advancing;
static bool pinned, closed, fault, prepared;
static int last_error;

static int clock_command(struct clock_endpoint *ep, u32 opcode, bool submit)
{
	struct clock_config config = { cpu_to_le32(1), cpu_to_le16(24), 0 };
	__le32 next = cpu_to_le32(156);
	const void *payload = opcode == 0 ? (void *)&config : opcode == 3 ? (void *)&next : NULL;
	size_t length = opcode == 0 ? sizeof(config) : opcode == 3 ? 4 : 0;
	struct qdx_reply_bounds bounds = { length, length, length };
	u8 reply[8] = {};
	int error;

	if (fault || (ep->request && ep->opcode != opcode))
		return fault ? -EPROTO : -EBUSY;
	if (!ep->request) {
		if (!submit)
			return 0;
		ep->request = qdx_command_submit(ep->endpoint, opcode, payload, length, &bounds, NULL);
		if (IS_ERR(ep->request)) {
			error = PTR_ERR(ep->request);
			ep->request = NULL;
			return error;
		}
		ep->opcode = opcode;
	}
	error = qdx_request_wait(ep->request, jiffies + msecs_to_jiffies(WAIT_MS),
		&ep->result, reply, sizeof(reply));
	if (ep->result.outcome == QDX_UNKNOWN && !ep->result.exposure_ended)
		return error ?: -EINPROGRESS;
	/* DISABLE on an already disabled instance returns NACK6. This exact
	 * response proves the desired control state, not any clock read.
	 */
	if (ep->result.outcome == QDX_ACK ||
	    (opcode == 2 && ep->result.outcome == QDX_REJECTED &&
	     ep->result.firmware_error == 6)) {
		if (ep->result.declared_len != length || ep->result.received_len < length) {
			fault = true;
			return -EPROTO;
		}
		error = 0;
		if (opcode == 0) ep->configured = true;
		if (opcode == 1) { ep->enabled = true; ep->disabled = false; }
		if (opcode == 2) { ep->enabled = false; ep->disabled = true; }
		if (opcode == 3) ep->next = true;
		if (opcode == 4) ep->next = false;
	} else {
		error = ep->result.error ?: error ?: -EIO;
	}
	qdx_request_put(ep->request);
	ep->request = NULL;
	return error;
}

static void clock_clone(void *owner, struct sk_buff *skb,
	const struct qdx_rx_meta *meta, struct napi_struct *napi)
{
	struct clock_endpoint *ep = owner;
	struct clock_row *row;
	unsigned long flags;
	u32 index = READ_ONCE(ep->active);

	spin_lock_irqsave(&clone_lock, flags);
	if (index >= ROWS_MAX) {
		ep->unexpected++;
		spin_unlock_irqrestore(&clone_lock, flags);
		dev_kfree_skb_any(skb);
		return;
	}
	row = &rows[index];
	row->clones++;
	row->clone_ns = ktime_get_ns();
	row->clone_ifnum = meta ? meta->ifnum : U32_MAX;
	row->clone_type = meta ? meta->type : U32_MAX;
	row->clone_length = skb->len;
	row->clone_mod4 = (unsigned long)skb->data & 3;
	row->clone_valid = row->clones == 1 && row->endpoint == 0 && meta &&
		meta->ifnum == ep->ifnum && meta->type == QDX_RECEIVE_PACKET &&
		skb->len == 24 && !skb_is_nonlinear(skb) && !row->clone_mod4;
	if (row->clone_valid)
		memcpy(row->clone_words, skb->data, 24);
	spin_unlock_irqrestore(&clone_lock, flags);
	dev_kfree_skb_any(skb);
	complete(&row->clone_done);
}
static const struct qdx_receive_ops clock_receive_ops = { .packet = clock_clone };

static int clock_prepare(void)
{
	struct clock_endpoint *ep;
	struct qdx_owner owner = { .module = THIS_MODULE };
	unsigned int i;
	int error;

	if (closed || fault || used)
		return -EPERM;
	if (!pinned) {
		if (!try_module_get(THIS_MODULE)) return -ENODEV;
		pinned = true;
	}
	if (!port) port = dev_get_by_name(&init_net, "lan3");
	if (!port || !netif_running(port)) return -ENODEV;
	if (!service) {
		service = qdx_service_get(port, QDX_SERVICE_MIRROR);
		if (IS_ERR(service)) {
			error = PTR_ERR(service); service = NULL; return error;
		}
	}
	for (i = 0; i < ARRAY_SIZE(endpoints); i++) {
		ep = &endpoints[i];
		if (!ep->endpoint) {
			ep->endpoint = qdx_endpoint_alloc(service, 65);
			if (IS_ERR(ep->endpoint)) {
				error = PTR_ERR(ep->endpoint); ep->endpoint = NULL; return error;
			}
		}
		error = qdx_endpoint_wait(ep->endpoint, jiffies + msecs_to_jiffies(WAIT_MS));
		if (error) return error;
		error = qdx_endpoint_ifnum(ep->endpoint, &ep->ifnum);
		if (error) return error;
		if (!ep->receiver) {
			owner.object = ep;
			ep->receiver = qdx_endpoint_receive_register(ep->endpoint, QDX_RECEIVE_PACKET,
				&owner, &clock_receive_ops);
			if (IS_ERR(ep->receiver)) {
				error = PTR_ERR(ep->receiver); ep->receiver = NULL; return error;
			}
		}
		if (ep->request) {
			error = clock_command(ep, ep->opcode, false);
			if (error) return error;
		}
		if (!ep->configured) {
			error = clock_command(ep, 0, true);
			if (error) return error;
		}
		if (!i && !ep->next) {
			error = clock_command(ep, 3, true);
			if (error) return error;
		}
		if ((!i && !ep->enabled) || (i && !ep->disabled)) {
			error = clock_command(ep, i ? 2 : 1, true);
			if (error) return error;
		}
		if (!ep->operation) {
			ep->operation = qdx_packet_op_prepare(ep->endpoint,
				QDX_DIAG_CLOCK_TAG, QDX_RECEIVE_PACKET);
			if (IS_ERR(ep->operation)) {
				error = PTR_ERR(ep->operation); ep->operation = NULL; return error;
			}
		}
	}
	prepared = true;
	return 0;
}

static int clock_read(unsigned int endpoint, unsigned int pair, bool probe)
{
	struct clock_endpoint *ep = &endpoints[endpoint];
	struct clock_row *row = &rows[used];
	struct qdx_owner owner = { .module = THIS_MODULE, .object = &row->sample };
	struct qdx_ready ready;
	unsigned long deadline = jiffies + msecs_to_jiffies(WAIT_MS);

	row->endpoint = endpoint;
	row->pair = pair;
	row->probe = probe;
	WRITE_ONCE(ep->active, used++);
	row->begin_ns = ktime_get_ns();
	ready = qdx_diag_clock_submit(ep->operation, &row->sample, &owner);
	row->submit_end_ns = ktime_get_ns();
	if (ready.status != QDX_ACCEPTED) {
		WRITE_ONCE(ep->active, U32_MAX);
		return ready.error ?: -EIO;
	}
	row->submitted = true;
	if (!wait_for_completion_timeout(&row->sample.done, msecs_to_jiffies(WAIT_MS)))
		return -ETIMEDOUT;
	/* A successful wait consumes complete(). Preserve that observed event;
	 * a later restore must not mistake the consumed count for live DMA.
	 */
	row->sample_waited = true;
	if (!endpoint) {
		if (!completion_done(&row->clone_done) &&
		    (time_after_eq(jiffies, deadline) ||
		     !wait_for_completion_timeout(&row->clone_done, deadline - jiffies)))
			return -ETIMEDOUT;
		row->clone_waited = true;
	}
	row->end_ns = ktime_get_ns();
	WRITE_ONCE(ep->active, U32_MAX);
	if (row->sample.error || !row->sample.published_ns || !row->sample.retired_ns)
		return row->sample.error ?: -EBADMSG;
	if (endpoint) {
		if (row->sample.type != CLOCK_EMPTY || READ_ONCE(row->clones)) return -EBADMSG;
	} else if (row->sample.type != QDX_RECEIVE_PACKET ||
		   row->sample.ifnum != ep->ifnum || !row->clone_valid || row->clones != 1) {
		return -EBADMSG;
	}
	return 0;
}

static int clock_run(unsigned int count, bool probe)
{
	struct clock_row *before, *flush, *after;
	u64 first, last, lifted;
	unsigned int n, start;
	int error;

	if (!prepared || closed || fault || used || !count || count > PAIRS_MAX)
		return -EPERM;
	pairs = count;
	for (n = 0; n < count; n++) {
		start = used;
		error = clock_read(0, n, probe);
		if (error) return error;
		/* Freshness-only probe separates stale prior publication from a new
		 * source return. This wait is outside every recorded read interval;
		 * run has no wait and supplies the ordinary cost comparison.
		 */
		if (probe) usleep_range(3000, 3100);
		error = clock_read(1, n, probe);
		if (error) return error;
		error = clock_read(0, n, probe);
		if (error) return error;
		before = &rows[start]; flush = &rows[start + 1]; after = &rows[start + 2];
		/* Do not claim atomic64 copying. The short bracket must not cross
		 * high-word rollover; actual low32 lifting is then unambiguous.
		 */
		if (before->clone_words[0] || after->clone_words[0] ||
		    before->clone_words[5] != after->clone_words[5]) return -EAGAIN;
		first = ((u64)before->clone_words[5] << 32) | before->clone_words[4];
		last = ((u64)after->clone_words[5] << 32) | after->clone_words[4];
		if (last < first || last - first >= BIT_ULL(31)) return -ERANGE;
		lifted = first + (u32)(flush->sample.words[4] - (u32)first);
		if (lifted > last || (probe && lifted == first)) return -ESTALE;
		before->checked = flush->checked = after->checked = true;
		verified++;
		advancing += lifted > first;
	}
	return 0;
}

static int clock_restore(void)
{
	struct clock_endpoint *ep;
	unsigned int i;
	int error;

	if (!pinned) return 0;
	closed = true;
	for (i = 0; i < ARRAY_SIZE(endpoints); i++)
		if (endpoints[i].operation) qdx_packet_op_close(endpoints[i].operation);
	for (i = 0; i < used; i++) {
		if (!rows[i].submitted) continue;
		if ((!rows[i].sample_waited && !completion_done(&rows[i].sample.done)) ||
		    (!rows[i].endpoint && !rows[i].clone_waited &&
		     !completion_done(&rows[i].clone_done)))
			return -EINPROGRESS;
	}
	for (i = 0; i < ARRAY_SIZE(endpoints); i++) {
		ep = &endpoints[i];
		if (ep->operation && !qdx_packet_op_drained(ep->operation)) return -EINPROGRESS;
	}
	synchronize_net();
	for (i = 0; i < ARRAY_SIZE(endpoints); i++) {
		ep = &endpoints[i];
		if (ep->request) {
			error = clock_command(ep, ep->opcode, false);
			if (error || ep->request) return error ?: -EINPROGRESS;
		}
		if (ep->enabled) {
			error = clock_command(ep, 2, true);
			if (error) return error;
		}
		if (ep->next) {
			error = clock_command(ep, 4, true);
			if (error) return error;
		}
		if (ep->endpoint && !ep->retired) {
			error = qdx_endpoint_wait(ep->endpoint, jiffies + msecs_to_jiffies(WAIT_MS));
			if (error) return error;
			error = qdx_endpoint_retire(ep->endpoint);
			if (error) return error;
			ep->retired = true;
		}
		if (ep->receiver) {
			error = qdx_endpoint_receive_unregister(ep->receiver);
			if (error) return error;
			ep->receiver = NULL;
		}
		qdx_packet_op_put(ep->operation); ep->operation = NULL;
		qdx_endpoint_put(ep->endpoint); ep->endpoint = NULL;
	}
	qdx_service_put(service); service = NULL;
	if (port) dev_put(port);
	port = NULL;
	pinned = false;
	module_put(THIS_MODULE);
	return 0;
}

static int clock_status_show(struct seq_file *seq, void *unused)
{
	struct clock_endpoint *ep;
	struct clock_row *row;
	unsigned int i;

	mutex_lock(&clock_lock);
	seq_printf(seq, "allow_writes=%u pinned=%u prepared=%u closed=%u fault=%u used=%u pairs=%u verified=%u advancing=%u error=%d\n",
		allow_writes, pinned, prepared, closed, fault, used, pairs, verified, advancing, last_error);
	for (i = 0; i < ARRAY_SIZE(endpoints); i++) {
		ep = &endpoints[i];
		seq_printf(seq, "endpoint=%u ifnum=%u present=%u operation=%u drained=%u receiver=%u request=%u configured=%u enabled=%u disabled=%u next=%u retired=%u active=%u unexpected=%u outcome=%u firmware_error=%u\n",
			i, ep->ifnum, !!ep->endpoint, !!ep->operation,
			ep->operation ? qdx_packet_op_drained(ep->operation) : true, !!ep->receiver,
			!!ep->request, ep->configured, ep->enabled, ep->disabled, ep->next, ep->retired,
			READ_ONCE(ep->active), READ_ONCE(ep->unexpected), ep->result.outcome, ep->result.firmware_error);
	}
	for (i = 0; i < used; i++) {
		row = &rows[i];
		seq_printf(seq, "row=%u pair=%u endpoint=%u probe=%u submitted=%u done=%u sample_waited=%u clone_waited=%u checked=%u type=%u ifnum=%u error=%d begin_ns=%llu submit_end_ns=%llu published_ns=%llu returned_ns=%llu read_begin_ns=%llu read_end_ns=%llu retired_ns=%llu end_ns=%llu clone_ns=%llu clones=%u clone_valid=%u clone_type=%u clone_ifnum=%u clone_length=%u clone_mod4=%u words=%24phN clone=%24phN\n",
			i, row->pair, row->endpoint, row->probe, row->submitted,
			completion_done(&row->sample.done), row->sample_waited, row->clone_waited, row->checked, row->sample.type, row->sample.ifnum,
			row->sample.error, (unsigned long long)row->begin_ns,
			(unsigned long long)row->submit_end_ns, (unsigned long long)row->sample.published_ns,
			(unsigned long long)row->sample.returned_ns, (unsigned long long)row->sample.read_begin_ns,
			(unsigned long long)row->sample.read_end_ns, (unsigned long long)row->sample.retired_ns,
			(unsigned long long)row->end_ns, (unsigned long long)row->clone_ns, row->clones,
			row->clone_valid, row->clone_type, row->clone_ifnum, row->clone_length,
			row->clone_mod4, row->sample.words, row->clone_words);
	}
	mutex_unlock(&clock_lock);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(clock_status);

static ssize_t clock_control_write(struct file *file, const char __user *buffer,
	size_t count, loff_t *position)
{
	char command[32];
	unsigned int pairs_count;
	int error;

	if (!allow_writes) return -EPERM;
	if (!count || count >= sizeof(command)) return -EINVAL;
	if (copy_from_user(command, buffer, count)) return -EFAULT;
	command[count] = 0;
	strim(command);
	mutex_lock(&clock_lock);
	if (!strcmp(command, "prepare")) error = clock_prepare();
	else if (!strncmp(command, "run ", 4) && !kstrtouint(command + 4, 10, &pairs_count))
		error = clock_run(pairs_count, false);
	else if (!strncmp(command, "probe ", 6) && !kstrtouint(command + 6, 10, &pairs_count))
		error = clock_run(pairs_count, true);
	else if (!strcmp(command, "restore")) error = clock_restore();
	else error = -EINVAL;
	last_error = error;
	mutex_unlock(&clock_lock);
	return error ?: count;
}
static const struct file_operations clock_control_fops = {
	.owner = THIS_MODULE, .write = clock_control_write,
};
static int __init clock_init(void)
{
	struct dentry *entry;
	unsigned int i;

	for (i = 0; i < ROWS_MAX; i++) {
		init_completion(&rows[i].sample.done);
		init_completion(&rows[i].clone_done);
	}
	for (i = 0; i < ARRAY_SIZE(endpoints); i++) endpoints[i].active = U32_MAX;
	directory = debugfs_create_dir("qdx_clock_diag", NULL);
	if (IS_ERR_OR_NULL(directory)) return -ENOMEM;
	entry = debugfs_create_file("control", 0200, directory, NULL, &clock_control_fops);
	if (IS_ERR_OR_NULL(entry)) goto fail;
	entry = debugfs_create_file("status", 0400, directory, NULL, &clock_status_fops);
	if (IS_ERR_OR_NULL(entry)) goto fail;
	return 0;
fail:
	debugfs_remove_recursive(directory);
	return -ENOMEM;
}
static void __exit clock_exit(void)
{
	WARN_ON(pinned || service || port || endpoints[0].endpoint || endpoints[1].endpoint);
	debugfs_remove_recursive(directory);
}
module_init(clock_init);
module_exit(clock_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Isolated fixed NSS clock original-return and fresh-clone comparison");
