// SPDX-License-Identifier: GPL-2.0-only
#include <linux/jiffies.h>
#include "tc.h"

void qdx_tc_stats_request(struct qdx_tc_node *node)
{
	struct qdx_tc_collector *stats = &node->stats;

	spin_lock_bh(&stats->command.lock);
	if (!READ_ONCE(node->retiring))
		stats->requested = true;
	spin_unlock_bh(&stats->command.lock);
	qdx_tc_schedule(node->tree->owner);
}

void qdx_tc_stats_detach(struct qdx_tc_node *node)
{
	struct qdx_tc_collector *stats = &node->stats;

	lockdep_assert_held(&node->tree->owner->cfg);
	if (stats->source && !stats->detached) {
		gnet_stats_hw_source_detach(stats->source);
		stats->detached = true;
	}
	spin_lock_bh(&stats->command.lock);
	stats->requested = false;
	spin_unlock_bh(&stats->command.lock);
}

bool qdx_tc_stats_drained(struct qdx_tc_node *node)
{
	lockdep_assert_held(&node->tree->owner->cfg);
	return node->stats.close != QDX_TC_STATS_CLOSING &&
		!node->stats.command.request && !node->stats.query_source &&
		completion_done(&node->stats.command.recipient_done);
}

void qdx_tc_stats_collect(struct qdx_tc_node *node)
{
	struct qdx_tc_owner *owner = node->tree->owner;
	struct qdx_tc_collector *stats = &node->stats;
	struct qdx_tc_command *command = &stats->command;
	struct qdx_shaper_message message = {};
	struct qdx_shaper_stats *wire = &message.data.stats.values;
	struct gnet_stats_hw_sample sample = {};
	struct qdx_reply_bounds bounds = {
		.minimum = sizeof(message),
		.maximum = sizeof(message),
		.capacity = sizeof(message),
	};
	struct qdx_result result;
	bool requested, replied;
	bool internal = !node->native && node->kind == QDX_SHAPER_HTB_GROUP;
	size_t received;
	int err;

	lockdep_assert_held(&owner->cfg);
	spin_lock_bh(&command->lock);
	replied = command->replied;
	result = command->result;
	received = command->reply_length;
	if (replied && received == sizeof(message))
		memcpy(&message, command->reply, sizeof(message));
	requested = stats->requested;
	spin_unlock_bh(&command->lock);

	if (command->request) {
		if (!replied)
			return;
		if (result.outcome == QDX_UNKNOWN && !result.exposure_ended) {
			stats->stale = true;
			return;
		}
		if (result.outcome != QDX_ACK || received != sizeof(message) ||
		    le32_to_cpu(message.command) != QDX_SHAPER_STATS ||
		    le32_to_cpu(message.response) != 0 ||
		    le32_to_cpu(message.data.stats.tag) != node->tag) {
			stats->stale = true;
			goto completed;
		}

		sample.bytes = le32_to_cpu(wire->dequeue_bytes);
		sample.packets = le32_to_cpu(wire->dequeue_packets);
		sample.queue.valid = GNET_STATS_HW_ENQUEUE_DROP_PACKETS |
			GNET_STATS_HW_ENQUEUE_DROP_BYTES |
			GNET_STATS_HW_DEQUEUE_DROP_PACKETS |
			GNET_STATS_HW_DEQUEUE_DROP_BYTES | GNET_STATS_HW_OVERRUNS |
			GNET_STATS_HW_QLEN | GNET_STATS_HW_BACKLOG;
		sample.queue.enqueue_drop_packets = le32_to_cpu(wire->enqueue_drop_packets);
		sample.queue.enqueue_drop_bytes = le32_to_cpu(wire->enqueue_drop_bytes);
		sample.queue.dequeue_drop_packets = le32_to_cpu(wire->dequeue_drop_packets);
		sample.queue.dequeue_drop_bytes = le32_to_cpu(wire->dequeue_drop_bytes);
		sample.queue.overruns = le32_to_cpu(wire->overruns);
		sample.queue.qlen = le32_to_cpu(wire->qlen_packets);
		sample.queue.backlog = le32_to_cpu(wire->qlen_bytes);
		if (node->kind == QDX_SHAPER_CODEL) {
			sample.app.valid = GNET_STATS_HW_PEAK_DELAY;
			sample.app.peak_delay_ns = (u64)max(
				le32_to_cpu(wire->peak_dequeue_ms),
				le32_to_cpu(wire->peak_drop_ms)) * NSEC_PER_MSEC;
			if (node->fq) {
				sample.app.valid |= GNET_STATS_HW_NEW_FLOWS |
					GNET_STATS_HW_ECN_MARKS | GNET_STATS_HW_NEW_LIST_LEN |
					GNET_STATS_HW_OLD_LIST_LEN | GNET_STATS_HW_MAXPACKET;
				sample.app.new_flows = le32_to_cpu(wire->new_flows);
				sample.app.ecn_marks = le32_to_cpu(wire->ecn_marks);
				sample.app.new_list_len = le32_to_cpu(wire->new_list_length);
				sample.app.old_list_len = le32_to_cpu(wire->old_list_length);
				sample.app.maxpacket = le32_to_cpu(wire->max_packet);
			}
		}
		if (stats->query_source)
			gnet_stats_hw_source_update(stats->query_source, &sample);
		stats->stale = false;
completed:
		/* The original source receives this delta once. It may be detached;
		 * native source identity decides whether any gauge is still current.
		 */
		qdx_tc_command_clear(command);
		if (stats->query_source)
			gnet_stats_hw_source_put(stats->query_source);
		stats->query_source = NULL;
		stats->next_query = jiffies + HZ;
	}

	if (!completion_done(&command->recipient_done))
		return;
	if (stats->close == QDX_TC_STATS_CLOSING) {
		/* One attempt while the held, still linked node is queryable.
		 * CLOSED forbids another GET, including after a NACK or an
		 * unsubmitted request; UNKNOWN retains this original command.
		 */
		stats->close = QDX_TC_STATS_CLOSED;
		if ((!stats->source && !internal) || !node->allocated || !node->configured ||
		    qdx_service_state(owner->service) != QDX_AVAILABLE ||
		    qdx_service_access_ended(owner->service)) {
			stats->stale = true;
			return;
		}
	} else {
		if (node->retiring || stats->close == QDX_TC_STATS_CLOSED ||
		    (!stats->source && !internal) || !node->allocated || !node->configured)
			return;
		if (!requested && time_before(jiffies, stats->next_query))
			return;
	}
	spin_lock_bh(&command->lock);
	stats->requested = false;
	spin_unlock_bh(&command->lock);
	memset(&message, 0, sizeof(message));
	message.command = cpu_to_le32(QDX_SHAPER_STATS);
	message.data.stats.tag = cpu_to_le32(node->tag);
	stats->query_source = stats->source;
	/* Internal GROUP GET advances firmware propagation only. Native get/put
	 * require an original native source. HTB fanout and TBF peak own no sink.
	 */
	if (stats->query_source)
		gnet_stats_hw_source_get(stats->query_source);
	err = qdx_tc_command_start(command, node->endpoint, QDX_TC_ISHAPER_CONFIG,
			&message, sizeof(message), &bounds);
	if (err) {
		/* An unsubmitted request never consumed a firmware delta. */
		if (stats->query_source)
			gnet_stats_hw_source_put(stats->query_source);
		stats->query_source = NULL;
		stats->stale = true;
		stats->next_query = jiffies + HZ;
	}
}
