// SPDX-License-Identifier: GPL-2.0-only
/* Task-local idle-fixture keyed FDB inspection/conditional repair.
 * No packet path, FDB ADD/FLUSH, timer, or firmware operation.
 */
#include <linux/debugfs.h>
#include <linux/delay.h>
#include <linux/etherdevice.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/rtnetlink.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <net/net_namespace.h>
#include "qca_ppe.h"

static char *source_mac;
static char *target_mac;
static bool allow_delete;
module_param(source_mac, charp, 0400);
module_param(target_mac, charp, 0400);
module_param(allow_delete, bool, 0400);
MODULE_PARM_DESC(source_mac, "Actual LAN3 source host MAC from fixture readback");
MODULE_PARM_DESC(target_mac, "Actual LAN2 target host MAC from fixture readback");
MODULE_PARM_DESC(allow_delete, "Permit only the obsolete dynamic source-MAC/old-bridge-VSI deletion");

struct key_result {
	u32 words[3];
	int error;
	bool observed;
};

static DEFINE_MUTEX(command_lock);
static struct dentry *directory;
static u8 source_addr[ETH_ALEN], target_addr[ETH_ALEN];
static struct key_result forward_key, reverse_key, reverse_recheck, reverse_after;
static u32 source_vp[3], target_vp[3], source_vsi, target_vsi;
static u32 source_members[2], target_members[2];
static u32 source_default_vid, target_default_vid;
static u32 conflict_xlt[5];
static int conflict_xlt_index = -1;
static unsigned int sequence;
static int last_error, delete_error;
static bool prepare_attempted, delete_attempted, delete_confirmed;
static bool accepted, command_uncertain;
static const char *phase = "not_run";

static int wait_fdb(struct qca_ppe_priv *priv, u32 reg, u32 command_id)
{
	u32 value;
	int error, tries;

	for (tries = 0; tries < 100; tries++) {
		error = regmap_read(priv->regmap, reg, &value);
		if (error)
			return error;
		if (FIELD_GET(PPE_FDB_RSLT_CMD_ID, value) == command_id)
			return 0;
		udelay(1);
	}
	return -ETIMEDOUT;
}

/* Caller holds the driver's FDB lock. The echoed ID differs from the last
 * result, so an old result cannot stand in for this GET's completion. The ID
 * field/echo also serves the native indexed GET producer.
 */
static int get_key_locked(struct qca_ppe_priv *priv, const u8 *addr, u32 vsi,
			  struct key_result *record)
{
	u32 last, id, key0, key1;
	bool published = false;
	int error, i;

	memset(record, 0, sizeof(*record));
	key0 = ((u32)addr[2] << 24) | ((u32)addr[3] << 16) |
	       ((u32)addr[4] << 8) | addr[5];
	key1 = ((u32)addr[0] << 8) | addr[1] |
	       FIELD_PREP(PPE_FDB_DATA1_VSI, vsi);
	error = regmap_read(priv->regmap, PPE_FDB_RD_OP_RSLT, &last);
	if (error)
		goto out;
	id = (FIELD_GET(PPE_FDB_RSLT_CMD_ID, last) + 1) % 15;
	error = regmap_write(priv->regmap, PPE_FDB_RD_OP_DATA0, key0);
	if (error)
		goto out;
	error = regmap_write(priv->regmap, PPE_FDB_RD_OP_DATA1, key1);
	if (error)
		goto out;
	error = regmap_write(priv->regmap, PPE_FDB_RD_OP_DATA2, 0);
	if (error)
		goto out;
	published = true; /* A failed MMIO publication may have reached hardware. */
	error = regmap_write(priv->regmap, PPE_FDB_RD_OP,
		FIELD_PREP(PPE_FDB_OP_CMD_ID, id) |
		FIELD_PREP(PPE_FDB_OP_TYPE, PPE_FDB_OP_GET) |
		FIELD_PREP(PPE_FDB_OP_HASH_BLOCK, 3));
	if (error)
		goto out;
	error = wait_fdb(priv, PPE_FDB_RD_OP_RSLT, id);
	if (error)
		goto out;
	published = false;
	for (i = 0; i < 3; i++) {
		error = regmap_read(priv->regmap, PPE_FDB_RD_RSLT_DATA0 + i * 4,
				    &record->words[i]);
		if (error)
			goto out;
	}
	record->observed = true;
	if (!(record->words[1] & PPE_FDB_DATA1_VALID)) {
		error = -ENOENT;
		goto out;
	}
	/* The actual result producer returns the key as well as its destination. */
	if (record->words[0] != key0 ||
	    (record->words[1] & (0xffff | PPE_FDB_DATA1_VSI)) != key1)
		error = -EUCLEAN;
out:
	if (published)
		command_uncertain = true;
	record->error = error;
	return error;
}

static int get_key(struct qca_ppe_priv *priv, const u8 *addr, u32 vsi,
		   struct key_result *record)
{
	int error;

	spin_lock_bh(&priv->fdb_lock);
	error = get_key_locked(priv, addr, vsi, record);
	spin_unlock_bh(&priv->fdb_lock);
	return error;
}

/* Returns 0 for no change, 1 for the one permitted dynamic location, or an
 * error for a conflicting/unknown owner. Zero age is a valid dynamic state.
 */
static int key_action(const struct key_result *record, bool reverse)
{
	u32 destination;

	if (record->error == -ENOENT && record->observed)
		return 0;
	if (record->error || !record->observed)
		return record->error ?: -EIO;
	if (FIELD_GET(PPE_FDB_DATA2_HIT_AGE, record->words[2]) == PPE_FDB_AGE_STATIC)
		return -EEXIST;
	if (FIELD_GET(PPE_FDB_DATA2_DST_TYPE, record->words[2]) != PPE_FDB_DST_PORT)
		return -EXDEV;
	destination = FIELD_GET(PPE_FDB_DATA1_DST_LO, record->words[1]) |
		(FIELD_GET(PPE_FDB_DATA2_DST_HI, record->words[2]) << 9);
	if (destination == QCA_PPE_CPU_PORT)
		return 0;
	return reverse && destination == 3 ? 1 : -EXDEV;
}

/* The selected experiment has untagged input. Native tagged-only translations
 * do not match it. Any default C-tag or other applicable VSI action must be
 * resolved by its owner rather than silently assuming the base VP key.
 */
static int check_untagged_domains(struct qca_ppe_priv *priv)
{
	u32 rule[3], action[2], format;
	int index, error;

	error = regmap_read(priv->regmap, PPE_PORT_DEF_VID(3), &source_default_vid);
	if (error)
		return error;
	error = regmap_read(priv->regmap, PPE_PORT_DEF_VID(4), &target_default_vid);
	if (error)
		return error;
	if ((source_default_vid | target_default_vid) & PPE_PORT_DEF_CVID_EN)
		return -EOPNOTSUPP;
	for (index = 0; index < PPE_XLT_TBL_NUM; index++) {
		error = regmap_bulk_read(priv->regmap, PPE_XLT_RULE_TBL(index), rule, 3);
		if (error)
			return error;
		if (!(rule[0] & PPE_XLT_VALID) ||
		    !(FIELD_GET(PPE_XLT_PORT_BMP, rule[0]) & (BIT(3) | BIT(4))))
			continue;
		format = (!!(rule[0] & PPE_XLT_CKEY_FMT_0)) |
			 (FIELD_GET(PPE_XLT_CKEY_FMT_1, rule[1]) << 1);
		if (format == PPE_XLT_CKEY_TAGGED)
			continue;
		error = regmap_bulk_read(priv->regmap, PPE_XLT_ACTION_TBL(index), action, 2);
		if (error)
			return error;
		if (!(action[1] & PPE_XLT_VSI_CMD))
			continue;
		conflict_xlt_index = index;
		memcpy(conflict_xlt, rule, sizeof(rule));
		memcpy(conflict_xlt + 3, action, sizeof(action));
		return -EOPNOTSUPP;
	}
	return 0;
}

static int inspect_topology(struct qca_ppe_priv *priv, struct net_device *source,
			    struct net_device *target)
{
	struct net_device *bridge = netdev_master_upper_dev_get(target);
	int error;

	if (netdev_master_upper_dev_get(source) || !bridge ||
	    priv->port_br_dev[3] || priv->port_br_dev[4] != bridge ||
	    priv->port_vsi[3] != PPE_VSI_INVALID ||
	    priv->port_config[3].vsi != 0 ||
	    priv->port_vsi[4] == PPE_VSI_INVALID ||
	    priv->port_vsi[4] != priv->port_config[4].vsi)
		return -EXDEV;
	if (priv->resources_terminal || priv->rx_resources[3] || priv->rx_resources[4] ||
	    priv->tx_holds[3] || priv->tx_holds[4] ||
	    priv->peak_resources[3] || priv->peak_resources[4] ||
	    priv->port_config[3].prepared || priv->port_config[4].prepared ||
	    priv->port_config[3].config_error || priv->port_config[4].config_error)
		return -EBUSY;
	error = regmap_bulk_read(priv->regmap, PPE_L3_VP_PORT_TBL(3), source_vp, 3);
	if (error)
		return error;
	error = regmap_bulk_read(priv->regmap, PPE_L3_VP_PORT_TBL(4), target_vp, 3);
	if (error)
		return error;
	if (!(source_vp[1] & PPE_L3_VP_VSI_VALID) ||
	    !(target_vp[1] & PPE_L3_VP_VSI_VALID))
		return -EUCLEAN;
	source_vsi = FIELD_GET(PPE_L3_VP_VSI, source_vp[1]);
	target_vsi = FIELD_GET(PPE_L3_VP_VSI, target_vp[1]);
	if (source_vsi != 0 || target_vsi == source_vsi ||
	    target_vsi != priv->port_vsi[4])
		return -EXDEV;
	error = check_untagged_domains(priv);
	if (error)
		return error;
	error = regmap_bulk_read(priv->regmap, PPE_VSI_TBL(source_vsi), source_members, 2);
	if (error)
		return error;
	error = regmap_bulk_read(priv->regmap, PPE_VSI_TBL(target_vsi), target_members, 2);
	if (error)
		return error;
	if (FIELD_GET(PPE_VSI_TBL_UUC, source_members[0]) != BIT(QCA_PPE_CPU_PORT) ||
	    !(FIELD_GET(PPE_VSI_TBL_MEMBER, source_members[0]) & BIT(3)) ||
	    !(FIELD_GET(PPE_VSI_TBL_UUC, target_members[0]) & BIT(QCA_PPE_CPU_PORT)) ||
	    (FIELD_GET(PPE_VSI_TBL_MEMBER, target_members[0]) & BIT(3)) ||
	    !(FIELD_GET(PPE_VSI_TBL_MEMBER, target_members[0]) & BIT(4)))
		return -EUCLEAN;
	return 0;
}

static int operate(bool repair)
{
	struct net_device *source = NULL, *target = NULL;
	struct dsa_port *source_dp, *target_dp;
	struct qca_ppe_priv *priv;
	struct dsa_db database = {};
	int error, action;
	u32 initial_vsi;

	phase = "resolve";
	rtnl_lock();
	source = dev_get_by_name(&init_net, "lan3");
	target = dev_get_by_name(&init_net, "lan2");
	source_dp = dsa_port_from_netdev(source);
	target_dp = dsa_port_from_netdev(target);
	if (IS_ERR(source_dp) || IS_ERR(target_dp) || source_dp->ds != target_dp->ds ||
	    source_dp->index != 3 || target_dp->index != 4 ||
	    !of_device_is_compatible(source_dp->ds->dev->of_node, "qualcomm,ipq8074-ppe") ||
	    !source_dp->ds->ops->port_fdb_del) {
		error = -ENODEV;
		goto out;
	}
	priv = ds_to_priv(source_dp->ds);
	if (priv != source_dp->ds->priv || priv->data->type != PPE_TYPE_IPQ8074) {
		error = -ENODEV;
		goto out;
	}
	/* Same order as the native config -> hardware resource relationship. */
	mutex_lock(&priv->port_config[3].lock);
	mutex_lock(&priv->port_config[4].lock);
	mutex_lock(&priv->resource_lock);
	phase = "topology";
	error = inspect_topology(priv, source, target);
	if (error)
		goto unlock;
	initial_vsi = target_vsi;
	phase = "forward_get";
	error = get_key(priv, target_addr, source_vsi, &forward_key);
	if (error && error != -ENOENT)
		goto unlock;
	error = key_action(&forward_key, false);
	if (error)
		goto unlock;
	phase = "reverse_get";
	error = get_key(priv, source_addr, target_vsi, &reverse_key);
	if (error && error != -ENOENT)
		goto unlock;
	action = key_action(&reverse_key, true);
	if (action < 0) {
		error = action;
		goto unlock;
	}
	if (!repair || !action) {
		error = 0;
		accepted = !action;
		phase = action ? "obsolete_dynamic_observed" : "unchanged_ready";
		goto unlock;
	}
	if (!allow_delete) {
		error = -EPERM;
		goto unlock;
	}
	/* Revalidate actual topology and the exact key immediately before DEL.
	 * RTNL + native config/resource locks exclude control-plane changes.
	 * Hardware learning is not locked: the caller's quiet-source boundary is
	 * required; source on standalone VSI0 cannot relearn this old bridge key.
	 */
	phase = "predelete_topology";
	error = inspect_topology(priv, source, target);
	if (error)
		goto unlock;
	if (target_vsi != initial_vsi) {
		error = -ESTALE;
		goto unlock;
	}
	phase = "predelete_get";
	error = get_key(priv, source_addr, target_vsi, &reverse_recheck);
	if (error && error != -ENOENT)
		goto unlock;
	action = key_action(&reverse_recheck, true);
	if (action <= 0) {
		error = action;
		accepted = !action;
		phase = action ? "predelete_conflict" : "unchanged_ready";
		goto unlock;
	}
	phase = "delete";
	delete_attempted = true;
	/* This driver ignores database; pass a zero initialized value instead of
	 * calling dsa_port_fdb_del on a port whose bridge relation was removed.
	 */
	delete_error = source_dp->ds->ops->port_fdb_del(source_dp->ds, 3,
						     source_addr, target_vsi, database);
	if (delete_error) {
		command_uncertain = true;
		error = delete_error;
		goto unlock;
	}
	phase = "delete_readback";
	error = get_key(priv, source_addr, target_vsi, &reverse_after);
	if (error == -ENOENT && reverse_after.observed) {
		delete_confirmed = true;
		accepted = true;
		phase = "deleted_ready";
		error = 0;
	} else if (!error) {
		error = -EAGAIN;
	}
unlock:
	mutex_unlock(&priv->resource_lock);
	mutex_unlock(&priv->port_config[4].lock);
	mutex_unlock(&priv->port_config[3].lock);
out:
	if (target)
		dev_put(target);
	if (source)
		dev_put(source);
	rtnl_unlock();
	return error;
}

static void show_key(struct seq_file *seq, const char *name, const struct key_result *record)
{
	u32 destination = FIELD_GET(PPE_FDB_DATA1_DST_LO, record->words[1]) |
		(FIELD_GET(PPE_FDB_DATA2_DST_HI, record->words[2]) << 9);

	seq_printf(seq, "%s observed=%u error=%d words=%08x,%08x,%08x valid=%u type=%u destination=%u age=%u\n",
		name, record->observed, record->error, record->words[0], record->words[1], record->words[2],
		!!(record->words[1] & PPE_FDB_DATA1_VALID),
		(u32)FIELD_GET(PPE_FDB_DATA2_DST_TYPE, record->words[2]), destination,
		(u32)FIELD_GET(PPE_FDB_DATA2_HIT_AGE, record->words[2]));
}

static int status_show(struct seq_file *seq, void *unused)
{
	mutex_lock(&command_lock);
	seq_printf(seq, "result sequence=%u phase=%s error=%d accepted=%u prepare_attempted=%u delete_attempted=%u delete_error=%d delete_confirmed=%u command_uncertain=%u\n",
		sequence, phase, last_error, accepted, prepare_attempted, delete_attempted,
		delete_error, delete_confirmed, command_uncertain);
	seq_printf(seq, "topology source_port=3 target_port=4 source_mac=%pM target_mac=%pM source_vsi=%u target_vsi=%u source_vp=%08x,%08x,%08x target_vp=%08x,%08x,%08x source_members=%08x,%08x target_members=%08x,%08x default_vid=%08x,%08x\n",
		source_addr, target_addr, source_vsi, target_vsi,
		source_vp[0], source_vp[1], source_vp[2], target_vp[0], target_vp[1], target_vp[2],
		source_members[0], source_members[1], target_members[0], target_members[1],
		source_default_vid, target_default_vid);
	seq_printf(seq, "xlt conflict_index=%d words=%08x,%08x,%08x,%08x,%08x\n", conflict_xlt_index,
		conflict_xlt[0], conflict_xlt[1], conflict_xlt[2], conflict_xlt[3], conflict_xlt[4]);
	show_key(seq, "forward", &forward_key);
	show_key(seq, "reverse", &reverse_key);
	show_key(seq, "reverse_recheck", &reverse_recheck);
	show_key(seq, "reverse_after", &reverse_after);
	mutex_unlock(&command_lock);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(status);

static ssize_t command_write(struct file *file, const char __user *user,
			     size_t count, loff_t *position)
{
	char command[24];
	bool repair;
	int error;

	if (!count || count >= sizeof(command))
		return -EINVAL;
	if (copy_from_user(command, user, count))
		return -EFAULT;
	command[count] = 0;
	strim(command);
	if (!strcmp(command, "prepare"))
		repair = true;
	else if (!strcmp(command, "inspect"))
		repair = false;
	else
		return -EINVAL;
	mutex_lock(&command_lock);
	if (command_uncertain || prepare_attempted) {
		error = -EALREADY;
		goto out;
	}
	sequence++;
	accepted = false;
	if (repair)
		prepare_attempted = true;
	error = operate(repair);
	last_error = error;
out:
	mutex_unlock(&command_lock);
	return error ? error : count;
}

static const struct file_operations command_ops = {
	.owner = THIS_MODULE,
	.write = command_write,
	.llseek = default_llseek,
};

static int __init fixture_init(void)
{
	struct dentry *file;

	if (!source_mac || !target_mac || !mac_pton(source_mac, source_addr) ||
	    !mac_pton(target_mac, target_addr) || !is_valid_ether_addr(source_addr) ||
	    !is_valid_ether_addr(target_addr) || ether_addr_equal(source_addr, target_addr))
		return -EINVAL;
	directory = debugfs_create_dir("qdx_fixture_fdb_diag", NULL);
	if (IS_ERR(directory))
		return PTR_ERR(directory);
	file = debugfs_create_file("status", 0400, directory, NULL, &status_fops);
	if (IS_ERR_OR_NULL(file))
		goto failed;
	file = debugfs_create_file("command", 0200, directory, NULL, &command_ops);
	if (IS_ERR_OR_NULL(file))
		goto failed;
	return 0;
failed:
	debugfs_remove_recursive(directory);
	return IS_ERR(file) ? PTR_ERR(file) : -ENOMEM;
}

static void __exit fixture_exit(void)
{
	/* No packet/timer/reference is published to hardware. Keep the saved
	 * status before unload, especially an unknown hardware command result.
	 */
	debugfs_remove_recursive(directory);
}
module_init(fixture_init);
module_exit(fixture_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Bounded conditional obsolete FDB repair for inquiry023 native-paired fixture");
