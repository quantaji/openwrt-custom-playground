// SPDX-License-Identifier: GPL-2.0-or-later OR MIT

#include <linux/delay.h>
#include <linux/clk.h>
#include <linux/module.h>
#include <linux/of_device.h>
#include <linux/of_net.h>
#include <linux/pcs/pcs.h>
#include <linux/pcs/pcs-qca-uniphy.h>
#include <linux/phy.h>
#include <linux/phylink.h>
#include <linux/platform_device.h>
#include <linux/reset.h>
#include <linux/if_bridge.h>
#include <linux/if_vlan.h>
#include <linux/version.h>
#include <linux/dsa/oob.h>
#include <linux/qdx/tc.h>
#include <net/pkt_cls.h>
#include <net/sch_generic.h>

#include "qca_ppe.h"

/* A port carrying nothing but minimum-sized frames at 10G wraps a packet
 * counter in under five minutes, and a total only stays monotonic for as long
 * as no counter wraps twice unobserved between folds.
 */
#define PPE_MIB_FOLD_INTERVAL	(30 * HZ)

static void ppe_port_gmac_set(struct qca_ppe_priv *priv, int port,
			     bool tx_en, bool rx_en)
{
	int gmac = port - 1;
	u32 val = 0;

	if (port < 1 || port >= priv->data->num_ports)
		return;

	if (tx_en)
		val |= PPE_MAC_ENABLE_TXMAC_EN;
	if (rx_en)
		val |= PPE_MAC_ENABLE_RXMAC_EN;
	regmap_update_bits(priv->regmap, PPE_GMAC_ENABLE(gmac),
			   PPE_MAC_ENABLE_TXMAC_EN | PPE_MAC_ENABLE_RXMAC_EN,
			   val);
}

static void ppe_port_xgmac_set(struct qca_ppe_priv *priv, int port,
			       bool tx_en, bool rx_en)
{
	int xgmac = port - 5;

	if (port < 5 || port >= priv->data->num_ports)
		return;

	regmap_update_bits(priv->regmap, PPE_XGMAC_TX_CONF(xgmac),
			   PPE_XGMAC_TX_ENABLE,
			   tx_en ? PPE_XGMAC_TX_ENABLE : 0);

	regmap_update_bits(priv->regmap, PPE_XGMAC_RX_CONF(xgmac),
			   PPE_XGMAC_RX_ENABLE,
			   rx_en ? PPE_XGMAC_RX_ENABLE : 0);
}

static void ppe_port_bridge_txmac_set(struct qca_ppe_priv *priv, int port,
				      bool enable)
{
	mutex_lock(&priv->resource_lock);
	priv->tx_bridge_enabled[port] = enable;
	if (priv->tx_holds[port])
		enable = false;
	regmap_update_bits(priv->regmap, PPE_PORT_BRIDGE_CTRL(port),
			   PPE_PORT_BRIDGE_CTRL_TXMAC_EN,
			   enable ? PPE_PORT_BRIDGE_CTRL_TXMAC_EN : 0);
	mutex_unlock(&priv->resource_lock);
}

static void ppe_gmac_link_up(struct qca_ppe_priv *priv, int port,
			     int speed, int duplex,
			     bool tx_pause, bool rx_pause)
{
	int gmac = port - 1;
	u32 val;

	regmap_read(priv->regmap, PPE_GMAC_SPEED(gmac), &val);
	val &= ~PPE_GMAC_SPEED_MASK;
	switch (speed) {
	case SPEED_100:
		val |= FIELD_PREP(PPE_GMAC_SPEED_MASK, 1);
		break;
	case SPEED_2500:
	case SPEED_1000:
		val |= FIELD_PREP(PPE_GMAC_SPEED_MASK, 2);
		break;
	}
	regmap_write(priv->regmap, PPE_GMAC_SPEED(gmac), val);

	val = 0;
	if (duplex == DUPLEX_FULL)
		val |= PPE_MAC_ENABLE_DUPLEX;
	if (tx_pause)
		val |= PPE_MAC_ENABLE_TX_FLOW_EN;
	if (rx_pause)
		val |= PPE_MAC_ENABLE_RX_FLOW_EN;
	regmap_update_bits(priv->regmap, PPE_GMAC_ENABLE(gmac),
			   PPE_MAC_ENABLE_DUPLEX | PPE_MAC_ENABLE_TX_FLOW_EN |
			   PPE_MAC_ENABLE_RX_FLOW_EN, val);
}

static void ppe_xgmac_link_up(struct qca_ppe_priv *priv, int port,
			      phy_interface_t interface, int speed,
			      bool tx_pause, bool rx_pause)
{
	int xgmac = port - 5;
	u32 val;

	switch (speed) {
	case SPEED_10:
	case SPEED_100:
	case SPEED_1000:
		val = PPE_XGMAC_SPEED_SELECT_1000;
		break;
	case SPEED_2500:
		val = PPE_XGMAC_SPEED_SELECT_2500;
		break;
	case SPEED_5000:
		val = PPE_XGMAC_SPEED_SELECT_5000;
		break;
	case SPEED_10000:
		val = PPE_XGMAC_SPEED_SELECT_10000;
		break;
	default:
		return;
	}

	if (interface == PHY_INTERFACE_MODE_USXGMII ||
	    interface == PHY_INTERFACE_MODE_10GBASER) {
		switch (speed) {
		case SPEED_2500:
		case SPEED_5000:
		case SPEED_10000:
			val |= PPE_XGMAC_USXGMII_SELECT;
			break;
		default:
			break;
		}
	}

	regmap_update_bits(priv->regmap, PPE_XGMAC_TX_CONF(xgmac),
			   PPE_XGMAC_SPEED_SELECT |
			   PPE_XGMAC_USXGMII_SELECT, val);

	regmap_write_bits(priv->regmap, PPE_XGMAC_RX_CONF(xgmac),
			   PPE_XGMAC_AUTO_CRC_STRIP |
			   PPE_XGMAC_CRC_STRIP_TYPE,
			   PPE_XGMAC_AUTO_CRC_STRIP |
			   PPE_XGMAC_CRC_STRIP_TYPE);

	regmap_write_bits(priv->regmap, PPE_XGMAC_TX_FLOW_CTRL(xgmac),
			  PPE_XGMAC_TX_FLOW_ENABLE,
			  tx_pause ? PPE_XGMAC_RX_FLOW_ENABLE : 0);

	regmap_write_bits(priv->regmap, PPE_XGMAC_RX_FLOW_CTRL(xgmac),
			  PPE_XGMAC_RX_FLOW_ENABLE,
			  rx_pause ? PPE_XGMAC_RX_FLOW_ENABLE : 0);
}

static int ppe_port_cnt_enable(struct qca_ppe_priv *priv, int port)
{
	u32 reg = PPE_MRU_MTU_CTRL(port, priv->data->mru_mtu_ctrl_stride);
	u32 row[2];
	int ret;

	mutex_lock(&priv->resource_lock);
	ret = regmap_bulk_read(priv->regmap, reg, row, ARRAY_SIZE(row));
	if (ret)
		goto out;
	row[1] |= PPE_MRU_MTU_CTRL_RX_CNT_EN | PPE_MRU_MTU_CTRL_TX_CNT_EN;
	ret = regmap_bulk_write(priv->regmap, reg, row, ARRAY_SIZE(row));
	if (ret)
		goto out;

	ret = regmap_update_bits(priv->regmap, PPE_MC_MTU_CTRL(port),
				 PPE_MC_MTU_CTRL_TX_CNT_EN, PPE_MC_MTU_CTRL_TX_CNT_EN);
	if (ret)
		goto out;

	ret = regmap_update_bits(priv->regmap, PPE_PORT_EG_VLAN(port),
				 PPE_PORT_EG_VLAN_TX_CNT_EN, PPE_PORT_EG_VLAN_TX_CNT_EN);
out:
	mutex_unlock(&priv->resource_lock);
	return ret;
}

int ppe_vsi_alloc(struct qca_ppe_priv *priv)
{
	int vsi;

	vsi = find_first_zero_bit(priv->vsi_bitmap, PPE_VSI_MAX);
	if (vsi >= PPE_VSI_MAX)
		return -ENOSPC;

	set_bit(vsi, priv->vsi_bitmap);

	regmap_write(priv->regmap, PPE_VSI_TBL(vsi), 0);
	regmap_write(priv->regmap, PPE_VSI_TBL(vsi) + 4,
		     PPE_VSI_TBL_NEW_ADDR_LRN_EN | PPE_VSI_TBL_STA_MOVE_LRN_EN);

	return vsi;
}

void ppe_vsi_free(struct qca_ppe_priv *priv, u32 vsi)
{
	regmap_write(priv->regmap, PPE_VSI_TBL(vsi), 0);
	regmap_write(priv->regmap, PPE_VSI_TBL(vsi) + 4, 0);
	clear_bit(vsi, priv->vsi_bitmap);
}

void ppe_vsi_member_set(struct qca_ppe_priv *priv, u32 vsi,
			       u32 portmask)
{
	u32 val;

	val = FIELD_PREP(PPE_VSI_TBL_MEMBER, portmask) |
	      FIELD_PREP(PPE_VSI_TBL_UUC, portmask) |
	      FIELD_PREP(PPE_VSI_TBL_UMC, portmask) |
	      FIELD_PREP(PPE_VSI_TBL_BC, portmask);
	regmap_write(priv->regmap, PPE_VSI_TBL(vsi), val);
	regmap_write(priv->regmap, PPE_VSI_TBL(vsi) + 4,
		PPE_VSI_TBL_NEW_ADDR_LRN_EN | PPE_VSI_TBL_STA_MOVE_LRN_EN);
}

static int ppe_port_vsi_set(struct qca_ppe_priv *priv, int port, u32 vsi)
{
	u32 values[3];
	unsigned int reg = PPE_L3_VP_PORT_TBL(port);
	int i, ret;

	for (i = 0; i < ARRAY_SIZE(values); i++) {
		ret = regmap_read(priv->regmap, reg + i * sizeof(u32), &values[i]);
		if (ret)
			return ret;
	}
	values[1] &= ~(PPE_L3_VP_VSI_VALID | PPE_L3_VP_VSI);
	if (vsi != PPE_VSI_INVALID)
		values[1] |= PPE_L3_VP_VSI_VALID | FIELD_PREP(PPE_L3_VP_VSI, vsi);
	/* The same table's native initialization writes all three latch words. */
	for (i = 0; i < ARRAY_SIZE(values); i++) {
		ret = regmap_write(priv->regmap, reg + i * sizeof(u32), values[i]);
		if (ret)
			return ret;
	}
	priv->port_config[port].vsi = vsi;
	return 0;
}

static int ppe_fdb_op_wait(struct qca_ppe_priv *priv, u32 rslt_reg,
			   u32 cmd_id)
{
	u32 val;
	int i;

	for (i = 0; i < 100; i++) {
		regmap_read(priv->regmap, rslt_reg, &val);
		if (FIELD_GET(PPE_FDB_RSLT_CMD_ID, val) == cmd_id)
			return 0;
		udelay(1);
	}

	return -ETIMEDOUT;
}

static void ppe_fdb_encode(const unsigned char *addr, int port, u16 vid,
			   bool is_static, u32 *data0, u32 *data1, u32 *data2)
{
	*data0 = (addr[2] << 24) | (addr[3] << 16) | (addr[4] << 8) | addr[5];

	*data1 = (addr[0] << 8) | addr[1];
	*data1 |= PPE_FDB_DATA1_VALID | PPE_FDB_DATA1_LKP_VALID;
	*data1 |= FIELD_PREP(PPE_FDB_DATA1_VSI, vid);
	*data1 |= FIELD_PREP(PPE_FDB_DATA1_DST_LO, port);

	*data2 = FIELD_PREP(PPE_FDB_DATA2_DST_TYPE, PPE_FDB_DST_PORT) |
		 FIELD_PREP(PPE_FDB_DATA2_HIT_AGE,
			    is_static ? PPE_FDB_AGE_STATIC : 2);
}

static int ppe_fdb_op(struct qca_ppe_priv *priv, const unsigned char *addr,
		      int port, u16 vid, u32 op_type)
{
	u32 data0, data1, data2;
	int ret;

	ppe_fdb_encode(addr, port, vid, op_type == PPE_FDB_OP_ADD,
		       &data0, &data1, &data2);

	spin_lock_bh(&priv->fdb_lock);

	regmap_write(priv->regmap, PPE_FDB_OP_DATA0, data0);
	regmap_write(priv->regmap, PPE_FDB_OP_DATA1, data1);
	regmap_write(priv->regmap, PPE_FDB_OP_DATA2, data2);
	regmap_write(priv->regmap, PPE_FDB_OP,
		     FIELD_PREP(PPE_FDB_OP_TYPE, op_type) |
		     FIELD_PREP(PPE_FDB_OP_HASH_BLOCK, 3));

	ret = ppe_fdb_op_wait(priv, PPE_FDB_OP_RSLT, 0);

	spin_unlock_bh(&priv->fdb_lock);

	return ret;
}

static int ppe_fdb_read_entry(struct qca_ppe_priv *priv, u32 index,
			      unsigned char *addr, u16 *vid, int *port,
			      bool *is_static)
{
	u32 data0, data1, data2, cmd_id, val;
	int ret;

	cmd_id = index % 15;

	spin_lock_bh(&priv->fdb_lock);

	regmap_write(priv->regmap, PPE_FDB_RD_OP_DATA0, 0);
	regmap_write(priv->regmap, PPE_FDB_RD_OP_DATA1, 0);
	regmap_write(priv->regmap, PPE_FDB_RD_OP_DATA2, 0);

	val = FIELD_PREP(PPE_FDB_OP_CMD_ID, cmd_id) |
	      FIELD_PREP(PPE_FDB_OP_TYPE, PPE_FDB_OP_GET) |
	      FIELD_PREP(PPE_FDB_OP_HASH_BLOCK, 3) |
	      PPE_FDB_OP_MODE |
	      FIELD_PREP(PPE_FDB_OP_ENTRY_IDX, index);
	regmap_write(priv->regmap, PPE_FDB_RD_OP, val);

	ret = ppe_fdb_op_wait(priv, PPE_FDB_RD_OP_RSLT, cmd_id);
	if (ret)
		goto unlock;

	regmap_read(priv->regmap, PPE_FDB_RD_RSLT_DATA0, &data0);
	regmap_read(priv->regmap, PPE_FDB_RD_RSLT_DATA1, &data1);
	regmap_read(priv->regmap, PPE_FDB_RD_RSLT_DATA2, &data2);

unlock:
	spin_unlock_bh(&priv->fdb_lock);

	if (ret)
		return ret;

	if (!(data1 & PPE_FDB_DATA1_VALID))
		return -ENOENT;

	if (FIELD_GET(PPE_FDB_DATA2_DST_TYPE, data2) != PPE_FDB_DST_PORT)
		return -ENOENT;

	addr[2] = (data0 >> 24) & 0xff;
	addr[3] = (data0 >> 16) & 0xff;
	addr[4] = (data0 >> 8) & 0xff;
	addr[5] = data0 & 0xff;
	addr[0] = (data1 >> 8) & 0xff;
	addr[1] = data1 & 0xff;

	*vid = FIELD_GET(PPE_FDB_DATA1_VSI, data1);
	*port = FIELD_GET(PPE_FDB_DATA1_DST_LO, data1) |
		(FIELD_GET(PPE_FDB_DATA2_DST_HI, data2) << 9);
	*is_static = FIELD_GET(PPE_FDB_DATA2_HIT_AGE, data2) == PPE_FDB_AGE_STATIC;

	return 0;
}

static int ppe_fdb_flush(struct qca_ppe_priv *priv)
{
	int ret;

	spin_lock_bh(&priv->fdb_lock);

	regmap_write(priv->regmap, PPE_FDB_OP,
		FIELD_PREP(PPE_FDB_OP_TYPE, PPE_FDB_OP_FLUSH));

	ret = ppe_fdb_op_wait(priv, PPE_FDB_OP_RSLT, 0);

	spin_unlock_bh(&priv->fdb_lock);

	return ret;
}

static void ppe_fdb_encode_mcast(const unsigned char *addr, u32 portmap,
				 u16 vid, u32 *data0, u32 *data1, u32 *data2)
{
	*data0 = (addr[2] << 24) | (addr[3] << 16) | (addr[4] << 8) | addr[5];

	*data1 = (addr[0] << 8) | addr[1];
	*data1 |= PPE_FDB_DATA1_VALID | PPE_FDB_DATA1_LKP_VALID;
	*data1 |= FIELD_PREP(PPE_FDB_DATA1_VSI, vid);
	*data1 |= FIELD_PREP(PPE_FDB_DATA1_DST_LO, portmap);

	*data2 = FIELD_PREP(PPE_FDB_DATA2_DST_HI, portmap >> 9) |
		 FIELD_PREP(PPE_FDB_DATA2_DST_TYPE, PPE_FDB_DST_PORTMAP) |
		 FIELD_PREP(PPE_FDB_DATA2_HIT_AGE, PPE_FDB_AGE_STATIC);
}

static int ppe_fdb_lookup(struct qca_ppe_priv *priv,
			  const unsigned char *addr, u16 vid, u32 *portmap)
{
	u32 data1, data2;
	int ret;

	spin_lock_bh(&priv->fdb_lock);

	regmap_write(priv->regmap, PPE_FDB_RD_OP_DATA0,
		     (addr[2] << 24) | (addr[3] << 16) | (addr[4] << 8) | addr[5]);
	regmap_write(priv->regmap, PPE_FDB_RD_OP_DATA1,
		     ((addr[0] << 8) | addr[1]) |
		     FIELD_PREP(PPE_FDB_DATA1_VSI, vid));
	regmap_write(priv->regmap, PPE_FDB_RD_OP_DATA2, 0);

	regmap_write(priv->regmap, PPE_FDB_RD_OP,
		     FIELD_PREP(PPE_FDB_OP_TYPE, PPE_FDB_OP_GET) |
		     FIELD_PREP(PPE_FDB_OP_HASH_BLOCK, 3));

	ret = ppe_fdb_op_wait(priv, PPE_FDB_RD_OP_RSLT, 0);
	if (ret)
		goto out;

	regmap_read(priv->regmap, PPE_FDB_RD_RSLT_DATA1, &data1);
	regmap_read(priv->regmap, PPE_FDB_RD_RSLT_DATA2, &data2);

	if (!(data1 & PPE_FDB_DATA1_VALID)) {
		ret = -ENOENT;
		goto out;
	}

	*portmap = FIELD_GET(PPE_FDB_DATA1_DST_LO, data1) |
		   (FIELD_GET(PPE_FDB_DATA2_DST_HI, data2) << 9);

out:
	spin_unlock_bh(&priv->fdb_lock);
	return ret;
}

static int ppe_fdb_mcast_op(struct qca_ppe_priv *priv,
			    const unsigned char *addr, u32 portmap,
			    u16 vid, u32 op_type)
{
	u32 data0, data1, data2;
	int ret;

	ppe_fdb_encode_mcast(addr, portmap, vid, &data0, &data1, &data2);

	spin_lock_bh(&priv->fdb_lock);

	regmap_write(priv->regmap, PPE_FDB_OP_DATA0, data0);
	regmap_write(priv->regmap, PPE_FDB_OP_DATA1, data1);
	regmap_write(priv->regmap, PPE_FDB_OP_DATA2, data2);
	regmap_write(priv->regmap, PPE_FDB_OP,
		     FIELD_PREP(PPE_FDB_OP_TYPE, op_type) |
		     FIELD_PREP(PPE_FDB_OP_HASH_BLOCK, 3));

	ret = ppe_fdb_op_wait(priv, PPE_FDB_OP_RSLT, 0);

	spin_unlock_bh(&priv->fdb_lock);

	return ret;
}

static enum dsa_tag_protocol
qca_ppe_get_tag_protocol(struct dsa_switch *ds, int port,
			     enum dsa_tag_protocol mprot)
{
	return DSA_TAG_PROTO_OOB;
}

static int qca_ppe_setup(struct dsa_switch *ds)
{
	struct qca_ppe_priv *priv = ds_to_priv(ds);
	int num_ports = ds->num_ports;
	u32 frame_size;
	u32 port_mask;
	u32 val;
	u32 row[2];
	int i, ret;

	port_mask = BIT(num_ports) - 1;
	frame_size = PPE_DEFAULT_MTU + 2 * VLAN_HLEN;

	for (i = 0; i < num_ports; i++)
		priv->port_vsi[i] = PPE_VSI_INVALID;

	regmap_write(priv->regmap, PPE_FDB_OP, 0);

	for (i = 0; i < num_ports; i++) {
		u32 reg = PPE_MRU_MTU_CTRL(i, priv->data->mru_mtu_ctrl_stride);

		regmap_write(priv->regmap, PPE_CST_STATE(i), PPE_STP_FORWARDING);

		mutex_lock(&priv->resource_lock);
		ret = regmap_bulk_read(priv->regmap, reg, row, ARRAY_SIZE(row));
		if (!ret) {
			row[0] = FIELD_PREP(PPE_MRU_MTU_CTRL_MRU, frame_size) |
				 FIELD_PREP(PPE_MRU_MTU_CTRL_MTU, frame_size);
			ret = regmap_bulk_write(priv->regmap, reg, row, ARRAY_SIZE(row));
		}
		mutex_unlock(&priv->resource_lock);
		if (ret)
			return ret;

		regmap_update_bits(priv->regmap, PPE_MC_MTU_CTRL(i),
				   PPE_MC_MTU_CTRL_MTU,
				   FIELD_PREP(PPE_MC_MTU_CTRL_MTU,
					      frame_size));

		if (i >= 1)
			regmap_write(priv->regmap, PPE_GMAC_MIB_CTRL(i - 1),
				     PPE_MIB_EN);

		val = PPE_BRIDGE_NEW_LRN_EN |
		      PPE_BRIDGE_STA_MOVE_EN |
		      FIELD_PREP(PPE_BRIDGE_PORT_ISOL, port_mask);
		if (dsa_is_cpu_port(ds, i))
			val |= PPE_PORT_BRIDGE_CTRL_TXMAC_EN;
		regmap_update_bits(priv->regmap, PPE_PORT_BRIDGE_CTRL(i),
				   PPE_BRIDGE_NEW_LRN_EN |
				   PPE_BRIDGE_STA_MOVE_EN |
				   PPE_BRIDGE_PORT_ISOL |
				   PPE_PORT_BRIDGE_CTRL_TXMAC_EN,
				   val);

		ret = ppe_port_cnt_enable(priv, i);
		if (ret)
			return ret;
	}

	qca_ppe_vlan_setup(ds);

	set_bit(0, priv->vsi_bitmap);
	val = FIELD_PREP(PPE_VSI_TBL_MEMBER,
			 dsa_user_ports(ds) | BIT(QCA_PPE_CPU_PORT)) |
	      FIELD_PREP(PPE_VSI_TBL_UUC, BIT(QCA_PPE_CPU_PORT)) |
	      FIELD_PREP(PPE_VSI_TBL_UMC, BIT(QCA_PPE_CPU_PORT)) |
	      FIELD_PREP(PPE_VSI_TBL_BC, BIT(QCA_PPE_CPU_PORT));
	regmap_write(priv->regmap, PPE_VSI_TBL(0), val);
	regmap_write(priv->regmap, PPE_VSI_TBL(0) + 4,
		PPE_VSI_TBL_NEW_ADDR_LRN_EN | PPE_VSI_TBL_STA_MOVE_LRN_EN);

	for (i = 1; i < num_ports; i++)
		ppe_port_vsi_set(priv, i, 0);

	ppe_fdb_flush(priv);

	regmap_update_bits(priv->regmap, PPE_L2_GLOBAL_CONF,
			   PPE_L2_LRN_EN | PPE_L2_AGE_EN,
			   PPE_L2_LRN_EN | PPE_L2_AGE_EN);

	ds->ageing_time_min = PPE_AGE_UNIT_MS;
	ds->ageing_time_max = (unsigned int)min_t(u64,
		(u64)PPE_AGE_UNIT_MS * PPE_AGE_TIMER_MASK, U32_MAX);
	ds->assisted_learning_on_cpu_port = true;

	schedule_delayed_work(&priv->mib_work, PPE_MIB_FOLD_INTERVAL);

	return 0;
}

static int qca_ppe_set_ageing_time(struct dsa_switch *ds, unsigned int msecs)
{
	struct qca_ppe_priv *priv = ds_to_priv(ds);
	u32 timer = msecs / PPE_AGE_UNIT_MS;

	regmap_update_bits(priv->regmap, PPE_AGE_TIMER, PPE_AGE_TIMER_MASK,
			   FIELD_PREP(PPE_AGE_TIMER_MASK, timer));

	return 0;
}

static int ppe_port_mtu_apply(struct qca_ppe_priv *priv, int port, int mtu)
{
	u32 size = mtu + ETH_HLEN + 2 * VLAN_HLEN;
	u32 reg = PPE_MRU_MTU_CTRL(port, priv->data->mru_mtu_ctrl_stride);
	u32 previous[2], values[2];
	int ret;

	mutex_lock(&priv->resource_lock);
	ret = regmap_bulk_read(priv->regmap, reg, previous, ARRAY_SIZE(previous));
	if (ret)
		goto out;
	values[0] = previous[0] & ~(PPE_MRU_MTU_CTRL_MRU | PPE_MRU_MTU_CTRL_MTU);
	values[0] |= FIELD_PREP(PPE_MRU_MTU_CTRL_MRU, size) |
		     FIELD_PREP(PPE_MRU_MTU_CTRL_MTU, size);
	values[1] = previous[1];
	/* The final word commits this table entry, even when unchanged. */
	ret = regmap_bulk_write(priv->regmap, reg, values, ARRAY_SIZE(values));
	if (ret)
		goto out;
	ret = regmap_update_bits(priv->regmap, PPE_MC_MTU_CTRL(port),
			PPE_MC_MTU_CTRL_MTU, FIELD_PREP(PPE_MC_MTU_CTRL_MTU, size));
	if (ret)
		regmap_bulk_write(priv->regmap, reg, previous, ARRAY_SIZE(previous));
out:
	mutex_unlock(&priv->resource_lock);
	return ret;
}

static int qca_ppe_port_change_mtu(struct dsa_switch *ds, int port, int new_mtu)
{
	struct qca_ppe_priv *priv = ds_to_priv(ds);
	struct qca_ppe_port_config *pc = &priv->port_config[port];
	int old_mtu, ret, finish, undo;
	bool firmware_changed = false;

	mutex_lock(&pc->lock);
	old_mtu = pc->mtu;
	ret = qdx_port_check_mtu(priv->qdx, port, new_mtu);
	if (ret)
		goto out;
	ret = qdx_port_prepare(priv->qdx, port);
	if (ret)
		goto out;
	ret = qdx_port_mtu(priv->qdx, port, new_mtu);
	if (!ret) {
		firmware_changed = true;
		ret = ppe_port_mtu_apply(priv, port, new_mtu);
	}
	if (!ret) {
		pc->mtu = new_mtu;
	} else if (firmware_changed) {
		undo = qdx_port_mtu(priv->qdx, port, old_mtu);
		if (undo)
			qdx_port_failed(priv->qdx, port, undo);
	}
	finish = qdx_port_finish(priv->qdx, port);
	if (!ret)
		ret = finish;
	if (ret && pc->mtu != old_mtu) {
		pc->mtu = old_mtu;
		undo = qdx_port_prepare(priv->qdx, port);
		if (!undo) {
			undo = qdx_port_mtu(priv->qdx, port, old_mtu);
			if (!undo)
				undo = ppe_port_mtu_apply(priv, port, old_mtu);
			finish = qdx_port_finish(priv->qdx, port);
			if (!undo)
				undo = finish;
		}
		if (undo) {
			ppe_port_bridge_txmac_set(priv, port, false);
			qdx_port_failed(priv->qdx, port, undo);
		}
	}
out:
	mutex_unlock(&pc->lock);
	return ret;
}

static int qca_ppe_port_max_mtu(struct dsa_switch *ds, int port)
{
	return PPE_MAX_FRAME_SIZE - ETH_HLEN - ETH_FCS_LEN -
	       2 * VLAN_HLEN;
}

static int qca_ppe_port_enable(struct dsa_switch *ds, int port,
				   struct phy_device *phy)
{
	struct qca_ppe_priv *priv = ds_to_priv(ds);
	int ret;

	/* A user port's gate is opened by qca_ppe_mac_link_up() once its MAC
	 * is up. DSA calls this before phylink_start(), so opening it here
	 * would aim the fabric at a MAC that is still down and about to be
	 * re-clocked. The CPU port has no MAC of ours to wait for.
	 */
	if (dsa_is_cpu_port(ds, port)) {
		priv->port_config[port].admin = true;
		ppe_port_bridge_txmac_set(priv, port, true);
		return 0;
	}
	mutex_lock(&priv->port_config[port].lock);
	priv->port_config[port].admin = true;
	ret = qdx_port_open(priv->qdx, port);
	if (ret)
		priv->port_config[port].admin = false;
	mutex_unlock(&priv->port_config[port].lock);
	return ret;
}

static void qca_ppe_port_disable(struct dsa_switch *ds, int port)
{
	struct qca_ppe_priv *priv = ds_to_priv(ds);

	mutex_lock(&priv->port_config[port].lock);
	priv->port_config[port].admin = false;
	ppe_port_bridge_txmac_set(priv, port, false);
	qdx_port_close(priv->qdx, port);
	mutex_unlock(&priv->port_config[port].lock);
}

static struct qca_ppe_bridge_vsi *
bridge_vsi_find(struct qca_ppe_priv *priv, struct net_device *br_dev)
{
	int i;

	for (i = 0; i < QCA_PPE_MAX_BRIDGES; i++)
		if (priv->bridges[i].br_dev == br_dev)
			return &priv->bridges[i];

	return NULL;
}

static struct qca_ppe_bridge_vsi *
bridge_vsi_alloc(struct qca_ppe_priv *priv, struct net_device *br_dev)
{
	int vsi, i;

	vsi = ppe_vsi_alloc(priv);
	if (vsi < 0)
		return NULL;

	for (i = 0; i < QCA_PPE_MAX_BRIDGES; i++) {
		if (priv->bridges[i].br_dev)
			continue;

		priv->bridges[i].br_dev = br_dev;
		priv->bridges[i].vsi = vsi;
		priv->bridges[i].refcount = 0;
		return &priv->bridges[i];
	}

	ppe_vsi_free(priv, vsi);
	return NULL;
}

static void bridge_vsi_put(struct qca_ppe_priv *priv,
			   struct qca_ppe_bridge_vsi *bvsi)
{
	bvsi->refcount--;
	if (bvsi->refcount > 0)
		return;

	ppe_vsi_free(priv, bvsi->vsi);
	bvsi->br_dev = NULL;
	bvsi->vsi = 0;
}

static void bridge_vsi_members_update(struct qca_ppe_priv *priv,
				      struct qca_ppe_bridge_vsi *bvsi)
{
	u32 portmask = 0;
	int i;

	for (i = 0; i < priv->ds.num_ports; i++)
		if (priv->port_vsi[i] != PPE_VSI_INVALID &&
		    priv->port_vsi[i] == bvsi->vsi)
			portmask |= BIT(i);

	portmask |= BIT(QCA_PPE_CPU_PORT);

	ppe_vsi_member_set(priv, bvsi->vsi, portmask);
}

static int qca_ppe_port_bridge_join(struct dsa_switch *ds, int port,
					struct dsa_bridge bridge,
					bool *tx_fwd_offload,
					struct netlink_ext_ack *extack)
{
	struct qca_ppe_priv *priv = ds_to_priv(ds);
	struct qca_ppe_bridge_vsi *bvsi;
	u32 old_vsi;
	int ret;

	bvsi = bridge_vsi_find(priv, bridge.dev);
	if (!bvsi) {
		bvsi = bridge_vsi_alloc(priv, bridge.dev);
		if (!bvsi)
			return -ENOSPC;
	}

	mutex_lock(&priv->port_config[port].lock);
	ret = qdx_port_prepare(priv->qdx, port);
	if (ret) {
		mutex_unlock(&priv->port_config[port].lock);
		if (!bvsi->refcount) {
			ppe_vsi_free(priv, bvsi->vsi);
			bvsi->br_dev = NULL;
		}
		return ret;
	}
	old_vsi = priv->port_config[port].vsi;
	bvsi->refcount++;
	priv->port_vsi[port] = bvsi->vsi;
	priv->port_br_dev[port] = bridge.dev;

	ppe_port_vsi_set(priv, port, bvsi->vsi);
	bridge_vsi_members_update(priv, bvsi);

	ret = qdx_port_finish(priv->qdx, port);
	if (ret) {
		priv->port_vsi[port] = PPE_VSI_INVALID;
		priv->port_br_dev[port] = NULL;
		ppe_port_vsi_set(priv, port, old_vsi);
		bridge_vsi_members_update(priv, bvsi);
		bridge_vsi_put(priv, bvsi);
		if (!qdx_port_prepare(priv->qdx, port)) {
			int restore = qdx_port_finish(priv->qdx, port);

			if (restore)
				qdx_port_failed(priv->qdx, port, restore);
		}
	}
	mutex_unlock(&priv->port_config[port].lock);
	return ret;
}

static void qca_ppe_port_bridge_leave(struct dsa_switch *ds, int port,
					  struct dsa_bridge bridge)
{
	struct qca_ppe_priv *priv = ds_to_priv(ds);
	struct qca_ppe_bridge_vsi *bvsi;
	int ret, vsi_ret = 0;

	bvsi = bridge_vsi_find(priv, bridge.dev);
	if (!bvsi)
		return;
	mutex_lock(&priv->port_config[port].lock);
	ret = qdx_port_prepare(priv->qdx, port);
	priv->port_vsi[port] = PPE_VSI_INVALID;
	priv->port_br_dev[port] = NULL;
	/* setup reserves VSI 0 for standalone ports and floods only to CPU.
	 * port_vsi stays INVALID because the port belongs to no bridge.
	 */
	priv->port_config[port].vsi = 0;
	if (!ret)
		vsi_ret = ppe_port_vsi_set(priv, port, 0);
	bridge_vsi_members_update(priv, bvsi);
	bridge_vsi_put(priv, bvsi);
	if (!ret) {
		if (vsi_ret)
			qdx_port_failed(priv->qdx, port, vsi_ret);
		/* Successful prepare owns the port lock, including update failures. */
		ret = qdx_port_finish(priv->qdx, port);
		if (vsi_ret)
			ret = vsi_ret;
	}
	if (ret) {
		ppe_port_bridge_txmac_set(priv, port, false);
		qdx_port_failed(priv->qdx, port, ret);
	}
	mutex_unlock(&priv->port_config[port].lock);
}

static int qca_ppe_port_fdb_add(struct dsa_switch *ds, int port,
				    const unsigned char *addr, u16 vid,
				    struct dsa_db db)
{
	struct qca_ppe_priv *priv = ds_to_priv(ds);

	return ppe_fdb_op(priv, addr, port, vid, PPE_FDB_OP_ADD);
}

static int qca_ppe_port_fdb_del(struct dsa_switch *ds, int port,
				    const unsigned char *addr, u16 vid,
				    struct dsa_db db)
{
	struct qca_ppe_priv *priv = ds_to_priv(ds);

	return ppe_fdb_op(priv, addr, port, vid, PPE_FDB_OP_DEL);
}

static int qca_ppe_port_fdb_dump(struct dsa_switch *ds, int port,
				     dsa_fdb_dump_cb_t *cb, void *data)
{
	struct qca_ppe_priv *priv = ds_to_priv(ds);
	unsigned char addr[ETH_ALEN];
	bool is_static;
	int fdb_port;
	u16 vid;
	u32 i;

	for (i = 0; i < PPE_FDB_TBL_NUM; i++) {
		if (ppe_fdb_read_entry(priv, i, addr, &vid, &fdb_port,
				       &is_static))
			continue;

		if (fdb_port != port)
			continue;

		if (cb(addr, vid, is_static, data))
			break;
	}

	return 0;
}

static int qca_ppe_port_mdb_add(struct dsa_switch *ds, int port,
				    const struct switchdev_obj_port_mdb *mdb,
				    struct dsa_db db)
{
	struct qca_ppe_priv *priv = ds_to_priv(ds);
	u32 portmap;
	int ret;

	ret = ppe_fdb_lookup(priv, mdb->addr, mdb->vid, &portmap);
	if (ret)
		portmap = BIT(QCA_PPE_CPU_PORT);

	portmap |= BIT(port);

	return ppe_fdb_mcast_op(priv, mdb->addr, portmap,
				mdb->vid, PPE_FDB_OP_ADD);
}

static int qca_ppe_port_mdb_del(struct dsa_switch *ds, int port,
				    const struct switchdev_obj_port_mdb *mdb,
				    struct dsa_db db)
{
	struct qca_ppe_priv *priv = ds_to_priv(ds);
	u32 portmap;
	int ret;

	ret = ppe_fdb_lookup(priv, mdb->addr, mdb->vid, &portmap);
	if (ret)
		return ret;

	portmap &= ~BIT(port);

	if (!portmap || portmap == BIT(QCA_PPE_CPU_PORT))
		return ppe_fdb_mcast_op(priv, mdb->addr, 0,
					mdb->vid, PPE_FDB_OP_DEL);

	return ppe_fdb_mcast_op(priv, mdb->addr, portmap,
				mdb->vid, PPE_FDB_OP_ADD);
}

static int qca_ppe_fill_available_pcs(struct phylink_config *config,
				      struct phylink_pcs **available_pcs,
				      unsigned int num_available_pcs)
{
	struct dsa_port *dp = dsa_phylink_to_port(config);

	return fwnode_phylink_pcs_parse(of_fwnode_handle(dp->dn), available_pcs,
					&num_available_pcs);
}

static void qca_ppe_phylink_get_caps(struct dsa_switch *ds, int port,
				     struct phylink_config *config)
{
	struct dsa_port *dp = dsa_to_port(ds, port);
	int ret;

	if (port != 0) {
		ret = fwnode_phylink_pcs_parse(of_fwnode_handle(dp->dn), NULL,
					       &config->num_available_pcs);
		if (ret)
			return;

		config->fill_available_pcs = qca_ppe_fill_available_pcs;
	}

	switch (port) {
	case 0:
		config->mac_capabilities =
			MAC_1000FD | MAC_SYM_PAUSE | MAC_ASYM_PAUSE;

		__set_bit(PHY_INTERFACE_MODE_INTERNAL,
			  config->supported_interfaces);
		break;
	case 1 ... 4:
		config->mac_capabilities =
			MAC_1000FD | MAC_100FD | MAC_10FD |
			MAC_SYM_PAUSE | MAC_ASYM_PAUSE;

		__set_bit(PHY_INTERFACE_MODE_QSGMII,
			  config->supported_interfaces);
		__set_bit(PHY_INTERFACE_MODE_PSGMII,
			  config->supported_interfaces);
		__set_bit(PHY_INTERFACE_MODE_SGMII,
			  config->supported_interfaces);
		__set_bit(PHY_INTERFACE_MODE_RGMII,
			  config->supported_interfaces);
		__set_bit(PHY_INTERFACE_MODE_RGMII_ID,
			  config->supported_interfaces);
		__set_bit(PHY_INTERFACE_MODE_RGMII_RXID,
			  config->supported_interfaces);
		__set_bit(PHY_INTERFACE_MODE_RGMII_TXID,
			  config->supported_interfaces);
		break;
	case 5 ... 6:
		config->mac_capabilities =
			MAC_10000FD | MAC_5000FD | MAC_2500FD |
			MAC_1000FD | MAC_100FD | MAC_10FD |
			MAC_SYM_PAUSE | MAC_ASYM_PAUSE;

		__set_bit(PHY_INTERFACE_MODE_PSGMII,
			  config->supported_interfaces);
		__set_bit(PHY_INTERFACE_MODE_SGMII,
			  config->supported_interfaces);
		__set_bit(PHY_INTERFACE_MODE_1000BASEX,
			  config->supported_interfaces);
		__set_bit(PHY_INTERFACE_MODE_2500BASEX,
			  config->supported_interfaces);
		__set_bit(PHY_INTERFACE_MODE_USXGMII,
			  config->supported_interfaces);
		__set_bit(PHY_INTERFACE_MODE_10GBASER,
			  config->supported_interfaces);
		break;
	}

	if (port != 0)
		phy_interface_copy(config->pcs_interfaces,
				   config->supported_interfaces);
}

static void ppe_pcs_set_mux_hppe(struct qca_ppe_priv *priv, int port,
				 unsigned int mode, phy_interface_t interface)
{
	u32 mask, val;

	switch (port) {
	case 4:
		mask = HPPE_PORT4_PCS_SEL;
		if (interface == PHY_INTERFACE_MODE_QSGMII ||
		    interface == PHY_INTERFACE_MODE_PSGMII)
			val = FIELD_PREP(HPPE_PORT4_PCS_SEL,
					 HPPE_PORT4_PCS0);
		break;
	case 5:
		mask = HPPE_PORT5_PCS_SEL | HPPE_PORT5_GMAC_SEL;
		switch (interface) {
		case PHY_INTERFACE_MODE_QSGMII:
		case PHY_INTERFACE_MODE_PSGMII:
			val = FIELD_PREP(HPPE_PORT5_PCS_SEL,
					 HPPE_PORT5_PCS0) |
			      FIELD_PREP(HPPE_PORT5_GMAC_SEL,
					 HPPE_PORT5_GMAC_SEL_GMAC);
			break;
		case PHY_INTERFACE_MODE_SGMII:
		case PHY_INTERFACE_MODE_1000BASEX:
			val = FIELD_PREP(HPPE_PORT5_PCS_SEL,
					 HPPE_PORT5_PCS1) |
			      FIELD_PREP(HPPE_PORT5_GMAC_SEL,
					 HPPE_PORT5_GMAC_SEL_GMAC);
			break;
		case PHY_INTERFACE_MODE_2500BASEX:
			val = FIELD_PREP(HPPE_PORT5_PCS_SEL,
					 HPPE_PORT5_PCS1);
			/* In-Band is only supported by XGMAC */
			if (!phylink_autoneg_inband(mode))
				val |= FIELD_PREP(HPPE_PORT5_GMAC_SEL,
						  HPPE_PORT5_GMAC_SEL_GMAC);
			break;
		case PHY_INTERFACE_MODE_10GBASER:
		case PHY_INTERFACE_MODE_USXGMII:
			val = FIELD_PREP(HPPE_PORT5_PCS_SEL,
					 HPPE_PORT5_PCS1);
			break;
		default:
			return;
		}
		break;
	case 6:
		mask = HPPE_PORT6_PCS_SEL | HPPE_PORT6_GMAC_SEL;
		val = FIELD_PREP(HPPE_PORT6_PCS_SEL, HPPE_PORT6_PCS2);

		switch (interface) {
		case PHY_INTERFACE_MODE_SGMII:
		case PHY_INTERFACE_MODE_1000BASEX:
			val |= FIELD_PREP(HPPE_PORT6_GMAC_SEL,
					  HPPE_PORT6_GMAC_SEL_GMAC);
			break;
		case PHY_INTERFACE_MODE_2500BASEX:
			/* In-Band is only supported by XGMAC */
			if (!phylink_autoneg_inband(mode))
				val |= FIELD_PREP(HPPE_PORT6_GMAC_SEL,
						  HPPE_PORT6_GMAC_SEL_GMAC);

			break;
		case PHY_INTERFACE_MODE_10GBASER:
		case PHY_INTERFACE_MODE_USXGMII:
			break;
		default:
			return;
		}
		break;
	default:
		return;
	}

	regmap_update_bits(priv->regmap, PPE_PORT_MUX_CTRL, mask, val);
}

static void ppe_pcs_set_mux_cppe(struct qca_ppe_priv *priv, int port,
				 unsigned int mode, phy_interface_t interface)
{
	u32 mask, val = 0;

	switch (port) {
	case 5:
		mask = CPPE_PORT5_PCS_SEL | CPPE_PORT5_GMAC_SEL;
		switch (interface) {
		case PHY_INTERFACE_MODE_SGMII:
		case PHY_INTERFACE_MODE_1000BASEX:
			val = FIELD_PREP(CPPE_PORT5_PCS_SEL,
					 CPPE_PORT5_PCS1_CH0);
			break;
		case PHY_INTERFACE_MODE_2500BASEX:
			val = FIELD_PREP(CPPE_PORT5_PCS_SEL,
					 CPPE_PORT5_PCS1_CH0);
			/* In-Band is only supported by XGMAC */
			if (phylink_autoneg_inband(mode))
				val |= CPPE_PORT5_GMAC_SEL;
			break;
		case PHY_INTERFACE_MODE_10GBASER:
		case PHY_INTERFACE_MODE_USXGMII:
			val = FIELD_PREP(CPPE_PORT5_PCS_SEL,
					 CPPE_PORT5_PCS1_CH0) |
					 CPPE_PORT5_GMAC_SEL;
			break;
		default:
			return;
		}
		break;
	default:
		return;
	}

	regmap_update_bits(priv->regmap, PPE_PORT_MUX_CTRL, mask, val);
}

static int qca_ppe_mac_prepare(struct phylink_config *config, unsigned int mode,
			       phy_interface_t interface)
{
	struct dsa_port *dp = dsa_phylink_to_port(config);
	struct qca_ppe_priv *priv = ds_to_priv(dp->ds);
	struct qca_ppe_port_config *pc = &priv->port_config[dp->index];
	int ret;

	mutex_lock(&pc->lock);
	pc->mode = mode;
	pc->interface = interface;
	pc->config_error = 0;
	ret = qdx_port_prepare(priv->qdx, dp->index);
	if (ret) {
		mutex_unlock(&pc->lock);
		return ret;
	}
	pc->prepared = true;
	if (priv->data->type == PPE_TYPE_IPQ8074)
		ppe_pcs_set_mux_hppe(priv, dp->index, mode, interface);
	else
		ppe_pcs_set_mux_cppe(priv, dp->index, mode, interface);
	/* phylink calls mac_finish after MAC and PCS configuration. */
	return 0;
}

static int qca_ppe_mac_finish(struct phylink_config *config, unsigned int mode,
			      phy_interface_t interface)
{
	struct dsa_port *dp = dsa_phylink_to_port(config);
	struct qca_ppe_priv *priv = ds_to_priv(dp->ds);
	struct qca_ppe_port_config *pc = &priv->port_config[dp->index];
	int ret;

	ret = qdx_port_finish(priv->qdx, dp->index);
	if (!ret)
		ret = pc->config_error;
	if (ret) {
		ppe_port_bridge_txmac_set(priv, dp->index, false);
		qdx_port_failed(priv->qdx, dp->index, ret);
	}
	pc->prepared = false;
	mutex_unlock(&pc->lock);
	return ret;
}

static void qca_ppe_xgmac_config(struct qca_ppe_priv *priv, int port)
{
	int xgmac = port - 5;

	regmap_set_bits(priv->regmap, PPE_XGMAC_TX_CONF(xgmac),
			PPE_XGMAC_JABBER_DISABLE);

	regmap_update_bits(priv->regmap, PPE_XGMAC_RX_CONF(xgmac),
			   PPE_XGMAC_GMII_MPLS_LAYER_CK |
			   PPE_XGMAC_WATCHDOG_DISABLE,
			   PPE_XGMAC_GMII_MPLS_LAYER_CK);

	regmap_update_bits(priv->regmap, PPE_XGMAC_PACKET_FILTER(xgmac),
			   PPE_XGMAC_PROMISCUOUS |
			   PPE_XGMAC_PASS_CONTROL_FRAME |
			   PPE_XGMAC_RATE_ADAPTATION,
			   PPE_XGMAC_PROMISCUOUS |
			   FIELD_PREP(PPE_XGMAC_PASS_CONTROL_FRAME, 0x2) |
			   PPE_XGMAC_RATE_ADAPTATION);

	regmap_update_bits(priv->regmap, PPE_XGMAC_WATCHDOG_TIMEOUT(xgmac),
			   PPE_XGMAC_WATCHDOG_ENABLE |
			   PPE_XGMAC_WATCHDOG_THRESHOLD,
			   PPE_XGMAC_WATCHDOG_ENABLE |
			   FIELD_PREP(PPE_XGMAC_WATCHDOG_THRESHOLD, 0xb));

	regmap_update_bits(priv->regmap, PPE_XGMAC_TX_FLOW_CTRL(xgmac),
			   PPE_XGMAC_PAUSE_TIME,
			   FIELD_PREP(PPE_XGMAC_PAUSE_TIME, 0xffff));
}

/* Defined with the MIB table it walks; the port reset and the bank change
 * below have to bank the counters before the MIB they read stops being the
 * one they were counted in.
 */
static void ppe_mib_fold(struct qca_ppe_priv *priv, int port);

static int ppe_mac_config_apply(struct qca_ppe_priv *priv, int port,
				 unsigned int mode, phy_interface_t interface)
{
	int ret;

	if ((interface == PHY_INTERFACE_MODE_2500BASEX &&
	     phylink_autoneg_inband(mode)) ||
	    interface == PHY_INTERFACE_MODE_USXGMII ||
	    interface == PHY_INTERFACE_MODE_10GBASER) {
		qca_ppe_xgmac_config(priv, port);
	}

	if (priv->port_rst[port]) {
		/* The reset clears the MIB, so bank what it has counted and
		 * hold the rebase across the reset: a fold racing the window
		 * below would otherwise consume it while the counters are
		 * still running, and leave the drop to zero to be read as a
		 * wrap. The baseline is taken here rather than left to the
		 * periodic fold, so that nothing the port counts from
		 * link-up is discarded.
		 */
		spin_lock_bh(&priv->mib_lock);
		ppe_mib_fold(priv, port);
		priv->mib_rebase[port] = true;
		spin_unlock_bh(&priv->mib_lock);

		ret = reset_control_assert(priv->port_rst[port]);
		if (ret)
			return ret;
		msleep(150);
		ret = reset_control_deassert(priv->port_rst[port]);
		if (ret)
			return ret;

		spin_lock_bh(&priv->mib_lock);
		ppe_mib_fold(priv, port);
		priv->mib_rebase[port] = false;
		spin_unlock_bh(&priv->mib_lock);
	}
	return 0;
}

static void qca_ppe_mac_config(struct phylink_config *config,
			       unsigned int mode,
			       const struct phylink_link_state *state)
{
	struct dsa_port *dp = dsa_phylink_to_port(config);
	struct qca_ppe_priv *priv = ds_to_priv(dp->ds);
	struct qca_ppe_port_config *pc = &priv->port_config[dp->index];
	bool standalone = !pc->prepared;
	int ret, finish;

	if (standalone)
		mutex_lock(&pc->lock);
	pc->mode = mode;
	pc->interface = state->interface;
	pc->reset_pending = true;
	if (standalone) {
		ret = qdx_port_prepare(priv->qdx, dp->index);
		if (ret)
			goto failed;
	}
	ret = ppe_mac_config_apply(priv, dp->index, mode, state->interface);
	if (ret)
		qdx_port_failed(priv->qdx, dp->index, ret);
	else
		pc->reset_pending = false;
	pc->config_error = ret;
	if (standalone) {
		finish = qdx_port_finish(priv->qdx, dp->index);
		if (!ret)
			ret = finish;
	}
failed:
	if (ret) {
		ppe_port_bridge_txmac_set(priv, dp->index, false);
		qdx_port_failed(priv->qdx, dp->index, ret);
	}
	if (standalone)
		mutex_unlock(&pc->lock);
}

/* Release what is still in an XGMAC port's egress path by looping the
 * transmitter back into it, as qca-ssdk does on link-down ("release ppe port
 * egress packets when link down"). RX goes down in the same write: only the
 * transmitter has to drain, and the loop would otherwise learn the hosts
 * behind the other ports onto this one.
 */
static void ppe_port_xgmac_loopback_pulse(struct qca_ppe_priv *priv, int port)
{
	int xgmac = port - 5;

	if (port < 5 || port >= priv->data->num_ports)
		return;

	regmap_update_bits(priv->regmap, PPE_XGMAC_RX_CONF(xgmac),
			   PPE_XGMAC_LOOPBACK | PPE_XGMAC_RX_ENABLE,
			   PPE_XGMAC_LOOPBACK);
	usleep_range(1000, 2000);
	regmap_clear_bits(priv->regmap, PPE_XGMAC_RX_CONF(xgmac),
			  PPE_XGMAC_LOOPBACK);
}

static void qca_ppe_mac_link_down(struct phylink_config *config,
				  unsigned int mode,
				  phy_interface_t interface)
{
	struct dsa_port *dp = dsa_phylink_to_port(config);
	struct qca_ppe_priv *priv = ds_to_priv(dp->ds);
	int port = dp->index;
	struct qca_ppe_port_config *pc = &priv->port_config[port];
	int ret;

	/* The CPU port is INTERNAL: it falls through the switch below
	 * without its MAC being touched, and qca_ppe_mac_link_up() would not
	 * re-open its gate. Leave it alone.
	 */
	if (dsa_is_cpu_port(dp->ds, port))
		return;

	mutex_lock(&pc->lock);
	pc->mode = mode;
	pc->interface = interface;
	pc->link = false;
	ppe_port_bridge_txmac_set(priv, port, false);
	ret = qdx_port_prepare(priv->qdx, port);
	if (ret)
		goto out;

	/* Gate the fabric before the MAC is torn down; qca_ppe_mac_link_up()
	 * turns it back on once the MAC is up. Left on across a flap, the
	 * fabric dequeues into a MAC that is still being re-clocked and
	 * latches the port's egress scheduler in a state only a reboot clears.
	 */
	ppe_port_bridge_txmac_set(priv, port, false);

	/* Let the egress path drain before the MAC goes: packets stranded
	 * there when the link drops wedge the queue manager for good. Same
	 * 10ms as qca-ssdk.
	 */
	msleep(10);

	switch (interface) {
	case PHY_INTERFACE_MODE_SGMII:
	case PHY_INTERFACE_MODE_QSGMII:
	case PHY_INTERFACE_MODE_PSGMII:
	case PHY_INTERFACE_MODE_1000BASEX:
		ppe_port_gmac_set(priv, port, false, false);
		break;
	case PHY_INTERFACE_MODE_2500BASEX:
		if (!phylink_autoneg_inband(mode)) {
			ppe_port_gmac_set(priv, port, false, false);
		} else {
			ppe_port_xgmac_loopback_pulse(priv, port);
			ppe_port_xgmac_set(priv, port, false, false);
		}
		break;
	case PHY_INTERFACE_MODE_10GBASER:
	case PHY_INTERFACE_MODE_USXGMII:
		ppe_port_xgmac_loopback_pulse(priv, port);
		ppe_port_xgmac_set(priv, port, false, false);
		break;
	default:
		break;
	}

	ret = qdx_port_finish(priv->qdx, port);
	if (ret)
		qdx_port_failed(priv->qdx, port, ret);
out:
	mutex_unlock(&pc->lock);
}

static bool qca_ppe_port_uses_xgmac(unsigned int mode, phy_interface_t interface)
{
	switch (interface) {
	case PHY_INTERFACE_MODE_2500BASEX:
		return phylink_autoneg_inband(mode);
	case PHY_INTERFACE_MODE_USXGMII:
	case PHY_INTERFACE_MODE_10GBASER:
		return true;
	default:
		return false;
	}
}

static int ppe_mac_link_apply(struct qca_ppe_priv *priv, int port,
			       unsigned int mode, phy_interface_t interface,
			       int speed, int duplex, bool tx_pause, bool rx_pause)
{
	unsigned long rate = 125000000;
	int ret;

	/* Invalid mode for port < 5 */
	if ((interface == PHY_INTERFACE_MODE_2500BASEX ||
	     interface == PHY_INTERFACE_MODE_USXGMII ||
	     interface == PHY_INTERFACE_MODE_10GBASER) &&
	     port < 5)
		return -EINVAL;

	/* Bank what the MAC the port is leaving has counted, then baseline
	 * the one it arrives on: a rebase left to the periodic fold would
	 * discard everything the new MAC counted in the meantime. Where the
	 * bank does not change the second fold adds nothing.
	 */
	spin_lock_bh(&priv->mib_lock);
	ppe_mib_fold(priv, port);
	priv->port_xgmac[port] = qca_ppe_port_uses_xgmac(mode, interface);
	ppe_mib_fold(priv, port);
	spin_unlock_bh(&priv->mib_lock);

	switch (interface) {
	case PHY_INTERFACE_MODE_SGMII:
	case PHY_INTERFACE_MODE_QSGMII:
	case PHY_INTERFACE_MODE_PSGMII:
	case PHY_INTERFACE_MODE_1000BASEX:
		ppe_gmac_link_up(priv, port, speed, duplex,
				 tx_pause, rx_pause);
		break;
	case PHY_INTERFACE_MODE_2500BASEX:
		if (!phylink_autoneg_inband(mode))
			ppe_gmac_link_up(priv, port, speed, duplex,
					 tx_pause, rx_pause);
		else
			ppe_xgmac_link_up(priv, port, interface, speed,
					  tx_pause, rx_pause);
		break;
	case PHY_INTERFACE_MODE_10GBASER:
	case PHY_INTERFACE_MODE_USXGMII:
		ppe_xgmac_link_up(priv, port, interface, speed,
				  tx_pause, rx_pause);
		break;
	default:
		return -EINVAL;
	}

	switch (interface) {
	case PHY_INTERFACE_MODE_SGMII:
	case PHY_INTERFACE_MODE_QSGMII:
	case PHY_INTERFACE_MODE_PSGMII:
	case PHY_INTERFACE_MODE_1000BASEX:
	case PHY_INTERFACE_MODE_2500BASEX:
		switch (speed) {
		case SPEED_10:
			rate = 2500000;
			break;
		case SPEED_100:
			rate = 25000000;
			break;
		case SPEED_1000:
			rate = 125000000;
			break;
		case SPEED_2500:
			rate = 312500000;
			break;
		}
		break;
	case PHY_INTERFACE_MODE_USXGMII:
	case PHY_INTERFACE_MODE_10GBASER:
		switch (speed) {
		case SPEED_10:
			rate = 1250000;
			break;
		case SPEED_100:
			rate = 12500000;
			break;
		case SPEED_1000:
			rate = 125000000;
			break;
		case SPEED_2500:
			rate = 78125000;
			break;
		case SPEED_5000:
			rate = 156250000;
			break;
		case SPEED_10000:
			rate = 312500000;
			break;
		}
		break;
	default:
		rate = 125000000;
		break;
	}

	if (priv->port_rx_clk[port]) {
		ret = clk_set_rate(priv->port_rx_clk[port], rate);
		if (ret)
			return ret;
	}
	if (priv->port_tx_clk[port]) {
		ret = clk_set_rate(priv->port_tx_clk[port], rate);
		if (ret)
			return ret;
	}

	switch (interface) {
	case PHY_INTERFACE_MODE_SGMII:
	case PHY_INTERFACE_MODE_QSGMII:
	case PHY_INTERFACE_MODE_PSGMII:
	case PHY_INTERFACE_MODE_1000BASEX:
		ppe_port_gmac_set(priv, port, true, true);
		break;
	case PHY_INTERFACE_MODE_2500BASEX:
		if (!phylink_autoneg_inband(mode))
			ppe_port_gmac_set(priv, port, true, true);
		else
			ppe_port_xgmac_set(priv, port, true, true);
		break;
	case PHY_INTERFACE_MODE_USXGMII:
	case PHY_INTERFACE_MODE_10GBASER:
		ppe_port_xgmac_set(priv, port, true, true);
		break;
	default:
		return -EINVAL;
	}

	/* MAC is up, so the fabric may feed the port again. The early returns
	 * above bring no MAC up, so they leave the gate closed on purpose.
	 */
	ppe_port_bridge_txmac_set(priv, port, true);
	return 0;
}

static void qca_ppe_mac_link_up(struct phylink_config *config,
			      struct phy_device *phydev, unsigned int mode,
			      phy_interface_t interface, int speed, int duplex,
			      bool tx_pause, bool rx_pause)
{
	struct dsa_port *dp = dsa_phylink_to_port(config);
	struct qca_ppe_priv *priv = ds_to_priv(dp->ds);
	struct qca_ppe_port_config *pc = &priv->port_config[dp->index];
	int ret;

	if (dsa_is_cpu_port(dp->ds, dp->index))
		return;
	mutex_lock(&pc->lock);
	pc->mode = mode;
	pc->interface = interface;
	pc->speed = speed;
	pc->duplex = duplex;
	pc->tx_pause = tx_pause;
	pc->rx_pause = rx_pause;
	pc->link = true;
	ret = qdx_port_prepare(priv->qdx, dp->index);
	if (ret) {
		ppe_port_bridge_txmac_set(priv, dp->index, false);
		goto out;
	}
	ret = ppe_mac_link_apply(priv, dp->index, mode, interface, speed, duplex,
				 tx_pause, rx_pause);
	if (ret)
		qdx_port_failed(priv->qdx, dp->index, ret);
	ret = qdx_port_finish(priv->qdx, dp->index);
	if (ret) {
		ppe_port_bridge_txmac_set(priv, dp->index, false);
		qdx_port_failed(priv->qdx, dp->index, ret);
	}
out:
	mutex_unlock(&pc->lock);
}

/* qca_ppe implements no LPI. The stubs exist only to make
 * phylink_mac_implements_lpi() true with lpi_capabilities left at 0 -
 * phylink's "EEE always disabled" case, where phylink_bringup_phy() calls
 * phy_disable_eee(). Without that the PHYs negotiate 802.3az and egress into
 * a MAC waking from LPI wedges the port. Never called; the ops are 6.14+.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 14, 0)
static int qca_ppe_mac_enable_tx_lpi(struct phylink_config *config, u32 timer,
				     bool tx_clk_stop)
{
	return 0;
}

static void qca_ppe_mac_disable_tx_lpi(struct phylink_config *config)
{
}
#endif

static const struct phylink_mac_ops qca_ppe_phylink_mac_ops = {
	.mac_prepare	= qca_ppe_mac_prepare,
	.mac_finish	= qca_ppe_mac_finish,
	.mac_config	= qca_ppe_mac_config,
	.mac_link_down	= qca_ppe_mac_link_down,
	.mac_link_up	= qca_ppe_mac_link_up,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 14, 0)
	.mac_enable_tx_lpi	= qca_ppe_mac_enable_tx_lpi,
	.mac_disable_tx_lpi	= qca_ppe_mac_disable_tx_lpi,
#endif
};

struct qca_ppe_mib_desc {
	unsigned int offset;
	unsigned int size;
	unsigned int xgmac;
	unsigned int xgmac_size;
	const char name[ETH_GSTRING_LEN];
};

#define MIB_ROW(_off, _sz, _xoff, _xsz, _name)				\
	{ .offset = (_off), .size = (_sz), .xgmac = (_xoff),		\
	  .xgmac_size = (_xsz), .name = _name }

/* Each counter as both MACs express it: the GMAC offset and word count, then
 * the XGMAC MMC offset and word count, or 0 where the XGMAC has no
 * equivalent. The XGMAC lumps 1519-and-up into its 1024-to-max bin and counts
 * no collisions, no alignment error and no bad receive bytes.
 */
static const struct qca_ppe_mib_desc qca_ppe_mib[] = {
	MIB_ROW(PPE_MIB_RXBROAD, 1, 0x918, 2, "rx_broadcast"),
	MIB_ROW(PPE_MIB_RXPAUSE, 1, 0x988, 2, "rx_pause"),
	MIB_ROW(PPE_MIB_RXMULTI, 1, 0x920, 2, "rx_multicast"),
	MIB_ROW(PPE_MIB_RXFCSERR, 1, 0x928, 2, "rx_fcs_error"),
	MIB_ROW(PPE_MIB_RXALIGNERR, 1, 0, 0, "rx_align_error"),
	MIB_ROW(PPE_MIB_RXRUNT, 1, 0x938, 1, "rx_runt"),
	MIB_ROW(PPE_MIB_RXFRAG, 1, 0x930, 1, "rx_fragment"),
	MIB_ROW(PPE_MIB_RXJUMBOFCSERR, 1, 0x934, 1, "rx_jumbo_fcs_error"),
	MIB_ROW(PPE_MIB_RXJUMBOALIGNERR, 1, 0, 0, "rx_jumbo_align_error"),
	MIB_ROW(PPE_MIB_RXPKT64, 1, 0x940, 2, "rx_64byte"),
	MIB_ROW(PPE_MIB_RXPKT65TO127, 1, 0x948, 2, "rx_65_127byte"),
	MIB_ROW(PPE_MIB_RXPKT128TO255, 1, 0x950, 2, "rx_128_255byte"),
	MIB_ROW(PPE_MIB_RXPKT256TO511, 1, 0x958, 2, "rx_256_511byte"),
	MIB_ROW(PPE_MIB_RXPKT512TO1023, 1, 0x960, 2, "rx_512_1023byte"),
	MIB_ROW(PPE_MIB_RXPKT1024TO1518, 1, 0x968, 2, "rx_1024_1518byte"),
	MIB_ROW(PPE_MIB_RXPKT1519TOX, 1, 0, 0, "rx_1519_maxbyte"),
	MIB_ROW(PPE_MIB_RXTOOLONG, 1, 0x93c, 1, "rx_too_long"),
	MIB_ROW(PPE_MIB_RXGOODBYTE_L, 2, 0x910, 2, "rx_good_bytes"),
	MIB_ROW(PPE_MIB_RXBADBYTE_L, 2, 0, 0, "rx_bad_bytes"),
	MIB_ROW(PPE_MIB_RXUNI, 1, 0x970, 2, "rx_unicast"),
	MIB_ROW(PPE_MIB_TXBROAD, 1, 0x874, 2, "tx_broadcast"),
	MIB_ROW(PPE_MIB_TXPAUSE, 1, 0x894, 2, "tx_pause"),
	MIB_ROW(PPE_MIB_TXMULTI, 1, 0x86c, 2, "tx_multicast"),
	MIB_ROW(PPE_MIB_TXUNDERRUN, 1, 0x87c, 2, "tx_underrun"),
	MIB_ROW(PPE_MIB_TXPKT64, 1, 0x834, 2, "tx_64byte"),
	MIB_ROW(PPE_MIB_TXPKT65TO127, 1, 0x83c, 2, "tx_65_127byte"),
	MIB_ROW(PPE_MIB_TXPKT128TO255, 1, 0x844, 2, "tx_128_255byte"),
	MIB_ROW(PPE_MIB_TXPKT256TO511, 1, 0x84c, 2, "tx_256_511byte"),
	MIB_ROW(PPE_MIB_TXPKT512TO1023, 1, 0x854, 2, "tx_512_1023byte"),
	MIB_ROW(PPE_MIB_TXPKT1024TO1518, 1, 0x85c, 2, "tx_1024_1518byte"),
	MIB_ROW(PPE_MIB_TXPKT1519TOX, 1, 0, 0, "tx_1519_maxbyte"),
	MIB_ROW(PPE_MIB_TXBYTE_L, 2, 0x814, 2, "tx_bytes"),
	MIB_ROW(PPE_MIB_TXCOLLISIONS, 1, 0, 0, "tx_collisions"),
	MIB_ROW(PPE_MIB_TXABORTCOL, 1, 0, 0, "tx_abort_collision"),
	MIB_ROW(PPE_MIB_TXMULTICOL, 1, 0, 0, "tx_multi_collision"),
	MIB_ROW(PPE_MIB_TXSINGLECOL, 1, 0, 0, "tx_single_collision"),
	MIB_ROW(PPE_MIB_TXEXCESSIVEDEFER, 1, 0, 0, "tx_excessive_defer"),
	MIB_ROW(PPE_MIB_TXDEFER, 1, 0, 0, "tx_defer"),
	MIB_ROW(PPE_MIB_TXLATECOL, 1, 0, 0, "tx_late_collision"),
	MIB_ROW(PPE_MIB_TXUNI, 1, 0x864, 2, "tx_unicast"),
};

/* What a counter has reached, and the raw register value that total was last
 * brought up to date from.
 */
struct qca_ppe_mib_stats {
	u64 total;
	u64 last;
};

static struct qca_ppe_mib_stats *ppe_port_mib(struct qca_ppe_priv *priv,
					      int port)
{
	return priv->port_mib + port * ARRAY_SIZE(qca_ppe_mib);
}

/* The GMAC keeps most counters in a single 32-bit register and neither MAC
 * ever stops counting, so the registers wrap where the totals reported to
 * userspace must not: each total takes the difference since the last fold, at
 * the width of the register it came from.
 *
 * A difference is only meaningful across a counter that kept running. Two
 * things break that, and both take a baseline instead: a port muxed to its
 * XGMAC starts reading a second MAC's independent counters, since the idle
 * block reads back zero; and resetting a port zeroes the MIB it owns, which
 * an unguarded difference would read as a wrap and add 2^32 for.
 */
static void ppe_mib_fold(struct qca_ppe_priv *priv, int port)
{
	struct qca_ppe_mib_stats *stats;
	bool xgmac, rebase;
	int i;

	/* The CPU port owns no MAC MIB, and phylink brings its fixed link up
	 * like any other, so the fold guards itself rather than each caller.
	 */
	if (port < 1)
		return;

	stats = ppe_port_mib(priv, port);
	xgmac = priv->port_xgmac[port];
	rebase = priv->mib_rebase[port] || xgmac != priv->mib_xgmac[port];

	for (i = 0; i < ARRAY_SIZE(qca_ppe_mib); i++) {
		const struct qca_ppe_mib_desc *mib = &qca_ppe_mib[i];
		unsigned int reg, size;
		u32 lo, hi = 0;
		u64 cur;

		if (xgmac) {
			reg = PPE_XGMAC_MIB(port - 5, mib->xgmac);
			size = mib->xgmac_size;
		} else {
			reg = PPE_GMAC_MIB(port - 1, mib->offset);
			size = mib->size;
		}

		if (!size)
			continue;

		regmap_read(priv->regmap, reg, &lo);
		if (size > 1)
			regmap_read(priv->regmap, reg + 4, &hi);
		cur = (u64)hi << 32 | lo;

		if (!rebase)
			stats[i].total += size > 1 ? cur - stats[i].last :
					  (u32)(cur - stats[i].last);
		stats[i].last = cur;
	}

	priv->mib_xgmac[port] = xgmac;
}

static u64 ppe_mib_total(const struct qca_ppe_mib_stats *stats,
			 unsigned int offset)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(qca_ppe_mib); i++)
		if (qca_ppe_mib[i].offset == offset)
			return stats[i].total;

	return 0;
}

static void ppe_mib_work(struct work_struct *work)
{
	struct qca_ppe_priv *priv = container_of(to_delayed_work(work),
						 struct qca_ppe_priv,
						 mib_work);
	struct dsa_port *dp;

	dsa_switch_for_each_user_port(dp, &priv->ds) {
		spin_lock_bh(&priv->mib_lock);
		ppe_mib_fold(priv, dp->index);
		spin_unlock_bh(&priv->mib_lock);
	}

	schedule_delayed_work(&priv->mib_work, PPE_MIB_FOLD_INTERVAL);
}

static void qca_ppe_get_strings(struct dsa_switch *ds, int port,
				    u32 stringset, uint8_t *data)
{
	int i;

	if (stringset != ETH_SS_STATS)
		return;

	for (i = 0; i < ARRAY_SIZE(qca_ppe_mib); i++)
		ethtool_puts(&data, qca_ppe_mib[i].name);
}

static int qca_ppe_get_sset_count(struct dsa_switch *ds, int port,
				      int sset)
{
	if (sset != ETH_SS_STATS)
		return 0;

	return ARRAY_SIZE(qca_ppe_mib);
}

static void qca_ppe_get_ethtool_stats(struct dsa_switch *ds, int port,
					  uint64_t *data)
{
	struct qca_ppe_priv *priv = ds_to_priv(ds);
	struct qca_ppe_mib_stats *stats;
	int i;

	if (port < 1 || port >= ds->num_ports) {
		memset(data, 0, sizeof(u64) * ARRAY_SIZE(qca_ppe_mib));
		return;
	}

	stats = ppe_port_mib(priv, port);

	spin_lock_bh(&priv->mib_lock);
	ppe_mib_fold(priv, port);

	for (i = 0; i < ARRAY_SIZE(qca_ppe_mib); i++)
		data[i] = stats[i].total;

	spin_unlock_bh(&priv->mib_lock);
}

/* Shorthand for the reader below, which holds the port's counters under that
 * name.
 */
#define MIB(_c)		ppe_mib_total(stats, PPE_MIB_ ## _c)

static void qca_ppe_get_stats64(struct dsa_switch *ds, int port,
				struct rtnl_link_stats64 *s)
{
	struct qca_ppe_priv *priv = ds_to_priv(ds);
	struct qca_ppe_mib_stats *stats;

	if (port < 1 || port >= ds->num_ports)
		return;

	stats = ppe_port_mib(priv, port);

	spin_lock_bh(&priv->mib_lock);
	ppe_mib_fold(priv, port);

	s->rx_packets = MIB(RXUNI) + MIB(RXMULTI) + MIB(RXBROAD);
	s->tx_packets = MIB(TXUNI) + MIB(TXMULTI) + MIB(TXBROAD);
	s->rx_bytes = MIB(RXGOODBYTE_L);
	s->tx_bytes = MIB(TXBYTE_L);
	s->multicast = MIB(RXMULTI);

	s->rx_crc_errors = MIB(RXFCSERR) + MIB(RXJUMBOFCSERR);
	s->rx_frame_errors = MIB(RXALIGNERR) + MIB(RXJUMBOALIGNERR);
	s->rx_length_errors = MIB(RXRUNT) + MIB(RXFRAG) + MIB(RXTOOLONG);
	s->rx_errors = s->rx_crc_errors + s->rx_frame_errors +
		       s->rx_length_errors;

	s->tx_fifo_errors = MIB(TXUNDERRUN);
	s->tx_aborted_errors = MIB(TXABORTCOL);
	s->tx_window_errors = MIB(TXLATECOL);
	s->tx_errors = s->tx_fifo_errors + s->tx_aborted_errors +
		       s->tx_window_errors;

	s->collisions = MIB(TXCOLLISIONS);

	spin_unlock_bh(&priv->mib_lock);
}

#undef MIB

static void qca_ppe_teardown(struct dsa_switch *ds)
{
	struct qca_ppe_priv *priv = ds_to_priv(ds);

	cancel_delayed_work_sync(&priv->mib_work);
}

static void qca_ppe_port_stp_state_set(struct dsa_switch *ds, int port,
					   u8 state)
{
	struct qca_ppe_priv *priv = ds_to_priv(ds);
	u32 stp_state;

	switch (state) {
	case BR_STATE_DISABLED:
		stp_state = PPE_STP_DISABLED;
		break;
	case BR_STATE_BLOCKING:
	case BR_STATE_LISTENING:
		stp_state = PPE_STP_BLOCKING;
		break;
	case BR_STATE_LEARNING:
		stp_state = PPE_STP_LEARNING;
		break;
	case BR_STATE_FORWARDING:
	default:
		stp_state = PPE_STP_FORWARDING;
		break;
	}

	regmap_update_bits(priv->regmap, PPE_CST_STATE(port),
			   PPE_STP_STATE_MASK, stp_state);
}

static const struct dsa_switch_ops qca_ppe_ops = {
	.get_tag_protocol	= qca_ppe_get_tag_protocol,
	.setup			= qca_ppe_setup,
	.teardown		= qca_ppe_teardown,
	.set_ageing_time	= qca_ppe_set_ageing_time,
	.port_change_mtu	= qca_ppe_port_change_mtu,
	.port_max_mtu		= qca_ppe_port_max_mtu,
	.port_enable		= qca_ppe_port_enable,
	.port_disable		= qca_ppe_port_disable,
	.port_stp_state_set	= qca_ppe_port_stp_state_set,
	.port_bridge_join	= qca_ppe_port_bridge_join,
	.port_bridge_leave	= qca_ppe_port_bridge_leave,
	.port_fdb_add		= qca_ppe_port_fdb_add,
	.port_fdb_del		= qca_ppe_port_fdb_del,
	.port_fdb_dump		= qca_ppe_port_fdb_dump,
	.port_mdb_add		= qca_ppe_port_mdb_add,
	.port_mdb_del		= qca_ppe_port_mdb_del,
	.phylink_get_caps	= qca_ppe_phylink_get_caps,
	.port_vlan_filtering	= qca_ppe_port_vlan_filtering,
	.port_vlan_add		= qca_ppe_port_vlan_add,
	.port_vlan_del		= qca_ppe_port_vlan_del,
	.get_strings		= qca_ppe_get_strings,
	.get_sset_count		= qca_ppe_get_sset_count,
	.get_ethtool_stats	= qca_ppe_get_ethtool_stats,
	.get_stats64		= qca_ppe_get_stats64,
};

static void ppe_vsi_init(struct qca_ppe_priv *priv)
{
	int i;

	/* All three words must be written back for the HW to latch the entry */
	for (i = 1; i < priv->data->num_ports; i++) {
		u32 val[3];

		regmap_read(priv->regmap, PPE_L3_VP_PORT_TBL(i), &val[0]);
		regmap_read(priv->regmap, PPE_L3_VP_PORT_TBL(i) + 4, &val[1]);
		regmap_read(priv->regmap, PPE_L3_VP_PORT_TBL(i) + 8, &val[2]);

		val[1] &= ~(PPE_L3_VP_VSI_VALID | PPE_L3_VP_VSI);
		val[1] |= PPE_L3_VP_VSI_VALID;

		regmap_write(priv->regmap, PPE_L3_VP_PORT_TBL(i), val[0]);
		regmap_write(priv->regmap, PPE_L3_VP_PORT_TBL(i) + 4, val[1]);
		regmap_write(priv->regmap, PPE_L3_VP_PORT_TBL(i) + 8, val[2]);
	}
}

static void ppe_mac_hw_init(struct qca_ppe_priv *priv)
{
	const struct ppe_data *d = priv->data;
	int lpbk_gmac = d->loopback_port - 1;
	int gmac;

	for (gmac = 0; gmac < d->num_gmacs; gmac++) {
		regmap_update_bits(priv->regmap, PPE_GMAC_CTRL2(gmac),
				   PPE_GMAC_CTRL2_MAXFR | PPE_GMAC_CTRL2_CRS_SEL |
				   PPE_GMAC_CTRL2_TX_THD,
				   FIELD_PREP(PPE_GMAC_CTRL2_MAXFR, PPE_MAX_FRAME_SIZE) |
				   FIELD_PREP(PPE_GMAC_CTRL2_TX_THD, 1));

		regmap_update_bits(priv->regmap, PPE_GMAC_DBG_CTRL(gmac),
				   PPE_GMAC_DBG_CTRL_HIHG_IPG,
				   FIELD_PREP(PPE_GMAC_DBG_CTRL_HIHG_IPG, 0xc));

		regmap_write(priv->regmap, PPE_GMAC_JUMBO_SIZE(gmac),
			     PPE_MAX_FRAME_SIZE);
	}

	regmap_update_bits(priv->regmap, PPE_LPBK_PPS_CTRL(lpbk_gmac),
			   PPE_LPBK_PPS_THRESHOLD,
			   FIELD_PREP(PPE_LPBK_PPS_THRESHOLD, 21));
	regmap_write(priv->regmap, PPE_LPBK_ENABLE(lpbk_gmac),
		PPE_LPBK_EN | PPE_LPBK_CRC_STRIP_EN);
	msleep(100);
	ppe_port_bridge_txmac_set(priv, d->loopback_port, true);
}

static void ppe_ctrlpkt_init(struct qca_ppe_priv *priv)
{
	/* RFDB_TBL[31]: STP multicast MAC 01:80:c2:00:00:00 */
	regmap_write(priv->regmap, PPE_RFDB_TBL(31), 0xc2000000);
	regmap_write(priv->regmap, PPE_RFDB_TBL(31) + 4, 0x00010180);

	/* APP_CTRL[0]: match RFDB profile 31, bypass STP, redirect to CPU */
	regmap_write(priv->regmap, PPE_APP_CTRL(0), 0x00000003);
	regmap_write(priv->regmap, PPE_APP_CTRL(0) + 4, 0x00000002);
	regmap_write(priv->regmap, PPE_APP_CTRL(0) + 8, 0x000093fc);
}

static int ppe_ipq6018_mux_setup(struct qca_ppe_priv *priv)
{
	struct device_node *ports_np, *port_np;
	struct of_phandle_args pcs_args;
	int port3_ch = -1;
	u32 port;
	int ret;

	ports_np = of_get_child_by_name(priv->ds.dev->of_node, "ports");
	if (!ports_np)
		return -ENODEV;

	for_each_available_child_of_node(ports_np, port_np) {
		ret = of_property_read_u32(port_np, "reg", &port);
		if (ret)
			continue;

		if (port != 3)
			continue;

		ret = of_parse_phandle_with_args(port_np, "pcs-handle",
						 "#pcs-cells", 0, &pcs_args);
		if (ret)
			continue;

		port3_ch = pcs_args.args[0];
	}

	of_node_put(ports_np);

	/* FIXME: better investigate this */
	if (port3_ch == 4)
		regmap_update_bits(priv->regmap, PPE_PORT_MUX_CTRL,
				   CPPE_PORT3_PCS_SEL | CPPE_PCS0_CH4_SEL,
				   FIELD_PREP(CPPE_PORT3_PCS_SEL,
					      CPPE_PORT3_PCS0_CH4) |
				   CPPE_PCS0_CH4_SEL);

	return 0;
}

/* Fixed native queue identity and its separately retired execution tokens. */
#define PPE_TC_NORMAL_QUEUES 1
#define PPE_TC_CLASS_QUEUES 64
#define PPE_TC_QUEUES (PPE_TC_NORMAL_QUEUES + PPE_TC_CLASS_QUEUES)

struct ppe_tc_port;
struct ppe_tc_execution {
	struct list_head list;
	struct qdx_tc_queue *slot;
	refcount_t refs;
	struct qdx_tx_path *path;
	struct qdx_tx_class class;
	enum qdx_disposition disposition;
	bool retired;
	bool held;
	bool stopped;
	int stop_error;
	bool base_path;
	bool native_return;
	bool handback_pending;
};

struct qdx_tc_queue {
	struct ppe_tc_port *port;
	struct mutex cfg;
	struct qdx_tc_queue_owner origin;
	struct qdx_tc_queue_owner claim;
	struct list_head executions;
	struct ppe_tc_execution *active_execution;
	u16 qid;
	bool claimed;
	bool exposed;
};

struct ppe_tc_block {
	struct list_head list;
	struct ppe_tc_port *port;
	struct tcf_block *native;
	enum flow_block_binder_type binder;
	struct flow_block_cb *callback;
	bool unbinding;
};

struct ppe_tc_root {
	struct list_head list;
	struct Qdisc *identity;
	struct qdx_binding *provider;
};

struct ppe_tc_port {
	struct qca_ppe_priv *priv;
	unsigned int number;
	struct qdx_binding *binding;
	struct net_device *dev;
	refcount_t refs;
	wait_queue_head_t drained;
	struct list_head blocks;
	struct list_head roots;
	struct qdx_tc_queue *slots[PPE_TC_QUEUES];
	bool closing;
};

struct qca_ppe_tc {
	spinlock_t lock;
	struct dsa_switch_ops ops;
	struct notifier_block netdev;
	bool notifier_registered;
	bool native_gone;
	struct ppe_tc_port ports[QCA_PPE_MAX_PORTS];
};

static LIST_HEAD(ppe_tc_block_callbacks);

static bool ppe_tc_port_get(void *object)
{
	struct ppe_tc_port *port = object;

	return refcount_inc_not_zero(&port->refs);
}

static void ppe_tc_port_put(void *object)
{
	struct ppe_tc_port *port = object;

	spin_lock_bh(&port->priv->tc->lock);
	refcount_dec(&port->refs);
	wake_up_all(&port->drained);
	spin_unlock_bh(&port->priv->tc->lock);
}

static bool ppe_tc_execution_get(void *object)
{
	struct ppe_tc_execution *execution = object;

	if (!refcount_inc_not_zero(&execution->refs))
		return false;
	qdx_tx_path_get(execution->path);
	return true;
}

static void ppe_tc_execution_put(void *object)
{
	struct ppe_tc_execution *execution = object;

	/* A returned selection owns this exact path independently of retirement. */
	qdx_tx_path_put(execution->path);
	refcount_dec(&execution->refs);
}

static bool ppe_tc_queue_cached(struct qdx_tc_queue *slot, struct Qdisc *root)
{
	struct sk_buff *skb;
	bool busy = false;

	if (!root || root->flags & TCQ_F_BUILTIN)
		return false;
	/* Caller holds the public native root lock through its identity update. */
	if (qdisc_is_running(root))
		return true;
	skb_queue_walk(&root->gso_skb, skb) {
		if (skb_get_queue_mapping(skb) == slot->qid) {
			busy = true;
			break;
		}
	}
	if (!busy)
		skb_queue_walk(&root->skb_bad_txq, skb) {
			if (skb_get_queue_mapping(skb) == slot->qid) {
				busy = true;
				break;
			}
		}
	return busy;
}

static int ppe_tc_queue_reserve(struct qdx_binding *binding,
		const struct qdx_tc_queue_owner *owner, u16 requested,
		struct qdx_tc_queue **result, u16 *queue)
{
	struct ppe_tc_port *port = qdx_binding_owner(binding);
	struct qdx_tc_queue *slot;
	unsigned int first, last, qid;
	int error = -ENOSPC;

	ASSERT_RTNL();
	if (!owner || !owner->root || !result || !queue ||
	    (requested != U16_MAX && requested >= PPE_TC_QUEUES) ||
	    (!requested && owner->class))
		return -EINVAL;
	first = requested == U16_MAX ? PPE_TC_NORMAL_QUEUES : requested;
	last = requested == U16_MAX ? PPE_TC_QUEUES : requested + 1;
	slot = kzalloc(sizeof(*slot), GFP_KERNEL);
	if (!slot)
		return -ENOMEM;
	slot->port = port;
	slot->origin = *owner;
	mutex_init(&slot->cfg);
	INIT_LIST_HEAD(&slot->executions);
	spin_lock_bh(&port->priv->tc->lock);
	if (port->closing) {
		error = -ESHUTDOWN;
		goto unlock;
	}
	for (qid = first; qid < last; qid++) {
		if (port->slots[qid])
			continue;
		port->slots[qid] = slot;
		slot->qid = qid;
		ppe_tc_port_get(port);
		error = 0;
		break;
	}
unlock:
	spin_unlock_bh(&port->priv->tc->lock);
	if (error) {
		kfree(slot);
		return error;
	}
	*result = slot;
	*queue = slot->qid;
	return 0;
}

static int ppe_tc_queue_claim(struct qdx_tc_queue *slot,
			    const struct qdx_tc_queue_owner *owner)
{
	struct ppe_tc_port *port = slot->port;
	spinlock_t *native_lock = NULL;
	int error = 0;

	ASSERT_RTNL();
	if (owner && !owner->root)
		return -EINVAL;
	mutex_lock(&slot->cfg);
	if (owner && slot->claimed &&
	    (owner->root != slot->claim.root || owner->class != slot->claim.class)) {
		if (ppe_qdx_tx_queue_busy(port->priv, port->number, slot->qid)) {
			error = -EBUSY;
			goto out;
		}
		native_lock = qdisc_lock(owner->root);
		spin_lock_bh(native_lock);
		if (ppe_tc_queue_cached(slot, owner->root)) {
			error = -EBUSY;
			goto out;
		}
	}
	spin_lock_bh(&port->priv->tc->lock);
	slot->claimed = !!owner;
	if (owner)
		slot->claim = *owner;
	else
		memset(&slot->claim, 0, sizeof(slot->claim));
	spin_unlock_bh(&port->priv->tc->lock);
out:
	if (native_lock)
		spin_unlock_bh(native_lock);
	mutex_unlock(&slot->cfg);
	return error;
}

static int ppe_tc_queue_activate(struct qdx_tc_queue *slot)
{
	struct net_device *dev = slot->port->dev;

	ASSERT_RTNL();
	if (READ_ONCE(slot->port->closing))
		return -ESHUTDOWN;
	if (slot->qid >= dev->num_tx_queues)
		return -ERANGE;
	if (slot->qid < dev->real_num_tx_queues)
		return 0;
	return netif_set_real_num_tx_queues(dev, slot->qid + 1);
}

static int ppe_tc_queue_execution_prepare(struct qdx_tc_queue *slot,
		struct qdx_endpoint *endpoint, u32 tag,
		enum qdx_disposition disposition, struct qdx_tx_path **path, u64 *token)
{
	struct ppe_tc_port *port = slot->port;
	struct ppe_tc_execution *execution, *old, *next;
	struct qdx_tx_path *prepared;
	u64 next_token;
	int error = 0;

	if (disposition == QDX_NATIVE || disposition > QDX_REQUIRED)
		return -EINVAL;
	mutex_lock(&slot->cfg);
	if (port->closing || (slot->active_execution && !slot->active_execution->retired)) {
		error = -EBUSY;
		goto out;
	}
	/* The old native qid remains reserved while execution changes. Each old
	 * accepted path has to release its real resource before replacement.
	 */
	if (ppe_qdx_tx_queue_busy(port->priv, port->number, slot->qid)) {
		error = -EAGAIN;
		goto out;
	}
	spin_lock_bh(&port->priv->tc->lock);
	list_for_each_entry(old, &slot->executions, list)
		if (refcount_read(&old->refs) != 1) {
			error = -EAGAIN;
			break;
		}
	if (!error) {
		list_for_each_entry_safe(old, next, &slot->executions, list) {
			list_del(&old->list);
			kfree(old);
		}
		slot->active_execution = NULL;
	}
	spin_unlock_bh(&port->priv->tc->lock);
	if (error)
		goto out;
	execution = kzalloc(sizeof(*execution), GFP_KERNEL);
	if (!execution) {
		error = -ENOMEM;
		goto out;
	}
	next_token = qdx_ppe_next_tx_token(port->priv->qdx);
	if (!next_token) {
		error = -ESHUTDOWN;
		goto free;
	}
	execution->class = (struct qdx_tx_class) { .tag = tag, .token = next_token };
	prepared = qdx_tx_prepare(endpoint, port->dev, slot->qid, execution->class,
				 disposition);
	if (IS_ERR(prepared)) {
		error = PTR_ERR(prepared);
		goto free;
	}
	execution->slot = slot;
	execution->path = prepared;
	execution->disposition = disposition;
	execution->held = true;
	execution->base_path = true;
	refcount_set(&execution->refs, 1);
	qdx_tx_path_get(prepared); /* The caller owns the original prepare reference. */
	spin_lock_bh(&port->priv->tc->lock);
	list_add_tail(&execution->list, &slot->executions);
	slot->active_execution = execution;
	spin_unlock_bh(&port->priv->tc->lock);
	*path = prepared;
	*token = execution->class.token;
	goto out;
free:
	kfree(execution);
out:
	mutex_unlock(&slot->cfg);
	return error;
}

static int ppe_tc_queue_publish(struct qdx_tc_queue *slot, struct qdx_tx_path *path)
{
	struct ppe_tc_port *port = slot->port;
	int error = 0;

	mutex_lock(&slot->cfg);
	qdx_ppe_tx_gate(port->priv->qdx, true);
	spin_lock_bh(&port->priv->tc->lock);
	if (port->closing || !slot->active_execution || slot->active_execution->path != path ||
	    slot->active_execution->retired || slot->active_execution->stopped ||
	    slot->qid >= port->dev->real_num_tx_queues)
		error = -ESTALE;
	else {
		slot->active_execution->held = false;
		slot->exposed = true;
	}
	spin_unlock_bh(&port->priv->tc->lock);
	qdx_ppe_tx_gate(port->priv->qdx, false);
	mutex_unlock(&slot->cfg);
	return error;
}

static int ppe_tc_queue_hold(struct qdx_tc_queue *slot)
{
	struct ppe_tc_port *port = slot->port;
	struct ppe_tc_execution *execution;
	int error = 0;

	mutex_lock(&slot->cfg);
	qdx_ppe_tx_gate(port->priv->qdx, true);
	spin_lock_bh(&port->priv->tc->lock);
	execution = slot->active_execution;
	if (execution) {
		execution->held = true;
		execution->stopped = true;
	}
	spin_unlock_bh(&port->priv->tc->lock);
	if (execution && execution->base_path)
		error = qdx_tx_hold(execution->path);
	if (execution && !execution->base_path) {
		error = execution->stop_error;
		if (error && !ppe_qdx_tx_queue_busy(port->priv, port->number, slot->qid))
			error = 0;
	}
	if (execution) {
		spin_lock_bh(&port->priv->tc->lock);
		execution->stop_error = error;
		spin_unlock_bh(&port->priv->tc->lock);
	}
	qdx_ppe_tx_gate(port->priv->qdx, false);
	mutex_unlock(&slot->cfg);
	return error;
}

static int ppe_tc_queue_retire(struct qdx_tc_queue *slot)
{
	struct ppe_tc_port *port = slot->port;
	struct ppe_tc_execution *execution;
	struct qdx_tx_path *path = NULL;
	int error = 0, cleanup;
	bool pending;

	mutex_lock(&slot->cfg);
	qdx_ppe_tx_gate(port->priv->qdx, true);
	spin_lock_bh(&port->priv->tc->lock);
	execution = slot->active_execution;
	if (execution) {
		execution->held = true;
		execution->retired = true;
		execution->stopped = true;
		if (execution->base_path) {
			path = execution->path;
			execution->handback_pending =
				execution->disposition == QDX_OPTIONAL && !port->closing;
		}
	}
	spin_unlock_bh(&port->priv->tc->lock);
	if (path)
		error = qdx_tx_hold(path);
	else if (execution)
		error = execution->stop_error;
	spin_lock_bh(&port->priv->tc->lock);
	if (path) {
		execution->stop_error = error;
		execution->base_path = false;
	}
	spin_unlock_bh(&port->priv->tc->lock);
	if (path)
		qdx_tx_release(path);
	/* A retained native claim can outlive this execution. Retry its exact
	 * orphan scope here as well as at final slot release.
	 */
	cleanup = ppe_qdx_tx_queue_retry(port->priv, port->number, slot->qid);
	if (!error)
		error = cleanup;
	pending = ppe_qdx_tx_queue_busy(port->priv, port->number, slot->qid);
	if (execution) {
		spin_lock_bh(&port->priv->tc->lock);
		execution->handback_pending = execution->disposition == QDX_OPTIONAL &&
			!port->closing && pending;
		if (!cleanup && !pending) {
			execution->stop_error = 0;
			execution->native_return = execution->disposition == QDX_OPTIONAL &&
				!ppe_qdx_port_tx_held(port->priv, port->number);
			error = 0;
		}
		spin_unlock_bh(&port->priv->tc->lock);
	}
	/* The caller retains its resource-progress subscription until this exact
	 * scope is gone and the original execution's handback is recorded.
	 */
	if (!error && pending)
		error = -EINPROGRESS;
	qdx_ppe_tx_gate(port->priv->qdx, false);
	mutex_unlock(&slot->cfg);
	return error;
}

static int ppe_tc_queue_release(struct qdx_tc_queue *slot, struct Qdisc *current_root)
{
	struct ppe_tc_port *port = slot->port;
	struct ppe_tc_execution *execution, *next;
	unsigned int floor = PPE_TC_NORMAL_QUEUES, i;
	spinlock_t *native_lock = NULL;
	int error = -EINPROGRESS;

	ASSERT_RTNL();
	mutex_lock(&slot->cfg);
	if (slot->claimed || (slot->active_execution && !slot->active_execution->retired) ||
	    (slot->exposed && !slot->origin.class && current_root == slot->origin.root))
		goto out;
	error = ppe_qdx_tx_queue_retry(port->priv, port->number, slot->qid);
	if (error)
		goto out;
	error = -EINPROGRESS;
	if (ppe_qdx_tx_queue_busy(port->priv, port->number, slot->qid))
		goto out;
	synchronize_net();
	if (current_root && !(current_root->flags & TCQ_F_BUILTIN)) {
		native_lock = qdisc_lock(current_root);
		spin_lock_bh(native_lock);
		if (ppe_tc_queue_cached(slot, current_root))
			goto out;
	}
	spin_lock_bh(&port->priv->tc->lock);
	list_for_each_entry(execution, &slot->executions, list)
		if (execution->base_path || refcount_read(&execution->refs) != 1)
			goto unlock;
	port->slots[slot->qid] = NULL;
	list_for_each_entry_safe(execution, next, &slot->executions, list) {
		list_del(&execution->list);
		kfree(execution);
	}
	for (i = PPE_TC_NORMAL_QUEUES; i < PPE_TC_QUEUES; i++)
		if (port->slots[i])
			floor = i + 1;
	error = 0;
unlock:
	spin_unlock_bh(&port->priv->tc->lock);
out:
	if (native_lock)
		spin_unlock_bh(native_lock);
	mutex_unlock(&slot->cfg);
	if (error)
		return error;
	/* This call is outside TC cfg. A failed shrink keeps the larger prefix;
	 * it cannot restore the removed class or compact a still-retiring slot.
	 */
	if (port->dev->reg_state == NETREG_REGISTERED &&
	    floor < port->dev->real_num_tx_queues)
		netif_set_real_num_tx_queues(port->dev, floor);
	kfree(slot);
	ppe_tc_port_put(port);
	return 0;
}

static const struct qdx_tc_queue_ops ppe_tc_queue_ops = {
	.reserve = ppe_tc_queue_reserve,
	.claim = ppe_tc_queue_claim,
	.activate = ppe_tc_queue_activate,
	.execution_prepare = ppe_tc_queue_execution_prepare,
	.publish = ppe_tc_queue_publish,
	.hold = ppe_tc_queue_hold,
	.retire = ppe_tc_queue_retire,
	.release = ppe_tc_queue_release,
};

static int ppe_tc_block_call(enum tc_setup_type type, void *data, void *context)
{
	const struct qdx_binding_key key = { .role = QDX_BINDING_TC_PROVIDER };
	struct ppe_tc_block *block = context;
	struct qdx_binding *provider;
	const struct qdx_tc_ops *ops;
	struct flow_block_offload bind = {
		.command = FLOW_BLOCK_BIND, .binder_type = block->binder,
		.native_block = block->native,
	};
	int error;

	/* Removal reaches the same peer before any new-HW admission checks. */
	if (!block->port->binding)
		return -EOPNOTSUPP;
	provider = qdx_binding_lookup(&key);
	if (IS_ERR_OR_NULL(provider))
		return provider ? PTR_ERR(provider) : -EOPNOTSUPP;
	ops = qdx_binding_ops(provider);
	if (type != TC_SETUP_BLOCK && !block->unbinding) {
		/* Replay or ordinary requests can attach a later-loaded peer to this
		 * existing native callback. This creates no native callback/count.
		 */
		error = ops->setup_block(provider, block->port->binding, block->native,
					 block->binder, TC_SETUP_BLOCK, &bind);
		if (error)
			goto out;
	}
	error = ops->setup_block(provider, block->port->binding, block->native,
				 block->binder, type, data);
out:
	qdx_binding_put(provider);
	return error;
}

static void ppe_tc_block_free(void *context)
{
	struct ppe_tc_block *block = context;
	struct ppe_tc_port *port = block->port;
	struct flow_block_offload unbind = {
		.command = FLOW_BLOCK_UNBIND, .binder_type = block->binder,
		.native_block = block->native,
	};

	ppe_tc_block_call(TC_SETUP_BLOCK, &unbind, block);
	list_del(&block->list);
	ppe_tc_port_put(port);
	kfree(block);
}

static int ppe_tc_setup_block(struct dsa_switch *ds, int number,
			     struct flow_block_offload *offload)
{
	struct qca_ppe_priv *priv = ds->priv;
	struct ppe_tc_port *port = &priv->tc->ports[number];
	struct ppe_tc_block *block;
	struct flow_block_cb *callback;
	int error;

	ASSERT_RTNL();
	if (!offload->native_block ||
	    (offload->binder_type != FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS &&
	     offload->binder_type != FLOW_BLOCK_BINDER_TYPE_CLSACT_EGRESS &&
	     offload->binder_type != FLOW_BLOCK_BINDER_TYPE_UNSPEC))
		return -EOPNOTSUPP;
	offload->driver_block_list = &ppe_tc_block_callbacks;
	list_for_each_entry(block, &port->blocks, list)
		if (block->native == offload->native_block &&
		    block->binder == offload->binder_type)
			goto found;
	block = NULL;
found:
	switch (offload->command) {
	case FLOW_BLOCK_BIND:
		if (block)
			return -EBUSY;
		if (port->closing)
			return -ESHUTDOWN;
		block = kzalloc(sizeof(*block), GFP_KERNEL);
		if (!block)
			return -ENOMEM;
		block->port = port;
		block->native = offload->native_block;
		block->binder = offload->binder_type;
		callback = flow_block_cb_alloc(ppe_tc_block_call, block, block,
					      ppe_tc_block_free);
		if (IS_ERR(callback)) {
			kfree(block);
			return PTR_ERR(callback);
		}
		block->callback = callback;
		ppe_tc_port_get(port);
		list_add_tail(&block->list, &port->blocks);
		error = ppe_tc_block_call(TC_SETUP_BLOCK, offload, block);
		if (error && error != -EOPNOTSUPP) {
			flow_block_cb_free(callback);
			return error;
		}
		flow_block_cb_add(callback, offload);
		list_add_tail(&callback->driver_list, &ppe_tc_block_callbacks);
		return 0;
	case FLOW_BLOCK_UNBIND:
		if (!block)
			return -ENOENT;
		block->unbinding = true;
		flow_block_cb_remove(block->callback, offload);
		list_del(&block->callback->driver_list);
		return 0;
	default:
		return -EOPNOTSUPP;
	}
}

static int ppe_tc_replay(struct qdx_binding *binding, struct tcf_block *native,
		       enum flow_block_binder_type binder, bool add,
		       struct netlink_ext_ack *extack)
{
	struct ppe_tc_port *port = qdx_binding_owner(binding);
	struct flow_block_offload offer = {
		.command = FLOW_BLOCK_BIND, .binder_type = binder,
		.native_block = native,
	};
	struct ppe_tc_block *block;
	int error;

	ASSERT_RTNL();
	list_for_each_entry(block, &port->blocks, list) {
		if (block->native != native || block->binder != binder || block->unbinding)
			continue;
		error = ppe_tc_block_call(TC_SETUP_BLOCK, &offer, block);
		if (error)
			return error;
#ifdef CONFIG_NET_CLS
		return tcf_block_replay_bound(native, ppe_tc_block_call,
					     block, add, extack);
#else
		return -EOPNOTSUPP;
#endif
	}
	return -ENOENT;
}

static int ppe_tc_peak_prepare(struct qdx_binding *binding,
			       const struct qdx_tc_peak_params *params,
			       struct qdx_tc_peak **result)
{
	struct ppe_tc_port *port = qdx_binding_owner(binding);
	int error;

	ASSERT_RTNL();
	*result = NULL;
	if (port->closing || !dsa_is_user_port(&port->priv->ds, port->number) ||
	    !ppe_tc_port_get(port))
		return -ESHUTDOWN;
	error = ppe_qdx_peak_prepare(port->priv, port->number, params, result);
	if (*result)
		(*result)->owner = port;
	else
		ppe_tc_port_put(port);
	return error;
}

static int ppe_tc_peak_publish(struct qdx_tc_peak *peak)
{
	ASSERT_RTNL();
	if (READ_ONCE(peak->owner->closing))
		return -ESHUTDOWN;
	return ppe_qdx_peak_publish(peak);
}

static int ppe_tc_peak_release(struct qdx_tc_peak *peak)
{
	struct ppe_tc_port *port = peak->owner;
	int error;

	ASSERT_RTNL();
	/* Closing/terminal stops creation, not restoration of this exact owner. */
	error = ppe_qdx_peak_release(peak);
	if (!error)
		ppe_tc_port_put(port);
	return error;
}

static const struct qdx_tc_port_ops ppe_tc_port_ops = {
	.normal_direct_count = PPE_TC_NORMAL_QUEUES,
	.queues = &ppe_tc_queue_ops,
	.replay = ppe_tc_replay,
	.peak_prepare = ppe_tc_peak_prepare,
	.peak_publish = ppe_tc_peak_publish,
	.peak_release = ppe_tc_peak_release,
};

static int ppe_tc_setup(struct dsa_switch *ds, int number,
		       enum tc_setup_type type, void *data)
{
	const struct qdx_binding_key key = { .role = QDX_BINDING_TC_PROVIDER };
	struct qca_ppe_priv *priv = ds->priv;
	struct ppe_tc_port *port = &priv->tc->ports[number];
	struct tc_htb_qopt_offload *htb = type == TC_SETUP_QDISC_HTB ? data : NULL;
	struct ppe_tc_root *root = NULL, *entry, *created = NULL;
	struct qdx_binding *provider;
	const struct qdx_tc_ops *ops;
	int error;

	ASSERT_RTNL();
	if (!port->binding)
		return -EOPNOTSUPP;
	if (htb)
		list_for_each_entry(entry, &port->roots, list)
			if (entry->identity == htb->owner.sch) {
				root = entry;
				break;
			}
	if (root) {
		provider = root->provider;
		if (!qdx_binding_hold(provider))
			return -ESHUTDOWN;
	} else {
		provider = qdx_binding_lookup(&key);
		if (IS_ERR_OR_NULL(provider))
			return provider ? PTR_ERR(provider) : -EOPNOTSUPP;
	}
	if (htb && htb->command == TC_HTB_CREATE) {
		if (root) {
			error = -EEXIST;
			goto out;
		}
		created = kzalloc(sizeof(*created), GFP_KERNEL);
		if (!created) {
			error = -ENOMEM;
			goto out;
		}
		created->identity = htb->owner.sch;
		created->provider = provider;
	}
	ops = qdx_binding_ops(provider);
	error = ops->setup_tc(provider, port->binding, type, data);
	if (created && !error) {
		spin_lock_bh(&priv->tc->lock);
		list_add_tail(&created->list, &port->roots);
		spin_unlock_bh(&priv->tc->lock);
		return 0; /* This actual successful root retains the provider reference. */
	}
	kfree(created);
	if (root && htb->command == TC_HTB_DESTROY) {
		/* Even a failed hardware destroy cannot retain a dead native root. */
		spin_lock_bh(&priv->tc->lock);
		list_del(&root->list);
		spin_unlock_bh(&priv->tc->lock);
		synchronize_net();
		qdx_binding_put(root->provider);
		kfree(root);
	}
out:
	qdx_binding_put(provider);
	return error;
}

static u16 ppe_tc_select_queue(struct dsa_switch *ds, int number,
			      struct sk_buff *skb, struct net_device *sb_dev)
{
	struct qca_ppe_priv *priv = ds->priv;
	struct ppe_tc_port *port = &priv->tc->ports[number];
	struct qdx_binding *provider = NULL;
	const struct qdx_tc_ops *ops;
	struct ppe_tc_root *entry;
	struct Qdisc *root;
	u16 queue;
	bool selected = false;

	rcu_read_lock_bh();
	root = rcu_dereference_bh(port->dev->qdisc);
	spin_lock_bh(&priv->tc->lock);
	list_for_each_entry(entry, &port->roots, list)
		if (entry->identity == root && qdx_binding_hold(entry->provider)) {
			provider = entry->provider;
			break;
		}
	spin_unlock_bh(&priv->tc->lock);
	if (provider) {
		ops = qdx_binding_ops(provider);
		selected = ops->select_queue(provider, port->dev, skb, &queue);
		qdx_binding_put(provider);
	}
	rcu_read_unlock_bh();
	if (selected && queue >= PPE_TC_NORMAL_QUEUES &&
	    queue < READ_ONCE(port->dev->real_num_tx_queues))
		return queue;
	queue = netdev_pick_tx(port->dev, skb, sb_dev);
	return queue % PPE_TC_NORMAL_QUEUES;
}

static int ppe_tc_oob_tag(struct dsa_switch *ds, int number,
			const struct sk_buff *skb, struct dsa_oob_tag_info *tag)
{
	struct qca_ppe_priv *priv = ds->priv;
	struct ppe_tc_port *port = &priv->tc->ports[number];
	struct ppe_tc_execution *execution;
	struct qdx_tc_queue *slot;
	u16 queue = skb_get_queue_mapping(skb);
	int error = 0;

	if (queue >= PPE_TC_QUEUES)
		return -ERANGE;
	spin_lock_bh(&priv->tc->lock);
	slot = port->slots[queue];
	execution = slot ? slot->active_execution : NULL;
	if (execution) {
		tag->token = execution->class.token;
		tag->disposition = execution->disposition == QDX_REQUIRED ?
			DSA_OOB_TX_REQUIRED : DSA_OOB_TX_OPTIONAL;
	} else if (queue >= PPE_TC_NORMAL_QUEUES || port->closing) {
		error = -ESTALE;
	}
	spin_unlock_bh(&priv->tc->lock);
	return error;
}

static void ppe_qdx_resolve_tx(void *context, unsigned int number, u16 queue,
			       u64 token, enum qdx_disposition disposition,
			       struct qdx_tx_selection *selection)
{
	struct qca_ppe_priv *priv = context;
	struct ppe_tc_execution *execution;
	struct qdx_tc_queue *slot;
	struct ppe_tc_port *port;

	*selection = (struct qdx_tx_selection) { .status = QDX_TX_REFUSED };
	if (!priv->tc || number >= priv->data->num_ports || queue >= PPE_TC_QUEUES)
		return;
	port = &priv->tc->ports[number];
	spin_lock_bh(&priv->tc->lock);
	slot = port->slots[queue];
	if (!token) {
		if (disposition != QDX_NATIVE || queue >= PPE_TC_NORMAL_QUEUES ||
		    (slot && slot->active_execution))
			goto out;
		selection->status = ppe_qdx_port_tx_held(priv, number) ?
			QDX_TX_HELD : QDX_TX_NATIVE;
		goto out;
	}
	if (!slot)
		goto out;
	list_for_each_entry(execution, &slot->executions, list) {
		if (execution->class.token != token)
			continue;
		if (execution->disposition != disposition)
			break;
		selection->class = execution->class;
		selection->disposition = disposition;
		if (execution->retired) {
			selection->status = QDX_TX_RETIRED;
			if (disposition == QDX_OPTIONAL && slot->active_execution == execution &&
			    !port->closing) {
				if (execution->native_return && !ppe_qdx_port_tx_held(priv, number))
					selection->status = QDX_TX_NATIVE;
				else if (execution->handback_pending)
					selection->status = QDX_TX_HELD;
			}
			break;
		}
		if (!try_module_get(THIS_MODULE))
			break;
		if (!ppe_tc_execution_get(execution)) {
			module_put(THIS_MODULE);
			break;
		}
		selection->owner = (struct qdx_owner) {
			.module = THIS_MODULE, .object = execution,
			.get = ppe_tc_execution_get, .put = ppe_tc_execution_put,
		};
		selection->path = execution->path;
		selection->status = execution->held || ppe_qdx_port_tx_held(priv, number) ?
			QDX_TX_HELD : QDX_TX_READY;
		break;
	}
out:
	spin_unlock_bh(&priv->tc->lock);
}

static int ppe_tc_netdev_event(struct notifier_block *notifier,
			       unsigned long event, void *data)
{
	struct qca_ppe_tc *tc = container_of(notifier, struct qca_ppe_tc, netdev);
	struct qca_ppe_priv *priv = tc->ports[0].priv;
	struct net_device *dev = netdev_notifier_info_to_dev(data);
	struct qdx_binding_scan scan;
	struct qdx_binding_use *use;
	struct ppe_tc_port *port;
	struct qdx_binding *binding;
	struct dsa_port *dp;
	struct ppe_tc_root *root, *next;
	LIST_HEAD(roots);
	unsigned int number;

	if (READ_ONCE(tc->native_gone) || !priv->ds.dst ||
	    (event != NETDEV_REGISTER && event != NETDEV_UNREGISTER))
		return NOTIFY_DONE;
	for (number = 0; number < priv->data->num_ports; number++) {
		dp = dsa_to_port(&priv->ds, number);
		if (dsa_is_user_port(&priv->ds, number) && dp->user == dev)
			break;
	}
	if (number == priv->data->num_ports)
		return NOTIFY_DONE;
	port = &tc->ports[number];
	if (event == NETDEV_REGISTER) {
		const struct qdx_binding_key key = {
			.dev = dev, .role = QDX_BINDING_TC_PORT,
		};
		const struct qdx_owner owner = {
			.module = THIS_MODULE, .object = port,
			.get = ppe_tc_port_get, .put = ppe_tc_port_put,
		};

		if (port->binding)
			return NOTIFY_DONE;
		port->dev = dev;
		WRITE_ONCE(port->closing, false);
		binding = qdx_binding_publish(&key, &owner, &ppe_tc_port_ops);
		if (IS_ERR(binding)) {
			/* No reachable QDX keeps ordinary native networking unchanged. */
			if (PTR_ERR(binding) == -EOPNOTSUPP)
				return NOTIFY_DONE;
			return notifier_from_errno(PTR_ERR(binding));
		}
		port->binding = binding;
		qdx_binding_available(binding);
		return NOTIFY_OK;
	}
	spin_lock_bh(&tc->lock);
	port->closing = true;
	list_splice_init(&port->roots, &roots);
	spin_unlock_bh(&tc->lock);
	synchronize_net();
	list_for_each_entry_safe(root, next, &roots, list) {
		list_del(&root->list);
		qdx_binding_put(root->provider);
		kfree(root);
	}
	binding = port->binding;
	if (!binding)
		return NOTIFY_DONE;
	/* Native dev_shutdown already destroyed qdiscs and their real blocks.
	 * Do not wait here for a retiring consumer's work which needs RTNL.
	 * Its retained key keeps this exact netdevice until native todo drain.
	 */
	qdx_binding_invalidate(binding);
	qdx_binding_scan_start(binding, &scan);
	while ((use = qdx_binding_user_get(binding, &scan))) {
		if (use->invalidate)
			use->invalidate(use->consumer.object, true);
		qdx_binding_user_put(use);
	}
	port->binding = NULL;
	qdx_binding_withdraw(binding);
	return NOTIFY_OK;
}

static int ppe_tc_init(struct qca_ppe_priv *priv)
{
	struct qca_ppe_tc *tc;
	unsigned int number;
	int error;

	tc = devm_kzalloc(priv->ds.dev, sizeof(*tc), GFP_KERNEL);
	if (!tc)
		return -ENOMEM;
	priv->tc = tc;
	spin_lock_init(&tc->lock);
	for (number = 0; number < priv->data->num_ports; number++) {
		struct ppe_tc_port *port = &tc->ports[number];

		port->priv = priv;
		port->number = number;
		refcount_set(&port->refs, 1);
		init_waitqueue_head(&port->drained);
		INIT_LIST_HEAD(&port->blocks);
		INIT_LIST_HEAD(&port->roots);
	}
	tc->ops = qca_ppe_ops;
	tc->ops.port_setup_tc = ppe_tc_setup;
	tc->ops.port_setup_tc_block = ppe_tc_setup_block;
	tc->ops.port_select_queue = ppe_tc_select_queue;
	tc->ops.port_oob_tx_tag = ppe_tc_oob_tag;
	priv->ds.ops = &tc->ops;
	priv->ds.num_tx_queues = PPE_TC_QUEUES;
	priv->ds.initial_real_num_tx_queues = PPE_TC_NORMAL_QUEUES;
	tc->netdev.notifier_call = ppe_tc_netdev_event;
	error = register_netdevice_notifier(&tc->netdev);
	if (error)
		return error;
	tc->notifier_registered = true;
	return 0;
}

static void ppe_tc_exit(struct qca_ppe_priv *priv)
{
	struct qca_ppe_tc *tc = priv->tc;
	unsigned int number;

	if (!tc)
		return;
	WRITE_ONCE(tc->native_gone, true);
	if (tc->notifier_registered) {
		unregister_netdevice_notifier(&tc->netdev);
		tc->notifier_registered = false;
	}
	/* Called after native DSA destruction, with no RTNL or peer cfg held. */
	for (number = 0; number < priv->data->num_ports; number++) {
		struct ppe_tc_port *port = &tc->ports[number];

		wait_event(port->drained, refcount_read(&port->refs) == 1);
		spin_lock_bh(&tc->lock);
		spin_unlock_bh(&tc->lock);
		WARN_ON_ONCE(!list_empty(&port->blocks));
		WARN_ON_ONCE(!list_empty(&port->roots));
	}
}

static void ppe_qdx_lock(void *context, unsigned int port)
{
	struct qca_ppe_priv *priv = context;

	mutex_lock(&priv->port_config[port].lock);
}

static void ppe_qdx_unlock(void *context, unsigned int port)
{
	struct qca_ppe_priv *priv = context;

	mutex_unlock(&priv->port_config[port].lock);
}

static int ppe_qdx_snapshot(void *context, unsigned int port,
			    struct qdx_port_state *state)
{
	struct qca_ppe_priv *priv = context;
	struct qca_ppe_port_config *pc = &priv->port_config[port];
	struct dsa_port *dp = dsa_to_port(&priv->ds, port);

	if (!dsa_is_user_port(&priv->ds, port) || !dp->user)
		return -ENODEV;
	state->netdev = dp->user;
	state->mtu = pc->mtu;
	state->admin = pc->admin;
	state->link_state = pc->link ? 1 : 0;
	ether_addr_copy(state->mac, dp->user->dev_addr);
	return 0;
}

/* Firmware commands may change these native-owned port fields. */
static int ppe_qdx_reapply(void *context, unsigned int port)
{
	struct qca_ppe_priv *priv = context;
	struct qca_ppe_port_config *pc = &priv->port_config[port];
	int ret;

	ret = ppe_port_mtu_apply(priv, port, pc->mtu);
	if (ret)
		return ret;
	ret = ppe_port_vsi_set(priv, port, pc->vsi);
	if (ret)
		return ret;
	ret = ppe_port_cnt_enable(priv, port);
	if (ret)
		return ret;
	ret = ppe_qdx_resources_reapply(priv, port);
	ppe_port_bridge_txmac_set(priv, port, !ret && pc->admin && pc->link);
	return ret;
}

static int ppe_qdx_restore(void *context)
{
	struct qca_ppe_priv *priv = context;
	struct dsa_port *dp;
	int i, ret;

	ret = ppe_qdx_resources_restore(priv);
	if (ret)
		return ret;
	mutex_lock(&priv->resource_lock);
	/* CPU queue 0 and its current native scheduler, without FDB/VLAN setup. */
	regmap_write(priv->regmap, PPE_QM_UCAST_MAP(QM_VP_PORT_OFFSET), 0);
	for (i = 0; i < 16; i++) {
		regmap_write(priv->regmap, PPE_QM_UCAST_PRI_MAP(i), 0);
		regmap_write(priv->regmap, PPE_QM_UCAST_PRI_MAP(15 * 16 + i), 0);
	}
	regmap_write(priv->regmap, PPE_TM_RING_Q_MAP(0), 0xf);
	for (i = 1; i < 10; i++)
		regmap_write(priv->regmap, PPE_TM_RING_Q_MAP(0) + i * 4, 0);
	regmap_write(priv->regmap, PPE_TM_L0_FLOW_MAP(0),
		FIELD_PREP(PPE_L0_C_DRR_WT, 1) | FIELD_PREP(PPE_L0_E_DRR_WT, 1));
	regmap_write(priv->regmap, PPE_TM_L0_C_SP(0), 0);
	regmap_write(priv->regmap, PPE_TM_L0_E_SP(0), 0);
	regmap_write(priv->regmap, PPE_TM_L0_PORT_MAP(0), 0);
	regmap_write(priv->regmap, PPE_TM_L1_FLOW_MAP(0),
		FIELD_PREP(PPE_L1_C_DRR_WT, 1) | FIELD_PREP(PPE_L1_E_DRR_WT, 1));
	regmap_write(priv->regmap, PPE_TM_L1_C_SP(0), 0);
	regmap_write(priv->regmap, PPE_TM_L1_E_SP(0), 0);
	regmap_write(priv->regmap, PPE_TM_L1_PORT_MAP(0), 0);
	mutex_unlock(&priv->resource_lock);
	ppe_port_bridge_txmac_set(priv, QCA_PPE_CPU_PORT, true);

	dsa_switch_for_each_user_port(dp, &priv->ds) {
		struct qca_ppe_port_config *pc = &priv->port_config[dp->index];

		ppe_port_bridge_txmac_set(priv, dp->index, false);
		ppe_pcs_set_mux_hppe(priv, dp->index, pc->mode, pc->interface);
		if (pc->reset_pending) {
			ret = ppe_mac_config_apply(priv, dp->index, pc->mode, pc->interface);
			if (ret)
				return ret;
			pc->reset_pending = false;
		}
		if (pc->link && pc->admin) {
			ret = ppe_mac_link_apply(priv, dp->index, pc->mode, pc->interface,
					  pc->speed, pc->duplex, pc->tx_pause, pc->rx_pause);
			if (ret)
				return ret;
		}
		ret = ppe_qdx_reapply(priv, dp->index);
		if (ret)
			return ret;
	}
	return 0;
}

/* Shared by acquisition rollback and final release. The caller owns RTNL
 * and resource_lock; a failed clear never makes the index available again.
 */
static int ppe_qdx_vsi_clear(struct qca_ppe_priv *priv, u32 vsi)
{
	const u32 zero[2] = {};
	u32 row[2];
	int error;

	ASSERT_RTNL();
	lockdep_assert_held(&priv->resource_lock);
	error = regmap_bulk_write(priv->regmap, PPE_VSI_TBL(vsi), zero, ARRAY_SIZE(zero));
	if (!error)
		error = regmap_bulk_read(priv->regmap, PPE_VSI_TBL(vsi), row, ARRAY_SIZE(row));
	if (!error && (row[0] || row[1]))
		error = -EIO;
	if (!error)
		clear_bit(vsi, priv->vsi_bitmap);
	return error;
}

static int ppe_qdx_vsi_alloc(void *context, unsigned int port, u32 *wire_vsi)
{
	struct qca_ppe_priv *priv = context;
	u32 row[2], actual[2];
	unsigned int vsi;
	int error, undo;

	ASSERT_RTNL();
	if (port >= priv->data->num_ports || !dsa_is_user_port(&priv->ds, port))
		return -EINVAL;
	mutex_lock(&priv->resource_lock);
	if (priv->resources_terminal) {
		error = -ESHUTDOWN;
		goto out;
	}
	/* All native bridge/VLAN bitmap users are serialized by RTNL too. */
	vsi = find_next_zero_bit(priv->vsi_bitmap, PPE_VSI_MAX, 1);
	if (vsi == PPE_VSI_MAX) {
		error = -ENOSPC;
		goto out;
	}
	set_bit(vsi, priv->vsi_bitmap);
	row[0] = FIELD_PREP(PPE_VSI_TBL_MEMBER, BIT(QCA_PPE_CPU_PORT) | BIT(port)) |
		 FIELD_PREP(PPE_VSI_TBL_UUC, BIT(QCA_PPE_CPU_PORT)) |
		 FIELD_PREP(PPE_VSI_TBL_UMC, BIT(QCA_PPE_CPU_PORT)) |
		 FIELD_PREP(PPE_VSI_TBL_BC, BIT(QCA_PPE_CPU_PORT));
	row[1] = PPE_VSI_TBL_NEW_ADDR_LRN_EN | PPE_VSI_TBL_STA_MOVE_LRN_EN;
	error = regmap_bulk_write(priv->regmap, PPE_VSI_TBL(vsi), row, ARRAY_SIZE(row));
	if (!error)
		error = regmap_bulk_read(priv->regmap, PPE_VSI_TBL(vsi), actual, ARRAY_SIZE(actual));
	if (!error && memcmp(row, actual, sizeof(row)))
		error = -EIO;
	if (error) {
		undo = ppe_qdx_vsi_clear(priv, vsi);
		if (undo)
			dev_err(priv->ds.dev, "VSI %u allocation rollback failed: %d; reserved\n",
				vsi, undo);
		goto out;
	}
	*wire_vsi = vsi;
out:
	mutex_unlock(&priv->resource_lock);
	return error;
}

static int ppe_qdx_vsi_release(void *context, u32 vsi)
{
	struct qca_ppe_priv *priv = context;
	int error;

	ASSERT_RTNL();
	mutex_lock(&priv->resource_lock);
	if (!vsi || vsi >= PPE_VSI_MAX || !test_bit(vsi, priv->vsi_bitmap))
		error = -EUCLEAN;
	else
		error = ppe_qdx_vsi_clear(priv, vsi);
	mutex_unlock(&priv->resource_lock);
	return error;
}

static const struct qdx_ppe_ops ppe_qdx_ops = {
	.lock = ppe_qdx_lock,
	.unlock = ppe_qdx_unlock,
	.snapshot = ppe_qdx_snapshot,
	.reapply = ppe_qdx_reapply,
	.restore = ppe_qdx_restore,
	.rx_acquire = ppe_qdx_rx_acquire,
	.rx_hold = ppe_qdx_rx_hold,
	.rx_release = ppe_qdx_rx_release,
	.tx_prepare = ppe_qdx_tx_prepare,
	.tx_hold = ppe_qdx_tx_hold,
	.tx_release = ppe_qdx_tx_release,
	.resolve_tx = ppe_qdx_resolve_tx,
	.vsi_alloc = ppe_qdx_vsi_alloc,
	.vsi_release = ppe_qdx_vsi_release,
};

static const struct regmap_config ppe_regmap_cfg = {
	.reg_bits = 32,
	.reg_stride = 4,
	.val_bits = 32,
};

static int qca_ppe_probe(struct platform_device *pdev)
{
	const struct ppe_data *data;
	struct device_node *ports;
	struct qca_ppe_priv *priv;
	struct reset_control *rst;
	struct dsa_switch *ds;
	void __iomem *base;
	int ret, i;

	data = of_device_get_match_data(&pdev->dev);
	if (!data)
		return -ENODEV;

	ports = of_get_child_by_name(pdev->dev.of_node, "ports");
	if (!ports)
		return -ENODEV;
	of_node_put(ports);

	priv = devm_kzalloc(&pdev->dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	priv->data = data;
	ppe_qdx_resources_init(priv);
	for (i = 0; i < QCA_PPE_MAX_PORTS; i++) {
		mutex_init(&priv->port_config[i].lock);
		priv->port_config[i].mtu = ETH_DATA_LEN;
		priv->port_config[i].vsi = PPE_VSI_INVALID;
	}

	priv->num_clks = devm_clk_bulk_get_all(&pdev->dev, &priv->clks);
	if (priv->num_clks < 0)
		return priv->num_clks;

	ret = clk_bulk_prepare_enable(priv->num_clks, priv->clks);
	if (ret)
		return ret;

	base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(base))
		return dev_err_probe(&pdev->dev, PTR_ERR(base), "failed to ioremap resource");

	priv->regmap = devm_regmap_init_mmio(&pdev->dev, base, &ppe_regmap_cfg);
	if (IS_ERR(priv->regmap))
		return dev_err_probe(&pdev->dev, PTR_ERR(priv->regmap), "failed to init regmap");

	rst = devm_reset_control_get(&pdev->dev, "ppe_rst");
	if (IS_ERR(rst)) {
		ret = PTR_ERR(rst);
		goto err_clk;
	}
	reset_control_assert(rst);
	msleep(100);
	reset_control_deassert(rst);
	msleep(100);

	spin_lock_init(&priv->fdb_lock);
	spin_lock_init(&priv->mib_lock);
	INIT_DELAYED_WORK(&priv->mib_work, ppe_mib_work);

	priv->port_mib = devm_kcalloc(&pdev->dev,
				      data->num_ports * ARRAY_SIZE(qca_ppe_mib),
				      sizeof(*priv->port_mib), GFP_KERNEL);
	if (!priv->port_mib) {
		ret = -ENOMEM;
		goto err_clk;
	}

	ds = &priv->ds;
	ds->dev = &pdev->dev;
	ds->num_ports = data->num_ports;
	ds->ops = &qca_ppe_ops;
	ds->priv = priv;
	ds->phylink_mac_ops = &qca_ppe_phylink_mac_ops;

	for (i = 1; i < data->num_ports; i++) {
		char name[32];

		snprintf(name, sizeof(name), "port%d_rx", i);
		priv->port_rx_clk[i] = devm_clk_get_optional(&pdev->dev, name);
		if (IS_ERR(priv->port_rx_clk[i])) {
			ret = PTR_ERR(priv->port_rx_clk[i]);
			goto err_clk;
		}

		snprintf(name, sizeof(name), "port%d_tx", i);
		priv->port_tx_clk[i] = devm_clk_get_optional(&pdev->dev, name);
		if (IS_ERR(priv->port_tx_clk[i])) {
			ret = PTR_ERR(priv->port_tx_clk[i]);
			goto err_clk;
		}

		snprintf(name, sizeof(name), "nss_port%d_rst", i);
		priv->port_rst[i] = devm_reset_control_get_optional_exclusive(
						&pdev->dev, name);
		if (IS_ERR(priv->port_rst[i])) {
			ret = PTR_ERR(priv->port_rst[i]);
			goto err_clk;
		}
	}

	ppe_vsi_init(priv);

	ppe_scheduler_init(priv);

	ppe_mac_hw_init(priv);
	ppe_ctrlpkt_init(priv);


	if (data->type == PPE_TYPE_IPQ6018) {
		ret = ppe_ipq6018_mux_setup(priv);
		if (ret)
			goto err_clk;
	}

	if (data->type == PPE_TYPE_IPQ8074) {
		ret = ppe_tc_init(priv);
		if (ret)
			goto err_tc;
	}
	ret = dsa_register_switch(ds);
	if (ret)
		goto err_tc;

	platform_set_drvdata(pdev, priv);
	if (data->type == PPE_TYPE_IPQ8074) {
		struct dsa_port *dp;
		struct qdx_ppe_info info = {
			.dev = &pdev->dev,
			.ops = &ppe_qdx_ops,
			.context = priv,
		};

		dsa_switch_for_each_user_port(dp, ds) {
			info.ports |= BIT(dp->index);
			info.conduit = dsa_port_to_conduit(dp);
		}
		/* Lifecycle preparation takes RTNL before using this backpointer. */
		rtnl_lock();
		priv->qdx = qdx_ppe_attach(&info);
		if (IS_ERR(priv->qdx)) {
			ret = PTR_ERR(priv->qdx);
			priv->qdx = NULL;
			rtnl_unlock();
			dsa_unregister_switch(ds);
			goto err_tc;
		}
		rtnl_unlock();
	}
	return 0;

err_tc:
	ppe_tc_exit(priv);
err_clk:
	clk_bulk_disable_unprepare(priv->num_clks, priv->clks);
	return ret;
}

static void qca_ppe_remove(struct platform_device *pdev)
{
	struct qca_ppe_priv *priv = platform_get_drvdata(pdev);

	qdx_ppe_detach(priv->qdx);
	priv->qdx = NULL;
	dsa_unregister_switch(&priv->ds);
	ppe_tc_exit(priv);
	clk_bulk_disable_unprepare(priv->num_clks, priv->clks);
}

static const struct ppe_data ipq6018_ppe_data = {
	.type			= PPE_TYPE_IPQ6018,
	.num_ports		= 7,
	.num_gmacs		= 5,
	.mru_mtu_ctrl_stride	= 0x10,
	.loopback_port		= 6,
	.bm_phy_end		= 12,
	.bm_internal_start	= 13,
	.bm_group_buf		= 1024,
	.bm_ceiling		= 216,
	.qm_total_buf		= 1506,
	.qm_ceiling		= 216,
	.qm_green_max		= 144,
	.psch_tdm		= &cppe_psch_tdm_data,
	.bm_tdm			= &cppe_bm_tdm_data,
};

static const struct ppe_data ipq8074_ppe_data = {
	.type			= PPE_TYPE_IPQ8074,
	.num_ports		= 8,
	.num_gmacs		= 6,
	.mru_mtu_ctrl_stride	= 0x8,
	.loopback_port		= 7,
	.bm_phy_end		= 13,
	.bm_internal_start	= 14,
	.bm_group_buf		= 1400,
	.bm_ceiling		= 250,
	.qm_total_buf		= 2000,
	.qm_ceiling		= 400,
	.qm_green_max		= 250,
	.psch_tdm		= &hppe_psch_tdm_data,
	.bm_tdm			= &hppe_bm_tdm_data,
};

static const struct of_device_id qca_ppe_of_match[] = {
	{ .compatible = "qualcomm,ipq6018-ppe", .data = &ipq6018_ppe_data },
	{ .compatible = "qualcomm,ipq8074-ppe", .data = &ipq8074_ppe_data },
	{},
};
MODULE_DEVICE_TABLE(of, qca_ppe_of_match);

static struct platform_driver qca_ppe_driver = {
	.driver = {
		.name = "qca-ppe",
		.of_match_table = qca_ppe_of_match,
	},
	.probe = qca_ppe_probe,
	.remove = qca_ppe_remove,
};
module_platform_driver(qca_ppe_driver);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Driver for Qualcomm PPE switches");
