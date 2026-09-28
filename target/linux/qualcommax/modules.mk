# SPDX-License-Identifier: GPL-2.0-only

define KernelPackage/qdx-drv
  SUBMENU:=$(NETWORK_DEVICES_MENU)
  TITLE:=IPQ8074 NSS execution driver
  DEPENDS:=@TARGET_qualcommax_ipq807x +qdx-nss-firmware
  KCONFIG:=CONFIG_QDX
  FILES:=$(LINUX_DIR)/drivers/net/ethernet/qualcomm/qdx-drv/qdx-drv.ko
  AUTOLOAD:=$(call AutoProbe,qdx-drv)
endef

define KernelPackage/qdx-drv/description
  Dual-core NSS 11.4 firmware, communication and wired packet transport.
  Linux and the native EDMA/PPE drivers retain network configuration.
endef

$(eval $(call KernelPackage,qdx-drv))

define KernelPackage/qdx-flow
  SUBMENU:=$(NETWORK_DEVICES_MENU)
  TITLE:=Native routed flowtable delegation
  DEPENDS:=@TARGET_qualcommax_ipq807x +kmod-qdx-drv +kmod-nf-flow
  KCONFIG:=CONFIG_QDX_FLOW
  FILES:=$(LINUX_DIR)/drivers/net/ethernet/qualcomm/qdx-flow/qdx-flow.ko
  AUTOLOAD:=$(call AutoProbe,qdx-flow)
endef

$(eval $(call KernelPackage,qdx-flow))

define KernelPackage/qdx-tc
  SUBMENU:=$(NETWORK_DEVICES_MENU)
  TITLE:=Native TC device-stage delegation
  DEPENDS:=@TARGET_qualcommax_ipq807x +kmod-qdx-drv +kmod-sched-core +kmod-ifb
  KCONFIG:=CONFIG_QDX_TC
  FILES:=$(LINUX_DIR)/drivers/net/ethernet/qualcomm/qdx-tc/qdx-tc.ko
  AUTOLOAD:=$(call AutoProbe,qdx-tc)
endef

$(eval $(call KernelPackage,qdx-tc))

define KernelPackage/qdx-bridge
  SUBMENU:=$(NETWORK_DEVICES_MENU)
  TITLE:=Native bridge path integration
  DEPENDS:=@TARGET_qualcommax_ipq807x +kmod-qdx-drv
  KCONFIG:=CONFIG_QDX_BRIDGE
  FILES:=$(LINUX_DIR)/drivers/net/ethernet/qualcomm/qdx-bridge/qdx-bridge.ko
  AUTOLOAD:=$(call AutoProbe,qdx-bridge)
endef

$(eval $(call KernelPackage,qdx-bridge))

define KernelPackage/qdx-vlan
  SUBMENU:=$(NETWORK_DEVICES_MENU)
  TITLE:=Native VLAN path integration
  DEPENDS:=@TARGET_qualcommax_ipq807x +kmod-qdx-drv
  KCONFIG:=CONFIG_QDX_VLAN
  FILES:=$(LINUX_DIR)/drivers/net/ethernet/qualcomm/qdx-vlan/qdx-vlan.ko
  AUTOLOAD:=$(call AutoProbe,qdx-vlan)
endef

$(eval $(call KernelPackage,qdx-vlan))

define KernelPackage/qdx-tunnel
  SUBMENU:=$(NETWORK_DEVICES_MENU)
  TITLE:=Native PPPoE session delegation
  DEPENDS:=@TARGET_qualcommax_ipq807x +kmod-qdx-drv +kmod-pppoe
  KCONFIG:=CONFIG_QDX_TUNNEL
  FILES:=$(LINUX_DIR)/drivers/net/ethernet/qualcomm/qdx-tunnel/qdx-tunnel.ko
  AUTOLOAD:=$(call AutoProbe,qdx-tunnel)
endef

$(eval $(call KernelPackage,qdx-tunnel))

define KernelPackage/qca-edma
  SUBMENU:=$(NETWORK_DEVICES_MENU)
  TITLE:=Qualcomm IPQ807x EDMA Ethernet controller
  DEPENDS:=@TARGET_qualcommax_ipq807x +PACKAGE_kmod-qdx-drv:kmod-qdx-drv
  KCONFIG:=CONFIG_QCOM_EDMA
  FILES:=$(LINUX_DIR)/drivers/net/ethernet/qualcomm/qca_edma.ko
  AUTOLOAD:=$(call AutoProbe,qca_edma)
endef

$(eval $(call KernelPackage,qca-edma))

define KernelPackage/qca-ppe
  SUBMENU:=$(NETWORK_DEVICES_MENU)
  TITLE:=Qualcomm IPQ807x 802.11ax PPE switch
  DEPENDS:=@TARGET_qualcommax_ipq807x +kmod-libphy +PACKAGE_kmod-qdx-drv:kmod-qdx-drv
  KCONFIG:=CONFIG_QCOM_80211AX_PPE
  FILES:=$(LINUX_DIR)/drivers/net/ethernet/qualcomm/qca_ppe.ko
  AUTOLOAD:=$(call AutoProbe,qca_ppe)
endef

$(eval $(call KernelPackage,qca-ppe))
