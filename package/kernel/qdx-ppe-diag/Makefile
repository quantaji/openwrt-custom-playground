include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=qdx-ppe-diag
PKG_RELEASE:=1
PKG_LICENSE:=GPL-2.0-only
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

define KernelPackage/qdx-ppe-diag
  SUBMENU:=Network Devices
  TITLE:=Isolated HPPE diagnostic
  DEPENDS:=+kmod-qdx-drv
  FILES:=$(PKG_BUILD_DIR)/qdx_ppe_diag.ko $(PKG_BUILD_DIR)/qdx_relay_diag.ko $(PKG_BUILD_DIR)/qdx_diag_cleanup.ko $(PKG_BUILD_DIR)/qdx_proxy_diag.ko $(PKG_BUILD_DIR)/qdx_charge_diag.ko $(PKG_BUILD_DIR)/qdx_nss_snapshot.ko $(PKG_BUILD_DIR)/qdx_rx_handoff_diag.ko $(PKG_BUILD_DIR)/qdx_codel_diag.ko $(PKG_BUILD_DIR)/qdx_tbf_diag.ko $(PKG_BUILD_DIR)/qdx_fifo_resident_diag.ko $(PKG_BUILD_DIR)/sch_drr.ko $(PKG_BUILD_DIR)/cls_bpf.ko $(PKG_BUILD_DIR)/qdx_tbf_failed_retire.ko $(PKG_BUILD_DIR)/qdx_finite_fifo_diag.ko $(PKG_BUILD_DIR)/qdx_d_bridge_flow_diag.ko $(PKG_BUILD_DIR)/qdx_fixture_fdb_diag.ko
  KCONFIG:=
endef

define Build/Compile
	$(KERNEL_MAKE) M="$(PKG_BUILD_DIR)" modules
endef

$(eval $(call KernelPackage,qdx-ppe-diag))
