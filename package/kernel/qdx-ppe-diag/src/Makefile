# Isolated diagnostics; build only through project Docker.
obj-m += qdx_ppe_diag.o qdx_relay_diag.o
obj-m += qdx_diag_cleanup.o
obj-m += qdx_proxy_diag.o
obj-m += qdx_nss_snapshot.o
obj-m += qdx_rx_handoff_diag.o
obj-m += qdx_codel_diag.o
obj-m += qdx_tbf_diag.o
obj-m += qdx_fifo_resident_diag.o
obj-m += sch_drr.o cls_bpf.o
obj-m += qdx_charge_diag.o
obj-m += qdx_command_ledger.o
obj-m += qdx_bridge_flow_diag.o
obj-m += qdx_mirror_copy_diag.o
obj-m += qdx_ipv4_notify_diag.o
obj-m += qdx_mirror_state_diag.o
obj-m += qdx_fifo_handover_diag.o
obj-m += qdx_clock_diag.o
obj-m += qdx_wrr_handover_diag.o
obj-m += qdx_physical_fq_diag.o
obj-m += qdx_rate_handover_diag.o
obj-m += qdx_aqm_handover_diag.o
obj-m += qdx_physical_rate_diag.o
obj-m += qdx_physical_wrr_diag.o
obj-m += qdx_rate_safety_recovery.o
obj-m += qdx_physical_aqm_diag.o

obj-m += qdx_ppe_recall_continuation.o

# ELF-bound historical recovery helpers retain their original source and artifacts.
# They must not be rebuilt against a different qdx_diag_fq_view layout.

obj-m += qdx_tbf_failed_retire.o

CFLAGS_qdx_fifo_resident_diag.o += -I$(srctree)/drivers/net/ethernet/qualcomm/qdx-drv

CFLAGS_qdx_tbf_diag.o += -I$(srctree)/drivers/net/ethernet/qualcomm/qdx-drv

obj-m += qdx_finite_fifo_diag.o qdx_d_bridge_flow_diag.o

obj-m += qdx_fixture_fdb_diag.o
CFLAGS_qdx_fixture_fdb_diag.o += -I$(srctree)/drivers/net/ethernet/qualcomm
