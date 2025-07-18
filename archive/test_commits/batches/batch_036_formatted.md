# Linux Kernel Commit Batch Analysis

## Commit 1: c4dce0c0

**Author:** Linus Torvalds
**Date:** 2025-06-25 11:54:04
**Files Changed:** drivers/spi/spi-cadence-quadspi.c

**Message:**
```
Merge tag 'spi-fix-v6.16-rc3' of git://git.kernel.org/pub/scm/linux/kernel/git/broonie/spi

Pull spi fix from Mark Brown:
 "One fix for a runtime PM underflow when removing the Cadence QuadSPI
  driver"

* tag 'spi-fix-v6.16-rc3' of git://git.kernel.org/pub/scm/linux/kernel/git/broonie/spi:
  spi: spi-cadence-quadspi: Fix pm runtime unbalance
```

**Diff:**
```diff
diff --git a/drivers/spi/spi-cadence-quadspi.c b/drivers/spi/spi-cadence-quadspi.c
index fe0f122f07b0..aa1932ba17cb 100644
--- a/drivers/spi/spi-cadence-quadspi.c
+++ b/drivers/spi/spi-cadence-quadspi.c
@@ -1958,10 +1958,10 @@ static int cqspi_probe(struct platform_device *pdev)
 			goto probe_setup_failed;
 	}
 
-	ret = devm_pm_runtime_enable(dev);
-	if (ret) {
-		if (cqspi->rx_chan)
-			dma_release_channel(cqspi->rx_chan);
+	pm_runtime_enable(dev);
+
+	if (cqspi->rx_chan) {
+		dma_release_channel(cqspi->rx_chan);
 		goto probe_setup_failed;
 	}
 
@@ -1981,6 +1981,7 @@ static int cqspi_probe(struct platform_device *pdev)
 	return 0;
 probe_setup_failed:
 	cqspi_controller_enable(cqspi, 0);
+	pm_runtime_disable(dev);
 probe_reset_failed:
 	if (cqspi->is_jh7110)
 		cqspi_jh7110_disable_clk(pdev, cqspi);
@@ -1999,7 +2000,8 @@ static void cqspi_remove(struct platform_device *pdev)
 	if (cqspi->rx_chan)
 		dma_release_channel(cqspi->rx_chan);
 
-	clk_disable_unprepare(cqspi->clk);
+	if (pm_runtime_get_sync(&pdev->dev) >= 0)
+		clk_disable(cqspi->clk);
 
 	if (cqspi->is_jh7110)
 		cqspi_jh7110_disable_clk(pdev, cqspi);
```

---

## Commit 2: 92ca6c49

**Author:** Linus Torvalds
**Date:** 2025-06-25 11:20:14
**Files Changed:** drivers/scsi/fnic/fdls_disc.c, drivers/scsi/fnic/fnic.h, drivers/scsi/fnic/fnic_fcs.c, drivers/scsi/fnic/fnic_fdls.h, drivers/scsi/fnic/fnic_scsi.c (+2 more)

**Message:**
```
Merge tag 'scsi-fixes' of git://git.kernel.org/pub/scm/linux/kernel/git/jejb/scsi

Pull SCSI fixes from James Bottomley:
 "Fixes all in drivers.

  ufs and megaraid_sas are small and obvious.

  The large diffstat in fnic comes from two pieces: the addition of
  quite a bit of logging (no change to function) and the reworking of
  the timeout allocation path for the two conditions that can occur
  simultaneously to prevent reusing the same abort frame and then both
  trying to free it"

* tag 'scsi-fixes' of git://git.kernel.org/pub/scm/linux/kernel/git/jejb/scsi:
  scsi: fnic: Fix missing DMA mapping error in fnic_send_frame()
  scsi: fnic: Set appropriate logging level for log message
  scsi: fnic: Add and improve logs in FDMI and FDMI ABTS paths
  scsi: fnic: Turn off FDMI ACTIVE flags on link down
  scsi: fnic: Fix crash in fnic_wq_cmpl_handler when FDMI times out
  scsi: ufs: core: Fix clk scaling to be conditional in reset and restore
  scsi: megaraid_sas: Fix invalid node index
```

**Diff:**
```diff
diff --git a/drivers/scsi/fnic/fdls_disc.c b/drivers/scsi/fnic/fdls_disc.c
index f8ab69c51dab..ae37f85f618b 100644
--- a/drivers/scsi/fnic/fdls_disc.c
+++ b/drivers/scsi/fnic/fdls_disc.c
@@ -763,50 +763,86 @@ static void fdls_send_fabric_abts(struct fnic_iport_s *iport)
 	iport->fabric.timer_pending = 1;
 }
 
-static void fdls_send_fdmi_abts(struct fnic_iport_s *iport)
+static uint8_t *fdls_alloc_init_fdmi_abts_frame(struct fnic_iport_s *iport,
+		uint16_t oxid)
 {
-	uint8_t *frame;
+	struct fc_frame_header *pfdmi_abts;
 	uint8_t d_id[3];
+	uint8_t *frame;
 	struct fnic *fnic = iport->fnic;
-	struct fc_frame_header *pfabric_abts;
-	unsigned long fdmi_tov;
-	uint16_t oxid;
-	uint16_t frame_size = FNIC_ETH_FCOE_HDRS_OFFSET +
-			sizeof(struct fc_frame_header);
 
 	frame = fdls_alloc_frame(iport);
 	if (frame == NULL) {
 		FNIC_FCS_DBG(KERN_ERR, fnic->host, fnic->fnic_num,
 				"Failed to allocate frame to send FDMI ABTS");
-		return;
+		return NULL;
 	}
 
-	pfabric_abts = (struct fc_frame_header *) (frame + FNIC_ETH_FCOE_HDRS_OFFSET);
+	pfdmi_abts = (struct fc_frame_header *) (frame + FNIC_ETH_FCOE_HDRS_OFFSET);
 	fdls_init_fabric_abts_frame(frame, iport);
 
 	hton24(d_id, FC_FID_MGMT_SERV);
-	FNIC_STD_SET_D_ID(*pfabric_abts, d_id);
+	FNIC_STD_SET_D_ID(*pfdmi_abts, d_id);
+	FNIC_STD_SET_OX_ID(*pfdmi_abts, oxid);
+
+	return frame;
+}
+
+static void fdls_send_fdmi_abts(struct fnic_iport_s *iport)
+{
+	uint8_t *frame;
+	struct fnic *fnic = iport->fnic;
+	unsigned long fdmi_tov;
+	uint16_t frame_size = FNIC_ETH_FCOE_HDRS_OFFSET +
+			sizeof(struct fc_frame_header);

... (truncated 328 lines)
```

---

## Commit 3: 010c40c1

**Author:** Jakub Kicinski
**Date:** 2025-06-25 10:26:16
**Files Changed:** drivers/net/wireless/intel/iwlegacy/4965-rs.c, drivers/net/wireless/intel/iwlwifi/mvm/mld-mac.c, net/mac80211/link.c, net/mac80211/util.c

**Message:**
```
Merge tag 'wireless-2025-06-25' of https://git.kernel.org/pub/scm/linux/kernel/git/wireless/wireless

Johannes Berg says:

====================
Just a few fixes:
 - iwlegacy: work around large stack with clang/kasan
 - mac80211: fix integer overflow
 - mac80211: fix link struct init vs. RCU publish
 - iwlwifi: fix warning on IFF_UP

* tag 'wireless-2025-06-25' of https://git.kernel.org/pub/scm/linux/kernel/git/wireless/wireless:
  wifi: mac80211: finish link init before RCU publish
  wifi: iwlwifi: mvm: assume '1' as the default mac_config_cmd version
  wifi: mac80211: fix beacon interval calculation overflow
  wifi: iwlegacy: work around excessive stack usage on clang/kasan
====================

Link: https://patch.msgid.link/20250625115433.41381-3-johannes@sipsolutions.net
Signed-off-by: Jakub Kicinski <kuba@kernel.org>
```

**Diff:**
```diff
diff --git a/drivers/net/wireless/intel/iwlegacy/4965-rs.c b/drivers/net/wireless/intel/iwlegacy/4965-rs.c
index 0e5130d1fccd..031d88bf6393 100644
--- a/drivers/net/wireless/intel/iwlegacy/4965-rs.c
+++ b/drivers/net/wireless/intel/iwlegacy/4965-rs.c
@@ -203,7 +203,8 @@ il4965_rs_extract_rate(u32 rate_n_flags)
 	return (u8) (rate_n_flags & 0xFF);
 }
 
-static void
+/* noinline works around https://github.com/llvm/llvm-project/issues/143908 */
+static noinline_for_stack void
 il4965_rs_rate_scale_clear_win(struct il_rate_scale_data *win)
 {
 	win->data = 0;
diff --git a/drivers/net/wireless/intel/iwlwifi/mvm/mld-mac.c b/drivers/net/wireless/intel/iwlwifi/mvm/mld-mac.c
index 3c255ae916c8..3f8b840871d3 100644
--- a/drivers/net/wireless/intel/iwlwifi/mvm/mld-mac.c
+++ b/drivers/net/wireless/intel/iwlwifi/mvm/mld-mac.c
@@ -32,9 +32,9 @@ static void iwl_mvm_mld_mac_ctxt_cmd_common(struct iwl_mvm *mvm,
 	unsigned int link_id;
 	int cmd_ver = iwl_fw_lookup_cmd_ver(mvm->fw,
 					    WIDE_ID(MAC_CONF_GROUP,
-						    MAC_CONFIG_CMD), 0);
+						    MAC_CONFIG_CMD), 1);
 
-	if (WARN_ON(cmd_ver < 1 || cmd_ver > 3))
+	if (WARN_ON(cmd_ver > 3))
 		return;
 
 	cmd->id_and_color = cpu_to_le32(mvmvif->id);
diff --git a/net/mac80211/link.c b/net/mac80211/link.c
index d40c2bd3b50b..4f7b7d0f64f2 100644
--- a/net/mac80211/link.c
+++ b/net/mac80211/link.c
@@ -93,9 +93,6 @@ void ieee80211_link_init(struct ieee80211_sub_if_data *sdata,
 	if (link_id < 0)
 		link_id = 0;
 
-	rcu_assign_pointer(sdata->vif.link_conf[link_id], link_conf);
-	rcu_assign_pointer(sdata->link[link_id], link);
-
 	if (sdata->vif.type == NL80211_IFTYPE_AP_VLAN) {
 		struct ieee80211_sub_if_data *ap_bss;
 		struct ieee80211_bss_conf *ap_bss_conf;
@@ -145,6 +142,9 @@ void ieee80211_link_init(struct ieee80211_sub_if_data *sdata,
 
 		ieee80211_link_debugfs_add(link);
 	}
+
+	rcu_assign_pointer(sdata->vif.link_conf[link_id], link_conf);

... (truncated 17 lines)
```

---

## Commit 4: fa787ac0

**Author:** Manuel Andreas
**Date:** 2025-06-25 09:15:24
**Files Changed:** arch/x86/kvm/hyperv.c

**Message:**
```
KVM: x86/hyper-v: Skip non-canonical addresses during PV TLB flush

In KVM guests with Hyper-V hypercalls enabled, the hypercalls
HVCALL_FLUSH_VIRTUAL_ADDRESS_LIST and HVCALL_FLUSH_VIRTUAL_ADDRESS_LIST_EX
allow a guest to request invalidation of portions of a virtual TLB.
For this, the hypercall parameter includes a list of GVAs that are supposed
to be invalidated.

However, when non-canonical GVAs are passed, there is currently no
filtering in place and they are eventually passed to checked invocations of
INVVPID on Intel / INVLPGA on AMD.  While AMD's INVLPGA silently ignores
non-canonical addresses (effectively a no-op), Intel's INVVPID explicitly
signals VM-Fail and ultimately triggers the WARN_ONCE in invvpid_error():

  invvpid failed: ext=0x0 vpid=1 gva=0xaaaaaaaaaaaaa000
  WARNING: CPU: 6 PID: 326 at arch/x86/kvm/vmx/vmx.c:482
  invvpid_error+0x91/0xa0 [kvm_intel]
  Modules linked in: kvm_intel kvm 9pnet_virtio irqbypass fuse
  CPU: 6 UID: 0 PID: 326 Comm: kvm-vm Not tainted 6.15.0 #14 PREEMPT(voluntary)
  RIP: 0010:invvpid_error+0x91/0xa0 [kvm_intel]
  Call Trace:
    vmx_flush_tlb_gva+0x320/0x490 [kvm_intel]
    kvm_hv_vcpu_flush_tlb+0x24f/0x4f0 [kvm]
    kvm_arch_vcpu_ioctl_run+0x3013/0x5810 [kvm]

Hyper-V documents that invalid GVAs (those that are beyond a partition's
GVA space) are to be ignored.  While not completely clear whether this
ruling also applies to non-canonical GVAs, it is likely fine to make that
assumption, and manual testing on Azure confirms "real" Hyper-V interprets
the specification in the same way.

Skip non-canonical GVAs when processing the list of address to avoid
tripping the INVVPID failure.  Alternatively, KVM could filter out "bad"
GVAs before inserting into the FIFO, but practically speaking the only
downside of pushing validation to the final processing is that doing so
is suboptimal for the guest, and no well-behaved guest will request TLB
flushes for non-canonical addresses.

Fixes: 260970862c88 ("KVM: x86: hyper-v: Handle HVCALL_FLUSH_VIRTUAL_ADDRESS_LIST{,EX} calls gently")
Cc: stable@vger.kernel.org
Signed-off-by: Manuel Andreas <manuel.andreas@tum.de>
Suggested-by: Vitaly Kuznetsov <vkuznets@redhat.com>
Link: https://lore.kernel.org/r/c090efb3-ef82-499f-a5e0-360fc8420fb7@tum.de
Signed-off-by: Sean Christopherson <seanjc@google.com>
```

**Diff:**
```diff
diff --git a/arch/x86/kvm/hyperv.c b/arch/x86/kvm/hyperv.c
index 75221a11e15e..ee27064dd72f 100644
--- a/arch/x86/kvm/hyperv.c
+++ b/arch/x86/kvm/hyperv.c
@@ -1979,6 +1979,9 @@ int kvm_hv_vcpu_flush_tlb(struct kvm_vcpu *vcpu)
 		if (entries[i] == KVM_HV_TLB_FLUSHALL_ENTRY)
 			goto out_flush_all;
 
+		if (is_noncanonical_invlpg_address(entries[i], vcpu))
+			continue;
+
 		/*
 		 * Lower 12 bits of 'address' encode the number of additional
 		 * pages to flush.
```

---

## Commit 5: 7cac633a

**Author:** Penglei Jiang
**Date:** 2025-06-25 08:14:14
**Files Changed:** io_uring/zcrx.c

**Message:**
```
io_uring: fix resource leak in io_import_dmabuf()

Replace the return statement with setting ret = -EINVAL and jumping to
the err label to ensure resources are released via io_release_dmabuf.

Fixes: a5c98e942457 ("io_uring/zcrx: dmabuf backed zerocopy receive")
Signed-off-by: Penglei Jiang <superman.xpt@gmail.com>
Link: https://lore.kernel.org/r/20250625102703.68336-1-superman.xpt@gmail.com
Signed-off-by: Jens Axboe <axboe@kernel.dk>
```

**Diff:**
```diff
diff --git a/io_uring/zcrx.c b/io_uring/zcrx.c
index 21c816c3bfe0..ade4da9c4e31 100644
--- a/io_uring/zcrx.c
+++ b/io_uring/zcrx.c
@@ -106,8 +106,10 @@ static int io_import_dmabuf(struct io_zcrx_ifq *ifq,
 	for_each_sgtable_dma_sg(mem->sgt, sg, i)
 		total_size += sg_dma_len(sg);
 
-	if (total_size < off + len)
-		return -EINVAL;
+	if (total_size < off + len) {
+		ret = -EINVAL;
+		goto err;
+	}
 
 	mem->dmabuf_offset = off;
 	mem->size = len;
```

---

