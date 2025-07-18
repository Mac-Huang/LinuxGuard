# Linux Kernel Commit Batch Analysis

## Commit 1: fa33adca

**Author:** Linus Torvalds
**Date:** 2025-06-27 20:17:48
**Files Changed:** drivers/pci/pcie/ptm.c

**Message:**
```
Merge tag 'pci-v6.16-fixes-2' of git://git.kernel.org/pub/scm/linux/kernel/git/pci/pci

Pull PCI fix from Bjorn Helgaas:

 - Fix a PTM debugfs build error with CONFIG_DEBUG_FS=n &&
   CONFIG_PCIE_PTM=y (Manivannan Sadhasivam)

* tag 'pci-v6.16-fixes-2' of git://git.kernel.org/pub/scm/linux/kernel/git/pci/pci:
  PCI/PTM: Build debugfs code only if CONFIG_DEBUG_FS is enabled
```

**Diff:**
```diff
diff --git a/drivers/pci/pcie/ptm.c b/drivers/pci/pcie/ptm.c
index ee5f615a9023..4bd73f038ffb 100644
--- a/drivers/pci/pcie/ptm.c
+++ b/drivers/pci/pcie/ptm.c
@@ -254,6 +254,7 @@ bool pcie_ptm_enabled(struct pci_dev *dev)
 }
 EXPORT_SYMBOL(pcie_ptm_enabled);
 
+#if IS_ENABLED(CONFIG_DEBUG_FS)
 static ssize_t context_update_write(struct file *file, const char __user *ubuf,
 			     size_t count, loff_t *ppos)
 {
@@ -552,3 +553,4 @@ void pcie_ptm_destroy_debugfs(struct pci_ptm_debugfs *ptm_debugfs)
 	debugfs_remove_recursive(ptm_debugfs->debugfs);
 }
 EXPORT_SYMBOL_GPL(pcie_ptm_destroy_debugfs);
+#endif
```

---

## Commit 2: 7abdafd2

**Author:** Linus Torvalds
**Date:** 2025-06-27 19:38:36
**Files Changed:** drivers/gpu/drm/amd/amdgpu/amdgpu_discovery.c, drivers/gpu/drm/amd/amdgpu/gfx_v9_0.c, drivers/gpu/drm/amd/amdgpu/mes_v11_0.c, drivers/gpu/drm/amd/amdgpu/mes_v12_0.c, drivers/gpu/drm/amd/amdgpu/sdma_v6_0.c (+16 more)

**Message:**
```
Merge tag 'drm-fixes-2025-06-28' of https://gitlab.freedesktop.org/drm/kernel

Pull drm fixes from Dave Airlie:
 "Regular weekly drm updates, nothing out of the ordinary, amdgpu, xe,
  i915 and a few misc bits. Seems about right for this time in the
  release cycle.

  core:
   - fix drm_writeback_connector_cleanup function signature
   - use correct HDMI audio bridge in drm_connector_hdmi_audio_init

  bridge:
   - SN65DSI86: fix HPD

  amdgpu:
   - Cleaner shader support for additional GFX9 GPUs
   - MES firmware compatibility fixes
   - Discovery error reporting fixes
   - SDMA6/7 userq fixes
   - Backlight fix
   - EDID sanity check

  i915:
   - Fix for SNPS PHY HDMI for 1080p@120Hz
   - Correct DP AUX DPCD probe address
   - Followup build fix for GCOV and AutoFDO enabled config

  xe:
   - Missing error check
   - Fix xe_hwmon_power_max_write
   - Move flushes
   - Explicitly exit CT safe mode on unwind
   - Process deferred GGTT node removals on device unwind"

* tag 'drm-fixes-2025-06-28' of https://gitlab.freedesktop.org/drm/kernel:
  drm/xe: Process deferred GGTT node removals on device unwind
  drm/xe/guc: Explicitly exit CT safe mode on unwind
  drm/xe: move DPT l2 flush to a more sensible place
  drm/xe: Move DSB l2 flush to a more sensible place
  drm/bridge: ti-sn65dsi86: Add HPD for DisplayPort connector type
  drm/i915: fix build error some more
  drm/xe/hwmon: Fix xe_hwmon_power_max_write
  drm/xe/display: Add check for alloc_ordered_workqueue()
  drm/amd/display: Add sanity checks for drm_edid_raw()
  drm/amd/display: Fix AMDGPU_MAX_BL_LEVEL value
  drm/amdgpu/sdma7: add ucode version checks for userq support
  drm/amdgpu/sdma6: add ucode version checks for userq support
  drm/amd: Adjust output for discovery error handling
  drm/amdgpu/mes: add compatibility checks for set_hw_resource_1
  drm/amdgpu/gfx9: Add Cleaner Shader Support for GFX9.x GPUs
  drm/bridge-connector: Fix bridge in drm_connector_hdmi_audio_init()
  drm/dp: Change AUX DPCD probe address from DPCD_REV to LANE0_1_STATUS
  drm/i915/snps_hdmi_pll: Fix 64-bit divisor truncation by using div64_u64
  drm: writeback: Fix drm_writeback_connector_cleanup signature
```

**Diff:**
```diff
diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_discovery.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_discovery.c
index a0e9bf9b2710..81b3443c8d7f 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_discovery.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_discovery.c
@@ -321,10 +321,12 @@ static int amdgpu_discovery_read_binary_from_file(struct amdgpu_device *adev,
 	const struct firmware *fw;
 	int r;
 
-	r = request_firmware(&fw, fw_name, adev->dev);
+	r = firmware_request_nowarn(&fw, fw_name, adev->dev);
 	if (r) {
-		dev_err(adev->dev, "can't load firmware \"%s\"\n",
-			fw_name);
+		if (amdgpu_discovery == 2)
+			dev_err(adev->dev, "can't load firmware \"%s\"\n", fw_name);
+		else
+			drm_info(&adev->ddev, "Optional firmware \"%s\" was not found\n", fw_name);
 		return r;
 	}
 
@@ -459,16 +461,12 @@ static int amdgpu_discovery_init(struct amdgpu_device *adev)
 	/* Read from file if it is the preferred option */
 	fw_name = amdgpu_discovery_get_fw_name(adev);
 	if (fw_name != NULL) {
-		dev_info(adev->dev, "use ip discovery information from file");
+		drm_dbg(&adev->ddev, "use ip discovery information from file");
 		r = amdgpu_discovery_read_binary_from_file(adev, adev->mman.discovery_bin, fw_name);
-
-		if (r) {
-			dev_err(adev->dev, "failed to read ip discovery binary from file\n");
-			r = -EINVAL;
+		if (r)
 			goto out;
-		}
-
 	} else {
+		drm_dbg(&adev->ddev, "use ip discovery information from memory");
 		r = amdgpu_discovery_read_binary_from_mem(
 			adev, adev->mman.discovery_bin);
 		if (r)
@@ -1338,10 +1336,8 @@ static int amdgpu_discovery_reg_base_init(struct amdgpu_device *adev)
 	int r;
 
 	r = amdgpu_discovery_init(adev);
-	if (r) {
-		DRM_ERROR("amdgpu_discovery_init failed\n");
+	if (r)
 		return r;
-	}
 

... (truncated 622 lines)
```

---

## Commit 3: 26fd9f7b

**Author:** Linus Torvalds
**Date:** 2025-06-27 17:58:32
**Files Changed:** drivers/cxl/core/edac.c, drivers/cxl/core/features.c, drivers/cxl/core/ras.c

**Message:**
```
Merge tag 'cxl-fixes-6.16-rc4' of git://git.kernel.org/pub/scm/linux/kernel/git/cxl/cxl

Pull Compute Express Link (CXL) fixes from Dave Jiang:
 "These fixes address a few issues in the CXL subsystem, including
  dealing with some bugs in the CXL EDAC and RAS drivers:

   - Fix return value of cxlctl_validate_set_features()

   - Fix min_scrub_cycle of a region miscaculation and add additional
     documentation

   - Fix potential memory leak issues for CXL EDAC

   - Fix CPER handler device confusion for CXL RAS

   - Fix using wrong repair type to check DRAM event record"

* tag 'cxl-fixes-6.16-rc4' of git://git.kernel.org/pub/scm/linux/kernel/git/cxl/cxl:
  cxl/edac: Fix using wrong repair type to check dram event record
  cxl/ras: Fix CPER handler device confusion
  cxl/edac: Fix potential memory leak issues
  cxl/Documentation: Add more description about min/max scrub cycle
  cxl/edac: Fix the min_scrub_cycle of a region miscalculation
  cxl: fix return value in cxlctl_validate_set_features()
```

**Diff:**
```diff
diff --git a/Documentation/ABI/testing/sysfs-edac-scrub b/Documentation/ABI/testing/sysfs-edac-scrub
index c43be90deab4..ab6014743da5 100644
--- a/Documentation/ABI/testing/sysfs-edac-scrub
+++ b/Documentation/ABI/testing/sysfs-edac-scrub
@@ -49,6 +49,12 @@ Description:
 		(RO) Supported minimum scrub cycle duration in seconds
 		by the memory scrubber.
 
+		Device-based scrub: returns the minimum scrub cycle
+		supported by the memory device.
+
+		Region-based scrub: returns the max of minimum scrub cycles
+		supported by individual memory devices that back the region.
+
 What:		/sys/bus/edac/devices/<dev-name>/scrubX/max_cycle_duration
 Date:		March 2025
 KernelVersion:	6.15
@@ -57,6 +63,16 @@ Description:
 		(RO) Supported maximum scrub cycle duration in seconds
 		by the memory scrubber.
 
+		Device-based scrub: returns the maximum scrub cycle supported
+		by the memory device.
+
+		Region-based scrub: returns the min of maximum scrub cycles
+		supported by individual memory devices that back the region.
+
+		If the memory device does not provide maximum scrub cycle
+		information, return the maximum supported value of the scrub
+		cycle field.
+
 What:		/sys/bus/edac/devices/<dev-name>/scrubX/current_cycle_duration
 Date:		March 2025
 KernelVersion:	6.15
diff --git a/drivers/cxl/core/edac.c b/drivers/cxl/core/edac.c
index 2cbc664e5d62..623aaa4439c4 100644
--- a/drivers/cxl/core/edac.c
+++ b/drivers/cxl/core/edac.c
@@ -103,10 +103,10 @@ static int cxl_scrub_get_attrbs(struct cxl_patrol_scrub_context *cxl_ps_ctx,
 				u8 *cap, u16 *cycle, u8 *flags, u8 *min_cycle)
 {
 	struct cxl_mailbox *cxl_mbox;
-	u8 min_scrub_cycle = U8_MAX;
 	struct cxl_region_params *p;
 	struct cxl_memdev *cxlmd;
 	struct cxl_region *cxlr;
+	u8 min_scrub_cycle = 0;
 	int i, ret;
 
 	if (!cxl_ps_ctx->cxlr) {

... (truncated 157 lines)
```

---

## Commit 4: 2def09ea

**Author:** Fushuai Wang
**Date:** 2025-06-27 17:11:10
**Files Changed:** drivers/net/ethernet/freescale/dpaa2/dpaa2-eth.c

**Message:**
```
dpaa2-eth: fix xdp_rxq_info leak

The driver registered xdp_rxq_info structures via xdp_rxq_info_reg()
but failed to properly unregister them in error paths and during
removal.

Fixes: d678be1dc1ec ("dpaa2-eth: add XDP_REDIRECT support")
Signed-off-by: Fushuai Wang <wangfushuai@baidu.com>
Reviewed-by: Simon Horman <horms@kernel.org>
Reviewed-by: Ioana Ciornei <ioana.ciornei@nxp.com>
Link: https://patch.msgid.link/20250626133003.80136-1-wangfushuai@baidu.com
Signed-off-by: Jakub Kicinski <kuba@kernel.org>
```

**Diff:**
```diff
diff --git a/drivers/net/ethernet/freescale/dpaa2/dpaa2-eth.c b/drivers/net/ethernet/freescale/dpaa2/dpaa2-eth.c
index 2ec2c3dab250..b82f121cadad 100644
--- a/drivers/net/ethernet/freescale/dpaa2/dpaa2-eth.c
+++ b/drivers/net/ethernet/freescale/dpaa2/dpaa2-eth.c
@@ -3939,6 +3939,7 @@ static int dpaa2_eth_setup_rx_flow(struct dpaa2_eth_priv *priv,
 					 MEM_TYPE_PAGE_ORDER0, NULL);
 	if (err) {
 		dev_err(dev, "xdp_rxq_info_reg_mem_model failed\n");
+		xdp_rxq_info_unreg(&fq->channel->xdp_rxq);
 		return err;
 	}
 
@@ -4432,17 +4433,25 @@ static int dpaa2_eth_bind_dpni(struct dpaa2_eth_priv *priv)
 			return -EINVAL;
 		}
 		if (err)
-			return err;
+			goto out;
 	}
 
 	err = dpni_get_qdid(priv->mc_io, 0, priv->mc_token,
 			    DPNI_QUEUE_TX, &priv->tx_qdid);
 	if (err) {
 		dev_err(dev, "dpni_get_qdid() failed\n");
-		return err;
+		goto out;
 	}
 
 	return 0;
+
+out:
+	while (i--) {
+		if (priv->fq[i].type == DPAA2_RX_FQ &&
+		    xdp_rxq_info_is_reg(&priv->fq[i].channel->xdp_rxq))
+			xdp_rxq_info_unreg(&priv->fq[i].channel->xdp_rxq);
+	}
+	return err;
 }
 
 /* Allocate rings for storing incoming frame descriptors */
@@ -4825,6 +4834,17 @@ static void dpaa2_eth_del_ch_napi(struct dpaa2_eth_priv *priv)
 	}
 }
 
+static void dpaa2_eth_free_rx_xdp_rxq(struct dpaa2_eth_priv *priv)
+{
+	int i;
+
+	for (i = 0; i < priv->num_fqs; i++) {
+		if (priv->fq[i].type == DPAA2_RX_FQ &&

... (truncated 24 lines)
```

---

## Commit 5: 6921d1e0

**Author:** Edward Adam Davis
**Date:** 2025-06-27 15:51:36
**Files Changed:** kernel/trace/trace_events_filter.c

**Message:**
```
tracing: Fix filter logic error

If the processing of the tr->events loop fails, the filter that has been
added to filter_head will be released twice in free_filter_list(&head->rcu)
and __free_filter(filter).

After adding the filter of tr->events, add the filter to the filter_head
process to avoid triggering uaf.

Link: https://lore.kernel.org/tencent_4EF87A626D702F816CD0951CE956EC32CD0A@qq.com
Fixes: a9d0aab5eb33 ("tracing: Fix regression of filter waiting a long time on RCU synchronization")
Reported-by: syzbot+daba72c4af9915e9c894@syzkaller.appspotmail.com
Closes: https://syzkaller.appspot.com/bug?extid=daba72c4af9915e9c894
Tested-by: syzbot+daba72c4af9915e9c894@syzkaller.appspotmail.com
Acked-by: Masami Hiramatsu (Google) <mhiramat@kernel.org>
Signed-off-by: Edward Adam Davis <eadavis@qq.com>
Signed-off-by: Steven Rostedt (Google) <rostedt@goodmis.org>
```

**Diff:**
```diff
diff --git a/kernel/trace/trace_events_filter.c b/kernel/trace/trace_events_filter.c
index 08141f105c95..3885aadc434d 100644
--- a/kernel/trace/trace_events_filter.c
+++ b/kernel/trace/trace_events_filter.c
@@ -1436,13 +1436,6 @@ static void filter_free_subsystem_filters(struct trace_subsystem_dir *dir,
 
 	INIT_LIST_HEAD(&head->list);
 
-	item = kmalloc(sizeof(*item), GFP_KERNEL);
-	if (!item)
-		goto free_now;
-
-	item->filter = filter;
-	list_add_tail(&item->list, &head->list);
-
 	list_for_each_entry(file, &tr->events, list) {
 		if (file->system != dir)
 			continue;
@@ -1454,6 +1447,13 @@ static void filter_free_subsystem_filters(struct trace_subsystem_dir *dir,
 		event_clear_filter(file);
 	}
 
+	item = kmalloc(sizeof(*item), GFP_KERNEL);
+	if (!item)
+		goto free_now;
+
+	item->filter = filter;
+	list_add_tail(&item->list, &head->list);
+
 	delay_free_filter(head);
 	return;
  free_now:
```

---

