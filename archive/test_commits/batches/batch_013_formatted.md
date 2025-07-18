# Linux Kernel Commit Batch Analysis

## Commit 1: df464267

**Author:** Linus Torvalds
**Date:** 2025-07-04 10:05:31
**Files Changed:** arch/x86/include/asm/amd/fch.h, arch/x86/kernel/cpu/amd.c, drivers/i2c/busses/i2c-piix4.c, drivers/platform/mellanox/mlxbf-pmc.c, drivers/platform/mellanox/mlxbf-tmfifo.c (+20 more)

**Message:**
```
Merge tag 'platform-drivers-x86-v6.16-3' of git://git.kernel.org/pub/scm/linux/kernel/git/pdx86/platform-drivers-x86

Pull x86 platform drivers fixes from Ilpo Järvinen:
 "Mostly a few lines fixed here and there except amd/isp4 which improves
  swnodes relationships but that is a new driver not in any stable
  kernels yet. The think-lmi driver changes also look relatively large
  but there are just many fixes to it.

  The i2c/piix4 change is a effectively a revert of the commit
  7e173eb82ae9 ("i2c: piix4: Make CONFIG_I2C_PIIX4 dependent on
  CONFIG_X86") but that required moving the header out from arch/x86
  under include/linux/platform_data/

  Summary:

   - amd/isp4: Improve swnode graph (new driver exception)

   - asus-nb-wmi: Use duo keyboard quirk for Zenbook Duo UX8406CA

   - dell-lis3lv02d: Add Latitude 5500 accelerometer address

   - dell-wmi-sysman: Fix WMI data block retrieval and class dev unreg

   - hp-bioscfg: Fix class device unregistration

   - i2c: piix4: Re-enable on non-x86 + move FCH header under platform_data/

   - intel/hid: Wildcat Lake support

   - mellanox:
      - mlxbf-pmc: Fix duplicate event ID
      - mlxbf-tmfifo: Fix vring_desc.len assignment
      - mlxreg-lc: Fix bit-not-set logic check
      - nvsw-sn2201: Fix bus number in error message & spelling errors

   - portwell-ec: Move watchdog device under correct platform hierarchy

   - think-lmi: Error handling fixes (sysfs, kset, kobject, class dev unreg)

   - thinkpad_acpi: Handle HKEY 0x1402 event (2025 Thinkpads)

   - wmi: Fix WMI event enablement"

* tag 'platform-drivers-x86-v6.16-3' of git://git.kernel.org/pub/scm/linux/kernel/git/pdx86/platform-drivers-x86: (22 commits)
  platform/x86: think-lmi: Fix sysfs group cleanup
  platform/x86: think-lmi: Fix kobject cleanup
  platform/x86: think-lmi: Create ksets consecutively
  platform/mellanox: mlxreg-lc: Fix logic error in power state check
  i2c: Re-enable piix4 driver on non-x86
  Move FCH header to a location accessible by all archs
  platform/x86/intel/hid: Add Wildcat Lake support
  platform/x86: dell-wmi-sysman: Fix class device unregistration
  platform/x86: think-lmi: Fix class device unregistration
  platform/x86: hp-bioscfg: Fix class device unregistration
  platform/x86: Update swnode graph for amd isp4
  platform/x86: dell-wmi-sysman: Fix WMI data block retrieval in sysfs callbacks
  platform/x86: wmi: Update documentation of WCxx/WExx ACPI methods
  platform/x86: wmi: Fix WMI event enablement
  platform/mellanox: nvsw-sn2201: Fix bus number in adapter error message
  platform/mellanox: Fix spelling and comment clarity in Mellanox drivers
  platform/mellanox: mlxbf-pmc: Fix duplicate event ID for CACHE_DATA1
  platform/x86: thinkpad_acpi: handle HKEY 0x1402 event
  platform/x86: asus-nb-wmi: add DMI quirk for ASUS Zenbook Duo UX8406CA
  platform/x86: dell-lis3lv02d: Add Latitude 5500
  ...
```

**Diff:**
```diff
diff --git a/Documentation/wmi/acpi-interface.rst b/Documentation/wmi/acpi-interface.rst
index f1b28835d23c..1ef003b033bf 100644
--- a/Documentation/wmi/acpi-interface.rst
+++ b/Documentation/wmi/acpi-interface.rst
@@ -36,7 +36,7 @@ Offset  Size (in bytes) Content
 
 The WMI object flags control whether the method or notification ID is used:
 
-- 0x1: Data block usage is expensive and must be explicitly enabled/disabled.
+- 0x1: Data block is expensive to collect.
 - 0x2: Data block contains WMI methods.
 - 0x4: Data block contains ASCIZ string.
 - 0x8: Data block describes a WMI event, use notification ID instead
@@ -83,14 +83,18 @@ event as hexadecimal value. Their first parameter is an integer with a value
 of 0 if the WMI event should be disabled, other values will enable
 the WMI event.
 
+Those ACPI methods are always called even for WMI events not registered as
+being expensive to collect to match the behavior of the Windows driver.
+
 WCxx ACPI methods
 -----------------
-Similar to the ``WExx`` ACPI methods, except that it controls data collection
-instead of events and thus the last two characters of the ACPI method name are
-the method ID of the data block to enable/disable.
+Similar to the ``WExx`` ACPI methods, except that instead of WMI events it controls
+data collection of data blocks registered as being expensive to collect. Thus the
+last two characters of the ACPI method name are the method ID of the data block
+to enable/disable.
 
 Those ACPI methods are also called before setting data blocks to match the
-behaviour of the Windows driver.
+behavior of the Windows driver.
 
 _WED ACPI method
 ----------------
diff --git a/arch/x86/kernel/cpu/amd.c b/arch/x86/kernel/cpu/amd.c
index b2ad8d13211a..655f44f89ded 100644
--- a/arch/x86/kernel/cpu/amd.c
+++ b/arch/x86/kernel/cpu/amd.c
@@ -9,7 +9,7 @@
 #include <linux/sched/clock.h>
 #include <linux/random.h>
 #include <linux/topology.h>
-#include <asm/amd/fch.h>
+#include <linux/platform_data/x86/amd-fch.h>
 #include <asm/processor.h>
 #include <asm/apic.h>
 #include <asm/cacheinfo.h>
diff --git a/drivers/i2c/busses/Kconfig b/drivers/i2c/busses/Kconfig

... (truncated 881 lines)
```

---

## Commit 2: 3c2bd251

**Author:** Linus Torvalds
**Date:** 2025-07-04 09:57:12
**Files Changed:** drivers/usb/cdns3/cdnsp-debug.h, drivers/usb/cdns3/cdnsp-ep0.c, drivers/usb/cdns3/cdnsp-gadget.h, drivers/usb/cdns3/cdnsp-ring.c, drivers/usb/chipidea/udc.c (+19 more)

**Message:**
```
Merge tag 'usb-6.16-rc5' of git://git.kernel.org/pub/scm/linux/kernel/git/gregkh/usb

Pull USB fixes from Greg KH:
 "Here are some USB driver fixes for 6.16-rc5. I originally wanted this
  to get into -rc4, but there were some regressions that had to be
  handled first. Now all looks good. Included in here are the following
  fixes:

   - cdns3 driver fixes

   - xhci driver fixes

   - typec driver fixes

   - USB hub fixes (this is what took the longest to get right)

   - new USB driver quirks added

   - chipidea driver fixes

  All of these have been in linux-next for a while and now we have no
  more reported problems with them"

* tag 'usb-6.16-rc5' of git://git.kernel.org/pub/scm/linux/kernel/git/gregkh/usb: (21 commits)
  usb: hub: Fix flushing of delayed work used for post resume purposes
  xhci: dbc: Flush queued requests before stopping dbc
  xhci: dbctty: disable ECHO flag by default
  xhci: Disable stream for xHC controller with XHCI_BROKEN_STREAMS
  usb: xhci: quirk for data loss in ISOC transfers
  usb: dwc3: gadget: Fix TRB reclaim logic for short transfers and ZLPs
  usb: hub: Fix flushing and scheduling of delayed work that tunes runtime pm
  usb: typec: displayport: Fix potential deadlock
  usb: typec: altmodes/displayport: do not index invalid pin_assignments
  usb: cdnsp: Fix issue with CV Bad Descriptor test
  usb: typec: tcpm: apply vbus before data bringup in tcpm_src_attach
  Revert "usb: xhci: Implement xhci_handshake_check_state() helper"
  usb: xhci: Skip xhci_reset in xhci_resume if xhci is being removed
  usb: gadget: u_serial: Fix race condition in TTY wakeup
  Revert "usb: gadget: u_serial: Add null pointer check in gs_start_io"
  usb: chipidea: udc: disconnect/reconnect from host when do suspend/resume
  usb: acpi: fix device link removal
  usb: hub: fix detection of high tier USB3 devices behind suspended hubs
  Logitech C-270 even more broken
  usb: dwc3: Abort suspend on soft disconnect failure
  ...
```

**Diff:**
```diff
diff --git a/drivers/usb/cdns3/cdnsp-debug.h b/drivers/usb/cdns3/cdnsp-debug.h
index cd138acdcce1..86860686d836 100644
--- a/drivers/usb/cdns3/cdnsp-debug.h
+++ b/drivers/usb/cdns3/cdnsp-debug.h
@@ -327,12 +327,13 @@ static inline const char *cdnsp_decode_trb(char *str, size_t size, u32 field0,
 	case TRB_RESET_EP:
 	case TRB_HALT_ENDPOINT:
 		ret = scnprintf(str, size,
-				"%s: ep%d%s(%d) ctx %08x%08x slot %ld flags %c",
+				"%s: ep%d%s(%d) ctx %08x%08x slot %ld flags %c %c",
 				cdnsp_trb_type_string(type),
 				ep_num, ep_id % 2 ? "out" : "in",
 				TRB_TO_EP_INDEX(field3), field1, field0,
 				TRB_TO_SLOT_ID(field3),
-				field3 & TRB_CYCLE ? 'C' : 'c');
+				field3 & TRB_CYCLE ? 'C' : 'c',
+				field3 & TRB_ESP ? 'P' : 'p');
 		break;
 	case TRB_STOP_RING:
 		ret = scnprintf(str, size,
diff --git a/drivers/usb/cdns3/cdnsp-ep0.c b/drivers/usb/cdns3/cdnsp-ep0.c
index f317d3c84781..5cd9b898ce97 100644
--- a/drivers/usb/cdns3/cdnsp-ep0.c
+++ b/drivers/usb/cdns3/cdnsp-ep0.c
@@ -414,6 +414,7 @@ static int cdnsp_ep0_std_request(struct cdnsp_device *pdev,
 void cdnsp_setup_analyze(struct cdnsp_device *pdev)
 {
 	struct usb_ctrlrequest *ctrl = &pdev->setup;
+	struct cdnsp_ep *pep;
 	int ret = -EINVAL;
 	u16 len;
 
@@ -427,10 +428,21 @@ void cdnsp_setup_analyze(struct cdnsp_device *pdev)
 		goto out;
 	}
 
+	pep = &pdev->eps[0];
+
 	/* Restore the ep0 to Stopped/Running state. */
-	if (pdev->eps[0].ep_state & EP_HALTED) {
-		trace_cdnsp_ep0_halted("Restore to normal state");
-		cdnsp_halt_endpoint(pdev, &pdev->eps[0], 0);
+	if (pep->ep_state & EP_HALTED) {
+		if (GET_EP_CTX_STATE(pep->out_ctx) == EP_STATE_HALTED)
+			cdnsp_halt_endpoint(pdev, pep, 0);
+
+		/*
+		 * Halt Endpoint Command for SSP2 for ep0 preserve current
+		 * endpoint state and driver has to synchronize the
+		 * software endpoint state with endpoint output context

... (truncated 656 lines)
```

---

## Commit 3: 42bb9b63

**Author:** Linus Torvalds
**Date:** 2025-07-04 09:48:36
**Files Changed:** drivers/dma-buf/dma-resv.c, drivers/gpu/drm/amd/amdgpu/amdgpu_amdkfd_gfx_v7.c, drivers/gpu/drm/amd/amdgpu/amdgpu_amdkfd_gfx_v8.c, drivers/gpu/drm/amd/amdgpu/amdgpu_ctx.c, drivers/gpu/drm/amd/amdgpu/sdma_v4_4_2.c (+40 more)

**Message:**
```
Merge tag 'drm-fixes-2025-07-04' of https://gitlab.freedesktop.org/drm/kernel

Pull drm fixes from Dave Airlie:
 "Weekly drm fixes, bit of a bumper crop, the usual amdgpu/xe/i915
  suspects, then there is a large scattering of fixes across core and
  drivers. I think the simple panel lookup fix is probably the largest,
  the sched race fix is also fun, but I don't see anything standing out
  too badly.

  dma-buf:
   - fix timeout handling

  gem:
   - fix framebuffer object references

  sched:
   - fix spsc queue job count race

  bridge:
   - fix aux hpd bridge of node
   - panel: move missing flag handling
   - samsung-dsim: fix %pK usage to %p

  panel:
   - fix problem with simple panel lookup

  ttm:
   - fix error path handling

  amdgpu:
   - SDMA 5.x reset fix
   - Add missing firmware declaration
   - Fix leak in amdgpu_ctx_mgr_entity_fini()
   - Freesync fix
   - OLED backlight fix

  amdkfd:
   - mtype fix for ext coherent system memory
   - MMU notifier fix
   - gfx7/8 fix

  xe:
   - Fix chunking the PTE updates and overflowing the maximum number of
     dwords with with MI_STORE_DATA_IMM
   - Move WA BB to the LRC BO to mitigate hangs on context switch
   - Fix frequency/flush WAs for BMG
   - Fix kconfig prompt title and description
   - Do not require kunit
   - Extend 14018094691 WA to BMG
   - Fix wedging the device on signal

  i915:
   - Make mei interrupt top half irq disabled to fix RT builds
   - Fix timeline left held on VMA alloc error
   - Fix NULL pointer deref in vlv_dphy_param_init()
   - Fix selftest mock_request() to avoid NULL deref

  exynos:
   - switch to using %p instead of %pK
   - fix vblank NULL ptr race
   - fix lockup on samsung peach-pit/pi chromebooks

  vesadrm:
   - NULL ptr fix

  vmwgfx:
   - fix encrypted memory allocation bug

  v3d:
   - fix irq enabled during reset"

* tag 'drm-fixes-2025-07-04' of https://gitlab.freedesktop.org/drm/kernel: (41 commits)
  drm/xe: Do not wedge device on killed exec queues
  drm/xe: Extend WA 14018094691 to BMG
  drm/v3d: Disable interrupts before resetting the GPU
  drm/gem: Acquire references on GEM handles for framebuffers
  drm/sched: Increment job count before swapping tail spsc queue
  drm/xe: Allow dropping kunit dependency as built-in
  drm/xe: Fix kconfig prompt
  drm/xe/bmg: Update Wa_22019338487
  drm/xe/bmg: Update Wa_14022085890
  drm/xe: Split xe_device_td_flush()
  drm/xe/xe_guc_pc: Lock once to update stashed frequencies
  drm/xe/guc_pc: Add _locked variant for min/max freq
  drm/xe: Make WA BB part of LRC BO
  drm/xe: Fix out-of-bounds field write in MI_STORE_DATA_IMM
  drm/i915/gsc: mei interrupt top half should be in irq disabled context
  drm/i915/gt: Fix timeline left held on VMA alloc error
  drm/vmwgfx: Fix guests running with TDX/SEV
  drm/amd/display: Don't allow OLED to go down to fully off
  drm/amd/display: Added case for when RR equals panel's max RR using freesync
  drm/amdkfd: add hqd_sdma_get_doorbell callbacks for gfx7/8
  ...
```

**Diff:**
```diff
diff --git a/drivers/dma-buf/dma-resv.c b/drivers/dma-buf/dma-resv.c
index b1ef4546346d..bea3e9858aca 100644
--- a/drivers/dma-buf/dma-resv.c
+++ b/drivers/dma-buf/dma-resv.c
@@ -685,11 +685,13 @@ long dma_resv_wait_timeout(struct dma_resv *obj, enum dma_resv_usage usage,
 	dma_resv_iter_begin(&cursor, obj, usage);
 	dma_resv_for_each_fence_unlocked(&cursor, fence) {
 
-		ret = dma_fence_wait_timeout(fence, intr, ret);
-		if (ret <= 0) {
-			dma_resv_iter_end(&cursor);
-			return ret;
-		}
+		ret = dma_fence_wait_timeout(fence, intr, timeout);
+		if (ret <= 0)
+			break;
+
+		/* Even for zero timeout the return value is 1 */
+		if (timeout)
+			timeout = ret;
 	}
 	dma_resv_iter_end(&cursor);
 
diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_amdkfd_gfx_v7.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_amdkfd_gfx_v7.c
index ca4a6b82817f..df77558e03ef 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_amdkfd_gfx_v7.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_amdkfd_gfx_v7.c
@@ -561,6 +561,13 @@ static uint32_t read_vmid_from_vmfault_reg(struct amdgpu_device *adev)
 	return REG_GET_FIELD(status, VM_CONTEXT1_PROTECTION_FAULT_STATUS, VMID);
 }
 
+static uint32_t kgd_hqd_sdma_get_doorbell(struct amdgpu_device *adev,
+					  int engine, int queue)
+
+{
+	return 0;
+}
+
 const struct kfd2kgd_calls gfx_v7_kfd2kgd = {
 	.program_sh_mem_settings = kgd_program_sh_mem_settings,
 	.set_pasid_vmid_mapping = kgd_set_pasid_vmid_mapping,
@@ -578,4 +585,5 @@ const struct kfd2kgd_calls gfx_v7_kfd2kgd = {
 	.set_scratch_backing_va = set_scratch_backing_va,
 	.set_vm_context_page_table_base = set_vm_context_page_table_base,
 	.read_vmid_from_vmfault_reg = read_vmid_from_vmfault_reg,
+	.hqd_sdma_get_doorbell = kgd_hqd_sdma_get_doorbell,
 };
diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_amdkfd_gfx_v8.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_amdkfd_gfx_v8.c
index 0f3e2944edd7..e68c0fa8d751 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_amdkfd_gfx_v8.c

... (truncated 2087 lines)
```

---

## Commit 4: 923d4012

**Author:** Linus Torvalds
**Date:** 2025-07-04 09:43:08
**Files Changed:** drivers/iommu/intel/cache.c, drivers/iommu/intel/iommu.c, drivers/iommu/intel/iommu.h, drivers/iommu/rockchip-iommu.c

**Message:**
```
Merge tag 'iommu-fixes-v6.16-rc4' of git://git.kernel.org/pub/scm/linux/kernel/git/iommu/linux

Pull iommu fixes from Joerg Roedel:

 - Rockchip: fix infinite loop caused by probing race condition

 - Intel VT-d: assign devtlb cache tag on ATS enablement

* tag 'iommu-fixes-v6.16-rc4' of git://git.kernel.org/pub/scm/linux/kernel/git/iommu/linux:
  iommu/vt-d: Assign devtlb cache tag on ATS enablement
  iommu/rockchip: prevent iommus dead loop when two masters share one IOMMU
```

**Diff:**
```diff
diff --git a/drivers/iommu/intel/cache.c b/drivers/iommu/intel/cache.c
index fc35cba59145..47692cbfaabd 100644
--- a/drivers/iommu/intel/cache.c
+++ b/drivers/iommu/intel/cache.c
@@ -40,9 +40,8 @@ static bool cache_tage_match(struct cache_tag *tag, u16 domain_id,
 }
 
 /* Assign a cache tag with specified type to domain. */
-static int cache_tag_assign(struct dmar_domain *domain, u16 did,
-			    struct device *dev, ioasid_t pasid,
-			    enum cache_tag_type type)
+int cache_tag_assign(struct dmar_domain *domain, u16 did, struct device *dev,
+		     ioasid_t pasid, enum cache_tag_type type)
 {
 	struct device_domain_info *info = dev_iommu_priv_get(dev);
 	struct intel_iommu *iommu = info->iommu;
diff --git a/drivers/iommu/intel/iommu.c b/drivers/iommu/intel/iommu.c
index 7aa3932251b2..148b944143b8 100644
--- a/drivers/iommu/intel/iommu.c
+++ b/drivers/iommu/intel/iommu.c
@@ -3780,8 +3780,17 @@ static void intel_iommu_probe_finalize(struct device *dev)
 	    !pci_enable_pasid(to_pci_dev(dev), info->pasid_supported & ~1))
 		info->pasid_enabled = 1;
 
-	if (sm_supported(iommu) && !dev_is_real_dma_subdevice(dev))
+	if (sm_supported(iommu) && !dev_is_real_dma_subdevice(dev)) {
 		iommu_enable_pci_ats(info);
+		/* Assign a DEVTLB cache tag to the default domain. */
+		if (info->ats_enabled && info->domain) {
+			u16 did = domain_id_iommu(info->domain, iommu);
+
+			if (cache_tag_assign(info->domain, did, dev,
+					     IOMMU_NO_PASID, CACHE_TAG_DEVTLB))
+				iommu_disable_pci_ats(info);
+		}
+	}
 	iommu_enable_pci_pri(info);
 }
 
diff --git a/drivers/iommu/intel/iommu.h b/drivers/iommu/intel/iommu.h
index 3ddbcc603de2..2d1afab5eedc 100644
--- a/drivers/iommu/intel/iommu.h
+++ b/drivers/iommu/intel/iommu.h
@@ -1289,6 +1289,8 @@ struct cache_tag {
 	unsigned int users;
 };
 
+int cache_tag_assign(struct dmar_domain *domain, u16 did, struct device *dev,
+		     ioasid_t pasid, enum cache_tag_type type);
 int cache_tag_assign_domain(struct dmar_domain *domain,

... (truncated 23 lines)
```

---

## Commit 5: 1880df2c

**Author:** Linus Torvalds
**Date:** 2025-07-04 09:33:59
**Files Changed:** drivers/block/brd.c, drivers/block/ublk_drv.c, drivers/nvme/host/core.c, drivers/nvme/host/multipath.c, drivers/nvme/host/pci.c (+1 more)

**Message:**
```
Merge tag 'block-6.16-20250704' of git://git.kernel.dk/linux

Pull block fixes from Jens Axboe:

 - NVMe fixes via Christoph:
     - fix incorrect cdw15 value in passthru error logging (Alok Tiwari)
     - fix memory leak of bio integrity in nvmet (Dmitry Bogdanov)
     - refresh visible attrs after being checked (Eugen Hristev)
     - fix suspicious RCU usage warning in the multipath code (Geliang Tang)
     - correctly account for namespace head reference counter (Nilay Shroff)

 - Fix for a regression introduced in ublk in this cycle, where it would
   attempt to queue a canceled request.

 - brd RCU sleeping fix, also introduced in this cycle. Bare bones fix,
   should be improved upon for the next release.

* tag 'block-6.16-20250704' of git://git.kernel.dk/linux:
  brd: fix sleeping function called from invalid context in brd_insert_page()
  ublk: don't queue request if the associated uring_cmd is canceled
  nvme-multipath: fix suspicious RCU usage warning
  nvme-pci: refresh visible attrs after being checked
  nvmet: fix memory leak of bio integrity
  nvme: correctly account for namespace head reference counter
  nvme: Fix incorrect cdw15 value in passthru error logging
```

**Diff:**
```diff
diff --git a/drivers/block/brd.c b/drivers/block/brd.c
index b1be6c510372..0c2eabe14af3 100644
--- a/drivers/block/brd.c
+++ b/drivers/block/brd.c
@@ -64,13 +64,15 @@ static struct page *brd_insert_page(struct brd_device *brd, sector_t sector,
 
 	rcu_read_unlock();
 	page = alloc_page(gfp | __GFP_ZERO | __GFP_HIGHMEM);
-	rcu_read_lock();
-	if (!page)
+	if (!page) {
+		rcu_read_lock();
 		return ERR_PTR(-ENOMEM);
+	}
 
 	xa_lock(&brd->brd_pages);
 	ret = __xa_cmpxchg(&brd->brd_pages, sector >> PAGE_SECTORS_SHIFT, NULL,
 			page, gfp);
+	rcu_read_lock();
 	if (ret) {
 		xa_unlock(&brd->brd_pages);
 		__free_page(page);
diff --git a/drivers/block/ublk_drv.c b/drivers/block/ublk_drv.c
index c3e3c3b65a6d..9fd284fa76dc 100644
--- a/drivers/block/ublk_drv.c
+++ b/drivers/block/ublk_drv.c
@@ -1442,15 +1442,16 @@ static void ublk_queue_rqs(struct rq_list *rqlist)
 		struct ublk_queue *this_q = req->mq_hctx->driver_data;
 		struct ublk_io *this_io = &this_q->ios[req->tag];
 
+		if (ublk_prep_req(this_q, req, true) != BLK_STS_OK) {
+			rq_list_add_tail(&requeue_list, req);
+			continue;
+		}
+
 		if (io && !ublk_belong_to_same_batch(io, this_io) &&
 				!rq_list_empty(&submit_list))
 			ublk_queue_cmd_list(io, &submit_list);
 		io = this_io;
-
-		if (ublk_prep_req(this_q, req, true) == BLK_STS_OK)
-			rq_list_add_tail(&submit_list, req);
-		else
-			rq_list_add_tail(&requeue_list, req);
+		rq_list_add_tail(&submit_list, req);
 	}
 
 	if (!rq_list_empty(&submit_list))
diff --git a/drivers/nvme/host/core.c b/drivers/nvme/host/core.c
index e533d791955d..7493e5aa984c 100644

... (truncated 121 lines)
```

---

