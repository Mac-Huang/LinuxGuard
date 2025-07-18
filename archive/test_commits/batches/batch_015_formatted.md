# Linux Kernel Commit Batch Analysis

## Commit 1: 25b1b75b

**Author:** Lu Baolu
**Date:** 2025-07-04 10:33:56
**Files Changed:** drivers/iommu/intel/cache.c, drivers/iommu/intel/iommu.c, drivers/iommu/intel/iommu.h

**Message:**
```
iommu/vt-d: Assign devtlb cache tag on ATS enablement

Commit <4f1492efb495> ("iommu/vt-d: Revert ATS timing change to fix boot
failure") placed the enabling of ATS in the probe_finalize callback. This
occurs after the default domain attachment, which is when the ATS cache
tag is assigned. Consequently, the device TLB cache tag is missed when the
domain is attached, leading to the device TLB not being invalidated in the
iommu_unmap paths.

Fix this by assigning the CACHE_TAG_DEVTLB cache tag when ATS is enabled.

Fixes: 4f1492efb495 ("iommu/vt-d: Revert ATS timing change to fix boot failure")
Cc: stable@vger.kernel.org
Suggested-by: Kevin Tian <kevin.tian@intel.com>
Signed-off-by: Lu Baolu <baolu.lu@linux.intel.com>
Tested-by: Shuicheng Lin <shuicheng.lin@intel.com>
Reviewed-by: Kevin Tian <kevin.tian@intel.com>
Link: https://lore.kernel.org/r/20250625050135.3129955-1-baolu.lu@linux.intel.com
Link: https://lore.kernel.org/r/20250628100351.3198955-2-baolu.lu@linux.intel.com
Signed-off-by: Joerg Roedel <joerg.roedel@amd.com>
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

... (truncated 2 lines)
```

---

## Commit 2: 30e0fd3c

**Author:** Hugo Villeneuve
**Date:** 2025-07-04 10:24:03
**Files Changed:** drivers/gpio/gpiolib.c

**Message:**
```
gpiolib: fix performance regression when using gpio_chip_get_multiple()

commit 74abd086d2ee ("gpiolib: sanitize the return value of
gpio_chip::get_multiple()") altered the value returned by
gc->get_multiple() in case it is positive (> 0), but failed to return
for other cases (<= 0).

This may result in the "if (gc->get)" block being executed and thus
negates the performance gain that is normally obtained by using
gc->get_multiple().

Fix by returning the result of gc->get_multiple() if it is <= 0.

Also move the "ret" variable to the scope where it is used, which as an
added bonus fixes an indentation error introduced by the aforementioned
commit.

Fixes: 74abd086d2ee ("gpiolib: sanitize the return value of gpio_chip::get_multiple()")
Cc: stable@vger.kernel.org
Signed-off-by: Hugo Villeneuve <hvilleneuve@dimonoff.com>
Link: https://lore.kernel.org/r/20250703191829.2952986-1-hugo@hugovil.com
Signed-off-by: Bartosz Golaszewski <bartosz.golaszewski@linaro.org>
```

**Diff:**
```diff
diff --git a/drivers/gpio/gpiolib.c b/drivers/gpio/gpiolib.c
index fdafa0df1b43..3a3eca5b4c40 100644
--- a/drivers/gpio/gpiolib.c
+++ b/drivers/gpio/gpiolib.c
@@ -3297,14 +3297,15 @@ static int gpiod_get_raw_value_commit(const struct gpio_desc *desc)
 static int gpio_chip_get_multiple(struct gpio_chip *gc,
 				  unsigned long *mask, unsigned long *bits)
 {
-	int ret;
-	
 	lockdep_assert_held(&gc->gpiodev->srcu);
 
 	if (gc->get_multiple) {
+		int ret;
+
 		ret = gc->get_multiple(gc, mask, bits);
 		if (ret > 0)
 			return -EBADE;
+		return ret;
 	}
 
 	if (gc->get) {
```

---

## Commit 3: 043faef3

**Author:** Thorsten Blum
**Date:** 2025-07-04 09:04:12
**Files Changed:** sound/isa/ad1816a/ad1816a.c

**Message:**
```
ALSA: ad1816a: Fix potential NULL pointer deref in snd_card_ad1816a_pnp()

Use pr_warn() instead of dev_warn() when 'pdev' is NULL to avoid a
potential NULL pointer dereference.

Cc: stable@vger.kernel.org
Fixes: 20869176d7a7 ("ALSA: ad1816a: Use standard print API")
Signed-off-by: Thorsten Blum <thorsten.blum@linux.dev>
Link: https://patch.msgid.link/20250703200616.304309-2-thorsten.blum@linux.dev
Signed-off-by: Takashi Iwai <tiwai@suse.de>
```

**Diff:**
```diff
diff --git a/sound/isa/ad1816a/ad1816a.c b/sound/isa/ad1816a/ad1816a.c
index 99006dc4777e..5c9e2d41d900 100644
--- a/sound/isa/ad1816a/ad1816a.c
+++ b/sound/isa/ad1816a/ad1816a.c
@@ -98,7 +98,7 @@ static int snd_card_ad1816a_pnp(int dev, struct pnp_card_link *card,
 	pdev = pnp_request_card_device(card, id->devs[1].id, NULL);
 	if (pdev == NULL) {
 		mpu_port[dev] = -1;
-		dev_warn(&pdev->dev, "MPU401 device busy, skipping.\n");
+		pr_warn("MPU401 device busy, skipping.\n");
 		return 0;
 	}
 
```

---

## Commit 4: 4cf65845

**Author:** Yunshui Jiang
**Date:** 2025-07-03 22:20:46
**Files Changed:** drivers/input/misc/cs40l50-vibra.c

**Message:**
```
Input: cs40l50-vibra - fix potential NULL dereference in cs40l50_upload_owt()

The cs40l50_upload_owt() function allocates memory via kmalloc()
without checking for allocation failure, which could lead to a
NULL pointer dereference.

Return -ENOMEM in case allocation fails.

Signed-off-by: Yunshui Jiang <jiangyunshui@kylinos.cn>
Fixes: c38fe1bb5d21 ("Input: cs40l50 - Add support for the CS40L50 haptic driver")
Link: https://lore.kernel.org/r/20250704024010.2353841-1-jiangyunshui@kylinos.cn
Cc: stable@vger.kernel.org
Signed-off-by: Dmitry Torokhov <dmitry.torokhov@gmail.com>
```

**Diff:**
```diff
diff --git a/drivers/input/misc/cs40l50-vibra.c b/drivers/input/misc/cs40l50-vibra.c
index dce3b0ec8cf3..330f09123631 100644
--- a/drivers/input/misc/cs40l50-vibra.c
+++ b/drivers/input/misc/cs40l50-vibra.c
@@ -238,6 +238,8 @@ static int cs40l50_upload_owt(struct cs40l50_work *work_data)
 	header.data_words = len / sizeof(u32);
 
 	new_owt_effect_data = kmalloc(sizeof(header) + len, GFP_KERNEL);
+	if (!new_owt_effect_data)
+		return -ENOMEM;
 
 	memcpy(new_owt_effect_data, &header, sizeof(header));
 	memcpy(new_owt_effect_data + sizeof(header), work_data->custom_data, len);
```

---

## Commit 5: da8d8e90

**Author:** Dave Airlie
**Date:** 2025-07-04 10:01:53
**Files Changed:** drivers/gpu/drm/xe/xe_device.c, drivers/gpu/drm/xe/xe_drv.h, drivers/gpu/drm/xe/xe_guc_pc.c, drivers/gpu/drm/xe/xe_guc_pc.h, drivers/gpu/drm/xe/xe_guc_pc_types.h (+4 more)

**Message:**
```
Merge tag 'drm-xe-fixes-2025-07-03' of https://gitlab.freedesktop.org/drm/xe/kernel into drm-fixes

Driver Changes:
- Fix chunking the PTE updates and overflowing the maximum number of
  dwords with with MI_STORE_DATA_IMM (Jia Yao)
- Move WA BB to the LRC BO to mitigate hangs on context switch (Matthew
  Brost)
- Fix frequency/flush WAs for BMG (Vinay / Lucas)
- Fix kconfig prompt title and description (Lucas)
- Do not require kunit (Harry Austen / Lucas)
- Extend 14018094691 WA to BMG (Daniele)
- Fix wedging the device on signal (Matthew Brost)

Signed-off-by: Dave Airlie <airlied@redhat.com>

From: Lucas De Marchi <lucas.demarchi@intel.com>
Link: https://lore.kernel.org/r/o5662wz6nrlf6xt5sjgxq5oe6qoujefzywuwblm3m626hreifv@foqayqydd6ig
```

**Diff:**
```diff
diff --git a/drivers/gpu/drm/xe/Kconfig b/drivers/gpu/drm/xe/Kconfig
index fcc2677a4229..99a91355842e 100644
--- a/drivers/gpu/drm/xe/Kconfig
+++ b/drivers/gpu/drm/xe/Kconfig
@@ -1,7 +1,8 @@
 # SPDX-License-Identifier: GPL-2.0-only
 config DRM_XE
-	tristate "Intel Xe Graphics"
-	depends on DRM && PCI && (m || (y && KUNIT=y))
+	tristate "Intel Xe2 Graphics"
+	depends on DRM && PCI
+	depends on KUNIT || !KUNIT
 	depends on INTEL_VSEC || !INTEL_VSEC
 	depends on X86_PLATFORM_DEVICES || !(X86 && ACPI)
 	select INTERVAL_TREE
@@ -46,7 +47,8 @@ config DRM_XE
 	select AUXILIARY_BUS
 	select HMM_MIRROR
 	help
-	  Experimental driver for Intel Xe series GPUs
+	  Driver for Intel Xe2 series GPUs and later. Experimental support
+	  for Xe series is also available.
 
 	  If "M" is selected, the module will be called xe.
 
diff --git a/drivers/gpu/drm/xe/xe_device.c b/drivers/gpu/drm/xe/xe_device.c
index c02c4c4e9412..e9f3c1a53db2 100644
--- a/drivers/gpu/drm/xe/xe_device.c
+++ b/drivers/gpu/drm/xe/xe_device.c
@@ -40,6 +40,7 @@
 #include "xe_gt_printk.h"
 #include "xe_gt_sriov_vf.h"
 #include "xe_guc.h"
+#include "xe_guc_pc.h"
 #include "xe_hw_engine_group.h"
 #include "xe_hwmon.h"
 #include "xe_irq.h"
@@ -986,38 +987,15 @@ void xe_device_wmb(struct xe_device *xe)
 		xe_mmio_write32(xe_root_tile_mmio(xe), VF_CAP_REG, 0);
 }
 
-/**
- * xe_device_td_flush() - Flush transient L3 cache entries
- * @xe: The device
- *
- * Display engine has direct access to memory and is never coherent with L3/L4
- * caches (or CPU caches), however KMD is responsible for specifically flushing
- * transient L3 GPU cache entries prior to the flip sequence to ensure scanout
- * can happen from such a surface without seeing corruption.
- *

... (truncated 750 lines)
```

---

