# Linux Kernel Commit Batch Analysis

## Commit 1: 3f75bfff

**Author:** Linus Torvalds
**Date:** 2025-06-20 22:36:48
**Files Changed:** drivers/mtd/mtdchar.c, drivers/mtd/mtdcore.c, drivers/mtd/mtdcore.h, drivers/mtd/mtdpart.c, drivers/mtd/nand/spi/core.c (+3 more)

**Message:**
```
Merge tag 'mtd/fixes-for-6.16-rc3' of git://git.kernel.org/pub/scm/linux/kernel/git/mtd/linux

Pull mtd fixes from Miquel Raynal:
 "The main fix that really needs to get in is the revert of the patch
  adding the new mtd_master class, because it entirely fails the
  partitioning if a specific Kconfig option is set. We need to think how
  to handle that differently, so let's revert it as we need to get back
  to the pen and paper situation again.

  Otherwise the definition of some Winbond SPI NAND chips are receiving
  some fixes (geometry and maximum frequency, mostly).

  And finally a small memory leak gets also fixed"

* tag 'mtd/fixes-for-6.16-rc3' of git://git.kernel.org/pub/scm/linux/kernel/git/mtd/linux:
  mtd: spinand: fix memory leak of ECC engine conf
  mtd: spinand: winbond: Prevent unsupported frequencies on dual/quad I/O variants
  mtd: spinand: winbond: Increase maximum frequency on an octal operation
  mtd: spinand: winbond: Fix W35N number of planes/LUN
  Revert "mtd: core: always create master device"
```

**Diff:**
```diff
diff --git a/drivers/mtd/mtdchar.c b/drivers/mtd/mtdchar.c
index 391d81ad960c..8dc4f5c493fc 100644
--- a/drivers/mtd/mtdchar.c
+++ b/drivers/mtd/mtdchar.c
@@ -559,7 +559,7 @@ static int mtdchar_blkpg_ioctl(struct mtd_info *mtd,
 		/* Sanitize user input */
 		p.devname[BLKPG_DEVNAMELTH - 1] = '\0';
 
-		return mtd_add_partition(mtd, p.devname, p.start, p.length, NULL);
+		return mtd_add_partition(mtd, p.devname, p.start, p.length);
 
 	case BLKPG_DEL_PARTITION:
 
diff --git a/drivers/mtd/mtdcore.c b/drivers/mtd/mtdcore.c
index 429d8c16baf0..5ba9a741f5ac 100644
--- a/drivers/mtd/mtdcore.c
+++ b/drivers/mtd/mtdcore.c
@@ -68,13 +68,7 @@ static struct class mtd_class = {
 	.pm = MTD_CLS_PM_OPS,
 };
 
-static struct class mtd_master_class = {
-	.name = "mtd_master",
-	.pm = MTD_CLS_PM_OPS,
-};
-
 static DEFINE_IDR(mtd_idr);
-static DEFINE_IDR(mtd_master_idr);
 
 /* These are exported solely for the purpose of mtd_blkdevs.c. You
    should not use them for _anything_ else */
@@ -89,9 +83,8 @@ EXPORT_SYMBOL_GPL(__mtd_next_device);
 
 static LIST_HEAD(mtd_notifiers);
 
-#define MTD_MASTER_DEVS 255
+
 #define MTD_DEVT(index) MKDEV(MTD_CHAR_MAJOR, (index)*2)
-static dev_t mtd_master_devt;
 
 /* REVISIT once MTD uses the driver model better, whoever allocates
  * the mtd_info will probably want to use the release() hook...
@@ -111,17 +104,6 @@ static void mtd_release(struct device *dev)
 	device_destroy(&mtd_class, index + 1);
 }
 
-static void mtd_master_release(struct device *dev)
-{
-	struct mtd_info *mtd = dev_get_drvdata(dev);
-

... (truncated 472 lines)
```

---

## Commit 2: a765b9e6

**Author:** Linus Torvalds
**Date:** 2025-06-20 22:34:52
**Files Changed:** drivers/scsi/elx/efct/efct_hw.c, drivers/target/target_core_pr.c

**Message:**
```
Merge tag 'scsi-fixes' of git://git.kernel.org/pub/scm/linux/kernel/git/jejb/scsi

Pull SCSI fixes from James Bottomley:
 "Two small and obvious driver fixes"

* tag 'scsi-fixes' of git://git.kernel.org/pub/scm/linux/kernel/git/jejb/scsi:
  scsi: elx: efct: Fix memory leak in efct_hw_parse_filter()
  scsi: target: Fix NULL pointer dereference in core_scsi3_decode_spec_i_port()
```

**Diff:**
```diff
diff --git a/drivers/scsi/elx/efct/efct_hw.c b/drivers/scsi/elx/efct/efct_hw.c
index 5a5525054d71..5b079b8b7a08 100644
--- a/drivers/scsi/elx/efct/efct_hw.c
+++ b/drivers/scsi/elx/efct/efct_hw.c
@@ -1120,7 +1120,7 @@ int
 efct_hw_parse_filter(struct efct_hw *hw, void *value)
 {
 	int rc = 0;
-	char *p = NULL;
+	char *p = NULL, *pp = NULL;
 	char *token;
 	u32 idx = 0;
 
@@ -1132,6 +1132,7 @@ efct_hw_parse_filter(struct efct_hw *hw, void *value)
 		efc_log_err(hw->os, "p is NULL\n");
 		return -ENOMEM;
 	}
+	pp = p;
 
 	idx = 0;
 	while ((token = strsep(&p, ",")) && *token) {
@@ -1144,7 +1145,7 @@ efct_hw_parse_filter(struct efct_hw *hw, void *value)
 		if (idx == ARRAY_SIZE(hw->config.filter_def))
 			break;
 	}
-	kfree(p);
+	kfree(pp);
 
 	return rc;
 }
diff --git a/drivers/target/target_core_pr.c b/drivers/target/target_core_pr.c
index 34cf2c399b39..70905805cb17 100644
--- a/drivers/target/target_core_pr.c
+++ b/drivers/target/target_core_pr.c
@@ -1842,7 +1842,9 @@ core_scsi3_decode_spec_i_port(
 		}
 
 		kmem_cache_free(t10_pr_reg_cache, dest_pr_reg);
-		core_scsi3_lunacl_undepend_item(dest_se_deve);
+
+		if (dest_se_deve)
+			core_scsi3_lunacl_undepend_item(dest_se_deve);
 
 		if (is_local)
 			continue;
```

---

## Commit 3: 33b6a1f1

**Author:** Uladzislau Rezki (Sony)
**Date:** 2025-06-20 15:31:48
**Files Changed:** kernel/rcu/tree.c

**Message:**
```
rcu: Return early if callback is not specified

Currently the call_rcu() API does not check whether a callback
pointer is NULL. If NULL is passed, rcu_core() will try to invoke
it, resulting in NULL pointer dereference and a kernel crash.

To prevent this and improve debuggability, this patch adds a check
for NULL and emits a kernel stack trace to help identify a faulty
caller.

Signed-off-by: Uladzislau Rezki (Sony) <urezki@gmail.com>
Reviewed-by: Joel Fernandes <joelagnelf@nvidia.com>
Signed-off-by: Joel Fernandes <joelagnelf@nvidia.com>
```

**Diff:**
```diff
diff --git a/kernel/rcu/tree.c b/kernel/rcu/tree.c
index e8a4b720d7d2..14d4499c6fc3 100644
--- a/kernel/rcu/tree.c
+++ b/kernel/rcu/tree.c
@@ -3072,6 +3072,10 @@ __call_rcu_common(struct rcu_head *head, rcu_callback_t func, bool lazy_in)
 	/* Misaligned rcu_head! */
 	WARN_ON_ONCE((unsigned long)head & (sizeof(void *) - 1));
 
+	/* Avoid NULL dereference if callback is NULL. */
+	if (WARN_ON_ONCE(!func))
+		return;
+
 	if (debug_rcu_head_queue(head)) {
 		/*
 		 * Probable double call_rcu(), so leak the callback.
```

---

## Commit 4: 11313e2f

**Author:** Linus Torvalds
**Date:** 2025-06-20 10:07:56
**Files Changed:** drivers/gpio/gpio-loongson-64bit.c, drivers/gpio/gpio-mlxbf3.c, drivers/gpio/gpio-pca953x.c, drivers/gpio/gpio-spacemit-k1.c

**Message:**
```
Merge tag 'gpio-fixes-for-v6.16-rc3' of git://git.kernel.org/pub/scm/linux/kernel/git/brgl/linux

Pull gpio fixes from Bartosz Golaszewski:

 - correct the ACPI GPIO access mode in gpio-loongson-64bit

 - only obtain the interrupt for a single instance of the chip
   controlled by gpio-mlxbf3

 - fix an invalid value return from probe() in gpio-pca953x

 - add missing MODULE_DEVICE_TABLE() to gpio-spacemit

 - update the HiSilicon GPIO driver maintainer entry

* tag 'gpio-fixes-for-v6.16-rc3' of git://git.kernel.org/pub/scm/linux/kernel/git/brgl/linux:
  gpio: mlxbf3: only get IRQ for device instance 0
  gpio: pca953x: fix wrong error probe return value
  gpio: spacemit: Add missing MODULE_DEVICE_TABLE
  gpio: loongson-64bit: Correct Loongson-7A2000 ACPI GPIO access mode
  MAINTAINERS: Update HiSilicon GPIO driver maintainer
```

**Diff:**
```diff
diff --git a/MAINTAINERS b/MAINTAINERS
index f584e170cfc3..c3f7fbd0d67a 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -10839,7 +10839,7 @@ S:	Maintained
 F:	drivers/dma/hisi_dma.c
 
 HISILICON GPIO DRIVER
-M:	Jay Fang <f.fangjian@huawei.com>
+M:	Yang Shen <shenyang39@huawei.com>
 L:	linux-gpio@vger.kernel.org
 S:	Maintained
 F:	Documentation/devicetree/bindings/gpio/hisilicon,ascend910-gpio.yaml
diff --git a/drivers/gpio/gpio-loongson-64bit.c b/drivers/gpio/gpio-loongson-64bit.c
index 26227669f026..70a01c5b8ad1 100644
--- a/drivers/gpio/gpio-loongson-64bit.c
+++ b/drivers/gpio/gpio-loongson-64bit.c
@@ -268,7 +268,7 @@ static const struct loongson_gpio_chip_data loongson_gpio_ls7a2000_data0 = {
 /* LS7A2000 ACPI GPIO */
 static const struct loongson_gpio_chip_data loongson_gpio_ls7a2000_data1 = {
 	.label = "ls7a2000_gpio",
-	.mode = BYTE_CTRL_MODE,
+	.mode = BIT_CTRL_MODE,
 	.conf_offset = 0x4,
 	.in_offset = 0x8,
 	.out_offset = 0x0,
diff --git a/drivers/gpio/gpio-mlxbf3.c b/drivers/gpio/gpio-mlxbf3.c
index 10ea71273c89..9875e34bde72 100644
--- a/drivers/gpio/gpio-mlxbf3.c
+++ b/drivers/gpio/gpio-mlxbf3.c
@@ -190,7 +190,9 @@ static int mlxbf3_gpio_probe(struct platform_device *pdev)
 	struct mlxbf3_gpio_context *gs;
 	struct gpio_irq_chip *girq;
 	struct gpio_chip *gc;
+	char *colon_ptr;
 	int ret, irq;
+	long num;
 
 	gs = devm_kzalloc(dev, sizeof(*gs), GFP_KERNEL);
 	if (!gs)
@@ -227,25 +229,39 @@ static int mlxbf3_gpio_probe(struct platform_device *pdev)
 	gc->owner = THIS_MODULE;
 	gc->add_pin_ranges = mlxbf3_gpio_add_pin_ranges;
 
-	irq = platform_get_irq(pdev, 0);
-	if (irq >= 0) {
-		girq = &gs->gc.irq;
-		gpio_irq_chip_set_chip(girq, &gpio_mlxbf3_irqchip);
-		girq->default_type = IRQ_TYPE_NONE;
-		/* This will let us handle the parent IRQ in the driver */

... (truncated 74 lines)
```

---

## Commit 5: 299f489f

**Author:** Linus Torvalds
**Date:** 2025-06-20 09:59:20
**Files Changed:** sound/isa/sb/sb16_main.c, sound/pci/ctxfi/xfi.c, sound/pci/hda/hda_intel.c, sound/pci/hda/patch_realtek.c, sound/soc/amd/yc/acp6x-mach.c (+12 more)

**Message:**
```
Merge tag 'sound-6.16-rc3' of git://git.kernel.org/pub/scm/linux/kernel/git/tiwai/sound

Pull sound fixes from Takashi Iwai:
 "A collection of small fixes. All changes are device-specific at this
  time:

   - Fixes for Cirrus codecs with SoundWire, including firmware name
     updates

   - Fix for i.MX8 SoC DSP

   - Usual HD-audio, USB-audio, and ASoC AMD quirks

   - Fixes for legendary SoundBlaster AWE32 ISA device (a real one, we
     still got a bug report after 25 years)

   - Minor build fixes"

* tag 'sound-6.16-rc3' of git://git.kernel.org/pub/scm/linux/kernel/git/tiwai/sound: (24 commits)
  ALSA: hda/realtek: Enable headset Mic on Positivo P15X
  ASoC: Intel: sof-function-topology-lib: Print out the unsupported dmic count
  ASoC: doc: cs35l56: Add CS35L63 to the list of supported devices
  ASoC: SOF: imx8: add core shutdown operation for imx8/imx8x
  ALSA: hda/realtek: Add quirk for Asus GA605K
  ALSA: hda/realtek: enable headset mic on Latitude 5420 Rugged
  ASoC: amd: yc: update quirk data for HP Victus
  ASoC: apple: mca: Drop default ARCH_APPLE in Kconfig
  ALSA: usb-audio: Rename ALSA kcontrol PCM and PCM1 for the KTMicro sound card
  ASoC: amd: yc: Add quirk for MSI Bravo 17 D7VF internal mic
  ASoC: doc: cs35l56: Update to add new SoundWire firmware filename suffix
  ASoC: cs35l56: Use SoundWire address as alternate firmware suffix on L56 B0
  ASoC: cs35l56: Use SoundWire address as firmware name suffix for new silicon
  ASoC: sdw_utils: Fix potential NULL pointer deref in is_sdca_endpoint_present()
  ALSA: sb: Force to disable DMAs once when DMA mode is changed
  ALSA: sb: Don't allow changing the DMA mode during operations
  ALSA: hda/realtek: Add quirk for Asus GU605C
  ALSA: hda/realtek: Fix built-in mic on ASUS VivoBook X513EA
  ALSA: hda/realtek - Add mute LED support for HP Victus 16-s1xxx and HP Victus 15-fa1xxx
  ALSA: ctxfi: Replace deprecated strcpy() with strscpy()
  ...
```

**Diff:**
```diff
diff --git a/Documentation/sound/codecs/cs35l56.rst b/Documentation/sound/codecs/cs35l56.rst
index 98c6f6c74394..57d1964453e1 100644
--- a/Documentation/sound/codecs/cs35l56.rst
+++ b/Documentation/sound/codecs/cs35l56.rst
@@ -1,8 +1,8 @@
 .. SPDX-License-Identifier: GPL-2.0-only
 
-=====================================================================
-Audio drivers for Cirrus Logic CS35L54/56/57 Boosted Smart Amplifiers
-=====================================================================
+========================================================================
+Audio drivers for Cirrus Logic CS35L54/56/57/63 Boosted Smart Amplifiers
+========================================================================
 :Copyright: 2025 Cirrus Logic, Inc. and
                  Cirrus Logic International Semiconductor Ltd.
 
@@ -13,11 +13,11 @@ Summary
 
 The high-level summary of this document is:
 
-**If you have a laptop that uses CS35L54/56/57 amplifiers but audio is not
+**If you have a laptop that uses CS35L54/56/57/63 amplifiers but audio is not
 working, DO NOT ATTEMPT TO USE FIRMWARE AND SETTINGS FROM ANOTHER LAPTOP,
 EVEN IF THAT LAPTOP SEEMS SIMILAR.**
 
-The CS35L54/56/57 amplifiers must be correctly configured for the power
+The CS35L54/56/57/63 amplifiers must be correctly configured for the power
 supply voltage, speaker impedance, maximum speaker voltage/current, and
 other external hardware connections.
 
@@ -34,6 +34,7 @@ The cs35l56 drivers support:
 * CS35L54
 * CS35L56
 * CS35L57
+* CS35L63
 
 There are two drivers in the kernel
 
@@ -104,6 +105,13 @@ In this example the SSID is 10280c63.
 
 The format of the firmware file names is:
 
+SoundWire (except CS35L56 Rev B0):
+    cs35lxx-b0-dsp1-misc-SSID[-spkidX]-l?u?
+
+SoundWire CS35L56 Rev B0:
+    cs35lxx-b0-dsp1-misc-SSID[-spkidX]-ampN
+
+Non-SoundWire (HDA and I2S):
     cs35lxx-b0-dsp1-misc-SSID[-spkidX]-ampN

... (truncated 626 lines)
```

---

