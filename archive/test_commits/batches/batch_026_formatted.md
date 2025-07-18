# Linux Kernel Commit Batch Analysis

## Commit 1: ca46946a

**Author:** Alessandro Carminati
**Date:** 2025-06-29 22:10:41
**Files Changed:** drivers/regulator/core.c

**Message:**
```
regulator: core: fix NULL dereference on unbind due to stale coupling data

Failing to reset coupling_desc.n_coupled after freeing coupled_rdevs can
lead to NULL pointer dereference when regulators are accessed post-unbind.

This can happen during runtime PM or other regulator operations that rely
on coupling metadata.

For example, on ridesx4, unbinding the 'reg-dummy' platform device triggers
a panic in regulator_lock_recursive() due to stale coupling state.

Ensure n_coupled is set to 0 to prevent access to invalid pointers.

Signed-off-by: Alessandro Carminati <acarmina@redhat.com>
Link: https://patch.msgid.link/20250626083809.314842-1-acarmina@redhat.com
Signed-off-by: Mark Brown <broonie@kernel.org>
```

**Diff:**
```diff
diff --git a/drivers/regulator/core.c b/drivers/regulator/core.c
index 7a248dc8d2e2..cbd6d53ebfb5 100644
--- a/drivers/regulator/core.c
+++ b/drivers/regulator/core.c
@@ -5639,6 +5639,7 @@ static void regulator_remove_coupling(struct regulator_dev *rdev)
 				 ERR_PTR(err));
 	}
 
+	rdev->coupling_desc.n_coupled = 0;
 	kfree(rdev->coupling_desc.coupled_rdevs);
 	rdev->coupling_desc.coupled_rdevs = NULL;
 }
```

---

## Commit 2: dc78f7e5

**Author:** Arun Raghavan
**Date:** 2025-06-29 22:10:26
**Files Changed:** sound/soc/fsl/fsl_sai.c

**Message:**
```
ASoC: fsl_sai: Force a software reset when starting in consumer mode

On an imx8mm platform with an external clock provider, when running the
receiver (arecord) and triggering an xrun with xrun_injection, we see a
channel swap/offset. This happens sometimes when running only the
receiver, but occurs reliably if a transmitter (aplay) is also
concurrently running.

It seems that the SAI loses track of frame sync during the trigger stop
-> trigger start cycle that occurs during an xrun. Doing just a FIFO
reset in this case does not suffice, and only a software reset seems to
get it back on track.

This looks like the same h/w bug that is already handled for the
producer case, so we now do the reset unconditionally on config disable.

Signed-off-by: Arun Raghavan <arun@asymptotic.io>
Reported-by: Pieterjan Camerlynck <p.camerlynck@televic.com>
Fixes: 3e3f8bd56955 ("ASoC: fsl_sai: fix no frame clk in master mode")
Cc: stable@vger.kernel.org
Reviewed-by: Fabio Estevam <festevam@gmail.com>
Link: https://patch.msgid.link/20250626130858.163825-1-arun@arunraghavan.net
Signed-off-by: Mark Brown <broonie@kernel.org>
```

**Diff:**
```diff
diff --git a/sound/soc/fsl/fsl_sai.c b/sound/soc/fsl/fsl_sai.c
index af1a168d35e3..50af6b725670 100644
--- a/sound/soc/fsl/fsl_sai.c
+++ b/sound/soc/fsl/fsl_sai.c
@@ -803,13 +803,15 @@ static void fsl_sai_config_disable(struct fsl_sai *sai, int dir)
 	 * anymore. Add software reset to fix this issue.
 	 * This is a hardware bug, and will be fix in the
 	 * next sai version.
+	 *
+	 * In consumer mode, this can happen even after a
+	 * single open/close, especially if both tx and rx
+	 * are running concurrently.
 	 */
-	if (!sai->is_consumer_mode[tx]) {
-		/* Software Reset */
-		regmap_write(sai->regmap, FSL_SAI_xCSR(tx, ofs), FSL_SAI_CSR_SR);
-		/* Clear SR bit to finish the reset */
-		regmap_write(sai->regmap, FSL_SAI_xCSR(tx, ofs), 0);
-	}
+	/* Software Reset */
+	regmap_write(sai->regmap, FSL_SAI_xCSR(tx, ofs), FSL_SAI_CSR_SR);
+	/* Clear SR bit to finish the reset */
+	regmap_write(sai->regmap, FSL_SAI_xCSR(tx, ofs), 0);
 }
 
 static int fsl_sai_trigger(struct snd_pcm_substream *substream, int cmd,
```

---

## Commit 3: b846350a

**Author:** Kaustabh Chakraborty
**Date:** 2025-06-29 16:58:16
**Files Changed:** drivers/gpu/drm/exynos/exynos7_drm_decon.c

**Message:**
```
drm/exynos: exynos7_drm_decon: add vblank check in IRQ handling

If there's support for another console device (such as a TTY serial),
the kernel occasionally panics during boot. The panic message and a
relevant snippet of the call stack is as follows:

  Unable to handle kernel NULL pointer dereference at virtual address 000000000000000
  Call trace:
    drm_crtc_handle_vblank+0x10/0x30 (P)
    decon_irq_handler+0x88/0xb4
    [...]

Otherwise, the panics don't happen. This indicates that it's some sort
of race condition.

Add a check to validate if the drm device can handle vblanks before
calling drm_crtc_handle_vblank() to avoid this.

Cc: stable@vger.kernel.org
Fixes: 96976c3d9aff ("drm/exynos: Add DECON driver")
Signed-off-by: Kaustabh Chakraborty <kauschluss@disroot.org>
Signed-off-by: Inki Dae <inki.dae@samsung.com>
```

**Diff:**
```diff
diff --git a/drivers/gpu/drm/exynos/exynos7_drm_decon.c b/drivers/gpu/drm/exynos/exynos7_drm_decon.c
index f91daefa9d2b..805aa28c1723 100644
--- a/drivers/gpu/drm/exynos/exynos7_drm_decon.c
+++ b/drivers/gpu/drm/exynos/exynos7_drm_decon.c
@@ -636,6 +636,10 @@ static irqreturn_t decon_irq_handler(int irq, void *dev_id)
 	if (!ctx->drm_dev)
 		goto out;
 
+	/* check if crtc and vblank have been initialized properly */
+	if (!drm_dev_has_vblank(ctx->drm_dev))
+		goto out;
+
 	if (!ctx->i80_if) {
 		drm_crtc_handle_vblank(&ctx->crtc->base);
 
```

---

## Commit 4: dfba48a7

**Author:** Linus Torvalds
**Date:** 2025-06-28 15:23:17
**Files Changed:** drivers/i2c/busses/i2c-designware-amdisp.c, drivers/i2c/busses/i2c-designware-master.c, drivers/i2c/busses/i2c-imx.c, drivers/i2c/busses/i2c-omap.c, drivers/i2c/busses/i2c-robotfuzz-osif.c (+3 more)

**Message:**
```
Merge tag 'i2c-for-6.16-rc4' of git://git.kernel.org/pub/scm/linux/kernel/git/wsa/linux

Pull i2c fixes from Wolfram Sang:

 - imx: fix SMBus protocol compliance during block read

 - omap: fix error handling path in probe

 - robotfuzz, tiny-usb: prevent zero-length reads

 - x86, designware, amdisp: fix build error when modules are disabled
   (agreed to go in via i2c)

 - scx200_acb: fix build error because of missing HAS_IOPORT

* tag 'i2c-for-6.16-rc4' of git://git.kernel.org/pub/scm/linux/kernel/git/wsa/linux:
  i2c: scx200_acb: depends on HAS_IOPORT
  i2c: omap: Fix an error handling path in omap_i2c_probe()
  platform/x86: Use i2c adapter name to fix build errors
  i2c: amd-isp: Initialize unique adapter name
  i2c: designware: Initialize adapter name only when not set
  i2c: tiny-usb: disable zero-length read messages
  i2c: robotfuzz-osif: disable zero-length read messages
  i2c: imx: fix emulated smbus block read
```

**Diff:**
```diff
diff --git a/MAINTAINERS b/MAINTAINERS
index 7aff9b0ead32..4bac4ea21b64 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -24099,6 +24099,7 @@ M:	Bin Du <bin.du@amd.com>
 L:	linux-i2c@vger.kernel.org
 S:	Maintained
 F:	drivers/i2c/busses/i2c-designware-amdisp.c
+F:	include/linux/soc/amd/isp4_misc.h
 
 SYNOPSYS DESIGNWARE MMC/SD/SDIO DRIVER
 M:	Jaehoon Chung <jh80.chung@samsung.com>
diff --git a/drivers/i2c/busses/Kconfig b/drivers/i2c/busses/Kconfig
index 48c5ab832009..0a4ecccd1851 100644
--- a/drivers/i2c/busses/Kconfig
+++ b/drivers/i2c/busses/Kconfig
@@ -1530,7 +1530,7 @@ config I2C_XGENE_SLIMPRO
 
 config SCx200_ACB
 	tristate "Geode ACCESS.bus support"
-	depends on X86_32 && PCI
+	depends on X86_32 && PCI && HAS_IOPORT
 	help
 	  Enable the use of the ACCESS.bus controllers on the Geode SCx200 and
 	  SC1100 processors and the CS5535 and CS5536 Geode companion devices.
diff --git a/drivers/i2c/busses/i2c-designware-amdisp.c b/drivers/i2c/busses/i2c-designware-amdisp.c
index ad6f08338124..450793d5f839 100644
--- a/drivers/i2c/busses/i2c-designware-amdisp.c
+++ b/drivers/i2c/busses/i2c-designware-amdisp.c
@@ -8,6 +8,7 @@
 #include <linux/module.h>
 #include <linux/platform_device.h>
 #include <linux/pm_runtime.h>
+#include <linux/soc/amd/isp4_misc.h>
 
 #include "i2c-designware-core.h"
 
@@ -62,6 +63,7 @@ static int amd_isp_dw_i2c_plat_probe(struct platform_device *pdev)
 
 	adap = &isp_i2c_dev->adapter;
 	adap->owner = THIS_MODULE;
+	scnprintf(adap->name, sizeof(adap->name), AMDISP_I2C_ADAP_NAME);
 	ACPI_COMPANION_SET(&adap->dev, ACPI_COMPANION(&pdev->dev));
 	adap->dev.of_node = pdev->dev.of_node;
 	/* use dynamically allocated adapter id */
diff --git a/drivers/i2c/busses/i2c-designware-master.c b/drivers/i2c/busses/i2c-designware-master.c
index c5394229b77f..9d7d9e47564a 100644
--- a/drivers/i2c/busses/i2c-designware-master.c
+++ b/drivers/i2c/busses/i2c-designware-master.c
@@ -1042,8 +1042,9 @@ int i2c_dw_probe_master(struct dw_i2c_dev *dev)

... (truncated 149 lines)
```

---

## Commit 5: ded77901

**Author:** Linus Torvalds
**Date:** 2025-06-28 11:39:24
**Files Changed:** kernel/trace/trace_events_filter.c

**Message:**
```
Merge tag 'trace-v6.16-rc3' of git://git.kernel.org/pub/scm/linux/kernel/git/trace/linux-trace

Pull tracing fix from Steven Rostedt:

 - Fix possible UAF on error path in filter_free_subsystem_filters()

   When freeing a subsystem filter, the filter for the subsystem is
   passed in to be freed and all the events within the subsystem will
   have their filter freed too. In order to free without waiting for RCU
   synchronization, list items are allocated to hold what is going to be
   freed to free it via a call_rcu(). If the allocation of these items
   fails, it will call the synchronization directly and free after that
   (causing a bit of delay for the user).

   The subsystem filter is first added to this list and then the filters
   for all the events under the subsystem. The bug is if one of the
   allocations of the list items for the event filters fail to allocate,
   it jumps to the "free_now" label which will free the subsystem
   filter, then all the items on the allocated list, and then the event
   filters that were not added to the list yet. But because the
   subsystem filter was added first, it gets freed twice.

   The solution is to add the subsystem filter after the events, and
   then if any of the allocations fail it will not try to free any of
   them twice

* tag 'trace-v6.16-rc3' of git://git.kernel.org/pub/scm/linux/kernel/git/trace/linux-trace:
  tracing: Fix filter logic error
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

