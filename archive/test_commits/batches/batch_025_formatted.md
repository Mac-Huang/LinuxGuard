# Linux Kernel Commit Batch Analysis

## Commit 1: 7da6c155

**Author:** Hans de Goede
**Date:** 2025-06-30 08:12:36
**Files Changed:** drivers/gpu/drm/i915/display/vlv_dsi.c

**Message:**
```
drm/i915/dsi: Fix NULL pointer deref in vlv_dphy_param_init()

Commit 77ba0b856225 ("drm/i915/dsi: convert vlv_dsi.[ch] to struct
intel_display") added a to_intel_display(connector) call to
vlv_dphy_param_init() but when vlv_dphy_param_init() gets called
the connector object has not been initialized yet, so this leads
to a NULL pointer deref:

 BUG: kernel NULL pointer dereference, address: 000000000000000c
 ...
 Hardware name: ASUSTeK COMPUTER INC. T100TA/T100TA, BIOS T100TA.314 08/13/2015
 RIP: 0010:vlv_dsi_init+0x4e6/0x1600 [i915]
 ...
 Call Trace:
  <TASK>
  ? intel_step_name+0x4be8/0x5c30 [i915]
  intel_setup_outputs+0x2d6/0xbd0 [i915]
  intel_display_driver_probe_nogem+0x13f/0x220 [i915]
  i915_driver_probe+0x3d9/0xaf0 [i915]

Use to_intel_display(&intel_dsi->base) instead to fix this.

Fixes: 77ba0b856225 ("drm/i915/dsi: convert vlv_dsi.[ch] to struct intel_display")
Signed-off-by: Hans de Goede <hansg@kernel.org>
Reviewed-by: Jani Nikula <jani.nikula@intel.com>
Link: https://lore.kernel.org/r/20250626143317.101706-1-hansg@kernel.org
Signed-off-by: Jani Nikula <jani.nikula@intel.com>
(cherry picked from commit 0dc6bfb50a5d0759e726cd36a3d3b7529fd2a627)
Signed-off-by: Joonas Lahtinen <joonas.lahtinen@linux.intel.com>
```

**Diff:**
```diff
diff --git a/drivers/gpu/drm/i915/display/vlv_dsi.c b/drivers/gpu/drm/i915/display/vlv_dsi.c
index 21c1e10caf68..2007bb9d974d 100644
--- a/drivers/gpu/drm/i915/display/vlv_dsi.c
+++ b/drivers/gpu/drm/i915/display/vlv_dsi.c
@@ -1589,8 +1589,8 @@ static void vlv_dsi_add_properties(struct intel_connector *connector)
 
 static void vlv_dphy_param_init(struct intel_dsi *intel_dsi)
 {
+	struct intel_display *display = to_intel_display(&intel_dsi->base);
 	struct intel_connector *connector = intel_dsi->attached_connector;
-	struct intel_display *display = to_intel_display(connector);
 	struct mipi_config *mipi_config = connector->panel.vbt.dsi.config;
 	u32 tlpx_ns, extra_byte_count, tlpx_ui;
 	u32 ui_num, ui_den;
```

---

## Commit 2: caa7c7a7

**Author:** Dan Carpenter
**Date:** 2025-06-30 08:12:33
**Files Changed:** drivers/gpu/drm/i915/selftests/i915_request.c, drivers/gpu/drm/i915/selftests/mock_request.c

**Message:**
```
drm/i915/selftests: Change mock_request() to return error pointers

There was an error pointer vs NULL bug in __igt_breadcrumbs_smoketest().
The __mock_request_alloc() function implements the
smoketest->request_alloc() function pointer.  It was supposed to return
error pointers, but it propogates the NULL return from mock_request()
so in the event of a failure, it would lead to a NULL pointer
dereference.

To fix this, change the mock_request() function to return error pointers
and update all the callers to expect that.

Fixes: 52c0fdb25c7c ("drm/i915: Replace global breadcrumbs with per-context interrupt tracking")
Signed-off-by: Dan Carpenter <dan.carpenter@linaro.org>
Reviewed-by: Rodrigo Vivi <rodrigo.vivi@intel.com>
Link: https://lore.kernel.org/r/685c1417.050a0220.696f5.5c05@mx.google.com
Signed-off-by: Rodrigo Vivi <rodrigo.vivi@intel.com>
(cherry picked from commit 778fa8ad5f0f23397d045c7ebca048ce8def1c43)
Signed-off-by: Joonas Lahtinen <joonas.lahtinen@linux.intel.com>
```

**Diff:**
```diff
diff --git a/drivers/gpu/drm/i915/selftests/i915_request.c b/drivers/gpu/drm/i915/selftests/i915_request.c
index 88870844b5bd..2fb7a9e7efec 100644
--- a/drivers/gpu/drm/i915/selftests/i915_request.c
+++ b/drivers/gpu/drm/i915/selftests/i915_request.c
@@ -73,8 +73,8 @@ static int igt_add_request(void *arg)
 	/* Basic preliminary test to create a request and let it loose! */
 
 	request = mock_request(rcs0(i915)->kernel_context, HZ / 10);
-	if (!request)
-		return -ENOMEM;
+	if (IS_ERR(request))
+		return PTR_ERR(request);
 
 	i915_request_add(request);
 
@@ -91,8 +91,8 @@ static int igt_wait_request(void *arg)
 	/* Submit a request, then wait upon it */
 
 	request = mock_request(rcs0(i915)->kernel_context, T);
-	if (!request)
-		return -ENOMEM;
+	if (IS_ERR(request))
+		return PTR_ERR(request);
 
 	i915_request_get(request);
 
@@ -160,8 +160,8 @@ static int igt_fence_wait(void *arg)
 	/* Submit a request, treat it as a fence and wait upon it */
 
 	request = mock_request(rcs0(i915)->kernel_context, T);
-	if (!request)
-		return -ENOMEM;
+	if (IS_ERR(request))
+		return PTR_ERR(request);
 
 	if (dma_fence_wait_timeout(&request->fence, false, T) != -ETIME) {
 		pr_err("fence wait success before submit (expected timeout)!\n");
@@ -219,8 +219,8 @@ static int igt_request_rewind(void *arg)
 	GEM_BUG_ON(IS_ERR(ce));
 	request = mock_request(ce, 2 * HZ);
 	intel_context_put(ce);
-	if (!request) {
-		err = -ENOMEM;
+	if (IS_ERR(request)) {
+		err = PTR_ERR(request);
 		goto err_context_0;
 	}
 
@@ -237,8 +237,8 @@ static int igt_request_rewind(void *arg)
 	GEM_BUG_ON(IS_ERR(ce));

... (truncated 22 lines)
```

---

## Commit 3: fa60c094

**Author:** James Clark
**Date:** 2025-06-29 22:10:53
**Files Changed:** drivers/spi/spi-fsl-dspi.c

**Message:**
```
spi: spi-fsl-dspi: Clear completion counter before initiating transfer

In target mode, extra interrupts can be received between the end of a
transfer and halting the module if the host continues sending more data.
If the interrupt from this occurs after the reinit_completion() then the
completion counter is left at a non-zero value. The next unrelated
transfer initiated by userspace will then complete immediately without
waiting for the interrupt or writing to the RX buffer.

Fix it by resetting the counter before the transfer so that lingering
values are cleared. This is done after clearing the FIFOs and the
status register but before the transfer is initiated, so no interrupts
should be received at this point resulting in other race conditions.

Fixes: 4f5ee75ea171 ("spi: spi-fsl-dspi: Replace interruptible wait queue with a simple completion")
Signed-off-by: James Clark <james.clark@linaro.org>
Reviewed-by: Frank Li <Frank.Li@nxp.com>
Link: https://patch.msgid.link/20250627-james-nxp-spi-dma-v4-1-178dba20c120@linaro.org
Signed-off-by: Mark Brown <broonie@kernel.org>
```

**Diff:**
```diff
diff --git a/drivers/spi/spi-fsl-dspi.c b/drivers/spi/spi-fsl-dspi.c
index 863781ba6c16..0dcd49114095 100644
--- a/drivers/spi/spi-fsl-dspi.c
+++ b/drivers/spi/spi-fsl-dspi.c
@@ -983,11 +983,20 @@ static int dspi_transfer_one_message(struct spi_controller *ctlr,
 		if (dspi->devtype_data->trans_mode == DSPI_DMA_MODE) {
 			status = dspi_dma_xfer(dspi);
 		} else {
+			/*
+			 * Reinitialize the completion before transferring data
+			 * to avoid the case where it might remain in the done
+			 * state due to a spurious interrupt from a previous
+			 * transfer. This could falsely signal that the current
+			 * transfer has completed.
+			 */
+			if (dspi->irq)
+				reinit_completion(&dspi->xfer_done);
+
 			dspi_fifo_write(dspi);
 
 			if (dspi->irq) {
 				wait_for_completion(&dspi->xfer_done);
-				reinit_completion(&dspi->xfer_done);
 			} else {
 				do {
 					status = dspi_poll(dspi);
```

---

## Commit 4: d85d0380

**Author:** Gabor Juhos
**Date:** 2025-06-29 22:10:46
**Files Changed:** drivers/spi/spi-qpic-snand.c

**Message:**
```
spi: spi-qpic-snand: reallocate BAM transactions

Using the mtd_nandbiterrs module for testing the driver occasionally
results in weird things like below.

1. swiotlb mapping fails with the following message:

  [   85.926216] qcom_snand 79b0000.spi: swiotlb buffer is full (sz: 4294967294 bytes), total 512 (slots), used 0 (slots)
  [   85.932937] qcom_snand 79b0000.spi: failure in mapping desc
  [   87.999314] qcom_snand 79b0000.spi: failure to write raw page
  [   87.999352] mtd_nandbiterrs: error: write_oob failed (-110)

  Rebooting the board after this causes a panic due to a NULL pointer
  dereference.

2. If the swiotlb mapping does not fail, rebooting the board may result
   in a different panic due to a bad spinlock magic:

  [  256.104459] BUG: spinlock bad magic on CPU#3, procd/2241
  [  256.104488] Unable to handle kernel paging request at virtual address ffffffff0000049b
  ...

Investigating the issue revealed that these symptoms are results of
memory corruption which is caused by out of bounds access within the
driver.

The driver uses a dynamically allocated structure for BAM transactions,
which structure must have enough space for all possible variations of
different flash operations initiated by the driver. The required space
heavily depends on the actual number of 'codewords' which is calculated
from the pagesize of the actual NAND chip.

Although the qcom_nandc_alloc() function allocates memory for the BAM
transactions during probe, but since the actual number of 'codewords'
is not yet know the allocation is done for one 'codeword' only.

Because of this, whenever the driver does a flash operation, and the
number of the required transactions exceeds the size of the allocated
arrays the driver accesses memory out of the allocated range.

To avoid this, change the code to free the initially allocated BAM
transactions memory, and allocate a new one once the actual number of
'codewords' required for a given NAND chip is known.

Fixes: 7304d1909080 ("spi: spi-qpic: add driver for QCOM SPI NAND flash Interface")
Reviewed-by: Md Sadre Alam <quic_mdalam@quicinc.com>
Signed-off-by: Gabor Juhos <j4g8y7@gmail.com>
Link: https://patch.msgid.link/20250618-qpic-snand-avoid-mem-corruption-v3-1-319c71296cda@gmail.com
Signed-off-by: Mark Brown <broonie@kernel.org>
```

**Diff:**
```diff
diff --git a/drivers/spi/spi-qpic-snand.c b/drivers/spi/spi-qpic-snand.c
index 77d9cc65477a..f2e1a27b410d 100644
--- a/drivers/spi/spi-qpic-snand.c
+++ b/drivers/spi/spi-qpic-snand.c
@@ -315,6 +315,22 @@ static int qcom_spi_ecc_init_ctx_pipelined(struct nand_device *nand)
 
 	mtd_set_ooblayout(mtd, &qcom_spi_ooblayout);
 
+	/*
+	 * Free the temporary BAM transaction allocated initially by
+	 * qcom_nandc_alloc(), and allocate a new one based on the
+	 * updated max_cwperpage value.
+	 */
+	qcom_free_bam_transaction(snandc);
+
+	snandc->max_cwperpage = cwperpage;
+
+	snandc->bam_txn = qcom_alloc_bam_transaction(snandc);
+	if (!snandc->bam_txn) {
+		dev_err(snandc->dev, "failed to allocate BAM transaction\n");
+		ret = -ENOMEM;
+		goto err_free_ecc_cfg;
+	}
+
 	ecc_cfg->cfg0 = FIELD_PREP(CW_PER_PAGE_MASK, (cwperpage - 1)) |
 			FIELD_PREP(UD_SIZE_BYTES_MASK, ecc_cfg->cw_data) |
 			FIELD_PREP(DISABLE_STATUS_AFTER_WRITE, 1) |
```

---

## Commit 5: eeca2091

**Author:** Shree Ramamoorthy
**Date:** 2025-06-29 22:10:41
**Files Changed:** drivers/regulator/tps65219-regulator.c

**Message:**
```
regulator: tps65219: Fix devm_kmalloc size allocation

In probe(), two arrays of structs are allocated with the devm_kmalloc()
function, but the memory size of the allocations were given as the arrays'
length (pmic->common_irq_size for the first call and pmic->dev_irq_size for
the second devm_kmalloc call). The memory size should have been the total
memory needed.

This led to a heap overflow when the struct array was used. The issue was
first discovered with the PocketBeagle2 and BeaglePlay. The common and
device-specific structs are now allocated one at a time within the loop.

Fixes: 38c9f98db20a ("regulator: tps65219: Add support for TPS65215 Regulator IRQs")
Reported-by: Dhruva Gole <d-gole@ti.com>
Closes: https://lore.kernel.org/all/20250619153526.297398-1-d-gole@ti.com/
Tested-by: Robert Nelson <robertcnelson@gmail.com>
Acked-by: Andrew Davis <afd@ti.com>
Signed-off-by: Shree Ramamoorthy <s-ramamoorthy@ti.com>
Reviewed-by: Nishanth Menon <nm@ti.com>
Link: https://patch.msgid.link/20250620154541.2713036-1-s-ramamoorthy@ti.com
Signed-off-by: Mark Brown <broonie@kernel.org>
```

**Diff:**
```diff
diff --git a/drivers/regulator/tps65219-regulator.c b/drivers/regulator/tps65219-regulator.c
index b16b300d7f45..5e67fdc88f49 100644
--- a/drivers/regulator/tps65219-regulator.c
+++ b/drivers/regulator/tps65219-regulator.c
@@ -436,46 +436,46 @@ static int tps65219_regulator_probe(struct platform_device *pdev)
 					     pmic->rdesc[i].name);
 	}
 
-	irq_data = devm_kmalloc(tps->dev, pmic->common_irq_size, GFP_KERNEL);
-	if (!irq_data)
-		return -ENOMEM;
-
 	for (i = 0; i < pmic->common_irq_size; ++i) {
 		irq_type = &pmic->common_irq_types[i];
 		irq = platform_get_irq_byname(pdev, irq_type->irq_name);
 		if (irq < 0)
 			return -EINVAL;
 
-		irq_data[i].dev = tps->dev;
-		irq_data[i].type = irq_type;
+		irq_data = devm_kmalloc(tps->dev, sizeof(*irq_data), GFP_KERNEL);
+		if (!irq_data)
+			return -ENOMEM;
+
+		irq_data->dev = tps->dev;
+		irq_data->type = irq_type;
 		error = devm_request_threaded_irq(tps->dev, irq, NULL,
 						  tps65219_regulator_irq_handler,
 						  IRQF_ONESHOT,
 						  irq_type->irq_name,
-						  &irq_data[i]);
+						  irq_data);
 		if (error)
 			return dev_err_probe(tps->dev, PTR_ERR(rdev),
 					     "Failed to request %s IRQ %d: %d\n",
 					     irq_type->irq_name, irq, error);
 	}
 
-	irq_data = devm_kmalloc(tps->dev, pmic->dev_irq_size, GFP_KERNEL);
-	if (!irq_data)
-		return -ENOMEM;
-
 	for (i = 0; i < pmic->dev_irq_size; ++i) {
 		irq_type = &pmic->irq_types[i];
 		irq = platform_get_irq_byname(pdev, irq_type->irq_name);
 		if (irq < 0)
 			return -EINVAL;
 
-		irq_data[i].dev = tps->dev;
-		irq_data[i].type = irq_type;

... (truncated 15 lines)
```

---

