# Linux Kernel Commit Batch Analysis

## Commit 1: 89a33de3

**Author:** Kiran K
**Date:** 2025-06-20 11:50:55
**Files Changed:** drivers/bluetooth/btintel_pcie.c

**Message:**
```
Bluetooth: btintel_pcie: Fix potential race condition in firmware download

During firmware download, if an error occurs, interrupts must be
disabled, synchronized, and re-enabled before retrying the download.
This change ensures proper interrupt handling to prevent race
conditions.

Signed-off-by: Chandrashekar Devegowda <chandrashekar.devegowda@intel.com>
Signed-off-by: Kiran K <kiran.k@intel.com>
Signed-off-by: Luiz Augusto von Dentz <luiz.von.dentz@intel.com>
```

**Diff:**
```diff
diff --git a/drivers/bluetooth/btintel_pcie.c b/drivers/bluetooth/btintel_pcie.c
index 563165c5efae..e1c688dd2d45 100644
--- a/drivers/bluetooth/btintel_pcie.c
+++ b/drivers/bluetooth/btintel_pcie.c
@@ -2033,6 +2033,28 @@ static void btintel_pcie_release_hdev(struct btintel_pcie_data *data)
 	data->hdev = NULL;
 }
 
+static void btintel_pcie_disable_interrupts(struct btintel_pcie_data *data)
+{
+	spin_lock(&data->irq_lock);
+	btintel_pcie_wr_reg32(data, BTINTEL_PCIE_CSR_MSIX_FH_INT_MASK, data->fh_init_mask);
+	btintel_pcie_wr_reg32(data, BTINTEL_PCIE_CSR_MSIX_HW_INT_MASK, data->hw_init_mask);
+	spin_unlock(&data->irq_lock);
+}
+
+static void btintel_pcie_enable_interrupts(struct btintel_pcie_data *data)
+{
+	spin_lock(&data->irq_lock);
+	btintel_pcie_wr_reg32(data, BTINTEL_PCIE_CSR_MSIX_FH_INT_MASK, ~data->fh_init_mask);
+	btintel_pcie_wr_reg32(data, BTINTEL_PCIE_CSR_MSIX_HW_INT_MASK, ~data->hw_init_mask);
+	spin_unlock(&data->irq_lock);
+}
+
+static void btintel_pcie_synchronize_irqs(struct btintel_pcie_data *data)
+{
+	for (int i = 0; i < data->alloc_vecs; i++)
+		synchronize_irq(data->msix_entries[i].vector);
+}
+
 static int btintel_pcie_setup_internal(struct hci_dev *hdev)
 {
 	struct btintel_pcie_data *data = hci_get_drvdata(hdev);
@@ -2152,6 +2174,8 @@ static int btintel_pcie_setup(struct hci_dev *hdev)
 		bt_dev_err(hdev, "Firmware download retry count: %d",
 			   fw_dl_retry);
 		btintel_pcie_dump_debug_registers(hdev);
+		btintel_pcie_disable_interrupts(data);
+		btintel_pcie_synchronize_irqs(data);
 		err = btintel_pcie_reset_bt(data);
 		if (err) {
 			bt_dev_err(hdev, "Failed to do shr reset: %d", err);
@@ -2159,6 +2183,7 @@ static int btintel_pcie_setup(struct hci_dev *hdev)
 		}
 		usleep_range(10000, 12000);
 		btintel_pcie_reset_ia(data);
+		btintel_pcie_enable_interrupts(data);
 		btintel_pcie_config_msix(data);
 		err = btintel_pcie_enable_bt(data);
 		if (err) {

... (truncated 22 lines)
```

---

## Commit 2: a8905238

**Author:** Akira Inoue
**Date:** 2025-06-20 09:10:14
**Files Changed:** drivers/hid/hid-ids.h, drivers/hid/hid-lenovo.c, drivers/hid/hid-multitouch.c

**Message:**
```
HID: lenovo: Add support for ThinkPad X1 Tablet Thin Keyboard Gen2

Add "Thinkpad X1 Tablet Gen 2 Keyboard" PID to hid-lenovo driver to fix trackpoint not working issue.

Signed-off-by: Akira Inoue <niyarium@gmail.com>
Signed-off-by: Jiri Kosina <jkosina@suse.com>
```

**Diff:**
```diff
diff --git a/drivers/hid/hid-ids.h b/drivers/hid/hid-ids.h
index 2d3769405ec3..c6468568aea1 100644
--- a/drivers/hid/hid-ids.h
+++ b/drivers/hid/hid-ids.h
@@ -821,6 +821,7 @@
 #define USB_DEVICE_ID_LENOVO_TPPRODOCK	0x6067
 #define USB_DEVICE_ID_LENOVO_X1_COVER	0x6085
 #define USB_DEVICE_ID_LENOVO_X1_TAB	0x60a3
+#define USB_DEVICE_ID_LENOVO_X1_TAB2	0x60a4
 #define USB_DEVICE_ID_LENOVO_X1_TAB3	0x60b5
 #define USB_DEVICE_ID_LENOVO_X12_TAB	0x60fe
 #define USB_DEVICE_ID_LENOVO_X12_TAB2	0x61ae
diff --git a/drivers/hid/hid-lenovo.c b/drivers/hid/hid-lenovo.c
index a3c23a72316a..b3121fa7a72d 100644
--- a/drivers/hid/hid-lenovo.c
+++ b/drivers/hid/hid-lenovo.c
@@ -492,6 +492,7 @@ static int lenovo_input_mapping(struct hid_device *hdev,
 	case USB_DEVICE_ID_LENOVO_X12_TAB:
 	case USB_DEVICE_ID_LENOVO_X12_TAB2:
 	case USB_DEVICE_ID_LENOVO_X1_TAB:
+	case USB_DEVICE_ID_LENOVO_X1_TAB2:
 	case USB_DEVICE_ID_LENOVO_X1_TAB3:
 		return lenovo_input_mapping_x1_tab_kbd(hdev, hi, field, usage, bit, max);
 	default:
@@ -608,6 +609,7 @@ static ssize_t attr_fn_lock_store(struct device *dev,
 	case USB_DEVICE_ID_LENOVO_X12_TAB2:
 	case USB_DEVICE_ID_LENOVO_TP10UBKBD:
 	case USB_DEVICE_ID_LENOVO_X1_TAB:
+	case USB_DEVICE_ID_LENOVO_X1_TAB2:
 	case USB_DEVICE_ID_LENOVO_X1_TAB3:
 		ret = lenovo_led_set_tp10ubkbd(hdev, TP10UBKBD_FN_LOCK_LED, value);
 		if (ret)
@@ -864,6 +866,7 @@ static int lenovo_event(struct hid_device *hdev, struct hid_field *field,
 	case USB_DEVICE_ID_LENOVO_X12_TAB2:
 	case USB_DEVICE_ID_LENOVO_TP10UBKBD:
 	case USB_DEVICE_ID_LENOVO_X1_TAB:
+	case USB_DEVICE_ID_LENOVO_X1_TAB2:
 	case USB_DEVICE_ID_LENOVO_X1_TAB3:
 		return lenovo_event_tp10ubkbd(hdev, field, usage, value);
 	default:
@@ -1147,6 +1150,7 @@ static int lenovo_led_brightness_set(struct led_classdev *led_cdev,
 	case USB_DEVICE_ID_LENOVO_X12_TAB2:
 	case USB_DEVICE_ID_LENOVO_TP10UBKBD:
 	case USB_DEVICE_ID_LENOVO_X1_TAB:
+	case USB_DEVICE_ID_LENOVO_X1_TAB2:
 	case USB_DEVICE_ID_LENOVO_X1_TAB3:
 		ret = lenovo_led_set_tp10ubkbd(hdev, tp10ubkbd_led[led_nr], value);
 		break;
@@ -1387,6 +1391,7 @@ static int lenovo_probe(struct hid_device *hdev,
 	case USB_DEVICE_ID_LENOVO_X12_TAB2:

... (truncated 47 lines)
```

---

## Commit 3: 255da9b8

**Author:** Linus Torvalds
**Date:** 2025-06-19 23:25:28
**Files Changed:** io_uring/io-wq.c, io_uring/io_uring.h, io_uring/rsrc.c, io_uring/sqpoll.c

**Message:**
```
Merge tag 'io_uring-6.16-20250619' of git://git.kernel.dk/linux

Pull io_uring fixes from Jens Axboe:

 - Two fixes for error injection failures. One fixes a task leak issue
   introduced in this merge window, the other an older issue with
   handling allocation of a mapped buffer.

 - Fix for a syzbot issue that triggers a kmalloc warning on attempting
   an allocation that's too large

 - Fix for an error injection failure causing a double put of a task,
   introduced in this merge window

* tag 'io_uring-6.16-20250619' of git://git.kernel.dk/linux:
  io_uring: fix potential page leak in io_sqe_buffer_register()
  io_uring/sqpoll: don't put task_struct on tctx setup failure
  io_uring: remove duplicate io_uring_alloc_task_context() definition
  io_uring: fix task leak issue in io_wq_create()
  io_uring/rsrc: validate buffer count with offset for cloning
```

**Diff:**
```diff
diff --git a/io_uring/io-wq.c b/io_uring/io-wq.c
index cd1fcb115739..be91edf34f01 100644
--- a/io_uring/io-wq.c
+++ b/io_uring/io-wq.c
@@ -1259,8 +1259,10 @@ struct io_wq *io_wq_create(unsigned bounded, struct io_wq_data *data)
 	atomic_set(&wq->worker_refs, 1);
 	init_completion(&wq->worker_done);
 	ret = cpuhp_state_add_instance_nocalls(io_wq_online, &wq->cpuhp_node);
-	if (ret)
+	if (ret) {
+		put_task_struct(wq->task);
 		goto err;
+	}
 
 	return wq;
 err:
diff --git a/io_uring/io_uring.h b/io_uring/io_uring.h
index d59c12277d58..66c1ca73f55e 100644
--- a/io_uring/io_uring.h
+++ b/io_uring/io_uring.h
@@ -98,8 +98,6 @@ struct llist_node *io_handle_tw_list(struct llist_node *node, unsigned int *coun
 struct llist_node *tctx_task_work_run(struct io_uring_task *tctx, unsigned int max_entries, unsigned int *count);
 void tctx_task_work(struct callback_head *cb);
 __cold void io_uring_cancel_generic(bool cancel_all, struct io_sq_data *sqd);
-int io_uring_alloc_task_context(struct task_struct *task,
-				struct io_ring_ctx *ctx);
 
 int io_ring_add_registered_file(struct io_uring_task *tctx, struct file *file,
 				     int start, int end);
diff --git a/io_uring/rsrc.c b/io_uring/rsrc.c
index c592ceace97d..d724602697e7 100644
--- a/io_uring/rsrc.c
+++ b/io_uring/rsrc.c
@@ -809,10 +809,8 @@ static struct io_rsrc_node *io_sqe_buffer_register(struct io_ring_ctx *ctx,
 
 	imu->nr_bvecs = nr_pages;
 	ret = io_buffer_account_pin(ctx, pages, nr_pages, imu, last_hpage);
-	if (ret) {
-		unpin_user_pages(pages, nr_pages);
+	if (ret)
 		goto done;
-	}
 
 	size = iov->iov_len;
 	/* store original address for later verification */
@@ -842,6 +840,8 @@ static struct io_rsrc_node *io_sqe_buffer_register(struct io_ring_ctx *ctx,
 	if (ret) {
 		if (imu)
 			io_free_imu(ctx, imu);
+		if (pages)

... (truncated 51 lines)
```

---

## Commit 4: 5f2b6c5f

**Author:** Linus Torvalds
**Date:** 2025-06-19 23:18:59
**Files Changed:** drivers/gpu/drm/amd/amdgpu/amdgpu_debugfs.c, drivers/gpu/drm/amd/amdgpu/amdgpu_device.c, drivers/gpu/drm/amd/amdgpu/amdgpu_fence.c, drivers/gpu/drm/amd/amdgpu/amdgpu_job.c, drivers/gpu/drm/amd/amdgpu/amdgpu_job.h (+64 more)

**Message:**
```
Merge tag 'drm-fixes-2025-06-20' of https://gitlab.freedesktop.org/drm/kernel

Pull drm fixes from Dave Airlie:
 "Bit of an uptick in fixes for rc3, msm and amdgpu leading the way,
  with i915/xe/nouveau with a few each and then some scattered misc
  bits, nothing looks too crazy:

  msm:
   - Display:
      - Fixed DP output on SDM845
      - Fixed 10nm DSI PLL init
   - GPU:
      - SUBMIT ioctl error path leak fixes
      - drm half of stall-on-fault fixes
      - a7xx: Missing CP_RESET_CONTEXT_STATE
      - Skip GPU component bind if GPU is not in the device table

  i915:
   - Fix MIPI vtotal programming off by one on Broxton
   - Fix PMU code for GCOV and AutoFDO enabled build

  xe:
   - A workaround update
   - Fix memset on iomem
   - Fix early wedge on GuC Load failure

  amdgpu:
   - DP tunneling fix
   - LTTPR fix
   - DSC fix
   - DML2.x ABGR16161616 fix
   - RMCM fix
   - Backlight fixes
   - GFX11 kicker support
   - SDMA reset fixes
   - VCN 5.0.1 fix
   - Reset fix
   - Misc small fixes

  amdkfd:
   - SDMA reset fix
   - Fix race in GWS scheduling

  nouveau:
   - update docs reference
   - fix backlight name buffer size
   - fix UAF in r535 gsp rpc msg
   - fix undefined shift

  mgag200:
   - drop export header

  ast:
   - drop export header

  malidp:
   - drop informational error

  ssd130x:
   - fix clear columns

  etnaviv:
   - scheduler locking fix

  v3d:
   - null pointer crash fix"

* tag 'drm-fixes-2025-06-20' of https://gitlab.freedesktop.org/drm/kernel: (50 commits)
  drm/xe: Fix early wedge on GuC load failure
  drm/xe: Fix memset on iomem
  drm/xe/bmg: Update Wa_16023588340
  drm/amdgpu/sdma5.2: init engine reset mutex
  drm/amdkfd: Fix race in GWS queue scheduling
  drm/amdgpu/sdma5: init engine reset mutex
  drm/amdgpu: switch job hw_fence to amdgpu_fence
  drm/amdgpu: Fix SDMA UTC_L1 handling during start/stop sequences
  drm/amdgpu: Release reset locks during failures
  drm/amd/display: Check dce_hwseq before dereferencing it
  drm/amdgpu: VCN v5_0_1 to prevent FW checking RB during DPG pause
  drm/amdgpu: Use logical instance ID for SDMA v4_4_2 queue operations
  drm/amdgpu: Fix SDMA engine reset with logical instance ID
  drm/amdgpu: add kicker fws loading for gfx11/smu13/psp13
  drm/amdgpu: Add kicker device detection
  drm/amd/display: Export full brightness range to userspace
  drm/amd/display: Only read ACPI backlight caps once
  drm/amd/display: Fix RMCM programming seq errors
  drm/amd/display: Fix mpv playback corruption on weston
  drm/amd/display: Add more checks for DSC / HUBP ONO guarantees
  ...
```

**Diff:**
```diff
diff --git a/Documentation/gpu/nouveau.rst b/Documentation/gpu/nouveau.rst
index b8c801e0068c..cab2e81013bc 100644
--- a/Documentation/gpu/nouveau.rst
+++ b/Documentation/gpu/nouveau.rst
@@ -25,7 +25,7 @@ providing a consistent API to upper layers of the driver stack.
 GSP Support
 ------------------------
 
-.. kernel-doc:: drivers/gpu/drm/nouveau/nvkm/subdev/gsp/r535.c
+.. kernel-doc:: drivers/gpu/drm/nouveau/nvkm/subdev/gsp/rm/r535/rpc.c
    :doc: GSP message queue element
 
 .. kernel-doc:: drivers/gpu/drm/nouveau/include/nvkm/subdev/gsp.h
diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_debugfs.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_debugfs.c
index 8e626f50b362..f81608330a3d 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_debugfs.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_debugfs.c
@@ -1902,7 +1902,7 @@ static void amdgpu_ib_preempt_mark_partial_job(struct amdgpu_ring *ring)
 			continue;
 		}
 		job = to_amdgpu_job(s_job);
-		if (preempted && (&job->hw_fence) == fence)
+		if (preempted && (&job->hw_fence.base) == fence)
 			/* mark the job as preempted */
 			job->preemption_status |= AMDGPU_IB_PREEMPTED;
 	}
diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_device.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_device.c
index e1bab6a96cb6..78f8755996f0 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_device.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_device.c
@@ -6019,16 +6019,12 @@ static int amdgpu_device_health_check(struct list_head *device_list_handle)
 	return ret;
 }
 
-static int amdgpu_device_halt_activities(struct amdgpu_device *adev,
-			      struct amdgpu_job *job,
-			      struct amdgpu_reset_context *reset_context,
-			      struct list_head *device_list,
-			      struct amdgpu_hive_info *hive,
-			      bool need_emergency_restart)
+static int amdgpu_device_recovery_prepare(struct amdgpu_device *adev,
+					  struct list_head *device_list,
+					  struct amdgpu_hive_info *hive)
 {
-	struct list_head *device_list_handle =  NULL;
 	struct amdgpu_device *tmp_adev = NULL;
-	int i, r = 0;
+	int r;
 
 	/*

... (truncated 2218 lines)
```

---

## Commit 5: fba46a5d

**Author:** Liam R. Howlett
**Date:** 2025-06-19 20:48:04
**Files Changed:** lib/maple_tree.c

**Message:**
```
maple_tree: fix MA_STATE_PREALLOC flag in mas_preallocate()

Temporarily clear the preallocation flag when explicitly requesting
allocations.  Pre-existing allocations are already counted against the
request through mas_node_count_gfp(), but the allocations will not happen
if the MA_STATE_PREALLOC flag is set.  This flag is meant to avoid
re-allocating in bulk allocation mode, and to detect issues with
preallocation calculations.

The MA_STATE_PREALLOC flag should also always be set on zero allocations
so that detection of underflow allocations will print a WARN_ON() during
consumption.

User visible effect of this flaw is a WARN_ON() followed by a null pointer
dereference when subsequent requests for larger number of nodes is
ignored, such as the vma merge retry in mmap_region() caused by drivers
altering the vma flags (which happens in v6.6, at least)

Link: https://lkml.kernel.org/r/20250616184521.3382795-3-Liam.Howlett@oracle.com
Fixes: 54a611b60590 ("Maple Tree: add new data structure")
Signed-off-by: Liam R. Howlett <Liam.Howlett@oracle.com>
Reported-by: Zhaoyang Huang <zhaoyang.huang@unisoc.com>
Reported-by: Hailong Liu <hailong.liu@oppo.com>
Link: https://lore.kernel.org/all/1652f7eb-a51b-4fee-8058-c73af63bacd1@oppo.com/
Link: https://lore.kernel.org/all/20250428184058.1416274-1-Liam.Howlett@oracle.com/
Link: https://lore.kernel.org/all/20250429014754.1479118-1-Liam.Howlett@oracle.com/
Cc: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Cc: Suren Baghdasaryan <surenb@google.com>
Cc: Hailong Liu <hailong.liu@oppo.com>
Cc: zhangpeng.00@bytedance.com <zhangpeng.00@bytedance.com>
Cc: Steve Kang <Steve.Kang@unisoc.com>
Cc: Matthew Wilcox <willy@infradead.org>
Cc: Sidhartha Kumar <sidhartha.kumar@oracle.com>
Cc: <stable@vger.kernel.org>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
```

**Diff:**
```diff
diff --git a/lib/maple_tree.c b/lib/maple_tree.c
index affe979bd14d..00524e55a21e 100644
--- a/lib/maple_tree.c
+++ b/lib/maple_tree.c
@@ -5527,8 +5527,9 @@ int mas_preallocate(struct ma_state *mas, void *entry, gfp_t gfp)
 	mas->store_type = mas_wr_store_type(&wr_mas);
 	request = mas_prealloc_calc(&wr_mas, entry);
 	if (!request)
-		return ret;
+		goto set_flag;
 
+	mas->mas_flags &= ~MA_STATE_PREALLOC;
 	mas_node_count_gfp(mas, request, gfp);
 	if (mas_is_err(mas)) {
 		mas_set_alloc_req(mas, 0);
@@ -5538,6 +5539,7 @@ int mas_preallocate(struct ma_state *mas, void *entry, gfp_t gfp)
 		return ret;
 	}
 
+set_flag:
 	mas->mas_flags |= MA_STATE_PREALLOC;
 	return ret;
 }
```

---

