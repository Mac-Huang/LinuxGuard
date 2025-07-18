# Linux Kernel Commit Batch Analysis

## Commit 1: a5aa7bc1

**Author:** Janusz Krzysztofik
**Date:** 2025-07-01 08:10:42
**Files Changed:** drivers/gpu/drm/i915/gt/intel_ring_submission.c

**Message:**
```
drm/i915/gt: Fix timeline left held on VMA alloc error

The following error has been reported sporadically by CI when a test
unbinds the i915 driver on a ring submission platform:

<4> [239.330153] ------------[ cut here ]------------
<4> [239.330166] i915 0000:00:02.0: [drm] drm_WARN_ON(dev_priv->mm.shrink_count)
<4> [239.330196] WARNING: CPU: 1 PID: 18570 at drivers/gpu/drm/i915/i915_gem.c:1309 i915_gem_cleanup_early+0x13e/0x150 [i915]
...
<4> [239.330640] RIP: 0010:i915_gem_cleanup_early+0x13e/0x150 [i915]
...
<4> [239.330942] Call Trace:
<4> [239.330944]  <TASK>
<4> [239.330949]  i915_driver_late_release+0x2b/0xa0 [i915]
<4> [239.331202]  i915_driver_release+0x86/0xa0 [i915]
<4> [239.331482]  devm_drm_dev_init_release+0x61/0x90
<4> [239.331494]  devm_action_release+0x15/0x30
<4> [239.331504]  release_nodes+0x3d/0x120
<4> [239.331517]  devres_release_all+0x96/0xd0
<4> [239.331533]  device_unbind_cleanup+0x12/0x80
<4> [239.331543]  device_release_driver_internal+0x23a/0x280
<4> [239.331550]  ? bus_find_device+0xa5/0xe0
<4> [239.331563]  device_driver_detach+0x14/0x20
...
<4> [357.719679] ---[ end trace 0000000000000000 ]---

If the test also unloads the i915 module then that's followed with:

<3> [357.787478] =============================================================================
<3> [357.788006] BUG i915_vma (Tainted: G     U  W        N ): Objects remaining on __kmem_cache_shutdown()
<3> [357.788031] -----------------------------------------------------------------------------
<3> [357.788204] Object 0xffff888109e7f480 @offset=29824
<3> [357.788670] Allocated in i915_vma_instance+0xee/0xc10 [i915] age=292729 cpu=4 pid=2244
<4> [357.788994]  i915_vma_instance+0xee/0xc10 [i915]
<4> [357.789290]  init_status_page+0x7b/0x420 [i915]
<4> [357.789532]  intel_engines_init+0x1d8/0x980 [i915]
<4> [357.789772]  intel_gt_init+0x175/0x450 [i915]
<4> [357.790014]  i915_gem_init+0x113/0x340 [i915]
<4> [357.790281]  i915_driver_probe+0x847/0xed0 [i915]
<4> [357.790504]  i915_pci_probe+0xe6/0x220 [i915]
...

Closer analysis of CI results history has revealed a dependency of the
error on a few IGT tests, namely:
- igt@api_intel_allocator@fork-simple-stress-signal,
- igt@api_intel_allocator@two-level-inception-interruptible,
- igt@gem_linear_blits@interruptible,
- igt@prime_mmap_coherency@ioctl-errors,
which invisibly trigger the issue, then exhibited with first driver unbind
attempt.

All of the above tests perform actions which are actively interrupted with
signals.  Further debugging has allowed to narrow that scope down to
DRM_IOCTL_I915_GEM_EXECBUFFER2, and ring_context_alloc(), specific to ring
submission, in particular.

If successful then that function, or its execlists or GuC submission
equivalent, is supposed to be called only once per GEM context engine,
followed by raise of a flag that prevents the function from being called
again.  The function is expected to unwind its internal errors itself, so
it may be safely called once more after it returns an error.

In case of ring submission, the function first gets a reference to the
engine's legacy timeline and then allocates a VMA.  If the VMA allocation
fails, e.g. when i915_vma_instance() called from inside is interrupted
with a signal, then ring_context_alloc() fails, leaving the timeline held
referenced.  On next I915_GEM_EXECBUFFER2 IOCTL, another reference to the
timeline is got, and only that last one is put on successful completion.
As a consequence, the legacy timeline, with its underlying engine status
page's VMA object, is still held and not released on driver unbind.

Get the legacy timeline only after successful allocation of the context
engine's VMA.

v2: Add a note on other submission methods (Krzysztof Karas):
    Both execlists and GuC submission use lrc_alloc() which seems free
    from a similar issue.

Fixes: 75d0a7f31eec ("drm/i915: Lift timeline into intel_context")
Closes: https://gitlab.freedesktop.org/drm/i915/kernel/-/issues/12061
Cc: Chris Wilson <chris.p.wilson@linux.intel.com>
Cc: Matthew Auld <matthew.auld@intel.com>
Cc: Krzysztof Karas <krzysztof.karas@intel.com>
Reviewed-by: Sebastian Brzezinka <sebastian.brzezinka@intel.com>
Reviewed-by: Krzysztof Niemiec <krzysztof.niemiec@intel.com>
Signed-off-by: Janusz Krzysztofik <janusz.krzysztofik@linux.intel.com>
Reviewed-by: Nitin Gote <nitin.r.gote@intel.com>
Reviewed-by: Andi Shyti <andi.shyti@linux.intel.com>
Signed-off-by: Andi Shyti <andi.shyti@linux.intel.com>
Link: https://lore.kernel.org/r/20250611104352.1014011-2-janusz.krzysztofik@linux.intel.com
(cherry picked from commit cc43422b3cc79eacff4c5a8ba0d224688ca9dd4f)
Signed-off-by: Joonas Lahtinen <joonas.lahtinen@linux.intel.com>
```

**Diff:**
```diff
diff --git a/drivers/gpu/drm/i915/gt/intel_ring_submission.c b/drivers/gpu/drm/i915/gt/intel_ring_submission.c
index a876a34455f1..2a6d79abf25b 100644
--- a/drivers/gpu/drm/i915/gt/intel_ring_submission.c
+++ b/drivers/gpu/drm/i915/gt/intel_ring_submission.c
@@ -610,7 +610,6 @@ static int ring_context_alloc(struct intel_context *ce)
 	/* One ringbuffer to rule them all */
 	GEM_BUG_ON(!engine->legacy.ring);
 	ce->ring = engine->legacy.ring;
-	ce->timeline = intel_timeline_get(engine->legacy.timeline);
 
 	GEM_BUG_ON(ce->state);
 	if (engine->context_size) {
@@ -623,6 +622,8 @@ static int ring_context_alloc(struct intel_context *ce)
 		ce->state = vma;
 	}
 
+	ce->timeline = intel_timeline_get(engine->legacy.timeline);
+
 	return 0;
 }
 
```

---

## Commit 2: e39ed71c

**Author:** Jiawen Wu
**Date:** 2025-06-30 18:15:53
**Files Changed:** drivers/net/ethernet/wangxun/txgbe/txgbe_aml.c

**Message:**
```
net: txgbe: fix the issue of TX failure

There is a occasional problem that ping is failed between AML devices.
That is because the manual enablement of the security Tx path on the
hardware is missing, no matter what its previous state was.

Fixes: 6f8b4c01a8cd ("net: txgbe: Implement PHYLINK for AML 25G/10G devices")
Signed-off-by: Jiawen Wu <jiawenwu@trustnetic.com>
Reviewed-by: Simon Horman <horms@kernel.org>
Link: https://patch.msgid.link/5BDFB14C57D1C42A+20250626085153.86122-1-jiawenwu@trustnetic.com
Signed-off-by: Jakub Kicinski <kuba@kernel.org>
```

**Diff:**
```diff
diff --git a/drivers/net/ethernet/wangxun/txgbe/txgbe_aml.c b/drivers/net/ethernet/wangxun/txgbe/txgbe_aml.c
index 7dbcf41750c1..dc87ccad9652 100644
--- a/drivers/net/ethernet/wangxun/txgbe/txgbe_aml.c
+++ b/drivers/net/ethernet/wangxun/txgbe/txgbe_aml.c
@@ -294,6 +294,7 @@ static void txgbe_mac_link_up_aml(struct phylink_config *config,
 	wx_fc_enable(wx, tx_pause, rx_pause);
 
 	txgbe_reconfig_mac(wx);
+	txgbe_enable_sec_tx_path(wx);
 
 	txcfg = rd32(wx, TXGBE_AML_MAC_TX_CFG);
 	txcfg &= ~TXGBE_AML_MAC_TX_CFG_SPEED_MASK;
```

---

## Commit 3: f3e58d8e

**Author:** Lin.Cao
**Date:** 2025-06-30 13:57:31
**Files Changed:** drivers/gpu/drm/amd/amdgpu/amdgpu_ctx.c

**Message:**
```
drm/amdgpu: Fix memory leak in amdgpu_ctx_mgr_entity_fini

patch dd64956685fa ("drm/amdgpu: Remove duplicated "context still
alive" check") removed ctx put, which will cause amdgpu_ctx_fini()
cannot be called and then cause some finished fence that added by
amdgpu_ctx_add_fence() cannot be released and cause memleak.

Fixes: dd64956685fa ("drm/amdgpu: Remove duplicated "context still alive" check")
Signed-off-by: Lin.Cao <lincao12@amd.com>
Reviewed-by: Tvrtko Ursulin <tvrtko.ursulin@igalia.com>
Acked-by: Christian König <christian.koenig@amd.com>
Signed-off-by: Alex Deucher <alexander.deucher@amd.com>
(cherry picked from commit 8cf66089e28108dedd47e6156a48489303cf525c)
Cc: stable@vger.kernel.org
```

**Diff:**
```diff
diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_ctx.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_ctx.c
index 85567d0d9545..f5d5c45ddc0d 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_ctx.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_ctx.c
@@ -944,6 +944,7 @@ static void amdgpu_ctx_mgr_entity_fini(struct amdgpu_ctx_mgr *mgr)
 				drm_sched_entity_fini(entity);
 			}
 		}
+		kref_put(&ctx->refcount, amdgpu_ctx_fini);
 	}
 }
 
```

---

## Commit 4: cf234231

**Author:** Philip Yang
**Date:** 2025-06-30 13:57:12
**Files Changed:** drivers/gpu/drm/amd/amdkfd/kfd_svm.c

**Message:**
```
drm/amdkfd: Don't call mmput from MMU notifier callback

If the process is exiting, the mmput inside mmu notifier callback from
compactd or fork or numa balancing could release the last reference
of mm struct to call exit_mmap and free_pgtable, this triggers deadlock
with below backtrace.

The deadlock will leak kfd process as mmu notifier release is not called
and cause VRAM leaking.

The fix is to take mm reference mmget_non_zero when adding prange to the
deferred list to pair with mmput in deferred list work.

If prange split and add into pchild list, the pchild work_item.mm is not
used, so remove the mm parameter from svm_range_unmap_split and
svm_range_add_child.

The backtrace of hung task:

 INFO: task python:348105 blocked for more than 64512 seconds.
 Call Trace:
  __schedule+0x1c3/0x550
  schedule+0x46/0xb0
  rwsem_down_write_slowpath+0x24b/0x4c0
  unlink_anon_vmas+0xb1/0x1c0
  free_pgtables+0xa9/0x130
  exit_mmap+0xbc/0x1a0
  mmput+0x5a/0x140
  svm_range_cpu_invalidate_pagetables+0x2b/0x40 [amdgpu]
  mn_itree_invalidate+0x72/0xc0
  __mmu_notifier_invalidate_range_start+0x48/0x60
  try_to_unmap_one+0x10fa/0x1400
  rmap_walk_anon+0x196/0x460
  try_to_unmap+0xbb/0x210
  migrate_page_unmap+0x54d/0x7e0
  migrate_pages_batch+0x1c3/0xae0
  migrate_pages_sync+0x98/0x240
  migrate_pages+0x25c/0x520
  compact_zone+0x29d/0x590
  compact_zone_order+0xb6/0xf0
  try_to_compact_pages+0xbe/0x220
  __alloc_pages_direct_compact+0x96/0x1a0
  __alloc_pages_slowpath+0x410/0x930
  __alloc_pages_nodemask+0x3a9/0x3e0
  do_huge_pmd_anonymous_page+0xd7/0x3e0
  __handle_mm_fault+0x5e3/0x5f0
  handle_mm_fault+0xf7/0x2e0
  hmm_vma_fault.isra.0+0x4d/0xa0
  walk_pmd_range.isra.0+0xa8/0x310
  walk_pud_range+0x167/0x240
  walk_pgd_range+0x55/0x100
  __walk_page_range+0x87/0x90
  walk_page_range+0xf6/0x160
  hmm_range_fault+0x4f/0x90
  amdgpu_hmm_range_get_pages+0x123/0x230 [amdgpu]
  amdgpu_ttm_tt_get_user_pages+0xb1/0x150 [amdgpu]
  init_user_pages+0xb1/0x2a0 [amdgpu]
  amdgpu_amdkfd_gpuvm_alloc_memory_of_gpu+0x543/0x7d0 [amdgpu]
  kfd_ioctl_alloc_memory_of_gpu+0x24c/0x4e0 [amdgpu]
  kfd_ioctl+0x29d/0x500 [amdgpu]

Fixes: fa582c6f3684 ("drm/amdkfd: Use mmget_not_zero in MMU notifier")
Signed-off-by: Philip Yang <Philip.Yang@amd.com>
Reviewed-by: Felix Kuehling <felix.kuehling@amd.com>
Signed-off-by: Alex Deucher <alexander.deucher@amd.com>
(cherry picked from commit a29e067bd38946f752b0ef855f3dfff87e77bec7)
Cc: stable@vger.kernel.org
```

**Diff:**
```diff
diff --git a/drivers/gpu/drm/amd/amdkfd/kfd_svm.c b/drivers/gpu/drm/amd/amdkfd/kfd_svm.c
index 7763e4742080..a0f22ea6d15a 100644
--- a/drivers/gpu/drm/amd/amdkfd/kfd_svm.c
+++ b/drivers/gpu/drm/amd/amdkfd/kfd_svm.c
@@ -1171,13 +1171,12 @@ svm_range_split_head(struct svm_range *prange, uint64_t new_start,
 }
 
 static void
-svm_range_add_child(struct svm_range *prange, struct mm_struct *mm,
-		    struct svm_range *pchild, enum svm_work_list_ops op)
+svm_range_add_child(struct svm_range *prange, struct svm_range *pchild, enum svm_work_list_ops op)
 {
 	pr_debug("add child 0x%p [0x%lx 0x%lx] to prange 0x%p child list %d\n",
 		 pchild, pchild->start, pchild->last, prange, op);
 
-	pchild->work_item.mm = mm;
+	pchild->work_item.mm = NULL;
 	pchild->work_item.op = op;
 	list_add_tail(&pchild->child_list, &prange->child_list);
 }
@@ -2394,15 +2393,17 @@ svm_range_add_list_work(struct svm_range_list *svms, struct svm_range *prange,
 		    prange->work_item.op != SVM_OP_UNMAP_RANGE)
 			prange->work_item.op = op;
 	} else {
-		prange->work_item.op = op;
-
-		/* Pairs with mmput in deferred_list_work */
-		mmget(mm);
-		prange->work_item.mm = mm;
-		list_add_tail(&prange->deferred_list,
-			      &prange->svms->deferred_range_list);
-		pr_debug("add prange 0x%p [0x%lx 0x%lx] to work list op %d\n",
-			 prange, prange->start, prange->last, op);
+		/* Pairs with mmput in deferred_list_work.
+		 * If process is exiting and mm is gone, don't update mmu notifier.
+		 */
+		if (mmget_not_zero(mm)) {
+			prange->work_item.mm = mm;
+			prange->work_item.op = op;
+			list_add_tail(&prange->deferred_list,
+				      &prange->svms->deferred_range_list);
+			pr_debug("add prange 0x%p [0x%lx 0x%lx] to work list op %d\n",
+				 prange, prange->start, prange->last, op);
+		}
 	}
 	spin_unlock(&svms->deferred_list_lock);
 }
@@ -2416,8 +2417,7 @@ void schedule_deferred_list_work(struct svm_range_list *svms)
 }
 

... (truncated 58 lines)
```

---

## Commit 5: 3d300489

**Author:** Michael J. Ruhl
**Date:** 2025-06-30 19:57:08
**Files Changed:** drivers/i2c/busses/i2c-designware-master.c

**Message:**
```
i2c/designware: Fix an initialization issue

The i2c_dw_xfer_init() function requires msgs and msg_write_idx from the
dev context to be initialized.

amd_i2c_dw_xfer_quirk() inits msgs and msgs_num, but not msg_write_idx.

This could allow an out of bounds access (of msgs).

Initialize msg_write_idx before calling i2c_dw_xfer_init().

Reviewed-by: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
Fixes: 17631e8ca2d3 ("i2c: designware: Add driver support for AMD NAVI GPU")
Cc: <stable@vger.kernel.org> # v5.13+
Signed-off-by: Michael J. Ruhl <michael.j.ruhl@intel.com>
Signed-off-by: Andi Shyti <andi.shyti@kernel.org>
Link: https://lore.kernel.org/r/20250627143511.489570-1-michael.j.ruhl@intel.com
```

**Diff:**
```diff
diff --git a/drivers/i2c/busses/i2c-designware-master.c b/drivers/i2c/busses/i2c-designware-master.c
index 9d7d9e47564a..cbd88ffa5610 100644
--- a/drivers/i2c/busses/i2c-designware-master.c
+++ b/drivers/i2c/busses/i2c-designware-master.c
@@ -363,6 +363,7 @@ static int amd_i2c_dw_xfer_quirk(struct i2c_adapter *adap, struct i2c_msg *msgs,
 
 	dev->msgs = msgs;
 	dev->msgs_num = num_msgs;
+	dev->msg_write_idx = 0;
 	i2c_dw_xfer_init(dev);
 
 	/* Initiate messages read/write transaction */
```

---

