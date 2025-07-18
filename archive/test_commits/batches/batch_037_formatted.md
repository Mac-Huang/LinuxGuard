# Linux Kernel Commit Batch Analysis

## Commit 1: 3f5f6321

**Author:** Or Har-Toov
**Date:** 2025-06-25 03:40:16
**Files Changed:** drivers/infiniband/core/umem_odp.c

**Message:**
```
IB/core: Annotate umem_mutex acquisition under fs_reclaim for lockdep

Following the fix in the previous commit ("IB/mlx5: Fix potential
deadlock in MR deregistration"), teach lockdep explicitly about the
locking order between fs_reclaim and umem_mutex.

The previous commit resolved a potential deadlock scenario where
kzalloc(GFP_KERNEL) was called while holding umem_mutex, which could
lead to reclaim and eventually invoke the MMU notifier
(mlx5_ib_invalidate_range()), causing a recursive acquisition of
umem_mutex.

To prevent such issues from reoccurring unnoticed in future code
changes, add a lockdep annotation in ib_init_umem_odp() that simulates
taking umem_mutex inside a reclaim context. This makes lockdep aware
of this locking dependency and ensures that future violations—such as
calling kzalloc() or any memory allocator that may enter reclaim while
holding umem_mutex—will immediately raise a lockdep warning.

Signed-off-by: Or Har-Toov <ohartoov@nvidia.com>
Reviewed-by: Michael Guralnik <michaelgur@nvidia.com>
Link: https://patch.msgid.link/9d31b9d8fe1db648a9f47cec3df6b8463319dee5.1750061698.git.leon@kernel.org
Signed-off-by: Leon Romanovsky <leon@kernel.org>
```

**Diff:**
```diff
diff --git a/drivers/infiniband/core/umem_odp.c b/drivers/infiniband/core/umem_odp.c
index c752ae9fad6c..b1c44ec1a3f3 100644
--- a/drivers/infiniband/core/umem_odp.c
+++ b/drivers/infiniband/core/umem_odp.c
@@ -76,6 +76,17 @@ static int ib_init_umem_odp(struct ib_umem_odp *umem_odp,
 	end = ALIGN(end, page_size);
 	if (unlikely(end < page_size))
 		return -EOVERFLOW;
+	/*
+	 * The mmu notifier can be called within reclaim contexts and takes the
+	 * umem_mutex. This is rare to trigger in testing, teach lockdep about
+	 * it.
+	 */
+	if (IS_ENABLED(CONFIG_LOCKDEP)) {
+		fs_reclaim_acquire(GFP_KERNEL);
+		mutex_lock(&umem_odp->umem_mutex);
+		mutex_unlock(&umem_odp->umem_mutex);
+		fs_reclaim_release(GFP_KERNEL);
+	}
 
 	nr_entries = (end - start) >> PAGE_SHIFT;
 	if (!(nr_entries * PAGE_SIZE / page_size))
```

---

## Commit 2: 2ed25aa7

**Author:** Or Har-Toov
**Date:** 2025-06-25 03:39:36
**Files Changed:** drivers/infiniband/hw/mlx5/mr.c

**Message:**
```
IB/mlx5: Fix potential deadlock in MR deregistration

The issue arises when kzalloc() is invoked while holding umem_mutex or
any other lock acquired under umem_mutex. This is problematic because
kzalloc() can trigger fs_reclaim_aqcuire(), which may, in turn, invoke
mmu_notifier_invalidate_range_start(). This function can lead to
mlx5_ib_invalidate_range(), which attempts to acquire umem_mutex again,
resulting in a deadlock.

The problematic flow:
             CPU0                      |              CPU1
---------------------------------------|------------------------------------------------
mlx5_ib_dereg_mr()                     |
 → revoke_mr()                         |
   → mutex_lock(&umem_odp->umem_mutex) |
                                       | mlx5_mkey_cache_init()
                                       |  → mutex_lock(&dev->cache.rb_lock)
                                       |  → mlx5r_cache_create_ent_locked()
                                       |    → kzalloc(GFP_KERNEL)
                                       |      → fs_reclaim()
                                       |        → mmu_notifier_invalidate_range_start()
                                       |          → mlx5_ib_invalidate_range()
                                       |            → mutex_lock(&umem_odp->umem_mutex)
   → cache_ent_find_and_store()        |
     → mutex_lock(&dev->cache.rb_lock) |

Additionally, when kzalloc() is called from within
cache_ent_find_and_store(), we encounter the same deadlock due to
re-acquisition of umem_mutex.

Solve by releasing umem_mutex in dereg_mr() after umr_revoke_mr()
and before acquiring rb_lock. This ensures that we don't hold
umem_mutex while performing memory allocations that could trigger
the reclaim path.

This change prevents the deadlock by ensuring proper lock ordering and
avoiding holding locks during memory allocation operations that could
trigger the reclaim path.

The following lockdep warning demonstrates the deadlock:

 python3/20557 is trying to acquire lock:
 ffff888387542128 (&umem_odp->umem_mutex){+.+.}-{4:4}, at:
 mlx5_ib_invalidate_range+0x5b/0x550 [mlx5_ib]

 but task is already holding lock:
 ffffffff82f6b840 (mmu_notifier_invalidate_range_start){+.+.}-{0:0}, at:
 unmap_vmas+0x7b/0x1a0

 which lock already depends on the new lock.

 the existing dependency chain (in reverse order) is:

 -> #3 (mmu_notifier_invalidate_range_start){+.+.}-{0:0}:
       fs_reclaim_acquire+0x60/0xd0
       mem_cgroup_css_alloc+0x6f/0x9b0
       cgroup_init_subsys+0xa4/0x240
       cgroup_init+0x1c8/0x510
       start_kernel+0x747/0x760
       x86_64_start_reservations+0x25/0x30
       x86_64_start_kernel+0x73/0x80
       common_startup_64+0x129/0x138

 -> #2 (fs_reclaim){+.+.}-{0:0}:
       fs_reclaim_acquire+0x91/0xd0
       __kmalloc_cache_noprof+0x4d/0x4c0
       mlx5r_cache_create_ent_locked+0x75/0x620 [mlx5_ib]
       mlx5_mkey_cache_init+0x186/0x360 [mlx5_ib]
       mlx5_ib_stage_post_ib_reg_umr_init+0x3c/0x60 [mlx5_ib]
       __mlx5_ib_add+0x4b/0x190 [mlx5_ib]
       mlx5r_probe+0xd9/0x320 [mlx5_ib]
       auxiliary_bus_probe+0x42/0x70
       really_probe+0xdb/0x360
       __driver_probe_device+0x8f/0x130
       driver_probe_device+0x1f/0xb0
       __driver_attach+0xd4/0x1f0
       bus_for_each_dev+0x79/0xd0
       bus_add_driver+0xf0/0x200
       driver_register+0x6e/0xc0
       __auxiliary_driver_register+0x6a/0xc0
       do_one_initcall+0x5e/0x390
       do_init_module+0x88/0x240
       init_module_from_file+0x85/0xc0
       idempotent_init_module+0x104/0x300
       __x64_sys_finit_module+0x68/0xc0
       do_syscall_64+0x6d/0x140
       entry_SYSCALL_64_after_hwframe+0x4b/0x53

 -> #1 (&dev->cache.rb_lock){+.+.}-{4:4}:
       __mutex_lock+0x98/0xf10
       __mlx5_ib_dereg_mr+0x6f2/0x890 [mlx5_ib]
       mlx5_ib_dereg_mr+0x21/0x110 [mlx5_ib]
       ib_dereg_mr_user+0x85/0x1f0 [ib_core]
       uverbs_free_mr+0x19/0x30 [ib_uverbs]
       destroy_hw_idr_uobject+0x21/0x80 [ib_uverbs]
       uverbs_destroy_uobject+0x60/0x3d0 [ib_uverbs]
       uobj_destroy+0x57/0xa0 [ib_uverbs]
       ib_uverbs_cmd_verbs+0x4d5/0x1210 [ib_uverbs]
       ib_uverbs_ioctl+0x129/0x230 [ib_uverbs]
       __x64_sys_ioctl+0x596/0xaa0
       do_syscall_64+0x6d/0x140
       entry_SYSCALL_64_after_hwframe+0x4b/0x53

 -> #0 (&umem_odp->umem_mutex){+.+.}-{4:4}:
       __lock_acquire+0x1826/0x2f00
       lock_acquire+0xd3/0x2e0
       __mutex_lock+0x98/0xf10
       mlx5_ib_invalidate_range+0x5b/0x550 [mlx5_ib]
       __mmu_notifier_invalidate_range_start+0x18e/0x1f0
       unmap_vmas+0x182/0x1a0
       exit_mmap+0xf3/0x4a0
       mmput+0x3a/0x100
       do_exit+0x2b9/0xa90
       do_group_exit+0x32/0xa0
       get_signal+0xc32/0xcb0
       arch_do_signal_or_restart+0x29/0x1d0
       syscall_exit_to_user_mode+0x105/0x1d0
       do_syscall_64+0x79/0x140
       entry_SYSCALL_64_after_hwframe+0x4b/0x53

 Chain exists of:
 &dev->cache.rb_lock --> mmu_notifier_invalidate_range_start -->
 &umem_odp->umem_mutex

 Possible unsafe locking scenario:

       CPU0                        CPU1
       ----                        ----
   lock(&umem_odp->umem_mutex);
                                lock(mmu_notifier_invalidate_range_start);
                                lock(&umem_odp->umem_mutex);
   lock(&dev->cache.rb_lock);

 *** DEADLOCK ***

Fixes: abb604a1a9c8 ("RDMA/mlx5: Fix a race for an ODP MR which leads to CQE with error")
Signed-off-by: Or Har-Toov <ohartoov@nvidia.com>
Reviewed-by: Michael Guralnik <michaelgur@nvidia.com>
Link: https://patch.msgid.link/3c8f225a8a9fade647d19b014df1172544643e4a.1750061612.git.leon@kernel.org
Signed-off-by: Leon Romanovsky <leon@kernel.org>
```

**Diff:**
```diff
diff --git a/drivers/infiniband/hw/mlx5/mr.c b/drivers/infiniband/hw/mlx5/mr.c
index 57f9bc2a4a3a..bd35e75d9ce5 100644
--- a/drivers/infiniband/hw/mlx5/mr.c
+++ b/drivers/infiniband/hw/mlx5/mr.c
@@ -2027,23 +2027,50 @@ void mlx5_ib_revoke_data_direct_mrs(struct mlx5_ib_dev *dev)
 	}
 }
 
-static int mlx5_revoke_mr(struct mlx5_ib_mr *mr)
+static int mlx5_umr_revoke_mr_with_lock(struct mlx5_ib_mr *mr)
 {
-	struct mlx5_ib_dev *dev = to_mdev(mr->ibmr.device);
-	struct mlx5_cache_ent *ent = mr->mmkey.cache_ent;
-	bool is_odp = is_odp_mr(mr);
 	bool is_odp_dma_buf = is_dmabuf_mr(mr) &&
-			!to_ib_umem_dmabuf(mr->umem)->pinned;
-	bool from_cache = !!ent;
-	int ret = 0;
+			      !to_ib_umem_dmabuf(mr->umem)->pinned;
+	bool is_odp = is_odp_mr(mr);
+	int ret;
 
 	if (is_odp)
 		mutex_lock(&to_ib_umem_odp(mr->umem)->umem_mutex);
 
 	if (is_odp_dma_buf)
-		dma_resv_lock(to_ib_umem_dmabuf(mr->umem)->attach->dmabuf->resv, NULL);
+		dma_resv_lock(to_ib_umem_dmabuf(mr->umem)->attach->dmabuf->resv,
+			      NULL);
+
+	ret = mlx5r_umr_revoke_mr(mr);
+
+	if (is_odp) {
+		if (!ret)
+			to_ib_umem_odp(mr->umem)->private = NULL;
+		mutex_unlock(&to_ib_umem_odp(mr->umem)->umem_mutex);
+	}
+
+	if (is_odp_dma_buf) {
+		if (!ret)
+			to_ib_umem_dmabuf(mr->umem)->private = NULL;
+		dma_resv_unlock(
+			to_ib_umem_dmabuf(mr->umem)->attach->dmabuf->resv);
+	}
 
-	if (mr->mmkey.cacheable && !mlx5r_umr_revoke_mr(mr) && !cache_ent_find_and_store(dev, mr)) {
+	return ret;
+}
+
+static int mlx5r_handle_mkey_cleanup(struct mlx5_ib_mr *mr)

... (truncated 60 lines)
```

---

## Commit 3: d02b2103

**Author:** Arnd Bergmann
**Date:** 2025-06-25 10:23:16
**Files Changed:** drivers/gpu/drm/i915/i915_pmu.c

**Message:**
```
drm/i915: fix build error some more

An earlier patch fixed a build failure with clang, but I still see the
same problem with some configurations using gcc:

drivers/gpu/drm/i915/i915_pmu.c: In function 'config_mask':
include/linux/compiler_types.h:568:38: error: call to '__compiletime_assert_462' declared with attribute error: BUILD_BUG_ON failed: bit > BITS_PER_TYPE(typeof_member(struct i915_pmu, enable)) - 1
drivers/gpu/drm/i915/i915_pmu.c:116:3: note: in expansion of macro 'BUILD_BUG_ON'
  116 |   BUILD_BUG_ON(bit >

As I understand it, the problem is that the function is not always fully
inlined, but the __builtin_constant_p() can still evaluate the argument
as being constant.

Marking it as __always_inline so far works for me in all configurations.

Fixes: a7137b1825b5 ("drm/i915/pmu: Fix build error with GCOV and AutoFDO enabled")
Fixes: a644fde77ff7 ("drm/i915/pmu: Change bitmask of enabled events to u32")
Reviewed-by: Rodrigo Vivi <rodrigo.vivi@intel.com>
Signed-off-by: Arnd Bergmann <arnd@arndb.de>
Link: https://lore.kernel.org/r/20250620111824.3395007-1-arnd@kernel.org
Signed-off-by: Rodrigo Vivi <rodrigo.vivi@intel.com>
(cherry picked from commit ef69f9dd1cd7301cdf04ba326ed28152a3affcf6)
Signed-off-by: Joonas Lahtinen <joonas.lahtinen@linux.intel.com>
```

**Diff:**
```diff
diff --git a/drivers/gpu/drm/i915/i915_pmu.c b/drivers/gpu/drm/i915/i915_pmu.c
index 990bfaba3ce4..5bc696bfbb0f 100644
--- a/drivers/gpu/drm/i915/i915_pmu.c
+++ b/drivers/gpu/drm/i915/i915_pmu.c
@@ -108,7 +108,7 @@ static unsigned int config_bit(const u64 config)
 		return other_bit(config);
 }
 
-static u32 config_mask(const u64 config)
+static __always_inline u32 config_mask(const u64 config)
 {
 	unsigned int bit = config_bit(config);
 
```

---

## Commit 4: 5e957175

**Author:** Pei Xiao
**Date:** 2025-06-25 08:28:16
**Files Changed:** sound/usb/qcom/qc_audio_offload.c

**Message:**
```
ALSA: usb: qcom: fix NULL pointer dereference in qmi_stop_session

The find_substream() call may return NULL, but the error path
dereferenced 'subs' unconditionally via dev_err(&subs->dev->dev, ...),
causing a NULL pointer dereference when subs is NULL.

Fix by switching to &uadev[idx].udev->dev which is always valid
in this context.

Signed-off-by: Pei Xiao <xiaopei01@kylinos.cn>
Link: https://patch.msgid.link/86ac2939273ac853535049e60391c09d7688714e.1750755508.git.xiaopei01@kylinos.cn
Signed-off-by: Takashi Iwai <tiwai@suse.de>
```

**Diff:**
```diff
diff --git a/sound/usb/qcom/qc_audio_offload.c b/sound/usb/qcom/qc_audio_offload.c
index 797afd4561bd..3543b5a53592 100644
--- a/sound/usb/qcom/qc_audio_offload.c
+++ b/sound/usb/qcom/qc_audio_offload.c
@@ -759,7 +759,7 @@ static void qmi_stop_session(void)
 			subs = find_substream(pcm_card_num, info->pcm_dev_num,
 					      info->direction);
 			if (!subs || !chip || atomic_read(&chip->shutdown)) {
-				dev_err(&subs->dev->dev,
+				dev_err(&uadev[idx].udev->dev,
 					"no sub for c#%u dev#%u dir%u\n",
 					info->pcm_card_num,
 					info->pcm_dev_num,
```

---

## Commit 5: 524346e9

**Author:** Ming Lei
**Date:** 2025-06-24 20:44:52
**Files Changed:** drivers/block/ublk_drv.c

**Message:**
```
ublk: build batch from IOs in same io_ring_ctx and io task

ublk_queue_cmd_list() dispatches the whole batch list by scheduling task
work via the tail request's io_uring_cmd, this way is fine even though
more than one io_ring_ctx are involved for this batch since it is just
one running context.

However, the task work handler ublk_cmd_list_tw_cb() takes `issue_flags`
of tail uring_cmd's io_ring_ctx for completing all commands. This way is
wrong if any uring_cmd is issued from different io_ring_ctx.

Fixes it by always building batch IOs from same io_ring_ctx and io task
because ublk_dispatch_req() does validate task context, and IO needs to
be aborted in case of running from fallback task work context.

For typical per-queue or per-io daemon implementation, this way shouldn't
make difference from performance viewpoint, because single io_ring_ctx is
taken in each daemon for normal use case.

Fixes: d796cea7b9f3 ("ublk: implement ->queue_rqs()")
Signed-off-by: Ming Lei <ming.lei@redhat.com>
Link: https://lore.kernel.org/r/20250625022554.883571-1-ming.lei@redhat.com
Signed-off-by: Jens Axboe <axboe@kernel.dk>
```

**Diff:**
```diff
diff --git a/drivers/block/ublk_drv.c b/drivers/block/ublk_drv.c
index d36f44f5ee80..90c02ced392a 100644
--- a/drivers/block/ublk_drv.c
+++ b/drivers/block/ublk_drv.c
@@ -1416,6 +1416,14 @@ static blk_status_t ublk_queue_rq(struct blk_mq_hw_ctx *hctx,
 	return BLK_STS_OK;
 }
 
+static inline bool ublk_belong_to_same_batch(const struct ublk_io *io,
+					     const struct ublk_io *io2)
+{
+	return (io_uring_cmd_ctx_handle(io->cmd) ==
+		io_uring_cmd_ctx_handle(io2->cmd)) &&
+		(io->task == io2->task);
+}
+
 static void ublk_queue_rqs(struct rq_list *rqlist)
 {
 	struct rq_list requeue_list = { };
@@ -1427,7 +1435,8 @@ static void ublk_queue_rqs(struct rq_list *rqlist)
 		struct ublk_queue *this_q = req->mq_hctx->driver_data;
 		struct ublk_io *this_io = &this_q->ios[req->tag];
 
-		if (io && io->task != this_io->task && !rq_list_empty(&submit_list))
+		if (io && !ublk_belong_to_same_batch(io, this_io) &&
+				!rq_list_empty(&submit_list))
 			ublk_queue_cmd_list(io, &submit_list);
 		io = this_io;
 
```

---

