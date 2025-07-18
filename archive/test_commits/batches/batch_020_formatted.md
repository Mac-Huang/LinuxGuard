# Linux Kernel Commit Batch Analysis

## Commit 1: 7e4a6b57

**Author:** Linus Torvalds
**Date:** 2025-07-02 09:17:40
**Files Changed:** drivers/infiniband/core/cache.c, drivers/infiniband/core/umem_odp.c, drivers/infiniband/hw/mlx5/counters.c, drivers/infiniband/hw/mlx5/devx.c, drivers/infiniband/hw/mlx5/main.c (+2 more)

**Message:**
```
Merge tag 'for-linus' of git://git.kernel.org/pub/scm/linux/kernel/git/rdma/rdma

Pull rdma fixes from Jason Gunthorpe:
 "Several mlx5 bugs, crashers, and reports:

   - Limit stack usage

   - Fix mis-use of __xa_store/erase() without holding the lock to a
     locked version

   - Rate limit prints in the gid cache error cases

   - Fully initialize the event object before making it globally visible
     in an xarray

   - Fix deadlock inside the ODP code if the MMU notifier was called
     from a reclaim context

   - Include missed counters for some switchdev configurations and
     mulit-port MPV mode

   - Fix loopback packet support when in mulit-port MPV mode"

* tag 'for-linus' of git://git.kernel.org/pub/scm/linux/kernel/git/rdma/rdma:
  RDMA/mlx5: Fix vport loopback for MPV device
  RDMA/mlx5: Fix CC counters query for MPV
  RDMA/mlx5: Fix HW counters query for non-representor devices
  IB/core: Annotate umem_mutex acquisition under fs_reclaim for lockdep
  IB/mlx5: Fix potential deadlock in MR deregistration
  RDMA/mlx5: Initialize obj_event->obj_sub_list before xa_insert
  RDMA/core: Rate limit GID cache warning messages
  RDMA/mlx5: Fix unsafe xarray access in implicit ODP handling
  RDMA/mlx5: reduce stack usage in mlx5_ib_ufile_hw_cleanup
```

**Diff:**
```diff
diff --git a/drivers/infiniband/core/cache.c b/drivers/infiniband/core/cache.c
index 9979a351577f..81cf3c902e81 100644
--- a/drivers/infiniband/core/cache.c
+++ b/drivers/infiniband/core/cache.c
@@ -582,8 +582,8 @@ static int __ib_cache_gid_add(struct ib_device *ib_dev, u32 port,
 out_unlock:
 	mutex_unlock(&table->lock);
 	if (ret)
-		pr_warn("%s: unable to add gid %pI6 error=%d\n",
-			__func__, gid->raw, ret);
+		pr_warn_ratelimited("%s: unable to add gid %pI6 error=%d\n",
+				    __func__, gid->raw, ret);
 	return ret;
 }
 
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
diff --git a/drivers/infiniband/hw/mlx5/counters.c b/drivers/infiniband/hw/mlx5/counters.c
index b847084dcd99..a506fafd2b15 100644
--- a/drivers/infiniband/hw/mlx5/counters.c
+++ b/drivers/infiniband/hw/mlx5/counters.c
@@ -398,7 +398,7 @@ static int do_get_hw_stats(struct ib_device *ibdev,
 		return ret;
 
 	/* We don't expose device counters over Vports */
-	if (is_mdev_switchdev_mode(dev->mdev) && port_num != 0)
+	if (is_mdev_switchdev_mode(dev->mdev) && dev->is_rep && port_num != 0)
 		goto done;
 
 	if (MLX5_CAP_PCAM_FEATURE(dev->mdev, rx_icrc_encapsulated_counter)) {

... (truncated 252 lines)
```

---

## Commit 2: 34a500ca

**Author:** Kohei Enju
**Date:** 2025-07-01 19:28:48
**Files Changed:** net/rose/rose_route.c

**Message:**
```
rose: fix dangling neighbour pointers in rose_rt_device_down()

There are two bugs in rose_rt_device_down() that can cause
use-after-free:

1. The loop bound `t->count` is modified within the loop, which can
   cause the loop to terminate early and miss some entries.

2. When removing an entry from the neighbour array, the subsequent entries
   are moved up to fill the gap, but the loop index `i` is still
   incremented, causing the next entry to be skipped.

For example, if a node has three neighbours (A, A, B) with count=3 and A
is being removed, the second A is not checked.

    i=0: (A, A, B) -> (A, B) with count=2
          ^ checked
    i=1: (A, B)    -> (A, B) with count=2
             ^ checked (B, not A!)
    i=2: (doesn't occur because i < count is false)

This leaves the second A in the array with count=2, but the rose_neigh
structure has been freed. Code that accesses these entries assumes that
the first `count` entries are valid pointers, causing a use-after-free
when it accesses the dangling pointer.

Fix both issues by iterating over the array in reverse order with a fixed
loop bound. This ensures that all entries are examined and that the removal
of an entry doesn't affect subsequent iterations.

Reported-by: syzbot+e04e2c007ba2c80476cb@syzkaller.appspotmail.com
Closes: https://syzkaller.appspot.com/bug?extid=e04e2c007ba2c80476cb
Tested-by: syzbot+e04e2c007ba2c80476cb@syzkaller.appspotmail.com
Fixes: 1da177e4c3f4 ("Linux-2.6.12-rc2")
Signed-off-by: Kohei Enju <enjuk@amazon.com>
Reviewed-by: Simon Horman <horms@kernel.org>
Link: https://patch.msgid.link/20250629030833.6680-1-enjuk@amazon.com
Signed-off-by: Jakub Kicinski <kuba@kernel.org>
```

**Diff:**
```diff
diff --git a/net/rose/rose_route.c b/net/rose/rose_route.c
index 2dd6bd3a3011..b72bf8a08d48 100644
--- a/net/rose/rose_route.c
+++ b/net/rose/rose_route.c
@@ -497,22 +497,15 @@ void rose_rt_device_down(struct net_device *dev)
 			t         = rose_node;
 			rose_node = rose_node->next;
 
-			for (i = 0; i < t->count; i++) {
+			for (i = t->count - 1; i >= 0; i--) {
 				if (t->neighbour[i] != s)
 					continue;
 
 				t->count--;
 
-				switch (i) {
-				case 0:
-					t->neighbour[0] = t->neighbour[1];
-					fallthrough;
-				case 1:
-					t->neighbour[1] = t->neighbour[2];
-					break;
-				case 2:
-					break;
-				}
+				memmove(&t->neighbour[i], &t->neighbour[i + 1],
+					sizeof(t->neighbour[0]) *
+						(t->count - i));
 			}
 
 			if (t->count <= 0)
```

---

## Commit 3: bf906c98

**Author:** Dave Airlie
**Date:** 2025-07-02 11:18:24
**Files Changed:** drivers/gpu/drm/amd/amdgpu/amdgpu_amdkfd_gfx_v7.c, drivers/gpu/drm/amd/amdgpu/amdgpu_amdkfd_gfx_v8.c, drivers/gpu/drm/amd/amdgpu/amdgpu_ctx.c, drivers/gpu/drm/amd/amdgpu/sdma_v4_4_2.c, drivers/gpu/drm/amd/amdgpu/sdma_v5_0.c (+5 more)

**Message:**
```
Merge tag 'amd-drm-fixes-6.16-2025-07-01' of https://gitlab.freedesktop.org/agd5f/linux into drm-fixes

amd-drm-fixes-6.16-2025-07-01:

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

Signed-off-by: Dave Airlie <airlied@redhat.com>

From: Alex Deucher <alexander.deucher@amd.com>
Link: https://lore.kernel.org/r/20250701192642.32490-1-alexander.deucher@amd.com
```

**Diff:**
```diff
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
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_amdkfd_gfx_v8.c
@@ -582,6 +582,13 @@ static void set_vm_context_page_table_base(struct amdgpu_device *adev,
 			lower_32_bits(page_table_base));
 }
 
+static uint32_t kgd_hqd_sdma_get_doorbell(struct amdgpu_device *adev,
+					  int engine, int queue)
+
+{
+	return 0;
+}
+
 const struct kfd2kgd_calls gfx_v8_kfd2kgd = {
 	.program_sh_mem_settings = kgd_program_sh_mem_settings,
 	.set_pasid_vmid_mapping = kgd_set_pasid_vmid_mapping,
@@ -599,4 +606,5 @@ const struct kfd2kgd_calls gfx_v8_kfd2kgd = {
 			get_atc_vmid_pasid_mapping_info,
 	.set_scratch_backing_va = set_scratch_backing_va,
 	.set_vm_context_page_table_base = set_vm_context_page_table_base,
+	.hqd_sdma_get_doorbell = kgd_hqd_sdma_get_doorbell,
 };
diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_ctx.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_ctx.c
index 85567d0d9545..f5d5c45ddc0d 100644

... (truncated 233 lines)
```

---

## Commit 4: c6e8d51b

**Author:** Kent Overstreet
**Date:** 2025-07-01 19:33:46
**Files Changed:** fs/bcachefs/btree_io.c

**Message:**
```
bcachefs: Work around deadlock to btree node rewrites in journal replay

Don't mark btree nodes for rewrites, if they are or would be degraded,
if journal replay hasn't finished, to avoid a deadlock.

This is because btree node rewrites generate more updates for the
interior updates (alloc, backpointers), and if those updates touch
new nodes and generate more rewrites - we can only have so many interior
btree updates in flight before we deadlock on open_buckets.

The biggest cause is that we don't use the btree write buffer (for
the backpointer updates - this needs some real thought on locking in
order to fix.

The problem with this workaround (not doing the rewrite for degraded
nodes in journal replay) is that those degraded nodes persist, and we
don't want that (this is a real bug when a btree node write completes
with fewer replicas than we wanted and leaves a degraded node due to
device _removal_, i.e. the device went away mid write).

It's less of a bug here, but still a problem because we don't yet
have a way of tracking degraded data - we another index (all
extents/btree nodes, by replicas entry) in order to fix properly
(re-replicate degraded data at the earliest possible time).

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
```

**Diff:**
```diff
diff --git a/fs/bcachefs/btree_io.c b/fs/bcachefs/btree_io.c
index 08b22bddd747..e874a4357f64 100644
--- a/fs/bcachefs/btree_io.c
+++ b/fs/bcachefs/btree_io.c
@@ -1337,15 +1337,42 @@ int bch2_btree_node_read_done(struct bch_fs *c, struct bch_dev *ca,
 
 	btree_node_reset_sib_u64s(b);
 
-	scoped_guard(rcu)
-		bkey_for_each_ptr(bch2_bkey_ptrs(bkey_i_to_s(&b->key)), ptr) {
-			struct bch_dev *ca2 = bch2_dev_rcu(c, ptr->dev);
-
-			if (!ca2 || ca2->mi.state != BCH_MEMBER_STATE_rw) {
-				set_btree_node_need_rewrite(b);
-				set_btree_node_need_rewrite_degraded(b);
+	/*
+	 * XXX:
+	 *
+	 * We deadlock if too many btree updates require node rewrites while
+	 * we're still in journal replay.
+	 *
+	 * This is because btree node rewrites generate more updates for the
+	 * interior updates (alloc, backpointers), and if those updates touch
+	 * new nodes and generate more rewrites - well, you see the problem.
+	 *
+	 * The biggest cause is that we don't use the btree write buffer (for
+	 * the backpointer updates - this needs some real thought on locking in
+	 * order to fix.
+	 *
+	 * The problem with this workaround (not doing the rewrite for degraded
+	 * nodes in journal replay) is that those degraded nodes persist, and we
+	 * don't want that (this is a real bug when a btree node write completes
+	 * with fewer replicas than we wanted and leaves a degraded node due to
+	 * device _removal_, i.e. the device went away mid write).
+	 *
+	 * It's less of a bug here, but still a problem because we don't yet
+	 * have a way of tracking degraded data - we another index (all
+	 * extents/btree nodes, by replicas entry) in order to fix properly
+	 * (re-replicate degraded data at the earliest possible time).
+	 */
+	if (c->recovery.passes_complete & BIT_ULL(BCH_RECOVERY_PASS_journal_replay)) {
+		scoped_guard(rcu)
+			bkey_for_each_ptr(bch2_bkey_ptrs(bkey_i_to_s(&b->key)), ptr) {
+				struct bch_dev *ca2 = bch2_dev_rcu(c, ptr->dev);
+
+				if (!ca2 || ca2->mi.state != BCH_MEMBER_STATE_rw) {
+					set_btree_node_need_rewrite(b);
+					set_btree_node_need_rewrite_degraded(b);
+				}
 			}

... (truncated 5 lines)
```

---

## Commit 5: d5cb81ba

**Author:** Christian Brauner
**Date:** 2025-07-01 22:37:20
**Files Changed:** fs/netfs/buffered_write.c, fs/netfs/direct_write.c, fs/netfs/internal.h, fs/netfs/main.c, fs/netfs/misc.c (+7 more)

**Message:**
```
Merge patch series "netfs, cifs: Fixes to retry-related code"

David Howells <dhowells@redhat.com> says:

Here are some miscellaneous fixes and changes for netfslib and cifs, if you
could consider pulling them.

Many of these were found because a bug in Samba was causing smbd to crash
and restart after about 1-2s and this was vigorously and abruptly
exercising the netfslib retry paths.

Subsequent testing of the cifs RDMA support showed up some more bugs, but
the fixes for those went via the cifs tree and have been removed from this set
as they're now upstream.

First, there are some netfs fixes:

 (1) Fix a hang due to missing case in final DIO read result collection
     not breaking out of a loop if the request finished, but there were no
     subrequests being processed and NETFS_RREQ_ALL_QUEUED wasn't yet set.

 (2) Fix a double put of the netfs_io_request struct if completion happened
     in the pause loop.

 (3) Provide some helpers to abstract out NETFS_RREQ_IN_PROGRESS flag
     wrangling.

 (4) Fix infinite looping in netfs_wait_for_pause/request() which wa caused
     by a loop waiting for NETFS_RREQ_ALL_QUEUED to get set - but which
     wouldn't get set until the looping function returned.  This uses patch
     (3) above.

 (5) Fix a ref leak on an extra subrequest inserted into a request's list
     of subreqs because more subreq records were needed for retrying than
     were needed for the original request (say, for instance, that the
     amount of cifs credit available was reduced and, subsequently, the ops
     had to be smaller).

Then a bunch of cifs fixes, some of which are from other people:

 (6-8) cifs: Fix various RPC callbacks to set NETFS_SREQ_NEED_RETRY if a
     subrequest fails retriably.

(10) Fix a warning in the workqueue code when reconnecting a channel.

Followed by some patches to deal with i_size handling:

(11) Fix the updating of i_size to use a lock to avoid a race between
     testing if we should have extended the file with a DIO write and
     changing i_size.

(12) A follow-up patch to (11) to merge the places in netfslib that update
     i_size on write.

And finally a couple of patches to improve tracing output, but that should
otherwise not affect functionality:

(13) Renumber the NETFS_RREQ_* flags to make the hex values easier to
     interpret by eye, including moving the main status flags down to the
     lowest bits, with IN_PROGRESS in bit 0.

(14) Update the tracepoints in a number of ways, including adding more
     tracepoints into the cifs read/write RPC callback so that differend
     MID_RESPONSE_* values can be differentiated.

* patches from https://lore.kernel.org/20250701163852.2171681-1-dhowells@redhat.com:
  netfs: Update tracepoints in a number of ways
  netfs: Renumber the NETFS_RREQ_* flags to make traces easier to read
  netfs: Merge i_size update functions
  netfs: Fix i_size updating
  smb: client: set missing retry flag in cifs_writev_callback()
  smb: client: set missing retry flag in cifs_readv_callback()
  smb: client: set missing retry flag in smb2_writev_callback()
  netfs: Fix ref leak on inserted extra subreq in write retry
  netfs: Fix looping in wait functions
  netfs: Provide helpers to perform NETFS_RREQ_IN_PROGRESS flag wangling
  netfs: Fix double put of request
  netfs: Fix hang due to missing case in final DIO read result collection

Link: https://lore.kernel.org/20250701163852.2171681-1-dhowells@redhat.com
Signed-off-by: Christian Brauner <brauner@kernel.org>
```

**Diff:**
```diff
diff --git a/fs/netfs/buffered_write.c b/fs/netfs/buffered_write.c
index 72a3e6db2524..f27ea5099a68 100644
--- a/fs/netfs/buffered_write.c
+++ b/fs/netfs/buffered_write.c
@@ -53,30 +53,40 @@ static struct folio *netfs_grab_folio_for_write(struct address_space *mapping,
  * data written into the pagecache until we can find out from the server what
  * the values actually are.
  */
-static void netfs_update_i_size(struct netfs_inode *ctx, struct inode *inode,
-				loff_t i_size, loff_t pos, size_t copied)
+void netfs_update_i_size(struct netfs_inode *ctx, struct inode *inode,
+			 loff_t pos, size_t copied)
 {
+	loff_t i_size, end = pos + copied;
 	blkcnt_t add;
 	size_t gap;
 
+	if (end <= i_size_read(inode))
+		return;
+
 	if (ctx->ops->update_i_size) {
-		ctx->ops->update_i_size(inode, pos);
+		ctx->ops->update_i_size(inode, end);
 		return;
 	}
 
-	i_size_write(inode, pos);
+	spin_lock(&inode->i_lock);
+
+	i_size = i_size_read(inode);
+	if (end > i_size) {
+		i_size_write(inode, end);
 #if IS_ENABLED(CONFIG_FSCACHE)
-	fscache_update_cookie(ctx->cache, NULL, &pos);
+		fscache_update_cookie(ctx->cache, NULL, &end);
 #endif
 
-	gap = SECTOR_SIZE - (i_size & (SECTOR_SIZE - 1));
-	if (copied > gap) {
-		add = DIV_ROUND_UP(copied - gap, SECTOR_SIZE);
+		gap = SECTOR_SIZE - (i_size & (SECTOR_SIZE - 1));
+		if (copied > gap) {
+			add = DIV_ROUND_UP(copied - gap, SECTOR_SIZE);
 
-		inode->i_blocks = min_t(blkcnt_t,
-					DIV_ROUND_UP(pos, SECTOR_SIZE),
-					inode->i_blocks + add);
+			inode->i_blocks = min_t(blkcnt_t,
+						DIV_ROUND_UP(end, SECTOR_SIZE),
+						inode->i_blocks + add);

... (truncated 689 lines)
```

---

