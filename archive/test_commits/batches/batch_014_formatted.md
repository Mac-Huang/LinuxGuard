# Linux Kernel Commit Batch Analysis

## Commit 1: 482deed9

**Author:** Linus Torvalds
**Date:** 2025-07-04 09:29:22
**Files Changed:** fs/bcachefs/bcachefs.h, fs/bcachefs/btree_io.c, fs/bcachefs/btree_iter.c, fs/bcachefs/dirent.c, fs/bcachefs/dirent.h (+8 more)

**Message:**
```
Merge tag 'bcachefs-2025-07-03' of git://evilpiepirate.org/bcachefs

Pull bcachefs fixes from Kent Overstreet:
 "The 'opts.casefold_disabled' patch is non critical, but would be a
  6.15 backport; it's to address the casefolding + overlayfs
  incompatibility that was discovvered late.

  It's late because I was hoping that this would be addressed on the
  overlayfs side (and will be in 6.17), but user reports keep coming in
  on this one (lots of people are using docker these days)"

* tag 'bcachefs-2025-07-03' of git://evilpiepirate.org/bcachefs:
  bcachefs: opts.casefold_disabled
  bcachefs: Work around deadlock to btree node rewrites in journal replay
  bcachefs: Fix incorrect transaction restart handling
  bcachefs: fix btree_trans_peek_prev_journal()
  bcachefs: mark invalid_btree_id autofix
```

**Diff:**
```diff
diff --git a/fs/bcachefs/bcachefs.h b/fs/bcachefs/bcachefs.h
index 8043943cdf6a..ddfacad0f70c 100644
--- a/fs/bcachefs/bcachefs.h
+++ b/fs/bcachefs/bcachefs.h
@@ -863,9 +863,7 @@ struct bch_fs {
 	DARRAY(enum bcachefs_metadata_version)
 				incompat_versions_requested;
 
-#ifdef CONFIG_UNICODE
 	struct unicode_map	*cf_encoding;
-#endif
 
 	struct bch_sb_handle	disk_sb;
 
@@ -1285,4 +1283,13 @@ static inline bool bch2_discard_opt_enabled(struct bch_fs *c, struct bch_dev *ca
 		: ca->mi.discard;
 }
 
+static inline bool bch2_fs_casefold_enabled(struct bch_fs *c)
+{
+#ifdef CONFIG_UNICODE
+	return !c->opts.casefold_disabled;
+#else
+	return false;
+#endif
+}
+
 #endif /* _BCACHEFS_H */
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

... (truncated 334 lines)
```

---

## Commit 2: 2eb7f03a

**Author:** Linus Torvalds
**Date:** 2025-07-04 09:06:49
**Files Changed:** fs/anon_inodes.c, fs/eventpoll.c, fs/exec.c, fs/fuse/file.c, fs/libfs.c (+16 more)

**Message:**
```
Merge tag 'vfs-6.16-rc5.fixes' of git://git.kernel.org/pub/scm/linux/kernel/git/vfs/vfs

Pull vfs fixes from Christian Brauner:

 - Fix a regression caused by the anonymous inode rework. Making them
   regular files causes various places in the kernel to tip over
   starting with io_uring.

   Revert to the former status quo and port our assertion to be based on
   checking the inode so we don't lose the valuable VFS_*_ON_*()
   assertions that have already helped discover weird behavior our
   outright bugs.

 - Fix the the upper bound calculation in fuse_fill_write_pages()

 - Fix priority inversion issues in the eventpoll code

 - Make secretmen use anon_inode_make_secure_inode() to avoid bypassing
   the LSM layer

 - Fix a netfs hang due to missing case in final DIO read result
   collection

 - Fix a double put of the netfs_io_request struct

 - Provide some helpers to abstract out NETFS_RREQ_IN_PROGRESS flag
   wrangling

 - Fix infinite looping in netfs_wait_for_pause/request()

 - Fix a netfs ref leak on an extra subrequest inserted into a request's
   list of subreqs

 - Fix various cifs RPC callbacks to set NETFS_SREQ_NEED_RETRY if a
   subrequest fails retriably

 - Fix a cifs warning in the workqueue code when reconnecting a channel

 - Fix the updating of i_size in netfs to avoid a race between testing
   if we should have extended the file with a DIO write and changing
   i_size

 - Merge the places in netfs that update i_size on write

 - Fix coredump socket selftests

* tag 'vfs-6.16-rc5.fixes' of git://git.kernel.org/pub/scm/linux/kernel/git/vfs/vfs:
  anon_inode: rework assertions
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
  eventpoll: Fix priority inversion problem
  fuse: fix fuse_fill_write_pages() upper bound calculation
  fs: export anon_inode_make_secure_inode() and fix secretmem LSM bypass
  selftests/coredump: Fix "socket_detect_userspace_client" test failure
```

**Diff:**
```diff
diff --git a/fs/anon_inodes.c b/fs/anon_inodes.c
index e51e7d88980a..1d847a939f29 100644
--- a/fs/anon_inodes.c
+++ b/fs/anon_inodes.c
@@ -98,14 +98,25 @@ static struct file_system_type anon_inode_fs_type = {
 	.kill_sb	= kill_anon_super,
 };
 
-static struct inode *anon_inode_make_secure_inode(
-	const char *name,
-	const struct inode *context_inode)
+/**
+ * anon_inode_make_secure_inode - allocate an anonymous inode with security context
+ * @sb:		[in]	Superblock to allocate from
+ * @name:	[in]	Name of the class of the newfile (e.g., "secretmem")
+ * @context_inode:
+ *		[in]	Optional parent inode for security inheritance
+ *
+ * The function ensures proper security initialization through the LSM hook
+ * security_inode_init_security_anon().
+ *
+ * Return:	Pointer to new inode on success, ERR_PTR on failure.
+ */
+struct inode *anon_inode_make_secure_inode(struct super_block *sb, const char *name,
+					   const struct inode *context_inode)
 {
 	struct inode *inode;
 	int error;
 
-	inode = alloc_anon_inode(anon_inode_mnt->mnt_sb);
+	inode = alloc_anon_inode(sb);
 	if (IS_ERR(inode))
 		return inode;
 	inode->i_flags &= ~S_PRIVATE;
@@ -118,6 +129,7 @@ static struct inode *anon_inode_make_secure_inode(
 	}
 	return inode;
 }
+EXPORT_SYMBOL_GPL_FOR_MODULES(anon_inode_make_secure_inode, "kvm");
 
 static struct file *__anon_inode_getfile(const char *name,
 					 const struct file_operations *fops,
@@ -132,7 +144,8 @@ static struct file *__anon_inode_getfile(const char *name,
 		return ERR_PTR(-ENOENT);
 
 	if (make_inode) {
-		inode =	anon_inode_make_secure_inode(name, context_inode);
+		inode =	anon_inode_make_secure_inode(anon_inode_mnt->mnt_sb,
+						     name, context_inode);
 		if (IS_ERR(inode)) {

... (truncated 1617 lines)
```

---

## Commit 3: d38376b3

**Author:** Alessio Belle
**Date:** 2025-07-04 16:32:10
**Files Changed:** drivers/gpu/drm/imagination/pvr_power.c

**Message:**
```
drm/imagination: Fix kernel crash when hard resetting the GPU

The GPU hard reset sequence calls pm_runtime_force_suspend() and
pm_runtime_force_resume(), which according to their documentation should
only be used during system-wide PM transitions to sleep states.

The main issue though is that depending on some internal runtime PM
state as seen by pm_runtime_force_suspend() (whether the usage count is
<= 1), pm_runtime_force_resume() might not resume the device unless
needed. If that happens, the runtime PM resume callback
pvr_power_device_resume() is not called, the GPU clocks are not
re-enabled, and the kernel crashes on the next attempt to access GPU
registers as part of the power-on sequence.

Replace calls to pm_runtime_force_suspend() and
pm_runtime_force_resume() with direct calls to the driver's runtime PM
callbacks, pvr_power_device_suspend() and pvr_power_device_resume(),
to ensure clocks are re-enabled and avoid the kernel crash.

Fixes: cc1aeedb98ad ("drm/imagination: Implement firmware infrastructure and META FW support")
Signed-off-by: Alessio Belle <alessio.belle@imgtec.com>
Reviewed-by: Matt Coster <matt.coster@imgtec.com>
Link: https://lore.kernel.org/r/20250624-fix-kernel-crash-gpu-hard-reset-v1-1-6d24810d72a6@imgtec.com
Cc: stable@vger.kernel.org
Signed-off-by: Matt Coster <matt.coster@imgtec.com>
```

**Diff:**
```diff
diff --git a/drivers/gpu/drm/imagination/pvr_power.c b/drivers/gpu/drm/imagination/pvr_power.c
index 41f5d89e78b8..3e349d039fc0 100644
--- a/drivers/gpu/drm/imagination/pvr_power.c
+++ b/drivers/gpu/drm/imagination/pvr_power.c
@@ -386,13 +386,13 @@ pvr_power_reset(struct pvr_device *pvr_dev, bool hard_reset)
 		if (!err) {
 			if (hard_reset) {
 				pvr_dev->fw_dev.booted = false;
-				WARN_ON(pm_runtime_force_suspend(from_pvr_device(pvr_dev)->dev));
+				WARN_ON(pvr_power_device_suspend(from_pvr_device(pvr_dev)->dev));
 
 				err = pvr_fw_hard_reset(pvr_dev);
 				if (err)
 					goto err_device_lost;
 
-				err = pm_runtime_force_resume(from_pvr_device(pvr_dev)->dev);
+				err = pvr_power_device_resume(from_pvr_device(pvr_dev)->dev);
 				pvr_dev->fw_dev.booted = true;
 				if (err)
 					goto err_device_lost;
```

---

## Commit 4: ef8923e6

**Author:** Breno Leitao
**Date:** 2025-07-04 14:47:06
**Files Changed:** arch/arm64/kernel/efi.c

**Message:**
```
arm64: efi: Fix KASAN false positive for EFI runtime stack

KASAN reports invalid accesses during arch_stack_walk() for EFI runtime
services due to vmalloc tagging[1]. The EFI runtime stack must be allocated
with KASAN tags reset to avoid false positives.

This patch uses arch_alloc_vmap_stack() instead of __vmalloc_node() for
EFI stack allocation, which internally calls kasan_reset_tag()

The changes ensure EFI runtime stacks are properly sanitized for KASAN
while maintaining functional consistency.

Link: https://lore.kernel.org/all/aFVVEgD0236LdrL6@gmail.com/ [1]
Suggested-by: Andrey Konovalov <andreyknvl@gmail.com>
Suggested-by: Catalin Marinas <catalin.marinas@arm.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
Signed-off-by: Breno Leitao <leitao@debian.org>
Link: https://lore.kernel.org/r/20250704-arm_kasan-v2-1-32ebb4fd7607@debian.org
Signed-off-by: Will Deacon <will@kernel.org>
```

**Diff:**
```diff
diff --git a/arch/arm64/kernel/efi.c b/arch/arm64/kernel/efi.c
index 3857fd7ee8d4..62230d6dd919 100644
--- a/arch/arm64/kernel/efi.c
+++ b/arch/arm64/kernel/efi.c
@@ -15,6 +15,7 @@
 
 #include <asm/efi.h>
 #include <asm/stacktrace.h>
+#include <asm/vmap_stack.h>
 
 static bool region_is_misaligned(const efi_memory_desc_t *md)
 {
@@ -214,9 +215,13 @@ static int __init arm64_efi_rt_init(void)
 	if (!efi_enabled(EFI_RUNTIME_SERVICES))
 		return 0;
 
-	p = __vmalloc_node(THREAD_SIZE, THREAD_ALIGN, GFP_KERNEL,
-			   NUMA_NO_NODE, &&l);
-l:	if (!p) {
+	if (!IS_ENABLED(CONFIG_VMAP_STACK)) {
+		clear_bit(EFI_RUNTIME_SERVICES, &efi.flags);
+		return -ENOMEM;
+	}
+
+	p = arch_alloc_vmap_stack(THREAD_SIZE, NUMA_NO_NODE);
+	if (!p) {
 		pr_warn("Failed to allocate EFI runtime stack\n");
 		clear_bit(EFI_RUNTIME_SERVICES, &efi.flags);
 		return -ENOMEM;
```

---

## Commit 5: 44306a68

**Author:** Mikko Perttunen
**Date:** 2025-07-04 11:15:07
**Files Changed:** drivers/gpu/drm/tegra/nvdec.c

**Message:**
```
drm/tegra: nvdec: Fix dma_alloc_coherent error check

Check for NULL return value with dma_alloc_coherent, in line with
Robin's fix for vic.c in 'drm/tegra: vic: Fix DMA API misuse'.

Fixes: 46f226c93d35 ("drm/tegra: Add NVDEC driver")
Signed-off-by: Mikko Perttunen <mperttunen@nvidia.com>
Signed-off-by: Thierry Reding <treding@nvidia.com>
Link: https://lore.kernel.org/r/20250702-nvdec-dma-error-check-v1-1-c388b402c53a@nvidia.com
```

**Diff:**
```diff
diff --git a/drivers/gpu/drm/tegra/nvdec.c b/drivers/gpu/drm/tegra/nvdec.c
index 2d9a0a3f6c38..7a38664e890e 100644
--- a/drivers/gpu/drm/tegra/nvdec.c
+++ b/drivers/gpu/drm/tegra/nvdec.c
@@ -261,10 +261,8 @@ static int nvdec_load_falcon_firmware(struct nvdec *nvdec)
 
 	if (!client->group) {
 		virt = dma_alloc_coherent(nvdec->dev, size, &iova, GFP_KERNEL);
-
-		err = dma_mapping_error(nvdec->dev, iova);
-		if (err < 0)
-			return err;
+		if (!virt)
+			return -ENOMEM;
 	} else {
 		virt = tegra_drm_alloc(tegra, size, &iova);
 		if (IS_ERR(virt))
```

---

