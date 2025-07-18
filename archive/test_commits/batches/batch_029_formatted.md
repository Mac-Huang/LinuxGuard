# Linux Kernel Commit Batch Analysis

## Commit 1: 35e261cd

**Author:** Linus Torvalds
**Date:** 2025-06-27 12:08:36
**Files Changed:** drivers/pci/pci-acpi.c

**Message:**
```
Merge tag 'acpi-6.16-rc4' of git://git.kernel.org/pub/scm/linux/kernel/git/rafael/linux-pm

Pull ACPI fix from Rafael Wysocki:
 "Revert a commit that attempted to fix a memory leak in an error code
  path and introduced a different issue (Zhe Qiao)"

* tag 'acpi-6.16-rc4' of git://git.kernel.org/pub/scm/linux/kernel/git/rafael/linux-pm:
  Revert "PCI/ACPI: Fix allocated memory release on error in pci_acpi_scan_root()"
```

**Diff:**
```diff
diff --git a/drivers/pci/pci-acpi.c b/drivers/pci/pci-acpi.c
index b78e0e417324..af370628e583 100644
--- a/drivers/pci/pci-acpi.c
+++ b/drivers/pci/pci-acpi.c
@@ -1676,19 +1676,24 @@ struct pci_bus *pci_acpi_scan_root(struct acpi_pci_root *root)
 		return NULL;
 
 	root_ops = kzalloc(sizeof(*root_ops), GFP_KERNEL);
-	if (!root_ops)
-		goto free_ri;
+	if (!root_ops) {
+		kfree(ri);
+		return NULL;
+	}
 
 	ri->cfg = pci_acpi_setup_ecam_mapping(root);
-	if (!ri->cfg)
-		goto free_root_ops;
+	if (!ri->cfg) {
+		kfree(ri);
+		kfree(root_ops);
+		return NULL;
+	}
 
 	root_ops->release_info = pci_acpi_generic_release_info;
 	root_ops->prepare_resources = pci_acpi_root_prepare_resources;
 	root_ops->pci_ops = (struct pci_ops *)&ri->cfg->ops->pci_ops;
 	bus = acpi_pci_root_create(root, root_ops, &ri->common, ri->cfg);
 	if (!bus)
-		goto free_cfg;
+		return NULL;
 
 	/* If we must preserve the resource configuration, claim now */
 	host = pci_find_host_bridge(bus);
@@ -1705,14 +1710,6 @@ struct pci_bus *pci_acpi_scan_root(struct acpi_pci_root *root)
 		pcie_bus_configure_settings(child);
 
 	return bus;
-
-free_cfg:
-	pci_ecam_free(ri->cfg);
-free_root_ops:
-	kfree(root_ops);
-free_ri:
-	kfree(ri);
-	return NULL;
 }
 
 void pcibios_add_bus(struct pci_bus *bus)
```

---

## Commit 2: 5f61b961

**Author:** Filipe Manana
**Date:** 2025-06-27 19:57:06
**Files Changed:** fs/btrfs/tree-log.c

**Message:**
```
btrfs: fix inode lookup error handling during log replay

When replaying log trees we use read_one_inode() to get an inode, which is
just a wrapper around btrfs_iget_logging(), which in turn is a wrapper for
btrfs_iget(). But read_one_inode() always returns NULL for any error
that btrfs_iget_logging() / btrfs_iget() may return and this is a problem
because:

1) In many callers of read_one_inode() we convert the NULL into -EIO,
   which is not accurate since btrfs_iget() may return -ENOMEM and -ENOENT
   for example, besides -EIO and other errors. So during log replay we
   may end up reporting a false -EIO, which is confusing since we may
   not have had any IO error at all;

2) When replaying directory deletes, at replay_dir_deletes(), we assume
   the NULL returned from read_one_inode() means that the inode doesn't
   exist and then proceed as if no error had happened. This is wrong
   because unless btrfs_iget() returned ERR_PTR(-ENOENT), we had an
   actual error and the target inode may exist in the target subvolume
   root - this may later result in the log replay code failing at a
   later stage (if we are "lucky") or succeed but leaving some
   inconsistency in the filesystem.

So fix this by not ignoring errors from btrfs_iget_logging() and as
a consequence remove the read_one_inode() wrapper and just use
btrfs_iget_logging() directly. Also since btrfs_iget_logging() is
supposed to be called only against subvolume roots, just like
read_one_inode() which had a comment about it, add an assertion to
btrfs_iget_logging() to check that the target root corresponds to a
subvolume root.

Fixes: 5d4f98a28c7d ("Btrfs: Mixed back reference  (FORWARD ROLLING FORMAT CHANGE)")
Reviewed-by: Johannes Thumshirn <johannes.thumshirn@wdc.com>
Reviewed-by: Qu Wenruo <wqu@suse.com>
Signed-off-by: Filipe Manana <fdmanana@suse.com>
Signed-off-by: David Sterba <dsterba@suse.com>
```

**Diff:**
```diff
diff --git a/fs/btrfs/tree-log.c b/fs/btrfs/tree-log.c
index d514bf531b3b..8cf5e5ae593c 100644
--- a/fs/btrfs/tree-log.c
+++ b/fs/btrfs/tree-log.c
@@ -143,6 +143,9 @@ static struct btrfs_inode *btrfs_iget_logging(u64 objectid, struct btrfs_root *r
 	unsigned int nofs_flag;
 	struct btrfs_inode *inode;
 
+	/* Only meant to be called for subvolume roots and not for log roots. */
+	ASSERT(is_fstree(btrfs_root_id(root)));
+
 	/*
 	 * We're holding a transaction handle whether we are logging or
 	 * replaying a log tree, so we must make sure NOFS semantics apply
@@ -604,21 +607,6 @@ static int read_alloc_one_name(struct extent_buffer *eb, void *start, int len,
 	return 0;
 }
 
-/*
- * simple helper to read an inode off the disk from a given root
- * This can only be called for subvolume roots and not for the log
- */
-static noinline struct btrfs_inode *read_one_inode(struct btrfs_root *root,
-						   u64 objectid)
-{
-	struct btrfs_inode *inode;
-
-	inode = btrfs_iget_logging(objectid, root);
-	if (IS_ERR(inode))
-		return NULL;
-	return inode;
-}
-
 /* replays a single extent in 'eb' at 'slot' with 'key' into the
  * subvolume 'root'.  path is released on entry and should be released
  * on exit.
@@ -674,9 +662,9 @@ static noinline int replay_one_extent(struct btrfs_trans_handle *trans,
 		return -EUCLEAN;
 	}
 
-	inode = read_one_inode(root, key->objectid);
-	if (!inode)
-		return -EIO;
+	inode = btrfs_iget_logging(key->objectid, root);
+	if (IS_ERR(inode))
+		return PTR_ERR(inode);
 
 	/*
 	 * first check to see if we already have this extent in the
@@ -948,9 +936,10 @@ static noinline int drop_one_dir_item(struct btrfs_trans_handle *trans,

... (truncated 194 lines)
```

---

## Commit 3: 6561a40c

**Author:** Filipe Manana
**Date:** 2025-06-27 19:56:35
**Files Changed:** fs/btrfs/tree-log.c

**Message:**
```
btrfs: fix missing error handling when searching for inode refs during log replay

During log replay, at __add_inode_ref(), when we are searching for inode
ref keys we totally ignore if btrfs_search_slot() returns an error. This
may make a log replay succeed when there was an actual error and leave
some metadata inconsistency in a subvolume tree. Fix this by checking if
an error was returned from btrfs_search_slot() and if so, return it to
the caller.

Fixes: e02119d5a7b4 ("Btrfs: Add a write ahead tree log to optimize synchronous operations")
Reviewed-by: Johannes Thumshirn <johannes.thumshirn@wdc.com>
Reviewed-by: Qu Wenruo <wqu@suse.com>
Signed-off-by: Filipe Manana <fdmanana@suse.com>
Signed-off-by: David Sterba <dsterba@suse.com>
```

**Diff:**
```diff
diff --git a/fs/btrfs/tree-log.c b/fs/btrfs/tree-log.c
index 858b609e292c..8b66173d9023 100644
--- a/fs/btrfs/tree-log.c
+++ b/fs/btrfs/tree-log.c
@@ -1073,7 +1073,9 @@ static inline int __add_inode_ref(struct btrfs_trans_handle *trans,
 	search_key.type = BTRFS_INODE_REF_KEY;
 	search_key.offset = parent_objectid;
 	ret = btrfs_search_slot(NULL, root, &search_key, path, 0, 0);
-	if (ret == 0) {
+	if (ret < 0) {
+		return ret;
+	} else if (ret == 0) {
 		struct btrfs_inode_ref *victim_ref;
 		unsigned long ptr;
 		unsigned long ptr_end;
```

---

## Commit 4: e5403415

**Author:** Linus Torvalds
**Date:** 2025-06-27 09:02:33
**Files Changed:** block/genhd.c, drivers/block/ublk_drv.c, drivers/nvme/host/core.c, drivers/nvme/host/multipath.c, drivers/nvme/host/nvme.h (+1 more)

**Message:**
```
Merge tag 'block-6.16-20250626' of git://git.kernel.dk/linux

Pull block fixes from Jens Axboe:

 - Fixes for ublk:
      - fix C++ narrowing warnings in the uapi header
      - update/improve UBLK_F_SUPPORT_ZERO_COPY comment in uapi header
      - fix for the ublk ->queue_rqs() implementation, limiting a batch
        to just the specific task AND ring
      - ublk_get_data() error handling fix
      - sanity check more arguments in ublk_ctrl_add_dev()
      - selftest addition

 - NVMe pull request via Christoph:
      - reset delayed remove_work after reconnect
      - fix atomic write size validation

 - Fix for a warning introduced in bdev_count_inflight_rw() in this
   merge window

* tag 'block-6.16-20250626' of git://git.kernel.dk/linux:
  block: fix false warning in bdev_count_inflight_rw()
  ublk: sanity check add_dev input for underflow
  nvme: fix atomic write size validation
  nvme: refactor the atomic write unit detection
  nvme: reset delayed remove_work after reconnect
  ublk: setup ublk_io correctly in case of ublk_get_data() failure
  ublk: update UBLK_F_SUPPORT_ZERO_COPY comment in UAPI header
  ublk: fix narrowing warnings in UAPI header
  selftests: ublk: don't take same backing file for more than one ublk devices
  ublk: build batch from IOs in same io_ring_ctx and io task
```

**Diff:**
```diff
diff --git a/block/genhd.c b/block/genhd.c
index 8171a6bc3210..c26733f6324b 100644
--- a/block/genhd.c
+++ b/block/genhd.c
@@ -128,23 +128,27 @@ static void part_stat_read_all(struct block_device *part,
 static void bdev_count_inflight_rw(struct block_device *part,
 		unsigned int inflight[2], bool mq_driver)
 {
+	int write = 0;
+	int read = 0;
 	int cpu;
 
 	if (mq_driver) {
 		blk_mq_in_driver_rw(part, inflight);
-	} else {
-		for_each_possible_cpu(cpu) {
-			inflight[READ] += part_stat_local_read_cpu(
-						part, in_flight[READ], cpu);
-			inflight[WRITE] += part_stat_local_read_cpu(
-						part, in_flight[WRITE], cpu);
-		}
+		return;
+	}
+
+	for_each_possible_cpu(cpu) {
+		read += part_stat_local_read_cpu(part, in_flight[READ], cpu);
+		write += part_stat_local_read_cpu(part, in_flight[WRITE], cpu);
 	}
 
-	if (WARN_ON_ONCE((int)inflight[READ] < 0))
-		inflight[READ] = 0;
-	if (WARN_ON_ONCE((int)inflight[WRITE] < 0))
-		inflight[WRITE] = 0;
+	/*
+	 * While iterating all CPUs, some IOs may be issued from a CPU already
+	 * traversed and complete on a CPU that has not yet been traversed,
+	 * causing the inflight number to be negative.
+	 */
+	inflight[READ] = read > 0 ? read : 0;
+	inflight[WRITE] = write > 0 ? write : 0;
 }
 
 /**
diff --git a/drivers/block/ublk_drv.c b/drivers/block/ublk_drv.c
index d36f44f5ee80..c3e3c3b65a6d 100644
--- a/drivers/block/ublk_drv.c
+++ b/drivers/block/ublk_drv.c
@@ -1148,8 +1148,8 @@ static inline void __ublk_complete_rq(struct request *req)
 	blk_mq_end_request(req, res);
 }

... (truncated 370 lines)
```

---

## Commit 5: 0a47e02d

**Author:** Linus Torvalds
**Date:** 2025-06-27 08:55:57
**Files Changed:** io_uring/kbuf.c, io_uring/kbuf.h, io_uring/net.c, io_uring/opdef.c, io_uring/rsrc.c (+2 more)

**Message:**
```
Merge tag 'io_uring-6.16-20250626' of git://git.kernel.dk/linux

Pull io_uring fixes from Jens Axboe:

 - Two tweaks for a recent fix: fixing a memory leak if multiple iovecs
   were initially mapped but only the first was used and hence turned
   into a UBUF rathan than an IOVEC iterator, and catching a case where
   a retry would be done even if the previous segment wasn't full

 - Small series fixing an issue making the vm unhappy if debugging is
   turned on, hitting a VM_BUG_ON_PAGE()

 - Fix a resource leak in io_import_dmabuf() in the error handling case,
   which is a regression in this merge window

 - Mark fallocate as needing to be write serialized, as is already done
   for truncate and buffered writes

* tag 'io_uring-6.16-20250626' of git://git.kernel.dk/linux:
  io_uring/kbuf: flag partial buffer mappings
  io_uring/net: mark iov as dynamically allocated even for single segments
  io_uring: fix resource leak in io_import_dmabuf()
  io_uring: don't assume uaddr alignment in io_vec_fill_bvec
  io_uring/rsrc: don't rely on user vaddr alignment
  io_uring/rsrc: fix folio unpinning
  io_uring: make fallocate be hashed work
```

**Diff:**
```diff
diff --git a/io_uring/kbuf.c b/io_uring/kbuf.c
index ce95e3af44a9..f2d2cc319faa 100644
--- a/io_uring/kbuf.c
+++ b/io_uring/kbuf.c
@@ -271,6 +271,7 @@ static int io_ring_buffers_peek(struct io_kiocb *req, struct buf_sel_arg *arg,
 		if (len > arg->max_len) {
 			len = arg->max_len;
 			if (!(bl->flags & IOBL_INC)) {
+				arg->partial_map = 1;
 				if (iov != arg->iovs)
 					break;
 				buf->len = len;
diff --git a/io_uring/kbuf.h b/io_uring/kbuf.h
index 5d83c7adc739..723d0361898e 100644
--- a/io_uring/kbuf.h
+++ b/io_uring/kbuf.h
@@ -58,7 +58,8 @@ struct buf_sel_arg {
 	size_t max_len;
 	unsigned short nr_iovs;
 	unsigned short mode;
-	unsigned buf_group;
+	unsigned short buf_group;
+	unsigned short partial_map;
 };
 
 void __user *io_buffer_select(struct io_kiocb *req, size_t *len,
diff --git a/io_uring/net.c b/io_uring/net.c
index 9550d4c8f866..43a43522f406 100644
--- a/io_uring/net.c
+++ b/io_uring/net.c
@@ -75,12 +75,17 @@ struct io_sr_msg {
 	u16				flags;
 	/* initialised and used only by !msg send variants */
 	u16				buf_group;
-	bool				retry;
+	unsigned short			retry_flags;
 	void __user			*msg_control;
 	/* used only for send zerocopy */
 	struct io_kiocb 		*notif;
 };
 
+enum sr_retry_flags {
+	IO_SR_MSG_RETRY		= 1,
+	IO_SR_MSG_PARTIAL_MAP	= 2,
+};
+
 /*
  * Number of times we'll try and do receives if there's more data. If we
  * exceed this limit, then add us to the back of the queue and retry from
@@ -187,7 +192,7 @@ static inline void io_mshot_prep_retry(struct io_kiocb *req,

... (truncated 203 lines)
```

---

