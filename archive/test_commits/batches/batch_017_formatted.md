# Linux Kernel Commit Batch Analysis

## Commit 1: 4c06e63b

**Author:** Linus Torvalds
**Date:** 2025-07-03 13:29:56
**Files Changed:** fs/btrfs/block-group.h, fs/btrfs/free-space-tree.c, fs/btrfs/inode.c, fs/btrfs/ioctl.c, fs/btrfs/tree-log.c

**Message:**
```
Merge tag 'for-6.16-rc4-tag' of git://git.kernel.org/pub/scm/linux/kernel/git/kdave/linux

Pull btrfs fixes from David Sterba:

 - tree-log fixes:
    - fixes of log tracking of directories and subvolumes
    - fix iteration and error handling of inode references
      during log replay

 - fix free space tree rebuild (reported by syzbot)

* tag 'for-6.16-rc4-tag' of git://git.kernel.org/pub/scm/linux/kernel/git/kdave/linux:
  btrfs: use btrfs_record_snapshot_destroy() during rmdir
  btrfs: propagate last_unlink_trans earlier when doing a rmdir
  btrfs: record new subvolume in parent dir earlier to avoid dir logging races
  btrfs: fix inode lookup error handling during log replay
  btrfs: fix iteration of extrefs during log replay
  btrfs: fix missing error handling when searching for inode refs during log replay
  btrfs: fix failure to rebuild free space tree using multiple transactions
```

**Diff:**
```diff
diff --git a/fs/btrfs/block-group.h b/fs/btrfs/block-group.h
index 9de356bcb411..aa176cc9a324 100644
--- a/fs/btrfs/block-group.h
+++ b/fs/btrfs/block-group.h
@@ -83,6 +83,8 @@ enum btrfs_block_group_flags {
 	BLOCK_GROUP_FLAG_ZONED_DATA_RELOC,
 	/* Does the block group need to be added to the free space tree? */
 	BLOCK_GROUP_FLAG_NEEDS_FREE_SPACE,
+	/* Set after we add a new block group to the free space tree. */
+	BLOCK_GROUP_FLAG_FREE_SPACE_ADDED,
 	/* Indicate that the block group is placed on a sequential zone */
 	BLOCK_GROUP_FLAG_SEQUENTIAL_ZONE,
 	/*
diff --git a/fs/btrfs/free-space-tree.c b/fs/btrfs/free-space-tree.c
index a3e2a2a81461..a83c268f7f87 100644
--- a/fs/btrfs/free-space-tree.c
+++ b/fs/btrfs/free-space-tree.c
@@ -1241,6 +1241,7 @@ static int clear_free_space_tree(struct btrfs_trans_handle *trans,
 {
 	BTRFS_PATH_AUTO_FREE(path);
 	struct btrfs_key key;
+	struct rb_node *node;
 	int nr;
 	int ret;
 
@@ -1269,6 +1270,16 @@ static int clear_free_space_tree(struct btrfs_trans_handle *trans,
 		btrfs_release_path(path);
 	}
 
+	node = rb_first_cached(&trans->fs_info->block_group_cache_tree);
+	while (node) {
+		struct btrfs_block_group *bg;
+
+		bg = rb_entry(node, struct btrfs_block_group, cache_node);
+		clear_bit(BLOCK_GROUP_FLAG_FREE_SPACE_ADDED, &bg->runtime_flags);
+		node = rb_next(node);
+		cond_resched();
+	}
+
 	return 0;
 }
 
@@ -1358,12 +1369,18 @@ int btrfs_rebuild_free_space_tree(struct btrfs_fs_info *fs_info)
 
 		block_group = rb_entry(node, struct btrfs_block_group,
 				       cache_node);
+
+		if (test_bit(BLOCK_GROUP_FLAG_FREE_SPACE_ADDED,
+			     &block_group->runtime_flags))
+			goto next;

... (truncated 407 lines)
```

---

## Commit 2: 025c1970

**Author:** Linus Torvalds
**Date:** 2025-07-03 11:52:39
**Files Changed:** drivers/infiniband/ulp/srp/ib_srp.c, drivers/scsi/hosts.c, drivers/scsi/qla2xxx/qla_mbx.c, drivers/scsi/qla4xxx/ql4_os.c, drivers/scsi/sd.c (+1 more)

**Message:**
```
Merge tag 'scsi-fixes' of git://git.kernel.org/pub/scm/linux/kernel/git/jejb/scsi

Pull SCSI fixes from James Bottomley:
 "Driver fixes plus core sd.c fix are all small and obvious.

  The larger change to hosts.c is less obvious, but required to avoid
  data corruption caused by bio splitting"

* tag 'scsi-fixes' of git://git.kernel.org/pub/scm/linux/kernel/git/jejb/scsi:
  scsi: ufs: core: Fix spelling of a sysfs attribute name
  scsi: core: Enforce unlimited max_segment_size when virt_boundary_mask is set
  scsi: RDMA/srp: Don't set a max_segment_size when virt_boundary_mask is set
  scsi: sd: Fix VPD page 0xb7 length check
  scsi: qla4xxx: Fix missing DMA mapping error in qla4xxx_alloc_pdu()
  scsi: qla2xxx: Fix DMA mapping test in qla24xx_get_port_database()
```

**Diff:**
```diff
diff --git a/Documentation/ABI/testing/sysfs-driver-ufs b/Documentation/ABI/testing/sysfs-driver-ufs
index d4140dc6c5ba..615453fcc9ff 100644
--- a/Documentation/ABI/testing/sysfs-driver-ufs
+++ b/Documentation/ABI/testing/sysfs-driver-ufs
@@ -711,7 +711,7 @@ Description:	This file shows the thin provisioning type. This is one of
 
 		The file is read only.
 
-What:		/sys/class/scsi_device/*/device/unit_descriptor/physical_memory_resourse_count
+What:		/sys/class/scsi_device/*/device/unit_descriptor/physical_memory_resource_count
 Date:		February 2018
 Contact:	Stanislav Nijnikov <stanislav.nijnikov@wdc.com>
 Description:	This file shows the total physical memory resources. This is
diff --git a/drivers/infiniband/ulp/srp/ib_srp.c b/drivers/infiniband/ulp/srp/ib_srp.c
index 1378651735f6..23ed2fc688f0 100644
--- a/drivers/infiniband/ulp/srp/ib_srp.c
+++ b/drivers/infiniband/ulp/srp/ib_srp.c
@@ -3705,9 +3705,10 @@ static ssize_t add_target_store(struct device *dev,
 	target_host->max_id      = 1;
 	target_host->max_lun     = -1LL;
 	target_host->max_cmd_len = sizeof ((struct srp_cmd *) (void *) 0L)->cdb;
-	target_host->max_segment_size = ib_dma_max_seg_size(ibdev);
 
-	if (!(ibdev->attrs.kernel_cap_flags & IBK_SG_GAPS_REG))
+	if (ibdev->attrs.kernel_cap_flags & IBK_SG_GAPS_REG)
+		target_host->max_segment_size = ib_dma_max_seg_size(ibdev);
+	else
 		target_host->virt_boundary_mask = ~srp_dev->mr_page_mask;
 
 	target = host_to_target(target_host);
diff --git a/drivers/scsi/hosts.c b/drivers/scsi/hosts.c
index e021f1106bea..cc5d05dc395c 100644
--- a/drivers/scsi/hosts.c
+++ b/drivers/scsi/hosts.c
@@ -473,10 +473,17 @@ struct Scsi_Host *scsi_host_alloc(const struct scsi_host_template *sht, int priv
 	else
 		shost->max_sectors = SCSI_DEFAULT_MAX_SECTORS;
 
-	if (sht->max_segment_size)
-		shost->max_segment_size = sht->max_segment_size;
-	else
-		shost->max_segment_size = BLK_MAX_SEGMENT_SIZE;
+	shost->virt_boundary_mask = sht->virt_boundary_mask;
+	if (shost->virt_boundary_mask) {
+		WARN_ON_ONCE(sht->max_segment_size &&
+			     sht->max_segment_size != UINT_MAX);
+		shost->max_segment_size = UINT_MAX;
+	} else {
+		if (sht->max_segment_size)
+			shost->max_segment_size = sht->max_segment_size;

... (truncated 77 lines)
```

---

## Commit 3: 17bbde2e

**Author:** Linus Torvalds
**Date:** 2025-07-03 09:18:55
**Files Changed:** drivers/net/ethernet/amd/xgbe/xgbe-common.h, drivers/net/ethernet/amd/xgbe/xgbe-mdio.c, drivers/net/ethernet/amd/xgbe/xgbe-phy-v2.c, drivers/net/ethernet/amd/xgbe/xgbe.h, drivers/net/ethernet/atheros/atlx/atl1.c (+29 more)

**Message:**
```
Merge tag 'net-6.16-rc5' of git://git.kernel.org/pub/scm/linux/kernel/git/netdev/net

Pull networking fixes from Paolo Abeni:
 "Including fixes from Bluetooth.

  Current release - new code bugs:

    - eth:
       - txgbe: fix the issue of TX failure
       - ngbe: specify IRQ vector when the number of VFs is 7

  Previous releases - regressions:

    - sched: always pass notifications when child class becomes empty

    - ipv4: fix stat increase when udp early demux drops the packet

    - bluetooth: prevent unintended pause by checking if advertising is active

    - virtio: fix error reporting in virtqueue_resize

    - eth:
       - virtio-net:
          - ensure the received length does not exceed allocated size
          - fix the xsk frame's length check
       - lan78xx: fix WARN in __netif_napi_del_locked on disconnect

  Previous releases - always broken:

    - bluetooth: mesh: check instances prior disabling advertising

    - eth:
       - idpf: convert control queue mutex to a spinlock
       - dpaa2: fix xdp_rxq_info leak
       - amd-xgbe: align CL37 AN sequence as per databook"

* tag 'net-6.16-rc5' of git://git.kernel.org/pub/scm/linux/kernel/git/netdev/net: (38 commits)
  vsock/vmci: Clear the vmci transport packet properly when initializing it
  dt-bindings: net: sophgo,sg2044-dwmac: Drop status from the example
  net: ngbe: specify IRQ vector when the number of VFs is 7
  net: wangxun: revert the adjustment of the IRQ vector sequence
  net: txgbe: request MISC IRQ in ndo_open
  virtio_net: Enforce minimum TX ring size for reliability
  virtio_net: Cleanup '2+MAX_SKB_FRAGS'
  virtio_ring: Fix error reporting in virtqueue_resize
  virtio-net: xsk: rx: fix the frame's length check
  virtio-net: use the check_mergeable_len helper
  virtio-net: remove redundant truesize check with PAGE_SIZE
  virtio-net: ensure the received length does not exceed allocated size
  net: ipv4: fix stat increase when udp early demux drops the packet
  net: libwx: fix the incorrect display of the queue number
  amd-xgbe: do not double read link status
  net/sched: Always pass notifications when child class becomes empty
  nui: Fix dma_mapping_error() check
  rose: fix dangling neighbour pointers in rose_rt_device_down()
  enic: fix incorrect MTU comparison in enic_change_mtu()
  amd-xgbe: align CL37 AN sequence as per databook
  ...
```

**Diff:**
```diff
diff --git a/Documentation/devicetree/bindings/net/sophgo,sg2044-dwmac.yaml b/Documentation/devicetree/bindings/net/sophgo,sg2044-dwmac.yaml
index 4dd2dc9c678b..8afbd9ebd73f 100644
--- a/Documentation/devicetree/bindings/net/sophgo,sg2044-dwmac.yaml
+++ b/Documentation/devicetree/bindings/net/sophgo,sg2044-dwmac.yaml
@@ -80,6 +80,8 @@ examples:
       interrupt-parent = <&intc>;
       interrupts = <296 IRQ_TYPE_LEVEL_HIGH>;
       interrupt-names = "macirq";
+      phy-handle = <&phy0>;
+      phy-mode = "rgmii-id";
       resets = <&rst 30>;
       reset-names = "stmmaceth";
       snps,multicast-filter-bins = <0>;
@@ -91,7 +93,6 @@ examples:
       snps,mtl-rx-config = <&gmac0_mtl_rx_setup>;
       snps,mtl-tx-config = <&gmac0_mtl_tx_setup>;
       snps,axi-config = <&gmac0_stmmac_axi_setup>;
-      status = "disabled";
 
       gmac0_mtl_rx_setup: rx-queues-config {
         snps,rx-queues-to-use = <8>;
diff --git a/Documentation/networking/tls.rst b/Documentation/networking/tls.rst
index c7904a1bc167..36cc7afc2527 100644
--- a/Documentation/networking/tls.rst
+++ b/Documentation/networking/tls.rst
@@ -16,11 +16,13 @@ User interface
 Creating a TLS connection
 -------------------------
 
-First create a new TCP socket and set the TLS ULP.
+First create a new TCP socket and once the connection is established set the
+TLS ULP.
 
 .. code-block:: c
 
   sock = socket(AF_INET, SOCK_STREAM, 0);
+  connect(sock, addr, addrlen);
   setsockopt(sock, SOL_TCP, TCP_ULP, "tls", sizeof("tls"));
 
 Setting the TLS ULP allows us to set/get TLS socket options. Currently
diff --git a/Documentation/process/maintainer-netdev.rst b/Documentation/process/maintainer-netdev.rst
index 1ac62dc3a66f..e1755610b4bc 100644
--- a/Documentation/process/maintainer-netdev.rst
+++ b/Documentation/process/maintainer-netdev.rst
@@ -312,7 +312,7 @@ Posting as one thread is discouraged because it confuses patchwork
 (as of patchwork 2.2.2).
 
 Co-posting selftests
---------------------
+~~~~~~~~~~~~~~~~~~~~

... (truncated 1965 lines)
```

---

## Commit 4: d32e907d

**Author:** Linus Torvalds
**Date:** 2025-07-03 09:00:04
**Files Changed:** fs/xfs/libxfs/xfs_alloc.c, fs/xfs/libxfs/xfs_ialloc.c, fs/xfs/xfs_buf.c, fs/xfs/xfs_buf.h, fs/xfs/xfs_buf_item.c (+14 more)

**Message:**
```
Merge tag 'xfs-fixes-6.16-rc5' of git://git.kernel.org/pub/scm/fs/xfs/xfs-linux

Pull xfs fixes from Carlos Maiolino:

 - Fix umount hang with unflushable inodes (and add new tracepoint used
   for debugging this)

 - Fix ABBA deadlock in xfs_reclaim_inode() vs xfs_ifree_cluster()

 - Fix dquot buffer pin deadlock

* tag 'xfs-fixes-6.16-rc5' of git://git.kernel.org/pub/scm/fs/xfs/xfs-linux:
  xfs: add FALLOC_FL_ALLOCATE_RANGE to supported flags mask
  xfs: fix unmount hang with unflushable inodes stuck in the AIL
  xfs: factor out stale buffer item completion
  xfs: rearrange code in xfs_buf_item.c
  xfs: add tracepoints for stale pinned inode state debug
  xfs: avoid dquot buffer pin deadlock
  xfs: catch stale AGF/AGF metadata
  xfs: xfs_ifree_cluster vs xfs_iflush_shutdown_abort deadlock
  xfs: actually use the xfs_growfs_check_rtgeom tracepoint
  xfs: Improve error handling in xfs_mru_cache_create()
  xfs: move xfs_submit_zoned_bio a bit
  xfs: use xfs_readonly_buftarg in xfs_remount_rw
  xfs: remove NULL pointer checks in xfs_mru_cache_insert
  xfs: check for shutdown before going to sleep in xfs_select_zone
```

**Diff:**
```diff
diff --git a/fs/xfs/libxfs/xfs_alloc.c b/fs/xfs/libxfs/xfs_alloc.c
index 7839efe050bf..000cc7f4a3ce 100644
--- a/fs/xfs/libxfs/xfs_alloc.c
+++ b/fs/xfs/libxfs/xfs_alloc.c
@@ -3444,16 +3444,41 @@ xfs_alloc_read_agf(
 
 		set_bit(XFS_AGSTATE_AGF_INIT, &pag->pag_opstate);
 	}
+
 #ifdef DEBUG
-	else if (!xfs_is_shutdown(mp)) {
-		ASSERT(pag->pagf_freeblks == be32_to_cpu(agf->agf_freeblks));
-		ASSERT(pag->pagf_btreeblks == be32_to_cpu(agf->agf_btreeblks));
-		ASSERT(pag->pagf_flcount == be32_to_cpu(agf->agf_flcount));
-		ASSERT(pag->pagf_longest == be32_to_cpu(agf->agf_longest));
-		ASSERT(pag->pagf_bno_level == be32_to_cpu(agf->agf_bno_level));
-		ASSERT(pag->pagf_cnt_level == be32_to_cpu(agf->agf_cnt_level));
+	/*
+	 * It's possible for the AGF to be out of sync if the block device is
+	 * silently dropping writes. This can happen in fstests with dmflakey
+	 * enabled, which allows the buffer to be cleaned and reclaimed by
+	 * memory pressure and then re-read from disk here. We will get a
+	 * stale version of the AGF from disk, and nothing good can happen from
+	 * here. Hence if we detect this situation, immediately shut down the
+	 * filesystem.
+	 *
+	 * This can also happen if we are already in the middle of a forced
+	 * shutdown, so don't bother checking if we are already shut down.
+	 */
+	if (!xfs_is_shutdown(pag_mount(pag))) {
+		bool	ok = true;
+
+		ok &= pag->pagf_freeblks == be32_to_cpu(agf->agf_freeblks);
+		ok &= pag->pagf_freeblks == be32_to_cpu(agf->agf_freeblks);
+		ok &= pag->pagf_btreeblks == be32_to_cpu(agf->agf_btreeblks);
+		ok &= pag->pagf_flcount == be32_to_cpu(agf->agf_flcount);
+		ok &= pag->pagf_longest == be32_to_cpu(agf->agf_longest);
+		ok &= pag->pagf_bno_level == be32_to_cpu(agf->agf_bno_level);
+		ok &= pag->pagf_cnt_level == be32_to_cpu(agf->agf_cnt_level);
+
+		if (XFS_IS_CORRUPT(pag_mount(pag), !ok)) {
+			xfs_ag_mark_sick(pag, XFS_SICK_AG_AGF);
+			xfs_trans_brelse(tp, agfbp);
+			xfs_force_shutdown(pag_mount(pag),
+					SHUTDOWN_CORRUPT_ONDISK);
+			return -EFSCORRUPTED;
+		}
 	}
-#endif
+#endif /* DEBUG */

... (truncated 989 lines)
```

---

## Commit 5: 75ef7b8d

**Author:** Jens Axboe
**Date:** 2025-07-03 09:42:07
**Files Changed:** drivers/nvme/host/core.c, drivers/nvme/host/multipath.c, drivers/nvme/host/pci.c, drivers/nvme/target/nvmet.h

**Message:**
```
Merge tag 'nvme-6.16-2025-07-03' of git://git.infradead.org/nvme into block-6.16

Pull NVMe fixes from Christoph:

"- fix incorrect cdw15 value in passthru error logging (Alok Tiwari)
 - fix memory leak of bio integrity in nvmet (Dmitry Bogdanov)
 - refresh visible attrs after being checked (Eugen Hristev)
 - fix suspicious RCU usage warning in the multipath code (Geliang Tang)
 - correctly account for namespace head reference counter (Nilay Shroff)"

* tag 'nvme-6.16-2025-07-03' of git://git.infradead.org/nvme:
  nvme-multipath: fix suspicious RCU usage warning
  nvme-pci: refresh visible attrs after being checked
  nvmet: fix memory leak of bio integrity
  nvme: correctly account for namespace head reference counter
  nvme: Fix incorrect cdw15 value in passthru error logging
```

**Diff:**
```diff
diff --git a/drivers/nvme/host/core.c b/drivers/nvme/host/core.c
index e533d791955d..7493e5aa984c 100644
--- a/drivers/nvme/host/core.c
+++ b/drivers/nvme/host/core.c
@@ -386,7 +386,7 @@ static void nvme_log_err_passthru(struct request *req)
 		nr->cmd->common.cdw12,
 		nr->cmd->common.cdw13,
 		nr->cmd->common.cdw14,
-		nr->cmd->common.cdw14);
+		nr->cmd->common.cdw15);
 }
 
 enum nvme_disposition {
@@ -4086,6 +4086,7 @@ static void nvme_alloc_ns(struct nvme_ctrl *ctrl, struct nvme_ns_info *info)
 	struct nvme_ns *ns;
 	struct gendisk *disk;
 	int node = ctrl->numa_node;
+	bool last_path = false;
 
 	ns = kzalloc_node(sizeof(*ns), GFP_KERNEL, node);
 	if (!ns)
@@ -4178,9 +4179,22 @@ static void nvme_alloc_ns(struct nvme_ctrl *ctrl, struct nvme_ns_info *info)
  out_unlink_ns:
 	mutex_lock(&ctrl->subsys->lock);
 	list_del_rcu(&ns->siblings);
-	if (list_empty(&ns->head->list))
+	if (list_empty(&ns->head->list)) {
 		list_del_init(&ns->head->entry);
+		/*
+		 * If multipath is not configured, we still create a namespace
+		 * head (nshead), but head->disk is not initialized in that
+		 * case.  As a result, only a single reference to nshead is held
+		 * (via kref_init()) when it is created. Therefore, ensure that
+		 * we do not release the reference to nshead twice if head->disk
+		 * is not present.
+		 */
+		if (ns->head->disk)
+			last_path = true;
+	}
 	mutex_unlock(&ctrl->subsys->lock);
+	if (last_path)
+		nvme_put_ns_head(ns->head);
 	nvme_put_ns_head(ns->head);
  out_cleanup_disk:
 	put_disk(disk);
diff --git a/drivers/nvme/host/multipath.c b/drivers/nvme/host/multipath.c
index 1062467595f3..5d1ad28986e9 100644
--- a/drivers/nvme/host/multipath.c
+++ b/drivers/nvme/host/multipath.c
@@ -690,8 +690,8 @@ static void nvme_remove_head(struct nvme_ns_head *head)

... (truncated 73 lines)
```

---

