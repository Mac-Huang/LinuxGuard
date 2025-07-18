# Linux Kernel Commit Batch Analysis

## Commit 1: 40f92e79

**Author:** Linus Torvalds
**Date:** 2025-07-11 10:35:54
**Files Changed:** drivers/block/nbd.c, drivers/md/md-bitmap.c, drivers/md/raid1.c, drivers/md/raid10.c, include/linux/blkdev.h

**Message:**
```
Merge tag 'block-6.16-20250710' of git://git.kernel.dk/linux

Pull block fixes from Jens Axboe:

 - MD changes via Yu:
     - fix UAF due to stack memory used for bio mempool (Jinchao)
     - fix raid10/raid1 nowait IO error path (Nigel and Qixing)
     - fix kernel crash from reading bitmap sysfs entry (Håkon)

 - Fix for a UAF in the nbd connect error path

 - Fix for blocksize being bigger than pagesize, if THP isn't enabled

* tag 'block-6.16-20250710' of git://git.kernel.dk/linux:
  block: reject bs > ps block devices when THP is disabled
  nbd: fix uaf in nbd_genl_connect() error path
  md/md-bitmap: fix GPF in bitmap_get_stats()
  md/raid1,raid10: strip REQ_NOWAIT from member bios
  raid10: cleanup memleak at raid10_make_request
  md/raid1: Fix stack memory use after return in raid1_reshape
```

**Diff:**
```diff
diff --git a/drivers/block/nbd.c b/drivers/block/nbd.c
index 7bdc7eb808ea..2592bd19ebc1 100644
--- a/drivers/block/nbd.c
+++ b/drivers/block/nbd.c
@@ -2198,9 +2198,7 @@ static int nbd_genl_connect(struct sk_buff *skb, struct genl_info *info)
 				goto out;
 		}
 	}
-	ret = nbd_start_device(nbd);
-	if (ret)
-		goto out;
+
 	if (info->attrs[NBD_ATTR_BACKEND_IDENTIFIER]) {
 		nbd->backend = nla_strdup(info->attrs[NBD_ATTR_BACKEND_IDENTIFIER],
 					  GFP_KERNEL);
@@ -2216,6 +2214,8 @@ static int nbd_genl_connect(struct sk_buff *skb, struct genl_info *info)
 		goto out;
 	}
 	set_bit(NBD_RT_HAS_BACKEND_FILE, &config->runtime_flags);
+
+	ret = nbd_start_device(nbd);
 out:
 	mutex_unlock(&nbd->config_lock);
 	if (!ret) {
diff --git a/drivers/md/md-bitmap.c b/drivers/md/md-bitmap.c
index bd694910b01b..7f524a26cebc 100644
--- a/drivers/md/md-bitmap.c
+++ b/drivers/md/md-bitmap.c
@@ -2366,8 +2366,7 @@ static int bitmap_get_stats(void *data, struct md_bitmap_stats *stats)
 
 	if (!bitmap)
 		return -ENOENT;
-	if (!bitmap->mddev->bitmap_info.external &&
-	    !bitmap->storage.sb_page)
+	if (!bitmap->storage.sb_page)
 		return -EINVAL;
 	sb = kmap_local_page(bitmap->storage.sb_page);
 	stats->sync_size = le64_to_cpu(sb->sync_size);
diff --git a/drivers/md/raid1.c b/drivers/md/raid1.c
index 19c5a0ce5a40..64b8176907a9 100644
--- a/drivers/md/raid1.c
+++ b/drivers/md/raid1.c
@@ -1399,7 +1399,7 @@ static void raid1_read_request(struct mddev *mddev, struct bio *bio,
 	}
 	read_bio = bio_alloc_clone(mirror->rdev->bdev, bio, gfp,
 				   &mddev->bio_set);
-
+	read_bio->bi_opf &= ~REQ_NOWAIT;
 	r1_bio->bios[rdisk] = read_bio;
 

... (truncated 84 lines)
```

---

## Commit 2: c7979c39

**Author:** Linus Torvalds
**Date:** 2025-07-11 10:18:51
**Files Changed:** drivers/net/can/m_can/m_can.c, drivers/net/ethernet/broadcom/bnxt/bnxt_coredump.c, drivers/net/ethernet/broadcom/bnxt/bnxt_dcb.c, drivers/net/ethernet/broadcom/bnxt/bnxt_xdp.c, drivers/net/ethernet/ibm/ibmvnic.h (+50 more)

**Message:**
```
Merge tag 'net-6.16-rc6-2' of git://git.kernel.org/pub/scm/linux/kernel/git/netdev/net

Pull more networking fixes from Jakub Kicinski
 "Big chunk of fixes for WiFi, Johannes says probably the last for the
  release.

  The Netlink fixes (on top of the tree) restore operation of iw (WiFi
  CLI) which uses sillily small recv buffer, and is the reason for this
  'emergency PR'.

  The GRE multicast fix also stands out among the user-visible
  regressions.

  Current release - fix to a fix:

   - netlink: make sure we always allow at least one skb to be queued,
     even if the recvbuf is (mis)configured to be tiny

  Previous releases - regressions:

   - gre: fix IPv6 multicast route creation

  Previous releases - always broken:

   - wifi: prevent A-MSDU attacks in mesh networks

   - wifi: cfg80211: fix S1G beacon head validation and detection

   - wifi: mac80211:
       - always clear frame buffer to prevent stack leak in cases which
         hit a WARN()
       - fix monitor interface in device restart

   - wifi: mwifiex: discard erroneous disassoc frames on STA interface

   - wifi: mt76:
       - prevent null-deref in mt7925_sta_set_decap_offload()
       - add missing RCU annotations, and fix sleep in atomic
       - fix decapsulation offload
       - fixes for scanning

   - phy: microchip: improve link establishment and reset handling

   - eth: mlx5e: fix race between DIM disable and net_dim()

   - bnxt_en: correct DMA unmap len for XDP_REDIRECT"

* tag 'net-6.16-rc6-2' of git://git.kernel.org/pub/scm/linux/kernel/git/netdev/net: (44 commits)
  netlink: make sure we allow at least one dump skb
  netlink: Fix rmem check in netlink_broadcast_deliver().
  bnxt_en: Set DMA unmap len correctly for XDP_REDIRECT
  bnxt_en: Flush FW trace before copying to the coredump
  bnxt_en: Fix DCB ETS validation
  net: ll_temac: Fix missing tx_pending check in ethtools_set_ringparam()
  net/mlx5e: Add new prio for promiscuous mode
  net/mlx5e: Fix race between DIM disable and net_dim()
  net/mlx5: Reset bw_share field when changing a node's parent
  can: m_can: m_can_handle_lost_msg(): downgrade msg lost in rx message to debug level
  selftests: net: lib: fix shift count out of range
  selftests: Add IPv6 multicast route generation tests for GRE devices.
  gre: Fix IPv6 multicast route creation.
  net: phy: microchip: limit 100M workaround to link-down events on LAN88xx
  net: phy: microchip: Use genphy_soft_reset() to purge stale LPA bits
  ibmvnic: Fix hardcoded NUM_RX_STATS/NUM_TX_STATS with dynamic sizeof
  net: appletalk: Fix device refcount leak in atrtr_create()
  netfilter: flowtable: account for Ethernet header in nf_flow_pppoe_proto()
  wifi: mac80211: add the virtual monitor after reconfig complete
  wifi: mac80211: always initialize sdata::key_list
  ...
```

**Diff:**
```diff
diff --git a/drivers/net/can/m_can/m_can.c b/drivers/net/can/m_can/m_can.c
index 6c656bfdb323..fe74dbd2c966 100644
--- a/drivers/net/can/m_can/m_can.c
+++ b/drivers/net/can/m_can/m_can.c
@@ -665,7 +665,7 @@ static int m_can_handle_lost_msg(struct net_device *dev)
 	struct can_frame *frame;
 	u32 timestamp = 0;
 
-	netdev_err(dev, "msg lost in rxf0\n");
+	netdev_dbg(dev, "msg lost in rxf0\n");
 
 	stats->rx_errors++;
 	stats->rx_over_errors++;
diff --git a/drivers/net/ethernet/broadcom/bnxt/bnxt_coredump.c b/drivers/net/ethernet/broadcom/bnxt/bnxt_coredump.c
index ce97befd3cb3..67e70d3d0980 100644
--- a/drivers/net/ethernet/broadcom/bnxt/bnxt_coredump.c
+++ b/drivers/net/ethernet/broadcom/bnxt/bnxt_coredump.c
@@ -368,23 +368,27 @@ static u32 bnxt_get_ctx_coredump(struct bnxt *bp, void *buf, u32 offset,
 		if (!ctxm->mem_valid || !seg_id)
 			continue;
 
-		if (trace)
+		if (trace) {
 			extra_hlen = BNXT_SEG_RCD_LEN;
+			if (buf) {
+				u16 trace_type = bnxt_bstore_to_trace[type];
+
+				bnxt_fill_drv_seg_record(bp, &record, ctxm,
+							 trace_type);
+			}
+		}
+
 		if (buf)
 			data = buf + BNXT_SEG_HDR_LEN + extra_hlen;
+
 		seg_len = bnxt_copy_ctx_mem(bp, ctxm, data, 0) + extra_hlen;
 		if (buf) {
 			bnxt_fill_coredump_seg_hdr(bp, &seg_hdr, NULL, seg_len,
 						   0, 0, 0, comp_id, seg_id);
 			memcpy(buf, &seg_hdr, BNXT_SEG_HDR_LEN);
 			buf += BNXT_SEG_HDR_LEN;
-			if (trace) {
-				u16 trace_type = bnxt_bstore_to_trace[type];
-
-				bnxt_fill_drv_seg_record(bp, &record, ctxm,
-							 trace_type);
+			if (trace)
 				memcpy(buf, &record, BNXT_SEG_RCD_LEN);
-			}
 			buf += seg_len;

... (truncated 1942 lines)
```

---

## Commit 3: b74c2a2e

**Author:** Shravya KN
**Date:** 2025-07-11 07:28:34
**Files Changed:** drivers/net/ethernet/broadcom/bnxt/bnxt_dcb.c

**Message:**
```
bnxt_en: Fix DCB ETS validation

In bnxt_ets_validate(), the code incorrectly loops over all possible
traffic classes to check and add the ETS settings.  Fix it to loop
over the configured traffic classes only.

The unconfigured traffic classes will default to TSA_ETS with 0
bandwidth.  Looping over these unconfigured traffic classes may
cause the validation to fail and trigger this error message:

"rejecting ETS config starving a TC\n"

The .ieee_setets() will then fail.

Fixes: 7df4ae9fe855 ("bnxt_en: Implement DCBNL to support host-based DCBX.")
Reviewed-by: Sreekanth Reddy <sreekanth.reddy@broadcom.com>
Signed-off-by: Shravya KN <shravya.k-n@broadcom.com>
Signed-off-by: Michael Chan <michael.chan@broadcom.com>
Link: https://patch.msgid.link/20250710213938.1959625-2-michael.chan@broadcom.com
Signed-off-by: Jakub Kicinski <kuba@kernel.org>
```

**Diff:**
```diff
diff --git a/drivers/net/ethernet/broadcom/bnxt/bnxt_dcb.c b/drivers/net/ethernet/broadcom/bnxt/bnxt_dcb.c
index 0dbb880a7aa0..71e14be2507e 100644
--- a/drivers/net/ethernet/broadcom/bnxt/bnxt_dcb.c
+++ b/drivers/net/ethernet/broadcom/bnxt/bnxt_dcb.c
@@ -487,7 +487,9 @@ static int bnxt_ets_validate(struct bnxt *bp, struct ieee_ets *ets, u8 *tc)
 
 		if ((ets->tc_tx_bw[i] || ets->tc_tsa[i]) && i > bp->max_tc)
 			return -EINVAL;
+	}
 
+	for (i = 0; i < max_tc; i++) {
 		switch (ets->tc_tsa[i]) {
 		case IEEE_8021QAZ_TSA_STRICT:
 			break;
```

---

## Commit 4: e81750b4

**Author:** Alok Tiwari
**Date:** 2025-07-11 07:27:26
**Files Changed:** drivers/net/ethernet/xilinx/ll_temac_main.c

**Message:**
```
net: ll_temac: Fix missing tx_pending check in ethtools_set_ringparam()

The function ll_temac_ethtools_set_ringparam() incorrectly checked
rx_pending twice, once correctly for RX and once mistakenly in place
of tx_pending. This caused tx_pending to be left unchecked against
TX_BD_NUM_MAX.
As a result, invalid TX ring sizes may have been accepted or valid
ones wrongly rejected based on the RX limit, leading to potential
misconfiguration or unexpected results.

This patch corrects the condition to properly validate tx_pending.

Fixes: f7b261bfc35e ("net: ll_temac: Make RX/TX ring sizes configurable")
Signed-off-by: Alok Tiwari <alok.a.tiwari@oracle.com>
Link: https://patch.msgid.link/20250710180621.2383000-1-alok.a.tiwari@oracle.com
Signed-off-by: Jakub Kicinski <kuba@kernel.org>
```

**Diff:**
```diff
diff --git a/drivers/net/ethernet/xilinx/ll_temac_main.c b/drivers/net/ethernet/xilinx/ll_temac_main.c
index edb36ff07a0c..6f82203a414c 100644
--- a/drivers/net/ethernet/xilinx/ll_temac_main.c
+++ b/drivers/net/ethernet/xilinx/ll_temac_main.c
@@ -1309,7 +1309,7 @@ ll_temac_ethtools_set_ringparam(struct net_device *ndev,
 	if (ering->rx_pending > RX_BD_NUM_MAX ||
 	    ering->rx_mini_pending ||
 	    ering->rx_jumbo_pending ||
-	    ering->rx_pending > TX_BD_NUM_MAX)
+	    ering->tx_pending > TX_BD_NUM_MAX)
 		return -EINVAL;
 
 	if (netif_running(ndev))
```

---

## Commit 5: eb41a264

**Author:** Carolina Jubran
**Date:** 2025-07-11 07:26:44
**Files Changed:** drivers/net/ethernet/mellanox/mlx5/core/en_dim.c

**Message:**
```
net/mlx5e: Fix race between DIM disable and net_dim()

There's a race between disabling DIM and NAPI callbacks using the dim
pointer on the RQ or SQ.

If NAPI checks the DIM state bit and sees it still set, it assumes
`rq->dim` or `sq->dim` is valid. But if DIM gets disabled right after
that check, the pointer might already be set to NULL, leading to a NULL
pointer dereference in net_dim().

Fix this by calling `synchronize_net()` before freeing the DIM context.
This ensures all in-progress NAPI callbacks are finished before the
pointer is cleared.

Kernel log:

BUG: kernel NULL pointer dereference, address: 0000000000000000
...
RIP: 0010:net_dim+0x23/0x190
...
Call Trace:
 <TASK>
 ? __die+0x20/0x60
 ? page_fault_oops+0x150/0x3e0
 ? common_interrupt+0xf/0xa0
 ? sysvec_call_function_single+0xb/0x90
 ? exc_page_fault+0x74/0x130
 ? asm_exc_page_fault+0x22/0x30
 ? net_dim+0x23/0x190
 ? mlx5e_poll_ico_cq+0x41/0x6f0 [mlx5_core]
 ? sysvec_apic_timer_interrupt+0xb/0x90
 mlx5e_handle_rx_dim+0x92/0xd0 [mlx5_core]
 mlx5e_napi_poll+0x2cd/0xac0 [mlx5_core]
 ? mlx5e_poll_ico_cq+0xe5/0x6f0 [mlx5_core]
 busy_poll_stop+0xa2/0x200
 ? mlx5e_napi_poll+0x1d9/0xac0 [mlx5_core]
 ? mlx5e_trigger_irq+0x130/0x130 [mlx5_core]
 __napi_busy_loop+0x345/0x3b0
 ? sysvec_call_function_single+0xb/0x90
 ? asm_sysvec_call_function_single+0x16/0x20
 ? sysvec_apic_timer_interrupt+0xb/0x90
 ? pcpu_free_area+0x1e4/0x2e0
 napi_busy_loop+0x11/0x20
 xsk_recvmsg+0x10c/0x130
 sock_recvmsg+0x44/0x70
 __sys_recvfrom+0xbc/0x130
 ? __schedule+0x398/0x890
 __x64_sys_recvfrom+0x20/0x30
 do_syscall_64+0x4c/0x100
 entry_SYSCALL_64_after_hwframe+0x4b/0x53
...
---[ end trace 0000000000000000 ]---
...
---[ end Kernel panic - not syncing: Fatal exception in interrupt ]---

Fixes: 445a25f6e1a2 ("net/mlx5e: Support updating coalescing configuration without resetting channels")
Signed-off-by: Carolina Jubran <cjubran@nvidia.com>
Reviewed-by: Cosmin Ratiu <cratiu@nvidia.com>
Signed-off-by: Tariq Toukan <tariqt@nvidia.com>
Reviewed-by: Jacob Keller <jacob.e.keller@intel.com>
Link: https://patch.msgid.link/1752155624-24095-3-git-send-email-tariqt@nvidia.com
Signed-off-by: Jakub Kicinski <kuba@kernel.org>
```

**Diff:**
```diff
diff --git a/drivers/net/ethernet/mellanox/mlx5/core/en_dim.c b/drivers/net/ethernet/mellanox/mlx5/core/en_dim.c
index 298bb74ec5e9..d1d629697e28 100644
--- a/drivers/net/ethernet/mellanox/mlx5/core/en_dim.c
+++ b/drivers/net/ethernet/mellanox/mlx5/core/en_dim.c
@@ -113,7 +113,7 @@ int mlx5e_dim_rx_change(struct mlx5e_rq *rq, bool enable)
 		__set_bit(MLX5E_RQ_STATE_DIM, &rq->state);
 	} else {
 		__clear_bit(MLX5E_RQ_STATE_DIM, &rq->state);
-
+		synchronize_net();
 		mlx5e_dim_disable(rq->dim);
 		rq->dim = NULL;
 	}
@@ -140,7 +140,7 @@ int mlx5e_dim_tx_change(struct mlx5e_txqsq *sq, bool enable)
 		__set_bit(MLX5E_SQ_STATE_DIM, &sq->state);
 	} else {
 		__clear_bit(MLX5E_SQ_STATE_DIM, &sq->state);
-
+		synchronize_net();
 		mlx5e_dim_disable(sq->dim);
 		sq->dim = NULL;
 	}
```

---

