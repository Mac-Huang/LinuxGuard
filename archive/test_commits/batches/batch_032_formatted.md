# Linux Kernel Commit Batch Analysis

## Commit 1: e34a79b9

**Author:** Linus Torvalds
**Date:** 2025-06-26 09:13:27
**Files Changed:** drivers/atm/idt77252.c, drivers/bluetooth/btintel_pcie.c, drivers/bluetooth/hci_qca.c, drivers/net/ethernet/broadcom/bnxt/bnxt.c, drivers/net/ethernet/freescale/enetc/enetc_hw.h (+21 more)

**Message:**
```
Merge tag 'net-6.16-rc4' of git://git.kernel.org/pub/scm/linux/kernel/git/netdev/net

Pull networking fixes from Paolo Abeni:
 "Including fixes from bluetooth and wireless.

  Current release - regressions:

   - bridge: fix use-after-free during router port configuration

  Current release - new code bugs:

   - eth: wangxun: fix the creation of page_pool

  Previous releases - regressions:

   - netpoll: initialize UDP checksum field before checksumming

   - wifi: mac80211: finish link init before RCU publish

   - bluetooth: fix use-after-free in vhci_flush()

   - eth:
      - ionic: fix DMA mapping test
      - bnxt: properly flush XDP redirect lists

  Previous releases - always broken:

   - netlink: specs: enforce strict naming of properties

   - unix: don't leave consecutive consumed OOB skbs.

   - vsock: fix linux/vm_sockets.h userspace compilation errors

   - selftests: fix TCP packet checksum"

* tag 'net-6.16-rc4' of git://git.kernel.org/pub/scm/linux/kernel/git/netdev/net: (38 commits)
  net: libwx: fix the creation of page_pool
  net: selftests: fix TCP packet checksum
  atm: Release atm_dev_mutex after removing procfs in atm_dev_deregister().
  netlink: specs: enforce strict naming of properties
  netlink: specs: tc: replace underscores with dashes in names
  netlink: specs: rt-link: replace underscores with dashes in names
  netlink: specs: mptcp: replace underscores with dashes in names
  netlink: specs: ovs_flow: replace underscores with dashes in names
  netlink: specs: devlink: replace underscores with dashes in names
  netlink: specs: dpll: replace underscores with dashes in names
  netlink: specs: ethtool: replace underscores with dashes in names
  netlink: specs: fou: replace underscores with dashes in names
  netlink: specs: nfsd: replace underscores with dashes in names
  net: enetc: Correct endianness handling in _enetc_rd_reg64
  atm: idt77252: Add missing `dma_map_error()`
  bnxt: properly flush XDP redirect lists
  vsock/uapi: fix linux/vm_sockets.h userspace compilation errors
  wifi: mac80211: finish link init before RCU publish
  wifi: iwlwifi: mvm: assume '1' as the default mac_config_cmd version
  selftest: af_unix: Add tests for -ECONNRESET.
  ...
```

**Diff:**
```diff
diff --git a/CREDITS b/CREDITS
index 45446ae322ec..c30b75f9a732 100644
--- a/CREDITS
+++ b/CREDITS
@@ -2981,6 +2981,11 @@ S: 521 Pleasant Valley Road
 S: Potsdam, New York 13676
 S: USA
 
+N: Shannon Nelson
+E: sln@onemain.com
+D: Worked on several network drivers including
+D: ixgbe, i40e, ionic, pds_core, pds_vdpa, pds_fwctl
+
 N: Dave Neuer
 E: dave.neuer@pobox.com
 D: Helped implement support for Compaq's H31xx series iPAQs
diff --git a/Documentation/netlink/genetlink-legacy.yaml b/Documentation/netlink/genetlink-legacy.yaml
index 4cbfe666e6f5..b29d62eefa16 100644
--- a/Documentation/netlink/genetlink-legacy.yaml
+++ b/Documentation/netlink/genetlink-legacy.yaml
@@ -6,6 +6,9 @@ $schema: https://json-schema.org/draft-07/schema
 
 # Common defines
 $defs:
+  name:
+    type: string
+    pattern: ^[0-9a-z-]+$
   uint:
     type: integer
     minimum: 0
@@ -76,7 +79,7 @@ properties:
       additionalProperties: False
       properties:
         name:
-          type: string
+          $ref: '#/$defs/name'
         header:
           description: For C-compatible languages, header which already defines this value.
           type: string
@@ -103,7 +106,7 @@ properties:
                 additionalProperties: False
                 properties:
                   name:
-                    type: string
+                    $ref: '#/$defs/name'
                   value:
                     type: integer
                   doc:
@@ -132,7 +135,7 @@ properties:
             additionalProperties: False

... (truncated 1558 lines)
```

---

## Commit 2: 711741f9

**Author:** Paulo Alcantara
**Date:** 2025-06-26 11:12:04
**Files Changed:** fs/smb/client/cifsglob.h, fs/smb/client/connect.c

**Message:**
```
smb: client: fix potential deadlock when reconnecting channels

Fix cifs_signal_cifsd_for_reconnect() to take the correct lock order
and prevent the following deadlock from happening

======================================================
WARNING: possible circular locking dependency detected
6.16.0-rc3-build2+ #1301 Tainted: G S      W
------------------------------------------------------
cifsd/6055 is trying to acquire lock:
ffff88810ad56038 (&tcp_ses->srv_lock){+.+.}-{3:3}, at: cifs_signal_cifsd_for_reconnect+0x134/0x200

but task is already holding lock:
ffff888119c64330 (&ret_buf->chan_lock){+.+.}-{3:3}, at: cifs_signal_cifsd_for_reconnect+0xcf/0x200

which lock already depends on the new lock.

the existing dependency chain (in reverse order) is:

-> #2 (&ret_buf->chan_lock){+.+.}-{3:3}:
       validate_chain+0x1cf/0x270
       __lock_acquire+0x60e/0x780
       lock_acquire.part.0+0xb4/0x1f0
       _raw_spin_lock+0x2f/0x40
       cifs_setup_session+0x81/0x4b0
       cifs_get_smb_ses+0x771/0x900
       cifs_mount_get_session+0x7e/0x170
       cifs_mount+0x92/0x2d0
       cifs_smb3_do_mount+0x161/0x460
       smb3_get_tree+0x55/0x90
       vfs_get_tree+0x46/0x180
       do_new_mount+0x1b0/0x2e0
       path_mount+0x6ee/0x740
       do_mount+0x98/0xe0
       __do_sys_mount+0x148/0x180
       do_syscall_64+0xa4/0x260
       entry_SYSCALL_64_after_hwframe+0x76/0x7e

-> #1 (&ret_buf->ses_lock){+.+.}-{3:3}:
       validate_chain+0x1cf/0x270
       __lock_acquire+0x60e/0x780
       lock_acquire.part.0+0xb4/0x1f0
       _raw_spin_lock+0x2f/0x40
       cifs_match_super+0x101/0x320
       sget+0xab/0x270
       cifs_smb3_do_mount+0x1e0/0x460
       smb3_get_tree+0x55/0x90
       vfs_get_tree+0x46/0x180
       do_new_mount+0x1b0/0x2e0
       path_mount+0x6ee/0x740
       do_mount+0x98/0xe0
       __do_sys_mount+0x148/0x180
       do_syscall_64+0xa4/0x260
       entry_SYSCALL_64_after_hwframe+0x76/0x7e

-> #0 (&tcp_ses->srv_lock){+.+.}-{3:3}:
       check_noncircular+0x95/0xc0
       check_prev_add+0x115/0x2f0
       validate_chain+0x1cf/0x270
       __lock_acquire+0x60e/0x780
       lock_acquire.part.0+0xb4/0x1f0
       _raw_spin_lock+0x2f/0x40
       cifs_signal_cifsd_for_reconnect+0x134/0x200
       __cifs_reconnect+0x8f/0x500
       cifs_handle_standard+0x112/0x280
       cifs_demultiplex_thread+0x64d/0xbc0
       kthread+0x2f7/0x310
       ret_from_fork+0x2a/0x230
       ret_from_fork_asm+0x1a/0x30

other info that might help us debug this:

Chain exists of:
  &tcp_ses->srv_lock --> &ret_buf->ses_lock --> &ret_buf->chan_lock

 Possible unsafe locking scenario:

       CPU0                    CPU1
       ----                    ----
  lock(&ret_buf->chan_lock);
                               lock(&ret_buf->ses_lock);
                               lock(&ret_buf->chan_lock);
  lock(&tcp_ses->srv_lock);

 *** DEADLOCK ***

3 locks held by cifsd/6055:
 #0: ffffffff857de398 (&cifs_tcp_ses_lock){+.+.}-{3:3}, at: cifs_signal_cifsd_for_reconnect+0x7b/0x200
 #1: ffff888119c64060 (&ret_buf->ses_lock){+.+.}-{3:3}, at: cifs_signal_cifsd_for_reconnect+0x9c/0x200
 #2: ffff888119c64330 (&ret_buf->chan_lock){+.+.}-{3:3}, at: cifs_signal_cifsd_for_reconnect+0xcf/0x200

Cc: linux-cifs@vger.kernel.org
Reported-by: David Howells <dhowells@redhat.com>
Fixes: d7d7a66aacd6 ("cifs: avoid use of global locks for high contention data")
Reviewed-by: David Howells <dhowells@redhat.com>
Tested-by: David Howells <dhowells@redhat.com>
Signed-off-by: Paulo Alcantara (Red Hat) <pc@manguebit.org>
Signed-off-by: David Howells <dhowells@redhat.com>
Signed-off-by: Steve French <stfrench@microsoft.com>
```

**Diff:**
```diff
diff --git a/fs/smb/client/cifsglob.h b/fs/smb/client/cifsglob.h
index 45e94e18f4d5..318a8405d475 100644
--- a/fs/smb/client/cifsglob.h
+++ b/fs/smb/client/cifsglob.h
@@ -709,6 +709,7 @@ inc_rfc1001_len(void *buf, int count)
 struct TCP_Server_Info {
 	struct list_head tcp_ses_list;
 	struct list_head smb_ses_list;
+	struct list_head rlist; /* reconnect list */
 	spinlock_t srv_lock;  /* protect anything here that is not protected */
 	__u64 conn_id; /* connection identifier (useful for debugging) */
 	int srv_count; /* reference counter */
diff --git a/fs/smb/client/connect.c b/fs/smb/client/connect.c
index c48869c29e15..685c65dcb8c4 100644
--- a/fs/smb/client/connect.c
+++ b/fs/smb/client/connect.c
@@ -124,6 +124,14 @@ static void smb2_query_server_interfaces(struct work_struct *work)
 			   (SMB_INTERFACE_POLL_INTERVAL * HZ));
 }
 
+#define set_need_reco(server) \
+do { \
+	spin_lock(&server->srv_lock); \
+	if (server->tcpStatus != CifsExiting) \
+		server->tcpStatus = CifsNeedReconnect; \
+	spin_unlock(&server->srv_lock); \
+} while (0)
+
 /*
  * Update the tcpStatus for the server.
  * This is used to signal the cifsd thread to call cifs_reconnect
@@ -137,39 +145,45 @@ void
 cifs_signal_cifsd_for_reconnect(struct TCP_Server_Info *server,
 				bool all_channels)
 {
-	struct TCP_Server_Info *pserver;
+	struct TCP_Server_Info *nserver;
 	struct cifs_ses *ses;
+	LIST_HEAD(reco);
 	int i;
 
-	/* If server is a channel, select the primary channel */
-	pserver = SERVER_IS_CHAN(server) ? server->primary_server : server;
-
 	/* if we need to signal just this channel */
 	if (!all_channels) {
-		spin_lock(&server->srv_lock);
-		if (server->tcpStatus != CifsExiting)
-			server->tcpStatus = CifsNeedReconnect;
-		spin_unlock(&server->srv_lock);

... (truncated 49 lines)
```

---

## Commit 3: d07143b5

**Author:** Alok Tiwari
**Date:** 2025-06-26 17:14:31
**Files Changed:** drivers/platform/mellanox/nvsw-sn2201.c

**Message:**
```
platform/mellanox: nvsw-sn2201: Fix bus number in adapter error message

change error log to use correct bus number from main_mux_devs
instead of cpld_devs.

Fixes: 662f24826f95 ("platform/mellanox: Add support for new SN2201 system")
Signed-off-by: Alok Tiwari <alok.a.tiwari@oracle.com>
Reviewed-by: Vadim Pasternak <vadimp@nvidia.com>
Link: https://lore.kernel.org/r/20250622072921.4111552-2-alok.a.tiwari@oracle.com
Signed-off-by: Ilpo Järvinen <ilpo.jarvinen@linux.intel.com>
```

**Diff:**
```diff
diff --git a/drivers/platform/mellanox/nvsw-sn2201.c b/drivers/platform/mellanox/nvsw-sn2201.c
index db31c8bf2255..51504113c17e 100644
--- a/drivers/platform/mellanox/nvsw-sn2201.c
+++ b/drivers/platform/mellanox/nvsw-sn2201.c
@@ -1181,7 +1181,7 @@ static int nvsw_sn2201_i2c_completion_notify(void *handle, int id)
 	if (!nvsw_sn2201->main_mux_devs->adapter) {
 		err = -ENODEV;
 		dev_err(nvsw_sn2201->dev, "Failed to get adapter for bus %d\n",
-			nvsw_sn2201->cpld_devs->nr);
+			nvsw_sn2201->main_mux_devs->nr);
 		goto i2c_get_adapter_main_fail;
 	}
 
```

---

## Commit 4: c0070621

**Author:** Yu Kuai
**Date:** 2025-06-26 07:34:11
**Files Changed:** block/genhd.c

**Message:**
```
block: fix false warning in bdev_count_inflight_rw()

While bdev_count_inflight is interating all cpus, if some IOs are issued
from traversed cpu and then completed from the cpu that is not traversed
yet:

cpu0
		cpu1
		bdev_count_inflight
		 //for_each_possible_cpu
		 // cpu0 is 0
		 infliht += 0
// issue a io
blk_account_io_start
// cpu0 inflight ++

				cpu2
				// the io is done
				blk_account_io_done
				// cpu2 inflight --
		 // cpu 1 is 0
		 inflight += 0
		 // cpu2 is -1
		 inflight += -1
		 ...

In this case, the total inflight will be -1, causing lots of false
warning. Fix the problem by removing the warning.

Noted there is still a valid warning for nvme-mpath(From Yi) that is not
fixed yet.

Fixes: f5482ee5edb9 ("block: WARN if bdev inflight counter is negative")
Reported-by: Yi Zhang <yi.zhang@redhat.com>
Closes: https://lore.kernel.org/linux-block/aFtUXy-lct0WxY2w@mozart.vkv.me/T/#mae89155a5006463d0a21a4a2c35ae0034b26a339
Reported-and-tested-by: Calvin Owens <calvin@wbinvd.org>
Closes: https://lore.kernel.org/linux-block/aFtUXy-lct0WxY2w@mozart.vkv.me/T/#m1d935a00070bf95055d0ac84e6075158b08acaef
Reported-by: Dave Chinner <david@fromorbit.com>
Closes: https://lore.kernel.org/linux-block/aFuypjqCXo9-5_En@dread.disaster.area/
Signed-off-by: Yu Kuai <yukuai3@huawei.com>
Link: https://lore.kernel.org/r/20250626115743.1641443-1-yukuai3@huawei.com
Reviewed-by: Christoph Hellwig <hch@lst.de>
Signed-off-by: Jens Axboe <axboe@kernel.dk>
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
```

---

## Commit 5: 969127bf

**Author:** Ronnie Sahlberg
**Date:** 2025-06-26 07:31:24
**Files Changed:** drivers/block/ublk_drv.c

**Message:**
```
ublk: sanity check add_dev input for underflow

Add additional checks that queue depth and number of queues are
non-zero.

Signed-off-by: Ronnie Sahlberg <rsahlberg@whamcloud.com>
Reviewed-by: Ming Lei <ming.lei@redhat.com>
Link: https://lore.kernel.org/r/20250626022046.235018-1-ronniesahlberg@gmail.com
Signed-off-by: Jens Axboe <axboe@kernel.dk>
```

**Diff:**
```diff
diff --git a/drivers/block/ublk_drv.c b/drivers/block/ublk_drv.c
index d441d3259edb..c3e3c3b65a6d 100644
--- a/drivers/block/ublk_drv.c
+++ b/drivers/block/ublk_drv.c
@@ -2849,7 +2849,8 @@ static int ublk_ctrl_add_dev(const struct ublksrv_ctrl_cmd *header)
 	if (copy_from_user(&info, argp, sizeof(info)))
 		return -EFAULT;
 
-	if (info.queue_depth > UBLK_MAX_QUEUE_DEPTH || info.nr_hw_queues > UBLK_MAX_NR_QUEUES)
+	if (info.queue_depth > UBLK_MAX_QUEUE_DEPTH || !info.queue_depth ||
+	    info.nr_hw_queues > UBLK_MAX_NR_QUEUES || !info.nr_hw_queues)
 		return -EINVAL;
 
 	if (capable(CAP_SYS_ADMIN))
```

---

