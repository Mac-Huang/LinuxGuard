# Linux Kernel Commit Batch Analysis

## Commit 1: 97aadc16

**Author:** Dave Airlie
**Date:** 2025-06-20 08:57:11
**Files Changed:** drivers/gpu/drm/arm/malidp_planes.c, drivers/gpu/drm/ast/ast_mode.c, drivers/gpu/drm/etnaviv/etnaviv_sched.c, drivers/gpu/drm/mgag200/mgag200_ddc.c, drivers/gpu/drm/nouveau/nouveau_backlight.c (+4 more)

**Message:**
```
Merge tag 'drm-misc-fixes-2025-06-19' of https://gitlab.freedesktop.org/drm/misc/kernel into drm-fixes

drm-misc-fixes for v6.16-rc3:
- vivante scheduler fix.
- v3d null pointer crash fix.
- fix backlight, booting GSP-RM, and potential integer shift overflow in nouveau.
- fix compiler warnings about unused linux/export.h
- fix malidp unknown modifier spam.
- fix for ssd130x.

Signed-off-by: Dave Airlie <airlied@redhat.com>
From: Maarten Lankhorst <maarten.lankhorst@linux.intel.com>
Link: https://lore.kernel.org/r/d44bab7b-01f8-45a8-a7f4-5d3d563d2f9d@linux.intel.com
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
diff --git a/drivers/gpu/drm/arm/malidp_planes.c b/drivers/gpu/drm/arm/malidp_planes.c
index 34547edf1ee3..87f2e5ee8790 100644
--- a/drivers/gpu/drm/arm/malidp_planes.c
+++ b/drivers/gpu/drm/arm/malidp_planes.c
@@ -159,7 +159,7 @@ bool malidp_format_mod_supported(struct drm_device *drm,
 	}
 
 	if (!fourcc_mod_is_vendor(modifier, ARM)) {
-		DRM_ERROR("Unknown modifier (not Arm)\n");
+		DRM_DEBUG_KMS("Unknown modifier (not Arm)\n");
 		return false;
 	}
 
diff --git a/drivers/gpu/drm/ast/ast_mode.c b/drivers/gpu/drm/ast/ast_mode.c
index 1de832964e92..031980d8f3ab 100644
--- a/drivers/gpu/drm/ast/ast_mode.c
+++ b/drivers/gpu/drm/ast/ast_mode.c
@@ -29,7 +29,6 @@
  */
 
 #include <linux/delay.h>
-#include <linux/export.h>
 #include <linux/pci.h>
 
 #include <drm/drm_atomic.h>
diff --git a/drivers/gpu/drm/etnaviv/etnaviv_sched.c b/drivers/gpu/drm/etnaviv/etnaviv_sched.c
index 76a3a3e517d8..71e2e6b9d713 100644
--- a/drivers/gpu/drm/etnaviv/etnaviv_sched.c
+++ b/drivers/gpu/drm/etnaviv/etnaviv_sched.c
@@ -35,6 +35,7 @@ static enum drm_gpu_sched_stat etnaviv_sched_timedout_job(struct drm_sched_job
 							  *sched_job)
 {
 	struct etnaviv_gem_submit *submit = to_etnaviv_submit(sched_job);
+	struct drm_gpu_scheduler *sched = sched_job->sched;
 	struct etnaviv_gpu *gpu = submit->gpu;
 	u32 dma_addr, primid = 0;
 	int change;

... (truncated 132 lines)
```

---

## Commit 2: fde46f60

**Author:** Stephen Smalley
**Date:** 2025-06-19 16:13:16
**Files Changed:** security/selinux/ss/services.c

**Message:**
```
selinux: change security_compute_sid to return the ssid or tsid on match

If the end result of a security_compute_sid() computation matches the
ssid or tsid, return that SID rather than looking it up again. This
avoids the problem of multiple initial SIDs that map to the same
context.

Cc: stable@vger.kernel.org
Reported-by: Guido Trentalancia <guido@trentalancia.com>
Fixes: ae254858ce07 ("selinux: introduce an initial SID for early boot processes")
Signed-off-by: Stephen Smalley <stephen.smalley.work@gmail.com>
Tested-by: Guido Trentalancia <guido@trentalancia.com>
Signed-off-by: Paul Moore <paul@paul-moore.com>
```

**Diff:**
```diff
diff --git a/security/selinux/ss/services.c b/security/selinux/ss/services.c
index 7becf3808818..d185754c2786 100644
--- a/security/selinux/ss/services.c
+++ b/security/selinux/ss/services.c
@@ -1909,11 +1909,17 @@ static int security_compute_sid(u32 ssid,
 			goto out_unlock;
 	}
 	/* Obtain the sid for the context. */
-	rc = sidtab_context_to_sid(sidtab, &newcontext, out_sid);
-	if (rc == -ESTALE) {
-		rcu_read_unlock();
-		context_destroy(&newcontext);
-		goto retry;
+	if (context_equal(scontext, &newcontext))
+		*out_sid = ssid;
+	else if (context_equal(tcontext, &newcontext))
+		*out_sid = tsid;
+	else {
+		rc = sidtab_context_to_sid(sidtab, &newcontext, out_sid);
+		if (rc == -ESTALE) {
+			rcu_read_unlock();
+			context_destroy(&newcontext);
+			goto retry;
+		}
 	}
 out_unlock:
 	rcu_read_unlock();
```

---

## Commit 3: 5c8013ae

**Author:** Linus Torvalds
**Date:** 2025-06-19 10:21:32
**Files Changed:** drivers/atm/atmtcp.c, drivers/net/can/m_can/tcan4x5x-core.c, drivers/net/ethernet/airoha/airoha_eth.c, drivers/net/ethernet/airoha/airoha_ppe.c, drivers/net/ethernet/broadcom/bnxt/bnxt.c (+49 more)

**Message:**
```
Merge tag 'net-6.16-rc3' of git://git.kernel.org/pub/scm/linux/kernel/git/netdev/net

Pull networking fixes from Jakub Kicinski:
 "Including fixes from wireless.

  The ath12k fix to avoid FW crashes requires adding support for a
  number of new FW commands so it's quite large in terms of LoC. The
  rest is relatively small.

  Current release - fix to a fix:

   - ptp: fix breakage after ptp_vclock_in_use() rework

  Current release - regressions:

   - openvswitch: allocate struct ovs_pcpu_storage dynamically, static
     allocation may exhaust module loader limit on smaller systems

  Previous releases - regressions:

   - tcp: fix tcp_packet_delayed() for peers with no selective ACK
     support

  Previous releases - always broken:

   - wifi: ath12k: don't activate more links than firmware supports

   - tcp: make sure sockets open via passive TFO have valid NAPI ID

   - eth: bnxt_en: update MRU and RSS table of RSS contexts on queue
     reset, prevent Rx queues from silently hanging after queue reset

   - NFC: uart: set tty->disc_data only in success path"

* tag 'net-6.16-rc3' of git://git.kernel.org/pub/scm/linux/kernel/git/netdev/net: (59 commits)
  net: airoha: Differentiate hwfd buffer size for QDMA0 and QDMA1
  net: airoha: Compute number of descriptors according to reserved memory size
  tools: ynl: fix mixing ops and notifications on one socket
  net: atm: fix /proc/net/atm/lec handling
  net: atm: add lec_mutex
  mlxbf_gige: return EPROBE_DEFER if PHY IRQ is not available
  net: airoha: Always check return value from airoha_ppe_foe_get_entry()
  NFC: nci: uart: Set tty->disc_data only in success path
  calipso: Fix null-ptr-deref in calipso_req_{set,del}attr().
  MAINTAINERS: Remove Shannon Nelson from MAINTAINERS file
  net: lan743x: fix potential out-of-bounds write in lan743x_ptp_io_event_clock_get()
  eth: fbnic: avoid double free when failing to DMA-map FW msg
  tcp: fix passive TFO socket having invalid NAPI ID
  selftests: net: add test for passive TFO socket NAPI ID
  selftests: net: add passive TFO test binary
  selftests: netdevsim: improve lib.sh include in peer.sh
  tipc: fix null-ptr-deref when acquiring remote ip of ethernet bearer
  Octeontx2-pf: Fix Backpresure configuration
  net: ftgmac100: select FIXED_PHY
  net: ethtool: remove duplicate defines for family info
  ...
```

**Diff:**
```diff
diff --git a/.mailmap b/.mailmap
index fee7681100a8..d57531dab08b 100644
--- a/.mailmap
+++ b/.mailmap
@@ -693,9 +693,10 @@ Serge Hallyn <sergeh@kernel.org> <serge.hallyn@canonical.com>
 Serge Hallyn <sergeh@kernel.org> <serue@us.ibm.com>
 Seth Forshee <sforshee@kernel.org> <seth.forshee@canonical.com>
 Shakeel Butt <shakeel.butt@linux.dev> <shakeelb@google.com>
-Shannon Nelson <shannon.nelson@amd.com> <snelson@pensando.io>
-Shannon Nelson <shannon.nelson@amd.com> <shannon.nelson@intel.com>
-Shannon Nelson <shannon.nelson@amd.com> <shannon.nelson@oracle.com>
+Shannon Nelson <sln@onemain.com> <shannon.nelson@amd.com>
+Shannon Nelson <sln@onemain.com> <snelson@pensando.io>
+Shannon Nelson <sln@onemain.com> <shannon.nelson@intel.com>
+Shannon Nelson <sln@onemain.com> <shannon.nelson@oracle.com>
 Sharath Chandra Vurukala <quic_sharathv@quicinc.com> <sharathv@codeaurora.org>
 Shiraz Hashim <shiraz.linux.kernel@gmail.com> <shiraz.hashim@st.com>
 Shuah Khan <shuah@kernel.org> <shuahkhan@gmail.com>
diff --git a/Documentation/netlink/specs/ethtool.yaml b/Documentation/netlink/specs/ethtool.yaml
index 9f98715a6512..72a076b0e1b5 100644
--- a/Documentation/netlink/specs/ethtool.yaml
+++ b/Documentation/netlink/specs/ethtool.yaml
@@ -7,6 +7,9 @@ protocol: genetlink-legacy
 doc: Partial family for Ethtool Netlink.
 uapi-header: linux/ethtool_netlink_generated.h
 
+c-family-name: ethtool-genl-name
+c-version-name: ethtool-genl-version
+
 definitions:
   -
     name: udp-tunnel-type
diff --git a/MAINTAINERS b/MAINTAINERS
index bf73c90a957a..f584e170cfc3 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -1157,7 +1157,6 @@ F:	arch/x86/include/asm/amd/node.h
 F:	arch/x86/kernel/amd_node.c
 
 AMD PDS CORE DRIVER
-M:	Shannon Nelson <shannon.nelson@amd.com>
 M:	Brett Creeley <brett.creeley@amd.com>
 L:	netdev@vger.kernel.org
 S:	Maintained
@@ -9942,7 +9941,6 @@ F:	drivers/fwctl/mlx5/
 
 FWCTL PDS DRIVER
 M:	Brett Creeley <brett.creeley@amd.com>
-R:	Shannon Nelson <shannon.nelson@amd.com>
 L:	linux-kernel@vger.kernel.org

... (truncated 3726 lines)
```

---

## Commit 4: 6463cbe0

**Author:** Pablo Martin-Gomez
**Date:** 2025-06-19 19:13:21
**Files Changed:** drivers/mtd/nand/spi/core.c

**Message:**
```
mtd: spinand: fix memory leak of ECC engine conf

Memory allocated for the ECC engine conf is not released during spinand
cleanup. Below kmemleak trace is seen for this memory leak:

unreferenced object 0xffffff80064f00e0 (size 8):
  comm "swapper/0", pid 1, jiffies 4294937458
  hex dump (first 8 bytes):
    00 00 00 00 00 00 00 00                          ........
  backtrace (crc 0):
    kmemleak_alloc+0x30/0x40
    __kmalloc_cache_noprof+0x208/0x3c0
    spinand_ondie_ecc_init_ctx+0x114/0x200
    nand_ecc_init_ctx+0x70/0xa8
    nanddev_ecc_engine_init+0xec/0x27c
    spinand_probe+0xa2c/0x1620
    spi_mem_probe+0x130/0x21c
    spi_probe+0xf0/0x170
    really_probe+0x17c/0x6e8
    __driver_probe_device+0x17c/0x21c
    driver_probe_device+0x58/0x180
    __device_attach_driver+0x15c/0x1f8
    bus_for_each_drv+0xec/0x150
    __device_attach+0x188/0x24c
    device_initial_probe+0x10/0x20
    bus_probe_device+0x11c/0x160

Fix the leak by calling nanddev_ecc_engine_cleanup() inside
spinand_cleanup().

Signed-off-by: Pablo Martin-Gomez <pmartin-gomez@freebox.fr>
Signed-off-by: Miquel Raynal <miquel.raynal@bootlin.com>
```

**Diff:**
```diff
diff --git a/drivers/mtd/nand/spi/core.c b/drivers/mtd/nand/spi/core.c
index 7099db7a62be..c411fe9be3ef 100644
--- a/drivers/mtd/nand/spi/core.c
+++ b/drivers/mtd/nand/spi/core.c
@@ -1585,6 +1585,7 @@ static void spinand_cleanup(struct spinand_device *spinand)
 {
 	struct nand_device *nand = spinand_to_nand(spinand);
 
+	nanddev_ecc_engine_cleanup(nand);
 	nanddev_cleanup(nand);
 	spinand_manufacturer_cleanup(spinand);
 	kfree(spinand->databuf);
```

---

## Commit 5: b2348fe6

**Author:** Kent Overstreet
**Date:** 2025-06-19 13:08:06
**Files Changed:** fs/bcachefs/btree_update.c

**Message:**
```
bcachefs: Fix *__bch2_trans_subbuf_alloc() error path

Don't change buf->size on error - this would usually be a transaction
restart, but it could also be -ENOMEM - when we've exceeded the bump
allocator max).

Fixes: 247abee6ae6d ("bcachefs: btree_trans_subbuf")
Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
```

**Diff:**
```diff
diff --git a/fs/bcachefs/btree_update.c b/fs/bcachefs/btree_update.c
index e97e78c10f49..ee657b9f4b96 100644
--- a/fs/bcachefs/btree_update.c
+++ b/fs/bcachefs/btree_update.c
@@ -549,20 +549,26 @@ void *__bch2_trans_subbuf_alloc(struct btree_trans *trans,
 				unsigned u64s)
 {
 	unsigned new_top = buf->u64s + u64s;
-	unsigned old_size = buf->size;
+	unsigned new_size = buf->size;
 
-	if (new_top > buf->size)
-		buf->size = roundup_pow_of_two(new_top);
+	BUG_ON(roundup_pow_of_two(new_top) > U16_MAX);
 
-	void *n = bch2_trans_kmalloc_nomemzero(trans, buf->size * sizeof(u64));
+	if (new_top > new_size)
+		new_size = roundup_pow_of_two(new_top);
+
+	void *n = bch2_trans_kmalloc_nomemzero(trans, new_size * sizeof(u64));
 	if (IS_ERR(n))
 		return n;
 
+	unsigned offset = (u64 *) n - (u64 *) trans->mem;
+	BUG_ON(offset > U16_MAX);
+
 	if (buf->u64s)
 		memcpy(n,
 		       btree_trans_subbuf_base(trans, buf),
-		       old_size * sizeof(u64));
+		       buf->size * sizeof(u64));
 	buf->base = (u64 *) n - (u64 *) trans->mem;
+	buf->size = new_size;
 
 	void *p = btree_trans_subbuf_top(trans, buf);
 	buf->u64s = new_top;
```

---

