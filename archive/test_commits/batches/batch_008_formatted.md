# Linux Kernel Commit Batch Analysis

## Commit 1: 70b9c0c1

**Author:** Thomas Weißschuh
**Date:** 2025-07-08 10:23:13
**Files Changed:** include/uapi/linux/bits.h, tools/include/uapi/linux/bits.h

**Message:**
```
uapi: bitops: use UAPI-safe variant of BITS_PER_LONG again (2)

BITS_PER_LONG does not exist in UAPI headers, so can't be used by the UAPI
__GENMASK(). Instead __BITS_PER_LONG needs to be used.

When __GENMASK() was introduced in commit 3c7a8e190bc5 ("uapi: introduce uapi-friendly macros for GENMASK"),
the code was fine. A broken revert in 1e7933a575ed ("uapi: Revert "bitops: avoid integer overflow in GENMASK(_ULL)"")
introduced the incorrect usage of BITS_PER_LONG.
That was fixed in commit 11fcf368506d ("uapi: bitops: use UAPI-safe variant of BITS_PER_LONG again").
But a broken sync of the kernel headers with the tools/ headers in
commit fc92099902fb ("tools headers: Synchronize linux/bits.h with the kernel sources")
undid the fix.

Reapply the fix and while at it also fix the tools header.

Fixes: fc92099902fb ("tools headers: Synchronize linux/bits.h with the kernel sources")
Signed-off-by: Thomas Weißschuh <thomas.weissschuh@linutronix.de>
Acked-by: Yury Norov (NVIDIA) <yury.norov@gmail.com>
Signed-off-by: Yury Norov (NVIDIA) <yury.norov@gmail.com>
```

**Diff:**
```diff
diff --git a/include/uapi/linux/bits.h b/include/uapi/linux/bits.h
index 682b406e1067..a04afef9efca 100644
--- a/include/uapi/linux/bits.h
+++ b/include/uapi/linux/bits.h
@@ -4,9 +4,9 @@
 #ifndef _UAPI_LINUX_BITS_H
 #define _UAPI_LINUX_BITS_H
 
-#define __GENMASK(h, l) (((~_UL(0)) << (l)) & (~_UL(0) >> (BITS_PER_LONG - 1 - (h))))
+#define __GENMASK(h, l) (((~_UL(0)) << (l)) & (~_UL(0) >> (__BITS_PER_LONG - 1 - (h))))
 
-#define __GENMASK_ULL(h, l) (((~_ULL(0)) << (l)) & (~_ULL(0) >> (BITS_PER_LONG_LONG - 1 - (h))))
+#define __GENMASK_ULL(h, l) (((~_ULL(0)) << (l)) & (~_ULL(0) >> (__BITS_PER_LONG_LONG - 1 - (h))))
 
 #define __GENMASK_U128(h, l) \
 	((_BIT128((h)) << 1) - (_BIT128(l)))
diff --git a/tools/include/uapi/linux/bits.h b/tools/include/uapi/linux/bits.h
index 682b406e1067..a04afef9efca 100644
--- a/tools/include/uapi/linux/bits.h
+++ b/tools/include/uapi/linux/bits.h
@@ -4,9 +4,9 @@
 #ifndef _UAPI_LINUX_BITS_H
 #define _UAPI_LINUX_BITS_H
 
-#define __GENMASK(h, l) (((~_UL(0)) << (l)) & (~_UL(0) >> (BITS_PER_LONG - 1 - (h))))
+#define __GENMASK(h, l) (((~_UL(0)) << (l)) & (~_UL(0) >> (__BITS_PER_LONG - 1 - (h))))
 
-#define __GENMASK_ULL(h, l) (((~_ULL(0)) << (l)) & (~_ULL(0) >> (BITS_PER_LONG_LONG - 1 - (h))))
+#define __GENMASK_ULL(h, l) (((~_ULL(0)) << (l)) & (~_ULL(0) >> (__BITS_PER_LONG_LONG - 1 - (h))))
 
 #define __GENMASK_U128(h, l) \
 	((_BIT128((h)) << 1) - (_BIT128(l)))
```

---

## Commit 2: 705a412a

**Author:** Michal Wajdeczko
**Date:** 2025-07-07 20:57:07
**Files Changed:** drivers/gpu/drm/xe/xe_lmtt.c

**Message:**
```
drm/xe/pf: Clear all LMTT pages on alloc

Our LMEM buffer objects are not cleared by default on alloc
and during VF provisioning we only setup LMTT PTEs for the
actually provisioned LMEM range. But beyond that valid range
we might leave some stale data that could either point to some
other VFs allocations or even to the PF pages.

Explicitly clear all new LMTT page to avoid the risk that a
malicious VF would try to exploit that gap.

While around add asserts to catch any undesired PTE overwrites
and low-level debug traces to track LMTT PT life-cycle.

Fixes: b1d204058218 ("drm/xe/pf: Introduce Local Memory Translation Table")
Signed-off-by: Michal Wajdeczko <michal.wajdeczko@intel.com>
Cc: Michał Winiarski <michal.winiarski@intel.com>
Cc: Lukasz Laguna <lukasz.laguna@intel.com>
Reviewed-by: Michał Winiarski <michal.winiarski@intel.com>
Reviewed-by: Piotr Piórkowski <piotr.piorkowski@intel.com>
Link: https://lore.kernel.org/r/20250701220052.1612-1-michal.wajdeczko@intel.com
(cherry picked from commit 3fae6918a3e27cce20ded2551f863fb05d4bef8d)
Signed-off-by: Lucas De Marchi <lucas.demarchi@intel.com>
```

**Diff:**
```diff
diff --git a/drivers/gpu/drm/xe/xe_lmtt.c b/drivers/gpu/drm/xe/xe_lmtt.c
index 63db66df064b..023ed6a6b49d 100644
--- a/drivers/gpu/drm/xe/xe_lmtt.c
+++ b/drivers/gpu/drm/xe/xe_lmtt.c
@@ -78,6 +78,9 @@ static struct xe_lmtt_pt *lmtt_pt_alloc(struct xe_lmtt *lmtt, unsigned int level
 	}
 
 	lmtt_assert(lmtt, xe_bo_is_vram(bo));
+	lmtt_debug(lmtt, "level=%u addr=%#llx\n", level, (u64)xe_bo_main_addr(bo, XE_PAGE_SIZE));
+
+	xe_map_memset(lmtt_to_xe(lmtt), &bo->vmap, 0, 0, bo->size);
 
 	pt->level = level;
 	pt->bo = bo;
@@ -91,6 +94,9 @@ static struct xe_lmtt_pt *lmtt_pt_alloc(struct xe_lmtt *lmtt, unsigned int level
 
 static void lmtt_pt_free(struct xe_lmtt_pt *pt)
 {
+	lmtt_debug(&pt->bo->tile->sriov.pf.lmtt, "level=%u addr=%llx\n",
+		   pt->level, (u64)xe_bo_main_addr(pt->bo, XE_PAGE_SIZE));
+
 	xe_bo_unpin_map_no_vm(pt->bo);
 	kfree(pt);
 }
@@ -226,9 +232,14 @@ static void lmtt_write_pte(struct xe_lmtt *lmtt, struct xe_lmtt_pt *pt,
 
 	switch (lmtt->ops->lmtt_pte_size(level)) {
 	case sizeof(u32):
+		lmtt_assert(lmtt, !overflows_type(pte, u32));
+		lmtt_assert(lmtt, !pte || !iosys_map_rd(&pt->bo->vmap, idx * sizeof(u32), u32));
+
 		xe_map_wr(lmtt_to_xe(lmtt), &pt->bo->vmap, idx * sizeof(u32), u32, pte);
 		break;
 	case sizeof(u64):
+		lmtt_assert(lmtt, !pte || !iosys_map_rd(&pt->bo->vmap, idx * sizeof(u64), u64));
+
 		xe_map_wr(lmtt_to_xe(lmtt), &pt->bo->vmap, idx * sizeof(u64), u64, pte);
 		break;
 	default:
```

---

## Commit 3: 667eeab4

**Author:** Kuniyuki Iwashima
**Date:** 2025-07-07 18:38:24
**Files Changed:** net/tipc/topsrv.c

**Message:**
```
tipc: Fix use-after-free in tipc_conn_close().

syzbot reported a null-ptr-deref in tipc_conn_close() during netns
dismantle. [0]

tipc_topsrv_stop() iterates tipc_net(net)->topsrv->conn_idr and calls
tipc_conn_close() for each tipc_conn.

The problem is that tipc_conn_close() is called after releasing the
IDR lock.

At the same time, there might be tipc_conn_recv_work() running and it
could call tipc_conn_close() for the same tipc_conn and release its
last ->kref.

Once we release the IDR lock in tipc_topsrv_stop(), there is no
guarantee that the tipc_conn is alive.

Let's hold the ref before releasing the lock and put the ref after
tipc_conn_close() in tipc_topsrv_stop().

[0]:
BUG: KASAN: use-after-free in tipc_conn_close+0x122/0x140 net/tipc/topsrv.c:165
Read of size 8 at addr ffff888099305a08 by task kworker/u4:3/435

CPU: 0 PID: 435 Comm: kworker/u4:3 Not tainted 4.19.204-syzkaller #0
Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011
Workqueue: netns cleanup_net
Call Trace:
 __dump_stack lib/dump_stack.c:77 [inline]
 dump_stack+0x1fc/0x2ef lib/dump_stack.c:118
 print_address_description.cold+0x54/0x219 mm/kasan/report.c:256
 kasan_report_error.cold+0x8a/0x1b9 mm/kasan/report.c:354
 kasan_report mm/kasan/report.c:412 [inline]
 __asan_report_load8_noabort+0x88/0x90 mm/kasan/report.c:433
 tipc_conn_close+0x122/0x140 net/tipc/topsrv.c:165
 tipc_topsrv_stop net/tipc/topsrv.c:701 [inline]
 tipc_topsrv_exit_net+0x27b/0x5c0 net/tipc/topsrv.c:722
 ops_exit_list+0xa5/0x150 net/core/net_namespace.c:153
 cleanup_net+0x3b4/0x8b0 net/core/net_namespace.c:553
 process_one_work+0x864/0x1570 kernel/workqueue.c:2153
 worker_thread+0x64c/0x1130 kernel/workqueue.c:2296
 kthread+0x33f/0x460 kernel/kthread.c:259
 ret_from_fork+0x24/0x30 arch/x86/entry/entry_64.S:415

Allocated by task 23:
 kmem_cache_alloc_trace+0x12f/0x380 mm/slab.c:3625
 kmalloc include/linux/slab.h:515 [inline]
 kzalloc include/linux/slab.h:709 [inline]
 tipc_conn_alloc+0x43/0x4f0 net/tipc/topsrv.c:192
 tipc_topsrv_accept+0x1b5/0x280 net/tipc/topsrv.c:470
 process_one_work+0x864/0x1570 kernel/workqueue.c:2153
 worker_thread+0x64c/0x1130 kernel/workqueue.c:2296
 kthread+0x33f/0x460 kernel/kthread.c:259
 ret_from_fork+0x24/0x30 arch/x86/entry/entry_64.S:415

Freed by task 23:
 __cache_free mm/slab.c:3503 [inline]
 kfree+0xcc/0x210 mm/slab.c:3822
 tipc_conn_kref_release net/tipc/topsrv.c:150 [inline]
 kref_put include/linux/kref.h:70 [inline]
 conn_put+0x2cd/0x3a0 net/tipc/topsrv.c:155
 process_one_work+0x864/0x1570 kernel/workqueue.c:2153
 worker_thread+0x64c/0x1130 kernel/workqueue.c:2296
 kthread+0x33f/0x460 kernel/kthread.c:259
 ret_from_fork+0x24/0x30 arch/x86/entry/entry_64.S:415

The buggy address belongs to the object at ffff888099305a00
 which belongs to the cache kmalloc-512 of size 512
The buggy address is located 8 bytes inside of
 512-byte region [ffff888099305a00, ffff888099305c00)
The buggy address belongs to the page:
page:ffffea000264c140 count:1 mapcount:0 mapping:ffff88813bff0940 index:0x0
flags: 0xfff00000000100(slab)
raw: 00fff00000000100 ffffea00028b6b88 ffffea0002cd2b08 ffff88813bff0940
raw: 0000000000000000 ffff888099305000 0000000100000006 0000000000000000
page dumped because: kasan: bad access detected

Memory state around the buggy address:
 ffff888099305900: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
 ffff888099305980: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
>ffff888099305a00: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
                      ^
 ffff888099305a80: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
 ffff888099305b00: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb

Fixes: c5fa7b3cf3cb ("tipc: introduce new TIPC server infrastructure")
Reported-by: syzbot+d333febcf8f4bc5f6110@syzkaller.appspotmail.com
Closes: https://syzkaller.appspot.com/bug?extid=27169a847a70550d17be
Signed-off-by: Kuniyuki Iwashima <kuniyu@google.com>
Reviewed-by: Tung Nguyen <tung.quang.nguyen@est.tech>
Link: https://patch.msgid.link/20250702014350.692213-1-kuniyu@google.com
Signed-off-by: Jakub Kicinski <kuba@kernel.org>
```

**Diff:**
```diff
diff --git a/net/tipc/topsrv.c b/net/tipc/topsrv.c
index 8ee0c07d00e9..ffe577bf6b51 100644
--- a/net/tipc/topsrv.c
+++ b/net/tipc/topsrv.c
@@ -704,8 +704,10 @@ static void tipc_topsrv_stop(struct net *net)
 	for (id = 0; srv->idr_in_use; id++) {
 		con = idr_find(&srv->conn_idr, id);
 		if (con) {
+			conn_get(con);
 			spin_unlock_bh(&srv->idr_lock);
 			tipc_conn_close(con);
+			conn_put(con);
 			spin_lock_bh(&srv->idr_lock);
 		}
 	}
```

---

## Commit 4: 4e2bba30

**Author:** Jakub Kicinski
**Date:** 2025-07-07 16:45:21
**Files Changed:** drivers/net/phy/qcom/at803x.c, drivers/net/phy/qcom/qca808x.c, drivers/net/phy/qcom/qcom-phy-lib.c, drivers/net/phy/qcom/qcom.h

**Message:**
```
Merge branch 'fix-qca808x-wol-issue'

Luo Jie says:

====================
Fix QCA808X WoL Issue

Restore WoL (Wake-on-LAN) enablement via MMD3 register 0x8012 BIT5 for
the QCA808X PHY. This change resolves the issue where WoL functionality
was not working due to its unintended removal in a previous commit.

Refactor at8031_set_wol() into a shared library to enable reuse of the
Wake-on-LAN (WoL) functionality by the AT8031, QCA807X and QCA808X PHY
drivers.
====================

Link: https://patch.msgid.link/20250704-qcom_phy_wol_support-v1-0-053342b1538d@quicinc.com
Signed-off-by: Jakub Kicinski <kuba@kernel.org>
```

**Diff:**
```diff
diff --git a/drivers/net/phy/qcom/at803x.c b/drivers/net/phy/qcom/at803x.c
index 26350b962890..8f26e395e39f 100644
--- a/drivers/net/phy/qcom/at803x.c
+++ b/drivers/net/phy/qcom/at803x.c
@@ -26,9 +26,6 @@
 
 #define AT803X_LED_CONTROL			0x18
 
-#define AT803X_PHY_MMD3_WOL_CTRL		0x8012
-#define AT803X_WOL_EN				BIT(5)
-
 #define AT803X_REG_CHIP_CONFIG			0x1f
 #define AT803X_BT_BX_REG_SEL			0x8000
 
@@ -866,30 +863,6 @@ static int at8031_config_init(struct phy_device *phydev)
 	return at803x_config_init(phydev);
 }
 
-static int at8031_set_wol(struct phy_device *phydev,
-			  struct ethtool_wolinfo *wol)
-{
-	int ret;
-
-	/* First setup MAC address and enable WOL interrupt */
-	ret = at803x_set_wol(phydev, wol);
-	if (ret)
-		return ret;
-
-	if (wol->wolopts & WAKE_MAGIC)
-		/* Enable WOL function for 1588 */
-		ret = phy_modify_mmd(phydev, MDIO_MMD_PCS,
-				     AT803X_PHY_MMD3_WOL_CTRL,
-				     0, AT803X_WOL_EN);
-	else
-		/* Disable WoL function for 1588 */
-		ret = phy_modify_mmd(phydev, MDIO_MMD_PCS,
-				     AT803X_PHY_MMD3_WOL_CTRL,
-				     AT803X_WOL_EN, 0);
-
-	return ret;
-}
-
 static int at8031_config_intr(struct phy_device *phydev)
 {
 	struct at803x_priv *priv = phydev->priv;
diff --git a/drivers/net/phy/qcom/qca808x.c b/drivers/net/phy/qcom/qca808x.c
index 71498c518f0f..6de16c0eaa08 100644
--- a/drivers/net/phy/qcom/qca808x.c
+++ b/drivers/net/phy/qcom/qca808x.c
@@ -633,7 +633,7 @@ static struct phy_driver qca808x_driver[] = {

... (truncated 67 lines)
```

---

## Commit 5: 4ab9ada7

**Author:** Luo Jie
**Date:** 2025-07-07 16:43:47
**Files Changed:** drivers/net/phy/qcom/qca808x.c

**Message:**
```
net: phy: qcom: qca808x: Fix WoL issue by utilizing at8031_set_wol()

The previous commit unintentionally removed the code responsible for
enabling WoL via MMD3 register 0x8012 BIT5. As a result, Wake-on-LAN
(WoL) support for the QCA808X PHY is no longer functional.

The WoL (Wake-on-LAN) feature for the QCA808X PHY is enabled via MMD3
register 0x8012, BIT5. This implementation is aligned with the approach
used in at8031_set_wol().

Fixes: e58f30246c35 ("net: phy: at803x: fix the wol setting functions")
Signed-off-by: Luo Jie <quic_luoj@quicinc.com>
Reviewed-by: Maxime Chevallier <maxime.chevallier@bootlin.com>
Link: https://patch.msgid.link/20250704-qcom_phy_wol_support-v1-2-053342b1538d@quicinc.com
Signed-off-by: Jakub Kicinski <kuba@kernel.org>
```

**Diff:**
```diff
diff --git a/drivers/net/phy/qcom/qca808x.c b/drivers/net/phy/qcom/qca808x.c
index 71498c518f0f..6de16c0eaa08 100644
--- a/drivers/net/phy/qcom/qca808x.c
+++ b/drivers/net/phy/qcom/qca808x.c
@@ -633,7 +633,7 @@ static struct phy_driver qca808x_driver[] = {
 	.handle_interrupt	= at803x_handle_interrupt,
 	.get_tunable		= at803x_get_tunable,
 	.set_tunable		= at803x_set_tunable,
-	.set_wol		= at803x_set_wol,
+	.set_wol		= at8031_set_wol,
 	.get_wol		= at803x_get_wol,
 	.get_features		= qca808x_get_features,
 	.config_aneg		= qca808x_config_aneg,
```

---

