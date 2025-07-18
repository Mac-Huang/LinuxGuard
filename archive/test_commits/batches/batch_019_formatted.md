# Linux Kernel Commit Batch Analysis

## Commit 1: 226862f5

**Author:** Maíra Canal
**Date:** 2025-07-02 19:08:11
**Files Changed:** drivers/gpu/drm/v3d/v3d_drv.h, drivers/gpu/drm/v3d/v3d_gem.c, drivers/gpu/drm/v3d/v3d_irq.c

**Message:**
```
drm/v3d: Disable interrupts before resetting the GPU

Currently, an interrupt can be triggered during a GPU reset, which can
lead to GPU hangs and NULL pointer dereference in an interrupt context
as shown in the following trace:

 [  314.035040] Unable to handle kernel NULL pointer dereference at virtual address 00000000000000c0
 [  314.043822] Mem abort info:
 [  314.046606]   ESR = 0x0000000096000005
 [  314.050347]   EC = 0x25: DABT (current EL), IL = 32 bits
 [  314.055651]   SET = 0, FnV = 0
 [  314.058695]   EA = 0, S1PTW = 0
 [  314.061826]   FSC = 0x05: level 1 translation fault
 [  314.066694] Data abort info:
 [  314.069564]   ISV = 0, ISS = 0x00000005, ISS2 = 0x00000000
 [  314.075039]   CM = 0, WnR = 0, TnD = 0, TagAccess = 0
 [  314.080080]   GCS = 0, Overlay = 0, DirtyBit = 0, Xs = 0
 [  314.085382] user pgtable: 4k pages, 39-bit VAs, pgdp=0000000102728000
 [  314.091814] [00000000000000c0] pgd=0000000000000000, p4d=0000000000000000, pud=0000000000000000
 [  314.100511] Internal error: Oops: 0000000096000005 [#1] PREEMPT SMP
 [  314.106770] Modules linked in: v3d i2c_brcmstb vc4 snd_soc_hdmi_codec gpu_sched drm_shmem_helper drm_display_helper cec drm_dma_helper drm_kms_helper drm drm_panel_orientation_quirks snd_soc_core snd_compress snd_pcm_dmaengine snd_pcm snd_timer snd backlight
 [  314.129654] CPU: 0 UID: 0 PID: 0 Comm: swapper/0 Not tainted 6.12.25+rpt-rpi-v8 #1  Debian 1:6.12.25-1+rpt1
 [  314.139388] Hardware name: Raspberry Pi 4 Model B Rev 1.4 (DT)
 [  314.145211] pstate: 600000c5 (nZCv daIF -PAN -UAO -TCO -DIT -SSBS BTYPE=--)
 [  314.152165] pc : v3d_irq+0xec/0x2e0 [v3d]
 [  314.156187] lr : v3d_irq+0xe0/0x2e0 [v3d]
 [  314.160198] sp : ffffffc080003ea0
 [  314.163502] x29: ffffffc080003ea0 x28: ffffffec1f184980 x27: 021202b000000000
 [  314.170633] x26: ffffffec1f17f630 x25: ffffff8101372000 x24: ffffffec1f17d9f0
 [  314.177764] x23: 000000000000002a x22: 000000000000002a x21: ffffff8103252000
 [  314.184895] x20: 0000000000000001 x19: 00000000deadbeef x18: 0000000000000000
 [  314.192026] x17: ffffff94e51d2000 x16: ffffffec1dac3cb0 x15: c306000000000000
 [  314.199156] x14: 0000000000000000 x13: b2fc982e03cc5168 x12: 0000000000000001
 [  314.206286] x11: ffffff8103f8bcc0 x10: ffffffec1f196868 x9 : ffffffec1dac3874
 [  314.213416] x8 : 0000000000000000 x7 : 0000000000042a3a x6 : ffffff810017a180
 [  314.220547] x5 : ffffffec1ebad400 x4 : ffffffec1ebad320 x3 : 00000000000bebeb
 [  314.227677] x2 : 0000000000000000 x1 : 0000000000000000 x0 : 0000000000000000
 [  314.234807] Call trace:
 [  314.237243]  v3d_irq+0xec/0x2e0 [v3d]
 [  314.240906]  __handle_irq_event_percpu+0x58/0x218
 [  314.245609]  handle_irq_event+0x54/0xb8
 [  314.249439]  handle_fasteoi_irq+0xac/0x240
 [  314.253527]  handle_irq_desc+0x48/0x68
 [  314.257269]  generic_handle_domain_irq+0x24/0x38
 [  314.261879]  gic_handle_irq+0x48/0xd8
 [  314.265533]  call_on_irq_stack+0x24/0x58
 [  314.269448]  do_interrupt_handler+0x88/0x98
 [  314.273624]  el1_interrupt+0x34/0x68
 [  314.277193]  el1h_64_irq_handler+0x18/0x28
 [  314.281281]  el1h_64_irq+0x64/0x68
 [  314.284673]  default_idle_call+0x3c/0x168
 [  314.288675]  do_idle+0x1fc/0x230
 [  314.291895]  cpu_startup_entry+0x3c/0x50
 [  314.295810]  rest_init+0xe4/0xf0
 [  314.299030]  start_kernel+0x5e8/0x790
 [  314.302684]  __primary_switched+0x80/0x90
 [  314.306691] Code: 940029eb 360ffc13 f9442ea0 52800001 (f9406017)
 [  314.312775] ---[ end trace 0000000000000000 ]---
 [  314.317384] Kernel panic - not syncing: Oops: Fatal exception in interrupt
 [  314.324249] SMP: stopping secondary CPUs
 [  314.328167] Kernel Offset: 0x2b9da00000 from 0xffffffc080000000
 [  314.334076] PHYS_OFFSET: 0x0
 [  314.336946] CPU features: 0x08,00002013,c0200000,0200421b
 [  314.342337] Memory Limit: none
 [  314.345382] ---[ end Kernel panic - not syncing: Oops: Fatal exception in interrupt ]---

Before resetting the GPU, it's necessary to disable all interrupts and
deal with any interrupt handler still in-flight. Otherwise, the GPU might
reset with jobs still running, or yet, an interrupt could be handled
during the reset.

Cc: stable@vger.kernel.org
Fixes: 57692c94dcbe ("drm/v3d: Introduce a new DRM driver for Broadcom V3D V3.x+")
Reviewed-by: Juan A. Suarez <jasuarez@igalia.com>
Reviewed-by: Iago Toral Quiroga <itoral@igalia.com>
Link: https://lore.kernel.org/r/20250628224243.47599-1-mcanal@igalia.com
Signed-off-by: Maíra Canal <mcanal@igalia.com>
```

**Diff:**
```diff
diff --git a/drivers/gpu/drm/v3d/v3d_drv.h b/drivers/gpu/drm/v3d/v3d_drv.h
index b51f0b648a08..411e47702f8a 100644
--- a/drivers/gpu/drm/v3d/v3d_drv.h
+++ b/drivers/gpu/drm/v3d/v3d_drv.h
@@ -101,6 +101,12 @@ enum v3d_gen {
 	V3D_GEN_71 = 71,
 };
 
+enum v3d_irq {
+	V3D_CORE_IRQ,
+	V3D_HUB_IRQ,
+	V3D_MAX_IRQS,
+};
+
 struct v3d_dev {
 	struct drm_device drm;
 
@@ -112,6 +118,8 @@ struct v3d_dev {
 
 	bool single_irq_line;
 
+	int irq[V3D_MAX_IRQS];
+
 	struct v3d_perfmon_info perfmon_info;
 
 	void __iomem *hub_regs;
diff --git a/drivers/gpu/drm/v3d/v3d_gem.c b/drivers/gpu/drm/v3d/v3d_gem.c
index d7d16da78db3..37bf5eecdd2c 100644
--- a/drivers/gpu/drm/v3d/v3d_gem.c
+++ b/drivers/gpu/drm/v3d/v3d_gem.c
@@ -134,6 +134,8 @@ v3d_reset(struct v3d_dev *v3d)
 	if (false)
 		v3d_idle_axi(v3d, 0);
 
+	v3d_irq_disable(v3d);
+
 	v3d_idle_gca(v3d);
 	v3d_reset_sms(v3d);
 	v3d_reset_v3d(v3d);
diff --git a/drivers/gpu/drm/v3d/v3d_irq.c b/drivers/gpu/drm/v3d/v3d_irq.c
index 2cca5d3a26a2..a515a301e480 100644
--- a/drivers/gpu/drm/v3d/v3d_irq.c
+++ b/drivers/gpu/drm/v3d/v3d_irq.c
@@ -260,7 +260,7 @@ v3d_hub_irq(int irq, void *arg)
 int
 v3d_irq_init(struct v3d_dev *v3d)
 {
-	int irq1, ret, core;
+	int irq, ret, core;
 

... (truncated 62 lines)
```

---

## Commit 2: c2a2ff6b

**Author:** Antoine Tenart
**Date:** 2025-07-02 14:46:44
**Files Changed:** net/ipv4/ip_input.c

**Message:**
```
net: ipv4: fix stat increase when udp early demux drops the packet

udp_v4_early_demux now returns drop reasons as it either returns 0 or
ip_mc_validate_source, which returns itself a drop reason. However its
use was not converted in ip_rcv_finish_core and the drop reason is
ignored, leading to potentially skipping increasing LINUX_MIB_IPRPFILTER
if the drop reason is SKB_DROP_REASON_IP_RPFILTER.

This is a fix and we're not converting udp_v4_early_demux to explicitly
return a drop reason to ease backports; this can be done as a follow-up.

Fixes: d46f827016d8 ("net: ip: make ip_mc_validate_source() return drop reason")
Cc: Menglong Dong <menglong8.dong@gmail.com>
Reported-by: Sabrina Dubroca <sd@queasysnail.net>
Signed-off-by: Antoine Tenart <atenart@kernel.org>
Reviewed-by: Sabrina Dubroca <sd@queasysnail.net>
Link: https://patch.msgid.link/20250701074935.144134-1-atenart@kernel.org
Signed-off-by: Jakub Kicinski <kuba@kernel.org>
```

**Diff:**
```diff
diff --git a/net/ipv4/ip_input.c b/net/ipv4/ip_input.c
index 30a5e9460d00..5a49eb99e5c4 100644
--- a/net/ipv4/ip_input.c
+++ b/net/ipv4/ip_input.c
@@ -319,8 +319,8 @@ static int ip_rcv_finish_core(struct net *net,
 			      const struct sk_buff *hint)
 {
 	const struct iphdr *iph = ip_hdr(skb);
-	int err, drop_reason;
 	struct rtable *rt;
+	int drop_reason;
 
 	if (ip_can_use_hint(skb, iph, hint)) {
 		drop_reason = ip_route_use_hint(skb, iph->daddr, iph->saddr,
@@ -345,9 +345,10 @@ static int ip_rcv_finish_core(struct net *net,
 			break;
 		case IPPROTO_UDP:
 			if (READ_ONCE(net->ipv4.sysctl_udp_early_demux)) {
-				err = udp_v4_early_demux(skb);
-				if (unlikely(err))
+				drop_reason = udp_v4_early_demux(skb);
+				if (unlikely(drop_reason))
 					goto drop_error;
+				drop_reason = SKB_DROP_REASON_NOT_SPECIFIED;
 
 				/* must reload iph, skb->head might have changed */
 				iph = ip_hdr(skb);
```

---

## Commit 3: 103406b3

**Author:** Lion Ackermann
**Date:** 2025-07-02 14:42:17
**Files Changed:** net/sched/sch_api.c

**Message:**
```
net/sched: Always pass notifications when child class becomes empty

Certain classful qdiscs may invoke their classes' dequeue handler on an
enqueue operation. This may unexpectedly empty the child qdisc and thus
make an in-flight class passive via qlen_notify(). Most qdiscs do not
expect such behaviour at this point in time and may re-activate the
class eventually anyways which will lead to a use-after-free.

The referenced fix commit attempted to fix this behavior for the HFSC
case by moving the backlog accounting around, though this turned out to
be incomplete since the parent's parent may run into the issue too.
The following reproducer demonstrates this use-after-free:

    tc qdisc add dev lo root handle 1: drr
    tc filter add dev lo parent 1: basic classid 1:1
    tc class add dev lo parent 1: classid 1:1 drr
    tc qdisc add dev lo parent 1:1 handle 2: hfsc def 1
    tc class add dev lo parent 2: classid 2:1 hfsc rt m1 8 d 1 m2 0
    tc qdisc add dev lo parent 2:1 handle 3: netem
    tc qdisc add dev lo parent 3:1 handle 4: blackhole

    echo 1 | socat -u STDIN UDP4-DATAGRAM:127.0.0.1:8888
    tc class delete dev lo classid 1:1
    echo 1 | socat -u STDIN UDP4-DATAGRAM:127.0.0.1:8888

Since backlog accounting issues leading to a use-after-frees on stale
class pointers is a recurring pattern at this point, this patch takes
a different approach. Instead of trying to fix the accounting, the patch
ensures that qdisc_tree_reduce_backlog always calls qlen_notify when
the child qdisc is empty. This solves the problem because deletion of
qdiscs always involves a call to qdisc_reset() and / or
qdisc_purge_queue() which ultimately resets its qlen to 0 thus causing
the following qdisc_tree_reduce_backlog() to report to the parent. Note
that this may call qlen_notify on passive classes multiple times. This
is not a problem after the recent patch series that made all the
classful qdiscs qlen_notify() handlers idempotent.

Fixes: 3f981138109f ("sch_hfsc: Fix qlen accounting bug when using peek in hfsc_enqueue()")
Signed-off-by: Lion Ackermann <nnamrec@gmail.com>
Reviewed-by: Jamal Hadi Salim <jhs@mojatatu.com>
Acked-by: Cong Wang <xiyou.wangcong@gmail.com>
Acked-by: Jamal Hadi Salim <jhs@mojatatu.com>
Link: https://patch.msgid.link/d912cbd7-193b-4269-9857-525bee8bbb6a@gmail.com
Signed-off-by: Jakub Kicinski <kuba@kernel.org>
```

**Diff:**
```diff
diff --git a/net/sched/sch_api.c b/net/sched/sch_api.c
index c5e3673aadbe..d8a33486c511 100644
--- a/net/sched/sch_api.c
+++ b/net/sched/sch_api.c
@@ -780,15 +780,12 @@ static u32 qdisc_alloc_handle(struct net_device *dev)
 
 void qdisc_tree_reduce_backlog(struct Qdisc *sch, int n, int len)
 {
-	bool qdisc_is_offloaded = sch->flags & TCQ_F_OFFLOADED;
 	const struct Qdisc_class_ops *cops;
 	unsigned long cl;
 	u32 parentid;
 	bool notify;
 	int drops;
 
-	if (n == 0 && len == 0)
-		return;
 	drops = max_t(int, n, 0);
 	rcu_read_lock();
 	while ((parentid = sch->parent)) {
@@ -797,17 +794,8 @@ void qdisc_tree_reduce_backlog(struct Qdisc *sch, int n, int len)
 
 		if (sch->flags & TCQ_F_NOPARENT)
 			break;
-		/* Notify parent qdisc only if child qdisc becomes empty.
-		 *
-		 * If child was empty even before update then backlog
-		 * counter is screwed and we skip notification because
-		 * parent class is already passive.
-		 *
-		 * If the original child was offloaded then it is allowed
-		 * to be seem as empty, so the parent is notified anyway.
-		 */
-		notify = !sch->q.qlen && !WARN_ON_ONCE(!n &&
-						       !qdisc_is_offloaded);
+		/* Notify parent qdisc only if child qdisc becomes empty. */
+		notify = !sch->q.qlen;
 		/* TODO: perform the search on a per txq basis */
 		sch = qdisc_lookup_rcu(qdisc_dev(sch), TC_H_MAJ(parentid));
 		if (sch == NULL) {
@@ -816,6 +804,9 @@ void qdisc_tree_reduce_backlog(struct Qdisc *sch, int n, int len)
 		}
 		cops = sch->ops->cl_ops;
 		if (notify && cops->qlen_notify) {
+			/* Note that qlen_notify must be idempotent as it may get called
+			 * multiple times.
+			 */
 			cl = cops->find(sch, parentid);
 			cops->qlen_notify(sch, cl);
 		}
```

---

## Commit 4: b4911fb0

**Author:** Linus Torvalds
**Date:** 2025-07-02 09:34:57
**Files Changed:** drivers/mmc/core/quirks.h, drivers/mmc/core/sd_uhs2.c, drivers/mmc/host/mtk-sd.c, drivers/mmc/host/sdhci-of-k1.c, drivers/mmc/host/sdhci-uhs2.c (+2 more)

**Message:**
```
Merge tag 'mmc-v6.16-rc1' of git://git.kernel.org/pub/scm/linux/kernel/git/ulfh/mmc

Pull MMC fixes from Ulf Hansson:
 "MMC core:
   - Apply BROKEN_SD_DISCARD quirk earlier during init
   - Silence some confusing error messages for SD UHS-II cards

  MMC host:
   - mtk-sd:
       - Prevent memory corruption from DMA map failure
       - Fix a pagefault in dma_unmap_sg() for not prepared data
   - sdhci: Revert "Disable SD card clock before changing parameters"
   - sdhci-of-k1: Fix error code in probe()
   - sdhci-uhs2: Silence some confusing error messages for SD UHS-II cards"

* tag 'mmc-v6.16-rc1' of git://git.kernel.org/pub/scm/linux/kernel/git/ulfh/mmc:
  mtk-sd: reset host->mrq on prepare_data() error
  Revert "mmc: sdhci: Disable SD card clock before changing parameters"
  mmc: sdhci-uhs2: Adjust some error messages and register dump for SD UHS-II card
  mmc: sdhci: Add a helper function for dump register in dynamic debug mode
  mmc: core: Adjust some error messages for SD UHS-II cards
  mtk-sd: Prevent memory corruption from DMA map failure
  mtk-sd: Fix a pagefault in dma_unmap_sg() for not prepared data
  mmc: sdhci-of-k1: Fix error code in probe()
  mmc: core: sd: Apply BROKEN_SD_DISCARD quirk earlier
```

**Diff:**
```diff
diff --git a/drivers/mmc/core/quirks.h b/drivers/mmc/core/quirks.h
index 7f893bafaa60..c417ed34c057 100644
--- a/drivers/mmc/core/quirks.h
+++ b/drivers/mmc/core/quirks.h
@@ -44,6 +44,12 @@ static const struct mmc_fixup __maybe_unused mmc_sd_fixups[] = {
 		   0, -1ull, SDIO_ANY_ID, SDIO_ANY_ID, add_quirk_sd,
 		   MMC_QUIRK_NO_UHS_DDR50_TUNING, EXT_CSD_REV_ANY),
 
+	/*
+	 * Some SD cards reports discard support while they don't
+	 */
+	MMC_FIXUP(CID_NAME_ANY, CID_MANFID_SANDISK_SD, 0x5344, add_quirk_sd,
+		  MMC_QUIRK_BROKEN_SD_DISCARD),
+
 	END_FIXUP
 };
 
@@ -147,12 +153,6 @@ static const struct mmc_fixup __maybe_unused mmc_blk_fixups[] = {
 	MMC_FIXUP("M62704", CID_MANFID_KINGSTON, 0x0100, add_quirk_mmc,
 		  MMC_QUIRK_TRIM_BROKEN),
 
-	/*
-	 * Some SD cards reports discard support while they don't
-	 */
-	MMC_FIXUP(CID_NAME_ANY, CID_MANFID_SANDISK_SD, 0x5344, add_quirk_sd,
-		  MMC_QUIRK_BROKEN_SD_DISCARD),
-
 	END_FIXUP
 };
 
diff --git a/drivers/mmc/core/sd_uhs2.c b/drivers/mmc/core/sd_uhs2.c
index 1c31d0dfa961..de17d1611290 100644
--- a/drivers/mmc/core/sd_uhs2.c
+++ b/drivers/mmc/core/sd_uhs2.c
@@ -91,8 +91,8 @@ static int sd_uhs2_phy_init(struct mmc_host *host)
 
 	err = host->ops->uhs2_control(host, UHS2_PHY_INIT);
 	if (err) {
-		pr_err("%s: failed to initial phy for UHS-II!\n",
-		       mmc_hostname(host));
+		pr_debug("%s: failed to initial phy for UHS-II!\n",
+			 mmc_hostname(host));
 	}
 
 	return err;
diff --git a/drivers/mmc/host/mtk-sd.c b/drivers/mmc/host/mtk-sd.c
index 31eb90536bce..d7020e06dd55 100644
--- a/drivers/mmc/host/mtk-sd.c
+++ b/drivers/mmc/host/mtk-sd.c
@@ -846,12 +846,18 @@ static inline void msdc_dma_setup(struct msdc_host *host, struct msdc_dma *dma,

... (truncated 164 lines)
```

---

## Commit 5: ba6a2f25

**Author:** Linus Torvalds
**Date:** 2025-07-02 09:27:57
**Files Changed:** arch/s390/pci/pci_event.c

**Message:**
```
Merge tag 's390-6.16-4' of git://git.kernel.org/pub/scm/linux/kernel/git/s390/linux

Pull s390 fixes from Alexander Gordeev:

 - Fix PCI error recovery and bring it in line with AER/EEH

* tag 's390-6.16-4' of git://git.kernel.org/pub/scm/linux/kernel/git/s390/linux:
  s390/pci: Allow automatic recovery with minimal driver support
  s390/pci: Do not try re-enabling load/store if device is disabled
  s390/pci: Fix stale function handles in error handling
```

**Diff:**
```diff
diff --git a/arch/s390/pci/pci_event.c b/arch/s390/pci/pci_event.c
index 2fbee3887d13..d930416d4c90 100644
--- a/arch/s390/pci/pci_event.c
+++ b/arch/s390/pci/pci_event.c
@@ -54,6 +54,7 @@ static inline bool ers_result_indicates_abort(pci_ers_result_t ers_res)
 	case PCI_ERS_RESULT_CAN_RECOVER:
 	case PCI_ERS_RESULT_RECOVERED:
 	case PCI_ERS_RESULT_NEED_RESET:
+	case PCI_ERS_RESULT_NONE:
 		return false;
 	default:
 		return true;
@@ -78,10 +79,6 @@ static bool is_driver_supported(struct pci_driver *driver)
 		return false;
 	if (!driver->err_handler->error_detected)
 		return false;
-	if (!driver->err_handler->slot_reset)
-		return false;
-	if (!driver->err_handler->resume)
-		return false;
 	return true;
 }
 
@@ -106,6 +103,10 @@ static pci_ers_result_t zpci_event_do_error_state_clear(struct pci_dev *pdev,
 	struct zpci_dev *zdev = to_zpci(pdev);
 	int rc;
 
+	/* The underlying device may have been disabled by the event */
+	if (!zdev_enabled(zdev))
+		return PCI_ERS_RESULT_NEED_RESET;
+
 	pr_info("%s: Unblocking device access for examination\n", pci_name(pdev));
 	rc = zpci_reset_load_store_blocked(zdev);
 	if (rc) {
@@ -114,16 +115,18 @@ static pci_ers_result_t zpci_event_do_error_state_clear(struct pci_dev *pdev,
 		return PCI_ERS_RESULT_NEED_RESET;
 	}
 
-	if (driver->err_handler->mmio_enabled) {
+	if (driver->err_handler->mmio_enabled)
 		ers_res = driver->err_handler->mmio_enabled(pdev);
-		if (ers_result_indicates_abort(ers_res)) {
-			pr_info("%s: Automatic recovery failed after MMIO re-enable\n",
-				pci_name(pdev));
-			return ers_res;
-		} else if (ers_res == PCI_ERS_RESULT_NEED_RESET) {
-			pr_debug("%s: Driver needs reset to recover\n", pci_name(pdev));
-			return ers_res;
-		}
+	else

... (truncated 77 lines)
```

---

