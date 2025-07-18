# Linux Kernel Commit Batch Analysis

## Commit 1: bdb32a0f

**Author:** Geert Uytterhoeven
**Date:** 2025-06-30 12:30:03
**Files Changed:** drivers/pci/controller/pci-host-common.c

**Message:**
```
PCI: host-generic: Set driver_data before calling gen_pci_init()

On MicroChip MPFS Icicle:

  microchip-pcie 2000000000.pcie: host bridge /soc/pcie@2000000000 ranges:
  microchip-pcie 2000000000.pcie: Parsing ranges property...
  microchip-pcie 2000000000.pcie:      MEM 0x2008000000..0x2087ffffff -> 0x0008000000
  Unable to handle kernel NULL pointer dereference at virtual address 0000000000000368
  Current swapper/0 pgtable: 4K pagesize, 39-bit VAs, pgdp=0x00000000814f1000
  [0000000000000368] pgd=0000000000000000, p4d=0000000000000000, pud=0000000000000000
  Oops [#1]
  Modules linked in:
  CPU: 0 UID: 0 PID: 1 Comm: swapper/0 Not tainted 6.15.0-rc1-icicle-00003-gafc0a570bb61 #232 NONE
  Hardware name: Microchip PolarFire-SoC Icicle Kit (DT)
  [...]
  [<ffffffff803fb8a4>] plda_pcie_setup_iomems+0xe/0x78
  [<ffffffff803fc246>] mc_platform_init+0x80/0x1d2
  [<ffffffff803f9c88>] pci_ecam_create+0x104/0x1e2
  [<ffffffff8000adbe>] pci_host_common_init+0x120/0x228
  [<ffffffff8000af42>] pci_host_common_probe+0x7c/0x8a

The initialization of driver_data was moved after the call to
gen_pci_init(), while the pci_ecam_ops.init() callback
mc_platform_init() expects it has already been initialized.

Fix this by moving the initialization of driver_data up.

Fixes: afc0a570bb613871 ("PCI: host-generic: Extract an ECAM bridge creation helper from pci_host_common_probe()")
Signed-off-by: Geert Uytterhoeven <geert+renesas@glider.be>
Signed-off-by: Marc Zyngier <maz@kernel.org>
Signed-off-by: Bjorn Helgaas <bhelgaas@google.com>
Link: https://lore.kernel.org/r/774290708a6f0f683711914fda110742c18a7fb2.1750787223.git.geert+renesas@glider.be
Link: https://patch.msgid.link/20250625111806.4153773-2-maz@kernel.org
```

**Diff:**
```diff
diff --git a/drivers/pci/controller/pci-host-common.c b/drivers/pci/controller/pci-host-common.c
index b0992325dd65..b37052863847 100644
--- a/drivers/pci/controller/pci-host-common.c
+++ b/drivers/pci/controller/pci-host-common.c
@@ -64,13 +64,13 @@ int pci_host_common_init(struct platform_device *pdev,
 
 	of_pci_check_probe_only();
 
+	platform_set_drvdata(pdev, bridge);
+
 	/* Parse and map our Configuration Space windows */
 	cfg = gen_pci_init(dev, bridge, ops);
 	if (IS_ERR(cfg))
 		return PTR_ERR(cfg);
 
-	platform_set_drvdata(pdev, bridge);
-
 	bridge->sysdata = cfg;
 	bridge->ops = (struct pci_ops *)&ops->pci_ops;
 	bridge->enable_device = ops->enable_device;
```

---

## Commit 2: 6729c134

**Author:** Jisheng Zhang
**Date:** 2025-06-30 16:06:40
**Files Changed:** drivers/regulator/mp886x.c

**Message:**
```
regulator: mp886x: Fix ID table driver_data

Currently, the driver_data of the i2c ID table is wrong, so it won't
work if any mp886x user makes use of the ID table. Fortunately, there's
no such user in upstream source code, we can fix the issue by using
different ID table entry for mp8867 and mp8869.

Signed-off-by: Jisheng Zhang <jszhang@kernel.org>
Link: https://patch.msgid.link/20250629095918.912-1-jszhang@kernel.org
Signed-off-by: Mark Brown <broonie@kernel.org>
```

**Diff:**
```diff
diff --git a/drivers/regulator/mp886x.c b/drivers/regulator/mp886x.c
index 48dcee5287f3..9ad16b04c913 100644
--- a/drivers/regulator/mp886x.c
+++ b/drivers/regulator/mp886x.c
@@ -348,7 +348,8 @@ static const struct of_device_id mp886x_dt_ids[] = {
 MODULE_DEVICE_TABLE(of, mp886x_dt_ids);
 
 static const struct i2c_device_id mp886x_id[] = {
-	{ "mp886x", (kernel_ulong_t)&mp8869_ci },
+	{ "mp8867", (kernel_ulong_t)&mp8867_ci },
+	{ "mp8869", (kernel_ulong_t)&mp8869_ci },
 	{ },
 };
 MODULE_DEVICE_TABLE(i2c, mp886x_id);
```

---

## Commit 3: f172ffde

**Author:** Jisheng Zhang
**Date:** 2025-06-30 16:06:39
**Files Changed:** drivers/regulator/sy8824x.c

**Message:**
```
regulator: sy8824x: Fix ID table driver_data

Currently, the driver_data of the i2c ID table is wrong, so it won't
work if any sy8824x user makes use of the ID table. Fortunately, there's
no such user in upstream source code, we can fix the issue by using
different ID table entry for sy8824c, sy8824e, sy20276 and sy20278.

Signed-off-by: Jisheng Zhang <jszhang@kernel.org>
Link: https://patch.msgid.link/20250629095905.898-1-jszhang@kernel.org
Signed-off-by: Mark Brown <broonie@kernel.org>
```

**Diff:**
```diff
diff --git a/drivers/regulator/sy8824x.c b/drivers/regulator/sy8824x.c
index c05b67e26ac8..5bec84db25f1 100644
--- a/drivers/regulator/sy8824x.c
+++ b/drivers/regulator/sy8824x.c
@@ -213,7 +213,10 @@ static const struct of_device_id sy8824_dt_ids[] = {
 MODULE_DEVICE_TABLE(of, sy8824_dt_ids);
 
 static const struct i2c_device_id sy8824_id[] = {
-	{ "sy8824", (kernel_ulong_t)&sy8824c_cfg },
+	{ "sy8824c", (kernel_ulong_t)&sy8824c_cfg },
+	{ "sy8824e", (kernel_ulong_t)&sy8824e_cfg },
+	{ "sy20276", (kernel_ulong_t)&sy20276_cfg },
+	{ "sy20278", (kernel_ulong_t)&sy20278_cfg },
 	{ }
 };
 MODULE_DEVICE_TABLE(i2c, sy8824_id);
```

---

## Commit 4: 74b1ec9f

**Author:** Daniil Dulov
**Date:** 2025-06-30 15:34:43
**Files Changed:** drivers/net/wireless/zydas/zd1211rw/zd_mac.c

**Message:**
```
wifi: zd1211rw: Fix potential NULL pointer dereference in zd_mac_tx_to_dev()

There is a potential NULL pointer dereference in zd_mac_tx_to_dev(). For
example, the following is possible:

    	T0			    		T1
zd_mac_tx_to_dev()
  /* len == skb_queue_len(q) */
  while (len > ZD_MAC_MAX_ACK_WAITERS) {

					  filter_ack()
					    spin_lock_irqsave(&q->lock, flags);
					    /* position == skb_queue_len(q) */
					    for (i=1; i<position; i++)
				    	      skb = __skb_dequeue(q)

					    if (mac->type == NL80211_IFTYPE_AP)
					      skb = __skb_dequeue(q);
					    spin_unlock_irqrestore(&q->lock, flags);

    skb_dequeue() -> NULL

Since there is a small gap between checking skb queue length and skb being
unconditionally dequeued in zd_mac_tx_to_dev(), skb_dequeue() can return NULL.
Then the pointer is passed to zd_mac_tx_status() where it is dereferenced.

In order to avoid potential NULL pointer dereference due to situations like
above, check if skb is not NULL before passing it to zd_mac_tx_status().

Found by Linux Verification Center (linuxtesting.org) with SVACE.

Fixes: 459c51ad6e1f ("zd1211rw: port to mac80211")
Signed-off-by: Daniil Dulov <d.dulov@aladdin.ru>
Link: https://patch.msgid.link/20250626114619.172631-1-d.dulov@aladdin.ru
Signed-off-by: Johannes Berg <johannes.berg@intel.com>
```

**Diff:**
```diff
diff --git a/drivers/net/wireless/zydas/zd1211rw/zd_mac.c b/drivers/net/wireless/zydas/zd1211rw/zd_mac.c
index 9653dbaac3c0..781510a3ec6d 100644
--- a/drivers/net/wireless/zydas/zd1211rw/zd_mac.c
+++ b/drivers/net/wireless/zydas/zd1211rw/zd_mac.c
@@ -583,7 +583,11 @@ void zd_mac_tx_to_dev(struct sk_buff *skb, int error)
 
 		skb_queue_tail(q, skb);
 		while (skb_queue_len(q) > ZD_MAC_MAX_ACK_WAITERS) {
-			zd_mac_tx_status(hw, skb_dequeue(q),
+			skb = skb_dequeue(q);
+			if (!skb)
+				break;
+
+			zd_mac_tx_status(hw, skb,
 					 mac->ack_pending ? mac->ack_signal : 0,
 					 NULL);
 			mac->ack_pending = 0;
```

---

## Commit 5: 1fe44a86

**Author:** Lachlan Hodges
**Date:** 2025-06-30 15:33:46
**Files Changed:** net/wireless/nl80211.c

**Message:**
```
wifi: cfg80211: fix S1G beacon head validation in nl80211

S1G beacons contain fixed length optional fields that precede the
variable length elements, ensure we take this into account when
validating the beacon. This particular case was missed in
1e1f706fc2ce ("wifi: cfg80211/mac80211: correctly parse S1G
beacon optional elements").

Fixes: 1d47f1198d58 ("nl80211: correctly validate S1G beacon head")
Signed-off-by: Lachlan Hodges <lachlan.hodges@morsemicro.com>
Link: https://patch.msgid.link/20250626115118.68660-1-lachlan.hodges@morsemicro.com
[shorten/reword subject]
Signed-off-by: Johannes Berg <johannes.berg@intel.com>
```

**Diff:**
```diff
diff --git a/net/wireless/nl80211.c b/net/wireless/nl80211.c
index 85f139016da2..50202d170f3a 100644
--- a/net/wireless/nl80211.c
+++ b/net/wireless/nl80211.c
@@ -229,6 +229,7 @@ static int validate_beacon_head(const struct nlattr *attr,
 	unsigned int len = nla_len(attr);
 	const struct element *elem;
 	const struct ieee80211_mgmt *mgmt = (void *)data;
+	const struct ieee80211_ext *ext;
 	unsigned int fixedlen, hdrlen;
 	bool s1g_bcn;
 
@@ -237,8 +238,10 @@ static int validate_beacon_head(const struct nlattr *attr,
 
 	s1g_bcn = ieee80211_is_s1g_beacon(mgmt->frame_control);
 	if (s1g_bcn) {
-		fixedlen = offsetof(struct ieee80211_ext,
-				    u.s1g_beacon.variable);
+		ext = (struct ieee80211_ext *)mgmt;
+		fixedlen =
+			offsetof(struct ieee80211_ext, u.s1g_beacon.variable) +
+			ieee80211_s1g_optional_len(ext->frame_control);
 		hdrlen = offsetof(struct ieee80211_ext, u.s1g_beacon);
 	} else {
 		fixedlen = offsetof(struct ieee80211_mgmt,
```

---

