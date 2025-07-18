# Linux Kernel Commit Batch Analysis

## Commit 1: b7dc79a6

**Author:** Simona Vetter
**Date:** 2025-07-11 14:11:19
**Files Changed:** drivers/char/agp/amd64-agp.c, drivers/gpu/drm/drm_framebuffer.c, drivers/gpu/drm/drm_gem.c, drivers/gpu/drm/drm_gem_framebuffer_helper.c, drivers/gpu/drm/drm_internal.h (+8 more)

**Message:**
```
Merge tag 'drm-misc-fixes-2025-07-10' of https://gitlab.freedesktop.org/drm/misc/kernel into drm-fixes

drm-misc-fixes for v6.16-rc6 or final:
- Fix nouveau fail on debugfs errors.
- Magic 50 ms to fix nouveau suspend.
- Call rust destructor on drm device release.
- Fix DMA api error handling in tegra/nvdec.
- Fix PVR device reset.
- Habanalabs maintainer update.
- Small memory leak fix when nouveau acpi init fails.
- Do not attempt to bind to any PCI device with AGP capability.
- Make FB's acquire handles on backing object, same as i915/xe already does.
- Fix race in drm_gem_handle_create_tail.

Signed-off-by: Simona Vetter <simona.vetter@ffwll.ch>
From: Maarten Lankhorst <maarten.lankhorst@linux.intel.com>
Link: https://patchwork.freedesktop.org/patch/msgid/e522cdc7-1787-48f2-97e5-0f94783970ab@linux.intel.com
```

**Diff:**
```diff
diff --git a/MAINTAINERS b/MAINTAINERS
index fad6cb025a19..76f78fe8e545 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -10504,7 +10504,7 @@ S:	Maintained
 F:	block/partitions/efi.*
 
 HABANALABS PCI DRIVER
-M:	Ofir Bitton <obitton@habana.ai>
+M:	Yaron Avizrat <yaron.avizrat@intel.com>
 L:	dri-devel@lists.freedesktop.org
 S:	Supported
 C:	irc://irc.oftc.net/dri-devel
diff --git a/drivers/char/agp/amd64-agp.c b/drivers/char/agp/amd64-agp.c
index bf490967241a..2505df1f4e69 100644
--- a/drivers/char/agp/amd64-agp.c
+++ b/drivers/char/agp/amd64-agp.c
@@ -720,11 +720,6 @@ static const struct pci_device_id agp_amd64_pci_table[] = {
 
 MODULE_DEVICE_TABLE(pci, agp_amd64_pci_table);
 
-static const struct pci_device_id agp_amd64_pci_promisc_table[] = {
-	{ PCI_DEVICE_CLASS(0, 0) },
-	{ }
-};
-
 static DEFINE_SIMPLE_DEV_PM_OPS(agp_amd64_pm_ops, NULL, agp_amd64_resume);
 
 static struct pci_driver agp_amd64_pci_driver = {
@@ -739,6 +734,7 @@ static struct pci_driver agp_amd64_pci_driver = {
 /* Not static due to IOMMU code calling it early. */
 int __init agp_amd64_init(void)
 {
+	struct pci_dev *pdev = NULL;
 	int err = 0;
 
 	if (agp_off)
@@ -767,9 +763,13 @@ int __init agp_amd64_init(void)
 		}
 
 		/* Look for any AGP bridge */
-		agp_amd64_pci_driver.id_table = agp_amd64_pci_promisc_table;
-		err = driver_attach(&agp_amd64_pci_driver.driver);
-		if (err == 0 && agp_bridges_found == 0) {
+		for_each_pci_dev(pdev)
+			if (pci_find_capability(pdev, PCI_CAP_ID_AGP))
+				pci_add_dynid(&agp_amd64_pci_driver,
+					      pdev->vendor, pdev->device,
+					      pdev->subsystem_vendor,
+					      pdev->subsystem_device, 0, 0, 0);

... (truncated 533 lines)
```

---

## Commit 2: 711c80f7

**Author:** Kito Xu
**Date:** 2025-07-10 18:01:08
**Files Changed:** net/appletalk/ddp.c

**Message:**
```
net: appletalk: Fix device refcount leak in atrtr_create()

When updating an existing route entry in atrtr_create(), the old device
reference was not being released before assigning the new device,
leading to a device refcount leak. Fix this by calling dev_put() to
release the old device reference before holding the new one.

Fixes: c7f905f0f6d4 ("[ATALK]: Add missing dev_hold() to atrtr_create().")
Signed-off-by: Kito Xu <veritas501@foxmail.com>
Link: https://patch.msgid.link/tencent_E1A26771CDAB389A0396D1681A90A49E5D09@qq.com
Signed-off-by: Jakub Kicinski <kuba@kernel.org>
```

**Diff:**
```diff
diff --git a/net/appletalk/ddp.c b/net/appletalk/ddp.c
index 73ea7e67f05a..30242fe10341 100644
--- a/net/appletalk/ddp.c
+++ b/net/appletalk/ddp.c
@@ -576,6 +576,7 @@ static int atrtr_create(struct rtentry *r, struct net_device *devhint)
 
 	/* Fill in the routing entry */
 	rt->target  = ta->sat_addr;
+	dev_put(rt->dev); /* Release old device */
 	dev_hold(devhint);
 	rt->dev     = devhint;
 	rt->flags   = r->rt_flags;
```

---

## Commit 3: 7ac5cc26

**Author:** Jakub Kicinski
**Date:** 2025-07-10 17:13:46
**Files Changed:** drivers/net/wireless/marvell/mwifiex/util.c, drivers/net/wireless/mediatek/mt76/mt76.h, drivers/net/wireless/mediatek/mt76/mt7603/dma.c, drivers/net/wireless/mediatek/mt76/mt7603/mac.c, drivers/net/wireless/mediatek/mt76/mt7615/mac.c (+34 more)

**Message:**
```
Merge tag 'wireless-2025-07-10' of https://git.kernel.org/pub/scm/linux/kernel/git/wireless/wireless

Johannes Berg says:

====================
Quite a number of fixes still:

 - mt76 (hadn't sent any fixes so far)
   - RCU
   - scanning
   - decapsulation offload
   - interface combinations
 - rt2x00: build fix (bad function pointer prototype)
 - cfg80211: prevent A-MSDU flipping attacks in mesh
 - zd1211rw: prevent race ending with NULL ptr deref
 - cfg80211/mac80211: more S1G fixes
 - mwifiex: avoid WARN on certain RX frames
 - mac80211:
   - avoid stack data leak in WARN cases
   - fix non-transmitted BSSID search
     (on certain multi-BSSID APs)
   - always initialize key list so driver
     iteration won't crash
   - fix monitor interface in device restart
   - fix __free() annotation usage

* tag 'wireless-2025-07-10' of https://git.kernel.org/pub/scm/linux/kernel/git/wireless/wireless: (26 commits)
  wifi: mac80211: add the virtual monitor after reconfig complete
  wifi: mac80211: always initialize sdata::key_list
  wifi: mac80211: Fix uninitialized variable with __free() in ieee80211_ml_epcs()
  wifi: mt76: mt792x: Limit the concurrent STA and SoftAP to operate on the same channel
  wifi: mt76: mt7925: Fix null-ptr-deref in mt7925_thermal_init()
  wifi: mt76: fix queue assignment for deauth packets
  wifi: mt76: add a wrapper for wcid access with validation
  wifi: mt76: mt7921: prevent decap offload config before STA initialization
  wifi: mt76: mt7925: prevent NULL pointer dereference in mt7925_sta_set_decap_offload()
  wifi: mt76: mt7925: fix incorrect scan probe IE handling for hw_scan
  wifi: mt76: mt7925: fix invalid array index in ssid assignment during hw scan
  wifi: mt76: mt7925: fix the wrong config for tx interrupt
  wifi: mt76: Remove RCU section in mt7996_mac_sta_rc_work()
  wifi: mt76: Move RCU section in mt7996_mcu_add_rate_ctrl()
  wifi: mt76: Move RCU section in mt7996_mcu_add_rate_ctrl_fixed()
  wifi: mt76: Move RCU section in mt7996_mcu_set_fixed_field()
  wifi: mt76: Assume __mt76_connac_mcu_alloc_sta_req runs in atomic context
  wifi: prevent A-MSDU attacks in mesh networks
  wifi: rt2x00: fix remove callback type mismatch
  wifi: mac80211: reject VHT opmode for unsupported channel widths
  ...
====================

Link: https://patch.msgid.link/20250710122212.24272-3-johannes@sipsolutions.net
Signed-off-by: Jakub Kicinski <kuba@kernel.org>
```

**Diff:**
```diff
diff --git a/drivers/net/wireless/marvell/mwifiex/util.c b/drivers/net/wireless/marvell/mwifiex/util.c
index 4c5b1de0e936..6882e90e90b2 100644
--- a/drivers/net/wireless/marvell/mwifiex/util.c
+++ b/drivers/net/wireless/marvell/mwifiex/util.c
@@ -459,7 +459,9 @@ mwifiex_process_mgmt_packet(struct mwifiex_private *priv,
 				    "auth: receive authentication from %pM\n",
 				    ieee_hdr->addr3);
 		} else {
-			if (!priv->wdev.connected)
+			if (!priv->wdev.connected ||
+			    !ether_addr_equal(ieee_hdr->addr3,
+					      priv->curr_bss_params.bss_descriptor.mac_address))
 				return 0;
 
 			if (ieee80211_is_deauth(ieee_hdr->frame_control)) {
diff --git a/drivers/net/wireless/mediatek/mt76/mt76.h b/drivers/net/wireless/mediatek/mt76/mt76.h
index 5f8d81cda6cd..74b75035d361 100644
--- a/drivers/net/wireless/mediatek/mt76/mt76.h
+++ b/drivers/net/wireless/mediatek/mt76/mt76.h
@@ -1224,6 +1224,16 @@ static inline int mt76_wed_dma_setup(struct mt76_dev *dev, struct mt76_queue *q,
 #define mt76_dereference(p, dev) \
 	rcu_dereference_protected(p, lockdep_is_held(&(dev)->mutex))
 
+static inline struct mt76_wcid *
+__mt76_wcid_ptr(struct mt76_dev *dev, u16 idx)
+{
+	if (idx >= ARRAY_SIZE(dev->wcid))
+		return NULL;
+	return rcu_dereference(dev->wcid[idx]);
+}
+
+#define mt76_wcid_ptr(dev, idx) __mt76_wcid_ptr(&(dev)->mt76, idx)
+
 struct mt76_dev *mt76_alloc_device(struct device *pdev, unsigned int size,
 				   const struct ieee80211_ops *ops,
 				   const struct mt76_driver_ops *drv_ops);
diff --git a/drivers/net/wireless/mediatek/mt76/mt7603/dma.c b/drivers/net/wireless/mediatek/mt76/mt7603/dma.c
index 863e5770df51..e26cc78fff94 100644
--- a/drivers/net/wireless/mediatek/mt76/mt7603/dma.c
+++ b/drivers/net/wireless/mediatek/mt76/mt7603/dma.c
@@ -44,7 +44,7 @@ mt7603_rx_loopback_skb(struct mt7603_dev *dev, struct sk_buff *skb)
 	if (idx >= MT7603_WTBL_STA - 1)
 		goto free;
 
-	wcid = rcu_dereference(dev->mt76.wcid[idx]);
+	wcid = mt76_wcid_ptr(dev, idx);
 	if (!wcid)
 		goto free;
 
diff --git a/drivers/net/wireless/mediatek/mt76/mt7603/mac.c b/drivers/net/wireless/mediatek/mt76/mt7603/mac.c

... (truncated 1502 lines)
```

---

## Commit 4: 18cdb3d9

**Author:** Eric Dumazet
**Date:** 2025-07-10 17:12:28
**Files Changed:** include/net/netfilter/nf_flow_table.h

**Message:**
```
netfilter: flowtable: account for Ethernet header in nf_flow_pppoe_proto()

syzbot found a potential access to uninit-value in nf_flow_pppoe_proto()

Blamed commit forgot the Ethernet header.

BUG: KMSAN: uninit-value in nf_flow_offload_inet_hook+0x7e4/0x940 net/netfilter/nf_flow_table_inet.c:27
  nf_flow_offload_inet_hook+0x7e4/0x940 net/netfilter/nf_flow_table_inet.c:27
  nf_hook_entry_hookfn include/linux/netfilter.h:157 [inline]
  nf_hook_slow+0xe1/0x3d0 net/netfilter/core.c:623
  nf_hook_ingress include/linux/netfilter_netdev.h:34 [inline]
  nf_ingress net/core/dev.c:5742 [inline]
  __netif_receive_skb_core+0x4aff/0x70c0 net/core/dev.c:5837
  __netif_receive_skb_one_core net/core/dev.c:5975 [inline]
  __netif_receive_skb+0xcc/0xac0 net/core/dev.c:6090
  netif_receive_skb_internal net/core/dev.c:6176 [inline]
  netif_receive_skb+0x57/0x630 net/core/dev.c:6235
  tun_rx_batched+0x1df/0x980 drivers/net/tun.c:1485
  tun_get_user+0x4ee0/0x6b40 drivers/net/tun.c:1938
  tun_chr_write_iter+0x3e9/0x5c0 drivers/net/tun.c:1984
  new_sync_write fs/read_write.c:593 [inline]
  vfs_write+0xb4b/0x1580 fs/read_write.c:686
  ksys_write fs/read_write.c:738 [inline]
  __do_sys_write fs/read_write.c:749 [inline]

Reported-by: syzbot+bf6ed459397e307c3ad2@syzkaller.appspotmail.com
Closes: https://lore.kernel.org/netdev/686bc073.a00a0220.c7b3.0086.GAE@google.com/T/#u
Fixes: 87b3593bed18 ("netfilter: flowtable: validate pppoe header")
Signed-off-by: Eric Dumazet <edumazet@google.com>
Reviewed-by: Pablo Neira Ayuso <pablo@netfilter.org>
Link: https://patch.msgid.link/20250707124517.614489-1-edumazet@google.com
Signed-off-by: Jakub Kicinski <kuba@kernel.org>
```

**Diff:**
```diff
diff --git a/include/net/netfilter/nf_flow_table.h b/include/net/netfilter/nf_flow_table.h
index d711642e78b5..c003cd194fa2 100644
--- a/include/net/netfilter/nf_flow_table.h
+++ b/include/net/netfilter/nf_flow_table.h
@@ -370,7 +370,7 @@ static inline __be16 __nf_flow_pppoe_proto(const struct sk_buff *skb)
 
 static inline bool nf_flow_pppoe_proto(struct sk_buff *skb, __be16 *inner_proto)
 {
-	if (!pskb_may_pull(skb, PPPOE_SES_HLEN))
+	if (!pskb_may_pull(skb, ETH_HLEN + PPPOE_SES_HLEN))
 		return false;
 
 	*inner_proto = __nf_flow_pppoe_proto(skb);
```

---

## Commit 5: bc9ff192

**Author:** Linus Torvalds
**Date:** 2025-07-10 09:18:53
**Files Changed:** drivers/net/ethernet/airoha/airoha_eth.c, drivers/net/ethernet/broadcom/bnxt/bnxt.c, drivers/net/ethernet/broadcom/genet/bcmgenet.c, drivers/net/ethernet/cavium/thunder/nicvf_main.c, drivers/net/ethernet/renesas/rtsn.c (+24 more)

**Message:**
```
Merge tag 'net-6.16-rc6' of git://git.kernel.org/pub/scm/linux/kernel/git/netdev/net

Pull networking fixes from Paolo Abeni:
 "Including fixes from Bluetooth.

  Current release - regressions:

   - tcp: refine sk_rcvbuf increase for ooo packets

   - bluetooth: fix attempting to send HCI_Disconnect to BIS handle

   - rxrpc: fix over large frame size warning

   - eth: bcmgenet: initialize u64 stats seq counter

  Previous releases - regressions:

   - tcp: correct signedness in skb remaining space calculation

   - sched: abort __tc_modify_qdisc if parent class does not exist

   - vsock: fix transport_{g2h,h2g} TOCTOU

   - rxrpc: fix bug due to prealloc collision

   - tipc: fix use-after-free in tipc_conn_close().

   - bluetooth: fix not marking Broadcast Sink BIS as connected

   - phy: qca808x: fix WoL issue by utilizing at8031_set_wol()

   - eth: am65-cpsw-nuss: fix skb size by accounting for skb_shared_info

  Previous releases - always broken:

   - netlink: fix wraparounds of sk->sk_rmem_alloc.

   - atm: fix infinite recursive call of clip_push().

   - eth:
      - stmmac: fix interrupt handling for level-triggered mode in DWC_XGMAC2
      - rtsn: fix a null pointer dereference in rtsn_probe()"

* tag 'net-6.16-rc6' of git://git.kernel.org/pub/scm/linux/kernel/git/netdev/net: (37 commits)
  net/sched: sch_qfq: Fix null-deref in agg_dequeue
  rxrpc: Fix oops due to non-existence of prealloc backlog struct
  rxrpc: Fix bug due to prealloc collision
  MAINTAINERS: remove myself as netronome maintainer
  selftests/net: packetdrill: add tcp_ooo-before-and-after-accept.pkt
  tcp: refine sk_rcvbuf increase for ooo packets
  net/sched: Abort __tc_modify_qdisc if parent class does not exist
  net: ethernet: ti: am65-cpsw-nuss: Fix skb size by accounting for skb_shared_info
  net: thunderx: avoid direct MTU assignment after WRITE_ONCE()
  selftests/tc-testing: Create test case for UAF scenario with DRR/NETEM/BLACKHOLE chain
  atm: clip: Fix NULL pointer dereference in vcc_sendmsg()
  atm: clip: Fix infinite recursive call of clip_push().
  atm: clip: Fix memory leak of struct clip_vcc.
  atm: clip: Fix potential null-ptr-deref in to_atmarpd().
  net: phy: smsc: Fix link failure in forced mode with Auto-MDIX
  net: phy: smsc: Force predictable MDI-X state on LAN87xx
  net: phy: smsc: Fix Auto-MDIX configuration when disabled by strap
  net: stmmac: Fix interrupt handling for level-triggered mode in DWC_XGMAC2
  rxrpc: Fix over large frame size warning
  net: airoha: Fix an error handling path in airoha_probe()
  ...
```

**Diff:**
```diff
diff --git a/Documentation/devicetree/bindings/net/allwinner,sun8i-a83t-emac.yaml b/Documentation/devicetree/bindings/net/allwinner,sun8i-a83t-emac.yaml
index 7b6a2fde8175..19934d5c24e5 100644
--- a/Documentation/devicetree/bindings/net/allwinner,sun8i-a83t-emac.yaml
+++ b/Documentation/devicetree/bindings/net/allwinner,sun8i-a83t-emac.yaml
@@ -23,7 +23,7 @@ properties:
               - allwinner,sun20i-d1-emac
               - allwinner,sun50i-h6-emac
               - allwinner,sun50i-h616-emac0
-              - allwinner,sun55i-a523-emac0
+              - allwinner,sun55i-a523-gmac0
           - const: allwinner,sun50i-a64-emac
 
   reg:
diff --git a/MAINTAINERS b/MAINTAINERS
index eb7616d241b9..60eba51d8839 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -17224,10 +17224,10 @@ F:	drivers/rtc/rtc-ntxec.c
 F:	include/linux/mfd/ntxec.h
 
 NETRONOME ETHERNET DRIVERS
-M:	Louis Peens <louis.peens@corigine.com>
 R:	Jakub Kicinski <kuba@kernel.org>
+R:	Simon Horman <horms@kernel.org>
 L:	oss-drivers@corigine.com
-S:	Maintained
+S:	Odd Fixes
 F:	drivers/net/ethernet/netronome/
 
 NETWORK BLOCK DEVICE (NBD)
diff --git a/drivers/net/ethernet/airoha/airoha_eth.c b/drivers/net/ethernet/airoha/airoha_eth.c
index 06dea3a13e77..9057180051df 100644
--- a/drivers/net/ethernet/airoha/airoha_eth.c
+++ b/drivers/net/ethernet/airoha/airoha_eth.c
@@ -2984,6 +2984,7 @@ static int airoha_probe(struct platform_device *pdev)
 error_napi_stop:
 	for (i = 0; i < ARRAY_SIZE(eth->qdma); i++)
 		airoha_qdma_stop_napi(&eth->qdma[i]);
+	airoha_ppe_deinit(eth);
 error_hw_cleanup:
 	for (i = 0; i < ARRAY_SIZE(eth->qdma); i++)
 		airoha_hw_cleanup(&eth->qdma[i]);
diff --git a/drivers/net/ethernet/broadcom/bnxt/bnxt.c b/drivers/net/ethernet/broadcom/bnxt/bnxt.c
index ae89a981e052..243cb13cb01c 100644
--- a/drivers/net/ethernet/broadcom/bnxt/bnxt.c
+++ b/drivers/net/ethernet/broadcom/bnxt/bnxt.c
@@ -11607,11 +11607,9 @@ static void bnxt_free_irq(struct bnxt *bp)
 
 static int bnxt_request_irq(struct bnxt *bp)
 {

... (truncated 1230 lines)
```

---

