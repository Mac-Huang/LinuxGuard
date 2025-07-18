# Linux Kernel Commit Batch Analysis

## Commit 1: aa955243

**Author:** Zheng Qixing
**Date:** 2025-07-07 11:58:08
**Files Changed:** drivers/block/nbd.c

**Message:**
```
nbd: fix uaf in nbd_genl_connect() error path

There is a use-after-free issue in nbd:

block nbd6: Receive control failed (result -104)
block nbd6: shutting down sockets
==================================================================
BUG: KASAN: slab-use-after-free in recv_work+0x694/0xa80 drivers/block/nbd.c:1022
Write of size 4 at addr ffff8880295de478 by task kworker/u33:0/67

CPU: 2 UID: 0 PID: 67 Comm: kworker/u33:0 Not tainted 6.15.0-rc5-syzkaller-00123-g2c89c1b655c0 #0 PREEMPT(full)
Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.16.3-debian-1.16.3-2~bpo12+1 04/01/2014
Workqueue: nbd6-recv recv_work
Call Trace:
 <TASK>
 __dump_stack lib/dump_stack.c:94 [inline]
 dump_stack_lvl+0x116/0x1f0 lib/dump_stack.c:120
 print_address_description mm/kasan/report.c:408 [inline]
 print_report+0xc3/0x670 mm/kasan/report.c:521
 kasan_report+0xe0/0x110 mm/kasan/report.c:634
 check_region_inline mm/kasan/generic.c:183 [inline]
 kasan_check_range+0xef/0x1a0 mm/kasan/generic.c:189
 instrument_atomic_read_write include/linux/instrumented.h:96 [inline]
 atomic_dec include/linux/atomic/atomic-instrumented.h:592 [inline]
 recv_work+0x694/0xa80 drivers/block/nbd.c:1022
 process_one_work+0x9cc/0x1b70 kernel/workqueue.c:3238
 process_scheduled_works kernel/workqueue.c:3319 [inline]
 worker_thread+0x6c8/0xf10 kernel/workqueue.c:3400
 kthread+0x3c2/0x780 kernel/kthread.c:464
 ret_from_fork+0x45/0x80 arch/x86/kernel/process.c:153
 ret_from_fork_asm+0x1a/0x30 arch/x86/entry/entry_64.S:245
 </TASK>

nbd_genl_connect() does not properly stop the device on certain
error paths after nbd_start_device() has been called. This causes
the error path to put nbd->config while recv_work continue to use
the config after putting it, leading to use-after-free in recv_work.

This patch moves nbd_start_device() after the backend file creation.

Reported-by: syzbot+48240bab47e705c53126@syzkaller.appspotmail.com
Closes: https://lore.kernel.org/all/68227a04.050a0220.f2294.00b5.GAE@google.com/T/
Fixes: 6497ef8df568 ("nbd: provide a way for userspace processes to identify device backends")
Signed-off-by: Zheng Qixing <zhengqixing@huawei.com>
Reviewed-by: Yu Kuai <yukuai3@huawei.com>
Link: https://lore.kernel.org/r/20250612132405.364904-1-zhengqixing@huaweicloud.com
Signed-off-by: Jens Axboe <axboe@kernel.dk>
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
```

---

## Commit 2: 03ee8f73

**Author:** Henry Martin
**Date:** 2025-07-07 18:05:52
**Files Changed:** drivers/net/wireless/mediatek/mt76/mt7925/init.c

**Message:**
```
wifi: mt76: mt7925: Fix null-ptr-deref in mt7925_thermal_init()

devm_kasprintf() returns NULL on error. Currently, mt7925_thermal_init()
does not check for this case, which results in a NULL pointer
dereference.

Add NULL check after devm_kasprintf() to prevent this issue.

Fixes: 396e41a74a88 ("wifi: mt76: mt7925: support temperature sensor")
Signed-off-by: Henry Martin <bsdhenryma@tencent.com>
Reviewed-by: AngeloGioacchino Del Regno <angelogioacchino.delregno@collabora.com>
Link: https://patch.msgid.link/20250625124901.1839832-1-bsdhenryma@tencent.com
Signed-off-by: Felix Fietkau <nbd@nbd.name>
```

**Diff:**
```diff
diff --git a/drivers/net/wireless/mediatek/mt76/mt7925/init.c b/drivers/net/wireless/mediatek/mt76/mt7925/init.c
index 2a83ff59a968..4249bad83c93 100644
--- a/drivers/net/wireless/mediatek/mt76/mt7925/init.c
+++ b/drivers/net/wireless/mediatek/mt76/mt7925/init.c
@@ -52,6 +52,8 @@ static int mt7925_thermal_init(struct mt792x_phy *phy)
 
 	name = devm_kasprintf(&wiphy->dev, GFP_KERNEL, "mt7925_%s",
 			      wiphy_name(wiphy));
+	if (!name)
+		return -ENOMEM;
 
 	hwmon = devm_hwmon_device_register_with_groups(&wiphy->dev, name, phy,
 						       mt7925_hwmon_groups);
```

---

## Commit 3: 35ad47c0

**Author:** Deren Wu
**Date:** 2025-07-07 17:42:20
**Files Changed:** drivers/net/wireless/mediatek/mt76/mt7925/main.c

**Message:**
```
wifi: mt76: mt7925: prevent NULL pointer dereference in mt7925_sta_set_decap_offload()

Add a NULL check for msta->vif before accessing its members to prevent
a kernel panic in AP mode deployment. This also fix the issue reported
in [1].

The crash occurs when this function is triggered before the station is
fully initialized. The call trace shows a page fault at
mt7925_sta_set_decap_offload() due to accessing resources when msta->vif
is NULL.

Fix this by adding an early return if msta->vif is NULL and also check
wcid.sta is ready. This ensures we only proceed with decap offload
configuration when the station's state is properly initialized.

[14739.655703] Unable to handle kernel paging request at virtual address ffffffffffffffa0
[14739.811820] CPU: 0 UID: 0 PID: 895854 Comm: hostapd Tainted: G
[14739.821394] Tainted: [C]=CRAP, [O]=OOT_MODULE
[14739.825746] Hardware name: Raspberry Pi 4 Model B Rev 1.1 (DT)
[14739.831577] pstate: 60000005 (nZCv daif -PAN -UAO -TCO -DIT -SSBS BTYPE=--)
[14739.838538] pc : mt7925_sta_set_decap_offload+0xc0/0x1b8 [mt7925_common]
[14739.845271] lr : mt7925_sta_set_decap_offload+0x58/0x1b8 [mt7925_common]
[14739.851985] sp : ffffffc085efb500
[14739.855295] x29: ffffffc085efb500 x28: 0000000000000000 x27: ffffff807803a158
[14739.862436] x26: ffffff8041ececb8 x25: 0000000000000001 x24: 0000000000000001
[14739.869577] x23: 0000000000000001 x22: 0000000000000008 x21: ffffff8041ecea88
[14739.876715] x20: ffffff8041c19ca0 x19: ffffff8078031fe0 x18: 0000000000000000
[14739.883853] x17: 0000000000000000 x16: ffffffe2aeac1110 x15: 000000559da48080
[14739.890991] x14: 0000000000000001 x13: 0000000000000000 x12: 0000000000000000
[14739.898130] x11: 0a10020001008e88 x10: 0000000000001a50 x9 : ffffffe26457bfa0
[14739.905269] x8 : ffffff8042013bb0 x7 : ffffff807fb6cbf8 x6 : dead000000000100
[14739.912407] x5 : dead000000000122 x4 : ffffff80780326c8 x3 : 0000000000000000
[14739.919546] x2 : 0000000000000000 x1 : 0000000000000000 x0 : ffffff8041ececb8
[14739.926686] Call trace:
[14739.929130]  mt7925_sta_set_decap_offload+0xc0/0x1b8 [mt7925_common]
[14739.935505]  ieee80211_check_fast_rx+0x19c/0x510 [mac80211]
[14739.941344]  _sta_info_move_state+0xe4/0x510 [mac80211]
[14739.946860]  sta_info_move_state+0x1c/0x30 [mac80211]
[14739.952116]  sta_apply_auth_flags.constprop.0+0x90/0x1b0 [mac80211]
[14739.958708]  sta_apply_parameters+0x234/0x5e0 [mac80211]
[14739.964332]  ieee80211_add_station+0xdc/0x190 [mac80211]
[14739.969950]  nl80211_new_station+0x46c/0x670 [cfg80211]
[14739.975516]  genl_family_rcv_msg_doit+0xdc/0x150
[14739.980158]  genl_rcv_msg+0x218/0x298
[14739.983830]  netlink_rcv_skb+0x64/0x138
[14739.987670]  genl_rcv+0x40/0x60
[14739.990816]  netlink_unicast+0x314/0x380
[14739.994742]  netlink_sendmsg+0x198/0x3f0
[14739.998664]  __sock_sendmsg+0x64/0xc0
[14740.002324]  ____sys_sendmsg+0x260/0x298
[14740.006242]  ___sys_sendmsg+0xb4/0x110

Cc: stable@vger.kernel.org
Link: https://github.com/morrownr/USB-WiFi/issues/603 [1]
Fixes: b859ad65309a ("wifi: mt76: mt7925: add link handling in mt7925_sta_set_decap_offload")
Signed-off-by: Deren Wu <deren.wu@mediatek.com>
Link: https://patch.msgid.link/35aedbffa050e98939264300407a52ba4e236d52.1748149855.git.deren.wu@mediatek.com
Signed-off-by: Felix Fietkau <nbd@nbd.name>
```

**Diff:**
```diff
diff --git a/drivers/net/wireless/mediatek/mt76/mt7925/main.c b/drivers/net/wireless/mediatek/mt76/mt7925/main.c
index f0f1b1e4d507..5b001548dffc 100644
--- a/drivers/net/wireless/mediatek/mt76/mt7925/main.c
+++ b/drivers/net/wireless/mediatek/mt76/mt7925/main.c
@@ -1603,6 +1603,9 @@ static void mt7925_sta_set_decap_offload(struct ieee80211_hw *hw,
 	unsigned long valid = mvif->valid_links;
 	u8 i;
 
+	if (!msta->vif)
+		return;
+
 	mt792x_mutex_acquire(dev);
 
 	valid = ieee80211_vif_is_mld(vif) ? mvif->valid_links : BIT(0);
@@ -1617,6 +1620,9 @@ static void mt7925_sta_set_decap_offload(struct ieee80211_hw *hw,
 		else
 			clear_bit(MT_WCID_FLAG_HDR_TRANS, &mlink->wcid.flags);
 
+		if (!mlink->wcid.sta)
+			continue;
+
 		mt7925_mcu_wtbl_update_hdr_trans(dev, vif, sta, i);
 	}
 
```

---

## Commit 4: 3dd6f67c

**Author:** Lorenzo Bianconi
**Date:** 2025-07-07 17:42:20
**Files Changed:** drivers/net/wireless/mediatek/mt76/mt7996/mac.c, drivers/net/wireless/mediatek/mt76/mt7996/main.c, drivers/net/wireless/mediatek/mt76/mt7996/mcu.c, drivers/net/wireless/mediatek/mt76/mt7996/mt7996.h

**Message:**
```
wifi: mt76: Move RCU section in mt7996_mcu_add_rate_ctrl()

Since mt76_mcu_skb_send_msg() routine can't be executed in atomic context,
move RCU section in mt7996_mcu_add_rate_ctrl() and execute
mt76_mcu_skb_send_msg() in non-atomic context. This is a preliminary
patch to fix a 'sleep while atomic' issue in mt7996_mac_sta_rc_work().

Fixes: 0762bdd30279 ("wifi: mt76: mt7996: rework mt7996_mac_sta_rc_work to support MLO")
Signed-off-by: Lorenzo Bianconi <lorenzo@kernel.org>
Link: https://patch.msgid.link/20250605-mt7996-sleep-while-atomic-v1-4-d46d15f9203c@kernel.org
Signed-off-by: Felix Fietkau <nbd@nbd.name>
```

**Diff:**
```diff
diff --git a/drivers/net/wireless/mediatek/mt76/mt7996/mac.c b/drivers/net/wireless/mediatek/mt76/mt7996/mac.c
index 7444bd374b50..329dc9edc80d 100644
--- a/drivers/net/wireless/mediatek/mt76/mt7996/mac.c
+++ b/drivers/net/wireless/mediatek/mt76/mt7996/mac.c
@@ -2356,7 +2356,6 @@ void mt7996_mac_sta_rc_work(struct work_struct *work)
 	struct ieee80211_bss_conf *link_conf;
 	struct ieee80211_link_sta *link_sta;
 	struct mt7996_sta_link *msta_link;
-	struct mt7996_vif_link *link;
 	struct mt76_vif_link *mlink;
 	struct ieee80211_sta *sta;
 	struct ieee80211_vif *vif;
@@ -2398,13 +2397,10 @@ void mt7996_mac_sta_rc_work(struct work_struct *work)
 
 		spin_unlock_bh(&dev->mt76.sta_poll_lock);
 
-		link = (struct mt7996_vif_link *)mlink;
-
 		if (changed & (IEEE80211_RC_SUPP_RATES_CHANGED |
 			       IEEE80211_RC_NSS_CHANGED |
 			       IEEE80211_RC_BW_CHANGED))
-			mt7996_mcu_add_rate_ctrl(dev, vif, link_conf,
-						 link_sta, link, msta_link,
+			mt7996_mcu_add_rate_ctrl(dev, msta_link->sta, vif,
 						 link_id, true);
 
 		if (changed & IEEE80211_RC_SMPS_CHANGED)
diff --git a/drivers/net/wireless/mediatek/mt76/mt7996/main.c b/drivers/net/wireless/mediatek/mt76/mt7996/main.c
index a096b5bab001..07dd75ce94a5 100644
--- a/drivers/net/wireless/mediatek/mt76/mt7996/main.c
+++ b/drivers/net/wireless/mediatek/mt76/mt7996/main.c
@@ -1112,10 +1112,8 @@ mt7996_mac_sta_event(struct mt7996_dev *dev, struct ieee80211_vif *vif,
 			if (err)
 				return err;
 
-			err = mt7996_mcu_add_rate_ctrl(dev, vif, link_conf,
-						       link_sta, link,
-						       msta_link, link_id,
-						       false);
+			err = mt7996_mcu_add_rate_ctrl(dev, msta_link->sta, vif,
+						       link_id, false);
 			if (err)
 				return err;
 
diff --git a/drivers/net/wireless/mediatek/mt76/mt7996/mcu.c b/drivers/net/wireless/mediatek/mt76/mt7996/mcu.c
index 742497ba2a6b..77ab1f4854a4 100644
--- a/drivers/net/wireless/mediatek/mt76/mt7996/mcu.c
+++ b/drivers/net/wireless/mediatek/mt76/mt7996/mcu.c
@@ -2201,23 +2201,44 @@ mt7996_mcu_sta_rate_ctrl_tlv(struct sk_buff *skb, struct mt7996_dev *dev,
 	memset(ra->rx_rcpi, INIT_RCPI, sizeof(ra->rx_rcpi));

... (truncated 95 lines)
```

---

## Commit 5: 28d519d0

**Author:** Lorenzo Bianconi
**Date:** 2025-07-07 17:42:20
**Files Changed:** drivers/net/wireless/mediatek/mt76/mt7996/mcu.c

**Message:**
```
wifi: mt76: Move RCU section in mt7996_mcu_add_rate_ctrl_fixed()

Since mt7996_mcu_set_fixed_field() can't be executed in a RCU critical
section, move RCU section in mt7996_mcu_add_rate_ctrl_fixed() and run
mt7996_mcu_set_fixed_field() in non-atomic context. This is a
preliminary patch to fix a 'sleep while atomic' issue in
mt7996_mac_sta_rc_work().

Fixes: 0762bdd30279 ("wifi: mt76: mt7996: rework mt7996_mac_sta_rc_work to support MLO")
Signed-off-by: Lorenzo Bianconi <lorenzo@kernel.org>
Link: https://patch.msgid.link/20250605-mt7996-sleep-while-atomic-v1-3-d46d15f9203c@kernel.org
Signed-off-by: Felix Fietkau <nbd@nbd.name>
```

**Diff:**
```diff
diff --git a/drivers/net/wireless/mediatek/mt76/mt7996/mcu.c b/drivers/net/wireless/mediatek/mt76/mt7996/mcu.c
index 33c61e795b73..742497ba2a6b 100644
--- a/drivers/net/wireless/mediatek/mt76/mt7996/mcu.c
+++ b/drivers/net/wireless/mediatek/mt76/mt7996/mcu.c
@@ -1977,51 +1977,74 @@ int mt7996_mcu_set_fixed_field(struct mt7996_dev *dev, struct mt7996_sta *msta,
 }
 
 static int
-mt7996_mcu_add_rate_ctrl_fixed(struct mt7996_dev *dev,
-			       struct ieee80211_link_sta *link_sta,
-			       struct mt7996_vif_link *link,
-			       struct mt7996_sta_link *msta_link,
-			       u8 link_id)
+mt7996_mcu_add_rate_ctrl_fixed(struct mt7996_dev *dev, struct mt7996_sta *msta,
+			       struct ieee80211_vif *vif, u8 link_id)
 {
-	struct cfg80211_chan_def *chandef = &link->phy->mt76->chandef;
-	struct cfg80211_bitrate_mask *mask = &link->bitrate_mask;
-	enum nl80211_band band = chandef->chan->band;
-	struct mt7996_sta *msta = msta_link->sta;
+	struct ieee80211_link_sta *link_sta;
+	struct cfg80211_bitrate_mask mask;
+	struct mt7996_sta_link *msta_link;
+	struct mt7996_vif_link *link;
 	struct sta_phy_uni phy = {};
-	int ret, nrates = 0;
+	struct ieee80211_sta *sta;
+	int ret, nrates = 0, idx;
+	enum nl80211_band band;
+	bool has_he;
 
 #define __sta_phy_bitrate_mask_check(_mcs, _gi, _ht, _he)			\
 	do {									\
-		u8 i, gi = mask->control[band]._gi;				\
+		u8 i, gi = mask.control[band]._gi;				\
 		gi = (_he) ? gi : gi == NL80211_TXRATE_FORCE_SGI;		\
 		phy.sgi = gi;							\
-		phy.he_ltf = mask->control[band].he_ltf;			\
-		for (i = 0; i < ARRAY_SIZE(mask->control[band]._mcs); i++) {	\
-			if (!mask->control[band]._mcs[i])			\
+		phy.he_ltf = mask.control[band].he_ltf;				\
+		for (i = 0; i < ARRAY_SIZE(mask.control[band]._mcs); i++) {	\
+			if (!mask.control[band]._mcs[i])			\
 				continue;					\
-			nrates += hweight16(mask->control[band]._mcs[i]);	\
-			phy.mcs = ffs(mask->control[band]._mcs[i]) - 1;		\
+			nrates += hweight16(mask.control[band]._mcs[i]);	\
+			phy.mcs = ffs(mask.control[band]._mcs[i]) - 1;		\
 			if (_ht)						\
 				phy.mcs += 8 * i;				\

... (truncated 111 lines)
```

---

