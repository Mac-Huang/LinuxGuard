# Linux Kernel Commit Batch Analysis

## Commit 1: c772cd72

**Author:** Lorenzo Bianconi
**Date:** 2025-07-07 17:42:20
**Files Changed:** drivers/net/wireless/mediatek/mt76/mt7996/mac.c, drivers/net/wireless/mediatek/mt76/mt7996/main.c, drivers/net/wireless/mediatek/mt76/mt7996/mcu.c, drivers/net/wireless/mediatek/mt76/mt7996/mt7996.h

**Message:**
```
wifi: mt76: Move RCU section in mt7996_mcu_set_fixed_field()

Since mt76_mcu_skb_send_msg() routine can't be executed in atomic context,
move RCU section in mt7996_mcu_set_fixed_field() and execute
mt76_mcu_skb_send_msg() in non-atomic context. This is a preliminary
patch to fix a 'sleep while atomic' issue in mt7996_mac_sta_rc_work().

Fixes: 0762bdd30279 ("wifi: mt76: mt7996: rework mt7996_mac_sta_rc_work to support MLO")
Signed-off-by: Lorenzo Bianconi <lorenzo@kernel.org>
Link: https://patch.msgid.link/20250605-mt7996-sleep-while-atomic-v1-2-d46d15f9203c@kernel.org
Signed-off-by: Felix Fietkau <nbd@nbd.name>
```

**Diff:**
```diff
diff --git a/drivers/net/wireless/mediatek/mt76/mt7996/mac.c b/drivers/net/wireless/mediatek/mt76/mt7996/mac.c
index 0dbd4662bc84..7444bd374b50 100644
--- a/drivers/net/wireless/mediatek/mt76/mt7996/mac.c
+++ b/drivers/net/wireless/mediatek/mt76/mt7996/mac.c
@@ -2405,11 +2405,10 @@ void mt7996_mac_sta_rc_work(struct work_struct *work)
 			       IEEE80211_RC_BW_CHANGED))
 			mt7996_mcu_add_rate_ctrl(dev, vif, link_conf,
 						 link_sta, link, msta_link,
-						 true);
+						 link_id, true);
 
 		if (changed & IEEE80211_RC_SMPS_CHANGED)
-			mt7996_mcu_set_fixed_field(dev, link_sta, link,
-						   msta_link, NULL,
+			mt7996_mcu_set_fixed_field(dev, msta, NULL, link_id,
 						   RATE_PARAM_MMPS_UPDATE);
 
 		spin_lock_bh(&dev->mt76.sta_poll_lock);
diff --git a/drivers/net/wireless/mediatek/mt76/mt7996/main.c b/drivers/net/wireless/mediatek/mt76/mt7996/main.c
index 78ae9f5cb176..a096b5bab001 100644
--- a/drivers/net/wireless/mediatek/mt76/mt7996/main.c
+++ b/drivers/net/wireless/mediatek/mt76/mt7996/main.c
@@ -1114,7 +1114,8 @@ mt7996_mac_sta_event(struct mt7996_dev *dev, struct ieee80211_vif *vif,
 
 			err = mt7996_mcu_add_rate_ctrl(dev, vif, link_conf,
 						       link_sta, link,
-						       msta_link, false);
+						       msta_link, link_id,
+						       false);
 			if (err)
 				return err;
 
diff --git a/drivers/net/wireless/mediatek/mt76/mt7996/mcu.c b/drivers/net/wireless/mediatek/mt76/mt7996/mcu.c
index f0adc0b4b8b6..33c61e795b73 100644
--- a/drivers/net/wireless/mediatek/mt76/mt7996/mcu.c
+++ b/drivers/net/wireless/mediatek/mt76/mt7996/mcu.c
@@ -1905,22 +1905,35 @@ int mt7996_mcu_set_fixed_rate_ctrl(struct mt7996_dev *dev,
 				     MCU_WM_UNI_CMD(RA), true);
 }
 
-int mt7996_mcu_set_fixed_field(struct mt7996_dev *dev,
-			       struct ieee80211_link_sta *link_sta,
-			       struct mt7996_vif_link *link,
-			       struct mt7996_sta_link *msta_link,
-			       void *data, u32 field)
+int mt7996_mcu_set_fixed_field(struct mt7996_dev *dev, struct mt7996_sta *msta,
+			       void *data, u8 link_id, u32 field)
 {
-	struct sta_phy_uni *phy = data;
+	struct mt7996_vif *mvif = msta->vif;

... (truncated 156 lines)
```

---

## Commit 2: d133036a

**Author:** Ben Skeggs
**Date:** 2025-07-07 16:32:44
**Files Changed:** drivers/gpu/drm/nouveau/nvkm/subdev/gsp/rm/r535/gsp.c

**Message:**
```
drm/nouveau/gsp: fix potential leak of memory used during acpi init

If any of the ACPI calls fail, memory allocated for the input buffer
would be leaked.  Fix failure paths to free allocated memory.

Also add checks to ensure the allocations succeeded in the first place.

Reported-by: Danilo Krummrich <dakr@kernel.org>
Fixes: 176fdcbddfd2 ("drm/nouveau/gsp/r535: add support for booting GSP-RM")
Signed-off-by: Ben Skeggs <bskeggs@nvidia.com>
Signed-off-by: Danilo Krummrich <dakr@kernel.org>
Link: https://lore.kernel.org/r/20250617040036.2932-1-bskeggs@nvidia.com
```

**Diff:**
```diff
diff --git a/drivers/gpu/drm/nouveau/nvkm/subdev/gsp/rm/r535/gsp.c b/drivers/gpu/drm/nouveau/nvkm/subdev/gsp/rm/r535/gsp.c
index 23f80e167705..588cb4ab85cb 100644
--- a/drivers/gpu/drm/nouveau/nvkm/subdev/gsp/rm/r535/gsp.c
+++ b/drivers/gpu/drm/nouveau/nvkm/subdev/gsp/rm/r535/gsp.c
@@ -719,7 +719,6 @@ r535_gsp_acpi_caps(acpi_handle handle, CAPS_METHOD_DATA *caps)
 	union acpi_object argv4 = {
 		.buffer.type    = ACPI_TYPE_BUFFER,
 		.buffer.length  = 4,
-		.buffer.pointer = kmalloc(argv4.buffer.length, GFP_KERNEL),
 	}, *obj;
 
 	caps->status = 0xffff;
@@ -727,17 +726,22 @@ r535_gsp_acpi_caps(acpi_handle handle, CAPS_METHOD_DATA *caps)
 	if (!acpi_check_dsm(handle, &NVOP_DSM_GUID, NVOP_DSM_REV, BIT_ULL(0x1a)))
 		return;
 
+	argv4.buffer.pointer = kmalloc(argv4.buffer.length, GFP_KERNEL);
+	if (!argv4.buffer.pointer)
+		return;
+
 	obj = acpi_evaluate_dsm(handle, &NVOP_DSM_GUID, NVOP_DSM_REV, 0x1a, &argv4);
 	if (!obj)
-		return;
+		goto done;
 
 	if (WARN_ON(obj->type != ACPI_TYPE_BUFFER) ||
 	    WARN_ON(obj->buffer.length != 4))
-		return;
+		goto done;
 
 	caps->status = 0;
 	caps->optimusCaps = *(u32 *)obj->buffer.pointer;
 
+done:
 	ACPI_FREE(obj);
 
 	kfree(argv4.buffer.pointer);
@@ -754,24 +758,28 @@ r535_gsp_acpi_jt(acpi_handle handle, JT_METHOD_DATA *jt)
 	union acpi_object argv4 = {
 		.buffer.type    = ACPI_TYPE_BUFFER,
 		.buffer.length  = sizeof(caps),
-		.buffer.pointer = kmalloc(argv4.buffer.length, GFP_KERNEL),
 	}, *obj;
 
 	jt->status = 0xffff;
 
+	argv4.buffer.pointer = kmalloc(argv4.buffer.length, GFP_KERNEL);
+	if (!argv4.buffer.pointer)
+		return;
+

... (truncated 19 lines)
```

---

## Commit 3: 85e323bd

**Author:** Baojun Xu
**Date:** 2025-07-07 11:23:28
**Files Changed:** sound/pci/hda/tas2781_hda.c

**Message:**
```
ALSA: hda/tas2781: Fix calibration data parser issue

We will copy calibration data from position behind to front.
We have created a variable (tmp_val) point on top of calibration data
buffer, and tmp_val[1] is max of node number in original calibration
data structure, it will be overwritten after first data copy,
so can't be used as max node number check in for loop.
So we create a new variable to save max of node number (tmp_val[1]),
used to check if max node number was reached in for loop.
And a point need to be increased to point at calibration data in node.
Data saved position also need to be increased one byte.

Fixes: 4fe238513407 ("ALSA: hda/tas2781: Move and unified the calibrated-data getting function for SPI and I2C into the tas2781_hda lib")
Signed-off-by: Baojun Xu <baojun.xu@ti.com>
Link: https://patch.msgid.link/20250707090513.1462-1-baojun.xu@ti.com
Signed-off-by: Takashi Iwai <tiwai@suse.de>
```

**Diff:**
```diff
diff --git a/sound/pci/hda/tas2781_hda.c b/sound/pci/hda/tas2781_hda.c
index 5f1d4b3e9688..34217ce9f28e 100644
--- a/sound/pci/hda/tas2781_hda.c
+++ b/sound/pci/hda/tas2781_hda.c
@@ -44,7 +44,7 @@ static void tas2781_apply_calib(struct tasdevice_priv *p)
 		TASDEVICE_REG(0, 0x13, 0x70),
 		TASDEVICE_REG(0, 0x18, 0x7c),
 	};
-	unsigned int crc, oft;
+	unsigned int crc, oft, node_num;
 	unsigned char *buf;
 	int i, j, k, l;
 
@@ -80,8 +80,9 @@ static void tas2781_apply_calib(struct tasdevice_priv *p)
 			dev_err(p->dev, "%s: CRC error\n", __func__);
 			return;
 		}
+		node_num = tmp_val[1];
 
-		for (j = 0, k = 0; j < tmp_val[1]; j++) {
+		for (j = 0, k = 0; j < node_num; j++) {
 			oft = j * 6 + 3;
 			if (tmp_val[oft] == TASDEV_UEFI_CALI_REG_ADDR_FLG) {
 				for (i = 0; i < TASDEV_CALIB_N; i++) {
@@ -99,8 +100,9 @@ static void tas2781_apply_calib(struct tasdevice_priv *p)
 				}
 
 				data[l] = k;
+				oft++;
 				for (i = 0; i < TASDEV_CALIB_N * 4; i++)
-					data[l + i] = data[4 * oft + i];
+					data[l + i + 1] = data[4 * oft + i];
 				k++;
 			}
 		}
```

---

## Commit 4: 737bb912

**Author:** Mathy Vanhoef
**Date:** 2025-07-07 10:54:13
**Files Changed:** net/wireless/util.c

**Message:**
```
wifi: prevent A-MSDU attacks in mesh networks

This patch is a mitigation to prevent the A-MSDU spoofing vulnerability
for mesh networks. The initial update to the IEEE 802.11 standard, in
response to the FragAttacks, missed this case (CVE-2025-27558). It can
be considered a variant of CVE-2020-24588 but for mesh networks.

This patch tries to detect if a standard MSDU was turned into an A-MSDU
by an adversary. This is done by parsing a received A-MSDU as a standard
MSDU, calculating the length of the Mesh Control header, and seeing if
the 6 bytes after this header equal the start of an rfc1042 header. If
equal, this is a strong indication of an ongoing attack attempt.

This defense was tested with mac80211_hwsim against a mesh network that
uses an empty Mesh Address Extension field, i.e., when four addresses
are used, and when using a 12-byte Mesh Address Extension field, i.e.,
when six addresses are used. Functionality of normal MSDUs and A-MSDUs
was also tested, and confirmed working, when using both an empty and
12-byte Mesh Address Extension field.

It was also tested with mac80211_hwsim that A-MSDU attacks in non-mesh
networks keep being detected and prevented.

Note that the vulnerability being patched, and the defense being
implemented, was also discussed in the following paper and in the
following IEEE 802.11 presentation:

https://papers.mathyvanhoef.com/wisec2025.pdf
https://mentor.ieee.org/802.11/dcn/25/11-25-0949-00-000m-a-msdu-mesh-spoof-protection.docx

Cc: stable@vger.kernel.org
Signed-off-by: Mathy Vanhoef <Mathy.Vanhoef@kuleuven.be>
Link: https://patch.msgid.link/20250616004635.224344-1-Mathy.Vanhoef@kuleuven.be
Signed-off-by: Johannes Berg <johannes.berg@intel.com>
```

**Diff:**
```diff
diff --git a/net/wireless/util.c b/net/wireless/util.c
index ed868c0f7ca8..1ad5a6bdfd75 100644
--- a/net/wireless/util.c
+++ b/net/wireless/util.c
@@ -820,6 +820,52 @@ bool ieee80211_is_valid_amsdu(struct sk_buff *skb, u8 mesh_hdr)
 }
 EXPORT_SYMBOL(ieee80211_is_valid_amsdu);
 
+
+/*
+ * Detects if an MSDU frame was maliciously converted into an A-MSDU
+ * frame by an adversary. This is done by parsing the received frame
+ * as if it were a regular MSDU, even though the A-MSDU flag is set.
+ *
+ * For non-mesh interfaces, detection involves checking whether the
+ * payload, when interpreted as an MSDU, begins with a valid RFC1042
+ * header. This is done by comparing the A-MSDU subheader's destination
+ * address to the start of the RFC1042 header.
+ *
+ * For mesh interfaces, the MSDU includes a 6-byte Mesh Control field
+ * and an optional variable-length Mesh Address Extension field before
+ * the RFC1042 header. The position of the RFC1042 header must therefore
+ * be calculated based on the mesh header length.
+ *
+ * Since this function intentionally parses an A-MSDU frame as an MSDU,
+ * it only assumes that the A-MSDU subframe header is present, and
+ * beyond this it performs its own bounds checks under the assumption
+ * that the frame is instead parsed as a non-aggregated MSDU.
+ */
+static bool
+is_amsdu_aggregation_attack(struct ethhdr *eth, struct sk_buff *skb,
+			    enum nl80211_iftype iftype)
+{
+	int offset;
+
+	/* Non-mesh case can be directly compared */
+	if (iftype != NL80211_IFTYPE_MESH_POINT)
+		return ether_addr_equal(eth->h_dest, rfc1042_header);
+
+	offset = __ieee80211_get_mesh_hdrlen(eth->h_dest[0]);
+	if (offset == 6) {
+		/* Mesh case with empty address extension field */
+		return ether_addr_equal(eth->h_source, rfc1042_header);
+	} else if (offset + ETH_ALEN <= skb->len) {
+		/* Mesh case with non-empty address extension field */
+		u8 temp[ETH_ALEN];
+
+		skb_copy_bits(skb, offset, temp, ETH_ALEN);
+		return ether_addr_equal(temp, rfc1042_header);
+	}

... (truncated 20 lines)
```

---

## Commit 5: c5fd399a

**Author:** Lachlan Hodges
**Date:** 2025-07-07 10:42:15
**Files Changed:** include/linux/ieee80211.h, net/mac80211/mlme.c

**Message:**
```
wifi: mac80211: correctly identify S1G short beacon

mac80211 identifies a short beacon by the presence of the next
TBTT field, however the standard actually doesn't explicitly state that
the next TBTT can't be in a long beacon or even that it is required in
a short beacon - and as a result this validation does not work for all
vendor implementations.

The standard explicitly states that an S1G long beacon shall contain
the S1G beacon compatibility element as the first element in a beacon
transmitted at a TBTT that is not a TSBTT (Target Short Beacon
Transmission Time) as per IEEE80211-2024 11.1.3.10.1. This is validated
by 9.3.4.3 Table 9-76 which states that the S1G beacon compatibility
element is only allowed in the full set and is not allowed in the
minimum set of elements permitted for use within short beacons.

Correctly identify short beacons by the lack of an S1G beacon
compatibility element as the first element in an S1G beacon frame.

Fixes: 9eaffe5078ca ("cfg80211: convert S1G beacon to scan results")
Signed-off-by: Simon Wadsworth <simon@morsemicro.com>
Signed-off-by: Lachlan Hodges <lachlan.hodges@morsemicro.com>
Link: https://patch.msgid.link/20250701075541.162619-1-lachlan.hodges@morsemicro.com
Signed-off-by: Johannes Berg <johannes.berg@intel.com>
```

**Diff:**
```diff
diff --git a/include/linux/ieee80211.h b/include/linux/ieee80211.h
index 22f39e5e2ff1..996be3c2cff0 100644
--- a/include/linux/ieee80211.h
+++ b/include/linux/ieee80211.h
@@ -662,18 +662,6 @@ static inline bool ieee80211_s1g_has_cssid(__le16 fc)
 		(fc & cpu_to_le16(IEEE80211_S1G_BCN_CSSID));
 }
 
-/**
- * ieee80211_is_s1g_short_beacon - check if frame is an S1G short beacon
- * @fc: frame control bytes in little-endian byteorder
- * Return: whether or not the frame is an S1G short beacon,
- *	i.e. it is an S1G beacon with 'next TBTT' flag set
- */
-static inline bool ieee80211_is_s1g_short_beacon(__le16 fc)
-{
-	return ieee80211_is_s1g_beacon(fc) &&
-		(fc & cpu_to_le16(IEEE80211_S1G_BCN_NEXT_TBTT));
-}
-
 /**
  * ieee80211_is_atim - check if IEEE80211_FTYPE_MGMT && IEEE80211_STYPE_ATIM
  * @fc: frame control bytes in little-endian byteorder
@@ -4901,6 +4889,39 @@ static inline bool ieee80211_is_ftm(struct sk_buff *skb)
 	return false;
 }
 
+/**
+ * ieee80211_is_s1g_short_beacon - check if frame is an S1G short beacon
+ * @fc: frame control bytes in little-endian byteorder
+ * @variable: pointer to the beacon frame elements
+ * @variable_len: length of the frame elements
+ * Return: whether or not the frame is an S1G short beacon. As per
+ *	IEEE80211-2024 11.1.3.10.1, The S1G beacon compatibility element shall
+ *	always be present as the first element in beacon frames generated at a
+ *	TBTT (Target Beacon Transmission Time), so any frame not containing
+ *	this element must have been generated at a TSBTT (Target Short Beacon
+ *	Transmission Time) that is not a TBTT. Additionally, short beacons are
+ *	prohibited from containing the S1G beacon compatibility element as per
+ *	IEEE80211-2024 9.3.4.3 Table 9-76, so if we have an S1G beacon with
+ *	either no elements or the first element is not the beacon compatibility
+ *	element, we have a short beacon.
+ */
+static inline bool ieee80211_is_s1g_short_beacon(__le16 fc, const u8 *variable,
+						 size_t variable_len)
+{
+	if (!ieee80211_is_s1g_beacon(fc))
+		return false;
+
+	/*

... (truncated 45 lines)
```

---

