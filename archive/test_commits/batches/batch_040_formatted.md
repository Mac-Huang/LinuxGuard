# Linux Kernel Commit Batch Analysis

## Commit 1: ff21a6ec

**Author:** Jack Yu
**Date:** 2025-06-24 13:55:18
**Files Changed:** sound/soc/codecs/rt721-sdca.c

**Message:**
```
ASoC: rt721-sdca: fix boost gain calculation error

Fix the boost gain calculation error in rt721_sdca_set_gain_get.
This patch is specific for "FU33 Boost Volume".

Signed-off-by: Jack Yu <jack.yu@realtek.com>
Link: https://patch.msgid.link/1b18fcde41c64d6fa85451d523c0434a@realtek.com
Signed-off-by: Mark Brown <broonie@kernel.org>
```

**Diff:**
```diff
diff --git a/sound/soc/codecs/rt721-sdca.c b/sound/soc/codecs/rt721-sdca.c
index 1c9f32e405cf..ba080957e933 100644
--- a/sound/soc/codecs/rt721-sdca.c
+++ b/sound/soc/codecs/rt721-sdca.c
@@ -430,6 +430,7 @@ static int rt721_sdca_set_gain_get(struct snd_kcontrol *kcontrol,
 	unsigned int read_l, read_r, ctl_l = 0, ctl_r = 0;
 	unsigned int adc_vol_flag = 0;
 	const unsigned int interval_offset = 0xc0;
+	const unsigned int tendA = 0x200;
 	const unsigned int tendB = 0xa00;
 
 	if (strstr(ucontrol->id.name, "FU1E Capture Volume") ||
@@ -439,9 +440,16 @@ static int rt721_sdca_set_gain_get(struct snd_kcontrol *kcontrol,
 	regmap_read(rt721->mbq_regmap, mc->reg, &read_l);
 	regmap_read(rt721->mbq_regmap, mc->rreg, &read_r);
 
-	if (mc->shift == 8) /* boost gain */
+	if (mc->shift == 8) {
+		/* boost gain */
 		ctl_l = read_l / tendB;
-	else {
+	} else if (mc->shift == 1) {
+		/* FU33 boost gain */
+		if (read_l == 0x8000 || read_l == 0xfe00)
+			ctl_l = 0;
+		else
+			ctl_l = read_l / tendA + 1;
+	} else {
 		if (adc_vol_flag)
 			ctl_l = mc->max - (((0x1e00 - read_l) & 0xffff) / interval_offset);
 		else
@@ -449,9 +457,16 @@ static int rt721_sdca_set_gain_get(struct snd_kcontrol *kcontrol,
 	}
 
 	if (read_l != read_r) {
-		if (mc->shift == 8) /* boost gain */
+		if (mc->shift == 8) {
+			/* boost gain */
 			ctl_r = read_r / tendB;
-		else { /* ADC/DAC gain */
+		} else if (mc->shift == 1) {
+			/* FU33 boost gain */
+			if (read_r == 0x8000 || read_r == 0xfe00)
+				ctl_r = 0;
+			else
+				ctl_r = read_r / tendA + 1;
+		} else { /* ADC/DAC gain */
 			if (adc_vol_flag)
 				ctl_r = mc->max - (((0x1e00 - read_r) & 0xffff) / interval_offset);
 			else
```

---

## Commit 2: 1fd26729

**Author:** Paolo Abeni
**Date:** 2025-06-24 12:40:54
**Files Changed:** drivers/bluetooth/btintel_pcie.c, drivers/bluetooth/hci_qca.c, include/net/bluetooth/hci_core.h, net/bluetooth/hci_core.c, net/bluetooth/l2cap_core.c

**Message:**
```
Merge tag 'for-net-2025-06-23' of git://git.kernel.org/pub/scm/linux/kernel/git/bluetooth/bluetooth

Luiz Augusto von Dentz says:

====================
bluetooth pull request for net:

 - L2CAP: Fix L2CAP MTU negotiation
 - hci_core: Fix use-after-free in vhci_flush()
 - btintel_pcie: Fix potential race condition in firmware download
 - hci_qca: fix unable to load the BT driver

* tag 'for-net-2025-06-23' of git://git.kernel.org/pub/scm/linux/kernel/git/bluetooth/bluetooth:
  Bluetooth: hci_core: Fix use-after-free in vhci_flush()
  driver: bluetooth: hci_qca:fix unable to load the BT driver
  Bluetooth: L2CAP: Fix L2CAP MTU negotiation
  Bluetooth: btintel_pcie: Fix potential race condition in firmware download
====================

Link: https://patch.msgid.link/20250623165405.227619-1-luiz.dentz@gmail.com
Signed-off-by: Paolo Abeni <pabeni@redhat.com>
```

**Diff:**
```diff
diff --git a/drivers/bluetooth/btintel_pcie.c b/drivers/bluetooth/btintel_pcie.c
index 563165c5efae..e1c688dd2d45 100644
--- a/drivers/bluetooth/btintel_pcie.c
+++ b/drivers/bluetooth/btintel_pcie.c
@@ -2033,6 +2033,28 @@ static void btintel_pcie_release_hdev(struct btintel_pcie_data *data)
 	data->hdev = NULL;
 }
 
+static void btintel_pcie_disable_interrupts(struct btintel_pcie_data *data)
+{
+	spin_lock(&data->irq_lock);
+	btintel_pcie_wr_reg32(data, BTINTEL_PCIE_CSR_MSIX_FH_INT_MASK, data->fh_init_mask);
+	btintel_pcie_wr_reg32(data, BTINTEL_PCIE_CSR_MSIX_HW_INT_MASK, data->hw_init_mask);
+	spin_unlock(&data->irq_lock);
+}
+
+static void btintel_pcie_enable_interrupts(struct btintel_pcie_data *data)
+{
+	spin_lock(&data->irq_lock);
+	btintel_pcie_wr_reg32(data, BTINTEL_PCIE_CSR_MSIX_FH_INT_MASK, ~data->fh_init_mask);
+	btintel_pcie_wr_reg32(data, BTINTEL_PCIE_CSR_MSIX_HW_INT_MASK, ~data->hw_init_mask);
+	spin_unlock(&data->irq_lock);
+}
+
+static void btintel_pcie_synchronize_irqs(struct btintel_pcie_data *data)
+{
+	for (int i = 0; i < data->alloc_vecs; i++)
+		synchronize_irq(data->msix_entries[i].vector);
+}
+
 static int btintel_pcie_setup_internal(struct hci_dev *hdev)
 {
 	struct btintel_pcie_data *data = hci_get_drvdata(hdev);
@@ -2152,6 +2174,8 @@ static int btintel_pcie_setup(struct hci_dev *hdev)
 		bt_dev_err(hdev, "Firmware download retry count: %d",
 			   fw_dl_retry);
 		btintel_pcie_dump_debug_registers(hdev);
+		btintel_pcie_disable_interrupts(data);
+		btintel_pcie_synchronize_irqs(data);
 		err = btintel_pcie_reset_bt(data);
 		if (err) {
 			bt_dev_err(hdev, "Failed to do shr reset: %d", err);
@@ -2159,6 +2183,7 @@ static int btintel_pcie_setup(struct hci_dev *hdev)
 		}
 		usleep_range(10000, 12000);
 		btintel_pcie_reset_ia(data);
+		btintel_pcie_enable_interrupts(data);
 		btintel_pcie_config_msix(data);
 		err = btintel_pcie_enable_bt(data);
 		if (err) {

... (truncated 182 lines)
```

---

## Commit 3: b272f425

**Author:** Harshit Mogalapalli
**Date:** 2025-06-24 10:11:02
**Files Changed:** sound/usb/qcom/qc_audio_offload.c

**Message:**
```
ALSA: qc_audio_offload: Fix missing error code in prepare_qmi_response()

When snd_soc_usb_find_priv_data() fails, return failure instead of
success. While we are at it also use direct returns at first few error
paths where there is no additional cleanup needed.

Reported-by: Dan Carpenter <dan.carpenter@linaro.org>
Closes: https://lore.kernel.org/all/Z_40qL4JnyjR4j0O@stanley.mountain/
Fixes: 326bbc348298 ("ALSA: usb-audio: qcom: Introduce QC USB SND offloading support")
Signed-off-by: Harshit Mogalapalli <harshit.m.mogalapalli@oracle.com>
Link: https://patch.msgid.link/20250623142639.2938056-1-harshit.m.mogalapalli@oracle.com
Signed-off-by: Takashi Iwai <tiwai@suse.de>
```

**Diff:**
```diff
diff --git a/sound/usb/qcom/qc_audio_offload.c b/sound/usb/qcom/qc_audio_offload.c
index 5bc27c82e0af..797afd4561bd 100644
--- a/sound/usb/qcom/qc_audio_offload.c
+++ b/sound/usb/qcom/qc_audio_offload.c
@@ -1360,20 +1360,21 @@ static int prepare_qmi_response(struct snd_usb_substream *subs,
 
 	if (!uadev[card_num].ctrl_intf) {
 		dev_err(&subs->dev->dev, "audio ctrl intf info not cached\n");
-		ret = -ENODEV;
-		goto err;
+		return -ENODEV;
 	}
 
 	ret = uaudio_populate_uac_desc(subs, resp);
 	if (ret < 0)
-		goto err;
+		return ret;
 
 	resp->slot_id = subs->dev->slot_id;
 	resp->slot_id_valid = 1;
 
 	data = snd_soc_usb_find_priv_data(uaudio_qdev->auxdev->dev.parent);
-	if (!data)
-		goto err;
+	if (!data) {
+		dev_err(&subs->dev->dev, "No private data found\n");
+		return -ENODEV;
+	}
 
 	uaudio_qdev->data = data;
 
@@ -1382,7 +1383,7 @@ static int prepare_qmi_response(struct snd_usb_substream *subs,
 				    &resp->xhci_mem_info.tr_data,
 				    &resp->std_as_data_ep_desc);
 	if (ret < 0)
-		goto err;
+		return ret;
 
 	resp->std_as_data_ep_desc_valid = 1;
 
@@ -1500,7 +1501,6 @@ static int prepare_qmi_response(struct snd_usb_substream *subs,
 	xhci_sideband_remove_endpoint(uadev[card_num].sb,
 			usb_pipe_endpoint(subs->dev, subs->data_endpoint->pipe));
 
-err:
 	return ret;
 }
 
```

---

## Commit 4: 32ca2454

**Author:** Kuniyuki Iwashima
**Date:** 2025-06-24 10:10:06
**Files Changed:** net/unix/af_unix.c

**Message:**
```
af_unix: Don't leave consecutive consumed OOB skbs.

Jann Horn reported a use-after-free in unix_stream_read_generic().

The following sequences reproduce the issue:

  $ python3
  from socket import *
  s1, s2 = socketpair(AF_UNIX, SOCK_STREAM)
  s1.send(b'x', MSG_OOB)
  s2.recv(1, MSG_OOB)     # leave a consumed OOB skb
  s1.send(b'y', MSG_OOB)
  s2.recv(1, MSG_OOB)     # leave a consumed OOB skb
  s1.send(b'z', MSG_OOB)
  s2.recv(1)              # recv 'z' illegally
  s2.recv(1, MSG_OOB)     # access 'z' skb (use-after-free)

Even though a user reads OOB data, the skb holding the data stays on
the recv queue to mark the OOB boundary and break the next recv().

After the last send() in the scenario above, the sk2's recv queue has
2 leading consumed OOB skbs and 1 real OOB skb.

Then, the following happens during the next recv() without MSG_OOB

  1. unix_stream_read_generic() peeks the first consumed OOB skb
  2. manage_oob() returns the next consumed OOB skb
  3. unix_stream_read_generic() fetches the next not-yet-consumed OOB skb
  4. unix_stream_read_generic() reads and frees the OOB skb

, and the last recv(MSG_OOB) triggers KASAN splat.

The 3. above occurs because of the SO_PEEK_OFF code, which does not
expect unix_skb_len(skb) to be 0, but this is true for such consumed
OOB skbs.

  while (skip >= unix_skb_len(skb)) {
    skip -= unix_skb_len(skb);
    skb = skb_peek_next(skb, &sk->sk_receive_queue);
    ...
  }

In addition to this use-after-free, there is another issue that
ioctl(SIOCATMARK) does not function properly with consecutive consumed
OOB skbs.

So, nothing good comes out of such a situation.

Instead of complicating manage_oob(), ioctl() handling, and the next
ECONNRESET fix by introducing a loop for consecutive consumed OOB skbs,
let's not leave such consecutive OOB unnecessarily.

Now, while receiving an OOB skb in unix_stream_recv_urg(), if its
previous skb is a consumed OOB skb, it is freed.

[0]:
BUG: KASAN: slab-use-after-free in unix_stream_read_actor (net/unix/af_unix.c:3027)
Read of size 4 at addr ffff888106ef2904 by task python3/315

CPU: 2 UID: 0 PID: 315 Comm: python3 Not tainted 6.16.0-rc1-00407-gec315832f6f9 #8 PREEMPT(voluntary)
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.3-4.fc42 04/01/2014
Call Trace:
 <TASK>
 dump_stack_lvl (lib/dump_stack.c:122)
 print_report (mm/kasan/report.c:409 mm/kasan/report.c:521)
 kasan_report (mm/kasan/report.c:636)
 unix_stream_read_actor (net/unix/af_unix.c:3027)
 unix_stream_read_generic (net/unix/af_unix.c:2708 net/unix/af_unix.c:2847)
 unix_stream_recvmsg (net/unix/af_unix.c:3048)
 sock_recvmsg (net/socket.c:1063 (discriminator 20) net/socket.c:1085 (discriminator 20))
 __sys_recvfrom (net/socket.c:2278)
 __x64_sys_recvfrom (net/socket.c:2291 (discriminator 1) net/socket.c:2287 (discriminator 1) net/socket.c:2287 (discriminator 1))
 do_syscall_64 (arch/x86/entry/syscall_64.c:63 (discriminator 1) arch/x86/entry/syscall_64.c:94 (discriminator 1))
 entry_SYSCALL_64_after_hwframe (arch/x86/entry/entry_64.S:130)
RIP: 0033:0x7f8911fcea06
Code: 5d e8 41 8b 93 08 03 00 00 59 5e 48 83 f8 fc 75 19 83 e2 39 83 fa 08 75 11 e8 26 ff ff ff 66 0f 1f 44 00 00 48 8b 45 10 0f 05 <48> 8b 5d f8 c9 c3 0f 1f 40 00 f3 0f 1e fa 55 48 89 e5 48 83 ec 08
RSP: 002b:00007fffdb0dccb0 EFLAGS: 00000202 ORIG_RAX: 000000000000002d
RAX: ffffffffffffffda RBX: 00007fffdb0dcdc8 RCX: 00007f8911fcea06
RDX: 0000000000000001 RSI: 00007f8911a5e060 RDI: 0000000000000006
RBP: 00007fffdb0dccd0 R08: 0000000000000000 R09: 0000000000000000
R10: 0000000000000001 R11: 0000000000000202 R12: 00007f89119a7d20
R13: ffffffffc4653600 R14: 0000000000000000 R15: 0000000000000000
 </TASK>

Allocated by task 315:
 kasan_save_stack (mm/kasan/common.c:48)
 kasan_save_track (mm/kasan/common.c:60 (discriminator 1) mm/kasan/common.c:69 (discriminator 1))
 __kasan_slab_alloc (mm/kasan/common.c:348)
 kmem_cache_alloc_node_noprof (./include/linux/kasan.h:250 mm/slub.c:4148 mm/slub.c:4197 mm/slub.c:4249)
 __alloc_skb (net/core/skbuff.c:660 (discriminator 4))
 alloc_skb_with_frags (./include/linux/skbuff.h:1336 net/core/skbuff.c:6668)
 sock_alloc_send_pskb (net/core/sock.c:2993)
 unix_stream_sendmsg (./include/net/sock.h:1847 net/unix/af_unix.c:2256 net/unix/af_unix.c:2418)
 __sys_sendto (net/socket.c:712 (discriminator 20) net/socket.c:727 (discriminator 20) net/socket.c:2226 (discriminator 20))
 __x64_sys_sendto (net/socket.c:2233 (discriminator 1) net/socket.c:2229 (discriminator 1) net/socket.c:2229 (discriminator 1))
 do_syscall_64 (arch/x86/entry/syscall_64.c:63 (discriminator 1) arch/x86/entry/syscall_64.c:94 (discriminator 1))
 entry_SYSCALL_64_after_hwframe (arch/x86/entry/entry_64.S:130)

Freed by task 315:
 kasan_save_stack (mm/kasan/common.c:48)
 kasan_save_track (mm/kasan/common.c:60 (discriminator 1) mm/kasan/common.c:69 (discriminator 1))
 kasan_save_free_info (mm/kasan/generic.c:579 (discriminator 1))
 __kasan_slab_free (mm/kasan/common.c:271)
 kmem_cache_free (mm/slub.c:4643 (discriminator 3) mm/slub.c:4745 (discriminator 3))
 unix_stream_read_generic (net/unix/af_unix.c:3010)
 unix_stream_recvmsg (net/unix/af_unix.c:3048)
 sock_recvmsg (net/socket.c:1063 (discriminator 20) net/socket.c:1085 (discriminator 20))
 __sys_recvfrom (net/socket.c:2278)
 __x64_sys_recvfrom (net/socket.c:2291 (discriminator 1) net/socket.c:2287 (discriminator 1) net/socket.c:2287 (discriminator 1))
 do_syscall_64 (arch/x86/entry/syscall_64.c:63 (discriminator 1) arch/x86/entry/syscall_64.c:94 (discriminator 1))
 entry_SYSCALL_64_after_hwframe (arch/x86/entry/entry_64.S:130)

The buggy address belongs to the object at ffff888106ef28c0
 which belongs to the cache skbuff_head_cache of size 224
The buggy address is located 68 bytes inside of
 freed 224-byte region [ffff888106ef28c0, ffff888106ef29a0)

The buggy address belongs to the physical page:
page: refcount:0 mapcount:0 mapping:0000000000000000 index:0xffff888106ef3cc0 pfn:0x106ef2
head: order:1 mapcount:0 entire_mapcount:0 nr_pages_mapped:0 pincount:0
flags: 0x200000000000040(head|node=0|zone=2)
page_type: f5(slab)
raw: 0200000000000040 ffff8881001d28c0 ffffea000422fe00 0000000000000004
raw: ffff888106ef3cc0 0000000080190010 00000000f5000000 0000000000000000
head: 0200000000000040 ffff8881001d28c0 ffffea000422fe00 0000000000000004
head: ffff888106ef3cc0 0000000080190010 00000000f5000000 0000000000000000
head: 0200000000000001 ffffea00041bbc81 00000000ffffffff 00000000ffffffff
head: 0000000000000000 0000000000000000 00000000ffffffff 0000000000000000
page dumped because: kasan: bad access detected

Memory state around the buggy address:
 ffff888106ef2800: 00 00 00 00 00 00 00 00 00 00 00 00 fc fc fc fc
 ffff888106ef2880: fc fc fc fc fc fc fc fc fa fb fb fb fb fb fb fb
>ffff888106ef2900: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
                   ^
 ffff888106ef2980: fb fb fb fb fc fc fc fc fc fc fc fc fc fc fc fc
 ffff888106ef2a00: fa fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb

Fixes: 314001f0bf92 ("af_unix: Add OOB support")
Reported-by: Jann Horn <jannh@google.com>
Signed-off-by: Kuniyuki Iwashima <kuniyu@google.com>
Reviewed-by: Jann Horn <jannh@google.com>
Link: https://patch.msgid.link/20250619041457.1132791-2-kuni1840@gmail.com
Signed-off-by: Paolo Abeni <pabeni@redhat.com>
```

**Diff:**
```diff
diff --git a/net/unix/af_unix.c b/net/unix/af_unix.c
index 22e170fb5dda..5392aa53cbc8 100644
--- a/net/unix/af_unix.c
+++ b/net/unix/af_unix.c
@@ -2680,11 +2680,11 @@ struct unix_stream_read_state {
 #if IS_ENABLED(CONFIG_AF_UNIX_OOB)
 static int unix_stream_recv_urg(struct unix_stream_read_state *state)
 {
+	struct sk_buff *oob_skb, *read_skb = NULL;
 	struct socket *sock = state->socket;
 	struct sock *sk = sock->sk;
 	struct unix_sock *u = unix_sk(sk);
 	int chunk = 1;
-	struct sk_buff *oob_skb;
 
 	mutex_lock(&u->iolock);
 	unix_state_lock(sk);
@@ -2699,9 +2699,16 @@ static int unix_stream_recv_urg(struct unix_stream_read_state *state)
 
 	oob_skb = u->oob_skb;
 
-	if (!(state->flags & MSG_PEEK))
+	if (!(state->flags & MSG_PEEK)) {
 		WRITE_ONCE(u->oob_skb, NULL);
 
+		if (oob_skb->prev != (struct sk_buff *)&sk->sk_receive_queue &&
+		    !unix_skb_len(oob_skb->prev)) {
+			read_skb = oob_skb->prev;
+			__skb_unlink(read_skb, &sk->sk_receive_queue);
+		}
+	}
+
 	spin_unlock(&sk->sk_receive_queue.lock);
 	unix_state_unlock(sk);
 
@@ -2712,6 +2719,8 @@ static int unix_stream_recv_urg(struct unix_stream_read_state *state)
 
 	mutex_unlock(&u->iolock);
 
+	consume_skb(read_skb);
+
 	if (chunk < 0)
 		return -EFAULT;
 
```

---

## Commit 5: 7a3750ff

**Author:** Lachlan Hodges
**Date:** 2025-06-24 09:04:55
**Files Changed:** net/mac80211/util.c

**Message:**
```
wifi: mac80211: fix beacon interval calculation overflow

As we are converting from TU to usecs, a beacon interval of
100*1024 usecs will lead to integer wrapping. To fix change
to use a u32.

Fixes: 057d5f4ba1e4 ("mac80211: sync dtim_count to TSF")
Signed-off-by: Lachlan Hodges <lachlan.hodges@morsemicro.com>
Link: https://patch.msgid.link/20250621123209.511796-1-lachlan.hodges@morsemicro.com
Signed-off-by: Johannes Berg <johannes.berg@intel.com>
```

**Diff:**
```diff
diff --git a/net/mac80211/util.c b/net/mac80211/util.c
index 27d414efa3fd..a125995ed252 100644
--- a/net/mac80211/util.c
+++ b/net/mac80211/util.c
@@ -3884,7 +3884,7 @@ void ieee80211_recalc_dtim(struct ieee80211_local *local,
 {
 	u64 tsf = drv_get_tsf(local, sdata);
 	u64 dtim_count = 0;
-	u16 beacon_int = sdata->vif.bss_conf.beacon_int * 1024;
+	u32 beacon_int = sdata->vif.bss_conf.beacon_int * 1024;
 	u8 dtim_period = sdata->vif.bss_conf.dtim_period;
 	struct ps_data *ps;
 	u8 bcns_from_dtim;
```

---

