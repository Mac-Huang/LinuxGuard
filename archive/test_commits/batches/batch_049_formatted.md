# Linux Kernel Commit Batch Analysis

## Commit 1: d03b79f4

**Author:** Eric Dumazet
**Date:** 2025-06-19 08:36:31
**Files Changed:** net/atm/lec.c

**Message:**
```
net: atm: fix /proc/net/atm/lec handling

/proc/net/atm/lec must ensure safety against dev_lec[] changes.

It appears it had dev_put() calls without prior dev_hold(),
leading to imbalance and UAF.

Fixes: 1da177e4c3f4 ("Linux-2.6.12-rc2")
Signed-off-by: Eric Dumazet <edumazet@google.com>
Acked-by: Francois Romieu <romieu@fr.zoreil.com> # Minor atm contributor
Link: https://patch.msgid.link/20250618140844.1686882-3-edumazet@google.com
Signed-off-by: Jakub Kicinski <kuba@kernel.org>
```

**Diff:**
```diff
diff --git a/net/atm/lec.c b/net/atm/lec.c
index 1e1f3eb0e2ba..afb8d3eb2185 100644
--- a/net/atm/lec.c
+++ b/net/atm/lec.c
@@ -909,7 +909,6 @@ static void *lec_itf_walk(struct lec_state *state, loff_t *l)
 	v = (dev && netdev_priv(dev)) ?
 		lec_priv_walk(state, l, netdev_priv(dev)) : NULL;
 	if (!v && dev) {
-		dev_put(dev);
 		/* Partial state reset for the next time we get called */
 		dev = NULL;
 	}
@@ -933,6 +932,7 @@ static void *lec_seq_start(struct seq_file *seq, loff_t *pos)
 {
 	struct lec_state *state = seq->private;
 
+	mutex_lock(&lec_mutex);
 	state->itf = 0;
 	state->dev = NULL;
 	state->locked = NULL;
@@ -950,8 +950,9 @@ static void lec_seq_stop(struct seq_file *seq, void *v)
 	if (state->dev) {
 		spin_unlock_irqrestore(&state->locked->lec_arp_lock,
 				       state->flags);
-		dev_put(state->dev);
+		state->dev = NULL;
 	}
+	mutex_unlock(&lec_mutex);
 }
 
 static void *lec_seq_next(struct seq_file *seq, void *v, loff_t *pos)
```

---

## Commit 2: d13a3824

**Author:** Eric Dumazet
**Date:** 2025-06-19 08:36:13
**Files Changed:** net/atm/lec.c

**Message:**
```
net: atm: add lec_mutex

syzbot found its way in net/atm/lec.c, and found an error path
in lecd_attach() could leave a dangling pointer in dev_lec[].

Add a mutex to protect dev_lecp[] uses from lecd_attach(),
lec_vcc_attach() and lec_mcast_attach().

Following patch will use this mutex for /proc/net/atm/lec.

BUG: KASAN: slab-use-after-free in lecd_attach net/atm/lec.c:751 [inline]
BUG: KASAN: slab-use-after-free in lane_ioctl+0x2224/0x23e0 net/atm/lec.c:1008
Read of size 8 at addr ffff88807c7b8e68 by task syz.1.17/6142

CPU: 1 UID: 0 PID: 6142 Comm: syz.1.17 Not tainted 6.16.0-rc1-syzkaller-00239-g08215f5486ec #0 PREEMPT(full)
Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 05/07/2025
Call Trace:
 <TASK>
  __dump_stack lib/dump_stack.c:94 [inline]
  dump_stack_lvl+0x116/0x1f0 lib/dump_stack.c:120
  print_address_description mm/kasan/report.c:408 [inline]
  print_report+0xcd/0x680 mm/kasan/report.c:521
  kasan_report+0xe0/0x110 mm/kasan/report.c:634
  lecd_attach net/atm/lec.c:751 [inline]
  lane_ioctl+0x2224/0x23e0 net/atm/lec.c:1008
  do_vcc_ioctl+0x12c/0x930 net/atm/ioctl.c:159
  sock_do_ioctl+0x118/0x280 net/socket.c:1190
  sock_ioctl+0x227/0x6b0 net/socket.c:1311
  vfs_ioctl fs/ioctl.c:51 [inline]
  __do_sys_ioctl fs/ioctl.c:907 [inline]
  __se_sys_ioctl fs/ioctl.c:893 [inline]
  __x64_sys_ioctl+0x18e/0x210 fs/ioctl.c:893
  do_syscall_x64 arch/x86/entry/syscall_64.c:63 [inline]
  do_syscall_64+0xcd/0x4c0 arch/x86/entry/syscall_64.c:94
 entry_SYSCALL_64_after_hwframe+0x77/0x7f
 </TASK>

Allocated by task 6132:
  kasan_save_stack+0x33/0x60 mm/kasan/common.c:47
  kasan_save_track+0x14/0x30 mm/kasan/common.c:68
  poison_kmalloc_redzone mm/kasan/common.c:377 [inline]
  __kasan_kmalloc+0xaa/0xb0 mm/kasan/common.c:394
  kasan_kmalloc include/linux/kasan.h:260 [inline]
  __do_kmalloc_node mm/slub.c:4328 [inline]
  __kvmalloc_node_noprof+0x27b/0x620 mm/slub.c:5015
  alloc_netdev_mqs+0xd2/0x1570 net/core/dev.c:11711
  lecd_attach net/atm/lec.c:737 [inline]
  lane_ioctl+0x17db/0x23e0 net/atm/lec.c:1008
  do_vcc_ioctl+0x12c/0x930 net/atm/ioctl.c:159
  sock_do_ioctl+0x118/0x280 net/socket.c:1190
  sock_ioctl+0x227/0x6b0 net/socket.c:1311
  vfs_ioctl fs/ioctl.c:51 [inline]
  __do_sys_ioctl fs/ioctl.c:907 [inline]
  __se_sys_ioctl fs/ioctl.c:893 [inline]
  __x64_sys_ioctl+0x18e/0x210 fs/ioctl.c:893
  do_syscall_x64 arch/x86/entry/syscall_64.c:63 [inline]
  do_syscall_64+0xcd/0x4c0 arch/x86/entry/syscall_64.c:94
 entry_SYSCALL_64_after_hwframe+0x77/0x7f

Freed by task 6132:
  kasan_save_stack+0x33/0x60 mm/kasan/common.c:47
  kasan_save_track+0x14/0x30 mm/kasan/common.c:68
  kasan_save_free_info+0x3b/0x60 mm/kasan/generic.c:576
  poison_slab_object mm/kasan/common.c:247 [inline]
  __kasan_slab_free+0x51/0x70 mm/kasan/common.c:264
  kasan_slab_free include/linux/kasan.h:233 [inline]
  slab_free_hook mm/slub.c:2381 [inline]
  slab_free mm/slub.c:4643 [inline]
  kfree+0x2b4/0x4d0 mm/slub.c:4842
  free_netdev+0x6c5/0x910 net/core/dev.c:11892
  lecd_attach net/atm/lec.c:744 [inline]
  lane_ioctl+0x1ce8/0x23e0 net/atm/lec.c:1008
  do_vcc_ioctl+0x12c/0x930 net/atm/ioctl.c:159
  sock_do_ioctl+0x118/0x280 net/socket.c:1190
  sock_ioctl+0x227/0x6b0 net/socket.c:1311
  vfs_ioctl fs/ioctl.c:51 [inline]
  __do_sys_ioctl fs/ioctl.c:907 [inline]
  __se_sys_ioctl fs/ioctl.c:893 [inline]
  __x64_sys_ioctl+0x18e/0x210 fs/ioctl.c:893

Fixes: 1da177e4c3f4 ("Linux-2.6.12-rc2")
Reported-by: syzbot+8b64dec3affaed7b3af5@syzkaller.appspotmail.com
Closes: https://lore.kernel.org/netdev/6852c6f6.050a0220.216029.0018.GAE@google.com/T/#u
Signed-off-by: Eric Dumazet <edumazet@google.com>
Link: https://patch.msgid.link/20250618140844.1686882-2-edumazet@google.com
Signed-off-by: Jakub Kicinski <kuba@kernel.org>
```

**Diff:**
```diff
diff --git a/net/atm/lec.c b/net/atm/lec.c
index acef984f3367..1e1f3eb0e2ba 100644
--- a/net/atm/lec.c
+++ b/net/atm/lec.c
@@ -124,6 +124,7 @@ static unsigned char bus_mac[ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
 
 /* Device structures */
 static struct net_device *dev_lec[MAX_LEC_ITF];
+static DEFINE_MUTEX(lec_mutex);
 
 #if IS_ENABLED(CONFIG_BRIDGE)
 static void lec_handle_bridge(struct sk_buff *skb, struct net_device *dev)
@@ -685,6 +686,7 @@ static int lec_vcc_attach(struct atm_vcc *vcc, void __user *arg)
 	int bytes_left;
 	struct atmlec_ioc ioc_data;
 
+	lockdep_assert_held(&lec_mutex);
 	/* Lecd must be up in this case */
 	bytes_left = copy_from_user(&ioc_data, arg, sizeof(struct atmlec_ioc));
 	if (bytes_left != 0)
@@ -710,6 +712,7 @@ static int lec_vcc_attach(struct atm_vcc *vcc, void __user *arg)
 
 static int lec_mcast_attach(struct atm_vcc *vcc, int arg)
 {
+	lockdep_assert_held(&lec_mutex);
 	if (arg < 0 || arg >= MAX_LEC_ITF)
 		return -EINVAL;
 	arg = array_index_nospec(arg, MAX_LEC_ITF);
@@ -725,6 +728,7 @@ static int lecd_attach(struct atm_vcc *vcc, int arg)
 	int i;
 	struct lec_priv *priv;
 
+	lockdep_assert_held(&lec_mutex);
 	if (arg < 0)
 		arg = 0;
 	if (arg >= MAX_LEC_ITF)
@@ -742,6 +746,7 @@ static int lecd_attach(struct atm_vcc *vcc, int arg)
 		snprintf(dev_lec[i]->name, IFNAMSIZ, "lec%d", i);
 		if (register_netdev(dev_lec[i])) {
 			free_netdev(dev_lec[i]);
+			dev_lec[i] = NULL;
 			return -EINVAL;
 		}
 
@@ -1003,6 +1008,7 @@ static int lane_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
 		return -ENOIOCTLCMD;
 	}
 
+	mutex_lock(&lec_mutex);
 	switch (cmd) {

... (truncated 10 lines)
```

---

## Commit 3: a55bc4ff

**Author:** Nathan Chancellor
**Date:** 2025-06-19 17:33:43
**Files Changed:** drivers/staging/rtl8723bs/core/rtw_security.c

**Message:**
```
staging: rtl8723bs: Avoid memset() in aes_cipher() and aes_decipher()

After commit 6f110a5e4f99 ("Disable SLUB_TINY for build testing"), which
causes CONFIG_KASAN to be enabled in allmodconfig again, arm64
allmodconfig builds with older versions of clang (15 through 17) show an
instance of -Wframe-larger-than (which breaks the build with
CONFIG_WERROR=y):

  drivers/staging/rtl8723bs/core/rtw_security.c:1287:5: error: stack frame size (2208) exceeds limit (2048) in 'rtw_aes_decrypt' [-Werror,-Wframe-larger-than]
   1287 | u32 rtw_aes_decrypt(struct adapter *padapter, u8 *precvframe)
        |     ^

This comes from aes_decipher() being inlined in rtw_aes_decrypt().
Running the same build with CONFIG_FRAME_WARN=128 shows aes_cipher()
also uses a decent amount of stack, just under the limit of 2048:

  drivers/staging/rtl8723bs/core/rtw_security.c:864:19: warning: stack frame size (1952) exceeds limit (128) in 'aes_cipher' [-Wframe-larger-than]
    864 | static signed int aes_cipher(u8 *key, uint      hdrlen,
        |                   ^

-Rpass-analysis=stack-frame-layout only shows one large structure on the
stack, which is the ctx variable inlined from aes128k128d(). A good
number of the other variables come from the additional checks of
fortified string routines, which are present in memset(), which both
aes_cipher() and aes_decipher() use to initialize some temporary
buffers. In this case, since the size is known at compile time, these
additional checks should not result in any code generation changes but
allmodconfig has several sanitizers enabled, which may make it harder
for the compiler to eliminate the compile time checks and the variables
that come about from them.

The memset() calls are just initializing these buffers to zero, so use
'= {}' instead, which is used all over the kernel and does the exact
same thing as memset() without the fortify checks, which drops the stack
usage of these functions by a few hundred kilobytes.

  drivers/staging/rtl8723bs/core/rtw_security.c:864:19: warning: stack frame size (1584) exceeds limit (128) in 'aes_cipher' [-Wframe-larger-than]
    864 | static signed int aes_cipher(u8 *key, uint      hdrlen,
        |                   ^
  drivers/staging/rtl8723bs/core/rtw_security.c:1271:5: warning: stack frame size (1456) exceeds limit (128) in 'rtw_aes_decrypt' [-Wframe-larger-than]
   1271 | u32 rtw_aes_decrypt(struct adapter *padapter, u8 *precvframe)
        |     ^

Cc: stable@vger.kernel.org
Fixes: 554c0a3abf21 ("staging: Add rtl8723bs sdio wifi driver")
Signed-off-by: Nathan Chancellor <nathan@kernel.org>
Reviewed-by: Dan Carpenter <dan.carpenter@linaro.org>
Link: https://lore.kernel.org/r/20250609-rtl8723bs-fix-clang-arm64-wflt-v1-1-e2accba43def@kernel.org
Signed-off-by: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
```

**Diff:**
```diff
diff --git a/drivers/staging/rtl8723bs/core/rtw_security.c b/drivers/staging/rtl8723bs/core/rtw_security.c
index 1e9eff01b1aa..e9f382c280d9 100644
--- a/drivers/staging/rtl8723bs/core/rtw_security.c
+++ b/drivers/staging/rtl8723bs/core/rtw_security.c
@@ -868,29 +868,21 @@ static signed int aes_cipher(u8 *key, uint	hdrlen,
 		num_blocks, payload_index;
 
 	u8 pn_vector[6];
-	u8 mic_iv[16];
-	u8 mic_header1[16];
-	u8 mic_header2[16];
-	u8 ctr_preload[16];
+	u8 mic_iv[16] = {};
+	u8 mic_header1[16] = {};
+	u8 mic_header2[16] = {};
+	u8 ctr_preload[16] = {};
 
 	/* Intermediate Buffers */
-	u8 chain_buffer[16];
-	u8 aes_out[16];
-	u8 padded_buffer[16];
+	u8 chain_buffer[16] = {};
+	u8 aes_out[16] = {};
+	u8 padded_buffer[16] = {};
 	u8 mic[8];
 	uint	frtype  = GetFrameType(pframe);
 	uint	frsubtype  = GetFrameSubType(pframe);
 
 	frsubtype = frsubtype>>4;
 
-	memset((void *)mic_iv, 0, 16);
-	memset((void *)mic_header1, 0, 16);
-	memset((void *)mic_header2, 0, 16);
-	memset((void *)ctr_preload, 0, 16);
-	memset((void *)chain_buffer, 0, 16);
-	memset((void *)aes_out, 0, 16);
-	memset((void *)padded_buffer, 0, 16);
-
 	if ((hdrlen == WLAN_HDR_A3_LEN) || (hdrlen ==  WLAN_HDR_A3_QOS_LEN))
 		a4_exists = 0;
 	else
@@ -1080,15 +1072,15 @@ static signed int aes_decipher(u8 *key, uint	hdrlen,
 			num_blocks, payload_index;
 	signed int res = _SUCCESS;
 	u8 pn_vector[6];
-	u8 mic_iv[16];
-	u8 mic_header1[16];
-	u8 mic_header2[16];
-	u8 ctr_preload[16];
+	u8 mic_iv[16] = {};

... (truncated 29 lines)
```

---

## Commit 4: 10876da9

**Author:** Kuniyuki Iwashima
**Date:** 2025-06-19 08:33:09
**Files Changed:** net/ipv6/calipso.c

**Message:**
```
calipso: Fix null-ptr-deref in calipso_req_{set,del}attr().

syzkaller reported a null-ptr-deref in sock_omalloc() while allocating
a CALIPSO option.  [0]

The NULL is of struct sock, which was fetched by sk_to_full_sk() in
calipso_req_setattr().

Since commit a1a5344ddbe8 ("tcp: avoid two atomic ops for syncookies"),
reqsk->rsk_listener could be NULL when SYN Cookie is returned to its
client, as hinted by the leading SYN Cookie log.

Here are 3 options to fix the bug:

  1) Return 0 in calipso_req_setattr()
  2) Return an error in calipso_req_setattr()
  3) Alaways set rsk_listener

1) is no go as it bypasses LSM, but 2) effectively disables SYN Cookie
for CALIPSO.  3) is also no go as there have been many efforts to reduce
atomic ops and make TCP robust against DDoS.  See also commit 3b24d854cb35
("tcp/dccp: do not touch listener sk_refcnt under synflood").

As of the blamed commit, SYN Cookie already did not need refcounting,
and no one has stumbled on the bug for 9 years, so no CALIPSO user will
care about SYN Cookie.

Let's return an error in calipso_req_setattr() and calipso_req_delattr()
in the SYN Cookie case.

This can be reproduced by [1] on Fedora and now connect() of nc times out.

[0]:
TCP: request_sock_TCPv6: Possible SYN flooding on port [::]:20002. Sending cookies.
Oops: general protection fault, probably for non-canonical address 0xdffffc0000000006: 0000 [#1] PREEMPT SMP KASAN NOPTI
KASAN: null-ptr-deref in range [0x0000000000000030-0x0000000000000037]
CPU: 3 UID: 0 PID: 12262 Comm: syz.1.2611 Not tainted 6.14.0 #2
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.16.3-0-ga6ed6b701f0a-prebuilt.qemu.org 04/01/2014
RIP: 0010:read_pnet include/net/net_namespace.h:406 [inline]
RIP: 0010:sock_net include/net/sock.h:655 [inline]
RIP: 0010:sock_kmalloc+0x35/0x170 net/core/sock.c:2806
Code: 89 d5 41 54 55 89 f5 53 48 89 fb e8 25 e3 c6 fd e8 f0 91 e3 00 48 8d 7b 30 48 b8 00 00 00 00 00 fc ff df 48 89 fa 48 c1 ea 03 <80> 3c 02 00 0f 85 26 01 00 00 48 b8 00 00 00 00 00 fc ff df 4c 8b
RSP: 0018:ffff88811af89038 EFLAGS: 00010216
RAX: dffffc0000000000 RBX: 0000000000000000 RCX: ffff888105266400
RDX: 0000000000000006 RSI: ffff88800c890000 RDI: 0000000000000030
RBP: 0000000000000050 R08: 0000000000000000 R09: ffff88810526640e
R10: ffffed1020a4cc81 R11: ffff88810526640f R12: 0000000000000000
R13: 0000000000000820 R14: ffff888105266400 R15: 0000000000000050
FS:  00007f0653a07640(0000) GS:ffff88811af80000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 00007f863ba096f4 CR3: 00000000163c0005 CR4: 0000000000770ef0
PKRU: 80000000
Call Trace:
 <IRQ>
 ipv6_renew_options+0x279/0x950 net/ipv6/exthdrs.c:1288
 calipso_req_setattr+0x181/0x340 net/ipv6/calipso.c:1204
 calipso_req_setattr+0x56/0x80 net/netlabel/netlabel_calipso.c:597
 netlbl_req_setattr+0x18a/0x440 net/netlabel/netlabel_kapi.c:1249
 selinux_netlbl_inet_conn_request+0x1fb/0x320 security/selinux/netlabel.c:342
 selinux_inet_conn_request+0x1eb/0x2c0 security/selinux/hooks.c:5551
 security_inet_conn_request+0x50/0xa0 security/security.c:4945
 tcp_v6_route_req+0x22c/0x550 net/ipv6/tcp_ipv6.c:825
 tcp_conn_request+0xec8/0x2b70 net/ipv4/tcp_input.c:7275
 tcp_v6_conn_request+0x1e3/0x440 net/ipv6/tcp_ipv6.c:1328
 tcp_rcv_state_process+0xafa/0x52b0 net/ipv4/tcp_input.c:6781
 tcp_v6_do_rcv+0x8a6/0x1a40 net/ipv6/tcp_ipv6.c:1667
 tcp_v6_rcv+0x505e/0x5b50 net/ipv6/tcp_ipv6.c:1904
 ip6_protocol_deliver_rcu+0x17c/0x1da0 net/ipv6/ip6_input.c:436
 ip6_input_finish+0x103/0x180 net/ipv6/ip6_input.c:480
 NF_HOOK include/linux/netfilter.h:314 [inline]
 NF_HOOK include/linux/netfilter.h:308 [inline]
 ip6_input+0x13c/0x6b0 net/ipv6/ip6_input.c:491
 dst_input include/net/dst.h:469 [inline]
 ip6_rcv_finish net/ipv6/ip6_input.c:79 [inline]
 ip6_rcv_finish+0xb6/0x490 net/ipv6/ip6_input.c:69
 NF_HOOK include/linux/netfilter.h:314 [inline]
 NF_HOOK include/linux/netfilter.h:308 [inline]
 ipv6_rcv+0xf9/0x490 net/ipv6/ip6_input.c:309
 __netif_receive_skb_one_core+0x12e/0x1f0 net/core/dev.c:5896
 __netif_receive_skb+0x1d/0x170 net/core/dev.c:6009
 process_backlog+0x41e/0x13b0 net/core/dev.c:6357
 __napi_poll+0xbd/0x710 net/core/dev.c:7191
 napi_poll net/core/dev.c:7260 [inline]
 net_rx_action+0x9de/0xde0 net/core/dev.c:7382
 handle_softirqs+0x19a/0x770 kernel/softirq.c:561
 do_softirq.part.0+0x36/0x70 kernel/softirq.c:462
 </IRQ>
 <TASK>
 do_softirq arch/x86/include/asm/preempt.h:26 [inline]
 __local_bh_enable_ip+0xf1/0x110 kernel/softirq.c:389
 local_bh_enable include/linux/bottom_half.h:33 [inline]
 rcu_read_unlock_bh include/linux/rcupdate.h:919 [inline]
 __dev_queue_xmit+0xc2a/0x3c40 net/core/dev.c:4679
 dev_queue_xmit include/linux/netdevice.h:3313 [inline]
 neigh_hh_output include/net/neighbour.h:523 [inline]
 neigh_output include/net/neighbour.h:537 [inline]
 ip6_finish_output2+0xd69/0x1f80 net/ipv6/ip6_output.c:141
 __ip6_finish_output net/ipv6/ip6_output.c:215 [inline]
 ip6_finish_output+0x5dc/0xd60 net/ipv6/ip6_output.c:226
 NF_HOOK_COND include/linux/netfilter.h:303 [inline]
 ip6_output+0x24b/0x8d0 net/ipv6/ip6_output.c:247
 dst_output include/net/dst.h:459 [inline]
 NF_HOOK include/linux/netfilter.h:314 [inline]
 NF_HOOK include/linux/netfilter.h:308 [inline]
 ip6_xmit+0xbbc/0x20d0 net/ipv6/ip6_output.c:366
 inet6_csk_xmit+0x39a/0x720 net/ipv6/inet6_connection_sock.c:135
 __tcp_transmit_skb+0x1a7b/0x3b40 net/ipv4/tcp_output.c:1471
 tcp_transmit_skb net/ipv4/tcp_output.c:1489 [inline]
 tcp_send_syn_data net/ipv4/tcp_output.c:4059 [inline]
 tcp_connect+0x1c0c/0x4510 net/ipv4/tcp_output.c:4148
 tcp_v6_connect+0x156c/0x2080 net/ipv6/tcp_ipv6.c:333
 __inet_stream_connect+0x3a7/0xed0 net/ipv4/af_inet.c:677
 tcp_sendmsg_fastopen+0x3e2/0x710 net/ipv4/tcp.c:1039
 tcp_sendmsg_locked+0x1e82/0x3570 net/ipv4/tcp.c:1091
 tcp_sendmsg+0x2f/0x50 net/ipv4/tcp.c:1358
 inet6_sendmsg+0xb9/0x150 net/ipv6/af_inet6.c:659
 sock_sendmsg_nosec net/socket.c:718 [inline]
 __sock_sendmsg+0xf4/0x2a0 net/socket.c:733
 __sys_sendto+0x29a/0x390 net/socket.c:2187
 __do_sys_sendto net/socket.c:2194 [inline]
 __se_sys_sendto net/socket.c:2190 [inline]
 __x64_sys_sendto+0xe1/0x1c0 net/socket.c:2190
 do_syscall_x64 arch/x86/entry/common.c:52 [inline]
 do_syscall_64+0xc3/0x1d0 arch/x86/entry/common.c:83
 entry_SYSCALL_64_after_hwframe+0x77/0x7f
RIP: 0033:0x7f06553c47ed
Code: 02 b8 ff ff ff ff c3 66 0f 1f 44 00 00 f3 0f 1e fa 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 c7 c1 a8 ff ff ff f7 d8 64 89 01 48
RSP: 002b:00007f0653a06fc8 EFLAGS: 00000246 ORIG_RAX: 000000000000002c
RAX: ffffffffffffffda RBX: 00007f0655605fa0 RCX: 00007f06553c47ed
RDX: 0000000000000000 RSI: 0000000000000000 RDI: 000000000000000b
RBP: 00007f065545db38 R08: 0000200000000140 R09: 000000000000001c
R10: f7384d4ea84b01bd R11: 0000000000000246 R12: 0000000000000000
R13: 00007f0655605fac R14: 00007f0655606038 R15: 00007f06539e7000
 </TASK>
Modules linked in:

[1]:
dnf install -y selinux-policy-targeted policycoreutils netlabel_tools procps-ng nmap-ncat
mount -t selinuxfs none /sys/fs/selinux
load_policy
netlabelctl calipso add pass doi:1
netlabelctl map del default
netlabelctl map add default address:::1 protocol:calipso,1
sysctl net.ipv4.tcp_syncookies=2
nc -l ::1 80 &
nc ::1 80

Fixes: e1adea927080 ("calipso: Allow request sockets to be relabelled by the lsm.")
Reported-by: syzkaller <syzkaller@googlegroups.com>
Reported-by: John Cheung <john.cs.hey@gmail.com>
Closes: https://lore.kernel.org/netdev/CAP=Rh=MvfhrGADy+-WJiftV2_WzMH4VEhEFmeT28qY+4yxNu4w@mail.gmail.com/
Signed-off-by: Kuniyuki Iwashima <kuniyu@google.com>
Acked-by: Paul Moore <paul@paul-moore.com>
Link: https://patch.msgid.link/20250617224125.17299-1-kuni1840@gmail.com
Signed-off-by: Jakub Kicinski <kuba@kernel.org>
```

**Diff:**
```diff
diff --git a/net/ipv6/calipso.c b/net/ipv6/calipso.c
index 62618a058b8f..a247bb93908b 100644
--- a/net/ipv6/calipso.c
+++ b/net/ipv6/calipso.c
@@ -1207,6 +1207,10 @@ static int calipso_req_setattr(struct request_sock *req,
 	struct ipv6_opt_hdr *old, *new;
 	struct sock *sk = sk_to_full_sk(req_to_sk(req));
 
+	/* sk is NULL for SYN+ACK w/ SYN Cookie */
+	if (!sk)
+		return -ENOMEM;
+
 	if (req_inet->ipv6_opt && req_inet->ipv6_opt->hopopt)
 		old = req_inet->ipv6_opt->hopopt;
 	else
@@ -1247,6 +1251,10 @@ static void calipso_req_delattr(struct request_sock *req)
 	struct ipv6_txoptions *txopts;
 	struct sock *sk = sk_to_full_sk(req_to_sk(req));
 
+	/* sk is NULL for SYN+ACK w/ SYN Cookie */
+	if (!sk)
+		return;
+
 	if (!req_inet->ipv6_opt || !req_inet->ipv6_opt->hopopt)
 		return;
 
```

---

## Commit 5: 547e8366

**Author:** Qu Wenruo
**Date:** 2025-06-19 15:21:06
**Files Changed:** fs/btrfs/disk-io.c

**Message:**
```
btrfs: handle csum tree error with rescue=ibadroots correctly

[BUG]
There is syzbot based reproducer that can crash the kernel, with the
following call trace: (With some debug output added)

 DEBUG: rescue=ibadroots parsed
 BTRFS: device fsid 14d642db-7b15-43e4-81e6-4b8fac6a25f8 devid 1 transid 8 /dev/loop0 (7:0) scanned by repro (1010)
 BTRFS info (device loop0): first mount of filesystem 14d642db-7b15-43e4-81e6-4b8fac6a25f8
 BTRFS info (device loop0): using blake2b (blake2b-256-generic) checksum algorithm
 BTRFS info (device loop0): using free-space-tree
 BTRFS warning (device loop0): checksum verify failed on logical 5312512 mirror 1 wanted 0xb043382657aede36608fd3386d6b001692ff406164733d94e2d9a180412c6003 found 0x810ceb2bacb7f0f9eb2bf3b2b15c02af867cb35ad450898169f3b1f0bd818651 level 0
 DEBUG: read tree root path failed for tree csum, ret=-5
 BTRFS warning (device loop0): checksum verify failed on logical 5328896 mirror 1 wanted 0x51be4e8b303da58e6340226815b70e3a93592dac3f30dd510c7517454de8567a found 0x51be4e8b303da58e634022a315b70e3a93592dac3f30dd510c7517454de8567a level 0
 BTRFS warning (device loop0): checksum verify failed on logical 5292032 mirror 1 wanted 0x1924ccd683be9efc2fa98582ef58760e3848e9043db8649ee382681e220cdee4 found 0x0cb6184f6e8799d9f8cb335dccd1d1832da1071d12290dab3b85b587ecacca6e level 0
 process 'repro' launched './file2' with NULL argv: empty string added
 DEBUG: no csum root, idatacsums=0 ibadroots=134217728
 Oops: general protection fault, probably for non-canonical address 0xdffffc0000000041: 0000 [#1] SMP KASAN NOPTI
 KASAN: null-ptr-deref in range [0x0000000000000208-0x000000000000020f]
 CPU: 5 UID: 0 PID: 1010 Comm: repro Tainted: G           OE       6.15.0-custom+ #249 PREEMPT(full)
 Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS unknown 02/02/2022
 RIP: 0010:btrfs_lookup_csum+0x93/0x3d0 [btrfs]
 Call Trace:
  <TASK>
  btrfs_lookup_bio_sums+0x47a/0xdf0 [btrfs]
  btrfs_submit_bbio+0x43e/0x1a80 [btrfs]
  submit_one_bio+0xde/0x160 [btrfs]
  btrfs_readahead+0x498/0x6a0 [btrfs]
  read_pages+0x1c3/0xb20
  page_cache_ra_order+0x4b5/0xc20
  filemap_get_pages+0x2d3/0x19e0
  filemap_read+0x314/0xde0
  __kernel_read+0x35b/0x900
  bprm_execve+0x62e/0x1140
  do_execveat_common.isra.0+0x3fc/0x520
  __x64_sys_execveat+0xdc/0x130
  do_syscall_64+0x54/0x1d0
  entry_SYSCALL_64_after_hwframe+0x76/0x7e
 ---[ end trace 0000000000000000 ]---

[CAUSE]
Firstly the fs has a corrupted csum tree root, thus to mount the fs we
have to go "ro,rescue=ibadroots" mount option.

Normally with that mount option, a bad csum tree root should set
BTRFS_FS_STATE_NO_DATA_CSUMS flag, so that any future data read will
ignore csum search.

But in this particular case, we have the following call trace that
caused NULL csum root, but not setting BTRFS_FS_STATE_NO_DATA_CSUMS:

load_global_roots_objectid():

		ret = btrfs_search_slot();
		/* Succeeded */
		btrfs_item_key_to_cpu()
		found = true;
		/* We found the root item for csum tree. */
		root = read_tree_root_path();
		if (IS_ERR(root)) {
			if (!btrfs_test_opt(fs_info, IGNOREBADROOTS))
			/*
			 * Since we have rescue=ibadroots mount option,
			 * @ret is still 0.
			 */
			break;
	if (!found || ret) {
		/* @found is true, @ret is 0, error handling for csum
		 * tree is skipped.
		 */
	}

This means we completely skipped to set BTRFS_FS_STATE_NO_DATA_CSUMS if
the csum tree is corrupted, which results unexpected later csum lookup.

[FIX]
If read_tree_root_path() failed, always populate @ret to the error
number.

As at the end of the function, we need @ret to determine if we need to
do the extra error handling for csum tree.

Fixes: abed4aaae4f7 ("btrfs: track the csum, extent, and free space trees in a rb tree")
Reported-by: Zhiyu Zhang <zhiyuzhang999@gmail.com>
Reported-by: Longxing Li <coregee2000@gmail.com>
Reviewed-by: David Sterba <dsterba@suse.com>
Signed-off-by: Qu Wenruo <wqu@suse.com>
Signed-off-by: David Sterba <dsterba@suse.com>
```

**Diff:**
```diff
diff --git a/fs/btrfs/disk-io.c b/fs/btrfs/disk-io.c
index f48f9d924a62..0d6ad7512f21 100644
--- a/fs/btrfs/disk-io.c
+++ b/fs/btrfs/disk-io.c
@@ -2158,8 +2158,7 @@ static int load_global_roots_objectid(struct btrfs_root *tree_root,
 		found = true;
 		root = read_tree_root_path(tree_root, path, &key);
 		if (IS_ERR(root)) {
-			if (!btrfs_test_opt(fs_info, IGNOREBADROOTS))
-				ret = PTR_ERR(root);
+			ret = PTR_ERR(root);
 			break;
 		}
 		set_bit(BTRFS_ROOT_TRACK_DIRTY, &root->state);
```

---

