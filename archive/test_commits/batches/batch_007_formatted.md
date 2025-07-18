# Linux Kernel Commit Batch Analysis

## Commit 1: 3ef07434

**Author:** Christophe JAILLET
**Date:** 2025-07-08 08:59:24
**Files Changed:** drivers/net/ethernet/airoha/airoha_eth.c

**Message:**
```
net: airoha: Fix an error handling path in airoha_probe()

If an error occurs after a successful airoha_hw_init() call,
airoha_ppe_deinit() needs to be called as already done in the remove
function.

Fixes: 00a7678310fe ("net: airoha: Introduce flowtable offload support")
Signed-off-by: Christophe JAILLET <christophe.jaillet@wanadoo.fr>
Reviewed-by: Simon Horman <horms@kernel.org>
Acked-by: Lorenzo Bianconi <lorenzo@kernel.org>
Link: https://patch.msgid.link/1c940851b4fa3c3ed2a142910c821493a136f121.1746715755.git.christophe.jaillet@wanadoo.fr
Signed-off-by: Jakub Kicinski <kuba@kernel.org>
```

**Diff:**
```diff
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
```

---

## Commit 2: d006330b

**Author:** Linus Torvalds
**Date:** 2025-07-08 08:55:18
**Files Changed:** sound/isa/ad1816a/ad1816a.c, sound/pci/hda/patch_hdmi.c, sound/pci/hda/patch_realtek.c, sound/pci/hda/tas2781_hda.c, sound/soc/codecs/cs35l56-shared.c (+5 more)

**Message:**
```
Merge tag 'sound-6.16-rc6' of git://git.kernel.org/pub/scm/linux/kernel/git/tiwai/sound

Pull sound fixes from Takashi Iwai:
 "Here are device-specific small fixes, including HD-audio, USB-audio
  and ASoC Intel quirks, as well as ASoC fsl, Cirrus codec and the
  legacy AD driver fixes.

  All look safe and easy"

* tag 'sound-6.16-rc6' of git://git.kernel.org/pub/scm/linux/kernel/git/tiwai/sound:
  ALSA: hda/realtek: Enable headset Mic on Positivo K116J
  ALSA: hda/tas2781: Fix calibration data parser issue
  ALSA: ad1816a: Fix potential NULL pointer deref in snd_card_ad1816a_pnp()
  ASoC: cs35l56: probe() should fail if the device ID is not recognized
  ALSA: hda/realtek: Add quirk for ASUS ExpertBook B9403CVAR
  ASoC: Intel: sof_sdw: Add quirks for Lenovo P1 and P16
  ALSA: usb-audio: Improve filtering of sample rates on Focusrite devices
  ASoC: Intel: soc-acpi: arl: Correct order of cs42l43 matches
  MAINTAINERS: update Qualcomm audio codec drivers list
  ASoC: fsl_sai: Force a software reset when starting in consumer mode
  ASoC: Intel: SND_SOC_INTEL_SOF_BOARD_HELPERS select SND_SOC_ACPI_INTEL_MATCH
  ASoC: fsl_asrc: use internal measured ratio for non-ideal ratio mode
  ALSA: hda/realtek - Add mute LED support for HP Victus 15-fb2xxx
  ALSA: hda: Add missing NVIDIA HDA codec IDs
```

**Diff:**
```diff
diff --git a/MAINTAINERS b/MAINTAINERS
index fad6cb025a19..1ff244fe3e1a 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -20155,21 +20155,15 @@ S:	Supported
 F:	Documentation/devicetree/bindings/soc/qcom/qcom,apr*
 F:	Documentation/devicetree/bindings/sound/qcom,*
 F:	drivers/soc/qcom/apr.c
-F:	include/dt-bindings/sound/qcom,wcd9335.h
-F:	include/dt-bindings/sound/qcom,wcd934x.h
-F:	sound/soc/codecs/lpass-rx-macro.*
-F:	sound/soc/codecs/lpass-tx-macro.*
-F:	sound/soc/codecs/lpass-va-macro.c
-F:	sound/soc/codecs/lpass-wsa-macro.*
+F:	drivers/soundwire/qcom.c
+F:	include/dt-bindings/sound/qcom,wcd93*
+F:	sound/soc/codecs/lpass-*.*
 F:	sound/soc/codecs/msm8916-wcd-analog.c
 F:	sound/soc/codecs/msm8916-wcd-digital.c
 F:	sound/soc/codecs/wcd-clsh-v2.*
 F:	sound/soc/codecs/wcd-mbhc-v2.*
-F:	sound/soc/codecs/wcd9335.*
-F:	sound/soc/codecs/wcd934x.c
-F:	sound/soc/codecs/wsa881x.c
-F:	sound/soc/codecs/wsa883x.c
-F:	sound/soc/codecs/wsa884x.c
+F:	sound/soc/codecs/wcd93*.*
+F:	sound/soc/codecs/wsa88*.*
 F:	sound/soc/qcom/
 
 QCOM EMBEDDED USB DEBUGGER (EUD)
diff --git a/sound/isa/ad1816a/ad1816a.c b/sound/isa/ad1816a/ad1816a.c
index 99006dc4777e..5c9e2d41d900 100644
--- a/sound/isa/ad1816a/ad1816a.c
+++ b/sound/isa/ad1816a/ad1816a.c
@@ -98,7 +98,7 @@ static int snd_card_ad1816a_pnp(int dev, struct pnp_card_link *card,
 	pdev = pnp_request_card_device(card, id->devs[1].id, NULL);
 	if (pdev == NULL) {
 		mpu_port[dev] = -1;
-		dev_warn(&pdev->dev, "MPU401 device busy, skipping.\n");
+		pr_warn("MPU401 device busy, skipping.\n");
 		return 0;
 	}
 
diff --git a/sound/pci/hda/patch_hdmi.c b/sound/pci/hda/patch_hdmi.c
index 08308231b4ed..9a7793eb16e9 100644
--- a/sound/pci/hda/patch_hdmi.c
+++ b/sound/pci/hda/patch_hdmi.c
@@ -4551,7 +4551,9 @@ HDA_CODEC_ENTRY(0x10de002e, "Tegra186 HDMI/DP1", patch_tegra_hdmi),
 HDA_CODEC_ENTRY(0x10de002f, "Tegra194 HDMI/DP2", patch_tegra_hdmi),

... (truncated 263 lines)
```

---

## Commit 3: 95a234f6

**Author:** Haoxiang Li
**Date:** 2025-07-08 08:34:05
**Files Changed:** drivers/net/ethernet/renesas/rtsn.c

**Message:**
```
net: ethernet: rtsn: Fix a null pointer dereference in rtsn_probe()

Add check for the return value of rcar_gen4_ptp_alloc()
to prevent potential null pointer dereference.

Fixes: b0d3969d2b4d ("net: ethernet: rtsn: Add support for Renesas Ethernet-TSN")
Cc: stable@vger.kernel.org
Signed-off-by: Haoxiang Li <haoxiang_li2024@163.com>
Reviewed-by: Niklas Söderlund <niklas.soderlund+renesas@ragnatech.se>
Link: https://patch.msgid.link/20250703100109.2541018-1-haoxiang_li2024@163.com
Signed-off-by: Jakub Kicinski <kuba@kernel.org>
```

**Diff:**
```diff
diff --git a/drivers/net/ethernet/renesas/rtsn.c b/drivers/net/ethernet/renesas/rtsn.c
index 6b3f7fca8d15..05c4b6c8c9c3 100644
--- a/drivers/net/ethernet/renesas/rtsn.c
+++ b/drivers/net/ethernet/renesas/rtsn.c
@@ -1259,7 +1259,12 @@ static int rtsn_probe(struct platform_device *pdev)
 	priv = netdev_priv(ndev);
 	priv->pdev = pdev;
 	priv->ndev = ndev;
+
 	priv->ptp_priv = rcar_gen4_ptp_alloc(pdev);
+	if (!priv->ptp_priv) {
+		ret = -ENOMEM;
+		goto error_free;
+	}
 
 	spin_lock_init(&priv->lock);
 	platform_set_drvdata(pdev, priv);
```

---

## Commit 4: d3a5f287

**Author:** Jiayuan Chen
**Date:** 2025-07-08 07:56:26
**Files Changed:** net/ipv4/tcp.c

**Message:**
```
tcp: Correct signedness in skb remaining space calculation

Syzkaller reported a bug [1] where sk->sk_forward_alloc can overflow.

When we send data, if an skb exists at the tail of the write queue, the
kernel will attempt to append the new data to that skb. However, the code
that checks for available space in the skb is flawed:
'''
copy = size_goal - skb->len
'''

The types of the variables involved are:
'''
copy: ssize_t (s64 on 64-bit systems)
size_goal: int
skb->len: unsigned int
'''

Due to C's type promotion rules, the signed size_goal is converted to an
unsigned int to match skb->len before the subtraction. The result is an
unsigned int.

When this unsigned int result is then assigned to the s64 copy variable,
it is zero-extended, preserving its non-negative value. Consequently, copy
is always >= 0.

Assume we are sending 2GB of data and size_goal has been adjusted to a
value smaller than skb->len. The subtraction will result in copy holding a
very large positive integer. In the subsequent logic, this large value is
used to update sk->sk_forward_alloc, which can easily cause it to overflow.

The syzkaller reproducer uses TCP_REPAIR to reliably create this
condition. However, this can also occur in real-world scenarios. The
tcp_bound_to_half_wnd() function can also reduce size_goal to a small
value. This would cause the subsequent tcp_wmem_schedule() to set
sk->sk_forward_alloc to a value close to INT_MAX. Further memory
allocation requests would then cause sk_forward_alloc to wrap around and
become negative.

[1]: https://syzkaller.appspot.com/bug?extid=de6565462ab540f50e47

Reported-by: syzbot+de6565462ab540f50e47@syzkaller.appspotmail.com
Fixes: 270a1c3de47e ("tcp: Support MSG_SPLICE_PAGES")
Signed-off-by: Jiayuan Chen <jiayuan.chen@linux.dev>
Reviewed-by: Eric Dumazet <edumazet@google.com>
Reviewed-by: David Howells <dhowells@redhat.com>
Link: https://patch.msgid.link/20250707054112.101081-1-jiayuan.chen@linux.dev
Signed-off-by: Jakub Kicinski <kuba@kernel.org>
```

**Diff:**
```diff
diff --git a/net/ipv4/tcp.c b/net/ipv4/tcp.c
index f64f8276a73c..461a9ab540af 100644
--- a/net/ipv4/tcp.c
+++ b/net/ipv4/tcp.c
@@ -1176,7 +1176,7 @@ int tcp_sendmsg_locked(struct sock *sk, struct msghdr *msg, size_t size)
 		goto do_error;
 
 	while (msg_data_left(msg)) {
-		ssize_t copy = 0;
+		int copy = 0;
 
 		skb = tcp_write_queue_tail(sk);
 		if (skb)
```

---

## Commit 5: 5383fc05

**Author:** Paolo Bonzini
**Date:** 2025-07-08 10:49:19
**Files Changed:** arch/x86/include/asm/kvm_host.h, arch/x86/include/asm/shared/tdx.h, arch/x86/include/uapi/asm/kvm.h, arch/x86/kvm/hyperv.c, arch/x86/kvm/svm/sev.c (+6 more)

**Message:**
```
Merge tag 'kvm-x86-fixes-6.16-rcN' of https://github.com/kvm-x86/linux into HEAD

KVM x86 fixes for 6.16-rcN

- Reject SEV{-ES} intra-host migration if one or more vCPUs are actively
  being created so as not to create a non-SEV{-ES} vCPU in an SEV{-ES} VM.

- Use a pre-allocated, per-vCPU buffer for handling de-sparsified vCPU masks
  when emulating Hyper-V hypercalls to fix a "stack frame too large" issue.

- Allow out-of-range/invalid Xen event channel ports when configuring IRQ
  routing to avoid dictating a specific ioctl() ordering to userspace.

- Conditionally reschedule when setting memory attributes to avoid soft
  lockups when userspace converts huge swaths of memory to/from private.

- Add back MWAIT as a required feature for the MONITOR/MWAIT selftest.

- Add a missing field in struct sev_data_snp_launch_start that resulted in
  the guest-visible workarounds field being filled at the wrong offset.

- Skip non-canonical address when processing Hyper-V PV TLB flushes to avoid
  VM-Fail on INVVPID.

- Advertise supported TDX TDVMCALLs to userspace.
```

**Diff:**
```diff
diff --git a/Documentation/virt/kvm/api.rst b/Documentation/virt/kvm/api.rst
index 9abf93ee5f65..43ed57e048a8 100644
--- a/Documentation/virt/kvm/api.rst
+++ b/Documentation/virt/kvm/api.rst
@@ -7196,6 +7196,10 @@ The valid value for 'flags' is:
 					u64 leaf;
 					u64 r11, r12, r13, r14;
 				} get_tdvmcall_info;
+				struct {
+					u64 ret;
+					u64 vector;
+				} setup_event_notify;
 			};
 		} tdx;
 
@@ -7210,21 +7214,24 @@ number from register R11.  The remaining field of the union provide the
 inputs and outputs of the TDVMCALL.  Currently the following values of
 ``nr`` are defined:
 
-* ``TDVMCALL_GET_QUOTE``: the guest has requested to generate a TD-Quote
-signed by a service hosting TD-Quoting Enclave operating on the host.
-Parameters and return value are in the ``get_quote`` field of the union.
-The ``gpa`` field and ``size`` specify the guest physical address
-(without the shared bit set) and the size of a shared-memory buffer, in
-which the TDX guest passes a TD Report.  The ``ret`` field represents
-the return value of the GetQuote request.  When the request has been
-queued successfully, the TDX guest can poll the status field in the
-shared-memory area to check whether the Quote generation is completed or
-not. When completed, the generated Quote is returned via the same buffer.
-
-* ``TDVMCALL_GET_TD_VM_CALL_INFO``: the guest has requested the support
-status of TDVMCALLs.  The output values for the given leaf should be
-placed in fields from ``r11`` to ``r14`` of the ``get_tdvmcall_info``
-field of the union.
+ * ``TDVMCALL_GET_QUOTE``: the guest has requested to generate a TD-Quote
+   signed by a service hosting TD-Quoting Enclave operating on the host.
+   Parameters and return value are in the ``get_quote`` field of the union.
+   The ``gpa`` field and ``size`` specify the guest physical address
+   (without the shared bit set) and the size of a shared-memory buffer, in
+   which the TDX guest passes a TD Report.  The ``ret`` field represents
+   the return value of the GetQuote request.  When the request has been
+   queued successfully, the TDX guest can poll the status field in the
+   shared-memory area to check whether the Quote generation is completed or
+   not. When completed, the generated Quote is returned via the same buffer.
+
+ * ``TDVMCALL_GET_TD_VM_CALL_INFO``: the guest has requested the support
+   status of TDVMCALLs.  The output values for the given leaf should be
+   placed in fields from ``r11`` to ``r14`` of the ``get_tdvmcall_info``
+   field of the union.
+

... (truncated 294 lines)
```

---

