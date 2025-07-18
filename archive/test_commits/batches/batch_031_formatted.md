# Linux Kernel Commit Batch Analysis

## Commit 1: 5f6e3b72

**Author:** Yazen Ghannam
**Date:** 2025-06-27 13:16:23
**Files Changed:** arch/x86/kernel/cpu/mce/amd.c

**Message:**
```
x86/mce/amd: Fix threshold limit reset

The MCA threshold limit must be reset after servicing the interrupt.

Currently, the restart function doesn't have an explicit check for this.  It
makes some assumptions based on the current limit and what's in the registers.
These assumptions don't always hold, so the limit won't be reset in some
cases.

Make the reset condition explicit. Either an interrupt/overflow has occurred
or the bank is being initialized.

Signed-off-by: Yazen Ghannam <yazen.ghannam@amd.com>
Signed-off-by: Borislav Petkov (AMD) <bp@alien8.de>
Cc: stable@vger.kernel.org
Link: https://lore.kernel.org/20250624-wip-mca-updates-v4-4-236dd74f645f@amd.com
```

**Diff:**
```diff
diff --git a/arch/x86/kernel/cpu/mce/amd.c b/arch/x86/kernel/cpu/mce/amd.c
index 6820ebce5d46..5c4eb28c3ac9 100644
--- a/arch/x86/kernel/cpu/mce/amd.c
+++ b/arch/x86/kernel/cpu/mce/amd.c
@@ -350,7 +350,6 @@ static void smca_configure(unsigned int bank, unsigned int cpu)
 
 struct thresh_restart {
 	struct threshold_block	*b;
-	int			reset;
 	int			set_lvt_off;
 	int			lvt_off;
 	u16			old_limit;
@@ -432,13 +431,13 @@ static void threshold_restart_bank(void *_tr)
 
 	rdmsr(tr->b->address, lo, hi);
 
-	if (tr->b->threshold_limit < (hi & THRESHOLD_MAX))
-		tr->reset = 1;	/* limit cannot be lower than err count */
-
-	if (tr->reset) {		/* reset err count and overflow bit */
-		hi =
-		    (hi & ~(MASK_ERR_COUNT_HI | MASK_OVERFLOW_HI)) |
-		    (THRESHOLD_MAX - tr->b->threshold_limit);
+	/*
+	 * Reset error count and overflow bit.
+	 * This is done during init or after handling an interrupt.
+	 */
+	if (hi & MASK_OVERFLOW_HI || tr->set_lvt_off) {
+		hi &= ~(MASK_ERR_COUNT_HI | MASK_OVERFLOW_HI);
+		hi |= THRESHOLD_MAX - tr->b->threshold_limit;
 	} else if (tr->old_limit) {	/* change limit w/o reset */
 		int new_count = (hi & THRESHOLD_MAX) +
 		    (tr->old_limit - tr->b->threshold_limit);
```

---

## Commit 2: cc8d5b20

**Author:** Bibo Mao
**Date:** 2025-06-27 18:27:44
**Files Changed:** arch/loongarch/kvm/intc/eiointc.c

**Message:**
```
LoongArch: KVM: Check validity of "num_cpu" from user space

The maximum supported cpu number is EIOINTC_ROUTE_MAX_VCPUS about
irqchip EIOINTC, here add validation about cpu number to avoid array
pointer overflow.

Cc: stable@vger.kernel.org
Fixes: 1ad7efa552fd ("LoongArch: KVM: Add EIOINTC user mode read and write functions")
Signed-off-by: Bibo Mao <maobibo@loongson.cn>
Signed-off-by: Huacai Chen <chenhuacai@loongson.cn>
```

**Diff:**
```diff
diff --git a/arch/loongarch/kvm/intc/eiointc.c b/arch/loongarch/kvm/intc/eiointc.c
index 644fb7785c07..056a75f7d090 100644
--- a/arch/loongarch/kvm/intc/eiointc.c
+++ b/arch/loongarch/kvm/intc/eiointc.c
@@ -805,7 +805,7 @@ static int kvm_eiointc_ctrl_access(struct kvm_device *dev,
 	int ret = 0;
 	unsigned long flags;
 	unsigned long type = (unsigned long)attr->attr;
-	u32 i, start_irq;
+	u32 i, start_irq, val;
 	void __user *data;
 	struct loongarch_eiointc *s = dev->kvm->arch.eiointc;
 
@@ -813,8 +813,14 @@ static int kvm_eiointc_ctrl_access(struct kvm_device *dev,
 	spin_lock_irqsave(&s->lock, flags);
 	switch (type) {
 	case KVM_DEV_LOONGARCH_EXTIOI_CTRL_INIT_NUM_CPU:
-		if (copy_from_user(&s->num_cpu, data, 4))
+		if (copy_from_user(&val, data, 4))
 			ret = -EFAULT;
+		else {
+			if (val >= EIOINTC_ROUTE_MAX_VCPUS)
+				ret = -EINVAL;
+			else
+				s->num_cpu = val;
+		}
 		break;
 	case KVM_DEV_LOONGARCH_EXTIOI_CTRL_INIT_FEATURE:
 		if (copy_from_user(&s->features, data, 4))
@@ -842,7 +848,7 @@ static int kvm_eiointc_regs_access(struct kvm_device *dev,
 					struct kvm_device_attr *attr,
 					bool is_write)
 {
-	int addr, cpuid, offset, ret = 0;
+	int addr, cpu, offset, ret = 0;
 	unsigned long flags;
 	void *p = NULL;
 	void __user *data;
@@ -850,7 +856,7 @@ static int kvm_eiointc_regs_access(struct kvm_device *dev,
 
 	s = dev->kvm->arch.eiointc;
 	addr = attr->attr;
-	cpuid = addr >> 16;
+	cpu = addr >> 16;
 	addr &= 0xffff;
 	data = (void __user *)attr->addr;
 	switch (addr) {
@@ -875,8 +881,11 @@ static int kvm_eiointc_regs_access(struct kvm_device *dev,
 		p = &s->isr.reg_u32[offset];
 		break;

... (truncated 10 lines)
```

---

## Commit 3: 48e29133

**Author:** Wolfram Sang
**Date:** 2025-06-27 11:58:27
**Files Changed:** drivers/i2c/busses/i2c-designware-amdisp.c, drivers/i2c/busses/i2c-designware-master.c, drivers/i2c/busses/i2c-imx.c, drivers/i2c/busses/i2c-omap.c, drivers/i2c/busses/i2c-robotfuzz-osif.c (+3 more)

**Message:**
```
Merge tag 'i2c-host-fixes-6.16-rc4' of git://git.kernel.org/pub/scm/linux/kernel/git/andi.shyti/linux into i2c/for-current

i2c-host fixes for v6.16-rc4

- imx: fix SMBus protocol compliance during block read
- omap: fix error handling path in probe
- robotfuzz, tiny-usb: prevent zero-length reads
- x86, designware, amdisp: fix build error when modules are
  disabled
```

**Diff:**
```diff
diff --git a/MAINTAINERS b/MAINTAINERS
index c3f7fbd0d67a..8719f097aae3 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -24063,6 +24063,7 @@ M:	Bin Du <bin.du@amd.com>
 L:	linux-i2c@vger.kernel.org
 S:	Maintained
 F:	drivers/i2c/busses/i2c-designware-amdisp.c
+F:	include/linux/soc/amd/isp4_misc.h
 
 SYNOPSYS DESIGNWARE MMC/SD/SDIO DRIVER
 M:	Jaehoon Chung <jh80.chung@samsung.com>
diff --git a/drivers/i2c/busses/i2c-designware-amdisp.c b/drivers/i2c/busses/i2c-designware-amdisp.c
index ad6f08338124..450793d5f839 100644
--- a/drivers/i2c/busses/i2c-designware-amdisp.c
+++ b/drivers/i2c/busses/i2c-designware-amdisp.c
@@ -8,6 +8,7 @@
 #include <linux/module.h>
 #include <linux/platform_device.h>
 #include <linux/pm_runtime.h>
+#include <linux/soc/amd/isp4_misc.h>
 
 #include "i2c-designware-core.h"
 
@@ -62,6 +63,7 @@ static int amd_isp_dw_i2c_plat_probe(struct platform_device *pdev)
 
 	adap = &isp_i2c_dev->adapter;
 	adap->owner = THIS_MODULE;
+	scnprintf(adap->name, sizeof(adap->name), AMDISP_I2C_ADAP_NAME);
 	ACPI_COMPANION_SET(&adap->dev, ACPI_COMPANION(&pdev->dev));
 	adap->dev.of_node = pdev->dev.of_node;
 	/* use dynamically allocated adapter id */
diff --git a/drivers/i2c/busses/i2c-designware-master.c b/drivers/i2c/busses/i2c-designware-master.c
index c5394229b77f..9d7d9e47564a 100644
--- a/drivers/i2c/busses/i2c-designware-master.c
+++ b/drivers/i2c/busses/i2c-designware-master.c
@@ -1042,8 +1042,9 @@ int i2c_dw_probe_master(struct dw_i2c_dev *dev)
 	if (ret)
 		return ret;
 
-	snprintf(adap->name, sizeof(adap->name),
-		 "Synopsys DesignWare I2C adapter");
+	if (!adap->name[0])
+		scnprintf(adap->name, sizeof(adap->name),
+			  "Synopsys DesignWare I2C adapter");
 	adap->retries = 3;
 	adap->algo = &i2c_dw_algo;
 	adap->quirks = &i2c_dw_quirks;
diff --git a/drivers/i2c/busses/i2c-imx.c b/drivers/i2c/busses/i2c-imx.c
index e5732b0557fb..205cc132fdec 100644

... (truncated 136 lines)
```

---

## Commit 4: 6f2a71a9

**Author:** Linus Torvalds
**Date:** 2025-06-26 19:49:12
**Files Changed:** fs/bcachefs/alloc_background.c, fs/bcachefs/backpointers.c, fs/bcachefs/bcachefs.h, fs/bcachefs/btree_gc.c, fs/bcachefs/btree_io.c (+37 more)

**Message:**
```
Merge tag 'bcachefs-2025-06-26' of git://evilpiepirate.org/bcachefs

Pull bcachefs fixes from Kent Overstreet:

 - Lots of small check/repair fixes, primarily in subvol loop and
   directory structure loop (when involving snapshots).

 - Fix a few 6.16 regressions: rare UAF in the foreground allocator path
   when taking a transaction restart from the transaction bump
   allocator, and some small fallout from the change to log the error
   being corrected in the journal when repairing errors, also some
   fallout from the btree node read error logging improvements.

   (Alan, Bharadwaj)

 - New option: journal_rewind

   This lets the entire filesystem be reset to an earlier point in time.

   Note that this is only a disaster recovery tool, and right now there
   are major caveats to using it (discards should be disabled, in
   particular), but it successfully restored the filesystem of one of
   the users who was bit by the subvolume deletion bug and didn't have
   backups. I'll likely be making some changes to the discard path in
   the future to make this a reliable recovery tool.

 - Some new btree iterator tracepoints, for tracking down some
   livelock-ish behaviour we've been seeing in the main data write path.

* tag 'bcachefs-2025-06-26' of git://evilpiepirate.org/bcachefs: (51 commits)
  bcachefs: Plumb correct ip to trans_relock_fail tracepoint
  bcachefs: Ensure we rewind to run recovery passes
  bcachefs: Ensure btree node scan runs before checking for scanned nodes
  bcachefs: btree_root_unreadable_and_scan_found_nothing should not be autofix
  bcachefs: fix bch2_journal_keys_peek_prev_min() underflow
  bcachefs: Use wait_on_allocator() when allocating journal
  bcachefs: Check for bad write buffer key when moving from journal
  bcachefs: Don't unlock the trans if ret doesn't match BCH_ERR_operation_blocked
  bcachefs: Fix range in bch2_lookup_indirect_extent() error path
  bcachefs: fix spurious error_throw
  bcachefs: Add missing bch2_err_class() to fileattr_set()
  bcachefs: Add missing key type checks to check_snapshot_exists()
  bcachefs: Don't log fsck err in the journal if doing repair elsewhere
  bcachefs: Fix *__bch2_trans_subbuf_alloc() error path
  bcachefs: Fix missing newlines before ero
  bcachefs: fix spurious error in read_btree_roots()
  bcachefs: fsck: Fix oops in key_visible_in_snapshot()
  bcachefs: fsck: fix unhandled restart in topology repair
  bcachefs: fsck: Fix check_directory_structure when no check_dirents
  bcachefs: Fix restart handling in btree_node_scrub_work()
  ...
```

**Diff:**
```diff
diff --git a/fs/bcachefs/alloc_background.c b/fs/bcachefs/alloc_background.c
index b228a5a64479..66de46318620 100644
--- a/fs/bcachefs/alloc_background.c
+++ b/fs/bcachefs/alloc_background.c
@@ -1406,6 +1406,9 @@ int bch2_check_discard_freespace_key(struct btree_trans *trans, struct btree_ite
 		: BCH_DATA_free;
 	struct printbuf buf = PRINTBUF;
 
+	unsigned fsck_flags = (async_repair ? FSCK_ERR_NO_LOG : 0)|
+		FSCK_CAN_FIX|FSCK_CAN_IGNORE;
+
 	struct bpos bucket = iter->pos;
 	bucket.offset &= ~(~0ULL << 56);
 	u64 genbits = iter->pos.offset & (~0ULL << 56);
@@ -1419,9 +1422,10 @@ int bch2_check_discard_freespace_key(struct btree_trans *trans, struct btree_ite
 		return ret;
 
 	if (!bch2_dev_bucket_exists(c, bucket)) {
-		if (fsck_err(trans, need_discard_freespace_key_to_invalid_dev_bucket,
-			     "entry in %s btree for nonexistant dev:bucket %llu:%llu",
-			     bch2_btree_id_str(iter->btree_id), bucket.inode, bucket.offset))
+		if (__fsck_err(trans, fsck_flags,
+			       need_discard_freespace_key_to_invalid_dev_bucket,
+			       "entry in %s btree for nonexistant dev:bucket %llu:%llu",
+			       bch2_btree_id_str(iter->btree_id), bucket.inode, bucket.offset))
 			goto delete;
 		ret = 1;
 		goto out;
@@ -1433,7 +1437,8 @@ int bch2_check_discard_freespace_key(struct btree_trans *trans, struct btree_ite
 	if (a->data_type != state ||
 	    (state == BCH_DATA_free &&
 	     genbits != alloc_freespace_genbits(*a))) {
-		if (fsck_err(trans, need_discard_freespace_key_bad,
+		if (__fsck_err(trans, fsck_flags,
+			       need_discard_freespace_key_bad,
 			     "%s\nincorrectly set at %s:%llu:%llu:0 (free %u, genbits %llu should be %llu)",
 			     (bch2_bkey_val_to_text(&buf, c, alloc_k), buf.buf),
 			     bch2_btree_id_str(iter->btree_id),
diff --git a/fs/bcachefs/backpointers.c b/fs/bcachefs/backpointers.c
index e76809e71858..77d93beb3c8f 100644
--- a/fs/bcachefs/backpointers.c
+++ b/fs/bcachefs/backpointers.c
@@ -353,7 +353,7 @@ static struct bkey_s_c __bch2_backpointer_get_key(struct btree_trans *trans,
 		return ret ? bkey_s_c_err(ret) : bkey_s_c_null;
 	} else {
 		struct btree *b = __bch2_backpointer_get_node(trans, bp, iter, last_flushed, commit);
-		if (b == ERR_PTR(bch_err_throw(c, backpointer_to_overwritten_btree_node)))
+		if (b == ERR_PTR(-BCH_ERR_backpointer_to_overwritten_btree_node))
 			return bkey_s_c_null;
 		if (IS_ERR_OR_NULL(b))

... (truncated 2611 lines)
```

---

## Commit 5: 8a20830f

**Author:** Linus Torvalds
**Date:** 2025-06-26 17:06:01
**Files Changed:** drivers/hid/hid-appletb-kbd.c, drivers/hid/hid-ids.h, drivers/hid/hid-input.c, drivers/hid/hid-lenovo.c, drivers/hid/hid-multitouch.c (+6 more)

**Message:**
```
Merge tag 'hid-for-linus-2025062701' of git://git.kernel.org/pub/scm/linux/kernel/git/hid/hid

Pull HID fixes from Jiri Kosina:

 - fix for stalls during suspend/resume cycles with hid-nintendo (Daniel
   J. Ogorchock)

 - memory leak and reference count fixes in hid-wacom and in-appletb-kdb
   (Qasim Ijaz)

 - race condition (leading to kernel crash) fix during device removal in
   hid-wacom (Thomas Zeitlhofer)

 - fix for missed interrupt in intel-thc-hid (Intel-thc-hid:)

 - support for a bunch of new device IDs

* tag 'hid-for-linus-2025062701' of git://git.kernel.org/pub/scm/linux/kernel/git/hid/hid:
  HID: lenovo: Add support for ThinkPad X1 Tablet Thin Keyboard Gen2
  HID: appletb-kbd: fix "appletb_backlight" backlight device reference counting
  HID: wacom: fix crash in wacom_aes_battery_handler()
  HID: intel-ish-hid: ipc: Add Wildcat Lake PCI device ID
  hid: intel-ish-hid: Use PCI_DEVICE_DATA() macro for ISH device table
  HID: lenovo: Restrict F7/9/11 mode to compact keyboards only
  HID: Add IGNORE quirk for SMARTLINKTECHNOLOGY
  HID: input: lower message severity of 'No inputs registered, leaving' to debug
  HID: quirks: Add quirk for 2 Chicony Electronics HP 5MP Cameras
  HID: Intel-thc-hid: Intel-quicki2c: Enhance QuickI2C reset flow
  HID: nintendo: avoid bluetooth suspend/resume stalls
  HID: wacom: fix kobject reference count leak
  HID: wacom: fix memory leak on sysfs attribute creation failure
  HID: wacom: fix memory leak on kobject creation failure
```

**Diff:**
```diff
diff --git a/drivers/hid/hid-appletb-kbd.c b/drivers/hid/hid-appletb-kbd.c
index 6f251b284018..2e0caf52af13 100644
--- a/drivers/hid/hid-appletb-kbd.c
+++ b/drivers/hid/hid-appletb-kbd.c
@@ -438,6 +438,8 @@ static int appletb_kbd_probe(struct hid_device *hdev, const struct hid_device_id
 	return 0;
 
 close_hw:
+	if (kbd->backlight_dev)
+		put_device(&kbd->backlight_dev->dev);
 	hid_hw_close(hdev);
 stop_hw:
 	hid_hw_stop(hdev);
@@ -453,6 +455,9 @@ static void appletb_kbd_remove(struct hid_device *hdev)
 	input_unregister_handler(&kbd->inp_handler);
 	timer_delete_sync(&kbd->inactivity_timer);
 
+	if (kbd->backlight_dev)
+		put_device(&kbd->backlight_dev->dev);
+
 	hid_hw_close(hdev);
 	hid_hw_stop(hdev);
 }
diff --git a/drivers/hid/hid-ids.h b/drivers/hid/hid-ids.h
index e3fb4e2fe911..c6468568aea1 100644
--- a/drivers/hid/hid-ids.h
+++ b/drivers/hid/hid-ids.h
@@ -312,6 +312,8 @@
 #define USB_DEVICE_ID_ASUS_AK1D		0x1125
 #define USB_DEVICE_ID_CHICONY_TOSHIBA_WT10A	0x1408
 #define USB_DEVICE_ID_CHICONY_ACER_SWITCH12	0x1421
+#define USB_DEVICE_ID_CHICONY_HP_5MP_CAMERA	0xb824
+#define USB_DEVICE_ID_CHICONY_HP_5MP_CAMERA2	0xb82c
 
 #define USB_VENDOR_ID_CHUNGHWAT		0x2247
 #define USB_DEVICE_ID_CHUNGHWAT_MULTITOUCH	0x0001
@@ -819,6 +821,7 @@
 #define USB_DEVICE_ID_LENOVO_TPPRODOCK	0x6067
 #define USB_DEVICE_ID_LENOVO_X1_COVER	0x6085
 #define USB_DEVICE_ID_LENOVO_X1_TAB	0x60a3
+#define USB_DEVICE_ID_LENOVO_X1_TAB2	0x60a4
 #define USB_DEVICE_ID_LENOVO_X1_TAB3	0x60b5
 #define USB_DEVICE_ID_LENOVO_X12_TAB	0x60fe
 #define USB_DEVICE_ID_LENOVO_X12_TAB2	0x61ae
@@ -1525,4 +1528,7 @@
 #define USB_VENDOR_ID_SIGNOTEC			0x2133
 #define USB_DEVICE_ID_SIGNOTEC_VIEWSONIC_PD1011	0x0018
 
+#define USB_VENDOR_ID_SMARTLINKTECHNOLOGY              0x4c4a
+#define USB_DEVICE_ID_SMARTLINKTECHNOLOGY_4155         0x4155

... (truncated 350 lines)
```

---

