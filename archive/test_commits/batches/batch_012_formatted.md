# Linux Kernel Commit Batch Analysis

## Commit 1: 14dd9564

**Author:** Kent Overstreet
**Date:** 2025-07-05 12:42:41
**Files Changed:** fs/bcachefs/btree_io.c, fs/bcachefs/errcode.h, fs/bcachefs/error.c

**Message:**
```
bcachefs: btree read retry fixes

Fix btree node read retries after validate errors:

__btree_err() is the wrong place to flag a topology error: that is done
by btree_lost_data().

Additionally, some calls to bch2_bkey_pick_read_device() were not
updated in the 6.16 rework for improved log messages; we were failing to
signal that we still had a retry.

Cc: Nikita Ofitserov <himikof@gmail.com>
Cc: Alan Huang <mmpgouride@gmail.com>
Reported-and-tested-by: Edoardo Codeglia <bcachefs@404.blue>
Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
```

**Diff:**
```diff
diff --git a/fs/bcachefs/btree_io.c b/fs/bcachefs/btree_io.c
index e874a4357f64..a4cc72986e36 100644
--- a/fs/bcachefs/btree_io.c
+++ b/fs/bcachefs/btree_io.c
@@ -568,9 +568,9 @@ static int __btree_err(int ret,
 		bch2_mark_btree_validate_failure(failed, ca->dev_idx);
 
 		struct extent_ptr_decoded pick;
-		have_retry = !bch2_bkey_pick_read_device(c,
+		have_retry = bch2_bkey_pick_read_device(c,
 					bkey_i_to_s_c(&b->key),
-					failed, &pick, -1);
+					failed, &pick, -1) == 1;
 	}
 
 	if (!have_retry && ret == -BCH_ERR_btree_node_read_err_want_retry)
@@ -615,7 +615,6 @@ static int __btree_err(int ret,
 			goto out;
 		case -BCH_ERR_btree_node_read_err_bad_node:
 			prt_str(&out, ", ");
-			ret = __bch2_topology_error(c, &out);
 			break;
 		}
 
@@ -644,7 +643,6 @@ static int __btree_err(int ret,
 		goto out;
 	case -BCH_ERR_btree_node_read_err_bad_node:
 		prt_str(&out, ", ");
-		ret = __bch2_topology_error(c, &out);
 		break;
 	}
 print:
@@ -1408,7 +1406,7 @@ static void btree_node_read_work(struct work_struct *work)
 		ret = bch2_bkey_pick_read_device(c,
 					bkey_i_to_s_c(&b->key),
 					&failed, &rb->pick, -1);
-		if (ret) {
+		if (ret <= 0) {
 			set_btree_node_read_error(b);
 			break;
 		}
diff --git a/fs/bcachefs/errcode.h b/fs/bcachefs/errcode.h
index 86a842f1e88e..acc3b7b67704 100644
--- a/fs/bcachefs/errcode.h
+++ b/fs/bcachefs/errcode.h
@@ -282,7 +282,6 @@
 	x(EIO,				sb_not_downgraded)			\
 	x(EIO,				btree_node_write_all_failed)		\
 	x(EIO,				btree_node_read_error)			\
-	x(EIO,				btree_node_read_validate_error)		\

... (truncated 16 lines)
```

---

## Commit 2: 454706f1

**Author:** Jens Axboe
**Date:** 2025-07-05 06:32:59
**Files Changed:** drivers/md/md-bitmap.c, drivers/md/raid1.c, drivers/md/raid10.c

**Message:**
```
Merge tag 'md-6.16-20250705' of gitolite.kernel.org:pub/scm/linux/kernel/git/mdraid/linux into block-6.16

Pull MD fixes from Yu:

" - fix uaf due to stack memory used for bio mempool, from Jinchao
  - fix raid10/raid1 nowait IO error path, from Nigel and Qixing
  - fix kernel crash from reading bitmap sysfs entry, by Håkon"

* tag 'md-6.16-20250705' of gitolite.kernel.org:pub/scm/linux/kernel/git/mdraid/linux:
  md/md-bitmap: fix GPF in bitmap_get_stats()
  md/raid1,raid10: strip REQ_NOWAIT from member bios
  raid10: cleanup memleak at raid10_make_request
  md/raid1: Fix stack memory use after return in raid1_reshape
```

**Diff:**
```diff
diff --git a/drivers/md/md-bitmap.c b/drivers/md/md-bitmap.c
index bd694910b01b..7f524a26cebc 100644
--- a/drivers/md/md-bitmap.c
+++ b/drivers/md/md-bitmap.c
@@ -2366,8 +2366,7 @@ static int bitmap_get_stats(void *data, struct md_bitmap_stats *stats)
 
 	if (!bitmap)
 		return -ENOENT;
-	if (!bitmap->mddev->bitmap_info.external &&
-	    !bitmap->storage.sb_page)
+	if (!bitmap->storage.sb_page)
 		return -EINVAL;
 	sb = kmap_local_page(bitmap->storage.sb_page);
 	stats->sync_size = le64_to_cpu(sb->sync_size);
diff --git a/drivers/md/raid1.c b/drivers/md/raid1.c
index 19c5a0ce5a40..64b8176907a9 100644
--- a/drivers/md/raid1.c
+++ b/drivers/md/raid1.c
@@ -1399,7 +1399,7 @@ static void raid1_read_request(struct mddev *mddev, struct bio *bio,
 	}
 	read_bio = bio_alloc_clone(mirror->rdev->bdev, bio, gfp,
 				   &mddev->bio_set);
-
+	read_bio->bi_opf &= ~REQ_NOWAIT;
 	r1_bio->bios[rdisk] = read_bio;
 
 	read_bio->bi_iter.bi_sector = r1_bio->sector +
@@ -1649,6 +1649,7 @@ static void raid1_write_request(struct mddev *mddev, struct bio *bio,
 				wait_for_serialization(rdev, r1_bio);
 		}
 
+		mbio->bi_opf &= ~REQ_NOWAIT;
 		r1_bio->bios[i] = mbio;
 
 		mbio->bi_iter.bi_sector	= (r1_bio->sector + rdev->data_offset);
@@ -3428,6 +3429,7 @@ static int raid1_reshape(struct mddev *mddev)
 	/* ok, everything is stopped */
 	oldpool = conf->r1bio_pool;
 	conf->r1bio_pool = newpool;
+	init_waitqueue_head(&conf->r1bio_pool.wait);
 
 	for (d = d2 = 0; d < conf->raid_disks; d++) {
 		struct md_rdev *rdev = conf->mirrors[d].rdev;
diff --git a/drivers/md/raid10.c b/drivers/md/raid10.c
index b74780af4c22..c9bd2005bfd0 100644
--- a/drivers/md/raid10.c
+++ b/drivers/md/raid10.c
@@ -1182,8 +1182,11 @@ static void raid10_read_request(struct mddev *mddev, struct bio *bio,
 		}
 	}

... (truncated 39 lines)
```

---

## Commit 3: ddb9680a

**Author:** Kent Overstreet
**Date:** 2025-07-04 15:47:13
**Files Changed:** fs/bcachefs/extents.c

**Message:**
```
bcachefs: Fix bch2_io_failures_to_text()

This wasn't updated when we added tracking for btree validate errors.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
```

**Diff:**
```diff
diff --git a/fs/bcachefs/extents.c b/fs/bcachefs/extents.c
index 036e4ad95987..83cbd77dcb9c 100644
--- a/fs/bcachefs/extents.c
+++ b/fs/bcachefs/extents.c
@@ -50,19 +50,17 @@ void bch2_io_failures_to_text(struct printbuf *out,
 			      struct bch_io_failures *failed)
 {
 	static const char * const error_types[] = {
-		"io", "checksum", "ec reconstruct", NULL
+		"btree validate", "io", "checksum", "ec reconstruct", NULL
 	};
 
 	for (struct bch_dev_io_failures *f = failed->devs;
 	     f < failed->devs + failed->nr;
 	     f++) {
 		unsigned errflags =
-			((!!f->failed_io)	<< 0) |
-			((!!f->failed_csum_nr)	<< 1) |
-			((!!f->failed_ec)	<< 2);
-
-		if (!errflags)
-			continue;
+			((!!f->failed_btree_validate)	<< 0) |
+			((!!f->failed_io)		<< 1) |
+			((!!f->failed_csum_nr)		<< 2) |
+			((!!f->failed_ec)		<< 3);
 
 		bch2_printbuf_make_room(out, 1024);
 		out->atomic++;
@@ -77,7 +75,9 @@ void bch2_io_failures_to_text(struct printbuf *out,
 
 		prt_char(out, ' ');
 
-		if (is_power_of_2(errflags)) {
+		if (!errflags) {
+			prt_str(out, "no error - confused");
+		} else if (is_power_of_2(errflags)) {
 			prt_bitflags(out, error_types, errflags);
 			prt_str(out, " error");
 		} else {
```

---

## Commit 4: 63d6e931

**Author:** Kent Overstreet
**Date:** 2025-07-04 15:45:22
**Files Changed:** fs/bcachefs/fsck.c, fs/bcachefs/io_misc.c, fs/bcachefs/io_misc.h

**Message:**
```
bcachefs: bch2_fpunch_snapshot()

Add a new version of fpunch for operating on a snapshot ID, not a
subvolume - and use it for "extent past end of inode" repair.

Previously, repair would try to delete everything at once, but deleting
too many extents at once can overflow the btree_trans bump allocator, as
well as causing other problems - the new helper properly uses
bch2_extent_trim_atomic().

Reported-and-tested-by: Edoardo Codeglia <bcachefs@404.blue>
Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
```

**Diff:**
```diff
diff --git a/fs/bcachefs/fsck.c b/fs/bcachefs/fsck.c
index dbf161e4311a..856eb2b41896 100644
--- a/fs/bcachefs/fsck.c
+++ b/fs/bcachefs/fsck.c
@@ -12,6 +12,7 @@
 #include "fs.h"
 #include "fsck.h"
 #include "inode.h"
+#include "io_misc.h"
 #include "keylist.h"
 #include "namei.h"
 #include "recovery_passes.h"
@@ -1919,33 +1920,11 @@ static int check_extent(struct btree_trans *trans, struct btree_iter *iter,
 					"extent type past end of inode %llu:%u, i_size %llu\n%s",
 					i->inode.bi_inum, i->inode.bi_snapshot, i->inode.bi_size,
 					(bch2_bkey_val_to_text(&buf, c, k), buf.buf))) {
-				struct bkey_i *whiteout = bch2_trans_kmalloc(trans, sizeof(*whiteout));
-				ret = PTR_ERR_OR_ZERO(whiteout);
-				if (ret)
-					goto err;
-
-				bkey_init(&whiteout->k);
-				whiteout->k.p = SPOS(k.k->p.inode,
-						     last_block,
-						     i->inode.bi_snapshot);
-				bch2_key_resize(&whiteout->k,
-						min(KEY_SIZE_MAX & (~0 << c->block_bits),
-						    U64_MAX - whiteout->k.p.offset));
-
-
-				/*
-				 * Need a normal (not BTREE_ITER_all_snapshots)
-				 * iterator, if we're deleting in a different
-				 * snapshot and need to emit a whiteout
-				 */
-				struct btree_iter iter2;
-				bch2_trans_iter_init(trans, &iter2, BTREE_ID_extents,
-						     bkey_start_pos(&whiteout->k),
-						     BTREE_ITER_intent);
-				ret =   bch2_btree_iter_traverse(trans, &iter2) ?:
-					bch2_trans_update(trans, &iter2, whiteout,
-						BTREE_UPDATE_internal_snapshot_node);
-				bch2_trans_iter_exit(trans, &iter2);
+				ret = bch2_fpunch_snapshot(trans,
+							   SPOS(i->inode.bi_inum,
+								last_block,
+								i->inode.bi_snapshot),
+							   POS(i->inode.bi_inum, U64_MAX));
 				if (ret)
 					goto err;

... (truncated 52 lines)
```

---

## Commit 5: b1bf2ef6

**Author:** Linus Torvalds
**Date:** 2025-07-04 12:05:36
**Files Changed:** drivers/firmware/arm_ffa/driver.c, drivers/firmware/samsung/exynos-acpm.c, drivers/tee/optee/ffa_abi.c, drivers/tee/optee/optee_private.h, include/linux/arm_ffa.h

**Message:**
```
Merge tag 'soc-fixes-6.16' of git://git.kernel.org/pub/scm/linux/kernel/git/soc/soc

Pull SoC fixes from Arnd Bergmann:
 "A couple of fixes for firmware drivers have come up, addressing kernel
  side bugs in op-tee and ff-a code, as well as compatibility issues
  with exynos-acpm and ff-a protocols.

  The only devicetree fixes are for the Apple platform, addressing
  issues with conformance to the bindings for the wlan, spi and mipi
  nodes"

* tag 'soc-fixes-6.16' of git://git.kernel.org/pub/scm/linux/kernel/git/soc/soc:
  arm64: dts: apple: Move touchbar mipi {address,size}-cells from dtsi to dts
  arm64: dts: apple: Drop {address,size}-cells from SPI NOR
  arm64: dts: apple: t8103: Fix PCIe BCM4377 nodename
  optee: ffa: fix sleep in atomic context
  firmware: exynos-acpm: fix timeouts on xfers handling
  arm64: defconfig: update renamed PHY_SNPS_EUSB2
  firmware: arm_ffa: Fix the missing entry in struct ffa_indirect_msg_hdr
  firmware: arm_ffa: Replace mutex with rwlock to avoid sleep in atomic context
  firmware: arm_ffa: Move memory allocation outside the mutex locking
  firmware: arm_ffa: Fix memory leak by freeing notifier callback node
```

**Diff:**
```diff
diff --git a/arch/arm64/boot/dts/apple/spi1-nvram.dtsi b/arch/arm64/boot/dts/apple/spi1-nvram.dtsi
index 3df2fd3993b5..9740fbf200f0 100644
--- a/arch/arm64/boot/dts/apple/spi1-nvram.dtsi
+++ b/arch/arm64/boot/dts/apple/spi1-nvram.dtsi
@@ -20,8 +20,6 @@ flash@0 {
 		compatible = "jedec,spi-nor";
 		reg = <0x0>;
 		spi-max-frequency = <25000000>;
-		#address-cells = <1>;
-		#size-cells = <1>;
 
 		partitions {
 			compatible = "fixed-partitions";
diff --git a/arch/arm64/boot/dts/apple/t8103-j293.dts b/arch/arm64/boot/dts/apple/t8103-j293.dts
index e2d9439397f7..5b3c42e9f0e6 100644
--- a/arch/arm64/boot/dts/apple/t8103-j293.dts
+++ b/arch/arm64/boot/dts/apple/t8103-j293.dts
@@ -100,6 +100,8 @@ dfr_mipi_out_panel: endpoint@0 {
 
 &displaydfr_mipi {
 	status = "okay";
+	#address-cells = <1>;
+	#size-cells = <0>;
 
 	dfr_panel: panel@0 {
 		compatible = "apple,j293-summit", "apple,summit";
diff --git a/arch/arm64/boot/dts/apple/t8103-jxxx.dtsi b/arch/arm64/boot/dts/apple/t8103-jxxx.dtsi
index 8e82231acab5..0c8206156bfe 100644
--- a/arch/arm64/boot/dts/apple/t8103-jxxx.dtsi
+++ b/arch/arm64/boot/dts/apple/t8103-jxxx.dtsi
@@ -71,7 +71,7 @@ hpm1: usb-pd@3f {
  */
 &port00 {
 	bus-range = <1 1>;
-	wifi0: network@0,0 {
+	wifi0: wifi@0,0 {
 		compatible = "pci14e4,4425";
 		reg = <0x10000 0x0 0x0 0x0 0x0>;
 		/* To be filled by the loader */
diff --git a/arch/arm64/boot/dts/apple/t8103.dtsi b/arch/arm64/boot/dts/apple/t8103.dtsi
index 20faf0c0d809..3a204845b85b 100644
--- a/arch/arm64/boot/dts/apple/t8103.dtsi
+++ b/arch/arm64/boot/dts/apple/t8103.dtsi
@@ -405,8 +405,6 @@ displaydfr_mipi: dsi@228600000 {
 			compatible = "apple,t8103-display-pipe-mipi", "apple,h7-display-pipe-mipi";
 			reg = <0x2 0x28600000 0x0 0x100000>;
 			power-domains = <&ps_mipi_dsi>;
-			#address-cells = <1>;
-			#size-cells = <0>;
 			status = "disabled";

... (truncated 373 lines)
```

---

