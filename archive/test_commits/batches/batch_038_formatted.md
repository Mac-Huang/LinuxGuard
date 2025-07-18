# Linux Kernel Commit Batch Analysis

## Commit 1: 4937e604

**Author:** Christoph Hellwig
**Date:** 2025-06-24 21:20:58
**Files Changed:** drivers/scsi/hosts.c

**Message:**
```
scsi: core: Enforce unlimited max_segment_size when virt_boundary_mask is set

The virt_boundary_mask limit requires an unlimited max_segment_size for
bio splitting to not corrupt data.  Historically, the block layer tried
to validate this, although the check was half-hearted until the addition
of the atomic queue limits API.  The full blown check then triggered
issues with stacked devices incorrectly inheriting limits such as the
virt boundary and got disabled in commit b561ea56a264 ("block: allow
device to have both virt_boundary_mask and max segment size") instead of
fixing the issue properly.

Ensure that the SCSI mid layer doesn't set the default low
max_segment_size limit for this case, and check for invalid
max_segment_size values in the host template, similar to the original
block layer check given that SCSI devices can't be stacked.

This fixes reported data corruption on storvsc, although as far as I can
tell storvsc always failed to properly set the max_segment_size limit as
the SCSI APIs historically applied that when setting up the host, while
storvsc only set the virt_boundary_mask when configuring the scsi_device.

Fixes: 81988a0e6b03 ("storvsc: get rid of bounce buffer")
Fixes: b561ea56a264 ("block: allow device to have both virt_boundary_mask and max segment size")
Reported-by: Ming Lei <ming.lei@redhat.com>
Signed-off-by: Christoph Hellwig <hch@lst.de>
Link: https://lore.kernel.org/r/20250624125233.219635-3-hch@lst.de
Reviewed-by: John Garry <john.g.garry@oracle.com>
Reviewed-by: Ming Lei <ming.lei@redhat.com>
Reviewed-by: Hannes Reinecke <hare@suse.de>
Reviewed-by: Bart Van Assche <bvanassche@acm.org>
Signed-off-by: Martin K. Petersen <martin.petersen@oracle.com>
```

**Diff:**
```diff
diff --git a/drivers/scsi/hosts.c b/drivers/scsi/hosts.c
index e021f1106bea..cc5d05dc395c 100644
--- a/drivers/scsi/hosts.c
+++ b/drivers/scsi/hosts.c
@@ -473,10 +473,17 @@ struct Scsi_Host *scsi_host_alloc(const struct scsi_host_template *sht, int priv
 	else
 		shost->max_sectors = SCSI_DEFAULT_MAX_SECTORS;
 
-	if (sht->max_segment_size)
-		shost->max_segment_size = sht->max_segment_size;
-	else
-		shost->max_segment_size = BLK_MAX_SEGMENT_SIZE;
+	shost->virt_boundary_mask = sht->virt_boundary_mask;
+	if (shost->virt_boundary_mask) {
+		WARN_ON_ONCE(sht->max_segment_size &&
+			     sht->max_segment_size != UINT_MAX);
+		shost->max_segment_size = UINT_MAX;
+	} else {
+		if (sht->max_segment_size)
+			shost->max_segment_size = sht->max_segment_size;
+		else
+			shost->max_segment_size = BLK_MAX_SEGMENT_SIZE;
+	}
 
 	/* 32-byte (dword) is a common minimum for HBAs. */
 	if (sht->dma_alignment)
@@ -492,9 +499,6 @@ struct Scsi_Host *scsi_host_alloc(const struct scsi_host_template *sht, int priv
 	else
 		shost->dma_boundary = 0xffffffff;
 
-	if (sht->virt_boundary_mask)
-		shost->virt_boundary_mask = sht->virt_boundary_mask;
-
 	device_initialize(&shost->shost_gendev);
 	dev_set_name(&shost->shost_gendev, "host%d", shost->host_no);
 	shost->shost_gendev.bus = &scsi_bus_type;
```

---

## Commit 2: 8889676c

**Author:** jackysliu
**Date:** 2025-06-24 21:05:42
**Files Changed:** drivers/scsi/sd.c

**Message:**
```
scsi: sd: Fix VPD page 0xb7 length check

sd_read_block_limits_ext() currently assumes that vpd->len excludes the
size of the page header. However, vpd->len describes the size of the entire
VPD page, therefore the sanity check is incorrect.

In practice this is not really a problem since we don't attach VPD
pages unless they actually report data trailing the header. But fix
the length check regardless.

This issue was identified by Wukong-Agent (formerly Tencent Woodpecker), a
code security AI agent, through static code analysis.

[mkp: rewrote patch description]

Signed-off-by: jackysliu <1972843537@qq.com>
Link: https://lore.kernel.org/r/tencent_ADA5210D1317EEB6CD7F3DE9FE9DA4591D05@qq.com
Fixes: 96b171d6dba6 ("scsi: core: Query the Block Limits Extension VPD page")
Signed-off-by: Martin K. Petersen <martin.petersen@oracle.com>
```

**Diff:**
```diff
diff --git a/drivers/scsi/sd.c b/drivers/scsi/sd.c
index 3f6e87705b62..eeaa6af294b8 100644
--- a/drivers/scsi/sd.c
+++ b/drivers/scsi/sd.c
@@ -3384,7 +3384,7 @@ static void sd_read_block_limits_ext(struct scsi_disk *sdkp)
 
 	rcu_read_lock();
 	vpd = rcu_dereference(sdkp->device->vpd_pgb7);
-	if (vpd && vpd->len >= 2)
+	if (vpd && vpd->len >= 6)
 		sdkp->rscs = vpd->data[5] & 1;
 	rcu_read_unlock();
 }
```

---

## Commit 3: 7595b66a

**Author:** Linus Torvalds
**Date:** 2025-06-24 17:20:43
**Files Changed:** security/selinux/ss/services.c

**Message:**
```
Merge tag 'selinux-pr-20250624' of git://git.kernel.org/pub/scm/linux/kernel/git/pcmoore/selinux

Pull selinux fix from Paul Moore:
 "Another small SELinux patch to fix a problem seen by the dracut-ng
  folks during early boot when SELinux is enabled, but the policy has
  yet to be loaded"

* tag 'selinux-pr-20250624' of git://git.kernel.org/pub/scm/linux/kernel/git/pcmoore/selinux:
  selinux: change security_compute_sid to return the ssid or tsid on match
```

**Diff:**
```diff
diff --git a/security/selinux/ss/services.c b/security/selinux/ss/services.c
index 7becf3808818..d185754c2786 100644
--- a/security/selinux/ss/services.c
+++ b/security/selinux/ss/services.c
@@ -1909,11 +1909,17 @@ static int security_compute_sid(u32 ssid,
 			goto out_unlock;
 	}
 	/* Obtain the sid for the context. */
-	rc = sidtab_context_to_sid(sidtab, &newcontext, out_sid);
-	if (rc == -ESTALE) {
-		rcu_read_unlock();
-		context_destroy(&newcontext);
-		goto retry;
+	if (context_equal(scontext, &newcontext))
+		*out_sid = ssid;
+	else if (context_equal(tcontext, &newcontext))
+		*out_sid = tsid;
+	else {
+		rc = sidtab_context_to_sid(sidtab, &newcontext, out_sid);
+		if (rc == -ESTALE) {
+			rcu_read_unlock();
+			context_destroy(&newcontext);
+			goto retry;
+		}
 	}
 out_unlock:
 	rcu_read_unlock();
```

---

## Commit 4: 1f8aede7

**Author:** Kent Overstreet
**Date:** 2025-06-24 18:58:18
**Files Changed:** fs/bcachefs/btree_journal_iter.c

**Message:**
```
bcachefs: fix bch2_journal_keys_peek_prev_min() underflow

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
```

**Diff:**
```diff
diff --git a/fs/bcachefs/btree_journal_iter.c b/fs/bcachefs/btree_journal_iter.c
index a41fabd06332..ea839560a136 100644
--- a/fs/bcachefs/btree_journal_iter.c
+++ b/fs/bcachefs/btree_journal_iter.c
@@ -137,12 +137,15 @@ struct bkey_i *bch2_journal_keys_peek_prev_min(struct bch_fs *c, enum btree_id b
 	struct journal_key *k;
 
 	BUG_ON(*idx > keys->nr);
+
+	if (!keys->nr)
+		return NULL;
 search:
 	if (!*idx)
 		*idx = __bch2_journal_key_search(keys, btree_id, level, pos);
 
 	while (*idx < keys->nr &&
-	       __journal_key_cmp(btree_id, level, end_pos, idx_to_key(keys, *idx - 1)) >= 0) {
+	       __journal_key_cmp(btree_id, level, end_pos, idx_to_key(keys, *idx)) >= 0) {
 		(*idx)++;
 		iters++;
 		if (iters == 10) {
@@ -151,18 +154,23 @@ struct bkey_i *bch2_journal_keys_peek_prev_min(struct bch_fs *c, enum btree_id b
 		}
 	}
 
+	if (*idx == keys->nr)
+		--(*idx);
+
 	struct bkey_i *ret = NULL;
 	rcu_read_lock(); /* for overwritten_ranges */
 
-	while ((k = *idx < keys->nr ? idx_to_key(keys, *idx) : NULL)) {
+	while (true) {
+		k = idx_to_key(keys, *idx);
 		if (__journal_key_cmp(btree_id, level, end_pos, k) > 0)
 			break;
 
 		if (k->overwritten) {
 			if (k->overwritten_range)
-				*idx = rcu_dereference(k->overwritten_range)->start - 1;
-			else
-				*idx -= 1;
+				*idx = rcu_dereference(k->overwritten_range)->start;
+			if (!*idx)
+				break;
+			--(*idx);
 			continue;
 		}
 
@@ -171,6 +179,8 @@ struct bkey_i *bch2_journal_keys_peek_prev_min(struct bch_fs *c, enum btree_id b

... (truncated 8 lines)
```

---

## Commit 5: ecf371f8

**Author:** Sean Christopherson
**Date:** 2025-06-24 12:20:10
**Files Changed:** arch/x86/kvm/svm/sev.c

**Message:**
```
KVM: SVM: Reject SEV{-ES} intra host migration if vCPU creation is in-flight

Reject migration of SEV{-ES} state if either the source or destination VM
is actively creating a vCPU, i.e. if kvm_vm_ioctl_create_vcpu() is in the
section between incrementing created_vcpus and online_vcpus.  The bulk of
vCPU creation runs _outside_ of kvm->lock to allow creating multiple vCPUs
in parallel, and so sev_info.es_active can get toggled from false=>true in
the destination VM after (or during) svm_vcpu_create(), resulting in an
SEV{-ES} VM effectively having a non-SEV{-ES} vCPU.

The issue manifests most visibly as a crash when trying to free a vCPU's
NULL VMSA page in an SEV-ES VM, but any number of things can go wrong.

  BUG: unable to handle page fault for address: ffffebde00000000
  #PF: supervisor read access in kernel mode
  #PF: error_code(0x0000) - not-present page
  PGD 0 P4D 0
  Oops: Oops: 0000 [#1] SMP KASAN NOPTI
  CPU: 227 UID: 0 PID: 64063 Comm: syz.5.60023 Tainted: G     U     O        6.15.0-smp-DEV #2 NONE
  Tainted: [U]=USER, [O]=OOT_MODULE
  Hardware name: Google, Inc. Arcadia_IT_80/Arcadia_IT_80, BIOS 12.52.0-0 10/28/2024
  RIP: 0010:constant_test_bit arch/x86/include/asm/bitops.h:206 [inline]
  RIP: 0010:arch_test_bit arch/x86/include/asm/bitops.h:238 [inline]
  RIP: 0010:_test_bit include/asm-generic/bitops/instrumented-non-atomic.h:142 [inline]
  RIP: 0010:PageHead include/linux/page-flags.h:866 [inline]
  RIP: 0010:___free_pages+0x3e/0x120 mm/page_alloc.c:5067
  Code: <49> f7 06 40 00 00 00 75 05 45 31 ff eb 0c 66 90 4c 89 f0 4c 39 f0
  RSP: 0018:ffff8984551978d0 EFLAGS: 00010246
  RAX: 0000777f80000001 RBX: 0000000000000000 RCX: ffffffff918aeb98
  RDX: 0000000000000000 RSI: 0000000000000008 RDI: ffffebde00000000
  RBP: 0000000000000000 R08: ffffebde00000007 R09: 1ffffd7bc0000000
  R10: dffffc0000000000 R11: fffff97bc0000001 R12: dffffc0000000000
  R13: ffff8983e19751a8 R14: ffffebde00000000 R15: 1ffffd7bc0000000
  FS:  0000000000000000(0000) GS:ffff89ee661d3000(0000) knlGS:0000000000000000
  CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
  CR2: ffffebde00000000 CR3: 000000793ceaa000 CR4: 0000000000350ef0
  DR0: 0000000000000000 DR1: 0000000000000b5f DR2: 0000000000000000
  DR3: 0000000000000000 DR6: 00000000ffff0ff0 DR7: 0000000000000400
  Call Trace:
   <TASK>
   sev_free_vcpu+0x413/0x630 arch/x86/kvm/svm/sev.c:3169
   svm_vcpu_free+0x13a/0x2a0 arch/x86/kvm/svm/svm.c:1515
   kvm_arch_vcpu_destroy+0x6a/0x1d0 arch/x86/kvm/x86.c:12396
   kvm_vcpu_destroy virt/kvm/kvm_main.c:470 [inline]
   kvm_destroy_vcpus+0xd1/0x300 virt/kvm/kvm_main.c:490
   kvm_arch_destroy_vm+0x636/0x820 arch/x86/kvm/x86.c:12895
   kvm_put_kvm+0xb8e/0xfb0 virt/kvm/kvm_main.c:1310
   kvm_vm_release+0x48/0x60 virt/kvm/kvm_main.c:1369
   __fput+0x3e4/0x9e0 fs/file_table.c:465
   task_work_run+0x1a9/0x220 kernel/task_work.c:227
   exit_task_work include/linux/task_work.h:40 [inline]
   do_exit+0x7f0/0x25b0 kernel/exit.c:953
   do_group_exit+0x203/0x2d0 kernel/exit.c:1102
   get_signal+0x1357/0x1480 kernel/signal.c:3034
   arch_do_signal_or_restart+0x40/0x690 arch/x86/kernel/signal.c:337
   exit_to_user_mode_loop kernel/entry/common.c:111 [inline]
   exit_to_user_mode_prepare include/linux/entry-common.h:329 [inline]
   __syscall_exit_to_user_mode_work kernel/entry/common.c:207 [inline]
   syscall_exit_to_user_mode+0x67/0xb0 kernel/entry/common.c:218
   do_syscall_64+0x7c/0x150 arch/x86/entry/syscall_64.c:100
   entry_SYSCALL_64_after_hwframe+0x76/0x7e
  RIP: 0033:0x7f87a898e969
   </TASK>
  Modules linked in: gq(O)
  gsmi: Log Shutdown Reason 0x03
  CR2: ffffebde00000000
  ---[ end trace 0000000000000000 ]---

Deliberately don't check for a NULL VMSA when freeing the vCPU, as crashing
the host is likely desirable due to the VMSA being consumed by hardware.
E.g. if KVM manages to allow VMRUN on the vCPU, hardware may read/write a
bogus VMSA page.  Accessing PFN 0 is "fine"-ish now that it's sequestered
away thanks to L1TF, but panicking in this scenario is preferable to
potentially running with corrupted state.

Reported-by: Alexander Potapenko <glider@google.com>
Tested-by: Alexander Potapenko <glider@google.com>
Fixes: 0b020f5af092 ("KVM: SEV: Add support for SEV-ES intra host migration")
Fixes: b56639318bb2 ("KVM: SEV: Add support for SEV intra host migration")
Cc: stable@vger.kernel.org
Cc: James Houghton <jthoughton@google.com>
Cc: Peter Gonda <pgonda@google.com>
Reviewed-by: Liam Merwick <liam.merwick@oracle.com>
Tested-by: Liam Merwick <liam.merwick@oracle.com>
Reviewed-by: James Houghton <jthoughton@google.com>
Link: https://lore.kernel.org/r/20250602224459.41505-2-seanjc@google.com
Signed-off-by: Sean Christopherson <seanjc@google.com>
```

**Diff:**
```diff
diff --git a/arch/x86/kvm/svm/sev.c b/arch/x86/kvm/svm/sev.c
index 459c3b791fd4..65d1597c3fed 100644
--- a/arch/x86/kvm/svm/sev.c
+++ b/arch/x86/kvm/svm/sev.c
@@ -1971,6 +1971,10 @@ static int sev_check_source_vcpus(struct kvm *dst, struct kvm *src)
 	struct kvm_vcpu *src_vcpu;
 	unsigned long i;
 
+	if (src->created_vcpus != atomic_read(&src->online_vcpus) ||
+	    dst->created_vcpus != atomic_read(&dst->online_vcpus))
+		return -EBUSY;
+
 	if (!sev_es_guest(src))
 		return 0;
 
```

---

