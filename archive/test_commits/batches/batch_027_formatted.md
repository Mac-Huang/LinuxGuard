# Linux Kernel Commit Batch Analysis

## Commit 1: 3a3de75a

**Author:** Linus Torvalds
**Date:** 2025-06-28 11:35:11
**Files Changed:** arch/loongarch/include/asm/addrspace.h, arch/loongarch/include/asm/alternative-asm.h, arch/loongarch/include/asm/alternative.h, arch/loongarch/include/asm/asm-extable.h, arch/loongarch/include/asm/asm.h (+39 more)

**Message:**
```
Merge tag 'loongarch-fixes-6.16-1' of git://git.kernel.org/pub/scm/linux/kernel/git/chenhuacai/linux-loongson

Pull LoongArch fixes from Huacai Chen:

 - replace __ASSEMBLY__ with __ASSEMBLER__ in headers like others

 - fix build warnings about export.h

 - reserve the EFI memory map region for kdump

 - handle __init vs inline mismatches

 - fix some KVM bugs

* tag 'loongarch-fixes-6.16-1' of git://git.kernel.org/pub/scm/linux/kernel/git/chenhuacai/linux-loongson:
  LoongArch: KVM: Disable updating of "num_cpu" and "feature"
  LoongArch: KVM: Check validity of "num_cpu" from user space
  LoongArch: KVM: Check interrupt route from physical CPU
  LoongArch: KVM: Fix interrupt route update with EIOINTC
  LoongArch: KVM: Add address alignment check for IOCSR emulation
  LoongArch: KVM: Avoid overflow with array index
  LoongArch: Handle KCOV __init vs inline mismatches
  LoongArch: Reserve the EFI memory map region
  LoongArch: Fix build warnings about export.h
  LoongArch: Replace __ASSEMBLY__ with __ASSEMBLER__ in headers
```

**Diff:**
```diff
diff --git a/arch/loongarch/include/asm/addrspace.h b/arch/loongarch/include/asm/addrspace.h
index fe198b473f84..e739dbc6329d 100644
--- a/arch/loongarch/include/asm/addrspace.h
+++ b/arch/loongarch/include/asm/addrspace.h
@@ -18,12 +18,12 @@
 /*
  * This gives the physical RAM offset.
  */
-#ifndef __ASSEMBLY__
+#ifndef __ASSEMBLER__
 #ifndef PHYS_OFFSET
 #define PHYS_OFFSET	_UL(0)
 #endif
 extern unsigned long vm_map_base;
-#endif /* __ASSEMBLY__ */
+#endif /* __ASSEMBLER__ */
 
 #ifndef IO_BASE
 #define IO_BASE			CSR_DMW0_BASE
@@ -66,7 +66,7 @@ extern unsigned long vm_map_base;
 #define FIXADDR_TOP		((unsigned long)(long)(int)0xfffe0000)
 #endif
 
-#ifdef __ASSEMBLY__
+#ifdef __ASSEMBLER__
 #define _ATYPE_
 #define _ATYPE32_
 #define _ATYPE64_
@@ -85,7 +85,7 @@ extern unsigned long vm_map_base;
 /*
  *  32/64-bit LoongArch address spaces
  */
-#ifdef __ASSEMBLY__
+#ifdef __ASSEMBLER__
 #define _ACAST32_
 #define _ACAST64_
 #else
diff --git a/arch/loongarch/include/asm/alternative-asm.h b/arch/loongarch/include/asm/alternative-asm.h
index ff3d10ac393f..7dc29bd9b2f0 100644
--- a/arch/loongarch/include/asm/alternative-asm.h
+++ b/arch/loongarch/include/asm/alternative-asm.h
@@ -2,7 +2,7 @@
 #ifndef _ASM_ALTERNATIVE_ASM_H
 #define _ASM_ALTERNATIVE_ASM_H
 
-#ifdef __ASSEMBLY__
+#ifdef __ASSEMBLER__
 
 #include <asm/asm.h>
 

... (truncated 1080 lines)
```

---

## Commit 2: 45537926

**Author:** Niklas Schnelle
**Date:** 2025-06-28 18:58:59
**Files Changed:** arch/s390/pci/pci_event.c

**Message:**
```
s390/pci: Fix stale function handles in error handling

The error event information for PCI error events contains a function
handle for the respective function. This handle is generally captured at
the time the error event was recorded. Due to delays in processing or
cascading issues, it may happen that during firmware recovery multiple
events are generated. When processing these events in order Linux may
already have recovered an affected function making the event information
stale. Fix this by doing an unconditional CLP List PCI function
retrieving the current function handle with the zdev->state_lock held
and ignoring the event if its function handle is stale.

Cc: stable@vger.kernel.org
Fixes: 4cdf2f4e24ff ("s390/pci: implement minimal PCI error recovery")
Reviewed-by: Julian Ruess <julianr@linux.ibm.com>
Reviewed-by: Gerd Bayer <gbayer@linux.ibm.com>
Reviewed-by: Farhan Ali <alifm@linux.ibm.com>
Signed-off-by: Niklas Schnelle <schnelle@linux.ibm.com>
Signed-off-by: Alexander Gordeev <agordeev@linux.ibm.com>
```

**Diff:**
```diff
diff --git a/arch/s390/pci/pci_event.c b/arch/s390/pci/pci_event.c
index 2fbee3887d13..82ee2578279a 100644
--- a/arch/s390/pci/pci_event.c
+++ b/arch/s390/pci/pci_event.c
@@ -273,6 +273,8 @@ static void __zpci_event_error(struct zpci_ccdf_err *ccdf)
 	struct zpci_dev *zdev = get_zdev_by_fid(ccdf->fid);
 	struct pci_dev *pdev = NULL;
 	pci_ers_result_t ers_res;
+	u32 fh = 0;
+	int rc;
 
 	zpci_dbg(3, "err fid:%x, fh:%x, pec:%x\n",
 		 ccdf->fid, ccdf->fh, ccdf->pec);
@@ -281,6 +283,15 @@ static void __zpci_event_error(struct zpci_ccdf_err *ccdf)
 
 	if (zdev) {
 		mutex_lock(&zdev->state_lock);
+		rc = clp_refresh_fh(zdev->fid, &fh);
+		if (rc)
+			goto no_pdev;
+		if (!fh || ccdf->fh != fh) {
+			/* Ignore events with stale handles */
+			zpci_dbg(3, "err fid:%x, fh:%x (stale %x)\n",
+				 ccdf->fid, fh, ccdf->fh);
+			goto no_pdev;
+		}
 		zpci_update_fh(zdev, ccdf->fh);
 		if (zdev->zbus->bus)
 			pdev = pci_get_slot(zdev->zbus->bus, zdev->devfn);
```

---

## Commit 3: aaf724ed

**Author:** Linus Torvalds
**Date:** 2025-06-27 20:38:05
**Files Changed:** fs/smb/client/cifsglob.h, fs/smb/client/connect.c, fs/smb/client/reparse.c, fs/smb/client/smbdirect.c, fs/smb/client/trace.h

**Message:**
```
Merge tag 'v6.16-rc3-smb3-client-fixes' of git://git.samba.org/sfrench/cifs-2.6

Pull smb client fixes from Steve French:

 - Multichannel reconnect lock ordering deadlock fix

 - Fix for regression in handling native Windows symlinks

 - Three smbdirect fixes:
     - oops in RDMA response processing
     - smbdirect memcpy issue
     - fix smbdirect regression with large writes (smbdirect test cases
       now all passing)

 - Fix for "FAILED_TO_PARSE" warning in trace-cmd report output

* tag 'v6.16-rc3-smb3-client-fixes' of git://git.samba.org/sfrench/cifs-2.6:
  cifs: Fix reading into an ITER_FOLIOQ from the smbdirect code
  cifs: Fix the smbd_response slab to allow usercopy
  smb: client: fix potential deadlock when reconnecting channels
  smb: client: remove \t from TP_printk statements
  smb: client: let smbd_post_send_iter() respect the peers max_send_size and transmit all data
  smb: client: fix regression with native SMB symlinks
```

**Diff:**
```diff
diff --git a/fs/smb/client/cifsglob.h b/fs/smb/client/cifsglob.h
index 45e94e18f4d5..318a8405d475 100644
--- a/fs/smb/client/cifsglob.h
+++ b/fs/smb/client/cifsglob.h
@@ -709,6 +709,7 @@ inc_rfc1001_len(void *buf, int count)
 struct TCP_Server_Info {
 	struct list_head tcp_ses_list;
 	struct list_head smb_ses_list;
+	struct list_head rlist; /* reconnect list */
 	spinlock_t srv_lock;  /* protect anything here that is not protected */
 	__u64 conn_id; /* connection identifier (useful for debugging) */
 	int srv_count; /* reference counter */
diff --git a/fs/smb/client/connect.c b/fs/smb/client/connect.c
index c48869c29e15..685c65dcb8c4 100644
--- a/fs/smb/client/connect.c
+++ b/fs/smb/client/connect.c
@@ -124,6 +124,14 @@ static void smb2_query_server_interfaces(struct work_struct *work)
 			   (SMB_INTERFACE_POLL_INTERVAL * HZ));
 }
 
+#define set_need_reco(server) \
+do { \
+	spin_lock(&server->srv_lock); \
+	if (server->tcpStatus != CifsExiting) \
+		server->tcpStatus = CifsNeedReconnect; \
+	spin_unlock(&server->srv_lock); \
+} while (0)
+
 /*
  * Update the tcpStatus for the server.
  * This is used to signal the cifsd thread to call cifs_reconnect
@@ -137,39 +145,45 @@ void
 cifs_signal_cifsd_for_reconnect(struct TCP_Server_Info *server,
 				bool all_channels)
 {
-	struct TCP_Server_Info *pserver;
+	struct TCP_Server_Info *nserver;
 	struct cifs_ses *ses;
+	LIST_HEAD(reco);
 	int i;
 
-	/* If server is a channel, select the primary channel */
-	pserver = SERVER_IS_CHAN(server) ? server->primary_server : server;
-
 	/* if we need to signal just this channel */
 	if (!all_channels) {
-		spin_lock(&server->srv_lock);
-		if (server->tcpStatus != CifsExiting)
-			server->tcpStatus = CifsNeedReconnect;
-		spin_unlock(&server->srv_lock);

... (truncated 464 lines)
```

---

## Commit 4: 0fd39af2

**Author:** Linus Torvalds
**Date:** 2025-06-27 20:34:10
**Files Changed:** fs/fuse/inode.c, fs/proc/task_mmu.c, include/linux/kmemleak.h, lib/alloc_tag.c, lib/group_cpus.c (+4 more)

**Message:**
```
Merge tag 'mm-hotfixes-stable-2025-06-27-16-56' of git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm

Pull misc fixes from Andrew Morton:
 "16 hotfixes.

  6 are cc:stable and the remainder address post-6.15 issues or aren't
  considered necessary for -stable kernels. 5 are for MM"

* tag 'mm-hotfixes-stable-2025-06-27-16-56' of git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm:
  MAINTAINERS: add Lorenzo as THP co-maintainer
  mailmap: update Duje Mihanović's email address
  selftests/mm: fix validate_addr() helper
  crashdump: add CONFIG_KEYS dependency
  mailmap: correct name for a historical account of Zijun Hu
  mailmap: add entries for Zijun Hu
  fuse: fix runtime warning on truncate_folio_batch_exceptionals()
  scripts/gdb: fix dentry_name() lookup
  mm/damon/sysfs-schemes: free old damon_sysfs_scheme_filter->memcg_path on write
  mm/alloc_tag: fix the kmemleak false positive issue in the allocation of the percpu variable tag->counters
  lib/group_cpus: fix NULL pointer dereference from group_cpus_evenly()
  mm/hugetlb: remove unnecessary holding of hugetlb_lock
  MAINTAINERS: add missing files to mm page alloc section
  MAINTAINERS: add tree entry to mm init block
  mm: add OOM killer maintainer structure
  fs/proc/task_mmu: fix PAGE_IS_PFNZERO detection for the huge zero folio
```

**Diff:**
```diff
diff --git a/.mailmap b/.mailmap
index 93e94b0b9376..b0ace71968ab 100644
--- a/.mailmap
+++ b/.mailmap
@@ -224,6 +224,7 @@ Dmitry Safonov <0x7f454c46@gmail.com> <dsafonov@virtuozzo.com>
 Domen Puncer <domen@coderock.org>
 Douglas Gilbert <dougg@torque.net>
 Drew Fustini <fustini@kernel.org> <drew@pdp7.com>
+<duje@dujemihanovic.xyz> <duje.mihanovic@skole.hr>
 Ed L. Cashin <ecashin@coraid.com>
 Elliot Berman <quic_eberman@quicinc.com> <eberman@codeaurora.org>
 Enric Balletbo i Serra <eballetbo@kernel.org> <enric.balletbo@collabora.com>
@@ -831,3 +832,6 @@ Yosry Ahmed <yosry.ahmed@linux.dev> <yosryahmed@google.com>
 Yusuke Goda <goda.yusuke@renesas.com>
 Zack Rusin <zack.rusin@broadcom.com> <zackr@vmware.com>
 Zhu Yanjun <zyjzyj2000@gmail.com> <yanjunz@nvidia.com>
+Zijun Hu <zijun.hu@oss.qualcomm.com> <quic_zijuhu@quicinc.com>
+Zijun Hu <zijun.hu@oss.qualcomm.com> <zijuhu@codeaurora.org>
+Zijun Hu <zijun_hu@htc.com>
diff --git a/MAINTAINERS b/MAINTAINERS
index 0fbfe93ba9f2..7aff9b0ead32 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -15676,6 +15676,8 @@ MEMBLOCK AND MEMORY MANAGEMENT INITIALIZATION
 M:	Mike Rapoport <rppt@kernel.org>
 L:	linux-mm@kvack.org
 S:	Maintained
+T:	git git://git.kernel.org/pub/scm/linux/kernel/git/rppt/memblock.git for-next
+T:	git git://git.kernel.org/pub/scm/linux/kernel/git/rppt/memblock.git fixes
 F:	Documentation/core-api/boot-time-mm.rst
 F:	Documentation/core-api/kho/bindings/memblock/*
 F:	include/linux/memblock.h
@@ -15848,6 +15850,17 @@ F:	mm/numa.c
 F:	mm/numa_emulation.c
 F:	mm/numa_memblks.c
 
+MEMORY MANAGEMENT - OOM KILLER
+M:	Michal Hocko <mhocko@suse.com>
+R:	David Rientjes <rientjes@google.com>
+R:	Shakeel Butt <shakeel.butt@linux.dev>
+L:	linux-mm@kvack.org
+S:	Maintained
+F:	include/linux/oom.h
+F:	include/trace/events/oom.h
+F:	include/uapi/linux/oom.h
+F:	mm/oom_kill.c
+
 MEMORY MANAGEMENT - PAGE ALLOCATOR
 M:	Andrew Morton <akpm@linux-foundation.org>
 M:	Vlastimil Babka <vbabka@suse.cz>

... (truncated 340 lines)
```

---

## Commit 5: 867b9987

**Author:** Linus Torvalds
**Date:** 2025-06-27 20:22:18
**Files Changed:** arch/riscv/include/asm/pgtable.h, arch/riscv/include/asm/runtime-const.h, arch/riscv/include/asm/uaccess.h, arch/riscv/include/asm/vdso/getrandom.h, arch/riscv/include/asm/vector.h (+4 more)

**Message:**
```
Merge tag 'riscv-for-linus-5.16-rc4' of git://git.kernel.org/pub/scm/linux/kernel/git/riscv/linux

Pull RISC-V Fixes for 5.16-rc4

 - .rodata is no longer linkd into PT_DYNAMIC.

   It was not supposed to be there in the first place and resulted in
   invalid (but unused) entries. This manifests as at least warnings in
   llvm-readelf

 - A fix for runtime constants with all-0 upper 32-bits. This should
   only manifest on MMU=n kernels

 - A fix for context save/restore on systems using the T-Head vector
   extensions

 - A fix for a conflicting "+r"/"r" register constraint in the VDSO
   getrandom syscall wrapper, which is undefined behavior in clang

 - A fix for a missing register clobber in the RVV raid6 implementation.

   This manifests as a NULL pointer reference on some compilers, but
   could trigger in other ways

 - Misaligned accesses from userspace at faulting addresses are now
   handled correctly

 - A fix for an incorrect optimization that allowed access_ok() to mark
   invalid addresses as accessible, which can result in userspace
   triggering BUG()s

 - A few fixes for build warnings, and an update to Drew's email address

* tag 'riscv-for-linus-5.16-rc4' of git://git.kernel.org/pub/scm/linux/kernel/git/riscv/linux:
  riscv: export boot_cpu_hartid
  Revert "riscv: Define TASK_SIZE_MAX for __access_ok()"
  riscv: Fix sparse warning in vendor_extensions/sifive.c
  Revert "riscv: misaligned: fix sleeping function called during misaligned access handling"
  MAINTAINERS: Update Drew Fustini's email address
  RISC-V: uaccess: Wrap the get_user_8 uaccess macro
  raid6: riscv: Fix NULL pointer dereference caused by a missing clobber
  RISC-V: vDSO: Correct inline assembly constraints in the getrandom syscall wrapper
  riscv: vector: Fix context save/restore with xtheadvector
  riscv: fix runtime constant support for nommu kernels
  riscv: vdso: Exclude .rodata from the PT_DYNAMIC segment
```

**Diff:**
```diff
diff --git a/.mailmap b/.mailmap
index d57531dab08b..93e94b0b9376 100644
--- a/.mailmap
+++ b/.mailmap
@@ -223,6 +223,7 @@ Dmitry Safonov <0x7f454c46@gmail.com> <d.safonov@partner.samsung.com>
 Dmitry Safonov <0x7f454c46@gmail.com> <dsafonov@virtuozzo.com>
 Domen Puncer <domen@coderock.org>
 Douglas Gilbert <dougg@torque.net>
+Drew Fustini <fustini@kernel.org> <drew@pdp7.com>
 Ed L. Cashin <ecashin@coraid.com>
 Elliot Berman <quic_eberman@quicinc.com> <eberman@codeaurora.org>
 Enric Balletbo i Serra <eballetbo@kernel.org> <enric.balletbo@collabora.com>
diff --git a/MAINTAINERS b/MAINTAINERS
index efb51ee92683..0fbfe93ba9f2 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -21388,7 +21388,7 @@ N:	spacemit
 K:	spacemit
 
 RISC-V THEAD SoC SUPPORT
-M:	Drew Fustini <drew@pdp7.com>
+M:	Drew Fustini <fustini@kernel.org>
 M:	Guo Ren <guoren@kernel.org>
 M:	Fu Wei <wefu@redhat.com>
 L:	linux-riscv@lists.infradead.org
diff --git a/arch/riscv/include/asm/pgtable.h b/arch/riscv/include/asm/pgtable.h
index 438ce7df24c3..5bd5aae60d53 100644
--- a/arch/riscv/include/asm/pgtable.h
+++ b/arch/riscv/include/asm/pgtable.h
@@ -1075,7 +1075,6 @@ static inline pte_t pte_swp_clear_exclusive(pte_t pte)
  */
 #ifdef CONFIG_64BIT
 #define TASK_SIZE_64	(PGDIR_SIZE * PTRS_PER_PGD / 2)
-#define TASK_SIZE_MAX	LONG_MAX
 
 #ifdef CONFIG_COMPAT
 #define TASK_SIZE_32	(_AC(0x80000000, UL) - PAGE_SIZE)
diff --git a/arch/riscv/include/asm/runtime-const.h b/arch/riscv/include/asm/runtime-const.h
index 451fd76b8811..d766e2b9e6df 100644
--- a/arch/riscv/include/asm/runtime-const.h
+++ b/arch/riscv/include/asm/runtime-const.h
@@ -206,7 +206,7 @@ static inline void __runtime_fixup_32(__le16 *lui_parcel, __le16 *addi_parcel, u
 		addi_insn_mask &= 0x07fff;
 	}
 
-	if (lower_immediate & 0x00000fff) {
+	if (lower_immediate & 0x00000fff || lui_insn == RISCV_INSN_NOP4) {
 		/* replace upper 12 bits of addi with lower 12 bits of val */
 		addi_insn &= addi_insn_mask;
 		addi_insn |= (lower_immediate & 0x00000fff) << 20;

... (truncated 304 lines)
```

---

