# Linux Kernel Commit Batch Analysis

## Commit 1: 2dbae28a

**Author:** Linus Torvalds
**Date:** 2025-07-08 12:22:16
**Files Changed:** include/uapi/linux/bits.h, tools/include/uapi/linux/bits.h

**Message:**
```
Merge tag 'bitmap-for-6.16-rc6' of https://github.com/norov/linux

Pull bitops UAPI fix from Yury Norov:
 "Fix BITS_PER_LONG merge error

  Tomas' fix for __BITS_PER_LONG was effectively reverted by a wrong
  merge. Fix it and add the related files to MAINTAINERS"

* tag 'bitmap-for-6.16-rc6' of https://github.com/norov/linux:
  MAINTAINERS: bitmap: add UAPI headers
  uapi: bitops: use UAPI-safe variant of BITS_PER_LONG again (2)
```

**Diff:**
```diff
diff --git a/MAINTAINERS b/MAINTAINERS
index 1ff244fe3e1a..2b8d9e608829 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -4181,6 +4181,7 @@ F:	include/linux/cpumask_types.h
 F:	include/linux/find.h
 F:	include/linux/nodemask.h
 F:	include/linux/nodemask_types.h
+F:	include/uapi/linux/bits.h
 F:	include/vdso/bits.h
 F:	lib/bitmap-str.c
 F:	lib/bitmap.c
@@ -4193,6 +4194,7 @@ F:	tools/include/linux/bitfield.h
 F:	tools/include/linux/bitmap.h
 F:	tools/include/linux/bits.h
 F:	tools/include/linux/find.h
+F:	tools/include/uapi/linux/bits.h
 F:	tools/include/vdso/bits.h
 F:	tools/lib/bitmap.c
 F:	tools/lib/find_bit.c
diff --git a/include/uapi/linux/bits.h b/include/uapi/linux/bits.h
index 682b406e1067..a04afef9efca 100644
--- a/include/uapi/linux/bits.h
+++ b/include/uapi/linux/bits.h
@@ -4,9 +4,9 @@
 #ifndef _UAPI_LINUX_BITS_H
 #define _UAPI_LINUX_BITS_H
 
-#define __GENMASK(h, l) (((~_UL(0)) << (l)) & (~_UL(0) >> (BITS_PER_LONG - 1 - (h))))
+#define __GENMASK(h, l) (((~_UL(0)) << (l)) & (~_UL(0) >> (__BITS_PER_LONG - 1 - (h))))
 
-#define __GENMASK_ULL(h, l) (((~_ULL(0)) << (l)) & (~_ULL(0) >> (BITS_PER_LONG_LONG - 1 - (h))))
+#define __GENMASK_ULL(h, l) (((~_ULL(0)) << (l)) & (~_ULL(0) >> (__BITS_PER_LONG_LONG - 1 - (h))))
 
 #define __GENMASK_U128(h, l) \
 	((_BIT128((h)) << 1) - (_BIT128(l)))
diff --git a/tools/include/uapi/linux/bits.h b/tools/include/uapi/linux/bits.h
index 682b406e1067..a04afef9efca 100644
--- a/tools/include/uapi/linux/bits.h
+++ b/tools/include/uapi/linux/bits.h
@@ -4,9 +4,9 @@
 #ifndef _UAPI_LINUX_BITS_H
 #define _UAPI_LINUX_BITS_H
 
-#define __GENMASK(h, l) (((~_UL(0)) << (l)) & (~_UL(0) >> (BITS_PER_LONG - 1 - (h))))
+#define __GENMASK(h, l) (((~_UL(0)) << (l)) & (~_UL(0) >> (__BITS_PER_LONG - 1 - (h))))
 
-#define __GENMASK_ULL(h, l) (((~_ULL(0)) << (l)) & (~_ULL(0) >> (BITS_PER_LONG_LONG - 1 - (h))))
+#define __GENMASK_ULL(h, l) (((~_ULL(0)) << (l)) & (~_ULL(0) >> (__BITS_PER_LONG_LONG - 1 - (h))))
 

... (truncated 2 lines)
```

---

## Commit 2: 570db4b3

**Author:** Sebastian Andrzej Siewior
**Date:** 2025-07-08 20:52:30
**Files Changed:** kernel/module/main.c

**Message:**
```
module: Make sure relocations are applied to the per-CPU section

The per-CPU data section is handled differently than the other sections.
The memory allocations requires a special __percpu pointer and then the
section is copied into the view of each CPU. Therefore the SHF_ALLOC
flag is removed to ensure move_module() skips it.

Later, relocations are applied and apply_relocations() skips sections
without SHF_ALLOC because they have not been copied. This also skips the
per-CPU data section.
The missing relocations result in a NULL pointer on x86-64 and very
small values on x86-32. This results in a crash because it is not
skipped like NULL pointer would and can't be dereferenced.

Such an assignment happens during static per-CPU lock initialisation
with lockdep enabled.

Allow relocation processing for the per-CPU section even if SHF_ALLOC is
missing.

Reported-by: kernel test robot <oliver.sang@intel.com>
Closes: https://lore.kernel.org/oe-lkp/202506041623.e45e4f7d-lkp@intel.com
Fixes: 1a6100caae425 ("Don't relocate non-allocated regions in modules.") #v2.6.1-rc3
Signed-off-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Reviewed-by: Petr Pavlu <petr.pavlu@suse.com>
Link: https://lore.kernel.org/r/20250610163328.URcsSUC1@linutronix.de
Signed-off-by: Daniel Gomez <da.gomez@samsung.com>
Message-ID: <20250610163328.URcsSUC1@linutronix.de>
```

**Diff:**
```diff
diff --git a/kernel/module/main.c b/kernel/module/main.c
index 7822b91fca6b..c2c08007029d 100644
--- a/kernel/module/main.c
+++ b/kernel/module/main.c
@@ -1573,8 +1573,14 @@ static int apply_relocations(struct module *mod, const struct load_info *info)
 		if (infosec >= info->hdr->e_shnum)
 			continue;
 
-		/* Don't bother with non-allocated sections */
-		if (!(info->sechdrs[infosec].sh_flags & SHF_ALLOC))
+		/*
+		 * Don't bother with non-allocated sections.
+		 * An exception is the percpu section, which has separate allocations
+		 * for individual CPUs. We relocate the percpu section in the initial
+		 * ELF template and subsequently copy it to the per-CPU destinations.
+		 */
+		if (!(info->sechdrs[infosec].sh_flags & SHF_ALLOC) &&
+		    (!infosec || infosec != info->index.pcpu))
 			continue;
 
 		if (info->sechdrs[i].sh_flags & SHF_RELA_LIVEPATCH)
```

---

## Commit 3: ca3881f6

**Author:** Petr Pavlu
**Date:** 2025-07-08 20:52:29
**Files Changed:** kernel/module/main.c

**Message:**
```
module: Fix memory deallocation on error path in move_module()

The function move_module() uses the variable t to track how many memory
types it has allocated and consequently how many should be freed if an
error occurs.

The variable is initially set to 0 and is updated when a call to
module_memory_alloc() fails. However, move_module() can fail for other
reasons as well, in which case t remains set to 0 and no memory is freed.

Fix the problem by initializing t to MOD_MEM_NUM_TYPES. Additionally, make
the deallocation loop more robust by not relying on the mod_mem_type_t enum
having a signed integer as its underlying type.

Fixes: c7ee8aebf6c0 ("module: add stop-grap sanity check on module memcpy()")
Signed-off-by: Petr Pavlu <petr.pavlu@suse.com>
Reviewed-by: Sami Tolvanen <samitolvanen@google.com>
Reviewed-by: Daniel Gomez <da.gomez@samsung.com>
Link: https://lore.kernel.org/r/20250618122730.51324-2-petr.pavlu@suse.com
Signed-off-by: Daniel Gomez <da.gomez@samsung.com>
Message-ID: <20250618122730.51324-2-petr.pavlu@suse.com>
```

**Diff:**
```diff
diff --git a/kernel/module/main.c b/kernel/module/main.c
index 413ac6ea3702..9ac994b2f354 100644
--- a/kernel/module/main.c
+++ b/kernel/module/main.c
@@ -2697,7 +2697,7 @@ static int find_module_sections(struct module *mod, struct load_info *info)
 static int move_module(struct module *mod, struct load_info *info)
 {
 	int i;
-	enum mod_mem_type t = 0;
+	enum mod_mem_type t = MOD_MEM_NUM_TYPES;
 	int ret = -ENOMEM;
 	bool codetag_section_found = false;
 
@@ -2776,7 +2776,7 @@ static int move_module(struct module *mod, struct load_info *info)
 	return 0;
 out_err:
 	module_memory_restore_rox(mod);
-	for (t--; t >= 0; t--)
+	while (t--)
 		module_memory_free(mod, t);
 	if (codetag_section_found)
 		codetag_free_module_sections(mod);
```

---

## Commit 4: 50f930db

**Author:** Namjae Jeon
**Date:** 2025-07-08 11:25:44
**Files Changed:** fs/smb/server/smb2pdu.c

**Message:**
```
ksmbd: fix potential use-after-free in oplock/lease break ack

If ksmbd_iov_pin_rsp return error, use-after-free can happen by
accessing opinfo->state and opinfo_put and ksmbd_fd_put could
called twice.

Reported-by: Ziyan Xu <research@securitygossip.com>
Signed-off-by: Namjae Jeon <linkinjeon@kernel.org>
Signed-off-by: Steve French <stfrench@microsoft.com>
```

**Diff:**
```diff
diff --git a/fs/smb/server/smb2pdu.c b/fs/smb/server/smb2pdu.c
index fafa86273f12..63d17cea2e95 100644
--- a/fs/smb/server/smb2pdu.c
+++ b/fs/smb/server/smb2pdu.c
@@ -8573,11 +8573,6 @@ static void smb20_oplock_break_ack(struct ksmbd_work *work)
 		goto err_out;
 	}
 
-	opinfo->op_state = OPLOCK_STATE_NONE;
-	wake_up_interruptible_all(&opinfo->oplock_q);
-	opinfo_put(opinfo);
-	ksmbd_fd_put(work, fp);
-
 	rsp->StructureSize = cpu_to_le16(24);
 	rsp->OplockLevel = rsp_oplevel;
 	rsp->Reserved = 0;
@@ -8585,16 +8580,15 @@ static void smb20_oplock_break_ack(struct ksmbd_work *work)
 	rsp->VolatileFid = volatile_id;
 	rsp->PersistentFid = persistent_id;
 	ret = ksmbd_iov_pin_rsp(work, rsp, sizeof(struct smb2_oplock_break));
-	if (!ret)
-		return;
-
+	if (ret) {
 err_out:
+		smb2_set_err_rsp(work);
+	}
+
 	opinfo->op_state = OPLOCK_STATE_NONE;
 	wake_up_interruptible_all(&opinfo->oplock_q);
-
 	opinfo_put(opinfo);
 	ksmbd_fd_put(work, fp);
-	smb2_set_err_rsp(work);
 }
 
 static int check_lease_state(struct lease *lease, __le32 req_state)
@@ -8724,11 +8718,6 @@ static void smb21_lease_break_ack(struct ksmbd_work *work)
 	}
 
 	lease_state = lease->state;
-	opinfo->op_state = OPLOCK_STATE_NONE;
-	wake_up_interruptible_all(&opinfo->oplock_q);
-	atomic_dec(&opinfo->breaking_cnt);
-	wake_up_interruptible_all(&opinfo->oplock_brk);
-	opinfo_put(opinfo);
 
 	rsp->StructureSize = cpu_to_le16(36);
 	rsp->Reserved = 0;
@@ -8737,16 +8726,16 @@ static void smb21_lease_break_ack(struct ksmbd_work *work)

... (truncated 21 lines)
```

---

## Commit 5: 277627b4

**Author:** Al Viro
**Date:** 2025-07-08 11:25:44
**Files Changed:** fs/smb/server/vfs.c

**Message:**
```
ksmbd: fix a mount write count leak in ksmbd_vfs_kern_path_locked()

If the call of ksmbd_vfs_lock_parent() fails, we drop the parent_path
references and return an error.  We need to drop the write access we
just got on parent_path->mnt before we drop the mount reference - callers
assume that ksmbd_vfs_kern_path_locked() returns with mount write
access grabbed if and only if it has returned 0.

Fixes: 864fb5d37163 ("ksmbd: fix possible deadlock in smb2_open")
Signed-off-by: Al Viro <viro@zeniv.linux.org.uk>
Acked-by: Namjae Jeon <linkinjeon@kernel.org>
Signed-off-by: Steve French <stfrench@microsoft.com>
```

**Diff:**
```diff
diff --git a/fs/smb/server/vfs.c b/fs/smb/server/vfs.c
index 0f3aad12e495..d3437f6644e3 100644
--- a/fs/smb/server/vfs.c
+++ b/fs/smb/server/vfs.c
@@ -1282,6 +1282,7 @@ int ksmbd_vfs_kern_path_locked(struct ksmbd_work *work, char *name,
 
 		err = ksmbd_vfs_lock_parent(parent_path->dentry, path->dentry);
 		if (err) {
+			mnt_drop_write(parent_path->mnt);
 			path_put(path);
 			path_put(parent_path);
 		}
```

---

