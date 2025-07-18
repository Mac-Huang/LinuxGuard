# Linux Kernel Commit Batch Analysis

## Commit 1: cbe4134e

**Author:** Shivank Garg
**Date:** 2025-06-23 12:41:17
**Files Changed:** fs/anon_inodes.c, include/linux/fs.h, mm/secretmem.c

**Message:**
```
fs: export anon_inode_make_secure_inode() and fix secretmem LSM bypass

Export anon_inode_make_secure_inode() to allow KVM guest_memfd to create
anonymous inodes with proper security context. This replaces the current
pattern of calling alloc_anon_inode() followed by
inode_init_security_anon() for creating security context manually.

This change also fixes a security regression in secretmem where the
S_PRIVATE flag was not cleared after alloc_anon_inode(), causing
LSM/SELinux checks to be bypassed for secretmem file descriptors.

As guest_memfd currently resides in the KVM module, we need to export this
symbol for use outside the core kernel. In the future, guest_memfd might be
moved to core-mm, at which point the symbols no longer would have to be
exported. When/if that happens is still unclear.

Fixes: 2bfe15c52612 ("mm: create security context for memfd_secret inodes")
Suggested-by: David Hildenbrand <david@redhat.com>
Suggested-by: Mike Rapoport <rppt@kernel.org>
Signed-off-by: Shivank Garg <shivankg@amd.com>
Link: https://lore.kernel.org/20250620070328.803704-3-shivankg@amd.com
Acked-by: "Mike Rapoport (Microsoft)" <rppt@kernel.org>
Signed-off-by: Christian Brauner <brauner@kernel.org>
```

**Diff:**
```diff
diff --git a/fs/anon_inodes.c b/fs/anon_inodes.c
index e51e7d88980a..1d847a939f29 100644
--- a/fs/anon_inodes.c
+++ b/fs/anon_inodes.c
@@ -98,14 +98,25 @@ static struct file_system_type anon_inode_fs_type = {
 	.kill_sb	= kill_anon_super,
 };
 
-static struct inode *anon_inode_make_secure_inode(
-	const char *name,
-	const struct inode *context_inode)
+/**
+ * anon_inode_make_secure_inode - allocate an anonymous inode with security context
+ * @sb:		[in]	Superblock to allocate from
+ * @name:	[in]	Name of the class of the newfile (e.g., "secretmem")
+ * @context_inode:
+ *		[in]	Optional parent inode for security inheritance
+ *
+ * The function ensures proper security initialization through the LSM hook
+ * security_inode_init_security_anon().
+ *
+ * Return:	Pointer to new inode on success, ERR_PTR on failure.
+ */
+struct inode *anon_inode_make_secure_inode(struct super_block *sb, const char *name,
+					   const struct inode *context_inode)
 {
 	struct inode *inode;
 	int error;
 
-	inode = alloc_anon_inode(anon_inode_mnt->mnt_sb);
+	inode = alloc_anon_inode(sb);
 	if (IS_ERR(inode))
 		return inode;
 	inode->i_flags &= ~S_PRIVATE;
@@ -118,6 +129,7 @@ static struct inode *anon_inode_make_secure_inode(
 	}
 	return inode;
 }
+EXPORT_SYMBOL_GPL_FOR_MODULES(anon_inode_make_secure_inode, "kvm");
 
 static struct file *__anon_inode_getfile(const char *name,
 					 const struct file_operations *fops,
@@ -132,7 +144,8 @@ static struct file *__anon_inode_getfile(const char *name,
 		return ERR_PTR(-ENOENT);
 
 	if (make_inode) {
-		inode =	anon_inode_make_secure_inode(name, context_inode);
+		inode =	anon_inode_make_secure_inode(anon_inode_mnt->mnt_sb,
+						     name, context_inode);
 		if (IS_ERR(inode)) {

... (truncated 39 lines)
```

---

## Commit 2: b993ea46

**Author:** Eric Dumazet
**Date:** 2025-06-22 19:31:14
**Files Changed:** net/atm/clip.c

**Message:**
```
atm: clip: prevent NULL deref in clip_push()

Blamed commit missed that vcc_destroy_socket() calls
clip_push() with a NULL skb.

If clip_devs is NULL, clip_push() then crashes when reading
skb->truesize.

Fixes: 93a2014afbac ("atm: fix a UAF in lec_arp_clear_vccs()")
Reported-by: syzbot+1316233c4c6803382a8b@syzkaller.appspotmail.com
Closes: https://lore.kernel.org/netdev/68556f59.a00a0220.137b3.004e.GAE@google.com/T/#u
Signed-off-by: Eric Dumazet <edumazet@google.com>
Cc: Cong Wang <xiyou.wangcong@gmail.com>
Cc: Gengming Liu <l.dmxcsnsbh@gmail.com>
Reviewed-by: Simon Horman <horms@kernel.org>
Signed-off-by: David S. Miller <davem@davemloft.net>
```

**Diff:**
```diff
diff --git a/net/atm/clip.c b/net/atm/clip.c
index 61b5b700817d..b234dc3bcb0d 100644
--- a/net/atm/clip.c
+++ b/net/atm/clip.c
@@ -193,12 +193,6 @@ static void clip_push(struct atm_vcc *vcc, struct sk_buff *skb)
 
 	pr_debug("\n");
 
-	if (!clip_devs) {
-		atm_return(vcc, skb->truesize);
-		kfree_skb(skb);
-		return;
-	}
-
 	if (!skb) {
 		pr_debug("removing VCC %p\n", clip_vcc);
 		if (clip_vcc->entry)
@@ -208,6 +202,11 @@ static void clip_push(struct atm_vcc *vcc, struct sk_buff *skb)
 		return;
 	}
 	atm_return(vcc, skb->truesize);
+	if (!clip_devs) {
+		kfree_skb(skb);
+		return;
+	}
+
 	skb->dev = clip_vcc->entry ? clip_vcc->entry->neigh->dev : clip_devs;
 	/* clip_vcc->entry == NULL if we don't have an IP address yet */
 	if (!skb->dev) {
```

---

## Commit 3: 5c00eca9

**Author:** Linus Torvalds
**Date:** 2025-06-22 10:30:44
**Files Changed:** arch/x86/kernel/alternative.c, arch/x86/kernel/cpu/amd.c, arch/x86/kernel/cpu/resctrl/core.c, arch/x86/mm/pti.c, fs/resctrl/ctrlmondata.c (+4 more)

**Message:**
```
Merge tag 'x86_urgent_for_v6.16_rc3' of git://git.kernel.org/pub/scm/linux/kernel/git/tip/tip

Pull x86 fixes from Borislav Petkov:

 - Make sure the array tracking which kernel text positions need to be
   alternatives-patched doesn't get mishandled by out-of-order
   modifications, leading to it overflowing and causing page faults when
   patching

 - Avoid an infinite loop when early code does a ranged TLB invalidation
   before the broadcast TLB invalidation count of how many pages it can
   flush, has been read from CPUID

 - Fix a CONFIG_MODULES typo

 - Disable broadcast TLB invalidation when PTI is enabled to avoid an
   overflow of the bitmap tracking dynamic ASIDs which need to be
   flushed when the kernel switches between the user and kernel address
   space

 - Handle the case of a CPU going offline and thus reporting zeroes when
   reading top-level events in the resctrl code

* tag 'x86_urgent_for_v6.16_rc3' of git://git.kernel.org/pub/scm/linux/kernel/git/tip/tip:
  x86/alternatives: Fix int3 handling failure from broken text_poke array
  x86/mm: Fix early boot use of INVPLGB
  x86/its: Fix an ifdef typo in its_alloc()
  x86/mm: Disable INVLPGB when PTI is enabled
  x86,fs/resctrl: Remove inappropriate references to cacheinfo in the resctrl subsystem
```

**Diff:**
```diff
diff --git a/arch/x86/kernel/alternative.c b/arch/x86/kernel/alternative.c
index 6455f7f751b3..ea1d984166cd 100644
--- a/arch/x86/kernel/alternative.c
+++ b/arch/x86/kernel/alternative.c
@@ -228,7 +228,7 @@ static void *its_alloc(void)
 	struct its_array *pages = &its_pages;
 	void *page;
 
-#ifdef CONFIG_MODULE
+#ifdef CONFIG_MODULES
 	if (its_mod)
 		pages = &its_mod->arch.its_pages;
 #endif
@@ -3138,6 +3138,6 @@ void __ref smp_text_poke_batch_add(void *addr, const void *opcode, size_t len, c
  */
 void __ref smp_text_poke_single(void *addr, const void *opcode, size_t len, const void *emulate)
 {
-	__smp_text_poke_batch_add(addr, opcode, len, emulate);
+	smp_text_poke_batch_add(addr, opcode, len, emulate);
 	smp_text_poke_batch_finish();
 }
diff --git a/arch/x86/kernel/cpu/amd.c b/arch/x86/kernel/cpu/amd.c
index 93da466dfe2c..b2ad8d13211a 100644
--- a/arch/x86/kernel/cpu/amd.c
+++ b/arch/x86/kernel/cpu/amd.c
@@ -31,7 +31,7 @@
 
 #include "cpu.h"
 
-u16 invlpgb_count_max __ro_after_init;
+u16 invlpgb_count_max __ro_after_init = 1;
 
 static inline int rdmsrq_amd_safe(unsigned msr, u64 *p)
 {
diff --git a/arch/x86/kernel/cpu/resctrl/core.c b/arch/x86/kernel/cpu/resctrl/core.c
index 7109cbfcad4f..187d527ef73b 100644
--- a/arch/x86/kernel/cpu/resctrl/core.c
+++ b/arch/x86/kernel/cpu/resctrl/core.c
@@ -498,6 +498,7 @@ static void domain_add_cpu_mon(int cpu, struct rdt_resource *r)
 	struct rdt_hw_mon_domain *hw_dom;
 	struct rdt_domain_hdr *hdr;
 	struct rdt_mon_domain *d;
+	struct cacheinfo *ci;
 	int err;
 
 	lockdep_assert_held(&domain_list_lock);
@@ -525,12 +526,13 @@ static void domain_add_cpu_mon(int cpu, struct rdt_resource *r)
 	d = &hw_dom->d_resctrl;
 	d->hdr.id = id;
 	d->hdr.type = RESCTRL_MON_DOMAIN;

... (truncated 168 lines)
```

---

## Commit 4: 17ef32ae

**Author:** Linus Torvalds
**Date:** 2025-06-22 10:11:45
**Files Changed:** arch/x86/events/intel/core.c, include/linux/perf_event.h, kernel/events/core.c, kernel/exit.c

**Message:**
```
Merge tag 'perf_urgent_for_v6.16_rc3' of git://git.kernel.org/pub/scm/linux/kernel/git/tip/tip

Pull perf fixes from Borislav Petkov:

 - Avoid a crash on a heterogeneous machine where not all cores support
   the same hw events features

 - Avoid a deadlock when throttling events

 - Document the perf event states more

 - Make sure a number of perf paths switching off or rescheduling events
   call perf_cgroup_event_disable()

 - Make sure perf does task sampling before its userspace mapping is
   torn down, and not after

* tag 'perf_urgent_for_v6.16_rc3' of git://git.kernel.org/pub/scm/linux/kernel/git/tip/tip:
  perf/x86/intel: Fix crash in icl_update_topdown_event()
  perf: Fix the throttle error of some clock events
  perf: Add comment to enum perf_event_state
  perf/core: Fix WARN in perf_cgroup_switch()
  perf: Fix dangling cgroup pointer in cpuctx
  perf: Fix cgroup state vs ERROR
  perf: Fix sample vs do_exit()
```

**Diff:**
```diff
diff --git a/arch/x86/events/intel/core.c b/arch/x86/events/intel/core.c
index 741b229f0718..c2fb729c270e 100644
--- a/arch/x86/events/intel/core.c
+++ b/arch/x86/events/intel/core.c
@@ -2826,7 +2826,7 @@ static void intel_pmu_read_event(struct perf_event *event)
 		 * If the PEBS counters snapshotting is enabled,
 		 * the topdown event is available in PEBS records.
 		 */
-		if (is_topdown_event(event) && !is_pebs_counter_event_group(event))
+		if (is_topdown_count(event) && !is_pebs_counter_event_group(event))
 			static_call(intel_pmu_update_topdown_event)(event, NULL);
 		else
 			intel_pmu_drain_pebs_buffer();
diff --git a/include/linux/perf_event.h b/include/linux/perf_event.h
index 52dc7cfab0e0..ec9d96025683 100644
--- a/include/linux/perf_event.h
+++ b/include/linux/perf_event.h
@@ -635,8 +635,46 @@ struct perf_addr_filter_range {
 	unsigned long			size;
 };
 
-/**
- * enum perf_event_state - the states of an event:
+/*
+ * The normal states are:
+ *
+ *            ACTIVE    --.
+ *               ^        |
+ *               |        |
+ *       sched_{in,out}() |
+ *               |        |
+ *               v        |
+ *      ,---> INACTIVE  --+ <-.
+ *      |                 |   |
+ *      |                {dis,en}able()
+ *   sched_in()           |   |
+ *      |       OFF    <--' --+
+ *      |                     |
+ *      `--->  ERROR    ------'
+ *
+ * That is:
+ *
+ * sched_in:       INACTIVE          -> {ACTIVE,ERROR}
+ * sched_out:      ACTIVE            -> INACTIVE
+ * disable:        {ACTIVE,INACTIVE} -> OFF
+ * enable:         {OFF,ERROR}       -> INACTIVE
+ *
+ * Where {OFF,ERROR} are disabled states.
+ *
+ * Then we have the {EXIT,REVOKED,DEAD} states which are various shades of

... (truncated 297 lines)
```

---

## Commit 5: 73543bad

**Author:** Linus Torvalds
**Date:** 2025-06-22 10:05:33
**Files Changed:** drivers/edac/amd64_edac.c, drivers/edac/igen6_edac.c

**Message:**
```
Merge tag 'edac_urgent_for_v6.16_rc3' of git://git.kernel.org/pub/scm/linux/kernel/git/ras/ras

Pull EDAC fixes from Borislav Petkov:

 - amd64: Correct the number of memory controllers on some AMD Zen
   clients

 - igen6: Handle firmware-disabled memory controllers properly

* tag 'edac_urgent_for_v6.16_rc3' of git://git.kernel.org/pub/scm/linux/kernel/git/ras/ras:
  EDAC/igen6: Fix NULL pointer dereference
  EDAC/amd64: Correct number of UMCs for family 19h models 70h-7fh
```

**Diff:**
```diff
diff --git a/drivers/edac/amd64_edac.c b/drivers/edac/amd64_edac.c
index 58b1482a0fbb..b681c0663203 100644
--- a/drivers/edac/amd64_edac.c
+++ b/drivers/edac/amd64_edac.c
@@ -3879,6 +3879,7 @@ static int per_family_init(struct amd64_pvt *pvt)
 			break;
 		case 0x70 ... 0x7f:
 			pvt->ctl_name			= "F19h_M70h";
+			pvt->max_mcs			= 4;
 			pvt->flags.zn_regs_v2		= 1;
 			break;
 		case 0x90 ... 0x9f:
diff --git a/drivers/edac/igen6_edac.c b/drivers/edac/igen6_edac.c
index 1930dc00c791..1cb5c67e78ae 100644
--- a/drivers/edac/igen6_edac.c
+++ b/drivers/edac/igen6_edac.c
@@ -125,7 +125,7 @@
 #define MEM_SLICE_HASH_MASK(v)		(GET_BITFIELD(v, 6, 19) << 6)
 #define MEM_SLICE_HASH_LSB_MASK_BIT(v)	GET_BITFIELD(v, 24, 26)
 
-static const struct res_config {
+static struct res_config {
 	bool machine_check;
 	/* The number of present memory controllers. */
 	int num_imc;
@@ -479,7 +479,7 @@ static u64 rpl_p_err_addr(u64 ecclog)
 	return ECC_ERROR_LOG_ADDR45(ecclog);
 }
 
-static const struct res_config ehl_cfg = {
+static struct res_config ehl_cfg = {
 	.num_imc		= 1,
 	.imc_base		= 0x5000,
 	.ibecc_base		= 0xdc00,
@@ -489,7 +489,7 @@ static const struct res_config ehl_cfg = {
 	.err_addr_to_imc_addr	= ehl_err_addr_to_imc_addr,
 };
 
-static const struct res_config icl_cfg = {
+static struct res_config icl_cfg = {
 	.num_imc		= 1,
 	.imc_base		= 0x5000,
 	.ibecc_base		= 0xd800,
@@ -499,7 +499,7 @@ static const struct res_config icl_cfg = {
 	.err_addr_to_imc_addr	= ehl_err_addr_to_imc_addr,
 };
 
-static const struct res_config tgl_cfg = {
+static struct res_config tgl_cfg = {
 	.machine_check		= true,

... (truncated 69 lines)
```

---

