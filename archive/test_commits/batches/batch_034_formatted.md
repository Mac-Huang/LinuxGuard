# Linux Kernel Commit Batch Analysis

## Commit 1: 9a2b9416

**Author:** Mostafa Saleh
**Date:** 2025-06-26 08:05:04
**Files Changed:** arch/arm64/kvm/arm.c

**Message:**
```
KVM: arm64: Fix error path in init_hyp_mode()

In the unlikely case pKVM failed to allocate carveout, the error path
tries to access NULL ptr when it de-reference the SVE state from the
uninitialized nVHE per-cpu base.

[    1.575420] pstate: 61400005 (nZCv daif +PAN -UAO -TCO +DIT -SSBS BTYPE=--)
[    1.576010] pc : teardown_hyp_mode+0xe4/0x180
[    1.576920] lr : teardown_hyp_mode+0xd0/0x180
[    1.577308] sp : ffff8000826fb9d0
[    1.577600] x29: ffff8000826fb9d0 x28: 0000000000000000 x27: ffff80008209b000
[    1.578383] x26: ffff800081dde000 x25: ffff8000820493c0 x24: ffff80008209eb00
[    1.579180] x23: 0000000000000040 x22: 0000000000000001 x21: 0000000000000000
[    1.579881] x20: 0000000000000002 x19: ffff800081d540b8 x18: 0000000000000000
[    1.580544] x17: ffff800081205230 x16: 0000000000000152 x15: 00000000fffffff8
[    1.581183] x14: 0000000000000008 x13: fff00000ff7f6880 x12: 000000000000003e
[    1.581813] x11: 0000000000000002 x10: 00000000000000ff x9 : 0000000000000000
[    1.582503] x8 : 0000000000000000 x7 : 7f7f7f7f7f7f7f7f x6 : 43485e525851ff30
[    1.583140] x5 : fff00000ff6e9030 x4 : fff00000ff6e8f80 x3 : 0000000000000000
[    1.583780] x2 : 0000000000000000 x1 : 0000000000000002 x0 : 0000000000000000
[    1.584526] Call trace:
[    1.584945]  teardown_hyp_mode+0xe4/0x180 (P)
[    1.585578]  init_hyp_mode+0x920/0x994
[    1.586005]  kvm_arm_init+0xb4/0x25c
[    1.586387]  do_one_initcall+0xe0/0x258
[    1.586819]  do_initcall_level+0xa0/0xd4
[    1.587224]  do_initcalls+0x54/0x94
[    1.587606]  do_basic_setup+0x1c/0x28
[    1.587998]  kernel_init_freeable+0xc8/0x130
[    1.588409]  kernel_init+0x20/0x1a4
[    1.588768]  ret_from_fork+0x10/0x20
[    1.589568] Code: f875db48 8b1c0109 f100011f 9a8903e8 (f9463100)
[    1.590332] ---[ end trace 0000000000000000 ]---

As Quentin pointed, the order of free is also wrong, we need to free
SVE state first before freeing the per CPU ptrs.

I initially observed this on 6.12, but I could also repro in master.

Signed-off-by: Mostafa Saleh <smostafa@google.com>
Fixes: 66d5b53e20a6 ("KVM: arm64: Allocate memory mapped at hyp for host sve state in pKVM")
Reviewed-by: Quentin Perret <qperret@google.com>
Link: https://lore.kernel.org/r/20250625123058.875179-1-smostafa@google.com
Signed-off-by: Marc Zyngier <maz@kernel.org>
```

**Diff:**
```diff
diff --git a/arch/arm64/kvm/arm.c b/arch/arm64/kvm/arm.c
index 38a91bb5d4c7..6bdf79bc5d95 100644
--- a/arch/arm64/kvm/arm.c
+++ b/arch/arm64/kvm/arm.c
@@ -2346,7 +2346,9 @@ static void __init teardown_hyp_mode(void)
 	free_hyp_pgds();
 	for_each_possible_cpu(cpu) {
 		free_pages(per_cpu(kvm_arm_hyp_stack_base, cpu), NVHE_STACK_SHIFT - PAGE_SHIFT);
-		free_pages(kvm_nvhe_sym(kvm_arm_hyp_percpu_base)[cpu], nvhe_percpu_order());
+
+		if (!kvm_nvhe_sym(kvm_arm_hyp_percpu_base)[cpu])
+			continue;
 
 		if (free_sve) {
 			struct cpu_sve_state *sve_state;
@@ -2354,6 +2356,9 @@ static void __init teardown_hyp_mode(void)
 			sve_state = per_cpu_ptr_nvhe_sym(kvm_host_data, cpu)->sve_state;
 			free_pages((unsigned long) sve_state, pkvm_host_sve_state_order());
 		}
+
+		free_pages(kvm_nvhe_sym(kvm_arm_hyp_percpu_base)[cpu], nvhe_percpu_order());
+
 	}
 }
 
```

---

## Commit 2: e728e705

**Author:** Quentin Perret
**Date:** 2025-06-26 08:04:43
**Files Changed:** arch/arm64/kvm/hyp/nvhe/mem_protect.c

**Message:**
```
KVM: arm64: Adjust range correctly during host stage-2 faults

host_stage2_adjust_range() tries to find the largest block mapping that
fits within a memory or mmio region (represented by a kvm_mem_range in
this function) during host stage-2 faults under pKVM. To do so, it walks
the host stage-2 page-table, finds the faulting PTE and its level, and
then progressively increments the level until it finds a granule of the
appropriate size. However, the condition in the loop implementing the
above is broken as it checks kvm_level_supports_block_mapping() for the
next level instead of the current, so pKVM may attempt to map a region
larger than can be covered with a single block.

This is not a security problem and is quite rare in practice (the
kvm_mem_range check usually forces host_stage2_adjust_range() to choose a
smaller granule), but this is clearly not the expected behaviour.

Refactor the loop to fix the bug and improve readability.

Fixes: c4f0935e4d95 ("KVM: arm64: Optimize host memory aborts")
Signed-off-by: Quentin Perret <qperret@google.com>
Link: https://lore.kernel.org/r/20250625105548.984572-1-qperret@google.com
Signed-off-by: Marc Zyngier <maz@kernel.org>
```

**Diff:**
```diff
diff --git a/arch/arm64/kvm/hyp/nvhe/mem_protect.c b/arch/arm64/kvm/hyp/nvhe/mem_protect.c
index 95d7534c9679..8957734d6183 100644
--- a/arch/arm64/kvm/hyp/nvhe/mem_protect.c
+++ b/arch/arm64/kvm/hyp/nvhe/mem_protect.c
@@ -479,6 +479,7 @@ static int host_stage2_adjust_range(u64 addr, struct kvm_mem_range *range)
 {
 	struct kvm_mem_range cur;
 	kvm_pte_t pte;
+	u64 granule;
 	s8 level;
 	int ret;
 
@@ -496,18 +497,21 @@ static int host_stage2_adjust_range(u64 addr, struct kvm_mem_range *range)
 		return -EPERM;
 	}
 
-	do {
-		u64 granule = kvm_granule_size(level);
+	for (; level <= KVM_PGTABLE_LAST_LEVEL; level++) {
+		if (!kvm_level_supports_block_mapping(level))
+			continue;
+		granule = kvm_granule_size(level);
 		cur.start = ALIGN_DOWN(addr, granule);
 		cur.end = cur.start + granule;
-		level++;
-	} while ((level <= KVM_PGTABLE_LAST_LEVEL) &&
-			!(kvm_level_supports_block_mapping(level) &&
-			  range_included(&cur, range)));
+		if (!range_included(&cur, range))
+			continue;
+		*range = cur;
+		return 0;
+	}
 
-	*range = cur;
+	WARN_ON(1);
 
-	return 0;
+	return -EINVAL;
 }
 
 int host_stage2_idmap_locked(phys_addr_t addr, u64 size,
```

---

## Commit 3: ee88bddf

**Author:** Linus Torvalds
**Date:** 2025-06-25 21:09:02
**Files Changed:** kernel/bpf/bpf_lru_list.c, kernel/bpf/bpf_lru_list.h, kernel/bpf/cgroup.c, kernel/bpf/verifier.c, tools/lib/bpf/btf_dump.c (+7 more)

**Message:**
```
Merge tag 'bpf-fixes' of git://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf

Pull bpf fixes from Alexei Starovoitov:

 - Fix use-after-free in libbpf when map is resized (Adin Scannell)

 - Fix verifier assumptions about 2nd argument of bpf_sysctl_get_name
   (Jerome Marchand)

 - Fix verifier assumption of nullness of d_inode in dentry (Song Liu)

 - Fix global starvation of LRU map (Willem de Bruijn)

 - Fix potential NULL dereference in btf_dump__free (Yuan Chen)

* tag 'bpf-fixes' of git://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf:
  selftests/bpf: adapt one more case in test_lru_map to the new target_free
  libbpf: Fix possible use-after-free for externs
  selftests/bpf: Convert test_sysctl to prog_tests
  bpf: Specify access type of bpf_sysctl_get_name args
  libbpf: Fix null pointer dereference in btf_dump__free on allocation failure
  bpf: Adjust free target to avoid global starvation of LRU map
  bpf: Mark dentry->d_inode as trusted_or_null
```

**Diff:**
```diff
diff --git a/Documentation/bpf/map_hash.rst b/Documentation/bpf/map_hash.rst
index d2343952f2cb..8606bf958a8c 100644
--- a/Documentation/bpf/map_hash.rst
+++ b/Documentation/bpf/map_hash.rst
@@ -233,10 +233,16 @@ attempts in order to enforce the LRU property which have increasing impacts on
 other CPUs involved in the following operation attempts:
 
 - Attempt to use CPU-local state to batch operations
-- Attempt to fetch free nodes from global lists
+- Attempt to fetch ``target_free`` free nodes from global lists
 - Attempt to pull any node from a global list and remove it from the hashmap
 - Attempt to pull any node from any CPU's list and remove it from the hashmap
 
+The number of nodes to borrow from the global list in a batch, ``target_free``,
+depends on the size of the map. Larger batch size reduces lock contention, but
+may also exhaust the global structure. The value is computed at map init to
+avoid exhaustion, by limiting aggregate reservation by all CPUs to half the map
+size. With a minimum of a single element and maximum budget of 128 at a time.
+
 This algorithm is described visually in the following diagram. See the
 description in commit 3a08c2fd7634 ("bpf: LRU List") for a full explanation of
 the corresponding operations:
diff --git a/Documentation/bpf/map_lru_hash_update.dot b/Documentation/bpf/map_lru_hash_update.dot
index a0fee349d29c..ab10058f5b79 100644
--- a/Documentation/bpf/map_lru_hash_update.dot
+++ b/Documentation/bpf/map_lru_hash_update.dot
@@ -35,18 +35,18 @@ digraph {
   fn_bpf_lru_list_pop_free_to_local [shape=rectangle,fillcolor=2,
     label="Flush local pending,
     Rotate Global list, move
-    LOCAL_FREE_TARGET
+    target_free
     from global -> local"]
   // Also corresponds to:
   // fn__local_list_flush()
   // fn_bpf_lru_list_rotate()
   fn___bpf_lru_node_move_to_free[shape=diamond,fillcolor=2,
-    label="Able to free\nLOCAL_FREE_TARGET\nnodes?"]
+    label="Able to free\ntarget_free\nnodes?"]
 
   fn___bpf_lru_list_shrink_inactive [shape=rectangle,fillcolor=3,
     label="Shrink inactive list
       up to remaining
-      LOCAL_FREE_TARGET
+      target_free
       (global LRU -> local)"]
   fn___bpf_lru_list_shrink [shape=diamond,fillcolor=2,
     label="> 0 entries in\nlocal free list?"]
diff --git a/kernel/bpf/bpf_lru_list.c b/kernel/bpf/bpf_lru_list.c
index 3dabdd137d10..2d6e1c98d8ad 100644

... (truncated 582 lines)
```

---

## Commit 4: 7c942f87

**Author:** Dev Jain
**Date:** 2025-06-25 15:55:04
**Files Changed:** tools/testing/selftests/mm/virtual_address_range.c

**Message:**
```
selftests/mm: fix validate_addr() helper

validate_addr() checks whether the address returned by mmap() lies in the
low or high VA space, according to whether a high addr hint was passed or
not.  The fix commit mentioned below changed the code in such a way that
this function will always return failure when passed high_addr == 1; addr
will be >= HIGH_ADDR_MARK always, we will fall down to "if (addr >
HIGH_ADDR_MARK)" and return failure.  Fix this.

Link: https://lkml.kernel.org/r/20250620111150.50344-1-dev.jain@arm.com
Fixes: d1d86ce28d0f ("selftests/mm: virtual_address_range: conform to TAP format output")
Signed-off-by: Dev Jain <dev.jain@arm.com>
Reviewed-by: Donet Tom <donettom@linux.ibm.com>
Acked-by: David Hildenbrand <david@redhat.com>
Cc: Anshuman Khandual <anshuman.khandual@arm.com>
Cc: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Cc: Ryan Roberts <ryan.roberts@arm.com>
Cc: Shuah Khan <shuah@kernel.org>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
```

**Diff:**
```diff
diff --git a/tools/testing/selftests/mm/virtual_address_range.c b/tools/testing/selftests/mm/virtual_address_range.c
index b380e102b22f..169dbd692bf5 100644
--- a/tools/testing/selftests/mm/virtual_address_range.c
+++ b/tools/testing/selftests/mm/virtual_address_range.c
@@ -77,8 +77,11 @@ static void validate_addr(char *ptr, int high_addr)
 {
 	unsigned long addr = (unsigned long) ptr;
 
-	if (high_addr && addr < HIGH_ADDR_MARK)
-		ksft_exit_fail_msg("Bad address %lx\n", addr);
+	if (high_addr) {
+		if (addr < HIGH_ADDR_MARK)
+			ksft_exit_fail_msg("Bad address %lx\n", addr);
+		return;
+	}
 
 	if (addr > HIGH_ADDR_MARK)
 		ksft_exit_fail_msg("Bad address %lx\n", addr);
```

---

## Commit 5: 4f489fe6

**Author:** SeongJae Park
**Date:** 2025-06-25 15:55:03
**Files Changed:** mm/damon/sysfs-schemes.c

**Message:**
```
mm/damon/sysfs-schemes: free old damon_sysfs_scheme_filter->memcg_path on write

memcg_path_store() assigns a newly allocated memory buffer to
filter->memcg_path, without deallocating the previously allocated and
assigned memory buffer.  As a result, users can leak kernel memory by
continuously writing a data to memcg_path DAMOS sysfs file.  Fix the leak
by deallocating the previously set memory buffer.

Link: https://lkml.kernel.org/r/20250619183608.6647-2-sj@kernel.org
Fixes: 7ee161f18b5d ("mm/damon/sysfs-schemes: implement filter directory")
Signed-off-by: SeongJae Park <sj@kernel.org>
Cc: Shuah Khan <shuah@kernel.org>
Cc: <stable@vger.kernel.org>		[6.3.x]
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
```

**Diff:**
```diff
diff --git a/mm/damon/sysfs-schemes.c b/mm/damon/sysfs-schemes.c
index 0f6c9e1fec0b..30ae7518ffbf 100644
--- a/mm/damon/sysfs-schemes.c
+++ b/mm/damon/sysfs-schemes.c
@@ -472,6 +472,7 @@ static ssize_t memcg_path_store(struct kobject *kobj,
 		return -ENOMEM;
 
 	strscpy(path, buf, count + 1);
+	kfree(filter->memcg_path);
 	filter->memcg_path = path;
 	return count;
 }
```

---

