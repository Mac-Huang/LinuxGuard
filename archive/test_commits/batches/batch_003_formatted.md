# Linux Kernel Commit Batch Analysis

## Commit 1: 73d7cf07

**Author:** Linus Torvalds
**Date:** 2025-07-10 09:06:53
**Files Changed:** arch/arm64/include/asm/kvm_host.h, arch/arm64/kvm/arm.c, arch/arm64/kvm/fpsimd.c, arch/arm64/kvm/hyp/nvhe/mem_protect.c, arch/arm64/kvm/nested.c (+13 more)

**Message:**
```
Merge tag 'for-linus' of git://git.kernel.org/pub/scm/virt/kvm/kvm

Pull KVM fixes from Paolo Bonzini:
 "Many patches, pretty much all of them small, that accumulated while I
  was on vacation.

  ARM:

   - Remove the last leftovers of the ill-fated FPSIMD host state
     mapping at EL2 stage-1

   - Fix unexpected advertisement to the guest of unimplemented S2 base
     granule sizes

   - Gracefully fail initialising pKVM if the interrupt controller isn't
     GICv3

   - Also gracefully fail initialising pKVM if the carveout allocation
     fails

   - Fix the computing of the minimum MMIO range required for the host
     on stage-2 fault

   - Fix the generation of the GICv3 Maintenance Interrupt in nested
     mode

  x86:

   - Reject SEV{-ES} intra-host migration if one or more vCPUs are
     actively being created, so as not to create a non-SEV{-ES} vCPU in
     an SEV{-ES} VM

   - Use a pre-allocated, per-vCPU buffer for handling de-sparsification
     of vCPU masks in Hyper-V hypercalls; fixes a "stack frame too
     large" issue

   - Allow out-of-range/invalid Xen event channel ports when configuring
     IRQ routing, to avoid dictating a specific ioctl() ordering to
     userspace

   - Conditionally reschedule when setting memory attributes to avoid
     soft lockups when userspace converts huge swaths of memory to/from
     private

   - Add back MWAIT as a required feature for the MONITOR/MWAIT selftest

   - Add a missing field in struct sev_data_snp_launch_start that
     resulted in the guest-visible workarounds field being filled at the
     wrong offset

   - Skip non-canonical address when processing Hyper-V PV TLB flushes
     to avoid VM-Fail on INVVPID

   - Advertise supported TDX TDVMCALLs to userspace

   - Pass SetupEventNotifyInterrupt arguments to userspace

   - Fix TSC frequency underflow"

* tag 'for-linus' of git://git.kernel.org/pub/scm/virt/kvm/kvm:
  KVM: x86: avoid underflow when scaling TSC frequency
  KVM: arm64: Remove kvm_arch_vcpu_run_map_fp()
  KVM: arm64: Fix handling of FEAT_GTG for unimplemented granule sizes
  KVM: arm64: Don't free hyp pages with pKVM on GICv2
  KVM: arm64: Fix error path in init_hyp_mode()
  KVM: arm64: Adjust range correctly during host stage-2 faults
  KVM: arm64: nv: Fix MI line level calculation in vgic_v3_nested_update_mi()
  KVM: x86/hyper-v: Skip non-canonical addresses during PV TLB flush
  KVM: SVM: Add missing member in SNP_LAUNCH_START command structure
  Documentation: KVM: Fix unexpected unindent warnings
  KVM: selftests: Add back the missing check of MONITOR/MWAIT availability
  KVM: Allow CPU to reschedule while setting per-page memory attributes
  KVM: x86/xen: Allow 'out of range' event channel ports in IRQ routing table.
  KVM: x86/hyper-v: Use preallocated per-vCPU buffer for de-sparsified vCPU masks
  KVM: SVM: Initialize vmsa_pa in VMCB to INVALID_PAGE if VMSA page is NULL
  KVM: SVM: Reject SEV{-ES} intra host migration if vCPU creation is in-flight
  KVM: TDX: Report supported optional TDVMCALLs in TDX capabilities
  KVM: TDX: Exit to userspace for SetupEventNotifyInterrupt
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

... (truncated 521 lines)
```

---

## Commit 2: d7a54d02

**Author:** Miri Korenblit
**Date:** 2025-07-10 13:26:13
**Files Changed:** net/mac80211/iface.c

**Message:**
```
wifi: mac80211: always initialize sdata::key_list

This is currently not initialized for a virtual monitor, leading to a
NULL pointer dereference when - for example - iterating over all the
keys of all the vifs.

Reviewed-by: Johannes Berg <johannes.berg@intel.com>
Signed-off-by: Miri Korenblit <miriam.rachel.korenblit@intel.com>
Link: https://patch.msgid.link/20250709233400.8dcefe578497.I4c90a00ae3256520e063199d7f6f2580d5451acf@changeid
Signed-off-by: Johannes Berg <johannes.berg@intel.com>
```

**Diff:**
```diff
diff --git a/net/mac80211/iface.c b/net/mac80211/iface.c
index 7c27f3cd841c..c01634fdba78 100644
--- a/net/mac80211/iface.c
+++ b/net/mac80211/iface.c
@@ -1150,6 +1150,8 @@ static void ieee80211_sdata_init(struct ieee80211_local *local,
 {
 	sdata->local = local;
 
+	INIT_LIST_HEAD(&sdata->key_list);
+
 	/*
 	 * Initialize the default link, so we can use link_id 0 for non-MLD,
 	 * and that continues to work for non-MLD-aware drivers that use just
@@ -2210,8 +2212,6 @@ int ieee80211_if_add(struct ieee80211_local *local, const char *name,
 
 	ieee80211_init_frag_cache(&sdata->frags);
 
-	INIT_LIST_HEAD(&sdata->key_list);
-
 	wiphy_delayed_work_init(&sdata->dec_tailroom_needed_wk,
 				ieee80211_delayed_tailroom_dec);
 
```

---

## Commit 3: db6cc3f4

**Author:** Chen Yu
**Date:** 2025-07-09 21:07:56
**Files Changed:** include/linux/sched.h, include/linux/vm_event_item.h, kernel/sched/core.c, kernel/sched/debug.c, mm/memcontrol.c (+1 more)

**Message:**
```
Revert "sched/numa: add statistics of numa balance task"

This reverts commit ad6b26b6a0a79166b53209df2ca1cf8636296382.

This commit introduces per-memcg/task NUMA balance statistics, but
unfortunately it introduced a NULL pointer exception due to the following
race condition: After a swap task candidate was chosen, its mm_struct
pointer was set to NULL due to task exit.  Later, when performing the
actual task swapping, the p->mm caused the problem.

CPU0                                   CPU1
:
...
task_numa_migrate
     task_numa_find_cpu
      task_numa_compare
        # a normal task p is chosen
        env->best_task = p

                                          # p exit:
                                          exit_signals(p);
                                             p->flags |= PF_EXITING
                                          exit_mm
                                             p->mm = NULL;

      migrate_swap_stop
        __migrate_swap_task((arg->src_task, arg->dst_cpu)
         count_memcg_event_mm(p->mm, NUMA_TASK_SWAP)# p->mm is NULL

task_lock() should be held and the PF_EXITING flag needs to be checked to
prevent this from happening.  After discussion, the conclusion was that
adding a lock is not worthwhile for some statistics calculations.  Revert
the change and rely on the tracepoint for this purpose.

Link: https://lkml.kernel.org/r/20250704135620.685752-1-yu.c.chen@intel.com
Link: https://lkml.kernel.org/r/20250708064917.BBD13C4CEED@smtp.kernel.org
Fixes: ad6b26b6a0a7 ("sched/numa: add statistics of numa balance task")
Signed-off-by: Chen Yu <yu.c.chen@intel.com>
Reported-by: Jirka Hladky <jhladky@redhat.com>
Closes: https://lore.kernel.org/all/CAE4VaGBLJxpd=NeRJXpSCuw=REhC5LWJpC29kDy-Zh2ZDyzQZA@mail.gmail.com/
Reported-by: Srikanth Aithal <Srikanth.Aithal@amd.com>
Reported-by: Suneeth D <Suneeth.D@amd.com>
Acked-by: Michal Hocko <mhocko@suse.com>
Cc: Borislav Petkov <bp@alien8.de>
Cc: Ingo Molnar <mingo@redhat.com>
Cc: Jiri Hladky <jhladky@redhat.com>
Cc: Libo Chen <libo.chen@oracle.com>
Cc: Peter Zijlstra <peterz@infradead.org>
Cc: Thomas Gleixner <tglx@linutronix.de>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
```

**Diff:**
```diff
diff --git a/Documentation/admin-guide/cgroup-v2.rst b/Documentation/admin-guide/cgroup-v2.rst
index 0cc35a14afbe..bd98ea3175ec 100644
--- a/Documentation/admin-guide/cgroup-v2.rst
+++ b/Documentation/admin-guide/cgroup-v2.rst
@@ -1732,12 +1732,6 @@ The following nested keys are defined.
 	  numa_hint_faults (npn)
 		Number of NUMA hinting faults.
 
-	  numa_task_migrated (npn)
-		Number of task migration by NUMA balancing.
-
-	  numa_task_swapped (npn)
-		Number of task swap by NUMA balancing.
-
 	  pgdemote_kswapd
 		Number of pages demoted by kswapd.
 
diff --git a/include/linux/sched.h b/include/linux/sched.h
index 4f78a64beb52..aa9c5be7a632 100644
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -548,10 +548,6 @@ struct sched_statistics {
 	u64				nr_failed_migrations_running;
 	u64				nr_failed_migrations_hot;
 	u64				nr_forced_migrations;
-#ifdef CONFIG_NUMA_BALANCING
-	u64				numa_task_migrated;
-	u64				numa_task_swapped;
-#endif
 
 	u64				nr_wakeups;
 	u64				nr_wakeups_sync;
diff --git a/include/linux/vm_event_item.h b/include/linux/vm_event_item.h
index 91a3ce9a2687..9e15a088ba38 100644
--- a/include/linux/vm_event_item.h
+++ b/include/linux/vm_event_item.h
@@ -66,8 +66,6 @@ enum vm_event_item { PGPGIN, PGPGOUT, PSWPIN, PSWPOUT,
 		NUMA_HINT_FAULTS,
 		NUMA_HINT_FAULTS_LOCAL,
 		NUMA_PAGE_MIGRATE,
-		NUMA_TASK_MIGRATE,
-		NUMA_TASK_SWAP,
 #endif
 #ifdef CONFIG_MIGRATION
 		PGMIGRATE_SUCCESS, PGMIGRATE_FAIL,
diff --git a/kernel/sched/core.c b/kernel/sched/core.c
index ec68fc686bd7..81c6df746df1 100644
--- a/kernel/sched/core.c
+++ b/kernel/sched/core.c
@@ -3362,10 +3362,6 @@ void set_task_cpu(struct task_struct *p, unsigned int new_cpu)

... (truncated 63 lines)
```

---

## Commit 4: 82241a83

**Author:** Baolin Wang
**Date:** 2025-07-09 21:07:55
**Files Changed:** fs/proc/task_mmu.c, include/linux/mm.h

**Message:**
```
mm: fix the inaccurate memory statistics issue for users

On some large machines with a high number of CPUs running a 64K pagesize
kernel, we found that the 'RES' field is always 0 displayed by the top
command for some processes, which will cause a lot of confusion for users.

    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND
 875525 root      20   0   12480      0      0 R   0.3   0.0   0:00.08 top
      1 root      20   0  172800      0      0 S   0.0   0.0   0:04.52 systemd

The main reason is that the batch size of the percpu counter is quite
large on these machines, caching a significant percpu value, since
converting mm's rss stats into percpu_counter by commit f1a7941243c1 ("mm:
convert mm's rss stats into percpu_counter").  Intuitively, the batch
number should be optimized, but on some paths, performance may take
precedence over statistical accuracy.  Therefore, introducing a new
interface to add the percpu statistical count and display it to users,
which can remove the confusion.  In addition, this change is not expected
to be on a performance-critical path, so the modification should be
acceptable.

In addition, the 'mm->rss_stat' is updated by using add_mm_counter() and
dec/inc_mm_counter(), which are all wrappers around
percpu_counter_add_batch().  In percpu_counter_add_batch(), there is
percpu batch caching to avoid 'fbc->lock' contention.  This patch changes
task_mem() and task_statm() to get the accurate mm counters under the
'fbc->lock', but this should not exacerbate kernel 'mm->rss_stat' lock
contention due to the percpu batch caching of the mm counters.  The
following test also confirm the theoretical analysis.

I run the stress-ng that stresses anon page faults in 32 threads on my 32
cores machine, while simultaneously running a script that starts 32
threads to busy-loop pread each stress-ng thread's /proc/pid/status
interface.  From the following data, I did not observe any obvious impact
of this patch on the stress-ng tests.

w/o patch:
stress-ng: info:  [6848]          4,399,219,085,152 CPU Cycles          67.327 B/sec
stress-ng: info:  [6848]          1,616,524,844,832 Instructions          24.740 B/sec (0.367 instr. per cycle)
stress-ng: info:  [6848]          39,529,792 Page Faults Total           0.605 M/sec
stress-ng: info:  [6848]          39,529,792 Page Faults Minor           0.605 M/sec

w/patch:
stress-ng: info:  [2485]          4,462,440,381,856 CPU Cycles          68.382 B/sec
stress-ng: info:  [2485]          1,615,101,503,296 Instructions          24.750 B/sec (0.362 instr. per cycle)
stress-ng: info:  [2485]          39,439,232 Page Faults Total           0.604 M/sec
stress-ng: info:  [2485]          39,439,232 Page Faults Minor           0.604 M/sec

On comparing a very simple app which just allocates & touches some
memory against v6.1 (which doesn't have f1a7941243c1) and latest Linus
tree (4c06e63b9203) I can see that on latest Linus tree the values for
VmRSS, RssAnon and RssFile from /proc/self/status are all zeroes while
they do report values on v6.1 and a Linus tree with this patch.

Link: https://lkml.kernel.org/r/f4586b17f66f97c174f7fd1f8647374fdb53de1c.1749119050.git.baolin.wang@linux.alibaba.com
Fixes: f1a7941243c1 ("mm: convert mm's rss stats into percpu_counter")
Signed-off-by: Baolin Wang <baolin.wang@linux.alibaba.com>
Reviewed-by: Aboorva Devarajan <aboorvad@linux.ibm.com>
Tested-by: Aboorva Devarajan <aboorvad@linux.ibm.com>
Tested-by Donet Tom <donettom@linux.ibm.com>
Acked-by: Shakeel Butt <shakeel.butt@linux.dev>
Acked-by: SeongJae Park <sj@kernel.org>
Acked-by: Michal Hocko <mhocko@suse.com>
Reviewed-by: Vlastimil Babka <vbabka@suse.cz>
Cc: David Hildenbrand <david@redhat.com>
Cc: Liam Howlett <liam.howlett@oracle.com>
Cc: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Cc: Mike Rapoport <rppt@kernel.org>
Cc: Suren Baghdasaryan <surenb@google.com>
Cc: <stable@vger.kernel.org>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
```

**Diff:**
```diff
diff --git a/fs/proc/task_mmu.c b/fs/proc/task_mmu.c
index 4be91eb6ea5c..751479eb128f 100644
--- a/fs/proc/task_mmu.c
+++ b/fs/proc/task_mmu.c
@@ -36,9 +36,9 @@ void task_mem(struct seq_file *m, struct mm_struct *mm)
 	unsigned long text, lib, swap, anon, file, shmem;
 	unsigned long hiwater_vm, total_vm, hiwater_rss, total_rss;
 
-	anon = get_mm_counter(mm, MM_ANONPAGES);
-	file = get_mm_counter(mm, MM_FILEPAGES);
-	shmem = get_mm_counter(mm, MM_SHMEMPAGES);
+	anon = get_mm_counter_sum(mm, MM_ANONPAGES);
+	file = get_mm_counter_sum(mm, MM_FILEPAGES);
+	shmem = get_mm_counter_sum(mm, MM_SHMEMPAGES);
 
 	/*
 	 * Note: to minimize their overhead, mm maintains hiwater_vm and
@@ -59,7 +59,7 @@ void task_mem(struct seq_file *m, struct mm_struct *mm)
 	text = min(text, mm->exec_vm << PAGE_SHIFT);
 	lib = (mm->exec_vm << PAGE_SHIFT) - text;
 
-	swap = get_mm_counter(mm, MM_SWAPENTS);
+	swap = get_mm_counter_sum(mm, MM_SWAPENTS);
 	SEQ_PUT_DEC("VmPeak:\t", hiwater_vm);
 	SEQ_PUT_DEC(" kB\nVmSize:\t", total_vm);
 	SEQ_PUT_DEC(" kB\nVmLck:\t", mm->locked_vm);
@@ -92,12 +92,12 @@ unsigned long task_statm(struct mm_struct *mm,
 			 unsigned long *shared, unsigned long *text,
 			 unsigned long *data, unsigned long *resident)
 {
-	*shared = get_mm_counter(mm, MM_FILEPAGES) +
-			get_mm_counter(mm, MM_SHMEMPAGES);
+	*shared = get_mm_counter_sum(mm, MM_FILEPAGES) +
+			get_mm_counter_sum(mm, MM_SHMEMPAGES);
 	*text = (PAGE_ALIGN(mm->end_code) - (mm->start_code & PAGE_MASK))
 								>> PAGE_SHIFT;
 	*data = mm->data_vm + mm->stack_vm;
-	*resident = *shared + get_mm_counter(mm, MM_ANONPAGES);
+	*resident = *shared + get_mm_counter_sum(mm, MM_ANONPAGES);
 	return mm->total_vm;
 }
 
diff --git a/include/linux/mm.h b/include/linux/mm.h
index 0ef2ba0c667a..fa538feaa8d9 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -2568,6 +2568,11 @@ static inline unsigned long get_mm_counter(struct mm_struct *mm, int member)
 	return percpu_counter_read_positive(&mm->rss_stat[member]);
 }
 

... (truncated 8 lines)
```

---

## Commit 5: d9e01c62

**Author:** Honggyu Kim
**Date:** 2025-07-09 21:07:54
**Files Changed:** samples/damon/prcl.c

**Message:**
```
samples/damon: fix damon sample prcl for start failure

Patch series "mm/damon: fix divide by zero and its samples", v3.

This series includes fixes against damon and its samples to make it safer
when damon sample starting fails.

It includes the following changes.
- fix unexpected divide by zero crash for zero size regions
- fix bugs for damon samples in case of start failures


This patch (of 4):

The damon_sample_prcl_start() can fail so we must reset the "enable"
parameter to "false" again for proper rollback.

In such cases, setting Y to "enable" then N triggers the following crash
because damon sample start failed but the "enable" stays as Y.

  [ 2441.419649] damon_sample_prcl: start
  [ 2454.146817] damon_sample_prcl: stop
  [ 2454.146862] ------------[ cut here ]------------
  [ 2454.146865] kernel BUG at mm/slub.c:546!
  [ 2454.148183] Oops: invalid opcode: 0000 [#1] SMP NOPTI
  	...
  [ 2454.167555] Call Trace:
  [ 2454.167822]  <TASK>
  [ 2454.168061]  damon_destroy_ctx+0x78/0x140
  [ 2454.168454]  damon_sample_prcl_enable_store+0x8d/0xd0
  [ 2454.168932]  param_attr_store+0xa1/0x120
  [ 2454.169315]  module_attr_store+0x20/0x50
  [ 2454.169695]  sysfs_kf_write+0x72/0x90
  [ 2454.170065]  kernfs_fop_write_iter+0x150/0x1e0
  [ 2454.170491]  vfs_write+0x315/0x440
  [ 2454.170833]  ksys_write+0x69/0xf0
  [ 2454.171162]  __x64_sys_write+0x19/0x30
  [ 2454.171525]  x64_sys_call+0x18b2/0x2700
  [ 2454.171900]  do_syscall_64+0x7f/0x680
  [ 2454.172258]  ? exit_to_user_mode_loop+0xf6/0x180
  [ 2454.172694]  ? clear_bhb_loop+0x30/0x80
  [ 2454.173067]  ? clear_bhb_loop+0x30/0x80
  [ 2454.173439]  entry_SYSCALL_64_after_hwframe+0x76/0x7e

Link: https://lkml.kernel.org/r/20250702000205.1921-1-honggyu.kim@sk.com
Link: https://lkml.kernel.org/r/20250702000205.1921-2-honggyu.kim@sk.com
Fixes: 2aca254620a8 ("samples/damon: introduce a skeleton of a smaple DAMON module for proactive reclamation")
Signed-off-by: Honggyu Kim <honggyu.kim@sk.com>
Reviewed-by: SeongJae Park <sj@kernel.org>
Cc: <stable@vger.kernel.org>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
```

**Diff:**
```diff
diff --git a/samples/damon/prcl.c b/samples/damon/prcl.c
index 056b1b21a0fe..5597e6a08ab2 100644
--- a/samples/damon/prcl.c
+++ b/samples/damon/prcl.c
@@ -122,8 +122,12 @@ static int damon_sample_prcl_enable_store(
 	if (enable == enabled)
 		return 0;
 
-	if (enable)
-		return damon_sample_prcl_start();
+	if (enable) {
+		err = damon_sample_prcl_start();
+		if (err)
+			enable = false;
+		return err;
+	}
 	damon_sample_prcl_stop();
 	return 0;
 }
```

---

