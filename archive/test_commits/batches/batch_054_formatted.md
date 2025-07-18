# Linux Kernel Commit Batch Analysis

## Commit 1: cb6075bc

**Author:** Rik van Riel
**Date:** 2025-06-17 16:36:58
**Files Changed:** arch/x86/kernel/cpu/amd.c

**Message:**
```
x86/mm: Fix early boot use of INVPLGB

The INVLPGB instruction has limits on how many pages it can invalidate
at once. That limit is enumerated in CPUID, read by the kernel, and
stored in 'invpgb_count_max'. Ranged invalidation, like
invlpgb_kernel_range_flush() break up their invalidations so
that they do not exceed the limit.

However, early boot code currently attempts to do ranged
invalidation before populating 'invlpgb_count_max'. There is a
for loop which is basically:

	for (...; addr < end; addr += invlpgb_count_max*PAGE_SIZE)

If invlpgb_kernel_range_flush is called before the kernel has read
the value of invlpgb_count_max from the hardware, the normally
bounded loop can become an infinite loop if invlpgb_count_max is
initialized to zero.

Fix that issue by initializing invlpgb_count_max to 1.

This way INVPLGB at early boot time will be a little bit slower
than normal (with initialized invplgb_count_max), and not an
instant hang at bootup time.

Fixes: b7aa05cbdc52 ("x86/mm: Add INVLPGB support code")
Signed-off-by: Rik van Riel <riel@surriel.com>
Signed-off-by: Dave Hansen <dave.hansen@linux.intel.com>
Link: https://lore.kernel.org/all/20250606171112.4013261-3-riel%40surriel.com
```

**Diff:**
```diff
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
```

---

## Commit 2: b160766e

**Author:** Hyunwoo Kim
**Date:** 2025-06-17 16:14:04
**Files Changed:** net/sched/sch_taprio.c

**Message:**
```
net/sched: fix use-after-free in taprio_dev_notifier

Since taprio’s taprio_dev_notifier() isn’t protected by an
RCU read-side critical section, a race with advance_sched()
can lead to a use-after-free.

Adding rcu_read_lock() inside taprio_dev_notifier() prevents this.

Fixes: fed87cc6718a ("net/sched: taprio: automatically calculate queueMaxSDU based on TC gate durations")
Cc: stable@vger.kernel.org
Signed-off-by: Hyunwoo Kim <imv4bel@gmail.com>
Reviewed-by: Simon Horman <horms@kernel.org>
Reviewed-by: Eric Dumazet <edumazet@google.com>
Link: https://patch.msgid.link/aEzIYYxt0is9upYG@v4bel-B760M-AORUS-ELITE-AX
Signed-off-by: Jakub Kicinski <kuba@kernel.org>
```

**Diff:**
```diff
diff --git a/net/sched/sch_taprio.c b/net/sched/sch_taprio.c
index 14021b812329..2b14c81a87e5 100644
--- a/net/sched/sch_taprio.c
+++ b/net/sched/sch_taprio.c
@@ -1328,13 +1328,15 @@ static int taprio_dev_notifier(struct notifier_block *nb, unsigned long event,
 
 		stab = rtnl_dereference(q->root->stab);
 
-		oper = rtnl_dereference(q->oper_sched);
+		rcu_read_lock();
+		oper = rcu_dereference(q->oper_sched);
 		if (oper)
 			taprio_update_queue_max_sdu(q, oper, stab);
 
-		admin = rtnl_dereference(q->admin_sched);
+		admin = rcu_dereference(q->admin_sched);
 		if (admin)
 			taprio_update_queue_max_sdu(q, admin, stab);
+		rcu_read_unlock();
 
 		break;
 	}
```

---

## Commit 3: 5ab73b01

**Author:** Vladimir Oltean
**Date:** 2025-06-17 16:13:09
**Files Changed:** drivers/ptp/ptp_private.h

**Message:**
```
ptp: fix breakage after ptp_vclock_in_use() rework

What is broken
--------------

ptp4l, and any other application which calls clock_adjtime() on a
physical clock, is greeted with error -EBUSY after commit 87f7ce260a3c
("ptp: remove ptp->n_vclocks check logic in ptp_vclock_in_use()").

Explanation for the breakage
----------------------------

The blamed commit was based on the false assumption that
ptp_vclock_in_use() callers already test for n_vclocks prior to calling
this function.

This is notably incorrect for the code path below, in which there is, in
fact, no n_vclocks test:

ptp_clock_adjtime()
-> ptp_clock_freerun()
   -> ptp_vclock_in_use()

The result is that any clock adjustment on any physical clock is now
impossible. This is _despite_ there not being any vclock over this
physical clock.

$ ptp4l -i eno0 -2 -P -m
ptp4l[58.425]: selected /dev/ptp0 as PTP clock
[   58.429749] ptp: physical clock is free running
ptp4l[58.431]: Failed to open /dev/ptp0: Device or resource busy
failed to create a clock
$ cat /sys/class/ptp/ptp0/n_vclocks
0

The patch makes the ptp_vclock_in_use() function say "if it's not a
virtual clock, then this physical clock does have virtual clocks on
top".

Then ptp_clock_freerun() uses this information to say "this physical
clock has virtual clocks on top, so it must stay free-running".

Then ptp_clock_adjtime() uses this information to say "well, if this
physical clock has to be free-running, I can't do it, return -EBUSY".

Simply put, ptp_vclock_in_use() cannot be simplified so as to remove the
test whether vclocks are in use.

What did the blamed commit intend to fix
----------------------------------------

The blamed commit presents a lockdep warning stating "possible recursive
locking detected", with the n_vclocks_store() and ptp_clock_unregister()
functions involved.

The recursive locking seems this:
n_vclocks_store()
-> mutex_lock_interruptible(&ptp->n_vclocks_mux) // 1
-> device_for_each_child_reverse(..., unregister_vclock)
   -> unregister_vclock()
      -> ptp_vclock_unregister()
         -> ptp_clock_unregister()
            -> ptp_vclock_in_use()
               -> mutex_lock_interruptible(&ptp->n_vclocks_mux) // 2

The issue can be triggered by creating and then deleting vclocks:
$ echo 2 > /sys/class/ptp/ptp0/n_vclocks
$ echo 0 > /sys/class/ptp/ptp0/n_vclocks

But note that in the original stack trace, the address of the first lock
is different from the address of the second lock. This is because at
step 1 marked above, &ptp->n_vclocks_mux is the lock of the parent
(physical) PTP clock, and at step 2, the lock is of the child (virtual)
PTP clock. They are different locks of different devices.

In this situation there is no real deadlock, the lockdep warning is
caused by the fact that the mutexes have the same lock class on both the
parent and the child. Functionally it is fine.

Proposed alternative solution
-----------------------------

We must reintroduce the body of ptp_vclock_in_use() mostly as it was
structured prior to the blamed commit, but avoid the lockdep warning.

Based on the fact that vclocks cannot be nested on top of one another
(ptp_is_attribute_visible() hides n_vclocks for virtual clocks), we
already know that ptp->n_vclocks is zero for a virtual clock. And
ptp->is_virtual_clock is a runtime invariant, established at
ptp_clock_register() time and never changed. There is no need to
serialize on any mutex in order to read ptp->is_virtual_clock, and we
take advantage of that by moving it outside the lock.

Thus, virtual clocks do not need to acquire &ptp->n_vclocks_mux at
all, and step 2 in the code walkthrough above can simply go away.
We can simply return false to the question "ptp_vclock_in_use(a virtual
clock)".

Other notes
-----------

Releasing &ptp->n_vclocks_mux before ptp_vclock_in_use() returns
execution seems racy, because the returned value can become stale as
soon as the function returns and before the return value is used (i.e.
n_vclocks_store() can run any time). The locking requirement should
somehow be transferred to the caller, to ensure a longer life time for
the returned value, but this seems out of scope for this severe bug fix.

Because we are also fixing up the logic from the original commit, there
is another Fixes: tag for that.

Fixes: 87f7ce260a3c ("ptp: remove ptp->n_vclocks check logic in ptp_vclock_in_use()")
Fixes: 73f37068d540 ("ptp: support ptp physical/virtual clocks conversion")
Signed-off-by: Vladimir Oltean <vladimir.oltean@nxp.com>
Link: https://patch.msgid.link/20250613174749.406826-2-vladimir.oltean@nxp.com
Signed-off-by: Jakub Kicinski <kuba@kernel.org>
```

**Diff:**
```diff
diff --git a/drivers/ptp/ptp_private.h b/drivers/ptp/ptp_private.h
index 528d86a33f37..a6aad743c282 100644
--- a/drivers/ptp/ptp_private.h
+++ b/drivers/ptp/ptp_private.h
@@ -98,7 +98,27 @@ static inline int queue_cnt(const struct timestamp_event_queue *q)
 /* Check if ptp virtual clock is in use */
 static inline bool ptp_vclock_in_use(struct ptp_clock *ptp)
 {
-	return !ptp->is_virtual_clock;
+	bool in_use = false;
+
+	/* Virtual clocks can't be stacked on top of virtual clocks.
+	 * Avoid acquiring the n_vclocks_mux on virtual clocks, to allow this
+	 * function to be called from code paths where the n_vclocks_mux of the
+	 * parent physical clock is already held. Functionally that's not an
+	 * issue, but lockdep would complain, because they have the same lock
+	 * class.
+	 */
+	if (ptp->is_virtual_clock)
+		return false;
+
+	if (mutex_lock_interruptible(&ptp->n_vclocks_mux))
+		return true;
+
+	if (ptp->n_vclocks)
+		in_use = true;
+
+	mutex_unlock(&ptp->n_vclocks_mux);
+
+	return in_use;
 }
 
 /* Check if ptp clock shall be free running */
```

---

## Commit 4: 1e9ac33f

**Author:** Kalesh AP
**Date:** 2025-06-17 15:56:22
**Files Changed:** drivers/net/ethernet/broadcom/bnxt/bnxt_ulp.c

**Message:**
```
bnxt_en: Fix double invocation of bnxt_ulp_stop()/bnxt_ulp_start()

Before the commit under the Fixes tag below, bnxt_ulp_stop() and
bnxt_ulp_start() were always invoked in pairs.  After that commit,
the new bnxt_ulp_restart() can be invoked after bnxt_ulp_stop()
has been called.  This may result in the RoCE driver's aux driver
.suspend() method being invoked twice.  The 2nd bnxt_re_suspend()
call will crash when it dereferences a NULL pointer:

(NULL ib_device): Handle device suspend call
BUG: kernel NULL pointer dereference, address: 0000000000000b78
PGD 0 P4D 0
Oops: Oops: 0000 [#1] SMP PTI
CPU: 20 UID: 0 PID: 181 Comm: kworker/u96:5 Tainted: G S                  6.15.0-rc1 #4 PREEMPT(voluntary)
Tainted: [S]=CPU_OUT_OF_SPEC
Hardware name: Dell Inc. PowerEdge R730/072T6D, BIOS 2.4.3 01/17/2017
Workqueue: bnxt_pf_wq bnxt_sp_task [bnxt_en]
RIP: 0010:bnxt_re_suspend+0x45/0x1f0 [bnxt_re]
Code: 8b 05 a7 3c 5b f5 48 89 44 24 18 31 c0 49 8b 5c 24 08 4d 8b 2c 24 e8 ea 06 0a f4 48 c7 c6 04 60 52 c0 48 89 df e8 1b ce f9 ff <48> 8b 83 78 0b 00 00 48 8b 80 38 03 00 00 a8 40 0f 85 b5 00 00 00
RSP: 0018:ffffa2e84084fd88 EFLAGS: 00010246
RAX: 0000000000000000 RBX: 0000000000000000 RCX: 0000000000000001
RDX: 0000000000000000 RSI: ffffffffb4b6b934 RDI: 00000000ffffffff
RBP: ffffa1760954c9c0 R08: 0000000000000000 R09: c0000000ffffdfff
R10: 0000000000000001 R11: ffffa2e84084fb50 R12: ffffa176031ef070
R13: ffffa17609775000 R14: ffffa17603adc180 R15: 0000000000000000
FS:  0000000000000000(0000) GS:ffffa17daa397000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 0000000000000b78 CR3: 00000004aaa30003 CR4: 00000000003706f0
DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
Call Trace:
<TASK>
bnxt_ulp_stop+0x69/0x90 [bnxt_en]
bnxt_sp_task+0x678/0x920 [bnxt_en]
? __schedule+0x514/0xf50
process_scheduled_works+0x9d/0x400
worker_thread+0x11c/0x260
? __pfx_worker_thread+0x10/0x10
kthread+0xfe/0x1e0
? __pfx_kthread+0x10/0x10
ret_from_fork+0x2b/0x40
? __pfx_kthread+0x10/0x10
ret_from_fork_asm+0x1a/0x30

Check the BNXT_EN_FLAG_ULP_STOPPED flag and do not proceed if the flag
is already set.  This will preserve the original symmetrical
bnxt_ulp_stop() and bnxt_ulp_start().

Also, inside bnxt_ulp_start(), clear the BNXT_EN_FLAG_ULP_STOPPED
flag after taking the mutex to avoid any race condition.  And for
symmetry, only proceed in bnxt_ulp_start() if the
BNXT_EN_FLAG_ULP_STOPPED is set.

Fixes: 3c163f35bd50 ("bnxt_en: Optimize recovery path ULP locking in the driver")
Signed-off-by: Kalesh AP <kalesh-anakkur.purayil@broadcom.com>
Co-developed-by: Michael Chan <michael.chan@broadcom.com>
Signed-off-by: Michael Chan <michael.chan@broadcom.com>
Reviewed-by: Simon Horman <horms@kernel.org>
Link: https://patch.msgid.link/20250613231841.377988-2-michael.chan@broadcom.com
Signed-off-by: Jakub Kicinski <kuba@kernel.org>
```

**Diff:**
```diff
diff --git a/drivers/net/ethernet/broadcom/bnxt/bnxt_ulp.c b/drivers/net/ethernet/broadcom/bnxt/bnxt_ulp.c
index 84c4812414fd..2450a369b792 100644
--- a/drivers/net/ethernet/broadcom/bnxt/bnxt_ulp.c
+++ b/drivers/net/ethernet/broadcom/bnxt/bnxt_ulp.c
@@ -231,10 +231,9 @@ void bnxt_ulp_stop(struct bnxt *bp)
 		return;
 
 	mutex_lock(&edev->en_dev_lock);
-	if (!bnxt_ulp_registered(edev)) {
-		mutex_unlock(&edev->en_dev_lock);
-		return;
-	}
+	if (!bnxt_ulp_registered(edev) ||
+	    (edev->flags & BNXT_EN_FLAG_ULP_STOPPED))
+		goto ulp_stop_exit;
 
 	edev->flags |= BNXT_EN_FLAG_ULP_STOPPED;
 	if (aux_priv) {
@@ -250,6 +249,7 @@ void bnxt_ulp_stop(struct bnxt *bp)
 			adrv->suspend(adev, pm);
 		}
 	}
+ulp_stop_exit:
 	mutex_unlock(&edev->en_dev_lock);
 }
 
@@ -258,19 +258,13 @@ void bnxt_ulp_start(struct bnxt *bp, int err)
 	struct bnxt_aux_priv *aux_priv = bp->aux_priv;
 	struct bnxt_en_dev *edev = bp->edev;
 
-	if (!edev)
-		return;
-
-	edev->flags &= ~BNXT_EN_FLAG_ULP_STOPPED;
-
-	if (err)
+	if (!edev || err)
 		return;
 
 	mutex_lock(&edev->en_dev_lock);
-	if (!bnxt_ulp_registered(edev)) {
-		mutex_unlock(&edev->en_dev_lock);
-		return;
-	}
+	if (!bnxt_ulp_registered(edev) ||
+	    !(edev->flags & BNXT_EN_FLAG_ULP_STOPPED))
+		goto ulp_start_exit;
 
 	if (edev->ulp_tbl->msix_requested)
 		bnxt_fill_msix_vecs(bp, edev->msix_entries);

... (truncated 9 lines)
```

---

## Commit 5: 94a17f2d

**Author:** Dave Hansen
**Date:** 2025-06-17 15:36:57
**Files Changed:** arch/x86/mm/pti.c

**Message:**
```
x86/mm: Disable INVLPGB when PTI is enabled

PTI uses separate ASIDs (aka. PCIDs) for kernel and user address
spaces. When the kernel needs to flush the user address space, it
just sets a bit in a bitmap and then flushes the entire PCID on
the next switch to userspace.

This bitmap is a single 'unsigned long' which is plenty for all 6
dynamic ASIDs. But, unfortunately, the INVLPGB support brings along a
bunch more user ASIDs, as many as ~2k more. The bitmap can't address
that many.

Fortunately, the bitmap is only needed for PTI and all the CPUs
with INVLPGB are AMD CPUs that aren't vulnerable to Meltdown and
don't need PTI. The only way someone can run into an issue in
practice is by booting with pti=on on a newer AMD CPU.

Disable INVLPGB if PTI is enabled. Avoid overrunning the small
bitmap.

Note: this will be fixed up properly by making the bitmap bigger.
For now, just avoid the mostly theoretical bug.

Fixes: 4afeb0ed1753 ("x86/mm: Enable broadcast TLB invalidation for multi-threaded processes")
Signed-off-by: Dave Hansen <dave.hansen@linux.intel.com>
Acked-by: Rik van Riel <riel@surriel.com>
Cc:stable@vger.kernel.org
Link: https://lore.kernel.org/all/20250610222420.E8CBF472%40davehans-spike.ostc.intel.com
```

**Diff:**
```diff
diff --git a/arch/x86/mm/pti.c b/arch/x86/mm/pti.c
index 190299834011..c0c40b67524e 100644
--- a/arch/x86/mm/pti.c
+++ b/arch/x86/mm/pti.c
@@ -98,6 +98,11 @@ void __init pti_check_boottime_disable(void)
 		return;
 
 	setup_force_cpu_cap(X86_FEATURE_PTI);
+
+	if (cpu_feature_enabled(X86_FEATURE_INVLPGB)) {
+		pr_debug("PTI enabled, disabling INVLPGB\n");
+		setup_clear_cpu_cap(X86_FEATURE_INVLPGB);
+	}
 }
 
 static int __init pti_parse_cmdline(char *arg)
```

---

