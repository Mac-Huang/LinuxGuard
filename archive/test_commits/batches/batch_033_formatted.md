# Linux Kernel Commit Batch Analysis

## Commit 1: 080e8d2e

**Author:** Bibo Mao
**Date:** 2025-06-26 20:07:27
**Files Changed:** arch/loongarch/kvm/intc/eiointc.c

**Message:**
```
LoongArch: KVM: Avoid overflow with array index

The variable index is modified and reused as array index when modify
register EIOINTC_ENABLE. There will be array index overflow problem.

Cc: stable@vger.kernel.org
Fixes: 3956a52bc05b ("LoongArch: KVM: Add EIOINTC read and write functions")
Signed-off-by: Bibo Mao <maobibo@loongson.cn>
Signed-off-by: Huacai Chen <chenhuacai@loongson.cn>
```

**Diff:**
```diff
diff --git a/arch/loongarch/kvm/intc/eiointc.c b/arch/loongarch/kvm/intc/eiointc.c
index f39929d7bf8a..9c47456b805c 100644
--- a/arch/loongarch/kvm/intc/eiointc.c
+++ b/arch/loongarch/kvm/intc/eiointc.c
@@ -436,17 +436,16 @@ static int loongarch_eiointc_writew(struct kvm_vcpu *vcpu,
 		break;
 	case EIOINTC_ENABLE_START ... EIOINTC_ENABLE_END:
 		index = (offset - EIOINTC_ENABLE_START) >> 1;
-		old_data = s->enable.reg_u32[index];
+		old_data = s->enable.reg_u16[index];
 		s->enable.reg_u16[index] = data;
 		/*
 		 * 1: enable irq.
 		 * update irq when isr is set.
 		 */
 		data = s->enable.reg_u16[index] & ~old_data & s->isr.reg_u16[index];
-		index = index << 1;
 		for (i = 0; i < sizeof(data); i++) {
 			u8 mask = (data >> (i * 8)) & 0xff;
-			eiointc_enable_irq(vcpu, s, index + i, mask, 1);
+			eiointc_enable_irq(vcpu, s, index * 2 + i, mask, 1);
 		}
 		/*
 		 * 0: disable irq.
@@ -455,7 +454,7 @@ static int loongarch_eiointc_writew(struct kvm_vcpu *vcpu,
 		data = ~s->enable.reg_u16[index] & old_data & s->isr.reg_u16[index];
 		for (i = 0; i < sizeof(data); i++) {
 			u8 mask = (data >> (i * 8)) & 0xff;
-			eiointc_enable_irq(vcpu, s, index, mask, 0);
+			eiointc_enable_irq(vcpu, s, index * 2 + i, mask, 0);
 		}
 		break;
 	case EIOINTC_BOUNCE_START ... EIOINTC_BOUNCE_END:
@@ -529,10 +528,9 @@ static int loongarch_eiointc_writel(struct kvm_vcpu *vcpu,
 		 * update irq when isr is set.
 		 */
 		data = s->enable.reg_u32[index] & ~old_data & s->isr.reg_u32[index];
-		index = index << 2;
 		for (i = 0; i < sizeof(data); i++) {
 			u8 mask = (data >> (i * 8)) & 0xff;
-			eiointc_enable_irq(vcpu, s, index + i, mask, 1);
+			eiointc_enable_irq(vcpu, s, index * 4 + i, mask, 1);
 		}
 		/*
 		 * 0: disable irq.
@@ -541,7 +539,7 @@ static int loongarch_eiointc_writel(struct kvm_vcpu *vcpu,
 		data = ~s->enable.reg_u32[index] & old_data & s->isr.reg_u32[index];
 		for (i = 0; i < sizeof(data); i++) {
 			u8 mask = (data >> (i * 8)) & 0xff;
-			eiointc_enable_irq(vcpu, s, index, mask, 0);

... (truncated 25 lines)
```

---

## Commit 2: a0137c90

**Author:** Kees Cook
**Date:** 2025-06-26 20:07:18
**Files Changed:** arch/loongarch/include/asm/smp.h, arch/loongarch/kernel/time.c, arch/loongarch/mm/ioremap.c

**Message:**
```
LoongArch: Handle KCOV __init vs inline mismatches

When the KCOV is enabled all functions get instrumented, unless
the __no_sanitize_coverage attribute is used. To prepare for
__no_sanitize_coverage being applied to __init functions, we have to
handle differences in how GCC's inline optimizations get resolved.
For LoongArch this exposed several places where __init annotations
were missing but ended up being "accidentally correct". So fix these
cases.

Signed-off-by: Kees Cook <kees@kernel.org>
Signed-off-by: Huacai Chen <chenhuacai@loongson.cn>
```

**Diff:**
```diff
diff --git a/arch/loongarch/include/asm/smp.h b/arch/loongarch/include/asm/smp.h
index ad0bd234a0f1..3a47f52959a8 100644
--- a/arch/loongarch/include/asm/smp.h
+++ b/arch/loongarch/include/asm/smp.h
@@ -39,7 +39,7 @@ int loongson_cpu_disable(void);
 void loongson_cpu_die(unsigned int cpu);
 #endif
 
-static inline void plat_smp_setup(void)
+static inline void __init plat_smp_setup(void)
 {
 	loongson_smp_setup();
 }
diff --git a/arch/loongarch/kernel/time.c b/arch/loongarch/kernel/time.c
index bc75a3a69fc8..367906b10f81 100644
--- a/arch/loongarch/kernel/time.c
+++ b/arch/loongarch/kernel/time.c
@@ -102,7 +102,7 @@ static int constant_timer_next_event(unsigned long delta, struct clock_event_dev
 	return 0;
 }
 
-static unsigned long __init get_loops_per_jiffy(void)
+static unsigned long get_loops_per_jiffy(void)
 {
 	unsigned long lpj = (unsigned long)const_clock_freq;
 
diff --git a/arch/loongarch/mm/ioremap.c b/arch/loongarch/mm/ioremap.c
index 70ca73019811..df949a3d0f34 100644
--- a/arch/loongarch/mm/ioremap.c
+++ b/arch/loongarch/mm/ioremap.c
@@ -16,12 +16,12 @@ void __init early_iounmap(void __iomem *addr, unsigned long size)
 
 }
 
-void *early_memremap_ro(resource_size_t phys_addr, unsigned long size)
+void * __init early_memremap_ro(resource_size_t phys_addr, unsigned long size)
 {
 	return early_memremap(phys_addr, size);
 }
 
-void *early_memremap_prot(resource_size_t phys_addr, unsigned long size,
+void * __init early_memremap_prot(resource_size_t phys_addr, unsigned long size,
 		    unsigned long prot_val)
 {
 	return early_memremap(phys_addr, size);
```

---

## Commit 3: f46d2734

**Author:** Christoph Hellwig
**Date:** 2025-06-26 13:04:37
**Files Changed:** drivers/nvme/host/core.c, drivers/nvme/host/nvme.h

**Message:**
```
nvme: fix atomic write size validation

Don't mix the namespace and controller values, and validate the
per-controller limit when probing the controller.  This avoid spurious
failures for controllers with namespaces that have different namespaces
with different logical block sizes, or report the per-namespace values
only for some namespaces.

It also fixes a missing queue_limits_cancel_update in an error path by
removing that error path.

Fixes: 8695f060a029 ("nvme: all namespaces in a subsystem must adhere to a common atomic write size")
Reported-by: Yi Zhang <yi.zhang@redhat.com>
Signed-off-by: Christoph Hellwig <hch@lst.de>
Reviewed-by: Luis Chamberlain <mcgrof@kernel.org>
Reviewed-by: John Garry <john.g.garry@oracle.com>
Tested-by: Yi Zhang <yi.zhang@redhat.com>
```

**Diff:**
```diff
diff --git a/drivers/nvme/host/core.c b/drivers/nvme/host/core.c
index 520fb5f1e214..e533d791955d 100644
--- a/drivers/nvme/host/core.c
+++ b/drivers/nvme/host/core.c
@@ -2041,17 +2041,7 @@ static u32 nvme_configure_atomic_write(struct nvme_ns *ns,
 		 * no clear language in the specification prohibiting different
 		 * values for different controllers in the subsystem.
 		 */
-		atomic_bs = (1 + ns->ctrl->awupf) * bs;
-	}
-
-	if (!ns->ctrl->subsys->atomic_bs) {
-		ns->ctrl->subsys->atomic_bs = atomic_bs;
-	} else if (ns->ctrl->subsys->atomic_bs != atomic_bs) {
-		dev_err_ratelimited(ns->ctrl->device,
-			"%s: Inconsistent Atomic Write Size, Namespace will not be added: Subsystem=%d bytes, Controller/Namespace=%d bytes\n",
-			ns->disk ? ns->disk->disk_name : "?",
-			ns->ctrl->subsys->atomic_bs,
-			atomic_bs);
+		atomic_bs = (1 + ns->ctrl->subsys->awupf) * bs;
 	}
 
 	lim->atomic_write_hw_max = atomic_bs;
@@ -2386,16 +2376,6 @@ static int nvme_update_ns_info_block(struct nvme_ns *ns,
 	if (!nvme_update_disk_info(ns, id, &lim))
 		capacity = 0;
 
-	/*
-	 * Validate the max atomic write size fits within the subsystem's
-	 * atomic write capabilities.
-	 */
-	if (lim.atomic_write_hw_max > ns->ctrl->subsys->atomic_bs) {
-		blk_mq_unfreeze_queue(ns->disk->queue, memflags);
-		ret = -ENXIO;
-		goto out;
-	}
-
 	nvme_config_discard(ns, &lim);
 	if (IS_ENABLED(CONFIG_BLK_DEV_ZONED) &&
 	    ns->head->ids.csi == NVME_CSI_ZNS)
@@ -3219,6 +3199,7 @@ static int nvme_init_subsystem(struct nvme_ctrl *ctrl, struct nvme_id_ctrl *id)
 	memcpy(subsys->model, id->mn, sizeof(subsys->model));
 	subsys->vendor_id = le16_to_cpu(id->vid);
 	subsys->cmic = id->cmic;
+	subsys->awupf = le16_to_cpu(id->awupf);
 
 	/* Versions prior to 1.4 don't necessarily report a valid type */
 	if (id->cntrltype == NVME_CTRL_DISC ||
@@ -3556,6 +3537,15 @@ static int nvme_init_identify(struct nvme_ctrl *ctrl)
 		if (ret)

... (truncated 47 lines)
```

---

## Commit 4: 0e02219f

**Author:** Quentin Perret
**Date:** 2025-06-26 11:39:15
**Files Changed:** arch/arm64/kvm/arm.c

**Message:**
```
KVM: arm64: Don't free hyp pages with pKVM on GICv2

Marc reported that enabling protected mode on a device with GICv2
doesn't fail gracefully as one would expect, and leads to a host
kernel crash.

As it turns out, the first half of pKVM init happens before the vgic
probe, and so by the time we find out we have a GICv2 we're already
committed to keeping the pKVM vectors installed at EL2 -- pKVM rejects
stub HVCs for obvious security reasons. However, the error path on KVM
init leads to teardown_hyp_mode() which unconditionally frees hypervisor
allocations (including the EL2 stacks and per-cpu pages) under the
assumption that a previous cpu_hyp_uninit() execution has reset the
vectors back to the stubs, which is false with pKVM.

Interestingly, host stage-2 protection is not enabled yet at this point,
so this use-after-free may go unnoticed for a while. The issue becomes
more obvious after the finalize_pkvm() call.

Fix this by keeping track of the CPUs on which pKVM is initialized in
the kvm_hyp_initialized per-cpu variable, and use it from
teardown_hyp_mode() to skip freeing pages that are in fact used.

Fixes: a770ee80e662 ("KVM: arm64: pkvm: Disable GICv2 support")
Reported-by: Marc Zyngier <maz@kernel.org>
Signed-off-by: Quentin Perret <qperret@google.com>
Link: https://lore.kernel.org/r/20250626101014.1519345-1-qperret@google.com
Signed-off-by: Marc Zyngier <maz@kernel.org>
```

**Diff:**
```diff
diff --git a/arch/arm64/kvm/arm.c b/arch/arm64/kvm/arm.c
index 6bdf79bc5d95..b223d21c063c 100644
--- a/arch/arm64/kvm/arm.c
+++ b/arch/arm64/kvm/arm.c
@@ -2129,7 +2129,7 @@ static void cpu_hyp_init(void *discard)
 
 static void cpu_hyp_uninit(void *discard)
 {
-	if (__this_cpu_read(kvm_hyp_initialized)) {
+	if (!is_protected_kvm_enabled() && __this_cpu_read(kvm_hyp_initialized)) {
 		cpu_hyp_reset();
 		__this_cpu_write(kvm_hyp_initialized, 0);
 	}
@@ -2345,6 +2345,9 @@ static void __init teardown_hyp_mode(void)
 
 	free_hyp_pgds();
 	for_each_possible_cpu(cpu) {
+		if (per_cpu(kvm_hyp_initialized, cpu))
+			continue;
+
 		free_pages(per_cpu(kvm_arm_hyp_stack_base, cpu), NVHE_STACK_SHIFT - PAGE_SHIFT);
 
 		if (!kvm_nvhe_sym(kvm_arm_hyp_percpu_base)[cpu])
```

---

## Commit 5: 1476b218

**Author:** Leo Yan
**Date:** 2025-06-26 10:50:37
**Files Changed:** kernel/events/core.c, kernel/events/ring_buffer.c

**Message:**
```
perf/aux: Fix pending disable flow when the AUX ring buffer overruns

If an AUX event overruns, the event core layer intends to disable the
event by setting the 'pending_disable' flag. Unfortunately, the event
is not actually disabled afterwards.

In commit:

  ca6c21327c6a ("perf: Fix missing SIGTRAPs")

the 'pending_disable' flag was changed to a boolean. However, the
AUX event code was not updated accordingly. The flag ends up holding a
CPU number. If this number is zero, the flag is taken as false and the
IRQ work is never triggered.

Later, with commit:

  2b84def990d3 ("perf: Split __perf_pending_irq() out of perf_pending_irq()")

a new IRQ work 'pending_disable_irq' was introduced to handle event
disabling. The AUX event path was not updated to kick off the work queue.

To fix this bug, when an AUX ring buffer overrun is detected, call
perf_event_disable_inatomic() to initiate the pending disable flow.

Also update the outdated comment for setting the flag, to reflect the
boolean values (0 or 1).

Fixes: 2b84def990d3 ("perf: Split __perf_pending_irq() out of perf_pending_irq()")
Fixes: ca6c21327c6a ("perf: Fix missing SIGTRAPs")
Signed-off-by: Leo Yan <leo.yan@arm.com>
Signed-off-by: Ingo Molnar <mingo@kernel.org>
Reviewed-by: James Clark <james.clark@linaro.org>
Reviewed-by: Yeoreum Yun <yeoreum.yun@arm.com>
Cc: Adrian Hunter <adrian.hunter@intel.com>
Cc: Alexander Shishkin <alexander.shishkin@linux.intel.com>
Cc: Arnaldo Carvalho de Melo <acme@kernel.org>
Cc: Ian Rogers <irogers@google.com>
Cc: Jiri Olsa <jolsa@redhat.com>
Cc: Liang Kan <kan.liang@linux.intel.com>
Cc: Marco Elver <elver@google.com>
Cc: Mark Rutland <mark.rutland@arm.com>
Cc: Namhyung Kim <namhyung@kernel.org>
Cc: Peter Zijlstra <peterz@infradead.org>
Cc: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: linux-perf-users@vger.kernel.org
Link: https://lore.kernel.org/r/20250625170737.2918295-1-leo.yan@arm.com
```

**Diff:**
```diff
diff --git a/kernel/events/core.c b/kernel/events/core.c
index 1f746469fda5..7281230044d0 100644
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -7251,15 +7251,15 @@ static void __perf_pending_disable(struct perf_event *event)
 	 *  CPU-A			CPU-B
 	 *
 	 *  perf_event_disable_inatomic()
-	 *    @pending_disable = CPU-A;
+	 *    @pending_disable = 1;
 	 *    irq_work_queue();
 	 *
 	 *  sched-out
-	 *    @pending_disable = -1;
+	 *    @pending_disable = 0;
 	 *
 	 *				sched-in
 	 *				perf_event_disable_inatomic()
-	 *				  @pending_disable = CPU-B;
+	 *				  @pending_disable = 1;
 	 *				  irq_work_queue(); // FAILS
 	 *
 	 *  irq_work_run()
diff --git a/kernel/events/ring_buffer.c b/kernel/events/ring_buffer.c
index d2aef87c7e9f..aa9a759e824f 100644
--- a/kernel/events/ring_buffer.c
+++ b/kernel/events/ring_buffer.c
@@ -441,7 +441,7 @@ void *perf_aux_output_begin(struct perf_output_handle *handle,
 		 * store that will be enabled on successful return
 		 */
 		if (!handle->size) { /* A, matches D */
-			event->pending_disable = smp_processor_id();
+			perf_event_disable_inatomic(handle->event);
 			perf_output_wakeup(handle);
 			WRITE_ONCE(rb->aux_nest, 0);
 			goto err_put;
@@ -526,7 +526,7 @@ void perf_aux_output_end(struct perf_output_handle *handle, unsigned long size)
 
 	if (wakeup) {
 		if (handle->aux_flags & PERF_AUX_FLAG_TRUNCATED)
-			handle->event->pending_disable = smp_processor_id();
+			perf_event_disable_inatomic(handle->event);
 		perf_output_wakeup(handle);
 	}
 
```

---

