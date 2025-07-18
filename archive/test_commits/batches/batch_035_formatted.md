# Linux Kernel Commit Batch Analysis

## Commit 1: f5769359

**Author:** Hao Ge
**Date:** 2025-06-25 15:55:03
**Files Changed:** include/linux/kmemleak.h, lib/alloc_tag.c, mm/kmemleak.c

**Message:**
```
mm/alloc_tag: fix the kmemleak false positive issue in the allocation of the percpu variable tag->counters

When loading a module, as long as the module has memory allocation
operations, kmemleak produces a false positive report that resembles the
following:

unreferenced object (percpu) 0x7dfd232a1650 (size 16):
  comm "modprobe", pid 1301, jiffies 4294940249
  hex dump (first 16 bytes on cpu 2):
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  backtrace (crc 0):
    kmemleak_alloc_percpu+0xb4/0xd0
    pcpu_alloc_noprof+0x700/0x1098
    load_module+0xd4/0x348
    codetag_module_init+0x20c/0x450
    codetag_load_module+0x70/0xb8
    load_module+0xef8/0x1608
    init_module_from_file+0xec/0x158
    idempotent_init_module+0x354/0x608
    __arm64_sys_finit_module+0xbc/0x150
    invoke_syscall+0xd4/0x258
    el0_svc_common.constprop.0+0xb4/0x240
    do_el0_svc+0x48/0x68
    el0_svc+0x40/0xf8
    el0t_64_sync_handler+0x10c/0x138
    el0t_64_sync+0x1ac/0x1b0

This is because the module can only indirectly reference
alloc_tag_counters through the alloc_tag section, which misleads kmemleak.

However, we don't have a kmemleak ignore interface for percpu allocations
yet.  So let's create one and invoke it for tag->counters.

[gehao@kylinos.cn: fix build error when CONFIG_DEBUG_KMEMLEAK=n, s/igonore/ignore/]
  Link: https://lkml.kernel.org/r/20250620093102.2416767-1-hao.ge@linux.dev
Link: https://lkml.kernel.org/r/20250619183154.2122608-1-hao.ge@linux.dev
Fixes: 12ca42c23775 ("alloc_tag: allocate percpu counters for module tags dynamically")
Signed-off-by: Hao Ge <gehao@kylinos.cn>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
Acked-by: Suren Baghdasaryan <surenb@google.com>	[lib/alloc_tag.c]
Cc: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
```

**Diff:**
```diff
diff --git a/include/linux/kmemleak.h b/include/linux/kmemleak.h
index 93a73c076d16..fbd424b2abb1 100644
--- a/include/linux/kmemleak.h
+++ b/include/linux/kmemleak.h
@@ -28,6 +28,7 @@ extern void kmemleak_update_trace(const void *ptr) __ref;
 extern void kmemleak_not_leak(const void *ptr) __ref;
 extern void kmemleak_transient_leak(const void *ptr) __ref;
 extern void kmemleak_ignore(const void *ptr) __ref;
+extern void kmemleak_ignore_percpu(const void __percpu *ptr) __ref;
 extern void kmemleak_scan_area(const void *ptr, size_t size, gfp_t gfp) __ref;
 extern void kmemleak_no_scan(const void *ptr) __ref;
 extern void kmemleak_alloc_phys(phys_addr_t phys, size_t size,
@@ -97,6 +98,9 @@ static inline void kmemleak_not_leak(const void *ptr)
 static inline void kmemleak_transient_leak(const void *ptr)
 {
 }
+static inline void kmemleak_ignore_percpu(const void __percpu *ptr)
+{
+}
 static inline void kmemleak_ignore(const void *ptr)
 {
 }
diff --git a/lib/alloc_tag.c b/lib/alloc_tag.c
index d48b80f3f007..3a74d63a959e 100644
--- a/lib/alloc_tag.c
+++ b/lib/alloc_tag.c
@@ -10,6 +10,7 @@
 #include <linux/seq_buf.h>
 #include <linux/seq_file.h>
 #include <linux/vmalloc.h>
+#include <linux/kmemleak.h>
 
 #define ALLOCINFO_FILE_NAME		"allocinfo"
 #define MODULE_ALLOC_TAG_VMAP_SIZE	(100000UL * sizeof(struct alloc_tag))
@@ -632,8 +633,13 @@ static int load_module(struct module *mod, struct codetag *start, struct codetag
 			       mod->name);
 			return -ENOMEM;
 		}
-	}
 
+		/*
+		 * Avoid a kmemleak false positive. The pointer to the counters is stored
+		 * in the alloc_tag section of the module and cannot be directly accessed.
+		 */
+		kmemleak_ignore_percpu(tag->counters);
+	}
 	return 0;
 }
 
diff --git a/mm/kmemleak.c b/mm/kmemleak.c

... (truncated 24 lines)
```

---

## Commit 2: df831e97

**Author:** Yu Kuai
**Date:** 2025-06-25 15:55:03
**Files Changed:** lib/group_cpus.c

**Message:**
```
lib/group_cpus: fix NULL pointer dereference from group_cpus_evenly()

While testing null_blk with configfs, echo 0 > poll_queues will trigger
following panic:

BUG: kernel NULL pointer dereference, address: 0000000000000010
Oops: Oops: 0000 [#1] SMP NOPTI
CPU: 27 UID: 0 PID: 920 Comm: bash Not tainted 6.15.0-02023-gadbdb95c8696-dirty #1238 PREEMPT(undef)
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.1-2.fc37 04/01/2014
RIP: 0010:__bitmap_or+0x48/0x70
Call Trace:
 <TASK>
 __group_cpus_evenly+0x822/0x8c0
 group_cpus_evenly+0x2d9/0x490
 blk_mq_map_queues+0x1e/0x110
 null_map_queues+0xc9/0x170 [null_blk]
 blk_mq_update_queue_map+0xdb/0x160
 blk_mq_update_nr_hw_queues+0x22b/0x560
 nullb_update_nr_hw_queues+0x71/0xf0 [null_blk]
 nullb_device_poll_queues_store+0xa4/0x130 [null_blk]
 configfs_write_iter+0x109/0x1d0
 vfs_write+0x26e/0x6f0
 ksys_write+0x79/0x180
 __x64_sys_write+0x1d/0x30
 x64_sys_call+0x45c4/0x45f0
 do_syscall_64+0xa5/0x240
 entry_SYSCALL_64_after_hwframe+0x76/0x7e

Root cause is that numgrps is set to 0, and ZERO_SIZE_PTR is returned from
kcalloc(), and later ZERO_SIZE_PTR will be deferenced.

Fix the problem by checking numgrps first in group_cpus_evenly(), and
return NULL directly if numgrps is zero.

[yukuai3@huawei.com: also fix the non-SMP version]
  Link: https://lkml.kernel.org/r/20250620010958.1265984-1-yukuai1@huaweicloud.com
Link: https://lkml.kernel.org/r/20250619132655.3318883-1-yukuai1@huaweicloud.com
Fixes: 6a6dcae8f486 ("blk-mq: Build default queue map via group_cpus_evenly()")
Signed-off-by: Yu Kuai <yukuai3@huawei.com>
Reviewed-by: Ming Lei <ming.lei@redhat.com>
Reviewed-by: Jens Axboe <axboe@kernel.dk>
Cc: ErKun Yang <yangerkun@huawei.com>
Cc: John Garry <john.g.garry@oracle.com>
Cc: Thomas Gleinxer <tglx@linutronix.de>
Cc: "zhangyi (F)" <yi.zhang@huawei.com>
Cc: <stable@vger.kernel.org>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
```

**Diff:**
```diff
diff --git a/lib/group_cpus.c b/lib/group_cpus.c
index ee272c4cefcc..18d43a406114 100644
--- a/lib/group_cpus.c
+++ b/lib/group_cpus.c
@@ -352,6 +352,9 @@ struct cpumask *group_cpus_evenly(unsigned int numgrps)
 	int ret = -ENOMEM;
 	struct cpumask *masks = NULL;
 
+	if (numgrps == 0)
+		return NULL;
+
 	if (!zalloc_cpumask_var(&nmsk, GFP_KERNEL))
 		return NULL;
 
@@ -426,8 +429,12 @@ struct cpumask *group_cpus_evenly(unsigned int numgrps)
 #else /* CONFIG_SMP */
 struct cpumask *group_cpus_evenly(unsigned int numgrps)
 {
-	struct cpumask *masks = kcalloc(numgrps, sizeof(*masks), GFP_KERNEL);
+	struct cpumask *masks;
 
+	if (numgrps == 0)
+		return NULL;
+
+	masks = kcalloc(numgrps, sizeof(*masks), GFP_KERNEL);
 	if (!masks)
 		return NULL;
 
```

---

## Commit 3: 344ef45b

**Author:** Ge Yang
**Date:** 2025-06-25 15:55:03
**Files Changed:** mm/hugetlb.c

**Message:**
```
mm/hugetlb: remove unnecessary holding of hugetlb_lock

In isolate_or_dissolve_huge_folio(), after acquiring the hugetlb_lock, it
is only for the purpose of obtaining the correct hstate, which is then
passed to alloc_and_dissolve_hugetlb_folio().

alloc_and_dissolve_hugetlb_folio() itself also acquires the hugetlb_lock. 
We can have alloc_and_dissolve_hugetlb_folio() obtain the hstate by
itself, so that isolate_or_dissolve_huge_folio() no longer needs to
acquire the hugetlb_lock.  In addition, we keep the folio_test_hugetlb()
check within isolate_or_dissolve_huge_folio().  By doing so, we can avoid
disrupting the normal path by vainly holding the hugetlb_lock.

replace_free_hugepage_folios() has the same issue, and we should address
it as well.

Addresses a possible performance problem which was added by the hotfix
113ed54ad276 ("mm/hugetlb: fix kernel NULL pointer dereference when
replacing free hugetlb folios").

Link: https://lkml.kernel.org/r/1748317010-16272-1-git-send-email-yangge1116@126.com
Fixes: 113ed54ad276 ("mm/hugetlb: fix kernel NULL pointer dereference when replacing free hugetlb folios")
Signed-off-by: Ge Yang <yangge1116@126.com>
Suggested-by: Oscar Salvador <osalvador@suse.de>
Reviewed-by: Muchun Song <muchun.song@linux.dev>
Cc: Baolin Wang <baolin.wang@linux.alibaba.com>
Cc: Barry Song <21cnbao@gmail.com>
Cc: David Hildenbrand <david@redhat.com>
Cc: <stable@vger.kernel.org>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
```

**Diff:**
```diff
diff --git a/mm/hugetlb.c b/mm/hugetlb.c
index 8746ed2fec13..9dc95eac558c 100644
--- a/mm/hugetlb.c
+++ b/mm/hugetlb.c
@@ -2787,20 +2787,24 @@ void restore_reserve_on_error(struct hstate *h, struct vm_area_struct *vma,
 /*
  * alloc_and_dissolve_hugetlb_folio - Allocate a new folio and dissolve
  * the old one
- * @h: struct hstate old page belongs to
  * @old_folio: Old folio to dissolve
  * @list: List to isolate the page in case we need to
  * Returns 0 on success, otherwise negated error.
  */
-static int alloc_and_dissolve_hugetlb_folio(struct hstate *h,
-			struct folio *old_folio, struct list_head *list)
+static int alloc_and_dissolve_hugetlb_folio(struct folio *old_folio,
+			struct list_head *list)
 {
-	gfp_t gfp_mask = htlb_alloc_mask(h) | __GFP_THISNODE;
+	gfp_t gfp_mask;
+	struct hstate *h;
 	int nid = folio_nid(old_folio);
 	struct folio *new_folio = NULL;
 	int ret = 0;
 
 retry:
+	/*
+	 * The old_folio might have been dissolved from under our feet, so make sure
+	 * to carefully check the state under the lock.
+	 */
 	spin_lock_irq(&hugetlb_lock);
 	if (!folio_test_hugetlb(old_folio)) {
 		/*
@@ -2829,8 +2833,10 @@ static int alloc_and_dissolve_hugetlb_folio(struct hstate *h,
 		cond_resched();
 		goto retry;
 	} else {
+		h = folio_hstate(old_folio);
 		if (!new_folio) {
 			spin_unlock_irq(&hugetlb_lock);
+			gfp_mask = htlb_alloc_mask(h) | __GFP_THISNODE;
 			new_folio = alloc_buddy_hugetlb_folio(h, gfp_mask, nid,
 							      NULL, NULL);
 			if (!new_folio)
@@ -2874,35 +2880,24 @@ static int alloc_and_dissolve_hugetlb_folio(struct hstate *h,
 
 int isolate_or_dissolve_huge_folio(struct folio *folio, struct list_head *list)
 {
-	struct hstate *h;
 	int ret = -EBUSY;

... (truncated 69 lines)
```

---

## Commit 4: 666c23af

**Author:** Christophe JAILLET
**Date:** 2025-06-26 00:07:33
**Files Changed:** drivers/i2c/busses/i2c-omap.c

**Message:**
```
i2c: omap: Fix an error handling path in omap_i2c_probe()

If an error occurs after calling mux_state_select(), mux_state_deselect()
should be called as already done in the remove function.

Fixes: b6ef830c60b6 ("i2c: omap: Add support for setting mux")
Signed-off-by: Christophe JAILLET <christophe.jaillet@wanadoo.fr>
Cc: <stable@vger.kernel.org> # v6.15+
Signed-off-by: Andi Shyti <andi.shyti@kernel.org>
Link: https://lore.kernel.org/r/998542981b6d2435c057dd8b9fe71743927babab.1749913149.git.christophe.jaillet@wanadoo.fr
```

**Diff:**
```diff
diff --git a/drivers/i2c/busses/i2c-omap.c b/drivers/i2c/busses/i2c-omap.c
index f1cc26ac5b80..8b01df3cc8e9 100644
--- a/drivers/i2c/busses/i2c-omap.c
+++ b/drivers/i2c/busses/i2c-omap.c
@@ -1461,13 +1461,13 @@ omap_i2c_probe(struct platform_device *pdev)
 		if (IS_ERR(mux_state)) {
 			r = PTR_ERR(mux_state);
 			dev_dbg(&pdev->dev, "failed to get I2C mux: %d\n", r);
-			goto err_disable_pm;
+			goto err_put_pm;
 		}
 		omap->mux_state = mux_state;
 		r = mux_state_select(omap->mux_state);
 		if (r) {
 			dev_err(&pdev->dev, "failed to select I2C mux: %d\n", r);
-			goto err_disable_pm;
+			goto err_put_pm;
 		}
 	}
 
@@ -1515,6 +1515,9 @@ omap_i2c_probe(struct platform_device *pdev)
 
 err_unuse_clocks:
 	omap_i2c_write_reg(omap, OMAP_I2C_CON_REG, 0);
+	if (omap->mux_state)
+		mux_state_deselect(omap->mux_state);
+err_put_pm:
 	pm_runtime_dont_use_autosuspend(omap->dev);
 	pm_runtime_put_sync(omap->dev);
 err_disable_pm:
```

---

## Commit 5: fa6f092c

**Author:** Adin Scannell
**Date:** 2025-06-25 12:28:58
**Files Changed:** tools/lib/bpf/libbpf.c, tools/testing/selftests/bpf/progs/test_global_map_resize.c

**Message:**
```
libbpf: Fix possible use-after-free for externs

The `name` field in `obj->externs` points into the BTF data at initial
open time. However, some functions may invalidate this after opening and
before loading (e.g. `bpf_map__set_value_size`), which results in
pointers into freed memory and undefined behavior.

The simplest solution is to simply `strdup` these strings, similar to
the `essent_name`, and free them at the same time.

In order to test this path, the `global_map_resize` BPF selftest is
modified slightly to ensure the presence of an extern, which causes this
test to fail prior to the fix. Given there isn't an obvious API or error
to test against, I opted to add this to the existing test as an aspect
of the resizing feature rather than duplicate the test.

Fixes: 9d0a23313b1a ("libbpf: Add capability for resizing datasec maps")
Signed-off-by: Adin Scannell <amscanne@meta.com>
Signed-off-by: Andrii Nakryiko <andrii@kernel.org>
Link: https://lore.kernel.org/bpf/20250625050215.2777374-1-amscanne@meta.com
```

**Diff:**
```diff
diff --git a/tools/lib/bpf/libbpf.c b/tools/lib/bpf/libbpf.c
index e9c641a2fb20..52e353368f58 100644
--- a/tools/lib/bpf/libbpf.c
+++ b/tools/lib/bpf/libbpf.c
@@ -597,7 +597,7 @@ struct extern_desc {
 	int sym_idx;
 	int btf_id;
 	int sec_btf_id;
-	const char *name;
+	char *name;
 	char *essent_name;
 	bool is_set;
 	bool is_weak;
@@ -4259,7 +4259,9 @@ static int bpf_object__collect_externs(struct bpf_object *obj)
 			return ext->btf_id;
 		}
 		t = btf__type_by_id(obj->btf, ext->btf_id);
-		ext->name = btf__name_by_offset(obj->btf, t->name_off);
+		ext->name = strdup(btf__name_by_offset(obj->btf, t->name_off));
+		if (!ext->name)
+			return -ENOMEM;
 		ext->sym_idx = i;
 		ext->is_weak = ELF64_ST_BIND(sym->st_info) == STB_WEAK;
 
@@ -9138,8 +9140,10 @@ void bpf_object__close(struct bpf_object *obj)
 	zfree(&obj->btf_custom_path);
 	zfree(&obj->kconfig);
 
-	for (i = 0; i < obj->nr_extern; i++)
+	for (i = 0; i < obj->nr_extern; i++) {
+		zfree(&obj->externs[i].name);
 		zfree(&obj->externs[i].essent_name);
+	}
 
 	zfree(&obj->externs);
 	obj->nr_extern = 0;
diff --git a/tools/testing/selftests/bpf/progs/test_global_map_resize.c b/tools/testing/selftests/bpf/progs/test_global_map_resize.c
index a3f220ba7025..ee65bad0436d 100644
--- a/tools/testing/selftests/bpf/progs/test_global_map_resize.c
+++ b/tools/testing/selftests/bpf/progs/test_global_map_resize.c
@@ -32,6 +32,16 @@ int my_int_last SEC(".data.array_not_last");
 
 int percpu_arr[1] SEC(".data.percpu_arr");
 
+/* at least one extern is included, to ensure that a specific
+ * regression is tested whereby resizing resulted in a free-after-use
+ * bug after type information is invalidated by the resize operation.
+ *
+ * There isn't a particularly good API to test for this specific condition,
+ * but by having externs for the resizing tests it will cover this path.

... (truncated 27 lines)
```

---

