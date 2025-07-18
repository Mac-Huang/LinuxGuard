# Linux Kernel Commit Batch Analysis

## Commit 1: 48fd7ebe

**Author:** Kuan-Wei Chiu
**Date:** 2025-06-19 20:48:03
**Files Changed:** drivers/md/bcache/alloc.c, drivers/md/bcache/bcache.h, drivers/md/bcache/bset.c, drivers/md/bcache/bset.h, drivers/md/bcache/btree.c (+6 more)

**Message:**
```
Revert "bcache: remove heap-related macros and switch to generic min_heap"

This reverts commit 866898efbb25bb44fd42848318e46db9e785973a.

The generic bottom-up min_heap implementation causes performance
regression in invalidate_buckets_lru(), a hot path in bcache.  Before the
cache is fully populated, new_bucket_prio() often returns zero, leading to
many equal comparisons.  In such cases, bottom-up sift_down performs up to
2 * log2(n) comparisons, while the original top-down approach completes
with just O() comparisons, resulting in a measurable performance gap.

The performance degradation is further worsened by the non-inlined
min_heap API functions introduced in commit 92a8b224b833 ("lib/min_heap:
introduce non-inline versions of min heap API functions"), adding function
call overhead to this critical path.

As reported by Robert, bcache now suffers from latency spikes, with P100
(max) latency increasing from 600 ms to 2.4 seconds every 5 minutes. 
These regressions degrade bcache's effectiveness as a low-latency cache
layer and lead to frequent timeouts and application stalls in production
environments.

This revert aims to restore bcache's original low-latency behavior.

Link: https://lore.kernel.org/lkml/CAJhEC05+0S69z+3+FB2Cd0hD+pCRyWTKLEOsc8BOmH73p1m+KQ@mail.gmail.com
Link: https://lkml.kernel.org/r/20250614202353.1632957-3-visitorckw@gmail.com
Fixes: 866898efbb25 ("bcache: remove heap-related macros and switch to generic min_heap")
Fixes: 92a8b224b833 ("lib/min_heap: introduce non-inline versions of min heap API functions")
Signed-off-by: Kuan-Wei Chiu <visitorckw@gmail.com>
Reported-by: Robert Pang <robertpang@google.com>
Closes: https://lore.kernel.org/linux-bcache/CAJhEC06F_AtrPgw2-7CvCqZgeStgCtitbD-ryuPpXQA-JG5XXw@mail.gmail.com
Acked-by: Coly Li <colyli@kernel.org>
Cc: Ching-Chun (Jim) Huang <jserv@ccns.ncku.edu.tw>
Cc: Kent Overstreet <kent.overstreet@linux.dev>
Cc: <stable@vger.kernel.org>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
```

**Diff:**
```diff
diff --git a/drivers/md/bcache/alloc.c b/drivers/md/bcache/alloc.c
index da50f6661bae..48ce750bf70a 100644
--- a/drivers/md/bcache/alloc.c
+++ b/drivers/md/bcache/alloc.c
@@ -164,68 +164,40 @@ static void bch_invalidate_one_bucket(struct cache *ca, struct bucket *b)
  * prio is worth 1/8th of what INITIAL_PRIO is worth.
  */
 
-static inline unsigned int new_bucket_prio(struct cache *ca, struct bucket *b)
-{
-	unsigned int min_prio = (INITIAL_PRIO - ca->set->min_prio) / 8;
-
-	return (b->prio - ca->set->min_prio + min_prio) * GC_SECTORS_USED(b);
-}
-
-static inline bool new_bucket_max_cmp(const void *l, const void *r, void *args)
-{
-	struct bucket **lhs = (struct bucket **)l;
-	struct bucket **rhs = (struct bucket **)r;
-	struct cache *ca = args;
-
-	return new_bucket_prio(ca, *lhs) > new_bucket_prio(ca, *rhs);
-}
-
-static inline bool new_bucket_min_cmp(const void *l, const void *r, void *args)
-{
-	struct bucket **lhs = (struct bucket **)l;
-	struct bucket **rhs = (struct bucket **)r;
-	struct cache *ca = args;
-
-	return new_bucket_prio(ca, *lhs) < new_bucket_prio(ca, *rhs);
-}
-
-static inline void new_bucket_swap(void *l, void *r, void __always_unused *args)
-{
-	struct bucket **lhs = l, **rhs = r;
+#define bucket_prio(b)							\
+({									\
+	unsigned int min_prio = (INITIAL_PRIO - ca->set->min_prio) / 8;	\
+									\
+	(b->prio - ca->set->min_prio + min_prio) * GC_SECTORS_USED(b);	\
+})
 
-	swap(*lhs, *rhs);
-}
+#define bucket_max_cmp(l, r)	(bucket_prio(l) < bucket_prio(r))
+#define bucket_min_cmp(l, r)	(bucket_prio(l) > bucket_prio(r))
 
 static void invalidate_buckets_lru(struct cache *ca)
 {

... (truncated 1002 lines)
```

---

## Commit 2: 517f496e

**Author:** David Hildenbrand
**Date:** 2025-06-19 20:48:01
**Files Changed:** mm/gup.c

**Message:**
```
mm/gup: revert "mm: gup: fix infinite loop within __get_longterm_locked"

After commit 1aaf8c122918 ("mm: gup: fix infinite loop within
__get_longterm_locked") we are able to longterm pin folios that are not
supposed to get longterm pinned, simply because they temporarily have the
LRU flag cleared (esp.  temporarily isolated).

For example, two __get_longterm_locked() callers can race, or
__get_longterm_locked() can race with anything else that temporarily
isolates folios.

The introducing commit mentions the use case of a driver that uses
vm_ops->fault to insert pages allocated through cma_alloc() into the page
tables, assuming they can later get longterm pinned.  These pages/ folios
would never have the LRU flag set and consequently cannot get isolated. 
There is no known in-tree user making use of that so far, fortunately.

To handle that in the future -- and avoid retrying forever to
isolate/migrate them -- we will need a different mechanism for the CMA
area *owner* to indicate that it actually already allocated the page and
is fine with longterm pinning it.  The LRU flag is not suitable for that.

Probably we can lookup the relevant CMA area and query the bitmap; we only
have have to care about some races, probably.  If already allocated, we
could just allow longterm pinning)

Anyhow, let's fix the "must not be longterm pinned" problem first by
reverting the original commit.

Link: https://lkml.kernel.org/r/20250611131314.594529-1-david@redhat.com
Fixes: 1aaf8c122918 ("mm: gup: fix infinite loop within __get_longterm_locked")
Signed-off-by: David Hildenbrand <david@redhat.com>
Closes: https://lore.kernel.org/all/20250522092755.GA3277597@tiffany/
Reported-by: Hyesoo Yu <hyesoo.yu@samsung.com>
Reviewed-by: John Hubbard <jhubbard@nvidia.com>
Cc: Jason Gunthorpe <jgg@ziepe.ca>
Cc: Peter Xu <peterx@redhat.com>
Cc: Zhaoyang Huang <zhaoyang.huang@unisoc.com>
Cc: Aijun Sun <aijun.sun@unisoc.com>
Cc: Alistair Popple <apopple@nvidia.com>
Cc: <stable@vger.kernel.org>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
```

**Diff:**
```diff
diff --git a/mm/gup.c b/mm/gup.c
index e065a49842a8..3c39cbbeebef 100644
--- a/mm/gup.c
+++ b/mm/gup.c
@@ -2303,13 +2303,13 @@ static void pofs_unpin(struct pages_or_folios *pofs)
 /*
  * Returns the number of collected folios. Return value is always >= 0.
  */
-static void collect_longterm_unpinnable_folios(
+static unsigned long collect_longterm_unpinnable_folios(
 		struct list_head *movable_folio_list,
 		struct pages_or_folios *pofs)
 {
+	unsigned long i, collected = 0;
 	struct folio *prev_folio = NULL;
 	bool drain_allow = true;
-	unsigned long i;
 
 	for (i = 0; i < pofs->nr_entries; i++) {
 		struct folio *folio = pofs_get_folio(pofs, i);
@@ -2321,6 +2321,8 @@ static void collect_longterm_unpinnable_folios(
 		if (folio_is_longterm_pinnable(folio))
 			continue;
 
+		collected++;
+
 		if (folio_is_device_coherent(folio))
 			continue;
 
@@ -2342,6 +2344,8 @@ static void collect_longterm_unpinnable_folios(
 				    NR_ISOLATED_ANON + folio_is_file_lru(folio),
 				    folio_nr_pages(folio));
 	}
+
+	return collected;
 }
 
 /*
@@ -2418,9 +2422,11 @@ static long
 check_and_migrate_movable_pages_or_folios(struct pages_or_folios *pofs)
 {
 	LIST_HEAD(movable_folio_list);
+	unsigned long collected;
 
-	collect_longterm_unpinnable_folios(&movable_folio_list, pofs);
-	if (list_empty(&movable_folio_list))
+	collected = collect_longterm_unpinnable_folios(&movable_folio_list,
+						       pofs);
+	if (!collected)
 		return 0;

... (truncated 2 lines)
```

---

## Commit 3: 85d6fbc4

**Author:** Thomas Fourier
**Date:** 2025-06-19 23:07:57
**Files Changed:** drivers/scsi/fnic/fnic_fcs.c

**Message:**
```
scsi: fnic: Fix missing DMA mapping error in fnic_send_frame()

dma_map_XXX() can fail and should be tested for errors with
dma_mapping_error().

Fixes: a63e78eb2b0f ("scsi: fnic: Add support for fabric based solicited requests and responses")
Signed-off-by: Thomas Fourier <fourier.thomas@gmail.com>
Link: https://lore.kernel.org/r/20250618065715.14740-2-fourier.thomas@gmail.com
Reviewed-by: Karan Tilak Kumar <kartilak@cisco.com>
Reviewed-by: John Menghini <jmeneghi@redhat.com>
Signed-off-by: Martin K. Petersen <martin.petersen@oracle.com>
```

**Diff:**
```diff
diff --git a/drivers/scsi/fnic/fnic_fcs.c b/drivers/scsi/fnic/fnic_fcs.c
index 1e8cd64f9a5c..103ab6f1f7cd 100644
--- a/drivers/scsi/fnic/fnic_fcs.c
+++ b/drivers/scsi/fnic/fnic_fcs.c
@@ -636,6 +636,8 @@ static int fnic_send_frame(struct fnic *fnic, void *frame, int frame_len)
 	unsigned long flags;
 
 	pa = dma_map_single(&fnic->pdev->dev, frame, frame_len, DMA_TO_DEVICE);
+	if (dma_mapping_error(&fnic->pdev->dev, pa))
+		return -ENOMEM;
 
 	if ((fnic_fc_trace_set_data(fnic->fnic_num,
 				FNIC_FC_SEND | 0x80, (char *) frame,
```

---

## Commit 4: 74f46a05

**Author:** Karan Tilak Kumar
**Date:** 2025-06-19 23:06:27
**Files Changed:** drivers/scsi/fnic/fdls_disc.c, drivers/scsi/fnic/fnic.h

**Message:**
```
scsi: fnic: Turn off FDMI ACTIVE flags on link down

When the link goes down and comes up, FDMI requests are not sent out
anymore.

Fix bug by turning off FNIC_FDMI_ACTIVE when the link goes down.

Fixes: 09c1e6ab4ab2 ("scsi: fnic: Add and integrate support for FDMI")
Reviewed-by: Sesidhar Baddela <sebaddel@cisco.com>
Reviewed-by: Arulprabhu Ponnusamy <arulponn@cisco.com>
Reviewed-by: Gian Carlo Boffa <gcboffa@cisco.com>
Reviewed-by: Arun Easi <aeasi@cisco.com>
Tested-by: Karan Tilak Kumar <kartilak@cisco.com>
Cc: stable@vger.kernel.org
Signed-off-by: Karan Tilak Kumar <kartilak@cisco.com>
Link: https://lore.kernel.org/r/20250618003431.6314-2-kartilak@cisco.com
Reviewed-by: John Meneghini <jmeneghi@redhat.com>
Signed-off-by: Martin K. Petersen <martin.petersen@oracle.com>
```

**Diff:**
```diff
diff --git a/drivers/scsi/fnic/fdls_disc.c b/drivers/scsi/fnic/fdls_disc.c
index 36b498ad55b4..fa9cf0b37d72 100644
--- a/drivers/scsi/fnic/fdls_disc.c
+++ b/drivers/scsi/fnic/fdls_disc.c
@@ -5029,9 +5029,12 @@ void fnic_fdls_link_down(struct fnic_iport_s *iport)
 		fdls_delete_tport(iport, tport);
 	}
 
-	if ((fnic_fdmi_support == 1) && (iport->fabric.fdmi_pending > 0)) {
-		timer_delete_sync(&iport->fabric.fdmi_timer);
-		iport->fabric.fdmi_pending = 0;
+	if (fnic_fdmi_support == 1) {
+		if (iport->fabric.fdmi_pending > 0) {
+			timer_delete_sync(&iport->fabric.fdmi_timer);
+			iport->fabric.fdmi_pending = 0;
+		}
+		iport->flags &= ~FNIC_FDMI_ACTIVE;
 	}
 
 	FNIC_FCS_DBG(KERN_INFO, fnic->host, fnic->fnic_num,
diff --git a/drivers/scsi/fnic/fnic.h b/drivers/scsi/fnic/fnic.h
index 86e293ce530d..c2fdc6553e62 100644
--- a/drivers/scsi/fnic/fnic.h
+++ b/drivers/scsi/fnic/fnic.h
@@ -30,7 +30,7 @@
 
 #define DRV_NAME		"fnic"
 #define DRV_DESCRIPTION		"Cisco FCoE HBA Driver"
-#define DRV_VERSION		"1.8.0.1"
+#define DRV_VERSION		"1.8.0.2"
 #define PFX			DRV_NAME ": "
 #define DFX                     DRV_NAME "%d: "
 
```

---

## Commit 5: a35b29bd

**Author:** Karan Tilak Kumar
**Date:** 2025-06-19 23:06:27
**Files Changed:** drivers/scsi/fnic/fdls_disc.c, drivers/scsi/fnic/fnic.h, drivers/scsi/fnic/fnic_fdls.h

**Message:**
```
scsi: fnic: Fix crash in fnic_wq_cmpl_handler when FDMI times out

When both the RHBA and RPA FDMI requests time out, fnic reuses a frame to
send ABTS for each of them. On send completion, this causes an attempt to
free the same frame twice that leads to a crash.

Fix crash by allocating separate frames for RHBA and RPA, and modify ABTS
logic accordingly.

Tested by checking MDS for FDMI information.

Tested by using instrumented driver to:

 - Drop PLOGI response
 - Drop RHBA response
 - Drop RPA response
 - Drop RHBA and RPA response
 - Drop PLOGI response + ABTS response
 - Drop RHBA response + ABTS response
 - Drop RPA response + ABTS response
 - Drop RHBA and RPA response + ABTS response for both of them

Fixes: 09c1e6ab4ab2 ("scsi: fnic: Add and integrate support for FDMI")
Reviewed-by: Sesidhar Baddela <sebaddel@cisco.com>
Reviewed-by: Arulprabhu Ponnusamy <arulponn@cisco.com>
Reviewed-by: Gian Carlo Boffa <gcboffa@cisco.com>
Tested-by: Arun Easi <aeasi@cisco.com>
Co-developed-by: Arun Easi <aeasi@cisco.com>
Signed-off-by: Arun Easi <aeasi@cisco.com>
Tested-by: Karan Tilak Kumar <kartilak@cisco.com>
Cc: stable@vger.kernel.org
Signed-off-by: Karan Tilak Kumar <kartilak@cisco.com>
Link: https://lore.kernel.org/r/20250618003431.6314-1-kartilak@cisco.com
Reviewed-by: John Meneghini <jmeneghi@redhat.com>
Signed-off-by: Martin K. Petersen <martin.petersen@oracle.com>
```

**Diff:**
```diff
diff --git a/drivers/scsi/fnic/fdls_disc.c b/drivers/scsi/fnic/fdls_disc.c
index f8ab69c51dab..36b498ad55b4 100644
--- a/drivers/scsi/fnic/fdls_disc.c
+++ b/drivers/scsi/fnic/fdls_disc.c
@@ -763,47 +763,69 @@ static void fdls_send_fabric_abts(struct fnic_iport_s *iport)
 	iport->fabric.timer_pending = 1;
 }
 
-static void fdls_send_fdmi_abts(struct fnic_iport_s *iport)
+static uint8_t *fdls_alloc_init_fdmi_abts_frame(struct fnic_iport_s *iport,
+		uint16_t oxid)
 {
-	uint8_t *frame;
+	struct fc_frame_header *pfdmi_abts;
 	uint8_t d_id[3];
+	uint8_t *frame;
 	struct fnic *fnic = iport->fnic;
-	struct fc_frame_header *pfabric_abts;
-	unsigned long fdmi_tov;
-	uint16_t oxid;
-	uint16_t frame_size = FNIC_ETH_FCOE_HDRS_OFFSET +
-			sizeof(struct fc_frame_header);
 
 	frame = fdls_alloc_frame(iport);
 	if (frame == NULL) {
 		FNIC_FCS_DBG(KERN_ERR, fnic->host, fnic->fnic_num,
 				"Failed to allocate frame to send FDMI ABTS");
-		return;
+		return NULL;
 	}
 
-	pfabric_abts = (struct fc_frame_header *) (frame + FNIC_ETH_FCOE_HDRS_OFFSET);
+	pfdmi_abts = (struct fc_frame_header *) (frame + FNIC_ETH_FCOE_HDRS_OFFSET);
 	fdls_init_fabric_abts_frame(frame, iport);
 
 	hton24(d_id, FC_FID_MGMT_SERV);
-	FNIC_STD_SET_D_ID(*pfabric_abts, d_id);
+	FNIC_STD_SET_D_ID(*pfdmi_abts, d_id);
+	FNIC_STD_SET_OX_ID(*pfdmi_abts, oxid);
+
+	return frame;
+}
+
+static void fdls_send_fdmi_abts(struct fnic_iport_s *iport)
+{
+	uint8_t *frame;
+	unsigned long fdmi_tov;
+	uint16_t frame_size = FNIC_ETH_FCOE_HDRS_OFFSET +
+			sizeof(struct fc_frame_header);
 

... (truncated 157 lines)
```

---

