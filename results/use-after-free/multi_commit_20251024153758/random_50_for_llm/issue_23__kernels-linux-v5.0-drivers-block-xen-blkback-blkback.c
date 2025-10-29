/*
 * Kernel version: linux-v5.0
 * Original file: kernels/linux-v5.0/drivers/block/xen-blkback/blkback.c
 * Checker: linuxkernel-use-after-free
 */

	}
	BUG_ON(num != 0);
}

void xen_blkbk_unmap_purged_grants(struct work_struct *work)
{
	struct gnttab_unmap_grant_ref unmap[BLKIF_MAX_SEGMENTS_PER_REQUEST];
	struct page *pages[BLKIF_MAX_SEGMENTS_PER_REQUEST];
	struct persistent_gnt *persistent_gnt;
	int segs_to_unmap = 0;
/* LINUXGUARD ISSUE: Line 352, Column 66
 * Message: Use of memory after potential free
 */
	struct xen_blkif_ring *ring = container_of(work, typeof(*ring), persistent_purge_work);
	struct gntab_unmap_queue_data unmap_data;

	unmap_data.pages = pages;
	unmap_data.unmap_ops = unmap;
	unmap_data.kunmap_ops = NULL;

	while(!list_empty(&ring->persistent_purge_list)) {
		persistent_gnt = list_first_entry(&ring->persistent_purge_list,
		                                  struct persistent_gnt,
		                                  remove_node);
