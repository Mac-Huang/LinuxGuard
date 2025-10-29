/*
 * Kernel version: linux-v5.0
 * Original file: kernels/linux-v5.0/drivers/net/wireless/ath/dfs_pri_detector.c
 * Checker: linuxkernel-use-after-free
 */

static void pool_deregister_ref(void)
{
	spin_lock_bh(&pool_lock);
	singleton_pool_references--;
	DFS_POOL_STAT_DEC(pool_reference);
	if (singleton_pool_references == 0) {
		/* free singleton pools with no references left */
		struct pri_sequence *ps, *ps0;
		struct pulse_elem *p, *p0;

/* LINUXGUARD ISSUE: Line 105, Column 48
 * Message: Use of memory after potential free
 */
		list_for_each_entry_safe(p, p0, &pulse_pool, head) {
			list_del(&p->head);
			DFS_POOL_STAT_DEC(pulse_allocated);
			kfree(p);
		}
		list_for_each_entry_safe(ps, ps0, &pseq_pool, head) {
			list_del(&ps->head);
			DFS_POOL_STAT_DEC(pseq_allocated);
			kfree(ps);
		}
	}
