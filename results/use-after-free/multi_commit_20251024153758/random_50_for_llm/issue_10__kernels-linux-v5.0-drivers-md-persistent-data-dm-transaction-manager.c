/*
 * Kernel version: linux-v5.0
 * Original file: kernels/linux-v5.0/drivers/md/persistent-data/dm-transaction-manager.c
 * Checker: linuxkernel-use-after-free
 */

static void wipe_shadow_table(struct dm_transaction_manager *tm)
{
	struct shadow_info *si;
	struct hlist_node *tmp;
	struct hlist_head *bucket;
	int i;

	spin_lock(&tm->lock);
	for (i = 0; i < DM_HASH_SIZE; i++) {
		bucket = tm->buckets + i;
/* LINUXGUARD ISSUE: Line 149, Column 46
 * Message: Use of memory after potential free
 */
		hlist_for_each_entry_safe(si, tmp, bucket, hlist)
			kfree(si);

		INIT_HLIST_HEAD(bucket);
	}

	spin_unlock(&tm->lock);
}

/*----------------------------------------------------------------*/

