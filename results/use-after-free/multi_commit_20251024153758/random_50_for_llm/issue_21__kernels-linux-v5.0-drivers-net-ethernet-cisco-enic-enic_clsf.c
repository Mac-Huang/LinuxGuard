/*
 * Kernel version: linux-v5.0
 * Original file: kernels/linux-v5.0/drivers/net/ethernet/cisco/enic/enic_clsf.c
 * Checker: linuxkernel-use-after-free
 */

	spin_lock_bh(&enic->rfs_h.lock);
	for (i = 0; i < (1 << ENIC_RFS_FLW_BITSHIFT); i++) {
		struct hlist_head *hhead;
		struct hlist_node *tmp;
		struct enic_rfs_fltr_node *n;

		hhead = &enic->rfs_h.ht_head[i];
		hlist_for_each_entry_safe(n, tmp, hhead, node) {
			enic_delfltr(enic, n->fltr_id);
			hlist_del(&n->node);
/* LINUXGUARD ISSUE: Line 99, Column 4
 * Message: Potential use-after-free vulnerability: Memory freed but possibly accessed later.
 */
			kfree(n);
			enic->rfs_h.free++;
		}
	}
	spin_unlock_bh(&enic->rfs_h.lock);
}

struct enic_rfs_fltr_node *htbl_fltr_search(struct enic *enic, u16 fltr_id)
{
	int i;

