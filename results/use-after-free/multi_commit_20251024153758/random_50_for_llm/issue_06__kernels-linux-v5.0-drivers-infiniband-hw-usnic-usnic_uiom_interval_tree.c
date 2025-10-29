/*
 * Kernel version: linux-v5.0
 * Original file: kernels/linux-v5.0/drivers/infiniband/hw/usnic/usnic_uiom_interval_tree.c
 * Checker: linuxkernel-use-after-free
 */


	if (pivot <= last)
		MAKE_NODE_AND_APPEND(tmp, pivot, last, 1, flags, err, err_out,
					diff_set);

	return 0;

err_out:
	list_for_each_entry_safe(interval, tmp, diff_set, link) {
		list_del(&interval->link);
/* LINUXGUARD ISSUE: Line 165, Column 3
 * Message: Potential use-after-free vulnerability: Memory freed but possibly accessed later.
 */
		kfree(interval);
	}

	return err;
}

void usnic_uiom_put_interval_set(struct list_head *intervals)
{
	struct usnic_uiom_interval_node *interval, *tmp;
	list_for_each_entry_safe(interval, tmp, intervals, link)
		kfree(interval);
