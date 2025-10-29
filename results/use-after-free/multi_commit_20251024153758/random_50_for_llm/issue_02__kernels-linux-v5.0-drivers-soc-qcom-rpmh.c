/*
 * Kernel version: linux-v5.0
 * Original file: kernels/linux-v5.0/drivers/soc/qcom/rpmh.c
 * Checker: linuxkernel-use-after-free
 */


	return ret;
}

static void invalidate_batch(struct rpmh_ctrlr *ctrlr)
{
	struct batch_cache_req *req, *tmp;
	unsigned long flags;

	spin_lock_irqsave(&ctrlr->cache_lock, flags);
/* LINUXGUARD ISSUE: Line 323, Column 58
 * Message: Use of memory after potential free
 */
	list_for_each_entry_safe(req, tmp, &ctrlr->batch_cache, list)
		kfree(req);
	INIT_LIST_HEAD(&ctrlr->batch_cache);
	spin_unlock_irqrestore(&ctrlr->cache_lock, flags);
}

/**
 * rpmh_write_batch: Write multiple sets of RPMH commands and wait for the
 * batch to finish.
 *
 * @dev: the device making the request
