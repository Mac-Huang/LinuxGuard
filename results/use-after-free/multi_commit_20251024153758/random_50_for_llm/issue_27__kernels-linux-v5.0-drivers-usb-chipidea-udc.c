/*
 * Kernel version: linux-v5.0
 * Original file: kernels/linux-v5.0/drivers/usb/chipidea/udc.c
 * Checker: linuxkernel-use-after-free
 */


	if (ep == NULL || req == NULL || hwreq->req.status != -EALREADY ||
		hwep->ep.desc == NULL || list_empty(&hwreq->queue) ||
		list_empty(&hwep->qh.queue))
		return -EINVAL;

	spin_lock_irqsave(hwep->lock, flags);

	hw_ep_flush(hwep->ci, hwep->num, hwep->dir);

/* LINUXGUARD ISSUE: Line 1421, Column 55
 * Message: Use of memory after potential free
 */
	list_for_each_entry_safe(node, tmpnode, &hwreq->tds, td) {
		dma_pool_free(hwep->td_pool, node->ptr, node->dma);
		list_del(&node->td);
		kfree(node);
	}

	/* pop request */
	list_del_init(&hwreq->queue);

	usb_gadget_unmap_request(&hwep->ci->gadget, req, hwep->dir);

