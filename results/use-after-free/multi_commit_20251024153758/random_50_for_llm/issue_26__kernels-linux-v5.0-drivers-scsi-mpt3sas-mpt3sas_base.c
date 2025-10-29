/*
 * Kernel version: linux-v5.0
 * Original file: kernels/linux-v5.0/drivers/scsi/mpt3sas/mpt3sas_base.c
 * Checker: linuxkernel-use-after-free
 */

{
	struct adapter_reply_queue *reply_q, *next;

	if (list_empty(&ioc->reply_queue_list))
		return;

	list_for_each_entry_safe(reply_q, next, &ioc->reply_queue_list, list) {
		list_del(&reply_q->list);
		free_irq(pci_irq_vector(ioc->pdev, reply_q->msix_index),
			 reply_q);
/* LINUXGUARD ISSUE: Line 2695, Column 3
 * Message: Potential use-after-free vulnerability: Memory freed but possibly accessed later.
 */
		kfree(reply_q);
	}
}

/**
 * _base_request_irq - request irq
 * @ioc: per adapter object
 * @index: msix index into vector table
 *
 * Inserting respective reply_queue into the list.
 */
