/*
 * Kernel version: linux-v5.0
 * Original file: kernels/linux-v5.0/drivers/scsi/lpfc/lpfc_bsg.c
 * Checker: linuxkernel-use-after-free
 */

	list_del(&evt->node);

	while (!list_empty(&evt->events_to_get)) {
		ed = list_entry(evt->events_to_get.next, typeof(*ed), node);
		list_del(&ed->node);
		kfree(ed->data);
		kfree(ed);
	}

	while (!list_empty(&evt->events_to_see)) {
/* LINUXGUARD ISSUE: Line 817, Column 57
 * Message: Use of memory after potential free
 */
		ed = list_entry(evt->events_to_see.next, typeof(*ed), node);
		list_del(&ed->node);
		kfree(ed->data);
		kfree(ed);
	}

	kfree(evt->dd_data);
	kfree(evt);
}

/**
