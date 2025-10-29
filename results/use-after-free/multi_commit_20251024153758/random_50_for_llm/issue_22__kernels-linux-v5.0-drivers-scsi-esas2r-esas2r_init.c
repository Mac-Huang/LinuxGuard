/*
 * Kernel version: linux-v5.0
 * Original file: kernels/linux-v5.0/drivers/scsi/esas2r/esas2r_init.c
 * Checker: linuxkernel-use-after-free
 */


	list_for_each_entry_safe(memdesc, next, &a->free_sg_list_head,
				 next_desc) {
		esas2r_initmem_free(a, memdesc);
	}

	/* Following frees everything allocated via alloc_vda_req */
	list_for_each_entry_safe(memdesc, next, &a->vrq_mds_head, next_desc) {
		esas2r_initmem_free(a, memdesc);
		list_del(&memdesc->next_desc);
/* LINUXGUARD ISSUE: Line 521, Column 3
 * Message: Potential use-after-free vulnerability: Memory freed but possibly accessed later.
 */
		kfree(memdesc);
	}

	kfree(a->first_ae_req);
	a->first_ae_req = NULL;

	kfree(a->sg_list_mds);
	a->sg_list_mds = NULL;

	kfree(a->req_table);
	a->req_table = NULL;
