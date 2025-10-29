/*
 * Kernel version: linux-v5.0
 * Original file: kernels/linux-v5.0/drivers/scsi/lpfc/lpfc_bsg.c
 * Checker: linuxkernel-use-after-free
 */

	event_reply->immed_data = evt_dat->immed_dat;
	if (evt_dat->len > 0)
		bsg_reply->reply_payload_rcv_len =
			sg_copy_from_buffer(job->request_payload.sg_list,
					    job->request_payload.sg_cnt,
					    evt_dat->data, evt_dat->len);
	else
		bsg_reply->reply_payload_rcv_len = 0;

	if (evt_dat) {
/* LINUXGUARD ISSUE: Line 1361, Column 3
 * Message: Potential use-after-free vulnerability: Memory freed but possibly accessed later.
 */
		kfree(evt_dat->data);
		kfree(evt_dat);
	}

	spin_lock_irqsave(&phba->ct_ev_lock, flags);
	lpfc_bsg_event_unref(evt);
	spin_unlock_irqrestore(&phba->ct_ev_lock, flags);
	job->dd_data = NULL;
	bsg_reply->result = 0;
	bsg_job_done(job, bsg_reply->result,
		       bsg_reply->reply_payload_rcv_len);
