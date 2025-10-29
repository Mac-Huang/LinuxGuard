/*
 * Kernel version: linux-v5.0
 * Original file: kernels/linux-v5.0/net/rds/rdma.c
 * Checker: linuxkernel-use-after-free
 */

		goto out_pages;
	}
	op->op_bytes = nr_bytes;

out_pages:
	kfree(pages);
out_ret:
	if (ret)
		rds_rdma_free_op(op);
	else
/* LINUXGUARD ISSUE: Line 728, Column 17
 * Message: Use of memory after potential free
 */
		rds_stats_inc(s_send_rdma);

	return ret;
}

/*
 * The application wants us to pass an RDMA destination (aka MR)
 * to the remote
 */
int rds_cmsg_rdma_dest(struct rds_sock *rs, struct rds_message *rm,
			  struct cmsghdr *cmsg)
