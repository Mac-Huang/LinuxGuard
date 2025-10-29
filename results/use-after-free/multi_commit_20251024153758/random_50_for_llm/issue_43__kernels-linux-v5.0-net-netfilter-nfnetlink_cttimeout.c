/*
 * Kernel version: linux-v5.0
 * Original file: kernels/linux-v5.0/net/netfilter/nfnetlink_cttimeout.c
 * Checker: linuxkernel-use-after-free
 */

		goto err;

	strcpy(timeout->name, nla_data(cda[CTA_TIMEOUT_NAME]));
	timeout->timeout.l3num = l3num;
	timeout->timeout.l4proto = l4proto;
	refcount_set(&timeout->refcnt, 1);
	list_add_tail_rcu(&timeout->head, &net->nfct_timeout_list);

	return 0;
err:
/* LINUXGUARD ISSUE: Line 153, Column 2
 * Message: Potential use-after-free vulnerability: Memory freed but possibly accessed later.
 */
	kfree(timeout);
err_proto_put:
	nf_ct_l4proto_put(l4proto);
	return ret;
}

static int
ctnl_timeout_fill_info(struct sk_buff *skb, u32 portid, u32 seq, u32 type,
		       int event, struct ctnl_timeout *timeout)
{
	struct nlmsghdr *nlh;
