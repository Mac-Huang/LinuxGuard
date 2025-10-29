/*
 * Kernel version: linux-v5.0
 * Original file: kernels/linux-v5.0/net/netlink/genetlink.c
 * Checker: linuxkernel-use-after-free
 */

		attrbuf = family->attrbuf;

	if (attrbuf) {
		err = nlmsg_parse(nlh, hdrlen, attrbuf, family->maxattr,
				  ops->policy, extack);
		if (err < 0)
			goto out;
	}

	info.snd_seq = nlh->nlmsg_seq;
/* LINUXGUARD ISSUE: Line 586, Column 36
 * Message: Use of memory after potential free
 */
	info.snd_portid = NETLINK_CB(skb).portid;
	info.nlhdr = nlh;
	info.genlhdr = nlmsg_data(nlh);
	info.userhdr = nlmsg_data(nlh) + GENL_HDRLEN;
	info.attrs = attrbuf;
	info.extack = extack;
	genl_info_net_set(&info, net);
	memset(&info.user_ptr, 0, sizeof(info.user_ptr));

	if (family->pre_doit) {
		err = family->pre_doit(ops, skb, &info);
