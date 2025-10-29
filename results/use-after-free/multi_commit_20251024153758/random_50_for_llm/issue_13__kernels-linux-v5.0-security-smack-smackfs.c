/*
 * Kernel version: linux-v5.0
 * Original file: kernels/linux-v5.0/security/smack/smackfs.c
 * Checker: linuxkernel-use-after-free
 */

	newname.sin_addr.s_addr &= mask.s_addr;
	/*
	 * Only allow one writer at a time. Writes should be
	 * quite rare and small in any case.
	 */
	mutex_lock(&smk_net4addr_lock);

	nsa = newname.sin_addr.s_addr;
	/* try to find if the prefix is already in the list */
	found = 0;
/* LINUXGUARD ISSUE: Line 1245, Column 51
 * Message: Use of memory after potential free
 */
	list_for_each_entry_rcu(snp, &smk_net4addr_list, list) {
		if (snp->smk_host.s_addr == nsa && snp->smk_masks == masks) {
			found = 1;
			break;
		}
	}
	smk_netlabel_audit_set(&audit_info);

	if (found == 0) {
		snp = kzalloc(sizeof(*snp), GFP_KERNEL);
		if (snp == NULL)
