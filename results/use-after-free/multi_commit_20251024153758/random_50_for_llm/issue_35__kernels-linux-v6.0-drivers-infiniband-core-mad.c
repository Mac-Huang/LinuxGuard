/*
 * Kernel version: linux-v6.0
 * Original file: kernels/linux-v6.0/drivers/infiniband/core/mad.c
 * Checker: linuxkernel-use-after-free
 */

	class = &port_priv->version[mad_reg_req->mgmt_class_version].class;
	if (!*class) {
		/* Allocate management class table for "new" class version */
		*class = kzalloc(sizeof **class, GFP_ATOMIC);
		if (!*class) {
			ret = -ENOMEM;
			goto error1;
		}

		/* Allocate method table for this management class */
/* LINUXGUARD ISSUE: Line 1300, Column 23
 * Message: Use of memory after potential free
 */
		method = &(*class)->method_table[mgmt_class];
		if ((ret = allocate_method_table(method)))
			goto error2;
	} else {
		method = &(*class)->method_table[mgmt_class];
		if (!*method) {
			/* Allocate method table for this management class */
			if ((ret = allocate_method_table(method)))
				goto error1;
		}
	}
