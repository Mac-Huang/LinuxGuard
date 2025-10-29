/*
 * Kernel version: linux-v5.0
 * Original file: kernels/linux-v5.0/arch/x86/kernel/cpu/mce/amd.c
 * Checker: linuxkernel-use-after-free
 */


	if (b->interrupt_capable) {
		threshold_ktype.default_attrs[2] = &interrupt_enable.attr;
		b->interrupt_enable = 1;
	} else {
		threshold_ktype.default_attrs[2] = NULL;
	}

	INIT_LIST_HEAD(&b->miscj);

/* LINUXGUARD ISSUE: Line 1164, Column 43
 * Message: Use of memory after potential free
 */
	if (per_cpu(threshold_banks, cpu)[bank]->blocks) {
		list_add(&b->miscj,
			 &per_cpu(threshold_banks, cpu)[bank]->blocks->miscj);
	} else {
		per_cpu(threshold_banks, cpu)[bank]->blocks = b;
	}

	err = kobject_init_and_add(&b->kobj, &threshold_ktype,
				   per_cpu(threshold_banks, cpu)[bank]->kobj,
				   get_name(bank, b));
	if (err)
