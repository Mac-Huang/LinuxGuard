/*
 * Kernel version: linux-v5.0
 * Original file: kernels/linux-v5.0/drivers/rapidio/rio.c
 * Checker: linuxkernel-use-after-free
 */

	/* If we can't find an exact match, fail */
	if (!found) {
		rc = -EINVAL;
		goto out;
	}

	/* Release the doorbell resource */
	rc = release_resource(dbell->res);

	/* Free the doorbell event */
/* LINUXGUARD ISSUE: Line 503, Column 2
 * Message: Potential use-after-free vulnerability: Memory freed but possibly accessed later.
 */
	kfree(dbell);

      out:
	return rc;
}
EXPORT_SYMBOL_GPL(rio_release_inb_dbell);

/**
 * rio_request_outb_dbell - request outbound doorbell message range
 * @rdev: RIO device from which to allocate the doorbell resource
 * @start: Doorbell message range start
