/*
 * Kernel version: linux-v5.0
 * Original file: kernels/linux-v5.0/drivers/net/ethernet/sfc/ef10.c
 * Checker: linuxkernel-use-after-free
 */

		if (rc)
			goto fail_add_vlan;
	}

	return 0;

fail_add_vlan:
	efx_ef10_filter_cleanup_vlans(efx);
	efx->filter_state = NULL;
fail:
/* LINUXGUARD ISSUE: Line 5026, Column 2
 * Message: Potential use-after-free vulnerability: Memory freed but possibly accessed later.
 */
	kfree(table);
	return rc;
}

/* Caller must hold efx->filter_sem for read if race against
 * efx_ef10_filter_table_remove() is possible
 */
static void efx_ef10_filter_table_restore(struct efx_nic *efx)
{
	struct efx_ef10_filter_table *table = efx->filter_state;
	struct efx_ef10_nic_data *nic_data = efx->nic_data;
