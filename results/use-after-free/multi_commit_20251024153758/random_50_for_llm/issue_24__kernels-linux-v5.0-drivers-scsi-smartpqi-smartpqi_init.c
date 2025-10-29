/*
 * Kernel version: linux-v5.0
 * Original file: kernels/linux-v5.0/drivers/scsi/smartpqi/smartpqi_init.c
 * Checker: linuxkernel-use-after-free
 */


out:
	list_for_each_entry_safe(device, next, &new_device_list_head,
		new_device_list_entry) {
		if (device->keep_device)
			continue;
		list_del(&device->new_device_list_entry);
		pqi_free_device(device);
	}

/* LINUXGUARD ISSUE: Line 2159, Column 2
 * Message: Potential use-after-free vulnerability: Memory freed but possibly accessed later.
 */
	kfree(new_device_list);
	kfree(physdev_list);
	kfree(logdev_list);
	kfree(id_phys);

	return rc;
}

static void pqi_remove_all_scsi_devices(struct pqi_ctrl_info *ctrl_info)
{
	unsigned long flags;
