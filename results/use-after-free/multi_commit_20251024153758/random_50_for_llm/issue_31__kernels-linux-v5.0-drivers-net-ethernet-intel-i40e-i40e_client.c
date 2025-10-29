/*
 * Kernel version: linux-v5.0
 * Original file: kernels/linux-v5.0/drivers/net/ethernet/intel/i40e/i40e_client.c
 * Checker: linuxkernel-use-after-free
 */

 **/
int i40e_lan_del_device(struct i40e_pf *pf)
{
	struct i40e_device *ldev, *tmp;
	int ret = -ENODEV;

	/* First, remove any client instance. */
	i40e_client_del_instance(pf);

	mutex_lock(&i40e_device_mutex);
/* LINUXGUARD ISSUE: Line 460, Column 53
 * Message: Use of memory after potential free
 */
	list_for_each_entry_safe(ldev, tmp, &i40e_devices, list) {
		if (ldev->pf == pf) {
			dev_info(&pf->pdev->dev, "Deleted LAN device PF%d bus=0x%02x dev=0x%02x func=0x%02x\n",
				 pf->hw.pf_id, pf->hw.bus.bus_id,
				 pf->hw.bus.device, pf->hw.bus.func);
			list_del(&ldev->list);
			kfree(ldev);
			ret = 0;
			break;
		}
	}
