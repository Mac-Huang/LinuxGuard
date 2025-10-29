/*
 * Kernel version: linux-v5.0
 * Original file: kernels/linux-v5.0/drivers/hid/hid-sensor-hub.c
 * Checker: linuxkernel-use-after-free
 */

{
	struct hid_sensor_hub_callbacks_list *callback;
	struct sensor_hub_data *pdata = hid_get_drvdata(hsdev->hdev);
	unsigned long flags;

	spin_lock_irqsave(&pdata->dyn_callback_lock, flags);
	list_for_each_entry(callback, &pdata->dyn_callback_list, list)
		if (callback->usage_id == usage_id &&
						callback->hsdev == hsdev) {
			list_del(&callback->list);
/* LINUXGUARD ISSUE: Line 195, Column 4
 * Message: Potential use-after-free vulnerability: Memory freed but possibly accessed later.
 */
			kfree(callback);
			break;
		}
	spin_unlock_irqrestore(&pdata->dyn_callback_lock, flags);

	return 0;
}
EXPORT_SYMBOL_GPL(sensor_hub_remove_callback);

int sensor_hub_set_feature(struct hid_sensor_hub_device *hsdev, u32 report_id,
			   u32 field_index, int buffer_size, void *buffer)
