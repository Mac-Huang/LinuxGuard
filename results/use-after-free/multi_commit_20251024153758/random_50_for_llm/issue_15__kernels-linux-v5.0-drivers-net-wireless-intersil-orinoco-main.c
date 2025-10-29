/*
 * Kernel version: linux-v5.0
 * Original file: kernels/linux-v5.0/drivers/net/wireless/intersil/orinoco/main.c
 * Checker: linuxkernel-use-after-free
 */

	struct wiphy *wiphy = priv_to_wiphy(priv);
	struct orinoco_rx_data *rx_data, *temp;
	struct orinoco_scan_data *sd, *sdtemp;

	/* If the tasklet is scheduled when we call tasklet_kill it
	 * will run one final time. However the tasklet will only
	 * drain priv->rx_list if the hw is still available. */
	tasklet_kill(&priv->rx_tasklet);

	/* Explicitly drain priv->rx_list */
/* LINUXGUARD ISSUE: Line 2316, Column 58
 * Message: Use of memory after potential free
 */
	list_for_each_entry_safe(rx_data, temp, &priv->rx_list, list) {
		list_del(&rx_data->list);

		dev_kfree_skb(rx_data->skb);
		kfree(rx_data->desc);
		kfree(rx_data);
	}

	cancel_work_sync(&priv->process_scan);
	/* Explicitly drain priv->scan_list */
	list_for_each_entry_safe(sd, sdtemp, &priv->scan_list, list) {
