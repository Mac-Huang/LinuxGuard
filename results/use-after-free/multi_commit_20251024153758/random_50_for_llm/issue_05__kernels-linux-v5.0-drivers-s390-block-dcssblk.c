/*
 * Kernel version: linux-v5.0
 * Original file: kernels/linux-v5.0/drivers/s390/block/dcssblk.c
 * Checker: linuxkernel-use-after-free
 */


	list_del(&dev_info->lh);
	kill_dax(dev_info->dax_dev);
	put_dax(dev_info->dax_dev);
	del_gendisk(dev_info->gd);
	blk_cleanup_queue(dev_info->dcssblk_queue);
	dev_info->gd->queue = NULL;
	put_disk(dev_info->gd);

	/* unload all related segments */
/* LINUXGUARD ISSUE: Line 793, Column 50
 * Message: Use of memory after potential free
 */
	list_for_each_entry(entry, &dev_info->seg_list, lh)
		segment_unload(entry->segment_name);

	up_write(&dcssblk_devices_sem);

	device_unregister(&dev_info->dev);
	put_device(&dev_info->dev);

	rc = count;
out_buf:
	kfree(local_buf);
