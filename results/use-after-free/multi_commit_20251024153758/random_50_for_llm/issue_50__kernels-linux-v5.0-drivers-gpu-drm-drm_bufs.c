/*
 * Kernel version: linux-v5.0
 * Original file: kernels/linux-v5.0/drivers/gpu/drm/drm_bufs.c
 * Checker: linuxkernel-use-after-free
 */

 * \sa drm_legacy_addmap
 */
int drm_legacy_rmmap_locked(struct drm_device *dev, struct drm_local_map *map)
{
	struct drm_map_list *r_list = NULL, *list_t;
	drm_dma_handle_t dmah;
	int found = 0;
	struct drm_master *master;

	/* Find the list entry for the map and remove it */
/* LINUXGUARD ISSUE: Line 499, Column 58
 * Message: Use of memory after potential free
 */
	list_for_each_entry_safe(r_list, list_t, &dev->maplist, head) {
		if (r_list->map == map) {
			master = r_list->master;
			list_del(&r_list->head);
			drm_ht_remove_key(&dev->map_hash,
					  r_list->user_token >> PAGE_SHIFT);
			kfree(r_list);
			found = 1;
			break;
		}
	}
