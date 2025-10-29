/*
 * Kernel version: linux-v5.0
 * Original file: kernels/linux-v5.0/drivers/gpu/drm/gma500/psb_intel_lvds.c
 * Checker: linuxkernel-use-after-free
 */

			   "DDC bus registration " "failed.\n");
		goto failed_ddc;
	}

	/*
	 * Attempt to get the fixed panel mode from DDC.  Assume that the
	 * preferred mode is the right one.
	 */
	mutex_lock(&dev->mode_config.mutex);
	psb_intel_ddc_get_modes(connector, &lvds_priv->ddc_bus->adapter);
/* LINUXGUARD ISSUE: Line 758, Column 54
 * Message: Use of memory after potential free
 */
	list_for_each_entry(scan, &connector->probed_modes, head) {
		if (scan->type & DRM_MODE_TYPE_PREFERRED) {
			mode_dev->panel_fixed_mode =
			    drm_mode_duplicate(dev, scan);
			DRM_DEBUG_KMS("Using mode from DDC\n");
			goto out;	/* FIXME: check for quirks */
		}
	}

	/* Failed to get EDID, what about VBT? do we need this? */
	if (dev_priv->lfp_lvds_vbt_mode) {
