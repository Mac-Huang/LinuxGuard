/*
 * Kernel version: linux-v5.0
 * Original file: kernels/linux-v5.0/drivers/staging/wilc1000/wilc_wfi_cfgoperations.c
 * Checker: linuxkernel-use-after-free
 */

static void remove_network_from_shadow(struct timer_list *t)
{
	struct wilc_priv *priv = from_timer(priv, t, aging_timer);
	unsigned long now = jiffies;
	int i, j;

	for (i = 0; i < priv->scanned_cnt; i++) {
		if (!time_after(now, priv->scanned_shadow[i].time_scan +
				(unsigned long)(SCAN_RESULT_EXPIRE)))
			continue;
/* LINUXGUARD ISSUE: Line 171, Column 3
 * Message: Potential use-after-free vulnerability: Memory freed but possibly accessed later.
 */
		kfree(priv->scanned_shadow[i].ies);
		priv->scanned_shadow[i].ies = NULL;

		kfree(priv->scanned_shadow[i].join_params);

		for (j = i; (j < priv->scanned_cnt - 1); j++)
			priv->scanned_shadow[j] = priv->scanned_shadow[j + 1];

		priv->scanned_cnt--;
	}

