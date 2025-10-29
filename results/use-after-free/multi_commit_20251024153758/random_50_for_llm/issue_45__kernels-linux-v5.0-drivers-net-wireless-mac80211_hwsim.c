/*
 * Kernel version: linux-v5.0
 * Original file: kernels/linux-v5.0/drivers/net/wireless/mac80211_hwsim.c
 * Checker: linuxkernel-use-after-free
 */

		if (!net_eq(wiphy_net(data->hw->wiphy), genl_info_net(info)))
			continue;

		list_del(&data->list);
		rhashtable_remove_fast(&hwsim_radios_rht, &data->rht,
				       hwsim_rht_params);
		hwsim_radios_generation++;
		spin_unlock_bh(&hwsim_radio_lock);
		mac80211_hwsim_del_radio(data, wiphy_name(data->hw->wiphy),
					 info);
/* LINUXGUARD ISSUE: Line 3517, Column 3
 * Message: Potential use-after-free vulnerability: Memory freed but possibly accessed later.
 */
		kfree(hwname);
		return 0;
	}
	spin_unlock_bh(&hwsim_radio_lock);

	kfree(hwname);
	return -ENODEV;
}

static int hwsim_get_radio_nl(struct sk_buff *msg, struct genl_info *info)
{
