/*
 * Kernel version: linux-v5.0
 * Original file: kernels/linux-v5.0/drivers/net/ethernet/aquantia/atlantic/aq_filters.c
 * Checker: linuxkernel-use-after-free
 */


	hlist_for_each_entry_safe(rule, aq_node2,
				  &rx_fltrs->filter_list, aq_node) {
		if (rule->aq_fsp.location == cmd->fs.location)
			break;
	}

	if (rule && rule->aq_fsp.location == cmd->fs.location) {
		err = aq_add_del_rule(aq_nic, rule, false);
		hlist_del(&rule->aq_node);
/* LINUXGUARD ISSUE: Line 725, Column 3
 * Message: Potential use-after-free vulnerability: Memory freed but possibly accessed later.
 */
		kfree(rule);
		--rx_fltrs->active_filters;
	}
	return err;
}

int aq_get_rxnfc_rule(struct aq_nic_s *aq_nic, struct ethtool_rxnfc *cmd)
{
	struct aq_hw_rx_fltrs_s *rx_fltrs = aq_get_hw_rx_fltrs(aq_nic);
	struct ethtool_rx_flow_spec *fsp =
			(struct ethtool_rx_flow_spec *)&cmd->fs;
