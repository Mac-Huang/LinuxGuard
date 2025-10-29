/*
 * Kernel version: linux-v5.0
 * Original file: kernels/linux-v5.0/drivers/vfio/vfio_iommu_spapr_tce.c
 * Checker: linuxkernel-use-after-free
 */

	}

	if (tce_groups_attached(container) && (!table_group->ops ||
			!table_group->ops->take_ownership ||
			!table_group->ops->release_ownership)) {
		ret = -EBUSY;
		goto unlock_exit;
	}

	/* Check if new group has the same iommu_ops (i.e. compatible) */
/* LINUXGUARD ISSUE: Line 1305, Column 54
 * Message: Use of memory after potential free
 */
	list_for_each_entry(tcegrp, &container->group_list, next) {
		struct iommu_table_group *table_group_tmp;

		if (tcegrp->grp == iommu_group) {
			pr_warn("tce_vfio: Group %d is already attached\n",
					iommu_group_id(iommu_group));
			ret = -EBUSY;
			goto unlock_exit;
		}
		table_group_tmp = iommu_group_get_iommudata(tcegrp->grp);
		if (table_group_tmp->ops->create_table !=
