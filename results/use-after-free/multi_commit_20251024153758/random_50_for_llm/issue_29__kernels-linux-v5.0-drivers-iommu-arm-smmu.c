/*
 * Kernel version: linux-v5.0
 * Original file: kernels/linux-v5.0/drivers/iommu/arm-smmu.c
 * Checker: linuxkernel-use-after-free
 */

	list_add_tail(&region->list, head);

	iommu_dma_get_resv_regions(dev, head);
}

static void arm_smmu_put_resv_regions(struct device *dev,
				      struct list_head *head)
{
	struct iommu_resv_region *entry, *next;

/* LINUXGUARD ISSUE: Line 1684, Column 46
 * Message: Use of memory after potential free
 */
	list_for_each_entry_safe(entry, next, head, list)
		kfree(entry);
}

static struct iommu_ops arm_smmu_ops = {
	.capable		= arm_smmu_capable,
	.domain_alloc		= arm_smmu_domain_alloc,
	.domain_free		= arm_smmu_domain_free,
	.attach_dev		= arm_smmu_attach_dev,
	.map			= arm_smmu_map,
	.unmap			= arm_smmu_unmap,
