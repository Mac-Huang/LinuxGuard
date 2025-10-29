/*
 * Kernel version: linux-v6.0
 * Original file: kernels/linux-v6.0/drivers/gpu/drm/amd/amdgpu/amdgpu_vm.c
 * Checker: linuxkernel-use-after-free
 */

	struct amdgpu_vm_bo_base **base;

	dma_resv_assert_held(vm->root.bo->tbo.base.resv);

	if (bo) {
		dma_resv_assert_held(bo->tbo.base.resv);
		if (bo->tbo.base.resv == vm->root.bo->tbo.base.resv)
			ttm_bo_set_bulk_move(&bo->tbo, NULL);

		for (base = &bo_va->base.bo->vm_bo; *base;
/* LINUXGUARD ISSUE: Line 1757, Column 25
 * Message: Use of memory after potential free
 */
		     base = &(*base)->next) {
			if (*base != &bo_va->base)
				continue;

			*base = bo_va->base.next;
			break;
		}
	}

	spin_lock(&vm->invalidated_lock);
	list_del(&bo_va->base.vm_status);
