/*
 * Kernel version: linux-v6.0
 * Original file: kernels/linux-v6.0/drivers/gpu/drm/radeon/radeon_semaphore.c
 * Checker: linuxkernel-use-after-free
 */

{
	int r;

	*semaphore = kmalloc(sizeof(struct radeon_semaphore), GFP_KERNEL);
	if (*semaphore == NULL) {
		return -ENOMEM;
	}
	r = radeon_sa_bo_new(rdev, &rdev->ring_tmp_bo,
			     &(*semaphore)->sa_bo, 8, 8);
	if (r) {
/* LINUXGUARD ISSUE: Line 46, Column 3
 * Message: Potential use-after-free vulnerability: Memory freed but possibly accessed later.
 */
		kfree(*semaphore);
		*semaphore = NULL;
		return r;
	}
	(*semaphore)->waiters = 0;
	(*semaphore)->gpu_addr = radeon_sa_bo_gpu_addr((*semaphore)->sa_bo);

	*((uint64_t *)radeon_sa_bo_cpu_addr((*semaphore)->sa_bo)) = 0;

	return 0;
}
