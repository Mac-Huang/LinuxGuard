/*
 * Kernel version: linux-v5.0
 * Original file: kernels/linux-v5.0/drivers/gpu/drm/radeon/radeon_semaphore.c
 * Checker: linuxkernel-use-after-free
 */

	return false;
}

void radeon_semaphore_free(struct radeon_device *rdev,
			   struct radeon_semaphore **semaphore,
			   struct radeon_fence *fence)
{
	if (semaphore == NULL || *semaphore == NULL) {
		return;
	}
/* LINUXGUARD ISSUE: Line 99, Column 20
 * Message: Use of memory after potential free
 */
	if ((*semaphore)->waiters > 0) {
		dev_err(rdev->dev, "semaphore %p has more waiters than signalers,"
			" hardware lockup imminent!\n", *semaphore);
	}
	radeon_sa_bo_free(rdev, &(*semaphore)->sa_bo, fence);
	kfree(*semaphore);
	*semaphore = NULL;
}
