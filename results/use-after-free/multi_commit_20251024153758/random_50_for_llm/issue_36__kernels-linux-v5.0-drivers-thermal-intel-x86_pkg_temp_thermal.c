/*
 * Kernel version: linux-v5.0
 * Original file: kernels/linux-v5.0/drivers/thermal/intel/x86_pkg_temp_thermal.c
 * Checker: linuxkernel-use-after-free
 */

		 * stays disabled forever.
		 */
		if (!lastcpu && pkgdev->work_scheduled)
			pkg_thermal_schedule_work(target, &pkgdev->work);
	}

	spin_unlock_irq(&pkg_temp_lock);

	/* Final cleanup if this is the last cpu */
	if (lastcpu)
/* LINUXGUARD ISSUE: Line 484, Column 3
 * Message: Potential use-after-free vulnerability: Memory freed but possibly accessed later.
 */
		kfree(pkgdev);
	return 0;
}

static int pkg_thermal_cpu_online(unsigned int cpu)
{
	struct pkg_device *pkgdev = pkg_temp_thermal_get_dev(cpu);
	struct cpuinfo_x86 *c = &cpu_data(cpu);

	/* Paranoia check */
	if (!cpu_has(c, X86_FEATURE_DTHERM) || !cpu_has(c, X86_FEATURE_PTS))
