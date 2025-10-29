/*
 * Kernel version: linux-v5.0
 * Original file: kernels/linux-v5.0/arch/x86/xen/smp_pv.c
 * Checker: linuxkernel-use-after-free
 */

asmlinkage __visible void cpu_bringup_and_idle(void)
{
	cpu_bringup();
	boot_init_stack_canary();
	cpu_startup_entry(CPUHP_AP_ONLINE_IDLE);
}

void xen_smp_intr_free_pv(unsigned int cpu)
{
	if (per_cpu(xen_irq_work, cpu).irq >= 0) {
/* LINUXGUARD ISSUE: Line 99, Column 53
 * Message: Use of memory after potential free
 */
		unbind_from_irqhandler(per_cpu(xen_irq_work, cpu).irq, NULL);
		per_cpu(xen_irq_work, cpu).irq = -1;
		kfree(per_cpu(xen_irq_work, cpu).name);
		per_cpu(xen_irq_work, cpu).name = NULL;
	}

	if (per_cpu(xen_pmu_irq, cpu).irq >= 0) {
		unbind_from_irqhandler(per_cpu(xen_pmu_irq, cpu).irq, NULL);
		per_cpu(xen_pmu_irq, cpu).irq = -1;
		kfree(per_cpu(xen_pmu_irq, cpu).name);
		per_cpu(xen_pmu_irq, cpu).name = NULL;
