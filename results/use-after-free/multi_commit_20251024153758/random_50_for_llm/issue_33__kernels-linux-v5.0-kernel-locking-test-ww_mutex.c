/*
 * Kernel version: linux-v5.0
 * Original file: kernels/linux-v5.0/kernel/locking/test-ww_mutex.c
 * Checker: linuxkernel-use-after-free
 */

		if (!err) {
			dummy_load(stress);
			ww_mutex_unlock(lock);
		} else {
			pr_err_once("stress (%s) failed with %d\n",
				    __func__, err);
			break;
		}
	} while (!time_after(jiffies, stress->timeout));

/* LINUXGUARD ISSUE: Line 529, Column 2
 * Message: Potential use-after-free vulnerability: Memory freed but possibly accessed later.
 */
	kfree(stress);
}

#define STRESS_INORDER BIT(0)
#define STRESS_REORDER BIT(1)
#define STRESS_ONE BIT(2)
#define STRESS_ALL (STRESS_INORDER | STRESS_REORDER | STRESS_ONE)

static int stress(int nlocks, int nthreads, unsigned int flags)
{
	struct ww_mutex *locks;
