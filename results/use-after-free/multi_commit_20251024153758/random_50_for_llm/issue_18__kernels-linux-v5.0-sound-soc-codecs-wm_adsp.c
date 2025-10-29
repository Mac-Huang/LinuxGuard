/*
 * Kernel version: linux-v5.0
 * Original file: kernels/linux-v5.0/sound/soc/codecs/wm_adsp.c
 * Checker: linuxkernel-use-after-free
 */

	}

	ctl_work->dsp = dsp;
	ctl_work->ctl = ctl;
	INIT_WORK(&ctl_work->work, wm_adsp_ctl_work);
	schedule_work(&ctl_work->work);

	return 0;

err_ctl_cache:
/* LINUXGUARD ISSUE: Line 1394, Column 2
 * Message: Potential use-after-free vulnerability: Memory freed but possibly accessed later.
 */
	kfree(ctl->cache);
err_ctl_name:
	kfree(ctl->name);
err_ctl:
	kfree(ctl);

	return ret;
}

struct wm_coeff_parsed_alg {
	int id;
