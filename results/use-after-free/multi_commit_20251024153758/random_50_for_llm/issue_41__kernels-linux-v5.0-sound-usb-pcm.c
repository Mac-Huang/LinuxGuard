/*
 * Kernel version: linux-v5.0
 * Original file: kernels/linux-v5.0/sound/usb/pcm.c
 * Checker: linuxkernel-use-after-free
 */

 *  If the device supports unusual bit rates, does the request meet these?
 */
static int snd_usb_pcm_check_knot(struct snd_pcm_runtime *runtime,
				  struct snd_usb_substream *subs)
{
	struct audioformat *fp;
	int *rate_list;
	int count = 0, needs_knot = 0;
	int err;

/* LINUXGUARD ISSUE: Line 1177, Column 2
 * Message: Potential use-after-free vulnerability: Memory freed but possibly accessed later.
 */
	kfree(subs->rate_list.list);
	subs->rate_list.list = NULL;

	list_for_each_entry(fp, &subs->fmt_list, list) {
		if (fp->rates & SNDRV_PCM_RATE_CONTINUOUS)
			return 0;
		count += fp->nr_rates;
		if (fp->rates & SNDRV_PCM_RATE_KNOT)
			needs_knot = 1;
	}
	if (!needs_knot)
