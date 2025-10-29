/*
 * Kernel version: linux-v5.0
 * Original file: kernels/linux-v5.0/sound/soc/soc-topology.c
 * Checker: linuxkernel-use-after-free
 */

	if (pass != SOC_TPLG_PASS_PCM_DAI)
		return;

	if (dobj->ops && dobj->ops->dai_unload)
		dobj->ops->dai_unload(comp, dobj);

	list_for_each_entry(dai, &comp->dai_list, list)
		if (dai->driver == dai_drv)
			dai->driver = NULL;

/* LINUXGUARD ISSUE: Line 517, Column 2
 * Message: Potential use-after-free vulnerability: Memory freed but possibly accessed later.
 */
	kfree(dai_drv->name);
	list_del(&dobj->list);
	kfree(dai_drv);
}

/* remove link configurations */
static void remove_link(struct snd_soc_component *comp,
	struct snd_soc_dobj *dobj, int pass)
{
	struct snd_soc_dai_link *link =
		container_of(dobj, struct snd_soc_dai_link, dobj);
