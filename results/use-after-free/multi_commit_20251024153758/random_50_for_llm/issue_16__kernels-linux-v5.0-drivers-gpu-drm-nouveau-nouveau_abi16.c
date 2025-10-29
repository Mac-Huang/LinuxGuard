/*
 * Kernel version: linux-v5.0
 * Original file: kernels/linux-v5.0/drivers/gpu/drm/nouveau/nouveau_abi16.c
 * Checker: linuxkernel-use-after-free
 */

	struct nouveau_abi16_chan *chan, *temp;

	/* cleanup channels */
	list_for_each_entry_safe(chan, temp, &abi16->channels, head) {
		nouveau_abi16_chan_fini(abi16, chan);
	}

	/* destroy the device object */
	nvif_device_fini(&abi16->device);

/* LINUXGUARD ISSUE: Line 172, Column 2
 * Message: Potential use-after-free vulnerability: Memory freed but possibly accessed later.
 */
	kfree(cli->abi16);
	cli->abi16 = NULL;
}

int
nouveau_abi16_ioctl_getparam(ABI16_IOCTL_ARGS)
{
	struct nouveau_cli *cli = nouveau_cli(file_priv);
	struct nouveau_drm *drm = nouveau_drm(dev);
	struct nvif_device *device = &drm->client.device;
	struct nvkm_gr *gr = nvxx_gr(device);
