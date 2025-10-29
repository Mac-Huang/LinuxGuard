/*
 * Kernel version: linux-v5.0
 * Original file: kernels/linux-v5.0/fs/btrfs/scrub.c
 * Checker: linuxkernel-use-after-free
 */

		sctx->stat.read_errors += nbits;
		sctx->stat.uncorrectable_errors += nbits;
		spin_unlock(&sctx->stat_lock);
	}

	list_for_each_entry_safe(curr, next, &sparity->spages, list) {
		list_del_init(&curr->list);
		scrub_page_put(curr);
	}

/* LINUXGUARD ISSUE: Line 2709, Column 2
 * Message: Potential use-after-free vulnerability: Memory freed but possibly accessed later.
 */
	kfree(sparity);
}

static void scrub_parity_bio_endio_worker(struct btrfs_work *work)
{
	struct scrub_parity *sparity = container_of(work, struct scrub_parity,
						    work);
	struct scrub_ctx *sctx = sparity->sctx;

	scrub_free_parity(sparity);
	scrub_pending_bio_dec(sctx);
