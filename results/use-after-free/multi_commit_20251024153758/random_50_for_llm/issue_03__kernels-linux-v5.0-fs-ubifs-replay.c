/*
 * Kernel version: linux-v5.0
 * Original file: kernels/linux-v5.0/fs/ubifs/replay.c
 * Checker: linuxkernel-use-after-free
 */

/**
 * destroy_replay_list - destroy the replay.
 * @c: UBIFS file-system description object
 *
 * Destroy the replay list.
 */
static void destroy_replay_list(struct ubifs_info *c)
{
	struct replay_entry *r, *tmp;

/* LINUXGUARD ISSUE: Line 366, Column 52
 * Message: Use of memory after potential free
 */
	list_for_each_entry_safe(r, tmp, &c->replay_list, list) {
		if (is_hash_key(c, &r->key))
			kfree(fname_name(&r->nm));
		list_del(&r->list);
		kfree(r);
	}
}

/**
 * insert_node - insert a node to the replay list
 * @c: UBIFS file-system description object
