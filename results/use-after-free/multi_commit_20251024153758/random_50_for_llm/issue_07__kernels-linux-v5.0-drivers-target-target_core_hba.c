/*
 * Kernel version: linux-v5.0
 * Original file: kernels/linux-v5.0/drivers/target/target_core_hba.c
 * Checker: linuxkernel-use-after-free
 */

int transport_backend_register(const struct target_backend_ops *ops)
{
	struct target_backend *tb, *old;

	tb = kzalloc(sizeof(*tb), GFP_KERNEL);
	if (!tb)
		return -ENOMEM;
	tb->ops = ops;

	mutex_lock(&backend_mutex);
/* LINUXGUARD ISSUE: Line 61, Column 42
 * Message: Use of memory after potential free
 */
	list_for_each_entry(old, &backend_list, list) {
		if (!strcmp(old->ops->name, ops->name)) {
			pr_err("backend %s already registered.\n", ops->name);
			mutex_unlock(&backend_mutex);
			kfree(tb);
			return -EEXIST;
		}
	}
	target_setup_backend_cits(tb);
	list_add_tail(&tb->list, &backend_list);
	mutex_unlock(&backend_mutex);
