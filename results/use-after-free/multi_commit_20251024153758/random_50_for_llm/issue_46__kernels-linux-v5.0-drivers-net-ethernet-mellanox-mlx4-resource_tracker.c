/*
 * Kernel version: linux-v5.0
 * Original file: kernels/linux-v5.0/drivers/net/ethernet/mellanox/mlx4/resource_tracker.c
 * Checker: linuxkernel-use-after-free
 */

	put_res(dev, slave, index, RES_COUNTER);
	return err;
}

static void detach_qp(struct mlx4_dev *dev, int slave, struct res_qp *rqp)
{
	struct res_gid *rgid;
	struct res_gid *tmp;
	struct mlx4_qp qp; /* dummy for calling attach/detach */

/* LINUXGUARD ISSUE: Line 4577, Column 54
 * Message: Use of memory after potential free
 */
	list_for_each_entry_safe(rgid, tmp, &rqp->mcg_list, list) {
		switch (dev->caps.steering_mode) {
		case MLX4_STEERING_MODE_DEVICE_MANAGED:
			mlx4_flow_detach(dev, rgid->reg_id);
			break;
		case MLX4_STEERING_MODE_B0:
			qp.qpn = rqp->local_qpn;
			(void) mlx4_qp_detach_common(dev, &qp, rgid->gid,
						     rgid->prot, rgid->steer);
			break;
		}
