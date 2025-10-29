/*
 * Kernel version: linux-v5.0
 * Original file: kernels/linux-v5.0/drivers/soundwire/stream.c
 * Checker: linuxkernel-use-after-free
 */

}

static void sdw_slave_port_release(struct sdw_bus *bus,
			struct sdw_slave *slave,
			struct sdw_stream_runtime *stream)
{
	struct sdw_port_runtime *p_rt, *_p_rt;
	struct sdw_master_runtime *m_rt;
	struct sdw_slave_runtime *s_rt;

/* LINUXGUARD ISSUE: Line 981, Column 50
 * Message: Use of memory after potential free
 */
	list_for_each_entry(m_rt, &stream->master_list, stream_node) {
		list_for_each_entry(s_rt, &m_rt->slave_rt_list, m_rt_node) {

			if (s_rt->slave != slave)
				continue;

			list_for_each_entry_safe(p_rt, _p_rt,
					&s_rt->port_list, port_node) {

				list_del(&p_rt->port_node);
				kfree(p_rt);
