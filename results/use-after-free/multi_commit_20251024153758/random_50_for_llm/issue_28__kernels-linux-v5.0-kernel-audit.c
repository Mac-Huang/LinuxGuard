/*
 * Kernel version: linux-v5.0
 * Original file: kernels/linux-v5.0/kernel/audit.c
 * Checker: linuxkernel-use-after-free
 */

 * @multi: multi-part message flag
 * @payload: payload data
 * @size: payload size
 *
 * Allocates an skb, builds the netlink message, and sends it to the port id.
 * No failure notifications.
 */
static void audit_send_reply(struct sk_buff *request_skb, int seq, int type, int done,
			     int multi, const void *payload, int size)
{
/* LINUXGUARD ISSUE: Line 971, Column 53
 * Message: Use of memory after potential free
 */
	struct net *net = sock_net(NETLINK_CB(request_skb).sk);
	struct sk_buff *skb;
	struct task_struct *tsk;
	struct audit_reply *reply = kmalloc(sizeof(struct audit_reply),
					    GFP_KERNEL);

	if (!reply)
		return;

	skb = audit_make_reply(seq, type, done, multi, payload, size);
	if (!skb)
