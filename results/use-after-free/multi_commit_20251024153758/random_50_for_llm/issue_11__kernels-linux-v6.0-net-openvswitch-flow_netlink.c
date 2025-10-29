/*
 * Kernel version: linux-v6.0
 * Original file: kernels/linux-v6.0/net/openvswitch/flow_netlink.c
 * Checker: linuxkernel-use-after-free
 */

		new_acts_size = MAX_ACTIONS_BUFSIZE;
	}

	acts = nla_alloc_flow_actions(new_acts_size);
	if (IS_ERR(acts))
		return (void *)acts;

	memcpy(acts->actions, (*sfa)->actions, (*sfa)->actions_len);
	acts->actions_len = (*sfa)->actions_len;
	acts->orig_len = (*sfa)->orig_len;
/* LINUXGUARD ISSUE: Line 2483, Column 2
 * Message: Potential use-after-free vulnerability: Memory freed but possibly accessed later.
 */
	kfree(*sfa);
	*sfa = acts;

out:
	(*sfa)->actions_len += req_size;
	return  (struct nlattr *) ((unsigned char *)(*sfa) + next_offset);
}

static struct nlattr *__add_action(struct sw_flow_actions **sfa,
				   int attrtype, void *data, int len, bool log)
{
