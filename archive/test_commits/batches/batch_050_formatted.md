# Linux Kernel Commit Batch Analysis

## Commit 1: 2dcf838c

**Author:** Filipe Manana
**Date:** 2025-06-19 15:20:42
**Files Changed:** fs/btrfs/tree-log.c

**Message:**
```
btrfs: fix invalid inode pointer dereferences during log replay

In a few places where we call read_one_inode(), if we get a NULL pointer
we end up jumping into an error path, or fallthrough in case of
__add_inode_ref(), where we then do something like this:

   iput(&inode->vfs_inode);

which results in an invalid inode pointer that triggers an invalid memory
access, resulting in a crash.

Fix this by making sure we don't do such dereferences.

Fixes: b4c50cbb01a1 ("btrfs: return a btrfs_inode from read_one_inode()")
CC: stable@vger.kernel.org # 6.15+
Signed-off-by: Filipe Manana <fdmanana@suse.com>
Reviewed-by: David Sterba <dsterba@suse.com>
Signed-off-by: David Sterba <dsterba@suse.com>
```

**Diff:**
```diff
diff --git a/fs/btrfs/tree-log.c b/fs/btrfs/tree-log.c
index 97e933113b82..21d2f3dded51 100644
--- a/fs/btrfs/tree-log.c
+++ b/fs/btrfs/tree-log.c
@@ -668,15 +668,12 @@ static noinline int replay_one_extent(struct btrfs_trans_handle *trans,
 		extent_end = ALIGN(start + size,
 				   fs_info->sectorsize);
 	} else {
-		ret = 0;
-		goto out;
+		return 0;
 	}
 
 	inode = read_one_inode(root, key->objectid);
-	if (!inode) {
-		ret = -EIO;
-		goto out;
-	}
+	if (!inode)
+		return -EIO;
 
 	/*
 	 * first check to see if we already have this extent in the
@@ -961,7 +958,8 @@ static noinline int drop_one_dir_item(struct btrfs_trans_handle *trans,
 	ret = unlink_inode_for_log_replay(trans, dir, inode, &name);
 out:
 	kfree(name.name);
-	iput(&inode->vfs_inode);
+	if (inode)
+		iput(&inode->vfs_inode);
 	return ret;
 }
 
@@ -1176,8 +1174,8 @@ static inline int __add_inode_ref(struct btrfs_trans_handle *trans,
 					ret = unlink_inode_for_log_replay(trans,
 							victim_parent,
 							inode, &victim_name);
+					iput(&victim_parent->vfs_inode);
 				}
-				iput(&victim_parent->vfs_inode);
 				kfree(victim_name.name);
 				if (ret)
 					return ret;
```

---

## Commit 2: dd276214

**Author:** Leo Martins
**Date:** 2025-06-19 15:18:35
**Files Changed:** fs/btrfs/delayed-inode.c

**Message:**
```
btrfs: fix delayed ref refcount leak in debug assertion

If the delayed_root is not empty we are increasing the number of
references to a delayed_node without decreasing it, causing a leak.  Fix
by decrementing the delayed_node reference count.

Reviewed-by: Filipe Manana <fdmanana@suse.com>
Signed-off-by: Leo Martins <loemra.dev@gmail.com>
Reviewed-by: Qu Wenruo <wqu@suse.com>
[ Remove the changelog from the commit message. ]
Signed-off-by: Qu Wenruo <wqu@suse.com>
Signed-off-by: David Sterba <dsterba@suse.com>
```

**Diff:**
```diff
diff --git a/fs/btrfs/delayed-inode.c b/fs/btrfs/delayed-inode.c
index c7cc24a5dd5e..8c597fa60523 100644
--- a/fs/btrfs/delayed-inode.c
+++ b/fs/btrfs/delayed-inode.c
@@ -1377,7 +1377,10 @@ static int btrfs_wq_run_delayed_node(struct btrfs_delayed_root *delayed_root,
 
 void btrfs_assert_delayed_root_empty(struct btrfs_fs_info *fs_info)
 {
-	WARN_ON(btrfs_first_delayed_node(fs_info->delayed_root));
+	struct btrfs_delayed_node *node = btrfs_first_delayed_node(fs_info->delayed_root);
+
+	if (WARN_ON(node))
+		refcount_dec(&node->refs);
 }
 
 static bool could_end_wait(struct btrfs_delayed_root *delayed_root, int seq)
```

---

## Commit 3: 186b58ba

**Author:** Mark Rutland
**Date:** 2025-06-19 13:06:20
**Files Changed:** arch/arm64/kvm/hyp/include/hyp/switch.h

**Message:**
```
KVM: arm64: Remove ad-hoc CPTR manipulation from kvm_hyp_handle_fpsimd()

The hyp code FPSIMD/SVE/SME trap handling logic has some rather messy
open-coded manipulation of CPTR/CPACR. This is benign for non-nested
guests, but broken for nested guests, as the guest hypervisor's CPTR
configuration is not taken into account.

Consider the case where L0 provides FPSIMD+SVE to an L1 guest
hypervisor, and the L1 guest hypervisor only provides FPSIMD to an L2
guest (with L1 configuring CPTR/CPACR to trap SVE usage from L2). If the
L2 guest triggers an FPSIMD trap to the L0 hypervisor,
kvm_hyp_handle_fpsimd() will see that the vCPU supports FPSIMD+SVE, and
will configure CPTR/CPACR to NOT trap FPSIMD+SVE before returning to the
L2 guest. Consequently the L2 guest would be able to manipulate SVE
state even though the L1 hypervisor had configured CPTR/CPACR to forbid
this.

Clean this up, and fix the nested virt issue by always using
__deactivate_cptr_traps() and __activate_cptr_traps() to manage the CPTR
traps. This removes the need for the ad-hoc fixup in
kvm_hyp_save_fpsimd_host(), and ensures that any guest hypervisor
configuration of CPTR/CPACR is taken into account.

Signed-off-by: Mark Rutland <mark.rutland@arm.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Fuad Tabba <tabba@google.com>
Cc: Marc Zyngier <maz@kernel.org>
Cc: Mark Brown <broonie@kernel.org>
Cc: Oliver Upton <oliver.upton@linux.dev>
Cc: Will Deacon <will@kernel.org>
Link: https://lore.kernel.org/r/20250617133718.4014181-6-mark.rutland@arm.com
Signed-off-by: Marc Zyngier <maz@kernel.org>
```

**Diff:**
```diff
diff --git a/arch/arm64/kvm/hyp/include/hyp/switch.h b/arch/arm64/kvm/hyp/include/hyp/switch.h
index 8a77fcccbcf6..2ad57b117385 100644
--- a/arch/arm64/kvm/hyp/include/hyp/switch.h
+++ b/arch/arm64/kvm/hyp/include/hyp/switch.h
@@ -616,11 +616,6 @@ static void kvm_hyp_save_fpsimd_host(struct kvm_vcpu *vcpu)
 	 */
 	if (system_supports_sve()) {
 		__hyp_sve_save_host();
-
-		/* Re-enable SVE traps if not supported for the guest vcpu. */
-		if (!vcpu_has_sve(vcpu))
-			cpacr_clear_set(CPACR_EL1_ZEN, 0);
-
 	} else {
 		__fpsimd_save_state(host_data_ptr(host_ctxt.fp_regs));
 	}
@@ -671,10 +666,7 @@ static inline bool kvm_hyp_handle_fpsimd(struct kvm_vcpu *vcpu, u64 *exit_code)
 	/* Valid trap.  Switch the context: */
 
 	/* First disable enough traps to allow us to update the registers */
-	if (sve_guest || (is_protected_kvm_enabled() && system_supports_sve()))
-		cpacr_clear_set(0, CPACR_EL1_FPEN | CPACR_EL1_ZEN);
-	else
-		cpacr_clear_set(0, CPACR_EL1_FPEN);
+	__deactivate_cptr_traps(vcpu);
 	isb();
 
 	/* Write out the host state if it's in the registers */
@@ -696,6 +688,13 @@ static inline bool kvm_hyp_handle_fpsimd(struct kvm_vcpu *vcpu, u64 *exit_code)
 
 	*host_data_ptr(fp_owner) = FP_STATE_GUEST_OWNED;
 
+	/*
+	 * Re-enable traps necessary for the current state of the guest, e.g.
+	 * those enabled by a guest hypervisor. The ERET to the guest will
+	 * provide the necessary context synchronization.
+	 */
+	__activate_cptr_traps(vcpu);
+
 	return true;
 }
 
```

---

## Commit 4: c529c373

**Author:** Kuen-Han Tsai
**Date:** 2025-06-19 12:41:13
**Files Changed:** drivers/usb/gadget/function/u_serial.c

**Message:**
```
usb: gadget: u_serial: Fix race condition in TTY wakeup

A race condition occurs when gs_start_io() calls either gs_start_rx() or
gs_start_tx(), as those functions briefly drop the port_lock for
usb_ep_queue(). This allows gs_close() and gserial_disconnect() to clear
port.tty and port_usb, respectively.

Use the null-safe TTY Port helper function to wake up TTY.

Example
  CPU1:			      CPU2:
  gserial_connect() // lock
  			      gs_close() // await lock
  gs_start_rx()     // unlock
  usb_ep_queue()
  			      gs_close() // lock, reset port.tty and unlock
  gs_start_rx()     // lock
  tty_wakeup()      // NPE

Fixes: 35f95fd7f234 ("TTY: usb/u_serial, use tty from tty_port")
Cc: stable <stable@kernel.org>
Signed-off-by: Kuen-Han Tsai <khtsai@google.com>
Reviewed-by: Prashanth K <prashanth.k@oss.qualcomm.com>
Link: https://lore.kernel.org/linux-usb/20240116141801.396398-1-khtsai@google.com/
Link: https://lore.kernel.org/r/20250617050844.1848232-2-khtsai@google.com
Signed-off-by: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
```

**Diff:**
```diff
diff --git a/drivers/usb/gadget/function/u_serial.c b/drivers/usb/gadget/function/u_serial.c
index c043bdc30d8a..540dc5ab96fc 100644
--- a/drivers/usb/gadget/function/u_serial.c
+++ b/drivers/usb/gadget/function/u_serial.c
@@ -295,8 +295,8 @@ __acquires(&port->port_lock)
 			break;
 	}
 
-	if (do_tty_wake && port->port.tty)
-		tty_wakeup(port->port.tty);
+	if (do_tty_wake)
+		tty_port_tty_wakeup(&port->port);
 	return status;
 }
 
@@ -574,7 +574,7 @@ static int gs_start_io(struct gs_port *port)
 		gs_start_tx(port);
 		/* Unblock any pending writes into our circular buffer, in case
 		 * we didn't in gs_start_tx() */
-		tty_wakeup(port->port.tty);
+		tty_port_tty_wakeup(&port->port);
 	} else {
 		/* Free reqs only if we are still connected */
 		if (port->port_usb) {
```

---

## Commit 5: f6c7bc4a

**Author:** Kuen-Han Tsai
**Date:** 2025-06-19 12:41:09
**Files Changed:** drivers/usb/gadget/function/u_serial.c

**Message:**
```
Revert "usb: gadget: u_serial: Add null pointer check in gs_start_io"

This reverts commit ffd603f214237e250271162a5b325c6199a65382.

Commit ffd603f21423 ("usb: gadget: u_serial: Add null pointer check in
gs_start_io") adds null pointer checks at the beginning of the
gs_start_io() function to prevent a null pointer dereference. However,
these checks are redundant because the function's comment already
requires callers to hold the port_lock and ensure port.tty and port_usb
are not null. All existing callers already follow these rules.

The true cause of the null pointer dereference is a race condition. When
gs_start_io() calls either gs_start_rx() or gs_start_tx(), the port_lock
is temporarily released for usb_ep_queue(). This allows port.tty and
port_usb to be cleared.

Fixes: ffd603f21423 ("usb: gadget: u_serial: Add null pointer check in gs_start_io")
Cc: stable <stable@kernel.org>
Signed-off-by: Kuen-Han Tsai <khtsai@google.com>
Reviewed-by: Prashanth K <prashanth.k@oss.qualcomm.com>
Link: https://lore.kernel.org/r/20250617050844.1848232-1-khtsai@google.com
Signed-off-by: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
```

**Diff:**
```diff
diff --git a/drivers/usb/gadget/function/u_serial.c b/drivers/usb/gadget/function/u_serial.c
index ab544f6824be..c043bdc30d8a 100644
--- a/drivers/usb/gadget/function/u_serial.c
+++ b/drivers/usb/gadget/function/u_serial.c
@@ -544,20 +544,16 @@ static int gs_alloc_requests(struct usb_ep *ep, struct list_head *head,
 static int gs_start_io(struct gs_port *port)
 {
 	struct list_head	*head = &port->read_pool;
-	struct usb_ep		*ep;
+	struct usb_ep		*ep = port->port_usb->out;
 	int			status;
 	unsigned		started;
 
-	if (!port->port_usb || !port->port.tty)
-		return -EIO;
-
 	/* Allocate RX and TX I/O buffers.  We can't easily do this much
 	 * earlier (with GFP_KERNEL) because the requests are coupled to
 	 * endpoints, as are the packet sizes we'll be using.  Different
 	 * configurations may use different endpoints with a given port;
 	 * and high speed vs full speed changes packet sizes too.
 	 */
-	ep = port->port_usb->out;
 	status = gs_alloc_requests(ep, head, gs_read_complete,
 		&port->read_allocated);
 	if (status)
```

---

