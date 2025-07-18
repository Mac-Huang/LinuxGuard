# Linux Kernel Commit Batch Analysis

## Commit 1: 7484e15d

**Author:** Al Viro
**Date:** 2025-06-23 14:01:49
**Files Changed:** fs/namespace.c, fs/pnode.h, include/linux/mount.h, kernel/audit_tree.c

**Message:**
```
replace collect_mounts()/drop_collected_mounts() with a safer variant

collect_mounts() has several problems - one can't iterate over the results
directly, so it has to be done with callback passed to iterate_mounts();
it has an oopsable race with d_invalidate(); it creates temporary clones
of mounts invisibly for sync umount (IOW, you can have non-lazy umount
succeed leaving filesystem not mounted anywhere and yet still busy).

A saner approach is to give caller an array of struct path that would pin
every mount in a subtree, without cloning any mounts.

        * collect_mounts()/drop_collected_mounts()/iterate_mounts() is gone
        * collect_paths(where, preallocated, size) gives either ERR_PTR(-E...) or
a pointer to array of struct path, one for each chunk of tree visible under
'where' (i.e. the first element is a copy of where, followed by (mount,root)
for everything mounted under it - the same set collect_mounts() would give).
Unlike collect_mounts(), the mounts are *not* cloned - we just get pinning
references to the roots of subtrees in the caller's namespace.
        Array is terminated by {NULL, NULL} struct path.  If it fits into
preallocated array (on-stack, normally), that's where it goes; otherwise
it's allocated by kmalloc_array().  Passing 0 as size means that 'preallocated'
is ignored (and expected to be NULL).
        * drop_collected_paths(paths, preallocated) is given the array returned
by an earlier call of collect_paths() and the preallocated array passed to that
call.  All mount/dentry references are dropped and array is kfree'd if it's not
equal to 'preallocated'.
        * instead of iterate_mounts(), users should just iterate over array
of struct path - nothing exotic is needed for that.  Existing users (all in
audit_tree.c) are converted.

[folded a fix for braino reported by Venkat Rao Bagalkote <venkat88@linux.ibm.com>]

Fixes: 80b5dce8c59b0 ("vfs: Add a function to lazily unmount all mounts from any dentry")
Tested-by: Venkat Rao Bagalkote <venkat88@linux.ibm.com>
Signed-off-by: Al Viro <viro@zeniv.linux.org.uk>
```

**Diff:**
```diff
diff --git a/Documentation/filesystems/porting.rst b/Documentation/filesystems/porting.rst
index 3616d7161dab..a5734bdd1cc7 100644
--- a/Documentation/filesystems/porting.rst
+++ b/Documentation/filesystems/porting.rst
@@ -1249,3 +1249,12 @@ Using try_lookup_noperm() will require linux/namei.h to be included.
 
 Calling conventions for ->d_automount() have changed; we should *not* grab
 an extra reference to new mount - it should be returned with refcount 1.
+
+---
+
+collect_mounts()/drop_collected_mounts()/iterate_mounts() are gone now.
+Replacement is collect_paths()/drop_collected_path(), with no special
+iterator needed.  Instead of a cloned mount tree, the new interface returns
+an array of struct path, one for each mount collect_mounts() would've
+created.  These struct path point to locations in the caller's namespace
+that would be roots of the cloned mounts.
diff --git a/fs/namespace.c b/fs/namespace.c
index e13d9ab4f564..14601ec4c2c5 100644
--- a/fs/namespace.c
+++ b/fs/namespace.c
@@ -2310,21 +2310,62 @@ struct mount *copy_tree(struct mount *src_root, struct dentry *dentry,
 	return dst_mnt;
 }
 
-/* Caller should check returned pointer for errors */
+static inline bool extend_array(struct path **res, struct path **to_free,
+				unsigned n, unsigned *count, unsigned new_count)
+{
+	struct path *p;
+
+	if (likely(n < *count))
+		return true;
+	p = kmalloc_array(new_count, sizeof(struct path), GFP_KERNEL);
+	if (p && *count)
+		memcpy(p, *res, *count * sizeof(struct path));
+	*count = new_count;
+	kfree(*to_free);
+	*to_free = *res = p;
+	return p;
+}
 
-struct vfsmount *collect_mounts(const struct path *path)
+struct path *collect_paths(const struct path *path,
+			      struct path *prealloc, unsigned count)
 {
-	struct mount *tree;
-	namespace_lock();
-	if (!check_mnt(real_mount(path->mnt)))
-		tree = ERR_PTR(-EINVAL);

... (truncated 285 lines)
```

---

## Commit 2: 00f452a1

**Author:** Thomas Fourier
**Date:** 2025-06-23 13:23:45
**Files Changed:** drivers/scsi/qla4xxx/ql4_os.c

**Message:**
```
scsi: qla4xxx: Fix missing DMA mapping error in qla4xxx_alloc_pdu()

dma_map_XXX() can fail and should be tested for errors with
dma_mapping_error().

Fixes: b3a271a94d00 ("[SCSI] qla4xxx: support iscsiadm session mgmt")
Signed-off-by: Thomas Fourier <fourier.thomas@gmail.com>
Link: https://lore.kernel.org/r/20250618071742.21822-2-fourier.thomas@gmail.com
Signed-off-by: Martin K. Petersen <martin.petersen@oracle.com>
```

**Diff:**
```diff
diff --git a/drivers/scsi/qla4xxx/ql4_os.c b/drivers/scsi/qla4xxx/ql4_os.c
index d4141656b204..a39f1da4ce47 100644
--- a/drivers/scsi/qla4xxx/ql4_os.c
+++ b/drivers/scsi/qla4xxx/ql4_os.c
@@ -3420,6 +3420,8 @@ static int qla4xxx_alloc_pdu(struct iscsi_task *task, uint8_t opcode)
 		task_data->data_dma = dma_map_single(&ha->pdev->dev, task->data,
 						     task->data_count,
 						     DMA_TO_DEVICE);
+		if (dma_mapping_error(&ha->pdev->dev, task_data->data_dma))
+			return -ENOMEM;
 	}
 
 	DEBUG2(ql4_printk(KERN_INFO, ha, "%s: MaxRecvLen %u, iscsi hrd %d\n",
```

---

## Commit 3: e8d6f3ab

**Author:** Kuniyuki Iwashima
**Date:** 2025-06-23 11:01:16
**Files Changed:** fs/nfs/inode.c

**Message:**
```
nfs: Clean up /proc/net/rpc/nfs when nfs_fs_proc_net_init() fails.

syzbot reported a warning below [1] following a fault injection in
nfs_fs_proc_net_init(). [0]

When nfs_fs_proc_net_init() fails, /proc/net/rpc/nfs is not removed.

Later, rpc_proc_exit() tries to remove /proc/net/rpc, and the warning
is logged as the directory is not empty.

Let's handle the error of nfs_fs_proc_net_init() properly.

[0]:
FAULT_INJECTION: forcing a failure.
name failslab, interval 1, probability 0, space 0, times 0
CPU: 1 UID: 0 PID: 6120 Comm: syz.2.27 Not tainted 6.16.0-rc1-syzkaller-00010-g2c4a1f3fe03e #0 PREEMPT(full)
Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 05/07/2025
Call Trace:
 <TASK>
  dump_stack_lvl (lib/dump_stack.c:123)
 should_fail_ex (lib/fault-inject.c:73 lib/fault-inject.c:174)
 should_failslab (mm/failslab.c:46)
 kmem_cache_alloc_noprof (mm/slub.c:4178 mm/slub.c:4204)
 __proc_create (fs/proc/generic.c:427)
 proc_create_reg (fs/proc/generic.c:554)
 proc_create_net_data (fs/proc/proc_net.c:120)
 nfs_fs_proc_net_init (fs/nfs/client.c:1409)
 nfs_net_init (fs/nfs/inode.c:2600)
 ops_init (net/core/net_namespace.c:138)
 setup_net (net/core/net_namespace.c:443)
 copy_net_ns (net/core/net_namespace.c:576)
 create_new_namespaces (kernel/nsproxy.c:110)
 unshare_nsproxy_namespaces (kernel/nsproxy.c:218 (discriminator 4))
 ksys_unshare (kernel/fork.c:3123)
 __x64_sys_unshare (kernel/fork.c:3190)
 do_syscall_64 (arch/x86/entry/syscall_64.c:63 arch/x86/entry/syscall_64.c:94)
 entry_SYSCALL_64_after_hwframe (arch/x86/entry/entry_64.S:130)
 </TASK>

[1]:
remove_proc_entry: removing non-empty directory 'net/rpc', leaking at least 'nfs'
 WARNING: CPU: 1 PID: 6120 at fs/proc/generic.c:727 remove_proc_entry+0x45e/0x530 fs/proc/generic.c:727
Modules linked in:
CPU: 1 UID: 0 PID: 6120 Comm: syz.2.27 Not tainted 6.16.0-rc1-syzkaller-00010-g2c4a1f3fe03e #0 PREEMPT(full)
Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 05/07/2025
 RIP: 0010:remove_proc_entry+0x45e/0x530 fs/proc/generic.c:727
Code: 3c 02 00 0f 85 85 00 00 00 48 8b 93 d8 00 00 00 4d 89 f0 4c 89 e9 48 c7 c6 40 ba a2 8b 48 c7 c7 60 b9 a2 8b e8 33 81 1d ff 90 <0f> 0b 90 90 e9 5f fe ff ff e8 04 69 5e ff 90 48 b8 00 00 00 00 00
RSP: 0018:ffffc90003637b08 EFLAGS: 00010282
RAX: 0000000000000000 RBX: ffff88805f534140 RCX: ffffffff817a92c8
RDX: ffff88807da99e00 RSI: ffffffff817a92d5 RDI: 0000000000000001
RBP: ffff888033431ac0 R08: 0000000000000001 R09: 0000000000000000
R10: 0000000000000001 R11: 0000000000000001 R12: ffff888033431a00
R13: ffff888033431ae4 R14: ffff888033184724 R15: dffffc0000000000
FS:  0000555580328500(0000) GS:ffff888124a62000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 00007f71733743e0 CR3: 000000007f618000 CR4: 00000000003526f0
DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
Call Trace:
 <TASK>
  sunrpc_exit_net+0x46/0x90 net/sunrpc/sunrpc_syms.c:76
  ops_exit_list net/core/net_namespace.c:200 [inline]
  ops_undo_list+0x2eb/0xab0 net/core/net_namespace.c:253
  setup_net+0x2e1/0x510 net/core/net_namespace.c:457
  copy_net_ns+0x2a6/0x5f0 net/core/net_namespace.c:574
  create_new_namespaces+0x3ea/0xa90 kernel/nsproxy.c:110
  unshare_nsproxy_namespaces+0xc0/0x1f0 kernel/nsproxy.c:218
  ksys_unshare+0x45b/0xa40 kernel/fork.c:3121
  __do_sys_unshare kernel/fork.c:3192 [inline]
  __se_sys_unshare kernel/fork.c:3190 [inline]
  __x64_sys_unshare+0x31/0x40 kernel/fork.c:3190
  do_syscall_x64 arch/x86/entry/syscall_64.c:63 [inline]
  do_syscall_64+0xcd/0x490 arch/x86/entry/syscall_64.c:94
 entry_SYSCALL_64_after_hwframe+0x77/0x7f
RIP: 0033:0x7fa1a6b8e929
Code: ff ff c3 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 40 00 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 c7 c1 a8 ff ff ff f7 d8 64 89 01 48
RSP: 002b:00007fff3a090368 EFLAGS: 00000246 ORIG_RAX: 0000000000000110
RAX: ffffffffffffffda RBX: 00007fa1a6db5fa0 RCX: 00007fa1a6b8e929
RDX: 0000000000000000 RSI: 0000000000000000 RDI: 0000000040000080
RBP: 00007fa1a6c10b39 R08: 0000000000000000 R09: 0000000000000000
R10: 0000000000000000 R11: 0000000000000246 R12: 0000000000000000
R13: 00007fa1a6db5fa0 R14: 00007fa1a6db5fa0 R15: 0000000000000001
 </TASK>

Fixes: d47151b79e32 ("nfs: expose /proc/net/sunrpc/nfs in net namespaces")
Reported-by: syzbot+a4cc4ac22daa4a71b87c@syzkaller.appspotmail.com
Closes: https://syzkaller.appspot.com/bug?extid=a4cc4ac22daa4a71b87c
Tested-by: syzbot+a4cc4ac22daa4a71b87c@syzkaller.appspotmail.com
Signed-off-by: Kuniyuki Iwashima <kuniyu@google.com>
Signed-off-by: Anna Schumaker <anna.schumaker@oracle.com>
```

**Diff:**
```diff
diff --git a/fs/nfs/inode.c b/fs/nfs/inode.c
index 8ab7868807a7..a2fa6bc4d74e 100644
--- a/fs/nfs/inode.c
+++ b/fs/nfs/inode.c
@@ -2589,15 +2589,26 @@ EXPORT_SYMBOL_GPL(nfs_net_id);
 static int nfs_net_init(struct net *net)
 {
 	struct nfs_net *nn = net_generic(net, nfs_net_id);
+	int err;
 
 	nfs_clients_init(net);
 
 	if (!rpc_proc_register(net, &nn->rpcstats)) {
-		nfs_clients_exit(net);
-		return -ENOMEM;
+		err = -ENOMEM;
+		goto err_proc_rpc;
 	}
 
-	return nfs_fs_proc_net_init(net);
+	err = nfs_fs_proc_net_init(net);
+	if (err)
+		goto err_proc_nfs;
+
+	return 0;
+
+err_proc_nfs:
+	rpc_proc_unregister(net, "nfs");
+err_proc_rpc:
+	nfs_clients_exit(net);
+	return err;
 }
 
 static void nfs_net_exit(struct net *net)
```

---

## Commit 4: 1d612310

**Author:** Kuniyuki Iwashima
**Date:** 2025-06-23 10:59:29
**Files Changed:** include/net/bluetooth/hci_core.h, net/bluetooth/hci_core.c

**Message:**
```
Bluetooth: hci_core: Fix use-after-free in vhci_flush()

syzbot reported use-after-free in vhci_flush() without repro. [0]

From the splat, a thread close()d a vhci file descriptor while
its device was being used by iotcl() on another thread.

Once the last fd refcnt is released, vhci_release() calls
hci_unregister_dev(), hci_free_dev(), and kfree() for struct
vhci_data, which is set to hci_dev->dev->driver_data.

The problem is that there is no synchronisation after unlinking
hdev from hci_dev_list in hci_unregister_dev().  There might be
another thread still accessing the hdev which was fetched before
the unlink operation.

We can use SRCU for such synchronisation.

Let's run hci_dev_reset() under SRCU and wait for its completion
in hci_unregister_dev().

Another option would be to restore hci_dev->destruct(), which was
removed in commit 587ae086f6e4 ("Bluetooth: Remove unused
hci-destruct cb").  However, this would not be a good solution, as
we should not run hci_unregister_dev() while there are in-flight
ioctl() requests, which could lead to another data-race KCSAN splat.

Note that other drivers seem to have the same problem, for exmaple,
virtbt_remove().

[0]:
BUG: KASAN: slab-use-after-free in skb_queue_empty_lockless include/linux/skbuff.h:1891 [inline]
BUG: KASAN: slab-use-after-free in skb_queue_purge_reason+0x99/0x360 net/core/skbuff.c:3937
Read of size 8 at addr ffff88807cb8d858 by task syz.1.219/6718

CPU: 1 UID: 0 PID: 6718 Comm: syz.1.219 Not tainted 6.16.0-rc1-syzkaller-00196-g08207f42d3ff #0 PREEMPT(full)
Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 05/07/2025
Call Trace:
 <TASK>
 dump_stack_lvl+0x189/0x250 lib/dump_stack.c:120
 print_address_description mm/kasan/report.c:408 [inline]
 print_report+0xd2/0x2b0 mm/kasan/report.c:521
 kasan_report+0x118/0x150 mm/kasan/report.c:634
 skb_queue_empty_lockless include/linux/skbuff.h:1891 [inline]
 skb_queue_purge_reason+0x99/0x360 net/core/skbuff.c:3937
 skb_queue_purge include/linux/skbuff.h:3368 [inline]
 vhci_flush+0x44/0x50 drivers/bluetooth/hci_vhci.c:69
 hci_dev_do_reset net/bluetooth/hci_core.c:552 [inline]
 hci_dev_reset+0x420/0x5c0 net/bluetooth/hci_core.c:592
 sock_do_ioctl+0xd9/0x300 net/socket.c:1190
 sock_ioctl+0x576/0x790 net/socket.c:1311
 vfs_ioctl fs/ioctl.c:51 [inline]
 __do_sys_ioctl fs/ioctl.c:907 [inline]
 __se_sys_ioctl+0xf9/0x170 fs/ioctl.c:893
 do_syscall_x64 arch/x86/entry/syscall_64.c:63 [inline]
 do_syscall_64+0xfa/0x3b0 arch/x86/entry/syscall_64.c:94
 entry_SYSCALL_64_after_hwframe+0x77/0x7f
RIP: 0033:0x7fcf5b98e929
Code: ff ff c3 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 40 00 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 c7 c1 a8 ff ff ff f7 d8 64 89 01 48
RSP: 002b:00007fcf5c7b9038 EFLAGS: 00000246 ORIG_RAX: 0000000000000010
RAX: ffffffffffffffda RBX: 00007fcf5bbb6160 RCX: 00007fcf5b98e929
RDX: 0000000000000000 RSI: 00000000400448cb RDI: 0000000000000009
RBP: 00007fcf5ba10b39 R08: 0000000000000000 R09: 0000000000000000
R10: 0000000000000000 R11: 0000000000000246 R12: 0000000000000000
R13: 0000000000000000 R14: 00007fcf5bbb6160 R15: 00007ffd6353d528
 </TASK>

Allocated by task 6535:
 kasan_save_stack mm/kasan/common.c:47 [inline]
 kasan_save_track+0x3e/0x80 mm/kasan/common.c:68
 poison_kmalloc_redzone mm/kasan/common.c:377 [inline]
 __kasan_kmalloc+0x93/0xb0 mm/kasan/common.c:394
 kasan_kmalloc include/linux/kasan.h:260 [inline]
 __kmalloc_cache_noprof+0x230/0x3d0 mm/slub.c:4359
 kmalloc_noprof include/linux/slab.h:905 [inline]
 kzalloc_noprof include/linux/slab.h:1039 [inline]
 vhci_open+0x57/0x360 drivers/bluetooth/hci_vhci.c:635
 misc_open+0x2bc/0x330 drivers/char/misc.c:161
 chrdev_open+0x4c9/0x5e0 fs/char_dev.c:414
 do_dentry_open+0xdf0/0x1970 fs/open.c:964
 vfs_open+0x3b/0x340 fs/open.c:1094
 do_open fs/namei.c:3887 [inline]
 path_openat+0x2ee5/0x3830 fs/namei.c:4046
 do_filp_open+0x1fa/0x410 fs/namei.c:4073
 do_sys_openat2+0x121/0x1c0 fs/open.c:1437
 do_sys_open fs/open.c:1452 [inline]
 __do_sys_openat fs/open.c:1468 [inline]
 __se_sys_openat fs/open.c:1463 [inline]
 __x64_sys_openat+0x138/0x170 fs/open.c:1463
 do_syscall_x64 arch/x86/entry/syscall_64.c:63 [inline]
 do_syscall_64+0xfa/0x3b0 arch/x86/entry/syscall_64.c:94
 entry_SYSCALL_64_after_hwframe+0x77/0x7f

Freed by task 6535:
 kasan_save_stack mm/kasan/common.c:47 [inline]
 kasan_save_track+0x3e/0x80 mm/kasan/common.c:68
 kasan_save_free_info+0x46/0x50 mm/kasan/generic.c:576
 poison_slab_object mm/kasan/common.c:247 [inline]
 __kasan_slab_free+0x62/0x70 mm/kasan/common.c:264
 kasan_slab_free include/linux/kasan.h:233 [inline]
 slab_free_hook mm/slub.c:2381 [inline]
 slab_free mm/slub.c:4643 [inline]
 kfree+0x18e/0x440 mm/slub.c:4842
 vhci_release+0xbc/0xd0 drivers/bluetooth/hci_vhci.c:671
 __fput+0x44c/0xa70 fs/file_table.c:465
 task_work_run+0x1d1/0x260 kernel/task_work.c:227
 exit_task_work include/linux/task_work.h:40 [inline]
 do_exit+0x6ad/0x22e0 kernel/exit.c:955
 do_group_exit+0x21c/0x2d0 kernel/exit.c:1104
 __do_sys_exit_group kernel/exit.c:1115 [inline]
 __se_sys_exit_group kernel/exit.c:1113 [inline]
 __x64_sys_exit_group+0x3f/0x40 kernel/exit.c:1113
 x64_sys_call+0x21ba/0x21c0 arch/x86/include/generated/asm/syscalls_64.h:232
 do_syscall_x64 arch/x86/entry/syscall_64.c:63 [inline]
 do_syscall_64+0xfa/0x3b0 arch/x86/entry/syscall_64.c:94
 entry_SYSCALL_64_after_hwframe+0x77/0x7f

The buggy address belongs to the object at ffff88807cb8d800
 which belongs to the cache kmalloc-1k of size 1024
The buggy address is located 88 bytes inside of
 freed 1024-byte region [ffff88807cb8d800, ffff88807cb8dc00)

Fixes: bf18c7118cf8 ("Bluetooth: vhci: Free driver_data on file release")
Reported-by: syzbot+2faa4825e556199361f9@syzkaller.appspotmail.com
Closes: https://syzkaller.appspot.com/bug?extid=f62d64848fc4c7c30cd6
Signed-off-by: Kuniyuki Iwashima <kuniyu@google.com>
Acked-by: Paul Menzel <pmenzel@molgen.mpg.de>
Signed-off-by: Luiz Augusto von Dentz <luiz.von.dentz@intel.com>
```

**Diff:**
```diff
diff --git a/include/net/bluetooth/hci_core.h b/include/net/bluetooth/hci_core.h
index a760f05fa3fb..9fc8f544e20e 100644
--- a/include/net/bluetooth/hci_core.h
+++ b/include/net/bluetooth/hci_core.h
@@ -29,6 +29,7 @@
 #include <linux/idr.h>
 #include <linux/leds.h>
 #include <linux/rculist.h>
+#include <linux/srcu.h>
 
 #include <net/bluetooth/hci.h>
 #include <net/bluetooth/hci_drv.h>
@@ -347,6 +348,7 @@ struct adv_monitor {
 
 struct hci_dev {
 	struct list_head list;
+	struct srcu_struct srcu;
 	struct mutex	lock;
 
 	struct ida	unset_handle_ida;
diff --git a/net/bluetooth/hci_core.c b/net/bluetooth/hci_core.c
index 07a8b4281a39..14d7221b8ac0 100644
--- a/net/bluetooth/hci_core.c
+++ b/net/bluetooth/hci_core.c
@@ -64,7 +64,7 @@ static DEFINE_IDA(hci_index_ida);
 
 /* Get HCI device by index.
  * Device is held on return. */
-struct hci_dev *hci_dev_get(int index)
+static struct hci_dev *__hci_dev_get(int index, int *srcu_index)
 {
 	struct hci_dev *hdev = NULL, *d;
 
@@ -77,6 +77,8 @@ struct hci_dev *hci_dev_get(int index)
 	list_for_each_entry(d, &hci_dev_list, list) {
 		if (d->id == index) {
 			hdev = hci_dev_hold(d);
+			if (srcu_index)
+				*srcu_index = srcu_read_lock(&d->srcu);
 			break;
 		}
 	}
@@ -84,6 +86,22 @@ struct hci_dev *hci_dev_get(int index)
 	return hdev;
 }
 
+struct hci_dev *hci_dev_get(int index)
+{
+	return __hci_dev_get(index, NULL);
+}

... (truncated 58 lines)
```

---

## Commit 5: 95b6759a

**Author:** Arnd Bergmann
**Date:** 2025-06-23 14:21:32
**Files Changed:** drivers/net/ethernet/qlogic/qed/qed_mng_tlv.c

**Message:**
```
net: qed: reduce stack usage for TLV processing

clang gets a bit confused by the code in the qed_mfw_process_tlv_req and
ends up spilling registers to the stack hundreds of times. When sanitizers
are enabled, this can end up blowing the stack warning limit:

drivers/net/ethernet/qlogic/qed/qed_mng_tlv.c:1244:5: error: stack frame size (1824) exceeds limit (1280) in 'qed_mfw_process_tlv_req' [-Werror,-Wframe-larger-than]

Apparently the problem is the complexity of qed_mfw_update_tlvs()
after inlining, and marking the four main branches of that function
as noinline_for_stack makes this problem completely go away, the stack
usage goes down to 100 bytes.

Signed-off-by: Arnd Bergmann <arnd@arndb.de>
Reviewed-by: Alexander Lobakin <aleksander.lobakin@intel.com>
Signed-off-by: David S. Miller <davem@davemloft.net>
```

**Diff:**
```diff
diff --git a/drivers/net/ethernet/qlogic/qed/qed_mng_tlv.c b/drivers/net/ethernet/qlogic/qed/qed_mng_tlv.c
index f55eed092f25..7d78f072b0a1 100644
--- a/drivers/net/ethernet/qlogic/qed/qed_mng_tlv.c
+++ b/drivers/net/ethernet/qlogic/qed/qed_mng_tlv.c
@@ -242,7 +242,7 @@ static int qed_mfw_get_tlv_group(u8 tlv_type, u8 *tlv_group)
 }
 
 /* Returns size of the data buffer or, -1 in case TLV data is not available. */
-static int
+static noinline_for_stack int
 qed_mfw_get_gen_tlv_value(struct qed_drv_tlv_hdr *p_tlv,
 			  struct qed_mfw_tlv_generic *p_drv_buf,
 			  struct qed_tlv_parsed_buf *p_buf)
@@ -304,7 +304,7 @@ qed_mfw_get_gen_tlv_value(struct qed_drv_tlv_hdr *p_tlv,
 	return -1;
 }
 
-static int
+static noinline_for_stack int
 qed_mfw_get_eth_tlv_value(struct qed_drv_tlv_hdr *p_tlv,
 			  struct qed_mfw_tlv_eth *p_drv_buf,
 			  struct qed_tlv_parsed_buf *p_buf)
@@ -438,7 +438,7 @@ qed_mfw_get_tlv_time_value(struct qed_mfw_tlv_time *p_time,
 	return QED_MFW_TLV_TIME_SIZE;
 }
 
-static int
+static noinline_for_stack int
 qed_mfw_get_fcoe_tlv_value(struct qed_drv_tlv_hdr *p_tlv,
 			   struct qed_mfw_tlv_fcoe *p_drv_buf,
 			   struct qed_tlv_parsed_buf *p_buf)
@@ -1073,7 +1073,7 @@ qed_mfw_get_fcoe_tlv_value(struct qed_drv_tlv_hdr *p_tlv,
 	return -1;
 }
 
-static int
+static noinline_for_stack int
 qed_mfw_get_iscsi_tlv_value(struct qed_drv_tlv_hdr *p_tlv,
 			    struct qed_mfw_tlv_iscsi *p_drv_buf,
 			    struct qed_tlv_parsed_buf *p_buf)
```

---

