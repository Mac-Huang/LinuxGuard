# Linux Kernel Commit Batch Analysis

## Commit 1: 7544f3f5

**Author:** Ido Schimmel
**Date:** 2025-06-23 18:19:10
**Files Changed:** net/bridge/br_multicast.c

**Message:**
```
bridge: mcast: Fix use-after-free during router port configuration

The bridge maintains a global list of ports behind which a multicast
router resides. The list is consulted during forwarding to ensure
multicast packets are forwarded to these ports even if the ports are not
member in the matching MDB entry.

When per-VLAN multicast snooping is enabled, the per-port multicast
context is disabled on each port and the port is removed from the global
router port list:

 # ip link add name br1 up type bridge vlan_filtering 1 mcast_snooping 1
 # ip link add name dummy1 up master br1 type dummy
 # ip link set dev dummy1 type bridge_slave mcast_router 2
 $ bridge -d mdb show | grep router
 router ports on br1: dummy1
 # ip link set dev br1 type bridge mcast_vlan_snooping 1
 $ bridge -d mdb show | grep router

However, the port can be re-added to the global list even when per-VLAN
multicast snooping is enabled:

 # ip link set dev dummy1 type bridge_slave mcast_router 0
 # ip link set dev dummy1 type bridge_slave mcast_router 2
 $ bridge -d mdb show | grep router
 router ports on br1: dummy1

Since commit 4b30ae9adb04 ("net: bridge: mcast: re-implement
br_multicast_{enable, disable}_port functions"), when per-VLAN multicast
snooping is enabled, multicast disablement on a port will disable the
per-{port, VLAN} multicast contexts and not the per-port one. As a
result, a port will remain in the global router port list even after it
is deleted. This will lead to a use-after-free [1] when the list is
traversed (when adding a new port to the list, for example):

 # ip link del dev dummy1
 # ip link add name dummy2 up master br1 type dummy
 # ip link set dev dummy2 type bridge_slave mcast_router 2

Similarly, stale entries can also be found in the per-VLAN router port
list. When per-VLAN multicast snooping is disabled, the per-{port, VLAN}
contexts are disabled on each port and the port is removed from the
per-VLAN router port list:

 # ip link add name br1 up type bridge vlan_filtering 1 mcast_snooping 1 mcast_vlan_snooping 1
 # ip link add name dummy1 up master br1 type dummy
 # bridge vlan add vid 2 dev dummy1
 # bridge vlan global set vid 2 dev br1 mcast_snooping 1
 # bridge vlan set vid 2 dev dummy1 mcast_router 2
 $ bridge vlan global show dev br1 vid 2 | grep router
       router ports: dummy1
 # ip link set dev br1 type bridge mcast_vlan_snooping 0
 $ bridge vlan global show dev br1 vid 2 | grep router

However, the port can be re-added to the per-VLAN list even when
per-VLAN multicast snooping is disabled:

 # bridge vlan set vid 2 dev dummy1 mcast_router 0
 # bridge vlan set vid 2 dev dummy1 mcast_router 2
 $ bridge vlan global show dev br1 vid 2 | grep router
       router ports: dummy1

When the VLAN is deleted from the port, the per-{port, VLAN} multicast
context will not be disabled since multicast snooping is not enabled
on the VLAN. As a result, the port will remain in the per-VLAN router
port list even after it is no longer member in the VLAN. This will lead
to a use-after-free [2] when the list is traversed (when adding a new
port to the list, for example):

 # ip link add name dummy2 up master br1 type dummy
 # bridge vlan add vid 2 dev dummy2
 # bridge vlan del vid 2 dev dummy1
 # bridge vlan set vid 2 dev dummy2 mcast_router 2

Fix these issues by removing the port from the relevant (global or
per-VLAN) router port list in br_multicast_port_ctx_deinit(). The
function is invoked during port deletion with the per-port multicast
context and during VLAN deletion with the per-{port, VLAN} multicast
context.

Note that deleting the multicast router timer is not enough as it only
takes care of the temporary multicast router states (1 or 3) and not the
permanent one (2).

[1]
BUG: KASAN: slab-out-of-bounds in br_multicast_add_router.part.0+0x3f1/0x560
Write of size 8 at addr ffff888004a67328 by task ip/384
[...]
Call Trace:
 <TASK>
 dump_stack_lvl+0x6f/0xa0
 print_address_description.constprop.0+0x6f/0x350
 print_report+0x108/0x205
 kasan_report+0xdf/0x110
 br_multicast_add_router.part.0+0x3f1/0x560
 br_multicast_set_port_router+0x74e/0xac0
 br_setport+0xa55/0x1870
 br_port_slave_changelink+0x95/0x120
 __rtnl_newlink+0x5e8/0xa40
 rtnl_newlink+0x627/0xb00
 rtnetlink_rcv_msg+0x6fb/0xb70
 netlink_rcv_skb+0x11f/0x350
 netlink_unicast+0x426/0x710
 netlink_sendmsg+0x75a/0xc20
 __sock_sendmsg+0xc1/0x150
 ____sys_sendmsg+0x5aa/0x7b0
 ___sys_sendmsg+0xfc/0x180
 __sys_sendmsg+0x124/0x1c0
 do_syscall_64+0xbb/0x360
 entry_SYSCALL_64_after_hwframe+0x4b/0x53

[2]
BUG: KASAN: slab-use-after-free in br_multicast_add_router.part.0+0x378/0x560
Read of size 8 at addr ffff888009f00840 by task bridge/391
[...]
Call Trace:
 <TASK>
 dump_stack_lvl+0x6f/0xa0
 print_address_description.constprop.0+0x6f/0x350
 print_report+0x108/0x205
 kasan_report+0xdf/0x110
 br_multicast_add_router.part.0+0x378/0x560
 br_multicast_set_port_router+0x6f9/0xac0
 br_vlan_process_options+0x8b6/0x1430
 br_vlan_rtm_process_one+0x605/0xa30
 br_vlan_rtm_process+0x396/0x4c0
 rtnetlink_rcv_msg+0x2f7/0xb70
 netlink_rcv_skb+0x11f/0x350
 netlink_unicast+0x426/0x710
 netlink_sendmsg+0x75a/0xc20
 __sock_sendmsg+0xc1/0x150
 ____sys_sendmsg+0x5aa/0x7b0
 ___sys_sendmsg+0xfc/0x180
 __sys_sendmsg+0x124/0x1c0
 do_syscall_64+0xbb/0x360
 entry_SYSCALL_64_after_hwframe+0x4b/0x53

Fixes: 2796d846d74a ("net: bridge: vlan: convert mcast router global option to per-vlan entry")
Fixes: 4b30ae9adb04 ("net: bridge: mcast: re-implement br_multicast_{enable, disable}_port functions")
Reported-by: syzbot+7bfa4b72c6a5da128d32@syzkaller.appspotmail.com
Closes: https://lore.kernel.org/all/684c18bd.a00a0220.279073.000b.GAE@google.com/T/
Signed-off-by: Ido Schimmel <idosch@nvidia.com>
Link: https://patch.msgid.link/20250619182228.1656906-1-idosch@nvidia.com
Signed-off-by: Jakub Kicinski <kuba@kernel.org>
```

**Diff:**
```diff
diff --git a/net/bridge/br_multicast.c b/net/bridge/br_multicast.c
index 0224ef3dfec0..1377f31b719c 100644
--- a/net/bridge/br_multicast.c
+++ b/net/bridge/br_multicast.c
@@ -2015,10 +2015,19 @@ void br_multicast_port_ctx_init(struct net_bridge_port *port,
 
 void br_multicast_port_ctx_deinit(struct net_bridge_mcast_port *pmctx)
 {
+	struct net_bridge *br = pmctx->port->br;
+	bool del = false;
+
 #if IS_ENABLED(CONFIG_IPV6)
 	timer_delete_sync(&pmctx->ip6_mc_router_timer);
 #endif
 	timer_delete_sync(&pmctx->ip4_mc_router_timer);
+
+	spin_lock_bh(&br->multicast_lock);
+	del |= br_ip6_multicast_rport_del(pmctx);
+	del |= br_ip4_multicast_rport_del(pmctx);
+	br_multicast_rport_del_notify(pmctx, del);
+	spin_unlock_bh(&br->multicast_lock);
 }
 
 int br_multicast_add_port(struct net_bridge_port *port)
```

---

## Commit 2: 78f4e737

**Author:** Linus Torvalds
**Date:** 2025-06-23 15:02:57
**Files Changed:** drivers/md/dm-crypt.c, drivers/md/dm-raid.c, include/crypto/hash.h, include/crypto/md5.h

**Message:**
```
Merge tag 'for-6.16/dm-fixes' of git://git.kernel.org/pub/scm/linux/kernel/git/device-mapper/linux-dm

Pull device mapper fixes from Mikulas Patocka:

 - dm-crypt: fix a crash on 32-bit machines

 - dm-raid: replace "rdev" with correct loop variable name "r"

* tag 'for-6.16/dm-fixes' of git://git.kernel.org/pub/scm/linux/kernel/git/device-mapper/linux-dm:
  dm-raid: fix variable in journal device check
  dm-crypt: Extend state buffer size in crypt_iv_lmk_one
```

**Diff:**
```diff
diff --git a/drivers/md/dm-crypt.c b/drivers/md/dm-crypt.c
index 9dfdb63220d7..17157c4216a5 100644
--- a/drivers/md/dm-crypt.c
+++ b/drivers/md/dm-crypt.c
@@ -517,7 +517,10 @@ static int crypt_iv_lmk_one(struct crypt_config *cc, u8 *iv,
 {
 	struct iv_lmk_private *lmk = &cc->iv_gen_private.lmk;
 	SHASH_DESC_ON_STACK(desc, lmk->hash_tfm);
-	struct md5_state md5state;
+	union {
+		struct md5_state md5state;
+		u8 state[CRYPTO_MD5_STATESIZE];
+	} u;
 	__le32 buf[4];
 	int i, r;
 
@@ -548,13 +551,13 @@ static int crypt_iv_lmk_one(struct crypt_config *cc, u8 *iv,
 		return r;
 
 	/* No MD5 padding here */
-	r = crypto_shash_export(desc, &md5state);
+	r = crypto_shash_export(desc, &u.md5state);
 	if (r)
 		return r;
 
 	for (i = 0; i < MD5_HASH_WORDS; i++)
-		__cpu_to_le32s(&md5state.hash[i]);
-	memcpy(iv, &md5state.hash, cc->iv_size);
+		__cpu_to_le32s(&u.md5state.hash[i]);
+	memcpy(iv, &u.md5state.hash, cc->iv_size);
 
 	return 0;
 }
diff --git a/drivers/md/dm-raid.c b/drivers/md/dm-raid.c
index d296770478b2..e8c0a8c6fb51 100644
--- a/drivers/md/dm-raid.c
+++ b/drivers/md/dm-raid.c
@@ -2407,7 +2407,7 @@ static int super_init_validation(struct raid_set *rs, struct md_rdev *rdev)
 	 */
 	sb_retrieve_failed_devices(sb, failed_devices);
 	rdev_for_each(r, mddev) {
-		if (test_bit(Journal, &rdev->flags) ||
+		if (test_bit(Journal, &r->flags) ||
 		    !r->sb_page)
 			continue;
 		sb2 = page_address(r->sb_page);
diff --git a/include/crypto/hash.h b/include/crypto/hash.h
index 6f6b9de12cd3..db294d452e8c 100644
--- a/include/crypto/hash.h
+++ b/include/crypto/hash.h

... (truncated 31 lines)
```

---

## Commit 3: 2b8be57f

**Author:** Zhe Qiao
**Date:** 2025-06-23 22:15:45
**Files Changed:** drivers/pci/pci-acpi.c

**Message:**
```
Revert "PCI/ACPI: Fix allocated memory release on error in pci_acpi_scan_root()"

This reverts commit 631b2af2f357 ("PCI/ACPI: Fix allocated memory release
on error in pci_acpi_scan_root()").

The reverted patch causes the 'ri->cfg' and 'root_ops' resources to be
released multiple times.

When acpi_pci_root_create() fails, these resources have already been
released internally by the __acpi_pci_root_release_info() function.

Releasing them again in pci_acpi_scan_root() leads to incorrect behavior
and potential memory issues.

We plan to resolve the issue using a more appropriate fix.

Reported-by: Dan Carpenter <dan.carpenter@linaro.org>
Closes: https://lore.kernel.org/all/aEmdnuw715btq7Q5@stanley.mountain/
Signed-off-by: Zhe Qiao <qiaozhe@iscas.ac.cn>
Acked-by: Dan Carpenter <dan.carpenter@linaro.org>
Link: https://patch.msgid.link/20250619072608.2075475-1-qiaozhe@iscas.ac.cn
Signed-off-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
```

**Diff:**
```diff
diff --git a/drivers/pci/pci-acpi.c b/drivers/pci/pci-acpi.c
index b78e0e417324..af370628e583 100644
--- a/drivers/pci/pci-acpi.c
+++ b/drivers/pci/pci-acpi.c
@@ -1676,19 +1676,24 @@ struct pci_bus *pci_acpi_scan_root(struct acpi_pci_root *root)
 		return NULL;
 
 	root_ops = kzalloc(sizeof(*root_ops), GFP_KERNEL);
-	if (!root_ops)
-		goto free_ri;
+	if (!root_ops) {
+		kfree(ri);
+		return NULL;
+	}
 
 	ri->cfg = pci_acpi_setup_ecam_mapping(root);
-	if (!ri->cfg)
-		goto free_root_ops;
+	if (!ri->cfg) {
+		kfree(ri);
+		kfree(root_ops);
+		return NULL;
+	}
 
 	root_ops->release_info = pci_acpi_generic_release_info;
 	root_ops->prepare_resources = pci_acpi_root_prepare_resources;
 	root_ops->pci_ops = (struct pci_ops *)&ri->cfg->ops->pci_ops;
 	bus = acpi_pci_root_create(root, root_ops, &ri->common, ri->cfg);
 	if (!bus)
-		goto free_cfg;
+		return NULL;
 
 	/* If we must preserve the resource configuration, claim now */
 	host = pci_find_host_bridge(bus);
@@ -1705,14 +1710,6 @@ struct pci_bus *pci_acpi_scan_root(struct acpi_pci_root *root)
 		pcie_bus_configure_settings(child);
 
 	return bus;
-
-free_cfg:
-	pci_ecam_free(ri->cfg);
-free_root_ops:
-	kfree(root_ops);
-free_ri:
-	kfree(ri);
-	return NULL;
 }
 
 void pcibios_add_bus(struct pci_bus *bus)
```

---

## Commit 4: 5ca7fe21

**Author:** Linus Torvalds
**Date:** 2025-06-23 11:16:38
**Files Changed:** fs/btrfs/delayed-inode.c, fs/btrfs/disk-io.c, fs/btrfs/extent_io.c, fs/btrfs/free-space-tree.c, fs/btrfs/inode.c (+5 more)

**Message:**
```
Merge tag 'for-6.16-rc3-tag' of git://git.kernel.org/pub/scm/linux/kernel/git/kdave/linux

Pull btrfs fixes from David Sterba:
 "Fixes:

   - fix invalid inode pointer dereferences during log replay

   - fix a race between renames and directory logging

   - fix shutting down delayed iput worker

   - fix device byte accounting when dropping chunk

   - in zoned mode, fix offset calculations for DUP profile when
     conventional and sequential zones are used together

  Regression fixes:

   - fix possible double unlock of extent buffer tree (xarray
     conversion)

   - in zoned mode, fix extent buffer refcount when writing out extents
     (xarray conversion)

  Error handling fixes and updates:

   - handle unexpected extent type when replaying log

   - check and warn if there are remaining delayed inodes when putting a
     root

   - fix assertion when building free space tree

   - handle csum tree error with mount option 'rescue=ibadroot'

  Other:

   - error message updates: add prefix to all scrub related messages,
     include other information in messages"

* tag 'for-6.16-rc3-tag' of git://git.kernel.org/pub/scm/linux/kernel/git/kdave/linux:
  btrfs: zoned: fix alloc_offset calculation for partly conventional block groups
  btrfs: handle csum tree error with rescue=ibadroots correctly
  btrfs: fix race between async reclaim worker and close_ctree()
  btrfs: fix assertion when building free space tree
  btrfs: don't silently ignore unexpected extent type when replaying log
  btrfs: fix invalid inode pointer dereferences during log replay
  btrfs: fix double unlock of buffer_tree xarray when releasing subpage eb
  btrfs: update superblock's device bytes_used when dropping chunk
  btrfs: fix a race between renames and directory logging
  btrfs: scrub: add prefix for the error messages
  btrfs: warn if leaking delayed_nodes in btrfs_put_root()
  btrfs: fix delayed ref refcount leak in debug assertion
  btrfs: include root in error message when unlinking inode
  btrfs: don't drop a reference if btrfs_check_write_meta_pointer() fails
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
diff --git a/fs/btrfs/disk-io.c b/fs/btrfs/disk-io.c
index 1beb9458f622..0d6ad7512f21 100644
--- a/fs/btrfs/disk-io.c
+++ b/fs/btrfs/disk-io.c
@@ -1835,6 +1835,8 @@ void btrfs_put_root(struct btrfs_root *root)
 	if (refcount_dec_and_test(&root->refs)) {
 		if (WARN_ON(!xa_empty(&root->inodes)))
 			xa_destroy(&root->inodes);
+		if (WARN_ON(!xa_empty(&root->delayed_nodes)))
+			xa_destroy(&root->delayed_nodes);
 		WARN_ON(test_bit(BTRFS_ROOT_DEAD_RELOC_TREE, &root->state));
 		if (root->anon_dev)
 			free_anon_bdev(root->anon_dev);
@@ -2156,8 +2158,7 @@ static int load_global_roots_objectid(struct btrfs_root *tree_root,
 		found = true;
 		root = read_tree_root_path(tree_root, path, &key);
 		if (IS_ERR(root)) {
-			if (!btrfs_test_opt(fs_info, IGNOREBADROOTS))
-				ret = PTR_ERR(root);
+			ret = PTR_ERR(root);
 			break;
 		}
 		set_bit(BTRFS_ROOT_TRACK_DIRTY, &root->state);
@@ -4310,8 +4311,8 @@ void __cold close_ctree(struct btrfs_fs_info *fs_info)
 	 *
 	 * So wait for all ongoing ordered extents to complete and then run
 	 * delayed iputs. This works because once we reach this point no one
-	 * can either create new ordered extents nor create delayed iputs
-	 * through some other means.
+	 * can create new ordered extents, but delayed iputs can still be added
+	 * by a reclaim worker (see comments further below).
 	 *
 	 * Also note that btrfs_wait_ordered_roots() is not safe here, because
 	 * it waits for BTRFS_ORDERED_COMPLETE to be set on an ordered extent,

... (truncated 705 lines)
```

---

## Commit 5: aa485e87

**Author:** Yuan Chen
**Date:** 2025-06-23 11:13:40
**Files Changed:** tools/lib/bpf/btf_dump.c

**Message:**
```
libbpf: Fix null pointer dereference in btf_dump__free on allocation failure

When btf_dump__new() fails to allocate memory for the internal hashmap
(btf_dump->type_names), it returns an error code. However, the cleanup
function btf_dump__free() does not check if btf_dump->type_names is NULL
before attempting to free it. This leads to a null pointer dereference
when btf_dump__free() is called on a btf_dump object.

Fixes: 351131b51c7a ("libbpf: add btf_dump API for BTF-to-C conversion")
Signed-off-by: Yuan Chen <chenyuan@kylinos.cn>
Signed-off-by: Andrii Nakryiko <andrii@kernel.org>
Link: https://lore.kernel.org/bpf/20250618011933.11423-1-chenyuan_fl@163.com
```

**Diff:**
```diff
diff --git a/tools/lib/bpf/btf_dump.c b/tools/lib/bpf/btf_dump.c
index 460c3e57fadb..0381f209920a 100644
--- a/tools/lib/bpf/btf_dump.c
+++ b/tools/lib/bpf/btf_dump.c
@@ -226,6 +226,9 @@ static void btf_dump_free_names(struct hashmap *map)
 	size_t bkt;
 	struct hashmap_entry *cur;
 
+	if (!map)
+		return;
+
 	hashmap__for_each_entry(map, cur, bkt)
 		free((void *)cur->pkey);
 
```

---

