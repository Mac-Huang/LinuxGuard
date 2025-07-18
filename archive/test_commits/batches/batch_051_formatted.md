# Linux Kernel Commit Batch Analysis

## Commit 1: 5bd1bafd

**Author:** Jakub Kicinski
**Date:** 2025-06-19 12:16:11
**Files Changed:** drivers/net/ethernet/meta/fbnic/fbnic_fw.c

**Message:**
```
eth: fbnic: avoid double free when failing to DMA-map FW msg

The semantics are that caller of fbnic_mbx_map_msg() retains
the ownership of the message on error. All existing callers
dutifully free the page.

Fixes: da3cde08209e ("eth: fbnic: Add FW communication mechanism")
Reviewed-by: Alexander Duyck <alexanderduyck@fb.com>
Signed-off-by: Jakub Kicinski <kuba@kernel.org>
Reviewed-by: Jacob Keller <jacob.e.keller@intel.com>
Link: https://patch.msgid.link/20250616195510.225819-1-kuba@kernel.org
Signed-off-by: Paolo Abeni <pabeni@redhat.com>
```

**Diff:**
```diff
diff --git a/drivers/net/ethernet/meta/fbnic/fbnic_fw.c b/drivers/net/ethernet/meta/fbnic/fbnic_fw.c
index e2368075ab8c..4521d0483d18 100644
--- a/drivers/net/ethernet/meta/fbnic/fbnic_fw.c
+++ b/drivers/net/ethernet/meta/fbnic/fbnic_fw.c
@@ -127,11 +127,8 @@ static int fbnic_mbx_map_msg(struct fbnic_dev *fbd, int mbx_idx,
 		return -EBUSY;
 
 	addr = dma_map_single(fbd->dev, msg, PAGE_SIZE, direction);
-	if (dma_mapping_error(fbd->dev, addr)) {
-		free_page((unsigned long)msg);
-
+	if (dma_mapping_error(fbd->dev, addr))
 		return -ENOSPC;
-	}
 
 	mbx->buf_info[tail].msg = msg;
 	mbx->buf_info[tail].addr = addr;
```

---

## Commit 2: 9b70c362

**Author:** Jakub Kicinski
**Date:** 2025-06-18 18:30:55
**Files Changed:** net/ipv4/tcp_fastopen.c, tools/testing/selftests/net/tfo.c

**Message:**
```
Merge branch 'net-fix-passive-tfo-socket-having-invalid-napi-id'

David Wei says:

====================
net: fix passive TFO socket having invalid NAPI ID

Found a bug where an accepted passive TFO socket returns an invalid NAPI
ID (i.e. 0) from SO_INCOMING_NAPI_ID. Add a selftest for this using
netdevsim and fix the bug.

Patch 1 is a drive-by fix for the lib.sh include in an existing
drivers/net/netdevsim/peer.sh selftest.

Patch 2 adds a test binary for a simple TFO server/client.

Patch 3 adds a selftest for checking that the NAPI ID of a passive TFO
socket is valid. This will currently fail.

Patch 4 adds a fix for the bug.
====================

Link: https://patch.msgid.link/20250617212102.175711-1-dw@davidwei.uk
Signed-off-by: Jakub Kicinski <kuba@kernel.org>
```

**Diff:**
```diff
diff --git a/net/ipv4/tcp_fastopen.c b/net/ipv4/tcp_fastopen.c
index 9b83d639b5ac..5107121c5e37 100644
--- a/net/ipv4/tcp_fastopen.c
+++ b/net/ipv4/tcp_fastopen.c
@@ -3,6 +3,7 @@
 #include <linux/tcp.h>
 #include <linux/rcupdate.h>
 #include <net/tcp.h>
+#include <net/busy_poll.h>
 
 void tcp_fastopen_init_key_once(struct net *net)
 {
@@ -279,6 +280,8 @@ static struct sock *tcp_fastopen_create_child(struct sock *sk,
 
 	refcount_set(&req->rsk_refcnt, 2);
 
+	sk_mark_napi_id_set(child, skb);
+
 	/* Now finish processing the fastopen child socket. */
 	tcp_init_transfer(child, BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB, skb);
 
diff --git a/tools/testing/selftests/drivers/net/netdevsim/peer.sh b/tools/testing/selftests/drivers/net/netdevsim/peer.sh
index 1bb46ec435d4..7f32b5600925 100755
--- a/tools/testing/selftests/drivers/net/netdevsim/peer.sh
+++ b/tools/testing/selftests/drivers/net/netdevsim/peer.sh
@@ -1,7 +1,8 @@
 #!/bin/bash
 # SPDX-License-Identifier: GPL-2.0-only
 
-source ../../../net/lib.sh
+lib_dir=$(dirname $0)/../../../net
+source $lib_dir/lib.sh
 
 NSIM_DEV_1_ID=$((256 + RANDOM % 256))
 NSIM_DEV_1_SYS=/sys/bus/netdevsim/devices/netdevsim$NSIM_DEV_1_ID
diff --git a/tools/testing/selftests/net/.gitignore b/tools/testing/selftests/net/.gitignore
index 532bb732bc6d..c6dd2a335cf4 100644
--- a/tools/testing/selftests/net/.gitignore
+++ b/tools/testing/selftests/net/.gitignore
@@ -50,6 +50,7 @@ tap
 tcp_fastopen_backup_key
 tcp_inq
 tcp_mmap
+tfo
 timestamping
 tls
 toeplitz
diff --git a/tools/testing/selftests/net/Makefile b/tools/testing/selftests/net/Makefile
index ab996bd22a5f..332f387615d7 100644
--- a/tools/testing/selftests/net/Makefile

... (truncated 305 lines)
```

---

## Commit 3: fb4d33ab

**Author:** Linus Torvalds
**Date:** 2025-06-18 17:47:27
**Files Changed:** fs/smb/server/connection.c, fs/smb/server/connection.h, fs/smb/server/smb2pdu.c, fs/smb/server/transport_rdma.c, fs/smb/server/transport_tcp.c (+2 more)

**Message:**
```
Merge tag '6.16-rc2-ksmbd-server-fixes' of git://git.samba.org/ksmbd

Pull smb server fixes from Steve French:

 - Fix alternate data streams bug

 - Important fix for null pointer deref with Kerberos authentication

 - Fix oops in smbdirect (RDMA) in free_transport

* tag '6.16-rc2-ksmbd-server-fixes' of git://git.samba.org/ksmbd:
  ksmbd: handle set/get info file for streamed file
  ksmbd: fix null pointer dereference in destroy_previous_session
  ksmbd: add free_transport ops in ksmbd connection
```

**Diff:**
```diff
diff --git a/fs/smb/server/connection.c b/fs/smb/server/connection.c
index 83764c230e9d..3f04a2977ba8 100644
--- a/fs/smb/server/connection.c
+++ b/fs/smb/server/connection.c
@@ -40,7 +40,7 @@ void ksmbd_conn_free(struct ksmbd_conn *conn)
 	kvfree(conn->request_buf);
 	kfree(conn->preauth_info);
 	if (atomic_dec_and_test(&conn->refcnt)) {
-		ksmbd_free_transport(conn->transport);
+		conn->transport->ops->free_transport(conn->transport);
 		kfree(conn);
 	}
 }
diff --git a/fs/smb/server/connection.h b/fs/smb/server/connection.h
index 6efed923bd68..dd3e0e3f7bf0 100644
--- a/fs/smb/server/connection.h
+++ b/fs/smb/server/connection.h
@@ -133,6 +133,7 @@ struct ksmbd_transport_ops {
 			  void *buf, unsigned int len,
 			  struct smb2_buffer_desc_v1 *desc,
 			  unsigned int desc_len);
+	void (*free_transport)(struct ksmbd_transport *kt);
 };
 
 struct ksmbd_transport {
diff --git a/fs/smb/server/smb2pdu.c b/fs/smb/server/smb2pdu.c
index 1a308171b599..fafa86273f12 100644
--- a/fs/smb/server/smb2pdu.c
+++ b/fs/smb/server/smb2pdu.c
@@ -1607,17 +1607,18 @@ static int krb5_authenticate(struct ksmbd_work *work,
 	out_len = work->response_sz -
 		(le16_to_cpu(rsp->SecurityBufferOffset) + 4);
 
-	/* Check previous session */
-	prev_sess_id = le64_to_cpu(req->PreviousSessionId);
-	if (prev_sess_id && prev_sess_id != sess->id)
-		destroy_previous_session(conn, sess->user, prev_sess_id);
-
 	retval = ksmbd_krb5_authenticate(sess, in_blob, in_len,
 					 out_blob, &out_len);
 	if (retval) {
 		ksmbd_debug(SMB, "krb5 authentication failed\n");
 		return -EINVAL;
 	}
+
+	/* Check previous session */
+	prev_sess_id = le64_to_cpu(req->PreviousSessionId);
+	if (prev_sess_id && prev_sess_id != sess->id)
+		destroy_previous_session(conn, sess->user, prev_sess_id);
+

... (truncated 223 lines)
```

---

## Commit 4: 229f135e

**Author:** Linus Torvalds
**Date:** 2025-06-18 14:31:16
**Files Changed:** rust/bindings/bindings_helper.h, rust/helpers/completion.c, rust/helpers/helpers.c

**Message:**
```
Merge tag 'driver-core-6.16-rc3' of git://git.kernel.org/pub/scm/linux/kernel/git/driver-core/driver-core

Pull driver core fixes from Danilo Krummrich:

 - Fix a race condition in Devres::drop(). This depends on two other
   patches:
     - (Minimal) Rust abstractions for struct completion
     - Let Revocable indicate whether its data is already being revoked

 - Fix Devres to avoid exposing the internal Revocable

 - Add .mailmap entry for Danilo Krummrich

 - Add Madhavan Srinivasan to embargoed-hardware-issues.rst

* tag 'driver-core-6.16-rc3' of git://git.kernel.org/pub/scm/linux/kernel/git/driver-core/driver-core:
  Documentation: embargoed-hardware-issues.rst: Add myself for Power
  mailmap: add entry for Danilo Krummrich
  rust: devres: do not dereference to the internal Revocable
  rust: devres: fix race in Devres::drop()
  rust: revocable: indicate whether `data` has been revoked already
  rust: completion: implement initial abstraction
```

**Diff:**
```diff
diff --git a/.mailmap b/.mailmap
index 1999905a9c7e..fee7681100a8 100644
--- a/.mailmap
+++ b/.mailmap
@@ -197,6 +197,7 @@ Daniel Borkmann <daniel@iogearbox.net> <daniel.borkmann@tik.ee.ethz.ch>
 Daniel Borkmann <daniel@iogearbox.net> <dborkmann@redhat.com>
 Daniel Borkmann <daniel@iogearbox.net> <dborkman@redhat.com>
 Daniel Borkmann <daniel@iogearbox.net> <dxchgb@gmail.com>
+Danilo Krummrich <dakr@kernel.org> <dakr@redhat.com>
 David Brownell <david-b@pacbell.net>
 David Collins <quic_collinsd@quicinc.com> <collinsd@codeaurora.org>
 David Heidelberg <david@ixit.cz> <d.okias@gmail.com>
diff --git a/Documentation/process/embargoed-hardware-issues.rst b/Documentation/process/embargoed-hardware-issues.rst
index da6bf0f6d01e..34e00848e0da 100644
--- a/Documentation/process/embargoed-hardware-issues.rst
+++ b/Documentation/process/embargoed-hardware-issues.rst
@@ -290,6 +290,7 @@ an involved disclosed party. The current ambassadors list:
   AMD		Tom Lendacky <thomas.lendacky@amd.com>
   Ampere	Darren Hart <darren@os.amperecomputing.com>
   ARM		Catalin Marinas <catalin.marinas@arm.com>
+  IBM Power	Madhavan Srinivasan <maddy@linux.ibm.com>
   IBM Z		Christian Borntraeger <borntraeger@de.ibm.com>
   Intel		Tony Luck <tony.luck@intel.com>
   Qualcomm	Trilok Soni <quic_tsoni@quicinc.com>
diff --git a/rust/bindings/bindings_helper.h b/rust/bindings/bindings_helper.h
index bc494745f67b..8cbb660e2ec2 100644
--- a/rust/bindings/bindings_helper.h
+++ b/rust/bindings/bindings_helper.h
@@ -39,6 +39,7 @@
 #include <linux/blk_types.h>
 #include <linux/blkdev.h>
 #include <linux/clk.h>
+#include <linux/completion.h>
 #include <linux/configfs.h>
 #include <linux/cpu.h>
 #include <linux/cpufreq.h>
diff --git a/rust/helpers/completion.c b/rust/helpers/completion.c
new file mode 100644
index 000000000000..b2443262a2ae
--- /dev/null
+++ b/rust/helpers/completion.c
@@ -0,0 +1,8 @@
+// SPDX-License-Identifier: GPL-2.0
+
+#include <linux/completion.h>
+
+void rust_helper_init_completion(struct completion *x)
+{
+	init_completion(x);
+}

... (truncated 340 lines)
```

---

## Commit 5: 28c0d775

**Author:** Jakub Kicinski
**Date:** 2025-06-18 14:15:15
**Files Changed:** drivers/net/ethernet/intel/e1000e/netdev.c, drivers/net/ethernet/intel/e1000e/ptp.c, drivers/net/ethernet/intel/ice/ice_arfs.c, drivers/net/ethernet/intel/ice/ice_eswitch.c

**Message:**
```
Merge branch '100GbE' of git://git.kernel.org/pub/scm/linux/kernel/git/tnguy/net-queue

Tony Nguyen says:

====================
Intel Wired LAN Driver Updates 2025-06-17 (ice, e1000e)

For ice:
Krishna Kumar modifies aRFS match criteria to correctly identify
matching filters.

Grzegorz fixes a memory leak in eswitch legacy mode.

For e1000e:
Vitaly sets clock frequency on some Nahum systems which may misreport
their value.

* '100GbE' of git://git.kernel.org/pub/scm/linux/kernel/git/tnguy/net-queue:
  e1000e: set fixed clock frequency indication for Nahum 11 and Nahum 13
  ice: fix eswitch code memory leak in reset scenario
  net: ice: Perform accurate aRFS flow match
====================

Link: https://patch.msgid.link/20250617172444.1419560-1-anthony.l.nguyen@intel.com
Signed-off-by: Jakub Kicinski <kuba@kernel.org>
```

**Diff:**
```diff
diff --git a/drivers/net/ethernet/intel/e1000e/netdev.c b/drivers/net/ethernet/intel/e1000e/netdev.c
index a96f4cfa6e17..7719e15813ee 100644
--- a/drivers/net/ethernet/intel/e1000e/netdev.c
+++ b/drivers/net/ethernet/intel/e1000e/netdev.c
@@ -3534,9 +3534,6 @@ s32 e1000e_get_base_timinca(struct e1000_adapter *adapter, u32 *timinca)
 	case e1000_pch_cnp:
 	case e1000_pch_tgp:
 	case e1000_pch_adp:
-	case e1000_pch_mtp:
-	case e1000_pch_lnp:
-	case e1000_pch_ptp:
 	case e1000_pch_nvp:
 		if (er32(TSYNCRXCTL) & E1000_TSYNCRXCTL_SYSCFI) {
 			/* Stable 24MHz frequency */
@@ -3552,6 +3549,17 @@ s32 e1000e_get_base_timinca(struct e1000_adapter *adapter, u32 *timinca)
 			adapter->cc.shift = shift;
 		}
 		break;
+	case e1000_pch_mtp:
+	case e1000_pch_lnp:
+	case e1000_pch_ptp:
+		/* System firmware can misreport this value, so set it to a
+		 * stable 38400KHz frequency.
+		 */
+		incperiod = INCPERIOD_38400KHZ;
+		incvalue = INCVALUE_38400KHZ;
+		shift = INCVALUE_SHIFT_38400KHZ;
+		adapter->cc.shift = shift;
+		break;
 	case e1000_82574:
 	case e1000_82583:
 		/* Stable 25MHz frequency */
diff --git a/drivers/net/ethernet/intel/e1000e/ptp.c b/drivers/net/ethernet/intel/e1000e/ptp.c
index 89d57dd911dc..ea3c3eb2ef20 100644
--- a/drivers/net/ethernet/intel/e1000e/ptp.c
+++ b/drivers/net/ethernet/intel/e1000e/ptp.c
@@ -295,15 +295,17 @@ void e1000e_ptp_init(struct e1000_adapter *adapter)
 	case e1000_pch_cnp:
 	case e1000_pch_tgp:
 	case e1000_pch_adp:
-	case e1000_pch_mtp:
-	case e1000_pch_lnp:
-	case e1000_pch_ptp:
 	case e1000_pch_nvp:
 		if (er32(TSYNCRXCTL) & E1000_TSYNCRXCTL_SYSCFI)
 			adapter->ptp_clock_info.max_adj = MAX_PPB_24MHZ;
 		else
 			adapter->ptp_clock_info.max_adj = MAX_PPB_38400KHZ;
 		break;
+	case e1000_pch_mtp:

... (truncated 93 lines)
```

---

