# Linux Kernel Commit Batch Analysis

## Commit 1: 2aebf5ee

**Author:** Masami Hiramatsu (Google)
**Date:** 2025-06-18 13:59:56
**Files Changed:** arch/x86/kernel/alternative.c

**Message:**
```
x86/alternatives: Fix int3 handling failure from broken text_poke array

Since smp_text_poke_single() does not expect there is another
text_poke request is queued, it can make text_poke_array not
sorted or cause a buffer overflow on the text_poke_array.vec[].
This will cause an Oops in int3 because of bsearch failing;

   CPU 0                        CPU 1                      CPU 2
   -----                        -----                      -----

 smp_text_poke_batch_add()

			    smp_text_poke_single() <<-- Adds out of order

							<int3>
                                                	[Fails o find address
                                                        in text_poke_array ]
                                                        OOPS!

Or unhandled page fault because of a buffer overflow;

   CPU 0                        CPU 1
   -----                        -----

 smp_text_poke_batch_add() <<+
 ...                         |
 smp_text_poke_batch_add() <<-- Adds TEXT_POKE_ARRAY_MAX times.

			     smp_text_poke_single() {
			     	__smp_text_poke_batch_add() <<-- Adds entry at
								TEXT_POKE_ARRAY_MAX + 1

                		smp_text_poke_batch_finish()
                        	  [Unhandled page fault because
				   text_poke_array.nr_entries is
				   overwritten]
				   BUG!
			     }

Use smp_text_poke_batch_add() instead of __smp_text_poke_batch_add()
so that it correctly flush the queue if needed.

Closes: https://lore.kernel.org/all/CA+G9fYsLu0roY3DV=tKyqP7FEKbOEETRvTDhnpPxJGbA=Cg+4w@mail.gmail.com/
Fixes: c8976ade0c1b ("x86/alternatives: Simplify smp_text_poke_single() by using tp_vec and existing APIs")
Reported-by: Linux Kernel Functional Testing <lkft@linaro.org>
Signed-off-by: Masami Hiramatsu (Google) <mhiramat@kernel.org>
Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Reviewed-by: Steven Rostedt (Google) <rostedt@goodmis.org>
Tested-by: Linux Kernel Functional Testing <lkft@linaro.org>
Link: https://lkml.kernel.org/r/\ 175020512308.3582717.13631440385506146631.stgit@mhiramat.tok.corp.google.com
```

**Diff:**
```diff
diff --git a/arch/x86/kernel/alternative.c b/arch/x86/kernel/alternative.c
index 9ae80fa904a2..ea1d984166cd 100644
--- a/arch/x86/kernel/alternative.c
+++ b/arch/x86/kernel/alternative.c
@@ -3138,6 +3138,6 @@ void __ref smp_text_poke_batch_add(void *addr, const void *opcode, size_t len, c
  */
 void __ref smp_text_poke_single(void *addr, const void *opcode, size_t len, const void *emulate)
 {
-	__smp_text_poke_batch_add(addr, opcode, len, emulate);
+	smp_text_poke_batch_add(addr, opcode, len, emulate);
 	smp_text_poke_batch_finish();
 }
```

---

## Commit 2: e1c75831

**Author:** Penglei Jiang
**Date:** 2025-06-18 05:09:46
**Files Changed:** io_uring/rsrc.c

**Message:**
```
io_uring: fix potential page leak in io_sqe_buffer_register()

If allocation of the 'imu' fails, then the existing pages aren't
unpinned in the error path. This is mostly a theoretical issue,
requiring fault injection to hit.

Move unpin_user_pages() to unified error handling to fix the page leak
issue.

Fixes: d8c2237d0aa9 ("io_uring: add io_pin_pages() helper")
Signed-off-by: Penglei Jiang <superman.xpt@gmail.com>
Link: https://lore.kernel.org/r/20250617165644.79165-1-superman.xpt@gmail.com
Signed-off-by: Jens Axboe <axboe@kernel.dk>
```

**Diff:**
```diff
diff --git a/io_uring/rsrc.c b/io_uring/rsrc.c
index 94a9db030e0e..d724602697e7 100644
--- a/io_uring/rsrc.c
+++ b/io_uring/rsrc.c
@@ -809,10 +809,8 @@ static struct io_rsrc_node *io_sqe_buffer_register(struct io_ring_ctx *ctx,
 
 	imu->nr_bvecs = nr_pages;
 	ret = io_buffer_account_pin(ctx, pages, nr_pages, imu, last_hpage);
-	if (ret) {
-		unpin_user_pages(pages, nr_pages);
+	if (ret)
 		goto done;
-	}
 
 	size = iov->iov_len;
 	/* store original address for later verification */
@@ -842,6 +840,8 @@ static struct io_rsrc_node *io_sqe_buffer_register(struct io_ring_ctx *ctx,
 	if (ret) {
 		if (imu)
 			io_free_imu(ctx, imu);
+		if (pages)
+			unpin_user_pages(pages, nr_pages);
 		io_cache_free(&ctx->node_cache, node);
 		node = ERR_PTR(ret);
 	}
```

---

## Commit 3: d5352b49

**Author:** Pei Xiao
**Date:** 2025-06-18 10:40:52
**Files Changed:** drivers/net/wireless/intel/iwlwifi/pcie/ctxt-info.c

**Message:**
```
wifi: iwlwifi: cfg: Limit cb_size to valid range

on arm64 defconfig build failed with gcc-8:

drivers/net/wireless/intel/iwlwifi/pcie/ctxt-info.c:208:3:
include/linux/bitfield.h:195:3: error: call to '__field_overflow'
declared with attribute error: value doesn't fit into mask
   __field_overflow();     \
   ^~~~~~~~~~~~~~~~~~
include/linux/bitfield.h:215:2: note: in expansion of macro '____MAKE_OP'
  ____MAKE_OP(u##size,u##size,,)
  ^~~~~~~~~~~
include/linux/bitfield.h:218:1: note: in expansion of macro '__MAKE_OP'
 __MAKE_OP(32)

Limit cb_size to valid range to fix it.

Signed-off-by: Pei Xiao <xiaopei01@kylinos.cn>
Link: https://patch.msgid.link/7b373a4426070d50b5afb3269fd116c18ce3aea8.1748332709.git.xiaopei01@kylinos.cn
Signed-off-by: Miri Korenblit <miriam.rachel.korenblit@intel.com>
```

**Diff:**
```diff
diff --git a/drivers/net/wireless/intel/iwlwifi/pcie/ctxt-info.c b/drivers/net/wireless/intel/iwlwifi/pcie/ctxt-info.c
index cb36baac14da..4f2be0c1bd97 100644
--- a/drivers/net/wireless/intel/iwlwifi/pcie/ctxt-info.c
+++ b/drivers/net/wireless/intel/iwlwifi/pcie/ctxt-info.c
@@ -166,7 +166,7 @@ int iwl_pcie_ctxt_info_init(struct iwl_trans *trans,
 	struct iwl_trans_pcie *trans_pcie = IWL_TRANS_GET_PCIE_TRANS(trans);
 	struct iwl_context_info *ctxt_info;
 	struct iwl_context_info_rbd_cfg *rx_cfg;
-	u32 control_flags = 0, rb_size;
+	u32 control_flags = 0, rb_size, cb_size;
 	dma_addr_t phys;
 	int ret;
 
@@ -202,11 +202,12 @@ int iwl_pcie_ctxt_info_init(struct iwl_trans *trans,
 		rb_size = IWL_CTXT_INFO_RB_SIZE_4K;
 	}
 
-	WARN_ON(RX_QUEUE_CB_SIZE(iwl_trans_get_num_rbds(trans)) > 12);
+	cb_size = RX_QUEUE_CB_SIZE(iwl_trans_get_num_rbds(trans));
+	if (WARN_ON(cb_size > 12))
+		cb_size = 12;
+
 	control_flags = IWL_CTXT_INFO_TFD_FORMAT_LONG;
-	control_flags |=
-		u32_encode_bits(RX_QUEUE_CB_SIZE(iwl_trans_get_num_rbds(trans)),
-				IWL_CTXT_INFO_RB_CB_SIZE);
+	control_flags |= u32_encode_bits(cb_size, IWL_CTXT_INFO_RB_CB_SIZE);
 	control_flags |= u32_encode_bits(rb_size, IWL_CTXT_INFO_RB_SIZE);
 	ctxt_info->control.control_flags = cpu_to_le32(control_flags);
 
```

---

## Commit 4: 0aff0043

**Author:** Jakub Kicinski
**Date:** 2025-06-17 18:42:49
**Files Changed:** drivers/atm/atmtcp.c, include/linux/atmdev.h, net/atm/common.c, net/atm/raw.c

**Message:**
```
Merge branch 'atm-fix-uninit-and-mem-accounting-leak-in-vcc_sendmsg'

Kuniyuki Iwashima says:

====================
atm: Fix uninit and mem accounting leak in vcc_sendmsg().

Patch 1 fixes uninit issue reported by KMSAN, and patch 2 fixes
another issue found by Simon Horman during review for v1 patch.

v1: https://lore.kernel.org/20250613055700.415596-1-kuni1840@gmail.com
====================

Link: https://patch.msgid.link/20250616182147.963333-1-kuni1840@gmail.com
Signed-off-by: Jakub Kicinski <kuba@kernel.org>
```

**Diff:**
```diff
diff --git a/drivers/atm/atmtcp.c b/drivers/atm/atmtcp.c
index d4aa0f353b6c..eeae160c898d 100644
--- a/drivers/atm/atmtcp.c
+++ b/drivers/atm/atmtcp.c
@@ -288,7 +288,9 @@ static int atmtcp_c_send(struct atm_vcc *vcc,struct sk_buff *skb)
 	struct sk_buff *new_skb;
 	int result = 0;
 
-	if (!skb->len) return 0;
+	if (skb->len < sizeof(struct atmtcp_hdr))
+		goto done;
+
 	dev = vcc->dev_data;
 	hdr = (struct atmtcp_hdr *) skb->data;
 	if (hdr->length == ATMTCP_HDR_MAGIC) {
diff --git a/include/linux/atmdev.h b/include/linux/atmdev.h
index 9b02961d65ee..45f2f278b50a 100644
--- a/include/linux/atmdev.h
+++ b/include/linux/atmdev.h
@@ -249,6 +249,12 @@ static inline void atm_account_tx(struct atm_vcc *vcc, struct sk_buff *skb)
 	ATM_SKB(skb)->atm_options = vcc->atm_options;
 }
 
+static inline void atm_return_tx(struct atm_vcc *vcc, struct sk_buff *skb)
+{
+	WARN_ON_ONCE(refcount_sub_and_test(ATM_SKB(skb)->acct_truesize,
+					   &sk_atm(vcc)->sk_wmem_alloc));
+}
+
 static inline void atm_force_charge(struct atm_vcc *vcc,int truesize)
 {
 	atomic_add(truesize, &sk_atm(vcc)->sk_rmem_alloc);
diff --git a/net/atm/common.c b/net/atm/common.c
index 9b75699992ff..d7f7976ea13a 100644
--- a/net/atm/common.c
+++ b/net/atm/common.c
@@ -635,6 +635,7 @@ int vcc_sendmsg(struct socket *sock, struct msghdr *m, size_t size)
 
 	skb->dev = NULL; /* for paths shared with net_device interfaces */
 	if (!copy_from_iter_full(skb_put(skb, size), size, &m->msg_iter)) {
+		atm_return_tx(vcc, skb);
 		kfree_skb(skb);
 		error = -EFAULT;
 		goto out;
diff --git a/net/atm/raw.c b/net/atm/raw.c
index 2b5f78a7ec3e..1e6511ec842c 100644
--- a/net/atm/raw.c
+++ b/net/atm/raw.c
@@ -36,7 +36,7 @@ static void atm_pop_raw(struct atm_vcc *vcc, struct sk_buff *skb)
 

... (truncated 7 lines)
```

---

## Commit 5: 88bd7711

**Author:** Kent Overstreet
**Date:** 2025-06-17 20:45:26
**Files Changed:** fs/bcachefs/recovery.c

**Message:**
```
bcachefs: fix spurious error in read_btree_roots()

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
```

**Diff:**
```diff
diff --git a/fs/bcachefs/recovery.c b/fs/bcachefs/recovery.c
index fa5d1ef5bea6..e0d824471bff 100644
--- a/fs/bcachefs/recovery.c
+++ b/fs/bcachefs/recovery.c
@@ -607,6 +607,7 @@ static int read_btree_roots(struct bch_fs *c)
 					buf.buf, bch2_err_str(ret))) {
 			if (btree_id_is_alloc(i))
 				r->error = 0;
+			ret = 0;
 		}
 	}
 
```

---

