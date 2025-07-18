# Linux Kernel Commit Batch Analysis

## Commit 1: 62dba282

**Author:** Kuniyuki Iwashima
**Date:** 2025-07-09 17:52:26
**Files Changed:** net/atm/clip.c

**Message:**
```
atm: clip: Fix memory leak of struct clip_vcc.

ioctl(ATMARP_MKIP) allocates struct clip_vcc and set it to
vcc->user_back.

The code assumes that vcc_destroy_socket() passes NULL skb
to vcc->push() when the socket is close()d, and then clip_push()
frees clip_vcc.

However, ioctl(ATMARPD_CTRL) sets NULL to vcc->push() in
atm_init_atmarp(), resulting in memory leak.

Let's serialise two ioctl() by lock_sock() and check vcc->push()
in atm_init_atmarp() to prevent memleak.

Fixes: 1da177e4c3f4 ("Linux-2.6.12-rc2")
Signed-off-by: Kuniyuki Iwashima <kuniyu@google.com>
Reviewed-by: Simon Horman <horms@kernel.org>
Link: https://patch.msgid.link/20250704062416.1613927-3-kuniyu@google.com
Signed-off-by: Jakub Kicinski <kuba@kernel.org>
```

**Diff:**
```diff
diff --git a/net/atm/clip.c b/net/atm/clip.c
index f36f2c7d8714..9c9c6c3d9886 100644
--- a/net/atm/clip.c
+++ b/net/atm/clip.c
@@ -645,6 +645,9 @@ static struct atm_dev atmarpd_dev = {
 
 static int atm_init_atmarp(struct atm_vcc *vcc)
 {
+	if (vcc->push == clip_push)
+		return -EINVAL;
+
 	mutex_lock(&atmarpd_lock);
 	if (atmarpd) {
 		mutex_unlock(&atmarpd_lock);
@@ -669,6 +672,7 @@ static int atm_init_atmarp(struct atm_vcc *vcc)
 static int clip_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
 {
 	struct atm_vcc *vcc = ATM_SD(sock);
+	struct sock *sk = sock->sk;
 	int err = 0;
 
 	switch (cmd) {
@@ -689,14 +693,18 @@ static int clip_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
 		err = clip_create(arg);
 		break;
 	case ATMARPD_CTRL:
+		lock_sock(sk);
 		err = atm_init_atmarp(vcc);
 		if (!err) {
 			sock->state = SS_CONNECTED;
 			__module_get(THIS_MODULE);
 		}
+		release_sock(sk);
 		break;
 	case ATMARP_MKIP:
+		lock_sock(sk);
 		err = clip_mkip(vcc, arg);
+		release_sock(sk);
 		break;
 	case ATMARP_SETENTRY:
 		err = clip_setentry(vcc, (__force __be32)arg);
```

---

## Commit 2: 4578a747

**Author:** Paolo Bonzini
**Date:** 2025-07-09 13:52:50
**Files Changed:** arch/x86/kvm/x86.c

**Message:**
```
KVM: x86: avoid underflow when scaling TSC frequency

In function kvm_guest_time_update(), __scale_tsc() is used to calculate
a TSC *frequency* rather than a TSC value.  With low-enough ratios,
a TSC value that is less than 1 would underflow to 0 and to an infinite
while loop in kvm_get_time_scale():

  kvm_guest_time_update(struct kvm_vcpu *v)
    if (kvm_caps.has_tsc_control)
      tgt_tsc_khz = kvm_scale_tsc(tgt_tsc_khz,
                                  v->arch.l1_tsc_scaling_ratio);
        __scale_tsc(u64 ratio, u64 tsc)
          ratio=122380531, tsc=2299998, N=48
          ratio*tsc >> N = 0.999... -> 0

Later in the function:

  Call Trace:
   <TASK>
   kvm_get_time_scale arch/x86/kvm/x86.c:2458 [inline]
   kvm_guest_time_update+0x926/0xb00 arch/x86/kvm/x86.c:3268
   vcpu_enter_guest.constprop.0+0x1e70/0x3cf0 arch/x86/kvm/x86.c:10678
   vcpu_run+0x129/0x8d0 arch/x86/kvm/x86.c:11126
   kvm_arch_vcpu_ioctl_run+0x37a/0x13d0 arch/x86/kvm/x86.c:11352
   kvm_vcpu_ioctl+0x56b/0xe60 virt/kvm/kvm_main.c:4188
   vfs_ioctl fs/ioctl.c:51 [inline]
   __do_sys_ioctl fs/ioctl.c:871 [inline]
   __se_sys_ioctl+0x12d/0x190 fs/ioctl.c:857
   do_syscall_x64 arch/x86/entry/common.c:51 [inline]
   do_syscall_64+0x59/0x110 arch/x86/entry/common.c:81
   entry_SYSCALL_64_after_hwframe+0x78/0xe2

This can really happen only when fuzzing, since the TSC frequency
would have to be nonsensically low.

Fixes: 35181e86df97 ("KVM: x86: Add a common TSC scaling function")
Reported-by: Yuntao Liu <liuyuntao12@huawei.com>
Suggested-by: Sean Christopherson <seanjc@google.com>
Signed-off-by: Paolo Bonzini <pbonzini@redhat.com>
```

**Diff:**
```diff
diff --git a/arch/x86/kvm/x86.c b/arch/x86/kvm/x86.c
index b58a74c1722d..de51dbd85a58 100644
--- a/arch/x86/kvm/x86.c
+++ b/arch/x86/kvm/x86.c
@@ -3258,9 +3258,11 @@ int kvm_guest_time_update(struct kvm_vcpu *v)
 
 	/* With all the info we got, fill in the values */
 
-	if (kvm_caps.has_tsc_control)
+	if (kvm_caps.has_tsc_control) {
 		tgt_tsc_khz = kvm_scale_tsc(tgt_tsc_khz,
 					    v->arch.l1_tsc_scaling_ratio);
+		tgt_tsc_khz = tgt_tsc_khz ? : 1;
+	}
 
 	if (unlikely(vcpu->hw_tsc_khz != tgt_tsc_khz)) {
 		kvm_get_time_scale(NSEC_PER_SEC, tgt_tsc_khz * 1000LL,
```

---

## Commit 3: 8c2e52eb

**Author:** Linus Torvalds
**Date:** 2025-07-09 10:38:29
**Files Changed:** fs/eventpoll.c

**Message:**
```
eventpoll: don't decrement ep refcount while still holding the ep mutex

Jann Horn points out that epoll is decrementing the ep refcount and then
doing a

    mutex_unlock(&ep->mtx);

afterwards. That's very wrong, because it can lead to a use-after-free.

That pattern is actually fine for the very last reference, because the
code in question will delay the actual call to "ep_free(ep)" until after
it has unlocked the mutex.

But it's wrong for the much subtler "next to last" case when somebody
*else* may also be dropping their reference and free the ep while we're
still using the mutex.

Note that this is true even if that other user is also using the same ep
mutex: mutexes, unlike spinlocks, can not be used for object ownership,
even if they guarantee mutual exclusion.

A mutex "unlock" operation is not atomic, and as one user is still
accessing the mutex as part of unlocking it, another user can come in
and get the now released mutex and free the data structure while the
first user is still cleaning up.

See our mutex documentation in Documentation/locking/mutex-design.rst,
in particular the section [1] about semantics:

	"mutex_unlock() may access the mutex structure even after it has
	 internally released the lock already - so it's not safe for
	 another context to acquire the mutex and assume that the
	 mutex_unlock() context is not using the structure anymore"

So if we drop our ep ref before the mutex unlock, but we weren't the
last one, we may then unlock the mutex, another user comes in, drops
_their_ reference and releases the 'ep' as it now has no users - all
while the mutex_unlock() is still accessing it.

Fix this by simply moving the ep refcount dropping to outside the mutex:
the refcount itself is atomic, and doesn't need mutex protection (that's
the whole _point_ of refcounts: unlike mutexes, they are inherently
about object lifetimes).

Reported-by: Jann Horn <jannh@google.com>
Link: https://docs.kernel.org/locking/mutex-design.html#semantics [1]
Cc: Alexander Viro <viro@zeniv.linux.org.uk>
Cc: Christian Brauner <brauner@kernel.org>
Cc: Jan Kara <jack@suse.cz>
Signed-off-by: Linus Torvalds <torvalds@linux-foundation.org>
```

**Diff:**
```diff
diff --git a/fs/eventpoll.c b/fs/eventpoll.c
index a97a771a459c..895256cd2786 100644
--- a/fs/eventpoll.c
+++ b/fs/eventpoll.c
@@ -828,7 +828,7 @@ static bool __ep_remove(struct eventpoll *ep, struct epitem *epi, bool force)
 	kfree_rcu(epi, rcu);
 
 	percpu_counter_dec(&ep->user->epoll_watches);
-	return ep_refcount_dec_and_test(ep);
+	return true;
 }
 
 /*
@@ -836,14 +836,14 @@ static bool __ep_remove(struct eventpoll *ep, struct epitem *epi, bool force)
  */
 static void ep_remove_safe(struct eventpoll *ep, struct epitem *epi)
 {
-	WARN_ON_ONCE(__ep_remove(ep, epi, false));
+	if (__ep_remove(ep, epi, false))
+		WARN_ON_ONCE(ep_refcount_dec_and_test(ep));
 }
 
 static void ep_clear_and_put(struct eventpoll *ep)
 {
 	struct rb_node *rbp, *next;
 	struct epitem *epi;
-	bool dispose;
 
 	/* We need to release all tasks waiting for these file */
 	if (waitqueue_active(&ep->poll_wait))
@@ -876,10 +876,8 @@ static void ep_clear_and_put(struct eventpoll *ep)
 		cond_resched();
 	}
 
-	dispose = ep_refcount_dec_and_test(ep);
 	mutex_unlock(&ep->mtx);
-
-	if (dispose)
+	if (ep_refcount_dec_and_test(ep))
 		ep_free(ep);
 }
 
@@ -1100,7 +1098,7 @@ void eventpoll_release_file(struct file *file)
 		dispose = __ep_remove(ep, epi, true);
 		mutex_unlock(&ep->mtx);
 
-		if (dispose)
+		if (dispose && ep_refcount_dec_and_test(ep))
 			ep_free(ep);
 		goto again;

... (truncated 1 lines)
```

---

## Commit 4: bd46cece

**Author:** Simona Vetter
**Date:** 2025-07-09 15:53:34
**Files Changed:** drivers/gpu/drm/drm_gem.c, include/drm/drm_file.h

**Message:**
```
drm/gem: Fix race in drm_gem_handle_create_tail()

Object creation is a careful dance where we must guarantee that the
object is fully constructed before it is visible to other threads, and
GEM buffer objects are no difference.

Final publishing happens by calling drm_gem_handle_create(). After
that the only allowed thing to do is call drm_gem_object_put() because
a concurrent call to the GEM_CLOSE ioctl with a correctly guessed id
(which is trivial since we have a linear allocator) can already tear
down the object again.

Luckily most drivers get this right, the very few exceptions I've
pinged the relevant maintainers for. Unfortunately we also need
drm_gem_handle_create() when creating additional handles for an
already existing object (e.g. GETFB ioctl or the various bo import
ioctl), and hence we cannot have a drm_gem_handle_create_and_put() as
the only exported function to stop these issues from happening.

Now unfortunately the implementation of drm_gem_handle_create() isn't
living up to standards: It does correctly finishe object
initialization at the global level, and hence is safe against a
concurrent tear down. But it also sets up the file-private aspects of
the handle, and that part goes wrong: We fully register the object in
the drm_file.object_idr before calling drm_vma_node_allow() or
obj->funcs->open, which opens up races against concurrent removal of
that handle in drm_gem_handle_delete().

Fix this with the usual two-stage approach of first reserving the
handle id, and then only registering the object after we've completed
the file-private setup.

Jacek reported this with a testcase of concurrently calling GEM_CLOSE
on a freshly-created object (which also destroys the object), but it
should be possible to hit this with just additional handles created
through import or GETFB without completed destroying the underlying
object with the concurrent GEM_CLOSE ioctl calls.

Note that the close-side of this race was fixed in f6cd7daecff5 ("drm:
Release driver references to handle before making it available
again"), which means a cool 9 years have passed until someone noticed
that we need to make this symmetry or there's still gaps left :-/
Without the 2-stage close approach we'd still have a race, therefore
that's an integral part of this bugfix.

More importantly, this means we can have NULL pointers behind
allocated id in our drm_file.object_idr. We need to check for that
now:

- drm_gem_handle_delete() checks for ERR_OR_NULL already

- drm_gem.c:object_lookup() also chekcs for NULL

- drm_gem_release() should never be called if there's another thread
  still existing that could call into an IOCTL that creates a new
  handle, so cannot race. For paranoia I added a NULL check to
  drm_gem_object_release_handle() though.

- most drivers (etnaviv, i915, msm) are find because they use
  idr_find(), which maps both ENOENT and NULL to NULL.

- drivers using idr_for_each_entry() should also be fine, because
  idr_get_next does filter out NULL entries and continues the
  iteration.

- The same holds for drm_show_memory_stats().

v2: Use drm_WARN_ON (Thomas)

Reported-by: Jacek Lawrynowicz <jacek.lawrynowicz@linux.intel.com>
Tested-by: Jacek Lawrynowicz <jacek.lawrynowicz@linux.intel.com>
Reviewed-by: Thomas Zimmermann <tzimmermann@suse.de>
Cc: stable@vger.kernel.org
Cc: Jacek Lawrynowicz <jacek.lawrynowicz@linux.intel.com>
Cc: Maarten Lankhorst <maarten.lankhorst@linux.intel.com>
Cc: Maxime Ripard <mripard@kernel.org>
Cc: Thomas Zimmermann <tzimmermann@suse.de>
Cc: David Airlie <airlied@gmail.com>
Cc: Simona Vetter <simona@ffwll.ch>
Signed-off-by: Simona Vetter <simona.vetter@intel.com>
Signed-off-by: Simona Vetter <simona.vetter@ffwll.ch>
Link: https://patchwork.freedesktop.org/patch/msgid/20250707151814.603897-1-simona.vetter@ffwll.ch
```

**Diff:**
```diff
diff --git a/drivers/gpu/drm/drm_gem.c b/drivers/gpu/drm/drm_gem.c
index aad6ac9748cc..ac0524595bd6 100644
--- a/drivers/gpu/drm/drm_gem.c
+++ b/drivers/gpu/drm/drm_gem.c
@@ -325,6 +325,9 @@ drm_gem_object_release_handle(int id, void *ptr, void *data)
 	struct drm_file *file_priv = data;
 	struct drm_gem_object *obj = ptr;
 
+	if (drm_WARN_ON(obj->dev, !data))
+		return 0;
+
 	if (obj->funcs->close)
 		obj->funcs->close(obj, file_priv);
 
@@ -445,7 +448,7 @@ drm_gem_handle_create_tail(struct drm_file *file_priv,
 	idr_preload(GFP_KERNEL);
 	spin_lock(&file_priv->table_lock);
 
-	ret = idr_alloc(&file_priv->object_idr, obj, 1, 0, GFP_NOWAIT);
+	ret = idr_alloc(&file_priv->object_idr, NULL, 1, 0, GFP_NOWAIT);
 
 	spin_unlock(&file_priv->table_lock);
 	idr_preload_end();
@@ -466,6 +469,11 @@ drm_gem_handle_create_tail(struct drm_file *file_priv,
 			goto err_revoke;
 	}
 
+	/* mirrors drm_gem_handle_delete to avoid races */
+	spin_lock(&file_priv->table_lock);
+	obj = idr_replace(&file_priv->object_idr, obj, handle);
+	WARN_ON(obj != NULL);
+	spin_unlock(&file_priv->table_lock);
 	*handlep = handle;
 	return 0;
 
diff --git a/include/drm/drm_file.h b/include/drm/drm_file.h
index 5c3b2aa3e69d..d344d41e6cfe 100644
--- a/include/drm/drm_file.h
+++ b/include/drm/drm_file.h
@@ -300,6 +300,9 @@ struct drm_file {
 	 *
 	 * Mapping of mm object handles to object pointers. Used by the GEM
 	 * subsystem. Protected by @table_lock.
+	 *
+	 * Note that allocated entries might be NULL as a transient state when
+	 * creating or deleting a handle.
 	 */
 	struct idr object_idr;
 
```

---

## Commit 5: 72782127

**Author:** Linus Torvalds
**Date:** 2025-07-08 13:10:32
**Files Changed:** kernel/module/main.c

**Message:**
```
Merge tag 'modules-6.16-rc6.fixes' of git://git.kernel.org/pub/scm/linux/kernel/git/modules/linux

Pull modules fixes from Daniel Gomez:
 "This includes two fixes: one introduced in the current release cycle
  and another introduced back in v6.4-rc1. Additionally, as Petr and
  Luis mentioned in previous pull requests, add myself (Daniel Gomez) to
  the list of modules maintainers.

  The first was reported by Intel's kernel test robot, and it addresses
  a crash exposed by Sebastian's commit c50d295c37f2 ("rds: Use
  nested-BH locking for rds_page_remainder") by allowing relocations for
  the per-CPU section even if it lacks the SHF_ALLOC flag.

  Petr and Sebastian went down to the archive history (before Git) and
  found the commit that broke it at [1] / [2] ("Don't relocate
  non-allocated regions in modules.").

  The second fix, reported and fixed by Petr (with additional cleanup),
  resolves a memory leak by ensuring proper deallocation if module
  loading fails.

  We couldn't find a reproducer other than forcing it manually or
  leveraging eBPF. So, I tested it by enabling error injection in the
  codetag functions through the error path that produces the leak and
  made it fail until execmem is unable to allocate more memory"

Link: https://git.kernel.org/pub/scm/linux/kernel/git/mpe/linux-fullhistory.git/commit/?id=b3b91325f3c7 [1]
Link: https://git.kernel.org/pub/scm/linux/kernel/git/tglx/history.git/commit/?id=1a6100caae [2]

* tag 'modules-6.16-rc6.fixes' of git://git.kernel.org/pub/scm/linux/kernel/git/modules/linux:
  MAINTAINERS: update Daniel Gomez's role and email address
  module: Make sure relocations are applied to the per-CPU section
  module: Avoid unnecessary return value initialization in move_module()
  module: Fix memory deallocation on error path in move_module()
```

**Diff:**
```diff
diff --git a/MAINTAINERS b/MAINTAINERS
index 2b8d9e608829..240793fbe64b 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -16824,8 +16824,8 @@ F:	include/dt-bindings/clock/mobileye,eyeq5-clk.h
 MODULE SUPPORT
 M:	Luis Chamberlain <mcgrof@kernel.org>
 M:	Petr Pavlu <petr.pavlu@suse.com>
+M:	Daniel Gomez <da.gomez@kernel.org>
 R:	Sami Tolvanen <samitolvanen@google.com>
-R:	Daniel Gomez <da.gomez@samsung.com>
 L:	linux-modules@vger.kernel.org
 L:	linux-kernel@vger.kernel.org
 S:	Maintained
diff --git a/kernel/module/main.c b/kernel/module/main.c
index 413ac6ea3702..c2c08007029d 100644
--- a/kernel/module/main.c
+++ b/kernel/module/main.c
@@ -1573,8 +1573,14 @@ static int apply_relocations(struct module *mod, const struct load_info *info)
 		if (infosec >= info->hdr->e_shnum)
 			continue;
 
-		/* Don't bother with non-allocated sections */
-		if (!(info->sechdrs[infosec].sh_flags & SHF_ALLOC))
+		/*
+		 * Don't bother with non-allocated sections.
+		 * An exception is the percpu section, which has separate allocations
+		 * for individual CPUs. We relocate the percpu section in the initial
+		 * ELF template and subsequently copy it to the per-CPU destinations.
+		 */
+		if (!(info->sechdrs[infosec].sh_flags & SHF_ALLOC) &&
+		    (!infosec || infosec != info->index.pcpu))
 			continue;
 
 		if (info->sechdrs[i].sh_flags & SHF_RELA_LIVEPATCH)
@@ -2696,9 +2702,8 @@ static int find_module_sections(struct module *mod, struct load_info *info)
 
 static int move_module(struct module *mod, struct load_info *info)
 {
-	int i;
-	enum mod_mem_type t = 0;
-	int ret = -ENOMEM;
+	int i, ret;
+	enum mod_mem_type t = MOD_MEM_NUM_TYPES;
 	bool codetag_section_found = false;
 
 	for_each_mod_mem_type(type) {
@@ -2776,7 +2781,7 @@ static int move_module(struct module *mod, struct load_info *info)
 	return 0;
 out_err:

... (truncated 6 lines)
```

---

