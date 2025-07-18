# Linux Kernel Commit Batch Analysis

## Commit 1: 9a5d769c

**Author:** Arnd Bergmann
**Date:** 2025-07-03 13:56:21
**Files Changed:** drivers/firmware/arm_ffa/driver.c, include/linux/arm_ffa.h

**Message:**
```
Merge tag 'ffa-fixes-6.16' of https://git.kernel.org/pub/scm/linux/kernel/git/sudeep.holla/linux into arm/fixes

Arm FF-A fixes for v6.16

Couple of fixes to address:

1. The safety and memory issues in the FF-A notification callback handler:

   The fixes replaces a mutex with an rwlock to prevent sleeping in atomic
   context, resolving kernel warnings. Memory allocation is moved outside
   the lock to support this transition safely. Additionally, a memory leak
   in the notifier unregistration path is fixed by properly freeing the
   callback node.

2. The missing entry in struct ffa_indirect_msg_hdr:

   The fix adds the missing 32 bit reserved entry in the structure as
   required by the FF-A specification.

* tag 'ffa-fixes-6.16' of https://git.kernel.org/pub/scm/linux/kernel/git/sudeep.holla/linux:
  firmware: arm_ffa: Fix the missing entry in struct ffa_indirect_msg_hdr
  firmware: arm_ffa: Replace mutex with rwlock to avoid sleep in atomic context
  firmware: arm_ffa: Move memory allocation outside the mutex locking
  firmware: arm_ffa: Fix memory leak by freeing notifier callback node

Link: https://lore.kernel.org/r/20250609105207.1185570-1-sudeep.holla@arm.com
Signed-off-by: Arnd Bergmann <arnd@arndb.de>
```

**Diff:**
```diff
diff --git a/drivers/firmware/arm_ffa/driver.c b/drivers/firmware/arm_ffa/driver.c
index fe55613a8ea9..37eb2e6c2f9f 100644
--- a/drivers/firmware/arm_ffa/driver.c
+++ b/drivers/firmware/arm_ffa/driver.c
@@ -110,7 +110,7 @@ struct ffa_drv_info {
 	struct work_struct sched_recv_irq_work;
 	struct xarray partition_info;
 	DECLARE_HASHTABLE(notifier_hash, ilog2(FFA_MAX_NOTIFICATIONS));
-	struct mutex notify_lock; /* lock to protect notifier hashtable  */
+	rwlock_t notify_lock; /* lock to protect notifier hashtable  */
 };
 
 static struct ffa_drv_info *drv_info;
@@ -1250,13 +1250,12 @@ notifier_hnode_get_by_type(u16 notify_id, enum notify_type type)
 	return NULL;
 }
 
-static int
-update_notifier_cb(struct ffa_device *dev, int notify_id, void *cb,
-		   void *cb_data, bool is_registration, bool is_framework)
+static int update_notifier_cb(struct ffa_device *dev, int notify_id,
+			      struct notifier_cb_info *cb, bool is_framework)
 {
 	struct notifier_cb_info *cb_info = NULL;
 	enum notify_type type = ffa_notify_type_get(dev->vm_id);
-	bool cb_found;
+	bool cb_found, is_registration = !!cb;
 
 	if (is_framework)
 		cb_info = notifier_hnode_get_by_vmid_uuid(notify_id, dev->vm_id,
@@ -1270,20 +1269,10 @@ update_notifier_cb(struct ffa_device *dev, int notify_id, void *cb,
 		return -EINVAL;
 
 	if (is_registration) {
-		cb_info = kzalloc(sizeof(*cb_info), GFP_KERNEL);
-		if (!cb_info)
-			return -ENOMEM;
-
-		cb_info->dev = dev;
-		cb_info->cb_data = cb_data;
-		if (is_framework)
-			cb_info->fwk_cb = cb;
-		else
-			cb_info->cb = cb;
-
-		hash_add(drv_info->notifier_hash, &cb_info->hnode, notify_id);
+		hash_add(drv_info->notifier_hash, &cb->hnode, notify_id);
 	} else {
 		hash_del(&cb_info->hnode);
+		kfree(cb_info);

... (truncated 130 lines)
```

---

## Commit 2: 45ebc7e6

**Author:** Laurent Vivier
**Date:** 2025-07-03 11:40:02
**Files Changed:** drivers/virtio/virtio_ring.c

**Message:**
```
virtio_ring: Fix error reporting in virtqueue_resize

The virtqueue_resize() function was not correctly propagating error codes
from its internal resize helper functions, specifically
virtqueue_resize_packet() and virtqueue_resize_split(). If these helpers
returned an error, but the subsequent call to virtqueue_enable_after_reset()
succeeded, the original error from the resize operation would be masked.
Consequently, virtqueue_resize() could incorrectly report success to its
caller despite an underlying resize failure.

This change restores the original code behavior:

       if (vdev->config->enable_vq_after_reset(_vq))
               return -EBUSY;

       return err;

Fix: commit ad48d53b5b3f ("virtio_ring: separate the logic of reset/enable from virtqueue_resize")
Cc: xuanzhuo@linux.alibaba.com
Signed-off-by: Laurent Vivier <lvivier@redhat.com>
Acked-by: Jason Wang <jasowang@redhat.com>
Link: https://patch.msgid.link/20250521092236.661410-2-lvivier@redhat.com
Tested-by: Lei Yang <leiyang@redhat.com>
Acked-by: Michael S. Tsirkin <mst@redhat.com>
Signed-off-by: Paolo Abeni <pabeni@redhat.com>
```

**Diff:**
```diff
diff --git a/drivers/virtio/virtio_ring.c b/drivers/virtio/virtio_ring.c
index b784aab66867..4397392bfef0 100644
--- a/drivers/virtio/virtio_ring.c
+++ b/drivers/virtio/virtio_ring.c
@@ -2797,7 +2797,7 @@ int virtqueue_resize(struct virtqueue *_vq, u32 num,
 		     void (*recycle_done)(struct virtqueue *vq))
 {
 	struct vring_virtqueue *vq = to_vvq(_vq);
-	int err;
+	int err, err_reset;
 
 	if (num > vq->vq.num_max)
 		return -E2BIG;
@@ -2819,7 +2819,11 @@ int virtqueue_resize(struct virtqueue *_vq, u32 num,
 	else
 		err = virtqueue_resize_split(_vq, num);
 
-	return virtqueue_enable_after_reset(_vq);
+	err_reset = virtqueue_enable_after_reset(_vq);
+	if (err_reset)
+		return err_reset;
+
+	return err;
 }
 EXPORT_SYMBOL_GPL(virtqueue_resize);
 
```

---

## Commit 3: 38224c47

**Author:** Qasim Ijaz
**Date:** 2025-07-03 11:34:49
**Files Changed:** drivers/hid/hid-appletb-kbd.c

**Message:**
```
HID: appletb-kbd: fix slab use-after-free bug in appletb_kbd_probe

In probe appletb_kbd_probe() a "struct appletb_kbd *kbd" is allocated
via devm_kzalloc() to store touch bar keyboard related data.
Later on if backlight_device_get_by_name() finds a backlight device
with name "appletb_backlight" a timer (kbd->inactivity_timer) is setup
with appletb_inactivity_timer() and the timer is armed to run after
appletb_tb_dim_timeout (60) seconds.

A use-after-free is triggered when failure occurs after the timer is
armed. This ultimately means probe failure occurs and as a result the
"struct appletb_kbd *kbd" which is device managed memory is freed.
After 60 seconds the timer will have expired and __run_timers will
attempt to access the timer (kbd->inactivity_timer) however the kdb
structure has been freed causing a use-after free.

[   71.636938] ==================================================================
[   71.637915] BUG: KASAN: slab-use-after-free in __run_timers+0x7ad/0x890
[   71.637915] Write of size 8 at addr ffff8881178c5958 by task swapper/1/0
[   71.637915]
[   71.637915] CPU: 1 UID: 0 PID: 0 Comm: swapper/1 Not tainted 6.16.0-rc2-00318-g739a6c93cc75-dirty #12 PREEMPT(voluntary)
[   71.637915] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.2-debian-1.16.2-1 04/01/2014
[   71.637915] Call Trace:
[   71.637915]  <IRQ>
[   71.637915]  dump_stack_lvl+0x53/0x70
[   71.637915]  print_report+0xce/0x670
[   71.637915]  ? __run_timers+0x7ad/0x890
[   71.637915]  kasan_report+0xce/0x100
[   71.637915]  ? __run_timers+0x7ad/0x890
[   71.637915]  __run_timers+0x7ad/0x890
[   71.637915]  ? __pfx___run_timers+0x10/0x10
[   71.637915]  ? update_process_times+0xfc/0x190
[   71.637915]  ? __pfx_update_process_times+0x10/0x10
[   71.637915]  ? _raw_spin_lock_irq+0x80/0xe0
[   71.637915]  ? _raw_spin_lock_irq+0x80/0xe0
[   71.637915]  ? __pfx__raw_spin_lock_irq+0x10/0x10
[   71.637915]  run_timer_softirq+0x141/0x240
[   71.637915]  ? __pfx_run_timer_softirq+0x10/0x10
[   71.637915]  ? __pfx___hrtimer_run_queues+0x10/0x10
[   71.637915]  ? kvm_clock_get_cycles+0x18/0x30
[   71.637915]  ? ktime_get+0x60/0x140
[   71.637915]  handle_softirqs+0x1b8/0x5c0
[   71.637915]  ? __pfx_handle_softirqs+0x10/0x10
[   71.637915]  irq_exit_rcu+0xaf/0xe0
[   71.637915]  sysvec_apic_timer_interrupt+0x6c/0x80
[   71.637915]  </IRQ>
[   71.637915]
[   71.637915] Allocated by task 39:
[   71.637915]  kasan_save_stack+0x33/0x60
[   71.637915]  kasan_save_track+0x14/0x30
[   71.637915]  __kasan_kmalloc+0x8f/0xa0
[   71.637915]  __kmalloc_node_track_caller_noprof+0x195/0x420
[   71.637915]  devm_kmalloc+0x74/0x1e0
[   71.637915]  appletb_kbd_probe+0x37/0x3c0
[   71.637915]  hid_device_probe+0x2d1/0x680
[   71.637915]  really_probe+0x1c3/0x690
[   71.637915]  __driver_probe_device+0x247/0x300
[   71.637915]  driver_probe_device+0x49/0x210
[...]
[   71.637915]
[   71.637915] Freed by task 39:
[   71.637915]  kasan_save_stack+0x33/0x60
[   71.637915]  kasan_save_track+0x14/0x30
[   71.637915]  kasan_save_free_info+0x3b/0x60
[   71.637915]  __kasan_slab_free+0x37/0x50
[   71.637915]  kfree+0xcf/0x360
[   71.637915]  devres_release_group+0x1f8/0x3c0
[   71.637915]  hid_device_probe+0x315/0x680
[   71.637915]  really_probe+0x1c3/0x690
[   71.637915]  __driver_probe_device+0x247/0x300
[   71.637915]  driver_probe_device+0x49/0x210
[...]

The root cause of the issue is that the timer is not disarmed
on failure paths leading to it remaining active and accessing
freed memory. To fix this call timer_delete_sync() to deactivate
the timer.

Another small issue is that timer_delete_sync is called
unconditionally in appletb_kbd_remove(), fix this by checking
for a valid kbd->backlight_dev before calling timer_delete_sync.

Fixes: 93a0fc489481 ("HID: hid-appletb-kbd: add support for automatic brightness control while using the touchbar")
Cc: stable@vger.kernel.org
Signed-off-by: Qasim Ijaz <qasdev00@gmail.com>
Reviewed-by: Aditya Garg <gargaditya08@live.com>
Signed-off-by: Jiri Kosina <jkosina@suse.com>
```

**Diff:**
```diff
diff --git a/drivers/hid/hid-appletb-kbd.c b/drivers/hid/hid-appletb-kbd.c
index b5d9e50bc231..271d1b27b8dd 100644
--- a/drivers/hid/hid-appletb-kbd.c
+++ b/drivers/hid/hid-appletb-kbd.c
@@ -440,8 +440,10 @@ static int appletb_kbd_probe(struct hid_device *hdev, const struct hid_device_id
 unregister_handler:
 	input_unregister_handler(&kbd->inp_handler);
 close_hw:
-	if (kbd->backlight_dev)
+	if (kbd->backlight_dev) {
 		put_device(&kbd->backlight_dev->dev);
+		timer_delete_sync(&kbd->inactivity_timer);
+	}
 	hid_hw_close(hdev);
 stop_hw:
 	hid_hw_stop(hdev);
@@ -455,10 +457,10 @@ static void appletb_kbd_remove(struct hid_device *hdev)
 	appletb_kbd_set_mode(kbd, APPLETB_KBD_MODE_OFF);
 
 	input_unregister_handler(&kbd->inp_handler);
-	timer_delete_sync(&kbd->inactivity_timer);
-
-	if (kbd->backlight_dev)
+	if (kbd->backlight_dev) {
 		put_device(&kbd->backlight_dev->dev);
+		timer_delete_sync(&kbd->inactivity_timer);
+	}
 
 	hid_hw_close(hdev);
 	hid_hw_stop(hdev);
```

---

## Commit 4: ba677dbe

**Author:** Peter Zijlstra
**Date:** 2025-07-03 10:33:55
**Files Changed:** kernel/events/core.c

**Message:**
```
perf: Revert to requiring CAP_SYS_ADMIN for uprobes

Jann reports that uprobes can be used destructively when used in the
middle of an instruction. The kernel only verifies there is a valid
instruction at the requested offset, but due to variable instruction
length cannot determine if this is an instruction as seen by the
intended execution stream.

Additionally, Mark Rutland notes that on architectures that mix data
in the text segment (like arm64), a similar things can be done if the
data word is 'mistaken' for an instruction.

As such, require CAP_SYS_ADMIN for uprobes.

Fixes: c9e0924e5c2b ("perf/core: open access to probes for CAP_PERFMON privileged process")
Reported-by: Jann Horn <jannh@google.com>
Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Link: https://lkml.kernel.org/r/CAG48ez1n4520sq0XrWYDHKiKxE_+WCfAK+qt9qkY4ZiBGmL-5g@mail.gmail.com
```

**Diff:**
```diff
diff --git a/kernel/events/core.c b/kernel/events/core.c
index bf2118c22126..0db36b2b2448 100644
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -11116,7 +11116,7 @@ static int perf_uprobe_event_init(struct perf_event *event)
 	if (event->attr.type != perf_uprobe.type)
 		return -ENOENT;
 
-	if (!perfmon_capable())
+	if (!capable(CAP_SYS_ADMIN))
 		return -EACCES;
 
 	/*
```

---

## Commit 5: c80f2b04

**Author:** Qasim Ijaz
**Date:** 2025-07-03 09:38:05
**Files Changed:** drivers/hid/hid-appletb-kbd.c

**Message:**
```
HID: appletb-kbd: fix memory corruption of input_handler_list

In appletb_kbd_probe an input handler is initialised and then registered
with input core through input_register_handler(). When this happens input
core will add the input handler (specifically its node) to the global
input_handler_list. The input_handler_list is central to the functionality
of input core and is traversed in various places in input core. An example
of this is when a new input device is plugged in and gets registered with
input core.

The input_handler in probe is allocated as device managed memory. If a
probe failure occurs after input_register_handler() the input_handler
memory is freed, yet it will remain in the input_handler_list. This
effectively means the input_handler_list contains a dangling pointer
to data belonging to a freed input handler.

This causes an issue when any other input device is plugged in - in my
case I had an old PixArt HP USB optical mouse and I decided to
plug it in after a failure occurred after input_register_handler().
This lead to the registration of this input device via
input_register_device which involves traversing over every handler
in the corrupted input_handler_list and calling input_attach_handler(),
giving each handler a chance to bind to newly registered device.

The core of this bug is a UAF which causes memory corruption of
input_handler_list and to fix it we must ensure the input handler is
unregistered from input core, this is done through
input_unregister_handler().

[   63.191597] ==================================================================
[   63.192094] BUG: KASAN: slab-use-after-free in input_attach_handler.isra.0+0x1a9/0x1e0
[   63.192094] Read of size 8 at addr ffff888105ea7c80 by task kworker/0:2/54
[   63.192094]
[   63.192094] CPU: 0 UID: 0 PID: 54 Comm: kworker/0:2 Not tainted 6.16.0-rc2-00321-g2aa6621d
[   63.192094] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.2-debian-1.164
[   63.192094] Workqueue: usb_hub_wq hub_event
[   63.192094] Call Trace:
[   63.192094]  <TASK>
[   63.192094]  dump_stack_lvl+0x53/0x70
[   63.192094]  print_report+0xce/0x670
[   63.192094]  kasan_report+0xce/0x100
[   63.192094]  input_attach_handler.isra.0+0x1a9/0x1e0
[   63.192094]  input_register_device+0x76c/0xd00
[   63.192094]  hidinput_connect+0x686d/0xad60
[   63.192094]  hid_connect+0xf20/0x1b10
[   63.192094]  hid_hw_start+0x83/0x100
[   63.192094]  hid_device_probe+0x2d1/0x680
[   63.192094]  really_probe+0x1c3/0x690
[   63.192094]  __driver_probe_device+0x247/0x300
[   63.192094]  driver_probe_device+0x49/0x210
[   63.192094]  __device_attach_driver+0x160/0x320
[   63.192094]  bus_for_each_drv+0x10f/0x190
[   63.192094]  __device_attach+0x18e/0x370
[   63.192094]  bus_probe_device+0x123/0x170
[   63.192094]  device_add+0xd4d/0x1460
[   63.192094]  hid_add_device+0x30b/0x910
[   63.192094]  usbhid_probe+0x920/0xe00
[   63.192094]  usb_probe_interface+0x363/0x9a0
[   63.192094]  really_probe+0x1c3/0x690
[   63.192094]  __driver_probe_device+0x247/0x300
[   63.192094]  driver_probe_device+0x49/0x210
[   63.192094]  __device_attach_driver+0x160/0x320
[   63.192094]  bus_for_each_drv+0x10f/0x190
[   63.192094]  __device_attach+0x18e/0x370
[   63.192094]  bus_probe_device+0x123/0x170
[   63.192094]  device_add+0xd4d/0x1460
[   63.192094]  usb_set_configuration+0xd14/0x1880
[   63.192094]  usb_generic_driver_probe+0x78/0xb0
[   63.192094]  usb_probe_device+0xaa/0x2e0
[   63.192094]  really_probe+0x1c3/0x690
[   63.192094]  __driver_probe_device+0x247/0x300
[   63.192094]  driver_probe_device+0x49/0x210
[   63.192094]  __device_attach_driver+0x160/0x320
[   63.192094]  bus_for_each_drv+0x10f/0x190
[   63.192094]  __device_attach+0x18e/0x370
[   63.192094]  bus_probe_device+0x123/0x170
[   63.192094]  device_add+0xd4d/0x1460
[   63.192094]  usb_new_device+0x7b4/0x1000
[   63.192094]  hub_event+0x234d/0x3fa0
[   63.192094]  process_one_work+0x5bf/0xfe0
[   63.192094]  worker_thread+0x777/0x13a0
[   63.192094]  </TASK>
[   63.192094]
[   63.192094] Allocated by task 54:
[   63.192094]  kasan_save_stack+0x33/0x60
[   63.192094]  kasan_save_track+0x14/0x30
[   63.192094]  __kasan_kmalloc+0x8f/0xa0
[   63.192094]  __kmalloc_node_track_caller_noprof+0x195/0x420
[   63.192094]  devm_kmalloc+0x74/0x1e0
[   63.192094]  appletb_kbd_probe+0x39/0x440
[   63.192094]  hid_device_probe+0x2d1/0x680
[   63.192094]  really_probe+0x1c3/0x690
[   63.192094]  __driver_probe_device+0x247/0x300
[   63.192094]  driver_probe_device+0x49/0x210
[   63.192094]  __device_attach_driver+0x160/0x320
[...]
[   63.192094]
[   63.192094] Freed by task 54:
[   63.192094]  kasan_save_stack+0x33/0x60
[   63.192094]  kasan_save_track+0x14/0x30
[   63.192094]  kasan_save_free_info+0x3b/0x60
[   63.192094]  __kasan_slab_free+0x37/0x50
[   63.192094]  kfree+0xcf/0x360
[   63.192094]  devres_release_group+0x1f8/0x3c0
[   63.192094]  hid_device_probe+0x315/0x680
[   63.192094]  really_probe+0x1c3/0x690
[   63.192094]  __driver_probe_device+0x247/0x300
[   63.192094]  driver_probe_device+0x49/0x210
[   63.192094]  __device_attach_driver+0x160/0x320
[...]

Fixes: 7d62ba8deacf ("HID: hid-appletb-kbd: add support for fn toggle between media and function mode")
Cc: stable@vger.kernel.org
Reviewed-by: Aditya Garg <gargaditya08@live.com>
Signed-off-by: Qasim Ijaz <qasdev00@gmail.com>
Signed-off-by: Jiri Kosina <jkosina@suse.com>
```

**Diff:**
```diff
diff --git a/drivers/hid/hid-appletb-kbd.c b/drivers/hid/hid-appletb-kbd.c
index e06567886e50..b5d9e50bc231 100644
--- a/drivers/hid/hid-appletb-kbd.c
+++ b/drivers/hid/hid-appletb-kbd.c
@@ -430,13 +430,15 @@ static int appletb_kbd_probe(struct hid_device *hdev, const struct hid_device_id
 	ret = appletb_kbd_set_mode(kbd, appletb_tb_def_mode);
 	if (ret) {
 		dev_err_probe(dev, ret, "Failed to set touchbar mode\n");
-		goto close_hw;
+		goto unregister_handler;
 	}
 
 	hid_set_drvdata(hdev, kbd);
 
 	return 0;
 
+unregister_handler:
+	input_unregister_handler(&kbd->inp_handler);
 close_hw:
 	if (kbd->backlight_dev)
 		put_device(&kbd->backlight_dev->dev);
```

---

