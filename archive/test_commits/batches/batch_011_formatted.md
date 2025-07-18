# Linux Kernel Commit Batch Analysis

## Commit 1: 772b78c2

**Author:** Linus Torvalds
**Date:** 2025-07-06 11:17:47
**Files Changed:** kernel/sched/core.c, kernel/sched/deadline.c, kernel/stop_machine.c

**Message:**
```
Merge tag 'sched_urgent_for_v6.16_rc5' of git://git.kernel.org/pub/scm/linux/kernel/git/tip/tip

Pull scheduler fixes from Borislav Petkov:

 - Fix the calculation of the deadline server task's runtime as this
   mishap was preventing realtime tasks from running

 - Avoid a race condition during migrate-swapping two tasks

 - Fix the string reported for the "none" dynamic preemption option

* tag 'sched_urgent_for_v6.16_rc5' of git://git.kernel.org/pub/scm/linux/kernel/git/tip/tip:
  sched/deadline: Fix dl_server runtime calculation formula
  sched/core: Fix migrate_swap() vs. hotplug
  sched: Fix preemption string of preempt_dynamic_none
```

**Diff:**
```diff
diff --git a/kernel/sched/core.c b/kernel/sched/core.c
index 8988d38d46a3..ec68fc686bd7 100644
--- a/kernel/sched/core.c
+++ b/kernel/sched/core.c
@@ -3943,6 +3943,11 @@ static inline bool ttwu_queue_cond(struct task_struct *p, int cpu)
 	if (!scx_allow_ttwu_queue(p))
 		return false;
 
+#ifdef CONFIG_SMP
+	if (p->sched_class == &stop_sched_class)
+		return false;
+#endif
+
 	/*
 	 * Do not complicate things with the async wake_list while the CPU is
 	 * in hotplug state.
@@ -7663,7 +7668,7 @@ const char *preempt_model_str(void)
 
 		if (IS_ENABLED(CONFIG_PREEMPT_DYNAMIC)) {
 			seq_buf_printf(&s, "(%s)%s",
-				       preempt_dynamic_mode > 0 ?
+				       preempt_dynamic_mode >= 0 ?
 				       preempt_modes[preempt_dynamic_mode] : "undef",
 				       brace ? "}" : "");
 			return seq_buf_str(&s);
diff --git a/kernel/sched/deadline.c b/kernel/sched/deadline.c
index ad45a8fea245..89019a140826 100644
--- a/kernel/sched/deadline.c
+++ b/kernel/sched/deadline.c
@@ -1504,7 +1504,9 @@ static void update_curr_dl_se(struct rq *rq, struct sched_dl_entity *dl_se, s64
 	if (dl_entity_is_special(dl_se))
 		return;
 
-	scaled_delta_exec = dl_scaled_delta_exec(rq, dl_se, delta_exec);
+	scaled_delta_exec = delta_exec;
+	if (!dl_server(dl_se))
+		scaled_delta_exec = dl_scaled_delta_exec(rq, dl_se, delta_exec);
 
 	dl_se->runtime -= scaled_delta_exec;
 
@@ -1611,7 +1613,7 @@ static void update_curr_dl_se(struct rq *rq, struct sched_dl_entity *dl_se, s64
  */
 void dl_server_update_idle_time(struct rq *rq, struct task_struct *p)
 {
-	s64 delta_exec, scaled_delta_exec;
+	s64 delta_exec;
 
 	if (!rq->fair_server.dl_defer)
 		return;
@@ -1624,9 +1626,7 @@ void dl_server_update_idle_time(struct rq *rq, struct task_struct *p)

... (truncated 81 lines)
```

---

## Commit 2: a1639ce5

**Author:** Linus Torvalds
**Date:** 2025-07-06 10:49:27
**Files Changed:** kernel/events/core.c

**Message:**
```
Merge tag 'perf_urgent_for_v6.16_rc5' of git://git.kernel.org/pub/scm/linux/kernel/git/tip/tip

Pull perf fixes from Borislav Petkov:

 - Revert uprobes to using CAP_SYS_ADMIN again as currently they can
   destructively modify kernel code from an unprivileged process

 - Move a warning to where it belongs

* tag 'perf_urgent_for_v6.16_rc5' of git://git.kernel.org/pub/scm/linux/kernel/git/tip/tip:
  perf: Revert to requiring CAP_SYS_ADMIN for uprobes
  perf/core: Fix the WARN_ON_ONCE is out of lock protected region
```

**Diff:**
```diff
diff --git a/kernel/events/core.c b/kernel/events/core.c
index 7281230044d0..0db36b2b2448 100644
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -951,8 +951,6 @@ static void perf_cgroup_switch(struct task_struct *task)
 	if (READ_ONCE(cpuctx->cgrp) == NULL)
 		return;
 
-	WARN_ON_ONCE(cpuctx->ctx.nr_cgroups == 0);
-
 	cgrp = perf_cgroup_from_task(task, NULL);
 	if (READ_ONCE(cpuctx->cgrp) == cgrp)
 		return;
@@ -964,6 +962,8 @@ static void perf_cgroup_switch(struct task_struct *task)
 	if (READ_ONCE(cpuctx->cgrp) == NULL)
 		return;
 
+	WARN_ON_ONCE(cpuctx->ctx.nr_cgroups == 0);
+
 	perf_ctx_disable(&cpuctx->ctx, true);
 
 	ctx_sched_out(&cpuctx->ctx, NULL, EVENT_ALL|EVENT_CGROUP);
@@ -11116,7 +11116,7 @@ static int perf_uprobe_event_init(struct perf_event *event)
 	if (event->attr.type != perf_uprobe.type)
 		return -ENOENT;
 
-	if (!perfmon_capable())
+	if (!capable(CAP_SYS_ADMIN))
 		return -EACCES;
 
 	/*
```

---

## Commit 3: 1f988d07

**Author:** Linus Torvalds
**Date:** 2025-07-05 16:14:03
**Files Changed:** drivers/hid/hid-appletb-kbd.c, drivers/hid/hid-debug.c, drivers/hid/hid-elecom.c, drivers/hid/hid-ids.h, drivers/hid/hid-quirks.c

**Message:**
```
Merge tag 'hid-for-linus-2025070502' of git://git.kernel.org/pub/scm/linux/kernel/git/hid/hid

Pull HID fixes from Jiri Kosina:

 - Memory corruption fixes in hid-appletb-kbd driver (Qasim Ijaz)

 - New device ID in hid-elecom driver (Leonard Dizon)

 - Fixed several HID debugfs contants (Vicki Pfau)

* tag 'hid-for-linus-2025070502' of git://git.kernel.org/pub/scm/linux/kernel/git/hid/hid:
  HID: appletb-kbd: fix slab use-after-free bug in appletb_kbd_probe
  HID: Fix debug name for BTN_GEAR_DOWN, BTN_GEAR_UP, BTN_WHEEL
  HID: elecom: add support for ELECOM HUGE 019B variant
  HID: appletb-kbd: fix memory corruption of input_handler_list
```

**Diff:**
```diff
diff --git a/drivers/hid/hid-appletb-kbd.c b/drivers/hid/hid-appletb-kbd.c
index 2e0caf52af13..b00687e67ce8 100644
--- a/drivers/hid/hid-appletb-kbd.c
+++ b/drivers/hid/hid-appletb-kbd.c
@@ -430,16 +430,20 @@ static int appletb_kbd_probe(struct hid_device *hdev, const struct hid_device_id
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
-	if (kbd->backlight_dev)
+	if (kbd->backlight_dev) {
 		put_device(&kbd->backlight_dev->dev);
+		timer_delete_sync(&kbd->inactivity_timer);
+	}
 	hid_hw_close(hdev);
 stop_hw:
 	hid_hw_stop(hdev);
@@ -453,10 +457,10 @@ static void appletb_kbd_remove(struct hid_device *hdev)
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
diff --git a/drivers/hid/hid-debug.c b/drivers/hid/hid-debug.c
index 8433306148d5..c6b6b1029540 100644
--- a/drivers/hid/hid-debug.c
+++ b/drivers/hid/hid-debug.c
@@ -3298,8 +3298,8 @@ static const char *keys[KEY_MAX + 1] = {
 	[BTN_TOUCH] = "Touch",			[BTN_STYLUS] = "Stylus",
 	[BTN_STYLUS2] = "Stylus2",		[BTN_TOOL_DOUBLETAP] = "ToolDoubleTap",
 	[BTN_TOOL_TRIPLETAP] = "ToolTripleTap",	[BTN_TOOL_QUADTAP] = "ToolQuadrupleTap",
-	[BTN_GEAR_DOWN] = "WheelBtn",

... (truncated 58 lines)
```

---

## Commit 4: 05df9192

**Author:** Linus Torvalds
**Date:** 2025-07-05 13:05:28
**Files Changed:** fs/smb/client/cifsglob.h, fs/smb/client/cifsproto.h, fs/smb/client/connect.c, fs/smb/client/fs_context.c, fs/smb/client/misc.c (+3 more)

**Message:**
```
Merge tag 'v6.16-rc4-smb3-client-fixes' of git://git.samba.org/sfrench/cifs-2.6

Pull smb client fixes from Steve French:

 - Two reconnect fixes including one for a reboot/reconnect race

 - Fix for incorrect file type that can be returned by SMB3.1.1 POSIX
   extensions

 - tcon initialization fix

 - Fix for resolving Windows symlinks with absolute paths

* tag 'v6.16-rc4-smb3-client-fixes' of git://git.samba.org/sfrench/cifs-2.6:
  smb: client: fix native SMB symlink traversal
  smb: client: fix race condition in negotiate timeout by using more precise timing
  cifs: all initializations for tcon should happen in tcon_info_alloc
  smb: client: fix warning when reconnecting channel
  smb: client: fix readdir returning wrong type with POSIX extensions
```

**Diff:**
```diff
diff --git a/fs/smb/client/cifsglob.h b/fs/smb/client/cifsglob.h
index 318a8405d475..89160bc34d35 100644
--- a/fs/smb/client/cifsglob.h
+++ b/fs/smb/client/cifsglob.h
@@ -777,6 +777,7 @@ struct TCP_Server_Info {
 	__le32 session_key_id; /* retrieved from negotiate response and send in session setup request */
 	struct session_key session_key;
 	unsigned long lstrp; /* when we got last response from this server */
+	unsigned long neg_start; /* when negotiate started (jiffies) */
 	struct cifs_secmech secmech; /* crypto sec mech functs, descriptors */
 #define	CIFS_NEGFLAVOR_UNENCAP	1	/* wct == 17, but no ext_sec */
 #define	CIFS_NEGFLAVOR_EXTENDED	2	/* wct == 17, ext_sec bit set */
@@ -1303,6 +1304,7 @@ struct cifs_tcon {
 	bool use_persistent:1; /* use persistent instead of durable handles */
 	bool no_lease:1;    /* Do not request leases on files or directories */
 	bool use_witness:1; /* use witness protocol */
+	bool dummy:1; /* dummy tcon used for reconnecting channels */
 	__le32 capabilities;
 	__u32 share_flags;
 	__u32 maximal_access;
diff --git a/fs/smb/client/cifsproto.h b/fs/smb/client/cifsproto.h
index 66093fa78aed..045227ed4efc 100644
--- a/fs/smb/client/cifsproto.h
+++ b/fs/smb/client/cifsproto.h
@@ -136,6 +136,7 @@ extern int SendReceiveBlockingLock(const unsigned int xid,
 			struct smb_hdr *out_buf,
 			int *bytes_returned);
 
+void smb2_query_server_interfaces(struct work_struct *work);
 void
 cifs_signal_cifsd_for_reconnect(struct TCP_Server_Info *server,
 				      bool all_channels);
diff --git a/fs/smb/client/connect.c b/fs/smb/client/connect.c
index 685c65dcb8c4..205f547ca49e 100644
--- a/fs/smb/client/connect.c
+++ b/fs/smb/client/connect.c
@@ -97,7 +97,7 @@ static int reconn_set_ipaddr_from_hostname(struct TCP_Server_Info *server)
 	return rc;
 }
 
-static void smb2_query_server_interfaces(struct work_struct *work)
+void smb2_query_server_interfaces(struct work_struct *work)
 {
 	int rc;
 	int xid;
@@ -679,12 +679,12 @@ server_unresponsive(struct TCP_Server_Info *server)
 	/*
 	 * If we're in the process of mounting a share or reconnecting a session
 	 * and the server abruptly shut down (e.g. socket wasn't closed, packet
-	 * had been ACK'ed but no SMB response), don't wait longer than 20s to

... (truncated 219 lines)
```

---

## Commit 5: fd860cd7

**Author:** Linus Torvalds
**Date:** 2025-07-05 12:54:24
**Files Changed:** drivers/i2c/busses/i2c-designware-master.c, drivers/i2c/busses/i2c-microchip-corei2c.c

**Message:**
```
Merge tag 'i2c-for-6.16-rc5' of git://git.kernel.org/pub/scm/linux/kernel/git/wsa/linux

Pull i2c fixes from Wolfram Sang:

 - designware: initialise msg_write_idx during transfer

 - microchip: check return value from core xfer call

 - realtek: add 'reg' property constraint to the device tree

* tag 'i2c-for-6.16-rc5' of git://git.kernel.org/pub/scm/linux/kernel/git/wsa/linux:
  dt-bindings: i2c: realtek,rtl9301: Fix missing 'reg' constraint
  i2c: microchip-core: re-fix fake detections w/ i2cdetect
  i2c/designware: Fix an initialization issue
```

**Diff:**
```diff
diff --git a/Documentation/devicetree/bindings/i2c/realtek,rtl9301-i2c.yaml b/Documentation/devicetree/bindings/i2c/realtek,rtl9301-i2c.yaml
index eddfd329c67b..69ac5db8b914 100644
--- a/Documentation/devicetree/bindings/i2c/realtek,rtl9301-i2c.yaml
+++ b/Documentation/devicetree/bindings/i2c/realtek,rtl9301-i2c.yaml
@@ -26,7 +26,8 @@ properties:
       - const: realtek,rtl9301-i2c
 
   reg:
-    description: Register offset and size this I2C controller.
+    items:
+      - description: Register offset and size this I2C controller.
 
   "#address-cells":
     const: 1
diff --git a/drivers/i2c/busses/i2c-designware-master.c b/drivers/i2c/busses/i2c-designware-master.c
index 9d7d9e47564a..cbd88ffa5610 100644
--- a/drivers/i2c/busses/i2c-designware-master.c
+++ b/drivers/i2c/busses/i2c-designware-master.c
@@ -363,6 +363,7 @@ static int amd_i2c_dw_xfer_quirk(struct i2c_adapter *adap, struct i2c_msg *msgs,
 
 	dev->msgs = msgs;
 	dev->msgs_num = num_msgs;
+	dev->msg_write_idx = 0;
 	i2c_dw_xfer_init(dev);
 
 	/* Initiate messages read/write transaction */
diff --git a/drivers/i2c/busses/i2c-microchip-corei2c.c b/drivers/i2c/busses/i2c-microchip-corei2c.c
index f173bda1c98c..c8599733633e 100644
--- a/drivers/i2c/busses/i2c-microchip-corei2c.c
+++ b/drivers/i2c/busses/i2c-microchip-corei2c.c
@@ -435,6 +435,7 @@ static int mchp_corei2c_smbus_xfer(struct i2c_adapter *adap, u16 addr, unsigned
 	u8 tx_buf[I2C_SMBUS_BLOCK_MAX + 2];
 	u8 rx_buf[I2C_SMBUS_BLOCK_MAX + 1];
 	int num_msgs = 1;
+	int ret;
 
 	msgs[CORE_I2C_SMBUS_MSG_WR].addr = addr;
 	msgs[CORE_I2C_SMBUS_MSG_WR].flags = 0;
@@ -505,7 +506,10 @@ static int mchp_corei2c_smbus_xfer(struct i2c_adapter *adap, u16 addr, unsigned
 		return -EOPNOTSUPP;
 	}
 
-	mchp_corei2c_xfer(&idev->adapter, msgs, num_msgs);
+	ret = mchp_corei2c_xfer(&idev->adapter, msgs, num_msgs);
+	if (ret < 0)
+		return ret;
+
 	if (read_write == I2C_SMBUS_WRITE || size <= I2C_SMBUS_BYTE_DATA)
 		return 0;
 
```

---

