# Linux Kernel Commit Batch Analysis

## Commit 1: 266b5d02

**Author:** Wang Zhaolong
**Date:** 2025-07-03 18:41:49
**Files Changed:** fs/smb/client/cifsglob.h, fs/smb/client/connect.c

**Message:**
```
smb: client: fix race condition in negotiate timeout by using more precise timing

When the SMB server reboots and the client immediately accesses the mount
point, a race condition can occur that causes operations to fail with
"Host is down" error.

Reproduction steps:
  # Mount SMB share
  mount -t cifs //192.168.245.109/TEST /mnt/ -o xxxx
  ls /mnt

  # Reboot server
  ssh root@192.168.245.109 reboot
  ssh root@192.168.245.109 /path/to/cifs_server_setup.sh
  ssh root@192.168.245.109 systemctl stop firewalld

  # Immediate access fails
  ls /mnt
  ls: cannot access '/mnt': Host is down

  # But works if there is a delay

The issue is caused by a race condition between negotiate and reconnect.
The 20-second negotiate timeout mechanism can interfere with the normal
recovery process when both are triggered simultaneously.

  ls                              cifsd
---------------------------------------------------
 cifs_getattr
 cifs_revalidate_dentry
 cifs_get_inode_info
 cifs_get_fattr
 smb2_query_path_info
 smb2_compound_op
 SMB2_open_init
 smb2_reconnect
 cifs_negotiate_protocol
  smb2_negotiate
   cifs_send_recv
    smb_send_rqst
    wait_for_response
                            cifs_demultiplex_thread
                              cifs_read_from_socket
                              cifs_readv_from_socket
                                server_unresponsive
                                cifs_reconnect
                                  __cifs_reconnect
                                  cifs_abort_connection
                                    mid->mid_state = MID_RETRY_NEEDED
                                    cifs_wake_up_task
    cifs_sync_mid_result
     // case MID_RETRY_NEEDED
     rc = -EAGAIN;
   // In smb2_negotiate()
   rc = -EHOSTDOWN;

The server_unresponsive() timeout triggers cifs_reconnect(), which aborts
ongoing mid requests and causes the ls command to receive -EAGAIN, leading
to -EHOSTDOWN.

Fix this by introducing a dedicated `neg_start` field to
precisely tracks when the negotiate process begins. The timeout check
now uses this accurate timestamp instead of `lstrp`, ensuring that:

1. Timeout is only triggered after negotiate has actually run for 20s
2. The mechanism doesn't interfere with concurrent recovery processes
3. Uninitialized timestamps (value 0) don't trigger false timeouts

Fixes: 7ccc1465465d ("smb: client: fix hang in wait_for_response() for negproto")
Signed-off-by: Wang Zhaolong <wangzhaolong@huaweicloud.com>
Signed-off-by: Steve French <stfrench@microsoft.com>
```

**Diff:**
```diff
diff --git a/fs/smb/client/cifsglob.h b/fs/smb/client/cifsglob.h
index fdd95e5100cd..89160bc34d35 100644
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
diff --git a/fs/smb/client/connect.c b/fs/smb/client/connect.c
index 484b677143fd..205f547ca49e 100644
--- a/fs/smb/client/connect.c
+++ b/fs/smb/client/connect.c
@@ -679,12 +679,12 @@ server_unresponsive(struct TCP_Server_Info *server)
 	/*
 	 * If we're in the process of mounting a share or reconnecting a session
 	 * and the server abruptly shut down (e.g. socket wasn't closed, packet
-	 * had been ACK'ed but no SMB response), don't wait longer than 20s to
-	 * negotiate protocol.
+	 * had been ACK'ed but no SMB response), don't wait longer than 20s from
+	 * when negotiate actually started.
 	 */
 	spin_lock(&server->srv_lock);
 	if (server->tcpStatus == CifsInNegotiate &&
-	    time_after(jiffies, server->lstrp + 20 * HZ)) {
+	    time_after(jiffies, server->neg_start + 20 * HZ)) {
 		spin_unlock(&server->srv_lock);
 		cifs_reconnect(server, false);
 		return true;
@@ -4209,6 +4209,7 @@ cifs_negotiate_protocol(const unsigned int xid, struct cifs_ses *ses,
 
 	server->lstrp = jiffies;
 	server->tcpStatus = CifsInNegotiate;
+	server->neg_start = jiffies;
 	spin_unlock(&server->srv_lock);
 
 	rc = server->ops->negotiate(xid, ses, server);
```

---

## Commit 2: ac2ad73e

**Author:** Dave Airlie
**Date:** 2025-07-04 09:38:01
**Files Changed:** drivers/gpu/drm/exynos/exynos7_drm_decon.c, drivers/gpu/drm/exynos/exynos_drm_fimd.c, drivers/gpu/drm/exynos/exynos_drm_gem.c, drivers/gpu/drm/exynos/exynos_drm_ipp.c

**Message:**
```
Merge tag 'exynos-drm-fixes-for-v6.16-rc4' of git://git.kernel.org/pub/scm/linux/kernel/git/daeinki/drm-exynos into drm-fixes

Fixups
- Fixed raw pointer leakage and unsafe behavior in printk()
  . Switch from %pK to %p for pointer formatting, as %p is now safer
    and prevents issues like raw pointer leakage and acquiring sleeping
    locks in atomic contexts.

- Fixed kernel panic during boot
  . A NULL pointer dereference issue occasionally occurred
    when the vblank interrupt handler was called before
    the DRM driver was fully initialized during boot.
    So this patch fixes the issue by adding a check in the interrupt handler
    to ensure the DRM driver is properly initialized.

- Fixed a lockup issue on Samsung Peach-Pit/Pi Chromebooks
  . The issue occurred after commit c9b1150a68d9 changed
    the call order of CRTC enable/disable and bridge pre_enable/post_disable
    methods, causing fimd_dp_clock_enable() to be called
    before the FIMD device was activated. To fix this,
    runtime PM guards were added to fimd_dp_clock_enable()
    to ensure proper operation even when CRTC is not enabled.

Signed-off-by: Dave Airlie <airlied@redhat.com>

From: Inki Dae <inki.dae@samsung.com>
Link: https://lore.kernel.org/r/20250629083554.28628-1-inki.dae@samsung.com
```

**Diff:**
```diff
diff --git a/drivers/gpu/drm/exynos/exynos7_drm_decon.c b/drivers/gpu/drm/exynos/exynos7_drm_decon.c
index f91daefa9d2b..805aa28c1723 100644
--- a/drivers/gpu/drm/exynos/exynos7_drm_decon.c
+++ b/drivers/gpu/drm/exynos/exynos7_drm_decon.c
@@ -636,6 +636,10 @@ static irqreturn_t decon_irq_handler(int irq, void *dev_id)
 	if (!ctx->drm_dev)
 		goto out;
 
+	/* check if crtc and vblank have been initialized properly */
+	if (!drm_dev_has_vblank(ctx->drm_dev))
+		goto out;
+
 	if (!ctx->i80_if) {
 		drm_crtc_handle_vblank(&ctx->crtc->base);
 
diff --git a/drivers/gpu/drm/exynos/exynos_drm_fimd.c b/drivers/gpu/drm/exynos/exynos_drm_fimd.c
index c394cc702d7d..205c238cc73a 100644
--- a/drivers/gpu/drm/exynos/exynos_drm_fimd.c
+++ b/drivers/gpu/drm/exynos/exynos_drm_fimd.c
@@ -187,6 +187,7 @@ struct fimd_context {
 	u32				i80ifcon;
 	bool				i80_if;
 	bool				suspended;
+	bool				dp_clk_enabled;
 	wait_queue_head_t		wait_vsync_queue;
 	atomic_t			wait_vsync_event;
 	atomic_t			win_updated;
@@ -1047,7 +1048,18 @@ static void fimd_dp_clock_enable(struct exynos_drm_clk *clk, bool enable)
 	struct fimd_context *ctx = container_of(clk, struct fimd_context,
 						dp_clk);
 	u32 val = enable ? DP_MIE_CLK_DP_ENABLE : DP_MIE_CLK_DISABLE;
+
+	if (enable == ctx->dp_clk_enabled)
+		return;
+
+	if (enable)
+		pm_runtime_resume_and_get(ctx->dev);
+
+	ctx->dp_clk_enabled = enable;
 	writel(val, ctx->regs + DP_MIE_CLKCON);
+
+	if (!enable)
+		pm_runtime_put(ctx->dev);
 }
 
 static const struct exynos_drm_crtc_ops fimd_crtc_ops = {
diff --git a/drivers/gpu/drm/exynos/exynos_drm_gem.c b/drivers/gpu/drm/exynos/exynos_drm_gem.c
index 4787fee4696f..d44401a695e2 100644
--- a/drivers/gpu/drm/exynos/exynos_drm_gem.c
+++ b/drivers/gpu/drm/exynos/exynos_drm_gem.c

... (truncated 150 lines)
```

---

## Commit 3: afd30ace

**Author:** Dave Airlie
**Date:** 2025-07-04 09:26:57
**Files Changed:** drivers/gpu/drm/i915/display/vlv_dsi.c, drivers/gpu/drm/i915/gt/intel_gsc.c, drivers/gpu/drm/i915/gt/intel_ring_submission.c, drivers/gpu/drm/i915/selftests/i915_request.c, drivers/gpu/drm/i915/selftests/mock_request.c

**Message:**
```
Merge tag 'drm-intel-fixes-2025-07-03' of https://gitlab.freedesktop.org/drm/i915/kernel into drm-fixes

- Make mei interrupt top half irq disabled to fix RT builds
- Fix timeline left held on VMA alloc error
- Fix NULL pointer deref in vlv_dphy_param_init()
- Fix selftest mock_request() to avoid NULL deref

Signed-off-by: Dave Airlie <airlied@redhat.com>
From: Joonas Lahtinen <joonas.lahtinen@linux.intel.com>
Link: https://lore.kernel.org/r/aGYVPAA4KvsZqDFx@jlahtine-mobl
```

**Diff:**
```diff
diff --git a/drivers/gpu/drm/i915/display/vlv_dsi.c b/drivers/gpu/drm/i915/display/vlv_dsi.c
index 21c1e10caf68..2007bb9d974d 100644
--- a/drivers/gpu/drm/i915/display/vlv_dsi.c
+++ b/drivers/gpu/drm/i915/display/vlv_dsi.c
@@ -1589,8 +1589,8 @@ static void vlv_dsi_add_properties(struct intel_connector *connector)
 
 static void vlv_dphy_param_init(struct intel_dsi *intel_dsi)
 {
+	struct intel_display *display = to_intel_display(&intel_dsi->base);
 	struct intel_connector *connector = intel_dsi->attached_connector;
-	struct intel_display *display = to_intel_display(connector);
 	struct mipi_config *mipi_config = connector->panel.vbt.dsi.config;
 	u32 tlpx_ns, extra_byte_count, tlpx_ui;
 	u32 ui_num, ui_den;
diff --git a/drivers/gpu/drm/i915/gt/intel_gsc.c b/drivers/gpu/drm/i915/gt/intel_gsc.c
index 1e925c75fb08..c43febc862dc 100644
--- a/drivers/gpu/drm/i915/gt/intel_gsc.c
+++ b/drivers/gpu/drm/i915/gt/intel_gsc.c
@@ -284,7 +284,7 @@ static void gsc_irq_handler(struct intel_gt *gt, unsigned int intf_id)
 	if (gt->gsc.intf[intf_id].irq < 0)
 		return;
 
-	ret = generic_handle_irq(gt->gsc.intf[intf_id].irq);
+	ret = generic_handle_irq_safe(gt->gsc.intf[intf_id].irq);
 	if (ret)
 		gt_err_ratelimited(gt, "error handling GSC irq: %d\n", ret);
 }
diff --git a/drivers/gpu/drm/i915/gt/intel_ring_submission.c b/drivers/gpu/drm/i915/gt/intel_ring_submission.c
index a876a34455f1..2a6d79abf25b 100644
--- a/drivers/gpu/drm/i915/gt/intel_ring_submission.c
+++ b/drivers/gpu/drm/i915/gt/intel_ring_submission.c
@@ -610,7 +610,6 @@ static int ring_context_alloc(struct intel_context *ce)
 	/* One ringbuffer to rule them all */
 	GEM_BUG_ON(!engine->legacy.ring);
 	ce->ring = engine->legacy.ring;
-	ce->timeline = intel_timeline_get(engine->legacy.timeline);
 
 	GEM_BUG_ON(ce->state);
 	if (engine->context_size) {
@@ -623,6 +622,8 @@ static int ring_context_alloc(struct intel_context *ce)
 		ce->state = vma;
 	}
 
+	ce->timeline = intel_timeline_get(engine->legacy.timeline);
+
 	return 0;
 }
 
diff --git a/drivers/gpu/drm/i915/selftests/i915_request.c b/drivers/gpu/drm/i915/selftests/i915_request.c
index 88870844b5bd..2fb7a9e7efec 100644

... (truncated 70 lines)
```

---

## Commit 4: b91e11ec

**Author:** Dave Airlie
**Date:** 2025-07-04 09:06:57
**Files Changed:** drivers/dma-buf/dma-resv.c, drivers/gpu/drm/bridge/aux-hpd-bridge.c, drivers/gpu/drm/bridge/panel.c, drivers/gpu/drm/drm_gem.c, drivers/gpu/drm/drm_gem_framebuffer_helper.c (+11 more)

**Message:**
```
Merge tag 'drm-misc-fixes-2025-07-03' of https://gitlab.freedesktop.org/drm/misc/kernel into drm-fixes

drm-misc-fixes for v6.16-rc5:
- Replace simple panel lookup hack with proper fix.
- nullpointer deref in vesadrm fix.
- fix dma_resv_wait_timeout.
- fix error handling in ttm_buffer_object_transfer.
- bridge fixes.
- Fix vmwgfx accidentally allocating encrypted memory.
- Fix race in spsc_queue_push()
- Add refcount on backing GEM objects during fb creation.
- Fix v3d irq's being enabled during gpu reset.

Signed-off-by: Dave Airlie <airlied@redhat.com>
From: Maarten Lankhorst <maarten.lankhorst@linux.intel.com>
Link: https://lore.kernel.org/r/a7461418-08dc-4b7c-b2fa-264155f66d5e@linux.intel.com
```

**Diff:**
```diff
diff --git a/drivers/dma-buf/dma-resv.c b/drivers/dma-buf/dma-resv.c
index b1ef4546346d..bea3e9858aca 100644
--- a/drivers/dma-buf/dma-resv.c
+++ b/drivers/dma-buf/dma-resv.c
@@ -685,11 +685,13 @@ long dma_resv_wait_timeout(struct dma_resv *obj, enum dma_resv_usage usage,
 	dma_resv_iter_begin(&cursor, obj, usage);
 	dma_resv_for_each_fence_unlocked(&cursor, fence) {
 
-		ret = dma_fence_wait_timeout(fence, intr, ret);
-		if (ret <= 0) {
-			dma_resv_iter_end(&cursor);
-			return ret;
-		}
+		ret = dma_fence_wait_timeout(fence, intr, timeout);
+		if (ret <= 0)
+			break;
+
+		/* Even for zero timeout the return value is 1 */
+		if (timeout)
+			timeout = ret;
 	}
 	dma_resv_iter_end(&cursor);
 
diff --git a/drivers/gpu/drm/bridge/aux-hpd-bridge.c b/drivers/gpu/drm/bridge/aux-hpd-bridge.c
index b3f588b71a7d..af6f79793407 100644
--- a/drivers/gpu/drm/bridge/aux-hpd-bridge.c
+++ b/drivers/gpu/drm/bridge/aux-hpd-bridge.c
@@ -64,10 +64,11 @@ struct auxiliary_device *devm_drm_dp_hpd_bridge_alloc(struct device *parent, str
 	adev->id = ret;
 	adev->name = "dp_hpd_bridge";
 	adev->dev.parent = parent;
-	adev->dev.of_node = of_node_get(parent->of_node);
 	adev->dev.release = drm_aux_hpd_bridge_release;
 	adev->dev.platform_data = of_node_get(np);
 
+	device_set_of_node_from_dev(&adev->dev, parent);
+
 	ret = auxiliary_device_init(adev);
 	if (ret) {
 		of_node_put(adev->dev.platform_data);
diff --git a/drivers/gpu/drm/bridge/panel.c b/drivers/gpu/drm/bridge/panel.c
index 79b009ab9396..29b0358a7b6d 100644
--- a/drivers/gpu/drm/bridge/panel.c
+++ b/drivers/gpu/drm/bridge/panel.c
@@ -299,6 +299,7 @@ struct drm_bridge *drm_panel_bridge_add_typed(struct drm_panel *panel,
 	panel_bridge->bridge.of_node = panel->dev->of_node;
 	panel_bridge->bridge.ops = DRM_BRIDGE_OP_MODES;
 	panel_bridge->bridge.type = connector_type;
+	panel_bridge->bridge.pre_enable_prev_first = panel->prepare_prev_first;
 

... (truncated 662 lines)
```

---

## Commit 5: e79d0ba6

**Author:** Dave Airlie
**Date:** 2025-07-04 00:22:12
**Files Changed:** drivers/gpu/drm/nouveau/nvkm/subdev/gsp/rm/r535/gsp.c

**Message:**
```
nouveau/gsp: add a 50ms delay between fbsr and driver unload rpcs

This fixes a bunch of command hangs after runtime suspend/resume.

This fixes a regression caused by code movement in the commit below,
the commit seems to just change timings enough to cause this to happen
now, and adding the sleep seems to avoid it.

I've spent some time trying to root cause it to no great avail,
it seems like a bug on the firmware side, but it could be a bug
in our rpc handling that I can't find.

Either way, we should land the workaround to fix the problem,
while we continue to work out the root cause.

Signed-off-by: Dave Airlie <airlied@redhat.com>
Cc: Ben Skeggs <bskeggs@nvidia.com>
Cc: Danilo Krummrich <dakr@kernel.org>
Fixes: c21b039715ce ("drm/nouveau/gsp: add hals for fbsr.suspend/resume()")
Signed-off-by: Danilo Krummrich <dakr@kernel.org>
Link: https://lore.kernel.org/r/20250702232707.175679-1-airlied@gmail.com
```

**Diff:**
```diff
diff --git a/drivers/gpu/drm/nouveau/nvkm/subdev/gsp/rm/r535/gsp.c b/drivers/gpu/drm/nouveau/nvkm/subdev/gsp/rm/r535/gsp.c
index baf42339f93e..23f80e167705 100644
--- a/drivers/gpu/drm/nouveau/nvkm/subdev/gsp/rm/r535/gsp.c
+++ b/drivers/gpu/drm/nouveau/nvkm/subdev/gsp/rm/r535/gsp.c
@@ -1744,6 +1744,13 @@ r535_gsp_fini(struct nvkm_gsp *gsp, bool suspend)
 			nvkm_gsp_sg_free(gsp->subdev.device, &gsp->sr.sgt);
 			return ret;
 		}
+
+		/*
+		 * TODO: Debug the GSP firmware / RPC handling to find out why
+		 * without this Turing (but none of the other architectures)
+		 * ends up resetting all channels after resume.
+		 */
+		msleep(50);
 	}
 
 	ret = r535_gsp_rpc_unloading_guest_driver(gsp, suspend);
```

---

