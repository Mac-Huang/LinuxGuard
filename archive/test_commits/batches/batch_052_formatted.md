# Linux Kernel Commit Batch Analysis

## Commit 1: 37fb58a7

**Author:** Chen Ridong
**Date:** 2025-06-18 09:43:30
**Files Changed:** kernel/cgroup/legacy_freezer.c

**Message:**
```
cgroup,freezer: fix incomplete freezing when attaching tasks

An issue was found:

	# cd /sys/fs/cgroup/freezer/
	# mkdir test
	# echo FROZEN > test/freezer.state
	# cat test/freezer.state
	FROZEN
	# sleep 1000 &
	[1] 863
	# echo 863 > test/cgroup.procs
	# cat test/freezer.state
	FREEZING

When tasks are migrated to a frozen cgroup, the freezer fails to
immediately freeze the tasks, causing the cgroup to remain in the
"FREEZING".

The freeze_task() function is called before clearing the CGROUP_FROZEN
flag. This causes the freezing() check to incorrectly return false,
preventing __freeze_task() from being invoked for the migrated task.

To fix this issue, clear the CGROUP_FROZEN state before calling
freeze_task().

Fixes: f5d39b020809 ("freezer,sched: Rewrite core freezer logic")
Cc: stable@vger.kernel.org # v6.1+
Reported-by: Zhong Jiawei <zhongjiawei1@huawei.com>
Signed-off-by: Chen Ridong <chenridong@huawei.com>
Acked-by: Michal Koutný <mkoutny@suse.com>
Signed-off-by: Tejun Heo <tj@kernel.org>
```

**Diff:**
```diff
diff --git a/kernel/cgroup/legacy_freezer.c b/kernel/cgroup/legacy_freezer.c
index 039d1eb2f215..507b8f19a262 100644
--- a/kernel/cgroup/legacy_freezer.c
+++ b/kernel/cgroup/legacy_freezer.c
@@ -188,13 +188,12 @@ static void freezer_attach(struct cgroup_taskset *tset)
 		if (!(freezer->state & CGROUP_FREEZING)) {
 			__thaw_task(task);
 		} else {
-			freeze_task(task);
-
 			/* clear FROZEN and propagate upwards */
 			while (freezer && (freezer->state & CGROUP_FROZEN)) {
 				freezer->state &= ~CGROUP_FROZEN;
 				freezer = parent_freezer(freezer);
 			}
+			freeze_task(task);
 		}
 	}
 
```

---

## Commit 2: 6fcab279

**Author:** Rafael J. Wysocki
**Date:** 2025-06-18 21:12:13
**Files Changed:** drivers/acpi/acpica/dsmethod.c

**Message:**
```
ACPICA: Refuse to evaluate a method if arguments are missing

As reported in [1], a platform firmware update that increased the number
of method parameters and forgot to update a least one of its callers,
caused ACPICA to crash due to use-after-free.

Since this a result of a clear AML issue that arguably cannot be fixed
up by the interpreter (it cannot produce missing data out of thin air),
address it by making ACPICA refuse to evaluate a method if the caller
attempts to pass fewer arguments than expected to it.

Closes: https://github.com/acpica/acpica/issues/1027 [1]
Reported-by: Peter Williams <peter@newton.cx>
Signed-off-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
Reviewed-by: Hans de Goede <hansg@kernel.org>
Tested-by: Hans de Goede <hansg@kernel.org> # Dell XPS 9640 with BIOS 1.12.0
Link: https://patch.msgid.link/5909446.DvuYhMxLoT@rjwysocki.net
Signed-off-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
```

**Diff:**
```diff
diff --git a/drivers/acpi/acpica/dsmethod.c b/drivers/acpi/acpica/dsmethod.c
index c8f37f4e6626..fef6fb29ece4 100644
--- a/drivers/acpi/acpica/dsmethod.c
+++ b/drivers/acpi/acpica/dsmethod.c
@@ -483,6 +483,13 @@ acpi_ds_call_control_method(struct acpi_thread_state *thread,
 		return_ACPI_STATUS(AE_NULL_OBJECT);
 	}
 
+	if (this_walk_state->num_operands < obj_desc->method.param_count) {
+		ACPI_ERROR((AE_INFO, "Missing argument for method [%4.4s]",
+			    acpi_ut_get_node_name(method_node)));
+
+		return_ACPI_STATUS(AE_AML_UNINITIALIZED_ARG);
+	}
+
 	/* Init for new method, possibly wait on method mutex */
 
 	status =
```

---

## Commit 3: 306cb65b

**Author:** Bharath SM
**Date:** 2025-06-18 13:27:45
**Files Changed:** fs/smb/client/sess.c

**Message:**
```
smb: fix secondary channel creation issue with kerberos by populating hostname when adding channels

When mounting a share with kerberos authentication with multichannel
support, share mounts correctly, but fails to create secondary
channels. This occurs because the hostname is not populated when
adding the channels. The hostname is necessary for the userspace
cifs.upcall program to retrieve the required credentials and pass
it back to kernel, without hostname secondary channels fails
establish.

Cc: stable@vger.kernel.org
Reviewed-by: Shyam Prasad N <sprasad@microsoft.com>
Signed-off-by: Bharath SM <bharathsm@microsoft.com>
Reported-by: xfuren <xfuren@gmail.com>
Link: https://bugzilla.samba.org/show_bug.cgi?id=15824
Signed-off-by: Steve French <stfrench@microsoft.com>
```

**Diff:**
```diff
diff --git a/fs/smb/client/sess.c b/fs/smb/client/sess.c
index ec0db32c7d98..330bc3d25bad 100644
--- a/fs/smb/client/sess.c
+++ b/fs/smb/client/sess.c
@@ -498,8 +498,7 @@ cifs_ses_add_channel(struct cifs_ses *ses,
 	ctx->domainauto = ses->domainAuto;
 	ctx->domainname = ses->domainName;
 
-	/* no hostname for extra channels */
-	ctx->server_hostname = "";
+	ctx->server_hostname = ses->server->hostname;
 
 	ctx->username = ses->user_name;
 	ctx->password = ses->password;
```

---

## Commit 4: 88efa0de

**Author:** Qiuxu Zhuo
**Date:** 2025-06-18 20:19:45
**Files Changed:** drivers/edac/igen6_edac.c

**Message:**
```
EDAC/igen6: Fix NULL pointer dereference

A kernel panic was reported with the following kernel log:

  EDAC igen6: Expected 2 mcs, but only 1 detected.
  BUG: unable to handle page fault for address: 000000000000d570
  ...
  Hardware name: Notebook V54x_6x_TU/V54x_6x_TU, BIOS Dasharo (coreboot+UEFI) v0.9.0 07/17/2024
  RIP: e030:ecclog_handler+0x7e/0xf0 [igen6_edac]
  ...
  igen6_probe+0x2a0/0x343 [igen6_edac]
  ...
  igen6_init+0xc5/0xff0 [igen6_edac]
  ...

This issue occurred because one memory controller was disabled by
the BIOS but the igen6_edac driver still checked all the memory
controllers, including this absent one, to identify the source of
the error. Accessing the null MMIO for the absent memory controller
resulted in the oops above.

Fix this issue by reverting the configuration structure to non-const
and updating the field 'res_cfg->num_imc' to reflect the number of
detected memory controllers.

Fixes: 20e190b1c1fd ("EDAC/igen6: Skip absent memory controllers")
Reported-by: Marek Marczykowski-Górecki <marmarek@invisiblethingslab.com>
Closes: https://lore.kernel.org/all/aFFN7RlXkaK_loQb@mail-itl/
Suggested-by: Borislav Petkov <bp@alien8.de>
Signed-off-by: Qiuxu Zhuo <qiuxu.zhuo@intel.com>
Signed-off-by: Tony Luck <tony.luck@intel.com>
Signed-off-by: Borislav Petkov (AMD) <bp@alien8.de>
Tested-by: Marek Marczykowski-Górecki <marmarek@invisiblethingslab.com>
Link: https://lore.kernel.org/r/20250618162307.1523736-1-qiuxu.zhuo@intel.com
```

**Diff:**
```diff
diff --git a/drivers/edac/igen6_edac.c b/drivers/edac/igen6_edac.c
index 1930dc00c791..1cb5c67e78ae 100644
--- a/drivers/edac/igen6_edac.c
+++ b/drivers/edac/igen6_edac.c
@@ -125,7 +125,7 @@
 #define MEM_SLICE_HASH_MASK(v)		(GET_BITFIELD(v, 6, 19) << 6)
 #define MEM_SLICE_HASH_LSB_MASK_BIT(v)	GET_BITFIELD(v, 24, 26)
 
-static const struct res_config {
+static struct res_config {
 	bool machine_check;
 	/* The number of present memory controllers. */
 	int num_imc;
@@ -479,7 +479,7 @@ static u64 rpl_p_err_addr(u64 ecclog)
 	return ECC_ERROR_LOG_ADDR45(ecclog);
 }
 
-static const struct res_config ehl_cfg = {
+static struct res_config ehl_cfg = {
 	.num_imc		= 1,
 	.imc_base		= 0x5000,
 	.ibecc_base		= 0xdc00,
@@ -489,7 +489,7 @@ static const struct res_config ehl_cfg = {
 	.err_addr_to_imc_addr	= ehl_err_addr_to_imc_addr,
 };
 
-static const struct res_config icl_cfg = {
+static struct res_config icl_cfg = {
 	.num_imc		= 1,
 	.imc_base		= 0x5000,
 	.ibecc_base		= 0xd800,
@@ -499,7 +499,7 @@ static const struct res_config icl_cfg = {
 	.err_addr_to_imc_addr	= ehl_err_addr_to_imc_addr,
 };
 
-static const struct res_config tgl_cfg = {
+static struct res_config tgl_cfg = {
 	.machine_check		= true,
 	.num_imc		= 2,
 	.imc_base		= 0x5000,
@@ -513,7 +513,7 @@ static const struct res_config tgl_cfg = {
 	.err_addr_to_imc_addr	= tgl_err_addr_to_imc_addr,
 };
 
-static const struct res_config adl_cfg = {
+static struct res_config adl_cfg = {
 	.machine_check		= true,
 	.num_imc		= 2,
 	.imc_base		= 0xd800,
@@ -524,7 +524,7 @@ static const struct res_config adl_cfg = {

... (truncated 57 lines)
```

---

## Commit 5: 5a3b583f

**Author:** Linus Torvalds
**Date:** 2025-06-18 10:21:39
**Files Changed:** drivers/ata/ahci.c, drivers/ata/libata-acpi.c, drivers/ata/pata_cs5536.c, drivers/ata/pata_macio.c, drivers/ata/pata_via.c (+1 more)

**Message:**
```
Merge tag 'ata-6.16-rc3' of git://git.kernel.org/pub/scm/linux/kernel/git/libata/linux

Pull ata fixes from Niklas Cassel:

 - Force PIO for ATAPI devices on VT6415/VT6330 as the controller locks
   up on ATAPI DMA (Tasos)

 - Fix ACPI PATA cable type detection such that the controller is not
   forced down to a slow transfer mode (Tasos)

 - Fix build error on 32-bit UML (Johannes)

 - Fix a PCI region leak in the pata_macio driver so that the driver no
   longer fails to load after rmmod (Philipp)

 - Use correct DMI BIOS build date for ThinkPad W541 quirk (me)

 - Disallow LPM for ASUSPRO-D840SA motherboard as this board
   interestingly enough gets graphical corruptions on the iGPU when LPM
   is enabled (me)

 - Disallow LPM for Asus B550-F motherboard as this board will get
   command timeouts on ports 5 and 6, yet LPM with the same drive works
   fine on all other ports (Mikko)

* tag 'ata-6.16-rc3' of git://git.kernel.org/pub/scm/linux/kernel/git/libata/linux:
  ata: ahci: Disallow LPM for Asus B550-F motherboard
  ata: ahci: Disallow LPM for ASUSPRO-D840SA motherboard
  ata: ahci: Use correct BIOS build date for ThinkPad W541 quirk
  ata: pata_macio: Fix PCI region leak
  ata: pata_cs5536: fix build on 32-bit UML
  ata: libata-acpi: Do not assume 40 wire cable if no devices are enabled
  ata: pata_via: Force PIO for ATAPI devices on VT6415/VT6330
```

**Diff:**
```diff
diff --git a/drivers/ata/ahci.c b/drivers/ata/ahci.c
index 163ac909bd06..e5e5c2e81d09 100644
--- a/drivers/ata/ahci.c
+++ b/drivers/ata/ahci.c
@@ -1410,8 +1410,15 @@ static bool ahci_broken_suspend(struct pci_dev *pdev)
 
 static bool ahci_broken_lpm(struct pci_dev *pdev)
 {
+	/*
+	 * Platforms with LPM problems.
+	 * If driver_data is NULL, there is no existing BIOS version with
+	 * functioning LPM.
+	 * If driver_data is non-NULL, then driver_data contains the DMI BIOS
+	 * build date of the first BIOS version with functioning LPM (i.e. older
+	 * BIOS versions have broken LPM).
+	 */
 	static const struct dmi_system_id sysids[] = {
-		/* Various Lenovo 50 series have LPM issues with older BIOSen */
 		{
 			.matches = {
 				DMI_MATCH(DMI_SYS_VENDOR, "LENOVO"),
@@ -1438,13 +1445,30 @@ static bool ahci_broken_lpm(struct pci_dev *pdev)
 				DMI_MATCH(DMI_SYS_VENDOR, "LENOVO"),
 				DMI_MATCH(DMI_PRODUCT_VERSION, "ThinkPad W541"),
 			},
+			.driver_data = "20180409", /* 2.35 */
+		},
+		{
+			.matches = {
+				DMI_MATCH(DMI_SYS_VENDOR, "ASUSTeK COMPUTER INC."),
+				DMI_MATCH(DMI_PRODUCT_VERSION, "ASUSPRO D840MB_M840SA"),
+			},
+			/* 320 is broken, there is no known good version. */
+		},
+		{
 			/*
-			 * Note date based on release notes, 2.35 has been
-			 * reported to be good, but I've been unable to get
-			 * a hold of the reporter to get the DMI BIOS date.
-			 * TODO: fix this.
+			 * AMD 500 Series Chipset SATA Controller [1022:43eb]
+			 * on this motherboard timeouts on ports 5 and 6 when
+			 * LPM is enabled, at least with WDC WD20EFAX-68FB5N0
+			 * hard drives. LPM with the same drive works fine on
+			 * all other ports on the same controller.
 			 */
-			.driver_data = "20180310", /* 2.35 */
+			.matches = {
+				DMI_MATCH(DMI_BOARD_VENDOR,
+					  "ASUSTeK COMPUTER INC."),

... (truncated 147 lines)
```

---

