@echo off
REM Batch script to extract kernel versions using git archive
REM This may work better on Windows than Python subprocess

set KERNEL_REPO=D:\Develop\Research\Detector\LinuxGuard\antipattern_pipeline\linux_kernel
set OUTPUT_DIR=D:\Develop\Research\Detector\LinuxGuard\antipattern_pipeline\kernel_versions_complete

echo ======================================================================
echo KERNEL EXTRACTION BATCH SCRIPT
echo ======================================================================
echo Source: %KERNEL_REPO%
echo Output: %OUTPUT_DIR%
echo.

REM Create output directory
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

REM Process each version
for %%V in (v5.10-rc1 v5.10-rc7 v6.0-rc1 v6.0-rc7) do (
    echo.
    echo Processing %%V...
    echo ----------------------------------------------------------------------

    REM Create version directory
    set VERSION_DIR=%OUTPUT_DIR%\%%V
    if not exist "%OUTPUT_DIR%\%%V" mkdir "%OUTPUT_DIR%\%%V"

    REM Change to kernel repository
    cd /d %KERNEL_REPO%

    REM Extract files using git archive
    echo Extracting files from %%V...

    REM Network subsystem
    git archive %%V net/core net/ipv4 net/ipv6 net/sctp net/bluetooth net/wireless net/packet net/netfilter 2>nul | tar -x -C "%OUTPUT_DIR%\%%V" 2>nul

    REM Filesystems
    git archive %%V fs/ext4 fs/xfs fs/btrfs fs/nfs fs/proc 2>nul | tar -x -C "%OUTPUT_DIR%\%%V" 2>nul

    REM Memory management
    git archive %%V mm 2>nul | tar -x -C "%OUTPUT_DIR%\%%V" 2>nul

    REM Kernel core
    git archive %%V kernel 2>nul | tar -x -C "%OUTPUT_DIR%\%%V" 2>nul

    REM Drivers
    git archive %%V drivers/net/ethernet drivers/net/wireless drivers/usb/core 2>nul | tar -x -C "%OUTPUT_DIR%\%%V" 2>nul
    git archive %%V drivers/gpu/drm drivers/block drivers/scsi drivers/media 2>nul | tar -x -C "%OUTPUT_DIR%\%%V" 2>nul

    REM Security
    git archive %%V security/selinux security/apparmor 2>nul | tar -x -C "%OUTPUT_DIR%\%%V" 2>nul

    REM Architecture
    git archive %%V arch/x86/kernel arch/x86/mm 2>nul | tar -x -C "%OUTPUT_DIR%\%%V" 2>nul

    REM IPC and sound
    git archive %%V ipc sound/core sound/pci 2>nul | tar -x -C "%OUTPUT_DIR%\%%V" 2>nul

    REM Headers (important for Clang)
    git archive %%V include/linux include/net include/uapi 2>nul | tar -x -C "%OUTPUT_DIR%\%%V" 2>nul

    echo Completed %%V
)

echo.
echo ======================================================================
echo EXTRACTION COMPLETE
echo ======================================================================
echo Files saved to: %OUTPUT_DIR%
echo.
echo Please check each version directory for extracted files.
pause