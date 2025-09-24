# PowerShell script to extract all kernel files
# Run with: powershell -ExecutionPolicy Bypass -File extract_kernel_complete.ps1

$KernelRepo = "D:\Develop\Research\Detector\LinuxGuard\antipattern_pipeline\linux_kernel"
$OutputDir = "D:\Develop\Research\Detector\LinuxGuard\antipattern_pipeline\kernel_versions_complete"

$Versions = @("v5.10-rc1", "v5.10-rc7", "v6.0-rc1", "v6.0-rc7")

$TargetDirs = @(
    "net/core", "net/ipv4", "net/ipv6", "net/sctp",
    "net/bluetooth", "net/wireless", "net/packet", "net/netfilter",
    "fs/ext4", "fs/xfs", "fs/btrfs", "fs/nfs", "fs/proc",
    "mm",
    "kernel", "kernel/bpf",
    "drivers/net/ethernet", "drivers/net/wireless",
    "drivers/usb/core", "drivers/gpu/drm",
    "drivers/block", "drivers/scsi", "drivers/media",
    "security/selinux", "security/apparmor",
    "arch/x86/kernel", "arch/x86/mm",
    "ipc",
    "sound/core", "sound/pci",
    "include/linux", "include/net", "include/uapi/linux"
)

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "COMPLETE KERNEL EXTRACTION (PowerShell)" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "Source: $KernelRepo"
Write-Host "Output: $OutputDir"
Write-Host ""

# Create output directory
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

# Change to kernel repository
Set-Location $KernelRepo

$TotalFiles = 0
$StartTime = Get-Date

foreach ($Version in $Versions) {
    Write-Host "`nProcessing $Version..." -ForegroundColor Yellow
    Write-Host "----------------------------------------------------------------------"

    $VersionDir = "$OutputDir\$($Version -replace '/', '_')"
    New-Item -ItemType Directory -Force -Path $VersionDir | Out-Null

    $VersionFiles = 0

    foreach ($Dir in $TargetDirs) {
        Write-Host "  Extracting $Dir..." -NoNewline

        # Get list of files
        $Files = git ls-tree -r --name-only $Version $Dir 2>$null

        if ($Files) {
            $FileList = $Files -split "`n"
            $CFiles = $FileList | Where-Object { $_ -match '\.(c|h)$' }

            $DirFiles = 0

            foreach ($File in $CFiles) {
                if ($File) {
                    # Get file content
                    $Content = git show "${Version}:${File}" 2>$null

                    if ($Content) {
                        $DestFile = "$VersionDir\$File"
                        $DestDir = Split-Path -Parent $DestFile

                        # Create directory if needed
                        if (!(Test-Path $DestDir)) {
                            New-Item -ItemType Directory -Force -Path $DestDir | Out-Null
                        }

                        # Save file
                        $Content | Out-File -Encoding UTF8 -FilePath $DestFile

                        $DirFiles++
                        $VersionFiles++
                        $TotalFiles++

                        # Show progress
                        if ($DirFiles % 50 -eq 0) {
                            Write-Host "." -NoNewline
                        }
                    }
                }
            }

            Write-Host " [$DirFiles files]" -ForegroundColor Green
        } else {
            Write-Host " [Not found]" -ForegroundColor Gray
        }
    }

    Write-Host "  Version summary: $VersionFiles files extracted" -ForegroundColor Cyan
}

$EndTime = Get-Date
$Duration = $EndTime - $StartTime

Write-Host "`n======================================================================" -ForegroundColor Cyan
Write-Host "EXTRACTION COMPLETE" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "Total files extracted: $TotalFiles" -ForegroundColor Green
Write-Host "Time taken: $($Duration.TotalMinutes.ToString('F2')) minutes"
Write-Host "Output directory: $OutputDir"

# Verify extraction
Write-Host "`nVerifying extraction..." -ForegroundColor Yellow

foreach ($Version in $Versions) {
    $VersionDir = "$OutputDir\$($Version -replace '/', '_')"
    if (Test-Path $VersionDir) {
        $CFiles = Get-ChildItem -Path $VersionDir -Filter "*.c" -Recurse
        $HFiles = Get-ChildItem -Path $VersionDir -Filter "*.h" -Recurse
        Write-Host "  $Version : $($CFiles.Count) C files, $($HFiles.Count) H files"
    }
}

Write-Host "`nExtraction complete! Ready for analysis." -ForegroundColor Green