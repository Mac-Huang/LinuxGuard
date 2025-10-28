#!/usr/bin/env python3
"""
Module 4: Multi-Version Validation
Scans Linux kernel versions with generated checkers and produces vulnerability reports.
"""

import json
import subprocess
import argparse
import re
import sys
import threading
from pathlib import Path
from typing import Callable, Dict, List, Optional
from datetime import datetime
import multiprocessing as mp

class KernelScanner:
    """Scans kernel versions with clang-tidy checkers."""

    def __init__(self, clang_tidy_path: str, kernels_dir: str):
        self.clang_tidy_path = Path(clang_tidy_path)
        self.kernels_dir = Path(kernels_dir)

        if not self.clang_tidy_path.exists():
            raise ValueError(f"clang-tidy not found: {clang_tidy_path}")
        if not self.kernels_dir.exists():
            raise ValueError(f"Kernels directory not found: {kernels_dir}")

    def get_kernel_versions(self) -> List[Path]:
        """Get available kernel versions."""
        versions = []
        print("\n🔍 Discovering kernel versions...")
        for item in self.kernels_dir.iterdir():
            if item.is_dir() and item.name.startswith("linux-"):
                compile_db = item / "compile_commands.json"
                if compile_db.exists():
                    print(f"  [✓] Found valid kernel: {item.name}")
                    versions.append(item)
                else:
                    print(f"  [✗] Skipping '{item.name}': missing compile_commands.json")
        return sorted(versions)

    def scan_kernel(self, kernel_path: Path, checker_pattern: str = "linuxkernel-*",
                    sample_size: Optional[int] = None,
                    progress_callback: Optional[Callable[[int, int, str], None]] = None) -> Dict:
        """Scan a kernel version with specified checkers."""

        log = print if progress_callback is None else (lambda *args, **kwargs: None)

        log(f"\nScanning {kernel_path.name}...")

        # Get list of C files to scan
        c_files = self.get_kernel_c_files(kernel_path, sample_size)

        if not c_files:
            log("  ✗ No C files found to scan")
            if progress_callback:
                progress_callback(0, 1, "skipped")
            return {}

        log(f"  Found {len(c_files)} C files to scan")

        # Prepare clang-tidy command
        cmd = [
                str(self.clang_tidy_path),
                f"-checks=-*,{checker_pattern}",
                "-p", str(kernel_path)
                ]

        results = {
                "kernel_version": kernel_path.name,
                "scan_time": datetime.now().isoformat(),
                "files_scanned": len(c_files),
                "issues": []
                }

        # Scan files in batches for better progress tracking
        batch_size = 10
        total_batches = max(1, (len(c_files) + batch_size - 1) // batch_size)
        current_batch = 0

        if progress_callback:
            progress_callback(0, total_batches, "running")

        for i in range(0, len(c_files), batch_size):
            batch = c_files[i:i+batch_size]
            current_batch = (i // batch_size) + 1
            log(f"  Scanning batch {current_batch}/{total_batches}...")

            batch_cmd = cmd + batch

            try:
                result = subprocess.run(batch_cmd, capture_output=True, text=True,
                                        timeout=300)  # 5 min timeout per batch

                # Parse clang-tidy output
                issues = self.parse_clang_tidy_output(result.stdout)
                results["issues"].extend(issues)

            except subprocess.TimeoutExpired:
                log(f"    ⚠ Timeout scanning batch")
                if progress_callback:
                    progress_callback(current_batch, total_batches, "error")
            except Exception as e:
                log(f"    ⚠ Error scanning batch: {e}")
                if progress_callback:
                    progress_callback(current_batch, total_batches, "error")

            if progress_callback:
                progress_callback(min(current_batch, total_batches), total_batches, "running")

        results["total_issues"] = len(results["issues"])
        log(f"  ✓ Found {results['total_issues']} issues")

        if progress_callback:
            progress_callback(total_batches, total_batches, "done")

        return results

    def get_kernel_c_files(self, kernel_path: Path, sample_size: Optional[int]) -> List[str]:
        """Get list of C files to scan from kernel."""

        # Priority subsystems for scanning
        priority_dirs = ["drivers", "net", "fs", "kernel", "mm", "security"]

        c_files = []

        for subdir in priority_dirs:
            subdir_path = kernel_path / subdir
            if subdir_path.exists():
                # Get .c files from this subsystem
                for c_file in subdir_path.rglob("*.c"):
                    c_files.append(str(c_file))

                    if sample_size and len(c_files) >= sample_size:
                        return c_files[:sample_size]

        # If we need more files and no sample limit
        if not sample_size:
            for c_file in kernel_path.rglob("*.c"):
                if str(c_file) not in c_files:
                    c_files.append(str(c_file))

        return c_files[:sample_size] if sample_size else c_files

    def parse_clang_tidy_output(self, output: str) -> List[Dict]:
        """Parse clang-tidy output to extract issues."""

        issues = []

        # Pattern: file:line:column: warning: message [checker-name]
        pattern = r'^(.+?):(\d+):(\d+):\s+warning:\s+(.+?)\s+\[(.+?)\]'

        for line in output.split('\n'):
            match = re.match(pattern, line)
            if match:
                issues.append({
                        "file": match.group(1),
                        "line": int(match.group(2)),
                        "column": int(match.group(3)),
                        "message": match.group(4),
                        "checker": match.group(5),
                        "subsystem": self.get_subsystem(match.group(1))
                        })

        return issues

    def get_subsystem(self, file_path: str) -> str:
        """Determine kernel subsystem from file path."""

        subsystems = {
                "/drivers/": "drivers",
                "/net/": "networking",
                "/fs/": "filesystem",
                "/kernel/": "core-kernel",
                "/mm/": "memory-management",
                "/security/": "security",
                "/arch/": "architecture",
                "/crypto/": "cryptography",
                "/sound/": "sound",
                "/block/": "block-layer"
                }

        for pattern, subsystem in subsystems.items():
            if pattern in file_path:
                return subsystem

        return "other"

    def analyze_results(self, scan_results: Dict) -> Dict:
        """Analyze scan results..."""
        analysis = {
                "summary": {
                    "total_issues": scan_results.get("total_issues", 0),
                    "unique_files_affected": len(set(i["file"] for i in scan_results.get("issues", [])))
                    },
                "by_subsystem": {},
                "by_checker": {},
                "hotspots": []
                }

        # Group by subsystem
        for issue in scan_results.get("issues", []):
            subsystem = issue.get("subsystem", "unknown")
            checker = issue.get("checker", "unknown")

            analysis["by_subsystem"][subsystem] = analysis["by_subsystem"].get(subsystem, 0) + 1
            analysis["by_checker"][checker] = analysis["by_checker"].get(checker, 0) + 1

        # Find hotspot files
        file_counts = {}
        for issue in scan_results.get("issues", []):
            file_path = issue["file"]
            file_counts[file_path] = file_counts.get(file_path, 0) + 1

        analysis["hotspots"] = sorted(
                [{"file": f, "issue_count": c} for f, c in file_counts.items() if c > 2],
                key=lambda x: x["issue_count"],
                reverse=True
                )[:10]

        return analysis

    def generate_report(self, all_results: List[Dict], output_path: Path, anti_pattern_type: Optional[str] = None):
        """Generate comprehensive vulnerability report."""

        report = {
                "scan_metadata": {
                    "timestamp": datetime.now().isoformat(),
                    "clang_tidy_binary": str(self.clang_tidy_path),
                    "kernels_scanned": len(all_results),
                    "anti_pattern_type": anti_pattern_type
                    },
                "results_by_version": {},
                "cross_version_analysis": {}
                }

        # Process each kernel's results
        for result in all_results:
            version = result["kernel_version"]
            report["results_by_version"][version] = {
                    "total_issues": result["total_issues"],
                    "files_scanned": result["files_scanned"],
                    "scan_time": result["scan_time"],
                    "issues": result.get("issues", []),  # Add the full list of issues
                    "analysis": self.analyze_results(result)
                    }

        # Cross-version analysis
        if len(all_results) > 1:
            report["cross_version_analysis"] = self.cross_version_analysis(all_results)

        # Organize output based on anti-pattern type
        final_output_path = output_path
        if anti_pattern_type:
            folder_name = anti_pattern_type.lower().replace('_', '-')
            if folder_name not in [p.name for p in final_output_path.parents]:
                output_dir = output_path.parent / folder_name
                final_output_path = output_dir / output_path.name
            else:
                final_output_path = output_path

        final_output_path.parent.mkdir(parents=True, exist_ok=True)

        # Save report
        with open(final_output_path, 'w') as f:
            json.dump(report, f, indent=2)

        # Generate markdown summary
        self.generate_markdown_summary(report, final_output_path.with_suffix('.md'))

        print(f"\n✓ Report saved to {final_output_path}")
        print(f"✓ Summary saved to {final_output_path.with_suffix('.md')}")

    def cross_version_analysis(self, all_results: List[Dict]) -> Dict:
        """Analyze patterns across kernel versions."""

        analysis = {
                "temporal_trends": {},
                "persistent_issues": [],
                "evolution": {}
                }

        # Track issues by file across versions
        file_issues = {}

        for result in all_results:
            version = result["kernel_version"]

            for issue in result["issues"]:
                file_path = issue["file"]
                if file_path not in file_issues:
                    file_issues[file_path] = {}
                if version not in file_issues[file_path]:
                    file_issues[file_path][version] = []
                file_issues[file_path][version].append(issue)

        # Find persistent issues (appear in multiple versions)
        for file_path, versions in file_issues.items():
            if len(versions) > 1:
                analysis["persistent_issues"].append({
                    "file": file_path,
                    "affected_versions": list(versions.keys()),
                    "issue_count": sum(len(issues) for issues in versions.values())
                    })

        # Sort by persistence
        analysis["persistent_issues"].sort(key=lambda x: len(x["affected_versions"]),
                reverse=True)

        return analysis

    def generate_markdown_summary(self, report: Dict, output_path: Path):
        """Generate a markdown summary of the report."""

        md_lines = [
                "# Linux Kernel Vulnerability Scan Report",
                f"\nGenerated: {report['scan_metadata']['timestamp']}",
                f"\nKernels Scanned: {report['scan_metadata']['kernels_scanned']}",
                "\n## Results by Version\n"
                ]

        for version, data in report["results_by_version"].items():
            md_lines.append(f"### {version}")
            md_lines.append(f"- **Total Issues**: {data['total_issues']}")
            md_lines.append(f"- **Files Scanned**: {data['files_scanned']}")

            if data["analysis"].get("by_subsystem"):
                md_lines.append("\n**Issues by Subsystem:**")
                for subsystem, count in sorted(data["analysis"]["by_subsystem"].items(),
                                               key=lambda x: x[1], reverse=True)[:5]:
                    md_lines.append(f"- {subsystem}: {count}")

        if report.get("cross_version_analysis", {}).get("persistent_issues"):
            md_lines.append("\n## Persistent Issues Across Versions\n")
            for issue in report["cross_version_analysis"]["persistent_issues"][:10]:
                md_lines.append(f"- `{issue['file']}`")
                md_lines.append(f"  - Affected versions: {', '.join(issue['affected_versions'])}")
                md_lines.append(f"  - Total issues: {issue['issue_count']}")

        with open(output_path, 'w') as f:
            f.write('\n'.join(md_lines))

def run_scan_for_kernel(args_tuple):
    """Helper function for multiprocessing pool to scan a single kernel."""
    (clang_tidy_path, kernels_dir, kernel_path, checker_pattern,
     sample_size, progress_key, progress_data) = args_tuple
    # We instantiate the scanner in the worker process to avoid pickling issues
    scanner = KernelScanner(str(clang_tidy_path), str(kernels_dir))
    def update_progress(current: int, total: int, status: str):
        try:
            progress_data[progress_key] = {
                "current": current,
                "total": total,
                "status": status
            }
        except Exception:
            pass

    progress_cb = update_progress if progress_data is not None else None
    return scanner.scan_kernel(kernel_path, checker_pattern, sample_size, progress_cb)


def render_progress_bar(current: int, total: int, width: int = 28) -> str:
    """Create an ASCII progress bar for display."""
    total = max(total, 1)
    ratio = min(max(current / total, 0.0), 1.0)
    filled = int(width * ratio)
    return '█' * filled + '░' * (width - filled)


def render_progress_bars(progress_data, total_kernels: int, stop_event: threading.Event,
                         display_limit: int = 4, refresh_interval: float = 0.2) -> None:
    """Continuously render up to display_limit progress bars for kernel scans."""

    lines_printed = 0

    while True:
        statuses = sorted(list(progress_data.items()), key=lambda item: item[0])

        completed = sum(
            1 for _, info in statuses
            if info.get("status") in {"done", "error", "skipped"}
        )

        if statuses:
            if lines_printed:
                sys.stdout.write(f"\033[{lines_printed}F")

            lines: List[str] = []
            for kernel, info in statuses[:display_limit]:
                current = int(info.get("current", 0))
                total = int(info.get("total", 1))
                status = info.get("status", "queued")
                bar = render_progress_bar(current, total)
                lines.append(f"  {kernel:<20} [{bar}] {current}/{total} {status}")

            remaining = len(statuses) - display_limit
            if remaining > 0:
                pending = sum(
                    1 for _, info in statuses[display_limit:]
                    if info.get("status") not in {"done", "error", "skipped"}
                )
                lines.append(f"  … {remaining} more kernels ({pending} pending)")

            for line in lines:
                sys.stdout.write("\033[2K" + line + "\n")
            sys.stdout.flush()
            lines_printed = len(lines)

        if completed >= total_kernels and statuses:
            break

        if stop_event.wait(refresh_interval):
            break

    if lines_printed:
        sys.stdout.write(f"\033[{lines_printed}F")
        statuses = sorted(list(progress_data.items()), key=lambda item: item[0])
        lines: List[str] = []
        for kernel, info in statuses[:display_limit]:
            current = int(info.get("current", 0))
            total = int(info.get("total", 1))
            status = info.get("status", "queued")
            bar = render_progress_bar(current, total)
            lines.append(f"  {kernel:<20} [{bar}] {current}/{total} {status}")

        remaining = len(statuses) - display_limit
        if remaining > 0:
            pending = sum(
                1 for _, info in statuses[display_limit:]
                if info.get("status") not in {"done", "error", "skipped"}
            )
            lines.append(f"  … {remaining} more kernels ({pending} pending)")

        for line in lines:
            sys.stdout.write("\033[2K" + line + "\n")
        sys.stdout.flush()

    if lines_printed:
        print()

def main():
    script_dir = Path(__file__).parent.resolve()
    default_base_dir = script_dir.parent  # Assumes script is in a 'scripts' subdir

    parser = argparse.ArgumentParser(description='Validate checkers across kernel versions')
    parser.add_argument('--clang-tidy',
            default=str(default_base_dir / 'llvm-project/build/bin/clang-tidy'),
            help='Path to clang-tidy binary')
    parser.add_argument('--kernels-dir', default=str(default_base_dir / 'kernels'),
            help='Directory containing kernel versions')
    parser.add_argument('--output', default=str(default_base_dir / 'results/scan_report.json'),
            help='Output file for scan report')
    parser.add_argument('--checker-pattern', default='linuxkernel-*',
            help='Pattern for checkers to use')
    parser.add_argument('--anti-pattern',
            help='Specific checker name to validate (e.g., UseAfterFreeCheck)')
    parser.add_argument('--kernel-version', help='Scan specific kernel version only')
    parser.add_argument('--sample-size', type=int,
            help='Limit number of files to scan per kernel')
    parser.add_argument('--anti-pattern-type', help='Anti-pattern type being validated (for organized output)')
    parser.add_argument('--processes', type=int, default=None,
            help='Number of worker processes for parallel kernel scans')

    args = parser.parse_args()

    print("=== Module 4: Multi-Version Validation ===")

    scanner = KernelScanner(args.clang_tidy, args.kernels_dir)

    # Get kernel versions to scan
    checker_pattern = args.checker_pattern
    if args.anti_pattern:
        # Convert CheckerName to clang-tidy pattern (UseAfterFreeCheck -> linuxkernel-use-after-free)
        name = args.anti_pattern.replace('Check', '')
        pattern_parts = []
        for index, char in enumerate(name):
            if char.isupper() and index > 0:
                pattern_parts.append('-')
            pattern_parts.append(char.lower())
        checker_pattern = f"linuxkernel-{''.join(pattern_parts)}"

    if args.kernel_version:
        kernel_path = scanner.kernels_dir / args.kernel_version
        if not kernel_path.exists():
            print(f"✗ Kernel version not found: {args.kernel_version}")
            return
        kernels_to_scan = [kernel_path]
    else:
        kernels_to_scan = scanner.get_kernel_versions()

    if not kernels_to_scan:
        print("✗ No kernel versions found to scan")
        return

    print(f"\nKernel versions to scan:")
    for kernel in kernels_to_scan:
        print(f"  - {kernel.name}")

    # Scan each kernel in parallel
    processes = args.processes or min(4, len(kernels_to_scan))
    print(f"\nStarting parallel scan with {processes} worker(s)...")

    manager = mp.Manager()
    progress_data = manager.dict()
    for kernel in kernels_to_scan:
        progress_data[kernel.name] = {
            "current": 0,
            "total": 1,
            "status": "queued"
        }

    stop_event = threading.Event()
    progress_thread = threading.Thread(
        target=render_progress_bars,
        args=(progress_data, len(kernels_to_scan), stop_event),
        daemon=True,
    )
    progress_thread.start()

    # Prepare arguments for each worker process
    scan_args = [
        (
            args.clang_tidy,
            args.kernels_dir,
            kernel_path,
            checker_pattern,
            args.sample_size,
            kernel_path.name,
            progress_data,
        )
        for kernel_path in kernels_to_scan
    ]

    all_results = []
    # Use a multiprocessing Pool to scan kernels concurrently
    try:
        with mp.Pool(processes=processes) as pool:
            results_from_pool = pool.map(run_scan_for_kernel, scan_args)
            # Filter out any None or empty dict results from failed/empty scans
            all_results = [r for r in results_from_pool if r]
    finally:
        stop_event.set()
        progress_thread.join()
        try:
            manager.shutdown()
        except Exception:
            pass

    if not all_results:
        print("\n✗ No scan results obtained")
        return

    # Generate report
    print("\nGenerating report...")
    output_path = Path(args.output)

    scanner.generate_report(all_results, output_path, args.anti_pattern_type)

    # Print summary
    print("\n=== Summary ===")
    total_issues = sum(r["total_issues"] for r in all_results)
    total_files = sum(r["files_scanned"] for r in all_results)

    print(f"Total issues found: {total_issues}")
    print(f"Total files scanned: {total_files}")

    if total_files > 0:
        print(f"Average issues per file: {total_issues / total_files:.2f}")

if __name__ == "__main__":
    main()
