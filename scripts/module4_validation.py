#!/usr/bin/env python3
"""
Module 4: Multi-Version Validation
Scans Linux kernel versions with generated checkers and produces vulnerability reports.
"""

import json
import subprocess
import os
import argparse
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple
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
        for item in self.kernels_dir.iterdir():
            if item.is_dir() and item.name.startswith("linux-"):
                compile_db = item / "compile_commands.json"
                if compile_db.exists():
                    versions.append(item)
        return sorted(versions)

    def scan_kernel(self, kernel_path: Path, checker_pattern: str = "linuxkernel-*",
                   sample_size: Optional[int] = None) -> Dict:
        """Scan a kernel version with specified checkers."""

        print(f"\nScanning {kernel_path.name}...")

        # Get list of C files to scan
        c_files = self.get_kernel_c_files(kernel_path, sample_size)

        if not c_files:
            print("  ✗ No C files found to scan")
            return {}

        print(f"  Found {len(c_files)} C files to scan")

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
        for i in range(0, len(c_files), batch_size):
            batch = c_files[i:i+batch_size]
            print(f"  Scanning batch {i//batch_size + 1}/{(len(c_files) + batch_size - 1)//batch_size}...")

            batch_cmd = cmd + batch

            try:
                result = subprocess.run(batch_cmd, capture_output=True, text=True,
                                      timeout=300)  # 5 min timeout per batch

                # Parse clang-tidy output
                issues = self.parse_clang_tidy_output(result.stdout)
                results["issues"].extend(issues)

            except subprocess.TimeoutExpired:
                print(f"    ⚠ Timeout scanning batch")
            except Exception as e:
                print(f"    ⚠ Error scanning batch: {e}")

        results["total_issues"] = len(results["issues"])
        print(f"  ✓ Found {results['total_issues']} issues")

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
        """Analyze scan results to generate insights about vulnerability patterns.

        TODO(human): Implement analysis logic that:
        1. Groups results by subsystem to identify most affected areas
        2. Calculates vulnerability density (issues per 1000 lines of code)
        3. Identifies top vulnerability patterns by checker type
        4. Tracks clustering of issues (files with multiple vulnerabilities)

        Args:
            scan_results: Dictionary containing scan results with 'issues' list

        Returns:
            Dictionary containing analysis insights
        """

        analysis = {
            "summary": {},
            "by_subsystem": {},
            "by_checker": {},
            "hotspots": []
        }

        # TODO(human): Add your analysis implementation here

        return analysis

    def generate_report(self, all_results: List[Dict], output_path: Path):
        """Generate comprehensive vulnerability report."""

        report = {
            "scan_metadata": {
                "timestamp": datetime.now().isoformat(),
                "clang_tidy_binary": str(self.clang_tidy_path),
                "kernels_scanned": len(all_results)
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
                "analysis": self.analyze_results(result)
            }

        # Cross-version analysis
        if len(all_results) > 1:
            report["cross_version_analysis"] = self.cross_version_analysis(all_results)

        # Save report
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)

        # Generate markdown summary
        self.generate_markdown_summary(report, output_path.with_suffix('.md'))

        print(f"\n✓ Report saved to {output_path}")
        print(f"✓ Summary saved to {output_path.with_suffix('.md')}")

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

def main():
    parser = argparse.ArgumentParser(description='Validate checkers across kernel versions')
    parser.add_argument('--clang-tidy',
                      default='/home/mac/private/linux-guard/llvm-project/build/bin/clang-tidy',
                      help='Path to clang-tidy binary')
    parser.add_argument('--kernels-dir', default='/home/mac/private/linux-guard/kernels',
                      help='Directory containing kernel versions')
    parser.add_argument('--output', default='/home/mac/private/linux-guard/results/scan_report.json',
                      help='Output file for scan report')
    parser.add_argument('--checker-pattern', default='linuxkernel-*',
                      help='Pattern for checkers to use')
    parser.add_argument('--kernel-version', help='Scan specific kernel version only')
    parser.add_argument('--sample-size', type=int,
                      help='Limit number of files to scan per kernel')

    args = parser.parse_args()

    print("=== Module 4: Multi-Version Validation ===")

    scanner = KernelScanner(args.clang_tidy, args.kernels_dir)

    # Get kernel versions to scan
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

    # Scan each kernel
    all_results = []

    for kernel_path in kernels_to_scan:
        result = scanner.scan_kernel(kernel_path, args.checker_pattern, args.sample_size)
        if result:
            all_results.append(result)

    if not all_results:
        print("\n✗ No scan results obtained")
        return

    # Generate report
    print("\nGenerating report...")
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    scanner.generate_report(all_results, output_path)

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