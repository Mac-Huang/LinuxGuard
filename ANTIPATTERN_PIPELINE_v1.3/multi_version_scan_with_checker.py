#!/usr/bin/env python3
"""
Multi-version scanner for vulnerability detection across multiple Linux kernel versions
Enhanced version for v1.3 focusing on detected vulnerability antipatterns
"""

import os
import json
import subprocess
import tempfile
import re
from pathlib import Path

# Import vulnerability type from commit data
try:
    from data.commit_data import VULNERABILITY_TYPE
except ImportError:
    VULNERABILITY_TYPE = 'vulnerability'

class MultiVersionVulnerabilityScanner:
    def __init__(self, kernel_path="../../linux"):
        self.kernel_path = Path(kernel_path)
        self.vulnerability_type = VULNERABILITY_TYPE
        self.vuln_name = self.vulnerability_type.replace('-', '_')
        self.results = {}
        # Scan RC (Release Candidate) versions from 5 and 10 years ago
        # Using more recent versions to avoid Windows case-sensitivity issues
        self.versions_to_scan = [
            'v5.10-rc1',  # Late 2020 RC version (~5 years ago)
            'v5.10-rc7',  # Late 2020 RC version (~5 years ago)
            'v6.0-rc1',   # 2022 RC version (more recent, better compatibility)
            'v6.0-rc7',   # 2022 RC version (more recent, better compatibility)
        ]

    def checkout_version(self, version):
        """Checkout a specific kernel version with force option for Windows compatibility"""
        print(f"Checking out version {version}...")
        try:
            # First, clean any untracked files and reset hard
            print("Cleaning workspace...")
            clean_cmd = ['git', 'clean', '-fd']
            subprocess.run(clean_cmd, cwd=self.kernel_path, capture_output=True, text=True)

            # Reset any changes
            reset_cmd = ['git', 'reset', '--hard']
            subprocess.run(reset_cmd, cwd=self.kernel_path, capture_output=True, text=True)

            # Stash any remaining local changes
            stash_cmd = ['git', 'stash', 'push', '-m', f'temp_stash_for_{version}', '--include-untracked']
            subprocess.run(stash_cmd, cwd=self.kernel_path, capture_output=True, text=True)

            # Force checkout the version
            cmd = ['git', 'checkout', '-f', version]
            result = subprocess.run(cmd, cwd=self.kernel_path, capture_output=True, text=True)
            if result.returncode == 0:
                print(f"Successfully checked out {version}")
                return True
            else:
                # Try harder with a more aggressive approach
                print(f"First attempt failed, trying aggressive checkout...")

                # Remove problematic files
                remove_cmd = ['git', 'rm', '-rf', '--cached', '.']
                subprocess.run(remove_cmd, cwd=self.kernel_path, capture_output=True, text=True)

                # Reset and checkout
                reset_cmd = ['git', 'reset', '--hard', version]
                result = subprocess.run(reset_cmd, cwd=self.kernel_path, capture_output=True, text=True)

                if result.returncode == 0:
                    print(f"Successfully checked out {version} (aggressive method)")
                    return True
                else:
                    print(f"Failed to checkout {version}: {result.stderr[:500]}")
                    return False
        except Exception as e:
            print(f"Error checking out {version}: {e}")
            return False

    def scan_version_without_checkout(self, version):
        """Scan a version using git show without checking out"""
        print(f"Analyzing {version} without checkout for {self.vulnerability_type}s...")

        # Comprehensive target directories covering critical kernel subsystems
        # Focus on areas with high vulnerability risk
        target_dirs = [
            # Networking (high vulnerability risk)
            "net/core",
            "net/ipv4",
            "net/ipv6",
            "net/sctp",
            "net/bluetooth",
            "net/wireless",
            "net/packet",
            "net/netfilter",

            # File systems (critical for data integrity)
            "fs/ext4",
            "fs/xfs",
            "fs/btrfs",
            "fs/nfs",
            "fs/proc",

            # Memory management (security critical)
            "mm",

            # Core kernel
            "kernel",
            "kernel/bpf",

            # Drivers with high exposure
            "drivers/net/ethernet",
            "drivers/net/wireless",
            "drivers/usb/core",
            "drivers/gpu/drm",
            "drivers/block",
            "drivers/scsi",
            "drivers/media",

            # Security subsystems
            "security/selinux",
            "security/apparmor",

            # Architecture-specific (x86)
            "arch/x86/kernel",
            "arch/x86/mm",

            # IPC and synchronization
            "ipc",

            # Sound subsystem
            "sound/core",
            "sound/pci",
        ]

        issues = []
        files_analyzed = 0
        max_total_files = 500  # Increased limit for more comprehensive scan

        for target_dir in target_dirs:
            print(f"  Scanning {target_dir}...")
            try:
                # List files in the directory for this version
                ls_cmd = ['git', 'ls-tree', '-r', '--name-only', version, target_dir]
                result = subprocess.run(ls_cmd, cwd=self.kernel_path,
                                      capture_output=True, text=True, timeout=30)

                if result.returncode == 0:
                    files = result.stdout.strip().split('\n')
                    c_files = [f for f in files if f.endswith(('.c', '.h')) and f][:20]  # Limit per directory

                    for file_path in c_files:
                        if file_path and files_analyzed < max_total_files:
                            # Get file content from specific version
                            show_cmd = ['git', 'show', f'{version}:{file_path}']
                            content_result = subprocess.run(show_cmd, cwd=self.kernel_path,
                                                          capture_output=True, text=True, timeout=10)

                            if content_result.returncode == 0 and content_result.stdout:
                                # Analyze content for vulnerability patterns
                                file_issues = self._detect_vulnerability_patterns(content_result.stdout, file_path)
                                if file_issues:
                                    print(f"  Found {len(file_issues)} {self.vulnerability_type} issues in {file_path}")
                                    issues.extend(file_issues)
                                files_analyzed += 1
            except subprocess.TimeoutExpired:
                print(f"  Timeout analyzing files in {target_dir}")
            except Exception as e:
                print(f"  Error analyzing {target_dir}: {str(e)[:100]}")

        print(f"  Analyzed {files_analyzed} files, found {len(issues)} potential {self.vulnerability_type} issues")
        return issues

    def _detect_vulnerability_patterns(self, content, file_path):
        """Detect vulnerability patterns in source code"""
        issues = []
        lines = content.split('\n')

        # Dynamically adjust patterns based on vulnerability type
        if 'overflow' in self.vulnerability_type.lower():
            # Buffer overflow specific patterns
            for i, line in enumerate(lines, 1):
                # Pattern 1: strcpy/strcat without bounds checking
                if re.search(r'\b(strcpy|strcat|sprintf|gets)\s*\(', line):
                    issues.append({
                        'file': file_path,
                        'line': i,
                        'type': 'unsafe_string_function',
                        'message': f'Unsafe string function at line {i}: {line.strip()[:80]}',
                        'analyzer': f'{self.vuln_name}_detection',
                        'severity': 'high'
                    })

                # Pattern 2: memcpy without size validation
                if 'memcpy(' in line or 'memmove(' in line:
                    # Check if there's a size check in previous lines
                    has_size_check = False
                    for j in range(max(0, i-5), i):
                        if j < len(lines) and ('if' in lines[j] and ('size' in lines[j] or 'len' in lines[j])):
                            has_size_check = True
                            break

                    if not has_size_check and 'sizeof' not in line:
                        issues.append({
                            'file': file_path,
                            'line': i,
                            'type': 'unchecked_memcpy',
                            'message': f'memcpy/memmove without apparent size check at line {i}',
                            'analyzer': f'{self.vuln_name}_detection',
                            'severity': 'medium'
                        })

                # Pattern 3: Array index without bounds checking
                array_access = re.search(r'(\w+)\[([^\]]+)\]', line)
                if array_access and not re.search(r'if.*[\<\>].*\[', line):
                    var_name = array_access.group(1)
                    index = array_access.group(2)

                    # Check if it's a constant or if there's a bounds check nearby
                    if not index.isdigit():
                        # Look for bounds check in surrounding lines
                        has_bounds_check = False
                        for j in range(max(0, i-3), min(len(lines), i+3)):
                            if j < len(lines) and index in lines[j] and ('if' in lines[j] or 'assert' in lines[j]):
                                has_bounds_check = True
                                break

                        if not has_bounds_check:
                            issues.append({
                                'file': file_path,
                                'line': i,
                                'type': 'unchecked_array_index',
                                'message': f'Array access without bounds check: {var_name}[{index}] at line {i}',
                                'analyzer': f'{self.vuln_name}_detection',
                                'severity': 'medium'
                            })

                # Pattern 4: Potential integer overflow in size calculation
                if re.search(r'malloc\s*\([^)]*\*[^)]*\)', line) or re.search(r'kmalloc\s*\([^)]*\*[^)]*\)', line):
                    if 'check' not in line.lower() and 'overflow' not in line.lower():
                        issues.append({
                            'file': file_path,
                            'line': i,
                            'type': 'integer_overflow_risk',
                            'message': f'Potential integer overflow in allocation size at line {i}',
                            'analyzer': f'{self.vuln_name}_detection',
                            'severity': 'medium'
                        })

                # Pattern 5: snprintf return value not checked
                if 'snprintf(' in line:
                    # Check if return value is checked
                    if '=' not in line or 'if' not in line:
                        # Look ahead for check
                        ret_checked = False
                        for j in range(i+1, min(len(lines), i+3)):
                            if j < len(lines) and ('if' in lines[j] or 'ret' in lines[j] or 'result' in lines[j]):
                                ret_checked = True
                                break

                        if not ret_checked:
                            issues.append({
                                'file': file_path,
                                'line': i,
                                'type': 'unchecked_snprintf',
                                'message': f'snprintf return value not checked at line {i}',
                                'analyzer': f'{self.vuln_name}_detection',
                                'severity': 'low'
                            })
        else:
            # Generic vulnerability patterns
            for i, line in enumerate(lines, 1):
                # Pattern: memory operations without checks
                if re.search(r'\b(memcpy|memmove|strcpy|strcat)\s*\(', line):
                    if 'if' not in line and 'check' not in line.lower():
                        issues.append({
                            'file': file_path,
                            'line': i,
                            'type': 'unchecked_memory_operation',
                            'message': f'Memory operation without apparent check at line {i}',
                            'analyzer': f'{self.vuln_name}_detection',
                            'severity': 'medium'
                        })

        return issues

    def run_multi_version_scan(self):
        """Run comprehensive multi-version vulnerability scan"""
        print(f"=== Multi-Version {self.vulnerability_type.replace('-', ' ').title()} Detection Scan ===")

        # Store original branch
        try:
            orig_branch = subprocess.run(
                ['git', 'rev-parse', '--abbrev-ref', 'HEAD'],
                cwd=self.kernel_path, capture_output=True, text=True
            ).stdout.strip()
        except:
            orig_branch = None

        for version in self.versions_to_scan:
            print(f"\n--- Scanning {version} ---")

            # Try to checkout the version
            checkout_success = self.checkout_version(version)

            if not checkout_success:
                # Try alternative: scan without checkout
                print(f"Checkout failed, using alternative scan method...")
                pattern_results = self.scan_version_without_checkout(version)

                self.results[version] = {
                    'status': 'scanned_without_checkout',
                    f'{self.vuln_name}_issues': pattern_results,
                    'total_issues': len(pattern_results),
                    'note': 'Analyzed using git show without checkout'
                }
            else:
                # Would normally scan with checkout, but fallback for now
                print(f"Checkout successful, but using safe scan method anyway...")
                pattern_results = self.scan_version_without_checkout(version)

                self.results[version] = {
                    'status': 'scanned',
                    f'{self.vuln_name}_issues': pattern_results,
                    'total_issues': len(pattern_results)
                }

            print(f"Version {version} scan complete:")
            print(f"  {self.vulnerability_type.replace('-', ' ').title()} issues: {len(pattern_results)}")
            print(f"  Total issues: {len(pattern_results)}")

        # Restore original state
        if orig_branch:
            try:
                subprocess.run(['git', 'checkout', orig_branch],
                             cwd=self.kernel_path, capture_output=True, text=True)
                print(f"\nRestored to branch: {orig_branch}")
            except:
                print("\nWarning: Could not restore original branch")

        # Save and display results
        self.save_results()
        return self.results

    def save_results(self):
        """Save scan results to files"""
        # Summary statistics
        total_versions = len(self.versions_to_scan)
        # Count both 'scanned' and 'scanned_without_checkout' as successful
        scanned_versions = sum(1 for r in self.results.values()
                             if r['status'] in ['scanned', 'scanned_without_checkout'])
        total_issues = sum(r['total_issues'] for r in self.results.values())

        summary_results = {
            'scan_type': f'multi_version_{self.vuln_name}_detection',
            'versions_requested': self.versions_to_scan,
            'versions_scanned': scanned_versions,
            'total_versions': total_versions,
            'total_issues_found': total_issues,
            'results_by_version': self.results,
            'summary': {
                'vulnerable_versions': [v for v, r in self.results.items() if r['total_issues'] > 0],
                'clean_versions': [v for v, r in self.results.items() if r['total_issues'] == 0],
                'failed_versions': [v for v, r in self.results.items()
                                  if r['status'] not in ['scanned', 'scanned_without_checkout']]
            }
        }

        # Save JSON results
        with open(f'results/multi_version_{self.vuln_name}_results.json', 'w') as f:
            json.dump(summary_results, f, indent=2)

        # Generate report
        self._generate_multi_version_report(summary_results)

        print(f"\n{'='*60}")
        print(f"MULTI-VERSION {self.vulnerability_type.upper()} SCAN SUMMARY")
        print(f"{'='*60}")
        print(f"Versions scanned: {scanned_versions}/{total_versions}")
        print(f"Total {self.vulnerability_type} issues found: {total_issues}")
        print(f"Results saved to: results/multi_version_{self.vuln_name}_results.json")
        print(f"Report saved to: results/multi_version_{self.vuln_name}_report.md")

    def _generate_multi_version_report(self, results):
        """Generate human-readable multi-version report"""
        report = []
        report.append(f"# Multi-Version {self.vulnerability_type.replace('-', ' ').title()} Detection Report")
        report.append("=" * 50)
        report.append("")
        report.append(f"**Scan Date**: {__import__('datetime').datetime.now()}")
        report.append(f"**Scan Type**: {self.vulnerability_type.replace('-', ' ').title()} Pattern Detection")
        report.append(f"**Versions Requested**: {len(results['versions_requested'])}")
        report.append(f"**Versions Successfully Scanned**: {results['versions_scanned']}")
        report.append(f"**Total {self.vulnerability_type.replace('-', ' ').title()} Issues Found**: {results['total_issues_found']}")
        report.append("")

        report.append("## Version Summary")
        report.append("")
        for version in results['versions_requested']:
            if version in results['results_by_version']:
                r = results['results_by_version'][version]
                status = r['status']
                issues = r['total_issues']
                scan_method = "checkout" if status == "scanned" else "git show (no checkout)"
                if status == 'scanned_without_checkout':
                    status = 'scanned'
                report.append(f"- **{version}**: {status} ({scan_method}) - {issues} {self.vulnerability_type} issues found")
            else:
                report.append(f"- **{version}**: not scanned")
        report.append("")

        if results['summary']['vulnerable_versions']:
            report.append(f"## Vulnerable Versions ({self.vulnerability_type.replace('-', ' ').title()} Issues)")
            report.append("")
            for version in results['summary']['vulnerable_versions']:
                r = results['results_by_version'][version]
                vuln_issues_key = f'{self.vuln_name}_issues'
                report.append(f"### {version}")
                report.append(f"- Total {self.vulnerability_type} issues: {len(r[vuln_issues_key])}")

                # Group issues by type
                issue_types = {}
                for issue in r[vuln_issues_key]:
                    issue_type = issue['type']
                    if issue_type not in issue_types:
                        issue_types[issue_type] = []
                    issue_types[issue_type].append(issue)

                # Show summary by type
                for issue_type, type_issues in issue_types.items():
                    report.append(f"  - {issue_type}: {len(type_issues)} occurrences")

                # Show sample issues
                report.append("\n**Sample Issues:**")
                for issue in r[vuln_issues_key][:5]:  # Show first 5 issues
                    report.append(f"  - {issue['file']}:{issue['line']} - {issue['type']}")
                    report.append(f"    {issue['message']}")
                report.append("")

        report_text = '\n'.join(report)

        with open(f'results/multi_version_{self.vuln_name}_report.md', 'w') as f:
            f.write(report_text)

def main():
    """Main function for multi-version vulnerability scanning"""
    scanner = MultiVersionVulnerabilityScanner()

    print(f"Starting multi-version {scanner.vulnerability_type} detection scan...")
    results = scanner.run_multi_version_scan()

    if results:
        total_issues = sum(r['total_issues'] for r in results.values())
        if total_issues > 0:
            print(f"\n[SUCCESS] Found {total_issues} potential {scanner.vulnerability_type} vulnerabilities across versions!")
        else:
            print(f"\n[INFO] No {scanner.vulnerability_type} issues found across {len(results)} kernel versions")
        return 0
    else:
        print("\n[ERROR] Multi-version scan failed")
        return 1

if __name__ == "__main__":
    exit(main())