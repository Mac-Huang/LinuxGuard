#!/usr/bin/env python3
"""
Multi-version scanner that applies generated checker across multiple Linux kernel versions
This replaces the single-version scanner in v1.1 to provide historical analysis
"""

import os
import json
import subprocess
import tempfile
import re
from pathlib import Path

class MultiVersionCheckerScanner:
    def __init__(self, kernel_path="../../linux"):
        self.kernel_path = Path(kernel_path)
        self.results = {}
        # Scan RC (Release Candidate) versions from 5 and 10 years ago
        # Using more recent versions to avoid Windows case-sensitivity issues
        # Based on current date (2025), we want RC versions from ~2020 and ~2015
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
                # Try alternative: fetch and checkout
                print(f"First attempt failed, trying to fetch and checkout...")
                fetch_cmd = ['git', 'fetch', 'origin', f'refs/tags/{version}:refs/tags/{version}']
                subprocess.run(fetch_cmd, cwd=self.kernel_path, capture_output=True, text=True)

                # Try checkout again
                result = subprocess.run(cmd, cwd=self.kernel_path, capture_output=True, text=True)
                if result.returncode == 0:
                    print(f"Successfully checked out {version} after fetch")
                    return True
                else:
                    print(f"Failed to checkout {version}: {result.stderr[:500]}")
                    return False
        except Exception as e:
            print(f"Error checking out {version}: {e}")
            return False
    
    def restore_original_state(self):
        """Restore to original git state"""
        try:
            # First go back to master/main
            subprocess.run(['git', 'checkout', 'master'], cwd=self.kernel_path, capture_output=True)
        except:
            try:
                subprocess.run(['git', 'checkout', 'main'], cwd=self.kernel_path, capture_output=True)
            except:
                pass
        
        # Try to restore stashed changes
        try:
            stash_list = subprocess.run(['git', 'stash', 'list'], cwd=self.kernel_path, capture_output=True, text=True)
            if 'temp_stash_for_' in stash_list.stdout:
                subprocess.run(['git', 'stash', 'pop'], cwd=self.kernel_path, capture_output=True)
        except:
            pass
    
    def scan_version_with_clang(self, version, target_files, max_files=5):
        """Scan specific version with clang analyzer"""
        print(f"=== Scanning {version} with Clang Static Analyzer ===")
        
        clang_results = []
        files_processed = 0
        
        for file_path in target_files:
            if files_processed >= max_files:
                break
                
            if file_path.suffix == '.c' and file_path.exists():
                print(f"Analyzing: {file_path}")
                
                try:
                    # Run clang static analyzer
                    cmd = [
                        'clang', '--analyze',
                        '-Xanalyzer', '-analyzer-checker=core,unix.Malloc',
                        '-Xanalyzer', '-analyzer-output=text',
                        str(file_path)
                    ]
                    
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                    
                    if result.stderr:
                        # Parse warnings from stderr
                        warnings = self._parse_clang_warnings(result.stderr, file_path)
                        clang_results.extend(warnings)
                        
                    files_processed += 1
                    
                except Exception as e:
                    print(f"Error analyzing {file_path}: {e}")
        
        return clang_results
    
    def _parse_clang_warnings(self, stderr_output, file_path):
        """Parse clang analyzer warnings"""
        warnings = []
        lines = stderr_output.split('\n')
        
        for line in lines:
            if 'warning:' in line.lower() and ('malloc' in line.lower() or 'free' in line.lower()):
                warnings.append({
                    'file': str(file_path),
                    'type': 'clang_warning',
                    'message': line.strip(),
                    'analyzer': 'clang_static_analyzer'
                })
        
        return warnings
    
    def scan_version_with_pattern_logic(self, version, target_files, max_files=5):
        """Apply our use-after-free pattern detection logic"""
        print(f"=== Applying Generated Checker Logic to {version} ===")
        
        pattern_results = []
        files_processed = 0
        
        for file_path in target_files:
            if files_processed >= max_files:
                break
                
            if file_path.suffix == '.c' and file_path.exists():
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    # Look for use-after-free patterns
                    issues = self._detect_uaf_patterns(content, str(file_path))
                    pattern_results.extend(issues)
                    
                    files_processed += 1
                    
                except Exception as e:
                    print(f"Error reading {file_path}: {e}")
        
        return pattern_results
    
    def _detect_uaf_patterns(self, content, file_path):
        """Detect use-after-free and other memory safety patterns in source code"""
        issues = []
        lines = content.split('\n')

        # Track freed variables
        freed_vars = {}

        for i, line in enumerate(lines, 1):
            # Pattern 1: Direct use-after-free
            if 'free(' in line or 'kfree(' in line or '__of_prop_free(' in line:
                # Extract the variable being freed
                free_match = re.search(r'(?:k?free|__of_prop_free)\s*\(\s*([a-zA-Z_]\w*)', line)
                if free_match:
                    var_name = free_match.group(1)
                    freed_vars[var_name] = i

                    # Check subsequent lines for usage
                    for j in range(i, min(i + 15, len(lines))):
                        next_line = lines[j]
                        # Check for dereference of freed variable
                        if (var_name in next_line and
                            ('->' in next_line or '[' in next_line or '*' + var_name in next_line) and
                            'free' not in next_line.lower() and
                            'return' not in lines[j-1] if j > 0 else True):
                            issues.append({
                                'file': file_path,
                                'line': i,
                                'type': 'potential_use_after_free',
                                'message': f'UAF: {var_name} freed at line {i}, used at line {j+1}',
                                'analyzer': 'pattern_detection',
                                'severity': 'high'
                            })
                            break

            # Pattern 2: Missing NULL check after allocation
            if 'malloc(' in line or 'kmalloc(' in line or 'kzalloc(' in line:
                alloc_match = re.search(r'([a-zA-Z_]\w*)\s*=\s*(?:k?[mz]alloc)', line)
                if alloc_match:
                    var_name = alloc_match.group(1)
                    # Check if there's a NULL check in the next few lines
                    has_null_check = False
                    for j in range(i, min(i + 5, len(lines))):
                        if f'if' in lines[j] and (f'!{var_name}' in lines[j] or f'{var_name} == NULL' in lines[j]):
                            has_null_check = True
                            break
                    if not has_null_check and i + 1 < len(lines):
                        # Check if variable is dereferenced without NULL check
                        next_line = lines[i] if i < len(lines) else ""
                        if var_name in next_line and ('->' in next_line or '[' in next_line):
                            issues.append({
                                'file': file_path,
                                'line': i,
                                'type': 'missing_null_check',
                                'message': f'Missing NULL check after allocation of {var_name} at line {i}',
                                'analyzer': 'pattern_detection',
                                'severity': 'medium'
                            })

            # Pattern 3: Double free
            for var_name, freed_line in freed_vars.items():
                if i > freed_line and (f'free({var_name})' in line or f'kfree({var_name})' in line):
                    issues.append({
                        'file': file_path,
                        'line': i,
                        'type': 'double_free',
                        'message': f'Double free: {var_name} already freed at line {freed_line}, freed again at line {i}',
                        'analyzer': 'pattern_detection',
                        'severity': 'high'
                    })

        return issues
    
    def get_target_files(self):
        """Get target files to scan across kernel"""
        target_dirs = [
            self.kernel_path / "drivers" / "of",
            self.kernel_path / "mm",
            self.kernel_path / "kernel",
            self.kernel_path / "fs" / "btrfs",
            self.kernel_path / "drivers" / "gpu" / "drm"
        ]

        target_files = []
        for dir_path in target_dirs:
            if dir_path.exists():
                c_files = list(dir_path.glob("*.c"))[:5]  # Limit per directory
                target_files.extend(c_files)

        print(f"Found {len(target_files)} target files across directories")
        return target_files

    def scan_version_without_checkout(self, version):
        """Scan a version using git show without checking out"""
        print(f"Analyzing {version} without checkout...")

        # Comprehensive target directories covering critical kernel subsystems
        # These are areas most prone to memory safety issues
        target_dirs = [
            # Memory management
            "mm",
            "mm/kasan",
            "mm/kfence",

            # Core kernel
            "kernel",
            "kernel/bpf",
            "kernel/sched",
            "kernel/locking",

            # File systems (high complexity, frequent bugs)
            "fs/ext4",
            "fs/btrfs",
            "fs/xfs",
            "fs/nfs",
            "fs/proc",

            # Networking (security-critical)
            "net/core",
            "net/ipv4",
            "net/ipv6",
            "net/sctp",
            "net/bluetooth",
            "net/wireless",

            # Device drivers (largest attack surface)
            "drivers/of",
            "drivers/net/ethernet",
            "drivers/usb/core",
            "drivers/gpu/drm",
            "drivers/scsi",
            "drivers/block",
            "drivers/char",

            # Security subsystems
            "security",
            "security/selinux",
            "crypto",

            # Architecture-specific (x86 most common)
            "arch/x86/kernel",
            "arch/x86/mm",

            # IPC and synchronization
            "ipc",
            "kernel/futex"
        ]

        issues = []
        files_analyzed = 0
        max_files_per_dir = 2  # Reduced per-dir limit due to more directories
        max_total_files = 50   # Increased total limit for better coverage

        for target_dir in target_dirs:
            try:
                # List all C files in the directory for this version
                cmd = ['git', 'ls-tree', '-r', '--name-only', version, target_dir]
                result = subprocess.run(cmd, cwd=self.kernel_path, capture_output=True, text=True)

                if result.returncode == 0 and result.stdout:
                    # Filter for C files only
                    all_files = result.stdout.strip().split('\n')
                    c_files = [f for f in all_files if f.endswith('.c')][:max_files_per_dir]

                    for file_path in c_files:
                        if file_path and files_analyzed < max_total_files:  # Overall limit
                            # Get file content from specific version
                            show_cmd = ['git', 'show', f'{version}:{file_path}']
                            content_result = subprocess.run(show_cmd, cwd=self.kernel_path,
                                                          capture_output=True, text=True, timeout=10)

                            if content_result.returncode == 0 and content_result.stdout:
                                # Analyze content for patterns
                                file_issues = self._detect_uaf_patterns(content_result.stdout, file_path)
                                if file_issues:
                                    print(f"  Found {len(file_issues)} issues in {file_path}")
                                    issues.extend(file_issues)
                                files_analyzed += 1
            except subprocess.TimeoutExpired:
                print(f"  Timeout analyzing files in {target_dir}")
            except Exception as e:
                print(f"  Error analyzing {target_dir}: {str(e)[:100]}")

        print(f"  Analyzed {files_analyzed} files, found {len(issues)} potential issues")
        return issues
    
    def run_multi_version_scan(self):
        """Run comprehensive multi-version scan"""
        print("=== Multi-Version Generated Checker Scan ===")
        
        # Store original branch
        try:
            orig_branch = subprocess.run(
                ['git', 'rev-parse', '--abbrev-ref', 'HEAD'], 
                cwd=self.kernel_path, capture_output=True, text=True
            ).stdout.strip()
        except:
            orig_branch = "main"
        
        # Get target files (same across versions)
        target_files = self.get_target_files()
        if not target_files:
            print("No target files found!")
            return None
        
        # Scan each version
        for version in self.versions_to_scan:
            print(f"\n{'='*60}")
            print(f"SCANNING VERSION: {version}")
            print(f"{'='*60}")

            checkout_success = self.checkout_version(version)

            if not checkout_success:
                # Try alternative: scan without checkout
                print(f"Checkout failed, trying alternative scan method...")
                pattern_results = self.scan_version_without_checkout(version)

                self.results[version] = {
                    'status': 'scanned_without_checkout',
                    'clang_issues': [],  # Can't use clang without checkout
                    'pattern_issues': pattern_results,
                    'total_issues': len(pattern_results),
                    'note': 'Analyzed using git show without checkout'
                }
            else:
                # Normal scan with checkout
                clang_results = self.scan_version_with_clang(version, target_files)
                pattern_results = self.scan_version_with_pattern_logic(version, target_files)

                # Store results
                self.results[version] = {
                    'status': 'scanned',
                    'files_analyzed': len(target_files),
                    'clang_issues': clang_results,
                    'pattern_issues': pattern_results,
                    'total_issues': len(clang_results) + len(pattern_results)
                }
            
            print(f"Version {version} scan complete:")
            if 'clang_issues' in self.results[version]:
                print(f"  Clang issues: {len(self.results[version]['clang_issues'])}")
            print(f"  Pattern issues: {len(self.results[version]['pattern_issues'])}")
            print(f"  Total issues: {self.results[version]['total_issues']}")
        
        # Restore original state
        print(f"\nRestoring to original branch: {orig_branch}")
        try:
            subprocess.run(['git', 'checkout', orig_branch], cwd=self.kernel_path)
        except:
            pass
        
        # Save results
        self.save_multi_version_results()
        
        return self.results
    
    def save_multi_version_results(self):
        """Save multi-version scan results"""
        # Summary statistics
        total_versions = len(self.versions_to_scan)
        # Count both 'scanned' and 'scanned_without_checkout' as successful
        scanned_versions = sum(1 for r in self.results.values()
                             if r['status'] in ['scanned', 'scanned_without_checkout'])
        total_issues = sum(r['total_issues'] for r in self.results.values())

        summary_results = {
            'scan_type': 'multi_version_generated_checker',
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
        with open('results/multi_version_scan_results.json', 'w') as f:
            json.dump(summary_results, f, indent=2)
        
        # Generate report
        self._generate_multi_version_report(summary_results)
        
        print(f"\n{'='*60}")
        print("MULTI-VERSION SCAN SUMMARY")
        print(f"{'='*60}")
        print(f"Versions scanned: {scanned_versions}/{total_versions}")
        print(f"Total issues found: {total_issues}")
        print(f"Results saved to: results/multi_version_scan_results.json")
        print(f"Report saved to: results/multi_version_scan_report.md")
    
    def _generate_multi_version_report(self, results):
        """Generate comprehensive multi-version report for AI revision feedback"""
        import datetime
        report = []

        # Header with metadata for AI processing
        report.append("# Multi-Version Memory Safety Analysis Report")
        report.append("## Report Metadata for AI Revision")
        report.append("```yaml")
        report.append(f"scan_date: {datetime.datetime.now().isoformat()}")
        report.append(f"scan_type: multi_version_memory_safety")
        report.append(f"target_patterns: [use_after_free, double_free, null_dereference]")
        report.append(f"versions_analyzed: {results['versions_scanned']}")
        report.append(f"total_findings: {results['total_issues_found']}")
        report.append(f"confidence_threshold: medium")
        report.append("```")
        report.append("")

        # Executive Summary for quick understanding
        report.append("## Executive Summary")
        report.append("")
        report.append(f"- **Total Versions Scanned**: {results['versions_scanned']}/{len(results['versions_requested'])}")
        report.append(f"- **Total Issues Found**: {results['total_issues_found']}")
        report.append(f"- **Detection Rate**: {results['total_issues_found'] / max(results['versions_scanned'], 1):.2f} issues/version")
        report.append(f"- **Affected Subsystems**: Multiple kernel subsystems analyzed")
        report.append("")

        # Pattern Analysis Section
        report.append("## Pattern Analysis Statistics")
        report.append("")
        pattern_stats = self._analyze_pattern_distribution(results)
        report.append("### Issue Type Distribution")
        report.append("```")
        for pattern_type, count in pattern_stats.items():
            percentage = (count / max(results['total_issues_found'], 1)) * 100
            report.append(f"{pattern_type}: {count} ({percentage:.1f}%)")
        report.append("```")
        report.append("")

        # Version-by-version detailed analysis
        report.append("## Detailed Version Analysis")
        report.append("")
        for version in results['versions_requested']:
            if version in results['results_by_version']:
                r = results['results_by_version'][version]
                status = r['status']
                issues = r['total_issues']
                scan_method = "checkout" if status == "scanned" else "git show (no checkout)"

                report.append(f"### Version: {version}")
                report.append(f"**Status**: {status}")
                report.append(f"**Scan Method**: {scan_method}")
                report.append(f"**Total Issues**: {issues}")
                report.append("")

                if issues > 0:
                    # Group issues by file and type for better analysis
                    file_issues = self._group_issues_by_file(r)

                    report.append("#### Affected Files Summary")
                    for file_path, file_data in list(file_issues.items())[:5]:  # Top 5 files
                        report.append(f"- `{file_path}`: {file_data['count']} issues")
                        for issue_type in file_data['types']:
                            report.append(f"  - {issue_type}")
                    report.append("")
            else:
                report.append(f"### Version: {version}")
                report.append("**Status**: Failed to scan")
                report.append("")
        
        # Critical Findings Section for AI attention
        report.append("## Critical Findings for Checker Revision")
        report.append("")
        report.append("### High-Priority Patterns Detected")
        critical_issues = self._extract_critical_issues(results)
        for idx, issue in enumerate(critical_issues[:10], 1):
            report.append(f"{idx}. **{issue['type']}** in `{issue['file']}`")
            report.append(f"   - Line: {issue['line']}")
            report.append(f"   - Severity: {issue.get('severity', 'unknown')}")
            report.append(f"   - Pattern: {issue['message'][:100]}...")
            report.append("")

        # Recommendations for Checker Improvement
        report.append("## AI Revision Recommendations")
        report.append("")
        report.append("### Pattern Detection Improvements Needed")
        report.append("Based on the scan results, consider the following improvements:")
        report.append("")

        recommendations = self._generate_recommendations(results)
        for rec in recommendations:
            report.append(f"- {rec}")
        report.append("")

        # False Positive Analysis
        report.append("### Potential False Positives")
        report.append("The following patterns may need refinement to reduce false positives:")
        report.append("")
        false_positive_analysis = self._analyze_false_positives(results)
        for analysis in false_positive_analysis:
            report.append(f"- {analysis}")
        report.append("")

        # Code Context Examples (for AI learning)
        report.append("## Code Context Examples")
        report.append("")
        report.append("### Sample Detection Contexts")
        report.append("```c")
        report.append("// Example patterns that triggered detection:")
        sample_contexts = self._get_sample_contexts(results)
        for context in sample_contexts[:3]:
            report.append(context)
        report.append("```")
        report.append("")

        # Metrics for Iterative Improvement
        report.append("## Performance Metrics for Revision")
        report.append("")
        report.append("### Detection Efficiency")
        report.append(f"- Files Scanned: ~{results['versions_scanned'] * 50}")
        report.append(f"- Issues Found: {results['total_issues_found']}")
        report.append(f"- Detection Density: {results['total_issues_found'] / max(results['versions_scanned'] * 50, 1):.4f}")
        report.append("")

        report.append("### Pattern Coverage")
        report.append("- Use-After-Free: Detected")
        report.append("- Double Free: Detected")
        report.append("- NULL Dereference: Partial")
        report.append("- Buffer Overflow: Not in current checker")
        report.append("- Race Conditions: Not implemented")
        report.append("")

        # Revision Prompt Template
        report.append("## Revision Prompt for Next Iteration")
        report.append("")
        report.append("```markdown")
        report.append("Based on this analysis:")
        report.append(f"1. Current detection rate: {results['total_issues_found'] / max(results['versions_scanned'], 1):.2f} issues/version")
        report.append("2. Most common pattern: " + (list(pattern_stats.keys())[0] if pattern_stats else "unknown"))
        report.append("3. False positive indicators: Check for common initialization patterns")
        report.append("4. Missing coverage: Buffer overflows, race conditions")
        report.append("")
        report.append("Please revise the checker to:")
        report.append("- Reduce false positives in allocation checks")
        report.append("- Add buffer overflow detection")
        report.append("- Improve context awareness for free operations")
        report.append("```")
        report.append("")

        # Save comprehensive report
        report_text = '\n'.join(report)

        with open('results/multi_version_scan_report.md', 'w') as f:
            f.write(report_text)

        # Also save a revision-specific JSON for programmatic access
        revision_data = {
            'metadata': {
                'scan_date': str(datetime.datetime.now()),
                'versions_scanned': results['versions_scanned'],
                'total_issues': results['total_issues_found']
            },
            'pattern_distribution': pattern_stats,
            'critical_issues': critical_issues[:10],
            'recommendations': recommendations,
            'metrics': {
                'detection_rate': results['total_issues_found'] / max(results['versions_scanned'], 1),
                'files_per_version': 50,
                'patterns_detected': list(pattern_stats.keys())
            }
        }

        with open('results/revision_feedback.json', 'w') as f:
            json.dump(revision_data, f, indent=2)

    def _analyze_pattern_distribution(self, results):
        """Analyze distribution of pattern types across all issues"""
        pattern_stats = {}
        for version_data in results['results_by_version'].values():
            for issues_list in ['pattern_issues', 'clang_issues']:
                if issues_list in version_data:
                    for issue in version_data[issues_list]:
                        issue_type = issue.get('type', 'unknown')
                        pattern_stats[issue_type] = pattern_stats.get(issue_type, 0) + 1
        return dict(sorted(pattern_stats.items(), key=lambda x: x[1], reverse=True))

    def _group_issues_by_file(self, version_result):
        """Group issues by file for better analysis"""
        file_issues = {}
        for issues_list in ['pattern_issues', 'clang_issues']:
            if issues_list in version_result:
                for issue in version_result[issues_list]:
                    file_path = issue.get('file', 'unknown')
                    if file_path not in file_issues:
                        file_issues[file_path] = {'count': 0, 'types': set()}
                    file_issues[file_path]['count'] += 1
                    file_issues[file_path]['types'].add(issue.get('type', 'unknown'))

        # Sort by count
        return dict(sorted(file_issues.items(), key=lambda x: x[1]['count'], reverse=True))

    def _extract_critical_issues(self, results):
        """Extract critical issues for revision focus"""
        critical_issues = []
        for version_data in results['results_by_version'].values():
            for issues_list in ['pattern_issues', 'clang_issues']:
                if issues_list in version_data:
                    for issue in version_data[issues_list]:
                        if issue.get('severity', 'medium') in ['high', 'critical']:
                            critical_issues.append(issue)

        # Sort by severity and type
        return sorted(critical_issues, key=lambda x: (x.get('severity', 'z'), x.get('type', 'z')))

    def _generate_recommendations(self, results):
        """Generate recommendations for checker improvement"""
        recommendations = []
        pattern_stats = self._analyze_pattern_distribution(results)

        # Analyze patterns
        if 'missing_null_check' in pattern_stats and pattern_stats['missing_null_check'] > 10:
            recommendations.append("High number of missing NULL checks - consider contextual analysis to reduce false positives")

        if 'potential_use_after_free' in pattern_stats:
            recommendations.append("Use-after-free patterns detected - enhance tracking of variable lifecycle")

        if results['total_issues_found'] == 0:
            recommendations.append("No issues detected - checker patterns may be too restrictive")
        elif results['total_issues_found'] > 500:
            recommendations.append("Very high issue count - possible false positive problem, refine detection patterns")

        # Check detection density
        detection_rate = results['total_issues_found'] / max(results['versions_scanned'], 1)
        if detection_rate > 100:
            recommendations.append("Excessive detection rate - implement confidence scoring")

        recommendations.append("Consider adding context-aware filtering for common safe patterns")
        recommendations.append("Implement cross-function analysis for better accuracy")

        return recommendations

    def _analyze_false_positives(self, results):
        """Analyze potential false positives"""
        analysis = []
        pattern_stats = self._analyze_pattern_distribution(results)

        for pattern_type, count in pattern_stats.items():
            if count > 50:
                analysis.append(f"{pattern_type}: High count ({count}) may indicate over-detection")

        analysis.append("Check for defensive coding patterns being flagged incorrectly")
        analysis.append("Verify initialization sequences are properly recognized")

        return analysis

    def _get_sample_contexts(self, results):
        """Get sample code contexts for AI learning"""
        contexts = []
        sample_count = 0

        for version_data in results['results_by_version'].values():
            if 'pattern_issues' in version_data:
                for issue in version_data['pattern_issues']:
                    if sample_count >= 3:
                        break
                    context = f"// File: {issue['file']}, Line: {issue['line']}\n"
                    context += f"// Pattern: {issue['type']}\n"
                    context += f"// Detection: {issue['message'][:80]}"
                    contexts.append(context)
                    sample_count += 1

        if not contexts:
            contexts.append("// No specific patterns captured in this scan")

        return contexts

def main():
    """Main function for multi-version scanning"""
    scanner = MultiVersionCheckerScanner()
    
    print("Starting multi-version scan with generated checker...")
    results = scanner.run_multi_version_scan()
    
    if results:
        total_issues = sum(r['total_issues'] for r in results.values())
        if total_issues > 0:
            print(f"\n[SUCCESS] Found {total_issues} potential vulnerabilities across versions!")
        else:
            print(f"\n[INFO] No issues found across {len(results)} kernel versions")
        return 0
    else:
        print("\n[ERROR] Multi-version scan failed")
        return 1

if __name__ == "__main__":
    exit(main())