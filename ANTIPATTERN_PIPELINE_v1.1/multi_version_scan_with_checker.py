#!/usr/bin/env python3
"""
Multi-version scanner that applies generated checker across multiple Linux kernel versions
This replaces the single-version scanner in v1.1 to provide historical analysis
"""

import os
import json
import subprocess
import tempfile
from pathlib import Path

class MultiVersionCheckerScanner:
    def __init__(self, kernel_path="../../linux"):
        self.kernel_path = Path(kernel_path)
        self.results = {}
        # Use commits around the vulnerability instead of version tags
        self.versions_to_scan = [
            '80af3745ca465c6c47e833c1902004a7fa944f37^',  # Parent (vulnerable)
            '80af3745ca465c6c47e833c1902004a7fa944f37',   # Fix commit
            'HEAD~10',  # 10 commits back
            'HEAD~5',   # 5 commits back  
            'HEAD'      # Current HEAD
        ]
        
    def checkout_version(self, version):
        """Checkout a specific kernel version"""
        print(f"Checking out version {version}...")
        try:
            # First, stash any local changes
            stash_cmd = ['git', 'stash', 'push', '-m', f'temp_stash_for_{version}']
            subprocess.run(stash_cmd, cwd=self.kernel_path, capture_output=True, text=True)
            
            # Then checkout the version
            cmd = ['git', 'checkout', version]
            result = subprocess.run(cmd, cwd=self.kernel_path, capture_output=True, text=True)
            if result.returncode == 0:
                print(f"Successfully checked out {version}")
                return True
            else:
                print(f"Failed to checkout {version}: {result.stderr}")
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
        """Detect use-after-free patterns in source code"""
        issues = []
        lines = content.split('\n')
        
        for i, line in enumerate(lines, 1):
            # Look for conditional free patterns
            if 'free(' in line and ('if' in line or 'ret' in line):
                # Check subsequent lines for pointer usage
                for j in range(i, min(i + 10, len(lines))):
                    next_line = lines[j]
                    if '->' in next_line and 'free' not in next_line:
                        issues.append({
                            'file': file_path,
                            'line': i,
                            'type': 'potential_use_after_free',
                            'message': f'Potential use-after-free: free at line {i}, use at line {j+1}',
                            'analyzer': 'pattern_detection'
                        })
                        break
        
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
            
            if not self.checkout_version(version):
                self.results[version] = {
                    'status': 'checkout_failed',
                    'clang_issues': [],
                    'pattern_issues': [],
                    'total_issues': 0
                }
                continue
            
            # Scan with both methods
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
            print(f"  Clang issues: {len(clang_results)}")
            print(f"  Pattern issues: {len(pattern_results)}")
            print(f"  Total issues: {len(clang_results) + len(pattern_results)}")
        
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
        scanned_versions = sum(1 for r in self.results.values() if r['status'] == 'scanned')
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
                'failed_versions': [v for v, r in self.results.items() if r['status'] != 'scanned']
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
        """Generate human-readable multi-version report"""
        report = []
        report.append("# Multi-Version Generated Checker Scan Report")
        report.append("=" * 50)
        report.append("")
        report.append(f"**Scan Date**: {__import__('datetime').datetime.now()}")
        report.append(f"**Versions Requested**: {len(results['versions_requested'])}")
        report.append(f"**Versions Successfully Scanned**: {results['versions_scanned']}")
        report.append(f"**Total Issues Found**: {results['total_issues_found']}")
        report.append("")
        
        report.append("## Version Summary")
        report.append("")
        for version in results['versions_requested']:
            if version in results['results_by_version']:
                r = results['results_by_version'][version]
                status = r['status']
                issues = r['total_issues']
                report.append(f"- **{version}**: {status} - {issues} issues")
            else:
                report.append(f"- **{version}**: not scanned")
        report.append("")
        
        if results['summary']['vulnerable_versions']:
            report.append("## Vulnerable Versions")
            report.append("")
            for version in results['summary']['vulnerable_versions']:
                r = results['results_by_version'][version]
                report.append(f"### {version}")
                report.append(f"- Clang issues: {len(r['clang_issues'])}")
                report.append(f"- Pattern issues: {len(r['pattern_issues'])}")
                
                # Show sample issues
                for issue in r['clang_issues'][:3]:
                    report.append(f"  - {issue['message']}")
                for issue in r['pattern_issues'][:3]:
                    report.append(f"  - {issue['message']}")
                report.append("")
        
        report_text = '\n'.join(report)
        
        with open('results/multi_version_scan_report.md', 'w') as f:
            f.write(report_text)

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