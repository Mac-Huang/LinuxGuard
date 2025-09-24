#!/usr/bin/env python3
"""
Comprehensive version scanner that finds both vulnerable and fixed versions
"""

import os
import json
import subprocess
from pathlib import Path
from datetime import datetime

class ComprehensiveVersionScanner:
    def __init__(self, kernel_path="../../linux"):
        self.kernel_path = Path(kernel_path)
        self.results = {}
        self.fix_commit = "80af3745ca465c6c47e833c1902004a7fa944f37"
        
    def get_versions_around_fix(self):
        """Get kernel versions before and after the fix"""
        os.chdir(self.kernel_path)
        
        # Get commit date of the fix
        cmd = ["git", "show", "-s", "--format=%ci", self.fix_commit]
        result = subprocess.run(cmd, capture_output=True, text=True)
        fix_date = result.stdout.strip()
        print(f"Fix commit date: {fix_date}")
        
        # Get tags before and after the fix
        cmd = ["git", "tag", "--sort=version:refname", "-l", "v6.*"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        all_tags = result.stdout.strip().split('\n')
        
        # Filter out rc/beta versions
        stable_tags = [tag for tag in all_tags if '-rc' not in tag and tag.startswith('v6.')]
        
        # Find the fix commit's position relative to tags
        versions_to_test = []
        
        # Add some older versions (likely vulnerable)
        older_versions = ['v6.9', 'v6.10', 'v6.11']
        
        # Add recent versions (likely fixed) 
        newer_versions = ['v6.12', 'v6.13', 'v6.14', 'v6.15']
        
        # Combine and filter for existing tags
        test_versions = []
        for version in older_versions + newer_versions:
            if version in stable_tags:
                test_versions.append(version)
        
        # Also add specific commits around the fix
        specific_commits = [
            (f"{self.fix_commit}^", "Parent of fix (vulnerable)"),
            (self.fix_commit, "Fix commit itself"),
            (f"{self.fix_commit}~5", "5 commits before fix"),
            (f"{self.fix_commit}~10", "10 commits before fix")
        ]
        
        print(f"Selected versions to test: {test_versions}")
        print(f"Specific commits to test: {[c[0] for c in specific_commits]}")
        
        return test_versions, specific_commits
    
    def scan_version(self, version, description=None):
        """Scan a specific version/commit"""
        print(f"\nScanning {version} {f'({description})' if description else ''}")
        
        try:
            os.chdir(self.kernel_path)
            
            # Checkout the version
            cmd = ["git", "checkout", version]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                return {
                    'version': version,
                    'status': 'checkout_failed',
                    'error': result.stderr,
                    'description': description
                }
            
            # Check target file
            target_file = self.kernel_path / "drivers/of/dynamic.c"
            if not target_file.exists():
                return {
                    'version': version,
                    'status': 'file_not_found',
                    'description': description
                }
            
            # Analyze the function
            analysis = self._analyze_changeset_function(target_file)
            
            # Run clang if available
            clang_results = self._run_clang_check(target_file)
            
            return {
                'version': version,
                'status': 'analyzed',
                'description': description,
                'function_analysis': analysis,
                'clang_results': clang_results,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                'version': version,
                'status': 'error',
                'error': str(e),
                'description': description
            }
    
    def _analyze_changeset_function(self, file_path):
        """Detailed analysis of the changeset function"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            return {'error': f'Could not read file: {e}'}
        
        lines = content.split('\n')
        
        # Find function start
        func_start = -1
        for i, line in enumerate(lines):
            if "of_changeset_add_prop_helper" in line and "static int" in line:
                func_start = i
                break
        
        if func_start == -1:
            return {'function_found': False, 'error': 'Function not found'}
        
        # Extract function
        func_lines = []
        brace_count = 0
        in_function = False
        
        for i in range(func_start, min(func_start + 100, len(lines))):
            line = lines[i]
            func_lines.append((i+1, line))  # Store line number
            
            if '{' in line:
                brace_count += line.count('{')
                in_function = True
            if '}' in line:
                brace_count -= line.count('}')
                if in_function and brace_count == 0:
                    break
        
        # Analyze the pattern in detail
        return self._detailed_pattern_analysis(func_lines)
    
    def _detailed_pattern_analysis(self, func_lines):
        """Detailed analysis of use-after-free pattern"""
        analysis = {
            'function_found': True,
            'total_lines': len(func_lines),
            'has_conditional_free': False,
            'has_member_access': False,
            'has_early_return_after_free': False,
            'pattern_details': {},
            'vulnerability_status': 'UNKNOWN'
        }
        
        free_line_num = None
        member_access_lines = []
        return_after_free = False
        
        # Analyze each line
        for line_num, line in func_lines:
            line_stripped = line.strip()
            
            # Look for conditional free
            if ('if' in line_stripped and '__of_prop_free' in line_stripped):
                analysis['has_conditional_free'] = True
                free_line_num = line_num
                analysis['pattern_details']['free_line'] = {
                    'line_num': line_num,
                    'content': line_stripped
                }
            
            # Look for member access to new_pp
            if 'new_pp->' in line_stripped:
                analysis['has_member_access'] = True
                member_access_lines.append({
                    'line_num': line_num,
                    'content': line_stripped
                })
            
            # Look for return after free
            if (free_line_num and line_num > free_line_num and 
                'return' in line_stripped and 'ret' in line_stripped):
                return_after_free = True
                analysis['pattern_details']['early_return'] = {
                    'line_num': line_num,
                    'content': line_stripped
                }
        
        analysis['pattern_details']['member_access_lines'] = member_access_lines
        analysis['has_early_return_after_free'] = return_after_free
        
        # Determine vulnerability status
        if analysis['has_conditional_free'] and analysis['has_member_access']:
            if free_line_num and member_access_lines:
                # Check if member access happens after free without early return
                has_access_after_free = any(
                    access['line_num'] > free_line_num 
                    for access in member_access_lines
                )
                
                if has_access_after_free and not return_after_free:
                    analysis['vulnerability_status'] = 'VULNERABLE'
                elif return_after_free:
                    analysis['vulnerability_status'] = 'FIXED'
                else:
                    analysis['vulnerability_status'] = 'UNCLEAR'
        else:
            analysis['vulnerability_status'] = 'NO_PATTERN'
        
        return analysis
    
    def _run_clang_check(self, file_path):
        """Run clang static analyzer"""
        try:
            cmd = [
                'clang', '--analyze',
                '-Xanalyzer', '-analyzer-checker=core,unix.Malloc',
                '-Xanalyzer', '-analyzer-output=text',
                str(file_path)
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            warnings = []
            if result.stderr:
                for line in result.stderr.split('\n'):
                    if ('warning:' in line and 
                        ('memory' in line.lower() or 'freed' in line.lower())):
                        warnings.append(line.strip())
            
            return {
                'warnings_found': len(warnings),
                'warnings': warnings,
                'exit_code': result.returncode
            }
            
        except Exception as e:
            return {'error': f'Clang check failed: {e}'}
    
    def run_comprehensive_scan(self):
        """Run comprehensive scan of multiple versions"""
        print("Comprehensive Linux Kernel Version Scanner")
        print("Target: Use-after-free in of_changeset_add_prop_helper")
        print("="*60)
        
        versions, commits = self.get_versions_around_fix()
        
        original_branch = self._get_current_branch()
        
        # Scan versions
        for version in versions:
            result = self.scan_version(version)
            self.results[version] = result
            self._print_result_summary(result)
        
        # Scan specific commits
        for commit, description in commits:
            result = self.scan_version(commit, description)
            self.results[commit] = result
            self._print_result_summary(result)
        
        # Restore original branch
        if original_branch:
            self._restore_branch(original_branch)
        
        return self.results
    
    def _print_result_summary(self, result):
        """Print summary of scan result"""
        version = result['version']
        desc = result.get('description', '')
        
        if result['status'] != 'analyzed':
            print(f"  [{version}] {desc}: {result.get('error', 'Error')}")
            return
        
        analysis = result.get('function_analysis', {})
        vuln_status = analysis.get('vulnerability_status', 'UNKNOWN')
        
        print(f"  [{version}] {desc}:")
        print(f"    Status: {vuln_status}")
        
        if vuln_status == 'VULNERABLE':
            print(f"    *** USE-AFTER-FREE DETECTED ***")
        elif vuln_status == 'FIXED':
            print(f"    *** VULNERABILITY FIXED ***")
        
        # Show pattern details
        details = analysis.get('pattern_details', {})
        if 'free_line' in details:
            print(f"    Free line: {details['free_line']['line_num']}")
        if 'member_access_lines' in details:
            access_count = len(details['member_access_lines'])
            if access_count > 0:
                print(f"    Member accesses: {access_count} found")
    
    def _get_current_branch(self):
        """Get current git branch"""
        try:
            os.chdir(self.kernel_path)
            cmd = ["git", "branch", "--show-current"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.stdout.strip() if result.returncode == 0 else None
        except:
            return None
    
    def _restore_branch(self, branch):
        """Restore original branch"""
        try:
            os.chdir(self.kernel_path)
            cmd = ["git", "checkout", branch]
            subprocess.run(cmd, capture_output=True, text=True)
            print(f"Restored to branch: {branch}")
        except:
            print("Could not restore original branch")
    
    def save_results(self):
        """Save results to file"""
        results_path = Path("results") / "comprehensive_scan_results.json"
        results_path.parent.mkdir(exist_ok=True)
        
        # Categorize results
        vulnerable = []
        fixed = []
        unclear = []
        
        for version, result in self.results.items():
            if result['status'] == 'analyzed':
                status = result['function_analysis'].get('vulnerability_status')
                if status == 'VULNERABLE':
                    vulnerable.append(version)
                elif status == 'FIXED':
                    fixed.append(version)
                else:
                    unclear.append(version)
        
        summary = {
            'scan_type': 'comprehensive_version_scan',
            'target_vulnerability': 'use_after_free_changeset_helper',
            'fix_commit': self.fix_commit,
            'total_scanned': len(self.results),
            'vulnerable_versions': len(vulnerable),
            'fixed_versions': len(fixed),
            'unclear_versions': len(unclear),
            'categorized_results': {
                'vulnerable': vulnerable,
                'fixed': fixed,
                'unclear': unclear
            },
            'detailed_results': self.results,
            'timestamp': datetime.now().isoformat()
        }
        
        with open(results_path, 'w') as f:
            json.dump(summary, f, indent=2)
        
        print(f"\nDetailed results saved to: {results_path}")
        
        # Generate summary report
        self._generate_summary_report(summary)
        
        return results_path
    
    def _generate_summary_report(self, summary):
        """Generate human-readable summary report"""
        report_lines = []
        report_lines.append("# Comprehensive Linux Kernel Vulnerability Scan Results")
        report_lines.append("="*60)
        report_lines.append("")
        report_lines.append(f"**Target**: Use-after-free in of_changeset_add_prop_helper")
        report_lines.append(f"**Fix Commit**: {self.fix_commit}")
        report_lines.append(f"**Total Versions Scanned**: {summary['total_scanned']}")
        report_lines.append("")
        
        report_lines.append("## Summary")
        report_lines.append(f"- **Vulnerable versions found**: {summary['vulnerable_versions']}")
        report_lines.append(f"- **Fixed versions found**: {summary['fixed_versions']}")
        report_lines.append(f"- **Unclear/Error versions**: {summary['unclear_versions']}")
        report_lines.append("")
        
        # Vulnerable versions
        if summary['categorized_results']['vulnerable']:
            report_lines.append("## Vulnerable Versions")
            for version in summary['categorized_results']['vulnerable']:
                result = self.results[version]
                desc = result.get('description', '')
                report_lines.append(f"- **{version}** {desc}")
                
                analysis = result['function_analysis']
                details = analysis.get('pattern_details', {})
                
                if 'free_line' in details:
                    report_lines.append(f"  - Conditional free at line {details['free_line']['line_num']}")
                if 'member_access_lines' in details:
                    for access in details['member_access_lines']:
                        report_lines.append(f"  - Use-after-free at line {access['line_num']}: {access['content']}")
                report_lines.append("")
        
        # Fixed versions
        if summary['categorized_results']['fixed']:
            report_lines.append("## Fixed Versions")
            for version in summary['categorized_results']['fixed']:
                result = self.results[version]
                desc = result.get('description', '')
                report_lines.append(f"- **{version}** {desc}")
                report_lines.append(f"  - Early return prevents use-after-free")
                report_lines.append("")
        
        report_text = '\n'.join(report_lines)
        
        # Save report
        report_path = Path("results") / "comprehensive_scan_report.md"
        with open(report_path, 'w') as f:
            f.write(report_text)
        
        print(f"Summary report saved to: {report_path}")
        
        # Print summary to console
        print(f"\n{'='*60}")
        print("FINAL RESULTS SUMMARY")
        print(f"{'='*60}")
        print(f"Vulnerable versions: {summary['vulnerable_versions']}")
        print(f"Fixed versions: {summary['fixed_versions']}")
        print(f"Total scanned: {summary['total_scanned']}")
        
        if summary['categorized_results']['vulnerable']:
            print(f"\nVulnerable versions found:")
            for version in summary['categorized_results']['vulnerable']:
                desc = self.results[version].get('description', '')
                print(f"  - {version} {desc}")

def main():
    """Main function"""
    scanner = ComprehensiveVersionScanner()
    results = scanner.run_comprehensive_scan()
    
    if results:
        scanner.save_results()
        return 0
    else:
        print("No results generated")
        return 1

if __name__ == "__main__":
    exit(main())