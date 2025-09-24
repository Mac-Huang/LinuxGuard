#!/usr/bin/env python3
"""
Clang Static Analyzer with Physical File Support
Demonstrates proper usage of Clang Static Analyzer
"""

import os
import subprocess
import tempfile
import shutil
from pathlib import Path
import json

class ClangPhysicalAnalyzer:
    def __init__(self):
        self.clang_path = self.find_clang()
        self.scan_build_path = self.find_scan_build()
        self.results = []

    def find_clang(self):
        """Find clang executable"""
        # Try common locations
        paths = [
            "clang",  # System PATH
            "D:/LLVM/bin/clang.exe",  # Windows LLVM
            "/usr/bin/clang",  # Linux
            "C:/Program Files/LLVM/bin/clang.exe",  # Windows default
        ]

        for path in paths:
            try:
                result = subprocess.run([path, "--version"],
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    print(f"[OK] Found clang: {path}")
                    return path
            except:
                continue

        print("[WARNING] Clang not found")
        return None

    def find_scan_build(self):
        """Find scan-build tool"""
        paths = [
            "scan-build",  # System PATH
            "D:/LLVM/bin/scan-build",  # Windows
            "/usr/bin/scan-build",  # Linux
        ]

        for path in paths:
            if Path(path).exists() or shutil.which(path):
                print(f"[OK] Found scan-build: {path}")
                return path

        print("[INFO] scan-build not found (optional)")
        return None

    def analyze_physical_file(self, file_path):
        """Analyze a physical C file with Clang Static Analyzer"""
        if not self.clang_path:
            return None

        print(f"Analyzing: {file_path}")

        # Run clang static analyzer
        cmd = [
            self.clang_path,
            "--analyze",
            "-Xclang", "-analyzer-checker=core",           # Core checkers
            "-Xclang", "-analyzer-checker=unix",           # Unix checkers
            "-Xclang", "-analyzer-checker=security",       # Security checkers
            "-Xclang", "-analyzer-checker=alpha.security", # Alpha security
            "-Xclang", "-analyzer-output=text",            # Text output
            str(file_path)
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)

        # Parse output
        issues = []
        if result.stderr:
            lines = result.stderr.split('\n')
            for line in lines:
                if 'warning:' in line or 'error:' in line:
                    issues.append(line.strip())

        return {
            'file': str(file_path),
            'issues': issues,
            'return_code': result.returncode
        }

    def analyze_with_scan_build(self, source_dir):
        """Use scan-build for comprehensive analysis with HTML report"""
        if not self.scan_build_path:
            print("[INFO] scan-build not available")
            return None

        output_dir = Path("scan-results")
        output_dir.mkdir(exist_ok=True)

        # Run scan-build
        cmd = [
            self.scan_build_path,
            "-o", str(output_dir),
            "-enable-checker", "security",
            "-enable-checker", "unix",
            "clang", "-c", f"{source_dir}/*.c"
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, shell=True)

        print(f"scan-build results saved to: {output_dir}")
        return result.returncode == 0

    def analyze_directory(self, directory):
        """Analyze all C files in a directory"""
        directory = Path(directory)
        c_files = list(directory.glob("**/*.c"))

        print(f"Found {len(c_files)} C files to analyze")

        results = []
        for c_file in c_files:
            result = self.analyze_physical_file(c_file)
            if result:
                results.append(result)
                if result['issues']:
                    print(f"  Found {len(result['issues'])} issues in {c_file.name}")

        return results

    def create_test_files(self):
        """Create test C files with vulnerabilities"""
        test_dir = Path("test_clang")
        test_dir.mkdir(exist_ok=True)

        # Buffer overflow example
        buffer_overflow = """
#include <stdio.h>
#include <string.h>

void vulnerable_buffer() {
    char buffer[10];
    char *input = "This is a very long string that will overflow";
    strcpy(buffer, input);  // Buffer overflow
}

void safe_buffer() {
    char buffer[10];
    char *input = "short";
    strncpy(buffer, input, sizeof(buffer)-1);
    buffer[sizeof(buffer)-1] = '\\0';
}
"""

        # Use after free example
        use_after_free = """
#include <stdlib.h>

void use_after_free_bug() {
    int *ptr = (int*)malloc(sizeof(int));
    *ptr = 42;
    free(ptr);
    *ptr = 10;  // Use after free
}

void null_deref_bug() {
    int *p = NULL;
    *p = 5;  // Null pointer dereference
}
"""

        # Memory leak example
        memory_leak = """
#include <stdlib.h>

void memory_leak() {
    int *leak = (int*)malloc(100 * sizeof(int));
    // Missing free(leak)
    return;  // Memory leak
}

int divide_by_zero(int x) {
    return x / 0;  // Division by zero
}
"""

        # Write test files
        (test_dir / "buffer_overflow.c").write_text(buffer_overflow)
        (test_dir / "use_after_free.c").write_text(use_after_free)
        (test_dir / "memory_leak.c").write_text(memory_leak)

        print(f"[OK] Created test files in {test_dir}")
        return test_dir

    def run_comparison(self):
        """Compare different Clang checker configurations"""
        test_dir = self.create_test_files()

        configurations = [
            {
                'name': 'Core Only',
                'checkers': ['-analyzer-checker=core']
            },
            {
                'name': 'Security Focus',
                'checkers': ['-analyzer-checker=security',
                           '-analyzer-checker=alpha.security']
            },
            {
                'name': 'Unix + Memory',
                'checkers': ['-analyzer-checker=unix',
                           '-analyzer-checker=cplusplus']
            },
            {
                'name': 'All Standard',
                'checkers': ['-analyzer-checker=core,unix,security,deadcode']
            }
        ]

        results_comparison = {}

        for config in configurations:
            print(f"\nTesting configuration: {config['name']}")

            issues_found = 0
            for c_file in test_dir.glob("*.c"):
                cmd = [self.clang_path, "--analyze"]
                for checker in config['checkers']:
                    cmd.extend(["-Xclang", checker])
                cmd.append(str(c_file))

                result = subprocess.run(cmd, capture_output=True, text=True)
                issues = len([l for l in result.stderr.split('\n')
                            if 'warning:' in l])
                issues_found += issues

            results_comparison[config['name']] = issues_found
            print(f"  Found {issues_found} issues")

        return results_comparison

def main():
    """Demonstrate Clang Static Analyzer usage"""
    print("="*70)
    print("CLANG STATIC ANALYZER - PHYSICAL FILE DEMONSTRATION")
    print("="*70)

    analyzer = ClangPhysicalAnalyzer()

    # Check if Clang is available
    if not analyzer.clang_path:
        print("\n[ERROR] Clang not installed. Install LLVM to use this feature.")
        print("\nInstallation instructions:")
        print("  Windows: winget install LLVM.LLVM")
        print("  Linux: sudo apt install clang llvm")
        return

    # Run analysis on test files
    print("\n[1/3] Creating test files with vulnerabilities...")
    test_dir = analyzer.create_test_files()

    print("\n[2/3] Running Clang Static Analyzer...")
    results = analyzer.analyze_directory(test_dir)

    # Show results
    print("\n[3/3] Analysis Results:")
    print("-"*70)

    total_issues = 0
    for result in results:
        if result['issues']:
            print(f"\nFile: {Path(result['file']).name}")
            for issue in result['issues']:
                print(f"  - {issue}")
                total_issues += 1

    print(f"\nTotal issues found: {total_issues}")

    # Compare configurations
    print("\n" + "="*70)
    print("CHECKER CONFIGURATION COMPARISON")
    print("="*70)

    comparison = analyzer.run_comparison()

    print("\nResults by Configuration:")
    for config, count in comparison.items():
        print(f"  {config:20} : {count} issues")

    # Save results
    results_file = Path("clang_analysis_results.json")
    with open(results_file, 'w') as f:
        json.dump({
            'analyzer': 'clang',
            'test_results': results,
            'comparison': comparison
        }, f, indent=2)

    print(f"\n[OK] Results saved to: {results_file}")

if __name__ == "__main__":
    main()