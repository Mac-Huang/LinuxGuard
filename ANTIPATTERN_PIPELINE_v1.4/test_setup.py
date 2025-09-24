#!/usr/bin/env python3
"""
Comprehensive Test Runner for ANTIPATTERN_PIPELINE v1.4
Tests all components and provides a full system check
"""

import os
import sys
import json
import subprocess
from pathlib import Path
from datetime import datetime

class PipelineTestRunner:
    def __init__(self):
        self.test_results = {}
        self.passed = 0
        self.failed = 0
        self.warnings = 0

    def test_environment(self):
        """Test that basic environment is set up"""
        print("\n=== Testing Environment ===")
        tests = []

        # Test Python version
        py_version = f"{sys.version_info.major}.{sys.version_info.minor}"
        tests.append(("Python 3.7+", sys.version_info >= (3, 7), f"Version {py_version}"))

        # Test required directories
        dirs = ['data', 'generated', 'results', 'detectors']
        for dir_name in dirs:
            exists = Path(dir_name).exists()
            tests.append((f"Directory {dir_name}", exists, ""))

        # Test required Python packages
        packages = ['requests', 'json', 'subprocess', 'pathlib']
        for package in packages:
            try:
                __import__(package)
                tests.append((f"Package {package}", True, ""))
            except ImportError:
                tests.append((f"Package {package}", False, "Not installed"))

        return self.report_tests("Environment", tests)

    def test_api_configuration(self):
        """Test API configuration"""
        print("\n=== Testing API Configuration ===")
        tests = []

        # Check for .env file
        env_exists = Path(".env").exists()
        tests.append((".env file", env_exists, "Create .env with API_KEY"))

        # Check environment variables
        api_key = os.getenv("API_KEY") or os.getenv("MODEL_API_KEY")
        tests.append(("API Key configured", bool(api_key and api_key != "YOUR_API_KEY_HERE"),
                     "Set API_KEY in .env or environment"))

        # Check config.py
        config_exists = Path("config.py").exists()
        tests.append(("config.py exists", config_exists, ""))

        if config_exists:
            try:
                import config
                tests.append(("Config imports", True, ""))
                tests.append(("MODEL_NAME set", hasattr(config, 'MODEL_NAME'), ""))
                tests.append(("MODEL_ENDPOINT set", hasattr(config, 'MODEL_ENDPOINT'), ""))
            except Exception as e:
                tests.append(("Config imports", False, str(e)))

        return self.report_tests("API Configuration", tests)

    def test_git_repository(self):
        """Test git repository access"""
        print("\n=== Testing Git Repository ===")
        tests = []

        # Check if git is available
        try:
            result = subprocess.run(['git', '--version'], capture_output=True, text=True)
            tests.append(("Git installed", result.returncode == 0, ""))
        except FileNotFoundError:
            tests.append(("Git installed", False, "Install git"))
            return self.report_tests("Git Repository", tests)

        # Check for Linux kernel repo
        kernel_path = Path("../../../linux")
        kernel_exists = kernel_path.exists() and (kernel_path / ".git").exists()
        tests.append(("Linux kernel repo", kernel_exists,
                     "Clone with: git clone https://github.com/torvalds/linux.git ../../../linux"))

        if kernel_exists:
            # Test git operations
            try:
                result = subprocess.run(['git', 'status'], cwd=kernel_path,
                                      capture_output=True, text=True)
                tests.append(("Git operations work", result.returncode == 0, ""))
            except:
                tests.append(("Git operations work", False, "Check git setup"))

        return self.report_tests("Git Repository", tests)

    def test_clang_tools(self):
        """Test Clang/LLVM tools"""
        print("\n=== Testing Clang/LLVM Tools ===")
        tests = []

        # Check clang
        try:
            result = subprocess.run(['clang', '--version'], capture_output=True, text=True)
            tests.append(("Clang installed", result.returncode == 0, ""))
        except FileNotFoundError:
            tests.append(("Clang installed", False, "Install LLVM/Clang"))

        # Check llvm-config
        try:
            result = subprocess.run(['llvm-config', '--version'], capture_output=True, text=True)
            tests.append(("LLVM-config installed", result.returncode == 0, ""))

            # Check for development headers
            result = subprocess.run(['llvm-config', '--cxxflags'], capture_output=True, text=True)
            has_headers = result.returncode == 0 and result.stdout.strip()
            tests.append(("LLVM dev headers", has_headers, "Install llvm-dev"))
        except FileNotFoundError:
            tests.append(("LLVM-config installed", False, "Install LLVM development tools"))
            tests.append(("LLVM dev headers", False, "Install llvm-dev"))

        return self.report_tests("Clang/LLVM Tools", tests)

    def test_coccinelle(self):
        """Test Coccinelle installation"""
        print("\n=== Testing Coccinelle ===")
        tests = []

        # Check spatch
        try:
            result = subprocess.run(['spatch', '--version'], capture_output=True, text=True)
            tests.append(("Coccinelle installed", result.returncode == 0, ""))
        except FileNotFoundError:
            tests.append(("Coccinelle installed", False, "Install with: apt install coccinelle"))

        # Check semantic patches
        patches_dir = Path("detectors/semantic_patches")
        patches_exist = patches_dir.exists()
        tests.append(("Semantic patches directory", patches_exist, ""))

        if patches_exist:
            patch_files = list(patches_dir.glob("*.cocci"))
            tests.append((f"Semantic patches created", len(patch_files) > 0,
                         f"Found {len(patch_files)} patches"))

        return self.report_tests("Coccinelle", tests)

    def test_generated_checker(self):
        """Test generated checker files"""
        print("\n=== Testing Generated Checker ===")
        tests = []

        generated_dir = Path("generated")
        tests.append(("Generated directory exists", generated_dir.exists(), ""))

        if generated_dir.exists():
            # Look for checker files
            checker_files = list(generated_dir.glob("*Checker.cpp"))
            tests.append(("Checker C++ file", len(checker_files) > 0,
                         "Run model_analyzer.py and checker_generator.py"))

            if checker_files:
                # Check if compiled
                dll_files = list(generated_dir.glob("*.dll"))
                so_files = list(generated_dir.glob("*.so"))
                compiled = len(dll_files) > 0 or len(so_files) > 0
                tests.append(("Checker compiled", compiled, "Run compile_checker.py"))

        return self.report_tests("Generated Checker", tests)

    def test_detectors(self):
        """Test individual detector modules"""
        print("\n=== Testing Detector Modules ===")
        tests = []

        detector_files = [
            "detectors/pattern_detector.py",
            "detectors/coccinelle_detector.py",
            "detectors/clang_detector.py"
        ]

        for detector_file in detector_files:
            exists = Path(detector_file).exists()
            tests.append((f"{Path(detector_file).stem}", exists, ""))

            if exists:
                # Try to import
                try:
                    spec = __import__(Path(detector_file).stem)
                    tests.append((f"  - imports correctly", True, ""))
                except Exception as e:
                    tests.append((f"  - imports correctly", False, str(e)[:50]))

        return self.report_tests("Detector Modules", tests)

    def test_pipeline_scripts(self):
        """Test main pipeline scripts"""
        print("\n=== Testing Pipeline Scripts ===")
        tests = []

        scripts = [
            "pipeline_v1.4.py",
            "model_analyzer.py",
            "checker_generator.py",
            "comparative_analyzer.py",
            "compile_checker.py",
            "setup_check.py"
        ]

        for script in scripts:
            exists = Path(script).exists()
            tests.append((script, exists, ""))

        return self.report_tests("Pipeline Scripts", tests)

    def report_tests(self, category, tests):
        """Report test results for a category"""
        category_passed = 0
        category_failed = 0
        category_warnings = 0

        for test_name, passed, note in tests:
            if passed:
                print(f"  ✓ {test_name}")
                category_passed += 1
                self.passed += 1
            else:
                if note and "optional" in note.lower():
                    print(f"  ⚠ {test_name}: {note}")
                    category_warnings += 1
                    self.warnings += 1
                else:
                    print(f"  ✗ {test_name}: {note}")
                    category_failed += 1
                    self.failed += 1

        self.test_results[category] = {
            'passed': category_passed,
            'failed': category_failed,
            'warnings': category_warnings,
            'total': len(tests)
        }

        return category_passed, category_failed, category_warnings

    def generate_report(self):
        """Generate final test report"""
        print("\n" + "="*80)
        print("TEST SUMMARY REPORT")
        print("="*80)

        # Category breakdown
        print("\nBy Category:")
        print("-"*40)
        for category, results in self.test_results.items():
            status = "✓" if results['failed'] == 0 else "✗"
            print(f"{status} {category:25} {results['passed']}/{results['total']} passed")

        # Overall summary
        print("\n" + "="*80)
        print("OVERALL RESULTS:")
        print(f"  Passed:   {self.passed}")
        print(f"  Failed:   {self.failed}")
        print(f"  Warnings: {self.warnings}")
        print(f"  Total:    {self.passed + self.failed + self.warnings}")

        # Readiness assessment
        print("\n" + "="*80)
        if self.failed == 0:
            print("✅ SYSTEM READY - All tests passed!")
            print("\nYou can now run:")
            print("  python pipeline_v1.4.py")
        elif self.failed <= 3:
            print("⚠️ SYSTEM PARTIALLY READY")
            print("\nCore functionality available. You can run:")
            print("  python pipeline_v1.4.py")
            print("\nSome features may not work. Check failed tests above.")
        else:
            print("❌ SYSTEM NOT READY")
            print("\nPlease fix the failed tests before running the pipeline.")
            print("\nRun setup_check.py for detailed setup instructions.")

        # Save report
        report = {
            'timestamp': datetime.now().isoformat(),
            'results': self.test_results,
            'summary': {
                'passed': self.passed,
                'failed': self.failed,
                'warnings': self.warnings,
                'total': self.passed + self.failed + self.warnings
            }
        }

        report_file = Path('results/test_report.json')
        report_file.parent.mkdir(exist_ok=True)
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"\nDetailed report saved to: {report_file}")

    def run_all_tests(self):
        """Run all tests"""
        print("="*80)
        print("ANTIPATTERN PIPELINE v1.4 - COMPREHENSIVE TEST SUITE")
        print("="*80)

        # Run test categories
        self.test_environment()
        self.test_api_configuration()
        self.test_git_repository()
        self.test_clang_tools()
        self.test_coccinelle()
        self.test_generated_checker()
        self.test_detectors()
        self.test_pipeline_scripts()

        # Generate report
        self.generate_report()

def main():
    """Main function"""
    tester = PipelineTestRunner()
    tester.run_all_tests()

    # Return exit code based on failures
    return 1 if tester.failed > 3 else 0

if __name__ == "__main__":
    sys.exit(main())