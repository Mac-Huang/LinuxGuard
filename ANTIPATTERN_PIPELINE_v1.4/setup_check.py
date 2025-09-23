#!/usr/bin/env python3
"""
Setup Verification Script
Checks if all required tools are properly installed
"""

import subprocess
import sys
import os
from pathlib import Path
import platform

class SetupChecker:
    def __init__(self):
        self.checks = {
            'python': {'status': False, 'version': None, 'required': True},
            'git': {'status': False, 'version': None, 'required': True},
            'clang': {'status': False, 'version': None, 'required': False},
            'llvm': {'status': False, 'version': None, 'required': False},
            'coccinelle': {'status': False, 'version': None, 'required': False},
        }
        self.os_type = platform.system()
        self.warnings = []
        self.errors = []

    def check_command(self, command, version_flag='--version'):
        """Check if a command is available and get its version"""
        try:
            result = subprocess.run(
                [command, version_flag],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return True, result.stdout.strip().split('\n')[0]
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
        return False, None

    def check_python(self):
        """Check Python version and required packages"""
        print("Checking Python...")

        # Check Python version
        version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        self.checks['python']['version'] = version
        self.checks['python']['status'] = sys.version_info >= (3, 7)

        if not self.checks['python']['status']:
            self.errors.append(f"Python 3.7+ required, found {version}")

        # Check required packages
        required_packages = ['requests', 'dotenv']
        missing_packages = []

        for package in required_packages:
            try:
                __import__(package)
            except ImportError:
                missing_packages.append(package)

        if missing_packages:
            self.warnings.append(f"Missing Python packages: {', '.join(missing_packages)}")
            self.warnings.append("Install with: pip install python-dotenv requests")

    def check_git(self):
        """Check Git installation"""
        print("Checking Git...")

        status, version = self.check_command('git')
        self.checks['git']['status'] = status
        self.checks['git']['version'] = version

        if not status:
            self.errors.append("Git is not installed or not in PATH")
            self.errors.append("Install from: https://git-scm.com/downloads")

    def check_clang(self):
        """Check Clang/LLVM installation"""
        print("Checking Clang/LLVM...")

        # Check clang
        status, version = self.check_command('clang')
        self.checks['clang']['status'] = status
        self.checks['clang']['version'] = version

        if not status:
            self.warnings.append("Clang not found - Clang detector will not work")
            self.warnings.append("Install LLVM from: https://github.com/llvm/llvm-project/releases")

        # Check llvm-config
        status, version = self.check_command('llvm-config')
        self.checks['llvm']['status'] = status
        self.checks['llvm']['version'] = version

        if self.checks['clang']['status'] and not self.checks['llvm']['status']:
            self.warnings.append("LLVM development tools not found")
            self.warnings.append("Clang checker compilation will not work")

        # Check if we can get compiler flags
        if self.checks['llvm']['status']:
            try:
                result = subprocess.run(
                    ['llvm-config', '--cxxflags'],
                    capture_output=True,
                    text=True
                )
                if not result.stdout.strip():
                    self.warnings.append("LLVM development headers may not be installed")
            except:
                pass

    def check_coccinelle(self):
        """Check Coccinelle installation"""
        print("Checking Coccinelle...")

        # Try both 'spatch' and 'coccinelle'
        for cmd in ['spatch', 'coccinelle']:
            status, version = self.check_command(cmd)
            if status:
                self.checks['coccinelle']['status'] = True
                self.checks['coccinelle']['version'] = version
                break

        if not self.checks['coccinelle']['status']:
            self.warnings.append("Coccinelle not found - Semantic patch detection will not work")
            if self.os_type == "Linux":
                self.warnings.append("Install with: sudo apt install coccinelle")
            elif self.os_type == "Windows":
                self.warnings.append("Install in WSL2 with: sudo apt install coccinelle")

    def check_kernel_source(self):
        """Check if Linux kernel source is available"""
        print("Checking Linux kernel source...")

        kernel_path = Path("../../../linux")
        if kernel_path.exists() and (kernel_path / ".git").exists():
            try:
                result = subprocess.run(
                    ['git', 'status'],
                    cwd=kernel_path,
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0:
                    print("  ✓ Linux kernel source found")
                    return True
            except:
                pass

        self.warnings.append("Linux kernel source not found at ../../../linux")
        self.warnings.append("Clone with: git clone https://github.com/torvalds/linux.git ../../../linux")
        return False

    def check_directories(self):
        """Check if required directories exist"""
        print("Checking directory structure...")

        required_dirs = ['data', 'generated', 'results', 'detectors']
        missing_dirs = []

        for dir_name in required_dirs:
            if not Path(dir_name).exists():
                missing_dirs.append(dir_name)
                Path(dir_name).mkdir(exist_ok=True)

        if missing_dirs:
            print(f"  Created missing directories: {', '.join(missing_dirs)}")

    def print_report(self):
        """Print the verification report"""
        print("\n" + "="*60)
        print("SETUP VERIFICATION REPORT")
        print("="*60)
        print(f"Operating System: {self.os_type}")
        print(f"Python Version: {sys.version}")
        print("-"*60)

        # Tool status
        print("\nTool Status:")
        print("-"*40)
        for tool, info in self.checks.items():
            status = "✓" if info['status'] else "✗"
            required = "(Required)" if info['required'] else "(Optional)"
            version = info['version'] if info['version'] else "Not installed"
            print(f"{status} {tool.capitalize():12} {required:12} {version}")

        # Errors
        if self.errors:
            print("\n" + "!"*60)
            print("ERRORS (Must fix):")
            print("-"*60)
            for error in self.errors:
                print(f"  ✗ {error}")

        # Warnings
        if self.warnings:
            print("\n" + "="*60)
            print("WARNINGS (Recommended fixes):")
            print("-"*60)
            for warning in self.warnings:
                print(f"  ⚠ {warning}")

        # Summary
        print("\n" + "="*60)
        if self.errors:
            print("❌ SETUP INCOMPLETE - Fix errors above")
            return False
        elif self.warnings:
            print("⚠️  SETUP PARTIALLY COMPLETE - Some features won't work")
            print("   You can still run pattern-based detection")
            return True
        else:
            print("✅ SETUP COMPLETE - All tools properly installed")
            return True

    def generate_setup_script(self):
        """Generate a setup script based on detected issues"""
        if not (self.errors or self.warnings):
            return

        print("\n" + "="*60)
        print("AUTOMATED SETUP SCRIPT")
        print("-"*60)

        if self.os_type == "Windows":
            script_name = "setup_tools.ps1"
            script_content = "# PowerShell setup script for Windows\n\n"

            if not self.checks['clang']['status']:
                script_content += "# Install LLVM/Clang\n"
                script_content += "winget install LLVM.LLVM\n\n"

            if not self.checks['coccinelle']['status']:
                script_content += "# Install Coccinelle (via WSL2)\n"
                script_content += "wsl --install\n"
                script_content += 'wsl -e bash -c "sudo apt update && sudo apt install -y coccinelle"\n\n'

        else:  # Linux/Mac
            script_name = "setup_tools.sh"
            script_content = "#!/bin/bash\n# Setup script for Linux\n\n"

            if not self.checks['clang']['status']:
                script_content += "# Install LLVM/Clang\n"
                script_content += "sudo apt update\n"
                script_content += "sudo apt install -y clang llvm llvm-dev libclang-dev\n\n"

            if not self.checks['coccinelle']['status']:
                script_content += "# Install Coccinelle\n"
                script_content += "sudo apt install -y coccinelle\n\n"

        # Write script
        with open(script_name, 'w') as f:
            f.write(script_content)

        print(f"Generated {script_name} to fix missing tools")
        if self.os_type != "Windows":
            os.chmod(script_name, 0o755)
            print(f"Run with: ./{script_name}")
        else:
            print(f"Run with: powershell -ExecutionPolicy Bypass -File {script_name}")

    def run(self):
        """Run all checks"""
        print("="*60)
        print("ANTIPATTERN PIPELINE v1.4 - SETUP VERIFICATION")
        print("="*60)

        # Run checks
        self.check_python()
        self.check_git()
        self.check_clang()
        self.check_coccinelle()
        self.check_kernel_source()
        self.check_directories()

        # Print report
        success = self.print_report()

        # Generate setup script if needed
        if self.errors or self.warnings:
            self.generate_setup_script()

        return success

def main():
    """Main function"""
    checker = SetupChecker()
    success = checker.run()

    if success:
        print("\nYou can now run: python pipeline_v1.4.py")
    else:
        print("\nFix the issues above before running the pipeline")

    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())