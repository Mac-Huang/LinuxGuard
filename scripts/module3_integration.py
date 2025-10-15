#!/usr/bin/env python3
"""
Module 3: Static Analysis Integration
Integrates generated checkers into clang-tidy and manages the build process.
"""

import json
import subprocess
import shutil
import os
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Tuple

class CheckerIntegrator:
    """Manages integration of checkers into clang-tidy build system."""

    def __init__(self, llvm_dir: str, build_dir: str):
        self.llvm_dir = Path(llvm_dir)
        self.build_dir = Path(build_dir)
        self.clang_tidy_dir = self.llvm_dir / "clang-tools-extra" / "clang-tidy" / "linuxkernel"

        if not self.llvm_dir.exists():
            raise ValueError(f"LLVM directory not found: {llvm_dir}")
        if not self.clang_tidy_dir.exists():
            raise ValueError(f"Clang-tidy linux kernel module not found: {self.clang_tidy_dir}")

    def backup_original_files(self):
        """Backup original files before modification."""
        backup_dir = self.clang_tidy_dir / ".backup"
        backup_dir.mkdir(exist_ok=True)

        files_to_backup = [
            "CMakeLists.txt",
            "LinuxKernelTidyModule.cpp"
        ]

        for file_name in files_to_backup:
            src = self.clang_tidy_dir / file_name
            if src.exists():
                dst = backup_dir / f"{file_name}.original"
                if not dst.exists():
                    shutil.copy2(src, dst)
                    print(f"  ✓ Backed up {file_name}")

    def restore_from_backup(self):
        """Restore original files from backup."""
        backup_dir = self.clang_tidy_dir / ".backup"

        if backup_dir.exists():
            for backup_file in backup_dir.glob("*.original"):
                original_name = backup_file.stem
                dst = self.clang_tidy_dir / original_name
                shutil.copy2(backup_file, dst)
                print(f"  ✓ Restored {original_name}")

    def integrate_checker(self, checker_info: Dict) -> bool:
        """Integrate a single checker into the clang-tidy module."""

        checker_name = checker_info["checker_name"]
        header_path = Path(checker_info["files"]["header_path"])
        cpp_path = Path(checker_info["files"]["cpp_path"])

        print(f"\nIntegrating {checker_name}...")

        # Copy checker files to clang-tidy module
        try:
            # Copy header file
            dst_header = self.clang_tidy_dir / f"{checker_name}.h"
            shutil.copy2(header_path, dst_header)
            print(f"  ✓ Copied {checker_name}.h")

            # Copy implementation file
            dst_cpp = self.clang_tidy_dir / f"{checker_name}.cpp"
            shutil.copy2(cpp_path, dst_cpp)
            print(f"  ✓ Copied {checker_name}.cpp")

            # Update CMakeLists.txt
            self.update_cmake_lists(checker_name)

            # Update LinuxKernelTidyModule.cpp
            self.update_module_registration(checker_name)

            return True
ang_tidy_dir / "CMakeLists.txt"

        with open(cmake_file, 'r') as f:
            lines = f.readlines()

        # Check if already added
        cpp_file = f"  {checker_name}.cpp\n"
        if cpp_file in lines:
            print(f"  - {checker_name}.cpp already in CMakeLists.txt")
            return

        # Find the position to insert (after the last .cpp file)
        insert_pos = -1
        for i, line in enumerate(lines):
            if line.strip().endswith('.cpp'):
                insert_pos = i + 1

        if insert_pos > 0:
            lines.insert(insert_pos, cpp_file)
            with open(cmake_file, 'w') as f:
                f.writelines(lines)
            print(f"  ✓ Added {checker_name}.cpp to CMakeLists.txt")
        else:
            print(f"  ✗ Could not find position in CMakeLists.txt")

    def update_module_registration(self, checker_name: str):
        """Register checker in LinuxKernelTidyModule.cpp."""

        module_file = self.clang_tidy_dir / "LinuxKernelTidyModule.cpp"

        with open(module_file, 'r') as f:
            content = f.read()

        # Check if already registered
        if checker_name in content:
            print(f"  - {checker_name} already registered")
            return

        # Add include directive
        include_line = f'#include "{checker_name}.h"\n'
        include_marker = '#include "MustCheckErrsCheck.h"'

        if include_marker in content:
            content = content.replace(include_marker,
                                    f'{include_marker}\n{include_line}')
        else:
            # Find last include and add after it
            lines = content.split('\n')
            for i, line in enumerate(lines):
                if line.startswith('#include "') and line.endswith('.h"'):
                    last_include = i
            lines.insert(last_include + 1, include_line.strip())
            content = '\n'.join(lines)

        # Add checker registration
        # Convert MustCheckErrorsCheck -> must-check-errors
        checker_id = self.camel_to_kebab(checker_name.replace("Check", ""))
        registration_line = f'    CheckFactories.registerCheck<{checker_name}>("linuxkernel-{checker_id}");\n'

        # Find the registration block and add our checker
        registration_marker = 'CheckFactories.registerCheck<MustCheckErrsCheck>("must-check-errs");'
        if registration_marker in content:
            content = content.replace(registration_marker,
                                    f'{registration_marker}\n{registration_line.rstrip()}')

        with open(module_file, 'w') as f:
            f.write(content)

        print(f"  ✓ Registered {checker_name} as '{checker_id}'")

    def camel_to_kebab(self, name: str) -> str:
        """Convert CamelCase to kebab-case."""
        result = []
        for i, char in enumerate(name):
            if char.isupper():
                if i > 0:
                    result.append('-')
                result.append(char.lower())
            else:
                result.append(char)
        return ''.join(result)

    def build_clang_tidy(self, jobs: int = 4) -> bool:
        """Build clang-tidy with the integrated checkers."""

        print(f"\nBuilding clang-tidy (using {jobs} jobs)...")

        # Check if ninja is available
        build_system = "ninja" if shutil.which("ninja") else "make"

        if build_system == "ninja":
            build_cmd = ["ninja", "-C", str(self.build_dir), f"-j{jobs}", "clang-tidy"]
        else:
            build_cmd = ["make", "-C", str(self.build_dir), f"-j{jobs}", "clang-tidy"]

        print(f"  Using build system: {build_system}")

        # Set up environment for ccache if available
        env = os.environ.copy()
        if shutil.which("ccache"):
            env["CC"] = "ccache clang"
            env["CXX"] = "ccache clang++"
            print("  Using ccache for faster builds")

        try:
            # Run build with nice to be resource-conscious
            nice_cmd = ["nice", "-n", "10"] + build_cmd

            print(f"  Running: {' '.join(build_cmd)}")
            result = subprocess.run(nice_cmd, env=env, capture_output=True, text=True)

            if result.returncode == 0:
                print("  ✓ Build successful")
                return True
            else:
                print("  ✗ Build failed")
                print("Error output:")
                print(result.stderr[-2000:])  # Show last 2000 chars of error

                # Try to extract specific error
                self.diagnose_build_error(result.stderr)
                return False

        except subprocess.CalledProcessError as e:
            print(f"  ✗ Build error: {e}")
            return False

    def diagnose_build_error(self, error_output: str):
        """Try to diagnose and suggest fixes for build errors."""

        if "undefined reference" in error_output:
            print("\n  Diagnosis: Linker error - missing symbol definitions")
            print("  Suggestion: Check that all required methods are implemented")

        elif "no matching function" in error_output:
            print("\n  Diagnosis: API mismatch - AST matcher syntax error")
            print("  Suggestion: Verify AST matcher syntax matches clang version")

        elif "no member named" in error_output:
            print("\n  Diagnosis: Missing member or method")
            print("  Suggestion: Check clang-tidy API for correct method names")

        elif "cannot open" in error_output or "No such file" in error_output:
            print("\n  Diagnosis: Missing include file")
            print("  Suggestion: Verify all header files are properly included")

    def verify_integration(self) -> bool:
        """Verify that the checker was successfully integrated."""

        clang_tidy_bin = self.build_dir / "bin" / "clang-tidy"

        if not clang_tidy_bin.exists():
            print("  ✗ clang-tidy binary not found")
            return False

        # List available checks
        cmd = [str(clang_tidy_bin), "--list-checks", "-checks='linuxkernel-*"]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            print("\n  Available Linux kernel checks:")

            checks = [line.strip() for line in result.stdout.split('\n')
                     if line.strip().startswith('linuxkernel-')]

            for check in checks:
                print(f"    - {check}")

            return len(checks) > 0

        except subprocess.CalledProcessError as e:
            print(f"  ✗ Error listing checks: {e}")
            return False

def main():
    parser = argparse.ArgumentParser(description='Integrate checkers into clang-tidy')
    parser.add_argument('--checker-metadata',
                      default='/home/mac/private/linux-guard/checkers/generated/generated_checkers.json',
                      help='Metadata file with generated checker information')
    parser.add_argument('--llvm-dir', default='/home/mac/private/linux-guard/llvm-project',
                      help='LLVM source directory')
    parser.add_argument('--build-dir', default='/home/mac/private/linux-guard/llvm-project/build',
                      help='LLVM build directory')
    parser.add_argument('--jobs', type=int, default=4,
                      help='Number of parallel build jobs')
    parser.add_argument('--single', action='store_true',
                      help='Integrate only the first checker')
    parser.add_argument('--no-build', action='store_true',
                      help='Skip the build step')
    parser.add_argument('--restore', action='store_true',
                      help='Restore original files from backup')

    args = parser.parse_args()

    print("=== Module 3: Static Analysis Integration ===")

    integrator = CheckerIntegrator(args.llvm_dir, args.build_dir)

    if args.restore:
        print("\nRestoring original files...")
        integrator.restore_from_backup()
        return

    # Backup original files first
    print("\nBacking up original files...")
    integrator.backup_original_files()

    # Load checker metadata
    if not Path(args.checker_metadata).exists():
        print(f"✗ Checker metadata not found: {args.checker_metadata}")
        print("  Run Module 2 first to generate checkers")
        return

    with open(args.checker_metadata, 'r') as f:
        checkers = json.load(f)

    if not checkers:
        print("✗ No checkers found in metadata")
        return

    # Integrate checkers
    successful_integrations = []

    for i, checker in enumerate(checkers):
        if args.single and i > 0:
            break

        if integrator.integrate_checker(checker):
            successful_integrations.append(checker["checker_name"])

    if not successful_integrations:
        print("\n✗ No checkers were successfully integrated")
        return

    print(f"\n✓ Integrated {len(successful_integrations)} checkers:")
    for name in successful_integrations:
        print(f"  - {name}")

    # Build if requested
    if not args.no_build:
        print("\n" + "="*50)
        if integrator.build_clang_tidy(args.jobs):
            print("\n✓ Build completed successfully")

            # Verify integration
            if integrator.verify_integration():
                print("\n✓ Integration verified - checkers are available")

                # Save integration status
                status_file = Path(args.checker_metadata).parent / "integration_status.json"
                with open(status_file, 'w') as f:
                    json.dump({
                        "integrated_checkers": successful_integrations,
                        "clang_tidy_binary": str(integrator.build_dir / "bin" / "clang-tidy"),
                        "status": "success"
                    }, f, indent=2)

                print(f"\n✓ Saved integration status to {status_file}")
            else:
                print("\n✗ Integration verification failed")
        else:
            print("\n✗ Build failed - check error messages above")
            print("\nTo restore original files, run: python3 module3_integration.py --restore")
    else:
        print("\n  Skipped build step (--no-build flag)")

if __name__ == "__main__":
    main()
