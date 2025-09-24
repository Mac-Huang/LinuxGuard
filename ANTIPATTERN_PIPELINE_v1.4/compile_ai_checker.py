#!/usr/bin/env python3
"""
Clang Checker Compilation Script
Compiles the AI-generated checker into a loadable plugin
"""

import os
import sys
import subprocess
import platform
from pathlib import Path
import json

class CheckerCompiler:
    def __init__(self):
        self.os_type = platform.system()
        self.checker_path = Path("generated")
        self.checker_name = None
        self.checker_cpp = None
        self.plugin_file = None

    def find_checker_file(self):
        """Find the generated checker C++ file"""
        print("Looking for checker file...")

        # Look for any *Checker.cpp file
        checker_files = list(self.checker_path.glob("*Checker.cpp"))

        if not checker_files:
            print("Error: No checker C++ file found in 'generated' directory")
            print("Run 'python checker_generator.py' first to generate the checker")
            return False

        self.checker_cpp = checker_files[0]
        self.checker_name = self.checker_cpp.stem
        print(f"Found checker: {self.checker_name}.cpp")
        return True

    def get_llvm_config(self):
        """Get LLVM configuration flags"""
        config = {
            'cxxflags': '',
            'ldflags': '',
            'version': '',
            'bindir': '',
            'includedir': '',
            'libdir': ''
        }

        try:
            # Get various config options
            for option in config.keys():
                cmd = ['llvm-config', f'--{option}']
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    config[option] = result.stdout.strip()

            return config
        except FileNotFoundError:
            print("Error: llvm-config not found")
            return None

    def compile_windows(self):
        """Compile checker on Windows"""
        print("Compiling for Windows...")

        # Check for Visual Studio
        vs_path = self.find_visual_studio()
        if not vs_path:
            print("Error: Visual Studio not found")
            print("Install Visual Studio Build Tools with C++ support")
            return False

        llvm_config = self.get_llvm_config()
        if not llvm_config:
            # Try default paths
            llvm_paths = [
                Path("C:/Program Files/LLVM"),
                Path("C:/LLVM"),
                Path("D:/LLVM")
            ]

            llvm_path = None
            for path in llvm_paths:
                if path.exists():
                    llvm_path = path
                    break

            if not llvm_path:
                print("Error: LLVM not found")
                return False

            llvm_config = {
                'includedir': str(llvm_path / 'include'),
                'libdir': str(llvm_path / 'lib'),
                'bindir': str(llvm_path / 'bin')
            }

        # Prepare compilation command
        self.plugin_file = self.checker_path / f"{self.checker_name}.dll"

        compile_cmd = [
            "cl.exe",
            "/MD",  # Multi-threaded DLL runtime
            "/EHsc",  # Exception handling
            "/std:c++17",
            f"/I{llvm_config['includedir']}",
            "/D_CRT_SECURE_NO_WARNINGS",
            "/D_SCL_SECURE_NO_WARNINGS",
            "/DLLVM_ENABLE_PLUGINS",
            "/c",  # Compile only
            str(self.checker_cpp),
            f"/Fo{self.checker_path / f'{self.checker_name}.obj'}"
        ]

        link_cmd = [
            "link.exe",
            "/DLL",
            f"/OUT:{self.plugin_file}",
            f"{self.checker_path / f'{self.checker_name}.obj'}",
            f"/LIBPATH:{llvm_config['libdir']}",
            "clangAST.lib",
            "clangBasic.lib",
            "clangStaticAnalyzerCore.lib",
            "clangStaticAnalyzerCheckers.lib",
            "LLVMSupport.lib"
        ]

        # Run compilation
        print("Compiling...")
        result = subprocess.run(compile_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Compilation failed:\n{result.stderr}")
            return False

        print("Linking...")
        result = subprocess.run(link_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Linking failed:\n{result.stderr}")
            return False

        print(f"Successfully compiled: {self.plugin_file}")
        return True

    def compile_linux(self):
        """Compile checker on Linux"""
        print("Compiling for Linux...")

        llvm_config = self.get_llvm_config()
        if not llvm_config:
            print("Error: llvm-config not found")
            print("Install with: sudo apt install llvm-dev libclang-dev")
            return False

        self.plugin_file = self.checker_path / f"{self.checker_name}.so"

        # Build compilation command
        compile_cmd = [
            "clang++",
            "-shared",
            "-fPIC",
            "-o", str(self.plugin_file),
            str(self.checker_cpp),
            "-std=c++17"
        ]

        # Add LLVM flags
        if llvm_config['cxxflags']:
            compile_cmd.extend(llvm_config['cxxflags'].split())
        if llvm_config['ldflags']:
            compile_cmd.extend(llvm_config['ldflags'].split())

        # Add required libraries
        compile_cmd.extend([
            "-lclangAST",
            "-lclangBasic",
            "-lclangStaticAnalyzerCore",
            "-lclangStaticAnalyzerCheckers"
        ])

        # Run compilation
        print(f"Compiling with: {' '.join(compile_cmd[:5])}...")
        result = subprocess.run(compile_cmd, capture_output=True, text=True)

        if result.returncode != 0:
            print(f"Compilation failed:\n{result.stderr}")

            # Try alternative compilation method
            print("\nTrying alternative compilation method...")
            return self.compile_linux_alternative()

        print(f"Successfully compiled: {self.plugin_file}")
        return True

    def compile_linux_alternative(self):
        """Alternative compilation method for Linux"""
        self.plugin_file = self.checker_path / f"{self.checker_name}.so"

        # Simpler compilation command
        compile_cmd = [
            "clang++",
            "-shared",
            "-fPIC",
            "-o", str(self.plugin_file),
            str(self.checker_cpp),
            "-std=c++14",
            "`llvm-config --cxxflags --ldflags --libs`",
            "-lclang"
        ]

        # Use shell to expand backticks
        cmd_str = ' '.join(compile_cmd)
        result = subprocess.run(cmd_str, shell=True, capture_output=True, text=True)

        if result.returncode == 0:
            print(f"Successfully compiled: {self.plugin_file}")
            return True

        print(f"Alternative compilation also failed:\n{result.stderr}")
        return False

    def find_visual_studio(self):
        """Find Visual Studio installation on Windows"""
        vs_paths = [
            Path("C:/Program Files/Microsoft Visual Studio/2022/Community"),
            Path("C:/Program Files/Microsoft Visual Studio/2022/Professional"),
            Path("C:/Program Files/Microsoft Visual Studio/2022/Enterprise"),
            Path("C:/Program Files (x86)/Microsoft Visual Studio/2019/Community"),
        ]

        for path in vs_paths:
            if path.exists():
                return path

        return None

    def create_wrapper_script(self):
        """Create a wrapper script to use the compiled checker"""
        if not self.plugin_file or not self.plugin_file.exists():
            return

        wrapper_name = "run_checker.sh" if self.os_type != "Windows" else "run_checker.bat"

        if self.os_type == "Windows":
            wrapper_content = f"""@echo off
REM Wrapper script to run Clang with custom checker

if "%1"=="" (
    echo Usage: run_checker.bat source_file.c
    exit /b 1
)

clang --analyze ^
    -Xclang -load ^
    -Xclang {self.plugin_file} ^
    -Xclang -analyzer-checker=custom.{self.checker_name} ^
    %1
"""
        else:
            wrapper_content = f"""#!/bin/bash
# Wrapper script to run Clang with custom checker

if [ $# -eq 0 ]; then
    echo "Usage: ./run_checker.sh source_file.c"
    exit 1
fi

clang --analyze \\
    -Xclang -load \\
    -Xclang {self.plugin_file} \\
    -Xclang -analyzer-checker=custom.{self.checker_name} \\
    "$1"
"""

        with open(wrapper_name, 'w') as f:
            f.write(wrapper_content)

        if self.os_type != "Windows":
            os.chmod(wrapper_name, 0o755)

        print(f"Created wrapper script: {wrapper_name}")
        print(f"Usage: {wrapper_name} <source_file.c>")

    def test_compilation(self):
        """Test the compiled checker with a sample file"""
        if not self.plugin_file or not self.plugin_file.exists():
            print("Plugin not compiled")
            return False

        # Create a test C file
        test_file = Path("test_vulnerability.c")
        test_content = """
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void vulnerable_function(char *user_input) {
    char buffer[100];

    // Buffer overflow vulnerability
    strcpy(buffer, user_input);

    // Use after free
    char *ptr = malloc(100);
    free(ptr);
    *ptr = 'A';  // Use after free

    // Null pointer dereference
    char *null_ptr = NULL;
    *null_ptr = 'B';
}

int main() {
    vulnerable_function("test");
    return 0;
}
"""
        test_file.write_text(test_content)

        print(f"\nTesting checker with {test_file}...")

        # Run clang with the plugin
        test_cmd = [
            "clang",
            "--analyze",
            "-Xclang", "-load",
            "-Xclang", str(self.plugin_file),
            "-Xclang", f"-analyzer-checker=custom.{self.checker_name}",
            str(test_file)
        ]

        result = subprocess.run(test_cmd, capture_output=True, text=True)

        if result.returncode == 0:
            print("✅ Checker executed successfully")
            if result.stdout:
                print("Output:", result.stdout)
            if result.stderr:
                print("Warnings:", result.stderr)
            return True
        else:
            print("❌ Checker execution failed")
            print("Error:", result.stderr)
            return False

    def compile(self):
        """Main compilation method"""
        print("="*60)
        print("CLANG CHECKER COMPILATION")
        print("="*60)

        # Find checker file
        if not self.find_checker_file():
            return False

        # Compile based on OS
        if self.os_type == "Windows":
            success = self.compile_windows()
        elif self.os_type == "Linux":
            success = self.compile_linux()
        elif self.os_type == "Darwin":  # macOS
            success = self.compile_linux()  # Similar to Linux
        else:
            print(f"Unsupported OS: {self.os_type}")
            return False

        if success:
            # Create wrapper script
            self.create_wrapper_script()

            # Test the compilation
            self.test_compilation()

            # Save compilation info
            info = {
                'checker_name': self.checker_name,
                'plugin_file': str(self.plugin_file),
                'os_type': self.os_type,
                'compilation_success': True
            }

            with open(self.checker_path / 'compilation_info.json', 'w') as f:
                json.dump(info, f, indent=2)

            print("\n✅ Compilation successful!")
            print(f"Plugin location: {self.plugin_file}")
            return True

        else:
            print("\n❌ Compilation failed")
            print("Check the SETUP_GUIDE.md for troubleshooting")
            return False

def main():
    """Main function"""
    compiler = CheckerCompiler()
    success = compiler.compile()
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())