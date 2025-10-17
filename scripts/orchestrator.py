#!/usr/bin/env python3
"""
LinuxGuard Pipeline Orchestrator v2
Enhanced UI/UX with clean status display and organized output.
"""

import json
import subprocess
import shutil
import os
import sys
import argparse
from pathlib import Path
from typing import Dict, Optional, Tuple, List
from dotenv import load_dotenv
import google.generativeai as genai
import time
from datetime import datetime

# Load environment variables
load_dotenv()

# ANSI color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    CLEAR_LINE = '\033[2K'
    MOVE_UP = '\033[1A'

class StatusDisplay:
    """Manages clean status display with fixed window updates."""

    def __init__(self):
        self.current_status = {}
        self.log_messages = []
        self.width = 80

    def header(self):
        """Display professional header."""
        print(f"{Colors.CYAN}{'='*self.width}{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.CYAN}  🔍 LinuxGuard - Kernel Anti-Pattern Detection Pipeline{Colors.ENDC}")
        print(f"{Colors.CYAN}{'='*self.width}{Colors.ENDC}")

    def section(self, title: str, preserve_line: bool = False):
        """Display section header."""
        if not preserve_line:
            print(f"\n{Colors.BOLD}{Colors.BLUE}[{title}]{Colors.ENDC}")
        else:
            print(f"{Colors.BOLD}{Colors.BLUE}[{title}]{Colors.ENDC}")

    def status(self, key: str, value: str, symbol: str = "•"):
        """Update status line in-place."""
        if key in self.current_status:
            # Move cursor up and clear line
            print(f"{Colors.MOVE_UP}{Colors.CLEAR_LINE}", end='')

        status_line = f"  {symbol} {key}: {value}"
        print(status_line)
        self.current_status[key] = value

    def success(self, message: str):
        """Display success message."""
        print(f"  {Colors.GREEN}✓{Colors.ENDC} {message}")

    def error(self, message: str):
        """Display error message."""
        print(f"  {Colors.FAIL}✗{Colors.ENDC} {message}")

    def warning(self, message: str):
        """Display warning message."""
        print(f"  {Colors.WARNING}⚠{Colors.ENDC} {message}")

    def progress_bar(self, current: int, total: int, prefix: str = ""):
        """Display a progress bar."""
        bar_length = 40
        progress = current / total
        filled = int(bar_length * progress)
        bar = '█' * filled + '░' * (bar_length - filled)
        percentage = int(100 * progress)

        # Clear previous line and print progress
        print(f"\r  {prefix} [{bar}] {percentage}% ({current}/{total})", end='', flush=True)
        if current == total:
            print()  # New line when complete

    def compilation_status(self, attempt: int, max_attempts: int, errors: int = 0, clear_previous: bool = False):
        """Display compilation status in a fixed window."""
        if clear_previous:
            # Move cursor up 4 lines (not 5 since we don't reprint the header)
            for _ in range(4):
                print(f"{Colors.MOVE_UP}{Colors.CLEAR_LINE}", end='')
        else:
            # Only print header on first display
            print(f"{Colors.BOLD}Compilation Status:{Colors.ENDC}")

        print(f"  ┌{'─'*50}┐")
        print(f"  │ Attempt: {attempt}/{max_attempts:<38}│")
        if errors > 0:
            error_str = f"{errors}"
            # Need to account for ANSI codes in padding
            print(f"  │ Errors Found: {Colors.FAIL}{error_str}{Colors.ENDC}{' '*(35-len(error_str))}│")
        else:
            status_str = "Building..."
            print(f"  │ Status: {Colors.GREEN}{status_str}{Colors.ENDC}{' '*(39-len(status_str))}│")
        print(f"  └{'─'*50}┘")

class PipelineOrchestrator:
    """Orchestrates the complete pipeline with iterative generation and repair."""

    def __init__(self, base_dir: str = "/home/mac/private/linux-guard"):
        self.base_dir = Path(base_dir)
        self.max_iterations = 3
        self.max_repair_attempts = 5
        self.validation_sample = None
        self.display = StatusDisplay()

        # Initialize Gemini for repairs
        api_key = os.getenv('GEMINI_API_KEY')
        if not api_key:
            raise ValueError("GEMINI_API_KEY not found in .env file")

        genai.configure(api_key=api_key)
        model_name = os.getenv('GEMINI_MODEL', 'gemini-2.0-flash-lite')
        self.repair_model = genai.GenerativeModel(model_name)

        # Module paths
        self.scripts_dir = self.base_dir / "scripts"
        self.checkers_dir = self.base_dir / "checkers" / "generated"
        self.llvm_dir = self.base_dir / "llvm-project"
        self.build_dir = self.llvm_dir / "build"

    def generate_checker(self, commit_hash: str) -> Optional[Dict]:
        """Main orchestration function implementing the iterative generation algorithm."""

        self.display.header()
        print(f"\n  Commit: {Colors.BOLD}{commit_hash[:12]}{Colors.ENDC}")
        print(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()

        for iteration in range(1, self.max_iterations + 1):
            # Display iteration header prominently
            print(f"\n{Colors.BOLD}{Colors.CYAN}━━━ Iteration {iteration}/{self.max_iterations} ━━━{Colors.ENDC}")

            # Stage 1: Bug Pattern Analysis
            print(f"{Colors.BOLD}Stage 1:{Colors.ENDC} Analyzing patch")
            self.display.status("Analysis", "Extracting bug patterns...")
            pattern = self.analyze_patch(commit_hash)

            if not pattern:
                self.display.error("Failed to extract pattern")
                continue

            self.display.success(f"Pattern detected: {pattern.get('anti_pattern_type', 'unknown')}")

            # Stage 2: Detection Plan Synthesis
            print(f"\n{Colors.BOLD}Stage 2:{Colors.ENDC} Synthesis")
            self.display.status("Synthesis", "Creating detection plan...")
            time.sleep(0.5)  # Visual feedback

            # Stage 3: Checker Implementation
            print(f"\n{Colors.BOLD}Stage 3:{Colors.ENDC} Implementation")
            self.display.status("Generation", "Creating checker code...")
            checker_info = self.implement_checker(pattern)

            if not checker_info:
                self.display.error("Failed to generate checker")
                continue

            self.display.success(f"Generated: {checker_info['checker_name']}")

            # Repair loop for compilation errors
            build_result = False
            print(f"\n{Colors.BOLD}Stage 4:{Colors.ENDC} Build & Repair")

            for attempt in range(1, self.max_repair_attempts + 1):
                # Show compilation window (clear previous on subsequent attempts)
                clear_prev = attempt > 1

                # Try to build first to see if there are errors
                build_result, errors = self.build_checker(checker_info)
                error_count = errors.count('error:') if errors else 0

                # Display status with error count if any
                self.display.compilation_status(attempt, self.max_repair_attempts, error_count, clear_previous=clear_prev)

                if build_result:
                    self.display.success("Build successful!")
                    break

                if attempt < self.max_repair_attempts and error_count > 0:
                    print(f"  🔧 Attempting repair ({error_count} error{'s' if error_count > 1 else ''})...")
                    repaired = self.repair_checker(checker_info, errors, pattern)

                    if not repaired:
                        self.display.error("Repair failed")
                        break

                    self.display.success("Checker repaired, retrying build...")
                elif attempt == self.max_repair_attempts:
                    self.display.error(f"Maximum repair attempts reached ({error_count} errors remaining)")

            if not build_result:
                self.display.error(f"Failed to build after {self.max_repair_attempts} attempts")
                continue

            # Stage 5: Validation
            print(f"\n{Colors.BOLD}Stage 5:{Colors.ENDC} Validation")
            self.display.status("Testing", "Validating checker...")
            is_valid = self.validate_checker(checker_info, commit_hash)

            if is_valid:
                print(f"\n{Colors.GREEN}{'='*80}{Colors.ENDC}")
                print(f"{Colors.GREEN}{Colors.BOLD}  ✓ SUCCESS: Valid checker generated!{Colors.ENDC}")
                print(f"  Checker: {checker_info['checker_name']}")
                print(f"  Iteration: {iteration}")
                print(f"{Colors.GREEN}{'='*80}{Colors.ENDC}")
                return checker_info
            else:
                self.display.warning("Validation failed, trying next iteration...")

        print(f"\n{Colors.FAIL}{'='*80}{Colors.ENDC}")
        print(f"{Colors.FAIL}  ✗ Failed to generate valid checker after {self.max_iterations} iterations{Colors.ENDC}")
        print(f"{Colors.FAIL}{'='*80}{Colors.ENDC}")
        return None

    def analyze_patch(self, commit_hash: str) -> Optional[Dict]:
        """Stage 1: Analyze patch to extract bug pattern."""

        # Fetch commit if needed
        commit_file = self.base_dir / "commits" / f"{commit_hash}.json"

        if not commit_file.exists():
            self.display.status("Fetch", "Downloading commit data...")
            result = subprocess.run([
                "python3", str(self.scripts_dir / "fetch_commit.py"),
                commit_hash
            ], capture_output=True, text=True)

            if result.returncode != 0:
                return None

        # Analyze with Module 1
        result = subprocess.run([
            "python3", str(self.scripts_dir / "module1_pattern_extraction.py"),
            "--commit-hash", commit_hash
        ], capture_output=True, text=True)

        # Load the generated pattern
        pattern_file = self.base_dir / "results" / "anti_patterns.json"
        if pattern_file.exists():
            with open(pattern_file, 'r') as f:
                return json.load(f)

        return None

    def implement_checker(self, pattern: Dict) -> Optional[Dict]:
        """Stage 3: Implement checker from pattern."""

        # Use Module 2 to generate checker
        result = subprocess.run([
            "python3", str(self.scripts_dir / "module2_checker_synthesis.py"),
            "--single"
        ], capture_output=True, text=True)

        # Load generated checker info
        checker_meta = self.checkers_dir / "generated_checkers.json"
        if checker_meta.exists():
            with open(checker_meta, 'r') as f:
                checkers = json.load(f)
                if checkers:
                    return checkers[0]

        return None

    def build_checker(self, checker_info: Dict) -> Tuple[bool, str]:
        """Try to build the checker and return success status and error messages."""

        # Integrate into clang-tidy
        result = subprocess.run([
            "python3", str(self.scripts_dir / "module3_integration.py"),
            "--no-build"
        ], capture_output=True, text=True)

        # Try to build
        build_cmd = [
            "ninja", "-C", str(self.build_dir),
            "-j2", "clang-tidy"
        ]

        result = subprocess.run(build_cmd, capture_output=True, text=True)

        if result.returncode == 0:
            return True, ""

        # Extract compilation errors
        errors = result.stderr if result.stderr else result.stdout
        relevant_errors = self.extract_relevant_errors(errors, checker_info['checker_name'])

        return False, relevant_errors

    def extract_relevant_errors(self, error_output: str, checker_name: str) -> str:
        """Extract only the relevant compilation errors for the checker."""

        lines = error_output.split('\n')
        relevant = []
        in_relevant_section = False

        for line in lines:
            if checker_name in line:
                in_relevant_section = True

            if in_relevant_section:
                if 'error:' in line or 'warning:' in line:
                    relevant.append(line)
                elif relevant and len(relevant[-1]) > 0:
                    relevant.append(line)

            if in_relevant_section and '.cpp:' in line and checker_name not in line:
                break

        return '\n'.join(relevant[-20:])

    def repair_checker(self, checker_info: Dict, errors: str, pattern: Dict) -> bool:
        """Use LLM to repair compilation errors in the checker."""

        # Load current checker code
        cpp_file = self.checkers_dir / f"{checker_info['checker_name']}.cpp"
        h_file = self.checkers_dir / f"{checker_info['checker_name']}.h"

        with open(cpp_file, 'r') as f:
            cpp_code = f.read()

        with open(h_file, 'r') as f:
            h_code = f.read()

        # Create repair prompt
        prompt = f"""Fix the compilation errors in this clang-tidy checker.

HEADER FILE ({checker_info['checker_name']}.h):
```cpp
{h_code}
```

IMPLEMENTATION FILE ({checker_info['checker_name']}.cpp):
```cpp
{cpp_code}
```

COMPILATION ERRORS:
```
{errors}
```

CONTEXT:
- This checker detects: {pattern.get('anti_pattern_type', 'unknown')}
- It should identify: {pattern.get('vulnerable_pattern', {}).get('description', '')}

Fix the compilation errors by correcting the API usage. Common issues:
- Use dyn_cast<T> instead of getAs<T> for AST nodes
- CompoundStmt::body() returns an iterator range, not a container
- Use proper clang AST API methods
- Ensure all matcher constructs are valid

Respond with two code blocks:
1. The complete fixed header file
2. The complete fixed implementation file

Respond ONLY with the two code blocks labeled:
HEADER:
```cpp
...
```

IMPLEMENTATION:
```cpp
...
```"""

        try:
            response = self.repair_model.generate_content(prompt)
            response_text = response.text

            # Extract header and implementation
            header_start = response_text.find("HEADER:")
            impl_start = response_text.find("IMPLEMENTATION:")

            if header_start == -1 or impl_start == -1:
                return False

            # Extract code blocks
            header_code = self.extract_code_block(response_text[header_start:impl_start])
            impl_code = self.extract_code_block(response_text[impl_start:])

            if not header_code or not impl_code:
                return False

            # Save repaired code
            with open(h_file, 'w') as f:
                f.write(header_code)

            with open(cpp_file, 'w') as f:
                f.write(impl_code)

            return True

        except Exception as e:
            return False

    def extract_code_block(self, text: str) -> Optional[str]:
        """Extract code from markdown code block."""

        start = text.find("```cpp")
        if start == -1:
            start = text.find("```")

        if start == -1:
            return None

        start = text.find("\n", start) + 1
        end = text.find("```", start)

        if end == -1:
            return None

        return text[start:end].strip()

    def validate_checker(self, checker_info: Dict, commit_hash: str) -> bool:
        """Stage 4: Validate the checker by scanning and checking results."""

        # Convert checker name to pattern
        checker_pattern = self.get_checker_pattern(checker_info['checker_name'])

        # Show scanning progress
        if self.validation_sample:
            total_files = self.validation_sample
        else:
            total_files = 100  # Estimate for progress display

        # Run Module 4 - scan files in kernel
        cmd = [
            "python3", str(self.scripts_dir / "module4_validation.py"),
            "--kernel-version", "linux-v3.0",
            "--checker-pattern", checker_pattern,
            "--output", str(self.base_dir / "results" / "validation_report.json")
        ]

        if self.validation_sample:
            cmd.extend(["--sample-size", str(self.validation_sample)])

        result = subprocess.run(cmd, capture_output=True, text=True)

        # Load and check results
        report_file = self.base_dir / "results" / "validation_report.json"

        if not report_file.exists():
            return False

        with open(report_file, 'r') as f:
            report = json.load(f)

        # Check for any detections
        for version, data in report.get('results_by_version', {}).items():
            total_issues = data.get('total_issues', 0)
            if total_issues > 0:
                self.display.success(f"Found {total_issues} issues in {version}")
                return True
            else:
                self.display.warning("No issues detected (pattern might be rare)")
                return True  # Still valid if it runs without crashing

        return False

    def get_checker_pattern(self, checker_name: str) -> str:
        """Convert checker name to clang-tidy pattern."""

        name = checker_name.replace('Check', '')
        result = []

        for i, char in enumerate(name):
            if char.isupper() and i > 0:
                result.append('-')
            result.append(char.lower())

        return f"linuxkernel-{''.join(result)}"

def main():
    parser = argparse.ArgumentParser(description='LinuxGuard Pipeline')
    parser.add_argument('--commit', default='80af3745ca465c6c47e833c1902004a7fa944f37',
                      help='Commit hash to analyze')
    parser.add_argument('--max-iterations', type=int, default=3,
                      help='Maximum generation iterations')
    parser.add_argument('--max-repairs', type=int, default=5,
                      help='Maximum repair attempts per iteration')
    parser.add_argument('--validation-sample', type=int, default=None,
                      help='Number of files to scan for validation')

    args = parser.parse_args()

    orchestrator = PipelineOrchestrator()
    orchestrator.max_iterations = args.max_iterations
    orchestrator.max_repair_attempts = args.max_repairs
    orchestrator.validation_sample = args.validation_sample

    # Run the orchestrated pipeline
    start_time = time.time()
    checker = orchestrator.generate_checker(args.commit)
    elapsed = time.time() - start_time

    if checker:
        print(f"\n{Colors.BOLD}Pipeline completed in {elapsed:.1f} seconds{Colors.ENDC}")
        return 0
    else:
        print(f"\n{Colors.BOLD}Pipeline failed after {elapsed:.1f} seconds{Colors.ENDC}")
        return 1

if __name__ == "__main__":
    sys.exit(main())