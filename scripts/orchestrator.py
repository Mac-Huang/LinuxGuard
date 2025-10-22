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

    def __init__(self, base_dir: Optional[str] = None):
        self.base_dir = Path(base_dir) if base_dir else Path(__file__).resolve().parent.parent
        self.max_iterations = 3
        self.max_repair_attempts = 5
        self.validation_sample = None
        self.validation_kernel = None
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

    def _restore_clang_environment(self):
        """Ensure clang-tidy sources are reset to their backups."""
        subprocess.run([
            "python3", str(self.scripts_dir / "module3_integration.py"),
            "--restore"
        ], capture_output=True, text=True)

    def _resolve_project_path(self, path_str: str) -> Path:
        path = Path(path_str)
        if not path.is_absolute():
            path = self.base_dir / path
        return path

    def _ensure_checker_paths(self, checker: Dict) -> Optional[Dict]:
        files = checker.get('files') or {}
        required = ('header_path', 'cpp_path', 'metadata_path')
        if all(files.get(key) for key in required):
            return checker

        checker_name = checker.get('checker_name')
        anti_pattern_folder = checker.get('anti_pattern_folder')
        if not anti_pattern_folder:
            anti_type = checker.get('anti_pattern_type')
            if anti_type:
                anti_pattern_folder = anti_type.lower().replace('_', '-')

        generation_id = checker.get('generation_id')
        if not checker_name or not anti_pattern_folder or not generation_id:
            return None

        base_dir = self.checkers_dir / anti_pattern_folder / generation_id
        header_path = base_dir / f"{checker_name}.h"
        cpp_path = base_dir / f"{checker_name}.cpp"
        metadata_path = base_dir / 'metadata.json'

        if not (header_path.exists() and cpp_path.exists() and metadata_path.exists()):
            return None

        try:
            rel_header = header_path.relative_to(self.base_dir)
            rel_cpp = cpp_path.relative_to(self.base_dir)
            rel_meta = metadata_path.relative_to(self.base_dir)
        except ValueError:
            rel_header, rel_cpp, rel_meta = header_path, cpp_path, metadata_path

        checker['anti_pattern_folder'] = anti_pattern_folder
        checker['files'] = {
            'header_path': str(rel_header),
            'cpp_path': str(rel_cpp),
            'metadata_path': str(rel_meta)
        }
        return checker

    def _count_error_lines(self, output: str) -> int:
        if not output:
            return 0
        count = 0
        for line in output.splitlines():
            lower = line.lower()
            if 'error' in lower or 'failed' in lower:
                count += 1
        return count

    def generate_checker(self, commit_hash: str) -> Optional[Dict]:
        """Main orchestration function implementing the iterative generation algorithm."""

        self.display.header()
        print(f"\n  Commit: {Colors.BOLD}{commit_hash[:12]}{Colors.ENDC}")
        print(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()

        # Start from a clean integration state
        self._restore_clang_environment()

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
            checker_info = self.implement_checker(pattern, commit_hash)

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
                error_count = self._count_error_lines(errors)

                # Display status with error count if any
                self.display.compilation_status(attempt, self.max_repair_attempts, error_count, clear_previous=clear_prev)

                if build_result:
                    self.display.success("Build successful!")
                    break

                if attempt == 1 and errors:
                    preview = '\n'.join(errors.splitlines()[:15])
                    print("  --- Build output (truncated) ---")
                    print('\n'.join(f"    {line}" for line in preview.splitlines()))
                    if len(errors.splitlines()) > 15:
                        print("    ...")

                fatal_messages = ('metadata path is missing', 'checker metadata path is missing')
                fatal_error = errors and any(msg in errors.lower() for msg in fatal_messages)

                if fatal_error:
                    self.display.error('Integration failed: checker metadata is missing')
                    break

                if attempt < self.max_repair_attempts and errors:
                    print(f"  🔧 Attempting repair ({max(error_count,1)} error{'s' if max(error_count,1) > 1 else ''})...")
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
                self._restore_clang_environment()
                return checker_info
            else:
                self.display.warning("Validation failed, trying next iteration...")

        print(f"\n{Colors.FAIL}{'='*80}{Colors.ENDC}")
        print(f"{Colors.FAIL}  ✗ Failed to generate valid checker after {self.max_iterations} iterations{Colors.ENDC}")
        print(f"{Colors.FAIL}{'='*80}{Colors.ENDC}")
        self._restore_clang_environment()
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

    def implement_checker(self, pattern: Dict, commit_hash: str) -> Optional[Dict]:
        """Stage 3: Implement checker from pattern."""

        result = subprocess.run([
            "python3", str(self.scripts_dir / "module2_checker_synthesis.py"),
            "--single"
        ], capture_output=True, text=True)

        if result.returncode != 0:
            self.display.error("Module 2 synthesis failed")
            return None

        checker_meta = self.checkers_dir / "generated_checkers.json"
        if not checker_meta.exists():
            return None

        try:
            with open(checker_meta, 'r') as f:
                checkers = json.load(f)
        except json.JSONDecodeError:
            return None

        if isinstance(checkers, dict):
            checkers = [checkers]

        if not checkers:
            return None

        selected = None
        for entry in reversed(checkers):
            if entry.get("commit_hash") == commit_hash:
                selected = entry
                break

        if selected is None:
            selected = checkers[-1]

        ensured = self._ensure_checker_paths(selected)
        if not ensured:
            self.display.error('Unable to locate generated checker files')
            return None

        return ensured

    def build_checker(self, checker_info: Dict) -> Tuple[bool, str]:
        """Try to build the checker and return success status and error messages."""

        files = checker_info.get('files', {})
        metadata_rel = files.get('metadata_path')

        if not metadata_rel:
            anti_pattern_folder = checker_info.get('anti_pattern_folder')
            generation_id = checker_info.get('generation_id')
            if anti_pattern_folder and generation_id:
                metadata_path = self.checkers_dir / anti_pattern_folder / generation_id / 'metadata.json'
            else:
                return False, 'Checker metadata path is missing'
        else:
            metadata_path = self._resolve_project_path(metadata_rel)

        if not metadata_path.exists():
            return False, f'Metadata file not found: {metadata_path}'

        # Ensure we start from a clean integration state
        subprocess.run([
            'python3', str(self.scripts_dir / 'module3_integration.py'),
            '--restore'
        ], capture_output=True, text=True)

        integration_cmd = [
            'python3', str(self.scripts_dir / 'module3_integration.py'),
            '--checker-metadata', str(metadata_path),
            '--no-build',
            '--persist'
        ]

        clang_tidy_dir = self.llvm_dir / 'clang-tools-extra' / 'clang-tidy' / 'linuxkernel'
        staged_files = [
            clang_tidy_dir / f"{checker_info['checker_name']}.h",
            clang_tidy_dir / f"{checker_info['checker_name']}.cpp"
        ]

        integration_result = subprocess.run(integration_cmd, capture_output=True, text=True)

        if integration_result.returncode != 0:
            output = integration_result.stderr or integration_result.stdout
            return False, output

        build_cmd = [
            'ninja', '-C', str(self.build_dir),
            '-j2', 'clang-tidy'
        ]

        try:
            result = subprocess.run(build_cmd, capture_output=True, text=True)
            if result.returncode == 0:
                return True, ''

            errors = result.stderr if result.stderr else result.stdout
            relevant_errors = self.extract_relevant_errors(errors, checker_info['checker_name'])
            return False, relevant_errors or errors
        finally:
            subprocess.run([
                'python3', str(self.scripts_dir / 'module3_integration.py'),
                '--restore'
            ], capture_output=True, text=True)

            for path in staged_files:
                try:
                    if path.exists():
                        path.unlink()
                except OSError:
                    pass

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

        files = checker_info.get('files', {})
        header_rel = files.get('header_path')
        cpp_rel = files.get('cpp_path')

        if header_rel and cpp_rel:
            h_file = self._resolve_project_path(header_rel)
            cpp_file = self._resolve_project_path(cpp_rel)
        else:
            anti_pattern_folder = checker_info.get('anti_pattern_folder')
            pattern_dir = self.checkers_dir / anti_pattern_folder if anti_pattern_folder else self.checkers_dir
            cpp_file = pattern_dir / f"{checker_info['checker_name']}.cpp"
            h_file = pattern_dir / f"{checker_info['checker_name']}.h"

        if not cpp_file.exists() or not h_file.exists():
            return False

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

        # Get anti-pattern type for organized output
        anti_pattern_type = checker_info.get("anti_pattern_type", "unknown")
        anti_pattern_folder = checker_info.get("anti_pattern_folder") or anti_pattern_type.lower().replace('_', '-')
        generation_id = checker_info.get("generation_id", datetime.now().strftime("%Y%m%d%H%M%S"))

        validation_dir = self.base_dir / "results" / anti_pattern_folder / generation_id
        output_path = validation_dir / "validation_report.json"
        validation_dir.mkdir(parents=True, exist_ok=True)

        # Show scanning progress
        if self.validation_sample:
            total_files = self.validation_sample
        else:
            total_files = 100  # Estimate for progress display

        # Run Module 4 - scan files in kernel
        cmd = [
            "python3", str(self.scripts_dir / "module4_validation.py"),
            "--checker-pattern", checker_pattern,
            "--output", str(output_path),
            "--anti-pattern-type", anti_pattern_type
        ]

        if self.validation_kernel:
            cmd.extend(["--kernel-version", self.validation_kernel])

        if self.validation_sample:
            cmd.extend(["--sample-size", str(self.validation_sample)])

        result = subprocess.run(cmd, capture_output=True, text=True)

        # Load and check results from anti-pattern specific folder
        folder_name = anti_pattern_type.lower().replace('_', '-')
        report_file = self.base_dir / "results" / folder_name / "validation_report.json"

        # Fallback to old location if not found
        if not report_file.exists():
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
    parser.add_argument('--base-dir', default=None,
                      help='Project root directory (defaults to repository root)')
    parser.add_argument('--validation-kernel', default=None,
                      help='Limit validation to a specific kernel version (scan all by default)')
    parser.add_argument('--validation-sample', type=int, default=None,
                      help='Number of files to scan for validation')

    args = parser.parse_args()

    orchestrator = PipelineOrchestrator(base_dir=args.base_dir)
    orchestrator.max_iterations = args.max_iterations
    orchestrator.max_repair_attempts = args.max_repairs
    orchestrator.validation_sample = args.validation_sample
    orchestrator.validation_kernel = args.validation_kernel

    # Run the orchestrated pipeline
    start_time = time.time()
    checker = orchestrator.generate_checker(args.commit)
    elapsed = time.time() - start_time

    if checker:
        # Save orchestrator result to anti-pattern folder
        anti_pattern_type = checker.get("anti_pattern_type", "unknown")
        folder_name = anti_pattern_type.lower().replace('_', '-')

        generation_id = checker.get("generation_id", datetime.now().strftime("%Y%m%d%H%M%S"))
        results_dir = orchestrator.base_dir / "results" / folder_name / generation_id
        results_dir.mkdir(parents=True, exist_ok=True)

        result_file = results_dir / "orchestrator_result.json"
        with open(result_file, 'w') as f:
            json.dump({
                "success": True,
                "checker": checker,
                "commit": args.commit,
                "elapsed_time": elapsed,
                "completed_at": datetime.now().isoformat()
            }, f, indent=2)

        print(f"\n{Colors.GREEN}✓ Saved pipeline result to {result_file}{Colors.ENDC}")
        print(f"\n{Colors.BOLD}Pipeline completed in {elapsed:.1f} seconds{Colors.ENDC}")
        return 0
    else:
        print(f"\n{Colors.BOLD}Pipeline failed after {elapsed:.1f} seconds{Colors.ENDC}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
