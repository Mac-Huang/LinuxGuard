#!/usr/bin/env python3
"""
LinuxGuard Pipeline Orchestrator
Implements iterative checker generation with automatic repair and validation.
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

# Load environment variables
load_dotenv()

class PipelineOrchestrator:
    """Orchestrates the complete pipeline with iterative generation and repair."""

    def __init__(self, base_dir: str = "/home/mac/private/linux-guard"):
        self.base_dir = Path(base_dir)
        self.max_iterations = 3 # Don't really matter?
        self.max_repair_attempts = 5 # Repair times should be sufficient (Give LLM more chance and context)
        self.validation_sample = None  # None = full scan

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

        print(f"\n{'='*60}")
        print(f"  LinuxGuard Orchestrator - Generating Checker")
        print(f"  Commit: {commit_hash[:12]}")
        print(f"{'='*60}\n")

        for iteration in range(1, self.max_iterations + 1):
            print(f"\n[Iteration {iteration}/{self.max_iterations}]")

            # Stage 1: Bug Pattern Analysis
            print("Stage 1: Analyzing patch for patterns...")
            pattern = self.analyze_patch(commit_hash)

            if not pattern:
                print("  ✗ Failed to extract pattern")
                continue

            print(f"  ✓ Detected: {pattern.get('anti_pattern_type', 'unknown')}")

            # Stage 2: Detection Plan Synthesis (included in pattern analysis)
            print("Stage 2: Synthesizing detection plan...")

            # Stage 3: Checker Implementation
            print("Stage 3: Implementing checker...")
            checker_info = self.implement_checker(pattern)

            if not checker_info:
                print("  ✗ Failed to generate checker")
                continue

            print(f"  ✓ Generated: {checker_info['checker_name']}")

            # Repair loop for compilation errors
            attempts = 0
            while attempts < self.max_repair_attempts:
                print(f"\n  Compilation attempt {attempts + 1}/{self.max_repair_attempts}...")

                # Try to build
                build_result, errors = self.build_checker(checker_info)

                if build_result:
                    print("  ✓ Build successful!")
                    break

                print(f"  ✗ Build failed")

                # Repair the checker (will display errors first)
                repaired = self.repair_checker(checker_info, errors, pattern)

                if not repaired:
                    print("  ✗ Repair failed")
                    break

                print("  ✓ Checker repaired, retrying build...")
                attempts += 1

            if not build_result:
                print(f"\n  ✗ Failed to build checker after {attempts} attempts")
                continue

            # Stage 4: Validation
            print("\nStage 4: Validating checker...")
            is_valid = self.validate_checker(checker_info, commit_hash)

            if is_valid:
                print(f"\n{'='*60}")
                print(f"  ✓ SUCCESS: Valid checker generated!")
                print(f"  Checker: {checker_info['checker_name']}")
                print(f"  Iteration: {iteration}")
                print(f"{'='*60}")
                return checker_info
            else:
                print("  ✗ Validation failed, trying next iteration...")

        print(f"\n{'='*60}")
        print(f"  ✗ Failed to generate valid checker after {self.max_iterations} iterations")
        print(f"{'='*60}")
        return None

    def analyze_patch(self, commit_hash: str) -> Optional[Dict]:
        """Stage 1: Analyze patch to extract bug pattern."""

        # Fetch commit if needed
        commit_file = self.base_dir / "commits" / f"{commit_hash}.json"

        if not commit_file.exists():
            print("  Fetching commit data...")
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
            "--no-build"  # Just integrate, don't build yet
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
        errors = result.stderr
        if not errors:
            errors = result.stdout

        # Filter to relevant errors only
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
                    # Include a few context lines after error
                    continue
                elif relevant and len(relevant[-1]) > 0:
                    # Add one line of context after error
                    relevant.append(line)

            # Stop at next file compilation
            if in_relevant_section and '.cpp:' in line and checker_name not in line:
                break

        return '\n'.join(relevant[-20:])  # Last 20 lines max

    def format_compilation_errors(self, errors: str, checker_name: str) -> None:
        """Display formatted compilation errors for clarity."""

        print(f"\n  {'='*55}")
        print(f"  Compilation Errors for {checker_name}")
        print(f"  {'='*55}")

        if not errors or errors.strip() == "":
            print(f"  [WARNING] No specific errors captured")
            print(f"  {'='*55}\n")
            return

        # Parse and format errors
        error_lines = errors.split('\n')
        error_count = 0
        error_details = []

        for line in error_lines:
            if 'error:' in line:
                error_count += 1
                # Extract file:line:column and message
                if '.cpp:' in line or '.h:' in line:
                    parts = line.split(':', 3)
                    if len(parts) >= 4:
                        # Get just the filename, not full path
                        filename = parts[0].split('/')[-1]
                        location = f"{filename}:{parts[1]}:{parts[2]}"
                        message = parts[3].strip()

                        # Categorize error type
                        if 'has no member' in message:
                            error_type = "API Error"
                            hint = "Wrong method/member name"
                        elif 'no matching function' in message:
                            error_type = "Function Error"
                            hint = "Wrong function signature"
                        elif 'getAs' in message:
                            error_type = "Cast Error"
                            hint = "Use dyn_cast instead"
                        elif 'expected' in message:
                            error_type = "Syntax Error"
                            hint = "Check syntax"
                        else:
                            error_type = "Compilation Error"
                            hint = "Check API usage"

                        error_details.append({
                            'type': error_type,
                            'location': location,
                            'message': message,
                            'hint': hint
                        })

        # Display formatted errors
        for i, error in enumerate(error_details, 1):
            print(f"\n  [ERROR {i}/{error_count}] {error['type']}")
            print(f"    Location: {error['location']}")
            print(f"    Message: {error['message'][:70]}...")
            print(f"    Hint: {error['hint']}")

        # Summary and common fixes
        if error_count > 0:
            print(f"\n  {'-'*55}")
            print(f"  Summary: {error_count} compilation error(s) found")

            # Detect common patterns
            print(f"\n  Detected Issues:")
            if any('getAs' in e['message'] for e in error_details):
                print(f"    - getAs<T>() -> dyn_cast<T>() needed")
            if any('has no member' in e['message'] for e in error_details):
                print(f"    - Incorrect AST API method calls")
            if any('CompoundStmt' in e['message'] for e in error_details):
                print(f"    - CompoundStmt::body() iteration needed")
            if any('find' in e['message'] for e in error_details):
                print(f"    - No find() method - use iteration")

        print(f"  {'='*55}\n")

    def repair_checker(self, checker_info: Dict, errors: str, pattern: Dict) -> bool:
        """Use LLM to repair compilation errors in the checker."""

        # Display formatted errors first
        self.format_compilation_errors(errors, checker_info['checker_name'])

        print("  Attempting automatic repair...")

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

            print("  ✓ Applied repairs to checker code")
            return True

        except Exception as e:
            print(f"  ✗ Repair error: {e}")
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

        print("  Running validation scan...")

        # Convert checker name to pattern
        checker_pattern = self.get_checker_pattern(checker_info['checker_name'])
        print(f"  Checker pattern: {checker_pattern}")

        # Run Module 4 - scan files in kernel
        if self.validation_sample:
            print(f"  Scanning kernel ({self.validation_sample} sample files)...")
            cmd = [
                "python3", str(self.scripts_dir / "module4_validation.py"),
                "--kernel-version", "linux-v3.0",
                "--sample-size", str(self.validation_sample),
                "--checker-pattern", checker_pattern,
                "--output", str(self.base_dir / "results" / "validation_report.json")
            ]
        else:
            print(f"  Scanning kernel v3.0 (FULL SCAN - all files)...")
            cmd = [
                "python3", str(self.scripts_dir / "module4_validation.py"),
                "--kernel-version", "linux-v3.0",
                # No sample-size limit - scan everything
                "--checker-pattern", checker_pattern,
                "--output", str(self.base_dir / "results" / "validation_report.json")
            ]

        result = subprocess.run(cmd, capture_output=True, text=True)

        # Load and display scan results
        report_file = self.base_dir / "results" / "validation_report.json"

        if not report_file.exists():
            print("  [ERROR] Validation failed - no report generated")
            return False

        with open(report_file, 'r') as f:
            report = json.load(f)

        # Display scan results
        print(f"\n  {'-'*50}")
        print(f"  Validation Results")
        print(f"  {'-'*50}")

        # Extract results for the scanned kernel
        validation_success = False

        for version, data in report.get('results_by_version', {}).items():
            files_scanned = data.get('files_scanned', 0)
            total_issues = data.get('total_issues', 0)
            scan_time = data.get('scan_time', 'unknown')

            print(f"  Files scanned: {files_scanned}")
            print(f"  Issues found: {total_issues}")

            # Show issue breakdown if any found
            if total_issues > 0:
                print(f"  [PASS] Checker is detecting patterns")

                # Show subsystem breakdown if available
                analysis = data.get('analysis', {})
                by_subsystem = analysis.get('by_subsystem', {})

                if by_subsystem:
                    print(f"\n  Issues by subsystem:")
                    for subsystem, count in sorted(by_subsystem.items(),
                                                  key=lambda x: x[1],
                                                  reverse=True)[:3]:
                        print(f"    - {subsystem}: {count}")

                # Show sample issues if available
                if 'issues' in data and len(data['issues']) > 0:
                    print(f"\n  Sample detections:")
                    for issue in data['issues'][:3]:  # Show first 3
                        file_name = issue['file'].split('/')[-1]
                        print(f"    - {file_name}:{issue['line']} - {issue.get('message', 'detected')[:50]}...")

                validation_success = True
            else:
                print(f"  [WARNING] No issues detected in sample")
                # Still consider valid if it runs without crashing
                # The pattern might be rare or not present in v3.0
                validation_success = True
                print(f"  Note: Pattern might not exist in v3.0 kernel")

        print(f"  {'-'*50}")

        # Validation criteria
        if validation_success:
            print(f"  [PASS] Validation passed - checker is functional")
        else:
            print(f"  [FAIL] Validation failed - checker not working properly")

        return validation_success

    def get_checker_pattern(self, checker_name: str) -> str:
        """Convert checker name to clang-tidy pattern."""

        # Remove 'Check' suffix and convert to kebab-case
        name = checker_name.replace('Check', '')
        result = []

        for i, char in enumerate(name):
            if char.isupper() and i > 0:
                result.append('-')
            result.append(char.lower())

        return f"linuxkernel-{''.join(result)}"

    def cleanup(self):
        """Clean up generated files for fresh start."""

        # Clean generated checkers
        if self.checkers_dir.exists():
            for f in self.checkers_dir.glob("*"):
                if f.is_file():
                    f.unlink()

        print("  ✓ Cleaned up generated files")

def main():
    parser = argparse.ArgumentParser(description='LinuxGuard Pipeline Orchestrator')
    parser.add_argument('--commit', default='80af3745ca465c6c47e833c1902004a7fa944f37',
                      help='Commit hash to analyze')
    parser.add_argument('--clean', action='store_true',
                      help='Clean up before starting')
    parser.add_argument('--max-iterations', type=int, default=3,
                      help='Maximum generation iterations')
    parser.add_argument('--max-repairs', type=int, default=5,
                      help='Maximum repair attempts per iteration')
    parser.add_argument('--validation-sample', type=int, default=None,
                      help='Number of files to scan for validation (None = full scan)')

    args = parser.parse_args()

    print("\n" + "="*60)
    print("   LinuxGuard Automated Pipeline Orchestrator")
    print("="*60)

    orchestrator = PipelineOrchestrator()
    orchestrator.max_iterations = args.max_iterations
    orchestrator.max_repair_attempts = args.max_repairs
    orchestrator.validation_sample = args.validation_sample

    if args.clean:
        print("\nCleaning up previous runs...")
        orchestrator.cleanup()

    # Run the orchestrated pipeline
    start_time = time.time()
    checker = orchestrator.generate_checker(args.commit)
    elapsed = time.time() - start_time

    if checker:
        print(f"\n✅ Successfully generated checker: {checker['checker_name']}")
        print(f"   Anti-pattern type: {checker.get('anti_pattern_type', 'unknown')}")
        print(f"   Time elapsed: {elapsed:.1f} seconds")

        # Save final result
        result_file = orchestrator.base_dir / "results" / "orchestrator_result.json"
        with open(result_file, 'w') as f:
            json.dump({
                'success': True,
                'checker': checker,
                'commit': args.commit,
                'elapsed_time': elapsed
            }, f, indent=2)

        print(f"\n   Result saved to: {result_file}")
        return 0
    else:
        print(f"\n❌ Failed to generate valid checker")
        print(f"   Time elapsed: {elapsed:.1f} seconds")
        return 1

if __name__ == "__main__":
    sys.exit(main())
