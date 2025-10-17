#!/usr/bin/env python3
"""
Test framework for validating checkers before kernel scanning.
Creates minimal test cases based on vulnerability patterns.
"""

import json
import subprocess
import tempfile
import argparse
from pathlib import Path
from typing import Dict, Optional, List

class CheckerTester:
    """Tests checkers with minimal vulnerable code samples."""

    def __init__(self, clang_tidy_path: str, base_dir: str = "../"):
        self.clang_tidy_path = Path(clang_tidy_path)
        self.base_dir = Path(base_dir)
        self.test_dir = self.base_dir / "tests" / "checker_tests"
        self.test_dir.mkdir(parents=True, exist_ok=True)

    def create_test_case(self, pattern: Dict) -> Optional[Path]:
        """Create a minimal C file containing the vulnerable pattern."""

        if not pattern or 'vulnerable_pattern' not in pattern:
            print("  ✗ No vulnerable pattern found in analysis")
            return None

        vuln_pattern = pattern['vulnerable_pattern']
        code_context = vuln_pattern.get('code_context', '')
        description = vuln_pattern.get('description', '')
        anti_pattern_type = pattern.get('anti_pattern_type', 'unknown')

        # Extract specific functions mentioned in the pattern
        key_indicators = vuln_pattern.get('key_indicators', [])

        # Create test filename based on anti-pattern type
        test_name = f"test_{anti_pattern_type.replace('-', '_')}.c"
        test_file = self.test_dir / test_name

        # Build the test case for the specific of_changeset_add_property pattern
        if 'of_changeset_add_property' in str(key_indicators) or 'of_changeset_add_property' in code_context:
            # This is the specific use-after-free case from the pattern
            test_code = f"""
/* Test case for use-after-free vulnerability
 * Pattern: {description}
 * Code context from bug: {code_context}
 */

#include <stdlib.h>
#include <stdio.h>

struct property {{
    char *name;
    int length;
    void *value;
    struct property *next;
}};

struct device_node {{
    const char *name;
    struct property *properties;
    struct property *deadprops;
}};

// Mock function that sometimes fails
int of_changeset_add_property(void *changeset, struct property *prop) {{
    // Simulate occasional failure
    static int call_count = 0;
    return (++call_count % 2) ? -1 : 0;  // Fails every other call
}}

// Mock free function
void __of_prop_free(struct property *prop) {{
    if (prop) {{
        free(prop);
    }}
}}

// Vulnerable function matching the exact pattern
void vulnerable_pattern_test(struct device_node *np) {{
    struct property *new_pp = malloc(sizeof(struct property));
    int ret;

    if (!new_pp)
        return;

    new_pp->name = "test_property";
    new_pp->length = 0;
    new_pp->value = NULL;
    new_pp->next = NULL;

    // The exact vulnerable pattern from the commit
    ret = of_changeset_add_property(NULL, new_pp);
    if (ret)
        __of_prop_free(new_pp);  // Free on error

    new_pp->next = np->deadprops;  // USE AFTER FREE - new_pp was freed above!
    np->deadprops = new_pp;
}}

int main() {{
    struct device_node node = {{"test_node", NULL, NULL}};
    vulnerable_pattern_test(&node);
    return 0;
}}
"""
        else:
            # Generic use-after-free pattern as fallback
            test_code = f"""
/* Test case for {anti_pattern_type} vulnerability
 * Pattern: {description}
 * Key indicators: {', '.join(key_indicators[:3]) if key_indicators else 'None'}
 */

#include <stdlib.h>
#include <stdio.h>

struct data {{
    int value;
    struct data *next;
}};

void vulnerable_function() {{
    struct data *ptr = malloc(sizeof(struct data));
    int error_condition = 1;  // Simulate error

    if (!ptr)
        return;

    ptr->value = 42;
    ptr->next = NULL;

    // Vulnerable pattern: free in error path without return
    if (error_condition) {{
        free(ptr);  // Free the pointer
        // Missing return here!
    }}

    ptr->value = 100;  // USE AFTER FREE
    ptr->next = NULL;  // USE AFTER FREE
}}

int main() {{
    vulnerable_function();
    return 0;
}}
"""

        # Write test file
        with open(test_file, 'w') as f:
            f.write(test_code)

        return test_file

    def run_checker_on_test(self, test_file: Path, checker_name: str) -> Dict:
        """Run specific checker on test file."""

        checker_pattern = self.get_checker_pattern(checker_name)

        # Create minimal compile_commands.json for test
        compile_db = [{
            "directory": str(test_file.parent),
            "command": f"cc -c {test_file.name}",
            "file": str(test_file)
        }]

        compile_db_path = test_file.parent / "compile_commands.json"
        with open(compile_db_path, 'w') as f:
            json.dump(compile_db, f)

        # Run clang-tidy
        cmd = [
            str(self.clang_tidy_path),
            f"-checks=-*,{checker_pattern}",
            "-p", str(test_file.parent),
            str(test_file)
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)

        # Parse output for detections
        detections = []
        for line in result.stdout.split('\n'):
            if 'warning:' in line and checker_pattern in line:
                detections.append(line.strip())

        return {
            "test_file": str(test_file),
            "checker": checker_pattern,
            "passed": len(detections) > 0,
            "detections": detections,
            "output": result.stdout[:1000]  # First 1000 chars
        }

    def validate_checker(self, checker_name: str, pattern_file: str) -> bool:
        """Validate that a checker detects its target pattern."""

        # Load pattern
        with open(pattern_file, 'r') as f:
            pattern = json.load(f)

        print(f"Testing {checker_name} against vulnerability pattern...")

        # Create test case
        test_file = self.create_test_case(pattern)
        if not test_file:
            print("✗ Failed to create test case")
            return False

        print(f"✓ Created test case: {test_file}")

        # Run checker
        result = self.run_checker_on_test(test_file, checker_name)

        if result['passed']:
            print(f"✓ Checker detected the vulnerability!")
            for detection in result['detections']:
                print(f"  - {detection}")
            return True
        else:
            print(f"✗ Checker did NOT detect the vulnerability")
            print(f"  Output: {result['output']}")
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

    def create_standard_test_suite(self) -> Dict[str, Path]:
        """Create standard test cases for common vulnerabilities."""

        tests = {}

        # Use-after-free test
        uaf_code = """
#include <stdlib.h>

struct device {
    int id;
    char *name;
};

int of_changeset_add_property(void *cs, void *prop) {
    // Simulated function
    return rand() % 2;  // Sometimes fails
}

void __of_prop_free(void *prop) {
    free(prop);
}

void vulnerable_function() {
    struct device *new_pp = malloc(sizeof(struct device));
    void *changeset = NULL;
    int ret;

    ret = of_changeset_add_property(changeset, new_pp);
    if (ret) {
        __of_prop_free(new_pp);  // Free on error
    }

    new_pp->id = 42;  // Use after free!
}

int main() {
    vulnerable_function();
    return 0;
}
"""

        uaf_test = self.test_dir / "use_after_free_test.c"
        with open(uaf_test, 'w') as f:
            f.write(uaf_code)
        tests['use-after-free'] = uaf_test

        # Add more standard tests as needed

        return tests

def main():
    parser = argparse.ArgumentParser(description='Test checker validation')
    parser.add_argument('--clang-tidy',
                      default='../llvm-project/build/bin/clang-tidy',
                      help='Path to clang-tidy binary')
    parser.add_argument('--checker', required=True,
                      help='Checker name to test')
    parser.add_argument('--pattern',
                      default='../results/anti_patterns.json',
                      help='Pattern file from analysis')
    parser.add_argument('--create-standard', action='store_true',
                      help='Create standard test suite')

    args = parser.parse_args()

    tester = CheckerTester(args.clang_tidy)

    if args.create_standard:
        print("Creating standard test suite...")
        tests = tester.create_standard_test_suite()
        for name, path in tests.items():
            print(f"  ✓ Created {name} test: {path}")
    else:
        # Validate specific checker
        success = tester.validate_checker(args.checker, args.pattern)

        if success:
            print("\n✅ Checker validation PASSED")
            return 0
        else:
            print("\n❌ Checker validation FAILED")
            return 1

if __name__ == "__main__":
    exit(main())
