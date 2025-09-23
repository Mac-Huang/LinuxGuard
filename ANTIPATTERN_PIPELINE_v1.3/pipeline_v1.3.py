#!/usr/bin/env python3
"""
ANTIPATTERN_PIPELINE v1.3
3-Step Pipeline for Vulnerability Detection: Analyze → Generate → Scan
"""

import os
import sys

# Import vulnerability type from commit data
try:
    from data.commit_data import VULNERABILITY_TYPE
    vuln_display = VULNERABILITY_TYPE.replace('-', ' ').title()
except ImportError:
    VULNERABILITY_TYPE = 'vulnerability'
    vuln_display = 'Vulnerability'

def run_pipeline():
    """Run the 3-step v1.3 pipeline for vulnerability detection"""

    print("ANTIPATTERN_PIPELINE v1.3")
    print("=" * 40)
    print(f"3-Step Pipeline for {vuln_display} Detection")
    print("=" * 40)

    steps = [
        ("Step 1: Analyze commit with Model", "model_analyzer.py"),
        ("Step 2: Generate checker with Model", "checker_generator.py"),
        (f"Step 3: Multi-version {VULNERABILITY_TYPE} scan", "multi_version_scan_with_checker.py"),
    ]

    results = {}

    for step_name, script_name in steps:
        print(f"\n{step_name}")
        print("-" * 50)

        if os.path.exists(script_name):
            print(f"Running: python {script_name}")
            exit_code = os.system(f"python {script_name}")

            if exit_code == 0:
                print(f"[SUCCESS] {step_name} completed")
                results[step_name] = "SUCCESS"
            else:
                print(f"[FAILED] {step_name} failed")
                results[step_name] = "FAILED"
                break
        else:
            print(f"[ERROR] Script not found: {script_name}")
            results[step_name] = "SCRIPT_NOT_FOUND"
            break

    # Final summary
    print(f"\n{'='*40}")
    print(f"PIPELINE v1.3 SUMMARY - {vuln_display} Detection")
    print(f"{'='*40}")

    successful_steps = sum(1 for result in results.values() if result == "SUCCESS")
    total_steps = len(steps)

    print(f"Completed: {successful_steps}/{total_steps} steps")

    for step_name, result in results.items():
        status = "[PASS]" if result == "SUCCESS" else "[FAIL]"
        print(f"{status} {step_name}")

    if successful_steps == total_steps:
        print(f"\n[COMPLETE] PIPELINE v1.3 SUCCESSFUL!")
        print(f"{vuln_display} vulnerability analysis complete.")
        return 0
    else:
        print(f"\n[FAILED] PIPELINE v1.3 INCOMPLETE")
        return 1

if __name__ == "__main__":
    exit(run_pipeline())