#!/usr/bin/env python3
"""
ANTIPATTERN_PIPELINE v1.2
5-Step Pipeline: Analyze → Generate → Test → Scan → Multi-Version Scan
"""

import os
import sys

def run_pipeline():
    """Run the 5-step v1.2 pipeline"""
    
    print("ANTIPATTERN_PIPELINE v1.2")
    print("=" * 50)
    print("5-Step Pipeline: Analyze → Generate → Test → Scan → Multi-Version")
    print("=" * 50)
    
    steps = [
        ("Step 1: Analyze commit with Gemini", "gemini_analyzer.py"),
        ("Step 2: Generate checker with Gemini", "checker_generator.py"), 
        ("Step 3: Test generated checker", "test_generated_checker.py"),
        ("Step 4: Single-version scan", "scan_with_generated_checker.py"),
        ("Step 5: Multi-version historical scanning", "multi_version_scan_with_checker.py"),
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
                # Continue even if step fails for comprehensive testing
                if "Step 5" not in step_name:  # Only break for critical steps
                    break
        else:
            print(f"[ERROR] Script not found: {script_name}")
            results[step_name] = "SCRIPT_NOT_FOUND"
            break
    
    # Final summary
    print(f"\n{'='*50}")
    print("PIPELINE v1.2 SUMMARY")
    print(f"{'='*50}")
    
    successful_steps = sum(1 for result in results.values() if result == "SUCCESS")
    total_steps = len(steps)
    
    print(f"Completed: {successful_steps}/{total_steps} steps")
    
    for step_name, result in results.items():
        status = "[PASS]" if result == "SUCCESS" else "[FAIL]"
        print(f"{status} {step_name}")
    
    if successful_steps >= 4:  # At least core pipeline works
        print(f"\n[COMPLETE] PIPELINE v1.2 SUCCESSFUL!")
        print("New in v1.2: Added multi-version scanning capability")
        return 0
    else:
        print(f"\n[FAILED] PIPELINE v1.2 INCOMPLETE")
        return 1

if __name__ == "__main__":
    exit(run_pipeline())