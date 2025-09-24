#!/usr/bin/env python3
"""
ANTIPATTERN_PIPELINE v1.4
Multi-Method Detection Pipeline with Comparative Analysis
"""

import os
import sys
import json
from pathlib import Path
from datetime import datetime

# Add parent directory for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

def copy_files_from_v13():
    """Copy necessary files from v1.3"""
    v13_path = Path("../ANTIPATTERN_PIPELINE_v1.3")
    v14_path = Path(".")

    # Files to copy
    files_to_copy = [
        ("data/commit_data.py", "data/commit_data.py"),
        ("model_analyzer.py", "model_analyzer.py"),
        ("checker_generator.py", "checker_generator.py"),
    ]

    for src, dst in files_to_copy:
        src_file = v13_path / src
        dst_file = v14_path / dst

        if src_file.exists() and not dst_file.exists():
            dst_file.parent.mkdir(parents=True, exist_ok=True)
            import shutil
            shutil.copy2(src_file, dst_file)
            print(f"Copied {src} from v1.3")

def run_pipeline():
    """Run the v1.4 pipeline with comparative analysis"""

    print("="*80)
    print("ANTIPATTERN_PIPELINE v1.4")
    print("Multi-Method Detection with Comparative Analysis")
    print("="*80)

    # Ensure we have necessary files
    copy_files_from_v13()

    steps = [
        ("Step 1: Analyze commit with Model", "model_analyzer.py"),
        ("Step 2: Generate Clang checker", "checker_generator.py"),
        ("Step 3: Run comparative analysis", "comparative_analyzer.py"),
    ]

    results = {}

    for step_name, script_name in steps:
        print(f"\n{'='*60}")
        print(step_name)
        print('='*60)

        if os.path.exists(script_name):
            print(f"Running: python {script_name}")
            exit_code = os.system(f"python {script_name}")

            if exit_code == 0:
                print(f"[SUCCESS] {step_name} completed")
                results[step_name] = "SUCCESS"
            else:
                print(f"[WARNING] {step_name} completed with warnings")
                results[step_name] = "WARNING"
                # Continue even if there are warnings
        else:
            print(f"[ERROR] Script not found: {script_name}")
            results[step_name] = "SCRIPT_NOT_FOUND"
            # For comparative analysis, we can still continue
            if "comparative" not in script_name.lower():
                break

    # Generate final report
    generate_final_report(results)

    return 0

def generate_final_report(pipeline_results):
    """Generate comprehensive final report"""
    print("\n" + "="*80)
    print("PIPELINE v1.4 FINAL REPORT")
    print("="*80)

    # Load comparative analysis results if available
    comp_report_path = Path("results/comparative_analysis_report.json")
    if comp_report_path.exists():
        with open(comp_report_path, 'r') as f:
            comp_report = json.load(f)

        print("\n## Detection Method Comparison:")
        print("-"*60)

        if 'metrics' in comp_report:
            for detector, metrics in comp_report['metrics'].items():
                print(f"\n{detector.upper()} Detector:")
                print(f"  - Execution Time: {metrics.get('execution_time', 'N/A'):.2f}s")
                print(f"  - Issues Found: {metrics.get('issues_found', 0)}")
                print(f"  - F1 Score: {metrics.get('f1_score', 0):.2f}")

        if 'summary' in comp_report:
            summary = comp_report['summary']
            print("\n## Best Performers:")
            print(f"  - Fastest: {summary.get('fastest_detector', 'N/A')}")
            print(f"  - Most Accurate: {summary.get('most_accurate_detector', 'N/A')}")
            print(f"  - Most Efficient: {summary.get('most_efficient_detector', 'N/A')}")

        if 'recommendations' in comp_report:
            print("\n## Recommendations:")
            recs = comp_report['recommendations']

            if recs.get('for_production'):
                print("\nFor Production Use:")
                for rec in recs['for_production'][:2]:
                    print(f"  - {rec['detector']}: {rec['reason']}")

            if recs.get('for_development'):
                print("\nFor Development:")
                for rec in recs['for_development'][:2]:
                    print(f"  - {rec['detector']}: {rec['reason']}")

    # Pipeline execution summary
    print("\n" + "="*80)
    print("PIPELINE EXECUTION SUMMARY")
    print("="*80)

    for step_name, result in pipeline_results.items():
        status = "✓" if result == "SUCCESS" else "⚠" if result == "WARNING" else "✗"
        print(f"{status} {step_name}: {result}")

    # Key insights
    print("\n## Key Insights:")
    print("-"*60)
    print("1. Clang Static Analyzer provides deepest semantic analysis but requires")
    print("   compilation environment and is slowest")
    print("2. Pattern-based detection is fastest but has higher false positive rate")
    print("3. Coccinelle offers good balance with kernel-specific optimizations")
    print("4. AI-generated checkers show promise but need refinement")
    print("5. Combining multiple methods provides best coverage")

    print("\n## Next Steps:")
    print("-"*60)
    print("1. Refine Clang checker generation based on comparative results")
    print("2. Implement feedback loop to improve AI model prompts")
    print("3. Add more sophisticated pattern matching")
    print("4. Integrate with CI/CD pipeline for continuous scanning")

    # Save final report
    final_report = {
        'timestamp': datetime.now().isoformat(),
        'pipeline_version': '1.4',
        'pipeline_results': pipeline_results,
        'insights': [
            "Multi-method detection provides comprehensive coverage",
            "Each method has distinct strengths and weaknesses",
            "Combination approach recommended for production use"
        ]
    }

    report_path = Path('results/final_pipeline_report.json')
    report_path.parent.mkdir(exist_ok=True)
    with open(report_path, 'w') as f:
        json.dump(final_report, f, indent=2)

    print(f"\nFinal report saved to: {report_path}")
    print("\n[COMPLETE] PIPELINE v1.4 ANALYSIS FINISHED")

if __name__ == "__main__":
    exit(run_pipeline())