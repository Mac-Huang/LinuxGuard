#!/usr/bin/env python3
"""
Test the full comparative analysis with all detection methods
Including the AI-generated buffer overflow checker
"""

import sys
import json
import time
from pathlib import Path

# Ensure proper imports
sys.path.insert(0, str(Path(__file__).parent))

def test_analysis():
    """Test the comparative analysis framework"""
    print("="*80)
    print("TESTING COMPARATIVE ANALYSIS - v1.4")
    print("="*80)

    # Check configuration
    print("\n[1/5] Checking configuration...")
    try:
        import config
        print(f"  Model: {config.MODEL_NAME}")
        print(f"  API Key: {'Configured' if config.MODEL_API_KEY != 'YOUR_API_KEY_HERE' else 'NOT SET'}")
    except Exception as e:
        print(f"  [WARNING] Config issue: {e}")

    # Test pattern detector
    print("\n[2/5] Testing pattern detector...")
    try:
        from detectors.pattern_detector import PatternDetector
        detector = PatternDetector(kernel_path="test_files/kernel")

        # Create a test file if needed
        test_dir = Path("test_files/kernel")
        test_dir.mkdir(parents=True, exist_ok=True)

        test_file = test_dir / "test.c"
        test_code = """
void test_buffer_overflow() {
    char buffer[10];
    strcpy(buffer, user_input);  // Buffer overflow
}

void test_use_after_free() {
    char *ptr = malloc(100);
    free(ptr);
    *ptr = 'A';  // Use after free
}
"""
        test_file.write_text(test_code)

        # Run detection
        results = detector.scan_file_content(test_code, "test.c")
        print(f"  [OK] Pattern detector found {len(results)} issues")
        for r in results[:2]:
            print(f"    - {r['type']} at line {r['line']}")
    except Exception as e:
        print(f"  [ERROR] Pattern detector failed: {e}")

    # Test Coccinelle (simulation)
    print("\n[3/5] Testing Coccinelle detector...")
    try:
        from detectors.coccinelle_detector import CoccinelleDetector
        detector = CoccinelleDetector(kernel_path="test_files/kernel")

        # This will run in simulation mode if Coccinelle not installed
        results = detector.detect(["test_files/kernel"])
        print(f"  [OK] Coccinelle detector returned {len(results)} results")
        if len(results) > 0:
            print(f"    Running in: {'simulation' if 'simulated' in str(results[0]) else 'real'} mode")
    except Exception as e:
        print(f"  [ERROR] Coccinelle detector failed: {e}")

    # Test Clang detector
    print("\n[4/5] Testing Clang detector...")
    try:
        from detectors.clang_detector import ClangDetector
        detector = ClangDetector(checker_path="generated", kernel_path="test_files/kernel")

        # This will simulate if LLVM dev tools not available
        results = detector.detect(["test_files/kernel"])
        print(f"  [OK] Clang detector returned {len(results)} results")
    except Exception as e:
        print(f"  [ERROR] Clang detector failed: {e}")

    # Test full comparative analysis
    print("\n[5/5] Running full comparative analysis...")
    try:
        from analyzer_engine import ComparativeAnalyzer

        analyzer = ComparativeAnalyzer()

        # Use test files
        target_dirs = ["test_files/kernel"]

        # Run comparison
        print("  Running all detectors...")
        for name, detector in analyzer.detectors.items():
            print(f"    - {name}...", end="")
            try:
                results, metrics = analyzer.run_detector(name, detector, target_dirs)
                print(f" OK ({len(results)} issues, {metrics['execution_time']:.2f}s)")
            except Exception as e:
                print(f" FAILED: {e}")

        # Generate report
        analyzer.generate_report()
        print("\n  [OK] Comparative analysis complete")

        # Show summary
        if Path("results/comparative_analysis_report.json").exists():
            with open("results/comparative_analysis_report.json", 'r') as f:
                report = json.load(f)

            print("\n  Summary:")
            if 'summary' in report:
                summary = report['summary']
                print(f"    Fastest: {summary.get('fastest_detector', 'N/A')}")
                print(f"    Most Accurate: {summary.get('most_accurate_detector', 'N/A')}")

    except Exception as e:
        print(f"  [ERROR] Comparative analysis failed: {e}")
        import traceback
        traceback.print_exc()

    print("\n" + "="*80)
    print("TEST COMPLETE")
    print("="*80)
    print("\nResults saved in:")
    print("  - results/comparative_analysis_report.json")
    print("  - results/comparative_analysis_report.md")
    print("  - results/*_detector_results.json")

def main():
    test_analysis()

if __name__ == "__main__":
    main()