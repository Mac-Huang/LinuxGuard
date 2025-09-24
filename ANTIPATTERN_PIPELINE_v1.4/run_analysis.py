#!/usr/bin/env python3
"""
Run Complete Comparison Analysis for v1.4
Including AI-generated buffer overflow checker
"""

import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from analyzer_engine import ComparativeAnalyzer

class ExtendedComparativeAnalyzer(ComparativeAnalyzer):
    def __init__(self):
        super().__init__()
        # Add AI-generated checker as a detection method
        self.add_ai_checker()

    def add_ai_checker(self):
        """Add AI-generated buffer overflow checker"""
        from detectors.clang_detector import ClangDetector

        class AICheckerDetector(ClangDetector):
            def __init__(self):
                super().__init__(checker_path="generated", kernel_path="test_files/kernel")
                self.name = "ai_buffer_overflow"

            def detect(self, target_dirs):
                """Run AI-generated checker"""
                print("\n=== AI-Generated Buffer Overflow Checker ===")
                # Use the generated BufferOverflowChecker.cpp
                return super().detect(target_dirs)

        self.detectors['ai_checker'] = AICheckerDetector()

def main():
    print("="*80)
    print("ANTIPATTERN PIPELINE v1.4 - FULL COMPARISON ANALYSIS")
    print("="*80)

    analyzer = ExtendedComparativeAnalyzer()

    # Use test files if no kernel available
    kernel_path = Path("../../../linux")
    if kernel_path.exists():
        target_dirs = ["net/core", "drivers/net", "mm"]
    else:
        print("\n[INFO] Using test files (Linux kernel not found)")
        target_dirs = ["test_files/kernel"]

    # Run comparison
    analyzer.run_comparison(target_dirs)

    print("\n[COMPLETE] Full comparison analysis finished")
    print("Check results/ directory for detailed reports")

if __name__ == "__main__":
    main()
