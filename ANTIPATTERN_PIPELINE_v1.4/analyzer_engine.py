#!/usr/bin/env python3
"""
Comparative Analysis Framework
Runs multiple detection methods and compares their performance
"""

import os
import sys
import json
import time
import tracemalloc
from pathlib import Path
from typing import Dict, List, Tuple
from datetime import datetime

# Import all detectors
sys.path.insert(0, str(Path(__file__).parent))
from detectors.clang_detector import ClangDetector
from detectors.pattern_detector import PatternDetector
from detectors.coccinelle_detector import CoccinelleDetector

class ComparativeAnalyzer:
    def __init__(self):
        self.detectors = {
            'clang': ClangDetector(),
            'pattern': PatternDetector(),
            'coccinelle': CoccinelleDetector()
        }
        self.results = {}
        self.metrics = {}
        self.ground_truth = self.load_ground_truth()

    def load_ground_truth(self) -> Dict:
        """Load known vulnerabilities as ground truth for evaluation"""
        # In a real scenario, this would load from CVE database or known patches
        ground_truth = {
            'buffer_overflow': [
                {'file': 'net/sctp/sm_make_chunk.c', 'line_range': (3130, 3160)},
                {'file': 'net/ipv4/tcp_input.c', 'line_range': (1000, 1050)},
            ],
            'use_after_free': [
                {'file': 'mm/slab.c', 'line_range': (500, 550)},
                {'file': 'kernel/fork.c', 'line_range': (200, 250)},
            ],
            'null_pointer': [
                {'file': 'drivers/net/ethernet/intel/e1000/e1000_main.c', 'line_range': (100, 150)},
            ]
        }
        return ground_truth

    def run_detector(self, detector_name: str, detector, target_dirs: List[str]) -> Tuple[List[Dict], Dict]:
        """Run a single detector and measure performance"""
        print(f"\n{'='*60}")
        print(f"Running {detector_name} detector...")
        print(f"{'='*60}")

        # Start performance monitoring
        start_time = time.time()
        tracemalloc.start()

        # Run detection
        try:
            results = detector.detect(target_dirs)
        except Exception as e:
            print(f"Error running {detector_name}: {e}")
            results = []

        # Stop performance monitoring
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        end_time = time.time()

        # Calculate metrics
        metrics = {
            'execution_time': end_time - start_time,
            'peak_memory_mb': peak / 1024 / 1024,
            'issues_found': len(results),
            'issues_per_second': len(results) / (end_time - start_time) if (end_time - start_time) > 0 else 0
        }

        return results, metrics

    def calculate_accuracy_metrics(self, detector_results: List[Dict], detector_name: str) -> Dict:
        """Calculate accuracy metrics against ground truth"""
        true_positives = 0
        false_positives = 0
        false_negatives = 0

        # Match results against ground truth
        for vuln_type, known_vulns in self.ground_truth.items():
            for known_vuln in known_vulns:
                found = False
                for result in detector_results:
                    if (result.get('file', '').endswith(known_vuln['file']) and
                        known_vuln['line_range'][0] <= result.get('line', 0) <= known_vuln['line_range'][1]):
                        found = True
                        true_positives += 1
                        break

                if not found:
                    false_negatives += 1

        # Count false positives (results not in ground truth)
        for result in detector_results:
            matched = False
            for vuln_type, known_vulns in self.ground_truth.items():
                for known_vuln in known_vulns:
                    if (result.get('file', '').endswith(known_vuln['file']) and
                        known_vuln['line_range'][0] <= result.get('line', 0) <= known_vuln['line_range'][1]):
                        matched = True
                        break
                if matched:
                    break

            if not matched:
                false_positives += 1

        # Calculate metrics
        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 1
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

        return {
            'true_positives': true_positives,
            'false_positives': false_positives,
            'false_negatives': false_negatives,
            'precision': precision,
            'recall': recall,
            'f1_score': f1_score
        }

    def run_comparison(self, target_dirs: List[str]):
        """Run all detectors and compare results"""
        print("\n" + "="*80)
        print("COMPARATIVE VULNERABILITY DETECTION ANALYSIS")
        print("="*80)

        # Run each detector
        for name, detector in self.detectors.items():
            results, metrics = self.run_detector(name, detector, target_dirs)
            self.results[name] = results
            self.metrics[name] = metrics

            # Calculate accuracy metrics
            accuracy = self.calculate_accuracy_metrics(results, name)
            self.metrics[name].update(accuracy)

        # Generate comparison report
        self.generate_report()

    def generate_report(self):
        """Generate comprehensive comparison report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'detectors': list(self.detectors.keys()),
            'metrics': self.metrics,
            'summary': self.generate_summary(),
            'recommendations': self.generate_recommendations()
        }

        # Save report
        report_file = Path('results/comparative_analysis_report.json')
        report_file.parent.mkdir(exist_ok=True)
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)

        # Print summary
        self.print_summary()

        # Generate markdown report
        self.generate_markdown_report()

    def generate_summary(self) -> Dict:
        """Generate summary statistics"""
        summary = {
            'total_issues_by_detector': {},
            'fastest_detector': None,
            'most_accurate_detector': None,
            'most_efficient_detector': None
        }

        # Find best performers
        min_time = float('inf')
        max_f1 = 0
        max_efficiency = 0

        for name, metrics in self.metrics.items():
            summary['total_issues_by_detector'][name] = metrics.get('issues_found', 0)

            if metrics.get('execution_time', float('inf')) < min_time:
                min_time = metrics['execution_time']
                summary['fastest_detector'] = name

            if metrics.get('f1_score', 0) > max_f1:
                max_f1 = metrics['f1_score']
                summary['most_accurate_detector'] = name

            efficiency = metrics.get('f1_score', 0) / metrics.get('execution_time', 1)
            if efficiency > max_efficiency:
                max_efficiency = efficiency
                summary['most_efficient_detector'] = name

        return summary

    def generate_recommendations(self) -> Dict:
        """Generate recommendations based on analysis"""
        recommendations = {
            'for_speed': [],
            'for_accuracy': [],
            'for_production': [],
            'for_development': []
        }

        for name, metrics in self.metrics.items():
            # Speed recommendations
            if metrics.get('execution_time', float('inf')) < 10:
                recommendations['for_speed'].append({
                    'detector': name,
                    'reason': f"Fast execution: {metrics.get('execution_time', 0):.2f}s"
                })

            # Accuracy recommendations
            if metrics.get('f1_score', 0) > 0.7:
                recommendations['for_accuracy'].append({
                    'detector': name,
                    'reason': f"High F1 score: {metrics.get('f1_score', 0):.2f}"
                })

            # Production recommendations
            if metrics.get('false_positives', float('inf')) < 10:
                recommendations['for_production'].append({
                    'detector': name,
                    'reason': f"Low false positives: {metrics.get('false_positives', 0)}"
                })

            # Development recommendations
            if metrics.get('issues_found', 0) > 0:
                recommendations['for_development'].append({
                    'detector': name,
                    'reason': f"Found {metrics.get('issues_found', 0)} issues"
                })

        return recommendations

    def print_summary(self):
        """Print summary to console"""
        print("\n" + "="*80)
        print("COMPARISON RESULTS SUMMARY")
        print("="*80)

        # Performance comparison table
        print("\nPerformance Metrics:")
        print("-" * 60)
        print(f"{'Detector':<15} {'Time (s)':<12} {'Memory (MB)':<12} {'Issues':<10} {'F1 Score':<10}")
        print("-" * 60)

        for name, metrics in self.metrics.items():
            print(f"{name:<15} "
                  f"{metrics.get('execution_time', 0):<12.2f} "
                  f"{metrics.get('peak_memory_mb', 0):<12.2f} "
                  f"{metrics.get('issues_found', 0):<10} "
                  f"{metrics.get('f1_score', 0):<10.2f}")

        # Best performers
        summary = self.generate_summary()
        print("\n" + "="*80)
        print("BEST PERFORMERS:")
        print(f"  Fastest: {summary['fastest_detector']}")
        print(f"  Most Accurate: {summary['most_accurate_detector']}")
        print(f"  Most Efficient: {summary['most_efficient_detector']}")

    def generate_markdown_report(self):
        """Generate detailed markdown report"""
        report_lines = []
        report_lines.append("# Comparative Vulnerability Detection Analysis Report")
        report_lines.append(f"\n**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append("\n## Executive Summary")

        summary = self.generate_summary()
        report_lines.append(f"\n- **Fastest Detector:** {summary['fastest_detector']}")
        report_lines.append(f"- **Most Accurate:** {summary['most_accurate_detector']}")
        report_lines.append(f"- **Most Efficient:** {summary['most_efficient_detector']}")

        # Detailed metrics table
        report_lines.append("\n## Detailed Performance Metrics")
        report_lines.append("\n| Detector | Execution Time (s) | Memory (MB) | Issues Found | Precision | Recall | F1 Score |")
        report_lines.append("|----------|-------------------|-------------|--------------|-----------|--------|----------|")

        for name, metrics in self.metrics.items():
            report_lines.append(f"| {name} | "
                              f"{metrics.get('execution_time', 0):.2f} | "
                              f"{metrics.get('peak_memory_mb', 0):.2f} | "
                              f"{metrics.get('issues_found', 0)} | "
                              f"{metrics.get('precision', 0):.2f} | "
                              f"{metrics.get('recall', 0):.2f} | "
                              f"{metrics.get('f1_score', 0):.2f} |")

        # Recommendations
        report_lines.append("\n## Recommendations")
        recommendations = self.generate_recommendations()

        for category, recs in recommendations.items():
            if recs:
                report_lines.append(f"\n### {category.replace('_', ' ').title()}")
                for rec in recs:
                    report_lines.append(f"- **{rec['detector']}**: {rec['reason']}")

        # Write report
        report_file = Path('results/comparative_analysis_report.md')
        report_file.write_text('\n'.join(report_lines))
        print(f"\nDetailed report saved to: {report_file}")

def main():
    """Run comparative analysis"""
    analyzer = ComparativeAnalyzer()

    target_dirs = [
        "net/core",
        "net/ipv4",
        "mm",
        "kernel"
    ]

    analyzer.run_comparison(target_dirs)

if __name__ == "__main__":
    main()