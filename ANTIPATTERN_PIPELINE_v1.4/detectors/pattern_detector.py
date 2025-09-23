#!/usr/bin/env python3
"""
Pattern-Based Vulnerability Detector
Enhanced regex and pattern matching from v1.3
"""

import re
import json
import subprocess
from pathlib import Path
from typing import List, Dict

class PatternDetector:
    def __init__(self, kernel_path="../../../linux"):
        self.kernel_path = Path(kernel_path)
        self.results = []

        # Enhanced vulnerability patterns
        self.patterns = {
            'buffer_overflow': [
                (r'\b(strcpy|strcat|sprintf|gets)\s*\(', 'unsafe_string_function', 'high'),
                (r'memcpy\s*\([^,]+,[^,]+,[^)]*\+[^)]*\)', 'unchecked_memcpy_size', 'high'),
                (r'(\w+)\[([^\]]+)\]\s*=', 'unchecked_array_write', 'medium'),
                (r'malloc\s*\([^)]*\*[^)]*\)', 'integer_overflow_alloc', 'medium'),
                (r'snprintf\s*\([^;]+\);(?!\s*if)', 'unchecked_snprintf', 'low'),
            ],
            'use_after_free': [
                (r'kfree\s*\([^)]+\).*\n.*\1->', 'use_after_kfree', 'critical'),
                (r'free\s*\([^)]+\).*\n.*\1->', 'use_after_free', 'critical'),
                (r'return.*;\s*}\s*kfree\s*\(', 'late_free_pattern', 'medium'),
            ],
            'null_pointer': [
                (r'(\w+)\s*=\s*NULL;.*\n.*\1->', 'null_deref', 'high'),
                (r'if\s*\(\s*!\s*(\w+)\s*\).*\n.*\1->', 'inconsistent_null_check', 'medium'),
                (r'(\w+)->.*(?<!if.*)\1\s*==\s*NULL', 'missing_null_check', 'high'),
            ],
            'race_condition': [
                (r'mutex_unlock.*\n.*\n.*mutex_lock', 'potential_race_window', 'medium'),
                (r'spin_unlock.*\n.*\n.*spin_lock', 'spinlock_race_window', 'medium'),
                (r'if\s*\([^)]+\).*\n[^{]*\n.*\1\s*=', 'TOCTOU_pattern', 'high'),
            ],
            'memory_leak': [
                (r'(kmalloc|kzalloc|vmalloc)\s*\([^)]+\)(?!.*kfree)', 'potential_memory_leak', 'medium'),
                (r'return\s+-?\d+;(?!.*kfree)', 'return_without_free', 'medium'),
                (r'goto\s+\w+;(?!.*kfree)', 'goto_without_cleanup', 'low'),
            ]
        }

    def scan_file_content(self, content: str, file_path: str, vuln_type: str = None) -> List[Dict]:
        """Scan file content for vulnerability patterns"""
        issues = []
        lines = content.split('\n')

        # Select patterns based on vulnerability type
        if vuln_type and vuln_type in self.patterns:
            patterns_to_check = {vuln_type: self.patterns[vuln_type]}
        else:
            patterns_to_check = self.patterns

        for vuln_category, pattern_list in patterns_to_check.items():
            for pattern, issue_type, severity in pattern_list:
                # Search for pattern in entire content
                for match in re.finditer(pattern, content, re.MULTILINE):
                    # Find line number
                    line_num = content[:match.start()].count('\n') + 1

                    # Get context (few lines around match)
                    context_start = max(0, line_num - 2)
                    context_end = min(len(lines), line_num + 2)
                    context = '\n'.join(lines[context_start:context_end])

                    issues.append({
                        'file': file_path,
                        'line': line_num,
                        'type': issue_type,
                        'category': vuln_category,
                        'severity': severity,
                        'pattern': pattern,
                        'context': context[:200],
                        'detector': 'pattern_detector'
                    })

        return issues

    def detect(self, target_dirs: List[str], vuln_type: str = None) -> List[Dict]:
        """Run pattern-based detection on target directories"""
        print("\n=== Pattern-Based Detection ===")
        print(f"Scanning for: {vuln_type if vuln_type else 'all vulnerability types'}")

        for target_dir in target_dirs:
            print(f"Scanning {target_dir}...")

            try:
                # Get list of C files
                cmd = ['git', 'ls-tree', '-r', '--name-only', 'HEAD', target_dir]
                result = subprocess.run(cmd, cwd=self.kernel_path,
                                      capture_output=True, text=True)

                if result.returncode == 0:
                    files = [f for f in result.stdout.strip().split('\n')
                            if f.endswith(('.c', '.h'))]

                    for file_path in files[:50]:  # Limit for performance
                        # Get file content
                        show_cmd = ['git', 'show', f'HEAD:{file_path}']
                        content_result = subprocess.run(show_cmd, cwd=self.kernel_path,
                                                       capture_output=True, text=True)

                        if content_result.returncode == 0:
                            file_issues = self.scan_file_content(
                                content_result.stdout, file_path, vuln_type
                            )
                            self.results.extend(file_issues)

            except Exception as e:
                print(f"Error scanning {target_dir}: {e}")

        # Save results
        output_file = Path('results/pattern_detector_results.json')
        output_file.parent.mkdir(exist_ok=True)
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2)

        print(f"Found {len(self.results)} issues with pattern detection")
        return self.results

    def get_statistics(self) -> Dict:
        """Get statistics about detected issues"""
        stats = {
            'total': len(self.results),
            'by_category': {},
            'by_severity': {},
            'by_type': {}
        }

        for issue in self.results:
            # By category
            cat = issue.get('category', 'unknown')
            stats['by_category'][cat] = stats['by_category'].get(cat, 0) + 1

            # By severity
            sev = issue.get('severity', 'unknown')
            stats['by_severity'][sev] = stats['by_severity'].get(sev, 0) + 1

            # By type
            typ = issue.get('type', 'unknown')
            stats['by_type'][typ] = stats['by_type'].get(typ, 0) + 1

        return stats

def main():
    """Test the pattern detector"""
    detector = PatternDetector()

    target_dirs = [
        "net/core",
        "net/ipv4",
        "mm",
        "kernel"
    ]

    # Detect all vulnerability types
    results = detector.detect(target_dirs)

    # Get statistics
    stats = detector.get_statistics()
    print("\nDetection Statistics:")
    print(json.dumps(stats, indent=2))

if __name__ == "__main__":
    main()