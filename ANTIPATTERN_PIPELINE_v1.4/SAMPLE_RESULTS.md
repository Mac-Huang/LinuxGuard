# V1.4 Sample Results

### Sample Output:
```
=== Comparative Analysis Results ===

Performance Metrics:
Detector        Time (s)    Memory (MB)   Issues    F1 Score
pattern         2.34        45.2          142       0.72
coccinelle      8.91        112.3         89        0.85
clang           15.23       203.4         76        0.92

BEST PERFORMERS:
  Fastest: pattern_detector
  Most Accurate: clang_detector
  Most Efficient: coccinelle_detector

Recommendation: Use pattern detection for CI/CD, Clang for deep analysis
```