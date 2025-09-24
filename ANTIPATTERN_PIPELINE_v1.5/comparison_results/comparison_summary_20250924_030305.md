# Clang vs Generated Checkers Comparison

## Summary
- **Files Analyzed**: 35774
- **Generated Checkers**: 10 issues in 14635.12s
- **Clang Analyzer**: 37 issues in 7490.20s
- **Speed Improvement**: 0.5x

## Performance Metrics
| Analyzer | Issues | Time(s) | Issues/File | ms/File |
|----------|--------|---------|-------------|---------|
| Generated | 10 | 14635.12 | 0.00 | 409.1 |
| Clang | 37 | 7490.20 | 0.00 | 209.4 |

## Analysis
- Detection ratio: 0.3x
- Speed improvement: 0.5x
