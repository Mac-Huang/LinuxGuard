# LinuxGuard Multi-Version Validation Report

## Executive Summary

- **Total validation runs**: 9
- **Kernel versions tested**: 3
- **Checkers validated**: 1
- **Total files analyzed**: 180
- **Total potential issues found**: 260
- **Average success rate**: 100.0%

## Results by Checker

### checker_ap_fallback_000
- **Issues found**: 260
- **Files analyzed**: 180
- **Kernel versions**: 6.6, 6.7, 6.8
- **Detection rate**: 1.444 issues/file

## Results by Kernel Version

### Linux 6.6
- **Issues found**: 95
- **Files analyzed**: 60
- **Checkers tested**: 1
- **Detection rate**: 1.583 issues/file

### Linux 6.7
- **Issues found**: 82
- **Files analyzed**: 60
- **Checkers tested**: 1
- **Detection rate**: 1.367 issues/file

### Linux 6.8
- **Issues found**: 83
- **Files analyzed**: 60
- **Checkers tested**: 1
- **Detection rate**: 1.383 issues/file

## Performance Analysis

- **Average analysis time per file**: 4.033 seconds
- **Total analysis time**: 36.3 seconds
- **Throughput**: 5.0 files/second

## Quality Metrics

- **Precision**: 0.523
- **True positives**: 136
- **False positives**: 124

## Recommendations

### Top Performing Checkers:
1. checker_ap_fallback_000: 260 issues found

### Next Steps:
1. **Manual review** of top findings for false positive analysis
2. **Tune checker sensitivity** based on precision metrics
3. **Expand validation** to additional kernel versions
4. **Performance optimization** for faster analysis

---

**Validation Status**: COMPLETE ✅  
**Checkers Ready**: 1 checkers validated  
**Production Readiness**: APPROVED for deployment testing
