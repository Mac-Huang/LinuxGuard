# ANTIPATTERN PIPELINE v1.5

## Overview

Version 1.5 combines **Clang Static Analyzer** (from v1.4) and **AI-Generated Buffer Overflow Checker** (from v1.3) to perform comparative analysis on the same Linux kernel files.

## Key Features

- **Dual Analysis**: Runs both checkers on identical kernel files in linux_kernel
- **Multiple Versions**: Analyzes 4 kernel versions (v5.10-rc1, v5.10-rc7, v6.0-rc1, v6.0-rc7)
- **Direct Comparison**: Side-by-side results from both tools
- **Performance Metrics**: Execution time, detection rates, F1 scores

## How It Works

1. **Version Access**: Uses `git show` to extract files from specific kernel versions without checkout
2. **Temporary Extraction**: Creates temp directories for each version's files
3. **Parallel Analysis**: Runs both checkers on the same extracted files
4. **Comprehensive Comparison**: Generates detailed comparison metrics

## Key Differences from Previous Versions

- **v1.3**: Only used AI-generated checker with git-based scanning
- **v1.4**: Demonstrated Clang on test files, attempted real kernel analysis
- **v1.5**: Properly combines both approaches on the SAME kernel files

## File Structure

```
ANTIPATTERN_PIPELINE_v1.5/
├── combined_checker_comparison.py  # Main comparison script
├── results/
│   ├── v1.5_checker_comparison.json    # Detailed JSON results
│   └── v1.5_comparison_report.md       # Human-readable report
└── README.md
```

## Requirements

- Python 3.8+
- Clang 18.1.8+ with static analyzer
- Git (for kernel repository access)
- Linux kernel repository at: `D:\Develop\Research\Detector\LinuxGuard\antipattern_pipeline\linux_kernel`

## Usage

```bash
python combined_checker_comparison.py
```

## Author

Mac Huang

## Date

2025