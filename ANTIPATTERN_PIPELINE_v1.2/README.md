# ANTIPATTERN_PIPELINE v1.2

## Overview
Advanced 4-step pipeline with multi-version kernel scanning.

## Pipeline Steps
1. **Step 1**: Analyze commit with Gemini (`gemini_analyzer.py`)
2. **Step 2**: Generate checker with Gemini (`checker_generator.py`)
3. **Step 3**: Test generated checker (`test_generated_checker.py`)
4. **Step 4**: Multi-version historical scanning (`multi_version_scan_with_checker.py`) ← **NEW**

## Directory Structure
```
ANTIPATTERN_PIPELINE_v1.2/
├── data/                    # Input data and analysis
│   ├── commit_data.py      # Vulnerability commit data
│   ├── gemini_analysis.json # AI analysis results
│   └── gemini_analysis.md  # Analysis report
├── generated/              # Generated checker files
│   ├── UseAfterFreeChecker.cpp
│   ├── UseAfterFreeChecker.h
│   ├── CMakeLists.txt
│   └── checker_generation_report.json
├── results/                # All scan results
│   ├── generated_checker_scan_results.json    # Single-version scan
│   ├── generated_checker_scan_report.md
│   ├── multi_version_scan_results.json       # Multi-version scan ← **NEW**
│   └── multi_version_scan_report.md          # Historical analysis ← **NEW**
├── tests/                  # Test workspace (temp files)
├── gemini_analyzer.py      # AI analysis engine
├── checker_generator.py    # Checker code generator
├── test_generated_checker.py # Checker validator
├── multi_version_scan_with_checker.py # Multi-version scanner ← **NEW**
├── comprehensive_version_scanner.py # Legacy multi-version tool
└── pipeline_v1.2.py       # Main runner
```

## What's New in v1.2
- **Multi-Version Analysis**: Added Step 5 for scanning multiple Linux kernel versions
- **Historical Tracking**: Can detect when vulnerabilities were introduced/fixed
- **Comprehensive Coverage**: Scans across different kernel releases
- **Version Comparison**: Compares vulnerable vs fixed versions

## Usage
```bash
python pipeline_v1.2.py
```

## Output
- Analysis saved in `data/`
- Generated checkers in `generated/`
- Test validation results in console
- Multi-version historical analysis in `results/`

## Multi-Version Features
- Scans 7+ different kernel versions/commits
- Identifies vulnerable vs fixed patterns
- Generates detailed version comparison reports
- Historical vulnerability tracking across kernel releases