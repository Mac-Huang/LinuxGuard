# ANTIPATTERN_PIPELINE v1.3

## Overview
Enhanced 3-step pipeline for automated buffer overflow anti-pattern detection.

## Key Difference from v1.0
- **v1.0**: Detects use-after-free vulnerabilities
- **v1.3**: Detects buffer overflow vulnerabilities (CVE-2024-26909)

## Pipeline Steps
1. **Step 1**: Analyze commit with Gemini (`gemini_analyzer.py`)
2. **Step 2**: Generate checker with Gemini (`checker_generator.py`)
3. **Step 3**: Scan codebase with checker (`scan_with_generated_checker.py`)

## Directory Structure
```
ANTIPATTERN_PIPELINE_v1.3/
├── data/                    # Input data and analysis
│   ├── commit_data.py      # Vulnerability commit data
│   ├── gemini_analysis.json # AI analysis results
│   └── gemini_analysis.md  # Analysis report
├── generated/              # Generated checker files
│   ├── BufferOverflowChecker.cpp
│   ├── BufferOverflowChecker.h
│   ├── CMakeLists.txt
│   └── checker_generation_report.json
├── results/                # Scan results
│   ├── generated_checker_scan_results.json
│   └── generated_checker_scan_report.md
├── gemini_analyzer.py      # AI analysis engine
├── checker_generator.py    # Checker code generator
├── scan_with_generated_checker.py # Scanner
└── pipeline_v1.3.py       # Main runner
```

## Usage
```bash
python pipeline_v1.3.py
```

## Output
- Analysis saved in `data/`
- Generated checkers in `generated/`
- Scan results in `results/`

## Requirements
- Python 3.7+
- Gemini API key
- Linux kernel source code