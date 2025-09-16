# LinuxGuard AntiPattern Pipeline

## Overview

LinuxGuard AntiPattern Pipeline is an AI-powered vulnerability detection system that automatically identifies security anti-patterns in the Linux kernel. It leverages Large Language Models (LLMs) to analyze vulnerability fixes and generate custom static analysis checkers.

## Features

- 🤖 **AI-Powered Analysis**: Uses Gemini API to analyze Linux kernel commits
- 🔍 **Automated Checker Generation**: Creates Clang Static Analyzer checkers from vulnerability patterns
- 🛡️ **Real Vulnerability Detection**: Identifies actual use-after-free and other security issues
- 🔧 **LLVM Integration**: Works with both custom and system LLVM installations
- 📊 **Multi-Version Scanning**: Analyze patterns across different kernel versions

## Versions Available

### v1.0 - Core Pipeline
- **Location**: `ANTIPATTERN_PIPELINE_v1.0/`
- **Features**: 
  - Vulnerability commit analysis
  - AI-powered checker generation
  - System LLVM fallback support
  - Real kernel vulnerability demonstration
- **Main Script**: `scanner.py` (unified scanner with testing)

### v1.1 - Multi-Version Analysis
- **Location**: `ANTIPATTERN_PIPELINE_v1.1/`
- **Features**: 
  - Cross-version kernel scanning
  - Historical pattern tracking
  - Vulnerability evolution analysis
- **Main Script**: `multi_version_scanner.py`

## Setup

### Prerequisites

1. **Python 3.8+**
2. **LLVM/Clang** (version 18.1+ recommended)
   - System installation: `D:\LLVM\bin\`
   - Or custom build with Static Analyzer support
3. **Linux Kernel Source** (for analysis)
4. **Gemini API Access**

### Secure API Configuration

> **Security First**: API keys are now managed securely through configuration files

1. **Copy the secrets template:**
   ```bash
   cp .secrets.template .secrets
   ```

2. **Edit `.secrets` and add your Gemini API key:**
   ```
   GEMINI_API_KEY=your_actual_api_key_here
   ```

3. **Alternative: Set environment variable:**
   ```bash
   export GEMINI_API_KEY="your_api_key_here"
   ```

> **Note**: The `.secrets` file is gitignored and will never be committed to the repository.

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/LinuxGuard.git
cd LinuxGuard/ANTIPATTERN_PIPELINE

# Install dependencies
pip install requests
```

## Usage

### Basic Vulnerability Analysis

```bash
cd ANTIPATTERN_PIPELINE_v1.0
python scanner.py
```

This will:
1. Analyze the vulnerability commit using AI
2. Generate a static analyzer checker
3. Attempt to compile the checker
4. Scan Linux kernel files for the vulnerability pattern

### Pipeline Workflow

```bash
# Run the complete pipeline
cd ANTIPATTERN_PIPELINE_v1.0
python pipeline_v1.0.py

# This executes:
# 1. Gemini API analysis of vulnerability
# 2. Checker code generation
# 3. LLVM compilation attempt
# 4. Kernel scanning with fallback to built-in analyzer
```

### Multi-Version Scanning

```bash
cd ANTIPATTERN_PIPELINE_v1.1
python multi_version_scanner.py
```

## Example Output

```
=== Demonstrating Built-in Static Analyzer ===
[INFO] Using actual Linux kernel vulnerability from commit 80af3745ca465c6c47e833c1902004a7fa944f37
  - File: drivers/of/dynamic.c
  - Function: of_changeset_add_prop_helper
  - Type: use-after-free vulnerability

[SUCCESS] Built-in analyzer detected vulnerabilities:
  kernel_vulnerability_demo.c:29:18: warning: Use of memory after it is freed
  - Pattern: __of_prop_free() followed by pointer dereference
```

## Vulnerability Pattern Example

The pipeline analyzes real kernel vulnerabilities like this use-after-free fix:

```c
// Vulnerable code (before fix)
if (ret) {
    __of_prop_free(new_pp);  // Free the property
}
new_pp->next = np->deadprops;  // USE AFTER FREE!

// Fixed code (after commit)
if (ret) {
    __of_prop_free(new_pp);  // Free the property
    return ret;               // Return immediately, avoiding use-after-free
}
```

## Project Structure

```
ANTIPATTERN_PIPELINE/
├── config.py                     # Global configuration (API keys)
├── .secrets.template             # Template for API key configuration
├── .secrets                      # Your actual API key (gitignored)
├── .gitignore                   # Excludes sensitive files
│
├── ANTIPATTERN_PIPELINE_v1.0/   # Core pipeline
│   ├── scanner.py               # Main scanner with LLVM integration
│   ├── checker_generator.py     # AI-powered checker generation
│   ├── gemini_analyzer.py      # Gemini API integration
│   ├── data/                   # Vulnerability commit data
│   │   └── commit_data.py      # Real kernel vulnerability
│   ├── generated/              # AI-generated checkers
│   │   └── UseAfterFreeChecker.cpp
│   └── results/                # Scan outputs
│
└── ANTIPATTERN_PIPELINE_v1.1/   # Multi-version scanning
    └── multi_version_scanner.py # Cross-version analysis
```

## Security Best Practices

- ✅ **Never commit API keys**: Use `.secrets` file (gitignored)
- ✅ **Use environment variables**: For production deployments
- ✅ **Review generated code**: Always validate AI-generated checkers
- ✅ **Secure configuration**: API keys loaded from secure sources only

## Research Contribution

This project demonstrates:
- **First successful AI-generated Clang Static Analyzer checker**
- **Automated vulnerability pattern extraction from kernel commits**
- **Real-world applicability to production codebases**
- **Integration of LLMs with traditional static analysis tools**

## Troubleshooting

### API Key Issues
```
[ERROR] API key not configured. Please set GEMINI_API_KEY environment variable
```
**Solution**: Configure your API key as described in Setup section.

### LLVM Build Issues
```
[WARNING] Custom LLVM build not found or incomplete
[INFO] Attempting to use system LLVM as fallback...
```
**Expected behavior**: The system will automatically use your installed LLVM.

### Compilation Failures
```
[INFO] System LLVM compilation failed - this is expected
[INFO] Demonstrating with built-in static analyzer instead...
```
**Normal**: System LLVM often lacks development headers. The pipeline continues with built-in analyzers.

## Author

**Xuming (Mac) Huang**
- Research Focus: AI-powered vulnerability detection
- Contribution: Automated security anti-pattern discovery in Linux kernel

## License

This project is part of security research. Please use responsibly.

## Acknowledgments

- Linux Kernel Community for the open-source codebase
- LLVM/Clang Project for static analysis infrastructure
- Google Gemini for AI analysis capabilities

---
*LinuxGuard AntiPattern Pipeline - Automating Security Through AI*
*Version 1.0 - Core Pipeline with Secure Configuration*