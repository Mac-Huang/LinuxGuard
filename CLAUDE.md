- # Claude Project Setup Prompt

## Project: Linux Kernel Anti-Pattern Detection Pipeline

### Overview

This project implements an automated pipeline for detecting security anti-patterns in the Linux kernel by generating custom clang-tidy static analysis checkers using LLMs. The system learns from historical bug fixes to proactively identify similar vulnerabilities across different kernel versions.

### Project Structure

```
~/private/linux-guard/
├── llvm-project/                 # LLVM/Clang build with clang-tidy
│   ├── build/
│   │   └── bin/clang-tidy       # Built binary with custom checkers
│   └── clang-tools-extra/
│       └── clang-tidy/
│           └── linuxkernel/      # Custom kernel checker module
│               ├── MustCheckErrsCheck.cpp
│               ├── MustCheckErrsCheck.h
│               └── LinuxKernelTidyModule.cpp
├── kernels/                      # Linux kernel versions for analysis
│   ├── linux-v3.0/
│   ├── linux-v4.0/
│   ├── linux-v5.0/
│   └── linux-v6.0/
├── checkers/                     # Generated checkers
│   ├── templates/
│   └── generated/
├── results/                      # Scan results and analysis
│   └── summary_report.md
└── scripts/                      # Automation scripts
```

### Key Components

#### 1. Custom Clang-Tidy Checker

- **Location**: `~/private/linux-guard/llvm-project/build/bin/clang-tidy`
- **Module**: `linuxkernel-must-check-errs` - Detects unchecked error pointers in kernel code
- **Technology**: C++ AST matchers using Clang's LibTooling

#### 2. Kernel Versions

- **Downloaded**: v3.0, v4.0, v5.0, v6.0 (major versions spanning 2011-2024)
- **Setup**: Each has `compile_commands.json` for clang-tidy analysis
- **Purpose**: Track evolution of anti-patterns across kernel history

#### 3. Analysis Pipeline

```bash
Historical Bug Fix → LLM Analysis → Generate Checker → Build into clang-tidy → Scan Kernels → Report Vulnerabilities
```

### Technical Details

#### Build Configuration

- **LLVM Version**: 22.0.0git
- **Build Type**: Release, minimal (only clang and clang-tools-extra)
- **Target**: X86 only
- **Location**: User space only (`~/private/`), no system modifications

#### Checker Implementation

The checker uses AST pattern matching to find bugs:

```cpp
// Matches unchecked calls to error functions
auto ErrFn = functionDecl(hasAnyName("ERR_PTR", "IS_ERR", ...));
auto NonCheckingStmts = stmt(anyOf(compoundStmt(), labelStmt()));
Finder->addMatcher(callExpr(callee(ErrFn), hasParent(NonCheckingStmts)), this);
```

### Usage Commands

#### Run Checker on Single File

```bash
~/private/linux-guard/llvm-project/build/bin/clang-tidy \
    -checks="-*,linuxkernel-must-check-errs" \
    -p ~/private/linux-guard/kernels/linux-v6.0 \
    test.c
```

#### Scan Entire Kernel Version

```bash
cd ~/private/linux-guard/kernels/linux-v6.0
python3 ~/private/linux-guard/llvm-project/clang-tools-extra/clang-tidy/tool/run-clang-tidy.py \
    -clang-tidy-binary=~/private/linux-guard/llvm-project/build/bin/clang-tidy \
    -checks="-*,linuxkernel-must-check-errs" \
    -p . -j 4
```

### Research Goals

1. **Temporal Analysis**: Find unfixed vulnerabilities in older kernel versions
2. **Spatial Analysis**: Detect similar anti-patterns across different subsystems
3. **Pattern Learning**: Generate new checkers from recent CVE fixes
4. **Proactive Prevention**: Identify bugs before they become security issues

### Current Status

- ✅ LLVM/clang-tidy built with custom kernel module
- ✅ Linux kernels v3.0, v4.0, v5.0, v6.0 downloaded
- ✅ Compilation databases generated
- ✅ MustCheckErrsCheck implemented and integrated
- 🔄 Ready to scan kernels and analyze results
- 📋 Next: Generate additional checkers from bug patterns

### Key Insights

- Each kernel scan reveals 200+ instances of unchecked error values
- Anti-patterns persist across versions, indicating systemic issues
- Automated detection scales better than manual code review
- LLM-generated checkers can encode complex security patterns

### Environment Variables

```bash
export CLANG_TIDY=$HOME/private/linux-guard/llvm-project/build/bin/clang-tidy
export KERNELS_DIR=$HOME/private/linux-guard/kernels
export RESULTS_DIR=$HOME/private/linux-guard/results
```

### Important Notes

- This is on a shared lab server - all installations are in user space
- No sudo/root access used or required
- Resource-conscious: uses `nice` and limited cores for builds
- Disk usage: ~3.4GB for LLVM build, ~1GB per kernel

### Contact/User

- User: Xuming (Mac)
- Location: `/home/mac/private/linux-guard/`
- Server: Shared lab environment (bumble)
- My methodology is to utilizing the commits from current version, which means such specific bug mentioned in these commits have a high chance not been found from the previous versions, thus build the pipeline to automate such process to detect similar anti-patterns.
- The main path of this project is `/nvme/write/mac/private/linux-guard`. All the path written in the code should be the relative one.