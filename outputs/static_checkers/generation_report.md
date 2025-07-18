# LinuxGuard Clang Checker Generation Report

## Summary
- **Generated checkers**: 3
- **Bug types covered**: 3

## Generated Checkers

### 1. Fallback Other Pattern

- **Checker ID**: checker_ap_fallback_000
- **Pattern ID**: ap_fallback_000
- **Bug Type**: other
- **Check Functions**: checkPreCall

**Description**: Fallback pattern for other vulnerabilities

**Source File**: `checkers/checker_ap_fallback_000.cpp`

---
### 2. Fallback Memory Leak Pattern

- **Checker ID**: checker_ap_fallback_000
- **Pattern ID**: ap_fallback_000
- **Bug Type**: memory_leak
- **Check Functions**: checkPreCall, checkEndFunction

**Description**: Fallback pattern for memory_leak vulnerabilities

**Source File**: `checkers/checker_ap_fallback_000.cpp`

---
### 3. Fallback Input Validation Pattern

- **Checker ID**: checker_ap_fallback_000
- **Pattern ID**: ap_fallback_000
- **Bug Type**: input_validation
- **Check Functions**: checkPreCall, checkPostCall

**Description**: Fallback pattern for input_validation vulnerabilities

**Source File**: `checkers/checker_ap_fallback_000.cpp`

---

## Build Instructions

```bash
cd data/static_checkers
mkdir build && cd build
cmake ..
make -j$(nproc)
```

## Usage

```bash
clang -cc1 -analyze -analyzer-checker=linuxguard.checker_ap_fallback_000 file.c
```
