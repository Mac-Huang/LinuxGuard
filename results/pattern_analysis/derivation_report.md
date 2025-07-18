# LinuxGuard Phase B: Anti-Pattern Derivation Report

## Summary
- **Commits analyzed**: 20
- **Pattern clusters**: 5
- **Derived patterns**: 3

## Derived Anti-Patterns

### 1. Fallback Other Pattern

- **Category**: other
- **Vulnerability Type**: other
- **Confidence**: 0.300
- **Examples**: 3b428e1c, 3c2fe279, 5f02b80c

**Description**: Fallback pattern for other vulnerabilities

**Detection Rules**:
- Check for other indicators

### 2. Fallback Memory Leak Pattern

- **Category**: other
- **Vulnerability Type**: memory_leak
- **Confidence**: 0.300
- **Examples**: 2632d81f, 40f92e79, b7dc79a6

**Description**: Fallback pattern for memory_leak vulnerabilities

**Detection Rules**:
- Check for memory_leak indicators

### 3. Fallback Input Validation Pattern

- **Category**: other
- **Vulnerability Type**: input_validation
- **Confidence**: 0.300
- **Examples**: c7979c39, b74c2a2e, e81750b4

**Description**: Fallback pattern for input_validation vulnerabilities

**Detection Rules**:
- Check for input_validation indicators

