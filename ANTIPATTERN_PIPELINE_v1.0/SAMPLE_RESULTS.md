# V1.0 Sample Results

### Sample Output:
```
=== Analyzing Linux Kernel Commit ===
Commit: 80af3745ca465c6c47e833c1902004a7fa944f37
Vulnerability Type: use-after-free

=== AI Analysis Result ===
Pattern Identified: Memory freed with __of_prop_free() but accessed afterward
Risk Level: Critical
Location: drivers/of/dynamic.c

=== Generated Checker ===
Created: UseAfterFreeChecker.cpp
Status: Ready for compilation
```