# Multi-Version Buffer Overflow Detection Report
==================================================

**Scan Date**: 2025-09-22 21:11:22.064067
**Scan Type**: Buffer Overflow Pattern Detection
**Versions Requested**: 4
**Versions Successfully Scanned**: 4
**Total Buffer Overflow Issues Found**: 21674

## Version Summary

- **v5.10-rc1**: scanned (git show (no checkout)) - 5284 buffer-overflow issues found
- **v5.10-rc7**: scanned (git show (no checkout)) - 5284 buffer-overflow issues found
- **v6.0-rc1**: scanned (git show (no checkout)) - 5553 buffer-overflow issues found
- **v6.0-rc7**: scanned (git show (no checkout)) - 5553 buffer-overflow issues found

## Vulnerable Versions (Buffer Overflow Issues)

### v5.10-rc1
- Total buffer-overflow issues: 5284
  - unchecked_array_index: 4598 occurrences
  - integer_overflow_risk: 70 occurrences
  - unsafe_string_function: 93 occurrences
  - unchecked_snprintf: 70 occurrences
  - unchecked_memcpy: 453 occurrences

**Sample Issues:**
  - net/core/bpf_sk_storage.c:417 - unchecked_array_index
    Array access without bounds check: maps[i] at line 417
  - net/core/bpf_sk_storage.c:483 - unchecked_array_index
    Array access without bounds check: maps[diag->nr_maps++] at line 483
  - net/core/bpf_sk_storage.c:683 - unchecked_array_index
    Array access without bounds check: buckets[bucket_id++] at line 683
  - net/core/bpf_sk_storage.c:697 - unchecked_array_index
    Array access without bounds check: buckets[i] at line 697
  - net/core/bpf_sk_storage.c:869 - unchecked_array_index
    Array access without bounds check: btf_sock_ids[BTF_SOCK_TYPE_SOCK] at line 869

### v5.10-rc7
- Total buffer-overflow issues: 5284
  - unchecked_array_index: 4597 occurrences
  - integer_overflow_risk: 70 occurrences
  - unsafe_string_function: 93 occurrences
  - unchecked_snprintf: 70 occurrences
  - unchecked_memcpy: 454 occurrences

**Sample Issues:**
  - net/core/bpf_sk_storage.c:417 - unchecked_array_index
    Array access without bounds check: maps[i] at line 417
  - net/core/bpf_sk_storage.c:483 - unchecked_array_index
    Array access without bounds check: maps[diag->nr_maps++] at line 483
  - net/core/bpf_sk_storage.c:683 - unchecked_array_index
    Array access without bounds check: buckets[bucket_id++] at line 683
  - net/core/bpf_sk_storage.c:697 - unchecked_array_index
    Array access without bounds check: buckets[i] at line 697
  - net/core/bpf_sk_storage.c:869 - unchecked_array_index
    Array access without bounds check: btf_sock_ids[BTF_SOCK_TYPE_SOCK] at line 869

### v6.0-rc1
- Total buffer-overflow issues: 5553
  - unchecked_array_index: 4885 occurrences
  - integer_overflow_risk: 73 occurrences
  - unsafe_string_function: 82 occurrences
  - unchecked_snprintf: 66 occurrences
  - unchecked_memcpy: 447 occurrences

**Sample Issues:**
  - net/core/bpf_sk_storage.c:450 - unchecked_array_index
    Array access without bounds check: btf_sock_ids[BTF_SOCK_TYPE_SOCK_COMMON] at line 450
  - net/core/bpf_sk_storage.c:462 - unchecked_array_index
    Array access without bounds check: btf_sock_ids[BTF_SOCK_TYPE_SOCK_COMMON] at line 462
  - net/core/bpf_sk_storage.c:499 - unchecked_array_index
    Array access without bounds check: maps[i] at line 499
  - net/core/bpf_sk_storage.c:564 - unchecked_array_index
    Array access without bounds check: maps[diag->nr_maps++] at line 564
  - net/core/bpf_sk_storage.c:764 - unchecked_array_index
    Array access without bounds check: buckets[bucket_id++] at line 764

### v6.0-rc7
- Total buffer-overflow issues: 5553
  - unchecked_array_index: 4885 occurrences
  - integer_overflow_risk: 73 occurrences
  - unsafe_string_function: 82 occurrences
  - unchecked_snprintf: 66 occurrences
  - unchecked_memcpy: 447 occurrences

**Sample Issues:**
  - net/core/bpf_sk_storage.c:451 - unchecked_array_index
    Array access without bounds check: btf_sock_ids[BTF_SOCK_TYPE_SOCK_COMMON] at line 451
  - net/core/bpf_sk_storage.c:463 - unchecked_array_index
    Array access without bounds check: btf_sock_ids[BTF_SOCK_TYPE_SOCK_COMMON] at line 463
  - net/core/bpf_sk_storage.c:500 - unchecked_array_index
    Array access without bounds check: maps[i] at line 500
  - net/core/bpf_sk_storage.c:565 - unchecked_array_index
    Array access without bounds check: maps[diag->nr_maps++] at line 565
  - net/core/bpf_sk_storage.c:765 - unchecked_array_index
    Array access without bounds check: buckets[bucket_id++] at line 765
