# Manual Verification Methodology

**Date:** 2025-10-19
**Verified By:** Xuming (Mac)
**Total Issues Verified:** 76

---

## Kernel Versions Analyzed

```
Linux v3.0.0 → v6.0.0 (latest RCs)
```

**Version Selection Strategy:**
- Wide major version span (3.0, 4.0, 5.0, 6.0)
- Covers ~13 years of kernel development (2011-2022)
- **Note:** RC (Release Candidate) versions used, but RC is not a valid control variable

---

## Verification Process

### Step 1: Combine Error Messages with Source Code
- Extract each detected issue from `scan_report.json`
- Locate the corresponding source file
- Extract code context around the reported line

### Step 2: Context Control
- **One file per chat session** (isolation to prevent context pollution)
- Consistent prompt across all verifications

### Step 3: LLM Verification Prompt

**Standard Instruction Used:**

```
You are a kernel-aware code reviewer.
Decide whether each reported must-check warning is a TRUE_POSITIVE (real bug)
or FALSE_POSITIVE by analyzing only the provided context.
```

**Key Constraints:**
- Binary decision: TRUE_POSITIVE or FALSE_POSITIVE
- Context-limited analysis (no external code references)
- Kernel domain expertise expected from LLM

---

## Verification Results

### Summary Statistics

| Version | Total Issues | True Positives | False Positives | Precision |
|---------|--------------|----------------|-----------------|-----------|
| v6.0    | 68           | 34             | 34              | 50.0%     |
| v5.0    | 8            | 2              | 6               | 25.0%     |
| v4.0    | 0            | -              | -               | N/A       |
| v3.0    | 0            | -              | -               | N/A       |
| **Overall** | **76**   | **36**         | **40**          | **47.368%** |

### Calculation

```
Overall Precision = (Total Issues - False Positives) / Total Issues
                  = (76 - 40) / 76
                  = 36 / 76
                  = 47.368%
```

---

## Process Characteristics

### Strengths ✓
- **Consistency:** Same prompt applied to all files
- **Isolation:** One file per chat prevents cross-contamination
- **Kernel-aware:** Prompt primes LLM for domain-specific analysis
- **Controlled context:** Only provided code shown, no speculation

### Limitations ✗
- **No ground truth validation:** LLM judgment, not CVE database
- **Context window constraints:** Limited code visibility
- **Manual effort:** 76 individual chat sessions
- **Subjectivity:** Different LLMs might give different results
- **RC version variability:** Not a controlled variable

---

## Insights from Manual Review

### Why v6.0 has Higher Precision (50%) vs v5.0 (25%)

Potential explanations:
1. **Pattern maturity:** Anti-pattern more established in v6.0
2. **Checker tuning:** AST matchers may be over-fitted to v6.0 code patterns
3. **Code quality evolution:** v6.0 may have more actual unchecked errors
4. **Sample size:** v5.0 only has 8 issues (small sample, high variance)

### Why v3.0/v4.0 have Zero Detections

1. **Pattern emergence timeline:**
   - Pattern source: Recent commits (likely 2019-2022)
   - v3.0 (2011): Too old, pattern didn't exist
   - v4.0 (2015): Still pre-dates pattern emergence
   - v5.0 (2019): Pattern starting to appear (8 cases)
   - v6.0 (2022): Pattern widespread (68 cases)

2. **Methodology validation:**
   - Confirms: "Use current commits to find bugs in previous versions"
   - Zero in v3.0/v4.0 suggests pattern is truly version-specific
   - Not a false negative—pattern genuinely absent in older kernels

---

## Recommendations for Future Verification

### Automate with LLM API
```python
# Pseudocode for automated verification
for issue in verification_dataset:
    prompt = f"""
    You are a kernel-aware code reviewer.
    Decide whether this warning is TRUE_POSITIVE or FALSE_POSITIVE.

    File: {issue['file']}
    Line: {issue['line']}
    Message: {issue['message']}

    Code:
    {issue['code_context']}

    Answer: TRUE_POSITIVE or FALSE_POSITIVE
    Confidence: 0-100%
    Reason: [brief explanation]
    """

    result = llm.complete(prompt)
    record_verification(issue, result)
```

### Improve Verification Quality

1. **Multi-LLM consensus:**
   - Run through 3+ different LLMs
   - Take majority vote
   - Flag disagreements for manual review

2. **Provide more context:**
   - Include function signature
   - Show error handling pattern in surrounding code
   - Provide relevant kernel subsystem documentation

3. **Ground truth comparison:**
   - Cross-reference with CVE database
   - Compare with other static analyzers (Coverity, CodeChecker)
   - Get kernel maintainer feedback on reported issues

4. **Control kernel version:**
   - Use stable releases, not RCs
   - Document exact kernel commit hash
   - Ensure reproducibility

---

## Files Generated

- `manual_verification_results.json` - Structured verification data
- `VERIFICATION_METHODOLOGY.md` - This document
- `verification_dataset/verification_dataset.json` - Issues ready for automated verification
- `verification_dataset/manual_verification.html` - Interactive web viewer
- `verification_dataset/verification_prompts.md` - Copy-paste prompts for web LLMs

---

**Methodology documented:** 2025-10-19
