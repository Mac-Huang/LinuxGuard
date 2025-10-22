"""Centralized prompt construction helpers for LinuxGuard."""

from __future__ import annotations

from textwrap import dedent
from typing import Dict


PATTERN_EXTRACTION_TEMPLATE = dedent(
    """You are analyzing a Linux kernel commit to identify the EXACT security bug pattern that was fixed.

Your goal: Extract the SPECIFIC pattern so we can find this EXACT bug in older kernel versions.

Analyze the following commit and determine:

1. Is this a security or critical bug fix? Look for:
   - Fixes tags referencing security issues
   - Security-related keywords in the commit message
   - Patterns indicating vulnerability fixes (bounds checks, null checks, race conditions, etc.)
   - Code changes that add defensive checks or fix dangerous patterns

2. If this IS a security/critical fix, extract THE EXACT PATTERN:
   - PRESERVE specific function names (e.g., "of_changeset_add_property", "__of_prop_free")
   - PRESERVE specific variable names and patterns
   - PRESERVE the exact control flow that causes the bug
   - This is about finding THE SAME BUG in older code, not similar bugs

Respond with this JSON structure:

If NOT a security fix:
{"is_security_fix": false, "reason": "brief explanation"}

If IS a security fix:
{{
  "is_security_fix": true,
  "confidence": "high|medium|low",
  "anti_pattern_type": "specific-type",
  "vulnerability_class": "CWE-XXX category if applicable",
  "vulnerable_pattern": {{
    "description": "EXACT description of what was wrong, including specific function/variable names",
    "key_indicators": ["EXACT function calls like 'of_changeset_add_property'", "EXACT variable patterns like 'new_pp'", "EXACT control flow patterns"],
    "code_context": "EXACT code snippet from BEFORE the fix showing the vulnerability",
    "specific_functions": ["list of EXACT function names involved"],
    "specific_variables": ["list of EXACT variable names if relevant"],
    "exploitability": "how could this be exploited"
  }},
  "fix_pattern": {{
    "description": "what the fix does to prevent the vulnerability",
    "required_checks": ["EXACT checks or validations added"],
    "code_context": "EXACT code snippet from AFTER the fix",
    "protection_mechanism": "type of protection added"
  }},
  "ast_matcher_hints": {{
    "node_types": ["AST node types to match"],
    "exact_function_names": ["EXACT function names to match in AST"],
    "relationships": ["EXACT parent-child or sibling relationships"],
    "conditions": ["EXACT conditions to check for"],
    "pattern_description": "Match calls to [EXACT FUNCTION NAMES] followed by [EXACT PATTERN]"
  }},
  "severity": "critical|high|medium|low",
  "cwe_ids": ["CWE-XXX"],
  "impact": "potential impact if exploited",
  "affected_subsystem": "kernel subsystem affected"
}}

IMPORTANT: We are looking for THIS EXACT BUG in older kernels, not similar bugs.
- Keep all specific function names exactly as they appear
- Keep all specific variable names and patterns
- Describe the exact control flow that causes the vulnerability

COMMIT TO ANALYZE:
{context}

Respond with ONLY valid JSON, no additional text.
"""
)


def build_pattern_extraction_prompt(context: str) -> str:
    """Build the Module 1 prompt from commit context."""
    return PATTERN_EXTRACTION_TEMPLATE.replace("{context}", context)


def build_header_generation_prompt(
    template_header: str,
    checker_name: str,
    anti_pattern_type: str,
    vulnerable_description: str,
) -> str:
    """Construct the header-generation prompt for Module 2."""
    return dedent(
        f"""Generate a clang-tidy checker header file based on this template and requirements.

Template structure to follow:
```cpp
{template_header}
```

Requirements:
- Checker name: {checker_name}
- Anti-pattern type: {anti_pattern_type}
- Description: Detect {vulnerable_description}

Generate a header file that:
1. Uses the same structure as the template
2. Replaces MustCheckErrsCheck with {checker_name}
3. Updates the class documentation to describe what this checker detects
4. Maintains the same namespace (clang::tidy::linuxkernel)
5. Uses proper include guards with the new checker name

Respond with ONLY the complete C++ header code, no explanations."""
    ).strip()


def build_implementation_prompt(
    template_cpp: str,
    checker_name: str,
    anti_pattern_type: str,
    vulnerable_description: str,
    vulnerable_context: str,
    key_indicators_json: str,
    fix_description: str,
    ast_requirements: Dict[str, list],
    pattern_specific_hints: str,
) -> str:
    """Construct the implementation-generation prompt for Module 2."""

    node_types = ast_requirements.get("node_types")
    conditions = ast_requirements.get("conditions")
    relationships = ast_requirements.get("relationships")

    return dedent(
        f"""Generate a clang-tidy checker implementation file that detects the EXACT pattern from this bug fix.

Template structure to follow:
```cpp
{template_cpp}
```

CRITICAL REQUIREMENTS - This checker must find the EXACT bug pattern:
- Checker Name: {checker_name}
- Bug Type: {anti_pattern_type}

EXACT VULNERABILITY PATTERN TO DETECT:
{vulnerable_description}

Code context showing the EXACT bug:
{vulnerable_context}

SPECIFIC indicators that MUST be matched:
{key_indicators_json}

The fix that was applied:
{fix_description}

IMPORTANT - BE SPECIFIC:
- If the bug involves specific function names (like "of_changeset_add_property", "__of_prop_free"), use THOSE EXACT names
- If the bug involves specific variable names or patterns, match those EXACTLY
- This is NOT about finding general patterns - we want to find THIS EXACT bug in older kernels

AST Matching Strategy:
- Node types involved: {node_types}
- Specific conditions: {conditions}
- Control flow relationships: {relationships}

For {anti_pattern_type}, create matchers that:
{pattern_specific_hints}

BUT prioritize matching the EXACT pattern described above over general patterns.

Common AST matchers to use:
- callExpr(callee(functionDecl(hasName("exact_function_name")))): Match specific function calls
- ifStmt(): Match if statements and their branches
- returnStmt(): Match return statements (or lack thereof)
- compoundStmt(): Match code blocks
- hasDescendant(): Check for patterns within blocks
- unless(hasDescendant(returnStmt())): Check for missing returns

Structure your implementation:
1. In registerMatchers(): Set up matchers for the EXACT pattern described
2. In check(): Report when the exact vulnerable pattern is found
3. Use the template structure but replace MustCheckErrsCheck with {checker_name}

Respond with ONLY the complete C++ implementation code, no explanations."""
    ).strip()


def build_repair_prompt(
    checker_name: str,
    header_code: str,
    cpp_code: str,
    errors: str,
    anti_pattern_type: str,
    vulnerable_description: str,
) -> str:
    """Construct the repair prompt used during compilation fixes."""
    anti_pattern = anti_pattern_type or "unknown"
    vulnerable = vulnerable_description or ""
    return dedent(
        f"""Fix the compilation errors in this clang-tidy checker.

HEADER FILE ({checker_name}.h):
```cpp
{header_code}
```

IMPLEMENTATION FILE ({checker_name}.cpp):
```cpp
{cpp_code}
```

COMPILATION ERRORS:
```
{errors}
```

CONTEXT:
- This checker detects: {anti_pattern}
- It should identify: {vulnerable}

Fix the compilation errors by correcting the API usage. Common issues:
- Use dyn_cast<T> instead of getAs<T> for AST nodes
- CompoundStmt::body() returns an iterator range, not a container
- Use proper clang AST API methods
- Ensure all matcher constructs are valid

Respond with two code blocks:
1. The complete fixed header file
2. The complete fixed implementation file

Respond ONLY with the two code blocks labeled:
HEADER:
```cpp
...
```

IMPLEMENTATION:
```cpp
...
```"""
    ).strip()


def build_verification_prompt(context: Dict[str, str]) -> str:
    """Construct the verification prompt for manual LLM validation."""
    checker = context.get("checker", "unknown checker")
    message = context.get("message", "No issue description provided")
    code_before = context.get("code_before", "")
    issue_code = context.get("issue_code", "")
    code_after = context.get("code_after", "")

    return dedent(
        f"""Analyze the following code for a potential bug:

Issue reported by checker '{checker}':
"{message}"

Code context (issue is at marked line):
```c
{code_before}
>>> {issue_code.rstrip()}  // <-- ISSUE REPORTED HERE
{code_after}
```

Questions:
1. Is this a real bug/vulnerability? (YES/NO)
2. What is the potential impact if this is a bug?
3. Could this lead to security issues?
4. Confidence level (0-100%)?

Please provide a brief analysis."""
    ).strip()
