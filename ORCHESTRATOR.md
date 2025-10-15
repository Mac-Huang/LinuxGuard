# LinuxGuard Orchestrator Documentation

## Overview

The orchestrator (`scripts/orchestrator.py`) is an intelligent automation system that converts Linux kernel security fixes into working clang-tidy checkers without human intervention. It implements a self-healing pipeline that can recover from compilation errors and iteratively improve until a valid checker is produced.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   ORCHESTRATOR                          │
│                                                          │
│  ┌──────────────┐  Iteration Loop (max 3)              │
│  │              │  ┌────────────────────────────────┐  │
│  │   Commit     ├──►  Stage 1: Pattern Analysis     │  │
│  │  (SHA hash)  │  └────────────┬───────────────────┘  │
│  │              │               ▼                       │
│  └──────────────┘  ┌────────────────────────────────┐  │
│                    │  Stage 2: Detection Planning    │  │
│                    └────────────┬───────────────────┘  │
│                                 ▼                       │
│                    ┌────────────────────────────────┐  │
│                    │  Stage 3: Implementation       │  │
│                    │  ┌──────────────────────┐     │  │
│                    │  │   Repair Loop (max 3) │     │  │
│                    │  │  ┌──────────────┐    │     │  │
│                    │  │  │   Compile    ├────┼─┐   │  │
│                    │  │  └──────┬───────┘    │ │   │  │
│                    │  │         ▼            │ │   │  │
│                    │  │  ┌──────────────┐    │ │   │  │
│                    │  │  │   Errors?    │    │ │   │  │
│                    │  │  └──────┬───────┘    │ │   │  │
│                    │  │         ▼            │ │   │  │
│                    │  │  ┌──────────────┐    │ │   │  │
│                    │  │  │  LLM Repair  ├────┼─┘   │  │
│                    │  │  └──────────────┘    │     │  │
│                    │  └──────────────────────┘     │  │
│                    └────────────┬───────────────────┘  │
│                                 ▼                       │
│                    ┌────────────────────────────────┐  │
│                    │  Stage 4: Validation           │  │
│                    └────────────┬───────────────────┘  │
│                                 ▼                       │
│                    ┌────────────────────────────────┐  │
│                    │  Success? → Return Checker     │  │
│                    │  Failure? → Next Iteration     │  │
│                    └────────────────────────────────┘  │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

## How It Works

### Stage 1: Pattern Analysis
```python
pattern = self.analyze_patch(commit_hash)
```
- Fetches complete commit information (message, author, diff)
- Uses Module 1 (`module1_pattern_extraction_rich.py`)
- Sends to Gemini LLM to identify:
  - Anti-pattern type (use-after-free, null-deref, etc.)
  - Vulnerability description
  - Required AST matchers
  - Severity and confidence

### Stage 2: Detection Planning
- Embedded within Stage 1's output
- Creates a plan for what the checker should detect:
  - AST node types to match
  - Relationships between nodes
  - Conditions to check

### Stage 3: Implementation with Self-Repair
```python
checker_info = self.implement_checker(pattern)
while attempts < self.max_repair_attempts:
    build_result, errors = self.build_checker(checker_info)
    if build_result:
        break
    repaired = self.repair_checker(checker_info, errors, pattern)
```

**Initial Generation:**
- Uses Module 2 to generate C++ checker code
- Creates both .h and .cpp files
- Integrates into clang-tidy build system

**Repair Loop:**
When compilation fails:
1. **Extract Errors**: Captures compiler output, filters to relevant errors
2. **Create Repair Prompt**: Sends to LLM with:
   - Current code (both header and implementation)
   - Exact compilation errors
   - Context about what the checker should detect
   - Common Clang API pitfalls

3. **Apply Fixes**: LLM generates corrected code
4. **Retry Build**: Attempts compilation again

### Stage 4: Validation
```python
is_valid = self.validate_checker(checker_info, commit_hash)
```
- Runs the checker on kernel code samples
- Verifies it executes without crashing
- Could be extended to check against known vulnerabilities

## Key Components

### 1. Error Extraction (`extract_relevant_errors`)
Filters compiler output to show only errors related to the generated checker:
```python
def extract_relevant_errors(self, error_output: str, checker_name: str) -> str:
    # Extracts only compilation errors for the specific checker
    # Removes unrelated warnings and build system messages
```

### 2. LLM Repair (`repair_checker`)
Uses targeted prompts with specific guidance:
```python
prompt = f"""
Fix the compilation errors in this clang-tidy checker.

COMPILATION ERRORS:
{errors}

Common issues:
- Use dyn_cast<T> instead of getAs<T>
- CompoundStmt::body() returns an iterator range
- Use proper clang AST API methods
"""
```

### 3. Iterative Generation
If validation fails, tries again with different approach:
- Maximum 3 complete iterations
- Each iteration learns from previous failures
- Can generate different AST matching strategies

## Configuration

**Default Settings:**
- `max_iterations`: 3 (complete generation attempts)
- `max_repair_attempts`: 3 (per iteration)
- `sample_size`: 20 files (for validation)

**Customization:**
```bash
python3 orchestrator.py \
    --commit <hash> \
    --max-iterations 5 \
    --max-repairs 5 \
    --clean  # Start fresh
```

## Example Run

```
=================================================
  LinuxGuard Orchestrator - Generating Checker
  Commit: 80af3745ca46
=================================================

[Iteration 1/3]
Stage 1: Analyzing patch for patterns...
  ✓ Detected: use-after-free
Stage 2: Synthesizing detection plan...
Stage 3: Implementing checker...
  ✓ Generated: UseAfterFreeCheck

  Compilation attempt 1/3...
  ✗ Build failed, attempting repair...
  ✓ Checker repaired, retrying build...

  Compilation attempt 2/3...
  ✓ Build successful!

Stage 4: Validating checker...

=================================================
  ✓ SUCCESS: Valid checker generated!
  Checker: UseAfterFreeCheck
  Iteration: 1
=================================================
```

## Advantages

1. **Self-Healing**: Automatically fixes common API usage errors
2. **No Manual Intervention**: Fully automated from commit to checker
3. **Learning from Errors**: Uses compiler feedback to improve
4. **Resilient**: Multiple attempts with different strategies
5. **Contextual**: Preserves vulnerability context through repairs

## Limitations

1. **LLM Dependency**: Requires API access and costs tokens
2. **Build Time**: Each iteration requires compilation
3. **Pattern Coverage**: Limited to patterns the LLM can understand
4. **Validation**: Basic validation, could use more test cases

## Future Improvements

1. **Caching**: Save successful repairs for similar errors
2. **Test Generation**: Create test cases for each pattern
3. **Parallel Processing**: Generate multiple checkers simultaneously
4. **Advanced Validation**: Test against known CVE databases
5. **Learning Database**: Store successful patterns and repairs

## Error Recovery Strategies

The orchestrator employs several strategies:

1. **API Mismatch Recovery**:
   - Detects `getAs<T>` errors → Suggests `dyn_cast<T>`
   - Detects missing methods → Provides correct API

2. **AST Matcher Recovery**:
   - Invalid matcher syntax → Simplifies matcher
   - Complex patterns → Breaks into simpler matchers

3. **Include/Namespace Issues**:
   - Missing includes → Adds required headers
   - Namespace conflicts → Fully qualifies names

## Integration with Modules

- **Module 1**: Provides pattern analysis
- **Module 2**: Generates initial checker code
- **Module 3**: Handles build integration
- **Module 4**: Performs validation scans

The orchestrator coordinates these modules while adding the critical self-repair capability that makes the pipeline robust and autonomous.