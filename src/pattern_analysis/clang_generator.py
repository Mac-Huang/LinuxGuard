"""
Clang Static Analyzer Generator
Automatically generates Clang checkers from derived anti-patterns
"""
import os
import json
from pathlib import Path
from typing import List, Dict, Any
from dataclasses import dataclass
import google.generativeai as genai
from loguru import logger
import re
import subprocess


@dataclass
class ClangChecker:
    """Generated Clang static analyzer checker"""
    checker_id: str
    name: str
    pattern_id: str
    source_code: str
    header_includes: List[str]
    check_functions: List[str]
    ast_matchers: List[str]
    bug_type: str
    description: str


class ClangCheckerGenerator:
    """Generates Clang static analyzer checkers from anti-patterns"""
    
    def __init__(self, api_key: str, model_name: str = "gemini-2.0-flash-exp"):
        self.api_key = api_key
        self.model_name = model_name
        
        # Initialize Gemini
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel(model_name)
        
        self.generated_checkers = []
        
        logger.info(f"Initialized ClangCheckerGenerator with {model_name}")
    
    def load_patterns(self, patterns_file: str = "data/pattern_analysis/derived_patterns.json") -> List[Dict]:
        """Load derived anti-patterns"""
        patterns_path = Path(patterns_file)
        if not patterns_path.exists():
            logger.error(f"Patterns file not found: {patterns_file}")
            return []
        
        with open(patterns_path, 'r', encoding='utf-8') as f:
            patterns = json.load(f)
        
        logger.info(f"Loaded {len(patterns)} anti-patterns for checker generation")
        return patterns
    
    def generate_checker_code(self, pattern: Dict) -> ClangChecker:
        """Generate Clang checker code for an anti-pattern"""
        
        generation_prompt = f"""Generate a complete Clang Static Analyzer checker for this Linux kernel anti-pattern:

**Pattern**: {pattern['name']}
**Category**: {pattern['category']}
**Vulnerability**: {pattern['vulnerability_type']}
**Description**: {pattern['description']}

**Detection Rules**:
{chr(10).join(f"- {rule}" for rule in pattern['detection_rules'])}

**Code Characteristics**:
{chr(10).join(f"- {char}" for char in pattern['code_characteristics'])}

Generate a complete Clang checker with this structure:

```cpp
//===--- {pattern['pattern_id']}Checker.cpp - {pattern['name']} checker -------*- C++ -*-===//
//
// Part of LinuxGuard Static Analysis Framework
//
//===----------------------------------------------------------------------===//

#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/DeclCXX.h"

using namespace clang;
using namespace ento;

namespace {{
class {pattern['pattern_id'].replace('_', '').title()}Checker : public Checker<check::PreCall, check::PostCall> {{
private:
  mutable std::unique_ptr<BugType> BT;
  
public:
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  
private:
  void reportBug(const CallEvent &Call, CheckerContext &C, 
                StringRef Description) const;
  bool isTargetFunction(const CallEvent &Call) const;
  bool detectAntiPattern(const CallEvent &Call, CheckerContext &C) const;
}};
}} // end anonymous namespace

// Implementation methods here...

void {pattern['pattern_id'].replace('_', '').title()}Checker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {{
  // Pre-call analysis
  if (!isTargetFunction(Call))
    return;
    
  if (detectAntiPattern(Call, C)) {{
    reportBug(Call, C, "{pattern['description']}");
  }}
}}

void {pattern['pattern_id'].replace('_', '').title()}Checker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {{
  // Post-call analysis if needed
}}

bool {pattern['pattern_id'].replace('_', '').title()}Checker::isTargetFunction(const CallEvent &Call) const {{
  // Function matching logic
  const FunctionDecl *FD = Call.getDecl();
  if (!FD)
    return false;
    
  StringRef FuncName = FD->getName();
  // Add specific function patterns based on the anti-pattern
  return false; // Replace with actual logic
}}

bool {pattern['pattern_id'].replace('_', '').title()}Checker::detectAntiPattern(const CallEvent &Call, CheckerContext &C) const {{
  // Anti-pattern detection logic
  // Implement based on detection rules
  return false; // Replace with actual detection
}}

void {pattern['pattern_id'].replace('_', '').title()}Checker::reportBug(const CallEvent &Call, CheckerContext &C, 
                                    StringRef Description) const {{
  if (!BT)
    BT.reset(new BugType(this, "{pattern['name']}", "{pattern['category']}"));
    
  ExplodedNode *N = C.generateErrorNode();
  if (!N)
    return;
    
  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Description, N);
  R->addRange(Call.getSourceRange());
  C.emitReport(std::move(R));
}}

// Registration
void ento::register{pattern['pattern_id'].replace('_', '').title()}Checker(CheckerManager &mgr) {{
  mgr.registerChecker<{pattern['pattern_id'].replace('_', '').title()}Checker>();
}}

bool ento::shouldRegister{pattern['pattern_id'].replace('_', '').title()}Checker(const CheckerManager &mgr) {{
  return true;
}}
```

Please provide:
1. **Complete implementation** of detection logic based on the rules
2. **Specific function patterns** to match
3. **AST analysis** for pattern detection
4. **Bug reporting** with detailed messages

Focus on **Linux kernel specific patterns** and make the checker **production-ready**."""

        try:
            response = self.model.generate_content(generation_prompt)
            
            if not response or not response.text:
                logger.warning(f"Empty response for pattern {pattern['pattern_id']}")
                return self._create_fallback_checker(pattern)
            
            # Extract C++ code from response
            cpp_code = self._extract_cpp_code(response.text)
            
            checker_id = f"checker_{pattern['pattern_id']}"
            
            return ClangChecker(
                checker_id=checker_id,
                name=pattern['name'],
                pattern_id=pattern['pattern_id'],
                source_code=cpp_code,
                header_includes=self._extract_includes(cpp_code),
                check_functions=self._extract_check_functions(cpp_code),
                ast_matchers=pattern.get('clang_ast_patterns', []),
                bug_type=pattern['vulnerability_type'],
                description=pattern['description']
            )
            
        except Exception as e:
            logger.error(f"Error generating checker for pattern {pattern['pattern_id']}: {e}")
            return self._create_fallback_checker(pattern)
    
    def _extract_cpp_code(self, response_text: str) -> str:
        """Extract C++ code from LLM response"""
        # Look for C++ code blocks
        cpp_pattern = r'```cpp\s*\n(.*?)\n\s*```'
        cpp_match = re.search(cpp_pattern, response_text, re.DOTALL)
        
        if cpp_match:
            return cpp_match.group(1)
        
        # If no code block, return the response (fallback)
        return response_text
    
    def _extract_includes(self, cpp_code: str) -> List[str]:
        """Extract #include statements from C++ code"""
        include_pattern = r'#include\s*[<"][^>"]+[>"]'
        includes = re.findall(include_pattern, cpp_code)
        return includes
    
    def _extract_check_functions(self, cpp_code: str) -> List[str]:
        """Extract check function names from C++ code"""
        function_pattern = r'void\s+(\w+)::(check\w+)\s*\('
        functions = re.findall(function_pattern, cpp_code)
        return [func[1] for func in functions]
    
    def _create_fallback_checker(self, pattern: Dict) -> ClangChecker:
        """Create fallback checker when generation fails"""
        checker_id = f"fallback_checker_{pattern['pattern_id']}"
        
        fallback_code = f"""
// Fallback checker for {pattern['name']}
// This is a template that needs manual implementation

#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

using namespace clang;
using namespace ento;

namespace {{
class FallbackChecker : public Checker<check::PreCall> {{
public:
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const {{
    // TODO: Implement {pattern['name']} detection
    // Pattern: {pattern['description']}
  }}
}};
}}

void ento::registerFallbackChecker(CheckerManager &mgr) {{
  mgr.registerChecker<FallbackChecker>();
}}

bool ento::shouldRegisterFallbackChecker(const CheckerManager &mgr) {{
  return true;
}}
"""
        
        return ClangChecker(
            checker_id=checker_id,
            name=f"Fallback {pattern['name']}",
            pattern_id=pattern['pattern_id'],
            source_code=fallback_code,
            header_includes=["clang/StaticAnalyzer/Core/Checker.h"],
            check_functions=["checkPreCall"],
            ast_matchers=[],
            bug_type=pattern['vulnerability_type'],
            description=f"Fallback checker for {pattern['description']}"
        )
    
    def generate_all_checkers(self, patterns: List[Dict] = None) -> List[ClangChecker]:
        """Generate Clang checkers for all patterns"""
        if patterns is None:
            patterns = self.load_patterns()
        
        if not patterns:
            logger.error("No patterns available for checker generation")
            return []
        
        logger.info(f"Generating Clang checkers for {len(patterns)} patterns...")
        
        checkers = []
        for i, pattern in enumerate(patterns):
            try:
                checker = self.generate_checker_code(pattern)
                checkers.append(checker)
                logger.info(f"Generated checker {i+1}/{len(patterns)}: {checker.name}")
                
                # Rate limiting
                if i % 3 == 2:  # Every 3 checkers
                    import time
                    time.sleep(3)
                    
            except Exception as e:
                logger.error(f"Failed to generate checker for pattern {pattern.get('pattern_id', 'unknown')}: {e}")
                continue
        
        self.generated_checkers = checkers
        logger.info(f"Generated {len(checkers)} Clang checkers")
        return checkers
    
    def save_checkers(self, output_dir: str = "data/static_checkers"):
        """Save generated checkers to files"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Create checkers directory
        checkers_dir = output_path / "checkers"
        checkers_dir.mkdir(exist_ok=True)
        
        for checker in self.generated_checkers:
            # Save individual checker source
            checker_file = checkers_dir / f"{checker.checker_id}.cpp"
            with open(checker_file, 'w', encoding='utf-8') as f:
                f.write(checker.source_code)
            
            logger.info(f"Saved checker: {checker_file}")
        
        # Save checker metadata
        metadata = []
        for checker in self.generated_checkers:
            metadata.append({
                'checker_id': checker.checker_id,
                'name': checker.name,
                'pattern_id': checker.pattern_id,
                'bug_type': checker.bug_type,
                'description': checker.description,
                'header_includes': checker.header_includes,
                'check_functions': checker.check_functions,
                'ast_matchers': checker.ast_matchers
            })
        
        metadata_file = output_path / "checkers_metadata.json"
        with open(metadata_file, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2, ensure_ascii=False)
        
        # Generate CMakeLists.txt for building
        self._generate_cmake_file(output_path)
        
        # Generate registration file
        self._generate_registration_file(output_path)
        
        logger.info(f"Saved {len(self.generated_checkers)} checkers to {output_path}")
    
    def _generate_cmake_file(self, output_path: Path):
        """Generate CMakeLists.txt for building checkers"""
        cmake_content = f"""# LinuxGuard Static Checkers CMakeLists.txt

cmake_minimum_required(VERSION 3.13.4)
project(LinuxGuardCheckers)

find_package(Clang REQUIRED)

# Add checker sources
set(CHECKER_SOURCES
"""
        
        for checker in self.generated_checkers:
            cmake_content += f"  checkers/{checker.checker_id}.cpp\n"
        
        cmake_content += f""")

# Create checker library
add_library(LinuxGuardCheckers SHARED ${{CHECKER_SOURCES}})

target_link_libraries(LinuxGuardCheckers
  clangStaticAnalyzerCore
  clangStaticAnalyzerCheckers
  clangAST
  clangBasic
)

target_include_directories(LinuxGuardCheckers PRIVATE
  ${{CLANG_INCLUDE_DIRS}}
)
"""
        
        cmake_file = output_path / "CMakeLists.txt"
        with open(cmake_file, 'w', encoding='utf-8') as f:
            f.write(cmake_content)
    
    def _generate_registration_file(self, output_path: Path):
        """Generate checker registration file"""
        reg_content = f"""// LinuxGuard Checker Registration
// Auto-generated file - do not edit manually

#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"

using namespace clang;
using namespace ento;

// Forward declarations
"""
        
        for checker in self.generated_checkers:
            class_name = checker.checker_id.replace('_', '').title() + "Checker"
            reg_content += f"void register{class_name}(CheckerManager &mgr);\n"
            reg_content += f"bool shouldRegister{class_name}(const CheckerManager &mgr);\n"
        
        reg_content += f"""

// Registration function
extern "C" void registerLinuxGuardCheckers(CheckerManager &mgr) {{
"""
        
        for checker in self.generated_checkers:
            class_name = checker.checker_id.replace('_', '').title() + "Checker"
            reg_content += f"  register{class_name}(mgr);\n"
        
        reg_content += "}\n"
        
        reg_file = output_path / "Registration.cpp"
        with open(reg_file, 'w', encoding='utf-8') as f:
            f.write(reg_content)
    
    def generate_summary_report(self) -> str:
        """Generate summary report of checker generation"""
        if not self.generated_checkers:
            return "No checkers generated yet. Run checker generation first."
        
        report = f"""# LinuxGuard Clang Checker Generation Report

## Summary
- **Generated checkers**: {len(self.generated_checkers)}
- **Bug types covered**: {len(set(checker.bug_type for checker in self.generated_checkers))}

## Generated Checkers

"""
        
        for i, checker in enumerate(self.generated_checkers, 1):
            report += f"""### {i}. {checker.name}

- **Checker ID**: {checker.checker_id}
- **Pattern ID**: {checker.pattern_id}
- **Bug Type**: {checker.bug_type}
- **Check Functions**: {', '.join(checker.check_functions)}

**Description**: {checker.description}

**Source File**: `checkers/{checker.checker_id}.cpp`

---
"""
        
        report += f"""
## Build Instructions

```bash
cd data/static_checkers
mkdir build && cd build
cmake ..
make -j$(nproc)
```

## Usage

```bash
clang -cc1 -analyze -analyzer-checker=linuxguard.{self.generated_checkers[0].checker_id if self.generated_checkers else 'example'} file.c
```
"""
        
        return report


def main():
    """Test the Clang checker generator"""
    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        logger.error("GOOGLE_API_KEY environment variable not set")
        return
    
    generator = ClangCheckerGenerator(api_key)
    checkers = generator.generate_all_checkers()
    
    if checkers:
        generator.save_checkers()
        
        report = generator.generate_summary_report()
        print(report)
        
        # Save report
        report_path = Path("data/static_checkers/checker_generation_report.md")
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report)


if __name__ == "__main__":
    main()