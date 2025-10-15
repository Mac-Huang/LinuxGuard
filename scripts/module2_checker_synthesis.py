#!/usr/bin/env python3
"""
Module 2: LLM-Guided Checker Synthesis
Generates clang-tidy checker code from anti-patterns using existing templates.
"""

import json
import os
import argparse
from pathlib import Path
from typing import Dict, List, Optional
from dotenv import load_dotenv
import google.generativeai as genai

# Load environment variables
load_dotenv()

class CheckerSynthesizer:
    """Synthesizes clang-tidy checkers using LLM and templates."""

    def __init__(self, template_dir: str = "/home/mac/private/linux-guard/checkers/templates"):
        self.template_dir = Path(template_dir)
        if not self.template_dir.exists():
            raise ValueError(f"Template directory {template_dir} does not exist")

        # Initialize Gemini
        api_key = os.getenv('GEMINI_API_KEY')
        if not api_key:
            raise ValueError("GEMINI_API_KEY not found in .env file")

        genai.configure(api_key=api_key)
        model_name = os.getenv('GEMINI_MODEL', 'gemini-2.0-flash-lite')
        self.model = genai.GenerativeModel(model_name)

        # Load templates
        self.templates = self.load_templates()

    def load_templates(self) -> Dict[str, str]:
        """Load template files."""
        templates = {}

        # Load header template
        header_path = self.template_dir / "MustCheckErrsCheck.h"
        if header_path.exists():
            with open(header_path, 'r') as f:
                templates['header'] = f.read()

        # Load implementation template
        cpp_path = self.template_dir / "MustCheckErrsCheck.cpp"
        if cpp_path.exists():
            with open(cpp_path, 'r') as f:
                templates['cpp'] = f.read()

        return templates

    def synthesize_checker(self, guidance: Dict) -> Dict[str, str]:
        """Generate checker code based on guidance from Module 1."""

        checker_name = guidance["checker_requirements"]["checker_name"]
        anti_pattern_type = guidance["anti_pattern_type"]

        # Generate header file
        header_code = self.generate_header(checker_name, guidance)

        # Generate implementation file
        cpp_code = self.generate_implementation(checker_name, guidance)

        return {
            "checker_name": checker_name,
            "header_file": f"{checker_name}.h",
            "cpp_file": f"{checker_name}.cpp",
            "header_code": header_code,
            "cpp_code": cpp_code,
            "anti_pattern_type": anti_pattern_type
        }

    def generate_header(self, checker_name: str, guidance: Dict) -> str:
        """Generate header file for the checker."""

        prompt = f"""Generate a clang-tidy checker header file based on this template and requirements.

Template structure to follow:
```cpp
{self.templates['header']}
```

Requirements:
- Checker name: {checker_name}
- Anti-pattern type: {guidance['anti_pattern_type']}
- Description: Detect {guidance['pattern_description']['vulnerable'].get('description', '')}

Generate a header file that:
1. Uses the same structure as the template
2. Replaces MustCheckErrsCheck with {checker_name}
3. Updates the class documentation to describe what this checker detects
4. Maintains the same namespace (clang::tidy::linuxkernel)
5. Uses proper include guards with the new checker name

Respond with ONLY the complete C++ header code, no explanations."""

        try:
            response = self.model.generate_content(prompt)
            return response.text.strip()
        except Exception as e:
            print(f"Error generating header: {e}")
            # Fallback to template-based generation
            return self.fallback_header_generation(checker_name, guidance)

    def generate_implementation(self, checker_name: str, guidance: Dict) -> str:
        """Generate implementation file for the checker using LLM."""

        # Prepare AST matcher requirements
        ast_requirements = {
            "node_types": guidance["checker_requirements"].get("ast_matchers_needed", []),
            "conditions": guidance["checker_requirements"].get("conditions_to_check", []),
            "relationships": guidance["checker_requirements"].get("relationships", [])
        }

        prompt = f"""Generate a clang-tidy checker implementation file based on this template and requirements.

Template structure to follow:
```cpp
{self.templates['cpp']}
```

Checker Requirements:
- Name: {checker_name}
- Anti-pattern: {guidance['anti_pattern_type']}
- Vulnerability description: {guidance['pattern_description']['vulnerable'].get('description', '')}
- Fix pattern: {guidance['pattern_description']['fixed'].get('description', '')}

AST Matcher Requirements:
- Node types to match: {ast_requirements['node_types']}
- Conditions to check: {ast_requirements['conditions']}
- Relationships between nodes: {ast_requirements['relationships']}

Key indicators of the vulnerability:
{json.dumps(guidance['pattern_description']['vulnerable'].get('key_indicators', []), indent=2)}

Generate an implementation that:
1. Uses the registerMatchers() function to set up AST matchers for this specific anti-pattern
2. Uses the check() function to report violations with descriptive messages
3. Follows the exact same structure as the template
4. Replaces MustCheckErrsCheck with {checker_name}
5. Creates appropriate AST matchers based on the anti-pattern type

For {guidance['anti_pattern_type']}, focus on:
{self.get_pattern_specific_hints(guidance['anti_pattern_type'])}

Use these common AST matchers as appropriate:
- callExpr(): Match function calls
- ifStmt(): Match if statements
- returnStmt(): Match return statements
- varDecl(): Match variable declarations
- memberExpr(): Match member access
- hasParent(): Check parent node relationships
- hasDescendant(): Check descendant nodes
- unless(): Negative matching

Respond with ONLY the complete C++ implementation code, no explanations."""

        try:
            response = self.model.generate_content(prompt)
            code = response.text.strip()

            # Clean up response if needed
            if code.startswith('```cpp'):
                code = code[6:]
            if code.startswith('```'):
                code = code[3:]
            if code.endswith('```'):
                code = code[:-3]

            return code.strip()
        except Exception as e:
            print(f"Error generating implementation: {e}")
            # Fallback to template-based generation
            return self.fallback_implementation_generation(checker_name, guidance)

    def get_pattern_specific_hints(self, anti_pattern_type: str) -> str:
        """Provide pattern-specific hints for AST matcher generation."""

        hints = {
            "unchecked-error": """
- Match function calls that return error pointers (ERR_PTR, IS_ERR, etc.)
- Check if the return value is used or checked
- Look for assignments without subsequent error checking""",

            "null-deref": """
- Match pointer dereferences (memberExpr with ->)
- Check if there's a null check before the dereference
- Track pointer assignments and subsequent uses""",

            "use-after-free": """
- Match kfree/free function calls
- Track the freed pointer variable
- Look for any uses of that pointer after the free call""",

            "overflow": """
- Match array subscript expressions
- Check bounds validation before array access
- Look for integer arithmetic that could overflow""",

            "race-condition": """
- Match lock/unlock pairs
- Check for shared data access without proper synchronization
- Look for missing memory barriers""",

            "double-free": """
- Match multiple kfree/free calls
- Track if the same pointer is freed twice
- Check for missing pointer nullification after free""",

            "uninitialized-var": """
- Match variable declarations without initializers
- Track uses before assignment
- Check all code paths for initialization"""
        }

        return hints.get(anti_pattern_type, "Match relevant AST nodes based on the vulnerability pattern")

    def fallback_header_generation(self, checker_name: str, guidance: Dict) -> str:
        """Generate header using simple template substitution if LLM fails."""

        header = self.templates['header']

        # Replace class name
        header = header.replace("MustCheckErrsCheck", checker_name)
        header = header.replace("MUSTCHECKERRSCHECK", checker_name.upper())

        # Update documentation
        doc = f"/// Checks for {guidance['anti_pattern_type']} vulnerabilities in Linux kernel code."
        header = header.replace("/// Checks Linux kernel code to see if it uses the results from the functions in", doc)
        header = header.replace("/// linux/err.h. Also checks to see if code uses the results from functions that", "///")
        header = header.replace("/// directly return a value from one of these error functions.", "///")

        return header

    def fallback_implementation_generation(self, checker_name: str, guidance: Dict) -> str:
        """Generate implementation using simple template substitution if LLM fails."""

        impl = self.templates['cpp']

        # Replace class name
        impl = impl.replace("MustCheckErrsCheck", checker_name)

        # Update the matcher based on anti-pattern type
        if "null" in guidance['anti_pattern_type']:
            # Modify for null dereference checking
            impl = impl.replace(
                'functionDecl(hasAnyName("ERR_PTR", "PTR_ERR", "IS_ERR", "IS_ERR_OR_NULL",\n                              "ERR_CAST", "PTR_ERR_OR_ZERO"))',
                'memberExpr(hasObjectExpression(expr().bind("ptr")))'
            )
            impl = impl.replace(
                '"result from function %0 is unused"',
                '"potential null pointer dereference"'
            )

        return impl

    def save_checker(self, checker_code: Dict, output_dir: str):
        """Save generated checker to files."""

        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        # Save header file
        header_path = output_path / checker_code["header_file"]
        with open(header_path, 'w') as f:
            f.write(checker_code["header_code"])

        # Save implementation file
        cpp_path = output_path / checker_code["cpp_file"]
        with open(cpp_path, 'w') as f:
            f.write(checker_code["cpp_code"])

        print(f"✓ Saved {checker_code['header_file']} to {header_path}")
        print(f"✓ Saved {checker_code['cpp_file']} to {cpp_path}")

        return {
            "header_path": str(header_path),
            "cpp_path": str(cpp_path)
        }

def main():
    parser = argparse.ArgumentParser(description='Synthesize clang-tidy checkers using LLM')
    parser.add_argument('--guidance', default='/home/mac/private/linux-guard/results/checker_guidance.json',
                      help='Input file with checker guidance from Module 1')
    parser.add_argument('--output-dir', default='/home/mac/private/linux-guard/checkers/generated',
                      help='Output directory for generated checkers')
    parser.add_argument('--template-dir', default='/home/mac/private/linux-guard/checkers/templates',
                      help='Directory containing checker templates')
    parser.add_argument('--single', action='store_true',
                      help='Process only the first guidance entry')

    args = parser.parse_args()

    print("=== Module 2: LLM-Guided Checker Synthesis ===")

    # Load guidance from Module 1
    if not Path(args.guidance).exists():
        print(f"✗ Guidance file not found: {args.guidance}")
        print("  Run Module 1 first to generate checker guidance")
        return

    with open(args.guidance, 'r') as f:
        guidances = json.load(f)

    # Handle both single and multiple guidance formats
    if isinstance(guidances, dict):
        guidances = [guidances]

    synthesizer = CheckerSynthesizer(args.template_dir)

    generated_checkers = []

    # Process guidances
    for i, guidance in enumerate(guidances):
        if args.single and i > 0:
            break

        print(f"\n[{i+1}/{len(guidances)}] Generating checker for: {guidance['anti_pattern_type']}")
        print(f"    Commit: {guidance['commit_hash'][:8]}")

        try:
            # Generate checker code
            checker_code = synthesizer.synthesize_checker(guidance)

            # Save to files
            file_paths = synthesizer.save_checker(checker_code, args.output_dir)

            # Record generated checker info
            generated_checkers.append({
                "checker_name": checker_code["checker_name"],
                "anti_pattern_type": checker_code["anti_pattern_type"],
                "files": file_paths,
                "commit_hash": guidance["commit_hash"]
            })

            print(f"    ✓ Successfully generated {checker_code['checker_name']}")

        except Exception as e:
            print(f"    ✗ Error generating checker: {e}")

    # Save metadata about generated checkers
    if generated_checkers:
        metadata_path = Path(args.output_dir) / "generated_checkers.json"
        with open(metadata_path, 'w') as f:
            json.dump(generated_checkers, f, indent=2)

        print(f"\n=== Summary ===")
        print(f"✓ Generated {len(generated_checkers)} checkers")
        print(f"✓ Saved metadata to {metadata_path}")
        print(f"\nGenerated checkers:")
        for checker in generated_checkers:
            print(f"  - {checker['checker_name']}: {checker['anti_pattern_type']}")
    else:
        print("\n✗ No checkers were generated")

if __name__ == "__main__":
    main()
