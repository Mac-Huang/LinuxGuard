#!/usr/bin/env python3
"""
ANTIPATTERN_PIPELINE v2.0
Optimized Clang Checker Generator based on LLVM clang-tidy examples
"""

import os
import sys
import json
import requests
from pathlib import Path
from datetime import datetime

# Add parent directory for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

class OptimizedCheckerGenerator:
    def __init__(self):
        self.llvm_examples_path = Path("llvm_examples/linuxkernel")
        self.generated_path = Path("generated")
        self.prompts_path = Path("prompts")

        # Load LLVM examples for reference
        self.load_llvm_examples()

        # Load configuration
        self.load_config()

    def load_llvm_examples(self):
        """Load and analyze LLVM clang-tidy examples"""
        self.examples = {}

        for example_file in self.llvm_examples_path.glob("*.cpp"):
            if example_file.exists():
                content = example_file.read_text()
                self.examples[example_file.stem] = content
                print(f"  [OK] Loaded example: {example_file.stem}")

    def load_config(self):
        """Load API configuration"""
        try:
            import config
            self.api_key = config.MODEL_API_KEY
            self.model_name = config.MODEL_NAME
            self.endpoint = config.MODEL_ENDPOINT
        except:
            print("[WARNING] Config not found, using environment variables")
            self.api_key = os.getenv("MODEL_API_KEY", "")
            self.model_name = os.getenv("MODEL_NAME", "gemini-2.0-flash-lite")
            self.endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model_name}:generateContent"

    def create_optimized_prompt(self, vulnerability_info):
        """Create an optimized prompt based on LLVM examples"""

        # Get a sample LLVM example for structure reference
        example_structure = self.examples.get("MustCheckErrsCheck", "")

        prompt = f"""You are an expert in LLVM/Clang static analysis and Linux kernel security.

Based on the professional LLVM clang-tidy LinuxKernel module structure, generate a production-ready Clang checker.

REFERENCE LLVM CLANG-TIDY STRUCTURE:
{example_structure[:3000]}  # First 3000 chars as reference

VULNERABILITY TO DETECT:
{json.dumps(vulnerability_info, indent=2)}

REQUIREMENTS:
1. Follow EXACT LLVM clang-tidy code structure and patterns
2. Use proper AST matchers from clang/ASTMatchers
3. Include proper namespace (clang::tidy::linuxkernel)
4. Generate both .h and .cpp files
5. Use professional C++ coding standards
6. Include detailed diagnostic messages
7. Follow Linux kernel coding conventions
8. Ensure the checker can be compiled as a clang-tidy module

Generate a complete, production-ready checker that:
- Uses AST matchers effectively
- Provides clear diagnostic messages
- Handles edge cases properly
- Can be integrated into CI/CD pipelines
- Follows LLVM project coding standards

Return the complete C++ implementation with proper headers and implementation."""

        return prompt

    def generate_checker(self, vulnerability_type):
        """Generate optimized checker using LLVM examples as reference"""
        print(f"\nGenerating optimized {vulnerability_type} checker...")

        # Prepare vulnerability info
        vuln_info = {
            "type": vulnerability_type,
            "patterns": self.get_vulnerability_patterns(vulnerability_type),
            "context": "Linux kernel code",
            "severity": "high"
        }

        # Create optimized prompt
        prompt = self.create_optimized_prompt(vuln_info)

        # Save prompt for debugging
        prompt_file = self.prompts_path / f"{vulnerability_type}_prompt.txt"
        prompt_file.parent.mkdir(exist_ok=True)
        prompt_file.write_text(prompt)
        print(f"  [OK] Saved prompt to {prompt_file}")

        # Call API to generate checker
        try:
            response = self.call_model_api(prompt)

            # Extract and save generated code
            if response:
                self.save_generated_checker(vulnerability_type, response)
                return True
        except Exception as e:
            print(f"  [ERROR] Error generating checker: {e}")
            return False

    def get_vulnerability_patterns(self, vuln_type):
        """Get vulnerability patterns based on type"""
        patterns = {
            "buffer-overflow": [
                "strcpy without bounds checking",
                "sprintf without size limits",
                "array access without bounds validation"
            ],
            "use-after-free": [
                "pointer dereference after kfree",
                "accessing freed memory",
                "double free patterns"
            ],
            "null-pointer": [
                "dereferencing NULL pointers",
                "missing NULL checks after allocation",
                "inconsistent NULL validation"
            ]
        }
        return patterns.get(vuln_type, ["generic vulnerability pattern"])

    def call_model_api(self, prompt):
        """Call the model API to generate checker"""
        headers = {
            "Content-Type": "application/json"
        }

        data = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.3,  # Lower temperature for code generation
                "topK": 40,
                "topP": 0.95,
                "maxOutputTokens": 8192
            }
        }

        # Add API key to URL
        url = f"{self.endpoint}?key={self.api_key}"

        response = requests.post(url, headers=headers, json=data)

        if response.status_code == 200:
            result = response.json()
            if 'candidates' in result and len(result['candidates']) > 0:
                return result['candidates'][0]['content']['parts'][0]['text']

        return None

    def save_generated_checker(self, vuln_type, code):
        """Save the generated checker code"""
        checker_name = f"{vuln_type.replace('-', '_').title()}Checker"

        # Parse the generated code to separate .h and .cpp
        if "#ifndef" in code or "#define" in code:
            # Split into header and implementation
            parts = code.split("\n\n")
            header_code = ""
            impl_code = ""

            in_header = True
            for part in parts:
                if "#include" in part and ".h" in part:
                    in_header = False

                if in_header:
                    header_code += part + "\n\n"
                else:
                    impl_code += part + "\n\n"

            # Save header file
            header_file = self.generated_path / f"{checker_name}.h"
            header_file.write_text(header_code)
            print(f"  [OK] Saved {header_file}")

            # Save implementation file
            impl_file = self.generated_path / f"{checker_name}.cpp"
            impl_file.write_text(impl_code)
            print(f"  [OK] Saved {impl_file}")
        else:
            # Save as single file
            cpp_file = self.generated_path / f"{checker_name}.cpp"
            cpp_file.write_text(code)
            print(f"  [OK] Saved {cpp_file}")

    def run(self):
        """Run the optimized checker generation"""
        print("="*80)
        print("ANTIPATTERN_PIPELINE v2.0 - LLVM-Optimized Checker Generation")
        print("="*80)

        # Load vulnerability type from commit_data
        try:
            from data.commit_data import VULNERABILITY_TYPE
            vuln_type = VULNERABILITY_TYPE
        except:
            vuln_type = "buffer-overflow"
            print(f"[WARNING] Using default vulnerability type: {vuln_type}")

        print(f"\nGenerating checker for: {vuln_type}")

        # Generate optimized checker
        if self.generate_checker(vuln_type):
            print("\n[SUCCESS] Successfully generated optimized checker")
            print("\nNext steps:")
            print("1. Review generated checker in 'generated/' directory")
            print("2. Compile with: python compile_checker.py")
            print("3. Run analysis with: python run_analysis.py")
        else:
            print("\n[FAILED] Failed to generate checker")

def main():
    generator = OptimizedCheckerGenerator()
    generator.run()

if __name__ == "__main__":
    main()

