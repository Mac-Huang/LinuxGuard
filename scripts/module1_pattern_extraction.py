#!/usr/bin/env python3
"""
Module 1 Rich: Pattern Extraction with Full Commit Context
Uses complete commit information for better LLM analysis.
"""

import json
import os
import subprocess
import argparse
from pathlib import Path
from typing import Dict, Optional
from dotenv import load_dotenv
import google.generativeai as genai

# Load environment variables
load_dotenv()

class RichCommitAnalyzer:
    """Analyzes commits with full context for security anti-patterns."""

    def __init__(self):
        # Initialize Gemini
        api_key = os.getenv('GEMINI_API_KEY')
        if not api_key:
            raise ValueError("GEMINI_API_KEY not found in .env file")

        genai.configure(api_key=api_key)
        model_name = os.getenv('GEMINI_MODEL', 'gemini-2.0-flash-lite')
        self.model = genai.GenerativeModel(model_name)

    def analyze_commit(self, commit_data: Dict, patch_content: str) -> Optional[Dict]:
        """Analyze commit with rich context."""

        # Build comprehensive context
        context = self.build_commit_context(commit_data, patch_content)

        print(f"Analyzing commit with full context...")
        print(f"  Subject: {commit_data['summary']['subject'][:60]}...")
        print(f"  Files: {commit_data['summary']['files_changed']} changed")

        return self.analyze_with_llm(context)

    def build_commit_context(self, commit_data: Dict, patch_content: str) -> str:
        """Build rich context for LLM analysis."""

        summary = commit_data['summary']
        commit_info = commit_data['commit_info']

        # Truncate patch if too large
        if len(patch_content) > 40000:
            patch_content = patch_content[:40000] + "\n... [truncated for analysis]"

        context = f"""
=== COMMIT INFORMATION ===
Commit: {commit_data['commit_hash'][:12]}
Author: {summary['author']}
Date: {summary['date']}
Subject: {summary['subject']}

=== COMMIT MESSAGE ===
{commit_info.get('message_body', 'No message body')}

=== METADATA ===
Files Changed: {summary['files_changed']}
Lines Added: {summary['additions']}
Lines Removed: {summary['deletions']}
"""

        # Add Fixes information if available
        if summary['has_fixes_tag'] and commit_info.get('fixes'):
            context += f"\nFixes: {', '.join(commit_info['fixes'])}"

        # Add reporter information if available
        if summary['reporters']:
            context += f"\nReported-by: {', '.join(summary['reporters'])}"

        # Add reviewers if available
        if commit_info.get('reviewed_by'):
            context += f"\nReviewed-by: {', '.join(commit_info['reviewed_by'][:2])}"

        # Add file change summary
        if commit_info.get('diff_analysis'):
            files = commit_info['diff_analysis'].get('files_changed', [])
            if files:
                context += "\n\n=== FILES MODIFIED ==="
                for f in files[:10]:  # Limit to first 10 files
                    context += f"\n- {f['from']}"
                    if f['from'] != f['to']:
                        context += f" -> {f['to']}"

        # Add the actual patch
        context += f"\n\n=== COMMIT PATCH ===\n{patch_content}"

        return context

    def analyze_with_llm(self, context: str) -> Optional[Dict]:
        """Use LLM to analyze commit with rich context."""

        prompt = f"""You are analyzing a Linux kernel commit to determine if it fixes a security vulnerability or critical bug.
You have access to the complete commit information including message, metadata, and full patch.

Analyze the following commit and determine:

1. Is this a security or critical bug fix? Look for:
   - Fixes tags referencing security issues
   - Security-related keywords in the commit message
   - Patterns indicating vulnerability fixes (bounds checks, null checks, race conditions, etc.)
   - Reporter information suggesting security research
   - Code changes that add defensive checks or fix dangerous patterns

2. If this IS a security/critical fix, extract:
   - Anti-pattern type (unchecked-error, null-deref, use-after-free, race-condition, overflow, double-free, uninitialized-var, missing-bounds-check, etc.)
   - What was vulnerable in the BEFORE code
   - What protection was added in the AFTER code
   - AST patterns that could detect similar issues
   - Severity assessment based on exploitability and impact

Respond with this JSON structure:

If NOT a security fix:
{{"is_security_fix": false, "reason": "brief explanation"}}

If IS a security fix:
{{
  "is_security_fix": true,
  "confidence": "high|medium|low",
  "anti_pattern_type": "specific-type",
  "vulnerability_class": "CWE-XXX category if applicable",
  "vulnerable_pattern": {{
    "description": "what was wrong in the original code",
    "key_indicators": ["specific code patterns that were vulnerable"],
    "code_context": "relevant code snippet showing the vulnerability",
    "exploitability": "how could this be exploited"
  }},
  "fix_pattern": {{
    "description": "what the fix does to prevent the vulnerability",
    "required_checks": ["specific checks or validations added"],
    "code_context": "relevant code snippet showing the fix",
    "protection_mechanism": "type of protection added"
  }},
  "ast_matcher_hints": {{
    "node_types": ["AST node types to match"],
    "relationships": ["parent-child or sibling relationships"],
    "conditions": ["specific conditions to check for"],
    "pattern_description": "natural language description of what to match"
  }},
  "severity": "critical|high|medium|low",
  "cwe_ids": ["CWE-XXX"],
  "impact": "potential impact if exploited",
  "affected_subsystem": "kernel subsystem affected"
}}

COMMIT TO ANALYZE:
{context}

Respond with ONLY valid JSON, no additional text."""

        try:
            response = self.model.generate_content(prompt)
            response_text = response.text.strip()

            # Clean response
            if response_text.startswith('```json'):
                response_text = response_text[7:]
            if response_text.startswith('```'):
                response_text = response_text[3:]
            if response_text.endswith('```'):
                response_text = response_text[:-3]

            result = json.loads(response_text.strip())

            # Log confidence if it's a security fix
            if result.get('is_security_fix'):
                print(f"  ✓ Security fix detected (confidence: {result.get('confidence', 'unknown')})")
                print(f"    Type: {result.get('anti_pattern_type', 'unknown')}")
                print(f"    Severity: {result.get('severity', 'unknown')}")
            else:
                print(f"  ✗ Not a security fix: {result.get('reason', 'no reason given')}")

            return result

        except Exception as e:
            print(f"Error analyzing with LLM: {e}")
            return None

    def generate_checker_guidance(self, analysis: Dict, commit_hash: str) -> Dict:
        """Generate comprehensive guidance for Module 2."""

        guidance = {
            "commit_hash": commit_hash,
            "anti_pattern_type": analysis.get("anti_pattern_type", "unknown"),
            "severity": analysis.get("severity", "medium"),
            "confidence": analysis.get("confidence", "medium"),
            "cwe_ids": analysis.get("cwe_ids", []),
            "vulnerability_class": analysis.get("vulnerability_class", ""),

            "checker_requirements": {
                "checker_name": self.suggest_checker_name(analysis["anti_pattern_type"]),
                "ast_matchers_needed": analysis.get("ast_matcher_hints", {}).get("node_types", []),
                "conditions_to_check": analysis.get("ast_matcher_hints", {}).get("conditions", []),
                "relationships": analysis.get("ast_matcher_hints", {}).get("relationships", []),
                "pattern_description": analysis.get("ast_matcher_hints", {}).get("pattern_description", "")
            },

            "pattern_description": {
                "vulnerable": analysis.get("vulnerable_pattern", {}),
                "fixed": analysis.get("fix_pattern", {})
            },

            "context": {
                "impact": analysis.get("impact", ""),
                "affected_subsystem": analysis.get("affected_subsystem", ""),
                "exploitability": analysis.get("vulnerable_pattern", {}).get("exploitability", "")
            },

            "template_hints": {
                "base_template": "MustCheckErrsCheck",
                "modifications_needed": self.suggest_template_modifications(analysis)
            }
        }

        return guidance

    def suggest_checker_name(self, anti_pattern_type: str) -> str:
        """Generate appropriate checker name based on anti-pattern type."""
        # Clean the anti-pattern type
        clean_type = anti_pattern_type.replace('-', '_').replace(' ', '_')

        # Map to checker names
        name_map = {
            "unchecked_error": "MustCheckErrors",
            "null_deref": "NullPointerDereference",
            "null_pointer_dereference": "NullPointerDereference",
            "use_after_free": "UseAfterFree",
            "race_condition": "RaceCondition",
            "buffer_overflow": "BufferOverflow",
            "overflow": "BufferOverflow",
            "double_free": "DoubleFree",
            "uninitialized_var": "UninitializedVariable",
            "uninitialized_variable": "UninitializedVariable",
            "missing_bounds_check": "MissingBoundsCheck",
            "integer_overflow": "IntegerOverflow",
            "memory_leak": "MemoryLeak"
        }

        base_name = name_map.get(clean_type, "Security" + clean_type.title().replace('_', ''))
        return f"{base_name}Check"

    def suggest_template_modifications(self, analysis: Dict) -> list:
        """Suggest detailed template modifications."""
        modifications = []
        anti_pattern = analysis.get("anti_pattern_type", "")

        # Can be replaced with RAG in the future
        # Base modifications from anti-pattern type
        if "unchecked" in anti_pattern or "error" in anti_pattern:
            modifications.append("Focus on function return value checking")
            modifications.append("Match error-returning functions without subsequent checks")
            modifications.append("Consider both direct checks and assigned-then-checked patterns")
        elif "null" in anti_pattern:
            modifications.append("Track pointer assignments and dereferences")
            modifications.append("Identify paths where pointers are used without null checks")
            modifications.append("Consider both explicit and implicit dereferences")
        elif "use-after-free" in anti_pattern or "use_after_free" in anti_pattern:
            modifications.append("Track memory allocation and deallocation")
            modifications.append("Build flow analysis to detect uses after free")
            modifications.append("Consider both direct and indirect accesses")
        elif "overflow" in anti_pattern:
            modifications.append("Identify array and buffer operations")
            modifications.append("Check for bounds validation before access")
            modifications.append("Consider integer overflow in size calculations")
        elif "race" in anti_pattern:
            modifications.append("Identify shared resource access")
            modifications.append("Check for proper synchronization primitives")
            modifications.append("Consider lock ordering and deadlock potential")

        # Add specific patterns from the analysis
        if analysis.get("ast_matcher_hints", {}).get("pattern_description"):
            modifications.append(f"Specific pattern: {analysis['ast_matcher_hints']['pattern_description']}")

        return modifications

def main():
    parser = argparse.ArgumentParser(description='Extract anti-patterns using rich commit context')
    parser.add_argument('--commit-hash', default='80af3745ca465c6c47e833c1902004a7fa944f37',
                      help='Commit hash to analyze')
    parser.add_argument('--commit-dir', default='/home/mac/private/linux-guard/commits',
                      help='Directory containing commit data')
    parser.add_argument('--output', default='/home/mac/private/linux-guard/results/anti_patterns.json',
                      help='Output file for analysis')
    parser.add_argument('--guidance-output', default='/home/mac/private/linux-guard/results/checker_guidance.json',
                      help='Output file for Module 2 guidance')

    args = parser.parse_args()

    print("=== Module 1 Rich: Pattern Extraction with Full Context ===")

    # Fetch commit if needed
    commit_json = Path(args.commit_dir) / f"{args.commit_hash}.json"
    commit_patch = Path(args.commit_dir) / f"{args.commit_hash}.patch"

    if not commit_json.exists() or not commit_patch.exists():
        print(f"\nFetching complete commit data...")
        result = subprocess.run([
            "python3", "/home/mac/private/linux-guard/scripts/fetch_commit_full.py",
            args.commit_hash, "--output-dir", args.commit_dir
        ], capture_output=True, text=True)

        if result.returncode != 0:
            print("✗ Failed to fetch commit")
            return 1

    # Load commit data
    with open(commit_json, 'r') as f:
        commit_data = json.load(f)

    with open(commit_patch, 'r') as f:
        patch_content = f.read()

    # Analyze commit
    analyzer = RichCommitAnalyzer()
    analysis = analyzer.analyze_commit(commit_data, patch_content)

    if analysis and analysis.get("is_security_fix", False):
        # Generate guidance
        guidance = analyzer.generate_checker_guidance(analysis, args.commit_hash)

        # Save outputs
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)

        with open(args.output, 'w') as f:
            json.dump(analysis, f, indent=2)

        with open(args.guidance_output, 'w') as f:
            json.dump(guidance, f, indent=2)

        print(f"\n✓ Analysis saved to {args.output}")
        print(f"✓ Guidance saved to {args.guidance_output}")

        return 0
    else:
        print("\n✗ Commit not identified as security fix or analysis failed")
        return 1

if __name__ == "__main__":
    exit(main())
