#!/usr/bin/env python3
"""
Module 1: Pattern Extraction from Kernel Commits
Uses LLM to analyze git commits and extract anti-patterns for checker generation.
"""

import json
import subprocess
import os
import argparse
from pathlib import Path
from typing import Dict, List, Optional
from dotenv import load_dotenv
import google.generativeai as genai

# Load environment variables
load_dotenv()

class KernelCommitAnalyzer:
    """Analyzes kernel commits using LLM to extract security anti-patterns."""

    def __init__(self, kernel_path: str):
        self.kernel_path = Path(kernel_path)
        if not self.kernel_path.exists():
            raise ValueError(f"Kernel path {kernel_path} does not exist")

        # Initialize Gemini
        api_key = os.getenv('GEMINI_API_KEY')
        if not api_key:
            raise ValueError("GEMINI_API_KEY not found in .env file")

        genai.configure(api_key=api_key)
        model_name = os.getenv('GEMINI_MODEL', 'gemini-2.0-flash-lite')
        self.model = genai.GenerativeModel(model_name)

    def get_security_commits(self, limit: int = 100) -> List[str]:
        """Find commits that might be security-related fixes."""
        # Cast a wider net - let LLM determine if it's security-relevant
        cmd = [
            "git", "-C", str(self.kernel_path), "log",
            "--grep", "fix\\|Fix\\|FIX\\|bug\\|Bug\\|BUG\\|error\\|Error\\|crash\\|Crash",
            "--pretty=format:%H|||%s|||%b",
            f"-{limit}"
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            commits = []
            for entry in result.stdout.strip().split('\n'):
                if entry:
                    parts = entry.split('|||')
                    if len(parts) >= 2:
                        commits.append({
                            'hash': parts[0],
                            'subject': parts[1],
                            'body': parts[2] if len(parts) > 2 else ''
                        })
            return commits
        except subprocess.CalledProcessError as e:
            print(f"Error getting commits: {e}")
            return []

    def get_commit_diff(self, commit_hash: str) -> str:
        """Get the full diff of a commit."""
        cmd = [
            "git", "-C", str(self.kernel_path), "show",
            "--format=fuller", commit_hash
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return result.stdout
        except subprocess.CalledProcessError as e:
            print(f"Error getting diff for {commit_hash}: {e}")
            return ""

    def analyze_commit_with_llm(self, commit_diff: str) -> Optional[Dict]:
        """Use LLM to analyze commit and extract anti-pattern information."""

        # Truncate very large diffs
        if len(commit_diff) > 50000:
            commit_diff = commit_diff[:50000] + "\n... [truncated for analysis]"

        prompt = """Analyze this Linux kernel commit diff and determine if it fixes a security vulnerability or critical bug.

If this IS a security/critical fix, extract:
1. Anti-pattern type (e.g., unchecked-error, null-deref, use-after-free, race-condition, overflow, double-free, uninitialized-var, missing-bounds-check)
2. Vulnerable code pattern (what was wrong in the BEFORE code)
3. Fixed pattern (what the AFTER code does correctly)
4. AST matcher hint (describe what AST patterns could detect this bug)
5. Severity (low/medium/high/critical)

If this is NOT a security/critical fix, respond with: {"is_security_fix": false}

Otherwise respond with this JSON structure:
{
  "is_security_fix": true,
  "anti_pattern_type": "...",
  "vulnerable_pattern": {
    "description": "...",
    "key_indicators": ["..."],
    "code_context": "..."
  },
  "fix_pattern": {
    "description": "...",
    "required_checks": ["..."],
    "code_context": "..."
  },
  "ast_matcher_hints": {
    "node_types": ["..."],
    "relationships": ["..."],
    "conditions": ["..."]
  },
  "severity": "...",
  "cwe_ids": ["..."]
}

Commit diff to analyze:
```
{}
```

Respond ONLY with valid JSON.""".format(commit_diff)

        try:
            response = self.model.generate_content(prompt)
            # Clean response and parse JSON
            response_text = response.text.strip()
            # Remove markdown code blocks if present
            if response_text.startswith('```json'):
                response_text = response_text[7:]
            if response_text.startswith('```'):
                response_text = response_text[3:]
            if response_text.endswith('```'):
                response_text = response_text[:-3]

            return json.loads(response_text.strip())
        except Exception as e:
            print(f"Error analyzing with LLM: {e}")
            return None

    def generate_checker_guidance(self, analysis: Dict, commit_hash: str) -> Dict:
        """Generate guidance for Module 2 based on LLM analysis."""

        guidance = {
            "commit_hash": commit_hash,
            "anti_pattern_type": analysis.get("anti_pattern_type", "unknown"),
            "severity": analysis.get("severity", "medium"),
            "cwe_ids": analysis.get("cwe_ids", []),

            # For Module 2: Checker synthesis guidance
            "checker_requirements": {
                "checker_name": self.suggest_checker_name(analysis["anti_pattern_type"]),
                "ast_matchers_needed": analysis.get("ast_matcher_hints", {}).get("node_types", []),
                "conditions_to_check": analysis.get("ast_matcher_hints", {}).get("conditions", []),
                "relationships": analysis.get("ast_matcher_hints", {}).get("relationships", []),
            },

            # Pattern descriptions for LLM in Module 2
            "pattern_description": {
                "vulnerable": analysis.get("vulnerable_pattern", {}),
                "fixed": analysis.get("fix_pattern", {})
            },

            # Template hints for Module 2
            "template_hints": {
                "base_template": "MustCheckErrsCheck",  # Reference to existing template
                "modifications_needed": self.suggest_template_modifications(analysis)
            }
        }

        return guidance

    def suggest_checker_name(self, anti_pattern_type: str) -> str:
        """Generate appropriate checker name based on anti-pattern type."""
        name_map = {
            "unchecked-error": "MustCheckErrors",
            "null-deref": "NullPointerDereference",
            "use-after-free": "UseAfterFree",
            "race-condition": "RaceCondition",
            "overflow": "BufferOverflow",
            "double-free": "DoubleFree",
            "uninitialized-var": "UninitializedVariable",
            "missing-bounds-check": "MissingBoundsCheck"
        }
        base_name = name_map.get(anti_pattern_type, "CustomSecurity")
        return f"{base_name}Check"

    def suggest_template_modifications(self, analysis: Dict) -> List[str]:
        """Suggest how to modify the template based on the anti-pattern."""
        modifications = []

        anti_pattern = analysis.get("anti_pattern_type", "")

        if "unchecked" in anti_pattern or "error" in anti_pattern:
            modifications.append("Focus on function return value checking")
            modifications.append("Look for error-returning functions without subsequent checks")
        elif "null" in anti_pattern:
            modifications.append("Track pointer assignments and dereferences")
            modifications.append("Check for null checks before pointer usage")
        elif "use-after-free" in anti_pattern:
            modifications.append("Track memory allocation and deallocation")
            modifications.append("Detect uses after free/kfree calls")
        elif "overflow" in anti_pattern:
            modifications.append("Check array access bounds")
            modifications.append("Verify size parameters in memory operations")

        return modifications

def main():
    parser = argparse.ArgumentParser(description='Extract anti-patterns from kernel commits using LLM')
    parser.add_argument('--kernel-path', default='/home/mac/private/linux-guard/kernels/linux-v3.0',
                      help='Path to Linux kernel source')
    parser.add_argument('--output', default='/home/mac/private/linux-guard/results/anti_patterns.json',
                      help='Output file for extracted patterns')
    parser.add_argument('--guidance-output', default='/home/mac/private/linux-guard/results/checker_guidance.json',
                      help='Output file for Module 2 guidance')
    parser.add_argument('--limit', type=int, default=20,
                      help='Number of commits to examine')
    parser.add_argument('--commit', help='Analyze specific commit hash')

    args = parser.parse_args()

    print("=== Module 1: Pattern Extraction from Kernel Commits ===")
    analyzer = KernelCommitAnalyzer(args.kernel_path)

    if args.commit:
        # Analyze specific commit
        print(f"\nAnalyzing specific commit: {args.commit}")
        commit_diff = analyzer.get_commit_diff(args.commit)

        if commit_diff:
            print("Sending to LLM for analysis...")
            analysis = analyzer.analyze_commit_with_llm(commit_diff)

            if analysis and analysis.get("is_security_fix", False):
                print(f"✓ Security fix detected: {analysis['anti_pattern_type']}")

                # Generate guidance for Module 2
                guidance = analyzer.generate_checker_guidance(analysis, args.commit)

                # Save outputs
                Path(args.output).parent.mkdir(parents=True, exist_ok=True)
                with open(args.output, 'w') as f:
                    json.dump(analysis, f, indent=2)

                with open(args.guidance_output, 'w') as f:
                    json.dump(guidance, f, indent=2)

                print(f"✓ Saved analysis to {args.output}")
                print(f"✓ Saved Module 2 guidance to {args.guidance_output}")
            else:
                print("✗ Not identified as security fix")
    else:
        # Analyze multiple commits
        print(f"\nSearching for commits in {args.kernel_path}")
        commits = analyzer.get_security_commits(args.limit)

        if not commits:
            print("No commits found")
            return

        print(f"Found {len(commits)} potential fix commits")
        print("Analyzing with LLM to identify security fixes...\n")

        security_fixes = []
        guidances = []

        for i, commit in enumerate(commits, 1):
            print(f"[{i}/{len(commits)}] {commit['hash'][:8]}: {commit['subject'][:60]}...")

            commit_diff = analyzer.get_commit_diff(commit['hash'])
            if not commit_diff:
                print("  ✗ Could not get diff")
                continue

            analysis = analyzer.analyze_commit_with_llm(commit_diff)

            if analysis and analysis.get("is_security_fix", False):
                print(f"  ✓ Security fix: {analysis['anti_pattern_type']} (severity: {analysis.get('severity', 'unknown')})")

                analysis['commit_hash'] = commit['hash']
                analysis['commit_subject'] = commit['subject']
                security_fixes.append(analysis)

                # Generate guidance for Module 2
                guidance = analyzer.generate_checker_guidance(analysis, commit['hash'])
                guidance['commit_subject'] = commit['subject']
                guidances.append(guidance)
            else:
                print("  ✗ Not a security fix")

            # Stop after finding 5 security fixes
            if len(security_fixes) >= 5:
                print("\nFound 5 security fixes, stopping analysis")
                break

        # Save results
        if security_fixes:
            Path(args.output).parent.mkdir(parents=True, exist_ok=True)

            with open(args.output, 'w') as f:
                json.dump(security_fixes, f, indent=2)

            with open(args.guidance_output, 'w') as f:
                json.dump(guidances, f, indent=2)

            print(f"\n=== Summary ===")
            print(f"✓ Found {len(security_fixes)} security fixes out of {i} commits analyzed")
            print(f"✓ Saved anti-patterns to {args.output}")
            print(f"✓ Saved checker guidance to {args.guidance_output}")

            # Print anti-pattern distribution
            pattern_types = {}
            for fix in security_fixes:
                ptype = fix.get('anti_pattern_type', 'unknown')
                pattern_types[ptype] = pattern_types.get(ptype, 0) + 1

            print("\nAnti-pattern Distribution:")
            for ptype, count in sorted(pattern_types.items(), key=lambda x: x[1], reverse=True):
                print(f"  {ptype}: {count}")
        else:
            print("\n✗ No security fixes found in analyzed commits")

if __name__ == "__main__":
    main()