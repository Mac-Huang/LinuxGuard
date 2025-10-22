#!/usr/bin/env python3
"""
Module 1 Rich: Pattern Extraction with Full Commit Context
Uses complete commit information for better LLM analysis.
"""

import json
import os
import subprocess
import argparse
import logging
import time
from pathlib import Path
from typing import Dict, Optional, Any
from dotenv import load_dotenv
import google.generativeai as genai
from google.api_core import exceptions as google_exceptions
from prompt_library import build_pattern_extraction_prompt

# --- Constants ---
PROJECT_ROOT = Path(__file__).parent.parent 
DEFAULT_COMMITS_DIR = PROJECT_ROOT / "commits"
DEFAULT_RESULTS_DIR = PROJECT_ROOT / "results"
# --- THIS IS THE FIX ---
# Correct the script name to match your actual file: 'fetch_commit.py'
FETCH_SCRIPT_PATH = PROJECT_ROOT / "scripts/fetch_commit.py" 

MAX_PATCH_LENGTH = 40000
MAX_FILES_TO_LIST = 10
API_RETRY_ATTEMPTS = 3
API_RETRY_DELAY = 5

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Load environment variables from a .env file
load_dotenv(PROJECT_ROOT / ".env")

# ... (The rest of the script remains exactly the same as the one I provided before) ...
# (No changes needed in RichCommitAnalyzer class or the rest of the main function)
class RichCommitAnalyzer:
    """Analyzes commits with full context for security anti-patterns."""

    def __init__(self):
        """Initializes the analyzer and the Gemini model."""
        self.model = self._initialize_model()

    def _initialize_model(self) -> genai.GenerativeModel:
        """Configures and returns the Gemini generative model."""
        api_key = os.getenv('GEMINI_API_KEY')
        if not api_key:
            logging.error("GEMINI_API_KEY not found in environment or .env file.")
            raise ValueError("GEMINI_API_KEY not set.")

        genai.configure(api_key=api_key)
        model_name = os.getenv('GEMINI_MODEL', 'gemini-1.5-flash')
        logging.info(f"Initializing Gemini model: {model_name}")
        return genai.GenerativeModel(model_name)

    def analyze_commit(self, commit_data: Dict[str, Any], patch_content: str) -> Optional[Dict[str, Any]]:
        """
        Orchestrates the analysis of a single commit.
        Builds context, analyzes with LLM, and logs the outcome.
        """
        context = self._build_commit_context(commit_data, patch_content)
        
        commit_hash = commit_data.get('commit_hash', 'unknown')
        subject = commit_data.get('summary', {}).get('subject', 'No Subject')
        logging.info(f"Analyzing commit {commit_hash[:12]}: {subject[:60]}...")
        
        return self._analyze_with_llm(context)

    def _build_commit_context(self, commit_data: Dict[str, Any], patch_content: str) -> str:
        """Builds the comprehensive context string for LLM analysis."""
        summary = commit_data.get('summary', {})
        commit_info = commit_data.get('commit_info', {})

        if len(patch_content) > MAX_PATCH_LENGTH:
            patch_content = patch_content[:MAX_PATCH_LENGTH] + "\n... [truncated for analysis]"

        context_parts = [
            "=== COMMIT INFORMATION ===",
            f"Commit: {commit_data.get('commit_hash', 'N/A')[:12]}",
            f"Author: {summary.get('author', 'N/A')}",
            f"Date: {summary.get('date', 'N/A')}",
            f"Subject: {summary.get('subject', 'N/A')}",
            "\n=== COMMIT MESSAGE ===",
            commit_info.get('message_body', 'No message body'),
            "\n=== METADATA ===",
            f"Files Changed: {summary.get('files_changed', 0)}",
            f"Lines Added: {summary.get('additions', 0)}",
            f"Lines Removed: {summary.get('deletions', 0)}",
        ]

        if summary.get('has_fixes_tag') and commit_info.get('fixes'):
            context_parts.append(f"Fixes: {', '.join(commit_info['fixes'])}")
        if summary.get('reporters'):
            context_parts.append(f"Reported-by: {', '.join(summary['reporters'])}")
        if commit_info.get('reviewed_by'):
            context_parts.append(f"Reviewed-by: {', '.join(commit_info['reviewed_by'][:2])}")
        
        files_changed = commit_info.get('diff_analysis', {}).get('files_changed', [])
        if files_changed:
            context_parts.append("\n=== FILES MODIFIED ===")
            for f in files_changed[:MAX_FILES_TO_LIST]:
                line = f"- {f['from']}"
                if f['from'] != f['to']:
                    line += f" -> {f['to']}"
                context_parts.append(line)
        
        context_parts.append(f"\n=== COMMIT PATCH ===\n{patch_content}")
        return "\n".join(context_parts)

    def _analyze_with_llm(self, context: str) -> Optional[Dict[str, Any]]:
        """
        Sends the context to the LLM for analysis with retry logic.
        Parses and validates the JSON response.
        """
        prompt = build_pattern_extraction_prompt(context)
        
        for attempt in range(API_RETRY_ATTEMPTS):
            try:
                response = self.model.generate_content(prompt)
                response_text = response.text.strip()

                if response_text.startswith('```json'):
                    response_text = response_text[7:-3].strip()
                elif response_text.startswith('```'):
                     response_text = response_text[3:-3].strip()

                result = json.loads(response_text)

                if result.get('is_security_fix'):
                    logging.info(
                        f"✓ Security fix detected (confidence: {result.get('confidence', 'N/A')}, "
                        f"type: {result.get('anti_pattern_type', 'N/A')}, "
                        f"severity: {result.get('severity', 'N/A')})"
                    )
                else:
                    logging.info(f"✗ Not a security fix: {result.get('reason', 'no reason given')}")
                
                return result

            except (google_exceptions.ResourceExhausted, google_exceptions.ServiceUnavailable) as e:
                logging.warning(f"API Error: {e}. Retrying in {API_RETRY_DELAY}s... (Attempt {attempt + 1}/{API_RETRY_ATTEMPTS})")
                time.sleep(API_RETRY_DELAY)
            except json.JSONDecodeError as e:
                logging.error(f"Failed to decode LLM response into JSON: {e}")
                logging.debug(f"LLM Raw Response:\n---\n{response.text[:500]}\n---")
                return None
            except Exception as e:
                logging.error(f"An unexpected error occurred during LLM analysis: {e}")
                return None
        
        logging.error("LLM analysis failed after multiple retries.")
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
                "checker_name": self.suggest_checker_name(analysis.get("anti_pattern_type", "unknown")),
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
        clean_type = anti_pattern_type.replace('-', '_').replace(' ', '_')
        name_map = {
            "unchecked_error": "MustCheckErrors", "null_deref": "NullPointerDereference",
            "null_pointer_dereference": "NullPointerDereference", "use_after_free": "UseAfterFree",
            "race_condition": "RaceCondition", "buffer_overflow": "BufferOverflow",
            "overflow": "BufferOverflow", "double_free": "DoubleFree",
            "uninitialized_var": "UninitializedVariable", "uninitialized_variable": "UninitializedVariable",
            "missing_bounds_check": "MissingBoundsCheck", "integer_overflow": "IntegerOverflow",
            "memory_leak": "MemoryLeak"
        }
        base_name = name_map.get(clean_type, "Security" + clean_type.title().replace('_', ''))
        return f"{base_name}Check"

    def suggest_template_modifications(self, analysis: Dict) -> list:
        """Suggest detailed template modifications."""
        modifications = []
        anti_pattern = analysis.get("anti_pattern_type", "")
        if "unchecked" in anti_pattern or "error" in anti_pattern:
            modifications.append("Focus on function return value checking")
        elif "null" in anti_pattern:
            modifications.append("Track pointer assignments and dereferences")
        if analysis.get("ast_matcher_hints", {}).get("pattern_description"):
            modifications.append(f"Specific pattern: {analysis['ast_matcher_hints']['pattern_description']}")
        return modifications

def main():
    parser = argparse.ArgumentParser(
        description='Extract anti-patterns from a Linux kernel commit using rich context and an LLM.',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('commit_hash', help='Commit hash to analyze (e.g., 80af3745ca46)')
    parser.add_argument('--commit-dir', type=Path, default=DEFAULT_COMMITS_DIR, help='Directory containing cached commit data.')
    parser.add_argument('--results-dir', type=Path, default=DEFAULT_RESULTS_DIR, help='Directory to save analysis and guidance files.')
    args = parser.parse_args()

    logging.info("=== Module 1 Rich: Pattern Extraction with Full Context ===")
    args.commit_dir.mkdir(parents=True, exist_ok=True)
    args.results_dir.mkdir(parents=True, exist_ok=True)
    commit_json = args.commit_dir / f"{args.commit_hash}.json"
    commit_patch = args.commit_dir / f"{args.commit_hash}.patch"
    
    if not commit_json.exists() or not commit_patch.exists():
        logging.info(f"Commit data for {args.commit_hash} not found. Fetching...")
        try:
            cmd = ["python3", str(FETCH_SCRIPT_PATH), args.commit_hash, "--output-dir", str(args.commit_dir)]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            logging.info("Successfully fetched commit data.")
            logging.debug(result.stdout)
        except FileNotFoundError:
            logging.error(f"Fetch script not found at {FETCH_SCRIPT_PATH}")
            return 1
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to fetch commit data for {args.commit_hash}.")
            logging.error(f"Stderr: {e.stderr}")
            return 1

    try:
        with open(commit_json, 'r') as f:
            commit_data = json.load(f)
        with open(commit_patch, 'r') as f:
            patch_content = f.read()
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logging.error(f"Failed to load commit data files: {e}")
        return 1

    analyzer = RichCommitAnalyzer()
    analysis = analyzer.analyze_commit(commit_data, patch_content)

    if analysis and analysis.get("is_security_fix"):
        guidance = analyzer.generate_checker_guidance(analysis, args.commit_hash)
        analysis_output_path = args.results_dir / f"{args.commit_hash}_analysis.json"
        guidance_output_path = args.results_dir / f"{args.commit_hash}_guidance.json"
        with open(analysis_output_path, 'w') as f:
            json.dump(analysis, f, indent=2)
        with open(guidance_output_path, 'w') as f:
            json.dump(guidance, f, indent=2)
        logging.info(f"✓ Analysis saved to {analysis_output_path}")
        logging.info(f"✓ Guidance for Module 2 saved to {guidance_output_path}")
        return 0
    else:
        logging.warning("Commit was not identified as a security fix, or the analysis failed.")
        return 1

if __name__ == "__main__":
    exit(main())
