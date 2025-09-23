#!/usr/bin/env python3
"""
Model API analyzer for commit vulnerability patterns
"""

import json
import sys
import os
import requests
from data.commit_data import *

# Add parent directory to path for config import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from config import get_api_key, MODEL_NAME, MODEL_ENDPOINT
    MODEL_API_KEY = get_api_key()
except ImportError:
    # Fallback to environment variable
    MODEL_API_KEY = os.getenv("API_KEY")
    MODEL_NAME = os.getenv("MODEL_NAME", "gemini-2.0-flash-lite")
    MODEL_ENDPOINT = f"https://generativelanguage.googleapis.com/v1beta/models/{MODEL_NAME}:generateContent"

if not MODEL_API_KEY:
    raise ValueError("Please set API_KEY in .env file or environment variable")

def analyze_commit_with_model():
    """Send commit to Model for analysis and checker generation"""

    # First, analyze the commit to determine the vulnerability type
    initial_prompt = f"""You are a security expert analyzing a Linux kernel commit that fixes a security vulnerability.

COMMIT INFORMATION:
Hash: {COMMIT_HASH}
Author: {COMMIT_AUTHOR}
Date: {COMMIT_DATE}
File: {FILE_PATH}
Function: {FUNCTION_NAME}

COMMIT MESSAGE:
{COMMIT_MESSAGE}

CODE DIFF:
{COMMIT_DIFF}

First, identify what type of vulnerability this commit fixes. Common types include:
- use-after-free
- buffer-overflow
- null-pointer-dereference
- memory-leak
- double-free
- race-condition
- integer-overflow
- out-of-bounds

Please provide:
1. The specific vulnerability type being fixed
2. A brief explanation of how you identified this vulnerability type"""

    # Get the vulnerability type if not provided or analyze it
    vuln_type_from_data = VULNERABILITY_TYPE if 'VULNERABILITY_TYPE' in globals() else None

    # Create the main analysis prompt
    vuln_description = f"a {vuln_type_from_data.replace('-', ' ')}" if vuln_type_from_data else "a security"

    prompt = f"""You are a security expert analyzing a Linux kernel commit that fixes {vuln_description} vulnerability.

COMMIT INFORMATION:
Hash: {COMMIT_HASH}
Author: {COMMIT_AUTHOR}
Date: {COMMIT_DATE}
File: {FILE_PATH}
Function: {FUNCTION_NAME}

COMMIT MESSAGE:
{COMMIT_MESSAGE}

CODE DIFF:
{COMMIT_DIFF}

Please analyze this commit and provide:

1. VULNERABILITY PATTERN ANALYSIS:
   - What exactly was the vulnerability?
   - What specific code pattern caused this issue?
   - How does the fix prevent the vulnerability?
   - What is the root cause of this vulnerability type?

2. GENERALIZED DETECTION PATTERN:
   - What general code pattern should a static analyzer look for to detect similar vulnerabilities?
   - What are the key elements that make this pattern dangerous?
   - What control flow or data flow characteristics indicate this anti-pattern?
   - What are common variations of this vulnerability pattern?

3. CHECKER SPECIFICATION:
   - Provide detailed specifications for a static analysis checker that can detect this pattern
   - Include the specific AST nodes, control flow patterns, and data dependencies to check
   - Provide concrete rules for flagging potential vulnerabilities
   - Define both must-have checks and nice-to-have heuristics

4. IMPLEMENTATION GUIDANCE:
   - How would you implement this checker using Clang Static Analyzer or similar tools?
   - What specific checks should be performed at each program point?
   - What heuristics would reduce false positives?
   - How can we balance detection accuracy with performance?

Please provide a comprehensive analysis that could be used to build an automated checker for this vulnerability pattern."""

    headers = {
        "Content-Type": "application/json"
    }

    data = {
        "contents": [{
            "parts": [{
                "text": prompt
            }]
        }],
        "generationConfig": {
            "temperature": 0.1,
            "topK": 40,
            "topP": 0.95,
            "maxOutputTokens": 8192
        }
    }

    url = f"{MODEL_ENDPOINT}?key={MODEL_API_KEY}"

    try:
        print("Sending commit analysis request to Model API...")
        response = requests.post(url, headers=headers, json=data, timeout=60)
        response.raise_for_status()

        result = response.json()

        if 'candidates' in result and len(result['candidates']) > 0:
            analysis = result['candidates'][0]['content']['parts'][0]['text']

            # Determine the vulnerability type from the analysis if not provided
            detected_vuln_type = vuln_type_from_data
            if not detected_vuln_type:
                # Try to extract vulnerability type from the analysis
                vuln_keywords = {
                    'use-after-free': ['use-after-free', 'use after free', 'UAF'],
                    'buffer-overflow': ['buffer overflow', 'buffer overrun', 'out of bounds'],
                    'null-pointer-dereference': ['null pointer', 'NULL dereference'],
                    'memory-leak': ['memory leak', 'resource leak'],
                    'double-free': ['double free', 'double-free'],
                    'race-condition': ['race condition', 'TOCTOU'],
                    'integer-overflow': ['integer overflow', 'integer underflow']
                }

                analysis_lower = analysis.lower()
                for vuln_type, keywords in vuln_keywords.items():
                    if any(keyword.lower() in analysis_lower for keyword in keywords):
                        detected_vuln_type = vuln_type
                        break

                if not detected_vuln_type:
                    detected_vuln_type = 'unknown'

            # Save the analysis
            with open('data/model_analysis.json', 'w') as f:
                json.dump({
                    'commit_hash': COMMIT_HASH,
                    'vulnerability_type': detected_vuln_type,
                    'analysis': analysis,
                    'raw_response': result
                }, f, indent=2)

            with open('data/model_analysis.md', 'w') as f:
                f.write(f"# Model Analysis of Commit {COMMIT_HASH}\n\n")
                f.write(f"**Vulnerability Type:** {detected_vuln_type}\n\n")
                f.write(f"**File:** {FILE_PATH}\n\n")
                f.write(f"**Function:** {FUNCTION_NAME}\n\n")
                f.write("## Analysis Results\n\n")
                f.write(analysis)

            print(f"Analysis completed and saved to model_analysis.json and model_analysis.md")
            print(f"Detected vulnerability type: {detected_vuln_type}")
            return analysis
        else:
            print("Error: No analysis returned from Model API")
            return None

    except requests.exceptions.RequestException as e:
        print(f"Error calling Model API: {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"Error parsing Model response: {e}")
        return None

if __name__ == "__main__":
    analysis = analyze_commit_with_model()
    if analysis:
        print("\n" + "="*50)
        print("MODEL ANALYSIS PREVIEW:")
        print("="*50)
        print(analysis[:1000] + "..." if len(analysis) > 1000 else analysis)