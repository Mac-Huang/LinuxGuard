#!/usr/bin/env python3
"""
Gemini API analyzer for commit vulnerability patterns
NOTE: API key will be removed before publication
"""

import json
import requests
from data.commit_data import *

GEMINI_API_KEY = "AIzaSyDhZ9-yVw8SZzDgVgzaaGYI-d-16iVL9Ys"
GEMINI_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent"

def analyze_commit_with_gemini():
    """Send commit to Gemini for analysis and checker generation"""
    
    prompt = f"""You are a security expert analyzing a Linux kernel commit that fixes a use-after-free vulnerability. 

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
   - What exactly was the use-after-free vulnerability?
   - What specific code pattern caused this issue?
   - How does the fix prevent the vulnerability?

2. GENERALIZED DETECTION PATTERN:
   - What general code pattern should a static analyzer look for to detect similar vulnerabilities?
   - What are the key elements that make this pattern dangerous?
   - What control flow or data flow characteristics indicate this anti-pattern?

3. CHECKER SPECIFICATION:
   - Provide detailed specifications for a static analysis checker that can detect this pattern
   - Include the specific AST nodes, control flow patterns, and data dependencies to check
   - Provide concrete rules for flagging potential vulnerabilities

4. IMPLEMENTATION GUIDANCE:
   - How would you implement this checker using Clang Static Analyzer or similar tools?
   - What specific checks should be performed at each program point?
   - What heuristics would reduce false positives?

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
    
    url = f"{GEMINI_ENDPOINT}?key={GEMINI_API_KEY}"
    
    try:
        print("Sending commit analysis request to Gemini API...")
        response = requests.post(url, headers=headers, json=data, timeout=60)
        response.raise_for_status()
        
        result = response.json()
        
        if 'candidates' in result and len(result['candidates']) > 0:
            analysis = result['candidates'][0]['content']['parts'][0]['text']
            
            # Save the analysis
            with open('data/gemini_analysis.json', 'w') as f:
                json.dump({
                    'commit_hash': COMMIT_HASH,
                    'vulnerability_type': VULNERABILITY_TYPE,
                    'analysis': analysis,
                    'raw_response': result
                }, f, indent=2)
            
            with open('data/gemini_analysis.md', 'w') as f:
                f.write(f"# Gemini Analysis of Commit {COMMIT_HASH}\n\n")
                f.write(f"**Vulnerability Type:** {VULNERABILITY_TYPE}\n\n")
                f.write(f"**File:** {FILE_PATH}\n\n")
                f.write(f"**Function:** {FUNCTION_NAME}\n\n")
                f.write("## Analysis Results\n\n")
                f.write(analysis)
            
            print("Analysis completed and saved to gemini_analysis.json and gemini_analysis.md")
            return analysis
        else:
            print("Error: No analysis returned from Gemini API")
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"Error calling Gemini API: {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"Error parsing Gemini response: {e}")
        return None

if __name__ == "__main__":
    analysis = analyze_commit_with_gemini()
    if analysis:
        print("\n" + "="*50)
        print("GEMINI ANALYSIS PREVIEW:")
        print("="*50)
        print(analysis[:1000] + "..." if len(analysis) > 1000 else analysis)