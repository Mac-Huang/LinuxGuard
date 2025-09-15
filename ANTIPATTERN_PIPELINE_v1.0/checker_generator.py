#!/usr/bin/env python3
"""
Automated checker generator using Gemini API
Generates Clang Static Analyzer checker code based on vulnerability analysis
NOTE: API key will be removed before publication
"""

import json
import requests
import os
from data.commit_data import *

GEMINI_API_KEY = "AIzaSyDhZ9-yVw8SZzDgVgzaaGYI-d-16iVL9Ys"
GEMINI_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent"

class CheckerGenerator:
    def __init__(self):
        self.analysis_file = "data/gemini_analysis.json"
        self.analysis_text = ""
        
    def load_analysis(self):
        """Load the Gemini analysis from previous step"""
        if os.path.exists(self.analysis_file):
            with open(self.analysis_file, 'r') as f:
                data = json.load(f)
                self.analysis_text = data.get('analysis', '')
                print("Analysis loaded from gemini_analysis.json")
        else:
            print("Error: gemini_analysis.json not found. Run gemini_analyzer.py first.")
            return False
        return True
    
    def generate_cpp_checker(self):
        """Generate C++ Clang Static Analyzer checker using Gemini"""
        
        prompt = f"""You are an expert C++ developer and static analysis expert. Based on the following vulnerability analysis, generate a complete, working Clang Static Analyzer checker in C++.

VULNERABILITY ANALYSIS:
{self.analysis_text}

REQUIREMENTS:
1. Generate a complete UseAfterFreeChecker.cpp file
2. Include all necessary headers and includes
3. Implement proper Clang Static Analyzer patterns
4. Use REGISTER_SET_WITH_PROGRAMSTATE for tracking freed pointers
5. Implement checkPostCall for tracking conditional frees
6. Implement checkPreStmt methods for detecting pointer usage
7. Include proper error reporting with PathSensitiveBugReport
8. Add registration functions at the bottom
9. Follow LLVM coding standards
10. Make it detect the specific pattern: conditional free followed by pointer access

The checker should detect this pattern:
```c
ret = some_function(ptr);
if (ret) {{
    free(ptr);
}}
ptr->member = value;  // Use-after-free!
```

Generate ONLY the complete C++ code for UseAfterFreeChecker.cpp. Do not include explanations or markdown - just the raw C++ code that can be saved directly to a file."""

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
            print("Generating C++ checker with Gemini...")
            response = requests.post(url, headers=headers, json=data, timeout=60)
            response.raise_for_status()
            
            result = response.json()
            
            if 'candidates' in result and len(result['candidates']) > 0:
                cpp_code = result['candidates'][0]['content']['parts'][0]['text']
                
                # Clean up the code (remove markdown if present)
                if '```cpp' in cpp_code:
                    cpp_code = cpp_code.split('```cpp')[1].split('```')[0].strip()
                elif '```' in cpp_code:
                    cpp_code = cpp_code.split('```')[1].split('```')[0].strip()
                
                with open('generated/UseAfterFreeChecker.cpp', 'w') as f:
                    f.write(cpp_code)
                
                print("UseAfterFreeChecker.cpp generated successfully")
                return cpp_code
            else:
                print("Error: No code generated from Gemini API")
                return None
                
        except requests.exceptions.RequestException as e:
            print(f"Error calling Gemini API: {e}")
            return None
        except json.JSONDecodeError as e:
            print(f"Error parsing Gemini response: {e}")
            return None
    
    def generate_header_file(self):
        """Generate header file using Gemini"""
        
        prompt = """Generate a complete header file UseAfterFreeChecker.h for the Clang Static Analyzer checker.

Requirements:
1. Include proper header guards
2. Include necessary forward declarations
3. Declare the registration functions
4. Follow LLVM coding standards

Generate ONLY the complete header file code. Do not include explanations or markdown."""

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
                "maxOutputTokens": 2048
            }
        }
        
        url = f"{GEMINI_ENDPOINT}?key={GEMINI_API_KEY}"
        
        try:
            print("Generating header file with Gemini...")
            response = requests.post(url, headers=headers, json=data, timeout=60)
            response.raise_for_status()
            
            result = response.json()
            
            if 'candidates' in result and len(result['candidates']) > 0:
                header_code = result['candidates'][0]['content']['parts'][0]['text']
                
                # Clean up the code
                if '```cpp' in header_code:
                    header_code = header_code.split('```cpp')[1].split('```')[0].strip()
                elif '```' in header_code:
                    header_code = header_code.split('```')[1].split('```')[0].strip()
                
                with open('generated/UseAfterFreeChecker.h', 'w') as f:
                    f.write(header_code)
                
                print("UseAfterFreeChecker.h generated successfully")
                return header_code
            else:
                print("Error: No header code generated from Gemini API")
                return None
                
        except requests.exceptions.RequestException as e:
            print(f"Error calling Gemini API: {e}")
            return None
    
    def generate_cmake_file(self):
        """Generate CMake build file using Gemini"""
        
        prompt = """Generate a complete CMakeLists.txt file for building a Clang Static Analyzer checker plugin.

Requirements:
1. Find LLVM and Clang packages
2. Set C++17 standard
3. Create shared library UseAfterFreeChecker
4. Link against necessary Clang/LLVM libraries
5. Set proper compiler flags
6. Include installation target

Generate ONLY the complete CMakeLists.txt content. Do not include explanations or markdown."""

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
                "maxOutputTokens": 2048
            }
        }
        
        url = f"{GEMINI_ENDPOINT}?key={GEMINI_API_KEY}"
        
        try:
            print("Generating CMakeLists.txt with Gemini...")
            response = requests.post(url, headers=headers, json=data, timeout=60)
            response.raise_for_status()
            
            result = response.json()
            
            if 'candidates' in result and len(result['candidates']) > 0:
                cmake_code = result['candidates'][0]['content']['parts'][0]['text']
                
                # Clean up the code
                if '```cmake' in cmake_code:
                    cmake_code = cmake_code.split('```cmake')[1].split('```')[0].strip()
                elif '```' in cmake_code:
                    cmake_code = cmake_code.split('```')[1].split('```')[0].strip()
                
                with open('generated/CMakeLists.txt', 'w') as f:
                    f.write(cmake_code)
                
                print("CMakeLists.txt generated successfully")
                return cmake_code
            else:
                print("Error: No CMake code generated from Gemini API")
                return None
                
        except requests.exceptions.RequestException as e:
            print(f"Error calling Gemini API: {e}")
            return None
    
    def generate_all_files(self):
        """Generate all checker files automatically"""
        print("=== Automated Checker Generation ===")
        
        if not self.load_analysis():
            return False
        
        # Generate C++ checker
        cpp_code = self.generate_cpp_checker()
        if not cpp_code:
            print("Failed to generate C++ checker")
            return False
        
        # Generate header file
        header_code = self.generate_header_file()
        if not header_code:
            print("Failed to generate header file")
            return False
        
        # Generate CMake file
        cmake_code = self.generate_cmake_file()
        if not cmake_code:
            print("Failed to generate CMake file")
            return False
        
        # Save generation report
        report = {
            'generation_method': 'automated_gemini',
            'api_model': 'gemini-1.5-pro-latest',
            'files_generated': [
                'UseAfterFreeChecker.cpp',
                'UseAfterFreeChecker.h', 
                'CMakeLists.txt'
            ],
            'source_analysis': self.analysis_file,
            'vulnerability_pattern': VULNERABILITY_TYPE,
            'target_commit': COMMIT_HASH
        }
        
        with open('generated/checker_generation_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        print("\n=== Generation Complete ===")
        print("Generated files:")
        print("- UseAfterFreeChecker.cpp")
        print("- UseAfterFreeChecker.h")
        print("- CMakeLists.txt")
        print("- checker_generation_report.json")
        
        return True

def main():
    """Main function to generate checker files"""
    generator = CheckerGenerator()
    
    if generator.generate_all_files():
        print("\nSuccess! All checker files generated automatically.")
        print("Next step: Build and test the checker")
    else:
        print("\nError: Failed to generate checker files")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())