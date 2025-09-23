#!/usr/bin/env python3
"""
Automated checker generator using Model API
Generates Clang Static Analyzer checker code based on vulnerability analysis
"""

import json
import requests
import os
import sys
from pathlib import Path
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

class CheckerGenerator:
    def __init__(self):
        self.analysis_file = "data/model_analysis.json"
        self.analysis_text = ""
        self.checker_name = "VulnerabilityChecker"  # Default name, will be determined from analysis
        
    def load_analysis(self):
        """Load the Model analysis from previous step"""
        if os.path.exists(self.analysis_file):
            with open(self.analysis_file, 'r') as f:
                data = json.load(f)
                self.analysis_text = data.get('analysis', '')
                # Determine checker name from vulnerability type
                vuln_type = data.get('vulnerability_type', 'unknown')
                self.checker_name = self._determine_checker_name(vuln_type, self.analysis_text)
                print(f"Analysis loaded from model_analysis.json")
                print(f"Detected vulnerability type: {vuln_type}")
                print(f"Generated checker name: {self.checker_name}")
        else:
            print("Error: model_analysis.json not found. Run model_analyzer.py first.")
            return False
        return True
    
    def _determine_checker_name(self, vuln_type, analysis_text):
        """Determine appropriate checker name based on vulnerability type and analysis"""
        vuln_type_lower = vuln_type.lower()
        analysis_lower = analysis_text.lower()
        
        # Map vulnerability types to checker names
        if 'use-after-free' in vuln_type_lower or 'use after free' in analysis_lower:
            return "UseAfterFreeChecker"
        elif 'buffer overflow' in vuln_type_lower or 'buffer overflow' in analysis_lower:
            return "BufferOverflowChecker"
        elif 'null pointer' in vuln_type_lower or 'null pointer dereference' in analysis_lower:
            return "NullPointerChecker"
        elif 'memory leak' in vuln_type_lower or 'memory leak' in analysis_lower:
            return "MemoryLeakChecker"
        elif 'double free' in vuln_type_lower or 'double free' in analysis_lower:
            return "DoubleFreeChecker"
        elif 'race condition' in vuln_type_lower or 'race condition' in analysis_lower:
            return "RaceConditionChecker"
        elif 'integer overflow' in vuln_type_lower or 'integer overflow' in analysis_lower:
            return "IntegerOverflowChecker"
        else:
            # Generic name based on vulnerability type or default
            if vuln_type and vuln_type != 'unknown':
                # Convert to PascalCase and add Checker suffix
                name = ''.join(word.capitalize() for word in vuln_type.replace('-', ' ').replace('_', ' ').split())
                return f"{name}Checker"
            return "VulnerabilityChecker"
    
    def generate_cpp_checker(self):
        """Generate C++ Clang Static Analyzer checker using Model API"""
        
        prompt = f"""You are an expert C++ developer and static analysis expert. Based on the following vulnerability analysis, generate a complete, working Clang Static Analyzer checker in C++.

VULNERABILITY ANALYSIS:
{self.analysis_text}

REQUIREMENTS:
1. Analyze the vulnerability pattern described in the analysis above
2. Generate a complete checker .cpp file with appropriate name based on the vulnerability type
3. Include all necessary headers and includes for Clang Static Analyzer
4. Implement appropriate Clang Static Analyzer checker patterns based on the vulnerability:
   - Use REGISTER_SET_WITH_PROGRAMSTATE if state tracking is needed
   - Implement checkPostCall for function call monitoring if relevant
   - Implement checkPreStmt/checkPostStmt methods for statement analysis if needed
   - Use checkBind for variable assignments if relevant
   - Add other check methods as appropriate for the specific vulnerability pattern
5. Include proper error reporting with PathSensitiveBugReport
6. Add registration functions at the bottom
7. Follow LLVM coding standards
8. Design the checker to detect the specific vulnerability pattern described in the analysis
9. Make the checker name and implementation match the vulnerability type (e.g., UseAfterFreeChecker, BufferOverflowChecker, etc.)
10. Ensure the checker is focused on the exact anti-pattern identified in the analysis

Generate ONLY the complete C++ code for the checker file. Do not include explanations or markdown - just the raw C++ code that can be saved directly to a file. The checker should be specifically tailored to detect the vulnerability pattern described in the analysis above."""

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
            print("Generating C++ checker with Model...")
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
                
                with open(f'generated/{self.checker_name}.cpp', 'w') as f:
                    f.write(cpp_code)
                
                print(f"{self.checker_name}.cpp generated successfully")
                return cpp_code
            else:
                print("Error: No code generated from Model API")
                return None
                
        except requests.exceptions.RequestException as e:
            print(f"Error calling Model API: {e}")
            return None
        except json.JSONDecodeError as e:
            print(f"Error parsing Model response: {e}")
            return None
    
    def generate_header_file(self):
        """Generate header file using Model API"""
        
        prompt = f"""Generate a complete header file {self.checker_name}.h for the Clang Static Analyzer checker.

Requirements:
1. Include proper header guards using the checker name
2. Include necessary forward declarations
3. Declare the registration functions for this specific checker
4. Follow LLVM coding standards
5. Make the header appropriate for the checker name: {self.checker_name}

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
        
        url = f"{MODEL_ENDPOINT}?key={MODEL_API_KEY}"
        
        try:
            print("Generating header file with Model...")
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
                
                with open(f'generated/{self.checker_name}.h', 'w') as f:
                    f.write(header_code)
                
                print(f"{self.checker_name}.h generated successfully")
                return header_code
            else:
                print("Error: No header code generated from Model API")
                return None
                
        except requests.exceptions.RequestException as e:
            print(f"Error calling Model API: {e}")
            return None
    
    def generate_cmake_file(self):
        """Generate CMake build file using Model API"""
        
        prompt = f"""Generate a complete CMakeLists.txt file for building a Clang Static Analyzer checker plugin.

Requirements:
1. Find LLVM and Clang packages
2. Set C++17 standard
3. Create shared library for the checker: {self.checker_name}
4. Link against necessary Clang/LLVM libraries
5. Set proper compiler flags
6. Include installation target
7. Use the checker name {self.checker_name} for the library target

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
        
        url = f"{MODEL_ENDPOINT}?key={MODEL_API_KEY}"
        
        try:
            print("Generating CMakeLists.txt with Model...")
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
                print("Error: No CMake code generated from Model API")
                return None
                
        except requests.exceptions.RequestException as e:
            print(f"Error calling Model API: {e}")
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
            'generation_method': 'automated_model',
            'api_model': MODEL_NAME if 'MODEL_NAME' in globals() else 'gemini-2.0-flash-lite',
            'checker_name': self.checker_name,
            'files_generated': [
                f'{self.checker_name}.cpp',
                f'{self.checker_name}.h', 
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
        print(f"- {self.checker_name}.cpp")
        print(f"- {self.checker_name}.h")
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