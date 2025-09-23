#!/usr/bin/env python3
"""
Configuration file for ANTIPATTERN_PIPELINE v2.0
"""

import os
from pathlib import Path

# Load API key from .env file if it exists
env_file = Path(".env")
if env_file.exists():
    with open(env_file, 'r') as f:
        for line in f:
            if '=' in line:
                key, value = line.strip().split('=', 1)
                os.environ[key] = value

# Model Configuration (supports any LLM)
MODEL_API_KEY = os.getenv("API_KEY") or os.getenv("MODEL_API_KEY", "YOUR_API_KEY_HERE")
MODEL_NAME = os.getenv("MODEL_NAME", "gemini-2.0-flash-lite")
MODEL_ENDPOINT = os.getenv("MODEL_ENDPOINT", f"https://generativelanguage.googleapis.com/v1beta/models/{MODEL_NAME}:generateContent")

# LLVM Configuration
LLVM_PATH = Path(os.getenv("LLVM_PATH", "D:/LLVM/bin"))
LLVM_INCLUDE_PATH = LLVM_PATH.parent / "include"
LLVM_LIB_PATH = LLVM_PATH.parent / "lib"

# Linux Kernel Configuration
KERNEL_PATH = Path(os.getenv("KERNEL_PATH", "../../../linux"))

# Generation Settings
TEMPERATURE = 0.3  # Lower for code generation
TOP_K = 40
TOP_P = 0.95
MAX_OUTPUT_TOKENS = 8192

# v2.0 Specific Settings
USE_LLVM_EXAMPLES = True  # Use LLVM examples as reference
OPTIMIZE_PROMPTS = True   # Use optimized prompts based on LLVM patterns
GENERATE_TESTS = True     # Generate test cases for checker

print(f"[v2.0 Config Loaded]")
print(f"  Model: {MODEL_NAME}")
print(f"  LLVM Path: {LLVM_PATH}")
print(f"  Using LLVM Examples: {USE_LLVM_EXAMPLES}")