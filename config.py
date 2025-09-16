#!/usr/bin/env python3
"""
Global configuration for LinuxGuard AntiPattern Pipeline
This file should NOT be committed to public repositories
Add this file to .gitignore to keep API keys private
"""

import os
from pathlib import Path

# API Configuration
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "YOUR_API_KEY_HERE")

# If API key not in environment, try to load from local file
CONFIG_DIR = Path(__file__).parent
SECRETS_FILE = CONFIG_DIR / ".secrets"

if GEMINI_API_KEY == "YOUR_API_KEY_HERE" and SECRETS_FILE.exists():
    try:
        with open(SECRETS_FILE, 'r') as f:
            for line in f:
                if line.startswith("GEMINI_API_KEY="):
                    GEMINI_API_KEY = line.split("=", 1)[1].strip()
                    break
    except Exception:
        pass

# Project Paths
PROJECT_ROOT = Path(__file__).parent.parent
LINUX_KERNEL_PATH = PROJECT_ROOT / "linux"
LLVM_SYSTEM_PATH = Path("D:/LLVM/bin")

# Pipeline Configuration
DEFAULT_KERNEL_VERSIONS = ["linux-6.6", "linux-6.7", "linux-6.8"]
MAX_FILES_PER_SCAN = 10
SCAN_TIMEOUT = 300  # seconds

# Checker Configuration
CHECKER_COMPILE_TIMEOUT = 120  # seconds
USE_SYSTEM_LLVM_FALLBACK = True

# Output Configuration
RESULTS_DIR = "results"
REPORT_FORMAT = "markdown"  # or "json"

def get_api_key():
    """Get the Gemini API key from configuration"""
    if GEMINI_API_KEY == "YOUR_API_KEY_HERE":
        raise ValueError(
            "API key not configured. Please set GEMINI_API_KEY environment variable "
            "or create a .secrets file with GEMINI_API_KEY=your_key_here"
        )
    return GEMINI_API_KEY

def is_configured():
    """Check if the configuration is properly set up"""
    return GEMINI_API_KEY != "YOUR_API_KEY_HERE"