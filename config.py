#!/usr/bin/env python3
"""
Global configuration for LinuxGuard AntiPattern Pipeline
This file should NOT be committed to public repositories
Add this file to .gitignore to keep API keys private
"""

import os
from pathlib import Path

# Try to load from .env file first
try:
    from dotenv import load_dotenv
    ENV_FILE = Path(__file__).parent / ".env"
    if ENV_FILE.exists():
        load_dotenv(ENV_FILE)
except ImportError:
    pass

# API Configuration
# Priority: 1. API_KEY from .env, 2. MODEL_API_KEY from env, 3. .secrets file
MODEL_API_KEY = os.getenv("API_KEY") or os.getenv("MODEL_API_KEY", "YOUR_API_KEY_HERE")

# Gemini 2.0 Flash Model Configuration
MODEL_NAME = os.getenv("MODEL_NAME", "gemini-2.0-flash-lite")
MODEL_ENDPOINT = f"https://generativelanguage.googleapis.com/v1beta/models/{MODEL_NAME}:generateContent"

# If API key not in environment, try to load from local file
CONFIG_DIR = Path(__file__).parent
SECRETS_FILE = CONFIG_DIR / ".secrets"

if MODEL_API_KEY == "YOUR_API_KEY_HERE" and SECRETS_FILE.exists():
    try:
        with open(SECRETS_FILE, 'r') as f:
            for line in f:
                if line.startswith("MODEL_API_KEY=") or line.startswith("API_KEY="):
                    MODEL_API_KEY = line.split("=", 1)[1].strip()
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
    """Get the Model API key from configuration"""
    if MODEL_API_KEY == "YOUR_API_KEY_HERE":
        raise ValueError(
            "API key not configured. Please set MODEL_API_KEY environment variable "
            "or create a .secrets file with MODEL_API_KEY=your_key_here"
        )
    return MODEL_API_KEY

def is_configured():
    """Check if the configuration is properly set up"""
    return MODEL_API_KEY != "YOUR_API_KEY_HERE"