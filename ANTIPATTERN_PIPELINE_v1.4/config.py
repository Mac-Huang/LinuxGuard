#!/usr/bin/env python3
"""
Configuration file for ANTIPATTERN_PIPELINE v1.4
"""

import os
from pathlib import Path

# Load from .env if exists
env_file = Path(".env")
if env_file.exists():
    with open(env_file, 'r') as f:
        for line in f:
            if '=' in line and not line.startswith('#'):
                key, value = line.strip().split('=', 1)
                os.environ[key] = value

# Model Configuration
MODEL_API_KEY = os.getenv("API_KEY") or os.getenv("MODEL_API_KEY", "YOUR_API_KEY_HERE")
MODEL_NAME = os.getenv("MODEL_NAME", "gemini-2.0-flash-lite")
MODEL_ENDPOINT = os.getenv("MODEL_ENDPOINT",
    f"https://generativelanguage.googleapis.com/v1beta/models/{MODEL_NAME}:generateContent")

# Linux Kernel Path
KERNEL_PATH = Path(os.getenv("KERNEL_PATH", "../../../linux"))

# Detection Settings
MAX_FILES_PER_DIR = 100
TIMEOUT_SECONDS = 30

print(f"[Config] Model: {MODEL_NAME}")
print(f"[Config] Kernel Path: {KERNEL_PATH}")
