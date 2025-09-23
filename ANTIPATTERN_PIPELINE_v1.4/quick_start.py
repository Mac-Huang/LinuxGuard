#!/usr/bin/env python3
"""
Quick Start Script for ANTIPATTERN_PIPELINE v1.4
Automated setup and execution helper
"""

import os
import sys
import subprocess
from pathlib import Path

def print_banner():
    """Print welcome banner"""
    print("="*80)
    print("ANTIPATTERN PIPELINE v1.4 - QUICK START")
    print("Multi-Method Vulnerability Detection with Comparative Analysis")
    print("="*80)

def check_basic_requirements():
    """Check basic requirements"""
    print("\n[1/5] Checking basic requirements...")

    # Python version
    if sys.version_info < (3, 7):
        print("  ✗ Python 3.7+ required")
        return False
    print("  ✓ Python version OK")

    # Git
    try:
        subprocess.run(['git', '--version'], capture_output=True, check=True)
        print("  ✓ Git installed")
    except:
        print("  ✗ Git not installed")
        return False

    return True

def setup_directories():
    """Create necessary directories"""
    print("\n[2/5] Setting up directories...")

    dirs = ['data', 'generated', 'results', 'detectors/semantic_patches']
    for dir_path in dirs:
        Path(dir_path).mkdir(parents=True, exist_ok=True)
        print(f"  ✓ Created {dir_path}")

    return True

def install_python_packages():
    """Install required Python packages"""
    print("\n[3/5] Installing Python packages...")

    packages = ['requests', 'python-dotenv']

    try:
        import requests
        import dotenv
        print("  ✓ Required packages already installed")
        return True
    except ImportError:
        print("  Installing packages...")
        result = subprocess.run([sys.executable, '-m', 'pip', 'install'] + packages,
                              capture_output=True, text=True)
        if result.returncode == 0:
            print("  ✓ Packages installed successfully")
            return True
        else:
            print("  ✗ Failed to install packages")
            print("  Run manually: pip install requests python-dotenv")
            return False

def setup_api_key():
    """Help user set up API key"""
    print("\n[4/5] Setting up API configuration...")

    env_file = Path(".env")

    if env_file.exists():
        print("  ✓ .env file exists")

        # Check if API key is set
        with open(env_file, 'r') as f:
            content = f.read()
            if 'API_KEY' in content and 'YOUR_API_KEY_HERE' not in content:
                print("  ✓ API key configured")
                return True

    print("\n  ⚠ API key not configured!")
    print("\n  To set up your API key:")
    print("  1. Get an API key from: https://makersuite.google.com/app/apikey")
    print("  2. Create a .env file in this directory")
    print("  3. Add this line to the .env file:")
    print("     API_KEY=your-actual-api-key-here")
    print("\n  Alternatively, set the environment variable:")
    print("     export MODEL_API_KEY=your-actual-api-key-here")

    response = input("\n  Do you want to enter your API key now? (y/n): ")
    if response.lower() == 'y':
        api_key = input("  Enter your API key: ").strip()
        if api_key:
            with open(env_file, 'w') as f:
                f.write(f"API_KEY={api_key}\n")
            print("  ✓ API key saved to .env")
            return True

    return False

def copy_files_from_v13():
    """Copy necessary files from v1.3 if they don't exist"""
    print("\n[5/5] Checking for required files...")

    v13_path = Path("../ANTIPATTERN_PIPELINE_v1.3")
    v14_path = Path(".")

    files_to_check = [
        ("data/commit_data.py", "data/commit_data.py"),
        ("model_analyzer.py", "model_analyzer.py"),
        ("checker_generator.py", "checker_generator.py"),
    ]

    all_exist = True
    for src, dst in files_to_check:
        dst_file = v14_path / dst
        if not dst_file.exists():
            src_file = v13_path / src
            if src_file.exists():
                import shutil
                dst_file.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src_file, dst_file)
                print(f"  ✓ Copied {src} from v1.3")
            else:
                print(f"  ✗ Missing {dst} (and not found in v1.3)")
                all_exist = False
        else:
            print(f"  ✓ {dst} exists")

    return all_exist

def run_options():
    """Present run options to user"""
    print("\n" + "="*80)
    print("SETUP COMPLETE!")
    print("="*80)

    print("\nAvailable options:")
    print("\n1. Run full test suite")
    print("   python run_full_test.py")
    print("\n2. Check setup and install missing tools")
    print("   python setup_check.py")
    print("\n3. Run the complete pipeline")
    print("   python pipeline_v1.4.py")
    print("\n4. Run comparative analysis only")
    print("   python comparative_analyzer.py")
    print("\n5. Run pattern detection only (no special tools needed)")
    print("   python detectors/pattern_detector.py")

    print("\nRecommended first step:")
    print("  python run_full_test.py")
    print("\nThis will check your entire setup and identify any missing components.")

    response = input("\nWould you like to run the full test suite now? (y/n): ")
    if response.lower() == 'y':
        print("\nRunning test suite...\n")
        subprocess.run([sys.executable, "run_full_test.py"])

def main():
    """Main function"""
    print_banner()

    # Run setup steps
    if not check_basic_requirements():
        print("\n❌ Basic requirements not met. Please install missing components.")
        return 1

    setup_directories()

    if not install_python_packages():
        print("\n⚠ Warning: Some Python packages not installed")

    if not setup_api_key():
        print("\n⚠ Warning: API key not configured. Some features won't work.")

    copy_files_from_v13()

    # Show run options
    run_options()

    return 0

if __name__ == "__main__":
    sys.exit(main())