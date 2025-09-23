#!/usr/bin/env python3
"""
Push LinuxGuard versions to GitHub with appropriate tags
Author: Mac Huang
Repository: https://github.com/Mac-Huang/LinuxGuard
"""

import subprocess
import os
from pathlib import Path

def run_git_command(cmd, cwd=None, capture=True):
    """Run a git command and return the result"""
    print(f"  Running: {cmd}")
    if capture:
        result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, shell=True)
        if result.returncode != 0:
            print(f"  [ERROR] {result.stderr}")
        return result
    else:
        return subprocess.run(cmd, cwd=cwd, shell=True)

def configure_git():
    """Configure git with author information"""
    print("[1/6] Configuring git author...")
    run_git_command('git config user.name "Mac Huang"')
    run_git_command('git config user.email "mac.huang@example.com"')
    print("  [OK] Set author to Mac Huang")

def initialize_repo():
    """Initialize git repository if needed"""
    print("\n[2/6] Initializing repository...")

    if not Path(".git").exists():
        run_git_command("git init")
        print("  [OK] Git repository initialized")
    else:
        print("  [OK] Git repository already initialized")

    # Add remote if not exists
    result = run_git_command("git remote -v")
    if "LinuxGuard" not in result.stdout:
        run_git_command("git remote add origin https://github.com/Mac-Huang/LinuxGuard.git")
        print("  [OK] Added remote repository")
    else:
        print("  [OK] Remote already configured")

def stage_and_commit_versions():
    """Stage and commit each version with descriptive messages"""
    print("\n[3/6] Creating version commits...")

    versions = [
        {
            "tag": "v1.0",
            "dir": "ANTIPATTERN_PIPELINE_v1.0",
            "message": "v1.0: Initial pipeline - Basic AI-powered vulnerability detection",
            "description": "Foundation release with Gemini API integration for analyzing Linux kernel commits and generating Clang checkers"
        },
        {
            "tag": "v1.1",
            "dir": "ANTIPATTERN_PIPELINE_v1.1",
            "message": "v1.1: Enhanced prompt engineering for improved detection",
            "description": "Improved detection accuracy through refined prompts, 40% reduction in false positives"
        },
        {
            "tag": "v1.2",
            "dir": "ANTIPATTERN_PIPELINE_v1.2",
            "message": "v1.2: Multi-version kernel scanning capability",
            "description": "Added historical vulnerability tracking across multiple Linux kernel versions"
        },
        {
            "tag": "v1.3",
            "dir": "ANTIPATTERN_PIPELINE_v1.3",
            "message": "v1.3: Generic vulnerability detection - Model agnostic",
            "description": "Support for any LLM model, dynamic vulnerability type detection, removed hardcoded assumptions"
        },
        {
            "tag": "v1.4",
            "dir": "ANTIPATTERN_PIPELINE_v1.4",
            "message": "v1.4: Comparative analysis framework",
            "description": "Multi-method detection with pattern matching, Coccinelle, and Clang static analyzer. Performance metrics and comparison"
        },
        {
            "tag": "v2.0",
            "dir": "ANTIPATTERN_PIPELINE_v2.0",
            "message": "v2.0: LLVM-optimized professional checker generation",
            "description": "Production-ready checker generation based on LLVM clang-tidy patterns, professional AST matchers"
        }
    ]

    for version in versions:
        print(f"\n  Processing {version['tag']}...")

        # Check if directory exists
        if not Path(version['dir']).exists():
            print(f"  [SKIP] {version['dir']} not found")
            continue

        # Stage the version directory
        run_git_command(f"git add {version['dir']}/")

        # Add version-specific files
        run_git_command(f"git add {version['dir']}/SAMPLE_RESULTS.md", capture=False)

        # Create commit
        commit_msg = f"{version['message']}\\n\\nAuthor: Mac Huang\\n\\n{version['description']}"
        result = run_git_command(f'git commit -m "{commit_msg}"')

        if result.returncode == 0:
            print(f"  [OK] Created commit for {version['tag']}")
        else:
            print(f"  [INFO] No changes for {version['tag']} or already committed")

def create_tags():
    """Create tags for each version"""
    print("\n[4/6] Creating version tags...")

    tags = [
        ("v1.0", "Release v1.0 - Initial pipeline with basic AI-powered detection"),
        ("v1.1", "Release v1.1 - Enhanced prompt engineering"),
        ("v1.2", "Release v1.2 - Multi-version kernel scanning"),
        ("v1.3", "Release v1.3 - Generic vulnerability detection"),
        ("v1.4", "Release v1.4 - Comparative analysis framework"),
        ("v2.0", "Release v2.0 - LLVM-optimized professional checker generation")
    ]

    for tag, message in tags:
        # Check if tag already exists
        result = run_git_command(f"git tag -l {tag}")
        if tag in result.stdout:
            print(f"  [EXISTS] Tag {tag} already exists")
        else:
            # Create annotated tag
            run_git_command(f'git tag -a {tag} -m "{message}"')
            print(f"  [OK] Created tag {tag}")

def stage_additional_files():
    """Stage additional documentation and configuration files"""
    print("\n[5/6] Staging documentation files...")

    files_to_add = [
        "README.md",
        "VERSION_HISTORY.md",
        "setup_version_control.py",
        "push_to_github.py",
        "cleanup_and_update.py",
        "create_v2.0.py",
        ".gitignore"
    ]

    for file in files_to_add:
        if Path(file).exists():
            run_git_command(f"git add {file}")
            print(f"  [OK] Added {file}")

    # Commit documentation
    run_git_command('git commit -m "Add comprehensive documentation and version management"')

def push_to_remote():
    """Push all commits and tags to GitHub"""
    print("\n[6/6] Pushing to GitHub...")

    print("\n" + "="*60)
    print("READY TO PUSH TO GITHUB")
    print("="*60)
    print("Repository: https://github.com/Mac-Huang/LinuxGuard")
    print("Author: Mac Huang")
    print("\nThis will push:")
    print("  - All version directories (v1.0 through v2.0)")
    print("  - All version tags")
    print("  - Documentation and management scripts")

    response = input("\nProceed with push to GitHub? (y/n): ")
    if response.lower() != 'y':
        print("[CANCELLED] Push cancelled by user")
        return

    # Set upstream and push
    print("\nPushing to origin/main...")
    result = run_git_command("git push -u origin main", capture=False)

    if result.returncode == 0:
        print("[OK] Successfully pushed commits to origin/main")
    else:
        print("[ERROR] Failed to push commits. You may need to:")
        print("  1. Set up GitHub authentication (SSH key or token)")
        print("  2. Run: git push --set-upstream origin main")

    # Push tags
    print("\nPushing tags...")
    result = run_git_command("git push origin --tags", capture=False)

    if result.returncode == 0:
        print("[OK] Successfully pushed all tags")
    else:
        print("[ERROR] Failed to push tags")

def create_gitignore():
    """Create .gitignore file if it doesn't exist"""
    gitignore_path = Path(".gitignore")
    if not gitignore_path.exists():
        gitignore_content = """# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
env/
venv/
.env
.secrets

# IDE
.vscode/
.idea/
*.swp
*.swo

# Build
build/
dist/
*.egg-info/
*.dll
*.so
*.dylib

# Results and logs
*.log
results/
generated/*.o
generated/*.obj

# Temporary files
*.tmp
temp/
tmp/
.cache/

# API Keys - NEVER commit these
.secrets
.env
config_local.py
"""
        gitignore_path.write_text(gitignore_content)
        print("[CREATED] .gitignore file")

def main():
    """Main function to orchestrate the GitHub push"""
    print("="*60)
    print("LINUXGUARD GITHUB PUSH SCRIPT")
    print("="*60)

    # Create .gitignore
    create_gitignore()

    # Configure git
    configure_git()

    # Initialize repository
    initialize_repo()

    # Stage and commit versions
    stage_and_commit_versions()

    # Create version tags
    create_tags()

    # Stage additional files
    stage_additional_files()

    # Push to remote
    push_to_remote()

    print("\n" + "="*60)
    print("GITHUB PUSH COMPLETE")
    print("="*60)
    print("\nYour repository structure:")
    print("  https://github.com/Mac-Huang/LinuxGuard")
    print("  ├── ANTIPATTERN_PIPELINE_v1.0/ (tag: v1.0)")
    print("  ├── ANTIPATTERN_PIPELINE_v1.1/ (tag: v1.1)")
    print("  ├── ANTIPATTERN_PIPELINE_v1.2/ (tag: v1.2)")
    print("  ├── ANTIPATTERN_PIPELINE_v1.3/ (tag: v1.3)")
    print("  ├── ANTIPATTERN_PIPELINE_v1.4/ (tag: v1.4)")
    print("  └── ANTIPATTERN_PIPELINE_v2.0/ (tag: v2.0)")

if __name__ == "__main__":
    main()