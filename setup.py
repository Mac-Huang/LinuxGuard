"""
LinuxGuard Setup Script
Handles initial setup and dependency installation
"""
import os
import sys
import subprocess
from pathlib import Path
from loguru import logger


def run_command(cmd, cwd=None, check=True):
    """Run shell command with error handling"""
    logger.info(f"Running: {cmd}")
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            cwd=cwd,
            capture_output=True,
            text=True,
            check=check
        )
        if result.stdout:
            logger.info(result.stdout)
        return result
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {e}")
        if e.stderr:
            logger.error(e.stderr)
        if check:
            raise
        return e


def setup_environment():
    """Set up conda environment"""
    logger.info("Setting up LinuxGuard environment...")
    
    # Check if conda is available
    try:
        run_command("conda --version")
    except:
        logger.error("Conda not found. Please install Anaconda or Miniconda first.")
        return False
    
    # Create environment from YAML
    env_file = Path("environment.yml")
    if env_file.exists():
        logger.info("Creating conda environment from environment.yml...")
        run_command("conda env create -f environment.yml")
    else:
        logger.error("environment.yml not found!")
        return False
    
    logger.info("Environment setup complete!")
    logger.info("Activate with: conda activate linuxguard")
    return True


def clone_linux_repo():
    """Clone Linux kernel repository"""
    repo_path = Path("data/linux_kernel")
    
    if repo_path.exists():
        logger.info("Linux kernel repository already exists")
        return True
    
    logger.info("Cloning Linux kernel repository (this may take a while)...")
    
    # Create data directory
    repo_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Clone with shallow history for faster download
    clone_cmd = f"git clone --depth 1000 https://github.com/torvalds/linux.git {repo_path}"
    
    try:
        result = run_command(clone_cmd, check=False)
        if result.returncode == 0:
            logger.info("Linux kernel repository cloned successfully")
            return True
        else:
            logger.error("Failed to clone Linux kernel repository")
            return False
    except Exception as e:
        logger.error(f"Error cloning repository: {e}")
        return False


def check_api_keys():
    """Check if required API keys are set"""
    google_key = os.getenv("GOOGLE_API_KEY")
    anthropic_key = os.getenv("ANTHROPIC_API_KEY")
    
    if not google_key and not anthropic_key:
        logger.warning("No API keys found!")
        logger.info("Please set one of the following environment variables:")
        logger.info("  - GOOGLE_API_KEY (for Gemini)")
        logger.info("  - ANTHROPIC_API_KEY (for Claude)")
        return False
    
    if google_key:
        logger.info("Google API key found")
    if anthropic_key:
        logger.info("Anthropic API key found")
    
    return True


def run_quick_test():
    """Run a quick test of the system"""
    logger.info("Running quick system test...")
    
    try:
        # Test imports
        sys.path.append("src")
        from src.data_collection.linux_docs_rag import LinuxDocsRAG
        from config import config
        
        logger.info("✓ Imports successful")
        
        # Test RAG system
        rag = LinuxDocsRAG()
        if rag.collection.count() == 0:
            logger.info("Populating RAG database for test...")
            rag.populate_vector_db()
        
        # Test query
        context = rag.query_context("memory management", n_results=1)
        if context:
            logger.info("✓ RAG system working")
        else:
            logger.warning("RAG system test failed")
        
        logger.info("Quick test completed successfully!")
        return True
        
    except Exception as e:
        logger.error(f"Quick test failed: {e}")
        return False


def main():
    """Main setup function"""
    logger.info("=" * 50)
    logger.info("LinuxGuard Setup")
    logger.info("=" * 50)
    
    # Step 1: Setup environment
    if not setup_environment():
        logger.error("Environment setup failed")
        return False
    
    # Step 2: Clone Linux repo
    if not clone_linux_repo():
        logger.warning("Linux repository clone failed - you can clone it manually later")
    
    # Step 3: Check API keys
    if not check_api_keys():
        logger.warning("API keys not configured - set them before running LinuxGuard")
    
    # Step 4: Quick test
    logger.info("Setup complete! To test the system:")
    logger.info("1. conda activate linuxguard")
    logger.info("2. python main.py --phase a")
    
    return True


if __name__ == "__main__":
    main()