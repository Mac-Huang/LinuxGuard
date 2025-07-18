"""
Simple test of LinuxGuard core functionality
"""
import os
import sys
sys.path.append("src")

from pathlib import Path
from src.data_collection.commit_processor import CommitProcessor

def test_commit_processor():
    """Test basic commit processing"""
    print("Testing commit processor...")
    
    # Use existing Linux repo
    repo_path = "../linux_kernel"
    
    if not Path(repo_path).exists():
        print(f"Repository not found at {repo_path}")
        return False
    
    processor = CommitProcessor(repo_path, output_dir="data/test_commits")
    
    # Test with small timeframe
    print("Processing commits from last 30 days...")
    batches = processor.process_commits(days_back=30, batch_size=5)
    
    print(f"Created {len(batches)} batches")
    
    if batches:
        print(f"First batch has {len(batches[0])} commits")
        first_commit = batches[0][0]
        print(f"Sample commit: {first_commit.sha[:8]} - {first_commit.message[:50]}")
        return True
    
    return False

def test_basic_llm():
    """Test basic LLM connectivity"""
    print("Testing LLM connectivity...")
    
    try:
        import google.generativeai as genai
        
        api_key = os.getenv("GOOGLE_API_KEY", "AIzaSyD1luvMQH0BT7sCg6SDZsC6eG4cJ8wa1TE")
        genai.configure(api_key=api_key)
        
        model = genai.GenerativeModel("gemini-2.0-flash-exp")
        response = model.generate_content("Hello, can you analyze Linux kernel code?")
        
        if response and response.text:
            print(f"LLM Response: {response.text[:100]}...")
            return True
        else:
            print("Empty response from LLM")
            return False
            
    except Exception as e:
        print(f"LLM test failed: {e}")
        return False

def main():
    """Run simple tests"""
    print("=" * 50)
    print("LinuxGuard Simple Test")
    print("=" * 50)
    
    # Test 1: Commit processor
    if test_commit_processor():
        print("+ Commit processor test passed")
    else:
        print("- Commit processor test failed")
    
    print()
    
    # Test 2: LLM connectivity
    if test_basic_llm():
        print("+ LLM connectivity test passed")
    else:
        print("- LLM connectivity test failed")
    
    print("\nBasic tests complete!")

if __name__ == "__main__":
    main()