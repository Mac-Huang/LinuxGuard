"""
Commit Batch Processing System
Efficiently processes Linux kernel commits in batches for anti-pattern detection
"""
import os
import json
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta
import git
from git import Commit
from loguru import logger
import re
from tqdm import tqdm


@dataclass
class CommitInfo:
    """Structure for commit information"""
    sha: str
    message: str
    author: str
    date: datetime
    files_changed: List[str]
    diff: str
    stats: Dict[str, int]


class CommitProcessor:
    def __init__(self, repo_path: str, output_dir: str = "data/commits"):
        """Initialize commit processor"""
        self.repo_path = Path(repo_path)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Load git repository
        try:
            self.repo = git.Repo(repo_path)
            logger.info(f"Loaded repository: {repo_path}")
        except Exception as e:
            logger.error(f"Failed to load repository: {e}")
            raise
    
    def get_commits_in_timeframe(self, days_back: int = 730) -> List[Commit]:
        """Get commits from the last N days (default: 2 years)"""
        since_date = datetime.now() - timedelta(days=days_back)
        
        logger.info(f"Collecting commits since {since_date.strftime('%Y-%m-%d')}...")
        
        commits = list(self.repo.iter_commits(
            'HEAD',
            since=since_date.strftime('%Y-%m-%d'),
            max_count=10000  # Limit for safety
        ))
        
        logger.info(f"Found {len(commits)} commits in timeframe")
        return commits
    
    def is_security_related(self, commit: Commit) -> bool:
        """Basic filtering for security-related commits"""
        message = commit.message.lower()
        
        security_keywords = [
            'cve', 'security', 'vuln', 'exploit', 'overflow', 'underflow',
            'use-after-free', 'uaf', 'memory leak', 'double free', 'null pointer',
            'race condition', 'deadlock', 'privilege', 'escalation', 'injection',
            'sanitize', 'validate', 'bounds check', 'integer overflow',
            'buffer overflow', 'stack overflow', 'heap overflow'
        ]
        
        # Check commit message
        for keyword in security_keywords:
            if keyword in message:
                return True
        
        # Check if it's a fix commit
        fix_patterns = [
            r'\bfix\b.*\b(bug|issue|problem|error|leak|crash)\b',
            r'\b(prevent|avoid|stop)\b.*\b(overflow|underflow|leak)\b',
            r'\bcheck\b.*\b(bounds|null|validation)\b'
        ]
        
        for pattern in fix_patterns:
            if re.search(pattern, message, re.IGNORECASE):
                return True
        
        return False
    
    def extract_commit_info(self, commit: Commit) -> Optional[CommitInfo]:
        """Extract detailed information from a commit"""
        try:
            # Get diff
            if commit.parents:
                diff = self.repo.git.diff(commit.parents[0], commit, '--no-merges')
            else:
                diff = self.repo.git.show(commit, '--format=', '--no-merges')
            
            # Filter for C/C++ files only
            c_files = []
            if hasattr(commit, 'stats') and hasattr(commit.stats, 'files'):
                for file_path in commit.stats.files.keys():
                    if file_path.endswith(('.c', '.h', '.cpp', '.hpp')):
                        c_files.append(file_path)
            
            # Skip if no C/C++ files changed
            if not c_files:
                return None
            
            # Extract stats
            stats = {
                'insertions': commit.stats.total.get('insertions', 0),
                'deletions': commit.stats.total.get('deletions', 0),
                'files': commit.stats.total.get('files', 0)
            }
            
            return CommitInfo(
                sha=commit.hexsha,
                message=commit.message.strip(),
                author=commit.author.name,
                date=commit.committed_datetime,
                files_changed=c_files,
                diff=diff,
                stats=stats
            )
            
        except Exception as e:
            logger.warning(f"Failed to extract info from commit {commit.hexsha}: {e}")
            return None
    
    def create_commit_batches(self, commits: List[CommitInfo], batch_size: int = 20) -> List[List[CommitInfo]]:
        """Group commits into batches for efficient LLM processing"""
        batches = []
        for i in range(0, len(commits), batch_size):
            batch = commits[i:i + batch_size]
            batches.append(batch)
        
        logger.info(f"Created {len(batches)} batches of size {batch_size}")
        return batches
    
    def format_batch_for_llm(self, batch: List[CommitInfo]) -> str:
        """Format commit batch for LLM analysis"""
        formatted = "# Linux Kernel Commit Batch Analysis\n\n"
        
        for i, commit in enumerate(batch, 1):
            formatted += f"## Commit {i}: {commit.sha[:8]}\n\n"
            formatted += f"**Author:** {commit.author}\n"
            formatted += f"**Date:** {commit.date.strftime('%Y-%m-%d %H:%M:%S')}\n"
            formatted += f"**Files Changed:** {', '.join(commit.files_changed[:5])}"  # Limit files shown
            if len(commit.files_changed) > 5:
                formatted += f" (+{len(commit.files_changed) - 5} more)"
            formatted += "\n\n"
            
            formatted += f"**Message:**\n```\n{commit.message}\n```\n\n"
            
            # Truncate diff if too long
            diff_lines = commit.diff.split('\n')
            if len(diff_lines) > 50:
                truncated_diff = '\n'.join(diff_lines[:50]) + f"\n\n... (truncated {len(diff_lines) - 50} lines)"
            else:
                truncated_diff = commit.diff
            
            formatted += f"**Diff:**\n```diff\n{truncated_diff}\n```\n\n"
            formatted += "---\n\n"
        
        return formatted
    
    def process_commits(self, days_back: int = 730, batch_size: int = 20) -> List[List[CommitInfo]]:
        """Main processing pipeline"""
        logger.info("Starting commit processing pipeline...")
        
        # Step 1: Get commits in timeframe
        raw_commits = self.get_commits_in_timeframe(days_back)
        
        # Step 2: Filter for security-related commits
        security_commits = []
        logger.info("Filtering for security-related commits...")
        
        for commit in tqdm(raw_commits, desc="Filtering commits"):
            if self.is_security_related(commit):
                security_commits.append(commit)
        
        logger.info(f"Found {len(security_commits)} security-related commits out of {len(raw_commits)}")
        
        # Step 3: Extract detailed information
        processed_commits = []
        logger.info("Extracting commit information...")
        
        for commit in tqdm(security_commits, desc="Processing commits"):
            commit_info = self.extract_commit_info(commit)
            if commit_info:
                processed_commits.append(commit_info)
        
        logger.info(f"Successfully processed {len(processed_commits)} commits")
        
        # Step 4: Create batches
        batches = self.create_commit_batches(processed_commits, batch_size)
        
        # Step 5: Save processed data
        self.save_batches(batches)
        
        return batches
    
    def save_batches(self, batches: List[List[CommitInfo]]):
        """Save commit batches to disk"""
        batches_dir = self.output_dir / "batches"
        batches_dir.mkdir(exist_ok=True)
        
        logger.info(f"Saving {len(batches)} batches to {batches_dir}")
        
        for i, batch in enumerate(batches):
            # Save raw data as JSON
            batch_data = []
            for commit in batch:
                batch_data.append({
                    'sha': commit.sha,
                    'message': commit.message,
                    'author': commit.author,
                    'date': commit.date.isoformat(),
                    'files_changed': commit.files_changed,
                    'diff': commit.diff,
                    'stats': commit.stats
                })
            
            json_file = batches_dir / f"batch_{i:03d}.json"
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(batch_data, f, indent=2, ensure_ascii=False)
            
            # Save formatted version for LLM
            formatted_file = batches_dir / f"batch_{i:03d}_formatted.md"
            formatted_content = self.format_batch_for_llm(batch)
            with open(formatted_file, 'w', encoding='utf-8') as f:
                f.write(formatted_content)
        
        logger.info(f"Saved {len(batches)} batches successfully")
    
    def load_batches(self) -> List[List[CommitInfo]]:
        """Load previously processed batches"""
        batches_dir = self.output_dir / "batches"
        if not batches_dir.exists():
            return []
        
        batches = []
        json_files = sorted(batches_dir.glob("batch_*.json"))
        
        for json_file in json_files:
            with open(json_file, 'r', encoding='utf-8') as f:
                batch_data = json.load(f)
            
            batch = []
            for commit_data in batch_data:
                commit = CommitInfo(
                    sha=commit_data['sha'],
                    message=commit_data['message'],
                    author=commit_data['author'],
                    date=datetime.fromisoformat(commit_data['date']),
                    files_changed=commit_data['files_changed'],
                    diff=commit_data['diff'],
                    stats=commit_data['stats']
                )
                batch.append(commit)
            
            batches.append(batch)
        
        logger.info(f"Loaded {len(batches)} batches from disk")
        return batches


def main():
    """Test the commit processor"""
    # Use KNighter's Linux repo for now
    repo_path = "../KNighter/linux"
    if not Path(repo_path).exists():
        logger.error(f"Repository not found at {repo_path}")
        return
    
    processor = CommitProcessor(repo_path)
    batches = processor.process_commits(days_back=365, batch_size=10)  # 1 year, smaller batches for testing
    
    logger.info(f"Processing complete. Created {len(batches)} batches.")


if __name__ == "__main__":
    main()