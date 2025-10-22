#!/usr/bin/env python3
"""
Fetch complete commit information from Linux kernel including full context.
Uses a local git clone for robust patch fetching, falling back to APIs.
"""

import json
import urllib.request
import urllib.error
import sys
import os
import argparse
import subprocess
from pathlib import Path
from datetime import datetime
from dotenv import load_dotenv
from typing import Optional

load_dotenv(Path(__file__).parent.parent / ".env")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

GITHUB_REPOSITORIES = [
    "torvalds/linux",
    "gregkh/linux",
    "stable/linux-stable",
]

# This will be stored within your project structure
LINUX_REPO_PATH = Path(__file__).parent.parent / "kernels" / "linux.git"
FALLBACK_FETCH_SOURCES = [
    {
        "description": "origin (torvalds/linux)",
        "fetch_args": ["origin"],
    },
    {
        "description": "linux-stable (kernel.org)",
        "fetch_args": ["https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git"],
    },
]

KERNEL_ORG_PATCH_SOURCES = [
    {
        "description": "kernel.org linux-stable",
        "url_template": "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/patch/?id={commit}",
    },
    {
        "description": "kernel.org torvalds/linux",
        "url_template": "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id={commit}",
    },
]

def _git_has_commit(commit_hash: str) -> bool:
    """Return True if the commit already exists in the local repository."""
    try:
        subprocess.run(
            ["git", "-C", str(LINUX_REPO_PATH), "cat-file", "-e", f"{commit_hash}^{{commit}}"],
            check=True,
            capture_output=True,
            text=True,
        )
        return True
    except subprocess.CalledProcessError:
        return False


def fetch_patch_with_git(commit_hash: str) -> Optional[str]:
    """
    Fetches a commit patch using a local, shallow clone of the Linux repo.
    This is the most robust method.
    """
    try:
        # Step 1: Clone the repo if it doesn't exist (this part is already working)
        if not LINUX_REPO_PATH.exists():
            print(f"Local Linux repo not found. Cloning a shallow copy to {LINUX_REPO_PATH}...", file=sys.stderr)
            print("This may take a few minutes, but it's a one-time setup.", file=sys.stderr)
            subprocess.run(
                ["git", "clone", "--depth=1", "https://github.com/torvalds/linux.git", str(LINUX_REPO_PATH)],
                check=True, capture_output=True, text=True
            )
            print("✓ Local repo cloned successfully.", file=sys.stderr)

        # Step 2: Fetch the specific commit. Try the local clone first, then fall back.
        if not _git_has_commit(commit_hash):
            fetch_errors = []
            for source in FALLBACK_FETCH_SOURCES:
                try:
                    print(
                        f"Fetching commit object {commit_hash[:8]} from {source['description']}...",
                        file=sys.stderr,
                    )
                    subprocess.run(
                        ["git", "-C", str(LINUX_REPO_PATH), "fetch", *source["fetch_args"], commit_hash],
                        check=True,
                        capture_output=True,
                        text=True
                    )
                    if _git_has_commit(commit_hash):
                        break
                except subprocess.CalledProcessError as e:
                    fetch_errors.append((source["description"], e.stderr.strip()))
            else:
                print(f"Git command failed: commit {commit_hash[:12]} not found in known remotes.", file=sys.stderr)
                for description, err in fetch_errors:
                    if err:
                        print(f"- {description}: {err}", file=sys.stderr)
                return None

        # Step 3: Now 'git show' will find the object.
        result = subprocess.run(
            ["git", "-C", str(LINUX_REPO_PATH), "show", "--no-color", commit_hash],
            check=True, capture_output=True, text=True
        )
        return result.stdout

    except subprocess.CalledProcessError as e:
        print(f"Git command failed: {e}", file=sys.stderr)
        print(f"Stderr: {e.stderr}", file=sys.stderr)
        return None
    except FileNotFoundError:
        print("Error: 'git' command not found. Please ensure Git is installed.", file=sys.stderr)
        return None

def fetch_commit_patch(commit_hash: str) -> Optional[str]:
    """
    Orchestrator for fetching a commit patch. Tries the robust git method first.
    """
    print("Attempting to fetch patch using local git repository...", file=sys.stderr)
    patch_content = fetch_patch_with_git(commit_hash)
    if patch_content:
        print("✓ Successfully fetched patch using git.", file=sys.stderr)
        return patch_content

    print("Local git fetch failed. Falling back to GitHub API...", file=sys.stderr)
    for repo in GITHUB_REPOSITORIES:
        api_url = f"https://api.github.com/repos/{repo}/commits/{commit_hash}"
        try:
            req = urllib.request.Request(api_url)
            req.add_header('Accept', 'application/vnd.github.v3.patch')
            if GITHUB_TOKEN:
                req.add_header('Authorization', f'token {GITHUB_TOKEN}')
            with urllib.request.urlopen(req) as response:
                patch_content = response.read().decode('utf-8')
            if patch_content:
                print(f"✓ Retrieved patch from GitHub repo {repo}.", file=sys.stderr)
                return patch_content
        except urllib.error.HTTPError as e:
            print(f"{repo} GitHub API patch download failed ({e}).", file=sys.stderr)
        except Exception as e:
            print(f"{repo} GitHub API patch download failed ({e}).", file=sys.stderr)

    print("GitHub API unavailable. Trying kernel.org patch endpoints...", file=sys.stderr)
    for source in KERNEL_ORG_PATCH_SOURCES:
        patch_url = source["url_template"].format(commit=commit_hash)
        try:
            print(f"Attempting download from {source['description']}...", file=sys.stderr)
            request = urllib.request.Request(
                patch_url, headers={"User-Agent": "linux-guard/1.0"}
            )
            with urllib.request.urlopen(request) as response:
                patch_text = response.read().decode('utf-8')
            if patch_text.strip():
                print(f"✓ Retrieved patch from {source['description']}.", file=sys.stderr)
                return patch_text
        except urllib.error.HTTPError as e:
            print(f"{source['description']} responded with {e}.", file=sys.stderr)
        except Exception as e:
            print(f"Error downloading patch from {source['description']}: {e}", file=sys.stderr)

    return None

def fetch_commit_from_github_api(commit_hash: str) -> dict:
    """Fetch complete commit data from GitHub API."""
    for repo in GITHUB_REPOSITORIES:
        api_url = f"https://api.github.com/repos/{repo}/commits/{commit_hash}"
        try:
            req = urllib.request.Request(api_url)
            req.add_header('Accept', 'application/vnd.github.v3+json')

            if GITHUB_TOKEN:
                req.add_header('Authorization', f'token {GITHUB_TOKEN}')

            with urllib.request.urlopen(req) as response:
                commit_data = json.loads(response.read().decode('utf-8'))
            return {
                'sha': commit_data['sha'],
                'author': {
                    'name': commit_data['commit']['author']['name'],
                    'email': commit_data['commit']['author']['email'],
                    'date': commit_data['commit']['author']['date']
                },
                'committer': {
                    'name': commit_data['commit']['committer']['name'],
                    'email': commit_data['commit']['committer']['email'],
                    'date': commit_data['commit']['committer']['date']
                },
                'message': commit_data['commit']['message'],
                'stats': commit_data.get('stats', {}),
                'files': [
                    {
                        'filename': f['filename'],
                        'status': f['status'],
                        'additions': f['additions'],
                        'deletions': f['deletions'],
                        'changes': f['changes']
                    } for f in commit_data.get('files', [])
                ]
            }
        except urllib.error.HTTPError as e:
            if e.code == 403:
                print("GitHub API rate limit exceeded or token is invalid.", file=sys.stderr)
                break
            if e.code not in (404, 422):
                print(f"Error fetching from GitHub API ({repo}): {e}", file=sys.stderr)
        except Exception as e:
            print(f"Error fetching from GitHub API ({repo}): {e}", file=sys.stderr)
    return None

def parse_patch_header(patch_content: str) -> dict:
    """Extract commit information from patch header."""
    lines = patch_content.split('\n')
    commit_info = { 'subject': '', 'author': '', 'date': '', 'message_body': '', 'signed_off_by': [], 'reviewed_by': [], 'reported_by': [], 'fixes': [], 'cc': [] }
    in_message = False
    message_lines = []
    for line in lines:
        if line.startswith('From '):
            parts = line.split()
            if len(parts) >= 2: commit_info['sha'] = parts[1]
        elif line.startswith('From:'): commit_info['author'] = line[5:].strip()
        elif line.startswith('Date:'): commit_info['date'] = line[5:].strip()
        elif line.startswith('Subject:'):
            commit_info['subject'] = line[8:].strip()
            in_message = True
        elif line.startswith('diff --git'): break
        elif in_message:
            if line.startswith('Signed-off-by:'): commit_info['signed_off_by'].append(line[14:].strip())
            elif line.startswith('Reviewed-by:'): commit_info['reviewed_by'].append(line[11:].strip())
            elif line.startswith('Reported-by:'): commit_info['reported_by'].append(line[11:].strip())
            elif line.startswith('Fixes:'): commit_info['fixes'].append(line[6:].strip())
            elif line.startswith('Cc:'): commit_info['cc'].append(line[3:].strip())
            else: message_lines.append(line)
    commit_info['message_body'] = '\n'.join(message_lines).strip()
    return commit_info

def extract_diff_context(patch_content: str) -> dict:
    """Extract structured diff information with context."""
    diff_info = { 'files_changed': [], 'total_additions': 0, 'total_deletions': 0, 'hunks': [] }
    lines = patch_content.split('\n')
    current_file = None
    in_diff = False
    for line in lines:
        if line.startswith('diff --git'):
            in_diff = True
            parts = line.split()
            if len(parts) >= 4:
                current_file = { 'from': parts[2][2:] if parts[2].startswith('a/') else parts[2], 'to': parts[3][2:] if parts[3].startswith('b/') else parts[3], 'hunks': [] }
                diff_info['files_changed'].append(current_file)
        elif line.startswith('@@') and in_diff and current_file:
            hunk_info = { 'header': line, 'context': [], 'removed': [], 'added': [] }
            current_file['hunks'].append(hunk_info)
        elif in_diff and current_file and 'hunks' in current_file and current_file['hunks']:
            current_hunk = current_file['hunks'][-1]
            if line.startswith('+') and not line.startswith('+++'):
                current_hunk['added'].append(line[1:])
                diff_info['total_additions'] += 1
            elif line.startswith('-') and not line.startswith('---'):
                current_hunk['removed'].append(line[1:])
                diff_info['total_deletions'] += 1
            elif line.startswith(' '):
                current_hunk['context'].append(line[1:])
    return diff_info

def save_complete_commit(commit_hash: str, output_dir: str):
    """Fetch and save complete commit information."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    json_file = output_path / f"{commit_hash}.json"
    patch_file = output_path / f"{commit_hash}.patch"
    if json_file.exists() and patch_file.exists():
        print(f"✓ Commit already downloaded: {commit_hash[:8]}")
        return str(json_file)

    print(f"Fetching complete commit {commit_hash[:8]}...")
    patch_content = fetch_commit_patch(commit_hash)
    if not patch_content:
        print("✗ Failed to fetch commit patch from all sources.", file=sys.stderr)
        return None

    with open(patch_file, 'w') as f:
        f.write(patch_content)
    print(f"✓ Saved patch to: {patch_file}")

    commit_info = parse_patch_header(patch_content)
    api_data = fetch_commit_from_github_api(commit_hash)
    if api_data: commit_info.update(api_data)
    diff_info = extract_diff_context(patch_content)
    
    complete_data = {
        'commit_hash': commit_hash, 'fetch_date': datetime.now().isoformat(), 'commit_info': commit_info, 'patch_file': str(patch_file),
        'summary': {
            'subject': commit_info.get('subject', ''), 'author': commit_info.get('author', ''), 'date': commit_info.get('date', ''),
            'files_changed': len(diff_info['files_changed']), 'additions': diff_info['total_additions'], 'deletions': diff_info['total_deletions'],
            'has_fixes_tag': len(commit_info.get('fixes', [])) > 0, 'reporters': commit_info.get('reported_by', [])
        }
    }
    with open(json_file, 'w') as f:
        json.dump(complete_data, f, indent=2)
    print(f"✓ Saved commit data to: {json_file}")
    return str(json_file)

def main():
    parser = argparse.ArgumentParser(description='Fetch complete Linux kernel commit with full context')
    parser.add_argument('commit', help='Commit hash to fetch')
    parser.add_argument('--output-dir', type=Path, default=Path(__file__).parent.parent / "commits", help='Directory to save commit data')
    args = parser.parse_args()
    result = save_complete_commit(args.commit, args.output_dir)
    if not result:
        sys.exit(1)

if __name__ == "__main__":
    main()
