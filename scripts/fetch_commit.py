#!/usr/bin/env python3
"""
Fetch complete commit information from Linux kernel including full context.
Gets commit message, author, date, and complete diff for rich LLM analysis.
"""

import json
import urllib.request
import urllib.error
import sys
import argparse
from pathlib import Path
from datetime import datetime

def fetch_commit_from_github_api(commit_hash: str) -> dict:
    """Fetch complete commit data from GitHub API."""

    # GitHub API endpoint for commit details
    api_url = f"https://api.github.com/repos/torvalds/linux/commits/{commit_hash}"

    try:
        # Fetch commit metadata from API
        req = urllib.request.Request(api_url)
        req.add_header('Accept', 'application/vnd.github.v3+json')

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
            print("GitHub API rate limit exceeded. Using alternative method.")
        return None
    except Exception as e:
        print(f"Error fetching from GitHub API: {e}")
        return None

def fetch_commit_patch(commit_hash: str) -> str:
    """Fetch the complete patch/diff for a commit."""

    # Try GitHub first (usually faster)
    patch_url = f"https://github.com/torvalds/linux/commit/{commit_hash}.patch"

    try:
        with urllib.request.urlopen(patch_url) as response:
            return response.read().decode('utf-8')
    except Exception:
        # Fallback to kernel.org
        patch_url = f"https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id={commit_hash}"
        try:
            with urllib.request.urlopen(patch_url) as response:
                return response.read().decode('utf-8')
        except Exception as e:
            print(f"Failed to fetch patch: {e}")
            return None

def parse_patch_header(patch_content: str) -> dict:
    """Extract commit information from patch header."""

    lines = patch_content.split('\n')
    commit_info = {
        'subject': '',
        'author': '',
        'date': '',
        'message_body': '',
        'signed_off_by': [],
        'reviewed_by': [],
        'reported_by': [],
        'fixes': [],
        'cc': []
    }

    in_message = False
    message_lines = []

    for line in lines:
        if line.startswith('From '):
            # Commit hash line
            parts = line.split()
            if len(parts) >= 2:
                commit_info['sha'] = parts[1]
        elif line.startswith('From:'):
            commit_info['author'] = line[5:].strip()
        elif line.startswith('Date:'):
            commit_info['date'] = line[5:].strip()
        elif line.startswith('Subject:'):
            commit_info['subject'] = line[8:].strip()
            in_message = True
        elif line.startswith('diff --git'):
            # End of commit message, start of diff
            break
        elif in_message:
            # Collect message body and tags
            if line.startswith('Signed-off-by:'):
                commit_info['signed_off_by'].append(line[14:].strip())
            elif line.startswith('Reviewed-by:'):
                commit_info['reviewed_by'].append(line[11:].strip())
            elif line.startswith('Reported-by:'):
                commit_info['reported_by'].append(line[11:].strip())
            elif line.startswith('Fixes:'):
                commit_info['fixes'].append(line[6:].strip())
            elif line.startswith('Cc:'):
                commit_info['cc'].append(line[3:].strip())
            else:
                message_lines.append(line)

    commit_info['message_body'] = '\n'.join(message_lines).strip()

    return commit_info

def extract_diff_context(patch_content: str) -> dict:
    """Extract structured diff information with context."""

    diff_info = {
        'files_changed': [],
        'total_additions': 0,
        'total_deletions': 0,
        'hunks': []
    }

    lines = patch_content.split('\n')
    current_file = None
    in_diff = False
    current_hunk = None

    for line in lines:
        if line.startswith('diff --git'):
            in_diff = True
            parts = line.split()
            if len(parts) >= 4:
                current_file = {
                    'from': parts[2][2:] if parts[2].startswith('a/') else parts[2],
                    'to': parts[3][2:] if parts[3].startswith('b/') else parts[3],
                    'hunks': []
                }
                diff_info['files_changed'].append(current_file)
        elif line.startswith('@@') and in_diff:
            # Hunk header
            if current_file:
                hunk_info = {
                    'header': line,
                    'context': [],
                    'removed': [],
                    'added': []
                }
                current_file['hunks'].append(hunk_info)
                current_hunk = hunk_info
        elif in_diff and current_hunk:
            if line.startswith('+') and not line.startswith('+++'):
                current_hunk['added'].append(line[1:])
                diff_info['total_additions'] += 1
            elif line.startswith('-') and not line.startswith('---'):
                current_hunk['removed'].append(line[1:])
                diff_info['total_deletions'] += 1
            elif line.startswith(' '):
                current_hunk['context'].append(line[1:])

    return diff_info

def save_complete_commit(commit_hash: str, output_dir: str = "/home/mac/private/linux-guard/commits"):
    """Fetch and save complete commit information."""

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # File paths
    json_file = output_path / f"{commit_hash}.json"
    patch_file = output_path / f"{commit_hash}.patch"

    # Check if already downloaded
    if json_file.exists() and patch_file.exists():
        print(f"✓ Commit already downloaded: {commit_hash[:8]}")
        return str(json_file)

    print(f"Fetching complete commit {commit_hash[:8]}...")

    # Fetch patch (contains everything)
    patch_content = fetch_commit_patch(commit_hash)
    if not patch_content:
        print(f"✗ Failed to fetch commit patch")
        return None

    # Save patch file
    with open(patch_file, 'w') as f:
        f.write(patch_content)
    print(f"✓ Saved patch to: {patch_file}")

    # Parse commit information from patch
    commit_info = parse_patch_header(patch_content)

    # Try to enrich with GitHub API data
    api_data = fetch_commit_from_github_api(commit_hash)
    if api_data:
        commit_info.update(api_data)

    # Add diff analysis
    diff_info = extract_diff_context(patch_content)
    commit_info['diff_analysis'] = diff_info

    # Create comprehensive commit data
    complete_data = {
        'commit_hash': commit_hash,
        'fetch_date': datetime.now().isoformat(),
        'commit_info': commit_info,
        'patch_file': str(patch_file),

        # Summary for quick access
        'summary': {
            'subject': commit_info.get('subject', ''),
            'author': commit_info.get('author', ''),
            'date': commit_info.get('date', ''),
            'files_changed': len(diff_info['files_changed']),
            'additions': diff_info['total_additions'],
            'deletions': diff_info['total_deletions'],
            'has_fixes_tag': len(commit_info.get('fixes', [])) > 0,
            'reporters': commit_info.get('reported_by', [])
        }
    }

    # Save JSON file
    with open(json_file, 'w') as f:
        json.dump(complete_data, f, indent=2)
    print(f"✓ Saved commit data to: {json_file}")

    # Print summary
    print(f"\nCommit Summary:")
    print(f"  Subject: {complete_data['summary']['subject'][:60]}...")
    print(f"  Author: {complete_data['summary']['author']}")
    print(f"  Files: {complete_data['summary']['files_changed']} changed")
    print(f"  Lines: +{complete_data['summary']['additions']} -{complete_data['summary']['deletions']}")

    if complete_data['summary']['has_fixes_tag']:
        print(f"  Fixes: {commit_info['fixes'][0][:50]}...")

    if complete_data['summary']['reporters']:
        print(f"  Reported by: {', '.join(complete_data['summary']['reporters'][:2])}")

    return str(json_file)

def main():
    parser = argparse.ArgumentParser(description='Fetch complete Linux kernel commit with full context')
    parser.add_argument('commit', help='Commit hash to fetch')
    parser.add_argument('--output-dir', default='/home/mac/private/linux-guard/commits',
                      help='Directory to save commit data')
    parser.add_argument('--api-only', action='store_true',
                      help='Only use GitHub API (requires less bandwidth)')

    args = parser.parse_args()

    result = save_complete_commit(args.commit, args.output_dir)

    if result:
        print(f"\n✓ Complete commit data ready for analysis")
        print(f"  JSON: {result}")
        print(f"  Patch: {result.replace('.json', '.patch')}")
        return 0
    else:
        return 1

if __name__ == "__main__":
    sys.exit(main())