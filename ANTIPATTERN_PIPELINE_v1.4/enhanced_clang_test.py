#!/usr/bin/env python3
"""
Enhanced Clang Static Analyzer Test with Real Vulnerability Patterns
Demonstrates actual detection capabilities with proper test cases
"""

import subprocess
import json
import time
from pathlib import Path
from datetime import datetime

class EnhancedClangTest:
    def __init__(self):
        self.test_dir = Path("enhanced_test_kernel")
        self.results = {}

    def create_realistic_kernel_files(self):
        """Create realistic kernel-like files with actual vulnerabilities"""
        print("Creating realistic test kernel files...")

        # Create directories
        dirs = [
            "net/core",
            "net/ipv4",
            "mm",
            "fs/ext4",
            "drivers/net/ethernet"
        ]

        for dir_path in dirs:
            (self.test_dir / dir_path).mkdir(parents=True, exist_ok=True)

        # 1. Buffer overflow vulnerabilities (net/core/skbuff.c)
        skbuff_code = """/* Linux kernel net/core/skbuff.c simulation */
#include <string.h>
#include <stdlib.h>

struct sk_buff {
    unsigned char *data;
    unsigned int len;
    struct sk_buff *next;
};

/* CVE-like: Buffer overflow in skb_copy */
int skb_copy_bits(struct sk_buff *skb, int offset, void *to, int len)
{
    char temp[256];  /* Fixed size buffer */

    if (!skb || !to)
        return -1;

    /* VULNERABILITY: No bounds checking */
    memcpy(temp, skb->data + offset, len);  /* Buffer overflow if len > 256 */

    /* VULNERABILITY: strcpy without bounds */
    char dest[100];
    strcpy(dest, (char*)to);  /* Buffer overflow */

    return 0;
}

/* CVE-like: Use-after-free in skb handling */
void skb_release(struct sk_buff *skb)
{
    if (skb) {
        free(skb->data);
        skb->data = NULL;
    }

    free(skb);
    /* VULNERABILITY: Use after free */
    skb->next = NULL;  /* Writing to freed memory */
}
"""

        # 2. Use-after-free vulnerabilities (mm/slab.c)
        slab_code = """/* Linux kernel mm/slab.c simulation */
#include <stdlib.h>
#include <string.h>

struct kmem_cache {
    size_t size;
    void *freelist;
};

/* CVE-like: Use-after-free in slab allocator */
void *kmem_cache_alloc(struct kmem_cache *cachep, unsigned int flags)
{
    void *objp = malloc(cachep->size);

    if (!objp)
        return NULL;

    /* Simulate complex allocation logic */
    void *temp = objp;
    free(temp);

    /* VULNERABILITY: Use after free */
    memset(objp, 0, cachep->size);  /* Writing to freed memory */

    return objp;
}

/* CVE-like: Double free vulnerability */
void kmem_cache_free(struct kmem_cache *cachep, void *objp)
{
    if (!objp)
        return;

    free(objp);

    /* VULNERABILITY: Potential double free */
    if (cachep->freelist == objp) {
        free(objp);  /* Double free */
    }
}
"""

        # 3. Integer overflow and null pointer (net/ipv4/tcp_input.c)
        tcp_input_code = """/* Linux kernel net/ipv4/tcp_input.c simulation */
#include <stdlib.h>

struct tcp_sock {
    unsigned int rcv_nxt;
    unsigned int copied_seq;
    void *rcv_queue;
};

/* CVE-like: Integer overflow in TCP handling */
int tcp_data_queue(struct tcp_sock *tp, unsigned int seq, unsigned int len)
{
    /* VULNERABILITY: Integer overflow */
    unsigned int end_seq = seq + len;  /* Can overflow */

    if (end_seq < seq) {  /* This check comes too late */
        return -1;
    }

    /* VULNERABILITY: Null pointer dereference */
    struct tcp_sock *sk = NULL;
    sk->rcv_nxt = end_seq;  /* Null pointer deref */

    /* VULNERABILITY: Division by zero */
    int mss = 0;
    int segments = len / mss;  /* Division by zero */

    return 0;
}

/* CVE-like: Memory leak in TCP */
void *tcp_alloc_skb(int size)
{
    void *skb = malloc(size);

    if (!skb)
        return NULL;

    /* VULNERABILITY: Memory leak - no corresponding free */
    void *data = malloc(size * 2);

    /* Missing: free(data) on error paths */

    return skb;
}
"""

        # 4. Race condition (fs/ext4/super.c)
        ext4_super_code = """/* Linux kernel fs/ext4/super.c simulation */
#include <pthread.h>
#include <stdlib.h>

struct super_block {
    int s_flags;
    void *s_fs_info;
    pthread_mutex_t s_lock;
};

static struct super_block *global_sb = NULL;

/* CVE-like: Race condition in filesystem operations */
int ext4_mount(struct super_block *sb)
{
    /* VULNERABILITY: Race condition - check without lock */
    if (global_sb != NULL) {  /* Check */
        return -1;
    }

    /* Time window for race condition */

    pthread_mutex_lock(&sb->s_lock);
    global_sb = sb;  /* Set - TOCTOU vulnerability */
    pthread_mutex_unlock(&sb->s_lock);

    return 0;
}

/* CVE-like: Uninitialized variable use */
int ext4_read_inode(int ino)
{
    int ret;  /* VULNERABILITY: Uninitialized */
    void *data;

    if (ino < 0)
        return ret;  /* Using uninitialized variable */

    data = malloc(4096);
    /* VULNERABILITY: Missing null check */
    memset(data, 0, 4096);  /* Potential null deref if malloc fails */

    return 0;
}
"""

        # 5. Format string vulnerability (drivers/net/ethernet/driver.c)
        driver_code = """/* Linux kernel driver simulation */
#include <stdio.h>
#include <string.h>

/* CVE-like: Format string vulnerability */
void driver_log_message(char *user_msg)
{
    char log_buf[512];

    /* VULNERABILITY: Format string bug */
    sprintf(log_buf, user_msg);  /* User controlled format string */

    /* Should be: sprintf(log_buf, "%s", user_msg); */

    printf(log_buf);  /* Another format string vulnerability */
}

/* CVE-like: Off-by-one error */
int driver_copy_data(char *dst, char *src, int size)
{
    int i;

    /* VULNERABILITY: Off-by-one error */
    for (i = 0; i <= size; i++) {  /* Should be i < size */
        dst[i] = src[i];
    }

    return 0;
}
"""

        # Write all test files
        files = {
            "net/core/skbuff.c": skbuff_code,
            "mm/slab.c": slab_code,
            "net/ipv4/tcp_input.c": tcp_input_code,
            "fs/ext4/super.c": ext4_super_code,
            "drivers/net/ethernet/driver.c": driver_code
        }

        for file_path, code in files.items():
            full_path = self.test_dir / file_path
            full_path.write_text(code)
            print(f"  Created: {file_path}")

    def run_clang_analysis(self):
        """Run Clang static analyzer on test files"""
        print("\nRunning Clang Static Analyzer...")

        all_issues = []

        for c_file in self.test_dir.glob("**/*.c"):
            print(f"\nAnalyzing: {c_file.relative_to(self.test_dir)}")

            # Run with multiple checker configurations
            configs = [
                {
                    'name': 'Security',
                    'checkers': [
                        '-analyzer-checker=security',
                        '-analyzer-checker=unix',
                        '-analyzer-checker=core'
                    ]
                },
                {
                    'name': 'Memory',
                    'checkers': [
                        '-analyzer-checker=unix.Malloc',
                        '-analyzer-checker=core.NullDereference',
                        '-analyzer-checker=deadcode'
                    ]
                },
                {
                    'name': 'All',
                    'checkers': [
                        '-analyzer-checker=core,unix,security,deadcode,alpha'
                    ]
                }
            ]

            file_issues = []

            for config in configs:
                cmd = ['clang', '--analyze', '-Xclang', '-analyzer-output=text']

                for checker in config['checkers']:
                    cmd.extend(['-Xclang', checker])

                cmd.append(str(c_file))

                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

                    # Parse warnings from stderr
                    if result.stderr:
                        for line in result.stderr.split('\n'):
                            if 'warning:' in line or 'error:' in line:
                                issue = {
                                    'file': str(c_file.relative_to(self.test_dir)),
                                    'config': config['name'],
                                    'issue': line.strip()
                                }
                                file_issues.append(issue)
                                print(f"  [{config['name']}] Found: {line[:80]}...")

                except subprocess.TimeoutExpired:
                    print(f"  [{config['name']}] Timeout")
                except Exception as e:
                    print(f"  [{config['name']}] Error: {e}")

            all_issues.extend(file_issues)
            print(f"  Total issues in file: {len(file_issues)}")

        return all_issues

    def categorize_issues(self, issues):
        """Categorize issues by vulnerability type"""
        categories = {
            'buffer_overflow': [],
            'use_after_free': [],
            'null_pointer': [],
            'memory_leak': [],
            'integer_overflow': [],
            'format_string': [],
            'race_condition': [],
            'uninitialized': [],
            'other': []
        }

        for issue in issues:
            issue_text = issue['issue'].lower()

            if 'buffer' in issue_text or 'overflow' in issue_text or 'strcpy' in issue_text:
                categories['buffer_overflow'].append(issue)
            elif 'use' in issue_text and 'free' in issue_text:
                categories['use_after_free'].append(issue)
            elif 'null' in issue_text or 'dereference' in issue_text:
                categories['null_pointer'].append(issue)
            elif 'leak' in issue_text:
                categories['memory_leak'].append(issue)
            elif 'integer' in issue_text or 'overflow' in issue_text:
                categories['integer_overflow'].append(issue)
            elif 'format' in issue_text:
                categories['format_string'].append(issue)
            elif 'race' in issue_text or 'toctou' in issue_text:
                categories['race_condition'].append(issue)
            elif 'uninitialized' in issue_text:
                categories['uninitialized'].append(issue)
            else:
                categories['other'].append(issue)

        return categories

    def generate_report(self, issues):
        """Generate analysis report"""
        categories = self.categorize_issues(issues)

        report = {
            'timestamp': datetime.now().isoformat(),
            'total_issues': len(issues),
            'by_category': {k: len(v) for k, v in categories.items()},
            'details': categories
        }

        # Save JSON report
        report_file = Path("results/enhanced_clang_report.json")
        report_file.parent.mkdir(exist_ok=True)
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)

        # Print summary
        print("\n" + "="*70)
        print("CLANG STATIC ANALYZER - ENHANCED TEST RESULTS")
        print("="*70)

        print(f"\nTotal Issues Found: {len(issues)}")

        print("\nIssues by Category:")
        print("-"*40)
        for category, count in report['by_category'].items():
            if count > 0:
                print(f"  {category:20}: {count}")

        print("\nIssues by File:")
        print("-"*40)
        file_counts = {}
        for issue in issues:
            file = issue['file']
            file_counts[file] = file_counts.get(file, 0) + 1

        for file, count in sorted(file_counts.items()):
            print(f"  {file:40}: {count}")

        print(f"\n[OK] Report saved to: {report_file}")

        return report

def main():
    """Run enhanced Clang test"""
    tester = EnhancedClangTest()

    # Create test files
    tester.create_realistic_kernel_files()

    # Run analysis
    issues = tester.run_clang_analysis()

    # Generate report
    report = tester.generate_report(issues)

    print("\n" + "="*70)
    print("TEST COMPLETE")
    print("="*70)

    if len(issues) > 0:
        print("\n✓ Clang successfully detected vulnerabilities")
        print("✓ Test demonstrates Clang's detection capabilities")
    else:
        print("\n⚠ No issues detected - check Clang installation")

if __name__ == "__main__":
    main()