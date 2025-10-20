#!/usr/bin/env python3
"""
Evaluation Script for LinuxGuard Scan Results
Extracts and annotates detected issues for precision/recall analysis
"""

import json
import argparse
import shutil
from pathlib import Path
from typing import Dict, List, Tuple
from datetime import datetime
import textwrap
import re

class ResultsEvaluator:
    """Evaluates scan results for precision and recall analysis."""

    def __init__(self, scan_report_path: str, output_dir: str):
        self.scan_report_path = Path(scan_report_path)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Create subdirectories
        self.annotated_dir = self.output_dir / "annotated_files"
        self.annotated_dir.mkdir(exist_ok=True)
        self.dataset_dir = self.output_dir / "verification_dataset"
        self.dataset_dir.mkdir(exist_ok=True)

        # Load scan results
        with open(self.scan_report_path, 'r') as f:
            self.scan_data = json.load(f)

    def extract_and_annotate_files(self) -> Dict[str, List[Dict]]:
        """Extract buggy files and annotate them with error messages."""
        print("=== Extracting and Annotating Buggy Files ===\n")

        all_annotations = {}

        for version, version_data in self.scan_data["results_by_version"].items():
            if version_data["total_issues"] == 0:
                print(f"  {version}: No issues found, skipping...")
                continue

            print(f"\n  Processing {version} ({version_data['total_issues']} issues)...")
            version_dir = self.annotated_dir / version
            version_dir.mkdir(exist_ok=True)

            annotations = []

            # Group issues by file
            issues_by_file = {}
            for issue in version_data["issues"]:
                file_path = issue["file"]
                if file_path not in issues_by_file:
                    issues_by_file[file_path] = []
                issues_by_file[file_path].append(issue)

            for file_path, issues in issues_by_file.items():
                annotation_data = self._annotate_single_file(
                    file_path, issues, version_dir, version
                )
                if annotation_data:
                    annotations.append(annotation_data)

            all_annotations[version] = annotations
            print(f"    ✓ Annotated {len(issues_by_file)} files")

        return all_annotations

    def _annotate_single_file(self, file_path: str, issues: List[Dict],
                             output_dir: Path, version: str) -> Dict:
        """Annotate a single file with error messages."""
        file_path = Path(file_path)

        if not file_path.exists():
            print(f"    ⚠ File not found: {file_path}")
            return None

        # Read original file
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception as e:
            print(f"    ⚠ Error reading {file_path}: {e}")
            return None

        # Create annotated content
        annotated_lines = []
        issue_lines = {issue["line"]: issue for issue in issues}

        for line_num, line_content in enumerate(lines, 1):
            # Add the original line
            annotated_lines.append(line_content)

            # Add annotation if this line has an issue
            if line_num in issue_lines:
                issue = issue_lines[line_num]
                # Create annotation comment
                annotation = f"/* LINUXGUARD ISSUE: Line {line_num}, Column {issue['column']}\n"
                annotation += f" * Checker: {issue['checker']}\n"
                annotation += f" * Message: {issue['message']}\n"
                annotation += " */\n"
                annotated_lines.append(annotation)

        # Save annotated file
        relative_path = file_path.relative_to(Path("/nvme/write/mac/private/linux-guard/kernels") / version)
        output_path = output_dir / f"{relative_path.stem}_annotated{relative_path.suffix}"
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, 'w') as f:
            f.writelines(annotated_lines)

        # Return annotation metadata
        return {
            "original_file": str(file_path),
            "annotated_file": str(output_path),
            "relative_path": str(relative_path),
            "issues": issues,
            "total_lines": len(lines),
            "context_extraction": self._extract_context(lines, issues)
        }

    def _extract_context(self, lines: List[str], issues: List[Dict],
                        context_lines: int = 5) -> List[Dict]:
        """Extract context around each issue for verification."""
        contexts = []

        for issue in issues:
            line_num = issue["line"]
            start = max(0, line_num - context_lines - 1)
            end = min(len(lines), line_num + context_lines)

            context = {
                "issue_line": line_num,
                "issue_column": issue["column"],
                "message": issue["message"],
                "checker": issue["checker"],
                "code_before": "".join(lines[start:line_num-1]),
                "issue_code": lines[line_num-1] if line_num-1 < len(lines) else "",
                "code_after": "".join(lines[line_num:end])
            }
            contexts.append(context)

        return contexts

    def generate_verification_dataset(self, annotations: Dict[str, List[Dict]]):
        """Generate JSON dataset for automated verification."""
        print("\n=== Generating Verification Dataset ===\n")

        dataset = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "scan_report": str(self.scan_report_path),
                "total_issues": sum(len(ann) for ann in annotations.values()),
                "checkers_used": list(set(
                    issue["checker"]
                    for version_anns in annotations.values()
                    for ann in version_anns
                    for issue in ann["issues"]
                ))
            },
            "verification_items": []
        }

        # Create verification items
        item_id = 0
        for version, version_annotations in annotations.items():
            for file_annotation in version_annotations:
                for context in file_annotation["context_extraction"]:
                    item_id += 1
                    item = {
                        "id": item_id,
                        "kernel_version": version,
                        "file": file_annotation["relative_path"],
                        "line": context["issue_line"],
                        "column": context["issue_column"],
                        "checker": context["checker"],
                        "message": context["message"],
                        "code_context": {
                            "before": context["code_before"],
                            "issue_line": context["issue_code"],
                            "after": context["code_after"]
                        },
                        "verification_prompt": self._create_verification_prompt(context),
                        "verification_status": "pending",  # To be filled by verification
                        "is_true_positive": None,  # To be determined
                        "confidence_score": None,  # LLM confidence
                        "explanation": None  # LLM explanation
                    }
                    dataset["verification_items"].append(item)

        # Save dataset
        dataset_path = self.dataset_dir / "verification_dataset.json"
        with open(dataset_path, 'w') as f:
            json.dump(dataset, f, indent=2)

        print(f"  ✓ Generated dataset with {len(dataset['verification_items'])} items")
        print(f"  ✓ Saved to: {dataset_path}")

        return dataset

    def _create_verification_prompt(self, context: Dict) -> str:
        """Create a prompt for LLM verification of the issue."""
        prompt = f"""Analyze the following code for a potential bug:

Issue reported by checker '{context['checker']}':
"{context['message']}"

Code context (issue is at marked line):
```c
{context['code_before']}
>>> {context['issue_code'].rstrip()}  // <-- ISSUE REPORTED HERE
{context['code_after']}
```

Questions:
1. Is this a real bug/vulnerability? (YES/NO)
2. What is the potential impact if this is a bug?
3. Could this lead to security issues?
4. Confidence level (0-100%)?

Please provide a brief analysis."""

        return prompt

    def create_manual_verification_helper(self, dataset: Dict):
        """Create helper files for manual verification."""
        print("\n=== Creating Manual Verification Helper ===\n")

        # Create HTML viewer for easy manual review
        html_path = self.dataset_dir / "manual_verification.html"
        html_content = self._generate_html_viewer(dataset)

        with open(html_path, 'w') as f:
            f.write(html_content)

        print(f"  ✓ Created HTML viewer: {html_path}")

        # Create markdown report for copy-paste to web LLMs
        md_path = self.dataset_dir / "verification_prompts.md"
        md_content = self._generate_markdown_prompts(dataset)

        with open(md_path, 'w') as f:
            f.write(md_content)

        print(f"  ✓ Created markdown prompts: {md_path}")

        # Create batch verification script
        script_path = self.dataset_dir / "batch_verify.py"
        script_content = self._generate_batch_script()

        with open(script_path, 'w') as f:
            f.write(script_content)

        script_path.chmod(0o755)
        print(f"  ✓ Created batch verification script: {script_path}")

    def _generate_html_viewer(self, dataset: Dict) -> str:
        """Generate HTML viewer for manual verification."""
        html = """<!DOCTYPE html>
<html>
<head>
    <title>LinuxGuard Manual Verification</title>
    <style>
        body { font-family: monospace; margin: 20px; }
        .item { border: 1px solid #ccc; margin: 10px 0; padding: 10px; }
        .metadata { background: #f0f0f0; padding: 5px; }
        .code { background: #f8f8f8; padding: 10px; overflow-x: auto; }
        .issue-line { background: #ffdddd; font-weight: bold; }
        .verdict { margin: 10px 0; padding: 10px; border: 1px dashed #999; }
        .true-positive { background: #ddffdd; }
        .false-positive { background: #ffdddd; }
        button { margin: 5px; padding: 5px 10px; }
    </style>
</head>
<body>
    <h1>LinuxGuard Detection Manual Verification</h1>
    <p>Total items to verify: """ + str(len(dataset["verification_items"])) + """</p>
    <hr>
"""

        for item in dataset["verification_items"]:
            html += f"""
    <div class="item" id="item-{item['id']}">
        <div class="metadata">
            <strong>Item #{item['id']}</strong> |
            {item['kernel_version']} |
            {item['file']}:{item['line']}:{item['column']} |
            Checker: {item['checker']}
        </div>
        <div class="message"><strong>Issue:</strong> {item['message']}</div>
        <div class="code">
            <pre>{item['code_context']['before']}<span class="issue-line">&gt;&gt;&gt; {item['code_context']['issue_line']}</span>{item['code_context']['after']}</pre>
        </div>
        <div class="verdict">
            <button onclick="markItem({item['id']}, true)">✓ True Positive</button>
            <button onclick="markItem({item['id']}, false)">✗ False Positive</button>
            <span id="status-{item['id']}"></span>
        </div>
    </div>
"""

        html += """
    <script>
        function markItem(id, isTrue) {
            document.getElementById('status-' + id).innerHTML =
                isTrue ? '<span class="true-positive">Marked as TRUE POSITIVE</span>' :
                         '<span class="false-positive">Marked as FALSE POSITIVE</span>';
            // Store in localStorage for later export
            localStorage.setItem('item-' + id, isTrue);
        }

        function exportResults() {
            let results = {};
            for (let i = 0; i < localStorage.length; i++) {
                let key = localStorage.key(i);
                if (key.startsWith('item-')) {
                    results[key] = localStorage.getItem(key) === 'true';
                }
            }
            console.log(JSON.stringify(results, null, 2));
            alert('Results exported to console (F12)');
        }
    </script>
    <hr>
    <button onclick="exportResults()">Export Results to Console</button>
</body>
</html>"""

        return html

    def _generate_markdown_prompts(self, dataset: Dict) -> str:
        """Generate markdown with prompts for copy-paste to web LLMs."""
        md = f"""# LinuxGuard Verification Prompts

Generated: {datetime.now().isoformat()}
Total Issues: {len(dataset['verification_items'])}

## Instructions

Copy each prompt below to your preferred LLM (ChatGPT, Claude, etc.) for verification.
Record the response for precision/recall analysis.

---

"""

        for item in dataset["verification_items"][:10]:  # Limit to first 10 for manual review
            md += f"""## Item #{item['id']} - {item['kernel_version']} - {item['file']}:{item['line']}

{item['verification_prompt']}

---

"""

        if len(dataset['verification_items']) > 10:
            md += f"\n*Note: Showing first 10 of {len(dataset['verification_items'])} items. See JSON for complete dataset.*\n"

        return md

    def _generate_batch_script(self) -> str:
        """Generate Python script for batch verification."""
        return '''#!/usr/bin/env python3
"""
Batch verification script for LinuxGuard results
This can be extended to use various LLM APIs for automated verification
"""

import json
from pathlib import Path

def verify_with_llm(item):
    """
    Placeholder for LLM verification.
    Replace with actual API call to your preferred LLM.
    """
    # Example structure for various LLM APIs:

    # OpenAI API example:
    # response = openai.Completion.create(
    #     model="gpt-4",
    #     prompt=item["verification_prompt"],
    #     max_tokens=200
    # )

    # Anthropic Claude example:
    # response = anthropic.Completion.create(
    #     model="claude-3",
    #     prompt=item["verification_prompt"],
    #     max_tokens=200
    # )

    # For now, return placeholder
    return {
        "is_true_positive": None,
        "confidence": 0.0,
        "explanation": "Manual verification required"
    }

def main():
    # Load dataset
    dataset_path = Path(__file__).parent / "verification_dataset.json"
    with open(dataset_path, 'r') as f:
        dataset = json.load(f)

    results = []
    for item in dataset["verification_items"]:
        print(f"Verifying item #{item['id']}...")

        # Verify with LLM
        verification = verify_with_llm(item)

        # Update item with verification results
        item["verification_status"] = "verified"
        item["is_true_positive"] = verification["is_true_positive"]
        item["confidence_score"] = verification["confidence"]
        item["explanation"] = verification["explanation"]

        results.append(item)

    # Calculate metrics
    true_positives = sum(1 for r in results if r["is_true_positive"] == True)
    false_positives = sum(1 for r in results if r["is_true_positive"] == False)
    pending = sum(1 for r in results if r["is_true_positive"] is None)

    print(f"\\nResults:")
    print(f"  True Positives: {true_positives}")
    print(f"  False Positives: {false_positives}")
    print(f"  Pending: {pending}")

    if true_positives + false_positives > 0:
        precision = true_positives / (true_positives + false_positives) * 100
        print(f"  Precision: {precision:.2f}%")

    # Save results
    output_path = Path(__file__).parent / "verification_results.json"
    with open(output_path, 'w') as f:
        json.dump({
            "dataset": dataset,
            "metrics": {
                "true_positives": true_positives,
                "false_positives": false_positives,
                "pending": pending,
                "precision": precision if true_positives + false_positives > 0 else None
            }
        }, f, indent=2)

    print(f"\\nResults saved to: {output_path}")

if __name__ == "__main__":
    main()
'''

    def calculate_metrics(self, verification_results: Dict):
        """Calculate precision and recall metrics."""
        print("\n=== Calculating Metrics ===\n")

        # This would be filled after verification
        true_positives = 0
        false_positives = 0
        false_negatives = 0  # Would need ground truth to determine

        for item in verification_results.get("verification_items", []):
            if item.get("is_true_positive") == True:
                true_positives += 1
            elif item.get("is_true_positive") == False:
                false_positives += 1

        if true_positives + false_positives > 0:
            precision = true_positives / (true_positives + false_positives)
            print(f"  Precision: {precision:.2%}")
        else:
            print("  Precision: N/A (no verified items)")

        # Recall calculation would require knowing all actual bugs
        print("  Recall: Requires ground truth dataset")

        print(f"\n  Summary:")
        print(f"    True Positives: {true_positives}")
        print(f"    False Positives: {false_positives}")
        print(f"    Unverified: {len(verification_results.get('verification_items', [])) - true_positives - false_positives}")

def main():
    parser = argparse.ArgumentParser(description='Evaluate LinuxGuard scan results')

    base_dir = Path(__file__).parent.parent

    parser.add_argument('--scan-report',
                      default=str(base_dir / 'results/scan_report.json'),
                      help='Path to scan report JSON')
    parser.add_argument('--output-dir',
                      default=str(base_dir / 'results/evaluation'),
                      help='Directory for evaluation output')
    parser.add_argument('--limit', type=int,
                      help='Limit number of files to process (for testing)')

    args = parser.parse_args()

    print("=== LinuxGuard Results Evaluation Tool ===\n")

    # Initialize evaluator
    evaluator = ResultsEvaluator(args.scan_report, args.output_dir)

    # Extract and annotate files
    annotations = evaluator.extract_and_annotate_files()

    # Generate verification dataset
    dataset = evaluator.generate_verification_dataset(annotations)

    # Create manual verification helpers
    evaluator.create_manual_verification_helper(dataset)

    print("\n=== Evaluation Complete ===")
    print(f"\nOutput directory: {args.output_dir}")
    print("\nNext steps:")
    print("1. Review annotated files in: evaluation/annotated_files/")
    print("2. Use verification dataset for automated LLM validation")
    print("3. Open manual_verification.html for web-based review")
    print("4. Run batch_verify.py with your LLM API for automated verification")
    print("5. Copy prompts from verification_prompts.md for manual LLM queries")

if __name__ == "__main__":
    main()