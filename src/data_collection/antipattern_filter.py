"""
Anti-Pattern Filtering System
Uses LLMs with RAG context to identify commits that fix anti-patterns
"""
import os
import json
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional
from dataclasses import dataclass
import google.generativeai as genai
from loguru import logger
from tqdm import tqdm
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from linux_docs_rag import LinuxDocsRAG
from commit_processor import CommitInfo, CommitProcessor


@dataclass
class AntiPatternResult:
    """Result of anti-pattern analysis"""
    commit_sha: str
    is_antipattern: bool
    confidence: float
    pattern_type: str
    description: str
    reasoning: str


class AntiPatternFilter:
    def __init__(self, api_key: str, model_name: str = "gemini-2.0-flash-exp"):
        """Initialize anti-pattern filter with LLM"""
        self.api_key = api_key
        self.model_name = model_name
        
        # Initialize Gemini
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel(model_name)
        
        # Initialize RAG system
        self.rag = LinuxDocsRAG()
        
        # Ensure RAG database is populated
        if self.rag.collection.count() == 0:
            logger.info("Populating RAG database...")
            self.rag.populate_vector_db()
        
        logger.info(f"Initialized AntiPatternFilter with {model_name}")
    
    def create_analysis_prompt(self, batch_formatted: str, linux_context: str) -> str:
        """Create comprehensive prompt for anti-pattern analysis"""
        
        prompt = f"""You are an expert Linux kernel security researcher analyzing commits for anti-patterns.

## Linux Kernel Context & Guidelines:
{linux_context}

## Anti-Pattern Categories to Look For:

1. **Memory Management Anti-Patterns:**
   - Memory leaks (missing kfree, put_page, etc.)
   - Use-after-free vulnerabilities
   - Double-free issues
   - Missing NULL checks before dereference
   - Buffer overflows/underflows
   - Improper memory ordering

2. **Locking Anti-Patterns:**
   - Deadlock scenarios (lock ordering violations)
   - Missing unlock operations
   - Lock imbalance (acquire without release)
   - Race conditions in critical sections
   - Improper RCU usage

3. **Resource Management Anti-Patterns:**
   - File descriptor leaks
   - Missing cleanup in error paths
   - Incomplete initialization
   - Reference counting errors
   - Missing error propagation

4. **Concurrency Anti-Patterns:**
   - Unprotected shared data access
   - Missing memory barriers
   - Improper atomic operations
   - Signal handling issues

5. **Input Validation Anti-Patterns:**
   - Missing bounds checking
   - Integer overflow/underflow
   - Unvalidated user input
   - TOCTOU (Time-of-Check-Time-of-Use) issues

## Commits to Analyze:
{batch_formatted}

## Analysis Instructions:

For EACH commit, determine:
1. **Is this commit fixing an anti-pattern?** (Yes/No)
2. **Confidence level** (0.0-1.0)
3. **Primary anti-pattern category** (from list above)
4. **Brief description** of the anti-pattern being fixed
5. **Reasoning** for your classification

## Output Format:

For each commit, provide analysis in this EXACT JSON format:

```json
{{
  "commit_sha": "abc123...",
  "is_antipattern": true/false,
  "confidence": 0.0-1.0,
  "pattern_type": "Memory Management/Locking/Resource Management/Concurrency/Input Validation/Other",
  "description": "Brief description of the anti-pattern",
  "reasoning": "Explanation of why this is/isn't an anti-pattern fix"
}}
```

## Important Guidelines:

- Focus on commits that FIX anti-patterns, not introduce them
- Look for keywords like "fix", "prevent", "avoid", "check", "validate"
- Consider the diff content, not just the commit message
- Be conservative: if unsure, mark confidence < 0.7
- Prioritize kernel-specific patterns over generic programming issues
- Consider the Linux kernel coding style and conventions

Analyze ALL commits in the batch and provide JSON output for each.
"""
        return prompt
    
    def parse_llm_response(self, response_text: str, batch: List[CommitInfo]) -> List[AntiPatternResult]:
        """Parse LLM response and extract anti-pattern results"""
        results = []
        
        # Try to extract JSON blocks from response
        json_pattern = r'```json\s*\n(.*?)\n\s*```'
        json_matches = re.findall(json_pattern, response_text, re.DOTALL)
        
        if json_matches:
            for json_str in json_matches:
                try:
                    data = json.loads(json_str)
                    result = AntiPatternResult(
                        commit_sha=data.get('commit_sha', ''),
                        is_antipattern=data.get('is_antipattern', False),
                        confidence=float(data.get('confidence', 0.0)),
                        pattern_type=data.get('pattern_type', 'Unknown'),
                        description=data.get('description', ''),
                        reasoning=data.get('reasoning', '')
                    )
                    results.append(result)
                except Exception as e:
                    logger.warning(f"Failed to parse JSON response: {e}")
        
        # If JSON parsing fails, try to extract information manually
        if not results:
            logger.warning("JSON parsing failed, attempting manual extraction")
            # This would be a fallback parser - simplified for now
            for commit in batch:
                if "fix" in response_text.lower() and commit.sha[:8] in response_text:
                    results.append(AntiPatternResult(
                        commit_sha=commit.sha,
                        is_antipattern=True,
                        confidence=0.5,
                        pattern_type="Unknown",
                        description="Manual extraction - requires review",
                        reasoning="Fallback parsing due to JSON format issues"
                    ))
        
        return results
    
    def analyze_batch(self, batch: List[CommitInfo], batch_formatted: str) -> List[AntiPatternResult]:
        """Analyze a batch of commits for anti-patterns"""
        try:
            # Get Linux-specific context from RAG
            commit_diffs = [commit.diff[:500] for commit in batch]  # Truncate for context
            linux_context = self.rag.get_antipattern_context(commit_diffs)
            
            # Create analysis prompt
            prompt = self.create_analysis_prompt(batch_formatted, linux_context)
            
            # Call LLM
            logger.debug(f"Analyzing batch of {len(batch)} commits...")
            response = self.model.generate_content(prompt)
            
            if not response or not response.text:
                logger.error("Empty response from LLM")
                return []
            
            # Parse results
            results = self.parse_llm_response(response.text, batch)
            
            logger.info(f"Analyzed batch: {len(results)} results, {sum(1 for r in results if r.is_antipattern)} anti-patterns found")
            
            return results
            
        except Exception as e:
            logger.error(f"Error analyzing batch: {e}")
            return []
    
    def filter_antipatterns(self, batches: List[List[CommitInfo]], max_workers: int = 3) -> List[AntiPatternResult]:
        """Process all batches and filter for anti-patterns"""
        all_results = []
        
        logger.info(f"Starting anti-pattern filtering for {len(batches)} batches...")
        
        # Process batches with rate limiting
        for i, batch in enumerate(tqdm(batches, desc="Processing batches")):
            try:
                # Create formatted content for this batch
                processor = CommitProcessor("")  # Empty path since we're not using repo here
                batch_formatted = processor.format_batch_for_llm(batch)
                
                # Analyze batch
                results = self.analyze_batch(batch, batch_formatted)
                all_results.extend(results)
                
                # Rate limiting - wait between requests
                if i < len(batches) - 1:  # Don't wait after last batch
                    time.sleep(2)  # 2 second delay between batches
                
            except Exception as e:
                logger.error(f"Error processing batch {i}: {e}")
                continue
        
        # Filter for actual anti-patterns
        antipattern_results = [r for r in all_results if r.is_antipattern and r.confidence >= 0.6]
        
        logger.info(f"Filtering complete: {len(antipattern_results)} anti-patterns found out of {len(all_results)} analyzed")
        
        return antipattern_results
    
    def save_results(self, results: List[AntiPatternResult], output_file: str = "data/commits/antipattern_results.json"):
        """Save anti-pattern analysis results"""
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Convert to serializable format
        serializable_results = []
        for result in results:
            serializable_results.append({
                'commit_sha': result.commit_sha,
                'is_antipattern': result.is_antipattern,
                'confidence': result.confidence,
                'pattern_type': result.pattern_type,
                'description': result.description,
                'reasoning': result.reasoning
            })
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(serializable_results, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Saved {len(results)} results to {output_path}")
    
    def load_results(self, input_file: str = "data/commits/antipattern_results.json") -> List[AntiPatternResult]:
        """Load previously saved results"""
        input_path = Path(input_file)
        if not input_path.exists():
            return []
        
        with open(input_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        results = []
        for item in data:
            result = AntiPatternResult(
                commit_sha=item['commit_sha'],
                is_antipattern=item['is_antipattern'],
                confidence=item['confidence'],
                pattern_type=item['pattern_type'],
                description=item['description'],
                reasoning=item['reasoning']
            )
            results.append(result)
        
        logger.info(f"Loaded {len(results)} results from {input_path}")
        return results
    
    def generate_summary_report(self, results: List[AntiPatternResult]) -> str:
        """Generate summary report of anti-pattern analysis"""
        antipatterns = [r for r in results if r.is_antipattern]
        
        # Category breakdown
        categories = {}
        for result in antipatterns:
            cat = result.pattern_type
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(result)
        
        report = f"""# LinuxGuard Anti-Pattern Analysis Report

## Summary
- **Total commits analyzed:** {len(results)}
- **Anti-patterns identified:** {len(antipatterns)}
- **Detection rate:** {len(antipatterns)/len(results)*100:.1f}%

## Anti-Pattern Categories:
"""
        
        for category, items in sorted(categories.items()):
            avg_confidence = sum(r.confidence for r in items) / len(items)
            report += f"- **{category}:** {len(items)} patterns (avg confidence: {avg_confidence:.2f})\n"
        
        report += f"\n## High-Confidence Detections (≥0.8):\n"
        high_conf = [r for r in antipatterns if r.confidence >= 0.8]
        for result in high_conf[:10]:  # Top 10
            report += f"- `{result.commit_sha[:8]}`: {result.description} (confidence: {result.confidence:.2f})\n"
        
        return report


def main():
    """Test the anti-pattern filter"""
    # Load API key
    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        logger.error("GOOGLE_API_KEY environment variable not set")
        return
    
    # Initialize filter
    filter_system = AntiPatternFilter(api_key)
    
    # Load batches (assuming they exist from previous step)
    processor = CommitProcessor("../KNighter/linux")
    batches = processor.load_batches()
    
    if not batches:
        logger.error("No batches found. Run commit_processor.py first.")
        return
    
    # Test with first few batches
    test_batches = batches[:2]  # Test with 2 batches
    results = filter_system.filter_antipatterns(test_batches)
    
    # Save results
    filter_system.save_results(results)
    
    # Generate report
    report = filter_system.generate_summary_report(results)
    print(report)


if __name__ == "__main__":
    main()