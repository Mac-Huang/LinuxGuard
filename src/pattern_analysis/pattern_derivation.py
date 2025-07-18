"""
Anti-Pattern Principle Derivation Engine
Extracts generalizable security patterns from filtered commits
"""
import os
import json
import re
from pathlib import Path
from typing import List, Dict, Any, Tuple, Set
from dataclasses import dataclass
from collections import defaultdict, Counter
import google.generativeai as genai
from loguru import logger
import networkx as nx
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans
import numpy as np


@dataclass
class AntiPattern:
    """Represents a derived anti-pattern"""
    pattern_id: str
    name: str
    category: str
    description: str
    vulnerability_type: str
    code_characteristics: List[str]
    detection_rules: List[str]
    example_commits: List[str]
    confidence_score: float
    affected_functions: List[str]
    clang_ast_patterns: List[str]


@dataclass
class CommitAnalysis:
    """Analysis of a single commit for pattern extraction"""
    commit_sha: str
    vulnerability_type: str
    root_cause: str
    fix_mechanism: str
    code_patterns: List[str]
    affected_constructs: List[str]
    generalization_potential: float


class PatternDerivationEngine:
    """Derives anti-patterns from filtered commits"""
    
    def __init__(self, api_key: str, model_name: str = "gemini-2.0-flash-exp"):
        self.api_key = api_key
        self.model_name = model_name
        
        # Initialize Gemini
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel(model_name)
        
        # Pattern storage
        self.commit_analyses = []
        self.derived_patterns = []
        self.pattern_clusters = {}
        
        logger.info(f"Initialized PatternDerivationEngine with {model_name}")
    
    def load_filtered_commits(self, commits_file: str = "data/test_commits/batches") -> List[Dict]:
        """Load filtered commits from Phase A"""
        commits = []
        batches_dir = Path(commits_file)
        
        if batches_dir.is_dir():
            # Load from batch files
            for batch_file in sorted(batches_dir.glob("batch_*.json")):
                with open(batch_file, 'r', encoding='utf-8') as f:
                    batch_data = json.load(f)
                    commits.extend(batch_data)
        else:
            # Load from single file
            with open(commits_file, 'r', encoding='utf-8') as f:
                commits = json.load(f)
        
        logger.info(f"Loaded {len(commits)} commits for pattern analysis")
        return commits
    
    def analyze_individual_commit(self, commit: Dict) -> CommitAnalysis:
        """Analyze individual commit to extract security patterns"""
        
        analysis_prompt = f"""Analyze this Linux kernel security fix commit for anti-pattern extraction:

**Commit**: {commit['sha'][:8]}
**Message**: {commit['message'][:500]}
**Files**: {', '.join(commit['files_changed'][:5])}
**Diff**: {commit['diff'][:2000]}

Provide detailed analysis in this JSON format:

```json
{{
  "vulnerability_type": "memory_leak|use_after_free|null_pointer|buffer_overflow|race_condition|deadlock|privilege_escalation|input_validation|other",
  "root_cause": "Brief description of what caused the vulnerability",
  "fix_mechanism": "How the fix addresses the issue",
  "code_patterns": ["Pattern 1", "Pattern 2", "Pattern 3"],
  "affected_constructs": ["function_calls", "memory_allocation", "locking", "error_handling", "validation"],
  "generalization_potential": 0.0-1.0
}}
```

Focus on:
1. **Root cause analysis**: What programming pattern led to the vulnerability?
2. **Fix mechanism**: How does the patch prevent the issue?
3. **Code patterns**: Specific code constructs involved
4. **Generalization**: How broadly applicable is this pattern?

Be precise and technical."""

        try:
            response = self.model.generate_content(analysis_prompt)
            
            if not response or not response.text:
                logger.warning(f"Empty response for commit {commit['sha'][:8]}")
                return self._create_fallback_analysis(commit)
            
            # Parse JSON response
            analysis_data = self._parse_llm_response(response.text)
            
            return CommitAnalysis(
                commit_sha=commit['sha'],
                vulnerability_type=analysis_data.get('vulnerability_type', 'other'),
                root_cause=analysis_data.get('root_cause', ''),
                fix_mechanism=analysis_data.get('fix_mechanism', ''),
                code_patterns=analysis_data.get('code_patterns', []),
                affected_constructs=analysis_data.get('affected_constructs', []),
                generalization_potential=float(analysis_data.get('generalization_potential', 0.5))
            )
            
        except Exception as e:
            logger.error(f"Error analyzing commit {commit['sha'][:8]}: {e}")
            return self._create_fallback_analysis(commit)
    
    def _parse_llm_response(self, response_text: str) -> Dict:
        """Parse LLM JSON response"""
        try:
            # Extract JSON from response
            json_pattern = r'```json\s*\n(.*?)\n\s*```'
            json_match = re.search(json_pattern, response_text, re.DOTALL)
            
            if json_match:
                json_str = json_match.group(1)
                return json.loads(json_str)
            else:
                # Try to parse entire response as JSON
                return json.loads(response_text)
                
        except Exception as e:
            logger.warning(f"Failed to parse LLM response: {e}")
            return {}
    
    def _create_fallback_analysis(self, commit: Dict) -> CommitAnalysis:
        """Create fallback analysis when LLM fails"""
        # Simple keyword-based analysis
        message = commit['message'].lower()
        
        vulnerability_type = 'other'
        if any(word in message for word in ['leak', 'memory']):
            vulnerability_type = 'memory_leak'
        elif any(word in message for word in ['null', 'pointer']):
            vulnerability_type = 'null_pointer'
        elif any(word in message for word in ['overflow', 'buffer']):
            vulnerability_type = 'buffer_overflow'
        elif any(word in message for word in ['race', 'lock']):
            vulnerability_type = 'race_condition'
        
        return CommitAnalysis(
            commit_sha=commit['sha'],
            vulnerability_type=vulnerability_type,
            root_cause="Fallback analysis - LLM unavailable",
            fix_mechanism="Unknown",
            code_patterns=["fallback_pattern"],
            affected_constructs=["unknown"],
            generalization_potential=0.3
        )
    
    def cluster_similar_patterns(self, analyses: List[CommitAnalysis]) -> Dict[str, List[CommitAnalysis]]:
        """Cluster similar vulnerability patterns using ML"""
        logger.info("Clustering similar anti-patterns...")
        
        # Create feature vectors from analyses
        features = []
        for analysis in analyses:
            feature_text = f"{analysis.vulnerability_type} {analysis.root_cause} {' '.join(analysis.code_patterns)}"
            features.append(feature_text)
        
        if len(features) < 3:
            # Too few samples for clustering
            return {"single_cluster": analyses}
        
        # TF-IDF vectorization
        vectorizer = TfidfVectorizer(max_features=100, stop_words='english')
        feature_matrix = vectorizer.fit_transform(features)
        
        # K-means clustering
        n_clusters = min(5, len(analyses) // 3)  # Adaptive cluster count
        if n_clusters < 2:
            return {"single_cluster": analyses}
        
        kmeans = KMeans(n_clusters=n_clusters, random_state=42)
        cluster_labels = kmeans.fit_predict(feature_matrix)
        
        # Group analyses by cluster
        clusters = defaultdict(list)
        for i, label in enumerate(cluster_labels):
            clusters[f"cluster_{label}"].append(analyses[i])
        
        logger.info(f"Created {len(clusters)} pattern clusters")
        return dict(clusters)
    
    def derive_generalized_patterns(self, cluster: List[CommitAnalysis]) -> AntiPattern:
        """Derive generalized anti-pattern from cluster of similar commits"""
        
        if not cluster:
            return None
        
        # Aggregate cluster information
        vulnerability_types = Counter(analysis.vulnerability_type for analysis in cluster)
        most_common_vuln = vulnerability_types.most_common(1)[0][0]
        
        all_patterns = []
        all_constructs = []
        for analysis in cluster:
            all_patterns.extend(analysis.code_patterns)
            all_constructs.extend(analysis.affected_constructs)
        
        pattern_counter = Counter(all_patterns)
        construct_counter = Counter(all_constructs)
        
        generalization_prompt = f"""Derive a generalized anti-pattern from these Linux kernel security issues:

**Vulnerability Type**: {most_common_vuln}
**Number of instances**: {len(cluster)}
**Common code patterns**: {dict(pattern_counter.most_common(5))}
**Affected constructs**: {dict(construct_counter.most_common(5))}

**Individual analyses**:
"""
        
        for i, analysis in enumerate(cluster[:5]):  # Limit to 5 examples
            generalization_prompt += f"""
{i+1}. **{analysis.commit_sha[:8]}**:
   - Root cause: {analysis.root_cause}
   - Fix: {analysis.fix_mechanism}
   - Patterns: {analysis.code_patterns[:3]}
"""
        
        generalization_prompt += f"""

Derive a generalized anti-pattern in this JSON format:

```json
{{
  "name": "Descriptive name for the anti-pattern",
  "category": "memory_management|concurrency|input_validation|error_handling|resource_management",
  "description": "Detailed description of the anti-pattern",
  "vulnerability_type": "{most_common_vuln}",
  "code_characteristics": ["Characteristic 1", "Characteristic 2", "Characteristic 3"],
  "detection_rules": ["Rule 1: Check for X", "Rule 2: Verify Y", "Rule 3: Validate Z"],
  "affected_functions": ["function_pattern_1", "function_pattern_2"],
  "clang_ast_patterns": ["AST pattern for Clang analysis"]
}}
```

Focus on creating **actionable detection rules** that can be implemented in static analysis tools."""

        try:
            response = self.model.generate_content(generalization_prompt)
            
            if not response or not response.text:
                return self._create_fallback_pattern(cluster, most_common_vuln)
            
            pattern_data = self._parse_llm_response(response.text)
            
            pattern_id = f"ap_{most_common_vuln}_{len(self.derived_patterns):03d}"
            
            return AntiPattern(
                pattern_id=pattern_id,
                name=pattern_data.get('name', f'Unknown Pattern {pattern_id}'),
                category=pattern_data.get('category', 'other'),
                description=pattern_data.get('description', ''),
                vulnerability_type=most_common_vuln,
                code_characteristics=pattern_data.get('code_characteristics', []),
                detection_rules=pattern_data.get('detection_rules', []),
                example_commits=[analysis.commit_sha[:8] for analysis in cluster[:3]],
                confidence_score=np.mean([analysis.generalization_potential for analysis in cluster]),
                affected_functions=pattern_data.get('affected_functions', []),
                clang_ast_patterns=pattern_data.get('clang_ast_patterns', [])
            )
            
        except Exception as e:
            logger.error(f"Error deriving pattern from cluster: {e}")
            return self._create_fallback_pattern(cluster, most_common_vuln)
    
    def _create_fallback_pattern(self, cluster: List[CommitAnalysis], vuln_type: str) -> AntiPattern:
        """Create fallback pattern when LLM fails"""
        pattern_id = f"ap_fallback_{len(self.derived_patterns):03d}"
        
        return AntiPattern(
            pattern_id=pattern_id,
            name=f"Fallback {vuln_type.replace('_', ' ').title()} Pattern",
            category="other",
            description=f"Fallback pattern for {vuln_type} vulnerabilities",
            vulnerability_type=vuln_type,
            code_characteristics=["fallback_characteristic"],
            detection_rules=[f"Check for {vuln_type} indicators"],
            example_commits=[analysis.commit_sha[:8] for analysis in cluster[:3]],
            confidence_score=0.3,
            affected_functions=["unknown"],
            clang_ast_patterns=["unknown"]
        )
    
    def run_pattern_derivation(self, commits_data: List[Dict] = None) -> List[AntiPattern]:
        """Main pipeline for deriving anti-patterns"""
        logger.info("Starting anti-pattern derivation pipeline...")
        
        # Load commits if not provided
        if commits_data is None:
            commits_data = self.load_filtered_commits()
        
        # Analyze individual commits
        logger.info("Analyzing individual commits...")
        analyses = []
        
        # Process in batches to avoid rate limits
        for i, commit in enumerate(commits_data[:20]):  # Limit for demo
            try:
                analysis = self.analyze_individual_commit(commit)
                analyses.append(analysis)
                logger.debug(f"Analyzed commit {i+1}/{min(20, len(commits_data))}: {commit['sha'][:8]}")
                
                # Rate limiting
                if i % 5 == 4:  # Every 5 commits
                    import time
                    time.sleep(2)
                    
            except Exception as e:
                logger.error(f"Error processing commit {commit['sha'][:8]}: {e}")
                continue
        
        self.commit_analyses = analyses
        logger.info(f"Completed analysis of {len(analyses)} commits")
        
        # Cluster similar patterns
        clusters = self.cluster_similar_patterns(analyses)
        self.pattern_clusters = clusters
        
        # Derive generalized patterns
        logger.info("Deriving generalized anti-patterns...")
        derived_patterns = []
        
        for cluster_name, cluster_analyses in clusters.items():
            if len(cluster_analyses) >= 2:  # Require at least 2 instances
                pattern = self.derive_generalized_patterns(cluster_analyses)
                if pattern:
                    derived_patterns.append(pattern)
                    logger.info(f"Derived pattern: {pattern.name}")
        
        self.derived_patterns = derived_patterns
        logger.info(f"Derived {len(derived_patterns)} anti-patterns")
        
        return derived_patterns
    
    def save_results(self, output_dir: str = "data/pattern_analysis"):
        """Save pattern derivation results"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Save commit analyses
        analyses_data = []
        for analysis in self.commit_analyses:
            analyses_data.append({
                'commit_sha': analysis.commit_sha,
                'vulnerability_type': analysis.vulnerability_type,
                'root_cause': analysis.root_cause,
                'fix_mechanism': analysis.fix_mechanism,
                'code_patterns': analysis.code_patterns,
                'affected_constructs': analysis.affected_constructs,
                'generalization_potential': analysis.generalization_potential
            })
        
        with open(output_path / "commit_analyses.json", 'w', encoding='utf-8') as f:
            json.dump(analyses_data, f, indent=2, ensure_ascii=False)
        
        # Save derived patterns
        patterns_data = []
        for pattern in self.derived_patterns:
            patterns_data.append({
                'pattern_id': pattern.pattern_id,
                'name': pattern.name,
                'category': pattern.category,
                'description': pattern.description,
                'vulnerability_type': pattern.vulnerability_type,
                'code_characteristics': pattern.code_characteristics,
                'detection_rules': pattern.detection_rules,
                'example_commits': pattern.example_commits,
                'confidence_score': pattern.confidence_score,
                'affected_functions': pattern.affected_functions,
                'clang_ast_patterns': pattern.clang_ast_patterns
            })
        
        with open(output_path / "derived_patterns.json", 'w', encoding='utf-8') as f:
            json.dump(patterns_data, f, indent=2, ensure_ascii=False)
        
        # Save cluster information
        cluster_data = {}
        for cluster_name, analyses in self.pattern_clusters.items():
            cluster_data[cluster_name] = [analysis.commit_sha for analysis in analyses]
        
        with open(output_path / "pattern_clusters.json", 'w', encoding='utf-8') as f:
            json.dump(cluster_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Results saved to {output_path}")
    
    def generate_summary_report(self) -> str:
        """Generate summary report of pattern derivation"""
        if not self.derived_patterns:
            return "No patterns derived yet. Run pattern derivation first."
        
        report = f"""# LinuxGuard Phase B: Anti-Pattern Derivation Report

## Summary
- **Commits analyzed**: {len(self.commit_analyses)}
- **Pattern clusters**: {len(self.pattern_clusters)}
- **Derived patterns**: {len(self.derived_patterns)}

## Derived Anti-Patterns

"""
        
        for i, pattern in enumerate(self.derived_patterns, 1):
            report += f"""### {i}. {pattern.name}

- **Category**: {pattern.category}
- **Vulnerability Type**: {pattern.vulnerability_type}
- **Confidence**: {pattern.confidence_score:.3f}
- **Examples**: {', '.join(pattern.example_commits)}

**Description**: {pattern.description}

**Detection Rules**:
"""
            for rule in pattern.detection_rules:
                report += f"- {rule}\n"
            
            report += "\n"
        
        return report


def main():
    """Test the pattern derivation engine"""
    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        logger.error("GOOGLE_API_KEY environment variable not set")
        return
    
    engine = PatternDerivationEngine(api_key)
    patterns = engine.run_pattern_derivation()
    
    engine.save_results()
    
    report = engine.generate_summary_report()
    print(report)


if __name__ == "__main__":
    main()