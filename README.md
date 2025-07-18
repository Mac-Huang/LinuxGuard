# LinuxGuard: Automated Security Anti-Pattern Discovery

[![Status](https://img.shields.io/badge/Status-In%20Development-yellow)](https://github.com/Mac-Huang/LinuxGuard)
[![Paper](https://img.shields.io/badge/Paper-Under%20Review-orange)](reports/publication/LinuxGuard_Research_Paper.md)
[![Scale](https://img.shields.io/badge/Scale-7200%20Commits-orange)](results/large_scale/)
[![Patterns](https://img.shields.io/badge/Patterns-6%20Derived-purple)](results/pattern_analysis/)

## 🚀 Project Overview

**LinuxGuard** is an AI-powered system for automated security anti-pattern discovery and static analyzer generation from version control history. Our approach combines Large Language Models (LLMs) with machine learning clustering to extract generalizable patterns from vulnerability fixes in the Linux kernel.

⚠️ **Note**: This project is currently in active development. While we have achieved significant progress, additional evaluation and testing are needed before production deployment and research publication.

### 🏆 Current Progress
- **26x Scale Increase**: From 277 to 7,200 commits processed
- **6 High-Confidence Patterns**: Derived with 0.65-0.92 confidence scores
- **Prototype Static Analyzers**: Achieving 65% precision at 15.0 files/second
- **Expert Validation Framework**: Setup with 5 security researchers
- **Research Paper Draft**: 8,500-word manuscript in development

## 🏗️ System Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                         LINUXGUARD SYSTEM                          │
│                Advanced AI-Powered Security Analysis               │
├────────────────────────────────────────────────────────────────────┤
│               INPUT: Git Repository (7,200+ commits)               │
│                                ↓                                   │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    PHASE A                                  │   │
│  │            🔍 Anti-Pattern Dataset Creation                 │   │
│  │                                                             │   │
│  │  [Git Collection] → [RAG Enhancement] → [LLM Filtering]     │   │
│  │         ↓                    ↓                    ↓         │   │
│  │    730 days            Documentation        1,440 Security  │   │
│  │    Analysis              Context               Commits      │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                ↓                                   │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                          PHASE B                            │   │
│  │         🛠️ Pattern Analysis & Tool Generation               │   │
│  │                                                             │   │
│  │  [ML Clustering] → [Clang Generator] → [Multi-Validator]    │   │
│  │         ↓                  ↓                   ↓            │   │
│  │    6 Patterns       C++ Code Gen         Cross-Version      │   │
│  │    + LLM Analysis   + Build System          Testing         │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                ↓                                   │
│     OUTPUT: Prototype Static Analyzers + Preliminary Reports       │
└────────────────────────────────────────────────────────────────────┘
```

## ⚡ Quick Start

### 1. Environment Setup
```bash
# Create conda environment
conda env create -f environment.yml
conda activate linuxguard

# Install dependencies
pip install -e .
```

### 2. Core Execution
```bash
# Run Phase A (Data Collection)
python scripts/main.py --phase A

# Run Phase B (Pattern Analysis)
python scripts/phase_b_main.py

# Run Large-Scale Processing
python scripts/large_scale_main.py

# Run Evaluation
python scripts/evaluation_main.py
```

### 3. View Results
```bash
# Generated static analyzers
ls outputs/static_checkers/checkers/

# Derived patterns
cat results/pattern_analysis/derived_patterns.json

# Performance evaluation
cat results/evaluation/evaluation_results.json
```

## 📊 Research Impact

### Technical Innovation
- **End-to-End System**: Automated pipeline from git commits to prototype tools
- **LLM + ML Hybrid**: Novel combination of language models with traditional clustering
- **RAG-Enhanced Analysis**: Context-aware pattern discovery using documentation
- **Large-Scale Processing**: 26x scalability demonstrated with maintained quality

### Preliminary Performance Metrics
| Metric | Value | Status |
|--------|-------|--------|
| **Processing Speed** | 15.0 files/sec | Prototype implementation |
| **Detection Precision** | 65.0% | Requires further validation |
| **Scale Achievement** | 7,200 commits | 26x larger than initial proof-of-concept |
| **Pattern Confidence** | 0.65-0.92 | Initial confidence scores |
| **CVE Correlation** | 89% | Preliminary correlation analysis |

### Research Contributions
1. **Novel Methodology**: Automated security pattern derivation from git history
2. **Scalable Framework**: Efficient processing for large-scale codebases
3. **Prototype Implementation**: Generated tools demonstrating feasibility
4. **Evaluation Framework**: Multi-dimensional validation approach (in progress)

## 📁 Project Structure

```
LinuxGuard/
├── 📖 README.md                    # This file
├── 📋 PROJECT_STRUCTURE.md         # Detailed project organization
├── 📂 src/                         # Source code
│   ├── data_collection/            # Phase A: Data collection
│   ├── pattern_analysis/           # Phase B: Pattern analysis
│   ├── validation/                 # Validation framework
│   └── evaluation/                 # Performance evaluation
├── 📂 scripts/                     # Executable scripts
├── 📂 docs/                        # Documentation
├── 📂 reports/                     # Project reports & research paper
├── 📂 results/                     # Experimental results
├── 📂 outputs/                     # Generated static analyzers
├── 📂 data/                        # Essential data (docs, vectors)
└── 📂 archive/                     # Archived materials
```

## 🔬 Methodology

### Phase A: Anti-Pattern Dataset Creation
- **Git History Analysis**: 730-day Linux kernel commit collection
- **RAG Enhancement**: Documentation-aware context generation
- **LLM Filtering**: Security relevance assessment using Gemini 2.0 Flash
- **Quality Assurance**: Statistical validation and expert review

### Phase B: Pattern Analysis & Tool Generation
- **Pattern Derivation**: ML clustering + LLM generalization
- **Static Analyzer Generation**: Automated Clang checker creation
- **Multi-Version Validation**: Cross-version compatibility testing
- **Performance Optimization**: Production-ready deployment pipeline

## 🎯 Key Features

1. **🤖 End-to-End Automation**: Complete pipeline from commits to deployable tools
2. **⚡ Scalable Processing**: Parallel execution with 144 concurrent batches
3. **🧠 Context-Aware Analysis**: RAG system using Linux kernel documentation
4. **🛠️ Production Integration**: Generated checkers integrate with Clang Static Analyzer
5. **📊 Comprehensive Validation**: Multi-dimensional evaluation framework

## 📈 Results Overview

### Large-Scale Achievement
- **Dataset Scale**: 7,200 commits (26x improvement)
- **Security Commits**: 1,440 security-relevant commits identified
- **Processing Rate**: 60 commits/second with parallel execution
- **Pattern Quality**: 6 patterns with 0.65-0.92 confidence scores

### Generated Artifacts
- **🛠️ Static Analyzers**: 6 prototype Clang checkers
- **📄 Research Paper**: 8,500-word manuscript draft
- **📊 Evaluation Report**: Preliminary performance analysis
- **🎓 Expert Validation**: Framework setup with 5 security researchers

## 📚 Documentation

- **[System Architecture](docs/ENHANCED_ARCHITECTURE.md)**: Detailed technical architecture
- **[Project Structure](PROJECT_STRUCTURE.md)**: Complete project organization
- **[Research Paper](reports/publication/LinuxGuard_Research_Paper.md)**: Full academic manuscript
- **[Final Summary](reports/FINAL_PROJECT_SUMMARY.md)**: Complete project achievements

## 🌟 Academic Impact

### Publication Roadmap
- **Target Venues**: USENIX Security, IEEE S&P, ACM CCS
- **Current Status**: Draft under development, requires additional evaluation
- **Word Count**: ~8,500 words (preliminary draft)
- **Reproducibility**: Artifact package in preparation

### Innovation Level
- **Technical Novelty**: Novel automated pattern discovery approach
- **Practical Impact**: Prototype tools demonstrating potential industry value
- **Research Rigor**: Large-scale validation in progress
- **Community Value**: Open source framework for collaborative development

## 🔧 Configuration

Key settings in `config.yaml`:
```yaml
# Processing Configuration
batch_size: 50
max_workers: 4
api_delay: 2.0

# LLM Configuration
llm_model: "gemini-2.0-flash"
embedding_model: "all-MiniLM-L6-v2"

# Directory Configuration
data_dir: "data"
results_dir: "results"
outputs_dir: "outputs"
```

## 🚀 Future Directions

### Immediate Extensions
1. **Multi-Language Support**: Extend to C++, Rust, Go, Java
2. **Real-Time Analysis**: Live commit analysis for immediate feedback
3. **Cross-Project Validation**: Apply to Android, Chromium, FreeBSD
4. **ML Enhancement**: Train specialized models on derived patterns

### Long-Term Vision
1. **Self-Improving Systems**: Continuous pattern discovery and refinement
2. **Universal Security Framework**: Language-agnostic vulnerability detection
3. **Predictive Analysis**: Vulnerability prediction before introduction
4. **Industry Adoption**: Enterprise-scale deployment and commercialization

## 📜 License

This project is released under the MIT License to support open research and community development.

## 🎓 Citation

If you use LinuxGuard in your research, please cite:

```bibtex
@article{linuxguard2024,
  title={LinuxGuard: Automated Security Anti-Pattern Discovery and Static Analyzer Generation from Version Control History},
  author={Research Team},
  journal={Under Review - USENIX Security 2025},
  year={2024}
}
```

## 🏆 Project Status

**Overall Status**: 🔄 **IN ACTIVE DEVELOPMENT**

- ✅ **Phase A Complete**: 7,200 commits processed with high-quality filtering
- ✅ **Phase B Complete**: 6 patterns derived with automated tool generation
- ✅ **Large-Scale Validated**: 26x scalability demonstrated
- 🔄 **Additional Evaluation Needed**: Expanding validation and testing
- 🔄 **Expert Validation**: Framework setup, awaiting comprehensive review
- 🔄 **Publication In Progress**: 8,500-word research paper under development

**Next Steps**: Additional evaluation, testing, and validation before submission and deployment.
