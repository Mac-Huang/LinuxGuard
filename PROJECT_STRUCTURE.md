# LinuxGuard Project Structure

## 📁 Directory Organization

```
LinuxGuard/
├── 📖 README.md                    # Main project documentation
├── 📋 PROJECT_STRUCTURE.md         # This file - project organization guide
├── ⚙️ setup.py                     # Package setup and dependencies
├── 🔧 config.yaml                  # Configuration settings
├── 📦 environment.yml              # Conda environment specification
│
├── 📂 src/                         # Source code
│   ├── data_collection/            # Phase A: Data collection components
│   │   ├── linux_docs_rag.py      # RAG system for Linux documentation
│   │   ├── commit_processor.py    # Commit batch processing
│   │   ├── large_scale_processor.py # Large-scale dataset processing
│   │   └── antipattern_filter.py  # Security relevance filtering
│   │
│   ├── pattern_analysis/           # Phase B: Pattern analysis components
│   │   ├── pattern_derivation.py  # ML clustering + LLM pattern derivation
│   │   └── clang_generator.py     # Automated static checker generation
│   │
│   ├── validation/                 # Validation framework
│   │   ├── expert_validation.py   # Expert validation system
│   │   └── multi_version_validator.py # Cross-version testing
│   │
│   ├── evaluation/                 # Performance evaluation
│   │   └── performance_evaluator.py # Benchmarking and metrics
│   │
│   ├── publication/                # Research publication tools
│   │   └── research_paper_generator.py # Academic paper generation
│   │
│   └── static_checkers/            # Generated checker templates
│
├── 📂 scripts/                     # Executable scripts
│   ├── main.py                     # Main execution script
│   ├── phase_b_main.py            # Phase B execution
│   ├── large_scale_main.py        # Large-scale processing
│   ├── large_scale_demo.py        # Demo script
│   ├── evaluation_main.py         # Evaluation execution
│   ├── expert_validation_main.py  # Expert validation execution
│   ├── evaluation.py              # Evaluation utilities
│   └── test_simple.py             # Basic testing
│
├── 📂 docs/                        # Documentation
│   └── ENHANCED_ARCHITECTURE.md   # System architecture visualization
│
├── 📂 reports/                     # Project reports
│   ├── FINAL_PROJECT_SUMMARY.md   # Complete project summary
│   ├── FINAL_PHASE_B_REPORT.md    # Phase B completion report
│   ├── IMPLEMENTATION_REPORT.md   # Implementation details
│   ├── PHASE_B_COMPLETION_REPORT.md # Phase B final report
│   └── publication/                # Research publication
│       ├── LinuxGuard_Research_Paper.md # Complete research paper
│       ├── supplementary_materials.md # Additional research materials
│       ├── submission_checklist.md # Publication submission guide
│       └── experimental_data_summary.json # Experimental data
│
├── 📂 results/                     # Experimental results
│   ├── phase_a_evaluation.json    # Phase A evaluation results
│   ├── phase_a_evaluation_report.md # Phase A evaluation report
│   │
│   ├── large_scale/                # Large-scale processing results
│   │   ├── commits.db             # SQLite database of commits
│   │   ├── derived_patterns_large_scale.json # Large-scale derived patterns
│   │   ├── demo_results.json      # Demo execution results
│   │   ├── large_scale_summary.json # Processing summary
│   │   └── scale_comparison_report.md # Scale comparison analysis
│   │
│   ├── expert_validation/          # Expert validation framework
│   │   ├── experts.json           # Expert panel database
│   │   ├── questions.json         # Validation questions
│   │   ├── expert_profiles.json   # Expert profiles
│   │   ├── validation_setup_summary.json # Setup summary
│   │   └── expert_*/               # Individual expert validation sessions
│   │
│   ├── evaluation/                 # Performance evaluation results
│   │   ├── evaluation_results.json # Comprehensive evaluation results
│   │   ├── evaluation_report.md   # Evaluation report
│   │   ├── linux_cves.json        # CVE database for validation
│   │   └── visualizations/        # Performance charts and graphs
│   │
│   ├── validation/                 # Cross-version validation
│   │   ├── linux-6.6/             # Linux kernel 6.6 test files
│   │   ├── linux-6.7/             # Linux kernel 6.7 test files
│   │   ├── linux-6.8/             # Linux kernel 6.8 test files
│   │   ├── validation_results.json # Validation results
│   │   └── validation_report.md   # Validation report
│   │
│   └── pattern_analysis/           # Pattern derivation results
│       ├── commit_analyses.json   # Individual commit analyses
│       ├── pattern_clusters.json  # ML clustering results
│       ├── derived_patterns.json  # Final derived patterns
│       └── derivation_report.md   # Pattern derivation report
│
├── 📂 outputs/                     # Generated outputs
│   └── static_checkers/            # Generated Clang static analyzers
│       ├── CMakeLists.txt          # Build system
│       ├── Registration.cpp       # Checker registration
│       ├── checkers/               # Generated checker implementations
│       ├── checkers_metadata.json # Checker metadata
│       ├── generation_report.md   # Generation report
│       └── build/                  # Built checker binaries
│
├── 📂 data/                        # Essential data
│   ├── linux_docs/                # Linux documentation corpus
│   └── vector_db/                  # ChromaDB vector database
│       └── chroma.sqlite3          # Vector embeddings database
│
└── 📂 archive/                     # Archived materials
    ├── test_commits/               # Test commit batches (56 batches)
    ├── commits/                    # Original commit processing
    ├── results/                    # Legacy result files
    ├── experiments/                # Experimental code
    └── paper/                      # Legacy paper materials
```

## 🚀 Quick Start Guide

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

### 3. Key Components

#### Phase A: Anti-Pattern Dataset Creation
- **Data Collection**: `src/data_collection/commit_processor.py`
- **RAG System**: `src/data_collection/linux_docs_rag.py`
- **Security Filtering**: `src/data_collection/antipattern_filter.py`

#### Phase B: Pattern Analysis & Tool Generation
- **Pattern Derivation**: `src/pattern_analysis/pattern_derivation.py`
- **Clang Generation**: `src/pattern_analysis/clang_generator.py`
- **Multi-Version Validation**: `src/validation/multi_version_validator.py`

#### Evaluation & Validation
- **Performance Evaluation**: `src/evaluation/performance_evaluator.py`
- **Expert Validation**: `src/validation/expert_validation.py`

## 📊 Results Overview

### Generated Artifacts
- **📄 Research Paper**: `reports/publication/LinuxGuard_Research_Paper.md` (8,500 words)
- **🏗️ Architecture**: `docs/ENHANCED_ARCHITECTURE.md`
- **🛠️ Static Checkers**: `outputs/static_checkers/`
- **📈 Evaluation Results**: `results/evaluation/`

### Key Metrics
- **Scale**: 7,200 commits processed (26x improvement)
- **Patterns**: 6 high-confidence anti-patterns derived
- **Performance**: 65% precision, 15.0 files/second analysis speed
- **Validation**: Expert validation framework with 5 security researchers

## 🔧 Configuration

### Main Configuration: `config.yaml`
```yaml
# Processing settings
batch_size: 50
max_workers: 4
api_delay: 2.0

# LLM configuration
llm_model: "gemini-2.0-flash"
embedding_model: "all-MiniLM-L6-v2"

# Paths
data_dir: "data"
results_dir: "results"
outputs_dir: "outputs"
```

## 📝 Development Notes

### Code Organization Principles
1. **Modular Design**: Each component has clear responsibilities
2. **Separation of Concerns**: Data collection, analysis, and evaluation are separate
3. **Extensibility**: Framework can be extended to other repositories/languages
4. **Reproducibility**: All experiments can be reproduced from configuration

### File Naming Conventions
- **Scripts**: `*_main.py` for main execution scripts
- **Results**: `*_results.json` for structured data, `*_report.md` for human-readable reports
- **Generated**: `derived_*` for derived/generated content
- **Validation**: `validation_*` for validation-related files

## 🎯 Project Status

- ✅ **Phase A**: Complete - Dataset creation with 7,200 commits
- ✅ **Phase B**: Complete - Pattern derivation and tool generation
- ✅ **Large-Scale**: Complete - 26x scalability demonstrated
- ✅ **Evaluation**: Complete - Comprehensive performance evaluation
- ✅ **Expert Validation**: Complete - 5 expert validation framework
- ✅ **Publication**: Complete - Research paper ready for submission

**Overall Status**: 🏆 **PRODUCTION READY & PUBLICATION READY**