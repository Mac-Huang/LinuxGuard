# Setup Guide for ANTIPATTERN_PIPELINE v1.4

## Prerequisites Installation Guide

This guide will help you install all necessary tools to run the complete comparative analysis pipeline.

## Table of Contents
1. [LLVM/Clang Development Tools](#1-llvmclang-development-tools)
2. [Coccinelle Installation](#2-coccinelle-installation)
3. [Python Dependencies](#3-python-dependencies)
4. [Verification](#4-verification)
5. [Running the Analysis](#5-running-the-analysis)

---

## 1. LLVM/Clang Development Tools

### Windows Installation

#### Option A: Using Pre-built Binaries (Recommended)
1. Download LLVM from: https://github.com/llvm/llvm-project/releases
   - Choose: `LLVM-<version>-win64.exe`
   - Current stable: LLVM 17.0.6

2. Install with these options:
   - Add LLVM to PATH: **Yes**
   - Install development headers: **Yes**
   - Install libraries: **Yes**

3. Install Visual Studio Build Tools:
   ```powershell
   # Download from Microsoft
   winget install Microsoft.VisualStudio.2022.BuildTools
   ```
   - Select: "Desktop development with C++"
   - Include: Windows 10/11 SDK

#### Option B: Using Chocolatey
```powershell
# Run as Administrator
choco install llvm
choco install visualstudio2022buildtools
choco install visualstudio2022-workload-vctools
```

### Linux Installation

#### Ubuntu/Debian
```bash
# Add LLVM repository
wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add -
sudo add-apt-repository "deb http://apt.llvm.org/$(lsb_release -cs)/ llvm-toolchain-$(lsb_release -cs)-17 main"

# Install LLVM/Clang
sudo apt update
sudo apt install -y \
    clang-17 \
    llvm-17 \
    llvm-17-dev \
    libclang-17-dev \
    libclang-cpp17-dev \
    clang-tools-17

# Create symbolic links
sudo update-alternatives --install /usr/bin/clang clang /usr/bin/clang-17 100
sudo update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-17 100
```

#### Fedora/RHEL
```bash
sudo dnf install -y \
    clang \
    llvm \
    llvm-devel \
    clang-devel \
    clang-tools-extra
```

#### Arch Linux
```bash
sudo pacman -S clang llvm
```

### Verify Installation
```bash
clang --version
llvm-config --version
llvm-config --cxxflags  # Should output compiler flags
llvm-config --ldflags   # Should output linker flags
```

---

## 2. Coccinelle Installation

### Windows Installation

#### Using WSL2 (Recommended for Windows)
```bash
# In WSL2 Ubuntu
sudo apt update
sudo apt install -y coccinelle

# Verify
spatch --version
```

#### Using Cygwin
1. Install Cygwin from https://cygwin.com
2. During setup, select:
   - ocaml
   - ocaml-findlib
   - make
   - gcc-core
3. Build Coccinelle:
```bash
wget https://github.com/coccinelle/coccinelle/archive/refs/tags/1.1.1.tar.gz
tar -xzf 1.1.1.tar.gz
cd coccinelle-1.1.1
./autogen
./configure
make
make install
```

### Linux Installation

#### Ubuntu/Debian
```bash
sudo apt update
sudo apt install -y coccinelle

# For latest version from source:
sudo apt install -y ocaml ocaml-findlib libpcre-ocaml-dev pkg-config
git clone https://github.com/coccinelle/coccinelle.git
cd coccinelle
./autogen
./configure
make
sudo make install
```

#### Fedora
```bash
sudo dnf install -y coccinelle
```

#### Arch Linux
```bash
sudo pacman -S coccinelle
```

### Verify Installation
```bash
spatch --version
# Should output: spatch version 1.1.1 or similar
```

---

## 3. Python Dependencies

Install required Python packages:

```bash
# Create virtual environment (recommended)
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

Create `requirements.txt`:
```txt
requests>=2.28.0
python-dotenv>=1.0.0
pygments>=2.15.0
tabulate>=0.9.0
matplotlib>=3.7.0
pandas>=2.0.0
numpy>=1.24.0
GitPython>=3.1.40
```

---

## 4. Verification

Run the verification script:

```bash
python setup_check.py
```

This will verify all tools are properly installed.

---

## 5. Running the Analysis

### Quick Start
```bash
# Run complete pipeline
cd ANTIPATTERN_PIPELINE_v1.4
python pipeline_v1.4.py
```

### Step-by-Step Analysis

#### Step 1: Generate Checker
```bash
python model_analyzer.py
python checker_generator.py
```

#### Step 2: Compile Clang Checker
```bash
python compile_checker.py
```

#### Step 3: Run Individual Detectors
```bash
# Pattern-based detection
python detectors/pattern_detector.py

# Coccinelle detection
python detectors/coccinelle_detector.py

# Clang static analyzer
python detectors/clang_detector.py
```

#### Step 4: Run Comparative Analysis
```bash
python comparative_analyzer.py
```

#### Step 5: View Results
```bash
# Open results in browser
python -m http.server 8000 --directory results
# Navigate to http://localhost:8000
```

---

## Troubleshooting

### Common Issues and Solutions

#### Issue: Clang plugin compilation fails
**Solution:**
```bash
# Ensure LLVM development headers are installed
llvm-config --cxxflags
# If empty, reinstall LLVM with development packages
```

#### Issue: Coccinelle not found
**Solution:**
```bash
# Check if spatch is in PATH
which spatch
# If not, add to PATH or create alias
echo 'export PATH=$PATH:/usr/local/bin' >> ~/.bashrc
```

#### Issue: Permission denied errors
**Solution:**
```bash
# Linux: Use sudo for system-wide installation
# Windows: Run as Administrator
```

#### Issue: Git operations fail
**Solution:**
```bash
# Ensure git is configured
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"
```

---

## Advanced Configuration

### Custom LLVM Path
Edit `config.py`:
```python
LLVM_PATH = Path("C:/Program Files/LLVM/bin")  # Windows
LLVM_PATH = Path("/usr/lib/llvm-17/bin")       # Linux
```

### Custom Coccinelle Rules
Add semantic patches to `detectors/semantic_patches/`:
```cocci
// custom_rule.cocci
@@
expression E;
@@
* if (E == NULL) { ... }
  E->field
```

### Performance Tuning
Edit `comparative_analyzer.py`:
```python
MAX_FILES_PER_DIR = 100  # Increase for more thorough analysis
TIMEOUT_SECONDS = 30     # Adjust based on system performance
```

---

## Next Steps

1. **Run the verification script** to ensure everything is installed
2. **Start with pattern detection** (no special tools needed)
3. **Add Coccinelle** for better semantic analysis
4. **Finally add Clang** for deepest analysis
5. **Compare results** and refine your checker

For support, check the [troubleshooting section](#troubleshooting) or create an issue in the repository.