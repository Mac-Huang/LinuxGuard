# Agent Guide – Linux Kernel Anti-Pattern Pipeline

Repository root: `/nvme/write/mac/private/linux-guard`

This document summarizes how the pipeline is organized, which script is responsible for each phase, and where artifacts are stored. All paths in scripts should be relative to the repository root so the project stays portable.

## End-to-End Flow

```
Module 1 (pattern extraction)
 → Module 2 (checker synthesis)
 → Module 3 (integration + build/verify)
 → Module 4 (multi-version validation)
 → Results saved per checker generation
```

The orchestrator (`scripts/orchestrator.py`) stitches these phases together but delegates actual work to the individual modules. It also ensures the clang-tidy source tree is restored before and after every run, preventing lingering checker files.

## Modules at a Glance

| Module | Script | Output |
| ------ | ------ | ------ |
| 1 | `module1_pattern_extraction.py` | `results/…/checker_guidance.json` |
| 2 | `module2_checker_synthesis.py` | Checker sources in `checkers/generated/<anti-pattern>/<generation_id>/` (header, cpp, metadata) |
| 3 | `module3_integration.py` | Builds clang-tidy with a selected checker, updates metadata, optional restore via `--restore` |
| 4 | `module4_validation.py` | JSON/markdown scan reports per kernel version |

## Repository Layout (high level)

```
llvm-project/                       # LLVM/Clang checkout + build tree
  build/bin/clang-tidy              # Binary used for validation
  clang-tools-extra/clang-tidy/linuxkernel/
    LinuxKernelTidyModule.cpp       # Updated by Module 3
kernels/                            # Local Linux kernel snapshots (with compile_commands.json)
checkers/
  templates/                        # Seed templates used by Module 2
  generated/<anti-pattern>/<generation_id>/
results/
  <anti-pattern>/<generation_id>/   # Orchestrator + validation artifacts
scripts/                            # Pipeline modules & helpers
```

Each checker generation folder contains:

```
BufferOverflowCheck.cpp / .h
metadata.json
```

The orchestrator mirrors every generation’s outputs under `results/<anti-pattern>/<generation_id>/`:

```
orchestrator_result.json
validation_report.json
validation_report.md
```

## Orchestrator Usage

Activate the virtual environment first:

```bash
source LinuxGuard/bin/activate
```

Run the pipeline for a given commit:

```bash
python3 scripts/orchestrator.py \
  --commit <commit_hash> \
  --max-iterations 5 \
  --max-repairs 10 \
  [--validation-kernel linux-v3.0]
```

Key behaviors:

* Automatically restores `clang-tools-extra/clang-tidy/linuxkernel/` at the start and end of the run.
* On success/failure it writes results to `results/<anti-pattern>/<generation_id>/` using metadata from `checkers/generated/...`.
* Leaving `--validation-kernel` unset makes Module 4 scan every kernel in `kernels/` using parallel worker processes.

## Running Modules Individually

```bash
# Module 1 – Extract guidance for a commit
python3 scripts/module1_pattern_extraction.py --commit-hash <hash>

# Module 2 – Generate checker sources (uses latest guidance by default)
python3 scripts/module2_checker_synthesis.py --single

# Module 3 – Integrate a specific generation
python3 scripts/module3_integration.py \
  --checker-metadata checkers/generated/<anti-pattern>/<generation_id>/metadata.json \
  --jobs $(nproc)

# Module 4 – Validate the currently integrated checker
python3 scripts/module4_validation.py \
  --checker-pattern linuxkernel-<checker-name> \
  --anti-pattern-type <anti-pattern> \
  --output results/<anti-pattern>/<generation_id>/validation_report.json \
  --processes 4
```

Module 3 accepts `--persist` when you want to keep checker files in the clang-tidy directory for inspection; the orchestrator never uses `--persist` so it can clean up automatically. Run `python3 scripts/module3_integration.py --restore` at any time to reset clang-tidy sources.

## Parallel Validation

`module4_validation.py` uses a multiprocessing pool to fan out scans across kernel versions. Use `--processes <N>` to control the number of workers (default: CPU count). Within each kernel the scan iterates batch by batch; reduce runtime by setting `--sample-size` during experiments.

## Git Hygiene

* Do **not** stage the kernel sources or other nested Git repositories (e.g., `kernels/linux.git`). Add them to `.gitignore` if necessary.
* Generated checkers and results should be tracked only when you explicitly want to commit them.

## Quick Reference

```bash
# Integrate but skip rebuilding
python3 scripts/module3_integration.py --no-build --checker-metadata <metadata.json>

# Scan only linux-v5.0 with 8 workers
python3 scripts/module4_validation.py \
  --checker-pattern linuxkernel-buffer-overflow \
  --anti-pattern-type buffer-overflow \
  --kernel-version linux-v5.0 \
  --processes 8 \
  --output results/buffer-overflow/<generation_id>/validation_report.json

# Restore clang-tidy sources
python3 scripts/module3_integration.py --restore
```

Following these conventions keeps the orchestrator lightweight, ensures modules stay single-purpose, and makes the results easy to navigate for each generated checker.
