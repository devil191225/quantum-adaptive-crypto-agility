# Config-Lab: Quantum-Adaptive Crypto-Agility Framework

This repository contains the `Config-Lab` framework, a reproducible synthetic simulator for studying post-quantum migration as a threat-parametric, support-constrained planning problem.

This code supports the manuscript:
**"Toward Quantum-Adaptive Crypto-Agility: A Formal Framework for Risk-Aware Post-Quantum Migration Planning"**

## Overview

Post-quantum migration is a continuous control problem over cryptographic infrastructure as primitives, threat assumptions, and operational constraints evolve, not a one-time algorithm swap. `Config-Lab` provides:

- A formal crypto-configuration model.
- Post-quantum-relevant fragility predicates.
- Configurable modeled-risk scoring.
- Support-constrained mutation planning.
- Reproducible synthetic experiments with baselines and sensitivity profiles.

## Development Environment

- **Python:** 3.11 or newer.
- **Install (editable + dev tools):** from the repo root:

  ```bash
  pip install -e ".[dev]"
  ```

- **Checks:**

  ```bash
  python -m pytest
  python -m qaca.experiments --help
  ```

## Reproducing Results

To regenerate all tests, scenarios, baselines, figures, and tables:

```bash
python scripts/reproduce_all.py
```

### Running Individual Scenarios

Run specific scenarios from the command line:

```bash
python -m qaca.experiments --scenario static_migration --seed 42
python -m qaca.experiments --scenario threat_switch --seed 42
python -m qaca.experiments --scenario sensitivity --seed 42
```

Optional robustness sweep (graph mode):

```bash
python -m qaca.experiments --scenario static_migration --seed 7 --template random_graph
```

## Repository Structure

- `configs/`: YAML configuration files for scenarios.
- `src/qaca/`: Core framework source code (models, threat, predicates, risk, planner, simulator).
- `scripts/`: Scripts for reproducing results (`reproduce_all.py`).
- `tests/`: Unit tests for the framework.

Running `python scripts/reproduce_all.py` writes generated artifacts under `results/` (not tracked in Git).

The manuscript (LaTeX, figures for Overleaf) is kept locally under `paper/` and is not part of this repository.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).

## Archiving for the paper (Zenodo)

*Scientific Reports* expects a **Data Availability** / **Code Availability** statement with a stable link to your code. This GitHub repo is that link:

https://github.com/devil191225/quantum-adaptive-crypto-agility

**Zenodo** is optional but recommended: it mints a **DOI** for a specific GitHub release so reviewers and readers have a permanent archive even if the repo changes later.

1. Sign in at [zenodo.org](https://zenodo.org) with your GitHub account.
2. Enable the Zenodo GitHub integration and select this repository.
3. On GitHub, create a **Release** (e.g. `v0.1.0`) after your final `reproduce_all.py` run.
4. Zenodo will build an archive and give you a DOI (e.g. `10.5281/zenodo.xxxxxx`).
5. Put that DOI in the manuscript’s Data/Code Availability sections, plus the release tag and commit hash.

If you have not archived yet at submission time, you can write: *An archival DOI will be provided upon acceptance.*
