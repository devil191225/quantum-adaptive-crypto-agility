# Config-Lab: Quantum-Adaptive Crypto-Agility Framework

This repository contains the `Config-Lab` framework, a reproducible synthetic simulator for studying post-quantum migration as a threat-parametric, support-constrained planning problem.

This code supports the manuscript:
**"Toward Quantum-Adaptive Crypto-Agility: A Formal Framework for Risk-Aware Post-Quantum Migration Planning"**

## Overview

Post-quantum migration is a continuous control problem over cryptographic infrastructure as primitives, threat assumptions, and operational constraints evolve—not a one-time algorithm swap. `Config-Lab` provides:

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
- `scripts/`: Scripts for reproducing results and generating figures.
- `paper/`: Manuscript source files (LaTeX) and figures.
- `results/`: Generated tables and figures from experiments.
- `tests/`: Unit tests for the framework.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
