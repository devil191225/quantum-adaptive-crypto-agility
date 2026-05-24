# QACA Claim Ledger

This file controls what can be claimed in manuscript text and generated docs.

| Claim ID | Claim | Claim type | Status | Evidence artifact | Paper section | Code artifact | Risk if overstated |
|---|---|---|---|---|---|---|---|
| C1 | Cryptographic posture can be represented as a threat-parametric configuration graph. | Formal/modeling | Defensible | Data model tests (`tests/test_models.py`) | Model | `src/qaca/models.py`, `src/qaca/threat.py` | Medium |
| C2 | PQC-relevant fragility predicates can be evaluated over the configuration graph. | Formal + executable | Defensible | Predicate tests (`tests/test_predicates.py`) | Fragility predicates | `src/qaca/predicates.py` | Medium |
| C3 | A local-instance risk functional can prioritize modeled fragility instances. | Formal/empirical | Defensible | Risk tests (`tests/test_risk.py`) + tables | Risk | `src/qaca/risk.py` | Medium |
| C4 | Support-constrained mutations reduce modeled risk in synthetic scenarios. | Empirical | Defensible | Scenario outputs and mutation logs | Results | `src/qaca/planner.py`, `src/qaca/mutations.py`, `src/qaca/simulator.py` | High |
| C5 | Threat-state updates trigger re-evaluation and re-planning. | Empirical | Defensible | Threat-switch scenario artifacts | Results | `src/qaca/simulator.py` | High |
| C6 | FO existential-positive fragment is maximal for the project abstraction family. | Formal theorem | Deferred (not claimed) | No project-specific proof | Theory discussion only | n/a | Critical |
| C7 | Abstraction preserves witness counts or exact risk equality. | Formal theorem | Deferred (not claimed) | Not implemented | Limitations | `src/qaca/abstraction.py` (coarse only) | Critical |
| C8 | Greedy planner is globally optimal. | Algorithmic guarantee | Rejected | None | Limitations | `src/qaca/planner.py` | Critical |
| C9 | System is production self-healing infrastructure. | System claim | Rejected | None | Discussion/future work only | n/a | Critical |

## Guardrail statement

The first paper claims only a threat-parametric model, executable fragility predicates, a local risk functional, and support-constrained mutation planning validated in synthetic scenarios. It does not claim production autonomy, complete cryptanalytic forecasting, or formal verification of infrastructure actuation.
