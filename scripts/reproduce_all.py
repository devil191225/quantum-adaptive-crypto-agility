#!/usr/bin/env python3
"""Regenerate tests, scenarios, baselines, figures, tables, and PoC report."""

from __future__ import annotations

import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
import json

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"


def _run(cmd: list[str]) -> None:
    print("+", " ".join(cmd))
    subprocess.run(cmd, cwd=ROOT, check=True)


def _fmt(v: object) -> str:
    if isinstance(v, float):
        return f"{v:.2f}"
    return str(v)


def _md_table(df: pd.DataFrame) -> str:
    cols = list(df.columns)
    lines = ["| " + " | ".join(cols) + " |", "| " + " | ".join("---" for _ in cols) + " |"]
    for _, row in df.iterrows():
        lines.append("| " + " | ".join(_fmt(row[c]) for c in cols) + " |")
    return "\n".join(lines)


def main() -> int:
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "figures").mkdir(parents=True, exist_ok=True)
    (RESULTS / "tables").mkdir(parents=True, exist_ok=True)

    _run([sys.executable, "-m", "pytest", str(ROOT / "tests")])
    _run(
        [
            sys.executable,
            "-m",
            "qaca.experiments",
            "--scenario",
            "static_migration",
            "--seed",
            "42",
            "--output-dir",
            str(RESULTS),
        ]
    )
    _run(
        [
            sys.executable,
            "-m",
            "qaca.experiments",
            "--scenario",
            "sensitivity",
            "--seed",
            "42",
            "--output-dir",
            str(RESULTS),
        ]
    )
    _run(
        [
            sys.executable,
            "-m",
            "qaca.experiments",
            "--scenario",
            "threat_switch",
            "--seed",
            "42",
            "--output-dir",
            str(RESULTS),
        ]
    )
    from qaca.baselines import run_all_baselines

    baseline_info = run_all_baselines(seed=42, output_dir=str(RESULTS))
    risk_df = pd.read_csv(RESULTS / "tables" / "risk_summary.csv")
    sens_df = pd.read_csv(RESULTS / "sensitivity" / "risk_sensitivity.csv")
    static_summary = json.loads((RESULTS / "static_migration" / "summary.json").read_text(encoding="utf-8"))
    switch_summary = json.loads((RESULTS / "threat_switch" / "summary.json").read_text(encoding="utf-8"))
    sens_summary = json.loads((RESULTS / "sensitivity" / "summary.json").read_text(encoding="utf-8"))

    runtime_df = pd.DataFrame(
        [
            {"scenario": "static_migration", "runtime_seconds": static_summary.get("runtime_seconds", 0.0)},
            {"scenario": "threat_switch", "runtime_seconds": switch_summary.get("runtime_seconds", 0.0)},
            {"scenario": "sensitivity", "runtime_seconds": sens_summary.get("runtime_seconds", 0.0)},
        ]
    )
    runtime_df.to_csv(RESULTS / "tables" / "runtime_summary.csv", index=False)
    (RESULTS / "tables" / "runtime_summary.md").write_text(_md_table(runtime_df) + "\n", encoding="utf-8")

    mutation_df = pd.DataFrame(
        [
            {
                "scenario": "static_migration",
                "attempted": static_summary.get("mutation_attempt_count", 0),
                "applied": static_summary.get("mutation_applied_count", 0),
                "blocked": static_summary.get("mutation_blocked_count", 0),
            },
            {
                "scenario": "threat_switch",
                "attempted": switch_summary.get("mutation_attempt_count", 0),
                "applied": switch_summary.get("mutation_applied_count", 0),
                "blocked": switch_summary.get("mutation_blocked_count", 0),
            },
        ]
    )
    mutation_df.to_csv(RESULTS / "tables" / "mutation_accounting.csv", index=False)
    (RESULTS / "tables" / "mutation_accounting.md").write_text(
        _md_table(mutation_df) + "\n",
        encoding="utf-8",
    )

    limitations = [
        "- Synthetic-only evaluation; no real TLS/certificate/Kubernetes ingestion yet.",
        "- Greedy risk-prioritized planner is heuristic and not globally optimal.",
        "- Threat-state updates are modeled policy/confidence events, not cryptanalytic break claims.",
        "- Coarse view ratio is an engineering grouping metric, not a formal abstraction-preservation guarantee.",
        "- Risk weights are illustrative defaults; sensitivity analysis is provided.",
    ]
    (RESULTS / "limitations.md").write_text(
        "# Synthetic evaluation limitations\n\n" + "\n".join(limitations) + "\n",
        encoding="utf-8",
    )

    file_manifest = [
        "results/static_migration/risk_by_step.csv",
        "results/static_migration/mutation_log.json",
        "results/static_migration/summary.json",
        "results/threat_switch/risk_by_step.csv",
        "results/threat_switch/mutation_log.json",
        "results/threat_switch/summary.json",
        "results/threat_switch/threat_state_transition.csv",
        "results/sensitivity/risk_sensitivity.csv",
        "results/figures/static_migration_risk.png",
        "results/figures/threat_switch_risk.png",
        "results/tables/risk_summary.csv",
        "results/tables/blocked_mutations.csv",
        "results/tables/coarse_view_ratio.csv",
        "results/tables/scenario_parameters.csv",
        "results/tables/predicate_categories.csv",
        "results/tables/runtime_summary.csv",
        "results/tables/mutation_accounting.csv",
        "results/poc_report.md",
        "results/limitations.md",
    ]

    report = [
        "# Config-Lab PoC report",
        "",
        f"Generated (UTC): {datetime.now(UTC).isoformat()}",
        "",
        "## Summary",
        "",
        "Synthetic Config-Lab for quantum-adaptive crypto-agility research (PoC only).",
        "This is not production infrastructure and does not assert real cryptanalysis.",
        "",
        "## Commands run",
        "",
        "```text",
        "python -m pytest tests",
        "python -m qaca.experiments --scenario static_migration --seed 42",
        "python -m qaca.experiments --scenario sensitivity --seed 42",
        "python -m qaca.experiments --scenario threat_switch --seed 42",
        "python scripts/reproduce_all.py (via baselines.run_all_baselines)",
        "```",
        "",
        "## Key metrics",
        "",
        "### Baseline risk summary",
        "",
        _md_table(risk_df),
        "",
        "### Sensitivity summary",
        "",
        _md_table(sens_df),
        "",
        "### Runtime summary",
        "",
        _md_table(runtime_df),
        "",
        "### Mutation accounting",
        "",
        _md_table(mutation_df),
        "",
        "### Scenario snapshots",
        "",
        f"- Static migration core risk: {_fmt(static_summary.get('initial_core_risk'))} -> {_fmt(static_summary.get('final_core_risk'))}",
        f"- Threat-switch core risk: {_fmt(switch_summary.get('initial_core_risk'))} -> {_fmt(switch_summary.get('final_core_risk'))}",
        f"- Threat-switch event: {switch_summary.get('event', 'n/a')}",
        "",
        "## Artifact manifest",
        "",
        *[f"- `{p}`" for p in file_manifest],
        "",
        "## Synthetic evaluation limitations",
        "",
        *limitations,
        "",
    ]
    (RESULTS / "poc_report.md").write_text("\n".join(report), encoding="utf-8")
    print("Wrote", RESULTS / "poc_report.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
