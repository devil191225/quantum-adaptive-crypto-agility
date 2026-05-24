"""Scenario smoke tests (writes under tmp_path)."""

from __future__ import annotations

from pathlib import Path

from qaca.baselines import run_all_baselines
from qaca.simulator import run_sensitivity, run_static_migration, run_threat_switch


def test_static_migration_writes_outputs(tmp_path: Path) -> None:
    assert run_static_migration(seed=42, output_dir=str(tmp_path)) == 0
    assert (tmp_path / "static_migration" / "risk_by_step.csv").is_file()
    assert (tmp_path / "figures" / "static_migration_risk.png").is_file()


def test_threat_switch_writes_outputs(tmp_path: Path) -> None:
    assert run_threat_switch(seed=42, output_dir=str(tmp_path)) == 0
    assert (tmp_path / "threat_switch" / "risk_by_step.csv").is_file()
    assert (tmp_path / "figures" / "threat_switch_risk.png").is_file()


def test_baselines_tables(tmp_path: Path) -> None:
    info = run_all_baselines(seed=42, output_dir=str(tmp_path))
    assert (Path(info["tables_dir"]) / "risk_summary.csv").is_file()


def test_sensitivity_outputs(tmp_path: Path) -> None:
    assert run_sensitivity(seed=42, output_dir=str(tmp_path)) == 0
    assert (tmp_path / "sensitivity" / "risk_sensitivity.csv").is_file()
    assert (tmp_path / "sensitivity" / "risk_sensitivity.md").is_file()


def test_random_graph_seed_reproducibility(tmp_path: Path) -> None:
    out1 = tmp_path / "r1"
    out2 = tmp_path / "r2"
    out3 = tmp_path / "r3"
    assert run_static_migration(seed=7, output_dir=str(out1), template="random_graph") == 0
    assert run_static_migration(seed=7, output_dir=str(out2), template="random_graph") == 0
    assert run_static_migration(seed=8, output_dir=str(out3), template="random_graph") == 0
    g1 = (out1 / "static_migration" / "graph_summary.csv").read_text(encoding="utf-8")
    g2 = (out2 / "static_migration" / "graph_summary.csv").read_text(encoding="utf-8")
    g3 = (out3 / "static_migration" / "graph_summary.csv").read_text(encoding="utf-8")
    assert g1 == g2
    assert g1 != g3
