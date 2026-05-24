"""Baseline planners and paper-oriented tabular exports."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pandas as pd

from qaca.abstraction import abstraction_compression_stats
from qaca.algorithm_registry import REGISTRY
from qaca.models import CryptoConfig
from qaca.mutations import KemUpgrade, SimulationPolicy, apply_kem_upgrade, can_apply_kem_upgrade
from qaca.planner import greedy_migrate_until_stable, summarize_blocked
from qaca.predicates import PREDICATE_CLASSIFICATION, collect_fragilities, split_core_and_heuristics
from qaca.risk import risk_summary_dict, score_instances, total_risk
from qaca.simulator import experiment_crypto_mesh, static_migration_threat
from qaca.threat import ThreatState


def _df_to_markdown(df: pd.DataFrame) -> str:
    """Markdown table without optional tabulate dependency."""
    def _fmt(v: Any) -> str:
        if isinstance(v, float):
            return f"{v:.2f}"
        return str(v)

    cols = list(df.columns)
    lines = ["| " + " | ".join(cols) + " |", "| " + " | ".join("---" for _ in cols) + " |"]
    for _, row in df.iterrows():
        lines.append("| " + " | ".join(_fmt(row[c]) for c in cols) + " |")
    return "\n".join(lines) + "\n"


def baseline_risk_scoring_only(
    cfg: CryptoConfig,
    threat: ThreatState,
    *,
    migration_targets: frozenset[str],
) -> dict[str, Any]:
    """Detect + score fragilities; do not mutate."""
    inst = collect_fragilities(cfg, threat, migration_targets=migration_targets)
    core, heur = split_core_and_heuristics(inst)
    scored = score_instances(cfg, core, include_heuristics=False)
    scored_all = score_instances(cfg, inst, include_heuristics=True)
    return {
        "name": "risk_scoring_only",
        "total_core_risk": total_risk(scored),
        "total_all_risk": total_risk(scored_all),
        "instance_count_core": len(scored),
        "instance_count_heuristic": len(heur),
        "summary": risk_summary_dict(cfg, scored),
    }


def baseline_no_support_checks(
    cfg: CryptoConfig,
    threat: ThreatState,
    *,
    migration_targets: frozenset[str],
    primary_target_algorithm_id: str,
) -> dict[str, Any]:
    """Greedy migration with endpoint support checks disabled (infeasible applies may occur)."""
    policy = SimulationPolicy(kms_capable_node_ids=None, check_endpoint_support=False)
    cfg_end, logs, risks = greedy_migrate_until_stable(
        cfg,
        threat,
        migration_targets=migration_targets,
        primary_target_algorithm_id=primary_target_algorithm_id,
        policy=policy,
    )
    return {
        "name": "no_support_checks",
        "final_risk": risks[-1],
        "initial_risk": risks[0],
        "mutation_steps": max(len(risks) - 1, 0),
        "logs": logs,
        "risks": risks,
    }


def baseline_static_checklist(
    cfg: CryptoConfig,
    threat: ThreatState,
    *,
    migration_targets: frozenset[str],
    target_algorithm_id: str,
) -> dict[str, Any]:
    """Fixed channel order: attempt one-shot migration to a default PQC target (support-aware apply)."""
    policy = SimulationPolicy(check_endpoint_support=True)
    infeasible = 0
    applied = 0
    logs: list[dict[str, Any]] = []
    for ch in sorted(cfg.channels.values(), key=lambda c: c.id):
        ok, reason = can_apply_kem_upgrade(cfg, ch, target_algorithm_id, policy)
        if ch.kem_algorithm_id == target_algorithm_id:
            continue
        if not ok:
            infeasible += 1
            logs.append(
                {
                    "channel_id": ch.id,
                    "status": "infeasible",
                    "reason": reason,
                }
            )
            continue
        mut = KemUpgrade(
            channel_id=ch.id,
            target_algorithm_id=target_algorithm_id,
            new_key_id=f"{ch.id}_checklist_{applied}",
        )
        cfg = apply_kem_upgrade(cfg, mut)
        applied += 1
        logs.append({"channel_id": ch.id, "status": "applied"})
    inst = collect_fragilities(cfg, threat, migration_targets=migration_targets)
    scored = score_instances(cfg, inst)
    return {
        "name": "static_checklist",
        "applied": applied,
        "infeasible": infeasible,
        "final_risk": total_risk(scored),
        "logs": logs,
    }


def run_all_baselines(
    *,
    seed: int,
    output_dir: str = "results",
) -> dict[str, Any]:
    """Execute baselines and write CSV/Markdown tables under results/tables/."""
    _ = seed
    cfg0 = experiment_crypto_mesh()
    theta = static_migration_threat()
    migration = frozenset({"alg_ml_kem", "alg_hybrid"})
    tables = Path(output_dir) / "tables"
    tables.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []
    b1 = baseline_risk_scoring_only(cfg0, theta, migration_targets=migration)
    initial_risk = float(b1["total_core_risk"])
    rows.append(
        {
            "baseline": b1["name"],
            "initial_total_risk": initial_risk,
            "final_total_risk": b1["total_core_risk"],
            "final_all_risk": b1["total_all_risk"],
            "mutations": 0,
            "heuristic_instances": b1["instance_count_heuristic"],
        }
    )
    b2 = baseline_static_checklist(
        experiment_crypto_mesh(),
        theta,
        migration_targets=migration,
        target_algorithm_id="alg_ml_kem",
    )
    rows.append(
        {
            "baseline": b2["name"],
            "initial_total_risk": initial_risk,
            "final_total_risk": b2["final_risk"],
            "mutations": b2["applied"],
            "infeasible": b2["infeasible"],
        }
    )
    b3 = baseline_no_support_checks(
        experiment_crypto_mesh(),
        theta,
        migration_targets=migration,
        primary_target_algorithm_id="alg_ml_kem",
    )
    rows.append(
        {
            "baseline": b3["name"],
            "initial_total_risk": b3["initial_risk"],
            "final_total_risk": b3["final_risk"],
            "mutations": b3["mutation_steps"],
        }
    )
    _, greedy_logs, _ = greedy_migrate_until_stable(
        experiment_crypto_mesh(),
        theta,
        migration_targets=migration,
        primary_target_algorithm_id="alg_ml_kem",
        policy=SimulationPolicy(),
    )
    blk = summarize_blocked(greedy_logs)
    blk_df = pd.DataFrame(blk if blk else [{"note": "none"}])
    blk_df.to_csv(tables / "blocked_mutations.csv", index=False)
    (tables / "blocked_mutations.md").write_text(_df_to_markdown(blk_df), encoding="utf-8")
    df = pd.DataFrame(rows)
    df.to_csv(tables / "risk_summary.csv", index=False)
    (tables / "risk_summary.md").write_text(_df_to_markdown(df), encoding="utf-8")
    comp = abstraction_compression_stats(cfg0)
    dfc = pd.DataFrame([comp])
    dfc.to_csv(tables / "coarse_view_ratio.csv", index=False)
    (tables / "coarse_view_ratio.md").write_text(_df_to_markdown(dfc), encoding="utf-8")
    # Backward-compatible filenames for older references.
    dfc.to_csv(tables / "compression_ratio.csv", index=False)
    (tables / "compression_ratio.md").write_text(_df_to_markdown(dfc), encoding="utf-8")
    params = pd.DataFrame(
        [
            {
                "seed": seed,
                "horizon_year": theta.horizon_year,
                "migration_targets": ",".join(sorted(migration)),
            }
        ]
    )
    params.to_csv(tables / "scenario_parameters.csv", index=False)
    (tables / "scenario_parameters.md").write_text(_df_to_markdown(params), encoding="utf-8")
    pred_rows = [
        {
            "predicate": pid,
            "category": meta["category"],
            "paper_core": meta["paper_core"],
            "preservation_safe": meta["preservation_safe"],
        }
        for pid, meta in sorted(PREDICATE_CLASSIFICATION.items())
    ]
    pred_df = pd.DataFrame(pred_rows)
    pred_df.to_csv(tables / "predicate_categories.csv", index=False)
    (tables / "predicate_categories.md").write_text(_df_to_markdown(pred_df), encoding="utf-8")
    reg_rows = [
        {"family": fam, "display_name": prof.display_name, "aliases": ", ".join(prof.aliases)}
        for fam, prof in sorted(REGISTRY.items())
    ]
    reg_df = pd.DataFrame(reg_rows)
    reg_df.to_csv(tables / "algorithm_registry.csv", index=False)
    (tables / "algorithm_registry.md").write_text(_df_to_markdown(reg_df), encoding="utf-8")
    return {"tables_dir": str(tables), "rows": rows, "compression": comp}


__all__ = [
    "baseline_no_support_checks",
    "baseline_risk_scoring_only",
    "baseline_static_checklist",
    "run_all_baselines",
]
