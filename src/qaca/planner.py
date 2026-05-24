"""Greedy mutation planning with support checks and mutation logs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

from qaca.models import CryptoConfig, KeyLifetimeClass
from qaca.mutations import (
    KemUpgrade,
    KeyLifetimeReduction,
    SimulationPolicy,
    apply_kem_upgrade,
    apply_key_lifetime_reduction,
    can_apply_kem_upgrade,
    can_apply_key_lifetime_reduction,
)
from qaca.predicates import collect_fragilities
from qaca.risk import score_instances, total_risk
from qaca.threat import ThreatState


def _risk_of(cfg: CryptoConfig, threat: ThreatState, migration_targets: frozenset[str]) -> float:
    inst = collect_fragilities(cfg, threat, migration_targets=migration_targets)
    return total_risk(score_instances(cfg, inst, include_heuristics=False))


def plan_greedy_kem_step(
    cfg: CryptoConfig,
    threat: ThreatState,
    *,
    migration_targets: frozenset[str],
    preferred_target_algorithm_id: str,
    policy: SimulationPolicy,
    step_index: int,
) -> tuple[CryptoConfig | None, list[dict[str, Any]]]:
    """Try F1/F8 channels in risk order; apply first feasible KEM upgrade; else log blocks."""
    instances = collect_fragilities(cfg, threat, migration_targets=migration_targets)
    scored = score_instances(cfg, instances)
    scored.sort(key=lambda s: s.weight, reverse=True)
    logs: list[dict[str, Any]] = []
    for s in scored:
        if s.instance.predicate not in {"F1", "F8"}:
            continue
        cid = s.instance.channel_id
        if cid is None:
            continue
        ch = cfg.channels[cid]
        ok, reason = can_apply_kem_upgrade(cfg, ch, preferred_target_algorithm_id, policy)
        new_key_id = f"{cid}_kem_{preferred_target_algorithm_id}_s{step_index}"
        mut = KemUpgrade(
            channel_id=cid,
            target_algorithm_id=preferred_target_algorithm_id,
            new_key_id=new_key_id,
        )
        rb = _risk_of(cfg, threat, migration_targets)
        log: dict[str, Any] = {
            "step": step_index,
            "mutation": "kem_upgrade",
            "target": cid,
            "from_algorithm_id": ch.kem_algorithm_id,
            "to_algorithm_id": preferred_target_algorithm_id,
            "risk_before": rb,
        }
        if not ok:
            log.update({"status": "blocked", "reason": reason})
            logs.append(log)
            continue
        new_cfg = apply_kem_upgrade(cfg, mut)
        log.update(
            {
                "status": "applied",
                "risk_after": _risk_of(new_cfg, threat, migration_targets),
            }
        )
        logs.append(log)
        return new_cfg, logs
    logs.append(
        {
            "step": step_index,
            "mutation": "kem_upgrade",
            "status": "noop",
            "reason": "no_candidate",
        }
    )
    return None, logs


def plan_key_lifetime_step(
    cfg: CryptoConfig,
    threat: ThreatState,
    *,
    migration_targets: frozenset[str],
    policy: SimulationPolicy,
    step_index: int,
) -> tuple[CryptoConfig | None, list[dict[str, Any]]]:
    """Address F4 by shortening key lifetime on the highest-weight F4 channel."""
    instances = collect_fragilities(cfg, threat, migration_targets=migration_targets)
    scored = score_instances(cfg, [i for i in instances if i.predicate == "F4"])
    scored.sort(key=lambda s: s.weight, reverse=True)
    logs: list[dict[str, Any]] = []
    for s in scored:
        cid = s.instance.channel_id
        if cid is None:
            continue
        ch = cfg.channels[cid]
        ok, reason = can_apply_key_lifetime_reduction(cfg, ch, policy)
        new_key_id = f"{cid}_life_s{step_index}"
        mut = KeyLifetimeReduction(
            channel_id=cid,
            new_key_id=new_key_id,
            new_lifetime=KeyLifetimeClass.SHORT,
        )
        log: dict[str, Any] = {
            "step": step_index,
            "mutation": "key_lifetime_reduction",
            "target": cid,
            "risk_before": _risk_of(cfg, threat, migration_targets),
        }
        if not ok:
            log.update({"status": "blocked", "reason": reason})
            logs.append(log)
            continue
        new_cfg = apply_key_lifetime_reduction(cfg, mut)
        log.update(
            {
                "status": "applied",
                "risk_after": _risk_of(new_cfg, threat, migration_targets),
            }
        )
        logs.append(log)
        return new_cfg, logs
    logs.append(
        {
            "step": step_index,
            "mutation": "key_lifetime_reduction",
            "status": "noop",
            "reason": "no_f4",
        }
    )
    return None, logs


def greedy_migrate_until_stable(
    cfg: CryptoConfig,
    threat: ThreatState,
    *,
    migration_targets: frozenset[str],
    primary_target_algorithm_id: str,
    policy: SimulationPolicy,
    max_steps: int = 64,
    prefer_key_lifetime_for_f4: bool = True,
) -> tuple[CryptoConfig, list[dict[str, Any]], list[float]]:
    """Alternate F4 lifetime reduction (optional) then KEM upgrades until no progress."""
    logs: list[dict[str, Any]] = []
    risks: list[float] = [_risk_of(cfg, threat, migration_targets)]
    for step in range(max_steps):
        progressed = False
        if prefer_key_lifetime_for_f4:
            new_cfg_f4, logs_f4 = plan_key_lifetime_step(
                cfg, threat, migration_targets=migration_targets, policy=policy, step_index=step
            )
            logs.extend(logs_f4)
            if new_cfg_f4 is not None:
                cfg = new_cfg_f4
                risks.append(_risk_of(cfg, threat, migration_targets))
                progressed = True
                continue
        new_cfg, logs_kem = plan_greedy_kem_step(
            cfg,
            threat,
            migration_targets=migration_targets,
            preferred_target_algorithm_id=primary_target_algorithm_id,
            policy=policy,
            step_index=step,
        )
        logs.extend(logs_kem)
        if new_cfg is not None:
            cfg = new_cfg
            risks.append(_risk_of(cfg, threat, migration_targets))
            progressed = True
            continue
        if not progressed:
            break
    return cfg, logs, risks


def save_mutation_log_json(path: str | Path, logs: list[dict[str, Any]]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(logs, indent=2), encoding="utf-8")


def summarize_blocked(logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for log in logs:
        if log.get("status") == "blocked":
            out.append(
                {
                    "step": log.get("step"),
                    "mutation": log.get("mutation"),
                    "target": log.get("target"),
                    "reason": log.get("reason"),
                }
            )
    return out


PlannerMode = Literal["greedy", "zone"]


def run_planner(
    mode: PlannerMode,
    cfg: CryptoConfig,
    threat: ThreatState,
    **kwargs: Any,
) -> tuple[CryptoConfig, list[dict[str, Any]], list[float]]:
    _ = mode  # zone planner not distinct in PoC; hook for future work
    return greedy_migrate_until_stable(cfg, threat, **kwargs)


__all__ = [
    "greedy_migrate_until_stable",
    "plan_greedy_kem_step",
    "plan_key_lifetime_step",
    "run_planner",
    "save_mutation_log_json",
    "summarize_blocked",
]
