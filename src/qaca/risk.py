"""Local-instance risk scoring over fragility instances (deterministic)."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pandas as pd

from qaca.models import CryptoConfig, DataSensitivity
from qaca.predicates import FragilityInstance

# Base weights by predicate id (tunable constants for the PoC).
DEFAULT_PREDICATE_WEIGHTS: dict[str, float] = {
    "F1": 10.0,
    "F2": 6.0,
    "F3": 7.0,
    "F4": 5.0,
    "F5": 6.0,
    "F6": 12.0,
    "F7": 3.0,
    "F8": 9.0,
}

SENSITIVITY_MULTIPLIER: dict[str, float] = {
    DataSensitivity.PUBLIC.value: 0.5,
    DataSensitivity.INTERNAL.value: 1.0,
    DataSensitivity.CONFIDENTIAL.value: 1.5,
    DataSensitivity.REGULATED.value: 2.0,
}

CRITICALITY_MULTIPLIER: dict[str, float] = {
    "low": 0.8,
    "medium": 1.0,
    "high": 1.4,
}


@dataclass(frozen=True, slots=True)
class ScoredInstance:
    """Fragility instance with computed weight contribution."""

    instance: FragilityInstance
    weight: float
    zone: str


def _criticality_for_channel(cfg: CryptoConfig, inst: FragilityInstance) -> str:
    if inst.channel_id is None:
        return "medium"
    ch = cfg.channels[inst.channel_id]
    crit_src = cfg.nodes[ch.src_node_id].criticality
    crit_dst = cfg.nodes[ch.dst_node_id].criticality
    order = {"low": 0, "medium": 1, "high": 2}
    return crit_src if order.get(crit_src, 1) >= order.get(crit_dst, 1) else crit_dst


def _zone_for_instance(cfg: CryptoConfig, inst: FragilityInstance) -> str:
    if inst.channel_id is not None:
        return cfg.channels[inst.channel_id].zone
    z = inst.context.get("zone")
    return str(z) if z is not None else "global"


def score_instances(
    cfg: CryptoConfig,
    instances: list[FragilityInstance],
    *,
    predicate_weights: Mapping[str, float] | None = None,
    include_heuristics: bool = True,
) -> list[ScoredInstance]:
    """Assign a scalar weight to each instance; deterministic order preserved."""
    pw = dict(DEFAULT_PREDICATE_WEIGHTS)
    if predicate_weights:
        pw.update(predicate_weights)
    scored: list[ScoredInstance] = []
    for inst in instances:
        if not include_heuristics and not inst.paper_core:
            continue
        base = pw.get(inst.predicate, 1.0)
        ds = inst.context.get("data_sensitivity", DataSensitivity.INTERNAL.value)
        sens_m = SENSITIVITY_MULTIPLIER.get(str(ds), 1.0)
        ext_m = 1.3 if inst.context.get("external") is True else 1.0
        crit = _criticality_for_channel(cfg, inst)
        crit_m = CRITICALITY_MULTIPLIER.get(crit, 1.0)
        w = base * sens_m * ext_m * crit_m
        scored.append(ScoredInstance(instance=inst, weight=w, zone=_zone_for_instance(cfg, inst)))
    return scored


def total_risk(scored: list[ScoredInstance]) -> float:
    return float(sum(s.weight for s in scored))


def risk_by_predicate(scored: list[ScoredInstance]) -> dict[str, float]:
    acc: dict[str, float] = defaultdict(float)
    for s in scored:
        acc[s.instance.predicate] += s.weight
    return dict(sorted(acc.items()))


def risk_by_zone(scored: list[ScoredInstance]) -> dict[str, float]:
    acc: dict[str, float] = defaultdict(float)
    for s in scored:
        acc[s.zone] += s.weight
    return dict(sorted(acc.items()))


def risk_by_channel(scored: list[ScoredInstance]) -> dict[str, float]:
    acc: dict[str, float] = defaultdict(float)
    for s in scored:
        cid = s.instance.channel_id
        if cid is not None:
            acc[cid] += s.weight
    return dict(sorted(acc.items()))


def scored_to_rows(scored: list[ScoredInstance]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for i, s in enumerate(scored):
        inst = s.instance
        rows.append(
            {
                "instance_index": i,
                "predicate": inst.predicate,
                "label": inst.label,
                "channel_id": inst.channel_id,
                "key_id": inst.key_id,
                "certificate_id": inst.certificate_id,
                "zone": s.zone,
                "weight": s.weight,
                "preservation_safe": inst.preservation_safe,
                "category": inst.category,
                "paper_core": inst.paper_core,
                "explanation": inst.explanation,
            }
        )
    return rows


def save_risk_table_csv(path: str | Path, scored: list[ScoredInstance]) -> None:
    """Write per-instance risk table to CSV."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    df = pd.DataFrame(scored_to_rows(scored))
    df.to_csv(path, index=False)


def risk_summary_dict(
    cfg: CryptoConfig,
    scored: list[ScoredInstance],
) -> dict[str, Any]:
    """Aggregate metrics for tables / reports."""
    _ = cfg
    return {
        "total_risk": total_risk(scored),
        "by_predicate": risk_by_predicate(scored),
        "by_zone": risk_by_zone(scored),
        "by_channel": risk_by_channel(scored),
        "instance_count": len(scored),
    }


__all__ = [
    "DEFAULT_PREDICATE_WEIGHTS",
    "ScoredInstance",
    "risk_by_channel",
    "risk_by_predicate",
    "risk_by_zone",
    "risk_summary_dict",
    "save_risk_table_csv",
    "score_instances",
    "total_risk",
]
