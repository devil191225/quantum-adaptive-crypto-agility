"""Synthetic graph fixtures and scenario drivers for Config-Lab experiments."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
import random
import time
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

from qaca.models import (
    Algorithm,
    Certificate,
    Channel,
    CryptoConfig,
    DataSensitivity,
    Key,
    KeyLifetimeClass,
    Node,
)
from qaca.mutations import SimulationPolicy
from qaca.planner import greedy_migrate_until_stable, save_mutation_log_json, summarize_blocked
from qaca.predicates import WEAK_CA_ISSUERS, collect_fragilities, split_core_and_heuristics
from qaca.risk import (
    DEFAULT_PREDICATE_WEIGHTS,
    risk_summary_dict,
    save_risk_table_csv,
    score_instances,
    total_risk,
)
from qaca.threat import ThreatState


def experiment_crypto_mesh() -> CryptoConfig:
    """Deterministic multi-zone mesh for static migration + threat-switch demos."""
    algs = {
        "alg_rsa": Algorithm(id="alg_rsa", family="rsa", name="RSA KEM"),
        "alg_ecdh": Algorithm(id="alg_ecdh", family="ecdh", name="ECDH KEM"),
        "alg_ml_kem": Algorithm(id="alg_ml_kem", family="ml_kem", name="ML-KEM"),
        "alg_hybrid": Algorithm(id="alg_hybrid", family="hybrid", name="Hybrid KEM"),
    }
    nodes = {
        "n_edge": Node(
            id="n_edge",
            zone="edge",
            trust_domain="corp.example",
            supported_algorithm_ids=frozenset(algs.keys()),
            criticality="high",
        ),
        "n_pay": Node(
            id="n_pay",
            zone="payments",
            trust_domain="corp.example",
            supported_algorithm_ids=frozenset(algs.keys()),
            criticality="high",
        ),
        "n_core": Node(
            id="n_core",
            zone="core",
            trust_domain="corp.example",
            supported_algorithm_ids=frozenset(algs.keys()),
            criticality="medium",
        ),
        "n_partner": Node(
            id="n_partner",
            zone="dmz",
            trust_domain="partner.example",
            supported_algorithm_ids=frozenset({"alg_ml_kem", "alg_hybrid", "alg_rsa"}),
            criticality="medium",
        ),
    }
    keys = {
        "k_rsa_edge": Key(
            id="k_rsa_edge",
            algorithm_id="alg_rsa",
            lifetime_class=KeyLifetimeClass.LONG,
            owner_node_id="n_edge",
        ),
        "k_rsa_pay": Key(
            id="k_rsa_pay",
            algorithm_id="alg_rsa",
            lifetime_class=KeyLifetimeClass.LONG,
            owner_node_id="n_pay",
        ),
        "k_ecdh_core": Key(
            id="k_ecdh_core",
            algorithm_id="alg_ecdh",
            lifetime_class=KeyLifetimeClass.MEDIUM,
            owner_node_id="n_core",
        ),
        "k_rsa_partner": Key(
            id="k_rsa_partner",
            algorithm_id="alg_rsa",
            lifetime_class=KeyLifetimeClass.LONG,
            owner_node_id="n_partner",
        ),
    }
    channels = {
        "ch_edge_pay": Channel(
            id="ch_edge_pay",
            src_node_id="n_edge",
            dst_node_id="n_pay",
            protocol="TLS1.3",
            kem_algorithm_id="alg_rsa",
            data_sensitivity=DataSensitivity.REGULATED,
            encrypted=True,
            external=False,
            zone="payments",
            key_id="k_rsa_edge",
        ),
        "ch_pay_core": Channel(
            id="ch_pay_core",
            src_node_id="n_pay",
            dst_node_id="n_core",
            protocol="TLS1.3",
            kem_algorithm_id="alg_ecdh",
            data_sensitivity=DataSensitivity.CONFIDENTIAL,
            encrypted=True,
            external=False,
            zone="core",
            key_id="k_ecdh_core",
        ),
        "ch_core_partner": Channel(
            id="ch_core_partner",
            src_node_id="n_core",
            dst_node_id="n_partner",
            protocol="TLS1.3",
            kem_algorithm_id="alg_rsa",
            data_sensitivity=DataSensitivity.CONFIDENTIAL,
            encrypted=True,
            external=True,
            zone="dmz",
            key_id="k_rsa_partner",
        ),
    }
    weak_issuer = next(iter(WEAK_CA_ISSUERS))
    certs = {
        "cert_pay": Certificate(
            id="cert_pay",
            subject="payments.corp.example",
            issuer=weak_issuer,
            linked_key_id="k_rsa_pay",
            subject_node_id="n_pay",
        ),
    }
    cfg = CryptoConfig(
        nodes=nodes,
        channels=channels,
        algorithms=algs,
        keys=keys,
        certificates=certs,
        zones=None,
    )
    cfg.validate()
    return cfg


def random_crypto_mesh(seed: int, *, node_count: int = 6) -> CryptoConfig:
    """Seeded stochastic synthetic graph for robustness sweeps."""
    rng = random.Random(seed)
    algs = {
        "alg_rsa": Algorithm(id="alg_rsa", family="rsa", name="RSA KEM"),
        "alg_ecdh": Algorithm(id="alg_ecdh", family="ecdh", name="ECDH KEM"),
        "alg_ml_kem": Algorithm(id="alg_ml_kem", family="ml_kem", name="ML-KEM"),
        "alg_hybrid": Algorithm(id="alg_hybrid", family="hybrid", name="Hybrid KEM"),
    }
    zones = ["edge", "payments", "core", "dmz", "analytics", "legacy"]
    domains = ["corp.example", "partner.example"]
    support_templates = [
        {"alg_rsa", "alg_ecdh", "alg_ml_kem", "alg_hybrid"},
        {"alg_rsa", "alg_ecdh", "alg_ml_kem"},
        {"alg_rsa", "alg_ml_kem", "alg_hybrid"},
        {"alg_rsa", "alg_ecdh"},
        {"alg_rsa", "alg_ml_kem"},
    ]
    nodes: dict[str, Node] = {}
    for i in range(node_count):
        sid = f"n{i}"
        sup = frozenset(rng.choice(support_templates))
        nodes[sid] = Node(
            id=sid,
            zone=rng.choice(zones),
            trust_domain=rng.choice(domains),
            supported_algorithm_ids=sup,
            criticality=rng.choice(["low", "medium", "high"]),
        )
    ch_count = max(node_count + 1, 5)
    channels: dict[str, Channel] = {}
    keys: dict[str, Key] = {}
    for i in range(ch_count):
        src = f"n{rng.randrange(node_count)}"
        dst = f"n{rng.randrange(node_count)}"
        if src == dst:
            dst = f"n{(int(src[1:]) + 1) % node_count}"
        inter = nodes[src].supported_algorithm_ids & nodes[dst].supported_algorithm_ids
        if not inter:
            # fallback to rsa if no overlap; ensure both support it
            src_node = nodes[src]
            dst_node = nodes[dst]
            nodes[src] = Node(
                id=src_node.id,
                zone=src_node.zone,
                trust_domain=src_node.trust_domain,
                supported_algorithm_ids=frozenset(set(src_node.supported_algorithm_ids) | {"alg_rsa"}),
                criticality=src_node.criticality,
            )
            nodes[dst] = Node(
                id=dst_node.id,
                zone=dst_node.zone,
                trust_domain=dst_node.trust_domain,
                supported_algorithm_ids=frozenset(set(dst_node.supported_algorithm_ids) | {"alg_rsa"}),
                criticality=dst_node.criticality,
            )
            inter = {"alg_rsa"}
        kem = rng.choice(sorted(inter))
        kid = f"k{i}"
        keys[kid] = Key(
            id=kid,
            algorithm_id=kem,
            lifetime_class=rng.choice(
                [KeyLifetimeClass.SHORT, KeyLifetimeClass.MEDIUM, KeyLifetimeClass.LONG, KeyLifetimeClass.OVERDUE]
            ),
            owner_node_id=src,
        )
        channels[f"ch{i}"] = Channel(
            id=f"ch{i}",
            src_node_id=src,
            dst_node_id=dst,
            protocol="TLS1.3",
            kem_algorithm_id=kem,
            data_sensitivity=rng.choice(list(DataSensitivity)),
            encrypted=rng.choice([True, True, True, False]),
            external=(nodes[src].trust_domain != nodes[dst].trust_domain),
            zone=rng.choice(zones),
            key_id=kid,
        )
    certs: dict[str, Certificate] = {}
    weak_issuer = next(iter(WEAK_CA_ISSUERS))
    for i in range(max(2, node_count // 2)):
        nid = f"n{i}"
        certs[f"cert{i}"] = Certificate(
            id=f"cert{i}",
            subject=f"svc-{nid}.example",
            issuer=weak_issuer if rng.random() < 0.4 else "Corp-SubCA",
            linked_key_id=rng.choice(list(keys.keys())),
            subject_node_id=nid,
        )
    cfg = CryptoConfig(
        nodes=nodes,
        channels=channels,
        algorithms=algs,
        keys=keys,
        certificates=certs,
        zones=None,
    )
    cfg.validate()
    return cfg


def _build_config(seed: int, template: str) -> CryptoConfig:
    if template == "fixed":
        return experiment_crypto_mesh()
    if template == "random_graph":
        return random_crypto_mesh(seed)
    raise ValueError(f"Unknown template {template!r}")


def _graph_summary(cfg: CryptoConfig, *, seed: int, template: str) -> dict[str, Any]:
    return {
        "seed": seed,
        "template": template,
        "node_count": len(cfg.nodes),
        "channel_count": len(cfg.channels),
        "key_count": len(cfg.keys),
        "certificate_count": len(cfg.certificates),
        "zone_count": len(cfg.derived_zones()),
    }


def static_migration_threat() -> ThreatState:
    return ThreatState(
        horizon_year=2030,
        algorithm_safety={
            "alg_rsa": "soon_broken",
            "alg_ecdh": "soon_broken",
            "alg_ml_kem": "safe",
            "alg_hybrid": "safe",
        },
        require_kem_diversity=False,
        degraded_algorithm_ids=frozenset(),
        notes="synthetic: classical KEMs soon_broken under horizon",
    )


def concentration_policy_update_theta() -> ThreatState:
    """Simulated policy/confidence update: concentration risk favors hybrid diversity."""
    return ThreatState(
        horizon_year=2035,
        algorithm_safety={
            "alg_rsa": "soon_broken",
            "alg_ecdh": "soon_broken",
            "alg_ml_kem": "safe",
            "alg_hybrid": "safe",
        },
        require_kem_diversity=True,
        degraded_algorithm_ids=frozenset({"alg_ml_kem"}),
        notes=(
            "synthetic policy/confidence event: concentration risk discourages reliance "
            "on a single KEM class; hybrid preferred where supported"
        ),
    )


def _save_risk_figure(
    path: Path,
    risks: list[float],
    *,
    title: str,
    threat_switch_index: int | None = None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.plot(range(len(risks)), risks, marker="o")
    ax.set_xlabel("mutation_step")
    ax.set_ylabel("total_risk")
    ax.set_title(title)
    if threat_switch_index is not None:
        ax.axvline(threat_switch_index, color="tab:red", linestyle="--", label="threat_switch")
        ax.legend()
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


def run_static_migration(*, seed: int, output_dir: str = "results", template: str = "fixed") -> int:
    """Scenario A: classical/ecdh risky → migrate toward ML-KEM under support constraints."""
    _ = seed
    base = Path(output_dir) / "static_migration"
    base.mkdir(parents=True, exist_ok=True)
    t0 = time.perf_counter()
    cfg = _build_config(seed, template)
    theta = static_migration_threat()
    migration = frozenset({"alg_ml_kem", "alg_hybrid"})
    policy = SimulationPolicy(kms_capable_node_ids=None, check_endpoint_support=True)
    inst0 = collect_fragilities(cfg, theta, migration_targets=migration)
    core0, heur0 = split_core_and_heuristics(inst0)
    scored0 = score_instances(cfg, core0, include_heuristics=False)
    scored0_all = score_instances(cfg, inst0, include_heuristics=True)
    save_risk_table_csv(base / "risk_instances_initial.csv", scored0)
    (base / "fragilities_initial.json").write_text(
        json.dumps([asdict(i) for i in inst0], indent=2),
        encoding="utf-8",
    )
    cfg_end, logs, risks = greedy_migrate_until_stable(
        cfg,
        theta,
        migration_targets=migration,
        primary_target_algorithm_id="alg_ml_kem",
        policy=policy,
    )
    save_mutation_log_json(base / "mutation_log.json", logs)
    blocked = summarize_blocked(logs)
    pd.DataFrame(blocked if blocked else [{"note": "none"}]).to_csv(
        base / "blocked_mutations.csv", index=False
    )
    risks_full = list(risks)
    inst1 = collect_fragilities(cfg_end, theta, migration_targets=migration)
    core1, heur1 = split_core_and_heuristics(inst1)
    scored1 = score_instances(cfg_end, core1, include_heuristics=False)
    scored1_all = score_instances(cfg_end, inst1, include_heuristics=True)
    save_risk_table_csv(base / "risk_instances_final.csv", scored1)
    pd.DataFrame({"step": list(range(len(risks_full))), "total_risk": risks_full}).to_csv(
        base / "risk_by_step.csv", index=False
    )
    pd.DataFrame([_graph_summary(cfg, seed=seed, template=template)]).to_csv(
        base / "graph_summary.csv", index=False
    )
    summary = {
        "scenario": "static_migration",
        "seed": seed,
        "template": template,
        "initial_core_risk": risks_full[0],
        "final_core_risk": risks_full[-1],
        "initial_all_risk": total_risk(scored0_all),
        "final_all_risk": total_risk(scored1_all),
        "heuristic_instance_count_initial": len(heur0),
        "heuristic_instance_count_final": len(heur1),
        "risk_summary_initial": risk_summary_dict(cfg, scored0),
        "risk_summary_final": risk_summary_dict(cfg_end, scored1),
        "mutation_attempt_count": len([x for x in logs if x.get("status") in {"applied", "blocked"}]),
        "mutation_applied_count": len([x for x in logs if x.get("status") == "applied"]),
        "mutation_blocked_count": len([x for x in logs if x.get("status") == "blocked"]),
        "runtime_seconds": time.perf_counter() - t0,
    }
    (base / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    fig_path = Path(output_dir) / "figures" / "static_migration_risk.png"
    _save_risk_figure(fig_path, risks_full, title="Static migration: total risk vs step")
    return 0


def run_threat_switch(*, seed: int, output_dir: str = "results", template: str = "fixed") -> int:
    """Scenario B: modeled policy/confidence update triggers diversity-oriented replanning."""
    _ = seed
    base = Path(output_dir) / "threat_switch"
    base.mkdir(parents=True, exist_ok=True)
    t0 = time.perf_counter()
    cfg0 = _build_config(seed, template)
    theta0 = static_migration_threat()
    migration = frozenset({"alg_ml_kem", "alg_hybrid"})
    policy = SimulationPolicy(kms_capable_node_ids=None, check_endpoint_support=True)
    cfg_mid, logs_a, risks_a = greedy_migrate_until_stable(
        cfg0,
        theta0,
        migration_targets=migration,
        primary_target_algorithm_id="alg_ml_kem",
        policy=policy,
    )
    theta1 = concentration_policy_update_theta()
    inst_mid = collect_fragilities(cfg_mid, theta1, migration_targets=migration)
    core_mid, heur_mid = split_core_and_heuristics(inst_mid)
    scored_mid = score_instances(cfg_mid, core_mid, include_heuristics=False)
    save_risk_table_csv(base / "risk_instances_after_threat_update.csv", scored_mid)
    cfg_end, logs_b, risks_b = greedy_migrate_until_stable(
        cfg_mid,
        theta1,
        migration_targets=migration,
        primary_target_algorithm_id="alg_hybrid",
        policy=policy,
    )
    all_logs = [{"phase": "static_style_migration", **x} for x in logs_a] + [
        {"phase": "post_threat_replan", **x} for x in logs_b
    ]
    save_mutation_log_json(base / "mutation_log.json", all_logs)
    switch_idx = max(len(risks_a) - 1, 0)
    risks_concat = risks_a + risks_b[1:]
    pd.DataFrame({"step": list(range(len(risks_concat))), "total_risk": risks_concat}).to_csv(
        base / "risk_by_step.csv", index=False
    )
    pd.DataFrame([_graph_summary(cfg0, seed=seed, template=template)]).to_csv(
        base / "graph_summary.csv", index=False
    )
    blk = summarize_blocked(all_logs)
    pd.DataFrame(blk if blk else [{"note": "none"}]).to_csv(base / "blocked_mutations.csv", index=False)
    summary = {
        "scenario": "threat_switch",
        "event": "concentration_policy_update",
        "seed": seed,
        "template": template,
        "threat_switch_step_index": switch_idx,
        "initial_core_risk": risks_concat[0],
        "final_core_risk": risks_concat[-1],
        "heuristic_instance_count_after_update": len(heur_mid),
        "note": (
            "This scenario models a policy/confidence update, not a cryptanalytic "
            "failure claim for ML-KEM."
        ),
        "mutation_attempt_count": len([x for x in all_logs if x.get("status") in {"applied", "blocked"}]),
        "mutation_applied_count": len([x for x in all_logs if x.get("status") == "applied"]),
        "mutation_blocked_count": len([x for x in all_logs if x.get("status") == "blocked"]),
        "runtime_seconds": time.perf_counter() - t0,
    }
    (base / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    pd.DataFrame(
        [
            {"phase": "before_update", **asdict(theta0)},
            {"phase": "after_update", **asdict(theta1)},
        ]
    ).to_csv(base / "threat_state_transition.csv", index=False)
    fig_path = Path(output_dir) / "figures" / "threat_switch_risk.png"
    _save_risk_figure(
        fig_path,
        risks_concat,
        title="Threat confidence/policy update: total risk vs step",
        threat_switch_index=switch_idx,
    )
    return 0


def run_sensitivity(*, seed: int, output_dir: str = "results", template: str = "fixed") -> int:
    """Sensitivity sweep over risk-weight scale profiles."""
    _ = seed
    t0 = time.perf_counter()
    base = Path(output_dir) / "sensitivity"
    base.mkdir(parents=True, exist_ok=True)
    profiles = {"low": 0.75, "default": 1.0, "high": 1.25}
    rows: list[dict[str, Any]] = []
    migration = frozenset({"alg_ml_kem", "alg_hybrid"})

    # Scenario A (static migration)
    cfg_s0 = _build_config(seed, template)
    theta_s = static_migration_threat()
    policy = SimulationPolicy(kms_capable_node_ids=None, check_endpoint_support=True)
    cfg_s1, _, _ = greedy_migrate_until_stable(
        cfg_s0,
        theta_s,
        migration_targets=migration,
        primary_target_algorithm_id="alg_ml_kem",
        policy=policy,
    )

    # Scenario B (threat switch end state)
    cfg_t0 = _build_config(seed, template)
    theta0 = static_migration_threat()
    cfg_mid, _, _ = greedy_migrate_until_stable(
        cfg_t0,
        theta0,
        migration_targets=migration,
        primary_target_algorithm_id="alg_ml_kem",
        policy=policy,
    )
    theta1 = concentration_policy_update_theta()
    cfg_t1, _, _ = greedy_migrate_until_stable(
        cfg_mid,
        theta1,
        migration_targets=migration,
        primary_target_algorithm_id="alg_hybrid",
        policy=policy,
    )

    for profile, scale in profiles.items():
        weights = {k: v * scale for k, v in DEFAULT_PREDICATE_WEIGHTS.items()}
        # Static scenario risk
        inst_a0, _ = split_core_and_heuristics(
            collect_fragilities(cfg_s0, theta_s, migration_targets=migration)
        )
        inst_a1, _ = split_core_and_heuristics(
            collect_fragilities(cfg_s1, theta_s, migration_targets=migration)
        )
        ra0 = total_risk(score_instances(cfg_s0, inst_a0, predicate_weights=weights, include_heuristics=False))
        ra1 = total_risk(score_instances(cfg_s1, inst_a1, predicate_weights=weights, include_heuristics=False))
        rows.append(
            {
                "scenario": "static_migration",
                "profile": profile,
                "scale": scale,
                "initial_core_risk": ra0,
                "final_core_risk": ra1,
                "risk_reduced": ra1 <= ra0,
            }
        )
        # Threat switch scenario risk under theta1
        inst_b0, _ = split_core_and_heuristics(
            collect_fragilities(cfg_mid, theta1, migration_targets=migration)
        )
        inst_b1, _ = split_core_and_heuristics(
            collect_fragilities(cfg_t1, theta1, migration_targets=migration)
        )
        rb0 = total_risk(score_instances(cfg_mid, inst_b0, predicate_weights=weights, include_heuristics=False))
        rb1 = total_risk(score_instances(cfg_t1, inst_b1, predicate_weights=weights, include_heuristics=False))
        rows.append(
            {
                "scenario": "threat_switch",
                "profile": profile,
                "scale": scale,
                "initial_core_risk": rb0,
                "final_core_risk": rb1,
                "risk_reduced": rb1 <= rb0,
            }
        )

    df = pd.DataFrame(rows)
    df.to_csv(base / "risk_sensitivity.csv", index=False)
    pd.DataFrame([_graph_summary(cfg_s0, seed=seed, template=template)]).to_csv(
        base / "graph_summary.csv", index=False
    )
    md = [
        "| scenario | profile | scale | initial_core_risk | final_core_risk | risk_reduced |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for _, r in df.iterrows():
        md.append(
            f"| {r['scenario']} | {r['profile']} | {r['scale']:.2f} | "
            f"{r['initial_core_risk']:.2f} | {r['final_core_risk']:.2f} | {bool(r['risk_reduced'])} |"
        )
    (base / "risk_sensitivity.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    (base / "summary.json").write_text(
        json.dumps(
            {
                "scenario": "sensitivity",
                "seed": seed,
                "template": template,
                "profile_count": len(profiles),
                "runtime_seconds": time.perf_counter() - t0,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return 0


__all__ = [
    "concentration_policy_update_theta",
    "experiment_crypto_mesh",
    "random_crypto_mesh",
    "run_sensitivity",
    "run_static_migration",
    "run_threat_switch",
    "static_migration_threat",
]
