"""Mutation and planner smoke tests."""

from __future__ import annotations

from qaca.models import three_node_example
from qaca.mutations import KemUpgrade, SimulationPolicy, apply_kem_upgrade, can_apply_kem_upgrade
from qaca.planner import greedy_migrate_until_stable
from qaca.simulator import experiment_crypto_mesh, static_migration_threat
from qaca.threat import ThreatState


def test_kem_upgrade_applies() -> None:
    cfg = three_node_example()
    ch = cfg.channels["ch_ab"]
    pol = SimulationPolicy()
    ok, _ = can_apply_kem_upgrade(cfg, ch, "alg_ml_kem", pol)
    assert ok
    mut = KemUpgrade(channel_id="ch_ab", target_algorithm_id="alg_ml_kem", new_key_id="k_new_ab")
    cfg2 = apply_kem_upgrade(cfg, mut)
    assert cfg2.channels["ch_ab"].kem_algorithm_id == "alg_ml_kem"


def test_greedy_reduces_risk_on_mesh() -> None:
    cfg = experiment_crypto_mesh()
    theta = static_migration_threat()
    migration = frozenset({"alg_ml_kem", "alg_hybrid"})
    policy = SimulationPolicy()
    _, _, risks = greedy_migrate_until_stable(
        cfg,
        theta,
        migration_targets=migration,
        primary_target_algorithm_id="alg_ml_kem",
        policy=policy,
    )
    assert risks[-1] <= risks[0]


def test_blocked_when_no_support() -> None:
    from qaca.models import Algorithm, Channel, CryptoConfig, DataSensitivity, Key, KeyLifetimeClass, Node

    alg_r = Algorithm(id="r", family="rsa", name="RSA")
    alg_m = Algorithm(id="m", family="ml_kem", name="ML")
    n1 = Node(id="a", zone="z", trust_domain="t", supported_algorithm_ids=frozenset({"r"}))
    n2 = Node(id="b", zone="z", trust_domain="t", supported_algorithm_ids=frozenset({"r"}))
    k = Key(id="k", algorithm_id="r", lifetime_class=KeyLifetimeClass.SHORT)
    ch = Channel(
        id="c",
        src_node_id="a",
        dst_node_id="b",
        protocol="TLS",
        kem_algorithm_id="r",
        data_sensitivity=DataSensitivity.REGULATED,
        encrypted=True,
        external=False,
        zone="z",
        key_id="k",
    )
    cfg = CryptoConfig(
        nodes={"a": n1, "b": n2},
        channels={"c": ch},
        algorithms={"r": alg_r, "m": alg_m},
        keys={"k": k},
        certificates={},
    )
    theta = ThreatState(horizon_year=2030, algorithm_safety={"r": "soon_broken", "m": "safe"})
    _, logs, _ = greedy_migrate_until_stable(
        cfg,
        theta,
        migration_targets=frozenset({"m"}),
        primary_target_algorithm_id="m",
        policy=SimulationPolicy(check_endpoint_support=True),
        max_steps=4,
    )
    assert any(log.get("status") == "blocked" for log in logs)
