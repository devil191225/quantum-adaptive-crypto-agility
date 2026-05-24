"""Tests for fragility predicates."""

from __future__ import annotations

from qaca.models import three_node_example
from qaca.predicates import (
    collect_fragilities,
    detect_f6_sensitive_unencrypted,
    detect_f8_regulated_without_pqc_safe_kem,
    split_core_and_heuristics,
)
from qaca.risk import score_instances
from qaca.threat import ThreatState


def test_f8_on_three_node_rsa_regulated() -> None:
    cfg = three_node_example()
    theta = ThreatState(
        horizon_year=2030,
        algorithm_safety={"alg_rsa": "soon_broken", "alg_ml_kem": "safe"},
    )
    f8 = detect_f8_regulated_without_pqc_safe_kem(cfg, theta)
    assert any(x.channel_id == "ch_ab" for x in f8)


def test_f1_soon_broken_on_sensitive() -> None:
    cfg = three_node_example()
    theta = ThreatState(
        horizon_year=2030,
        algorithm_safety={"alg_rsa": "soon_broken", "alg_ml_kem": "safe"},
    )
    inst = collect_fragilities(cfg, theta, migration_targets=frozenset({"alg_ml_kem"}))
    preds = {i.predicate for i in inst}
    assert "F1" in preds


def test_f6_unencrypted_sensitive() -> None:
    from qaca.models import Channel, CryptoConfig, DataSensitivity, Key, KeyLifetimeClass, Node
    from qaca.models import Algorithm

    alg = Algorithm(id="a1", family="rsa", name="RSA")
    n = Node(
        id="n1",
        zone="z",
        trust_domain="t",
        supported_algorithm_ids=frozenset({"a1"}),
    )
    k = Key(id="k1", algorithm_id="a1", lifetime_class=KeyLifetimeClass.SHORT)
    ch = Channel(
        id="c1",
        src_node_id="n1",
        dst_node_id="n1",
        protocol="x",
        kem_algorithm_id="a1",
        data_sensitivity=DataSensitivity.CONFIDENTIAL,
        encrypted=False,
        external=False,
        zone="z",
        key_id="k1",
    )
    cfg = CryptoConfig(
        nodes={"n1": n},
        channels={"c1": ch},
        algorithms={"a1": alg},
        keys={"k1": k},
        certificates={},
    )
    theta = ThreatState(horizon_year=None, algorithm_safety={})
    hits = detect_f6_sensitive_unencrypted(cfg, theta)
    assert len(hits) == 1


def test_f7_excluded_from_core_risk_unless_enabled() -> None:
    from dataclasses import replace

    from qaca.simulator import experiment_crypto_mesh, static_migration_threat

    cfg = experiment_crypto_mesh()
    # Force two different KEM families into one zone to trigger F7.
    ch = cfg.channels["ch_pay_core"]
    mixed = replace(ch, zone="payments")
    channels = dict(cfg.channels)
    channels[mixed.id] = mixed
    from qaca.models import CryptoConfig

    cfg = CryptoConfig(
        nodes=cfg.nodes,
        channels=channels,
        algorithms=cfg.algorithms,
        keys=cfg.keys,
        certificates=cfg.certificates,
        zones=cfg.zones,
    )
    theta = static_migration_threat()
    all_inst = collect_fragilities(cfg, theta, migration_targets=frozenset({"alg_ml_kem"}), include_f7=True)
    core, heur = split_core_and_heuristics(all_inst)
    assert any(i.predicate == "F7" for i in heur)
    assert all(i.predicate != "F7" for i in core)
    scored_core = score_instances(cfg, all_inst, include_heuristics=False)
    scored_all = score_instances(cfg, all_inst, include_heuristics=True)
    assert len(scored_all) >= len(scored_core)
