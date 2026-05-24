"""Tests for TASK-002 crypto-configuration data model."""

from __future__ import annotations

import json

import pytest

from qaca.io import config_full_dict, config_summary_dict, config_summary_json
from qaca.models import (
    Algorithm,
    Certificate,
    Channel,
    CryptoConfig,
    DataSensitivity,
    Key,
    KeyLifetimeClass,
    Node,
    three_node_example,
)
from qaca.threat import ThreatState


def test_three_node_example_validates() -> None:
    cfg = three_node_example()
    cfg.validate()
    assert len(cfg.nodes) == 3
    assert len(cfg.channels) == 2


def test_config_summary_json_roundtrip() -> None:
    cfg = three_node_example()
    s = config_summary_json(cfg)
    parsed = json.loads(s)
    assert parsed["node_count"] == 3
    assert set(parsed["zones"]) == {"edge", "payments", "analytics"}
    assert "ch_ab" in parsed["channels"]


def test_config_summary_with_threat() -> None:
    cfg = three_node_example()
    theta = ThreatState(
        horizon_year=2030,
        algorithm_safety={
            "alg_rsa": "soon_broken",
            "alg_ml_kem": "safe",
        },
        degraded_algorithm_ids=frozenset(),
    )
    d = config_summary_dict(cfg, theta)
    assert d["threat"]["horizon_year"] == 2030
    assert d["threat"]["algorithm_safety"]["alg_rsa"] == "soon_broken"


def test_channel_endpoint_must_exist() -> None:
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
        dst_node_id="missing",
        protocol="TLS1.3",
        kem_algorithm_id="a1",
        data_sensitivity=DataSensitivity.INTERNAL,
        encrypted=True,
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
    with pytest.raises(ValueError, match="dst_node_id"):
        cfg.validate()


def test_channel_requires_endpoint_support_for_kem() -> None:
    alg = Algorithm(id="a1", family="ml_kem", name="ML-KEM")
    n1 = Node(
        id="n1",
        zone="z",
        trust_domain="t",
        supported_algorithm_ids=frozenset(),  # does not support a1
    )
    n2 = Node(
        id="n2",
        zone="z",
        trust_domain="t",
        supported_algorithm_ids=frozenset({"a1"}),
    )
    k = Key(id="k1", algorithm_id="a1", lifetime_class=KeyLifetimeClass.SHORT)
    ch = Channel(
        id="c1",
        src_node_id="n1",
        dst_node_id="n2",
        protocol="TLS1.3",
        kem_algorithm_id="a1",
        data_sensitivity=DataSensitivity.PUBLIC,
        encrypted=True,
        external=False,
        zone="z",
        key_id="k1",
    )
    cfg = CryptoConfig(
        nodes={"n1": n1, "n2": n2},
        channels={"c1": ch},
        algorithms={"a1": alg},
        keys={"k1": k},
        certificates={},
    )
    with pytest.raises(ValueError, match="source node"):
        cfg.validate()


def test_key_algorithm_must_match_channel_kem() -> None:
    alg_rsa = Algorithm(id="rsa", family="rsa", name="RSA")
    alg_ml = Algorithm(id="ml", family="ml_kem", name="ML-KEM")
    n1 = Node(
        id="n1",
        zone="z",
        trust_domain="t",
        supported_algorithm_ids=frozenset({"rsa", "ml"}),
    )
    n2 = Node(
        id="n2",
        zone="z",
        trust_domain="t",
        supported_algorithm_ids=frozenset({"rsa", "ml"}),
    )
    k = Key(id="k1", algorithm_id="rsa", lifetime_class=KeyLifetimeClass.SHORT)
    ch = Channel(
        id="c1",
        src_node_id="n1",
        dst_node_id="n2",
        protocol="TLS1.3",
        kem_algorithm_id="ml",
        data_sensitivity=DataSensitivity.PUBLIC,
        encrypted=True,
        external=False,
        zone="z",
        key_id="k1",
    )
    cfg = CryptoConfig(
        nodes={"n1": n1, "n2": n2},
        channels={"c1": ch},
        algorithms={"rsa": alg_rsa, "ml": alg_ml},
        keys={"k1": k},
        certificates={},
    )
    with pytest.raises(ValueError, match="key .* algorithm_id"):
        cfg.validate()


def test_certificate_linked_key_must_exist() -> None:
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
        protocol="TLS1.3",
        kem_algorithm_id="a1",
        data_sensitivity=DataSensitivity.PUBLIC,
        encrypted=True,
        external=False,
        zone="z",
        key_id="k1",
    )
    cert = Certificate(
        id="cert1",
        subject="n1",
        issuer="CA",
        linked_key_id="no_such_key",
        subject_node_id="n1",
    )
    cfg = CryptoConfig(
        nodes={"n1": n},
        channels={"c1": ch},
        algorithms={"a1": alg},
        keys={"k1": k},
        certificates={"cert1": cert},
    )
    with pytest.raises(ValueError, match="linked_key_id"):
        cfg.validate()


def test_config_full_dict_serializable() -> None:
    cfg = three_node_example()
    blob = config_full_dict(cfg)
    json.dumps(blob)


def test_threat_state_safety_for() -> None:
    theta = ThreatState(
        horizon_year=2035,
        algorithm_safety={"alg_ml_kem": "safe"},
        degraded_algorithm_ids=frozenset({"alg_ml_kem"}),
    )
    assert theta.safety_for("alg_ml_kem") == "degraded"
    assert theta.safety_for("other") == "unknown"
