"""Risk engine tests."""

from __future__ import annotations

from qaca.models import three_node_example
from qaca.predicates import collect_fragilities
from qaca.risk import risk_summary_dict, score_instances, total_risk
from qaca.threat import ThreatState


def test_total_risk_deterministic() -> None:
    cfg = three_node_example()
    theta = ThreatState(
        horizon_year=2030,
        algorithm_safety={"alg_rsa": "soon_broken", "alg_ml_kem": "safe"},
    )
    inst = collect_fragilities(cfg, theta, migration_targets=frozenset({"alg_ml_kem"}))
    s1 = score_instances(cfg, inst)
    s2 = score_instances(cfg, inst)
    assert total_risk(s1) == total_risk(s2)
    summary = risk_summary_dict(cfg, s1)
    assert "by_predicate" in summary
