"""PQC-relevant fragility predicates (structured instances, not bare booleans)."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace
from typing import Any

from qaca.models import (
    Algorithm,
    Certificate,
    Channel,
    CryptoConfig,
    DataSensitivity,
    KeyLifetimeClass,
)
from qaca.threat import ThreatState

# Families treated as quantum-resistant for F8 / migration posture (Config-Lab convention).
PQC_SAFE_FAMILIES: frozenset[str] = frozenset({"ml_kem", "hybrid"})

HIGH_SENSITIVITY: frozenset[DataSensitivity] = frozenset(
    {DataSensitivity.CONFIDENTIAL, DataSensitivity.REGULATED}
)

# Optional F5: issuer strings considered weak for regulated/confidential services.
WEAK_CA_ISSUERS: frozenset[str] = frozenset({"Legacy-Root", "Test-Weak-CA"})


@dataclass(frozen=True, slots=True)
class FragilityInstance:
    """Single witness for a fragility predicate."""

    predicate: str
    """Short id, e.g. F1, F2."""
    label: str
    """Stable snake_case label for logging and risk weights."""
    channel_id: str | None
    key_id: str | None
    certificate_id: str | None
    context: dict[str, Any]
    explanation: str
    preservation_safe: bool = True
    """False for heuristic / non-preservation-safe patterns (e.g. F7)."""
    category: str = "core"
    """core or heuristic."""
    paper_core: bool = True
    """Included in first-paper core risk totals when True."""


def _safety(threat: ThreatState, algorithm_id: str) -> str:
    return threat.safety_for(algorithm_id)


def _alg(cfg: CryptoConfig, algorithm_id: str) -> Algorithm:
    return cfg.algorithms[algorithm_id]


def detect_f1_soon_broken_kem_on_sensitive_channel(
    cfg: CryptoConfig,
    threat: ThreatState,
) -> list[FragilityInstance]:
    """F1: KEM labeled soon_broken or degraded on confidential/regulated traffic."""
    out: list[FragilityInstance] = []
    for ch in cfg.channels.values():
        if ch.data_sensitivity not in HIGH_SENSITIVITY:
            continue
        lab = _safety(threat, ch.kem_algorithm_id)
        if lab not in {"soon_broken", "degraded"}:
            continue
        ctx = {
            "zone": ch.zone,
            "data_sensitivity": ch.data_sensitivity.value,
            "external": ch.external,
            "algorithm_id": ch.kem_algorithm_id,
            "threat_label": lab,
        }
        out.append(
            FragilityInstance(
                predicate="F1",
                label="soon_broken_kem_on_sensitive_channel",
                channel_id=ch.id,
                key_id=ch.key_id,
                certificate_id=None,
                context=ctx,
                explanation=(
                    f"Channel {ch.id} carries {ch.data_sensitivity.value} data using "
                    f"{ch.kem_algorithm_id} while threat model marks it {lab!r}."
                ),
                preservation_safe=True,
            )
        )
    return out


def detect_f2_unsupported_migration_target(
    cfg: CryptoConfig,
    threat: ThreatState,
    *,
    migration_targets: frozenset[str],
) -> list[FragilityInstance]:
    """F2: Endpoint lacks support for a configured migration-target algorithm id.

    Operational / support predicate: valid graphs always support the *current* KEM;
    this checks readiness to move to named targets (e.g. ML-KEM).
    """
    out: list[FragilityInstance] = []
    if not migration_targets:
        return out
    for ch in cfg.channels.values():
        src = cfg.nodes[ch.src_node_id]
        dst = cfg.nodes[ch.dst_node_id]
        for tid in sorted(migration_targets):
            if tid not in cfg.algorithms:
                continue
            missing_on: list[str] = []
            if tid not in src.supported_algorithm_ids:
                missing_on.append(f"src:{src.id}")
            if tid not in dst.supported_algorithm_ids:
                missing_on.append(f"dst:{dst.id}")
            if not missing_on:
                continue
            ctx = {
                "zone": ch.zone,
                "data_sensitivity": ch.data_sensitivity.value,
                "target_algorithm_id": tid,
                "missing_on": missing_on,
            }
            out.append(
                FragilityInstance(
                    predicate="F2",
                    label="unsupported_kem_class_at_endpoint",
                    channel_id=ch.id,
                    key_id=ch.key_id,
                    certificate_id=None,
                    context=ctx,
                    explanation=(
                        f"Channel {ch.id} cannot adopt target algorithm {tid!r}: "
                        f"unsupported on {', '.join(missing_on)}."
                    ),
                    preservation_safe=True,
                )
            )
    return out


def detect_f3_sensitive_cross_domain(
    cfg: CryptoConfig,
    threat: ThreatState,
) -> list[FragilityInstance]:
    """F3: Sensitive data crosses an untrusted boundary (external or trust domain change)."""
    _ = threat
    out: list[FragilityInstance] = []
    for ch in cfg.channels.values():
        if ch.data_sensitivity not in HIGH_SENSITIVITY:
            continue
        src = cfg.nodes[ch.src_node_id]
        dst = cfg.nodes[ch.dst_node_id]
        cross = ch.external or (src.trust_domain != dst.trust_domain)
        if not cross:
            continue
        ctx = {
            "zone": ch.zone,
            "data_sensitivity": ch.data_sensitivity.value,
            "external": ch.external,
            "src_trust_domain": src.trust_domain,
            "dst_trust_domain": dst.trust_domain,
        }
        out.append(
            FragilityInstance(
                predicate="F3",
                label="sensitive_channel_untrusted_domain",
                channel_id=ch.id,
                key_id=ch.key_id,
                certificate_id=None,
                context=ctx,
                explanation=(
                    f"Channel {ch.id} carries {ch.data_sensitivity.value} data across "
                    f"boundary (external={ch.external}, "
                    f"trust {src.trust_domain!r} -> {dst.trust_domain!r})."
                ),
                preservation_safe=True,
            )
        )
    return out


def detect_f4_overlifetime_key_sensitive(
    cfg: CryptoConfig,
    threat: ThreatState,
) -> list[FragilityInstance]:
    """F4: Aging or overdue key material on sensitive channels."""
    _ = threat
    out: list[FragilityInstance] = []
    risky_lifetime = frozenset(
        {KeyLifetimeClass.LONG, KeyLifetimeClass.OVERDUE, KeyLifetimeClass.MEDIUM}
    )
    for ch in cfg.channels.values():
        if ch.data_sensitivity not in HIGH_SENSITIVITY:
            continue
        key = cfg.keys[ch.key_id]
        if key.lifetime_class not in risky_lifetime:
            continue
        ctx = {
            "zone": ch.zone,
            "data_sensitivity": ch.data_sensitivity.value,
            "lifetime_class": key.lifetime_class.value,
            "key_id": key.id,
        }
        out.append(
            FragilityInstance(
                predicate="F4",
                label="overlifetime_key_on_sensitive_channel",
                channel_id=ch.id,
                key_id=key.id,
                certificate_id=None,
                context=ctx,
                explanation=(
                    f"Channel {ch.id} uses key {key.id} with lifetime_class="
                    f"{key.lifetime_class.value} for {ch.data_sensitivity.value} data."
                ),
                preservation_safe=True,
            )
        )
    return out


def detect_f5_weak_ca_sensitive(
    cfg: CryptoConfig,
    threat: ThreatState,
) -> list[FragilityInstance]:
    """F5 (optional): Weak issuer for a certificate tied to a sensitive channel endpoint."""
    _ = threat
    out: list[FragilityInstance] = []
    node_certs: dict[str, list[Certificate]] = defaultdict(list)
    for cert in cfg.certificates.values():
        if cert.subject_node_id is not None:
            node_certs[cert.subject_node_id].append(cert)
    for ch in cfg.channels.values():
        if ch.data_sensitivity not in HIGH_SENSITIVITY:
            continue
        for nid in (ch.src_node_id, ch.dst_node_id):
            for cert in node_certs.get(nid, ()):
                if cert.issuer in WEAK_CA_ISSUERS:
                    ctx = {
                        "zone": ch.zone,
                        "data_sensitivity": ch.data_sensitivity.value,
                        "node_id": nid,
                        "issuer": cert.issuer,
                    }
                    out.append(
                        FragilityInstance(
                            predicate="F5",
                            label="weak_ca_on_sensitive_service",
                            channel_id=ch.id,
                            key_id=ch.key_id,
                            certificate_id=cert.id,
                            context=ctx,
                            explanation=(
                                f"Channel {ch.id} touches node {nid} with certificate "
                                f"{cert.id} signed by weak issuer {cert.issuer!r}."
                            ),
                            preservation_safe=True,
                        )
                    )
    return out


def detect_f6_sensitive_unencrypted(
    cfg: CryptoConfig,
    threat: ThreatState,
) -> list[FragilityInstance]:
    """F6: Sensitive classification but channel not encrypted."""
    _ = threat
    out: list[FragilityInstance] = []
    for ch in cfg.channels.values():
        if ch.data_sensitivity not in HIGH_SENSITIVITY:
            continue
        if ch.encrypted:
            continue
        ctx = {
            "zone": ch.zone,
            "data_sensitivity": ch.data_sensitivity.value,
            "encrypted": ch.encrypted,
        }
        out.append(
            FragilityInstance(
                predicate="F6",
                label="sensitive_unencrypted_channel",
                channel_id=ch.id,
                key_id=ch.key_id,
                certificate_id=None,
                context=ctx,
                explanation=(
                    f"Channel {ch.id} is marked {ch.data_sensitivity.value} but encrypted=False."
                ),
                preservation_safe=True,
            )
        )
    return out


def detect_f7_heterogeneous_kem_in_zone(
    cfg: CryptoConfig,
    threat: ThreatState,
) -> list[FragilityInstance]:
    """F7 (optional, heuristic): Multiple KEM families active in the same zone.

    **Not preservation-safe:** abstraction may merge nodes and lose multiplicity.
    """
    _ = threat
    out: list[FragilityInstance] = []
    zone_families: dict[str, set[str]] = defaultdict(set)
    for ch in cfg.channels.values():
        fam = _alg(cfg, ch.kem_algorithm_id).family
        zone_families[ch.zone].add(fam)
    for zone, fams in sorted(zone_families.items()):
        if len(fams) <= 1:
            continue
        ctx = {"zone": zone, "families": sorted(fams)}
        out.append(
            FragilityInstance(
                predicate="F7",
                label="heterogeneous_kem_in_zone",
                channel_id=None,
                key_id=None,
                certificate_id=None,
                context=ctx,
                explanation=(
                    f"Zone {zone!r} mixes KEM families {sorted(fams)!r} "
                    f"(heuristic concentration / inconsistency signal)."
                ),
                preservation_safe=False,
            )
        )
    return out


def detect_f8_regulated_without_pqc_safe_kem(
    cfg: CryptoConfig,
    threat: ThreatState,
) -> list[FragilityInstance]:
    """F8: Regulated data on a channel whose KEM family is not PQC-safe."""
    _ = threat
    out: list[FragilityInstance] = []
    for ch in cfg.channels.values():
        if ch.data_sensitivity != DataSensitivity.REGULATED:
            continue
        fam = _alg(cfg, ch.kem_algorithm_id).family
        if fam in PQC_SAFE_FAMILIES:
            continue
        ctx = {
            "zone": ch.zone,
            "data_sensitivity": ch.data_sensitivity.value,
            "family": fam,
            "algorithm_id": ch.kem_algorithm_id,
        }
        out.append(
            FragilityInstance(
                predicate="F8",
                label="regulated_without_pqc_safe_kem",
                channel_id=ch.id,
                key_id=ch.key_id,
                certificate_id=None,
                context=ctx,
                explanation=(
                    f"Channel {ch.id} carries regulated data using family {fam!r} "
                    f"({ch.kem_algorithm_id}), outside configured PQC-safe families."
                ),
                preservation_safe=True,
            )
        )
    return out


PREDICATE_DETECTORS: tuple[tuple[str, Callable[[CryptoConfig, ThreatState], Iterable[FragilityInstance]]], ...] = (
    ("F1", detect_f1_soon_broken_kem_on_sensitive_channel),
    ("F3", detect_f3_sensitive_cross_domain),
    ("F4", detect_f4_overlifetime_key_sensitive),
    ("F5", detect_f5_weak_ca_sensitive),
    ("F6", detect_f6_sensitive_unencrypted),
    ("F7", detect_f7_heterogeneous_kem_in_zone),
    ("F8", detect_f8_regulated_without_pqc_safe_kem),
)

PREDICATE_CLASSIFICATION: dict[str, dict[str, Any]] = {
    "F1": {"category": "core", "paper_core": True, "preservation_safe": True},
    "F2": {"category": "core", "paper_core": True, "preservation_safe": True},
    "F3": {"category": "core", "paper_core": True, "preservation_safe": True},
    "F4": {"category": "core", "paper_core": True, "preservation_safe": True},
    # F5 remains heuristic until explicit certificate<->channel identity binding exists.
    "F5": {"category": "heuristic", "paper_core": False, "preservation_safe": False},
    "F6": {"category": "core", "paper_core": True, "preservation_safe": True},
    "F7": {"category": "heuristic", "paper_core": False, "preservation_safe": False},
    "F8": {"category": "core", "paper_core": True, "preservation_safe": True},
}


def _classify(inst: FragilityInstance) -> FragilityInstance:
    meta = PREDICATE_CLASSIFICATION.get(inst.predicate, {})
    return replace(
        inst,
        category=str(meta.get("category", "core")),
        paper_core=bool(meta.get("paper_core", True)),
        preservation_safe=bool(meta.get("preservation_safe", inst.preservation_safe)),
    )


def split_core_and_heuristics(
    instances: list[FragilityInstance],
) -> tuple[list[FragilityInstance], list[FragilityInstance]]:
    core = [i for i in instances if i.paper_core]
    heuristics = [i for i in instances if not i.paper_core]
    return core, heuristics


def collect_fragilities(
    cfg: CryptoConfig,
    threat: ThreatState,
    *,
    migration_targets: frozenset[str] | None = None,
    include_f2: bool = True,
    include_f7: bool = True,
) -> list[FragilityInstance]:
    """Run all enabled detectors plus optional F2 (requires migration_targets)."""
    cfg.validate()
    instances: list[FragilityInstance] = []
    for pid, fn in PREDICATE_DETECTORS:
        if not include_f7 and pid == "F7":
            continue
        instances.extend(fn(cfg, threat))
    if include_f2 and migration_targets:
        instances.extend(detect_f2_unsupported_migration_target(cfg, threat, migration_targets=migration_targets))
    instances = [_classify(i) for i in instances]
    instances.sort(key=lambda x: (x.predicate, x.channel_id or "", x.label))
    return instances


__all__ = [
    "FragilityInstance",
    "PREDICATE_CLASSIFICATION",
    "PREDICATE_DETECTORS",
    "PQC_SAFE_FAMILIES",
    "WEAK_CA_ISSUERS",
    "collect_fragilities",
    "detect_f1_soon_broken_kem_on_sensitive_channel",
    "detect_f2_unsupported_migration_target",
    "detect_f3_sensitive_cross_domain",
    "detect_f4_overlifetime_key_sensitive",
    "detect_f5_weak_ca_sensitive",
    "detect_f6_sensitive_unencrypted",
    "detect_f7_heterogeneous_kem_in_zone",
    "detect_f8_regulated_without_pqc_safe_kem",
    "split_core_and_heuristics",
]
