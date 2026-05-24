"""Support-constrained mutations (simulation only; no production actuation)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from qaca.models import (
    Algorithm,
    Channel,
    CryptoConfig,
    Key,
    KeyLifetimeClass,
)


@dataclass(frozen=True, slots=True)
class SimulationPolicy:
    """Operational assumptions for simulated KMS / support checks."""

    kms_capable_node_ids: frozenset[str] | None = None
    """None: all nodes may perform key rotation; else both endpoints must be listed."""
    check_endpoint_support: bool = True
    """If False, baseline-style planner skips endpoint capability checks."""


@dataclass(frozen=True, slots=True)
class KemUpgrade:
    kind: Literal["kem_upgrade"] = "kem_upgrade"
    channel_id: str = ""
    target_algorithm_id: str = ""
    new_key_id: str = ""


@dataclass(frozen=True, slots=True)
class KeyLifetimeReduction:
    kind: Literal["key_lifetime_reduction"] = "key_lifetime_reduction"
    channel_id: str = ""
    new_key_id: str = ""
    new_lifetime: KeyLifetimeClass = KeyLifetimeClass.SHORT


Mutation = KemUpgrade | KeyLifetimeReduction


def _kms_allows(policy: SimulationPolicy, src_id: str, dst_id: str) -> bool:
    if policy.kms_capable_node_ids is None:
        return True
    return src_id in policy.kms_capable_node_ids and dst_id in policy.kms_capable_node_ids


def can_apply_kem_upgrade(
    cfg: CryptoConfig,
    ch: Channel,
    target_algorithm_id: str,
    policy: SimulationPolicy,
) -> tuple[bool, str]:
    if target_algorithm_id not in cfg.algorithms:
        return False, "unknown_target_algorithm"
    src = cfg.nodes[ch.src_node_id]
    dst = cfg.nodes[ch.dst_node_id]
    if policy.check_endpoint_support:
        if target_algorithm_id not in src.supported_algorithm_ids:
            return False, "source_endpoint_does_not_support_target_class"
        if target_algorithm_id not in dst.supported_algorithm_ids:
            return False, "destination_endpoint_does_not_support_target_class"
    if not _kms_allows(policy, ch.src_node_id, ch.dst_node_id):
        return False, "kms_policy_blocks_rotation_on_endpoints"
    return True, "ok"


def can_apply_key_lifetime_reduction(
    cfg: CryptoConfig,
    ch: Channel,
    policy: SimulationPolicy,
) -> tuple[bool, str]:
    key = cfg.keys[ch.key_id]
    if key.lifetime_class == KeyLifetimeClass.SHORT:
        return False, "already_short_lifetime"
    if not _kms_allows(policy, ch.src_node_id, ch.dst_node_id):
        return False, "kms_policy_blocks_key_rotation"
    return True, "ok"


def apply_kem_upgrade(cfg: CryptoConfig, mut: KemUpgrade) -> CryptoConfig:
    """Return new config with channel KEM + key replaced (simulated fresh key)."""
    ch = cfg.channels[mut.channel_id]
    tgt = cfg.algorithms[mut.target_algorithm_id]
    new_key = Key(
        id=mut.new_key_id,
        algorithm_id=tgt.id,
        lifetime_class=KeyLifetimeClass.SHORT,
        owner_node_id=cfg.keys[ch.key_id].owner_node_id,
        protection_tier=cfg.keys[ch.key_id].protection_tier,
    )
    new_ch = Channel(
        id=ch.id,
        src_node_id=ch.src_node_id,
        dst_node_id=ch.dst_node_id,
        protocol=ch.protocol,
        kem_algorithm_id=tgt.id,
        data_sensitivity=ch.data_sensitivity,
        encrypted=ch.encrypted,
        external=ch.external,
        zone=ch.zone,
        key_id=new_key.id,
    )
    keys = dict(cfg.keys)
    keys[new_key.id] = new_key
    channels = dict(cfg.channels)
    channels[new_ch.id] = new_ch
    # Keep old key in the store for audit trail (PoC); production might archive.
    return CryptoConfig(
        nodes=cfg.nodes,
        channels=channels,
        algorithms=cfg.algorithms,
        keys=keys,
        certificates=cfg.certificates,
        zones=cfg.zones,
    )


def apply_key_lifetime_reduction(cfg: CryptoConfig, mut: KeyLifetimeReduction) -> CryptoConfig:
    ch = cfg.channels[mut.channel_id]
    old = cfg.keys[ch.key_id]
    new_key = Key(
        id=mut.new_key_id,
        algorithm_id=old.algorithm_id,
        lifetime_class=mut.new_lifetime,
        owner_node_id=old.owner_node_id,
        protection_tier=old.protection_tier,
    )
    new_ch = Channel(
        id=ch.id,
        src_node_id=ch.src_node_id,
        dst_node_id=ch.dst_node_id,
        protocol=ch.protocol,
        kem_algorithm_id=ch.kem_algorithm_id,
        data_sensitivity=ch.data_sensitivity,
        encrypted=ch.encrypted,
        external=ch.external,
        zone=ch.zone,
        key_id=new_key.id,
    )
    keys = dict(cfg.keys)
    keys[new_key.id] = new_key
    channels = dict(cfg.channels)
    channels[new_ch.id] = new_ch
    return CryptoConfig(
        nodes=cfg.nodes,
        channels=channels,
        algorithms=cfg.algorithms,
        keys=keys,
        certificates=cfg.certificates,
        zones=cfg.zones,
    )


def ensure_algorithm(cfg: CryptoConfig, alg: Algorithm) -> CryptoConfig:
    if alg.id in cfg.algorithms:
        return cfg
    algs = dict(cfg.algorithms)
    algs[alg.id] = alg
    return CryptoConfig(
        nodes=cfg.nodes,
        channels=cfg.channels,
        algorithms=algs,
        keys=cfg.keys,
        certificates=cfg.certificates,
        zones=cfg.zones,
    )


__all__ = [
    "KemUpgrade",
    "KeyLifetimeReduction",
    "Mutation",
    "SimulationPolicy",
    "apply_kem_upgrade",
    "apply_key_lifetime_reduction",
    "can_apply_kem_upgrade",
    "can_apply_key_lifetime_reduction",
    "ensure_algorithm",
]
