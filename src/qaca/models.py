"""Core crypto-configuration graph (executable counterpart of configuration space C)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class DataSensitivity(str, Enum):
    """Data classification carried on a channel."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    REGULATED = "regulated"


class KeyLifetimeClass(str, Enum):
    """Coarse key age / rotation policy bucket."""

    SHORT = "short"
    MEDIUM = "medium"
    LONG = "long"
    OVERDUE = "overdue"


@dataclass(frozen=True, slots=True)
class Algorithm:
    """Cryptographic algorithm entry (e.g. a KEM suite used on a channel)."""

    id: str
    family: str
    """Logical family for migration rules, e.g. rsa, ecdh, ml_kem, hybrid."""
    name: str = ""


@dataclass(frozen=True, slots=True)
class Key:
    """Key material metadata (no secrets; identifiers only)."""

    id: str
    algorithm_id: str
    lifetime_class: KeyLifetimeClass
    owner_node_id: str | None = None
    protection_tier: str = "standard"


@dataclass(frozen=True, slots=True)
class Certificate:
    """Simplified certificate / trust anchor reference."""

    id: str
    subject: str
    issuer: str
    linked_key_id: str
    subject_node_id: str | None = None


@dataclass(frozen=True, slots=True)
class Node:
    """Infrastructure endpoint or service identity."""

    id: str
    zone: str
    trust_domain: str
    supported_algorithm_ids: frozenset[str] = field(default_factory=frozenset)
    criticality: str = "medium"


@dataclass(frozen=True, slots=True)
class Channel:
    """Logical communication path between two nodes."""

    id: str
    src_node_id: str
    dst_node_id: str
    protocol: str
    kem_algorithm_id: str
    data_sensitivity: DataSensitivity
    encrypted: bool
    external: bool
    zone: str
    key_id: str


@dataclass(frozen=True, slots=True)
class CryptoConfig:
    """Full synthetic crypto-infrastructure configuration."""

    nodes: dict[str, Node]
    channels: dict[str, Channel]
    algorithms: dict[str, Algorithm]
    keys: dict[str, Key]
    certificates: dict[str, Certificate]
    zones: frozenset[str] | None = None
    """If None, zones are derived from nodes and channels."""

    def derived_zones(self) -> frozenset[str]:
        if self.zones is not None:
            return self.zones
        zs = {n.zone for n in self.nodes.values()} | {c.zone for c in self.channels.values()}
        return frozenset(zs)

    def validate(self) -> None:
        """Raise ValueError if references or basic invariants are broken."""
        if not self.nodes:
            raise ValueError("CryptoConfig requires at least one node.")
        for nid, node in self.nodes.items():
            if nid != node.id:
                raise ValueError(f"Node key {nid!r} must match node.id {node.id!r}.")
            unknown = node.supported_algorithm_ids - self.algorithms.keys()
            if unknown:
                raise ValueError(
                    f"Node {nid!r} supports unknown algorithm ids: {sorted(unknown)}."
                )
        for aid, alg in self.algorithms.items():
            if aid != alg.id:
                raise ValueError(f"Algorithm key {aid!r} must match algorithm.id {alg.id!r}.")
        for kid, key in self.keys.items():
            if kid != key.id:
                raise ValueError(f"Key key {kid!r} must match key.id {key.id!r}.")
            if key.algorithm_id not in self.algorithms:
                raise ValueError(
                    f"Key {kid!r} references unknown algorithm_id {key.algorithm_id!r}."
                )
            if key.owner_node_id is not None and key.owner_node_id not in self.nodes:
                raise ValueError(
                    f"Key {kid!r} owner_node_id {key.owner_node_id!r} is not a known node."
                )
        for cid, cert in self.certificates.items():
            if cid != cert.id:
                raise ValueError(f"Certificate key {cid!r} must match certificate.id {cert.id!r}.")
            if cert.linked_key_id not in self.keys:
                raise ValueError(
                    f"Certificate {cid!r} linked_key_id {cert.linked_key_id!r} is not a known key."
                )
            if cert.subject_node_id is not None and cert.subject_node_id not in self.nodes:
                raise ValueError(
                    f"Certificate {cid!r} subject_node_id {cert.subject_node_id!r} "
                    "is not a known node."
                )
        for chid, ch in self.channels.items():
            if chid != ch.id:
                raise ValueError(f"Channel key {chid!r} must match channel.id {ch.id!r}.")
            if ch.src_node_id not in self.nodes:
                raise ValueError(
                    f"Channel {chid!r} src_node_id {ch.src_node_id!r} is not a known node."
                )
            if ch.dst_node_id not in self.nodes:
                raise ValueError(
                    f"Channel {chid!r} dst_node_id {ch.dst_node_id!r} is not a known node."
                )
            if ch.kem_algorithm_id not in self.algorithms:
                raise ValueError(
                    f"Channel {chid!r} kem_algorithm_id {ch.kem_algorithm_id!r} "
                    "is not a known algorithm."
                )
            if ch.key_id not in self.keys:
                raise ValueError(f"Channel {chid!r} key_id {ch.key_id!r} is not a known key.")
            src = self.nodes[ch.src_node_id]
            dst = self.nodes[ch.dst_node_id]
            if ch.kem_algorithm_id not in src.supported_algorithm_ids:
                raise ValueError(
                    f"Channel {chid!r}: source node {src.id!r} does not support "
                    f"kem algorithm {ch.kem_algorithm_id!r}."
                )
            if ch.kem_algorithm_id not in dst.supported_algorithm_ids:
                raise ValueError(
                    f"Channel {chid!r}: destination node {dst.id!r} does not support "
                    f"kem algorithm {ch.kem_algorithm_id!r}."
                )
            key = self.keys[ch.key_id]
            if key.algorithm_id != ch.kem_algorithm_id:
                raise ValueError(
                    f"Channel {chid!r} key {key.id!r} has algorithm_id {key.algorithm_id!r} "
                    f"but channel expects kem_algorithm_id {ch.kem_algorithm_id!r}."
                )
        if self.zones is not None:
            unknown_z = self.zones - self.derived_zones()
            if unknown_z:
                raise ValueError(
                    f"zones {sorted(unknown_z)} are not present on any node or channel."
                )


def three_node_example() -> CryptoConfig:
    """Minimal connected graph: three nodes, two channels, shared algorithm registry."""
    alg_rsa = Algorithm(id="alg_rsa", family="rsa", name="RSA KEM")
    alg_ml = Algorithm(id="alg_ml_kem", family="ml_kem", name="ML-KEM")
    keys = {
        "key_rsa_a": Key(
            id="key_rsa_a",
            algorithm_id="alg_rsa",
            lifetime_class=KeyLifetimeClass.LONG,
            owner_node_id="node_a",
        ),
        "key_rsa_b": Key(
            id="key_rsa_b",
            algorithm_id="alg_rsa",
            lifetime_class=KeyLifetimeClass.MEDIUM,
            owner_node_id="node_b",
        ),
        "key_ml_c": Key(
            id="key_ml_c",
            algorithm_id="alg_ml_kem",
            lifetime_class=KeyLifetimeClass.SHORT,
            owner_node_id="node_c",
        ),
    }
    nodes = {
        "node_a": Node(
            id="node_a",
            zone="edge",
            trust_domain="corp.example",
            supported_algorithm_ids=frozenset({"alg_rsa", "alg_ml_kem"}),
            criticality="high",
        ),
        "node_b": Node(
            id="node_b",
            zone="payments",
            trust_domain="corp.example",
            supported_algorithm_ids=frozenset({"alg_rsa", "alg_ml_kem"}),
            criticality="high",
        ),
        "node_c": Node(
            id="node_c",
            zone="analytics",
            trust_domain="partner.example",
            supported_algorithm_ids=frozenset({"alg_ml_kem"}),
            criticality="low",
        ),
    }
    channels = {
        "ch_ab": Channel(
            id="ch_ab",
            src_node_id="node_a",
            dst_node_id="node_b",
            protocol="TLS1.3",
            kem_algorithm_id="alg_rsa",
            data_sensitivity=DataSensitivity.REGULATED,
            encrypted=True,
            external=False,
            zone="payments",
            key_id="key_rsa_a",
        ),
        "ch_bc": Channel(
            id="ch_bc",
            src_node_id="node_b",
            dst_node_id="node_c",
            protocol="TLS1.3",
            kem_algorithm_id="alg_ml_kem",
            data_sensitivity=DataSensitivity.INTERNAL,
            encrypted=True,
            external=True,
            zone="analytics",
            key_id="key_ml_c",
        ),
    }
    certs = {
        "cert_b": Certificate(
            id="cert_b",
            subject="svc-b.corp.example",
            issuer="Corp-SubCA",
            linked_key_id="key_rsa_b",
            subject_node_id="node_b",
        ),
    }
    cfg = CryptoConfig(
        nodes=nodes,
        channels=channels,
        algorithms={"alg_rsa": alg_rsa, "alg_ml_kem": alg_ml},
        keys=keys,
        certificates=certs,
        zones=frozenset({"edge", "payments", "analytics"}),
    )
    cfg.validate()
    return cfg


__all__ = [
    "Algorithm",
    "Certificate",
    "Channel",
    "CryptoConfig",
    "DataSensitivity",
    "Key",
    "KeyLifetimeClass",
    "Node",
    "three_node_example",
]
