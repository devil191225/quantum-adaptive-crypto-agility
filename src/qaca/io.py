"""Serialization helpers for configs and experiment outputs."""

from __future__ import annotations

import json
from dataclasses import asdict
from enum import Enum
from typing import Any

from qaca.models import CryptoConfig
from qaca.threat import ThreatState


def _json_safe(obj: Any) -> Any:
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, frozenset):
        return sorted(obj)
    if isinstance(obj, dict):
        return {k: _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_json_safe(v) for v in obj]
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    if hasattr(obj, "__dataclass_fields__"):
        return _json_safe(asdict(obj))
    return str(obj)


def config_summary_dict(
    config: CryptoConfig,
    threat: ThreatState | None = None,
) -> dict[str, Any]:
    """Return a JSON-serializable summary (counts, ids, zones)—not a full dump."""
    zones = sorted(config.derived_zones())
    summary: dict[str, Any] = {
        "node_count": len(config.nodes),
        "channel_count": len(config.channels),
        "algorithm_count": len(config.algorithms),
        "key_count": len(config.keys),
        "certificate_count": len(config.certificates),
        "zones": zones,
        "node_ids": sorted(config.nodes.keys()),
        "channel_ids": sorted(config.channels.keys()),
        "algorithm_ids": sorted(config.algorithms.keys()),
        "algorithms": {
            aid: {"id": a.id, "family": a.family, "name": a.name}
            for aid, a in sorted(config.algorithms.items())
        },
        "channels": {
            cid: {
                "id": c.id,
                "src": c.src_node_id,
                "dst": c.dst_node_id,
                "protocol": c.protocol,
                "kem_algorithm_id": c.kem_algorithm_id,
                "data_sensitivity": c.data_sensitivity.value,
                "encrypted": c.encrypted,
                "external": c.external,
                "zone": c.zone,
                "key_id": c.key_id,
            }
            for cid, c in sorted(config.channels.items())
        },
    }
    if threat is not None:
        summary["threat"] = {
            "horizon_year": threat.horizon_year,
            "algorithm_safety": dict(sorted(threat.algorithm_safety.items())),
            "require_kem_diversity": threat.require_kem_diversity,
            "degraded_algorithm_ids": sorted(threat.degraded_algorithm_ids),
            "notes": threat.notes,
        }
    return summary


def config_summary_json(
    config: CryptoConfig,
    threat: ThreatState | None = None,
    *,
    indent: int | None = 2,
) -> str:
    """Serialize `config_summary_dict` to a JSON string."""
    return json.dumps(config_summary_dict(config, threat), indent=indent, sort_keys=True)


def config_full_dict(config: CryptoConfig) -> dict[str, Any]:
    """Full dataclass tree as JSON-serializable dict (for debugging / fixtures)."""
    return {
        "nodes": {k: _json_safe(v) for k, v in sorted(config.nodes.items())},
        "channels": {k: _json_safe(v) for k, v in sorted(config.channels.items())},
        "algorithms": {k: _json_safe(v) for k, v in sorted(config.algorithms.items())},
        "keys": {k: _json_safe(v) for k, v in sorted(config.keys.items())},
        "certificates": {k: _json_safe(v) for k, v in sorted(config.certificates.items())},
        "zones": sorted(config.derived_zones()) if config.zones is None else sorted(config.zones),
    }


__all__ = [
    "config_full_dict",
    "config_summary_dict",
    "config_summary_json",
]
