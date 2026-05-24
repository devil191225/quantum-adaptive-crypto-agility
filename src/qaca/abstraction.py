"""Abstraction helpers (compression metrics for Config-Lab tables)."""

from __future__ import annotations

from typing import Any

from qaca.models import CryptoConfig


def abstraction_compression_stats(cfg: CryptoConfig) -> dict[str, Any]:
    """Return simple node/zone compression metrics (PoC; not a full abstract graph)."""
    zones = cfg.derived_zones()
    n_nodes = len(cfg.nodes)
    n_zones = len(zones)
    return {
        "node_count": n_nodes,
        "zone_count": n_zones,
        "nodes_per_zone": n_nodes / max(n_zones, 1),
        "channel_count": len(cfg.channels),
        "channels_per_zone": len(cfg.channels) / max(n_zones, 1),
    }


__all__ = ["abstraction_compression_stats"]
