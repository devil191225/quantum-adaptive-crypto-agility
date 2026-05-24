"""Threat state θ: primitive safety labels, horizon, and policy hooks (Config-Lab)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

PrimitiveSafety = Literal["safe", "soon_broken", "degraded", "unknown"]


@dataclass(frozen=True, slots=True)
class ThreatState:
    """Evolving assumptions about algorithm viability and migration policy.

    This is a *model* object: degraded does not assert real-world cryptanalysis.
    """

    horizon_year: int | None
    """Calendar year used as a coarse “break horizon” in synthetic experiments."""
    algorithm_safety: dict[str, PrimitiveSafety]
    """Maps algorithm *id* (as in CryptoConfig.algorithms) to a safety label."""
    require_kem_diversity: bool = False
    """If True, planner may need multiple KEM families in a zone (policy stub)."""
    degraded_algorithm_ids: frozenset[str] = field(default_factory=frozenset)
    """Explicit subset treated as degraded (e.g. simulated confidence loss)."""
    notes: str = ""

    def safety_for(self, algorithm_id: str) -> PrimitiveSafety:
        if algorithm_id in self.degraded_algorithm_ids:
            return "degraded"
        return self.algorithm_safety.get(algorithm_id, "unknown")


__all__ = ["PrimitiveSafety", "ThreatState"]
