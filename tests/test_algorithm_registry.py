"""Tests for illustrative algorithm registry aliases."""

from __future__ import annotations

from qaca.algorithm_registry import display_name, resolve_family


def test_resolve_mlkem_aliases() -> None:
    assert resolve_family("ML-KEM-768") == "ml_kem"
    assert resolve_family("ml-kem") == "ml_kem"


def test_resolve_hybrid_aliases() -> None:
    assert resolve_family("X25519MLKEM768") == "ecdhe_mlkem_hybrid"


def test_display_name_passthrough_unknown() -> None:
    assert display_name("unknown_alg") == "unknown_alg"
