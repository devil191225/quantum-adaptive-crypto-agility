"""Illustrative algorithm registry for Config-Lab (not a complete standards registry)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AlgorithmProfile:
    family: str
    display_name: str
    aliases: tuple[str, ...] = ()


REGISTRY: dict[str, AlgorithmProfile] = {
    "rsa_kex": AlgorithmProfile(
        family="rsa_kex",
        display_name="RSA key establishment",
        aliases=("rsa", "rsa_kem", "rsa-key-transport"),
    ),
    "ecdh": AlgorithmProfile(
        family="ecdh",
        display_name="ECDH/ECDHE",
        aliases=("ecdhe",),
    ),
    "ml_kem": AlgorithmProfile(
        family="ml_kem",
        display_name="ML-KEM",
        aliases=("ml-kem", "mlkem", "ml_kem_512", "ml_kem_768", "ml_kem_1024", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"),
    ),
    "ecdhe_mlkem_hybrid": AlgorithmProfile(
        family="ecdhe_mlkem_hybrid",
        display_name="ECDHE-MLKEM hybrid",
        aliases=(
            "hybrid",
            "x25519mlkem768",
            "secp256r1mlkem768",
            "secp384r1mlkem1024",
            "X25519MLKEM768",
            "SecP256r1MLKEM768",
            "SecP384r1MLKEM1024",
        ),
    ),
    "hqc_candidate": AlgorithmProfile(
        family="hqc_candidate",
        display_name="HQC candidate",
        aliases=("hqc",),
    ),
}


def resolve_family(name_or_alias: str) -> str | None:
    key = name_or_alias.strip()
    low = key.lower()
    for fam, prof in REGISTRY.items():
        if low == fam.lower():
            return fam
        if any(low == a.lower() for a in prof.aliases):
            return fam
    return None


def display_name(name_or_alias: str) -> str:
    fam = resolve_family(name_or_alias)
    if fam is None:
        return name_or_alias
    return REGISTRY[fam].display_name


__all__ = ["AlgorithmProfile", "REGISTRY", "display_name", "resolve_family"]
