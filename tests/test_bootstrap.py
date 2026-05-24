"""Smoke tests for TASK-001 bootstrap."""

from __future__ import annotations

import pytest

import qaca
from qaca import experiments


def test_package_version() -> None:
    assert qaca.__version__ == "0.1.0"


def test_experiments_help_exits_zero() -> None:
    with pytest.raises(SystemExit) as cm:
        experiments.main(["--help"])
    assert cm.value.code == 0


def test_experiments_parser_has_scenario() -> None:
    p = experiments.build_parser()
    args = p.parse_args(["--scenario", "static_migration", "--seed", "7"])
    assert args.scenario == "static_migration"
    assert args.seed == 7
