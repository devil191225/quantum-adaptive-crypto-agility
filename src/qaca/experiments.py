"""CLI entry points for Config-Lab scenarios."""

from __future__ import annotations

import argparse
import sys

from qaca.simulator import run_sensitivity, run_static_migration, run_threat_switch


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m qaca.experiments",
        description="Config-Lab experiment runner (synthetic scenarios).",
    )
    p.add_argument(
        "--scenario",
        choices=("static_migration", "threat_switch", "sensitivity"),
        default=None,
        help="Named scenario to run.",
    )
    p.add_argument(
        "--seed",
        type=int,
        default=42,
        help="RNG seed for deterministic synthetic runs.",
    )
    p.add_argument(
        "--output-dir",
        type=str,
        default="results",
        help="Directory for figures, tables, and logs.",
    )
    p.add_argument(
        "--template",
        choices=("fixed", "random_graph"),
        default="fixed",
        help="Use fixed template graph or seed-driven random graph.",
    )
    p.add_argument(
        "--random-graph",
        action="store_true",
        help="Shortcut for --template random_graph.",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    template = "random_graph" if args.random_graph else args.template
    if args.scenario is None:
        print(
            "No --scenario given. Use --help for options.",
            file=sys.stderr,
        )
        return 2
    if args.scenario == "static_migration":
        return run_static_migration(seed=args.seed, output_dir=args.output_dir, template=template)
    if args.scenario == "threat_switch":
        return run_threat_switch(seed=args.seed, output_dir=args.output_dir, template=template)
    if args.scenario == "sensitivity":
        return run_sensitivity(seed=args.seed, output_dir=args.output_dir, template=template)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
