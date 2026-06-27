"""Console entrypoint for the public phantom-secops release surface."""

from __future__ import annotations

import argparse
import sys

from phantom_secops import defensive_loop, evidence_playbook, reasoning_scenario


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="phantom-secops",
        description=(
            "Run hermetic, read-only phantom-secops public demos. These commands "
            "use synthetic fixtures and do not perform active scanning."
        ),
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    for name, help_text in (
        ("defensive-loop", "write synthetic defensive findings and timeline artifacts"),
        ("evidence-playbook", "write synthetic metadata-only evidence and tabletop playbook artifacts"),
        ("reasoning-scenario", "write synthetic read-only reasoning artifacts"),
    ):
        sub = subcommands.add_parser(name, help=help_text)
        sub.add_argument("--out", required=True, help="directory to write the artifact bundle")

    args = parser.parse_args(argv)
    forwarded = ["--out", args.out]
    if args.command == "defensive-loop":
        return defensive_loop.main(forwarded)
    if args.command == "evidence-playbook":
        return evidence_playbook.main(forwarded)
    if args.command == "reasoning-scenario":
        return reasoning_scenario.main(forwarded)

    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

