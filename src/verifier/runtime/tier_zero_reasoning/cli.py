"""Integrated command-line interface (CLI) for Verifier Standard (VSTD) Tier-zero reason analysis.

The command can emit a JavaScript Object Notation (JSON) receipt.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def add_reasoning_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(
        "reasons",
        help="Assess reasons, falsifiers, redundancy, bindings, and effect reach at one coordinate.",
    )
    commands = parser.add_subparsers(dest="reasons_command", required=True)
    assess_parser = commands.add_parser(
        "assess",
        help=(
            "Compile ROOT/objects.vstd, then assess the single "
            "ROOT/reasons.vstd ledger."
        ),
    )
    assess_parser.add_argument("--root", default=".", help="Selected Git worktree root.")
    assess_parser.add_argument(
        "--out", help="Ignored output directory (default: ROOT/.vstd-work/reasons-assessment).",
    )
    assess_parser.add_argument("--witness-specs", help="Optional runtime witness specification JSON.")
    assess_parser.add_argument("--subject", choices=("whole", "shipped", "nontest"), default="nontest")
    assess_parser.add_argument("--annotations", choices=("on", "concrete", "off"), default="concrete")
    assess_parser.add_argument("--implicit", choices=("off", "ops", "all"), default="all")
    assess_parser.add_argument("--name-rule", choices=("on", "off"), default="off")
    assess_parser.add_argument("--timeout", type=int, default=1800, help="Per-component timeout in seconds.")
    assess_parser.add_argument(
        "--alias-gate", action="store_true",
        help="Also execute the focused alias-hole pytest gate (requires the test extra).",
    )
    assess_parser.add_argument("--json", action="store_true")


def handle_reasoning_command(args: argparse.Namespace) -> int:
    if args.reasons_command != "assess":
        raise ValueError("TIER_ZERO_REASONING_COMMAND_UNKNOWN")
    from verifier.runtime.tier_zero_reasoning.integration import assess

    root = Path(args.root).resolve(strict=True)
    output = Path(args.out).resolve() if args.out else root / ".vstd-work" / "reasons-assessment"
    receipt = assess(
        root,
        root / "reasons.vstd",
        output,
        witness_specs=Path(args.witness_specs) if args.witness_specs else None,
        subject=args.subject,
        annotations=args.annotations,
        implicit=args.implicit,
        name_rule=args.name_rule,
        timeout=args.timeout,
        run_alias_gate=args.alias_gate,
    )
    if args.json:
        print(json.dumps(receipt, sort_keys=True, ensure_ascii=True, allow_nan=False))
    else:
        print(f"[{receipt['status']}] integrated Tier-zero reason assessment")
        print(f"  Coordinate: {receipt['coordinate_after']['head']}")
        print(f"  Source unchanged: {receipt['source_unchanged_during_assessment']}")
        for step in receipt["steps"]:
            print(f"  {step['state']:13} {step['name']}")
        print(f"  Receipt: {output / 'assessment.json'}")
        print("  Boundary: " + receipt["claim_boundary"])
    return 0 if receipt["status"] == "PASS" else 2 if receipt["status"] == "UNKNOWN" else 1


__all__ = ["add_reasoning_parser", "handle_reasoning_command"]
