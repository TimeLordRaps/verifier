"""Terminology: application programming interface (API); command-line interface (CLI);
Verifier Standard (VSTD).

Public VSTD 3 CLI facade. Command mechanisms live beside their bounded responsibility;
this module preserves the stable parser, key-parser, and dispatch API.
"""

from __future__ import annotations

import argparse

from verifier.hardware.registry import load_builtin_registry
from verifier.runtime.hardware_cli_support import parse_verification_keys
from verifier.runtime.hardware_discovery_cli import (
    add_discovery_parser,
    handle_discovery_command,
)
from verifier.runtime.hardware_probe_cli import add_probe_parsers, handle_probe_command
from verifier.runtime.hardware_receipt_cli import (
    add_hardware_receipt_parsers,
    add_receipt_family_parsers,
    handle_hardware_receipt_command,
    handle_receipt_family_command,
)
from verifier.runtime.hardware_registry_cli import (
    add_registry_parsers,
    handle_registry_command,
)


__all__ = ("add_vstd3_parsers", "parse_verification_keys", "handle_vstd3_command")


def add_vstd3_parsers(subparsers: argparse._SubParsersAction) -> None:
    hardware = subparsers.add_parser("hardware", help="Discover or emulate accelerator evidence.")
    hardware_commands = hardware.add_subparsers(dest="hardware_command", required=True)

    # Keep the established help and parse order while each module owns one mechanism family.
    add_registry_parsers(hardware_commands)
    add_discovery_parser(hardware_commands)
    add_probe_parsers(hardware_commands)
    add_hardware_receipt_parsers(hardware_commands)
    add_receipt_family_parsers(subparsers)


def _handle_hardware_command(args: argparse.Namespace) -> int:
    # Registry loading historically precedes every hardware subcommand. Some callers rely on
    # its failure ordering, so the facade retains that coupling until a separate API change.
    registry = load_builtin_registry()
    if args.hardware_command in {"list", "inspect"}:
        return handle_registry_command(args, registry)
    if args.hardware_command == "discover":
        return handle_discovery_command(args)
    if args.hardware_command in {"capabilities", "verify"}:
        return handle_hardware_receipt_command(args)
    return handle_probe_command(args)


def handle_vstd3_command(args: argparse.Namespace) -> int:
    if args.command == "hardware":
        return _handle_hardware_command(args)
    return handle_receipt_family_command(args)
