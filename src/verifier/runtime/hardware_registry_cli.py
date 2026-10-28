"""Terminology: command-line interface (CLI); Verifier Standard (VSTD).

Registry list and inspection commands for the VSTD 3 CLI.
"""

from __future__ import annotations

import argparse

from verifier.hardware.models import ClaimStatus
from verifier.hardware.registry import AcceleratorRegistry
from verifier.runtime.hardware_cli_support import PASS_EXIT, add_output_flags, emit


def add_registry_parsers(hardware_commands: argparse._SubParsersAction) -> None:
    registry_list = hardware_commands.add_parser("list", help="List accelerator profiles.")
    registry_list.add_argument("--vendor")
    add_output_flags(registry_list)

    registry_inspect = hardware_commands.add_parser(
        "inspect", help="Inspect one accelerator profile."
    )
    registry_inspect.add_argument("profile_id")
    add_output_flags(registry_inspect)


def handle_registry_command(args: argparse.Namespace, registry: AcceleratorRegistry) -> int:
    if args.hardware_command == "list":
        profiles = registry.list()
        if args.vendor:
            profiles = tuple(
                item for item in profiles if item.vendor.casefold() == args.vendor.casefold()
            )
        payload = {
            "status": ClaimStatus.PASS.value,
            "operation": "hardware.list",
            "registry_version": registry.registry_version,
            "profiles": [
                {
                    "profile_id": item.profile_id,
                    "vendor": item.vendor,
                    "family": item.family,
                    "models": list(item.models),
                }
                for item in profiles
            ],
        }
        emit(payload, as_json=args.json)
        return PASS_EXIT

    payload = {
        "status": ClaimStatus.PASS.value,
        "operation": "hardware.inspect",
        "profile": registry.get(args.profile_id).to_dict(),
    }
    emit(payload, as_json=args.json)
    return PASS_EXIT
