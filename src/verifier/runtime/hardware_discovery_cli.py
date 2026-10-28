"""Terminology: command-line interface (CLI); JavaScript Object Notation (JSON);
Verifier Standard (VSTD).

Vendor and fixture discovery commands for the VSTD 3 CLI.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Callable

from verifier.hardware.adapters.amd import AmdAdapter
from verifier.hardware.adapters.generic import GenericFixtureAdapter
from verifier.hardware.adapters.intel import IntelGaudiAdapter
from verifier.hardware.adapters.nvidia import NvidiaAdapter
from verifier.hardware.models import AdapterResult, ClaimStatus
from verifier.runtime.hardware_cli_support import add_output_flags, emit, status_exit


def add_discovery_parser(hardware_commands: argparse._SubParsersAction) -> None:
    discover = hardware_commands.add_parser("discover", help="Run a vendor or generic adapter.")
    discover.add_argument(
        "--adapter", choices=("generic", "nvidia", "amd", "intel"), required=True
    )
    discover.add_argument("--fixture", type=Path)
    discover.add_argument("--output", type=Path, help="Write the normalized adapter result JSON.")
    add_output_flags(discover)


def _required_fixture(args: argparse.Namespace) -> Path:
    if args.fixture is None:
        raise ValueError("the generic adapter requires --fixture")
    return args.fixture


def handle_discovery_command(args: argparse.Namespace) -> int:
    adapters: dict[str, Callable[[], AdapterResult]] = {
        "generic": lambda: GenericFixtureAdapter(_required_fixture(args)).discover(),
        "nvidia": lambda: NvidiaAdapter(fixture_path=args.fixture).discover(),
        "amd": lambda: AmdAdapter(fixture_path=args.fixture).discover(),
        "intel": lambda: IntelGaudiAdapter(fixture_path=args.fixture).discover(),
    }
    result_payload = adapters[args.adapter]().to_dict()
    status = (
        ClaimStatus.PASS.value
        if result_payload["descriptors"]
        else ClaimStatus.UNSUPPORTED.value
    )
    payload = {
        "status": status,
        "operation": "hardware.discover",
        "adapter_result": result_payload,
    }
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(result_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        payload["output"] = str(args.output.resolve())
    emit(payload, as_json=args.json)
    return status_exit(status)
