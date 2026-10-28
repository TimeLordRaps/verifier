"""Verifier Standard (VSTD) polish command-line interface (CLI) routing."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
from typing import Any

from verifier.core.certificate import canonical_bytes
from verifier.runtime import polish


def add_polish_parsers(subparsers: Any) -> None:
    """Register artifact and package polish command parsers."""
    parser = subparsers.add_parser(
        "polish", help="Assess declared object wiring and polishing gaps."
    )
    commands = parser.add_subparsers(dest="polish_command", required=True)
    # The public entry point dispatches these four numeric commands before
    # argparse because their evidence surfaces are intentionally isolated from
    # the historical artifact-polish parser. Register help-only entries here
    # as well so the parent command truthfully advertises the gate sequence.
    commands.add_parser(
        "0",
        help=(
            "Refresh a recognized Verifier root manifest, then assess source-owned "
            "repository admission before numbered self-polish tiers."
        ),
    )
    commands.add_parser(
        "1",
        help="Refresh and evaluate root objects.vstd package GRAPH through Tier 1 Facets.",
    )
    commands.add_parser(
        "2",
        help="Refresh and evaluate root objects.vstd package GRAPH through Tier 2 Dynamics.",
    )
    commands.add_parser(
        "3",
        help=(
            "Refresh and evaluate the root objects.vstd package GRAPH through Tier 3 "
            "Statics, including the fresh source-bound package-root GRAPH-3.1 projection."
        ),
    )
    recheck_package = commands.add_parser(
        "recheck-package",
        help=(
            "Independently recheck one retained package GRAPH report; exit 0 "
            "means report-integrity PASS, not package polish."
        ),
    )
    recheck_package.add_argument("report")
    recheck_package.add_argument(
        "--report-digest",
        required=True,
        type=polish._hash,
        help="Expected semantic report digest (sha256:...).",
    )
    recheck_package.add_argument(
        "--report-bytes-digest",
        required=True,
        type=polish._hash,
        help="Expected digest of the exact retained report bytes (sha256:...).",
    )
    recheck_package.add_argument("--json", action="store_true")

    from verifier.runtime.polish_findings import add_report_parser

    add_report_parser(commands)
    from verifier.runtime.application_release import add_application_parser

    add_application_parser(commands)
    from verifier.runtime.core_application_release import (
        add_application_parser as add_core_application_parser,
    )

    add_core_application_parser(commands)
    catalog = commands.add_parser(
        "catalog", help="Show installed routes and outstanding closure gates."
    )
    catalog.add_argument("--json", action="store_true")
    catalog.add_argument(
        "--inventory",
        action="store_true",
        help="Include the complete 234-slot applicability and objective inventory.",
    )
    assess = commands.add_parser(
        "assess", help="Replay a retained bundle against an external request."
    )
    assess.add_argument("bundle")
    assess.add_argument("--request", required=True)
    assess.add_argument("--json", action="store_true")
    assess.add_argument(
        "--contract-version",
        choices=("1", "2"),
        default="1",
        help=(
            "Select the exact bundle/request contract; version 2 has "
            "explicit resource limits."
        ),
    )
    coverage = commands.add_parser(
        "coverage",
        help="Replay obligations against a separately pinned requirements inventory.",
    )
    coverage.add_argument("bundle")
    coverage.add_argument("--request", required=True)
    coverage.add_argument("--requirements", required=True)
    coverage.add_argument(
        "--requirements-digest",
        required=True,
        help="Independently selected exact inventory byte digest (sha256:...).",
    )
    coverage.add_argument("--json", action="store_true")
    coverage.add_argument("--contract-version", choices=("1", "2"), default="1")
    check = commands.add_parser(
        "check", help="Recompute a stored assessment against exact inputs."
    )
    check.add_argument("assessment")
    check.add_argument("--bundle", required=True)
    check.add_argument("--request", required=True)
    check.add_argument("--json", action="store_true")
    check.add_argument(
        "--contract-version",
        choices=("1", "2"),
        default="1",
        help="Select the exact assessment and retained input contract.",
    )

    from verifier.runtime.polish_workflow import STAGES

    preparation = commands.add_parser(
        "prepare",
        help="Prepare selected source, explanations and optional quality checks.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Run admitted preparation stages without publication or "
            "polished status. Default check-only stages projected "
            "bytes outside the source. Explicit --apply uses a "
            "retained recovery plan.\n\nStages:\n"
        )
        + "\n".join("  " + row["id"] + ": " + row["description"] for row in STAGES),
    )
    preparation.add_argument(
        "artifact",
        help="Ordinary artifact; the workflow format selects files in a directory.",
    )
    preparation.add_argument(
        "--report-format",
        choices=("verifier-polish-workflow-report-1", "verifier-polish-preparation-1"),
        default="verifier-polish-workflow-report-1",
        help="Select the workflow report or the existing gates preparation contract.",
    )
    preparation.add_argument(
        "--normalize-text",
        action="store_true",
        help=(
            "With verifier-polish-preparation-1, select the existing "
            "source/prose text fix."
        ),
    )
    preparation.add_argument(
        "--dry-run",
        action="store_true",
        help="With verifier-polish-preparation-1, inspect without applying changes.",
    )
    preparation.add_argument(
        "--policy", help="Separately selected closed workflow policy."
    )
    preparation.add_argument(
        "--policy-digest", help="Exact selected policy byte digest (sha256:...)."
    )
    preparation.add_argument(
        "--definition", help="Canonical versioned authored explanation definitions."
    )
    preparation.add_argument(
        "--quality-profile", help="Opt-in independently selected quality profile."
    )
    preparation.add_argument(
        "--quality-profile-digest", help="Exact selected quality profile byte digest."
    )
    preparation.add_argument(
        "--requirements", help="Independent requirements for committed explanations."
    )
    preparation.add_argument(
        "--requirements-digest",
        help="Exact independently selected requirement byte digest.",
    )
    preparation.add_argument(
        "--git-root", help="Repository containing exact committed explanation source."
    )
    preparation.add_argument("--base", help="Exact committed explanation base.")
    preparation.add_argument(
        "--commit", help="Exact committed explanation head or later association commit."
    )
    preparation.add_argument(
        "--output",
        help="External directory for immutable bundles, attempts and apply plans.",
    )
    preparation.add_argument(
        "--resume",
        help="Prior retained attempt or bundle; rechecks all selected stages.",
    )
    preparation.add_argument(
        "--apply",
        action="store_true",
        help=(
            "Explicitly apply successful staged comment bytes using "
            "a retained recovery plan."
        ),
    )
    actions = preparation.add_mutually_exclusive_group()
    actions.add_argument(
        "--recover",
        help="Recover a retained local apply plan after comparing current bytes.",
    )
    actions.add_argument(
        "--associate",
        help="Compare a retained bundle manifest with the exact later whole Git tree.",
    )
    preparation.add_argument(
        "--rollback",
        action="store_true",
        help=(
            "With --recover, restore retained prior bytes unless a "
            "later edit intervened."
        ),
    )
    preparation.add_argument("--json", action="store_true")


def _recheck_package(args: argparse.Namespace) -> int:
    """Recheck exact retained package report bytes without granting polish."""
    from verifier.runtime import package_self_polish_recheck

    try:
        selected_report = Path(args.report)
        if not stat.S_ISREG(selected_report.stat().st_mode):
            raise OSError("selected report is not a regular file")
        open_flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        descriptor = os.open(selected_report, open_flags)
        with os.fdopen(descriptor, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise OSError("opened report is not a regular file")
            report_bytes = handle.read(
                package_self_polish_recheck.MAX_PACKAGE_REPORT_BYTES + 1
            )
        result = package_self_polish_recheck.recheck_package_self_polish_report(
            report_bytes,
            expected_report_digest=args.report_digest,
            expected_report_bytes_digest=args.report_bytes_digest,
        )
    except OSError:
        result = package_self_polish_recheck.unavailable_package_self_polish_recheck()
    if args.json:
        print(json.dumps(result, sort_keys=True, indent=2, allow_nan=False))
    else:
        print(
            f"[{result['status']}] retained project status="
            f"{result['rechecked_project_status']}"
        )
        print(result["claim_boundary"])
    return {"PASS": 0, "FAIL": 1, "UNKNOWN": 2}[result["status"]]


def handle_polish_command(args: argparse.Namespace) -> int:
    """Route one parsed polish command without changing assessment semantics."""
    if args.polish_command == "application":
        from verifier.runtime.application_release import handle_application_command

        return handle_application_command(args)
    if args.polish_command == "core-application":
        from verifier.runtime.core_application_release import handle_application_command

        return handle_application_command(args)
    if args.polish_command == "report":
        from verifier.runtime.polish_findings import handle_report_command

        return handle_report_command(args)
    if args.polish_command == "recheck-package":
        return _recheck_package(args)
    if args.polish_command == "prepare":
        if args.report_format == "verifier-polish-preparation-1":
            incompatible = any(
                getattr(args, name)
                for name in (
                    "policy",
                    "policy_digest",
                    "definition",
                    "quality_profile",
                    "quality_profile_digest",
                    "requirements",
                    "requirements_digest",
                    "git_root",
                    "base",
                    "commit",
                    "resume",
                    "recover",
                    "associate",
                    "rollback",
                )
            ) or (args.dry_run and args.apply)
            if incompatible:
                result = {
                    "schema_version": args.report_format,
                    "status": "FAIL",
                    "polished": False,
                    "reason": "INCOMPATIBLE_PREPARATION_OPTIONS",
                }
                print(
                    json.dumps(result, sort_keys=True)
                    if args.json
                    else "[FAIL] Incompatible preparation report options."
                )
                return 1
            from verifier.runtime.polish_prepare import handle_prepare_command

            return handle_prepare_command(args)
        from verifier.runtime.polish_workflow_cli import _handle_preparation

        result = _handle_preparation(args)
        code = {"PASS": 0, "FAIL": 1, "UNKNOWN": 2}.get(result["status"], 2)
    elif args.polish_command == "catalog":
        result = polish.polish_catalog(
            include_inventory=getattr(args, "inventory", False)
        )
        code = 0
    else:
        version = getattr(args, "contract_version", "1")
        bundle_limit, request_limit, output_limit = (
            polish.MAX_BUNDLE_BYTES,
            polish.MAX_REQUEST_BYTES,
            polish.MAX_REQUEST_BYTES,
        )
        if version == "2":
            from verifier.runtime.polish_capacity import CEILINGS

            bundle_limit, request_limit, output_limit = (
                CEILINGS["bundle_bytes"],
                CEILINGS["request_bytes"],
                CEILINGS["output_bytes"],
            )
        try:
            with Path(args.bundle).open("rb") as handle:
                bundle = handle.read(bundle_limit + 1)
            with Path(args.request).open("rb") as handle:
                request = handle.read(request_limit + 1)
            if args.polish_command == "check":
                with Path(args.assessment).open("rb") as handle:
                    assessment = handle.read(output_limit + 1)
                result = polish.recheck_polish(
                    assessment,
                    bundle_bytes=bundle,
                    request_bytes=request,
                    contract_version=version,
                )
            elif args.polish_command == "coverage":
                from verifier.runtime.polish_requirements import (
                    MAX_INVENTORY_BYTES,
                    assess_polish_inventory,
                )

                with Path(args.requirements).open("rb") as handle:
                    inventory = handle.read(MAX_INVENTORY_BYTES + 1)
                result = assess_polish_inventory(
                    bundle,
                    request_bytes=request,
                    inventory_bytes=inventory,
                    expected_inventory_digest=args.requirements_digest,
                    contract_version=version,
                )
            else:
                result = polish.assess_polish(
                    bundle, request_bytes=request, contract_version=version
                )
        except OSError:
            result = {
                "schema_version": "verifier-polish-assessment-" + version,
                "status": "UNKNOWN",
                "polished": False,
                "reason": "INPUT_UNAVAILABLE",
                "claim_boundary": polish.BOUNDARY,
            }
            if args.polish_command == "coverage":
                result.update(
                    schema_version="verifier-polish-requirements-assessment-1",
                    declared_coverage="UNKNOWN",
                    inventory_authentication="NOT_ESTABLISHED",
                    objective_inventory_closure="NOT_ESTABLISHED",
                )
        code = {"PASS": 0, "FAIL": 1, "UNKNOWN": 2}[result["status"]]
    if args.json:
        print(json.dumps(result, sort_keys=True, indent=2, allow_nan=False))
    else:
        print(f"[{result.get('status', 'CATALOG')}] polished=false")
        if "inventory" in result:
            print(
                (
                    "234-slot applicability and objective "
                    f"inventory ({result['slot_count']} slots)"
                )
            )
        print(result.get("claim_boundary", polish.BOUNDARY))
        if args.polish_command != "catalog":
            from verifier.runtime.polish_findings import project_reports, render_findings

            print(render_findings(project_reports(canonical_bytes(result))))
    return code
