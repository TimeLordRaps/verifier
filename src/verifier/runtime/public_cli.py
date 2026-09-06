"""Terminology: command-line interface (CLI); identifier (ID); JavaScript Object Notation (JSON);
Secure Hash Algorithm 256-bit (SHA-256); Verifier Standard (VSTD);
YAML Ain't Markup Language (YAML).

Public, target-neutral CLI for the VSTD reference implementation.

This entry point deliberately excludes repository-specific generators and verifiers.
It operates on declared manifests, stored receipts, verification geometries, and
component packages. Package inspection and surface planning never execute components.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import shutil
import sys
from pathlib import Path
from typing import Any, Callable

from verifier.artifact_control import (
    freeze_artifact,
    seal_artifact,
    thaw_artifact,
    thawed_artifact_status,
    verify_frozen_artifact,
)
from verifier.core.checker import independence_is_evidenced
from verifier.core.geometry_io import load_verification_geometry
from verifier.core.platform_comparison import compare_platform_run_receipts
from verifier.core.run import (
    RunError,
    capture_run,
    describe_run_plan,
    find_run_receipts_impacted_by_revocation,
    inspect_run_receipt,
    is_generic_run_receipt,
    load_manifest,
    reproduce_run_receipt,
    validate_run_receipt,
)
from verifier.data.models import ProvenanceHypergraph
from verifier.data.receipt import reproduce_data_receipt, validate_data_receipt
from verifier.hardware.receipt import is_vstd3_receipt, load_vstd3_receipt
from verifier.hardware.validation import validate_vstd3_receipt
from verifier.runtime.hardware_cli import (
    add_vstd3_parsers,
    handle_vstd3_command,
    parse_verification_keys,
)
from verifier.runtime.experimental_workflow_cli import (
    add_experiment_parsers,
    handle_experiment_command,
)
from verifier.runtime.demo import SCENARIOS, demo_report, emit_specimens, run_demo
from verifier.interoperability.catalog import AWARENESS_CLAIM_BOUNDARY
from verifier.interoperability.control_surface import (
    analyze_verification_surface,
    plan_validation,
)
from verifier.interoperability.reference_catalog import (
    REFERENCE_CATALOG_CLAIM_BOUNDARY,
    reference_component_registry,
)


_STORED_PACKAGE_CLAIM_BOUNDARY = (
    "Stored package declarations and exact byte integrity only; no component is "
    "imported or executed. Packaging does not establish availability, correctness, "
    "authorship, authorization, native qualification, or executable dependency closure. "
    + AWARENESS_CLAIM_BOUNDARY
)


def _receipt_file(path_or_dir: Path) -> Path:
    return path_or_dir / "receipt.json" if path_or_dir.is_dir() else path_or_dir


def _read_receipt(path_or_dir: Path) -> dict[str, Any] | None:
    receipt_file = _receipt_file(path_or_dir)
    if not receipt_file.exists():
        return None
    try:
        payload = json.loads(receipt_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _is_data_receipt(payload: dict[str, Any]) -> bool:
    return payload.get("schema_version") == "VSTD-DATA-0.1" and "hypergraph" in payload


def _load_hypergraph(path_or_dir: Path) -> tuple[dict[str, Any], ProvenanceHypergraph]:
    payload = _read_receipt(path_or_dir)
    if payload is None or not _is_data_receipt(payload):
        raise ValueError(
            "not a readable VSTD-Graph-1 receipt with serialized schema_version identifier "
            f"VSTD-DATA-0.1: {_receipt_file(path_or_dir)}"
        )
    return payload, ProvenanceHypergraph.from_dict(payload["hypergraph"])


def _within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _write_reproduction_bundle(
    manifest: dict[str, Any], manifest_dir: Path, output_dir: Path
) -> None:
    """Copy declared artifacts when a receipt is written outside its source tree."""
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "manifest.source.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
    )
    if output_dir.resolve() == manifest_dir.resolve():
        return

    cwd = Path(str(manifest.get("cwd", ".")))
    source_base = (manifest_dir / cwd).resolve()
    target_base = (output_dir / cwd).resolve()
    if not _within(target_base, output_dir.resolve()):
        raise RunError("cannot create a portable receipt bundle when cwd escapes the output directory")

    for entry in (*manifest.get("inputs", []), *manifest.get("outputs", [])):
        relative = Path(str(entry.get("path", "")))
        source = (source_base / relative).resolve()
        target = (target_base / relative).resolve()
        if not _within(source, source_base) or not _within(target, target_base):
            raise RunError(f"cannot bundle artifact path outside the declared cwd: {relative}")
        if not source.is_file():
            raise RunError(f"cannot bundle missing or non-file artifact: {relative}")
        target.parent.mkdir(parents=True, exist_ok=True)
        if source != target:
            shutil.copy2(source, target)


def _inspect_data_receipt(path_or_dir: Path) -> int:
    try:
        payload, graph = _load_hypergraph(path_or_dir)
    except ValueError as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1
    print("=" * 70)
    print(f"VSTD-GRAPH RECEIPT: {payload.get('receipt_id')}")
    print("=" * 70)
    print(f"Canonical Digest: {payload.get('canonical_digest')}")
    print(f"Target Artifact:  {payload.get('dataset_spec', {}).get('target_artifact_id')}")
    print(f"Checker Verdict:  {payload.get('independent_audit', {}).get('overall_verdict')}")
    basis = payload.get("independent_audit", {}).get("independence_basis", {})
    print(
        "Independence:     "
        + ("EVIDENCED" if independence_is_evidenced(basis) else "NOT_DEMONSTRATED")
    )
    print(f"Artifacts:        {len(graph.artifacts)}")
    print(f"Transformations:  {len(graph.transformations)}")
    print("=" * 70)
    return 0


def _run_receipt_handler_as_json(
    command: str, receipt_kind: str, handler: Callable[[], int]
) -> int:
    """Keep the common receipt commands machine-readable without changing their APIs."""

    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        exit_code = handler()
    result = (
        "COMPLETED"
        if exit_code == 0
        else "UNSUPPORTED"
        if exit_code == 2
        else "FAILED"
    )
    print(
        json.dumps(
            {
                "command": command,
                "receipt_kind": receipt_kind,
                "result": result,
                "exit_code": exit_code,
                "messages": stdout.getvalue().splitlines(),
                "errors": stderr.getvalue().splitlines(),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return exit_code


def _receipt_command_failure(args: argparse.Namespace, message: str) -> int:
    if args.json:
        print(
            json.dumps(
                {
                    "command": args.command,
                    "receipt_kind": "UNKNOWN",
                    "result": "FAILED",
                    "exit_code": 1,
                    "messages": [],
                    "errors": [message],
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        print(f"[FAIL] {message}", file=sys.stderr)
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vstd",
        description="Target-neutral VSTD receipt and provenance reference runtime.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    demo_parser = subparsers.add_parser(
        "demo",
        help="Run the side-effect-free VSTD adversarial flagship demonstration.",
    )
    demo_parser.add_argument(
        "--scenario",
        choices=("all", *SCENARIOS),
        default="all",
        help="Run all scenarios or one named scenario.",
    )
    demo_parser.add_argument("--json", action="store_true")
    demo_parser.add_argument(
        "--emit-specimens",
        metavar="DIR",
        help="Write deterministic JSON specimens and observations to DIR.",
    )

    run_parser = subparsers.add_parser(
        "run",
        help="Execute a trusted manifest without sandboxing and capture a VSTD receipt.",
    )
    run_parser.add_argument("manifest", help="JSON or YAML run manifest.")
    run_parser.add_argument("--output", help="Receipt output directory.")
    run_parser.add_argument("--receipt-id", help="Override the manifest claim id.")

    plan_parser = subparsers.add_parser(
        "plan", help="Show a manifest's declared command and paths without executing it."
    )
    plan_parser.add_argument("manifest", help="JSON or YAML run manifest.")
    plan_parser.add_argument("--json", action="store_true")

    compare_platforms_parser = subparsers.add_parser(
        "compare-platforms",
        help="Compare declared generic-run result surfaces across operating systems.",
    )
    compare_platforms_parser.add_argument(
        "receipts",
        nargs="+",
        help="Receipt directories or receipt.json files, one per declared platform.",
    )
    compare_platforms_parser.add_argument("--json", action="store_true")

    components_parser = subparsers.add_parser(
        "components",
        help="Inspect stored component declarations and byte integrity without execution.",
    )
    components_commands = components_parser.add_subparsers(
        dest="components_command", required=True
    )
    components_inspect_parser = components_commands.add_parser(
        "inspect", help="Read one local component package without importing its code."
    )
    components_inspect_parser.add_argument("package", help="Stored component package path.")
    components_inspect_parser.add_argument("--json", action="store_true")
    components_inspect_parser.add_argument(
        "--expected-sha256",
        metavar="HEX",
        help="Require this externally supplied canonical package SHA-256 digest.",
    )

    surface_parser = subparsers.add_parser(
        "surface",
        help="Analyze holes in one strictly loaded VSTD-2 modeled verification surface.",
    )
    surface_commands = surface_parser.add_subparsers(
        dest="surface_command", required=True
    )
    surface_analyze_parser = surface_commands.add_parser(
        "analyze",
        help="Emit deterministic modeled-surface diagnostics without executing a checker.",
    )
    surface_analyze_parser.add_argument("geometry", help="VSTD-2 geometry JSON path.")
    surface_analyze_parser.add_argument("--json", action="store_true")
    surface_analyze_parser.add_argument(
        "--plan",
        action="store_true",
        help=(
            "Add an experimental catalog match plan (first-party by default); no component is "
            "selected or executed."
        ),
    )
    surface_analyze_parser.add_argument(
        "--package",
        metavar="PACKAGE",
        help="With --plan, use the registry in this local stored component package.",
    )
    surface_analyze_parser.add_argument(
        "--expected-package-sha256",
        metavar="HEX",
        help="With --plan --package, require this canonical package SHA-256 digest.",
    )

    for command, help_text in (
        ("validate", "Run implemented receipt checks; Graph candidate validation is not conformance."),
        ("inspect", "Inspect a generic-run or VSTD-Graph receipt; validate and report VSTD-3."),
        ("reproduce", "Replay the mechanisms available in a stored receipt."),
    ):
        command_parser = subparsers.add_parser(command, help=help_text)
        command_parser.add_argument("receipt", help="Receipt directory or receipt.json.")
        command_parser.add_argument("--json", action="store_true")
        if command in {"validate", "inspect"}:
            command_parser.add_argument(
                "--key", action="append", default=[], metavar="KEY_ID=HEX"
            )
        if command == "reproduce":
            command_parser.add_argument(
                "--rerun",
                action="store_true",
                help="Generic-run receipts only: execute the recorded command again.",
            )

    impact_parser = subparsers.add_parser(
        "impact", help="Find run receipts affected by a provenance-artifact revocation."
    )
    impact_parser.add_argument("dataset_receipt")
    impact_parser.add_argument("artifact_id")
    impact_parser.add_argument("--search-root", default="receipts")

    data_parser = subparsers.add_parser("data", help="Inspect a stored VSTD-Graph hypergraph.")
    data_commands = data_parser.add_subparsers(dest="data_command", required=True)

    trace_parser = data_commands.add_parser("trace")
    trace_parser.add_argument("artifact_id")
    trace_parser.add_argument("--receipt", required=True)
    trace_parser.add_argument(
        "--direction", choices=("ancestors", "descendants", "blast_radius"), default="ancestors"
    )

    graph_parser = data_commands.add_parser("graph")
    graph_parser.add_argument("receipt")

    export_parser = data_commands.add_parser("export")
    export_parser.add_argument("receipt")

    artifact_parser = subparsers.add_parser(
        "artifact",
        help="Freeze exact artifact bytes, add or verify a seal, or thaw a descendant.",
    )
    artifact_commands = artifact_parser.add_subparsers(
        dest="artifact_command", required=True
    )
    freeze_parser = artifact_commands.add_parser(
        "freeze",
        help=(
            "Copy exact ordinary file or directory bytes into a new guarded bundle; "
            "symbolic-link sources are refused."
        ),
    )
    freeze_parser.add_argument("source")
    freeze_parser.add_argument("bundle")
    freeze_parser.add_argument("--media-type", default="application/octet-stream")
    freeze_parser.add_argument("--parent", action="append", default=[])
    freeze_parser.add_argument("--context", action="append", default=[])
    freeze_parser.add_argument("--json", action="store_true")

    seal_parser = artifact_commands.add_parser(
        "seal", help="Add a readable finite self-closing Ed25519 seal."
    )
    seal_parser.add_argument("bundle")
    seal_parser.add_argument("--private-key", required=True)
    seal_parser.add_argument("--json", action="store_true")

    verify_parser = artifact_commands.add_parser(
        "verify", help="Recompute exact bytes, guards, seals, and optional external anchors."
    )
    verify_parser.add_argument("bundle")
    verify_parser.add_argument("--expected-artifact-id")
    verify_parser.add_argument("--expected-key-id")
    verify_parser.add_argument(
        "--freeze-only",
        action="store_true",
        help="Accept a clean freeze without claiming seal-backed identity.",
    )
    verify_parser.add_argument("--json", action="store_true")

    thaw_parser = artifact_commands.add_parser(
        "thaw",
        help="Copy a clean sealed parent into a new, lexically absent mutable descendant.",
    )
    thaw_parser.add_argument("bundle")
    thaw_parser.add_argument("destination")
    thaw_parser.add_argument("--expected-artifact-id")
    thaw_parser.add_argument("--expected-key-id")
    thaw_parser.add_argument("--json", action="store_true")

    status_parser = artifact_commands.add_parser(
        "status",
        help=(
            "Compare a descendant with recorded sidecar metadata, or verify current "
            "equality against a supplied sealed parent."
        ),
    )
    status_parser.add_argument("artifact")
    status_parser.add_argument("--record")
    status_parser.add_argument(
        "--parent-bundle",
        help="Actual frozen parent bundle required to establish THAWED_CLEAN or THAWED_DIRTY.",
    )
    status_parser.add_argument("--expected-artifact-id")
    status_parser.add_argument("--expected-key-id")
    status_parser.add_argument("--json", action="store_true")
    add_experiment_parsers(subparsers)
    add_vstd3_parsers(subparsers)
    return parser


def _handle_receipt_command(args: argparse.Namespace) -> int:
    receipt_path = Path(args.receipt).resolve()
    payload = _read_receipt(receipt_path)
    if payload is None:
        return _receipt_command_failure(
            args, f"Receipt is missing or malformed: {_receipt_file(receipt_path)}"
        )

    if is_generic_run_receipt(payload):
        if args.command == "validate":
            handler = lambda: validate_run_receipt(receipt_path)
        elif args.command == "inspect":
            handler = lambda: inspect_run_receipt(receipt_path)
        else:
            handler = lambda: reproduce_run_receipt(receipt_path, rerun=args.rerun)
        return (
            _run_receipt_handler_as_json(args.command, "generic_computational_run", handler)
            if args.json
            else handler()
        )

    if _is_data_receipt(payload):
        if args.command == "validate":
            handler = lambda: validate_data_receipt(receipt_path)
        elif args.command == "inspect":
            handler = lambda: _inspect_data_receipt(receipt_path)
        elif args.rerun:
            handler = lambda: _receipt_command_failure(
                argparse.Namespace(command=args.command, json=False),
                "--rerun is not defined for stored VSTD-Graph receipts",
            )
        else:
            handler = lambda: reproduce_data_receipt(receipt_path)
        return (
            _run_receipt_handler_as_json(args.command, "vstd_graph", handler)
            if args.json
            else handler()
        )

    if is_vstd3_receipt(payload):
        receipt = load_vstd3_receipt(receipt_path)
        if args.command == "reproduce":
            message = (
                "A stored hardware receipt cannot replay physical execution; use its "
                "declared emulator or vendor collection mechanism."
            )
            if args.json:
                return _run_receipt_handler_as_json(
                    args.command,
                    "vstd3_hardware",
                    lambda: (print(f"[UNSUPPORTED] {message}", file=sys.stderr) or 2),
                )
            print(f"[UNSUPPORTED] {message}", file=sys.stderr)
            return 2
        resolver, _ = parse_verification_keys(args.key)
        validation = validate_vstd3_receipt(receipt, key_resolver=resolver)
        result = {
            "status": validation.status.value,
            "schema_version": receipt.schema_version,
            "receipt_id": receipt.receipt_id,
            "canonical_digest": receipt.canonical_digest,
            "errors": list(validation.errors),
            "warnings": list(validation.warnings),
            "claims": [claim.to_dict() for claim in receipt.claim_evaluations],
        }
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(f"[{result['status']}] VSTD 3 receipt {receipt.receipt_id}")
            print(f"  Canonical digest: {receipt.canonical_digest}")
            print(f"  Claims: {len(receipt.claim_evaluations)}")
            for message in (*validation.errors, *validation.warnings):
                print(f"  - {message}")
        return 0 if validation.status.value == "PASS" else (1 if validation.status.value == "FAIL" else 2)

    return _receipt_command_failure(args, "Unsupported receipt kind or schema")


def _handle_data_command(args: argparse.Namespace) -> int:
    receipt_path = Path(args.receipt).resolve()
    try:
        payload, graph = _load_hypergraph(receipt_path)
    except ValueError as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1

    if args.data_command == "export":
        print(json.dumps(payload["hypergraph"], indent=2, sort_keys=True))
        return 0

    if args.data_command == "graph":
        print("```mermaid")
        print("graph TD")
        for artifact in graph.artifacts.values():
            node_id = artifact.artifact_id.replace(":", "_").replace("-", "_")
            label = artifact.label.replace('"', "").replace("'", "")
            print(f'    {node_id}["{label}"]')
        for transform in graph.transformations.values():
            transform_id = transform.transformation_id.replace(":", "_").replace("-", "_")
            label = transform.label.replace('"', "").replace("'", "")
            print(f'    {transform_id}{{"{label}"}}')
            for input_port in transform.inputs:
                artifact_id = input_port.artifact_id.replace(":", "_").replace("-", "_")
                print(f"    {artifact_id} -->|{input_port.role}| {transform_id}")
            for output_port in transform.outputs:
                artifact_id = output_port.artifact_id.replace(":", "_").replace("-", "_")
                print(f"    {transform_id} -->|{output_port.role}| {artifact_id}")
        print("```")
        return 0

    artifact_id = args.artifact_id
    if artifact_id not in graph.artifacts:
        print(f"[FAIL] Unknown artifact id: {artifact_id}", file=sys.stderr)
        return 1
    if args.direction == "ancestors":
        selected = sorted(graph.ancestors([artifact_id]))
    elif args.direction == "descendants":
        selected = sorted(graph.descendants([artifact_id]))
    else:
        selected = graph.blast_radius(artifact_id)
    print(json.dumps({"artifact_id": artifact_id, "direction": args.direction, "matches": selected}))
    return 0


def _handle_components_command(args: argparse.Namespace) -> int:
    from verifier.interoperability.storage import load_component_package

    package = load_component_package(args.package, expected_digest=args.expected_sha256)
    if args.json:
        print(json.dumps(package.inspect(), indent=2, sort_keys=True))
    else:
        print("[PACKAGE INTEGRITY; NO EXECUTION]")
        print(f"  Canonical digest: {package.canonical_digest()}")
        print(f"  Components:       {len(package.registry.components)}")
        print(f"  Boundary: {_STORED_PACKAGE_CLAIM_BOUNDARY}")
        print(json.dumps(package.inspect(), indent=2, sort_keys=True))
    return 0


def _handle_surface_command(args: argparse.Namespace) -> int:
    if (args.package is not None or args.expected_package_sha256 is not None) and not args.plan:
        raise ValueError("package options require --plan")
    if args.expected_package_sha256 is not None and args.package is None:
        raise ValueError("--expected-package-sha256 requires --package")
    geometry = load_verification_geometry(Path(args.geometry).resolve())
    analysis = analyze_verification_surface(geometry)
    report: dict[str, Any] = analysis.to_dict()
    plan = None
    if args.plan:
        package = None
        if args.package is not None:
            from verifier.interoperability.storage import load_component_package

            package = load_component_package(
                args.package, expected_digest=args.expected_package_sha256
            )
        registry = package.registry if package is not None else reference_component_registry()
        plan = plan_validation(analysis, registry, package=package)
        family_count = len(
            {
                family
                for component in registry.components
                for family in component.verifier_family_ids
            }
        )
        report = {
            "analysis": analysis.to_dict(),
            "catalog": {
                "registry_version": registry.registry_version,
                "registry_digest": registry.canonical_digest(),
                "component_count": len(registry.components),
                "implementation_family_count": family_count,
                "claim_boundary": REFERENCE_CATALOG_CLAIM_BOUNDARY,
            },
            "plan": plan.to_dict(),
        }
        if package is not None:
            report["catalog"].update(
                source="STORED_COMPONENT_PACKAGE",
                package_digest=package.canonical_digest(),
                claim_boundary=_STORED_PACKAGE_CLAIM_BOUNDARY,
            )
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    print(f"[MODELED SURFACE] {analysis.geometry_id}")
    print(f"  Ordinary closed: {str(analysis.ordinary_closed).lower()}")
    print(f"  Self closed:     {str(analysis.self_closed).lower()}")
    print(f"  Surface holes:  {len(analysis.holes)}")
    for hole in analysis.holes:
        print(
            f"  - {hole.kind.value}: {hole.source_kind} {hole.source_id} "
            f"({hole.native_status})"
        )
    print(f"  Boundary: {analysis.claim_boundary}")
    if plan is not None:
        matched = sum(candidate.component_id is not None for candidate in plan.candidates)
        print("[EXPERIMENTAL PLAN; NO EXECUTION]")
        print(f"  Candidates: {matched}/{len(plan.candidates)} matched")
        print(f"  Registry:   {plan.registry_version} ({plan.registry_digest})")
        if args.package is not None:
            print(f"  Package:    {report['catalog']['package_digest']}")
            print(f"  Source boundary: {_STORED_PACKAGE_CLAIM_BOUNDARY}")
        print(f"  Boundary:   {plan.claim_boundary}")
    return 0


def _print_artifact_result(result: dict[str, Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return
    print(f"[{result.get('state', 'COMPLETED')}] artifact control")
    for key, value in result.items():
        if key != "state":
            print(f"  {key}: {value}")


def _handle_artifact_command(args: argparse.Namespace) -> int:
    if args.artifact_command == "freeze":
        result = freeze_artifact(
            args.source,
            args.bundle,
            media_type=args.media_type,
            parent_bundles=args.parent,
            context_bundles=args.context,
        )
        output = {"state": "FROZEN_UNSEALED", **result}
        _print_artifact_result(output, args.json)
        return 0
    if args.artifact_command == "seal":
        result = seal_artifact(args.bundle, args.private_key)
        output = {"state": "SEALED", **result}
        _print_artifact_result(output, args.json)
        return 0
    if args.artifact_command == "verify":
        verification = verify_frozen_artifact(
            args.bundle,
            expected_artifact_id=args.expected_artifact_id,
            expected_key_id=args.expected_key_id,
            require_seal=not args.freeze_only,
        )
        output = verification.to_dict()
        _print_artifact_result(output, args.json)
        if verification.state in {"SEALED", "FROZEN_UNSEALED"}:
            return 0
        return 2 if verification.state == "NOT_ESTABLISHED" else 1
    if args.artifact_command == "thaw":
        result = thaw_artifact(
            args.bundle,
            args.destination,
            expected_artifact_id=args.expected_artifact_id,
            expected_key_id=args.expected_key_id,
        )
        output = {"state": "THAWED_CLEAN", **result}
        _print_artifact_result(output, args.json)
        return 0
    result = thawed_artifact_status(
        args.artifact,
        args.record,
        parent_bundle=args.parent_bundle,
        expected_artifact_id=args.expected_artifact_id,
        expected_key_id=args.expected_key_id,
    )
    _print_artifact_result(result, args.json)
    if result["state"] == "THAWED_CLEAN":
        return 0
    if result["state"] == "NOT_ESTABLISHED":
        return 2
    return 1


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "demo":
            results = run_demo(args.scenario)
            report = demo_report(results)
            if args.emit_specimens:
                emit_specimens(results, Path(args.emit_specimens).resolve())
            if args.json:
                print(json.dumps(report, indent=2, sort_keys=True))
            else:
                print("VSTD flagship adversarial demo")
                print(
                    f"{report['successful_scenarios']}/{report['scenario_count']} "
                    "scenarios behaved as required."
                )
                for result in results:
                    marker = "DEMO OK" if result.ok else "DEMO FAILED"
                    print(f"[{marker}] {result.title}")
                    print(f"  expected: {result.expected}")
                    print(f"  observed: {result.observed}")
                    print(f"  detail:   {result.details}")
                print(f"Boundary: {report['claim_boundary']}")
                if args.emit_specimens:
                    print(f"Specimens: {Path(args.emit_specimens).resolve()}")
            return 0 if report["status"] == "OK" else 1

        if args.command == "plan":
            manifest_path = Path(args.manifest).resolve()
            manifest = load_manifest(manifest_path)
            plan = describe_run_plan(manifest, manifest_path.parent)
            if args.json:
                print(json.dumps(plan, indent=2, sort_keys=True))
            else:
                print("[NO EXECUTION] Manifest plan")
                print(f"  Command: {' '.join(plan['command'])}")
                print(f"  CWD:     {plan['cwd']['resolved']}")
                print(f"  Repo:    {plan['repo_dir']['resolved']}")
                print("  Warning: execution is not sandboxed; declared paths are capture scope only.")
                external = [
                    item
                    for item in (plan["cwd"], plan["repo_dir"], *plan["inputs"], *plan["outputs"])
                    if item["outside_manifest_directory"]
                ]
                print(f"  Declared paths outside manifest directory: {len(external)}")
            return 0

        if args.command == "run":
            manifest_path = Path(args.manifest).resolve()
            manifest = load_manifest(manifest_path)
            print(
                "[UNSANDBOXED EXECUTION] Run only trusted manifests inside an "
                "isolation boundary appropriate to the declared command.",
                file=sys.stderr,
            )
            receipt = capture_run(
                manifest,
                manifest_dir=manifest_path.parent,
                receipt_id=args.receipt_id,
            )
            output_dir = Path(args.output).resolve() if args.output else manifest_path.parent
            _write_reproduction_bundle(manifest, manifest_path.parent, output_dir)
            receipt_path = receipt.save_to_directory(output_dir)
            print(f"[SUCCESS] Receipt generated at: {receipt_path}")
            print(f"          Receipt ID: {receipt.receipt_id}")
            print(f"          Canonical Digest: {receipt.canonical_digest}")
            return 0 if receipt.execution.outcome == "COMPLETED" else 1

        if args.command == "compare-platforms":
            comparison = compare_platform_run_receipts(args.receipts)
            report = comparison.to_dict()
            if args.json:
                print(json.dumps(report, indent=2, sort_keys=True))
            else:
                print(f"[{comparison.status.value}] {comparison.reason}")
                print(
                    "  Required platforms: "
                    + (", ".join(comparison.required_platforms) or "none")
                )
                print(
                    "  Observed platforms: "
                    + (", ".join(comparison.observed_platforms) or "none")
                )
                for error in comparison.errors:
                    print(f"  Error: {error}")
                for difference in comparison.differences:
                    print(
                        "  Difference: "
                        f"{difference.get('reference_platform')} -> "
                        f"{difference.get('observed_platform')} at "
                        f"{difference.get('path')}"
                    )
                print(f"  Boundary: {report['claim_boundary']}")
            return comparison.exit_code

        if args.command == "components":
            return _handle_components_command(args)

        if args.command == "surface":
            return _handle_surface_command(args)

        if args.command in {"validate", "inspect", "reproduce"}:
            return _handle_receipt_command(args)

        if args.command == "impact":
            impacted = find_run_receipts_impacted_by_revocation(
                Path(args.search_root).resolve(),
                _receipt_file(Path(args.dataset_receipt).resolve()),
                args.artifact_id,
            )
            print(json.dumps(impacted, indent=2, sort_keys=True))
            return 0

        if args.command == "data":
            return _handle_data_command(args)
        if args.command == "artifact":
            return _handle_artifact_command(args)
        if args.command == "experiment":
            return handle_experiment_command(args)
        if args.command in {"hardware", "continuity", "fleet", "evidence", "claims"}:
            return handle_vstd3_command(args)
    except (OSError, RunError, ValueError, KeyError) as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
