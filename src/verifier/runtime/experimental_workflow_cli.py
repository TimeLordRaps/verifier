"""CLI boundary for the experimental, non-normative workflow profile."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from verifier.experimental_workflow import (
    GitHubAdapterError,
    github_snapshot_to_events,
    load_manifest,
    verify_repo_artifacts,
)


def add_experiment_parsers(subparsers: argparse._SubParsersAction) -> None:
    """Add verdict-neutral experimental-workflow commands to the public parser."""

    parser = subparsers.add_parser(
        "experiment",
        help="Validate or adapt experimental, non-normative workflow records.",
    )
    commands = parser.add_subparsers(dest="experiment_command", required=True)

    validate_parser = commands.add_parser(
        "validate",
        help="Validate a profile manifest without granting a VSTD verdict.",
    )
    validate_parser.add_argument("manifest", help="Experimental workflow manifest JSON.")
    validate_parser.add_argument(
        "--repo-root",
        help="Repository root used to verify every repo: artifact locator.",
    )
    validate_parser.add_argument("--json", action="store_true")

    github_parser = commands.add_parser(
        "github-events",
        help="Map a strict normalized GitHub snapshot to verdict-neutral events.",
    )
    github_parser.add_argument("snapshot", help="Normalized GitHub snapshot JSON.")
    github_parser.add_argument("--json", action="store_true")


def _repository_artifact_count(payload: dict[str, Any]) -> int:
    artifacts = payload.get("artifacts", [])
    if not isinstance(artifacts, list):
        return 0
    return sum(
        1
        for artifact in artifacts
        if isinstance(artifact, dict)
        and isinstance(artifact.get("locator"), str)
        and artifact["locator"].startswith("repo:")
    )


def _validate(args: argparse.Namespace) -> int:
    manifest_path = Path(args.manifest).resolve()
    payload = load_manifest(manifest_path)
    repo_artifact_count = _repository_artifact_count(payload)
    if not repo_artifact_count:
        repository_artifacts = "NOT_APPLICABLE"
    elif args.repo_root:
        verify_repo_artifacts(payload, Path(args.repo_root).resolve())
        repository_artifacts = "VERIFIED"
    else:
        repository_artifacts = "NOT_CHECKED"

    experiment = payload["experiment"]
    profile = payload["profile"]
    assert isinstance(experiment, dict) and isinstance(profile, dict)
    result = {
        "status": (
            "VALID"
            if repository_artifacts != "NOT_CHECKED"
            else "VALID_WITH_UNCHECKED_REPOSITORY_ARTIFACTS"
        ),
        "profile": {
            "id": profile["id"],
            "version": profile["version"],
            "status": profile["status"],
        },
        "experiment": {
            "id": experiment["id"],
            "state": experiment["state"],
        },
        "manifest_digest": payload["manifest_digest"],
        "repository_artifact_count": repo_artifact_count,
        "repository_artifacts": repository_artifacts,
        "vstd_verdict_granted": False,
        "claim_boundary": (
            "Structural validity and bound-byte checks do not establish the hypothesis, "
            "native verifier, publication, independence, or a VSTD verdict."
        ),
    }
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"[{result['status']}] experimental workflow {experiment['id']}")
        print(f"  Manifest digest:      {payload['manifest_digest']}")
        print(f"  Repository artifacts: {repository_artifacts}")
        print("  VSTD verdict granted: no")
        print(f"  Boundary: {result['claim_boundary']}")
    return 2 if repository_artifacts == "NOT_CHECKED" else 0


def _github_events(args: argparse.Namespace) -> int:
    snapshot_path = Path(args.snapshot).resolve()
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    if not isinstance(snapshot, dict):
        raise GitHubAdapterError("normalized GitHub snapshot must be a JSON object")
    events = github_snapshot_to_events(snapshot)
    result = {
        "adapter": "github-normalized-0.1",
        "events": list(events),
        "event_count": len(events),
        "verification_effects": sorted({event["verification_effect"] for event in events}),
        "vstd_verdicts_granted": 0,
    }
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"[ADAPTED] {len(events)} normalized GitHub events")
        print("  Verification effects: NONE")
        print("  VSTD verdicts granted: 0")
    return 0


def handle_experiment_command(args: argparse.Namespace) -> int:
    """Dispatch one experimental-workflow command without widening its result."""

    if args.experiment_command == "validate":
        return _validate(args)
    if args.experiment_command == "github-events":
        return _github_events(args)
    return 1
