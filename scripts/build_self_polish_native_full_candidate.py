"""Capture the current source coordinate and emit the full native candidate."""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from verifier.runtime import core_obligation_union
from verifier.runtime import polish_requirements
from verifier.runtime import self_polish_native_full_candidate


ARTIFACT_SCHEMA = "verifier-self-polish-full-native-candidate-artifact-1"


def _source_coordinate(observed: dict[str, Any]) -> dict[str, str]:
    return {
        "source_head": observed["git_head"],
        "source_tree": observed["git_tree"],
        "source_worktree_status_digest": observed[
            "worktree_status_digest"
        ],
        "source_manifest_digest": (
            polish_requirements.source_manifest_digest(observed)
        ),
    }


def build_artifact(root: str | Path) -> dict[str, Any]:
    selected_root = Path(root).resolve(strict=True)
    observed = polish_requirements.capture_core_self_polish_source(
        selected_root
    )
    coordinate = _source_coordinate(observed)
    coordinate_digest = core_obligation_union.value_digest(coordinate)
    candidate = (
        self_polish_native_full_candidate.replay_full_native_candidate(
            selected_root,
            source_coordinate_digest=coordinate_digest,
        )
    )
    body = {
        "schema_version": ARTIFACT_SCHEMA,
        "source_coordinate": coordinate,
        "source_coordinate_digest": coordinate_digest,
        "source_evidence": {
            "candidate_source_census_digest": observed[
                "candidate_source_census_digest"
            ],
            "candidate_source_file_count": observed[
                "candidate_source_file_count"
            ],
            "candidate_source_bytes": observed["candidate_source_bytes"],
            "tracked_file_count": observed["tracked_file_count"],
            "untracked_nonignored_file_count": observed[
                "untracked_nonignored_file_count"
            ],
        },
        "candidate": candidate,
    }
    body["artifact_digest"] = core_obligation_union.value_digest(body)
    return body


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    artifact = build_artifact(args.root)
    encoded = core_obligation_union.canonical_bytes(artifact)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(encoded)
    print(f"output={args.output.resolve()}")
    print(f"bytes={len(encoded)}")
    print(f"artifact_digest={artifact['artifact_digest']}")
    print(
        "source_coordinate_digest="
        f"{artifact['source_coordinate_digest']}"
    )
    print(f"candidate_status={artifact['candidate']['status']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
