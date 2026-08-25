"""Terminology: application programming interface (API); Verifier Standard (VSTD).

Deterministic GitHub-to-workflow observations with no verification upgrade."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping


class GitHubAdapterError(ValueError):
    """Raised when the normalized GitHub snapshot is incomplete or unsupported."""


def _expect_object(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise GitHubAdapterError(f"{path} must be an object")
    return value


def _expect_array(value: Any, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise GitHubAdapterError(f"{path} must be an array")
    return value


def _exact(value: Mapping[str, Any], path: str, fields: set[str]) -> None:
    missing = sorted(fields - set(value))
    unknown = sorted(set(value) - fields)
    if missing:
        raise GitHubAdapterError(f"{path} missing fields: {', '.join(missing)}")
    if unknown:
        raise GitHubAdapterError(f"{path} unsupported fields: {', '.join(unknown)}")


def _text(value: Any, path: str, *, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise GitHubAdapterError(f"{path} must be a non-empty string")
    return value


def _integer(value: Any, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise GitHubAdapterError(f"{path} must be a non-negative integer")
    return value


def _event_id(kind: str, repository: str, coordinate: str) -> str:
    stable = json.dumps(
        [kind, repository, coordinate], ensure_ascii=True, separators=(",", ":")
    ).encode("utf-8")
    return f"github-event-{hashlib.sha256(stable).hexdigest()[:20]}"


def _event(
    *,
    kind: str,
    repository: str,
    coordinate: str,
    recorded_at: str,
    native_state: str,
    details: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "id": _event_id(kind, repository, coordinate),
        "kind": kind,
        "recorded_at": recorded_at,
        "source": {
            "platform": "github",
            "repository": repository,
            "coordinate": coordinate,
        },
        "native_state": native_state,
        "verification_effect": "NONE",
        "details": dict(details),
    }


def github_snapshot_to_events(snapshot: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
    """Map the documented normalized snapshot to verdict-neutral workflow events.

    The input is not the unconstrained GitHub API response. Rejecting unknown fields
    prevents a caller from assuming that unparsed platform semantics were preserved.
    A successful workflow or merged pull request remains a platform fact only.
    """

    root = _expect_object(snapshot, "$")
    _exact(
        root,
        "$",
        {"repository", "issues", "commits", "workflow_runs", "pull_requests"},
    )
    repository = _text(root["repository"], "$.repository")
    assert repository is not None
    events: list[dict[str, Any]] = []

    for index, value in enumerate(_expect_array(root["issues"], "$.issues")):
        path = f"$.issues[{index}]"
        item = _expect_object(value, path)
        _exact(item, path, {"number", "title", "state", "updated_at"})
        number = _integer(item["number"], f"{path}.number")
        title = _text(item["title"], f"{path}.title")
        state = _text(item["state"], f"{path}.state")
        updated_at = _text(item["updated_at"], f"{path}.updated_at")
        assert title is not None and state is not None and updated_at is not None
        events.append(
            _event(
                kind="PLATFORM_ISSUE",
                repository=repository,
                coordinate=f"issue:{number}",
                recorded_at=updated_at,
                native_state=state,
                details={"number": number, "title": title},
            )
        )

    for index, value in enumerate(_expect_array(root["commits"], "$.commits")):
        path = f"$.commits[{index}]"
        item = _expect_object(value, path)
        _exact(item, path, {"sha", "subject", "committed_at"})
        sha = _text(item["sha"], f"{path}.sha")
        subject = _text(item["subject"], f"{path}.subject")
        committed_at = _text(item["committed_at"], f"{path}.committed_at")
        assert sha is not None and subject is not None and committed_at is not None
        events.append(
            _event(
                kind="PLATFORM_COMMIT",
                repository=repository,
                coordinate=f"commit:{sha}",
                recorded_at=committed_at,
                native_state="RECORDED",
                details={"sha": sha, "subject": subject},
            )
        )

    for index, value in enumerate(_expect_array(root["workflow_runs"], "$.workflow_runs")):
        path = f"$.workflow_runs[{index}]"
        item = _expect_object(value, path)
        _exact(
            item,
            path,
            {"id", "workflow", "status", "conclusion", "head_sha", "updated_at", "artifacts"},
        )
        run_id = _integer(item["id"], f"{path}.id")
        workflow = _text(item["workflow"], f"{path}.workflow")
        status = _text(item["status"], f"{path}.status")
        conclusion = _text(item["conclusion"], f"{path}.conclusion", nullable=True)
        head_sha = _text(item["head_sha"], f"{path}.head_sha")
        updated_at = _text(item["updated_at"], f"{path}.updated_at")
        assert workflow is not None and status is not None and head_sha is not None and updated_at is not None
        native_state = status if conclusion is None else f"{status}/{conclusion}"
        events.append(
            _event(
                kind="PLATFORM_WORKFLOW_RUN",
                repository=repository,
                coordinate=f"workflow-run:{run_id}",
                recorded_at=updated_at,
                native_state=native_state,
                details={"id": run_id, "workflow": workflow, "head_sha": head_sha},
            )
        )
        for artifact_index, artifact_value in enumerate(
            _expect_array(item["artifacts"], f"{path}.artifacts")
        ):
            artifact_path = f"{path}.artifacts[{artifact_index}]"
            artifact = _expect_object(artifact_value, artifact_path)
            _exact(artifact, artifact_path, {"id", "name", "digest", "expired"})
            artifact_id = _integer(artifact["id"], f"{artifact_path}.id")
            name = _text(artifact["name"], f"{artifact_path}.name")
            digest = _text(artifact["digest"], f"{artifact_path}.digest", nullable=True)
            expired = artifact["expired"]
            if not isinstance(expired, bool):
                raise GitHubAdapterError(f"{artifact_path}.expired must be boolean")
            assert name is not None
            events.append(
                _event(
                    kind="PLATFORM_ARTIFACT",
                    repository=repository,
                    coordinate=f"workflow-artifact:{artifact_id}",
                    recorded_at=updated_at,
                    native_state="EXPIRED" if expired else "AVAILABLE",
                    details={"id": artifact_id, "name": name, "digest": digest, "run_id": run_id},
                )
            )

    for index, value in enumerate(_expect_array(root["pull_requests"], "$.pull_requests")):
        path = f"$.pull_requests[{index}]"
        item = _expect_object(value, path)
        _exact(item, path, {"number", "state", "merged", "head_sha", "base_sha", "updated_at"})
        number = _integer(item["number"], f"{path}.number")
        state = _text(item["state"], f"{path}.state")
        merged = item["merged"]
        if not isinstance(merged, bool):
            raise GitHubAdapterError(f"{path}.merged must be boolean")
        head_sha = _text(item["head_sha"], f"{path}.head_sha")
        base_sha = _text(item["base_sha"], f"{path}.base_sha")
        updated_at = _text(item["updated_at"], f"{path}.updated_at")
        assert state is not None and head_sha is not None and base_sha is not None and updated_at is not None
        events.append(
            _event(
                kind="PLATFORM_PULL_REQUEST",
                repository=repository,
                coordinate=f"pull-request:{number}",
                recorded_at=updated_at,
                native_state=f"{state}/{'MERGED' if merged else 'NOT_MERGED'}",
                details={
                    "number": number,
                    "head_sha": head_sha,
                    "base_sha": base_sha,
                    "merged": merged,
                },
            )
        )

    return tuple(sorted(events, key=lambda item: item["id"]))
