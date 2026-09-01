"""Terminology: identifier (ID); JavaScript Object Notation (JSON);
Secure Hash Algorithm 256-bit (SHA-256); Unicode Transformation Format, 8-bit (UTF-8);
Verifier Standard (VSTD).

Validate the non-normative experimental-workflow profile.

This module records allocation and workflow facts. It deliberately does not execute
domain verifiers, derive VSTD verdicts, or treat repository state as verification.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any, Mapping


PROFILE_ID = "vstd.experimental-workflow"
PROFILE_VERSION = "0.1"
PROFILE_STATUS = "EXPERIMENTAL_NON_NORMATIVE"

EXPERIMENT_STATES = frozenset(
    {"DRAFT", "PREREGISTERED", "RUNNING", "BLOCKED", "COMPLETED", "ABANDONED"}
)
HYPOTHESIS_STATES = frozenset({"OPEN", "SUPPORTED", "REFUTED", "UNKNOWN", "CONFLICTED"})
PREREGISTRATION_STATES = frozenset({"NONE", "DRAFT", "FROZEN", "AMENDED"})
ACTION_STATES = frozenset({"PLANNED", "RUNNING", "BLOCKED", "COMPLETED", "ABANDONED"})
OBSERVATION_STATES = frozenset({"OBSERVED", "UNKNOWN", "CONFLICTED"})
MAPPING_STATES = frozenset({"NOT_EVALUATED", "MAPPED"})
VSTD_VERDICTS = frozenset({"PASS", "FAIL", "UNKNOWN", "CONFLICTED", "REJECTED"})
CHALLENGE_STATES = frozenset({"OPEN", "RESOLVED", "REJECTED"})
HORIZON_STATES = frozenset({"UNKNOWN", "CONFLICTED", "BLOCKED", "OUT_OF_SCOPE"})
PUBLICATION_STATES = frozenset({"PRIVATE", "INTERNAL", "CANDIDATE", "PUBLISHED", "RETRACTED"})
PLATFORM_EVENT_KINDS = frozenset(
    {
        "PLATFORM_ISSUE",
        "PLATFORM_COMMIT",
        "PLATFORM_WORKFLOW_RUN",
        "PLATFORM_ARTIFACT",
        "PLATFORM_PULL_REQUEST",
    }
)

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_PORTABLE_LOCATOR_PREFIXES = (
    "artifact:",
    "git:",
    "https://",
    "repo:",
    "urn:",
)


class WorkflowProfileError(ValueError):
    """Raised when a workflow manifest exceeds or violates the profile boundary."""


def _fail(path: str, message: str) -> None:
    raise WorkflowProfileError(f"{path}: {message}")


def _mapping(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail(path, "must be an object")
    return value


def _sequence(value: Any, path: str) -> list[Any]:
    if not isinstance(value, list):
        _fail(path, "must be an array")
    return value


def _string(value: Any, path: str, *, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        _fail(path, "must be a non-empty string")
    return value


def _string_list(value: Any, path: str) -> list[str]:
    items = _sequence(value, path)
    for index, item in enumerate(items):
        _string(item, f"{path}[{index}]")
    if len(items) != len(set(items)):
        _fail(path, "must not contain duplicates")
    return items


def _exact_keys(
    value: Mapping[str, Any],
    path: str,
    *,
    required: set[str],
    optional: set[str] | None = None,
) -> None:
    optional = optional or set()
    missing = sorted(required - set(value))
    unknown = sorted(set(value) - required - optional)
    if missing:
        _fail(path, f"missing fields: {', '.join(missing)}")
    if unknown:
        _fail(path, f"unsupported fields: {', '.join(unknown)}")


def _enum(value: Any, allowed: frozenset[str], path: str) -> str:
    text = _string(value, path)
    assert text is not None
    if text not in allowed:
        _fail(path, f"unsupported value {text!r}")
    return text


def _nonnegative_integer(value: Any, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        _fail(path, "must be a non-negative integer")
    return value


def _reject_floats(value: Any, path: str = "$", *, seen: set[int] | None = None) -> None:
    if isinstance(value, float):
        _fail(path, "floating-point values are not canonical in this profile")
    if isinstance(value, Mapping):
        seen = seen or set()
        identity = id(value)
        if identity in seen:
            _fail(path, "cyclic objects cannot be serialized")
        seen.add(identity)
        for key, item in value.items():
            if not isinstance(key, str):
                _fail(path, "object keys must be strings")
            _reject_floats(item, f"{path}.{key}", seen=seen)
        seen.remove(identity)
    elif isinstance(value, (list, tuple)):
        seen = seen or set()
        identity = id(value)
        if identity in seen:
            _fail(path, "cyclic arrays cannot be serialized")
        seen.add(identity)
        for index, item in enumerate(value):
            _reject_floats(item, f"{path}[{index}]", seen=seen)
        seen.remove(identity)
    elif value is not None and not isinstance(value, (str, int, bool)):
        _fail(path, f"unsupported canonical type {type(value).__name__}")


def canonical_bytes(payload: Any) -> bytes:
    """Return deterministic UTF-8 JSON bytes after rejecting ambiguous numeric input."""

    _reject_floats(payload)
    return json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def manifest_digest(payload: Mapping[str, Any]) -> str:
    """Digest every manifest field except the digest that seals those fields."""

    stable = dict(payload)
    stable.pop("manifest_digest", None)
    return "sha256:" + hashlib.sha256(canonical_bytes(stable)).hexdigest()


def seal_manifest(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Deep-copy and seal a manifest without mutating the caller's object."""

    sealed = copy.deepcopy(dict(payload))
    sealed["manifest_digest"] = manifest_digest(sealed)
    validate_manifest(sealed)
    return sealed


def _register_id(identifier: Any, path: str, ids: dict[str, str]) -> str:
    text = _string(identifier, path)
    assert text is not None
    if text in ids:
        _fail(path, f"duplicates {ids[text]}")
    ids[text] = path
    return text


def _validate_artifact(value: Any, index: int, ids: dict[str, str]) -> str:
    path = f"$.artifacts[{index}]"
    item = _mapping(value, path)
    _exact_keys(
        item,
        path,
        required={"id", "role", "media_type", "digest", "locator"},
    )
    identifier = _register_id(item["id"], f"{path}.id", ids)
    _string(item["role"], f"{path}.role")
    _string(item["media_type"], f"{path}.media_type")
    digest = _string(item["digest"], f"{path}.digest")
    assert digest is not None
    if not _DIGEST_RE.fullmatch(digest):
        _fail(f"{path}.digest", "must be lowercase sha256:<64 hex>")
    locator = _string(item["locator"], f"{path}.locator")
    assert locator is not None
    if not locator.startswith(_PORTABLE_LOCATOR_PREFIXES):
        _fail(
            f"{path}.locator",
            "must use artifact:, git:, https://, repo:, or urn: coordinates",
        )
    if locator.startswith("repo:"):
        relative = locator.removeprefix("repo:")
        candidate = PurePosixPath(relative)
        if (
            not relative
            or "\\" in relative
            or candidate.is_absolute()
            or ".." in candidate.parts
            or "." in candidate.parts
        ):
            _fail(f"{path}.locator", "repo: coordinates must be normalized repository-relative paths")
    return identifier


def _validate_substrate(value: Any, path: str) -> None:
    item = _mapping(value, path)
    _exact_keys(item, path, required={"kind", "name", "version", "coordinate"})
    for field in ("kind", "name", "version", "coordinate"):
        _string(item[field], f"{path}.{field}")


def _validate_mapping(value: Any, path: str) -> None:
    item = _mapping(value, path)
    _exact_keys(
        item,
        path,
        required={"status", "vstd_verdict", "mapping_profile", "receipt_artifact_id", "reason"},
    )
    state = _enum(item["status"], MAPPING_STATES, f"{path}.status")
    verdict = _string(item["vstd_verdict"], f"{path}.vstd_verdict", nullable=True)
    mapping_profile = _string(item["mapping_profile"], f"{path}.mapping_profile", nullable=True)
    receipt_id = _string(item["receipt_artifact_id"], f"{path}.receipt_artifact_id", nullable=True)
    _string(item["reason"], f"{path}.reason")
    if state == "NOT_EVALUATED":
        if any(value is not None for value in (verdict, mapping_profile, receipt_id)):
            _fail(path, "NOT_EVALUATED cannot carry a VSTD verdict, profile, or receipt")
    else:
        if verdict not in VSTD_VERDICTS:
            _fail(f"{path}.vstd_verdict", "MAPPED requires an explicit VSTD verdict")
        if mapping_profile is None or receipt_id is None:
            _fail(path, "MAPPED requires a mapping profile and receipt artifact")


def _validate_action_graph(actions: Mapping[str, list[str]]) -> None:
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(identifier: str) -> None:
        if identifier in visiting:
            _fail("$.actions", f"dependency cycle includes {identifier!r}")
        if identifier in visited:
            return
        visiting.add(identifier)
        for dependency in actions[identifier]:
            if dependency not in actions:
                _fail("$.actions", f"{identifier!r} depends on unknown action {dependency!r}")
            visit(dependency)
        visiting.remove(identifier)
        visited.add(identifier)

    for identifier in actions:
        visit(identifier)


def _validate_references(references: list[tuple[str, str]], ids: Mapping[str, str]) -> None:
    for path, target in references:
        if target not in ids:
            _fail(path, f"references unknown id {target!r}")


def validate_manifest(payload: Mapping[str, Any], *, verify_digest: bool = True) -> None:
    """Validate syntax, references, bounds, and non-upgrade invariants.

    Validation says that the workflow record is internally well-formed. It does not
    verify any referenced artifact, native result, hypothesis, or VSTD receipt.
    """

    root = _mapping(payload, "$")
    _reject_floats(root)
    _exact_keys(
        root,
        "$",
        required={
            "profile",
            "experiment",
            "hypotheses",
            "preregistration",
            "artifacts",
            "budgets",
            "actions",
            "observations",
            "interventions",
            "native_results",
            "adaptations",
            "amendments",
            "challenges",
            "horizons",
            "publication",
            "workflow_events",
            "manifest_digest",
        },
    )

    profile = _mapping(root["profile"], "$.profile")
    _exact_keys(profile, "$.profile", required={"id", "version", "status"})
    if profile["id"] != PROFILE_ID or profile["version"] != PROFILE_VERSION:
        _fail("$.profile", "unsupported profile identifier or version")
    if profile["status"] != PROFILE_STATUS:
        _fail("$.profile.status", f"must be {PROFILE_STATUS}")

    ids: dict[str, str] = {}
    references: list[tuple[str, str]] = []

    experiment = _mapping(root["experiment"], "$.experiment")
    _exact_keys(
        experiment,
        "$.experiment",
        required={"id", "title", "question", "state", "started_at"},
    )
    _register_id(experiment["id"], "$.experiment.id", ids)
    _string(experiment["title"], "$.experiment.title")
    _string(experiment["question"], "$.experiment.question")
    _enum(experiment["state"], EXPERIMENT_STATES, "$.experiment.state")
    _string(experiment["started_at"], "$.experiment.started_at", nullable=True)

    hypotheses = _sequence(root["hypotheses"], "$.hypotheses")
    if not hypotheses:
        _fail("$.hypotheses", "must declare at least one falsifiable hypothesis")
    for index, value in enumerate(hypotheses):
        path = f"$.hypotheses[{index}]"
        item = _mapping(value, path)
        _exact_keys(
            item,
            path,
            required={"id", "statement", "falsification_condition", "state"},
        )
        _register_id(item["id"], f"{path}.id", ids)
        _string(item["statement"], f"{path}.statement")
        _string(item["falsification_condition"], f"{path}.falsification_condition")
        _enum(item["state"], HYPOTHESIS_STATES, f"{path}.state")

    preregistration = _mapping(root["preregistration"], "$.preregistration")
    _exact_keys(
        preregistration,
        "$.preregistration",
        required={"state", "recorded_at", "artifact_id", "limitations"},
    )
    preregistration_state = _enum(
        preregistration["state"], PREREGISTRATION_STATES, "$.preregistration.state"
    )
    _string(preregistration["recorded_at"], "$.preregistration.recorded_at", nullable=True)
    preregistration_artifact = _string(
        preregistration["artifact_id"], "$.preregistration.artifact_id", nullable=True
    )
    _string_list(preregistration["limitations"], "$.preregistration.limitations")
    if preregistration_state in {"FROZEN", "AMENDED"} and preregistration_artifact is None:
        _fail("$.preregistration", "FROZEN or AMENDED requires a bound artifact")
    if preregistration_artifact is not None:
        references.append(("$.preregistration.artifact_id", preregistration_artifact))

    artifact_ids = {
        _validate_artifact(value, index, ids)
        for index, value in enumerate(_sequence(root["artifacts"], "$.artifacts"))
    }

    budget_ids: set[str] = set()
    for index, value in enumerate(_sequence(root["budgets"], "$.budgets")):
        path = f"$.budgets[{index}]"
        item = _mapping(value, path)
        _exact_keys(
            item,
            path,
            required={"id", "resource", "limit", "consumed", "unit", "scope"},
        )
        identifier = _register_id(item["id"], f"{path}.id", ids)
        budget_ids.add(identifier)
        _string(item["resource"], f"{path}.resource")
        limit = _nonnegative_integer(item["limit"], f"{path}.limit")
        consumed = _nonnegative_integer(item["consumed"], f"{path}.consumed")
        if consumed > limit:
            _fail(path, "consumed work exceeds the declared limit")
        _string(item["unit"], f"{path}.unit")
        _string(item["scope"], f"{path}.scope")

    action_dependencies: dict[str, list[str]] = {}
    action_ids: set[str] = set()
    for index, value in enumerate(_sequence(root["actions"], "$.actions")):
        path = f"$.actions[{index}]"
        item = _mapping(value, path)
        _exact_keys(
            item,
            path,
            required={
                "id",
                "kind",
                "target",
                "state",
                "priority",
                "selected_because",
                "selection_evidence_ids",
                "alternatives_considered",
                "budget_ids",
                "depends_on",
                "triggered_by",
                "expected_artifact_effect",
                "substrate",
                "native_result_ids",
                "produced_artifact_ids",
            },
        )
        identifier = _register_id(item["id"], f"{path}.id", ids)
        action_ids.add(identifier)
        _string(item["kind"], f"{path}.kind")
        _string(item["target"], f"{path}.target")
        _enum(item["state"], ACTION_STATES, f"{path}.state")
        priority = _nonnegative_integer(item["priority"], f"{path}.priority")
        if priority == 0:
            _fail(f"{path}.priority", "must be at least 1")
        _string(item["selected_because"], f"{path}.selected_because")
        _string(item["expected_artifact_effect"], f"{path}.expected_artifact_effect")
        _validate_substrate(item["substrate"], f"{path}.substrate")
        selection_evidence = _string_list(
            item["selection_evidence_ids"], f"{path}.selection_evidence_ids"
        )
        _string_list(item["alternatives_considered"], f"{path}.alternatives_considered")
        action_budgets = _string_list(item["budget_ids"], f"{path}.budget_ids")
        if not action_budgets:
            _fail(f"{path}.budget_ids", "every selected action must bind at least one budget")
        unknown_budgets = sorted(set(action_budgets) - budget_ids)
        if unknown_budgets:
            _fail(f"{path}.budget_ids", f"unknown budgets: {', '.join(unknown_budgets)}")
        dependencies = _string_list(item["depends_on"], f"{path}.depends_on")
        action_dependencies[identifier] = dependencies
        for field in ("triggered_by", "native_result_ids", "produced_artifact_ids"):
            values = _string_list(item[field], f"{path}.{field}")
            references.extend((f"{path}.{field}", target) for target in values)
        references.extend(
            (f"{path}.selection_evidence_ids", target) for target in selection_evidence
        )

    observation_ids: set[str] = set()
    for index, value in enumerate(_sequence(root["observations"], "$.observations")):
        path = f"$.observations[{index}]"
        item = _mapping(value, path)
        _exact_keys(
            item,
            path,
            required={
                "id",
                "action_id",
                "recorded_at",
                "statement",
                "status",
                "evidence_artifact_ids",
                "limitations",
            },
        )
        identifier = _register_id(item["id"], f"{path}.id", ids)
        observation_ids.add(identifier)
        action_id = _string(item["action_id"], f"{path}.action_id")
        assert action_id is not None
        references.append((f"{path}.action_id", action_id))
        _string(item["recorded_at"], f"{path}.recorded_at")
        _string(item["statement"], f"{path}.statement")
        _enum(item["status"], OBSERVATION_STATES, f"{path}.status")
        evidence_ids = _string_list(
            item["evidence_artifact_ids"], f"{path}.evidence_artifact_ids"
        )
        references.extend((f"{path}.evidence_artifact_ids", target) for target in evidence_ids)
        _string_list(item["limitations"], f"{path}.limitations")

    for index, value in enumerate(_sequence(root["interventions"], "$.interventions")):
        path = f"$.interventions[{index}]"
        item = _mapping(value, path)
        _exact_keys(
            item,
            path,
            required={
                "id",
                "action_id",
                "description",
                "applied_at",
                "target_artifact_ids",
                "produced_artifact_ids",
            },
        )
        _register_id(item["id"], f"{path}.id", ids)
        action_id = _string(item["action_id"], f"{path}.action_id")
        assert action_id is not None
        references.append((f"{path}.action_id", action_id))
        _string(item["description"], f"{path}.description")
        _string(item["applied_at"], f"{path}.applied_at")
        for field in ("target_artifact_ids", "produced_artifact_ids"):
            values = _string_list(item[field], f"{path}.{field}")
            references.extend((f"{path}.{field}", target) for target in values)

    native_result_ids: set[str] = set()
    for index, value in enumerate(_sequence(root["native_results"], "$.native_results")):
        path = f"$.native_results[{index}]"
        item = _mapping(value, path)
        _exact_keys(
            item,
            path,
            required={"id", "action_id", "verifier", "native_status", "result_artifact_id", "mapping"},
        )
        identifier = _register_id(item["id"], f"{path}.id", ids)
        native_result_ids.add(identifier)
        action_id = _string(item["action_id"], f"{path}.action_id")
        assert action_id is not None
        references.append((f"{path}.action_id", action_id))
        _validate_substrate(item["verifier"], f"{path}.verifier")
        _string(item["native_status"], f"{path}.native_status")
        result_artifact = _string(
            item["result_artifact_id"], f"{path}.result_artifact_id", nullable=True
        )
        if result_artifact is not None:
            references.append((f"{path}.result_artifact_id", result_artifact))
        _validate_mapping(item["mapping"], f"{path}.mapping")
        mapped_receipt = item["mapping"]["receipt_artifact_id"]
        if mapped_receipt is not None:
            references.append((f"{path}.mapping.receipt_artifact_id", mapped_receipt))

    for index, value in enumerate(_sequence(root["adaptations"], "$.adaptations")):
        path = f"$.adaptations[{index}]"
        item = _mapping(value, path)
        _exact_keys(
            item,
            path,
            required={"id", "trigger_ids", "decision", "reason", "action_ids", "artifact_ids"},
        )
        _register_id(item["id"], f"{path}.id", ids)
        _string(item["decision"], f"{path}.decision")
        _string(item["reason"], f"{path}.reason")
        for field in ("trigger_ids", "action_ids", "artifact_ids"):
            values = _string_list(item[field], f"{path}.{field}")
            references.extend((f"{path}.{field}", target) for target in values)

    for collection_name, required, enum_field, allowed in (
        (
            "amendments",
            {"id", "recorded_at", "reason", "supersedes", "artifact_id"},
            None,
            None,
        ),
        (
            "challenges",
            {"id", "target_id", "state", "statement", "evidence_artifact_ids"},
            "state",
            CHALLENGE_STATES,
        ),
        (
            "horizons",
            {"id", "status", "description", "reason"},
            "status",
            HORIZON_STATES,
        ),
    ):
        for index, value in enumerate(_sequence(root[collection_name], f"$.{collection_name}")):
            path = f"$.{collection_name}[{index}]"
            item = _mapping(value, path)
            _exact_keys(item, path, required=required)
            _register_id(item["id"], f"{path}.id", ids)
            if enum_field is not None and allowed is not None:
                _enum(item[enum_field], allowed, f"{path}.{enum_field}")
            if collection_name == "amendments":
                _string(item["recorded_at"], f"{path}.recorded_at")
                _string(item["reason"], f"{path}.reason")
                supersedes = _string_list(item["supersedes"], f"{path}.supersedes")
                references.extend((f"{path}.supersedes", target) for target in supersedes)
                artifact_id = _string(item["artifact_id"], f"{path}.artifact_id")
                assert artifact_id is not None
                references.append((f"{path}.artifact_id", artifact_id))
            elif collection_name == "challenges":
                target_id = _string(item["target_id"], f"{path}.target_id")
                assert target_id is not None
                references.append((f"{path}.target_id", target_id))
                _string(item["statement"], f"{path}.statement")
                evidence_ids = _string_list(
                    item["evidence_artifact_ids"], f"{path}.evidence_artifact_ids"
                )
                references.extend(
                    (f"{path}.evidence_artifact_ids", target) for target in evidence_ids
                )
            else:
                _string(item["description"], f"{path}.description")
                _string(item["reason"], f"{path}.reason")

    publication = _mapping(root["publication"], "$.publication")
    _exact_keys(publication, "$.publication", required={"state", "artifact_ids"})
    _enum(publication["state"], PUBLICATION_STATES, "$.publication.state")
    publication_artifacts = _string_list(publication["artifact_ids"], "$.publication.artifact_ids")
    references.extend(("$.publication.artifact_ids", target) for target in publication_artifacts)

    event_ids: set[str] = set()
    for index, value in enumerate(_sequence(root["workflow_events"], "$.workflow_events")):
        path = f"$.workflow_events[{index}]"
        item = _mapping(value, path)
        _exact_keys(
            item,
            path,
            required={
                "id",
                "kind",
                "recorded_at",
                "source",
                "native_state",
                "verification_effect",
                "details",
            },
        )
        identifier = _register_id(item["id"], f"{path}.id", ids)
        event_ids.add(identifier)
        _enum(item["kind"], PLATFORM_EVENT_KINDS, f"{path}.kind")
        _string(item["recorded_at"], f"{path}.recorded_at")
        _string(item["native_state"], f"{path}.native_state")
        if item["verification_effect"] != "NONE":
            _fail(f"{path}.verification_effect", "platform events cannot grant a verification verdict")
        source = _mapping(item["source"], f"{path}.source")
        _exact_keys(source, f"{path}.source", required={"platform", "repository", "coordinate"})
        for field in ("platform", "repository", "coordinate"):
            _string(source[field], f"{path}.source.{field}")
        details = _mapping(item["details"], f"{path}.details")
        canonical_bytes(details)

    _validate_action_graph(action_dependencies)
    _validate_references(references, ids)

    for index, action in enumerate(root["actions"]):
        unknown_results = sorted(set(action["native_result_ids"]) - native_result_ids)
        if unknown_results:
            _fail(
                f"$.actions[{index}].native_result_ids",
                f"not native results: {', '.join(unknown_results)}",
            )
        unknown_artifacts = sorted(set(action["produced_artifact_ids"]) - artifact_ids)
        if unknown_artifacts:
            _fail(
                f"$.actions[{index}].produced_artifact_ids",
                f"not artifacts: {', '.join(unknown_artifacts)}",
            )
    for index, result in enumerate(root["native_results"]):
        if result["action_id"] not in action_ids:
            _fail(f"$.native_results[{index}].action_id", "must reference an action")
    for index, observation in enumerate(root["observations"]):
        if observation["action_id"] not in action_ids:
            _fail(f"$.observations[{index}].action_id", "must reference an action")
    for index, intervention in enumerate(root["interventions"]):
        if intervention["action_id"] not in action_ids:
            _fail(f"$.interventions[{index}].action_id", "must reference an action")

    digest = _string(root["manifest_digest"], "$.manifest_digest")
    assert digest is not None
    if not _DIGEST_RE.fullmatch(digest):
        _fail("$.manifest_digest", "must be lowercase sha256:<64 hex>")
    if verify_digest and digest != manifest_digest(root):
        _fail("$.manifest_digest", "does not match the canonical stable payload")


def load_manifest(path: Path) -> dict[str, Any]:
    """Load and validate a UTF-8 JSON workflow manifest."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise WorkflowProfileError(f"cannot load {path.name}: {exc}") from exc
    if not isinstance(payload, dict):
        raise WorkflowProfileError("workflow manifest root must be an object")
    validate_manifest(payload)
    return payload


def verify_repo_artifacts(payload: Mapping[str, Any], repository_root: Path) -> None:
    """Verify every repository-relative artifact against its bound SHA-256 digest.

    Other locator schemes require their own retriever and trust policy. Skipping those
    schemes here does not verify them and does not change any recorded result.
    """

    validate_manifest(payload)
    root = repository_root.resolve()
    for index, artifact in enumerate(payload["artifacts"]):
        locator = artifact["locator"]
        if not locator.startswith("repo:"):
            continue
        relative = PurePosixPath(locator.removeprefix("repo:"))
        candidate = root.joinpath(*relative.parts).resolve()
        try:
            candidate.relative_to(root)
        except ValueError as exc:
            _fail(f"$.artifacts[{index}].locator", "resolves outside the repository")
            raise AssertionError("unreachable") from exc
        if not candidate.is_file():
            _fail(f"$.artifacts[{index}].locator", "bound repository artifact is missing")
        actual = "sha256:" + hashlib.sha256(candidate.read_bytes()).hexdigest()
        if actual != artifact["digest"]:
            _fail(
                f"$.artifacts[{index}].digest",
                f"does not match {locator}; expected {artifact['digest']}, observed {actual}",
            )
