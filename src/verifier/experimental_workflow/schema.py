"""JSON Schema generator for the experimental workflow interchange profile."""

from __future__ import annotations

from typing import Any

from .profile import PROFILE_ID, PROFILE_STATUS, PROFILE_VERSION


def _object(properties: dict[str, Any], required: tuple[str, ...] | None = None) -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": properties,
        "required": list(required or properties),
    }


def _array(items: dict[str, Any], *, minimum: int = 0) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": "array", "items": items}
    if minimum:
        schema["minItems"] = minimum
    return schema


def workflow_manifest_schema() -> dict[str, Any]:
    """Return the complete draft-2020-12 interchange schema."""

    nonempty = {"type": "string", "minLength": 1}
    nullable_nonempty = {"type": ["string", "null"], "minLength": 1}
    identifier = {"type": "string", "minLength": 1, "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]*$"}
    identifier_list = _array(identifier)
    digest = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
    substrate = _object(
        {
            "kind": nonempty,
            "name": nonempty,
            "version": nonempty,
            "coordinate": nonempty,
        }
    )
    artifact = _object(
        {
            "id": identifier,
            "role": nonempty,
            "media_type": nonempty,
            "digest": digest,
            "locator": {
                "type": "string",
                "pattern": "^(artifact:|git:|https://|repo:|urn:).+",
            },
        }
    )
    mapping = _object(
        {
            "status": {"enum": ["NOT_EVALUATED", "MAPPED"]},
            "vstd_verdict": {
                "type": ["string", "null"],
                "enum": ["PASS", "FAIL", "UNKNOWN", "CONFLICTED", "REJECTED", None],
            },
            "mapping_profile": nullable_nonempty,
            "receipt_artifact_id": nullable_nonempty,
            "reason": nonempty,
        }
    )
    platform_event = _object(
        {
            "id": identifier,
            "kind": {
                "enum": [
                    "PLATFORM_ISSUE",
                    "PLATFORM_COMMIT",
                    "PLATFORM_WORKFLOW_RUN",
                    "PLATFORM_ARTIFACT",
                    "PLATFORM_PULL_REQUEST",
                ]
            },
            "recorded_at": nonempty,
            "source": _object(
                {"platform": nonempty, "repository": nonempty, "coordinate": nonempty}
            ),
            "native_state": nonempty,
            "verification_effect": {"const": "NONE"},
            "details": {"type": "object"},
        }
    )

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://timelordraps.github.io/verifier/profiles/experimental-workflow.schema.json",
        "title": "VSTD experimental workflow profile 0.1",
        "description": (
            "Non-normative, verdict-neutral interchange for bounded experimental work. "
            "Schema validity does not verify referenced evidence or native results."
        ),
        **_object(
            {
                "profile": _object(
                    {
                        "id": {"const": PROFILE_ID},
                        "version": {"const": PROFILE_VERSION},
                        "status": {"const": PROFILE_STATUS},
                    }
                ),
                "experiment": _object(
                    {
                        "id": identifier,
                        "title": nonempty,
                        "question": nonempty,
                        "state": {
                            "enum": [
                                "DRAFT",
                                "PREREGISTERED",
                                "RUNNING",
                                "BLOCKED",
                                "COMPLETED",
                                "ABANDONED",
                            ]
                        },
                        "started_at": nullable_nonempty,
                    }
                ),
                "hypotheses": _array(
                    _object(
                        {
                            "id": identifier,
                            "statement": nonempty,
                            "falsification_condition": nonempty,
                            "state": {
                                "enum": ["OPEN", "SUPPORTED", "REFUTED", "UNKNOWN", "CONFLICTED"]
                            },
                        }
                    ),
                    minimum=1,
                ),
                "preregistration": _object(
                    {
                        "state": {"enum": ["NONE", "DRAFT", "FROZEN", "AMENDED"]},
                        "recorded_at": nullable_nonempty,
                        "artifact_id": nullable_nonempty,
                        "limitations": _array(nonempty),
                    }
                ),
                "artifacts": _array(artifact),
                "budgets": _array(
                    _object(
                        {
                            "id": identifier,
                            "resource": nonempty,
                            "limit": {"type": "integer", "minimum": 0},
                            "consumed": {"type": "integer", "minimum": 0},
                            "unit": nonempty,
                            "scope": nonempty,
                        }
                    )
                ),
                "actions": _array(
                    _object(
                        {
                            "id": identifier,
                            "kind": nonempty,
                            "target": nonempty,
                            "state": {
                                "enum": ["PLANNED", "RUNNING", "BLOCKED", "COMPLETED", "ABANDONED"]
                            },
                            "priority": {"type": "integer", "minimum": 1},
                            "selected_because": nonempty,
                            "selection_evidence_ids": identifier_list,
                            "alternatives_considered": _array(nonempty),
                            "budget_ids": _array(identifier, minimum=1),
                            "depends_on": identifier_list,
                            "triggered_by": identifier_list,
                            "expected_artifact_effect": nonempty,
                            "substrate": substrate,
                            "native_result_ids": identifier_list,
                            "produced_artifact_ids": identifier_list,
                        }
                    )
                ),
                "observations": _array(
                    _object(
                        {
                            "id": identifier,
                            "action_id": identifier,
                            "recorded_at": nonempty,
                            "statement": nonempty,
                            "status": {"enum": ["OBSERVED", "UNKNOWN", "CONFLICTED"]},
                            "evidence_artifact_ids": identifier_list,
                            "limitations": _array(nonempty),
                        }
                    )
                ),
                "interventions": _array(
                    _object(
                        {
                            "id": identifier,
                            "action_id": identifier,
                            "description": nonempty,
                            "applied_at": nonempty,
                            "target_artifact_ids": identifier_list,
                            "produced_artifact_ids": identifier_list,
                        }
                    )
                ),
                "native_results": _array(
                    _object(
                        {
                            "id": identifier,
                            "action_id": identifier,
                            "verifier": substrate,
                            "native_status": nonempty,
                            "result_artifact_id": nullable_nonempty,
                            "mapping": mapping,
                        }
                    )
                ),
                "adaptations": _array(
                    _object(
                        {
                            "id": identifier,
                            "trigger_ids": identifier_list,
                            "decision": nonempty,
                            "reason": nonempty,
                            "action_ids": identifier_list,
                            "artifact_ids": identifier_list,
                        }
                    )
                ),
                "amendments": _array(
                    _object(
                        {
                            "id": identifier,
                            "recorded_at": nonempty,
                            "reason": nonempty,
                            "supersedes": identifier_list,
                            "artifact_id": identifier,
                        }
                    )
                ),
                "challenges": _array(
                    _object(
                        {
                            "id": identifier,
                            "target_id": identifier,
                            "state": {"enum": ["OPEN", "RESOLVED", "REJECTED"]},
                            "statement": nonempty,
                            "evidence_artifact_ids": identifier_list,
                        }
                    )
                ),
                "horizons": _array(
                    _object(
                        {
                            "id": identifier,
                            "status": {"enum": ["UNKNOWN", "CONFLICTED", "BLOCKED", "OUT_OF_SCOPE"]},
                            "description": nonempty,
                            "reason": nonempty,
                        }
                    )
                ),
                "publication": _object(
                    {
                        "state": {
                            "enum": ["PRIVATE", "INTERNAL", "CANDIDATE", "PUBLISHED", "RETRACTED"]
                        },
                        "artifact_ids": identifier_list,
                    }
                ),
                "workflow_events": _array(platform_event),
                "manifest_digest": digest,
            }
        ),
    }
