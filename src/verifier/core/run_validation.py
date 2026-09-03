"""Terminology: JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256); Verifier Standard (VSTD).

Fail-closed structural and canonical-digest validation for generic-run receipts.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any, Mapping

from verifier.core.receipt import (
    StrictJsonError,
    compute_canonical_digest,
    strict_json_loads,
)
from verifier.core.run_support import (
    RUN_RECEIPT_KIND,
    RUN_SCHEMA_VERSION,
    DeterminismDeclaration,
    RunOutcome,
)


_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def _rebuild_stable_payload_from_dict(data: Mapping[str, Any]) -> dict[str, Any]:
    src = data.get("source_state", {})
    payload = {
        "schema_version": data.get("schema_version"),
        "receipt_kind": data.get("receipt_kind"),
        "receipt_id": data.get("receipt_id"),
        "claim_title": data.get("claim_title"),
        "claim_statement": data.get("claim_statement"),
        "claim_scope": data.get("claim_scope"),
        "claim_limitations": data.get("claim_limitations"),
        "falsification_condition": data.get("falsification_condition"),
        "source_state_stable": {
            "target_name": src.get("target_name"),
            "portable_repository_id": src.get("portable_repository_id"),
            "git_commit_sha": src.get("git", {}).get("commit_sha"),
            "git_branch": src.get("git", {}).get("branch"),
            "git_is_dirty": src.get("git", {}).get("is_dirty"),
            "git_dirty_files": src.get("git", {}).get("dirty_files", []),
            "source_file_hashes": src.get("source_file_hashes", {}),
            "runtime_python_version": src.get("runtime", {}).get("python_version"),
        },
        "inputs": data.get("inputs", []),
        "outputs": data.get("outputs", []),
        "execution_stable": {
            "command": data.get("execution", {}).get("command"),
            "cwd": data.get("execution", {}).get("cwd"),
            "exit_code": data.get("execution", {}).get("exit_code"),
            "outcome": data.get("execution", {}).get("outcome"),
            "python_version": data.get("execution", {}).get("python_version"),
            "platform_system": data.get("execution", {}).get("platform_system"),
            "determinism_declared": data.get("execution", {}).get("determinism_declared"),
            "seed_declared": data.get("execution", {}).get("seed_declared"),
            "stdout_sha256": data.get("execution", {}).get("stdout_sha256"),
            "stderr_sha256": data.get("execution", {}).get("stderr_sha256"),
        },
        "claims": data.get("claims", {}),
        "provenance_linkage": data.get("provenance_linkage", []),
        "reproducibility": data.get("reproducibility", {}),
        "assessment_context": data.get("assessment_context", {}),
    }
    return payload


def _missing_fields(
    value: object,
    label: str,
    required: tuple[str, ...],
    errors: list[str],
) -> Mapping[str, Any] | None:
    if not isinstance(value, Mapping):
        errors.append(f"{label} must be an object")
        return None
    missing = [name for name in required if name not in value]
    if missing:
        errors.append(f"{label} missing required fields: {', '.join(missing)}")
    return value


def _unexpected_fields(
    value: Mapping[str, Any], label: str, allowed: tuple[str, ...], errors: list[str]
) -> None:
    unexpected = sorted(set(value) - set(allowed))
    if unexpected:
        errors.append(f"{label} has unexpected fields: {', '.join(unexpected)}")


def _run_payload_errors(data: Mapping[str, Any]) -> list[str]:
    """Fail-closed structural checks for the generic-run wire profile."""

    errors: list[str] = []
    required = (
        "schema_version",
        "receipt_kind",
        "receipt_id",
        "canonical_digest",
        "claim_title",
        "claim_statement",
        "claim_scope",
        "claim_limitations",
        "falsification_condition",
        "source_state",
        "inputs",
        "outputs",
        "execution",
        "claims",
        "provenance_linkage",
        "reproducibility",
        "assessment_context",
    )
    _missing_fields(data, "receipt", required, errors)
    _unexpected_fields(data, "receipt", required, errors)
    if data.get("schema_version") != RUN_SCHEMA_VERSION:
        errors.append(f"schema_version must be {RUN_SCHEMA_VERSION}")
    if data.get("receipt_kind") != RUN_RECEIPT_KIND:
        errors.append(f"receipt_kind must be {RUN_RECEIPT_KIND}")
    for name in (
        "receipt_id",
        "claim_title",
        "claim_statement",
        "claim_scope",
        "falsification_condition",
    ):
        if not isinstance(data.get(name), str):
            errors.append(f"{name} must be a string")
    digest = data.get("canonical_digest")
    if not isinstance(digest, str) or not _SHA256_PATTERN.fullmatch(digest):
        errors.append("canonical_digest must be 64 lowercase hexadecimal characters")
    if not isinstance(data.get("claim_limitations"), list) or not all(
        isinstance(item, str) for item in data.get("claim_limitations", [])
    ):
        errors.append("claim_limitations must be an array of strings")

    source = _missing_fields(
        data.get("source_state"),
        "source_state",
        (
            "target_name",
            "portable_repository_id",
            "local_repository_path",
            "git",
            "runtime",
            "captured_at_utc",
            "command_executed",
            "source_file_hashes",
        ),
        errors,
    )
    if source is not None:
        source_fields = (
            "target_name",
            "portable_repository_id",
            "local_repository_path",
            "git",
            "runtime",
            "captured_at_utc",
            "command_executed",
            "source_file_hashes",
        )
        _unexpected_fields(source, "source_state", source_fields, errors)
        for name in (
            "target_name",
            "portable_repository_id",
            "local_repository_path",
            "captured_at_utc",
            "command_executed",
        ):
            if not isinstance(source.get(name), str):
                errors.append(f"source_state.{name} must be a string")
        source_hashes = source.get("source_file_hashes")
        if not isinstance(source_hashes, Mapping) or not all(
            isinstance(path, str)
            and isinstance(digest, str)
            and bool(_SHA256_PATTERN.fullmatch(digest))
            for path, digest in (
                source_hashes.items() if isinstance(source_hashes, Mapping) else ()
            )
        ):
            errors.append("source_state.source_file_hashes must map paths to SHA-256 digests")
        git = _missing_fields(
            source.get("git"),
            "source_state.git",
            ("commit_sha", "branch", "is_dirty"),
            errors,
        )
        if git is not None:
            git_fields = (
                "commit_sha",
                "branch",
                "is_dirty",
                "dirty_files",
                "untracked_files",
                "remote_origin",
            )
            _unexpected_fields(git, "source_state.git", git_fields, errors)
            if not isinstance(git.get("commit_sha"), str) or not isinstance(
                git.get("branch"), str
            ):
                errors.append("source_state.git commit_sha and branch must be strings")
            if type(git.get("is_dirty")) is not bool:
                errors.append("source_state.git.is_dirty must be a boolean")
            for name in ("dirty_files", "untracked_files"):
                if name in git and (
                    not isinstance(git.get(name), list)
                    or not all(isinstance(item, str) for item in git.get(name, []))
                ):
                    errors.append(f"source_state.git.{name} must be an array of strings")
            if "remote_origin" in git and not isinstance(git.get("remote_origin"), str):
                errors.append("source_state.git.remote_origin must be a string")
        runtime = _missing_fields(
            source.get("runtime"),
            "source_state.runtime",
            ("python_version", "platform_system"),
            errors,
        )
        if runtime is not None and any(
            not isinstance(runtime.get(name), str)
            for name in ("python_version", "platform_system")
        ):
            errors.append("source_state.runtime required fields must be strings")
        if runtime is not None:
            runtime_fields = (
                "python_version",
                "python_implementation",
                "platform_system",
                "platform_release",
                "platform_machine",
                "hostname_masked",
            )
            _unexpected_fields(runtime, "source_state.runtime", runtime_fields, errors)
            for name in runtime_fields:
                if name in runtime and not isinstance(runtime.get(name), str):
                    errors.append(f"source_state.runtime.{name} must be a string")

    for collection_name in ("inputs", "outputs"):
        collection = data.get(collection_name)
        if not isinstance(collection, list):
            errors.append(f"{collection_name} must be an array")
            continue
        for index, raw in enumerate(collection):
            label = f"{collection_name}[{index}]"
            item = _missing_fields(raw, label, ("path", "role", "present", "sha256", "byte_size"), errors)
            if item is None:
                continue
            _unexpected_fields(
                item, label, ("path", "role", "present", "sha256", "byte_size"), errors
            )
            if not isinstance(item.get("path"), str) or not isinstance(item.get("role"), str):
                errors.append(f"{label}.path and .role must be strings")
            if type(item.get("present")) is not bool:
                errors.append(f"{label}.present must be a boolean")
            artifact_digest = item.get("sha256")
            if artifact_digest is not None and (
                not isinstance(artifact_digest, str)
                or not _SHA256_PATTERN.fullmatch(artifact_digest)
            ):
                errors.append(f"{label}.sha256 must be null or 64 lowercase hexadecimal characters")
            byte_size = item.get("byte_size")
            if byte_size is not None and (type(byte_size) is not int or byte_size < 0):
                errors.append(f"{label}.byte_size must be null or a non-negative integer")
            if item.get("present") is True and (artifact_digest is None or byte_size is None):
                errors.append(f"{label} is present but lacks a digest or byte size")

    execution = _missing_fields(
        data.get("execution"),
        "execution",
        (
            "command",
            "cwd",
            "started_at_utc",
            "ended_at_utc",
            "elapsed_ms",
            "exit_code",
            "outcome",
            "python_version",
            "platform_system",
            "determinism_declared",
            "seed_declared",
            "stdout_sha256",
            "stderr_sha256",
            "stdout_snippet",
            "stderr_snippet",
        ),
        errors,
    )
    if execution is not None:
        _unexpected_fields(
            execution,
            "execution",
            (
                "command",
                "cwd",
                "started_at_utc",
                "ended_at_utc",
                "elapsed_ms",
                "exit_code",
                "outcome",
                "python_version",
                "platform_system",
                "determinism_declared",
                "seed_declared",
                "stdout_sha256",
                "stderr_sha256",
                "stdout_snippet",
                "stderr_snippet",
            ),
            errors,
        )
        command = execution.get("command")
        if not isinstance(command, list) or not command or not all(isinstance(arg, str) for arg in command):
            errors.append("execution.command must be a non-empty array of strings")
        if execution.get("outcome") not in {member.value for member in RunOutcome}:
            errors.append("execution.outcome is not a recognized run outcome")
        if execution.get("determinism_declared") not in {
            member.value for member in DeterminismDeclaration
        }:
            errors.append("execution.determinism_declared is not recognized")
        for name in (
            "cwd",
            "started_at_utc",
            "ended_at_utc",
            "python_version",
            "platform_system",
            "stdout_snippet",
            "stderr_snippet",
        ):
            if not isinstance(execution.get(name), str):
                errors.append(f"execution.{name} must be a string")
        elapsed = execution.get("elapsed_ms")
        if isinstance(elapsed, bool) or not isinstance(elapsed, (int, float)) or elapsed < 0:
            errors.append("execution.elapsed_ms must be a non-negative number")
        exit_code = execution.get("exit_code")
        if exit_code is not None and (type(exit_code) is not int):
            errors.append("execution.exit_code must be an integer or null")
        seed = execution.get("seed_declared")
        if seed is not None and not isinstance(seed, str):
            errors.append("execution.seed_declared must be a string or null")
        for name in ("stdout_sha256", "stderr_sha256"):
            value = execution.get(name)
            if not isinstance(value, str) or not _SHA256_PATTERN.fullmatch(value):
                errors.append(f"execution.{name} must be 64 lowercase hexadecimal characters")

    claims = _missing_fields(
        data.get("claims"),
        "claims",
        (
            "execution_completed",
            "output_digests_recorded",
            "all_declared_artifacts_present",
            "evaluator_claims",
            "external_evaluation",
        ),
        errors,
    )
    if claims is not None:
        _unexpected_fields(
            claims,
            "claims",
            (
                "execution_completed",
                "output_digests_recorded",
                "all_declared_artifacts_present",
                "evaluator_claims",
                "external_evaluation",
            ),
            errors,
        )
        for name in ("execution_completed", "output_digests_recorded"):
            if type(claims.get(name)) is not bool:
                errors.append(f"claims.{name} must be a boolean")
        if claims.get("all_declared_artifacts_present") is not None and type(
            claims.get("all_declared_artifacts_present")
        ) is not bool:
            errors.append("claims.all_declared_artifacts_present must be a boolean or null")
        evaluator_claims = claims.get("evaluator_claims")
        if not isinstance(evaluator_claims, list):
            errors.append("claims.evaluator_claims must be an array")
        else:
            evaluator_fields = (
                "evaluator_name",
                "metric_name",
                "value",
                "computed_by",
                "verified_independently",
            )
            for index, raw in enumerate(evaluator_claims):
                label = f"claims.evaluator_claims[{index}]"
                evaluator = _missing_fields(raw, label, evaluator_fields, errors)
                if evaluator is None:
                    continue
                _unexpected_fields(evaluator, label, evaluator_fields, errors)
                if not isinstance(evaluator.get("evaluator_name"), str) or not isinstance(
                    evaluator.get("metric_name"), str
                ):
                    errors.append(f"{label} names must be strings")
                if evaluator.get("computed_by") not in {
                    "bound_output_extraction",
                    "declared_by_manifest_author",
                }:
                    errors.append(f"{label}.computed_by is not recognized")
                if evaluator.get("verified_independently") is not False:
                    errors.append(
                        f"{label}.verified_independently must be false for this runtime"
                    )
        external = claims.get("external_evaluation")
        if external is not None and not isinstance(external, Mapping):
            errors.append("claims.external_evaluation must be an object or null")
        elif isinstance(external, Mapping):
            external_fields = (
                "source",
                "description",
                "reported_value",
                "evidence_kind",
                "evidence_ref",
                "attested",
            )
            _missing_fields(external, "claims.external_evaluation", external_fields, errors)
            _unexpected_fields(
                external, "claims.external_evaluation", external_fields, errors
            )
            for name in ("source", "description", "evidence_kind"):
                if not isinstance(external.get(name), str):
                    errors.append(f"claims.external_evaluation.{name} must be a string")
            if external.get("evidence_ref") is not None and not isinstance(
                external.get("evidence_ref"), str
            ):
                errors.append("claims.external_evaluation.evidence_ref must be a string or null")
            if external.get("attested") is not False:
                errors.append("claims.external_evaluation.attested must be false for this runtime")

    linkage = data.get("provenance_linkage")
    if not isinstance(linkage, list):
        errors.append("provenance_linkage must be an array")
    else:
        linkage_fields = (
            "dataset_receipt_path",
            "artifact_id",
            "found_in_hypergraph",
            "ancestor_count",
            "ancestor_ids",
        )
        for index, raw in enumerate(linkage):
            label = f"provenance_linkage[{index}]"
            item = _missing_fields(raw, label, linkage_fields, errors)
            if item is None:
                continue
            _unexpected_fields(item, label, linkage_fields, errors)
            if not isinstance(item.get("dataset_receipt_path"), str) or not isinstance(
                item.get("artifact_id"), str
            ):
                errors.append(f"{label} paths and identifiers must be strings")
            if type(item.get("found_in_hypergraph")) is not bool:
                errors.append(f"{label}.found_in_hypergraph must be a boolean")
            count = item.get("ancestor_count")
            if count is not None and (type(count) is not int or count < 0):
                errors.append(f"{label}.ancestor_count must be a non-negative integer or null")
            if not isinstance(item.get("ancestor_ids"), list) or not all(
                isinstance(ancestor, str) for ancestor in item.get("ancestor_ids", [])
            ):
                errors.append(f"{label}.ancestor_ids must be an array of strings")
    reproduction = _missing_fields(
        data.get("reproducibility"),
        "reproducibility",
        ("highest_demonstrated_level", "declared_ceiling", "supported_levels", "reproduction_command"),
        errors,
    )
    if reproduction is not None:
        reproduction_fields = (
            "highest_demonstrated_level",
            "declared_ceiling",
            "supported_levels",
            "reproduction_command",
        )
        _unexpected_fields(reproduction, "reproducibility", reproduction_fields, errors)
        if reproduction.get("highest_demonstrated_level") is not None and not isinstance(
            reproduction.get("highest_demonstrated_level"), str
        ):
            errors.append("reproducibility.highest_demonstrated_level must be a string or null")
        if not isinstance(reproduction.get("declared_ceiling"), str) or not isinstance(
            reproduction.get("reproduction_command"), str
        ):
            errors.append("reproducibility ceiling and command must be strings")
        if not isinstance(reproduction.get("supported_levels"), list) or not all(
            isinstance(level, str) for level in reproduction.get("supported_levels", [])
        ):
            errors.append("reproducibility.supported_levels must be an array of strings")
    context = _missing_fields(
        data.get("assessment_context"),
        "assessment_context",
        ("verifier", "resource_bounds", "prior_commitment", "refutation_surface"),
        errors,
    )
    if context is not None:
        context_fields = (
            "verifier",
            "resource_bounds",
            "prior_commitment",
            "refutation_surface",
        )
        _unexpected_fields(context, "assessment_context", context_fields, errors)
        verifier = _missing_fields(
            context.get("verifier"),
            "assessment_context.verifier",
            (
                "specification_hash",
                "implementation_hash",
                "parser_hash",
                "certificate_format",
                "format_fragment",
                "dependencies",
                "deterministic",
            ),
            errors,
        )
        if verifier is not None:
            verifier_fields = (
                "specification_hash",
                "implementation_hash",
                "parser_hash",
                "certificate_format",
                "format_fragment",
                "dependencies",
                "deterministic",
            )
            _unexpected_fields(
                verifier, "assessment_context.verifier", verifier_fields, errors
            )
            for name in (
                "specification_hash",
                "implementation_hash",
                "parser_hash",
            ):
                value = verifier.get(name)
                unavailable_specification = (
                    name == "specification_hash"
                    and isinstance(value, str)
                    and value.startswith("UNAVAILABLE:")
                )
                if (
                    not unavailable_specification
                    and (
                        not isinstance(value, str)
                        or not re.fullmatch(r"sha256:[0-9a-f]{64}", value)
                    )
                ):
                    errors.append(
                        f"assessment_context.verifier.{name} must be a prefixed SHA-256 digest"
                    )
            for name in ("certificate_format", "format_fragment"):
                if not isinstance(verifier.get(name), str):
                    errors.append(f"assessment_context.verifier.{name} must be a string")
            if not isinstance(verifier.get("dependencies"), list) or not all(
                isinstance(item, str) for item in verifier.get("dependencies", [])
            ):
                errors.append(
                    "assessment_context.verifier.dependencies must be an array of strings"
                )
            if type(verifier.get("deterministic")) is not bool:
                errors.append("assessment_context.verifier.deterministic must be a boolean")
        bounds = _missing_fields(
            context.get("resource_bounds"),
            "assessment_context.resource_bounds",
            (
                "verification_cost_bound",
                "memory_bound",
                "certificate_size_bound",
            ),
            errors,
        )
        if bounds is not None:
            bound_fields = (
                "verification_cost_bound",
                "memory_bound",
                "certificate_size_bound",
            )
            _unexpected_fields(
                bounds, "assessment_context.resource_bounds", bound_fields, errors
            )
            for name in bound_fields:
                value = bounds.get(name)
                if type(value) is not int or value < 0:
                    errors.append(
                        f"assessment_context.resource_bounds.{name} must be a non-negative integer"
                    )
        if not isinstance(context.get("prior_commitment"), str):
            errors.append("assessment_context.prior_commitment must be a string")
        surface = _missing_fields(
            context.get("refutation_surface"),
            "assessment_context.refutation_surface",
            (
                "admissible_refutations",
                "excluded_claims",
                "falsification_condition",
            ),
            errors,
        )
        if surface is not None:
            for name in ("admissible_refutations", "excluded_claims"):
                if not isinstance(surface.get(name), list) or not all(
                    isinstance(item, str) for item in surface.get(name, [])
                ):
                    errors.append(
                        f"assessment_context.refutation_surface.{name} must be an array of strings"
                    )
            if not isinstance(surface.get("falsification_condition"), str):
                errors.append(
                    "assessment_context.refutation_surface.falsification_condition must be a string"
                )
    return errors


def is_generic_run_receipt(data: Mapping[str, Any]) -> bool:
    return (
        data.get("schema_version") == RUN_SCHEMA_VERSION
        and data.get("receipt_kind") == RUN_RECEIPT_KIND
    )


def validate_run_receipt(receipt_path_or_dir: Path) -> int:
    """Validate one generic-run receipt's required fields and stable canonical digest."""

    receipt_file = receipt_path_or_dir / "receipt.json" if receipt_path_or_dir.is_dir() else receipt_path_or_dir
    if not receipt_file.exists():
        print(f"[FAIL] Receipt file not found: {receipt_file}")
        return 1
    try:
        data = strict_json_loads(receipt_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, StrictJsonError) as exc:
        print(f"[FAIL] Receipt is not readable JSON: {exc}")
        return 1
    if not isinstance(data, Mapping):
        print("[FAIL] Receipt root must be an object")
        return 1
    errors = _run_payload_errors(data)
    if errors:
        for error in errors:
            print(f"[FAIL] {error}")
        return 1
    recorded_digest = data.get("canonical_digest", "")
    recomputed = compute_canonical_digest(_rebuild_stable_payload_from_dict(data))
    if recomputed != recorded_digest:
        print(f"[FAIL] Canonical digest mismatch:\n  Recorded:   {recorded_digest}\n  Recomputed: {recomputed}")
        return 1
    print(f"[INTEGRITY OK] Run receipt {data.get('receipt_id')} stable digest matches.")
    print(f"       Digest: {recorded_digest}")
    print(f"       Outcome: {data.get('execution', {}).get('outcome')}")
    return 0
