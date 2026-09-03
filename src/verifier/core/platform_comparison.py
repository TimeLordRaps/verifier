"""Terminology: JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit
(SHA-256); standard input/output (stdio); standard output (stdout); standard error
(stderr); Verifier Standard (VSTD).

Bounded comparison of generic-run receipt results across operating systems.

The declaration carried by each receipt names the operating systems and result
surfaces that are intended to be comparable.  It is not evidence by itself.
This module returns ``PASS`` only when every declared operating system has one
valid receipt, the non-platform bindings agree, and the declared result
projections agree.  Comparable disagreement is preserved as ``CONFLICTED``.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import unicodedata
from pathlib import Path
from typing import Any, Iterable, Mapping

from verifier.core.receipt import (
    StrictJsonError,
    canonical_json_dumps,
    compute_canonical_digest,
    strict_json_loads,
)
from verifier.core.run_validation import (
    _rebuild_stable_payload_from_dict,
    _run_payload_errors,
)


PLATFORM_COMPARISON_MECHANISM = "VSTD-PLATFORM-COMPARISON-0.1"
_ALLOWED_RESULT_SURFACES = (
    "execution",
    "declared_outputs",
    "evaluator_claims",
    "stdio",
)


def _implementation_digest() -> str:
    digest = hashlib.sha256()
    for path in (
        Path(__file__),
        Path(__file__).with_name("run_validation.py"),
        Path(__file__).with_name("receipt.py"),
    ):
        payload = path.read_bytes()
        digest.update(path.name.encode("utf-8") + b"\0")
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return "sha256:" + digest.hexdigest()


class PlatformComparisonStatus(str, Enum):
    """Typed outcome of a bounded platform comparison."""

    PASS = "PASS"
    CONFLICTED = "CONFLICTED"
    NOT_ESTABLISHED = "NOT_ESTABLISHED"
    INVALID = "INVALID"


@dataclass(frozen=True)
class PlatformComparisonResult:
    """Machine-readable diagnostic result; this object is not a VSTD receipt."""

    status: PlatformComparisonStatus
    reason: str
    declaration: dict[str, Any] | None
    required_platforms: tuple[str, ...]
    observed_platforms: tuple[str, ...]
    comparison_binding_digest: str | None
    observations: tuple[dict[str, Any], ...]
    differences: tuple[dict[str, Any], ...]
    errors: tuple[str, ...]

    @property
    def exit_code(self) -> int:
        if self.status is PlatformComparisonStatus.PASS:
            return 0
        if self.status in {
            PlatformComparisonStatus.CONFLICTED,
            PlatformComparisonStatus.INVALID,
        }:
            return 1
        return 2

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_kind": "platform_comparison_diagnostic",
            "mechanism": {
                "identifier": PLATFORM_COMPARISON_MECHANISM,
                "implementation_sha256": _implementation_digest(),
                "dependencies": ["python-stdlib"],
            },
            "status": self.status.value,
            "reason": self.reason,
            "exit_code": self.exit_code,
            "declaration": self.declaration,
            "required_platforms": list(self.required_platforms),
            "observed_platforms": list(self.observed_platforms),
            "comparison_binding_digest": self.comparison_binding_digest,
            "observations": list(self.observations),
            "differences": list(self.differences),
            "errors": list(self.errors),
            "claim_boundary": (
                "PASS establishes only that the supplied canonically intact generic-run "
                "receipts cover every declared operating system, share the compared "
                "non-platform bindings, and record identical values on the declared "
                "result surfaces. CONFLICTED establishes a recorded result disagreement "
                "only after those comparability conditions pass."
            ),
            "limitations": [
                "The declaration does not prove that its named mechanism is compatible across operating systems.",
                "The receipt platform value is an operating-system observation, not native-hardware or virtual-machine attestation.",
                "The comparison does not establish semantic correctness, universal portability, actor independence, or behavior outside the supplied coordinates.",
                "Receipt validation checks canonical integrity; this comparison does not independently rehash external artifacts or rerun recorded commands.",
            ],
        }


def _receipt_file(path: Path) -> Path:
    return path / "receipt.json" if path.is_dir() else path


def _machine_family(value: object) -> str:
    aliases = {
        "amd64": "x86_64",
        "x64": "x86_64",
        "x86_64": "x86_64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }
    normalized = str(value).lower()
    return aliases.get(normalized, normalized)


def _platform_collision_key(value: str) -> str:
    return unicodedata.normalize("NFKC", value).casefold()


def _load_receipt(path: Path) -> tuple[dict[str, Any] | None, list[str]]:
    receipt_file = _receipt_file(path)
    try:
        payload = strict_json_loads(receipt_file.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None, [f"receipt file not found: {receipt_file}"]
    except (OSError, UnicodeError, json.JSONDecodeError, StrictJsonError) as exc:
        return None, [f"receipt is not readable JSON at {receipt_file}: {exc}"]
    if not isinstance(payload, Mapping):
        return None, [f"receipt root must be an object: {receipt_file}"]
    data = dict(payload)
    errors = _run_payload_errors(data)
    if not errors:
        recomputed = compute_canonical_digest(_rebuild_stable_payload_from_dict(data))
        if recomputed != data.get("canonical_digest"):
            errors.append(
                "canonical digest mismatch at "
                f"{receipt_file}: recorded={data.get('canonical_digest')} "
                f"recomputed={recomputed}"
            )
    return data, [f"{receipt_file}: {error}" for error in errors]


def _parse_declaration(
    receipt: Mapping[str, Any],
) -> tuple[dict[str, Any] | None, list[str], bool]:
    surface = receipt.get("assessment_context", {}).get("refutation_surface", {})
    raw = surface.get("platform_comparability") if isinstance(surface, Mapping) else None
    if raw is None:
        return None, ["platform_comparability declaration is absent"], True
    if not isinstance(raw, Mapping):
        return None, ["platform_comparability must be an object"], False
    expected = {"mechanism_id", "compatible_platforms", "result_surfaces"}
    unexpected = sorted(set(raw) - expected)
    missing = sorted(expected - set(raw))
    errors: list[str] = []
    if missing:
        errors.append(f"platform_comparability missing fields: {', '.join(missing)}")
    if unexpected:
        errors.append(
            f"platform_comparability has unexpected fields: {', '.join(unexpected)}"
        )
    mechanism_id = raw.get("mechanism_id")
    if (
        not isinstance(mechanism_id, str)
        or not mechanism_id
        or mechanism_id != mechanism_id.strip()
    ):
        errors.append(
            "platform_comparability.mechanism_id must identify the compared subject mechanism"
        )
    platforms = raw.get("compatible_platforms")
    if (
        not isinstance(platforms, list)
        or len(platforms) < 2
        or not all(
            isinstance(item, str) and bool(item) and item == item.strip()
            for item in platforms
        )
    ):
        errors.append(
            "platform_comparability.compatible_platforms must contain at least two non-empty platform strings"
        )
        normalized_platforms: list[str] = []
    else:
        normalized_platforms = sorted(platforms)
        if len(set(normalized_platforms)) != len(normalized_platforms):
            errors.append(
                "platform_comparability.compatible_platforms must not contain duplicates"
            )
        collision_keys: dict[str, str] = {}
        collisions: list[tuple[str, str]] = []
        for platform in platforms:
            collision_key = _platform_collision_key(platform)
            previous = collision_keys.get(collision_key)
            if previous is not None and previous != platform:
                collisions.append((previous, platform))
            else:
                collision_keys[collision_key] = platform
        if collisions:
            rendered = ", ".join(
                f"{first!r} and {second!r}" for first, second in collisions
            )
            errors.append(
                "platform_comparability.compatible_platforms values collide "
                f"after Unicode normalization and casefold: {rendered}"
            )
    surfaces = raw.get("result_surfaces")
    if (
        not isinstance(surfaces, list)
        or not surfaces
        or not all(isinstance(item, str) for item in surfaces)
    ):
        errors.append(
            "platform_comparability.result_surfaces must be a non-empty array of strings"
        )
        normalized_surfaces: list[str] = []
    else:
        unknown = sorted(set(surfaces) - set(_ALLOWED_RESULT_SURFACES))
        if unknown:
            errors.append(
                "platform_comparability.result_surfaces has unsupported values: "
                + ", ".join(unknown)
            )
        if len(set(surfaces)) != len(surfaces):
            errors.append("platform_comparability.result_surfaces must not contain duplicates")
        normalized_surfaces = [
            name for name in _ALLOWED_RESULT_SURFACES if name in surfaces
        ]
    if errors:
        return None, errors, False
    return {
        "mechanism_id": mechanism_id,
        "compatible_platforms": normalized_platforms,
        "result_surfaces": normalized_surfaces,
    }, [], False


def _normalize_source_hash_paths(
    binding: dict[str, Any], platform: str
) -> None:
    if _platform_collision_key(platform) != "windows":
        return
    source_state = binding.get("source_state_stable")
    hashes = (
        source_state.get("source_file_hashes")
        if isinstance(source_state, Mapping)
        else None
    )
    if not isinstance(hashes, Mapping):
        raise ValueError("source_file_hashes must be an object")
    normalized: dict[str, Any] = {}
    original_paths: dict[str, str] = {}
    for raw_path, digest in hashes.items():
        if not isinstance(raw_path, str):
            raise ValueError("source_file_hashes keys must be strings")
        normalized_path = raw_path.replace("\\", "/")
        if normalized_path in normalized:
            raise ValueError(
                "source_file_hashes paths collide after Windows separator "
                f"normalization: {original_paths[normalized_path]!r} and "
                f"{raw_path!r}"
            )
        normalized[normalized_path] = digest
        original_paths[normalized_path] = raw_path
    source_state["source_file_hashes"] = normalized


def _comparison_binding(
    receipt: Mapping[str, Any],
    result_surfaces: tuple[str, ...],
    platform: str,
) -> dict[str, Any]:
    binding = copy.deepcopy(_rebuild_stable_payload_from_dict(receipt))
    normalized_declaration, declaration_errors, _absent = _parse_declaration(receipt)
    if normalized_declaration is None or declaration_errors:
        raise ValueError("comparison binding requires a valid platform declaration")
    binding["assessment_context"]["refutation_surface"][
        "platform_comparability"
    ] = normalized_declaration
    runtime = receipt["source_state"]["runtime"]
    binding["platform_comparison_environment"] = {
        "python_implementation": runtime.get("python_implementation"),
        "machine_family": _machine_family(runtime.get("platform_machine")),
    }
    execution = binding["execution_stable"]
    execution.pop("platform_system", None)
    claims = binding["claims"]

    if "execution" in result_surfaces:
        for name in ("exit_code", "outcome"):
            execution.pop(name, None)
        for name in (
            "execution_completed",
            "output_digests_recorded",
            "all_declared_artifacts_present",
        ):
            claims.pop(name, None)
    if "declared_outputs" in result_surfaces:
        binding["outputs"] = [
            {"path": output["path"], "role": output["role"]}
            for output in receipt["outputs"]
        ]
    if "evaluator_claims" in result_surfaces:
        claims["evaluator_claims"] = [
            {
                "evaluator_name": evaluator["evaluator_name"],
                "metric_name": evaluator["metric_name"],
                "computed_by": evaluator["computed_by"],
                "verified_independently": evaluator["verified_independently"],
            }
            for evaluator in receipt["claims"]["evaluator_claims"]
        ]
    if "stdio" in result_surfaces:
        execution.pop("stdout_sha256", None)
        execution.pop("stderr_sha256", None)
    _normalize_source_hash_paths(binding, platform)
    return binding


def _result_projection(
    receipt: Mapping[str, Any], result_surfaces: tuple[str, ...]
) -> dict[str, Any]:
    execution = receipt["execution"]
    claims = receipt["claims"]
    projection: dict[str, Any] = {}
    if "execution" in result_surfaces:
        projection["execution"] = {
            "exit_code": execution["exit_code"],
            "outcome": execution["outcome"],
            "execution_completed": claims["execution_completed"],
            "output_digests_recorded": claims["output_digests_recorded"],
            "all_declared_artifacts_present": claims[
                "all_declared_artifacts_present"
            ],
        }
    if "declared_outputs" in result_surfaces:
        projection["declared_outputs"] = receipt["outputs"]
    if "evaluator_claims" in result_surfaces:
        projection["evaluator_claims"] = claims["evaluator_claims"]
    if "stdio" in result_surfaces:
        projection["stdio"] = {
            "stdout_sha256": execution["stdout_sha256"],
            "stderr_sha256": execution["stderr_sha256"],
        }
    return projection


def _differences(
    reference: Any, observed: Any, *, path: str = ""
) -> list[dict[str, Any]]:
    if isinstance(reference, Mapping) and isinstance(observed, Mapping):
        differences: list[dict[str, Any]] = []
        for key in sorted(set(reference) | set(observed)):
            child = f"{path}.{key}" if path else str(key)
            if key not in reference:
                differences.append(
                    {"path": child, "reference": None, "observed": observed[key]}
                )
            elif key not in observed:
                differences.append(
                    {"path": child, "reference": reference[key], "observed": None}
                )
            else:
                differences.extend(
                    _differences(reference[key], observed[key], path=child)
                )
        return differences
    if isinstance(reference, list) and isinstance(observed, list):
        differences = []
        for index in range(max(len(reference), len(observed))):
            child = f"{path}[{index}]"
            if index >= len(reference):
                differences.append(
                    {"path": child, "reference": None, "observed": observed[index]}
                )
            elif index >= len(observed):
                differences.append(
                    {"path": child, "reference": reference[index], "observed": None}
                )
            else:
                differences.extend(
                    _differences(reference[index], observed[index], path=child)
                )
        return differences
    if canonical_json_dumps(reference) != canonical_json_dumps(observed):
        return [{"path": path, "reference": reference, "observed": observed}]
    return []


def _result(
    status: PlatformComparisonStatus,
    reason: str,
    *,
    declaration: dict[str, Any] | None = None,
    required_platforms: Iterable[str] = (),
    observed_platforms: Iterable[str] = (),
    comparison_binding_digest: str | None = None,
    observations: Iterable[dict[str, Any]] = (),
    differences: Iterable[dict[str, Any]] = (),
    errors: Iterable[str] = (),
) -> PlatformComparisonResult:
    return PlatformComparisonResult(
        status=status,
        reason=reason,
        declaration=declaration,
        required_platforms=tuple(required_platforms),
        observed_platforms=tuple(observed_platforms),
        comparison_binding_digest=comparison_binding_digest,
        observations=tuple(observations),
        differences=tuple(differences),
        errors=tuple(errors),
    )


def compare_platform_run_receipts(
    receipts: Iterable[str | Path],
) -> PlatformComparisonResult:
    """Compare declared result surfaces across canonically intact run receipts."""

    loaded: list[tuple[Path, dict[str, Any]]] = []
    load_errors: list[str] = []
    for raw_path in receipts:
        path = Path(raw_path)
        receipt, errors = _load_receipt(path)
        load_errors.extend(errors)
        if receipt is not None:
            loaded.append((path, receipt))
    if load_errors:
        return _result(
            PlatformComparisonStatus.INVALID,
            "At least one supplied receipt is malformed or lacks canonical integrity.",
            errors=load_errors,
        )
    if not loaded:
        return _result(
            PlatformComparisonStatus.NOT_ESTABLISHED,
            "No platform receipts were supplied.",
        )

    declarations: list[dict[str, Any]] = []
    declaration_errors: list[str] = []
    declaration_errors_are_all_absent = True
    for path, receipt in loaded:
        declaration, errors, absent = _parse_declaration(receipt)
        if errors:
            declaration_errors.extend(f"{_receipt_file(path)}: {error}" for error in errors)
            declaration_errors_are_all_absent = (
                declaration_errors_are_all_absent and absent
            )
        elif declaration is not None:
            declarations.append(declaration)
    if declaration_errors:
        status = (
            PlatformComparisonStatus.NOT_ESTABLISHED
            if declaration_errors_are_all_absent
            else PlatformComparisonStatus.INVALID
        )
        return _result(
            status,
            "Platform comparability is undeclared."
            if status is PlatformComparisonStatus.NOT_ESTABLISHED
            else "At least one platform-comparability declaration is malformed.",
            errors=declaration_errors,
        )

    declaration = declarations[0]
    if any(item != declaration for item in declarations[1:]):
        return _result(
            PlatformComparisonStatus.NOT_ESTABLISHED,
            "The supplied receipts do not share one platform-comparability declaration.",
            declaration=declaration,
            errors=["platform_comparability declarations differ across receipts"],
        )

    required_platforms = tuple(declaration["compatible_platforms"])
    observed: dict[str, tuple[Path, dict[str, Any]]] = {}
    set_errors: list[str] = []
    contradiction_errors: list[str] = []
    for path, receipt in loaded:
        runtime = receipt["source_state"]["runtime"]
        source_platform = runtime["platform_system"]
        execution_platform = receipt["execution"]["platform_system"]
        if source_platform != execution_platform:
            contradiction_errors.append(
                f"{_receipt_file(path)}: source_state.runtime.platform_system "
                f"{source_platform!r} does not equal execution.platform_system "
                f"{execution_platform!r}"
            )
            continue
        if runtime["python_version"] != receipt["execution"]["python_version"]:
            contradiction_errors.append(
                f"{_receipt_file(path)}: source_state.runtime.python_version "
                "does not equal execution.python_version"
            )
            continue
        missing_environment = [
            name
            for name in ("python_implementation", "platform_machine")
            if not isinstance(runtime.get(name), str) or not runtime.get(name)
        ]
        if missing_environment:
            set_errors.append(
                f"{_receipt_file(path)}: comparison environment is missing "
                + ", ".join(missing_environment)
            )
            continue
        if execution_platform in observed:
            set_errors.append(
                f"duplicate receipt for declared platform {execution_platform!r}"
            )
            continue
        observed[execution_platform] = (path, receipt)
    if contradiction_errors:
        return _result(
            PlatformComparisonStatus.INVALID,
            "At least one receipt contains internally contradictory execution observations.",
            declaration=declaration,
            required_platforms=required_platforms,
            observed_platforms=sorted(observed),
            errors=[*contradiction_errors, *set_errors],
        )

    missing = sorted(set(required_platforms) - set(observed))
    unexpected = sorted(set(observed) - set(required_platforms))
    if set_errors or missing or unexpected:
        errors = list(set_errors)
        if missing:
            errors.append("missing declared platforms: " + ", ".join(missing))
        if unexpected:
            errors.append("unexpected platforms: " + ", ".join(unexpected))
        return _result(
            PlatformComparisonStatus.NOT_ESTABLISHED,
            "The supplied receipt set does not contain exactly one receipt for every declared platform.",
            declaration=declaration,
            required_platforms=required_platforms,
            observed_platforms=sorted(observed),
            errors=errors,
        )

    surfaces = tuple(declaration["result_surfaces"])
    ordered = [(platform, *observed[platform]) for platform in required_platforms]
    bindings: dict[str, dict[str, Any]] = {}
    binding_errors: list[str] = []
    for platform, path, receipt in ordered:
        try:
            bindings[platform] = _comparison_binding(
                receipt, surfaces, platform
            )
        except ValueError as exc:
            binding_errors.append(f"{_receipt_file(path)}: {exc}")
    if binding_errors:
        return _result(
            PlatformComparisonStatus.INVALID,
            "At least one receipt has ambiguous source-path identity.",
            declaration=declaration,
            required_platforms=required_platforms,
            observed_platforms=required_platforms,
            errors=binding_errors,
        )
    binding_digests = {
        platform: compute_canonical_digest(binding)
        for platform, binding in bindings.items()
    }
    reference_platform = required_platforms[0]
    binding_differences: list[dict[str, Any]] = []
    for platform in required_platforms[1:]:
        for difference in _differences(
            bindings[reference_platform], bindings[platform]
        ):
            binding_differences.append(
                {
                    "kind": "comparison_binding",
                    "reference_platform": reference_platform,
                    "observed_platform": platform,
                    **difference,
                }
            )
    if binding_differences:
        observations = [
            {
                "platform": platform,
                "platform_machine": receipt["source_state"]["runtime"].get(
                    "platform_machine"
                ),
                "machine_family": _machine_family(
                    receipt["source_state"]["runtime"].get("platform_machine")
                ),
                "receipt": str(_receipt_file(path)),
                "receipt_id": receipt["receipt_id"],
                "receipt_canonical_digest": receipt["canonical_digest"],
                "comparison_binding_digest": binding_digests[platform],
                "result_digest": None,
            }
            for platform, path, receipt in ordered
        ]
        return _result(
            PlatformComparisonStatus.NOT_ESTABLISHED,
            "Non-platform receipt bindings differ, so result disagreement would not isolate the operating-system dimension.",
            declaration=declaration,
            required_platforms=required_platforms,
            observed_platforms=required_platforms,
            observations=observations,
            differences=binding_differences,
        )

    projections = {
        platform: _result_projection(receipt, surfaces)
        for platform, _path, receipt in ordered
    }
    result_digests = {
        platform: compute_canonical_digest(projection)
        for platform, projection in projections.items()
    }
    observations = [
        {
            "platform": platform,
            "platform_machine": receipt["source_state"]["runtime"].get(
                "platform_machine"
            ),
            "machine_family": _machine_family(
                receipt["source_state"]["runtime"].get("platform_machine")
            ),
            "receipt": str(_receipt_file(path)),
            "receipt_id": receipt["receipt_id"],
            "receipt_canonical_digest": receipt["canonical_digest"],
            "comparison_binding_digest": binding_digests[platform],
            "result_digest": result_digests[platform],
        }
        for platform, path, receipt in ordered
    ]
    result_differences: list[dict[str, Any]] = []
    for platform in required_platforms[1:]:
        for difference in _differences(
            projections[reference_platform], projections[platform]
        ):
            result_differences.append(
                {
                    "kind": "declared_result",
                    "reference_platform": reference_platform,
                    "observed_platform": platform,
                    **difference,
                }
            )
    binding_digest = binding_digests[reference_platform]
    if result_differences:
        return _result(
            PlatformComparisonStatus.CONFLICTED,
            "Comparable receipts record different values on at least one declared result surface.",
            declaration=declaration,
            required_platforms=required_platforms,
            observed_platforms=required_platforms,
            comparison_binding_digest=binding_digest,
            observations=observations,
            differences=result_differences,
        )
    return _result(
        PlatformComparisonStatus.PASS,
        "Every declared platform is represented once with matching non-platform bindings and recorded result projections.",
        declaration=declaration,
        required_platforms=required_platforms,
        observed_platforms=required_platforms,
        comparison_binding_digest=binding_digest,
        observations=observations,
    )
