"""Compose installed and prepared native replay into one candidate report."""
from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from verifier.runtime import core_obligation_union
from verifier.runtime import self_polish_native_extension_replay
from verifier.runtime import self_polish_native_replay


CANDIDATE_SCHEMA = "verifier-self-polish-full-native-candidate-1"
_EXPECTED_TIER_COUNTS = {
    "1": 45, "2": 37, "3": 31, "4": 32, "5": 26,
    "6": 26, "7": 156, "8": 26, "9": 29,
}


class FullNativeCandidateError(ValueError):
    """The full native candidate denominator or binding differs."""


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise FullNativeCandidateError(code)


def _digest(value: Any) -> str:
    return core_obligation_union.value_digest(value)


def mechanism_digest() -> str:
    """Bind the composer and both native replay mechanisms."""

    return _digest({
        "candidate_module": core_obligation_union.bytes_digest(
            Path(__file__).read_bytes()
        ),
        "installed_replay_mechanism": (
            self_polish_native_replay.mechanism_digest()
        ),
        "prepared_replay_mechanism": (
            self_polish_native_extension_replay.mechanism_digest()
        ),
    })


def _installed_tier(
        root: Path, tier: int, source_coordinate_digest: str,
        ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    manifest = self_polish_native_replay.build_installed_replay_manifest(
        tier,
        root,
        source_coordinate_digest=source_coordinate_digest,
    )
    receipt = self_polish_native_replay.replay_native_obligations(
        manifest,
        root,
        tier=tier,
        expected_manifest_digest=(
            core_obligation_union.bytes_digest(manifest)
        ),
        expected_source_coordinate_digest=source_coordinate_digest,
    )
    if receipt["membership_count"] != _EXPECTED_TIER_COUNTS[str(tier)]:
        if receipt["status"] == "UNKNOWN":
            raise self_polish_native_replay.NativeReplayResourceError(
                failure_observed=False
            )
        raise FullNativeCandidateError("FULL_NATIVE_INSTALLED_TIER_INCOMPLETE")
    routes = []
    for row in receipt["memberships"]:
        membership = row["membership"]
        routes.append({
            "obligation_id": row["obligation_id"],
            "object_kind": membership["object_kind"],
            "tier": membership["tier"],
            "coordinate": membership["coordinate"],
            "proposition_digest": membership["proposition_digest"],
            "checking_mechanism": membership["checking_mechanism"],
            "lifecycle": "INSTALLED",
            "status": row["status"],
            "route_replay_digest": row["native_replay_digest"],
            "cases": [
                {
                    key: case[key] for key in (
                        "case_kind", "expected_native_status",
                        "native_status", "status", "native_result_digest",
                    )
                }
                for case in row["cases"]
            ],
        })
    summary = {
        "tier": tier,
        "status": receipt["status"],
        "manifest_digest": receipt["manifest_digest"],
        "receipt_digest": receipt["receipt_digest"],
        "membership_count": receipt["membership_count"],
        "case_count": receipt["case_count"],
        "invalidators": receipt["invalidators"],
        "whole_tier_conformance": receipt["whole_tier_conformance"],
    }
    return summary, routes


def replay_full_native_candidate(
        source_root: str | Path, *, source_coordinate_digest: str,
        ) -> dict[str, Any]:
    """Replay all 408 routes while preserving installation boundaries."""

    root = Path(source_root).resolve(strict=True)
    installed_summaries = []
    routes: list[dict[str, Any]] = []
    try:
        for tier in (1, 2):
            summary, tier_routes = _installed_tier(
                root, tier, source_coordinate_digest
            )
            installed_summaries.append(summary)
            routes.extend(tier_routes)

        prepared = (
            self_polish_native_extension_replay.replay_prepared_extensions(
                root,
                source_coordinate_digest=source_coordinate_digest,
            )
        )
    except (self_polish_native_replay.NativeReplayResourceError,
            OSError, ImportError, MemoryError, RecursionError, OverflowError) as exc:
        raise self_polish_native_replay.NativeReplayResourceError(
            failure_observed=(
                getattr(exc, "failure_observed", False)
                or any(row["status"] == "FAIL" for row in installed_summaries)
            )
        ) from exc
    routes.extend({
        "obligation_id": row["obligation_id"],
        "object_kind": row["object_kind"],
        "tier": row["tier"],
        "coordinate": row["coordinate"],
        "proposition_digest": row["proposition_digest"],
        "checking_mechanism": row["checking_mechanism"],
        "lifecycle": "PREPARED_NOT_INSTALLED",
        "status": row["status"],
        "route_replay_digest": _digest(row),
        "cases": [
            {
                key: case[key] for key in (
                    "case_kind", "expected_native_status", "native_status",
                    "status", "native_result_digest",
                )
            }
            for case in row["cases"]
        ],
    } for row in prepared["memberships"])
    routes.sort(key=lambda row: (row["tier"], row["obligation_id"]))

    _require(
        len(routes) == sum(_EXPECTED_TIER_COUNTS.values())
        and len({row["obligation_id"] for row in routes}) == len(routes),
        "FULL_NATIVE_CANDIDATE_DENOMINATOR_DIFFERS",
    )
    observed_tier_counts = Counter(str(row["tier"]) for row in routes)
    _require(
        dict(sorted(observed_tier_counts.items()))
            == _EXPECTED_TIER_COUNTS,
        "FULL_NATIVE_CANDIDATE_TIER_DENOMINATOR_DIFFERS",
    )
    _require(
        all(len(row["cases"]) == 3 for row in routes),
        "FULL_NATIVE_CANDIDATE_CASE_DENOMINATOR_DIFFERS",
    )

    route_status_counts = Counter(row["status"] for row in routes)
    case_status_counts = Counter(
        case["status"] for row in routes for case in row["cases"]
    )
    native_status_counts = Counter(
        case["native_status"] for row in routes for case in row["cases"]
    )
    statuses = set(route_status_counts)
    status = (
        "FAIL" if "FAIL" in statuses else
        "UNKNOWN" if "UNKNOWN" in statuses else "PASS"
    )
    invalidators = sorted({
        invalidator
        for summary in installed_summaries
        for invalidator in summary["invalidators"]
    })
    body = {
        "schema_version": CANDIDATE_SCHEMA,
        "status": status,
        "source_coordinate_digest": source_coordinate_digest,
        "mechanism_digest": mechanism_digest(),
        "tiers": list(range(1, 10)),
        "tier_membership_counts": dict(_EXPECTED_TIER_COUNTS),
        "membership_count": len(routes),
        "case_count": sum(len(row["cases"]) for row in routes),
        "installed_membership_count": sum(
            summary["membership_count"]
            for summary in installed_summaries
        ),
        "prepared_membership_count": prepared["membership_count"],
        "route_status_counts": dict(sorted(route_status_counts.items())),
        "case_status_counts": dict(sorted(case_status_counts.items())),
        "native_status_counts": dict(sorted(native_status_counts.items())),
        "installed_tier_replays": installed_summaries,
        "prepared_extension_replay_digest": prepared["replay_digest"],
        "routes": routes,
        "invalidators": invalidators,
        "extension_installation_status": "PREPARED_NOT_INSTALLED",
        "whole_tier_conformance": "NOT_ESTABLISHED",
        "polished": False,
        "release_authority": "NONE",
        "claim_boundary": (
            "The candidate covers all registered route specimens at the "
            "selected source coordinate. Tiers 3-9 remain uninstalled, the "
            "SIM-2.4 positive case remains UNKNOWN, and no whole-tier, package, "
            "release, or deployment qualification is established."
        ),
    }
    body["candidate_digest"] = _digest(body)
    return body


__all__ = [
    "CANDIDATE_SCHEMA", "FullNativeCandidateError", "mechanism_digest",
    "replay_full_native_candidate",
]
