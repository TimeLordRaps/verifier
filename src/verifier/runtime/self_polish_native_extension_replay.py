"""Replay prepared native extensions without installing or qualifying them."""
from __future__ import annotations

import base64
import binascii
from collections import Counter
import inspect
from pathlib import Path
import re
from typing import Any, Callable

from verifier.runtime import core_obligation_union
from verifier.runtime import self_polish_native_adapters
from verifier.runtime import self_polish_native_extensions
from verifier.domains.contracts import current_object_routes


REPLAY_SCHEMA = "verifier-self-polish-prepared-extension-replay-1"
CASE_KINDS = ("POSITIVE", "NEGATIVE", "UNKNOWN")
CASE_OUTCOMES = {
    "POSITIVE": "PASS", "NEGATIVE": "FAIL", "UNKNOWN": "UNKNOWN",
}
MAX_CERTIFICATE_BYTES = 32 * 1024 * 1024
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")


class PreparedNativeReplayError(ValueError):
    """A prepared extension cannot be replayed at the selected source."""


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise PreparedNativeReplayError(code)


def _digest(value: Any) -> str:
    return core_obligation_union.value_digest(value)


def mechanism_digest() -> str:
    """Bind this replay and its prepared registry and adapter mechanisms."""

    return _digest({
        "replay_module": core_obligation_union.bytes_digest(
            Path(__file__).read_bytes()
        ),
        "extension_registry_module": core_obligation_union.bytes_digest(
            Path(self_polish_native_extensions.__file__).read_bytes()
        ),
        "adapter_module": core_obligation_union.bytes_digest(
            Path(self_polish_native_adapters.__file__).read_bytes()
        ),
    })


def _resolve_mechanism(
        source_root: Path, dotted: str,
        ) -> tuple[Callable[..., Any], str, str]:
    module_name, symbol = dotted.rsplit(".", 1)
    try:
        module = current_object_routes.registered_mechanism_module(dotted)
    except current_object_routes.CurrentObjectRouteRefusal as exc:
        raise PreparedNativeReplayError(
            "PREPARED_NATIVE_MECHANISM_UNAVAILABLE"
        ) from exc
    function = getattr(module, symbol, None)
    _require(callable(function), "PREPARED_NATIVE_MECHANISM_UNAVAILABLE")
    root = Path(source_root).resolve(strict=True)
    parts = module_name.split(".")
    expected = root.joinpath("src", *parts).with_suffix(".py").resolve()
    actual = Path(inspect.getsourcefile(function) or "").resolve()
    loaded = Path(__file__).resolve().parents[2].joinpath(
        *parts
    ).with_suffix(".py").resolve()
    _require(
        parts[0] == "verifier"
        and expected.is_relative_to(root)
        and expected.is_file()
        and actual == loaded
        and actual.is_file(),
        "PREPARED_NATIVE_MECHANISM_SOURCE_DIFFERS",
    )
    selected_bytes = expected.read_bytes()
    _require(
        actual.read_bytes() == selected_bytes,
        "PREPARED_NATIVE_MECHANISM_SOURCE_DIFFERS",
    )
    return (
        function,
        expected.relative_to(root).as_posix(),
        core_obligation_union.bytes_digest(selected_bytes),
    )


def _membership_rows(registry: dict[str, Any]) -> list[dict[str, Any]]:
    rows = [
        row
        for tier_rows in registry["memberships_by_tier"].values()
        for row in tier_rows
    ]
    rows.sort(key=lambda row: (row["tier"], row["obligation_id"]))
    _require(
        len(rows) == registry["membership_count"]
        and len({row["obligation_id"] for row in rows}) == len(rows),
        "PREPARED_NATIVE_REPLAY_DENOMINATOR_DIFFERS",
    )
    return rows


def replay_prepared_extensions(
        source_root: str | Path, *, source_coordinate_digest: str,
        ) -> dict[str, Any]:
    """Replay all prepared Tier 3-9 triads at one exact source root.

    A PASS means only that the prepared specimens discriminate their declared
    native PASS, FAIL, and UNKNOWN outcomes at this source coordinate.  It does
    not install the specimens or establish whole-tier/package conformance.
    """

    root = Path(source_root).resolve(strict=True)
    _require(root.is_dir(), "PREPARED_NATIVE_SOURCE_ROOT_UNAVAILABLE")
    _require(
        type(source_coordinate_digest) is str
        and _SHA256.fullmatch(source_coordinate_digest) is not None,
        "PREPARED_NATIVE_SOURCE_COORDINATE_INVALID",
    )
    registry = self_polish_native_extensions.prepared_extension_registry()
    selected = (
        self_polish_native_extensions.prepared_extension_case_inputs()
    )
    rows = _membership_rows(registry)
    _require(
        registry["status"] == "PREPARED_NOT_INSTALLED"
        and set(selected) == {row["obligation_id"] for row in rows},
        "PREPARED_NATIVE_REGISTRY_BINDING_DIFFERS",
    )

    memberships: list[dict[str, Any]] = []
    case_status_counts: Counter[str] = Counter()
    for row in rows:
        identifier = row["obligation_id"]
        case = selected[identifier]
        rechecker, mechanism_path, mechanism_file_digest = (
            _resolve_mechanism(root, row["checking_mechanism"])
        )
        module_name, recheck_symbol = row["checking_mechanism"].rsplit(
            ".", 1
        )
        build_symbol = recheck_symbol.replace("recheck_", "build_", 1)
        _require(
            build_symbol != recheck_symbol,
            "PREPARED_NATIVE_BUILDER_UNAVAILABLE",
        )
        builder, builder_path, builder_file_digest = _resolve_mechanism(
            root, module_name + "." + build_symbol
        )
        _require(
            builder_path == mechanism_path
            and builder_file_digest == mechanism_file_digest,
            "PREPARED_NATIVE_BUILDER_SOURCE_DIFFERS",
        )
        try:
            replay_input = base64.b64decode(
                case["evidence_base64"], validate=True
            )
        except (ValueError, TypeError, binascii.Error) as exc:
            raise PreparedNativeReplayError(
                "PREPARED_NATIVE_REPLAY_INPUT_INVALID"
            ) from exc
        request = case["request"]
        policy = case["policy"]
        negative_request, negative_input = (
            self_polish_native_adapters.negative_case(
                case["negative_adapter"], request, replay_input,
                policy=policy,
            )
        )
        unknown_request, unknown_input = (
            self_polish_native_adapters.unknown_case(
                case["unknown_adapter"], request, replay_input,
                policy=policy,
            )
        )
        inputs = {
            "POSITIVE": (request, replay_input, "POSITIVE"),
            "NEGATIVE": (negative_request, negative_input, "NEGATIVE"),
            "UNKNOWN": (
                unknown_request, unknown_input, case["unknown_adapter"],
            ),
        }
        case_results = []
        for case_kind in CASE_KINDS:
            selected_request, selected_input, adapter_case_kind = inputs[
                case_kind
            ]
            try:
                certificate = self_polish_native_adapters.build_certificate(
                    case["builder_adapter"], adapter_case_kind, builder,
                    selected_request, selected_input, policy,
                )
                _require(
                    type(certificate) is bytes
                    and len(certificate) <= MAX_CERTIFICATE_BYTES,
                    "PREPARED_NATIVE_CERTIFICATE_CAPACITY_EXHAUSTED",
                )
                result = rechecker(
                    certificate,
                    expected_request=selected_request,
                    policy=policy,
                )
            except PreparedNativeReplayError:
                raise
            except (ValueError, TypeError, KeyError, AttributeError,
                    UnicodeError, binascii.Error) as exc:
                raise PreparedNativeReplayError(
                    "PREPARED_NATIVE_CASE_REPLAY_REFUSED"
                ) from exc
            native_status = result.get("status") \
                if type(result) is dict else None
            case_status = (
                "PASS"
                if native_status == CASE_OUTCOMES[case_kind]
                else "FAIL"
            )
            case_status_counts[case_status] += 1
            case_results.append({
                "case_kind": case_kind,
                "expected_native_status": CASE_OUTCOMES[case_kind],
                "native_status": native_status,
                "status": case_status,
                "selected_request_digest": _digest(selected_request),
                "certificate_digest": (
                    core_obligation_union.bytes_digest(certificate)
                ),
                "native_result_digest": _digest(result),
            })
        membership_status = (
            "PASS"
            if all(item["status"] == "PASS" for item in case_results)
            else "FAIL"
        )
        memberships.append({
            "obligation_id": identifier,
            "object_kind": row["object_kind"],
            "tier": row["tier"],
            "coordinate": row["coordinate"],
            "proposition_digest": row["proposition_digest"],
            "checking_mechanism": row["checking_mechanism"],
            "mechanism_source_path": mechanism_path,
            "mechanism_source_digest": mechanism_file_digest,
            "status": membership_status,
            "cases": case_results,
        })

    tier_results = []
    for tier in registry["tiers"]:
        tier_memberships = [
            row for row in memberships if row["tier"] == tier
        ]
        tier_results.append({
            "tier": tier,
            "status": (
                "PASS" if all(
                    row["status"] == "PASS" for row in tier_memberships
                ) else "FAIL"
            ),
            "membership_count": len(tier_memberships),
            "case_count": sum(
                len(row["cases"]) for row in tier_memberships
            ),
        })
    status = (
        "PASS"
        if len(memberships) == registry["membership_count"]
        and all(row["status"] == "PASS" for row in memberships)
        else "FAIL"
    )
    body = {
        "schema_version": REPLAY_SCHEMA,
        "status": status,
        "preparation_status": "PREPARED_NOT_INSTALLED",
        "source_coordinate_digest": source_coordinate_digest,
        "mechanism_digest": mechanism_digest(),
        "prepared_registry_digest": registry["registry_digest"],
        "tiers": registry["tiers"],
        "tier_membership_counts": registry["tier_membership_counts"],
        "membership_count": registry["membership_count"],
        "case_count": registry["case_count"],
        "completed_membership_count": len(memberships),
        "completed_case_count": sum(
            len(row["cases"]) for row in memberships
        ),
        "case_status_counts": dict(sorted(case_status_counts.items())),
        "tier_results": tier_results,
        "memberships": memberships,
        "whole_tier_conformance": "NOT_ESTABLISHED",
        "release_authority": "NONE",
        "claim_boundary": (
            "PASS establishes prepared specimen discrimination at the selected "
            "source coordinate only. The cases remain uninstalled and establish "
            "no whole-tier, package, release, or deployment qualification."
        ),
    }
    body["replay_digest"] = _digest(body)
    return body


__all__ = [
    "CASE_KINDS", "CASE_OUTCOMES", "MAX_CERTIFICATE_BYTES",
    "PreparedNativeReplayError", "REPLAY_SCHEMA", "mechanism_digest",
    "replay_prepared_extensions",
]
