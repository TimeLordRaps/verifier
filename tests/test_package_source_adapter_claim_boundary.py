"""Claim-boundary guard for the package source adapter (finding F-06).

A source-adapter route establishes installed-review binding, current source
evidence, and the SOURCE-0.1 or installed admission ledger only. Typed
composition is checked by the package graph gate, and behavioral applicability
stays an independent necessary or conditional route. Adapter-authored text may
name those excluded claims only inside an explicit negation or boundary.
"""
from __future__ import annotations

import re
from typing import Any

import pytest

from test_package_source_contracts import _fixture
from verifier.runtime import package_source_contracts as contracts

# Words that name a composition, behavioral, Facets/Dynamics/Statics, or kind-
# semantics claim. A sentence containing one of them must also state a boundary.
_EXCLUDED_CLAIM = re.compile(
    r"typed[- ]composition|composition|behavio|kind semantics|"
    r"\b(Facets|Dynamics|Statics)\b",
    re.IGNORECASE,
)
_BOUNDARY = re.compile(
    r"\b(not|no|never|without|separate|separately|independent|independently)\b",
    re.IGNORECASE,
)


def _sentences(text: str) -> list[str]:
    return [part.strip() for part in re.split(r"[.;]\s*", text) if part.strip()]


def _unbounded_claims(text: str) -> list[str]:
    return [
        sentence for sentence in _sentences(text)
        if _EXCLUDED_CLAIM.search(sentence) and not _BOUNDARY.search(sentence)
    ]


def _adapter_text(route: dict[str, Any]) -> list[tuple[str, str]]:
    """Return (field, text) for every adapter-authored sentence source."""
    fields = [
        ("reason", route["reason"]),
        ("exact_claim", route["exact_claim"]),
        ("applicability.reason", route["applicability"]["reason"]),
    ]
    for entry in route["covered_admission_obligations"]:
        # Installed added-kind obligation text is installed authority, not an
        # adapter claim; only the adapter-owned SOURCE-0.1 proposition is scanned.
        if entry["obligation_id"].endswith("-SOURCE-0.1-installed-review-binding"):
            fields.append(("ledger.reason", entry["reason"]))
            fields.append(("ledger.claim_boundary", entry["claim_boundary"]))
    return fields


def test_boundary_guard_accepts_honest_negated_text_and_refuses_claims() -> None:
    good = (
        "It does not establish typed composition, which the package graph gate "
        "checks separately. Behavioral applicability remains an independent "
        "necessary or conditional route."
    )
    bad_composition = "This route preserves typed composition."
    bad_facets = "Its adapted Facets, Dynamics, and Statics require an exact review."
    bad_behavior = "This route establishes behavioral applicability for the object."
    assert _unbounded_claims(good) == []
    assert _unbounded_claims(bad_composition) == [bad_composition.rstrip(".")]
    assert _unbounded_claims(bad_facets) == [bad_facets.rstrip(".")]
    assert _unbounded_claims(bad_behavior) == [bad_behavior.rstrip(".")]


def test_every_source_route_text_states_no_unbounded_composition_or_behavior_claim() -> None:
    violations = []
    for route in contracts.catalog():
        for field, text in _adapter_text(route):
            for sentence in _unbounded_claims(text):
                violations.append((route["coordinate"], field, sentence))
    assert violations == []


def test_every_source_route_names_package_graph_composition_as_a_separate_gate() -> None:
    missing = [
        route["coordinate"] for route in contracts.catalog()
        if not any("package graph" in sentence and _BOUNDARY.search(sentence)
                   for sentence in _sentences(route["reason"]))
    ]
    assert missing == []


def test_every_source_route_keeps_behavioral_applicability_independent() -> None:
    missing = [
        route["coordinate"] for route in contracts.catalog()
        if not any("behavioral" in sentence.lower() and "independent" in sentence.lower()
                   for sentence in _sentences(route["reason"]))
    ]
    assert missing == []


def test_source_pass_result_states_its_boundary_without_composition_or_behavior_claims(
        monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    item, kinds, _declaration = _fixture(monkeypatch)
    assessment = contracts.SourceContractAssessment(tmp_path, (item,), kinds)
    route = next(row for row in contracts.catalog()
                 if row["object_kind"] == "OBJECT" and row["tier"] == 1)
    result = assessment.evaluate(item, route)
    assert result["status"] == "PASS"
    assert result["reason"] == route["exact_claim"]
    violations = [
        (field, sentence)
        for field in ("reason", "applicability_reason", "claim_boundary")
        for sentence in _unbounded_claims(result[field])
    ]
    assert violations == []
    assert any("package graph" in sentence and _BOUNDARY.search(sentence)
               for sentence in _sentences(result["claim_boundary"]))
