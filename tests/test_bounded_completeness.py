"""Adversarial bounded-completeness tests for Verifier Standard (VSTD).

JavaScript Object Notation (JSON), Secure Hash Algorithm 256-bit (SHA-256), and
identifier (ID) records here establish only finite, externally grounded disposition coverage.
"""

from __future__ import annotations

import json

import pytest

from verifier.interoperability import bounded_completeness as completeness
from verifier.interoperability import source_grounding as grounding


VOCABULARY_DIGEST = "sha256:" + "a" * 64
PRODUCER = "test:bounded-completeness-source-producer@0.1"


def _grounding(
    source: bytes,
    *,
    path: list[str],
    expected: object,
    proposition_id: str,
    evidence: dict[str, bytes],
) -> dict[str, str]:
    source_value = json.loads(source)
    declaration_value = {
        "assumptions": ["source uses the declared bounded vocabulary"],
        "certificate": {
            "certificate_kind": "DERIVATION",
            "digest": "sha256:" + "0" * 64,
            "size_bytes": 0,
        },
        "declarer_coordinate": "test:bounded-completeness-declarer@0.1",
        "ground_proposition": {
            "expected": expected,
            "path": path,
            "predicate": "JSON_POINTER_EQUALS",
            "proposition_id": proposition_id,
        },
        "interpretation": {
            "checker_coordinate": grounding.current_checker_coordinate().to_dict(),
            "mechanism_id": grounding.MECHANISM_ID,
            "mechanism_profile_digest": grounding.source_grounding_mechanism_profile_digest(),
            "profile_id": grounding.INTERPRETATION_PROFILE,
        },
        "schema_version": grounding.DECLARATION_SCHEMA,
        "semantic_frame": {
            "facets": sorted(source_value),
            "frame_id": "CANONICAL-JSON-OBJECT-0.1",
            "proposition_language": "CANONICAL_JSON_OBJECT",
            "vocabulary_digest": VOCABULARY_DIGEST,
        },
        "source": {
            "digest": grounding.digest_bytes(source),
            "size_bytes": len(source),
        },
    }
    provisional = grounding.decode_source_grounding_declaration(
        grounding.canonical_bytes(declaration_value)
    )
    certificate = grounding.expected_source_grounding_certificate(
        provisional, source, PRODUCER
    )
    declaration_value["certificate"] = {
        "certificate_kind": "DERIVATION",
        "digest": grounding.digest_bytes(certificate),
        "size_bytes": len(certificate),
    }
    declaration = grounding.canonical_bytes(declaration_value)
    grounding_evidence = {
        grounding.digest_bytes(source): source,
        grounding.digest_bytes(certificate): certificate,
    }
    receipt = grounding.build_source_grounding_receipt(
        declaration, grounding_evidence
    )
    declaration_digest = grounding.digest_bytes(declaration)
    receipt_digest = grounding.digest_bytes(receipt)
    evidence.update(grounding_evidence)
    evidence[declaration_digest] = declaration
    evidence[receipt_digest] = receipt
    ground_proposition_digest = grounding.digest_bytes(
        grounding.canonical_bytes(provisional.ground_proposition.to_dict())
    )
    return {
        "declaration_digest": declaration_digest,
        "ground_proposition_digest": ground_proposition_digest,
        "receipt_digest": receipt_digest,
        "source_digest": grounding.digest_bytes(source),
    }


def _fixture(
    *,
    omitted_member: str | None = None,
    profile_id: str = completeness.PROFILE_ID,
) -> tuple[bytes, dict[str, bytes], dict[str, dict[str, str]]]:
    evidence: dict[str, bytes] = {}
    first_source = grounding.canonical_bytes({"value": "ready"})
    second_source = grounding.canonical_bytes({"value": "stopped"})
    first = _grounding(
        first_source,
        path=["value"],
        expected="ready",
        proposition_id="first-is-ready",
        evidence=evidence,
    )
    second = _grounding(
        second_source,
        path=["value"],
        expected="ready",
        proposition_id="second-is-ready",
        evidence=evidence,
    )
    references = {"first": first, "second": second}
    denominator_record = {
        "members": [
            {
                "ground_proposition_digest": references[name]["ground_proposition_digest"],
                "grounding_declaration_digest": references[name]["declaration_digest"],
                "member_id": name,
            }
            for name in ("first", "second")
        ],
        "profile_id": profile_id,
        "schema_version": completeness.DENOMINATOR_SCHEMA,
        "subject_id": "test:finite-verification-surface",
    }
    denominator = completeness.canonical_bytes(denominator_record)
    census_digest = completeness.digest_bytes(
        completeness.canonical_bytes(
            {
                "members": denominator_record["members"],
                "subject_id": denominator_record["subject_id"],
            }
        )
    )
    external_census_source = grounding.canonical_bytes(
        {
            "member_census_digest": census_digest,
            "source_scope": "test:external-denominator-register",
        }
    )
    denominator_grounding = _grounding(
        external_census_source,
        path=["member_census_digest"],
        expected=census_digest,
        proposition_id="external-source-binds-denominator-census",
        evidence=evidence,
    )
    observations = completeness.canonical_bytes(
        {
            "denominator_digest": completeness.digest_bytes(denominator),
            "members": [
                {
                    "grounding_declaration_digest": references[name]["declaration_digest"],
                    "grounding_receipt_digest": references[name]["receipt_digest"],
                    "member_id": name,
                }
                for name in ("first", "second")
                if name != omitted_member
            ],
            "procedure_id": "source-grounding-replay-v1",
            "profile_id": profile_id,
            "schema_version": completeness.OBSERVATIONS_SCHEMA,
        }
    )
    evidence[completeness.digest_bytes(denominator)] = denominator
    evidence[completeness.digest_bytes(observations)] = observations
    declaration = completeness.canonical_bytes(
        {
            "declarer_coordinate": "test:bounded-completeness-declarer@0.1",
            "denominator": {
                "digest": completeness.digest_bytes(denominator),
                "size_bytes": len(denominator),
            },
            "denominator_grounding": {
                "declaration_digest": denominator_grounding["declaration_digest"],
                "ground_proposition_digest": denominator_grounding[
                    "ground_proposition_digest"
                ],
                "receipt_digest": denominator_grounding["receipt_digest"],
            },
            "observations": {
                "digest": completeness.digest_bytes(observations),
                "size_bytes": len(observations),
            },
            "profile_id": profile_id,
            "schema_version": completeness.DECLARATION_SCHEMA,
        }
    )
    references["denominator"] = denominator_grounding
    return declaration, evidence, references


def _rebind_observations(
    declaration: bytes, evidence: dict[str, bytes], record: dict[str, object]
) -> bytes:
    declaration_value = json.loads(declaration)
    evidence.pop(declaration_value["observations"]["digest"])
    observations = completeness.canonical_bytes(record)
    declaration_value["observations"] = {
        "digest": completeness.digest_bytes(observations),
        "size_bytes": len(observations),
    }
    evidence[completeness.digest_bytes(observations)] = observations
    return completeness.canonical_bytes(declaration_value)


def test_decisive_established_and_refuted_members_complete_the_finite_surface() -> None:
    declaration, evidence, _references = _fixture()

    receipt = completeness.assess_bounded_completeness(declaration, evidence)

    assert receipt.result is completeness.CompletenessResult.COMPLETE
    assert [item.grounding_result for item in receipt.member_assessments] == [
        "ESTABLISHED",
        "REFUTED",
    ]
    assert {item.disposition for item in receipt.member_assessments} == {"DISPOSED"}
    assert dict(receipt.effectiveness)["termination"] == "TERMINATED"
    assert "ABSOLUTE_UNIVERSE_NOT_ESTABLISHED" in receipt.residual_obligations


def test_missing_denominator_member_observation_is_incomplete() -> None:
    declaration, evidence, _references = _fixture(omitted_member="second")

    receipt = completeness.assess_bounded_completeness(declaration, evidence)

    assert receipt.result is completeness.CompletenessResult.INCOMPLETE
    assert dict(receipt.checks)["member_binding"] == "INCOMPLETE"
    assert receipt.member_assessments[1].disposition == "NOT_CHECKED"


def test_missing_member_receipt_cannot_be_counted_as_a_disposition() -> None:
    declaration, evidence, references = _fixture()
    evidence.pop(references["second"]["receipt_digest"])

    receipt = completeness.assess_bounded_completeness(declaration, evidence)

    assert receipt.result is completeness.CompletenessResult.INCOMPLETE
    assert receipt.member_assessments[1].grounding_result == "UNKNOWN"
    assert "GROUNDING_BYTES_MISSING" in receipt.reason_codes


def test_missing_external_denominator_grounding_keeps_scope_unknown() -> None:
    declaration, evidence, references = _fixture()
    evidence.pop(references["denominator"]["receipt_digest"])

    receipt = completeness.assess_bounded_completeness(declaration, evidence)

    assert receipt.result is completeness.CompletenessResult.UNKNOWN
    assert dict(receipt.checks)["denominator_grounding"] == "UNKNOWN"


def test_substituted_member_source_is_invalid() -> None:
    declaration, evidence, references = _fixture()
    evidence[references["first"]["source_digest"]] += b" "

    receipt = completeness.assess_bounded_completeness(declaration, evidence)

    assert receipt.result is completeness.CompletenessResult.INVALID
    assert receipt.member_assessments[0].grounding_result == "INVALID"


def test_observation_cannot_substitute_another_members_declaration() -> None:
    declaration, evidence, references = _fixture()
    record = json.loads(evidence[json.loads(declaration)["observations"]["digest"]])
    record["members"][0]["grounding_declaration_digest"] = references["second"][
        "declaration_digest"
    ]
    observations = completeness.canonical_bytes(record)
    declaration_value = json.loads(declaration)
    old_digest = declaration_value["observations"]["digest"]
    evidence.pop(old_digest)
    declaration_value["observations"] = {
        "digest": completeness.digest_bytes(observations),
        "size_bytes": len(observations),
    }
    evidence[completeness.digest_bytes(observations)] = observations

    receipt = completeness.assess_bounded_completeness(
        completeness.canonical_bytes(declaration_value), evidence
    )

    assert receipt.result is completeness.CompletenessResult.INVALID
    assert receipt.member_assessments[0].disposition == "INVALID"


def test_unsupported_profile_remains_unknown_even_with_exact_bytes() -> None:
    declaration, evidence, _references = _fixture(profile_id="unregistered-profile")

    receipt = completeness.assess_bounded_completeness(declaration, evidence)

    assert receipt.result is completeness.CompletenessResult.UNKNOWN
    assert "PROFILE_UNSUPPORTED" in receipt.reason_codes


def test_evidence_budget_exhaustion_is_unknown_not_complete(monkeypatch: pytest.MonkeyPatch) -> None:
    declaration, evidence, _references = _fixture()
    monkeypatch.setattr(completeness, "MAX_EVIDENCE_BYTES", 9_000)

    receipt = completeness.assess_bounded_completeness(declaration, evidence)

    assert receipt.result is completeness.CompletenessResult.UNKNOWN
    assert dict(receipt.checks)["denominator_binding"] == "BOUND"
    assert "EVIDENCE_BUDGET_EXHAUSTED" in receipt.reason_codes


@pytest.mark.parametrize("remove_expected", [False, True])
def test_extra_observation_member_is_invalid_not_ignored(remove_expected: bool) -> None:
    declaration, evidence, references = _fixture()
    record = json.loads(evidence[json.loads(declaration)["observations"]["digest"]])
    if remove_expected:
        record["members"].pop()
    record["members"].append(
        {
            "grounding_declaration_digest": references["first"]["declaration_digest"],
            "grounding_receipt_digest": references["first"]["receipt_digest"],
            "member_id": "third",
        }
    )
    rebound = _rebind_observations(declaration, evidence, record)

    receipt = completeness.assess_bounded_completeness(rebound, evidence)

    assert receipt.result is completeness.CompletenessResult.INVALID
    assert dict(receipt.checks)["member_binding"] == "INVALID"
    assert dict(receipt.checks)["member_recheck"] == "INVALID"
    assert "OBSERVATION_MEMBER_OUTSIDE_DENOMINATOR" in receipt.reason_codes


def test_denominator_grounding_must_bind_external_exact_census() -> None:
    declaration, evidence, _references = _fixture()
    denominator = evidence[json.loads(declaration)["denominator"]["digest"]]
    weak = _grounding(
        denominator,
        path=["profile_id"],
        expected=completeness.PROFILE_ID,
        proposition_id="weak-profile-only-grounding",
        evidence=evidence,
    )
    declaration_value = json.loads(declaration)
    declaration_value["denominator_grounding"] = {
        "declaration_digest": weak["declaration_digest"],
        "ground_proposition_digest": weak["ground_proposition_digest"],
        "receipt_digest": weak["receipt_digest"],
    }

    receipt = completeness.assess_bounded_completeness(
        completeness.canonical_bytes(declaration_value), evidence
    )

    assert receipt.result is completeness.CompletenessResult.INVALID
    assert "DENOMINATOR_GROUNDING_CIRCULAR" in receipt.reason_codes


def test_external_grounding_of_an_unrelated_field_cannot_establish_census() -> None:
    declaration, evidence, _references = _fixture()
    external = grounding.canonical_bytes(
        {"member_census_digest": "sha256:" + "0" * 64, "source_scope": "wrong"}
    )
    weak = _grounding(
        external,
        path=["source_scope"],
        expected="wrong",
        proposition_id="unrelated-source-field",
        evidence=evidence,
    )
    declaration_value = json.loads(declaration)
    declaration_value["denominator_grounding"] = {
        "declaration_digest": weak["declaration_digest"],
        "ground_proposition_digest": weak["ground_proposition_digest"],
        "receipt_digest": weak["receipt_digest"],
    }

    receipt = completeness.assess_bounded_completeness(
        completeness.canonical_bytes(declaration_value), evidence
    )

    assert receipt.result is completeness.CompletenessResult.INVALID
    assert "DENOMINATOR_CENSUS_PROPOSITION_INVALID" in receipt.reason_codes


def test_denominator_member_bound_is_enforced_before_assessment() -> None:
    members = [
        {
            "ground_proposition_digest": f"sha256:{index:064x}",
            "grounding_declaration_digest": f"sha256:{index + 1000:064x}",
            "member_id": f"member-{index:03d}",
        }
        for index in range(completeness.MAX_MEMBERS + 1)
    ]
    data = completeness.canonical_bytes(
        {
            "members": members,
            "profile_id": completeness.PROFILE_ID,
            "schema_version": completeness.DENOMINATOR_SCHEMA,
            "subject_id": "over-limit",
        }
    )

    with pytest.raises(completeness.BoundedCompletenessError):
        completeness._denominator(data)


def test_noncanonical_or_extended_declarations_fail_closed() -> None:
    declaration, _evidence, _references = _fixture()
    with pytest.raises(completeness.BoundedCompletenessError):
        completeness.decode_bounded_completeness_declaration(declaration + b" ")
    extended = json.loads(declaration)
    extended["asserted_complete"] = True
    with pytest.raises(completeness.BoundedCompletenessError):
        completeness.decode_bounded_completeness_declaration(
            completeness.canonical_bytes(extended)
        )
    with pytest.raises(completeness.BoundedCompletenessError):
        completeness.decode_bounded_completeness_declaration(
            b'{"declarer_coordinate":"\\ud800"}'
        )


@pytest.mark.parametrize(
    ("mutation", "value"),
    [
        (("checks", "denominator_grounding"), "REFUTED"),
        (("profile_id",), "vstd.bounded-completeness.unsupported"),
        (("reason_codes",), ["EVIDENCE_BUDGET_EXHAUSTED"]),
        (("effectiveness", "bytes_retained"), 0),
    ],
)
def test_structural_receipt_decode_rejects_contradictory_complete_state(
    mutation: tuple[str, ...], value: object
) -> None:
    declaration, evidence, _references = _fixture()
    forged = json.loads(
        completeness.build_bounded_completeness_receipt(declaration, evidence)
    )
    target = forged
    for key in mutation[:-1]:
        target = target[key]
    target[mutation[-1]] = value

    with pytest.raises(completeness.BoundedCompletenessError):
        completeness.decode_bounded_completeness_receipt(
            completeness.canonical_bytes(forged)
        )


def test_receipt_recheck_rejects_a_relabelled_result() -> None:
    declaration, evidence, _references = _fixture()
    receipt = completeness.build_bounded_completeness_receipt(declaration, evidence)
    forged = json.loads(receipt)
    forged["result"] = "INCOMPLETE"

    with pytest.raises(completeness.BoundedCompletenessError):
        completeness.recheck_bounded_completeness_receipt(
            declaration, completeness.canonical_bytes(forged), evidence
        )


def test_receipt_round_trip_is_exact_and_deterministic() -> None:
    declaration, evidence, _references = _fixture()
    first = completeness.build_bounded_completeness_receipt(declaration, evidence)
    second = completeness.build_bounded_completeness_receipt(
        declaration, dict(reversed(list(evidence.items())))
    )

    assert first == second
    assert completeness.recheck_bounded_completeness_receipt(
        declaration, first, evidence
    ).result is completeness.CompletenessResult.COMPLETE
