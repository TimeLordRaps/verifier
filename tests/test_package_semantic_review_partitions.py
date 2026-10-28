# Terminology: abstract syntax tree (AST).
from __future__ import annotations

import ast
from copy import deepcopy
from dataclasses import replace
import hashlib
from pathlib import Path
import re

import pytest

from verifier.runtime.namespace_contracts import namespace_registry, requirements_for
from verifier.runtime import package_semantic_ownership as ownership
from verifier.runtime import package_semantic_review_partitions as review
from verifier.runtime import package_semantic_review_verifier as verifier_review


ROOT = Path(__file__).parents[1]
SELF_PATH = "tests/test_package_semantic_review_partitions.py"
DERIVED_INVENTORY_PATHS = {
    SELF_PATH,
    "tests/test_package_semantic_ownership_tests_fixtures.py",
}
EXPECTED_COUNTS = {
    "objects": 319,
    "paths": 1551,
    "decisions": 3828,
    "applies": 863,
    "refuted": 2965,
    "unresolved": 0,
    "declarations": 2589,
    "declaration_fields": 10491,
}
STATUS_LITERALS = {"APPLIES", "DOES_NOT_APPLY", "UNRESOLVED"}
SOURCE_AUDITED_APPLIES: set[tuple[str, str]] = {
    ("vstd-domain-grounding-specimen", "FINBOT"),
    ("vstd-agency-surface-crosswalk-assets", "ACTUATOR"),
    ("vstd-agency-surface-crosswalk-assets", "ASSET"),
    ("vstd-agency-surface-crosswalk-assets", "CONTROLLER"),
    ("vstd-agency-surface-crosswalk-assets", "FINBOT"),
    ("vstd-agency-surface-crosswalk-assets", "LEDGER"),
    ("vstd-agency-surface-crosswalk-assets", "MARKET"),
    ("vstd-agency-surface-crosswalk-assets", "MEASUREMENT"),
    ("vstd-agency-surface-crosswalk-assets", "ROBOT"),
    ("vstd-agency-surface-crosswalk-assets", "SENSOR"),
    ("vstd-agency-surface-crosswalk-assets", "TRANSACTION"),
}
UNCHECKED_EXTERNAL_CALLABLE_CELLS = {
    ("vstd-provider-control-plane-evidence-protocol", "ACTUATOR"),
    ("vstd-hardware-attestation-verifier", "ACTUATOR"),
    ("vstd-hardware-accounting-continuity-ledger", "ACTUATOR"),
    ("vstd-hardware-provenance-graph-attachment", "ACTUATOR"),
    ("vstd-hardware-receipt-validator", "ACTUATOR"),
    ("vstd-retained-selection-policy", "ACTUATOR"),
    ("vstd-retained-execution-measurement", "ACTUATOR"),
    ("vstd-sim-host-time-mapping-verifier", "ACTUATOR"),
}
EXPOSED_EFFECT_ROUTE_CELLS = {
    ("vstd-hardware-public-api", "ACTUATOR"),
}
OBLIGATION_RETENTION_APPLIES = (
    UNCHECKED_EXTERNAL_CALLABLE_CELLS | EXPOSED_EFFECT_ROUTE_CELLS
)


def _digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _files() -> dict[str, str]:
    return {
        path: _digest(ROOT / path)
        for spec in review.PARTITION_SPECS
        for path in spec.owned_paths
    }


def _rows() -> dict[str, dict]:
    return {
        spec.object_id: {
            "object_id": spec.object_id,
            "kind": spec.primary_kind,
            # This reviewer owns only the twelve added consequence kinds.  In
            # a migrated package row the retained-kind labels already come
            # from semantic ownership installation and must be preserved.
            "specializations": [
                kind
                for kind in spec.specializations
                if kind not in review.REVIEW_KINDS
            ],
            "operands": {
                name: list(targets) for name, targets in spec.operands
            },
            "surfaces": ["file:" + path for path in spec.owned_paths],
            "classification": {},
            "obligations": {},
        }
        for spec in review.PARTITION_SPECS
    }


def _requirements() -> dict[str, dict[str, tuple[str, ...]]]:
    registry = namespace_registry()
    return {
        kind: {
            item["id"]: tuple(item["declaration_fields"])
            for item in requirements_for(registry, (kind,))
            if item["kind"] == kind
        }
        for kind in review.REVIEW_KINDS
    }


def _sha256(lines: list[str]) -> str:
    return hashlib.sha256("\n".join(sorted(lines)).encode("utf-8")).hexdigest()


def _normalized_source(path: str) -> bytes:
    """Remove mutually derived inventory values from the source-byte question."""
    content = (ROOT / path).read_bytes()
    if path in DERIVED_INVENTORY_PATHS:
        content, substitutions = re.subn(
            rb'EXPECTED_SOURCE_INVENTORY_DIGEST = "[0-9a-f]{64}"',
            b'EXPECTED_SOURCE_INVENTORY_DIGEST = "<self-normalized>"',
            content,
            count=1,
        )
        assert substitutions == 1
    return content


def _applicable_kinds(spec) -> set[str]:
    """Explicit labels and source-bound APPLIES root decisions only."""
    return {
        kind
        for kind in review.REVIEW_KINDS
        if kind == spec.primary_kind
        or kind in spec.specializations
        or any(
            decision.kind == kind and decision.status == "APPLIES"
            for decision in spec.root_role_decisions
        )
        or (spec.object_id, kind) in SOURCE_AUDITED_APPLIES
        or (spec.object_id, kind) in OBLIGATION_RETENTION_APPLIES
    }


def _expected_status(spec, kind: str) -> str:
    """Independent oracle: label first, then literal refutation, else UNRESOLVED."""
    if kind in _applicable_kinds(spec):
        return "APPLIES"
    if (spec.object_id, kind) in review._REFUTATIONS:
        return "DOES_NOT_APPLY"
    return "UNRESOLVED"


def _evidence(spec, files: dict[str, str]) -> list[dict[str, str]]:
    return [{"path": path, "sha256": files[path]} for path in spec.owned_paths]


def _violations(source: str) -> list[str]:
    """Flag status ternaries and set/membership complements over applicability."""
    found = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.IfExp):
            branches = {_literal(node.body), _literal(node.orelse)}
            if "APPLIES" in branches and branches & {"DOES_NOT_APPLY", "UNRESOLVED"}:
                found.append(f"line {node.lineno}: status ternary")
        if isinstance(node, ast.Compare) and any(
            isinstance(op, ast.NotIn) for op in node.ops
        ):
            if any("applicable" in ast.unparse(item) for item in node.comparators):
                found.append(f"line {node.lineno}: not-in applicable complement")
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            operand = node.operand
            if (
                isinstance(operand, ast.Compare)
                and any(isinstance(op, ast.In) for op in operand.ops)
                and any("applicable" in ast.unparse(item) for item in operand.comparators)
            ):
                found.append(f"line {node.lineno}: negated applicable membership")
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Sub):
            text = ast.unparse(node)
            if "applicable" in text or "REVIEW_KINDS" in text:
                found.append(f"line {node.lineno}: set complement over kinds")
        if isinstance(node, ast.If) and "applicable" in ast.unparse(node.test):
            body = _status_literals(node.body)
            orelse = _status_literals(node.orelse)
            if body and orelse and len(body | orelse) > 1:
                found.append(f"line {node.lineno}: statement complement")
    return found


def _literal(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _status_literals(statements: list[ast.stmt]) -> set[str]:
    found: set[str] = set()
    for statement in statements:
        for node in ast.walk(statement):
            value = _literal(node)
            if value in STATUS_LITERALS:
                found.add(value)
    return found


def test_review_document_closes_the_exact_partition_denominator() -> None:
    first = review.review_document()
    second = review.review_document()
    assert first == second
    assert first is not second
    assert review.review_counts() == EXPECTED_COUNTS
    assert len(review.PARTITION_OBJECT_IDS) == 319 == len(set(review.PARTITION_OBJECT_IDS))
    assert tuple(first) == review.PARTITION_OBJECT_IDS

    contracts = _requirements()
    for spec in review.PARTITION_SPECS:
        item = first[spec.object_id]
        assert item["primary_kind"] == spec.primary_kind
        assert item["owned_paths"] == list(spec.owned_paths)
        assert set(item["classification"]) == set(review.REVIEW_KINDS)
        applicable = _applicable_kinds(spec)
        assert {
            kind
            for kind, decision in item["classification"].items()
            if decision["status"] == "APPLIES"
        } == applicable
        for kind, decision in item["classification"].items():
            expected = _expected_status(spec, kind)
            assert decision["status"] == expected
            assert decision["reason"].strip()
            assert spec.object_id in decision["reason"]
            if expected == "UNRESOLVED":
                assert decision["evidence_paths"] == []
            else:
                assert decision["evidence_paths"] == list(spec.owned_paths)
            if expected == "DOES_NOT_APPLY":
                assert review._source_denominator(spec) in decision["reason"]
                assert spec.representation_role in decision["reason"]
                assert spec.necessity_reason in decision["reason"]
                assert spec.consequence_boundary in decision["reason"]
                assert review._KIND_SPECIFIC_ABSENCE[kind] in decision["reason"]

        expected = {
            obligation_id: fields
            for kind in applicable
            for obligation_id, fields in contracts[kind].items()
        }
        assert set(item["declarations"]) == set(expected)
        for obligation_id, declaration in item["declarations"].items():
            assert set(declaration) == set(expected[obligation_id])
            for value in declaration.values():
                assert value.strip()
                assert len(value) <= 8192
                assert spec.object_id in value
                assert review._declaration_basis(spec) in value
                assert review._declaration_basis_digest(spec) in value
                assert review._source_denominator(spec) in value

    large = next(
        spec
        for spec in review.PARTITION_SPECS
        if spec.object_id == "vstd-retained-typed-facet-requests"
    )
    summary = review._source_denominator(large)
    assert summary.startswith(str(len(large.owned_paths)) + " exact paths bound by sha256:")
    assert "complete current path/digest denominator is carried by evidence" in summary

    first[review.PARTITION_OBJECT_IDS[0]]["declarations"].clear()
    assert review.review_document() == second


def test_inline_source_denominator_is_short_and_longer_lists_are_digest_bound() -> None:
    """Keep the receipt inside its 32 MiB invariant without dropping any path.

    Every reason and declaration repeats the denominator text, so a long inline path list
    is multiplied by the object's hundreds of fields.  Lists above the short threshold use
    the digest form; the exact path and digest list stays carried by each cell's evidence.
    """

    assert review.MAX_INLINE_SOURCE_DENOMINATOR_CHARS == 512
    short = medium = None
    for spec in review.PARTITION_SPECS:
        joined = ", ".join(spec.owned_paths)
        if len(joined) <= 512 and short is None:
            short = spec
        if 512 < len(joined) <= 2_048 and medium is None:
            medium = spec
    assert short is not None and medium is not None
    assert review._source_denominator(short) == ", ".join(short.owned_paths)
    digest = hashlib.sha256(
        "\n".join(medium.owned_paths).encode("utf-8")
    ).hexdigest()
    assert review._source_denominator(medium) == (
        str(len(medium.owned_paths)) + " exact paths bound by sha256:" + digest
        + "; the complete current path/digest denominator is carried by evidence"
    )


def test_compact_declaration_basis_binds_every_full_semantic_dimension() -> None:
    spec = review._SPECS["vstd-agency-surface-crosswalk-assets"]
    variants = (
        spec,
        replace(spec, representation_role=spec.representation_role + " changed"),
        replace(spec, necessity_reason=spec.necessity_reason + " changed"),
        replace(spec, consequence_boundary=spec.consequence_boundary + " changed"),
        replace(spec, owned_paths=("src/verifier/standard/VSTD-1.md",)),
        replace(spec, operands=(("subject", ("vstd-package-object",)),)),
    )
    digests = {review._declaration_basis_digest(item) for item in variants}
    assert len(digests) == len(variants)
    assert all(re.fullmatch(r"sha256:[0-9a-f]{64}", digest) for digest in digests)

    document = review.review_document()[spec.object_id]
    assert len(str(document).encode("utf-8")) < 85_000
    for declaration in document["declarations"].values():
        assert all(
            review._declaration_basis(spec) in value
            for value in declaration.values()
        )


def test_logits_feedback_is_a_central_controller_role() -> None:
    assert {
        (object_id, kind)
        for object_id, kind, _reason in review.SOURCE_AUDITED_APPLICABILITY_BASIS
    } == SOURCE_AUDITED_APPLIES
    spec = review._SPECS["vstd-logits-constraint-harness"]
    assert "CONTROLLER" in spec.specializations
    item = review.review_document()["vstd-logits-constraint-harness"]
    decision = item["classification"]["CONTROLLER"]
    assert decision["status"] == "APPLIES"
    assert decision["evidence_paths"] == [
        "examples/logits_constraint_kernel/README.md",
        "examples/logits_constraint_kernel/demo.py",
        "examples/logits_constraint_kernel/trace.json",
    ]
    assert "mask_logits" in decision["reason"]
    assert "accept_token" in decision["reason"]
    assert {
        name for name in item["declarations"] if name.startswith("CONTROLLER-")
    } == set(_requirements()["CONTROLLER"])


def test_apply_populates_exact_current_evidence_decisions_and_declarations() -> None:
    files = _files()
    rows = _rows()
    original = deepcopy(rows)
    result = review.apply_package_semantic_review_partitions(ROOT, rows, files)
    assert rows == original
    assert result is not rows

    contracts = _requirements()
    decision_count = declaration_count = declaration_field_count = 0
    unresolved_count = 0
    for spec in review.PARTITION_SPECS:
        row = result[spec.object_id]
        applicable = _applicable_kinds(spec)
        assert set(row["classification"]) == set(review.REVIEW_KINDS)
        assert set(row["specializations"]) == set(spec.specializations) | {
            kind
            for object_id, kind in (
                SOURCE_AUDITED_APPLIES | OBLIGATION_RETENTION_APPLIES
            )
            if object_id == spec.object_id and kind != spec.primary_kind
        }
        for kind, decision in row["classification"].items():
            decision_count += 1
            expected = _expected_status(spec, kind)
            assert decision["status"] == expected
            if expected == "UNRESOLVED":
                unresolved_count += 1
                assert decision["evidence"] == []
            else:
                assert decision["evidence"] == _evidence(spec, files)

        expected = {
            obligation_id: fields
            for kind in applicable
            for obligation_id, fields in contracts[kind].items()
        }
        assert set(row["obligations"]) == set(expected)
        for obligation_id, binding in row["obligations"].items():
            declaration_count += 1
            declaration_field_count += len(binding["declaration"])
            assert set(binding["declaration"]) == set(expected[obligation_id])
            assert all(value.strip() for value in binding["declaration"].values())
            assert binding["evidence"] == _evidence(spec, files)
            assert "mechanism execution" in binding["reason"]

    assert decision_count == EXPECTED_COUNTS["decisions"]
    assert unresolved_count == EXPECTED_COUNTS["unresolved"]
    assert declaration_count == EXPECTED_COUNTS["declarations"]
    assert declaration_field_count == EXPECTED_COUNTS["declaration_fields"]


def test_unknown_future_object_and_kind_remain_canonical_unresolved() -> None:
    current = review.PARTITION_SPECS[0]
    future = replace(current, object_id="vstd-future-unreviewed-partition")
    current_review = review._REVIEWS[current.object_id]
    kind = next(
        item for item in review.REVIEW_KINDS if item not in current_review.applicable
    )

    status, reason, paths = review._cell(future, current_review, kind)
    assert status == "UNRESOLVED"
    assert paths == ()
    assert "no literal per-object refutation basis is authored" in reason
    assert future.object_id in reason

    status, reason, paths = review._cell(
        current, current_review, "FUTURE_CONSEQUENCE_KIND"
    )
    assert status == "UNRESOLVED"
    assert paths == ()
    assert "FUTURE_CONSEQUENCE_KIND" in reason


def test_unresolved_inventory_is_the_exact_missing_review_denominator() -> None:
    inventory = review.unresolved_inventory()
    assert tuple(inventory) == review.PARTITION_OBJECT_IDS
    total = 0
    for spec in review.PARTITION_SPECS:
        expected = tuple(
            kind
            for kind in review.REVIEW_KINDS
            if _expected_status(spec, kind) == "UNRESOLVED"
        )
        assert inventory[spec.object_id] == expected
        total += len(expected)
    assert total == EXPECTED_COUNTS["unresolved"]


def test_unchecked_external_callables_retain_obligations_without_effect_contract() -> None:
    basis = {
        (object_id, kind): reason
        for object_id, kind, reason in review.UNCHECKED_EXTERNAL_CALLABLE_BASIS
    }
    assert set(basis) == UNCHECKED_EXTERNAL_CALLABLE_CELLS
    assert {
        (object_id, kind)
        for object_id, kind, _reason in (
            review.OBLIGATION_RETENTION_APPLICABILITY_BASIS
        )
    } == OBLIGATION_RETENTION_APPLIES
    document = review.review_document()

    for object_id, kind in sorted(UNCHECKED_EXTERNAL_CALLABLE_CELLS):
        assert (object_id, kind) not in review._REFUTATIONS
        decision = document[object_id]["classification"][kind]
        assert decision["status"] == "APPLIES"
        assert object_id in decision["reason"]
        assert kind in decision["reason"]
        assert basis[(object_id, kind)] in decision["reason"]
        assert "sole authored reasons.vstd" in decision["reason"]
        assert "external effect occurred" in decision["reason"]


def test_public_export_route_retains_obligation_without_claiming_reachable_effect() -> None:
    basis = {
        (object_id, kind): reason
        for object_id, kind, reason in review.EXPOSED_EFFECT_ROUTE_BASIS
    }
    assert set(basis) == EXPOSED_EFFECT_ROUTE_CELLS
    document = review.review_document()

    for object_id, kind in sorted(EXPOSED_EFFECT_ROUTE_CELLS):
        assert (object_id, kind) not in review._REFUTATIONS
        decision = document[object_id]["classification"][kind]
        assert decision["status"] == "APPLIES"
        assert basis[(object_id, kind)] in decision["reason"]
        assert "sole authored reasons.vstd" in decision["reason"]
        assert "external effect occurred" in decision["reason"]


def test_refutation_catalog_rejects_non_literal_overlapping_or_generic_entries() -> None:
    object_id = "vstd-hardware-evidence-records"
    spec = review._SPECS[object_id]
    assert "ASSET" in _applicable_kinds(spec)
    assert "FINBOT" not in _applicable_kinds(spec)
    reason = review._refutation_reason(spec, "FINBOT")
    valid = ((object_id, "FINBOT", reason),)
    assert review._validated_refutations(valid) == {(object_id, "FINBOT"): reason}
    assert review._validated_refutations(review.REFUTATION_BASIS) == review._REFUTATIONS
    assert review._expand_literal_refutations(
        ((object_id, ("FINBOT",)),)
    ) == valid

    other = next(item for item in review.PARTITION_SPECS if item.object_id != object_id)
    substituted = review._refutation_reason(other, "FINBOT")

    rejected = [
        valid + valid,
        (("missing-object", "FINBOT", "missing-object FINBOT is refuted."),),
        ((object_id, "BOT", object_id + " BOT is refuted."),),
        ((object_id, "ASSET", object_id + " ASSET is refuted."),),
        ((object_id, "FINBOT", substituted),),
        ((object_id, "FINBOT", "not applicable"),),
        ((object_id, "FINBOT"),),
        ((object_id, "FINBOT", ""),),
        (
            (
                "vstd-hardware-attestation-verifier",
                "ACTUATOR",
                review._refutation_reason(
                    review._SPECS["vstd-hardware-attestation-verifier"],
                    "ACTUATOR",
                ),
            ),
        ),
        (
            (
                "vstd-hardware-public-api",
                "ACTUATOR",
                review._refutation_reason(
                    review._SPECS["vstd-hardware-public-api"],
                    "ACTUATOR",
                ),
            ),
        ),
    ]
    for entries in rejected:
        with pytest.raises(AssertionError):
            review._validated_refutations(entries)

    rejected_assignments = [
        ((object_id, ("FINBOT",)), (object_id, ("ROBOT",))),
        (("missing-object", ("FINBOT",)),),
        ((object_id, ("FINBOT", "FINBOT")),),
        ((object_id, ("BOT",)),),
        ((object_id, ("ASSET",)),),
        ((object_id, ["FINBOT"]),),
        (("vstd-hardware-attestation-verifier", ("ACTUATOR",)),),
        (("vstd-hardware-public-api", ("ACTUATOR",)),),
    ]
    for assignments in rejected_assignments:
        with pytest.raises(AssertionError):
            review._expand_literal_refutations(assignments)


def test_only_explicit_literal_refutation_yields_does_not_apply(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    object_id = "vstd-hardware-evidence-records"
    reason = review._refutation_reason(review._SPECS[object_id], "FINBOT")
    monkeypatch.setattr(
        review,
        "_REFUTATIONS",
        review._validated_refutations(((object_id, "FINBOT", reason),)),
    )
    files = _files()
    result = review.apply_package_semantic_review_partitions(ROOT, _rows(), files)
    spec = review._SPECS[object_id]

    finbot = result[object_id]["classification"]["FINBOT"]
    assert finbot["status"] == "DOES_NOT_APPLY"
    assert finbot["reason"].startswith(reason)
    assert finbot["evidence"] == _evidence(spec, files)
    assert result[object_id]["classification"]["ROBOT"]["status"] == "UNRESOLVED"

    other = next(
        identifier
        for identifier in result
        if identifier not in {object_id, "vstd-domain-grounding-specimen"}
    )
    assert result[other]["classification"]["FINBOT"]["status"] == "UNRESOLVED"
    assert (
        result["vstd-domain-grounding-specimen"]["classification"]["FINBOT"][
            "status"
        ]
        == "APPLIES"
    )
    assert review.review_counts()["refuted"] == 1
    # Replacing the fixed refutation map with one literal refutation reopens
    # every other refuted cell, but the nine exact demand-only cells remain
    # source-owned APPLIES decisions rather than becoming unresolved.
    assert review.review_counts()["unresolved"] == 2_964


def test_refuted_cell_rejects_nonblank_declarations_and_removes_blank_ones(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    object_id = "vstd-hardware-evidence-records"
    spec = review._SPECS[object_id]
    contracts = _requirements()
    kind = next(
        kind
        for kind in review.REVIEW_KINDS
        if kind not in _applicable_kinds(spec) and contracts[kind]
    )
    obligation_id, fields = next(iter(contracts[kind].items()))
    reason = review._refutation_reason(spec, kind)
    monkeypatch.setattr(
        review,
        "_REFUTATIONS",
        review._validated_refutations(((object_id, kind, reason),)),
    )
    files = _files()
    rows = review.apply_package_semantic_review_partitions(ROOT, _rows(), files)
    assert obligation_id not in rows[object_id]["obligations"]

    filled = deepcopy(rows)
    filled[object_id]["obligations"][obligation_id] = {
        "reason": "Prior non-blank declaration without applicability.",
        "evidence": [],
        "declaration": {field: "x" for field in fields},
    }
    with pytest.raises(
        ValueError, match="PACKAGE_SEMANTIC_REVIEW_REFUTED_DECLARATION_CONFLICT:"
    ):
        review.apply_package_semantic_review_partitions(ROOT, filled, files)

    blank = deepcopy(rows)
    blank[object_id]["obligations"][obligation_id] = {
        "reason": "",
        "evidence": [],
        "declaration": {field: "" for field in fields},
    }
    cleaned = review.apply_package_semantic_review_partitions(ROOT, blank, files)
    assert obligation_id not in cleaned[object_id]["obligations"]


def test_refuted_or_unresolved_labels_conflict_with_the_classification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    object_id = "vstd-hardware-evidence-records"
    spec = review._SPECS[object_id]
    refuted = "FINBOT"
    monkeypatch.setattr(
        review,
        "_REFUTATIONS",
        review._validated_refutations(
            ((object_id, refuted, review._refutation_reason(spec, refuted)),)
        ),
    )
    unresolved = next(
        kind
        for kind in review.REVIEW_KINDS
        if kind not in _applicable_kinds(spec) and kind != refuted
    )
    for label in (refuted, unresolved):
        rows = _rows()
        rows[object_id]["specializations"].append(label)
        with pytest.raises(
            ValueError,
            match="PACKAGE_SEMANTIC_REVIEW_LABEL_CONFLICT:" + object_id + ":" + label,
        ):
            review.apply_package_semantic_review_partitions(ROOT, rows, _files())


@pytest.mark.parametrize(
    "failure",
    [
        "refuted_other_reason",
        "refuted_other_object_reason",
        "refuted_other_object_evidence",
        "refuted_as_applies",
        "applies_other_reason",
        "partial_evidence",
        "duplicate_evidence",
        "unowned_evidence",
        "stale_row_evidence",
    ],
)
def test_same_status_other_reason_or_evidence_is_not_preserved_authority(
    failure: str,
) -> None:
    files = _files()
    object_id = next(
        spec.object_id
        for spec in review.PARTITION_SPECS
        if len(spec.owned_paths) > 1 and _applicable_kinds(spec)
    )
    rows = review.apply_package_semantic_review_partitions(ROOT, _rows(), files)
    classification = rows[object_id]["classification"]
    applies = next(kind for kind, cell in classification.items() if cell["status"] == "APPLIES")
    refuted = next(
        kind for kind, cell in classification.items() if cell["status"] == "DOES_NOT_APPLY"
    )
    evidence = classification[applies]["evidence"]
    other = next(spec for spec in review.PARTITION_SPECS if spec.object_id != object_id)
    if failure == "refuted_other_reason":
        classification[refuted]["reason"] = "Custom same-status refutation."
    elif failure == "refuted_other_object_reason":
        classification[refuted]["reason"] = review._reason(
            other, review._REVIEWS[other.object_id], refuted
        )
    elif failure == "refuted_other_object_evidence":
        classification[refuted]["evidence"] = _evidence(other, files)
    elif failure == "refuted_as_applies":
        classification[refuted]["status"] = "APPLIES"
    elif failure == "applies_other_reason":
        classification[applies]["reason"] = "Prior custom reason for the same status."
    elif failure == "partial_evidence":
        classification[applies]["evidence"] = deepcopy(evidence[:-1])
    elif failure == "duplicate_evidence":
        classification[applies]["evidence"] = deepcopy(evidence + evidence[:1])
    elif failure == "unowned_evidence":
        changed = deepcopy(evidence)
        changed[0]["path"] = "src/verifier/unowned_source.py"
        classification[applies]["evidence"] = changed
    else:
        changed = deepcopy(evidence)
        changed[0]["sha256"] = "sha256:" + "0" * 64
        classification[applies]["evidence"] = changed
    before = deepcopy(rows)
    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_"):
        review.apply_package_semantic_review_partitions(ROOT, rows, files)
    assert rows == before


def test_apply_is_atomic_idempotent_and_stable_under_reapplication() -> None:
    files = _files()
    once = review.apply_package_semantic_review_partitions(ROOT, _rows(), files)
    twice = review.apply_package_semantic_review_partitions(ROOT, once, files)
    assert twice == once
    assert review.apply_package_semantic_review_partitions(ROOT, deepcopy(once), files) == once


def test_apply_preserves_exact_complete_declarations_across_reapply() -> None:
    files = _files()
    result = review.apply_package_semantic_review_partitions(ROOT, _rows(), files)
    object_id = "vstd-hardware-evidence-records"
    item = result[object_id]
    obligation_id = "ASSET-0.1-identity-and-quantity"
    custom_binding = deepcopy(item["obligations"][obligation_id])
    custom_binding["reason"] = "Prior complete compatible current-byte declaration."
    custom_binding["declaration"] = {
        field: "Prior object-specific current-byte declaration for " + field + "."
        for field in custom_binding["declaration"]
    }
    item["obligations"][obligation_id] = deepcopy(custom_binding)

    reapplied = review.apply_package_semantic_review_partitions(ROOT, result, files)
    assert reapplied[object_id]["obligations"][obligation_id] == custom_binding


def test_apply_preserves_current_cross_root_role_decisions() -> None:
    files = _files()
    rows = _rows()
    spec = next(
        item
        for item in review.PARTITION_SPECS
        if item.object_id == "vstd-vgsat-public-result-records"
    )
    evidence = [
        {"path": path, "sha256": files[path]} for path in spec.owned_paths
    ]
    expected = {}
    for decision in spec.root_role_decisions:
        binding = {
            "status": decision.status,
            "reason": decision.reason,
            "evidence": deepcopy(evidence),
        }
        rows[spec.object_id]["classification"][decision.kind] = deepcopy(binding)
        expected[decision.kind] = binding

    result = review.apply_package_semantic_review_partitions(ROOT, rows, files)
    selected = result[spec.object_id]
    assert {
        kind: selected["classification"][kind] for kind in expected
    } == expected
    assert set(expected).isdisjoint(selected["specializations"])


def test_partition_source_and_mapping_digests_remain_exact() -> None:
    paths = [
        path for spec in review.PARTITION_SPECS for path in spec.owned_paths
    ]
    assert len(paths) == len(set(paths)) == 1551
    assert all((ROOT / path).is_file() for path in paths)
    assert _sha256(paths) == "841019e38a624a91bff829a1ed19be26b971831fb8c2834ca342be0eaddba7a5"

    mapping = [
        f"{spec.object_id}\t{path}"
        for spec in review.PARTITION_SPECS
        for path in spec.owned_paths
    ]
    assert _sha256(mapping) == "5acc0fc8b016e00511d118917aed9e642eff31ad049296ef73adee4a9536375c"

    refutations = [
        f"{object_id}\t{kind}"
        for object_id, kinds in review.REFUTED_KINDS_BY_OBJECT
        for kind in kinds
    ]
    assert len(refutations) == 2965
    assert _sha256(refutations) == "7c5ab8f389eeb84804ba3fa65b84fe3fac2db8475e47a0b2f491543aaf92fe20"

    inventory = []
    for path in paths:
        content = _normalized_source(path)
        inventory.append(
            f"{path}\t{len(content)}\t{hashlib.sha256(content).hexdigest()}"
        )
    EXPECTED_SOURCE_INVENTORY_DIGEST = "9acfb3f554ed6753a8388df3cff595d7a32abd38d668bfee28f1f6a9c38cf046"
    assert _sha256(inventory) == EXPECTED_SOURCE_INVENTORY_DIGEST


def test_apply_rejects_conflicts_and_stale_bindings_atomically_on_fixed_object() -> None:
    files = _files()
    rows = review.apply_package_semantic_review_partitions(ROOT, _rows(), files)
    object_id = "vstd-hardware-evidence-records"
    failures = {
        "partial_declaration": lambda item: item["obligations"][
            "ASSET-0.1-identity-and-quantity"
        ]["declaration"].__setitem__("identity", ""),
        "ownership": lambda item: item.__setitem__("surfaces", item["surfaces"][:-1]),
        "operand_conflict": lambda item: item["operands"].__setitem__(
            "subject", ["vstd-package-object"]
        ),
    }
    for name, mutate in failures.items():
        candidate = deepcopy(rows)
        mutate(candidate[object_id])
        before = deepcopy(candidate)
        with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_"):
            review.apply_package_semantic_review_partitions(ROOT, candidate, files)
        assert candidate == before, name

    stale = dict(files)
    stale[review.PARTITION_SPECS[0].owned_paths[0]] = "sha256:" + "0" * 64
    before = deepcopy(rows)
    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_SOURCE_DIFFERS"):
        review.apply_package_semantic_review_partitions(ROOT, rows, stale)
    assert rows == before


def test_apply_rejects_source_change_during_full_preflight_atomically(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    files = _files()
    rows = _rows()
    before = deepcopy(rows)
    original = review._source_evidence
    changed = False

    def changed_source(root: Path, paths: tuple[str, ...]) -> list[dict[str, str]]:
        nonlocal changed
        evidence = original(root, paths)
        if not changed:
            changed = True
            evidence[0] = {
                "path": evidence[0]["path"],
                "sha256": "sha256:" + "f" * 64,
            }
        return evidence

    monkeypatch.setattr(review, "_source_evidence", changed_source)
    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_SOURCE_CHANGED"):
        review.apply_package_semantic_review_partitions(ROOT, rows, files)
    assert rows == before


def test_static_guard_rejects_applicability_complement_logic() -> None:
    module_source = Path(review.__file__).read_text(encoding="utf-8")
    assert _violations(module_source) == []

    bad = {
        "ternary_refuted": 'status = "APPLIES" if kind in applicable else "DOES_NOT_APPLY"\n',
        "ternary_unresolved": 'status = "APPLIES" if kind in applicable else "UNRESOLVED"\n',
        "complement_compare": 'status = "DOES_NOT_APPLY" if kind not in applicable else "APPLIES"\n',
        "set_difference": "refuted = set(REVIEW_KINDS) - set(applicable)\n",
        "negated_membership": 'status = "DOES_NOT_APPLY" if not (kind in applicable) else "APPLIES"\n',
        "statement_complement": (
            "if kind in applicable:\n"
            '    status = "APPLIES"\n'
            "else:\n"
            '    status = "DOES_NOT_APPLY"\n'
        ),
    }
    for name, fixture in bad.items():
        assert _violations(fixture), name

    good = (
        'status = "DOES_NOT_APPLY" if (object_id, kind) in REFUTATIONS else "UNRESOLVED"\n'
        "if kind in applicable:\n"
        '    status = "APPLIES"\n'
    )
    assert _violations(good) == []


def test_fixed_review_counts_are_the_exact_inventory() -> None:
    counts = review.review_counts()
    assert counts == EXPECTED_COUNTS
    assert counts["applies"] + counts["refuted"] + counts["unresolved"] == counts["decisions"]


ASSET_OBJECT_ID = "vstd-asset-tier0-execution-verifier"
AGENCY_OBJECT_ID = "vstd-agency-surface-crosswalk-assets"


def _central_spec(object_id: str):
    matches = [
        spec
        for spec in ownership.SEMANTIC_OWNERSHIP_SPECS
        if spec.object_id == object_id
    ]
    assert len(matches) == 1
    return matches[0]


def test_partition_union_is_exact_against_the_central_ownership_catalog() -> None:
    assert (
        review._union_failure(
            review.PARTITION_SPECS,
            review._LOCAL_OWNERSHIP_SPECS,
            ownership.SEMANTIC_OWNERSHIP_SPECS,
        )
        is None
    )
    local_ids = {spec.object_id for spec in review._LOCAL_OWNERSHIP_SPECS}
    assert len(review._LOCAL_OWNERSHIP_SPECS) == 122 == len(local_ids)
    assert set(review.PARTITION_OBJECT_IDS).isdisjoint(local_ids)
    assert set(review.PARTITION_OBJECT_IDS) | local_ids == {
        spec.object_id for spec in ownership.SEMANTIC_OWNERSHIP_SPECS
    }


def test_partition_union_rejects_omission_duplication_and_wrong_partition() -> None:
    partition = review.PARTITION_SPECS
    local = review._LOCAL_OWNERSHIP_SPECS
    central = ownership.SEMANTIC_OWNERSHIP_SPECS
    asset = _central_spec(ASSET_OBJECT_ID)
    victim = partition[0]
    drifted = replace(victim, necessity_reason=victim.necessity_reason + " drift")
    shared_path = replace(victim, owned_paths=(asset.owned_paths[0],))
    shared_central = tuple(
        shared_path if spec.object_id == victim.object_id else spec
        for spec in central
    )
    cases = {
        "omitted_partition_object": (partition[1:], local, central, "omit or add"),
        "duplicated_partition_object": (
            (*partition, victim),
            local,
            central,
            "duplicated",
        ),
        "asset_also_in_partition": ((*partition, asset), local, central, "duplicated"),
        "asset_omitted_from_both_catalogs": (
            partition,
            tuple(spec for spec in local if spec.object_id != ASSET_OBJECT_ID),
            central,
            "omit or add",
        ),
        "partition_value_drift": ((drifted, *partition[1:]), local, central, "differs"),
        "two_objects_own_one_path": (
            (shared_path, *partition[1:]),
            local,
            shared_central,
            "more than one object",
        ),
    }
    for name, (candidate, candidate_local, candidate_central, keyword) in cases.items():
        failure = review._union_failure(candidate, candidate_local, candidate_central)
        assert failure is not None, name
        assert keyword in failure, name


def test_refutation_coverage_requires_exactly_one_explicit_status_per_object() -> None:
    ids = list(review.PARTITION_OBJECT_IDS)
    refuted = [object_id for object_id, _kinds in review.REFUTED_KINDS_BY_OBJECT]
    pending = list(review.PENDING_REFUTATION_AUDIT_OBJECT_IDS)
    assert review._refutation_coverage_failure(ids, refuted, pending) is None
    assert AGENCY_OBJECT_ID in pending
    cases = {
        "object_neither_refuted_nor_pending": (ids, refuted, pending[:0], "lacks"),
        "object_both_refuted_and_pending": (ids, refuted, [*pending, refuted[0]], "both"),
        "pending_duplicated": (ids, refuted, [*pending, *pending], "duplicate"),
        "refuted_duplicated": (ids, [*refuted, refuted[0]], pending, "duplicate"),
    }
    for name, (object_ids, refuted_ids, pending_ids, keyword) in cases.items():
        failure = review._refutation_coverage_failure(object_ids, refuted_ids, pending_ids)
        assert failure is not None, name
        assert keyword in failure, name


def test_pending_object_without_literal_refutation_stays_unresolved() -> None:
    assert AGENCY_OBJECT_ID not in {
        object_id for object_id, _kinds in review.REFUTED_KINDS_BY_OBJECT
    }
    assert not any(
        (AGENCY_OBJECT_ID, kind) in review._REFUTATIONS for kind in review.REVIEW_KINDS
    )
    applicable = review._REVIEWS[AGENCY_OBJECT_ID].applicable
    assert review.unresolved_inventory()[AGENCY_OBJECT_ID] == tuple(
        kind for kind in review.REVIEW_KINDS if kind not in applicable
    )


def test_asset_execution_verifier_has_one_central_record_and_one_verifier_review() -> None:
    spec = _central_spec(ASSET_OBJECT_ID)
    assert spec.primary_kind == "VERIFIER"
    assert spec.specializations == ("POLICY",)
    assert spec.owned_paths == ("src/verifier/runtime/asset_execution.py",)
    assert ASSET_OBJECT_ID not in review.PARTITION_OBJECT_IDS
    assert verifier_review.VERIFIER_OBJECT_IDS.count(ASSET_OBJECT_ID) == 1
    review_record = verifier_review._REVIEWS[ASSET_OBJECT_ID]
    assert review_record.primary_kind == spec.primary_kind
    assert review_record.applicable == spec.specializations
    assert review_record.owned_paths == spec.owned_paths
