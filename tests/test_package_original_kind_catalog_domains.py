"""Fail-closed boundaries for the 38-row domain original-kind catalog."""

from __future__ import annotations

import ast
from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
from pathlib import Path

import pytest

from verifier.runtime import package_original_kind_catalog_domains as catalog
from verifier.runtime import package_original_kind_review as review
from verifier.runtime.package_original_kind_profiles import (
    APPLIES,
    ORIGINAL_NON_OBJECT_KINDS,
    OriginalKindAssignment,
    OriginalKindDecision,
    owned_path_set_digest,
    profile_digest,
    validate_full_closure,
    validate_profile,
)
from verifier.runtime.package_semantic_ownership_domains import (
    DOMAIN_OWNERSHIP_SPECS,
    canonical_executable_ast_sha256,
)


ROOT = Path(__file__).parents[1]
MARKER = "vstd-domains-package-marker"
MARKER_PATH = "src/verifier/domains/__init__.py"
INVENTORY = "vstd-object-obligation-inventory"
INVENTORY_PATH = "src/verifier/domains/inventory.py"
INVENTORY_RAW_SHA256 = (
    "sha256:13667a264342d4e5c1ee53ba08195277c3ec06b12268fd1ffcd5a159da7a2694"
)
# Golden for the executable form only; a docstring-only edit leaves it unchanged.
INVENTORY_CANONICAL_EXECUTABLE_AST_SHA256 = (
    "b7529ac824838b7cee78bc693b0dfdd5f44cc75339e3b54c73a1fc2f6f413a4e"
)


def _digest(raw: bytes) -> str:
    return "sha256:" + sha256(raw).hexdigest()


def _fixture(tmp_path: Path):
    files: dict[str, str] = {}
    rows: dict[str, dict] = {}
    for spec in DOMAIN_OWNERSHIP_SPECS:
        for path in spec.owned_paths:
            raw = (ROOT / path).read_bytes()
            target = tmp_path / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
            files[path] = _digest(raw)
        rows[spec.object_id] = {
            "object_id": spec.object_id,
            "kind": spec.primary_kind,
            "surfaces": ["file:" + path for path in spec.owned_paths],
            "specializations": list(spec.specializations),
            "classification": {
                kind: {
                    "status": catalog.UNRESOLVED,
                    "reason": "The literal original-kind question remains open.",
                    "evidence": [],
                }
                for kind in ORIGINAL_NON_OBJECT_KINDS
            },
        }
    return rows, files


def _audits():
    return {audit.object_id: audit for audit in catalog.DOMAIN_ORIGINAL_KIND_AUDITS}


def _proposed_cells() -> set[tuple[str, str]]:
    return {
        (object_id, kind)
        for object_id, kinds in catalog._PROPOSED_IDENTITY_REFUTATIONS.items()
        for kind in kinds
    }


def test_exact_domain_denominator_exposes_all_950_human_questions():
    audits = _audits()
    assert len(audits) == len(DOMAIN_OWNERSHIP_SPECS) == 38
    assert tuple(audits) == tuple(spec.object_id for spec in DOMAIN_OWNERSHIP_SPECS)
    for audit in audits.values():
        assert len(audit.questions) == 25
        assert tuple(question.kind for question in audit.questions) == (
            ORIGINAL_NON_OBJECT_KINDS
        )
        assert all(question.reason.startswith(audit.scope_reason) for question in audit.questions)
        assert all(question.kind in question.reason for question in audit.questions)
        for question in audit.questions:
            if question.status == catalog.UNRESOLVED:
                assert "For exact owned source" in question.reason
                assert "this partition has no source-near decision" in question.reason
                assert "no source-grounded bounded refutation" in question.reason
                assert all(path in question.reason for path in audit.expected_owned_paths)
            else:
                assert "Source-near original-role" in question.reason
                assert " decision:" in question.reason


def test_partial_profile_carries_only_literal_decisions():
    statuses = [
        question.status
        for audit in catalog.DOMAIN_ORIGINAL_KIND_AUDITS
        for question in audit.questions
    ]
    assert statuses.count(APPLIES) == 28
    assert statuses.count(catalog.DOES_NOT_APPLY) == 0
    assert statuses.count(catalog.UNRESOLVED) == 922
    assert validate_profile(catalog.DOMAIN_ORIGINAL_KIND_PROFILE) is (
        catalog.DOMAIN_ORIGINAL_KIND_PROFILE
    )
    assert catalog.DOMAIN_ORIGINAL_KIND_PROFILE.revision == 2
    decided_owners = {
        audit.object_id
        for audit in catalog.DOMAIN_ORIGINAL_KIND_AUDITS
        if any(question.status != catalog.UNRESOLVED for question in audit.questions)
    }
    assignments = catalog.DOMAIN_ORIGINAL_KIND_PROFILE.assignments
    assert len(assignments) == len(decided_owners) == 28
    profile_decisions = [
        decision for assignment in assignments for decision in assignment.decisions
    ]
    assert len(profile_decisions) == 28
    assert {decision.status for decision in profile_decisions} == {APPLIES}
    assert not any(
        decision.status == catalog.DOES_NOT_APPLY for decision in profile_decisions
    )
    with pytest.raises(
        ValueError,
        match="PACKAGE_ORIGINAL_KIND_PROFILE_OBJECT_DENOMINATOR_INCOMPLETE",
    ):
        validate_full_closure(
            catalog.DOMAIN_ORIGINAL_KIND_PROFILE,
            tuple(
                sorted(
                    audit.object_id
                    for audit in catalog.DOMAIN_ORIGINAL_KIND_AUDITS
                )
            ),
            expected_object_count=38,
        )


def test_only_literal_primary_and_four_source_near_verifier_roles_apply():
    audits = _audits()
    accumulated = {
        "vstd-certificate-dependency-controller",
        "vstd-object-governance-protocol",
        "vstd-spacetime-capability-measurement",
        "vstd-subject-security-chain-verifier",
    }
    for spec in DOMAIN_OWNERSHIP_SPECS:
        applied = {
            question.kind
            for question in audits[spec.object_id].questions
            if question.status == APPLIES
        }
        expected = (
            {spec.primary_kind}
            if spec.primary_kind in ORIGINAL_NON_OBJECT_KINDS
            else set()
        )
        if spec.object_id in accumulated:
            expected.add("VERIFIER")
        assert applied == expected


def test_catalog_decisions_are_exactly_primary_and_root_decisions():
    # No claim is admitted, so no proposed refutation may appear as a decision.
    assert catalog._IDENTITY_CLAIMS == {}
    audits = _audits()
    for spec in DOMAIN_OWNERSHIP_SPECS:
        decided = {
            question.kind: question.status
            for question in audits[spec.object_id].questions
            if question.status != catalog.UNRESOLVED
        }
        source_near = {
            decision.kind: decision.status
            for decision in spec.root_role_decisions
        }
        if spec.primary_kind in ORIGINAL_NON_OBJECT_KINDS:
            source_near[spec.primary_kind] = APPLIES
        assert decided == source_near


def test_subject_names_and_consequences_do_not_promote_original_roles():
    audits = _audits()
    checks = {
        "vstd-retained-model-training-arithmetic": ("MODEL", "TRAIN"),
        "vstd-sim-grounding-verifier": ("SIM",),
        "vstd-current-object-replay-router": (
            "AGENT",
            "BOT",
            "SIM",
            "TRAIN",
            "HARDWARE",
            "OWNER",
        ),
        "vstd-hardware-ownership-eligibility": ("HARDWARE", "OWNER", "ACTOR"),
        "vstd-subject-security-chain-verifier": ("RECEIPT", "IDENTITY", "OWNER"),
        "vstd-domain-certificate-engine": ("AGENT", "BOT", "MODEL", "SIM", "TRAIN"),
    }
    for object_id, kinds in checks.items():
        decisions = {question.kind: question for question in audits[object_id].questions}
        assert all(decisions[kind].status == catalog.UNRESOLVED for kind in kinds)
    # The router's own bytes carry no MODEL counterexample term, but zero hits
    # never admit a refutation, so MODEL stays open with the exact closure blocker.
    router = {question.kind: question for question in audits["vstd-current-object-replay-router"].questions}
    assert router["MODEL"].status == catalog.UNRESOLVED
    assert "proposed MODEL identity refutation" in router["MODEL"].reason
    assert "zero-hit lexical search is never admissible" in router["MODEL"].reason


def test_review_document_binds_paths_profile_digest_and_every_reason():
    document = catalog.review_document()
    assert len(document) == 38
    assert sum(
        question["status"] == APPLIES
        for row in document.values()
        for question in row["questions"].values()
    ) == 28
    assert sum(
        question["status"] == catalog.DOES_NOT_APPLY
        for row in document.values()
        for question in row["questions"].values()
    ) == 0
    assert sum(
        question["status"] == catalog.UNRESOLVED
        for row in document.values()
        for question in row["questions"].values()
    ) == 922
    assert all(
        row["profile_digest"]
        == catalog.DOMAIN_ORIGINAL_KIND_PROFILE.canonical_digest
        for row in document.values()
    )
    assert catalog.SOURCE_BINDING_DIGEST.startswith("sha256:")
    assert catalog.SOURCE_BINDING_DIGEST in (
        catalog.DOMAIN_ORIGINAL_KIND_PROFILE.claim_boundary
    )
    assert sum(row["profile_assignment_member"] for row in document.values()) == 28
    for spec in DOMAIN_OWNERSHIP_SPECS:
        row = document[spec.object_id]
        assert tuple(row["expected_specializations"]) == spec.specializations
        assert tuple(row["expected_owned_paths"]) == spec.owned_paths
        assert row["expected_owned_path_set_digest"] == owned_path_set_digest(
            spec.owned_paths
        )
        assert set(row["expected_source_sha256"]) == set(spec.owned_paths)
        assert all(
            digest.startswith("sha256:")
            for digest in row["expected_source_sha256"].values()
        )
        assert all(question["reason"] for question in row["questions"].values())


def test_profile_digest_rejects_path_scope_and_decision_substitutions():
    profile = catalog.DOMAIN_ORIGINAL_KIND_PROFILE
    assignment = profile.assignments[0]
    variants = (
        replace(assignment, scope_reason=assignment.scope_reason + " substituted"),
        replace(
            assignment,
            expected_owned_path_set_digest="sha256:" + "0" * 64,
        ),
        replace(
            assignment,
            decisions=(
                replace(
                    assignment.decisions[0],
                    reason=assignment.decisions[0].reason + " substituted",
                ),
            ),
        ),
    )
    for variant in variants:
        assignments = (variant,) + profile.assignments[1:]
        changed = replace(profile, assignments=assignments)
        assert profile_digest(changed) != profile.canonical_digest
        with pytest.raises(ValueError):
            validate_profile(changed)


def test_application_emits_current_source_evidence_and_preserves_unknowns(tmp_path: Path):
    rows, files = _fixture(tmp_path)
    result = catalog.apply_domain_original_kind_profile(tmp_path, rows, files)
    applied = result["vstd-domain-certificate-engine"]["classification"]["VERIFIER"]
    assert applied["status"] == APPLIES
    assert catalog.DOMAIN_ORIGINAL_KIND_PROFILE.canonical_digest in applied["reason"]
    assert applied["evidence"] == [
        {
            "path": "src/verifier/domains/certification.py",
            "sha256": files["src/verifier/domains/certification.py"],
        }
    ]
    assert result["vstd-domain-certificate-engine"]["classification"]["SIM"] == (
        rows["vstd-domain-certificate-engine"]["classification"]["SIM"]
    )
    assert rows["vstd-domain-certificate-engine"]["classification"]["VERIFIER"][
        "status"
    ] == catalog.UNRESOLVED


def test_apply_keeps_every_proposed_cell_unresolved_with_its_input_reason(tmp_path: Path):
    rows, files = _fixture(tmp_path)
    result = catalog.apply_domain_original_kind_profile(tmp_path, rows, files)
    for object_id, kind in sorted(_proposed_cells()):
        assert result[object_id]["classification"][kind] == (
            rows[object_id]["classification"][kind]
        )
        assert result[object_id]["classification"][kind]["status"] == catalog.UNRESOLVED
    applied = sum(
        cell["status"] == APPLIES
        for row in result.values()
        for cell in row["classification"].values()
    )
    assert applied == 28


def test_unknown_future_row_is_not_completed_by_complement(tmp_path: Path):
    rows, files = _fixture(tmp_path)
    future = {
        "object_id": "future-domain-owner",
        "kind": "OBJECT",
        "surfaces": [],
        "specializations": [],
        "classification": {
            kind: {
                "status": catalog.UNRESOLVED,
                "reason": "No source audit exists.",
                "evidence": [],
            }
            for kind in ORIGINAL_NON_OBJECT_KINDS
        },
    }
    rows[future["object_id"]] = deepcopy(future)
    result = catalog.apply_domain_original_kind_profile(tmp_path, rows, files)
    assert result[future["object_id"]] == future
    assert all(
        decision["status"] == catalog.UNRESOLVED
        for decision in result[future["object_id"]]["classification"].values()
    )


def test_invented_negative_on_unreviewed_cell_fails_closed(tmp_path: Path):
    rows, files = _fixture(tmp_path)
    rows["vstd-retained-model-training-arithmetic"]["classification"]["MODEL"] = {
        "status": "DOES_NOT_APPLY",
        "reason": "Invented from a missing declaration.",
        "evidence": [],
    }
    with pytest.raises(
        ValueError,
        match=(
            "PACKAGE_DOMAIN_ORIGINAL_KIND_UNREVIEWED_DECISION:"
            "vstd-retained-model-training-arithmetic:MODEL"
        ),
    ):
        catalog.apply_domain_original_kind_profile(tmp_path, rows, files)


def test_same_status_reason_or_evidence_substitution_fails_closed(tmp_path: Path):
    rows, files = _fixture(tmp_path)
    first = catalog.apply_domain_original_kind_profile(tmp_path, rows, files)
    first["vstd-domain-certificate-engine"]["classification"]["VERIFIER"][
        "reason"
    ] += " substituted"
    with pytest.raises(
        ValueError,
        match=(
            "PACKAGE_DOMAIN_ORIGINAL_KIND_DECISION_SUBSTITUTION:"
            "vstd-domain-certificate-engine:VERIFIER"
        ),
    ):
        catalog.apply_domain_original_kind_profile(tmp_path, first, files)

    second = catalog.apply_domain_original_kind_profile(tmp_path, rows, files)
    second["vstd-domain-certificate-engine"]["classification"]["VERIFIER"][
        "evidence"
    ] = []
    with pytest.raises(ValueError, match="DECISION_SUBSTITUTION"):
        catalog.apply_domain_original_kind_profile(tmp_path, second, files)


def test_generated_primary_declaration_is_replaced_but_a_hand_edit_is_not(
    tmp_path: Path,
):
    from verifier.runtime import package_manifest_migration as migration

    rows, files = _fixture(tmp_path)
    canonical = catalog.apply_domain_original_kind_profile(tmp_path, rows, files)
    object_id = "vstd-domain-certificate-engine"
    reviewed = canonical[object_id]["classification"]["VERIFIER"]
    assert reviewed["status"] == APPLIES

    # Discovery writes this exact text for a new object's declared primary kind.
    generated = {
        "status": APPLIES,
        "reason": migration._primary_original_kind_reason(
            "VERIFIER", "The engine decides finite certificates."
        ),
        "evidence": deepcopy(reviewed["evidence"]),
    }
    fresh = deepcopy(rows)
    fresh[object_id]["classification"]["VERIFIER"] = generated
    result = catalog.apply_domain_original_kind_profile(tmp_path, fresh, files)
    assert result[object_id]["classification"]["VERIFIER"] == reviewed
    assert fresh[object_id]["classification"]["VERIFIER"] == generated

    edited = deepcopy(rows)
    edited[object_id]["classification"]["VERIFIER"] = {
        **generated,
        "reason": generated["reason"] + " substituted",
    }
    with pytest.raises(ValueError, match="DECISION_SUBSTITUTION"):
        catalog.apply_domain_original_kind_profile(tmp_path, edited, files)

    other_evidence = deepcopy(rows)
    other_evidence[object_id]["classification"]["VERIFIER"] = {
        **generated,
        "evidence": [],
    }
    with pytest.raises(ValueError, match="DECISION_SUBSTITUTION"):
        catalog.apply_domain_original_kind_profile(tmp_path, other_evidence, files)


def test_source_owned_role_reason_is_replaced_but_a_hand_edit_is_not(
    tmp_path: Path,
):
    rows, files = _fixture(tmp_path)
    object_id = "vstd-certificate-dependency-controller"
    spec = next(item for item in DOMAIN_OWNERSHIP_SPECS if item.object_id == object_id)
    role = next(item for item in spec.root_role_decisions if item.kind == "VERIFIER")
    assert role.status == APPLIES
    canonical = catalog.apply_domain_original_kind_profile(tmp_path, rows, files)
    reviewed = canonical[object_id]["classification"]["VERIFIER"]

    # The ownership catalog installs its own audited role reason before this review.
    installed = {
        "status": APPLIES,
        "reason": role.reason,
        "evidence": deepcopy(reviewed["evidence"]),
    }
    fresh = deepcopy(rows)
    fresh[object_id]["classification"]["VERIFIER"] = installed
    result = catalog.apply_domain_original_kind_profile(tmp_path, fresh, files)
    assert result[object_id]["classification"]["VERIFIER"] == reviewed

    edited = deepcopy(rows)
    edited[object_id]["classification"]["VERIFIER"] = {
        **installed,
        "reason": role.reason + " substituted",
    }
    with pytest.raises(ValueError, match="DECISION_SUBSTITUTION"):
        catalog.apply_domain_original_kind_profile(tmp_path, edited, files)

    other_object = deepcopy(rows)
    other = "vstd-object-governance-protocol"
    other_object[other]["classification"]["VERIFIER"] = {
        **installed,
        "evidence": deepcopy(canonical[other]["classification"]["VERIFIER"]["evidence"]),
    }
    with pytest.raises(ValueError, match="DECISION_SUBSTITUTION"):
        catalog.apply_domain_original_kind_profile(tmp_path, other_object, files)


def test_owned_source_drift_fails_before_any_result(tmp_path: Path):
    rows, files = _fixture(tmp_path)
    target = tmp_path / "src/verifier/domains/numerical.py"
    target.write_bytes(target.read_bytes() + b"\n# drift\n")
    files["src/verifier/domains/numerical.py"] = _digest(target.read_bytes())
    with pytest.raises(
        ValueError,
        match=(
            "PACKAGE_DOMAIN_ORIGINAL_KIND_SOURCE_PIN_DIFFERS:"
            "vstd-retained-model-training-arithmetic:"
        ),
    ):
        catalog.apply_domain_original_kind_profile(tmp_path, rows, files)


def test_atomic_partition_recapture_rejects_mid_review_source_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    rows, files = _fixture(tmp_path)
    original = catalog._source_snapshot
    calls = 0

    def changed(root, audit):
        nonlocal calls
        calls += 1
        evidence = original(root, audit)
        if calls == len(catalog.DOMAIN_ORIGINAL_KIND_AUDITS) + 1:
            altered = [dict(item) for item in evidence]
            altered[0]["sha256"] = "sha256:" + "0" * 64
            return tuple(altered)
        return evidence

    monkeypatch.setattr(catalog, "_source_snapshot", changed)
    with pytest.raises(
        ValueError,
        match="PACKAGE_DOMAIN_ORIGINAL_KIND_SOURCE_CHANGED:",
    ):
        catalog.apply_domain_original_kind_profile(tmp_path, rows, files)


@pytest.mark.parametrize("invented", ("SIM", "ROBOT", "FINBOT"))
def test_accumulated_role_conflict_cannot_be_hidden_by_specialization(
    tmp_path: Path, invented: str
):
    rows, files = _fixture(tmp_path)
    rows["vstd-current-object-replay-router"]["specializations"].append(invented)
    with pytest.raises(
        ValueError,
        match=(
            "PACKAGE_DOMAIN_ORIGINAL_KIND_SPECIALIZATIONS_DIFFER:"
            "vstd-current-object-replay-router"
        ),
    ):
        catalog.apply_domain_original_kind_profile(tmp_path, rows, files)


def test_declared_consequence_role_cannot_be_dropped(tmp_path: Path):
    rows, files = _fixture(tmp_path)
    rows["vstd-current-object-replay-router"]["specializations"].remove(
        "TRANSACTION"
    )
    with pytest.raises(
        ValueError,
        match=(
            "PACKAGE_DOMAIN_ORIGINAL_KIND_SPECIALIZATIONS_DIFFER:"
            "vstd-current-object-replay-router"
        ),
    ):
        catalog.apply_domain_original_kind_profile(tmp_path, rows, files)


# Independent oracle for the bounded lexical zero-hit proposal.  It is kept
# separate from the module so that a module-side vocabulary or walk error cannot
# certify itself.
HIGH_RISK_KINDS = ("MODEL", "SIM", "AGENT", "BOT", "HARDWARE")
ORACLE_TERMS = {
    "MODEL": ("forward", "logit", "weight", "architecture", "tensor", "safetensor", "parameter"),
    "SIM": ("simulat", "transition", "next_state", "tick", "state_space", "generative"),
    "AGENT": ("agent", "trajector", "autonom"),
    "BOT": ("bot", "closed_loop", "actuat", "envelope", "observation"),
    "HARDWARE": ("device", "hardware", "topolog", "gpu", "cpu", "sensor", "capacity", "allocation"),
}


def _oracle_tokens(raw: bytes) -> list[str]:
    tree = ast.parse(raw)
    docstring_nodes = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.body and isinstance(node.body[0], ast.Expr):
                if isinstance(node.body[0].value, ast.Constant):
                    docstring_nodes.add(id(node.body[0].value))
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            found.append(node.id)
        elif isinstance(node, ast.Attribute):
            found.append(node.attr)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            found.append(node.name)
        elif isinstance(node, ast.arg):
            found.append(node.arg)
        elif isinstance(node, ast.keyword) and node.arg:
            found.append(node.arg)
        elif isinstance(node, ast.alias):
            found.extend((node.name, node.asname or ""))
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.append(node.module)
        elif (
            isinstance(node, ast.Constant)
            and type(node.value) is str
            and id(node) not in docstring_nodes
        ):
            found.append(node.value)
    return [token.lower() for token in found if token]


def _oracle_zero_cells() -> set[tuple[str, str]]:
    cells: set[tuple[str, str]] = set()
    for spec in DOMAIN_OWNERSHIP_SPECS:
        raws = [(ROOT / path).read_bytes() for path in spec.owned_paths]
        for kind in HIGH_RISK_KINDS:
            hit = any(
                term in token
                for raw in raws
                for token in _oracle_tokens(raw)
                for term in ORACLE_TERMS[kind]
            )
            if not hit:
                cells.add((spec.object_id, kind))
    return cells


def _declared_refuted_cells() -> set[tuple[str, str]]:
    return {
        (audit.object_id, question.kind)
        for audit in catalog.DOMAIN_ORIGINAL_KIND_AUDITS
        for question in audit.questions
        if question.status == catalog.DOES_NOT_APPLY
    }


def test_proposed_cells_are_exactly_the_bounded_zero_hit_cells_and_none_is_admitted():
    # Zero lexical hits propose a cell; they never decide it.
    assert _proposed_cells() == _oracle_zero_cells()
    assert len(_proposed_cells()) == 85
    assert _declared_refuted_cells() == set()


def test_refutation_denominator_is_exact_and_every_proposed_cell_stays_unknown():
    statuses = [
        question.status
        for audit in catalog.DOMAIN_ORIGINAL_KIND_AUDITS
        for question in audit.questions
    ]
    assert statuses.count(APPLIES) == 28
    assert statuses.count(catalog.DOES_NOT_APPLY) == 0
    assert statuses.count(catalog.UNRESOLVED) == 950 - 28
    audits = _audits()
    for object_id, kind in _proposed_cells():
        decisions = {question.kind: question for question in audits[object_id].questions}
        assert decisions[kind].status == catalog.UNRESOLVED


def test_every_proposed_cell_is_downgraded_with_its_exact_blocker():
    audits = _audits()
    for object_id, kind in sorted(_proposed_cells()):
        question = {q.kind: q for q in audits[object_id].questions}[kind]
        assert question.status == catalog.UNRESOLVED
        assert (
            "Exact blocker for the proposed " + kind + " identity refutation"
            in question.reason
        )
        assert "zero-hit lexical search is never admissible" in question.reason
        status, count, digest, first = catalog._CLOSURE_PINS[object_id]
        if status == "CLOSED":
            assert count == 0
            assert "submodules, which lie outside this owned file" in question.reason
        else:
            assert "with " + str(count) + " exact blockers" in question.reason
            assert digest in question.reason
            assert "first blocker " + first in question.reason


def test_package_markers_close_yet_do_not_admit_a_different_identity():
    for object_id in ("vstd-domains-package-marker", "vstd-domain-contracts-package-marker"):
        spec = next(row for row in DOMAIN_OWNERSHIP_SPECS if row.object_id == object_id)
        tree = ast.parse((ROOT / spec.owned_paths[0]).read_bytes())
        assert all(
            isinstance(node, ast.ImportFrom)
            or (isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant))
            for node in tree.body
        )
        closure = review.audit_closed_effects(ROOT, spec.owned_paths)
        assert closure.status == "CLOSED"
        assert closure.blockers == ()
        decided = {
            question.kind
            for question in _audits()[object_id].questions
            if question.status == catalog.DOES_NOT_APPLY
        }
        assert decided == set()
        assert {
            kind for oid, kind in _proposed_cells() if oid == object_id
        } == set(HIGH_RISK_KINDS)


def test_closure_pins_are_recomputed_from_current_bytes():
    assert set(catalog._CLOSURE_PINS) == {object_id for object_id, _ in _proposed_cells()}
    for object_id, pin in sorted(catalog._CLOSURE_PINS.items()):
        spec = next(row for row in DOMAIN_OWNERSHIP_SPECS if row.object_id == object_id)
        closure = review.audit_closed_effects(ROOT, spec.owned_paths)
        digest = "sha256:" + sha256("\n".join(closure.blockers).encode("utf-8")).hexdigest()
        first = closure.blockers[0] if closure.blockers else ""
        assert (closure.status, len(closure.blockers), digest, first) == pin, object_id
    closed = {
        object_id
        for object_id, pin in catalog._CLOSURE_PINS.items()
        if pin[0] == "CLOSED"
    }
    assert closed == {"vstd-domains-package-marker", "vstd-domain-contracts-package-marker"}


def test_refutation_reason_names_identity_search_scope_and_non_inference():
    # The admitted-path reason is exercised on synthetic admission below; here
    # every real cell must name its proposal and the non-inference boundary.
    checked = 0
    for audit in catalog.DOMAIN_ORIGINAL_KIND_AUDITS:
        for question in audit.questions:
            if (audit.object_id, question.kind) not in _proposed_cells():
                continue
            checked += 1
            assert question.status == catalog.UNRESOLVED
            assert "zero-hit lexical search is never admissible" in question.reason
            assert "no source-bound positive identity claim exists" in question.reason
    assert checked == len(_proposed_cells()) == 85


def test_closed_marker_identity_is_bounded_by_the_admission_gate_alone(monkeypatch):
    # Every conjunct is needed: a CLOSED closure, a digest-bound claim, and zero hits.
    claim = ("bounded different identity claim", MARKER_PATH, catalog._EXPECTED_SOURCE_DIGESTS[MARKER_PATH])
    monkeypatch.setitem(catalog._IDENTITY_CLAIMS, (MARKER, "MODEL"), claim)
    assert catalog._admits_refutation(MARKER, "MODEL", "CLOSED", ()) is True
    assert catalog._admits_refutation(MARKER, "MODEL", "UNKNOWN", ()) is False
    assert catalog._admits_refutation(MARKER, "MODEL", "CLOSED", ("forward",)) is False
    assert catalog._admits_refutation(MARKER, "SIM", "CLOSED", ()) is False
    stale = (claim[0], claim[1], "sha256:" + "0" * 64)
    monkeypatch.setitem(catalog._IDENTITY_CLAIMS, (MARKER, "MODEL"), stale)
    assert catalog._admits_refutation(MARKER, "MODEL", "CLOSED", ()) is False


def test_admitted_refutation_is_emitted_only_on_closed_exact_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    _, files = _fixture(tmp_path)
    monkeypatch.setitem(
        catalog._IDENTITY_CLAIMS,
        (MARKER, "MODEL"),
        ("bounded different identity claim", MARKER_PATH, catalog._EXPECTED_SOURCE_DIGESTS[MARKER_PATH]),
    )
    spec = next(row for row in DOMAIN_OWNERSHIP_SPECS if row.object_id == MARKER)
    audit = catalog._audit(spec)
    model = {question.kind: question for question in audit.questions}["MODEL"]
    assert model.status == catalog.DOES_NOT_APPLY
    assert "Identity refutation for MODEL:" in model.reason
    assert "imported modules outside ownership are not searched" in model.reason
    assert "refutes only the owner's own identity" in model.reason
    catalog._refutation_guard(tmp_path, audit, files)
    altered = (ROOT / MARKER_PATH).read_bytes() + b"\n\ndef forward(x):\n    return x\n"
    (tmp_path / MARKER_PATH).write_bytes(altered)
    altered_files = dict(files)
    altered_files[MARKER_PATH] = _digest(altered)
    with pytest.raises(
        ValueError,
        match="PACKAGE_DOMAIN_ORIGINAL_KIND_COUNTEREXAMPLE_FOUND:" + MARKER + ":MODEL",
    ):
        catalog._refutation_guard(tmp_path, audit, altered_files)


def test_zero_hits_and_closed_local_closure_alone_cannot_generate_a_refutation(tmp_path: Path):
    # Empty marker bytes, a purely local function, and a synonym are all CLOSED
    # with zero keyword hits.  None of them is positive identity evidence.
    sources = {
        "pkg/__init__.py": b"",
        "pkg/local_owner.py": b"def f(x):\n    return x + 1\n",
        "pkg/synonym_owner.py": b"def build():\n    neural_network = object()\n    return neural_network\n",
    }
    for rel, raw in sources.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_bytes(raw)
    for rel, raw in sources.items():
        closure = review.audit_closed_effects(tmp_path, (rel,))
        assert closure.status == "CLOSED"
        assert closure.blockers == ()
        for kind in HIGH_RISK_KINDS:
            hits = catalog._counterexample_hits({rel: raw}, kind)
            assert hits == ()
            assert catalog._admits_refutation("fixture-owner", kind, closure.status, hits) is False


def test_limited_local_search_cannot_see_import_or_callback_counterexamples(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    sources = {
        "pkg/model_impl.py": b"class Net:\n    def forward(self, x):\n        return x\n",
        "pkg/import_owner.py": b"from pkg.model_impl import Net\n\ndef build():\n    return Net()\n",
        "pkg/callback_owner.py": b"def run(engine):\n    return engine(1)\n",
    }
    for rel, raw in sources.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_bytes(raw)
    expected_blocker = {
        "pkg/import_owner.py": "IMPORT_ESCAPES_OWNERSHIP:",
        "pkg/callback_owner.py": "INJECTED_CALLABLE_UNRESOLVED:",
    }
    for rel, prefix in expected_blocker.items():
        raw = sources[rel]
        # The owned bytes alone show no MODEL term, so the lexical search is silent.
        assert catalog._counterexample_hits({rel: raw}, "MODEL") == ()
        closure = review.audit_closed_effects(tmp_path, (rel,))
        assert closure.status != "CLOSED"
        assert any(blocker.startswith(prefix) for blocker in closure.blockers)
        monkeypatch.setitem(catalog._EXPECTED_SOURCE_DIGESTS, rel, _digest(raw))
        monkeypatch.setitem(
            catalog._IDENTITY_CLAIMS,
            ("fixture-owner", "MODEL"),
            ("bounded different identity claim", rel, _digest(raw)),
        )
        assert catalog._admits_refutation("fixture-owner", "MODEL", closure.status, ()) is False


def test_synonym_injection_invalidates_a_digest_bound_refutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    rel = "pkg/owner.py"
    original = b"def build():\n    return object()\n"
    (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / rel).write_bytes(original)
    monkeypatch.setitem(catalog._EXPECTED_SOURCE_DIGESTS, rel, _digest(original))
    monkeypatch.setitem(
        catalog._IDENTITY_CLAIMS,
        ("fixture-owner", "MODEL"),
        ("bounded different identity claim", rel, _digest(original)),
    )
    closure = review.audit_closed_effects(
        tmp_path, (rel,), expected_source_digests={rel: _digest(original)}
    )
    assert closure.status == "CLOSED"
    assert catalog._admits_refutation("fixture-owner", "MODEL", closure.status, ()) is True
    synonym = b"def build():\n    neural_network = object()\n    return neural_network\n"
    (tmp_path / rel).write_bytes(synonym)
    # The lexical vocabulary misses the synonym, and the closure is not the cure.
    assert catalog._counterexample_hits({rel: synonym}, "MODEL") == ()
    drifted = review.audit_closed_effects(
        tmp_path, (rel,), expected_source_digests={rel: _digest(original)}
    )
    assert any(blocker.startswith("SOURCE_DIGEST_DIFFERS:") for blocker in drifted.blockers)
    assert catalog._admits_refutation("fixture-owner", "MODEL", drifted.status, ()) is False


def test_counterexample_vocabulary_and_token_scope_are_pinned():
    assert catalog._COUNTEREXAMPLE_TERMS == ORACLE_TERMS
    source = b'"""agent docstring"""\ndef forward(x):\n    return "bot"\n'
    tokens = catalog._counterexample_tokens(source)
    assert "forward" in tokens
    assert "bot" in tokens
    assert not any("agent" in token for token in tokens)


def test_injected_counterexample_in_owned_bytes_stays_unresolved_not_admitted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    rows, files = _fixture(tmp_path)
    path = "src/verifier/domains/common.py"
    altered = (ROOT / path).read_bytes() + b"\n\ndef forward(x):\n    return x\n"
    (tmp_path / path).write_bytes(altered)
    files[path] = _digest(altered)
    monkeypatch.setitem(catalog._EXPECTED_SOURCE_DIGESTS, path, _digest(altered))
    assert catalog._counterexample_hits({path: altered}, "MODEL") != ()
    result = catalog.apply_domain_original_kind_profile(tmp_path, rows, files)
    model = result["vstd-domain-checking-primitives"]["classification"]["MODEL"]
    assert model["status"] == catalog.UNRESOLVED


def test_injected_negative_on_proposed_cell_fails_closed(tmp_path: Path):
    rows, files = _fixture(tmp_path)
    rows["vstd-domain-checking-primitives"]["classification"]["MODEL"] = {
        "status": catalog.DOES_NOT_APPLY,
        "reason": "Invented identity refutation.",
        "evidence": [],
    }
    with pytest.raises(
        ValueError,
        match=(
            "PACKAGE_DOMAIN_ORIGINAL_KIND_UNREVIEWED_DECISION:"
            "vstd-domain-checking-primitives:MODEL"
        ),
    ):
        catalog.apply_domain_original_kind_profile(tmp_path, rows, files)


def test_proposed_cell_cannot_be_flipped_to_applies_without_review(tmp_path: Path):
    rows, files = _fixture(tmp_path)
    rows["vstd-domain-checking-primitives"]["classification"]["MODEL"] = {
        "status": APPLIES,
        "reason": "Invented affirmative role.",
        "evidence": [],
    }
    with pytest.raises(
        ValueError,
        match=(
            "PACKAGE_DOMAIN_ORIGINAL_KIND_UNREVIEWED_DECISION:"
            "vstd-domain-checking-primitives:MODEL"
        ),
    ):
        catalog.apply_domain_original_kind_profile(tmp_path, rows, files)


def test_object_label_cannot_bypass_the_exact_primary_role(tmp_path: Path):
    rows, files = _fixture(tmp_path)
    rows["vstd-domain-certificate-engine"]["kind"] = "OBJECT"
    with pytest.raises(
        ValueError,
        match=(
            "PACKAGE_DOMAIN_ORIGINAL_KIND_PRIMARY_DIFFERS:"
            "vstd-domain-certificate-engine"
        ),
    ):
        catalog.apply_domain_original_kind_profile(tmp_path, rows, files)


def test_inventory_pin_binds_raw_bytes_to_executable_ast_and_doc_claim():
    raw = (ROOT / INVENTORY_PATH).read_bytes()
    assert _digest(raw) == INVENTORY_RAW_SHA256
    assert catalog._EXPECTED_SOURCE_DIGESTS[INVENTORY_PATH] == INVENTORY_RAW_SHA256
    # A raw re-pin after an executable edit must still fail here.
    assert (
        canonical_executable_ast_sha256(raw.decode("utf-8"))
        == INVENTORY_CANONICAL_EXECUTABLE_AST_SHA256
    )
    document = ast.get_docstring(ast.parse(raw), clean=False)
    assert document is not None
    normalized = " ".join(document.split())
    assert "retained 26-``ObjectKind`` by nine-tier native" in normalized
    assert "12 accumulating consequential roles, for 38 kinds in total" in normalized
    assert "does not discharge their obligations" in normalized


def test_canonical_executable_digest_ignores_docstrings_but_sees_code_edits():
    raw = (ROOT / INVENTORY_PATH).read_text(encoding="utf-8")
    golden = INVENTORY_CANONICAL_EXECUTABLE_AST_SHA256
    doc_only = raw.replace("Verifier Standard (VSTD).", "Verifier Standard (VSTD). Extra prose.", 1)
    assert doc_only != raw
    assert canonical_executable_ast_sha256(doc_only) == golden
    # Bad fixture: one executable statement added; the same golden must reject it.
    code_edit = raw.replace("from __future__ import annotations", "from __future__ import annotations\n_PROBE = 1", 1)
    assert code_edit != raw
    assert canonical_executable_ast_sha256(code_edit) != golden


def test_inventory_audit_row_keeps_unresolved_cells_and_no_effect_boundary():
    # POLICY is an extensible role, outside the 25 original non-OBJECT kinds, so
    # the native inventory owner carries no affirmative original-kind cell.
    audit = _audits()[INVENTORY]
    assert audit.expected_primary == "POLICY"
    assert "POLICY" not in ORIGINAL_NON_OBJECT_KINDS
    assert audit.expected_owned_paths == (INVENTORY_PATH,)
    assert "does not discharge extensible-role obligations" in audit.scope_reason
    assert all(question.status == catalog.UNRESOLVED for question in audit.questions)
    assert all(
        INVENTORY_PATH in question.reason for question in audit.questions
    )
    assert INVENTORY not in {
        assignment.object_id for assignment in catalog.DOMAIN_ORIGINAL_KIND_PROFILE.assignments
    }
