from __future__ import annotations

import ast
from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
from pathlib import Path

import pytest

from verifier.runtime import package_namespace_review as review
from verifier.runtime import package_protocol_dependency_relation as relation
from verifier.runtime.namespace_contracts import namespace_registry, requirements_for


EXPECTED_APPLICABILITY = {
    "vstd-core-pure-verifier": set(),
    "vstd-hardware": {"ASSET", "MEASUREMENT", "POLICY"},
    "vstd-simulation": {
        "TRANSACTION",
        "MEASUREMENT",
        "SENSOR",
        "ACTUATOR",
        "PROTOCOL",
        "POLICY",
    },
    "vstd-harness": {
        "TRANSACTION",
        "MEASUREMENT",
        "SENSOR",
        "ACTUATOR",
        "PROTOCOL",
        "POLICY",
    },
    "vstd-invocation-ledger": {"LEDGER", "TRANSACTION", "PROTOCOL", "POLICY"},
    "vstd-manifest-write": {"TRANSACTION", "PROTOCOL"},
    relation.OBJECT_ID: set(),
    "vstd-openshell-environment": {
        "TRANSACTION",
        "MEASUREMENT",
        "SENSOR",
        "CONTROLLER",
        "ACTUATOR",
        "PROTOCOL",
        "POLICY",
    },
}


# Literal DOES_NOT_APPLY bases that survived the source audit.  Every other
# non-APPLIES kind is UNRESOLVED: absence of role vocabulary or an import
# inventory is not an affirmative exclusion.
EXPECTED_DOES_NOT_APPLY = {
    "vstd-core-pure-verifier": set(),
    "vstd-hardware": set(),
    "vstd-simulation": set(),
    "vstd-harness": {"LEDGER"},
    "vstd-invocation-ledger": {"FINBOT"},
    "vstd-manifest-write": set(),
    relation.OBJECT_ID: set(),
    "vstd-openshell-environment": {"LEDGER"},
}


EXPECTED_HARNESS_OWNED_PATHS = (
    "extensions/languages/pyproject.toml",
    "extensions/languages/src/vstd_languages/__init__.py",
    "extensions/languages/src/vstd_languages/extended_batch_two.py",
    "extensions/languages/src/vstd_languages/extended_batch_three.py",
    "src/verifier/core/owned_process.py",
    "src/verifier/core/run.py",
    "src/verifier/core/run_impact.py",
    "src/verifier/core/run_inspection.py",
    "src/verifier/core/run_planning.py",
    "src/verifier/core/run_process_observation.py",
    "src/verifier/core/run_reproduction.py",
    "src/verifier/core/run_support.py",
    "src/verifier/core/run_validation.py",
    "src/verifier/domains/harness.py",
    "src/verifier/domains/contracts/harness_checks.py",
    "src/verifier/domains/contracts/harness_gap_boundary.py",
    "src/verifier/runtime/language_runners.py",
    "src/verifier/runtime/package_harness_applicability.py",
)

EXPECTED_HARNESS_TRANSACTION_PATHS = (
    "src/verifier/core/run.py",
    "src/verifier/core/run_reproduction.py",
    "src/verifier/core/run_process_observation.py",
    "src/verifier/core/owned_process.py",
    "src/verifier/runtime/language_runners.py",
    "extensions/languages/src/vstd_languages/__init__.py",
    "extensions/languages/src/vstd_languages/extended_batch_two.py",
    "extensions/languages/src/vstd_languages/extended_batch_three.py",
)

HARNESS_RETAINED_EXECUTION_PATHS = {
    "src/verifier/core/owned_process.py",
    "extensions/languages/src/vstd_languages/extended_batch_two.py",
    "extensions/languages/src/vstd_languages/extended_batch_three.py",
}


def _digest(raw: bytes) -> str:
    return "sha256:" + sha256(raw).hexdigest()


def _all_obligations() -> dict[str, dict]:
    result = {}
    registry = namespace_registry()
    for kind in review.REVIEW_KINDS:
        for obligation in requirements_for(registry, (kind,)):
            if obligation["kind"] != kind:
                continue
            result[obligation["id"]] = {
                "reason": "",
                "evidence": [],
                "declaration": {
                    field: "" for field in obligation["declaration_fields"]
                },
            }
    return result


def _workspace(tmp_path: Path) -> tuple[Path, dict[str, dict], dict[str, str]]:
    catalog = review.review_document()
    anchors: dict[str, list[str]] = {}
    dependency_targets: set[str] = set()
    for basis in review._REVIEWS.values():
        for cited in basis.refutation_anchors.values():
            for path, values in cited.items():
                anchors.setdefault(path, []).extend(values)
        for dependency in basis.dependency_operands.values():
            for path, values in dependency.anchors.items():
                anchors.setdefault(path, []).extend(values)
            dependency_targets.update(dependency.target_evidence_paths)
    rows = {}
    files = {}
    for object_id, item in catalog.items():
        for path in item["owned_paths"]:
            target = tmp_path / path
            target.parent.mkdir(parents=True, exist_ok=True)
            raw = (object_id + "\0" + path + "\n").encode()
            raw += "".join(anchor + "\n" for anchor in anchors.get(path, [])).encode()
            target.write_bytes(raw)
            files[path] = _digest(raw)
        rows[object_id] = {
            "object_id": object_id,
            "kind": item["primary_kind"],
            "specializations": [],
            "payload": {},
            "operands": {},
            "surfaces": ["file:" + path for path in item["owned_paths"]],
            "reason": "Synthetic exact owner for the review mechanism test.",
            "classification": {
                kind: {
                    "status": "UNRESOLVED",
                    "reason": "Not yet reviewed.",
                    "evidence": [],
                }
                for kind in review.REVIEW_KINDS
            },
            "obligations": _all_obligations(),
        }
    for path in sorted(dependency_targets):
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        raw = ("dependency\0" + path + "\n").encode()
        raw += "".join(anchor + "\n" for anchor in anchors[path]).encode()
        target.write_bytes(raw)
        files[path] = _digest(raw)
    return tmp_path, rows, files


def test_review_catalog_has_complete_exact_matrices_and_declarations():
    catalog = review.review_document()
    registry = namespace_registry()
    assert set(catalog) == set(EXPECTED_APPLICABILITY)
    assert review.REVIEW_KINDS == (
        "LEDGER",
        "TRANSACTION",
        "ASSET",
        "MARKET",
        "MEASUREMENT",
        "SENSOR",
        "CONTROLLER",
        "ACTUATOR",
        "PROTOCOL",
        "POLICY",
        "ROBOT",
        "FINBOT",
    )
    assert sum(len(item["declarations"]) for item in catalog.values()) == 84

    for object_id, item in catalog.items():
        basis = review._REVIEWS[object_id]
        assert not (set(basis.applicable) & set(basis.refuted))
        assert set(basis.applicable) | set(basis.refuted) <= set(review.REVIEW_KINDS)
        assert set(basis.reasons) == set(basis.applicable) | set(basis.refuted)
        classifications = item["classification"]
        assert set(classifications) == set(review.REVIEW_KINDS)
        assert {
            kind
            for kind, decision in classifications.items()
            if decision["status"] == "APPLIES"
        } == EXPECTED_APPLICABILITY[object_id]
        assert {
            kind
            for kind, decision in classifications.items()
            if decision["status"] == "DOES_NOT_APPLY"
        } == set(basis.refuted) == EXPECTED_DOES_NOT_APPLY[object_id]
        assert {
            kind
            for kind, decision in classifications.items()
            if decision["status"] == "UNRESOLVED"
        } == set(review.REVIEW_KINDS) - set(basis.applicable) - set(basis.refuted)
        assert all(decision["reason"].strip() for decision in classifications.values())
        for decision in classifications.values():
            if decision["status"] == "UNRESOLVED":
                assert decision["evidence_paths"] == []
            else:
                assert decision["evidence_paths"]
        assert all(
            set(decision["evidence_paths"]) <= set(item["owned_paths"])
            for decision in classifications.values()
        )

        expected = {}
        for kind in EXPECTED_APPLICABILITY[object_id]:
            for obligation in requirements_for(registry, (kind,)):
                if obligation["kind"] == kind:
                    expected[obligation["id"]] = set(obligation["declaration_fields"])
        assert set(item["declarations"]) == set(expected)
        for obligation_id, fields in item["declarations"].items():
            assert set(fields) == expected[obligation_id]
            assert all(value.strip() for value in fields.values())


def test_openshell_review_is_optional_env_and_retains_only_proven_refutations() -> None:
    item = review.review_document()["vstd-openshell-environment"]
    assert item["primary_kind"] == "ENV"
    assert set(item["classification"]) == set(review.REVIEW_KINDS)
    assert item["classification"]["LEDGER"]["status"] == "DOES_NOT_APPLY"
    assert "ephemeral-stop-contained" in item["classification"]["LEDGER"]["reason"]
    assert item["classification"]["ROBOT"]["status"] == "UNRESOLVED"
    assert item["classification"]["FINBOT"]["status"] == "UNRESOLVED"
    assert (
        "explicitly selected optional OpenShell"
        in item["declarations"]["POLICY-0.1-rules-and-precedence"]["scope"]
    )
    assert (
        "not selected by the basic runner"
        in item["declarations"]["POLICY-0.1-rules-and-precedence"]["defaults"]
    )


def test_invocation_ledger_protocol_is_exact_bounded_and_non_authoritative() -> None:
    item = review.review_document()["vstd-invocation-ledger"]
    protocol = item["classification"]["PROTOCOL"]
    assert protocol["status"] == "APPLIES"
    assert protocol["evidence_paths"] == [
        "src/verifier/runtime/local_ledger_execution.py",
        "src/verifier/runtime/local_ledger_worker.py",
    ]
    declarations = {
        name: value
        for name, value in item["declarations"].items()
        if name.startswith("PROTOCOL-")
    }
    assert set(declarations) == {
        "PROTOCOL-0.1-participants-and-states",
        "PROTOCOL-0.2-ordering-and-replay",
        "PROTOCOL-0.3-failures-and-progress",
    }
    flattened = " ".join(
        value
        for declaration in declarations.values()
        for value in declaration.values()
    )
    assert "authenticate no actor" in flattened
    assert "no automatic retry" in flattened
    assert "No completion or availability guarantee" in flattened
    assert "not a sandbox" in flattened


def test_pure_verifier_child_keeps_added_roles_unresolved_without_positive_refutation() -> None:
    item = review.review_document()["vstd-core-pure-verifier"]
    assert item["primary_kind"] == "VERIFIER"
    assert len(item["owned_paths"]) == 12
    assert not item["declarations"]
    # Import/call inventories and absent vocabulary do not exclude a role on
    # their own, and the owned imports reach subprocess transitively.
    assert all(
        decision["status"] == "UNRESOLVED" and decision["evidence_paths"] == []
        for decision in item["classification"].values()
    )
    assert item["classification"]["ACTUATOR"]["reason"] == review._unresolved_reason(
        "ACTUATOR"
    )


def test_apply_is_pure_complete_deterministic_and_idempotent(tmp_path):
    root, rows, files = _workspace(tmp_path)
    before = deepcopy(rows)
    first = review.apply_package_namespace_review(root, rows, files)
    second = review.apply_package_namespace_review(root, first, files)

    assert rows == before
    assert first == second
    for object_id, row in first.items():
        applies = EXPECTED_APPLICABILITY[object_id]
        refuted = EXPECTED_DOES_NOT_APPLY[object_id]
        assert {
            kind
            for kind, decision in row["classification"].items()
            if decision["status"] == "APPLIES"
        } == applies
        assert all(
            decision["status"]
            == (
                "APPLIES"
                if kind in applies
                else "DOES_NOT_APPLY"
                if kind in refuted
                else "UNRESOLVED"
            )
            for kind, decision in row["classification"].items()
        )
        assert applies - {row["kind"]} <= set(row["specializations"])
        assert all(
            obligation_id.split("-", 1)[0] in applies
            for obligation_id in row["obligations"]
        )
        assert all(binding["reason"].strip() for binding in row["obligations"].values())
        assert all(binding["evidence"] for binding in row["obligations"].values())
        assert all(
            decision["evidence"] == []
            for decision in row["classification"].values()
            if decision["status"] == "UNRESOLVED"
        )
        assert all(
            value.strip()
            for binding in row["obligations"].values()
            for value in binding["declaration"].values()
        )


def test_apply_preserves_complete_current_same_status_reviews(tmp_path):
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_namespace_review(root, rows, files)
    expected = deepcopy(selected)

    result = review.apply_package_namespace_review(root, selected, files)
    assert result == expected


def test_unreviewed_extra_object_is_not_classified_by_catalog_complement(tmp_path):
    root, rows, files = _workspace(tmp_path)
    future = deepcopy(rows["vstd-core-pure-verifier"])
    future["object_id"] = "future-namespace-object"
    future["surfaces"] = []
    rows[future["object_id"]] = future

    result = review.apply_package_namespace_review(root, rows, files)

    assert result[future["object_id"]] == future
    assert {
        decision["status"] for decision in future["classification"].values()
    } == {"UNRESOLVED"}


def test_unlisted_kind_is_unresolved_and_invented_dne_fails_closed(
    tmp_path, monkeypatch
):
    object_id = "vstd-invocation-ledger"
    original = review._REVIEWS[object_id]
    narrowed = replace(
        original,
        refuted=tuple(kind for kind in original.refuted if kind != "FINBOT"),
        reasons={
            kind: reason
            for kind, reason in original.reasons.items()
            if kind != "FINBOT"
        },
        refutation_anchors={
            kind: cited
            for kind, cited in original.refutation_anchors.items()
            if kind != "FINBOT"
        },
    )
    monkeypatch.setitem(review._REVIEWS, object_id, narrowed)
    root, rows, files = _workspace(tmp_path)

    result = review.apply_package_namespace_review(root, rows, files)
    assert result[object_id]["classification"]["FINBOT"] == {
        "status": "UNRESOLVED",
        "reason": review._unresolved_reason("FINBOT"),
        "evidence": [],
    }

    result[object_id]["classification"]["FINBOT"] = {
        "status": "DOES_NOT_APPLY",
        "reason": "Invented from absence.",
        "evidence": deepcopy(
            result[object_id]["classification"]["TRANSACTION"]["evidence"]
        ),
    }
    before = deepcopy(result)
    with pytest.raises(ValueError, match="PACKAGE_NAMESPACE_REVIEW_DECISION_CONFLICT"):
        review.apply_package_namespace_review(root, result, files)
    assert result == before


@pytest.mark.parametrize("failure", ["stale", "missing", "unowned", "extra_owned"])
def test_apply_rejects_source_or_ownership_drift_without_mutation(tmp_path, failure):
    root, rows, files = _workspace(tmp_path)
    before = deepcopy(rows)
    object_id = "vstd-hardware"
    path = review.review_document()[object_id]["owned_paths"][0]
    if failure == "stale":
        files[path] = "sha256:" + "0" * 64
    elif failure == "missing":
        (root / path).unlink()
    elif failure == "unowned":
        rows[object_id]["surfaces"].remove("file:" + path)
        before = deepcopy(rows)
    else:
        rows[object_id]["surfaces"].append("file:unreviewed/new_hardware.py")
        before = deepcopy(rows)

    with pytest.raises(ValueError) as caught:
        review.apply_package_namespace_review(root, rows, files)
    assert str(caught.value) == EXPECTED_DRIFT_CODE[failure].format(path=path)
    assert rows == before


@pytest.mark.parametrize(
    "failure",
    [
        "status",
        "stale_decision",
        "partial_declaration",
        "refuted_declaration",
        "reason_substitution",
        "refutation_substitution",
        "obligation_reason_substitution",
        "label_conflict",
        "unknown_obligation",
    ],
)
def test_apply_refuses_review_conflicts_atomically(tmp_path, failure):
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_namespace_review(root, rows, files)
    if failure == "status":
        selected["vstd-manifest-write"]["classification"]["TRANSACTION"]["status"] = (
            "DOES_NOT_APPLY"
        )
    elif failure == "stale_decision":
        selected["vstd-manifest-write"]["classification"]["TRANSACTION"]["evidence"][0][
            "sha256"
        ] = "sha256:" + "f" * 64
    elif failure == "partial_declaration":
        selected["vstd-manifest-write"]["obligations"][
            "TRANSACTION-0.1-effects-and-authority"
        ]["declaration"]["effects"] = ""
    elif failure == "refuted_declaration":
        hardware = selected["vstd-hardware"]
        hardware["obligations"]["SENSOR-0.1-acquisition-and-observations"] = {
            "reason": "A contradictory reviewed SENSOR declaration.",
            "evidence": deepcopy(hardware["classification"]["SENSOR"]["evidence"]),
            "declaration": {
                field: "Contradictory " + field
                for field in (
                    "acquisition",
                    "phenomena",
                    "measurements",
                    "deployment",
                )
            },
        }
    elif failure == "reason_substitution":
        selected["vstd-manifest-write"]["classification"]["TRANSACTION"][
            "reason"
        ] = "Different same-status reason."
    elif failure == "refutation_substitution":
        selected["vstd-invocation-ledger"]["classification"]["FINBOT"]["reason"] = (
            "Different same-status refutation."
        )
    elif failure == "obligation_reason_substitution":
        selected["vstd-manifest-write"]["obligations"][
            "TRANSACTION-0.1-effects-and-authority"
        ]["reason"] = "Different same-shape declaration reason."
    elif failure == "label_conflict":
        selected["vstd-hardware"]["specializations"].append("SENSOR")
    else:
        selected["vstd-manifest-write"]["obligations"][
            "TRANSACTION-0.99-invented"
        ] = {"reason": "Invented.", "evidence": [], "declaration": {}}
    before = deepcopy(selected)

    with pytest.raises(ValueError) as caught:
        review.apply_package_namespace_review(root, selected, files)
    assert str(caught.value) == EXPECTED_CONFLICT_CODE[failure]
    assert selected == before


def test_record_gaps_rederives_stale_obligation_text_and_keeps_the_declaration(
    tmp_path,
):
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_namespace_review(root, rows, files)
    name = "TRANSACTION-0.1-effects-and-authority"
    binding = selected["vstd-manifest-write"]["obligations"][name]
    expected = deepcopy(binding)
    binding["reason"] = "An older generated reason."
    binding["declaration"]["effects"] = "Authored wording survives regeneration."
    before = deepcopy(selected)

    with pytest.raises(ValueError) as caught:
        review.apply_package_namespace_review(root, selected, files)
    assert str(caught.value) == EXPECTED_CONFLICT_CODE["obligation_reason_substitution"]

    result = review.apply_package_namespace_review(
        root, selected, files, record_gaps=True
    )
    got = result["vstd-manifest-write"]["obligations"][name]
    assert got["reason"] == expected["reason"]
    assert got["evidence"] == expected["evidence"]
    assert got["declaration"]["effects"] == "Authored wording survives regeneration."
    assert {
        field: value
        for field, value in got["declaration"].items()
        if field != "effects"
    } == {
        field: value
        for field, value in expected["declaration"].items()
        if field != "effects"
    }
    assert selected == before


@pytest.mark.parametrize("failure", ["stale_source", "partial_declaration"])
def test_record_gaps_never_rederives_over_source_drift_or_a_blank_field(
    tmp_path, failure
):
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_namespace_review(root, rows, files)
    name = "TRANSACTION-0.1-effects-and-authority"
    binding = selected["vstd-manifest-write"]["obligations"][name]
    binding["reason"] = "An older generated reason."
    if failure == "stale_source":
        binding["evidence"][0]["sha256"] = "sha256:" + "f" * 64
    else:
        binding["declaration"]["effects"] = ""
    before = deepcopy(selected)

    with pytest.raises(ValueError) as caught:
        review.apply_package_namespace_review(
            root, selected, files, record_gaps=True
        )
    assert str(caught.value) == EXPECTED_CONFLICT_CODE["partial_declaration"]
    assert selected == before


def test_apply_rechecks_complete_source_denominator_before_mutation(
    tmp_path, monkeypatch
):
    root, rows, files = _workspace(tmp_path)
    target_id = "vstd-openshell-environment"
    original = review._source_evidence
    calls = 0

    def drifting_source(selected_root, paths, *, object_id):
        nonlocal calls
        evidence = original(selected_root, paths, object_id=object_id)
        if object_id == target_id:
            calls += 1
            if calls == 2:
                evidence[-1] = {
                    "path": evidence[-1]["path"],
                    "sha256": "sha256:" + "a" * 64,
                }
        return evidence

    monkeypatch.setattr(review, "_source_evidence", drifting_source)
    before = deepcopy(rows)
    with pytest.raises(ValueError, match="PACKAGE_NAMESPACE_REVIEW_SOURCE_CHANGED"):
        review.apply_package_namespace_review(root, rows, files)
    assert rows == before


def test_role_boundaries_keep_sim_launch_hardware_and_consequences_distinct():
    catalog = review.review_document()
    hardware = catalog["vstd-hardware"]
    sim = catalog["vstd-simulation"]
    harness = catalog["vstd-harness"]

    assert hardware["classification"]["SENSOR"]["status"] == "UNRESOLVED"
    assert hardware["classification"]["SENSOR"]["evidence_paths"] == []
    assert (
        "SIMULATED_MODEL_ONLY"
        in sim["declarations"]["ACTUATOR-0.1-command-to-effect"]["effect_domains"]
    )
    sim_transaction_evidence = sim["classification"]["TRANSACTION"]["evidence_paths"]
    assert sim_transaction_evidence == [
        "src/verifier/domains/contracts/sim_resource_fresh.py",
        "src/verifier/domains/contracts/sim_fresh_bootstrap.py",
        "src/verifier/domains/contracts/sim_fresh_worker.py",
    ]
    assert "src/verifier/domains/sim.py" not in sim_transaction_evidence
    assert (
        "src/verifier/domains/contracts/sim_response.py"
        in sim["classification"]["ACTUATOR"]["evidence_paths"]
    )
    sim_protocol_evidence = sim["classification"]["PROTOCOL"]["evidence_paths"]
    assert (
        "src/verifier/domains/contracts/sim_resource_fresh.py" in sim_protocol_evidence
    )
    assert (
        "src/verifier/domains/contracts/sim_fresh_bootstrap.py" in sim_protocol_evidence
    )
    assert "src/verifier/domains/contracts/sim_fresh_worker.py" in sim_protocol_evidence
    assert sim["classification"]["ROBOT"]["status"] == "UNRESOLVED"
    assert sim["classification"]["ROBOT"]["reason"] == review._unresolved_reason("ROBOT")
    assert (
        "LAUNCH_SUBMISSION"
        in harness["declarations"]["ACTUATOR-0.1-command-to-effect"]["effect_domains"]
    )
    assert (
        "does not establish any subject or external effect"
        in harness["classification"]["ACTUATOR"]["reason"]
    )
    assert (
        "not transactional commit"
        in harness["declarations"]["TRANSACTION-0.2-commit-and-failure"]["commit"]
    )
    for object_id, item in catalog.items():
        for kind in ("ROBOT", "FINBOT"):
            expected = (
                "DOES_NOT_APPLY"
                if kind in EXPECTED_DOES_NOT_APPLY[object_id]
                else "UNRESOLVED"
            )
            assert item["classification"][kind]["status"] == expected
        assert "Tier-0" in item["claim_boundary"]
        assert "Tier-1-plus" in item["claim_boundary"]


def test_harness_review_closes_exact_retained_source_and_accumulates_roles():
    item = review.review_document()["vstd-harness"]

    assert tuple(item["owned_paths"]) == EXPECTED_HARNESS_OWNED_PATHS
    assert len(item["owned_paths"]) == 18
    ledger = item["classification"]["LEDGER"]
    assert ledger["status"] == "DOES_NOT_APPLY"
    assert "no authoritative" in ledger["reason"]
    assert tuple(ledger["evidence_paths"]) == EXPECTED_HARNESS_OWNED_PATHS

    transaction = item["classification"]["TRANSACTION"]
    assert transaction["status"] == "APPLIES"
    assert tuple(transaction["evidence_paths"]) == EXPECTED_HARNESS_TRANSACTION_PATHS
    assert "process exit is not transaction commit" in transaction["reason"]

    # The retained process primitive and the two native adapter workers execute,
    # observe, bound, and report launches.  They therefore accumulate every
    # applicable HARNESS role rather than appearing only in ownership metadata.
    for kind in EXPECTED_APPLICABILITY["vstd-harness"]:
        assert HARNESS_RETAINED_EXECUTION_PATHS <= set(
            item["classification"][kind]["evidence_paths"]
        )
    assert (
        "undeclared subject effects remain explicitly unobserved"
        in item["declarations"]["TRANSACTION-0.1-effects-and-authority"]["effects"]
    )
    assert (
        "no subject or real-world effect is inferred"
        in item["declarations"]["ACTUATOR-0.1-command-to-effect"]["effect_domains"]
    )


def test_harness_ledger_closure_anchors_are_present_in_current_source():
    root = Path(__file__).resolve().parents[1]
    basis = review._REVIEWS["vstd-harness"]
    cited = basis.refutation_anchors["LEDGER"]

    assert tuple(cited) == EXPECTED_HARNESS_OWNED_PATHS
    for path, anchors in cited.items():
        source = (root / path).read_bytes().decode("utf-8", errors="replace")
        assert all(anchor in source for anchor in anchors), path
    review._require_refutation_anchors(root, basis, object_id="vstd-harness")


def test_retained_refutations_cite_explicit_source_exclusions() -> None:
    catalog = review.review_document()
    harness = catalog["vstd-harness"]["classification"]
    ledger = catalog["vstd-invocation-ledger"]["classification"]
    openshell = catalog["vstd-openshell-environment"]["classification"]
    # The HARNESS self-description "not the actor" does not exclude ROBOT or
    # FINBOT: the installed contracts bind the governing harness into the
    # effect path, so both remain UNRESOLVED rather than refuted.
    assert harness["ROBOT"]["status"] == "UNRESOLVED"
    assert harness["FINBOT"]["status"] == "UNRESOLVED"
    assert ledger["FINBOT"]["evidence_paths"] == SECOND_PASS_REFUTATION_EVIDENCE[
        ("vstd-invocation-ledger", "FINBOT")
    ]
    assert "monetary accounting" in ledger["FINBOT"]["reason"]
    assert "ephemeral-stop-contained" in openshell["LEDGER"]["reason"]


@pytest.mark.parametrize(
    ("object_id", "kind"),
    [
        ("vstd-core-pure-verifier", "LEDGER"),
        ("vstd-hardware", "ROBOT"),
        ("vstd-manifest-write", "FINBOT"),
        ("vstd-simulation", "ROBOT"),
        ("vstd-harness", "ROBOT"),
        ("vstd-harness", "FINBOT"),
    ],
)
def test_demoted_refutation_forged_as_complete_decision_fails_closed(
    tmp_path, object_id, kind
):
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_namespace_review(root, rows, files)
    owned = review.review_document()[object_id]["owned_paths"]
    selected[object_id]["classification"][kind] = {
        "status": "DOES_NOT_APPLY",
        "reason": "Forged refutation carried over from an older table.",
        "evidence": [{"path": path, "sha256": files[path]} for path in owned],
    }
    before = deepcopy(selected)
    with pytest.raises(ValueError, match="PACKAGE_NAMESPACE_REVIEW_DECISION_CONFLICT"):
        review.apply_package_namespace_review(root, selected, files)
    assert selected == before


# Second-pass RED tests.  Each one fails against the first-pass catalog and
# pins a repaired failure class: a refutation that rests on simulation or object
# labeling, a refutation whose evidence is the whole owned denominator rather
# than the source that carries the exclusion, and a cited exclusion whose
# anchor text is absent from the current source.
OLD_SIM_ROBOT_REASON = (
    "The SIM isolation checker lists external_actuation as a boundary effect and "
    "refutes it when reached (sim_isolation.py, _BOUNDARY_EFFECTS), so an admitted "
    "SIM result cannot itself be a real-world actuation; simulated actions remain "
    "model consequences."
)

SECOND_PASS_REFUTATION_EVIDENCE = {
    ("vstd-harness", "LEDGER"): list(EXPECTED_HARNESS_OWNED_PATHS),
    ("vstd-invocation-ledger", "FINBOT"): [
        "src/verifier/runtime/local_ledger_execution.py",
        "src/verifier/runtime/polish_invocation_ledger.py",
    ],
    ("vstd-openshell-environment", "LEDGER"): [
        "extensions/openshell/src/vstd_openshell/__init__.py",
    ],
}


def test_second_pass_demotes_simulation_and_harness_refutations_to_unresolved():
    catalog = review.review_document()
    assert catalog["vstd-simulation"]["classification"]["ROBOT"]["status"] == "UNRESOLVED"
    assert catalog["vstd-harness"]["classification"]["ROBOT"]["status"] == "UNRESOLVED"
    assert catalog["vstd-harness"]["classification"]["FINBOT"]["status"] == "UNRESOLVED"


def test_refutation_evidence_cites_exactly_the_source_that_carries_the_exclusion():
    catalog = review.review_document()
    for object_id, item in catalog.items():
        for kind, decision in item["classification"].items():
            if decision["status"] != "DOES_NOT_APPLY":
                continue
            assert decision["evidence_paths"] == SECOND_PASS_REFUTATION_EVIDENCE[
                (object_id, kind)
            ], (object_id, kind)
    assert {
        (object_id, kind)
        for object_id, item in catalog.items()
        for kind, decision in item["classification"].items()
        if decision["status"] == "DOES_NOT_APPLY"
    } == set(SECOND_PASS_REFUTATION_EVIDENCE)


def test_stale_simulation_robot_refutation_verdict_fails_closed(tmp_path):
    root, rows, files = _workspace(tmp_path)
    owned = review.review_document()["vstd-simulation"]["owned_paths"]
    rows["vstd-simulation"]["classification"]["ROBOT"] = {
        "status": "DOES_NOT_APPLY",
        "reason": OLD_SIM_ROBOT_REASON,
        "evidence": [{"path": path, "sha256": files[path]} for path in owned],
    }
    before = deepcopy(rows)
    with pytest.raises(
        ValueError,
        match="PACKAGE_NAMESPACE_REVIEW_DECISION_CONFLICT:vstd-simulation:ROBOT",
    ):
        review.apply_package_namespace_review(root, rows, files)
    assert rows == before


def test_refutation_anchor_missing_from_cited_source_fails_closed(tmp_path):
    root, rows, files = _workspace(tmp_path)
    cited = "src/verifier/runtime/polish_invocation_ledger.py"
    (root / cited).write_bytes(b"# no ledger boundary declaration here\n")
    files[cited] = _digest((root / cited).read_bytes())
    before = deepcopy(rows)
    with pytest.raises(
        ValueError,
        match="PACKAGE_NAMESPACE_REVIEW_REFUTATION_ANCHOR_MISSING:vstd-invocation-ledger:FINBOT",
    ):
        review.apply_package_namespace_review(root, rows, files)
    assert rows == before


@pytest.mark.parametrize("cited", EXPECTED_HARNESS_OWNED_PATHS)
def test_harness_ledger_closure_anchor_drift_fails_closed(tmp_path, cited):
    root, rows, files = _workspace(tmp_path)
    anchor = review._HARNESS_LEDGER_REFUTATION_ANCHORS[cited][0]
    target = root / cited
    source = target.read_text(encoding="utf-8")
    assert anchor in source
    target.write_text(
        source.replace(anchor, "HARNESS review anchor removed", 1), encoding="utf-8"
    )
    files[cited] = _digest(target.read_bytes())
    before = deepcopy(rows)

    with pytest.raises(ValueError) as caught:
        review.apply_package_namespace_review(root, rows, files)
    assert str(caught.value) == (
        "PACKAGE_NAMESPACE_REVIEW_REFUTATION_ANCHOR_MISSING:vstd-harness:LEDGER"
    )
    assert rows == before


# Second-pass regressions.  Diagnostics are compared in full so that a different
# failure class cannot satisfy a prefix match, and the cross-owned parent/child
# facts are checked against their actual source bytes.

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
PURE_VERIFIER = "vstd-core-pure-verifier"
PARENT_EXECUTION = "src/verifier/runtime/package_execution.py"
OPENSHELL_INIT = "extensions/openshell/src/vstd_openshell/__init__.py"

EXPECTED_DRIFT_CODE = {
    "stale": "PACKAGE_NAMESPACE_REVIEW_SOURCE_DIFFERS:vstd-hardware:{path}",
    "missing": "PACKAGE_NAMESPACE_REVIEW_SOURCE_UNAVAILABLE:vstd-hardware:{path}",
    "unowned": "PACKAGE_NAMESPACE_REVIEW_OWNERSHIP_DIFFERS:vstd-hardware",
    "extra_owned": "PACKAGE_NAMESPACE_REVIEW_OWNERSHIP_DIFFERS:vstd-hardware",
}

EXPECTED_CONFLICT_CODE = {
    "status": "PACKAGE_NAMESPACE_REVIEW_DECISION_CONFLICT:vstd-manifest-write:TRANSACTION",
    "stale_decision": "PACKAGE_NAMESPACE_REVIEW_DECISION_CONFLICT:vstd-manifest-write:TRANSACTION",
    "partial_declaration": (
        "PACKAGE_NAMESPACE_REVIEW_DECLARATION_CONFLICT:vstd-manifest-write:"
        "TRANSACTION-0.1-effects-and-authority"
    ),
    "refuted_declaration": (
        "PACKAGE_NAMESPACE_REVIEW_UNLISTED_DECLARATION_CONFLICT:vstd-hardware:"
        "SENSOR-0.1-acquisition-and-observations"
    ),
    "reason_substitution": "PACKAGE_NAMESPACE_REVIEW_DECISION_CONFLICT:vstd-manifest-write:TRANSACTION",
    "refutation_substitution": "PACKAGE_NAMESPACE_REVIEW_DECISION_CONFLICT:vstd-invocation-ledger:FINBOT",
    "obligation_reason_substitution": (
        "PACKAGE_NAMESPACE_REVIEW_DECLARATION_CONFLICT:vstd-manifest-write:"
        "TRANSACTION-0.1-effects-and-authority"
    ),
    "label_conflict": "PACKAGE_NAMESPACE_REVIEW_LABEL_CONFLICT:vstd-hardware:SENSOR",
    "unknown_obligation": (
        "PACKAGE_NAMESPACE_REVIEW_OBLIGATION_UNKNOWN:vstd-manifest-write:"
        "TRANSACTION-0.99-invented"
    ),
}


def test_foreign_prefixed_obligation_fails_closed_without_mutation(tmp_path):
    root, rows, files = _workspace(tmp_path)
    rows["vstd-manifest-write"]["obligations"]["BOGUS-0.1-foreign"] = {
        "reason": "",
        "evidence": [],
        "declaration": {},
    }
    before = deepcopy(rows)

    with pytest.raises(ValueError) as caught:
        review.apply_package_namespace_review(root, rows, files)
    assert str(caught.value) == (
        "PACKAGE_NAMESPACE_REVIEW_OBLIGATION_UNKNOWN:vstd-manifest-write:BOGUS-0.1-foreign"
    )
    assert rows == before


def test_openshell_ledger_refutation_cites_only_the_enforced_refusals():
    cited = review._REVIEWS["vstd-openshell-environment"].refutation_anchors["LEDGER"]
    assert tuple(cited) == (OPENSHELL_INIT,)
    # The delete-failure label is a cleanup outcome, not an exclusion of a ledger.
    assert cited[OPENSHELL_INIT] == (
        "ephemeral-stop-contained",
        "RUNNER_SANDBOX_CONTINUITY_NOT_IMPLEMENTED",
    )
    source = (ROOT / OPENSHELL_INIT).read_text(encoding="utf-8")
    assert 'if config["lifecycle"] != "ephemeral-stop-contained":' in source
    assert 'raise ValueError("RUNNER_SANDBOX_CONTINUITY_NOT_IMPLEMENTED")' in source


def _module_file(module: str) -> Path | None:
    stem = SRC.joinpath(*module.split("."))
    for candidate in (stem.with_suffix(".py"), stem / "__init__.py"):
        if candidate.is_file():
            return candidate
    return None


def _imports(module: str) -> tuple[set[str], set[str]]:
    """Return (verifier modules, external top-level modules) imported by one source."""
    source = _module_file(module)
    assert source is not None, module
    tree = ast.parse(source.read_text(encoding="utf-8"))
    package = module if source.name == "__init__.py" else module.rpartition(".")[0]
    internal: set[str] = set()
    external: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            external.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                parts = package.split(".")[: len(package.split(".")) - (node.level - 1)]
                base = ".".join(parts + ([node.module] if node.module else []))
            else:
                base = node.module or ""
            if base != "verifier" and not base.startswith("verifier."):
                external.add(base.split(".")[0])
                continue
            internal.add(base)
            internal.update(base + "." + alias.name for alias in node.names)
    return {name for name in internal if _module_file(name) is not None}, external


def _reachable(start: set[str]) -> tuple[set[str], set[str]]:
    seen: set[str] = set()
    pending = list(start)
    external: set[str] = set()
    while pending:
        module = pending.pop()
        if module in seen:
            continue
        seen.add(module)
        internal, direct = _imports(module)
        external |= direct
        pending.extend(internal - seen)
    return seen, external


def test_pure_verifier_import_closure_reaches_subprocess_through_harness_modules():
    # Characterization of the imported-effect claim in the pure-verifier test
    # comment: the closure is real and runs through harness-owned modules.
    owned = review._REVIEWS[PURE_VERIFIER].owned_paths
    start = {
        path.removeprefix("src/").removesuffix(".py").replace("/", ".")
        for path in owned
    }
    reached, external = _reachable(start)
    assert "subprocess" in external
    assert "verifier.core.run_validation" in reached
    assert "verifier.core.run_process_observation" in reached


def test_pure_verifier_has_source_bound_file_acquisitions_and_no_refutation():
    # The object is not effect-free: these files read caller or installed bytes.
    # That keeps every role UNRESOLVED, never DOES_NOT_APPLY.
    reads = set()
    for path in review._REVIEWS[PURE_VERIFIER].owned_paths:
        tree = ast.parse((ROOT / path).read_text(encoding="utf-8"))
        if any(
            (isinstance(node, ast.Attribute) and node.attr in {"read_bytes", "read_text"})
            or (isinstance(node, ast.Name) and node.id == "open")
            for node in ast.walk(tree)
        ):
            reads.add(path)
    assert reads == {
        "src/verifier/core/checker.py",
        "src/verifier/core/geometry_io.py",
        "src/verifier/core/kernel.py",
        "src/verifier/core/platform_comparison.py",
    }
    decisions = review.review_document()[PURE_VERIFIER]["classification"]
    assert not any(decision["status"] == "DOES_NOT_APPLY" for decision in decisions.values())


def test_protocol_parent_facts_hold_in_the_unowned_parent_source():
    # The ledger and manifest mechanisms delegate their exchange to the parent.
    # The parent's nonce, isolated launch, bounded timeout, and binding check are
    # the facts their PROTOCOL declarations describe, and they live outside the
    # objects' owned denominators.
    for path in (
        "src/verifier/runtime/local_ledger_execution.py",
        "src/verifier/runtime/manifest_write_execution.py",
    ):
        tree = ast.parse((ROOT / path).read_text(encoding="utf-8"), filename=path)
        endpoint = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "_execute"
        )
        imports = [
            node
            for node in endpoint.body
            if isinstance(node, ast.ImportFrom)
            and node.module == "verifier.runtime.package_execution"
        ]
        assert len(imports) == 1
        assert [(item.name, item.asname) for item in imports[0].names] == [
            ("execute_bound", None)
        ]
        assert any(
            isinstance(node, ast.Return)
            and ast.dump(node.value, include_attributes=False)
            == (
                "Call(func=Name(id='execute_bound', ctx=Load()), args=[Name(id='snapshot', "
                "ctx=Load()), Name(id='item', ctx=Load()), Name(id='selection', ctx=Load())], "
                "keywords=[])"
            )
            for node in endpoint.body
        )

    parent = ast.parse(
        (ROOT / PARENT_EXECUTION).read_text(encoding="utf-8"),
        filename=PARENT_EXECUTION,
    )

    def assignment(scope, name):
        matches = [
            node.value
            for node in scope
            if isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == name
        ]
        assert len(matches) == 1, name
        return matches[0]

    timeout = assignment(parent.body, "_WORKER_TIMEOUT_SECONDS")
    assert isinstance(timeout, ast.Constant)
    assert type(timeout.value) is int and timeout.value == 30
    timeout_max = assignment(parent.body, "_MAX_WORKER_TIMEOUT_SECONDS")
    assert isinstance(timeout_max, ast.Constant)
    assert type(timeout_max.value) is int and timeout_max.value == 90

    execute = next(
        node
        for node in parent.body
        if isinstance(node, ast.FunctionDef) and node.name == "execute_bound"
    )
    request = assignment(execute.body, "request")
    command = assignment(execute.body, "command")
    resolved_timeout = assignment(execute.body, "timeout_seconds")
    parameters = assignment(execute.body, "parameters")
    assert isinstance(request, ast.Dict)
    request_fields = {
        key.value: value
        for key, value in zip(request.keys, request.values, strict=True)
        if isinstance(key, ast.Constant) and type(key.value) is str
    }
    assert ast.dump(request_fields["nonce"], include_attributes=False) == (
        "Call(func=Attribute(value=Call(func=Attribute(value=Name(id='os', "
        "ctx=Load()), attr='urandom', ctx=Load()), args=[Constant(value=32)], "
        "keywords=[]), attr='hex', ctx=Load()), args=[], keywords=[])"
    )
    assert isinstance(command, ast.List) and len(command.elts) == 5
    assert ast.dump(command.elts[0], include_attributes=False) == (
        "Attribute(value=Name(id='sys', ctx=Load()), attr='executable', ctx=Load())"
    )
    assert [item.value for item in command.elts[1:4]] == ["-I", "-S", "-B"]
    assert isinstance(parameters, ast.Dict)
    parameter_fields = {
        key.value: value
        for key, value in zip(parameters.keys, parameters.values, strict=True)
        if isinstance(key, ast.Constant) and type(key.value) is str
    }
    assert ast.dump(resolved_timeout, include_attributes=False) == (
        "Call(func=Name(id='_worker_timeout_seconds', ctx=Load()), "
        "args=[Name(id='module', ctx=Load())], keywords=[])"
    )
    assert isinstance(parameter_fields["timeout"], ast.Name)
    assert parameter_fields["timeout"].id == "timeout_seconds"
    assert isinstance(parameter_fields["check"], ast.Constant)
    assert parameter_fields["check"].value is False

    worker = next(
        node
        for node in parent.body
        if isinstance(node, ast.FunctionDef) and node.name == "_run_package_worker"
    )
    launches = [
        node
        for node in ast.walk(worker)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "owned_process"
        and node.func.attr == "run_owned_process"
    ]
    assert len(launches) == 1
    launch_keywords = {item.arg: item.value for item in launches[0].keywords}
    assert ast.dump(
        launch_keywords["timeout_seconds"], include_attributes=False
    ) == (
        "Subscript(value=Name(id='child_parameters', ctx=Load()), "
        "slice=Constant(value='timeout'), ctx=Load())"
    )
    assert "PACKAGE_EXECUTION_REQUEST_BINDING_DIFFERS" in {
        node.value
        for node in ast.walk(parent)
        if isinstance(node, ast.Constant) and type(node.value) is str
    }


@pytest.mark.parametrize("object_id", ["vstd-invocation-ledger", "vstd-manifest-write"])
def test_protocol_delegating_objects_keep_unique_parent_owner_and_dependency_edge(
    tmp_path, object_id,
):
    from verifier.runtime import package_semantic_review_operations as operations

    central = operations.review_document()
    assert [
        owner
        for owner, item in central.items()
        if PARENT_EXECUTION in item["owned_paths"]
    ] == ["vstd-package-worker-exchange"]

    item = review.review_document()[object_id]
    dependency = item["dependency_operands"]["protocol_exchange"]
    assert dependency == {
        "targets": list(relation.PROTOCOL_EXCHANGE_OBJECT_IDS),
        "reason": relation.PARTICIPANT_DEPENDENCY_REASON,
        "local_endpoint_paths": [
            (
                "src/verifier/runtime/local_ledger_execution.py"
                if object_id == "vstd-invocation-ledger"
                else "src/verifier/runtime/manifest_write_execution.py"
            )
        ],
        "target_evidence_paths": [PARENT_EXECUTION, relation.SOURCE_PATH],
    }
    assert PARENT_EXECUTION not in item["owned_paths"]
    assert item["classification"]["PROTOCOL"]["status"] == "APPLIES"
    assert set(item["classification"]["PROTOCOL"]["evidence_paths"]) == {
        *dependency["local_endpoint_paths"],
        (
            "src/verifier/runtime/local_ledger_worker.py"
            if object_id == "vstd-invocation-ledger"
            else "src/verifier/runtime/manifest_write_worker.py"
        ),
    }
    assert {
        name for name in item["declarations"] if name.startswith("PROTOCOL-")
    } == {
        "PROTOCOL-0.1-participants-and-states",
        "PROTOCOL-0.2-ordering-and-replay",
        "PROTOCOL-0.3-failures-and-progress",
    }

    local = (ROOT / dependency["local_endpoint_paths"][0]).read_text(
        encoding="utf-8"
    )
    assert "from verifier.runtime.package_execution import execute_bound" in local
    target = (ROOT / dependency["target_evidence_paths"][0]).read_text(
        encoding="utf-8"
    )
    assert "def execute_bound(" in target

    # The edge is executable review input, not informational prose: removing
    # the owned import anchor from otherwise current bytes fails atomically.
    root, rows, files = _workspace(tmp_path)
    local_path = dependency["local_endpoint_paths"][0]
    local = root / local_path
    local.write_text(
        local.read_text(encoding="utf-8").replace(
            "from verifier.runtime.package_execution import execute_bound",
            "delegated transport anchor removed",
        ),
        encoding="utf-8",
    )
    files[local_path] = _digest(local.read_bytes())
    before = deepcopy(rows)
    with pytest.raises(ValueError) as caught:
        review.apply_package_namespace_review(root, rows, files)
    assert str(caught.value) == (
        "PACKAGE_NAMESPACE_REVIEW_DEPENDENCY_ANCHOR_MISSING:"
        + object_id
        + ":protocol_exchange:"
        + local_path
    )
    assert rows == before


def test_protocol_relation_source_anchor_drift_fails_atomically(tmp_path) -> None:
    root, rows, files = _workspace(tmp_path)
    target = root / relation.SOURCE_PATH
    anchor = relation.SOURCE_ANCHORS[0]
    target.write_text(
        target.read_text(encoding="utf-8").replace(anchor, "relation anchor removed"),
        encoding="utf-8",
    )
    files[relation.SOURCE_PATH] = _digest(target.read_bytes())
    before = deepcopy(rows)
    with pytest.raises(ValueError) as caught:
        review.apply_package_namespace_review(root, rows, files)
    assert str(caught.value) == (
        "PACKAGE_NAMESPACE_REVIEW_DEPENDENCY_ANCHOR_MISSING:"
        "vstd-invocation-ledger:protocol_exchange:"
        + relation.SOURCE_PATH
    )
    assert rows == before
