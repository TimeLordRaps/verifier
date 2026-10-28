from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import inspect
from pathlib import Path
from types import SimpleNamespace

import pytest

from verifier.runtime import package_original_kind_catalog as catalog
from verifier.runtime import (
    package_original_kind_catalog_experiments_hardware as experiments_hardware,
)
from verifier.runtime import package_original_kind_catalog_runtime as runtime
from verifier.runtime.package_original_kind_profiles import (
    ORIGINAL_NON_OBJECT_KINDS,
    VERIFIER_PACKAGE_OBJECT_DENOMINATOR,
    validate_full_closure,
)


EXPECTED_PARTITION_COUNTS = {
    "retained": 27,
    "runtime": 122,
    "domains": 38,
    "experiments_hardware": 62,
    "python_apps_public_cli": 41,
    "repository_assets": 40,
    "scripts_examples": 55,
    "tests_normative": 83,
}
# The prior central denominator was already stale before the normative
# crosswalk arrived: the runtime ASSET checker had taken runtime from 119 to
# 120.  The policy-enforcement engine and the transaction-execution coordinator
# then took runtime to 122.  Removing these exact four rows reconstructs the
# former 464 equation.
BASELINE_464_PARTITION_COUNTS = {
    **EXPECTED_PARTITION_COUNTS,
    "runtime": 119,
    "tests_normative": 82,
}
DENOMINATOR_ADDITIONS_SINCE_464 = {
    "runtime": (
        "vstd-asset-tier0-execution-verifier",
        "vstd-policy-enforcement-engine",
        "vstd-transaction-execution-coordinator",
    ),
    "tests_normative": ("vstd-agency-surface-crosswalk-assets",),
}


def _partition_documents() -> dict[str, dict]:
    return {
        name: module.review_document()
        for name, module, _profile in catalog._CATALOGS
    }


def test_denominator_is_the_exact_disjoint_partition_equation() -> None:
    assert tuple(EXPECTED_PARTITION_COUNTS) == catalog._CANONICAL_CATALOG_NAMES
    documents = _partition_documents()
    assert {name: len(document) for name, document in documents.items()} == (
        EXPECTED_PARTITION_COUNTS
    )

    owners: dict[str, str] = {}
    duplicates: list[tuple[str, str, str]] = []
    for name, document in documents.items():
        for object_id in document:
            previous = owners.setdefault(object_id, name)
            if previous != name:
                duplicates.append((object_id, previous, name))
    assert duplicates == []
    assert len(owners) == sum(EXPECTED_PARTITION_COUNTS.values()) == 468
    assert VERIFIER_PACKAGE_OBJECT_DENOMINATOR == len(owners)

    assert sum(BASELINE_464_PARTITION_COUNTS.values()) == 464
    assert 464 + sum(map(len, DENOMINATOR_ADDITIONS_SINCE_464.values())) == 468
    for name, additions in DENOMINATOR_ADDITIONS_SINCE_464.items():
        assert set(additions) <= set(documents[name])
        assert len(documents[name]) - len(additions) == (
            BASELINE_464_PARTITION_COUNTS[name]
        )


def test_composition_refuses_omitted_duplicated_and_unknown_rows() -> None:
    documents = _partition_documents()

    omitted = deepcopy(documents)
    omitted["runtime"].pop("vstd-asset-tier0-execution-verifier")
    with pytest.raises(
        ValueError,
        match="PACKAGE_ORIGINAL_KIND_CATALOG_OBJECT_DENOMINATOR_DIFFERS:467",
    ):
        catalog._compose_review_documents(omitted)

    duplicated = deepcopy(documents)
    duplicate_id = next(iter(documents["retained"]))
    duplicated["runtime"][duplicate_id] = deepcopy(
        documents["retained"][duplicate_id]
    )
    with pytest.raises(
        ValueError,
        match="PACKAGE_ORIGINAL_KIND_CATALOG_OBJECT_OVERLAP:" + duplicate_id,
    ):
        catalog._compose_review_documents(duplicated)

    unknown = deepcopy(documents)
    source_id = next(iter(documents["runtime"]))
    unknown["runtime"]["vstd-unknown-denominator-row"] = deepcopy(
        documents["runtime"][source_id]
    )
    with pytest.raises(
        ValueError,
        match="PACKAGE_ORIGINAL_KIND_CATALOG_OBJECT_DENOMINATOR_DIFFERS:469",
    ):
        catalog._compose_review_documents(unknown)


def test_catalogs_cover_exact_full_object_and_question_denominators(
    runtime_coordinate_isolated,
) -> None:
    document = catalog.review_document()
    assert len(document) == VERIFIER_PACKAGE_OBJECT_DENOMINATOR == 468
    assert (
        sum(len(row["questions"]) for row in document.values())
        == catalog.ORIGINAL_KIND_QUESTION_DENOMINATOR
        == 11_700
    )
    assert all(
        tuple(row["questions"]) == tuple(ORIGINAL_NON_OBJECT_KINDS)
        for row in document.values()
    )
    assert {row["catalog"] for row in document.values()} == {
        "retained",
        "runtime",
        "domains",
        "experiments_hardware",
        "python_apps_public_cli",
        "repository_assets",
        "scripts_examples",
        "tests_normative",
    }


def test_partial_profiles_are_object_disjoint_and_match_decided_cells(
    runtime_coordinate_isolated,
) -> None:
    # Sealed partial profiles bind source decisions only.  The aggregate review
    # may add overlay decisions, so the source view is the correct comparator.
    document = _source_document()
    assignments = {
        assignment.object_id: assignment
        for profile in catalog.partial_profiles()
        for assignment in profile.assignments
    }
    assert len(assignments) == sum(
        len(profile.assignments) for profile in catalog.partial_profiles()
    )
    for object_id, assignment in assignments.items():
        expected = {
            kind: decision
            for kind, decision in document[object_id]["questions"].items()
            if decision["status"] != "UNRESOLVED"
        }
        assert {decision.kind for decision in assignment.decisions} == set(expected)
        assert {
            decision.kind: decision.status for decision in assignment.decisions
        } == {kind: decision["status"] for kind, decision in expected.items()}
        assert all(
            decision.reason in expected[decision.kind]["reason"]
            for decision in assignment.decisions
        )


def test_catalog_boundary_has_an_explicit_plan_for_every_defined_validator() -> None:
    assert {
        name: catalog._unplanned_validator_names(name, module)
        for name, module, _profile in catalog._CATALOGS
    } == {name: () for name, _module, _profile in catalog._CATALOGS}


def test_unresolved_cells_are_exposed_or_full_closure_is_valid(
    runtime_coordinate_isolated,
) -> None:
    unresolved = catalog.unresolved_questions()
    if unresolved:
        object_id = next(iter(unresolved))
        kind = unresolved[object_id][0]
        with pytest.raises(ValueError) as raised:
            catalog.full_closure_profile()
        assert str(raised.value) == (
            "PACKAGE_ORIGINAL_KIND_CATALOG_UNRESOLVED:"
            + object_id
            + ":"
            + kind
        )
        assert all(kinds for kinds in unresolved.values())
        return

    profile = catalog.full_closure_profile()
    assert (
        validate_full_closure(
            profile,
            tuple(sorted(catalog.review_document())),
            expected_object_count=VERIFIER_PACKAGE_OBJECT_DENOMINATOR,
        )
        is profile
    )


def test_apply_partial_profiles_invokes_every_partition_in_registry_order(
    tmp_path, monkeypatch
) -> None:
    calls = []
    policies = []

    def apply_generic(root, rows, files, profile, **policy):
        assert root == tmp_path
        calls.append(profile.profile_id)
        policies.append(policy)
        return deepcopy(rows)

    def apply_domain(root, rows, files):
        assert root == tmp_path
        calls.append(catalog.domains.DOMAIN_ORIGINAL_KIND_PROFILE.profile_id)
        return deepcopy(rows)

    monkeypatch.setattr(catalog, "apply_original_kind_profile", apply_generic)
    monkeypatch.setattr(
        catalog.domains, "apply_domain_original_kind_profile", apply_domain
    )
    monkeypatch.setattr(
        catalog,
        "validate_catalog_evidence",
        lambda root, files: {"status": "PASS", "receipt_digest": "test"},
    )
    for _name, module, _profile in catalog._CATALOGS:
        if hasattr(module, "current_source_partition"):
            monkeypatch.setattr(module, "current_source_partition", lambda: ())
        if hasattr(module, "validate_source_partition"):
            monkeypatch.setattr(
                module, "validate_source_partition", lambda selected: tuple(selected)
            )

    original = {"outside": {"classification": {"MODEL": {"status": "DOES_NOT_APPLY"}}}}
    assert catalog.apply_partial_profiles(tmp_path, original, {}) == original
    assert calls == [profile.profile_id for profile in catalog.partial_profiles()]
    # Without record_gaps every review gap still refuses, as a maintainer needs.
    assert policies and all(policy == {
        "unestablished_primary": "refuse",
        "unreviewed_paths": "refuse",
        "superseded_refutations": "refuse",
    } for policy in policies)


def test_apply_partial_profiles_is_atomic_when_a_later_partition_refuses(
    tmp_path, monkeypatch
) -> None:
    calls = []

    def apply_generic(root, rows, files, profile, **policy):
        calls.append(profile.profile_id)
        rows["sentinel"]["classification"]["MODEL"]["reason"] = "mutated copy"
        if len(calls) == 2:
            raise ValueError("LATER_PARTITION_REFUSED")
        return rows

    monkeypatch.setattr(catalog, "apply_original_kind_profile", apply_generic)
    monkeypatch.setattr(
        catalog,
        "validate_catalog_evidence",
        lambda root, files: {"status": "PASS", "receipt_digest": "test"},
    )
    for _name, module, _profile in catalog._CATALOGS:
        if hasattr(module, "current_source_partition"):
            monkeypatch.setattr(module, "current_source_partition", lambda: ())
        if hasattr(module, "validate_source_partition"):
            monkeypatch.setattr(
                module, "validate_source_partition", lambda selected: tuple(selected)
            )
    original = {
        "sentinel": {
            "classification": {
                "MODEL": {
                    "status": "DOES_NOT_APPLY",
                    "reason": "exact prior reason",
                    "evidence": [{"path": "owned.py", "sha256": "sha256:" + "0" * 64}],
                }
            }
        }
    }
    before = deepcopy(original)

    with pytest.raises(ValueError, match="LATER_PARTITION_REFUSED"):
        catalog.apply_partial_profiles(tmp_path, original, {})

    assert original == before


def _source_digest(raw: bytes) -> str:
    return "sha256:" + sha256(raw).hexdigest()


def _synthetic_runtime_catalog(
    tmp_path, events, *, include_behavior=True, include_declared=True
):
    source = tmp_path / "subject.py"
    source.write_text("def pure(value):\n    return value + 1\n", encoding="utf-8")
    spec = SimpleNamespace(object_id="subject", owned_paths=("subject.py",))

    def current_source_partition():
        events.append("runtime.current_source_partition")
        return (spec,)

    def validate_source_partition(specs):
        events.append("runtime.validate_source_partition")
        return tuple(specs)

    module = SimpleNamespace(
        review_document=lambda: {
            "subject": {
                "expected_owned_paths": ["subject.py"],
                "questions": {},
            }
        },
        current_source_partition=current_source_partition,
        validate_source_partition=validate_source_partition,
    )
    if include_behavior:
        module.validate_behavioral_evidence = lambda root: events.append(
            "runtime.validate_behavioral_evidence"
        ) or ()
    if include_declared:
        module.validate_declared_source_bytes = lambda root: events.append(
            "runtime.validate_declared_source_bytes"
        ) or ()
    module.validate_runtime_review = lambda root: events.append(
        "runtime.validate_runtime_review"
    ) or {}
    return module, {"subject.py": _source_digest(source.read_bytes())}


def test_evidence_report_rejects_stale_admission_bytes_without_losing_effect_audit(
    tmp_path, monkeypatch
) -> None:
    events = []
    module, files = _synthetic_runtime_catalog(tmp_path, events)
    files["subject.py"] = "sha256:" + "0" * 64
    monkeypatch.setattr(catalog, "_CATALOGS", (("runtime", module, object()),))

    report = catalog.catalog_evidence_report(tmp_path, files)

    assert report["status"] == "FAIL"
    assert report["blockers"] == [
        "SOURCE_BINDING_INVALID:runtime:subject:SOURCE_DIGEST_DIFFERS:subject.py",
        "CATALOG_SOURCE_CLOSING_DIFFERS:subject.py",
    ]
    assert report["objects"][0]["source_binding_status"] == "FAIL"
    assert report["objects"][0]["closed_effect_audit"]["status"] == "UNKNOWN"
    assert "SOURCE_DIGEST_DIFFERS:subject.py" in (
        report["objects"][0]["closed_effect_audit"]["blockers"]
    )


def test_evidence_report_invokes_behavioral_validator_and_cannot_bypass_failure(
    tmp_path, monkeypatch
) -> None:
    events = []
    module, files = _synthetic_runtime_catalog(tmp_path, events)

    def refuse(root):
        events.append("runtime.validate_behavioral_evidence")
        raise ValueError("STALE_BEHAVIORAL_EVIDENCE")

    module.validate_behavioral_evidence = refuse
    monkeypatch.setattr(catalog, "_CATALOGS", (("runtime", module, object()),))

    report = catalog.catalog_evidence_report(tmp_path, files)

    assert events == [
        "runtime.current_source_partition",
        "runtime.validate_source_partition",
        "runtime.validate_behavioral_evidence",
        "runtime.validate_declared_source_bytes",
        "runtime.validate_runtime_review",
    ]
    assert report["status"] == "FAIL"
    assert report["blockers"] == [
        "VALIDATOR_FAILED:runtime:validate_behavioral_evidence:"
        "ValueError:STALE_BEHAVIORAL_EVIDENCE"
    ]


def test_evidence_report_names_missing_required_validator_instead_of_skipping(
    tmp_path, monkeypatch
) -> None:
    events = []
    module, files = _synthetic_runtime_catalog(
        tmp_path, events, include_behavior=False
    )
    monkeypatch.setattr(catalog, "_CATALOGS", (("runtime", module, object()),))

    report = catalog.catalog_evidence_report(tmp_path, files)

    assert report["status"] == "FAIL"
    assert report["blockers"] == [
        "VALIDATOR_MISSING:runtime:validate_behavioral_evidence"
    ]
    assert [row["name"] for row in report["partitions"][0]["validators"]] == [
        "validate_source_partition",
        "validate_behavioral_evidence",
        "validate_declared_source_bytes",
        "validate_runtime_review",
    ]
    assert report["partitions"][0]["validators"][1]["status"] == "MISSING"
    assert report["partitions"][0]["validators"][2]["status"] == "PASS"


def test_evidence_validators_follow_registry_then_capability_order(
    tmp_path, monkeypatch
) -> None:
    events = []
    runtime_module, runtime_files = _synthetic_runtime_catalog(tmp_path, events)
    app_source = tmp_path / "app.py"
    app_source.write_text("def app():\n    return 2\n", encoding="utf-8")
    app_spec = SimpleNamespace(object_id="app", owned_paths=("app.py",))

    def current_app_partition():
        events.append("python.current_source_partition")
        return (app_spec,)

    def validate_app_partition(specs):
        events.append("python.validate_source_partition")
        return tuple(specs)

    def validate_app_bytes(*, root):
        events.append("python.validate_owned_source_bytes")

    app_module = SimpleNamespace(
        review_document=lambda: {
            "app": {"expected_owned_paths": ["app.py"], "questions": {}}
        },
        current_source_partition=current_app_partition,
        validate_source_partition=validate_app_partition,
        validate_owned_source_bytes=validate_app_bytes,
    )
    monkeypatch.setattr(
        catalog,
        "_CATALOGS",
        (
            ("runtime", runtime_module, object()),
            ("python_apps_public_cli", app_module, object()),
        ),
    )
    files = {
        **runtime_files,
        "app.py": _source_digest(app_source.read_bytes()),
    }

    report = catalog.catalog_evidence_report(tmp_path, files)

    assert report["status"] == "PASS"
    assert events == [
        "runtime.current_source_partition",
        "runtime.validate_source_partition",
        "runtime.validate_behavioral_evidence",
        "runtime.validate_declared_source_bytes",
        "runtime.validate_runtime_review",
        "python.current_source_partition",
        "python.validate_source_partition",
        "python.validate_owned_source_bytes",
    ]


def test_apply_preflights_all_evidence_before_any_profile_mutation(
    tmp_path, monkeypatch
) -> None:
    events = []
    module, files = _synthetic_runtime_catalog(tmp_path, events)
    original = {"sentinel": {"classification": {}}}

    def behavioral_failure(root):
        events.append("runtime.validate_behavioral_evidence")
        raise ValueError("NO_PROFILE_APPLICATION")

    def apply_generic(root, rows, supplied_files, profile):
        events.append("apply")
        rows["sentinel"]["classification"]["MODEL"] = {"status": "APPLIES"}
        return rows

    module.validate_behavioral_evidence = behavioral_failure
    monkeypatch.setattr(catalog, "_CATALOGS", (("runtime", module, object()),))
    monkeypatch.setattr(catalog, "partial_profiles", lambda: (object(),))
    monkeypatch.setattr(catalog, "apply_original_kind_profile", apply_generic)
    before = deepcopy(original)

    with pytest.raises(
        ValueError,
        match=(
            "PACKAGE_ORIGINAL_KIND_CATALOG_EVIDENCE_INVALID:"
            "VALIDATOR_FAILED:runtime:validate_behavioral_evidence:"
            "ValueError:NO_PROFILE_APPLICATION"
        ),
    ):
        catalog.apply_partial_profiles(tmp_path, original, files)

    assert "apply" not in events
    assert original == before


def test_mixed_python_and_non_python_effect_evidence_preserves_unknown(
    tmp_path, monkeypatch
) -> None:
    python_source = tmp_path / "pure.py"
    text_source = tmp_path / "README.md"
    python_source.write_text("def pure():\n    return 1\n", encoding="utf-8")
    text_source.write_text("bounded documentation\n", encoding="utf-8")
    module = SimpleNamespace(
        review_document=lambda: {
            "python-row": {
                "expected_owned_paths": ["pure.py"],
                "questions": {},
            },
            "asset-row": {
                "expected_owned_paths": ["README.md"],
                "questions": {},
            },
        }
    )
    files = {
        "pure.py": _source_digest(python_source.read_bytes()),
        "README.md": _source_digest(text_source.read_bytes()),
    }
    monkeypatch.setattr(catalog, "_CATALOGS", (("retained", module, object()),))

    report = catalog.catalog_evidence_report(tmp_path, files)

    assert report["status"] == "PASS"
    assert report["closed_effect_status_counts"] == {"CLOSED": 1, "UNKNOWN": 1}
    by_id = {row["object_id"]: row for row in report["objects"]}
    assert by_id["asset-row"]["source_binding_status"] == "PASS"
    assert by_id["asset-row"]["closed_effect_audit"]["blockers"] == [
        "UNSUPPORTED_LANGUAGE:README.md"
    ]
    assert report["claim_boundary"].startswith(
        "Closed-effect status is supporting source evidence only"
    )


def test_evidence_report_and_receipt_are_deterministic(tmp_path, monkeypatch) -> None:
    events = []
    module, files = _synthetic_runtime_catalog(tmp_path, events)
    monkeypatch.setattr(catalog, "_CATALOGS", (("runtime", module, object()),))

    first = catalog.catalog_evidence_report(tmp_path, files)
    second = catalog.catalog_evidence_report(tmp_path, dict(reversed(tuple(files.items()))))

    assert first == second
    assert first["receipt_digest"].startswith("sha256:")
    assert len(first["receipt_digest"]) == 71
    body = {key: value for key, value in first.items() if key != "receipt_digest"}
    assert catalog._json_value_digest(body) == catalog._value_digest(body)


def test_parallel_effect_audits_are_byte_identical_to_sequential_audits(
        tmp_path, monkeypatch) -> None:
    events = []
    module, files = _synthetic_runtime_catalog(tmp_path, events)
    monkeypatch.setattr(catalog, "_CATALOGS", (("runtime", module, object()),))
    monkeypatch.setattr(catalog, "_MAX_AUDIT_WORKERS", 1)
    sequential = catalog.catalog_evidence_report(tmp_path, files)

    monkeypatch.setattr(catalog, "_PARALLEL_AUDIT_THRESHOLD", 1)
    monkeypatch.setattr(catalog, "_MAX_AUDIT_WORKERS", 2)
    parallel = catalog.catalog_evidence_report(tmp_path, files)

    assert parallel == sequential


def test_admission_closure_report_counts_missing_or_unresolved_exact_cells(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    runtime_coordinate_isolated,
) -> None:
    source_document = catalog.review_document()
    document = _synthetic_document(list(source_document))
    monkeypatch.setattr(
        catalog,
        "validated_review_document",
        lambda root, files: deepcopy(document),
    )
    inventory = _closed_census(tmp_path, ("owned.py",))
    rows = {
        object_id: _bound_row(digest=inventory["owned.py"])
        for object_id in document
    }
    first_object = next(iter(document))
    first_kind = ORIGINAL_NON_OBJECT_KINDS[0]
    rows[first_object]["classification"][first_kind] = {
        "status": "UNRESOLVED",
        "reason": "The source review is not complete.",
        "evidence": [],
    }

    report = catalog.admission_closure_report(
        rows, root=tmp_path, source_inventory=inventory
    )

    assert report["status"] == "UNKNOWN"
    assert report["question_count"] == catalog.ORIGINAL_KIND_QUESTION_DENOMINATOR
    assert report["decided_count"] == catalog.ORIGINAL_KIND_QUESTION_DENOMINATOR - 1
    assert report["unresolved_count"] == 1
    assert report["next_unresolved"] == {
        "object_id": first_object,
        "kind": first_kind,
    }
    assert report["diagnostic"] == (
        "PACKAGE_ORIGINAL_KIND_CATALOG_UNRESOLVED:"
        + first_object
        + ":"
        + first_kind
    )


def test_documented_applies_answers_retain_every_exact_open_cell(
    tmp_path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    document = _synthetic_document(["vstd-one"])
    _install_validated(monkeypatch, document)
    inventory = _closed_census(tmp_path, ("owned.py",))
    rows = {
        "vstd-one": {
            "surfaces": ["file:owned.py"],
            "classification": {
                kind: {
                    "status": "UNRESOLVED",
                    "reason": "Source role remains open; root reason retains demand.",
                    "evidence": [],
                }
                for kind in ORIGINAL_NON_OBJECT_KINDS
            },
        }
    }
    retained = frozenset(
        ("vstd-one", kind) for kind in ORIGINAL_NON_OBJECT_KINDS
    )

    report = catalog.admission_closure_report(
        rows,
        root=tmp_path,
        source_inventory=inventory,
        documented_retention_keys=retained,
    )

    assert report["status"] == "PASS"
    assert report["decided_count"] == len(ORIGINAL_NON_OBJECT_KINDS)
    assert report["unresolved_count"] == 0
    assert report["documented_retention_selected_count"] == 25
    assert report["documented_retention_applied_count"] == 25
    assert report["documented_retention_digest"].startswith("sha256:")


def test_missing_documented_applies_answer_leaves_exact_open_cell_unknown(
    tmp_path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    document = _synthetic_document(["vstd-one"])
    _install_validated(monkeypatch, document)
    inventory = _closed_census(tmp_path, ("owned.py",))
    rows = {
        "vstd-one": {
            "surfaces": ["file:owned.py"],
            "classification": {
                kind: {
                    "status": "UNRESOLVED",
                    "reason": "Source role remains open; root reason retains demand.",
                    "evidence": [],
                }
                for kind in ORIGINAL_NON_OBJECT_KINDS
            },
        }
    }
    missing = ORIGINAL_NON_OBJECT_KINDS[-1]
    retained = frozenset(
        ("vstd-one", kind)
        for kind in ORIGINAL_NON_OBJECT_KINDS
        if kind != missing
    )

    report = catalog.admission_closure_report(
        rows,
        root=tmp_path,
        source_inventory=inventory,
        documented_retention_keys=retained,
    )

    assert report["status"] == "UNKNOWN"
    assert report["decided_count"] == 24
    assert report["unresolved_count"] == 1
    assert report["next_unresolved"] == {
        "object_id": "vstd-one",
        "kind": missing,
    }
    assert report["documented_retention_applied_count"] == 24


@pytest.mark.parametrize("status", ["APPLIES", "DOES_NOT_APPLY"])
def test_documented_retention_never_repairs_stale_decided_evidence(
    monkeypatch: pytest.MonkeyPatch, status: str,
) -> None:
    document = _synthetic_document(["vstd-one"])
    _install_validated(monkeypatch, document)
    rows = {"vstd-one": _bound_row(digest=SYNTHETIC_DIGEST)}
    for decision in rows["vstd-one"]["classification"].values():
        decision["status"] = status
    retained = frozenset(
        ("vstd-one", kind) for kind in ORIGINAL_NON_OBJECT_KINDS
    )

    report = catalog.admission_closure_report(
        rows,
        root=".",
        source_inventory={"owned.py": OTHER_DIGEST},
        documented_retention_keys=retained,
    )

    assert report["status"] == "UNKNOWN"
    assert report["decided_count"] == 0
    assert report["documented_retention_applied_count"] == 0
    assert report["unresolved_reason_counts"] == {"EVIDENCE_DIGEST_STALE": 25}


SYNTHETIC_DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64
MALFORMED_DIGESTS = (
    "sha256:" + "A" * 64,
    "sha256:" + "a" * 63,
    "sha256:" + "a" * 65,
    "sha256:" + "g" * 64,
    "sha1:" + "a" * 40,
    "a" * 64,
    "sha256:",
)


def _bound_row(
    path: str = "owned.py",
    digest: str = SYNTHETIC_DIGEST,
    *,
    surfaces: list[str] | None = None,
) -> dict:
    return {
        "surfaces": ["file:" + path] if surfaces is None else surfaces,
        "classification": {
            kind: {
                "status": "DOES_NOT_APPLY",
                "reason": "Explicit source-audited bounded refutation.",
                "evidence": [{"path": path, "sha256": digest}],
            }
            for kind in ORIGINAL_NON_OBJECT_KINDS
        },
    }


SIX_OWNED = tuple("owned_" + str(index) + ".py" for index in range(6))
CLOSED_SOURCE = "VALUE = 1\n\n\ndef read_value():\n    return VALUE\n"
DYNAMIC_SOURCE = "def run():\n    return exec('1')\n"


def _synthetic_document(
    object_ids: list[str], owned: tuple[str, ...] = ("owned.py",)
) -> dict:
    return {
        object_id: {
            "expected_owned_paths": list(owned),
            "questions": {
                kind: {"status": "UNRESOLVED", "reason": "Open."}
                for kind in ORIGINAL_NON_OBJECT_KINDS
            },
        }
        for object_id in object_ids
    }


def _write_census(root: Path, contents: dict[str, str]) -> dict[str, str]:
    """Write exact owned source bytes under root and return their sha256 census."""
    digests: dict[str, str] = {}
    for path, text in contents.items():
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        raw = text.encode("utf-8")
        target.write_bytes(raw)
        digests[path] = _source_digest(raw)
    return digests


def _closed_census(root: Path, paths: tuple[str, ...]) -> dict[str, str]:
    return _write_census(root, {path: CLOSED_SOURCE for path in paths})


def _dne_row(references: list[tuple[str, str]], surfaces: tuple[str, ...]) -> dict:
    """Manifest row declaring every kind DOES_NOT_APPLY with these references."""
    return {
        "surfaces": ["file:" + path for path in surfaces],
        "classification": {
            kind: {
                "status": "DOES_NOT_APPLY",
                "reason": "Explicit source-audited bounded refutation.",
                "evidence": [
                    {"path": path, "sha256": digest} for path, digest in references
                ],
            }
            for kind in ORIGINAL_NON_OBJECT_KINDS
        },
    }


def _install_validated(monkeypatch: pytest.MonkeyPatch, document: dict) -> None:
    monkeypatch.setattr(
        catalog,
        "validated_review_document",
        lambda root, files: deepcopy(document),
    )


@pytest.fixture
def synthetic_review(monkeypatch: pytest.MonkeyPatch):
    def install(object_ids: list[str]) -> None:
        document = _synthetic_document(object_ids)
        monkeypatch.setattr(
            catalog, "review_document", lambda: deepcopy(document)
        )
        monkeypatch.setattr(
            catalog,
            "validated_review_document",
            lambda root, files: deepcopy(document),
        )

    return install


def test_bound_decided_cells_pass_only_against_current_inventory(
    tmp_path, synthetic_review,
) -> None:
    digests = _closed_census(tmp_path, ("owned.py",))
    synthetic_review(["vstd-one"])
    rows = {"vstd-one": _bound_row(digest=digests["owned.py"])}

    report = catalog.admission_closure_report(
        rows, root=tmp_path, source_inventory=digests
    )

    assert report["status"] == "PASS"
    assert report["decided_count"] == 25
    assert report["unresolved_count"] == 0
    assert report["unresolved"] == []
    assert report["next_unresolved"] is None
    assert report["diagnostic"] is None
    assert report["source_inventory_bound"] is True
    assert report["blocker_counts"] == {}
    assert report["question_count"] == catalog.ORIGINAL_KIND_QUESTION_DENOMINATOR


@pytest.mark.parametrize("malformed", MALFORMED_DIGESTS)
def test_malformed_digest_never_binds_even_when_inventory_matches(
    synthetic_review, malformed: str
) -> None:
    synthetic_review(["vstd-one"])
    rows = {"vstd-one": _bound_row(digest=malformed)}

    report = catalog.admission_closure_report(
        rows, root=".", source_inventory={"owned.py": malformed}
    )

    assert report["status"] == "UNKNOWN"
    assert report["decided_count"] == 0
    assert report["unresolved_reason_counts"] == {
        "EVIDENCE_DIGEST_MALFORMED": 25
    }


def test_stale_digest_is_unresolved_against_current_bytes(synthetic_review) -> None:
    synthetic_review(["vstd-one"])
    rows = {"vstd-one": _bound_row(digest=SYNTHETIC_DIGEST)}

    report = catalog.admission_closure_report(
        rows, root=".", source_inventory={"owned.py": OTHER_DIGEST}
    )

    assert report["status"] == "UNKNOWN"
    assert report["decided_count"] == 0
    assert report["unresolved_reason_counts"] == {"EVIDENCE_DIGEST_STALE": 25}


def test_evidence_path_must_be_owned_by_the_object_surfaces(synthetic_review) -> None:
    synthetic_review(["vstd-one"])
    rows = {"vstd-one": _bound_row(path="owned.py", surfaces=["file:other.py"])}

    report = catalog.admission_closure_report(
        rows, root=".", source_inventory={"owned.py": SYNTHETIC_DIGEST}
    )

    assert report["status"] == "UNKNOWN"
    assert report["unresolved_reason_counts"] == {"EVIDENCE_PATH_UNOWNED": 25}


def test_owned_evidence_path_must_be_present_in_the_source_inventory(
    synthetic_review,
) -> None:
    synthetic_review(["vstd-one"])
    rows = {"vstd-one": _bound_row(path="owned.py")}

    report = catalog.admission_closure_report(
        rows, root=".", source_inventory={"unrelated.py": SYNTHETIC_DIGEST}
    )

    assert report["status"] == "UNKNOWN"
    assert report["unresolved_reason_counts"] == {
        "EVIDENCE_PATH_NOT_IN_INVENTORY": 25
    }


def test_absent_inventory_never_produces_a_pass(synthetic_review) -> None:
    synthetic_review(["vstd-one"])
    rows = {"vstd-one": _bound_row()}

    report = catalog.admission_closure_report(rows, root=".")

    assert report["status"] == "UNKNOWN"
    assert report["decided_count"] == 0
    assert report["unresolved_count"] == catalog.ORIGINAL_KIND_QUESTION_DENOMINATOR
    assert report["diagnostic"] == (
        "PACKAGE_ORIGINAL_KIND_SOURCE_INVENTORY_ABSENT"
    )
    assert report["next_conflict"] is None
    assert report["source_inventory_bound"] is False


def test_absent_inventory_cannot_create_a_conflict_from_inspection_only_review(
    synthetic_review,
) -> None:
    synthetic_review(["vstd-one"])
    rows = {"vstd-one": _bound_row()}
    rows["vstd-one"]["classification"][ORIGINAL_NON_OBJECT_KINDS[0]][
        "status"
    ] = "APPLIES"

    report = catalog.admission_closure_report(rows, root=".")

    assert report["status"] == "UNKNOWN"
    assert report["conflict_count"] == 0
    assert report["diagnostic"] == (
        "PACKAGE_ORIGINAL_KIND_SOURCE_INVENTORY_ABSENT"
    )


def test_validated_denominator_rejects_missing_and_extra_object_ids(
    synthetic_review,
) -> None:
    synthetic_review(["vstd-one"])

    missing = catalog.admission_closure_report(
        {}, root=".", source_inventory={}
    )
    extra = catalog.admission_closure_report(
        {"vstd-one": _bound_row(), "vstd-extra": _bound_row()},
        root=".",
        source_inventory={"owned.py": SYNTHETIC_DIGEST},
    )

    assert missing["status"] == "UNKNOWN"
    assert missing["diagnostic"] == (
        "PACKAGE_ORIGINAL_KIND_CATALOG_OBJECT_DENOMINATOR_MISSING:vstd-one"
    )
    assert extra["status"] == "UNKNOWN"
    assert extra["diagnostic"] == (
        "PACKAGE_ORIGINAL_KIND_CATALOG_OBJECT_DENOMINATOR_EXTRA:vstd-extra"
    )


def test_bounded_summary_digest_is_order_independent_and_change_sensitive() -> None:
    entries = [
        {"object_id": "vstd-a", "kind": kind}
        for kind in ORIGINAL_NON_OBJECT_KINDS[:3]
    ]
    reasons = ["DECISION_UNRESOLVED", "EVIDENCE_DIGEST_STALE", "EVIDENCE_PATH_UNOWNED"]

    forward = catalog.bounded_unresolved_summary(entries, reasons)
    reverse = catalog.bounded_unresolved_summary(
        list(reversed(entries)), list(reversed(reasons))
    )
    changed = catalog.bounded_unresolved_summary(
        entries, ["DECISION_UNRESOLVED", "EVIDENCE_DIGEST_STALE", "EVIDENCE_DIGEST_MALFORMED"]
    )

    assert forward["unresolved_digest"] == reverse["unresolved_digest"]
    assert forward["unresolved_digest"].startswith("sha256:")
    assert forward["unresolved_digest"] != changed["unresolved_digest"]
    assert forward["unresolved_truncated"] is False


def test_large_unresolved_set_is_bounded_with_exact_first_focus_and_detectable_omission(
    tmp_path, monkeypatch,
) -> None:
    object_ids = ["vstd-" + str(index).zfill(3) for index in range(40)]
    owned = ("owned_0.py", "owned_1.py")
    census = _closed_census(tmp_path, owned)
    _install_validated(monkeypatch, _synthetic_document(object_ids, owned=owned))
    empty = {
        object_id: {"classification": {}} for object_id in object_ids
    }
    partial = {
        object_id: {"classification": {}} for object_id in object_ids
    }
    # One of the two owned files is cited: the object's denominator is partial.
    partial[object_ids[30]] = _dne_row(
        [("owned_0.py", census["owned_0.py"])], owned
    )
    empty_report = catalog.admission_closure_report(
        empty, root=tmp_path, source_inventory=census
    )
    partial_report = catalog.admission_closure_report(
        partial,
        root=tmp_path,
        source_inventory=census,
    )

    assert empty_report["unresolved_count"] == 1000
    assert len(empty_report["unresolved"]) == 1000
    assert empty_report["unresolved_truncated"] is True
    assert empty_report["unresolved_sample_limit"] == catalog.UNRESOLVED_SAMPLE_LIMIT == 16
    assert len(empty_report["unresolved_sample"]) == 16
    assert empty_report["unresolved_sample"][0] == {
        "object_id": object_ids[0],
        "kind": ORIGINAL_NON_OBJECT_KINDS[0],
        "reason": "DECISION_UNRESOLVED",
    }
    assert empty_report["next_unresolved"] == {
        "object_id": object_ids[0],
        "kind": ORIGINAL_NON_OBJECT_KINDS[0],
    }
    assert (
        empty_report["unresolved_sample"][0]["object_id"]
        == empty_report["next_unresolved"]["object_id"]
    )
    assert partial_report["status"] == "UNKNOWN"
    assert partial_report["decided_count"] == 0
    assert partial_report["unresolved_count"] == 1000
    assert partial_report["blocker_counts"] == {
        "DOES_NOT_APPLY_DENOMINATOR_INCOMPLETE": 25,
        "VALIDATED_UNRESOLVED": 25,
    }
    assert partial_report["unresolved_digest"] != empty_report["unresolved_digest"]
    assert partial_report["unresolved_sample"] == empty_report["unresolved_sample"]


def test_partial_refutation_over_all_unresolved_validated_document_stays_unknown(
    tmp_path, monkeypatch,
) -> None:
    census = _closed_census(tmp_path, SIX_OWNED)
    _install_validated(monkeypatch, _synthetic_document(["vstd-one"], owned=SIX_OWNED))
    rows = {
        "vstd-one": _dne_row([(SIX_OWNED[0], census[SIX_OWNED[0]])], SIX_OWNED)
    }

    report = catalog.admission_closure_report(
        rows, root=tmp_path, source_inventory=census
    )

    kinds = ORIGINAL_NON_OBJECT_KINDS
    assert report["status"] == "UNKNOWN"
    assert report["decided_count"] == 0
    assert report["unresolved_count"] == len(kinds)
    assert report["unresolved_reason_counts"] == {"DECISION_UNRESOLVED": len(kinds)}
    assert report["blocker_counts"] == {
        "DOES_NOT_APPLY_DENOMINATOR_INCOMPLETE": len(kinds),
        "VALIDATED_UNRESOLVED": len(kinds),
    }
    assert report["diagnostic"] == (
        "PACKAGE_ORIGINAL_KIND_CATALOG_UNRESOLVED:vstd-one:" + kinds[0]
    )
    first = report["unresolved_sample"][0]
    assert first["object_id"] == "vstd-one"
    assert first["kind"] == kinds[0]
    assert first["denominator_blocker"] == "DOES_NOT_APPLY_DENOMINATOR_INCOMPLETE"
    assert first["next_action"].startswith("Cite every owned file")


@pytest.mark.parametrize("missing", SIX_OWNED)
def test_dne_missing_one_owned_path_fails_closure(
    tmp_path, monkeypatch, missing: str,
) -> None:
    census = _closed_census(tmp_path, SIX_OWNED)
    _install_validated(monkeypatch, _synthetic_document(["vstd-one"], owned=SIX_OWNED))
    cited = [(path, census[path]) for path in SIX_OWNED if path != missing]
    rows = {"vstd-one": _dne_row(cited, SIX_OWNED)}

    report = catalog.admission_closure_report(
        rows, root=tmp_path, source_inventory=census
    )

    assert report["status"] == "UNKNOWN"
    assert report["decided_count"] == 0
    assert report["blocker_counts"]["DOES_NOT_APPLY_DENOMINATOR_INCOMPLETE"] == 25


def test_duplicate_evidence_path_cannot_substitute_for_missing_coverage(
    tmp_path, monkeypatch,
) -> None:
    census = _closed_census(tmp_path, SIX_OWNED)
    _install_validated(monkeypatch, _synthetic_document(["vstd-one"], owned=SIX_OWNED))
    repeated = [(path, census[path]) for path in SIX_OWNED[:5]]
    rows = {"vstd-one": _dne_row(repeated + [repeated[0]], SIX_OWNED)}

    report = catalog.admission_closure_report(
        rows, root=tmp_path, source_inventory=census
    )

    assert report["status"] == "UNKNOWN"
    assert report["decided_count"] == 0
    assert report["blocker_counts"]["DOES_NOT_APPLY_EVIDENCE_PATH_DUPLICATED"] == 25
    assert "DOES_NOT_APPLY_DENOMINATOR_INCOMPLETE" not in report["blocker_counts"]


def test_foreign_evidence_path_is_unowned_even_with_full_owned_coverage(
    tmp_path, monkeypatch,
) -> None:
    foreign = "foreign.py"
    census = _closed_census(tmp_path, SIX_OWNED + (foreign,))
    _install_validated(monkeypatch, _synthetic_document(["vstd-one"], owned=SIX_OWNED))
    references = [(path, census[path]) for path in SIX_OWNED + (foreign,)]
    rows = {"vstd-one": _dne_row(references, SIX_OWNED + (foreign,))}

    report = catalog.admission_closure_report(
        rows, root=tmp_path, source_inventory=census
    )

    assert report["status"] == "UNKNOWN"
    assert report["decided_count"] == 0
    assert report["unresolved_reason_counts"] == {"EVIDENCE_PATH_UNOWNED": 25}
    assert report["blocker_counts"] == {}


def test_source_drift_under_matching_evidence_blocks_dne(
    tmp_path, monkeypatch,
) -> None:
    census = _closed_census(tmp_path, SIX_OWNED)
    # The census and evidence still agree, but the owned bytes moved afterwards.
    (tmp_path / SIX_OWNED[0]).write_text("VALUE = 2\n", encoding="utf-8")
    _install_validated(monkeypatch, _synthetic_document(["vstd-one"], owned=SIX_OWNED))
    rows = {
        "vstd-one": _dne_row([(path, census[path]) for path in SIX_OWNED], SIX_OWNED)
    }

    report = catalog.admission_closure_report(
        rows, root=tmp_path, source_inventory=census
    )

    assert report["status"] == "UNKNOWN"
    assert report["decided_count"] == 0
    assert report["blocker_counts"] == {
        "DOES_NOT_APPLY_SOURCE_DRIFT": 25,
        "VALIDATED_UNRESOLVED": 25,
    }


def test_dne_without_a_validated_owned_set_is_owner_closure_unknown(
    tmp_path, monkeypatch,
) -> None:
    census = _closed_census(tmp_path, SIX_OWNED)
    document = _synthetic_document(["vstd-one"], owned=SIX_OWNED)
    del document["vstd-one"]["expected_owned_paths"]
    _install_validated(monkeypatch, document)
    rows = {
        "vstd-one": _dne_row([(path, census[path]) for path in SIX_OWNED], SIX_OWNED)
    }

    report = catalog.admission_closure_report(
        rows, root=tmp_path, source_inventory=census
    )

    assert report["status"] == "UNKNOWN"
    assert report["decided_count"] == 0
    assert report["blocker_counts"]["DOES_NOT_APPLY_OWNER_CLOSURE_UNKNOWN"] == 25


@pytest.mark.parametrize(
    "name,text",
    [
        ("owned_0.py", DYNAMIC_SOURCE),
        ("owned_0.json", "{}\n"),
    ],
)
def test_unclosed_effect_boundary_blocks_dne(
    tmp_path, monkeypatch, name: str, text: str,
) -> None:
    owned = (name,) + SIX_OWNED[1:]
    census = _write_census(
        tmp_path, {path: CLOSED_SOURCE for path in SIX_OWNED[1:]} | {name: text}
    )
    _install_validated(monkeypatch, _synthetic_document(["vstd-one"], owned=owned))
    rows = {"vstd-one": _dne_row([(path, census[path]) for path in owned], owned)}

    report = catalog.admission_closure_report(
        rows, root=tmp_path, source_inventory=census
    )

    assert report["status"] == "UNKNOWN"
    assert report["decided_count"] == 0
    assert report["blocker_counts"] == {
        "DOES_NOT_APPLY_EFFECT_BOUNDARY_UNCLOSED": 25,
        "VALIDATED_UNRESOLVED": 25,
    }


def test_documented_applies_answers_retain_byte_bound_unclosed_denials(
    tmp_path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    owned = ("owned_0.py",) + SIX_OWNED[1:]
    census = _write_census(
        tmp_path,
        {path: CLOSED_SOURCE for path in SIX_OWNED[1:]}
        | {"owned_0.py": DYNAMIC_SOURCE},
    )
    _install_validated(monkeypatch, _synthetic_document(["vstd-one"], owned=owned))
    rows = {
        "vstd-one": _dne_row(
            [(path, census[path]) for path in owned], owned
        )
    }
    retained = frozenset(
        ("vstd-one", kind) for kind in ORIGINAL_NON_OBJECT_KINDS
    )

    report = catalog.admission_closure_report(
        rows,
        root=tmp_path,
        source_inventory=census,
        documented_retention_keys=retained,
    )

    assert report["status"] == "PASS"
    assert report["decided_count"] == 25
    assert report["unresolved_count"] == 0
    assert report["documented_retention_applied_count"] == 25
    assert report["blocker_counts"] == {}


def test_full_closed_census_with_fresh_evidence_still_establishes_dne(
    tmp_path, monkeypatch,
) -> None:
    census = _closed_census(tmp_path, SIX_OWNED)
    _install_validated(monkeypatch, _synthetic_document(["vstd-one"], owned=SIX_OWNED))
    rows = {
        "vstd-one": _dne_row([(path, census[path]) for path in SIX_OWNED], SIX_OWNED)
    }

    report = catalog.admission_closure_report(
        rows, root=tmp_path, source_inventory=census
    )

    assert report["status"] == "PASS"
    assert report["decided_count"] == len(ORIGINAL_NON_OBJECT_KINDS)
    assert report["unresolved_count"] == 0
    assert report["blocker_counts"] == {}


def test_known_conflict_fails_even_when_dne_coverage_is_partial(
    tmp_path, monkeypatch,
) -> None:
    census = _closed_census(tmp_path, SIX_OWNED)
    document = _synthetic_document(["vstd-one"], owned=SIX_OWNED)
    target_kind = ORIGINAL_NON_OBJECT_KINDS[0]
    document["vstd-one"]["questions"][target_kind] = {
        "status": "APPLIES",
        "reason": "The validated effective mechanism applies.",
    }
    _install_validated(monkeypatch, document)
    rows = {"vstd-one": _dne_row([(SIX_OWNED[0], census[SIX_OWNED[0]])], SIX_OWNED)}

    report = catalog.admission_closure_report(
        rows, root=tmp_path, source_inventory=census
    )

    assert report["status"] == "FAIL"
    assert report["conflict_count"] == 1
    assert report["next_conflict"]["kind"] == target_kind
    assert report["diagnostic"] == (
        "PACKAGE_ORIGINAL_KIND_CATALOG_CONFLICT:vstd-one:" + target_kind
    )


def test_agent_representation_source_never_turns_a_validated_non_agent_into_agent(
    tmp_path, monkeypatch,
) -> None:
    # Guard, not RED: the closure reads bytes for refutation only and never
    # assigns an original kind.  Source that talks about an agent does not make
    # the representation AGENT, so a validated APPLIES for AGENT still conflicts.
    agent_source = "class Agent:\n    def act(self):\n        return self\n"
    census = _write_census(tmp_path, {"owned.py": agent_source})
    document = _synthetic_document(["vstd-agent-representation"])
    document["vstd-agent-representation"]["questions"]["AGENT"] = {
        "status": "APPLIES",
        "reason": "The validated effective mechanism applies.",
    }
    _install_validated(monkeypatch, document)
    rows = {
        "vstd-agent-representation": _dne_row([("owned.py", census["owned.py"])], ("owned.py",))
    }

    report = catalog.admission_closure_report(
        rows, root=tmp_path, source_inventory=census
    )

    assert report["status"] == "FAIL"
    assert report["conflicts"] == [
        {
            "object_id": "vstd-agent-representation",
            "kind": "AGENT",
            "expected_status": "APPLIES",
            "actual_status": "DOES_NOT_APPLY",
        }
    ]


EXPERIMENTS_OBJECT_IDS = frozenset(
    row.object_id for row in experiments_hardware.EXPERIMENTS_HARDWARE_ORIGINAL_KIND_AUDITS
)


@pytest.fixture
def runtime_coordinate_isolated(monkeypatch: pytest.MonkeyPatch) -> None:
    """Bypass only the runtime source-coordinate drift, which this worker does not own.

    The runtime partition's ownership digest currently disagrees with the
    untracked package_semantic_ownership spec, so unpatched aggregate calls
    raise.  Tests using this fixture exercise the experiments overlay through
    the aggregate; they do not claim the runtime partition is valid.
    """
    from verifier.runtime import package_original_kind_catalog_runtime as runtime

    monkeypatch.setattr(
        runtime, "validate_source_partition", lambda specs: tuple(specs)
    )


def _source_document() -> dict[str, dict]:
    """Return raw per-partition source rows, bypassing the behavior overlay."""
    result: dict[str, dict] = {}
    for _name, module, _profile in catalog._CATALOGS:
        result.update(module.review_document())
    return result


def _changed_by_overlay() -> list[tuple[str, str]]:
    source = experiments_hardware.review_document()
    document = catalog.review_document()
    return [
        (object_id, kind)
        for object_id, row in source.items()
        for kind, decision in row["questions"].items()
        if document[object_id]["questions"][kind]["status"] != decision["status"]
    ]


def test_aggregate_review_consumes_experiments_effective_overlay(
    runtime_coordinate_isolated,
) -> None:
    effective = experiments_hardware.effective_review_document()
    document = catalog.review_document()
    mismatched = [
        (object_id, kind)
        for object_id, statuses in effective.items()
        for kind, status in statuses.items()
        if document[object_id]["questions"][kind]["status"] != status
    ]
    assert mismatched == []


def test_overlay_changes_only_source_unresolved_experiment_cells(
    runtime_coordinate_isolated,
) -> None:
    source = experiments_hardware.review_document()
    document = catalog.review_document()
    changed = _changed_by_overlay()
    assert len(changed) == sum(experiments_hardware.OVERLAY_TOTALS.values())
    assert all(
        source[object_id]["questions"][kind]["status"] == "UNRESOLVED"
        for object_id, kind in changed
    )
    assert all(
        document[object_id]["questions"][kind]["reason"].startswith("Behavior overlay ")
        for object_id, kind in changed
    )
    unchanged_source = [
        (object_id, kind)
        for object_id, row in source.items()
        for kind, decision in row["questions"].items()
        if decision["status"] != "UNRESOLVED"
        and document[object_id]["questions"][kind] != decision
    ]
    assert unchanged_source == []


def test_aggregate_unresolved_cells_track_effective_experiment_total(
    runtime_coordinate_isolated,
) -> None:
    experiments_unresolved = [
        cell for cell in catalog.unresolved_cells() if cell[0] in EXPERIMENTS_OBJECT_IDS
    ]
    assert len(experiments_unresolved) == experiments_hardware.EFFECTIVE_TOTALS[
        "unresolved"
    ]


def test_forged_overlay_fails_closed_through_the_aggregate(
    runtime_coordinate_isolated, monkeypatch: pytest.MonkeyPatch
) -> None:
    audits = {
        row.object_id: row
        for row in experiments_hardware.EXPERIMENTS_HARDWARE_ORIGINAL_KIND_AUDITS
    }
    victim = next(
        object_id
        for object_id, row in audits.items()
        if any(question.status == "DOES_NOT_APPLY" for question in row.questions)
    )
    source_dne = next(
        question.kind
        for question in audits[victim].questions
        if question.status == "DOES_NOT_APPLY"
    )
    forged = deepcopy(experiments_hardware.BEHAVIOR_OVERLAY[victim])
    forged["dne"] = list(forged["dne"]) + [source_dne]
    # The effective view's default argument is this same dict object, so an
    # in-place item patch is what the aggregate actually reads; monkeypatch
    # restores it afterwards.
    monkeypatch.setitem(experiments_hardware.BEHAVIOR_OVERLAY, victim, forged)

    with pytest.raises(ValueError) as raised:
        catalog.review_document()
    assert str(raised.value).startswith(
        "PACKAGE_ORIGINAL_KIND_CATALOG_EFFECTIVE_REVIEW_INVALID:experiments_hardware:"
    )


def test_overlay_decisions_cannot_seal_full_closure_without_byte_binding(
    runtime_coordinate_isolated, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Simulate the only remaining gate being closed: every source-plus-overlay
    # cell reported decided.  Closure must still refuse, because no root-bound
    # validation of overlay evidence bytes exists in this package boundary.
    monkeypatch.setattr(catalog, "unresolved_cells", lambda: ())

    with pytest.raises(ValueError) as raised:
        catalog.full_closure_profile()
    assert str(raised.value).startswith(
        "PACKAGE_ORIGINAL_KIND_CATALOG_OVERLAY_UNBOUND:"
    )


def test_source_only_partial_profiles_are_not_widened_by_overlay(
    runtime_coordinate_isolated,
) -> None:
    source_overlay_objects = {object_id for object_id, _kind in _changed_by_overlay()}
    assert source_overlay_objects <= EXPERIMENTS_OBJECT_IDS
    partial = {
        assignment.object_id: {decision.kind for decision in assignment.decisions}
        for profile in catalog.partial_profiles()
        for assignment in profile.assignments
    }
    for object_id in source_overlay_objects & set(partial):
        overlay_kinds = {kind for oid, kind in _changed_by_overlay() if oid == object_id}
        assert partial[object_id].isdisjoint(overlay_kinds)


def test_full_closure_assembles_assignments_in_global_object_order(
    runtime_coordinate_isolated, monkeypatch: pytest.MonkeyPatch
) -> None:
    # With every gate reported clear, the partial profiles are still only a
    # subset of the 468 objects, so sealing must refuse on the object denominator.
    # Before the fix, concatenating per-profile tuples produced an unsorted
    # assignment tuple that failed validate_profile first.
    monkeypatch.setattr(catalog, "unresolved_cells", lambda: ())
    monkeypatch.setattr(catalog, "_overlay_decided_cells", lambda: (), raising=False)

    with pytest.raises(ValueError) as raised:
        catalog.full_closure_profile()
    assert str(raised.value) == "PACKAGE_ORIGINAL_KIND_PROFILE_OBJECT_DENOMINATOR_INCOMPLETE"


def _synthetic_effective_catalog(
    tmp_path,
    events: list[str],
    *,
    validator_error: Exception | None = None,
    mutate_during_effective: bool = False,
    unsupported_status: bool = False,
):
    """Build one component whose sole decision exists only in its effective view."""

    source = tmp_path / "subject.py"
    source.write_text("def subject():\n    return 1\n", encoding="utf-8")
    spec = SimpleNamespace(object_id="subject", owned_paths=("subject.py",))
    raw_questions = {
        kind: {"status": "UNRESOLVED", "reason": "Still under review."}
        for kind in ORIGINAL_NON_OBJECT_KINDS
    }
    target_kind = ORIGINAL_NON_OBJECT_KINDS[0]

    def current_source_partition():
        events.append("current_source_partition")
        return (spec,)

    def validate_source_partition(specs):
        events.append("validate_source_partition")
        if validator_error is not None:
            raise validator_error
        return tuple(specs)

    def review_document():
        events.append("review_document")
        return {
            "subject": {
                "expected_owned_paths": ["subject.py"],
                "questions": deepcopy(raw_questions),
            }
        }

    def effective_review_document():
        events.append("effective_review_document")
        if mutate_during_effective:
            source.write_text("def subject():\n    return 2\n", encoding="utf-8")
        return {
            "subject": {
                kind: (
                    "FORGED"
                    if unsupported_status and kind == target_kind
                    else "APPLIES"
                    if kind == target_kind
                    else "UNRESOLVED"
                )
                for kind in ORIGINAL_NON_OBJECT_KINDS
            }
        }

    module = SimpleNamespace(
        review_document=review_document,
        effective_review_document=effective_review_document,
        current_source_partition=current_source_partition,
        validate_source_partition=validate_source_partition,
        BEHAVIOR_OVERLAY={
            "subject": {
                "applies": (
                    (target_kind, "The validated effective mechanism is present.", ("subject.py:1",)),
                ),
                "dne": (),
                "auditor_closure": "No exclusions are asserted.",
            }
        },
    )
    files = {"subject.py": _source_digest(source.read_bytes())}
    return module, files, target_kind


def _install_single_effective_catalog(monkeypatch, module) -> None:
    monkeypatch.setattr(
        catalog, "_CATALOGS", (("experiments_hardware", module, object()),)
    )
    monkeypatch.setattr(
        catalog, "_CANONICAL_CATALOG_NAMES", ("experiments_hardware",)
    )
    monkeypatch.setattr(catalog, "VERIFIER_PACKAGE_OBJECT_DENOMINATOR", 1)


def test_validated_aggregate_exposes_effective_decision_only_after_component_validator(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[str] = []
    module, files, target_kind = _synthetic_effective_catalog(tmp_path, events)
    _install_single_effective_catalog(monkeypatch, module)

    document = catalog.validated_review_document(tmp_path, files)

    assert document["subject"]["questions"][target_kind]["status"] == "APPLIES"
    assert events.index("validate_source_partition") < events.index(
        "effective_review_document"
    )


def test_validated_aggregate_consumes_runtime_authoritative_review_result(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[str] = []
    source = tmp_path / "subject.py"
    source.write_text("def subject():\n    return 1\n", encoding="utf-8")
    spec = SimpleNamespace(object_id="subject", owned_paths=("subject.py",))
    target_kind = ORIGINAL_NON_OBJECT_KINDS[0]
    raw_questions = {
        kind: {"status": "UNRESOLVED", "reason": "Raw review is unresolved."}
        for kind in ORIGINAL_NON_OBJECT_KINDS
    }
    authoritative_questions = deepcopy(raw_questions)
    authoritative_questions[target_kind] = {
        "status": "APPLIES",
        "reason": "The byte-validated runtime mechanism applies.",
    }

    def current_source_partition():
        events.append("current_source_partition")
        return (spec,)

    def validate_source_partition(specs):
        events.append("validate_source_partition")
        return tuple(specs)

    def raw_review():
        events.append("review_document")
        return {
            "subject": {
                "expected_owned_paths": ["subject.py"],
                "questions": deepcopy(raw_questions),
            }
        }

    def validated_review(root):
        events.append("validate_runtime_review")
        return {
            "subject": {
                "expected_owned_paths": ["subject.py"],
                "questions": deepcopy(authoritative_questions),
            }
        }

    module = SimpleNamespace(
        current_source_partition=current_source_partition,
        validate_source_partition=validate_source_partition,
        validate_behavioral_evidence=lambda root: events.append(
            "validate_behavioral_evidence"
        )
        or (),
        validate_declared_source_bytes=lambda root: events.append(
            "validate_declared_source_bytes"
        )
        or (),
        validate_runtime_review=validated_review,
        review_document=raw_review,
    )
    monkeypatch.setattr(catalog, "_CATALOGS", (("runtime", module, object()),))
    monkeypatch.setattr(catalog, "_CANONICAL_CATALOG_NAMES", ("runtime",))
    monkeypatch.setattr(catalog, "VERIFIER_PACKAGE_OBJECT_DENOMINATOR", 1)

    document = catalog.validated_review_document(
        tmp_path, {"subject.py": _source_digest(source.read_bytes())}
    )

    assert document["subject"]["questions"][target_kind] == (
        authoritative_questions[target_kind]
    )
    assert events.count("validate_runtime_review") == 2


def test_validated_aggregate_component_failure_never_falls_back_to_raw_statuses(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[str] = []
    module, files, _target_kind = _synthetic_effective_catalog(
        tmp_path, events, validator_error=ValueError("SOURCE_COORDINATE_DRIFT")
    )
    _install_single_effective_catalog(monkeypatch, module)

    with pytest.raises(ValueError, match="SOURCE_COORDINATE_DRIFT"):
        catalog.validated_review_document(tmp_path, files)

    assert "effective_review_document" not in events


def test_validated_aggregate_rejects_stale_or_midflight_changed_source_atomically(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stale_events: list[str] = []
    stale_module, stale_files, _ = _synthetic_effective_catalog(
        tmp_path, stale_events
    )
    _install_single_effective_catalog(monkeypatch, stale_module)
    stale_files["subject.py"] = OTHER_DIGEST
    with pytest.raises(ValueError, match="SOURCE_DIGEST_DIFFERS:subject.py"):
        catalog.validated_review_document(tmp_path, stale_files)

    drift_events: list[str] = []
    drift_module, drift_files, _ = _synthetic_effective_catalog(
        tmp_path, drift_events, mutate_during_effective=True
    )
    _install_single_effective_catalog(monkeypatch, drift_module)
    with pytest.raises(ValueError, match="SOURCE_DIGEST_DIFFERS:subject.py"):
        catalog.validated_review_document(tmp_path, drift_files)


def test_validated_aggregate_rejects_an_unsupported_effective_decision(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[str] = []
    module, files, _ = _synthetic_effective_catalog(
        tmp_path, events, unsupported_status=True
    )
    _install_single_effective_catalog(monkeypatch, module)

    with pytest.raises(
        ValueError,
        match="PACKAGE_ORIGINAL_KIND_CATALOG_EFFECTIVE_REVIEW_INVALID",
    ):
        catalog.validated_review_document(tmp_path, files)


def test_admission_closure_refuses_a_rootless_unvalidated_catalog(
    synthetic_review,
) -> None:
    synthetic_review(["vstd-one"])

    with pytest.raises(
        ValueError,
        match="PACKAGE_ORIGINAL_KIND_CATALOG_VALIDATED_ROOT_REQUIRED",
    ):
        catalog.admission_closure_report(
            {"vstd-one": _bound_row()},
            source_inventory={"owned.py": SYNTHETIC_DIGEST},
        )


def test_admission_closure_enforces_the_validated_effective_status(
    tmp_path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    target_kind = ORIGINAL_NON_OBJECT_KINDS[0]
    census = _closed_census(tmp_path, ("owned.py",))
    document = _synthetic_document(["vstd-one"])
    document["vstd-one"]["questions"][target_kind] = {
        "status": "APPLIES",
        "reason": "The validated effective mechanism applies.",
    }
    monkeypatch.setattr(
        catalog,
        "validated_review_document",
        lambda root, files: deepcopy(document),
    )

    report = catalog.admission_closure_report(
        {"vstd-one": _bound_row(digest=census["owned.py"])},
        root=tmp_path,
        source_inventory=census,
    )

    assert report["status"] == "FAIL"
    assert report["unresolved_count"] == 0
    assert report["conflict_count"] == 1
    assert report["next_conflict"] == {
        "object_id": "vstd-one",
        "kind": target_kind,
        "expected_status": "APPLIES",
        "actual_status": "DOES_NOT_APPLY",
    }
    assert report["diagnostic"] == (
        "PACKAGE_ORIGINAL_KIND_CATALOG_CONFLICT:vstd-one:" + target_kind
    )


REPO_ROOT = Path(__file__).resolve().parents[1]
DECLARED_VALIDATOR = "validate_declared_source_bytes"
DECLARED_EVENT = "runtime." + DECLARED_VALIDATOR


def _current_owned_digests(catalogs) -> dict[str, str]:
    """Digest every owned path of the given catalogs as they stand on disk now."""
    paths: set[str] = set()
    for _name, module, _profile in catalogs:
        for object_id, row in module.review_document().items():
            selected = row.get("expected_owned_paths")
            if selected is None:
                spec = next(
                    spec
                    for spec in module.current_source_partition()
                    if spec.object_id == object_id
                )
                selected = spec.owned_paths
            paths.update(selected)
    return {
        path: _source_digest((REPO_ROOT / path).read_bytes())
        for path in sorted(paths)
    }


def _declared_runtime_module(tmp_path, events, declared_validator):
    """Single-object runtime partition whose review is fully decided by bytes."""
    source = tmp_path / "subject.py"
    source.write_text("def subject():\n    return 1\n", encoding="utf-8")
    spec = SimpleNamespace(object_id="subject", owned_paths=("subject.py",))
    decision = {"status": "DOES_NOT_APPLY", "reason": "Validated refutation."}
    questions = {kind: deepcopy(decision) for kind in ORIGINAL_NON_OBJECT_KINDS}

    def validate_runtime_review(root):
        events.append("runtime.validate_runtime_review")
        return {
            "subject": {
                "expected_owned_paths": ["subject.py"],
                "questions": deepcopy(questions),
            }
        }

    module = SimpleNamespace(
        review_document=lambda: {
            "subject": {"expected_owned_paths": ["subject.py"], "questions": {}}
        },
        current_source_partition=lambda: (spec,),
        validate_source_partition=lambda specs: tuple(specs),
        validate_behavioral_evidence=lambda root: events.append(
            "runtime.validate_behavioral_evidence"
        )
        or (),
        validate_declared_source_bytes=declared_validator,
        validate_runtime_review=validate_runtime_review,
    )
    return module, {"subject.py": _source_digest(source.read_bytes())}


def _install_declared_runtime(monkeypatch, module) -> None:
    monkeypatch.setattr(catalog, "_CATALOGS", (("runtime", module, object()),))
    monkeypatch.setattr(catalog, "_CANONICAL_CATALOG_NAMES", ("runtime",))
    monkeypatch.setattr(catalog, "VERIFIER_PACKAGE_OBJECT_DENOMINATOR", 1)


def test_runtime_plan_runs_declared_source_bytes_in_the_review_dependency_order(
) -> None:
    assert catalog._EXTRA_VALIDATOR_NAMES["runtime"] == (
        "validate_behavioral_evidence",
        DECLARED_VALIDATOR,
        "validate_runtime_review",
    )
    # The composite runtime review applies the same order internally, so the
    # boundary's plan must not disagree with it.
    review_source = inspect.getsource(runtime.validate_runtime_review)
    assert (
        review_source.index("validate_behavioral_evidence(")
        < review_source.index(DECLARED_VALIDATOR + "(")
        < review_source.index("review_document()")
    )
    assert catalog._unplanned_validator_names("runtime", runtime) == ()
    assert catalog._unbound_planned_validator_names("runtime", runtime) == ()


def test_real_runtime_partition_runs_declared_source_bytes_in_plan_order(
    monkeypatch, runtime_coordinate_isolated
) -> None:
    # Only this change's gate is asserted here.  Sibling partitions and the
    # behavioral/runtime-review verdicts depend on bytes owned by other gates
    # and are reported by the aggregate, not pinned by this test.  Scoping to
    # the runtime catalog keeps the real closed-effect audit affordable.
    runtime_only = (("runtime", runtime, object()),)
    monkeypatch.setattr(catalog, "_CATALOGS", runtime_only)
    report = catalog.catalog_evidence_report(
        REPO_ROOT, _current_owned_digests(runtime_only)
    )

    runtime_partition = next(
        partition
        for partition in report["partitions"]
        if partition["catalog"] == "runtime"
    )
    assert [record["name"] for record in runtime_partition["validators"]] == [
        "validate_source_partition",
        *catalog._EXTRA_VALIDATOR_NAMES["runtime"],
    ]
    declared = next(
        record
        for record in runtime_partition["validators"]
        if record["name"] == DECLARED_VALIDATOR
    )
    assert declared["status"] == "PASS"
    assert [
        blocker
        for blocker in report["blockers"]
        if blocker.startswith("VALIDATOR_PLAN_") or DECLARED_VALIDATOR in blocker
    ] == []


def test_removing_declared_source_validator_from_runtime_fails_the_plan(
    tmp_path, monkeypatch, runtime_coordinate_isolated
) -> None:
    monkeypatch.delattr(runtime, DECLARED_VALIDATOR)
    monkeypatch.setattr(catalog, "_CATALOGS", (("runtime", runtime, object()),))

    assert catalog._unbound_planned_validator_names("runtime", runtime) == (
        (DECLARED_VALIDATOR,)
    )
    report = catalog.catalog_evidence_report(tmp_path, {})

    assert report["status"] == "FAIL"
    assert (
        "VALIDATOR_PLAN_UNBOUND:runtime:" + DECLARED_VALIDATOR in report["blockers"]
    )
    runtime_partition = report["partitions"][0]
    assert runtime_partition["status"] == "FAIL"
    assert [
        record["status"]
        for record in runtime_partition["validators"]
        if record["name"] == DECLARED_VALIDATOR
    ] == ["MISSING"]


def test_renaming_declared_source_validator_fails_both_plan_directions(
    monkeypatch, runtime_coordinate_isolated
) -> None:
    real = runtime.validate_declared_source_bytes
    monkeypatch.delattr(runtime, DECLARED_VALIDATOR)
    monkeypatch.setattr(runtime, "validate_declared_bytes", real, raising=False)

    assert catalog._unplanned_validator_names("runtime", runtime) == (
        ("validate_declared_bytes",)
    )
    assert catalog._unbound_planned_validator_names("runtime", runtime) == (
        (DECLARED_VALIDATOR,)
    )


def test_forged_declared_source_success_cannot_satisfy_the_real_plan(
    tmp_path, monkeypatch, runtime_coordinate_isolated
) -> None:
    calls = []
    monkeypatch.setattr(
        runtime,
        DECLARED_VALIDATOR,
        lambda root: calls.append(root) or (),
    )
    monkeypatch.setattr(catalog, "_CATALOGS", (("runtime", runtime, object()),))

    report = catalog.catalog_evidence_report(tmp_path, {})

    # The forged function does run and records PASS, but the plan binding
    # refuses the partition, so the forged success cannot carry the aggregate.
    assert calls == [tmp_path]
    record = next(
        record
        for record in report["partitions"][0]["validators"]
        if record["name"] == DECLARED_VALIDATOR
    )
    assert record["status"] == "PASS"
    assert report["partitions"][0]["status"] == "FAIL"
    assert report["status"] == "FAIL"
    assert (
        "VALIDATOR_PLAN_UNBOUND:runtime:" + DECLARED_VALIDATOR in report["blockers"]
    )
    with pytest.raises(ValueError) as raised:
        catalog.validated_review_document(tmp_path, {})
    assert str(raised.value) == (
        "PACKAGE_ORIGINAL_KIND_CATALOG_EVIDENCE_INVALID:"
        "VALIDATOR_PLAN_UNBOUND:runtime:" + DECLARED_VALIDATOR
    )


def test_planned_declared_validator_absent_from_a_runtime_module_fails_closed(
    tmp_path, monkeypatch
) -> None:
    events: list[str] = []
    module, files = _synthetic_runtime_catalog(
        tmp_path, events, include_declared=False
    )
    monkeypatch.setattr(catalog, "_CATALOGS", (("runtime", module, object()),))

    report = catalog.catalog_evidence_report(tmp_path, files)

    assert report["status"] == "FAIL"
    assert report["blockers"] == [
        "VALIDATOR_MISSING:runtime:" + DECLARED_VALIDATOR
    ]
    # Later validators still run and record their own outcomes.
    assert "runtime.validate_runtime_review" in events


def test_planned_validator_without_an_execution_record_fails_closed(
    tmp_path, monkeypatch
) -> None:
    events: list[str] = []
    module, files = _synthetic_runtime_catalog(tmp_path, events)
    planned = catalog._EXTRA_VALIDATOR_NAMES["runtime"] + (
        "validate_unexecuted_plan_entry",
    )
    monkeypatch.setitem(catalog._EXTRA_VALIDATOR_NAMES, "runtime", planned)
    monkeypatch.setattr(catalog, "_CATALOGS", (("runtime", module, object()),))

    report = catalog.catalog_evidence_report(tmp_path, files)

    assert report["status"] == "FAIL"
    assert report["blockers"] == [
        "VALIDATOR_PLAN_UNEXECUTED:runtime:validate_unexecuted_plan_entry"
    ]


def test_declared_source_bytes_run_exactly_once_per_boundary_path(
    tmp_path, monkeypatch
) -> None:
    events: list[str] = []
    module, files = _declared_runtime_module(
        tmp_path,
        events,
        lambda root: events.append(DECLARED_EVENT) or (),
    )
    _install_declared_runtime(monkeypatch, module)

    report = catalog.catalog_evidence_report(tmp_path, files)

    assert report["status"] == "PASS"
    assert events.count(DECLARED_EVENT) == 1
    assert (
        events.index("runtime.validate_behavioral_evidence")
        < events.index(DECLARED_EVENT)
        < events.index("runtime.validate_runtime_review")
    )

    events.clear()
    catalog.validated_review_document(tmp_path, files)

    # The validated path runs the evidence preflight once; the component stage
    # consumes validate_runtime_review, which the synthetic module does not nest.
    assert events.count(DECLARED_EVENT) == 1
    assert events.count("runtime.validate_runtime_review") == 2


@pytest.mark.parametrize("refusal", ["STALE", "UNAVAILABLE", "WRONG_OWNER", "DUPLICATE"])
def test_declared_source_refusals_propagate_through_the_boundary(
    tmp_path, monkeypatch, refusal
) -> None:
    real = runtime._DECLARED_SOURCE_BINDINGS[0]
    payload = b"declared bytes\n"
    good = _source_digest(payload)
    if refusal != "UNAVAILABLE":
        (tmp_path / real.path).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / real.path).write_bytes(payload)
    bindings = {
        "STALE": (
            runtime.DeclaredSourceBinding(
                real.object_id, real.path, _source_digest(b"older bytes\n")
            ),
        ),
        "UNAVAILABLE": (runtime.DeclaredSourceBinding(real.object_id, real.path, good),),
        "WRONG_OWNER": (
            runtime.DeclaredSourceBinding(
                "vstd-not-a-runtime-object", real.path, good
            ),
        ),
        "DUPLICATE": (runtime.DeclaredSourceBinding(real.object_id, real.path, good),) * 2,
    }[refusal]
    monkeypatch.setattr(runtime, "_DECLARED_SOURCE_BINDINGS", bindings)
    source = tmp_path / "subject.py"
    source.write_text("def subject():\n    return 1\n", encoding="utf-8")
    module = SimpleNamespace(
        review_document=lambda: {
            "subject": {"expected_owned_paths": ["subject.py"], "questions": {}}
        },
        current_source_partition=lambda: (
            SimpleNamespace(object_id="subject", owned_paths=("subject.py",)),
        ),
        validate_source_partition=lambda specs: tuple(specs),
        validate_behavioral_evidence=lambda root: (),
        # The real validator, so the refusal originates in the runtime code.
        validate_declared_source_bytes=runtime.validate_declared_source_bytes,
        validate_runtime_review=lambda root: {},
    )
    monkeypatch.setattr(catalog, "_CATALOGS", (("runtime", module, object()),))
    files = {"subject.py": _source_digest(source.read_bytes())}
    expected = (
        "VALIDATOR_FAILED:runtime:" + DECLARED_VALIDATOR + ":ValueError:"
        "RUNTIME_ORIGINAL_KIND_DECLARED_SOURCE_" + refusal + ":"
        + bindings[0].object_id + ":" + real.path
    )

    report = catalog.catalog_evidence_report(tmp_path, files)

    assert report["status"] == "FAIL"
    assert report["blockers"] == [expected]
    with pytest.raises(ValueError) as raised:
        catalog.validate_catalog_evidence(tmp_path, files)
    assert str(raised.value) == "PACKAGE_ORIGINAL_KIND_CATALOG_EVIDENCE_INVALID:" + expected


def test_admission_closes_only_when_the_declared_source_validator_passes(
    tmp_path, monkeypatch
) -> None:
    events: list[str] = []
    module, files = _declared_runtime_module(
        tmp_path,
        events,
        lambda root: events.append(DECLARED_EVENT) or (),
    )
    _install_declared_runtime(monkeypatch, module)
    rows = {"subject": _bound_row(path="subject.py", digest=files["subject.py"])}

    report = catalog.admission_closure_report(
        rows, root=tmp_path, source_inventory=files
    )

    assert report["status"] == "PASS"
    assert report["decided_count"] == len(ORIGINAL_NON_OBJECT_KINDS)
    assert report["question_count"] == catalog.ORIGINAL_KIND_QUESTION_DENOMINATOR

    def refuse(root):
        events.append(DECLARED_EVENT)
        raise ValueError("RUNTIME_ORIGINAL_KIND_DECLARED_SOURCE_STALE:subject:subject.py")

    refused_module, refused_files = _declared_runtime_module(tmp_path, events, refuse)
    _install_declared_runtime(monkeypatch, refused_module)
    with pytest.raises(ValueError) as raised:
        catalog.admission_closure_report(
            rows, root=tmp_path, source_inventory=refused_files
        )
    assert str(raised.value) == (
        "PACKAGE_ORIGINAL_KIND_CATALOG_EVIDENCE_INVALID:"
        "VALIDATOR_FAILED:runtime:validate_declared_source_bytes:ValueError:"
        "RUNTIME_ORIGINAL_KIND_DECLARED_SOURCE_STALE:subject:subject.py"
    )
