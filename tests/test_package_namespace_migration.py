"""No-weaken migration gates for the package's single root declaration.

Terminology: identifier (ID).
"""

from copy import deepcopy
import json
from pathlib import Path

import pytest

from verifier.runtime import package_manifest_migration as migration_module
from verifier.runtime import package_manifest, tier_zero_manifest, tier_zero_profile
from verifier.runtime.package_original_kind_catalog import (
    ORIGINAL_KIND_QUESTION_DENOMINATOR,
)
from verifier.runtime.package_original_kind_profiles import (
    VERIFIER_PACKAGE_OBJECT_DENOMINATOR,
)
from verifier.runtime.namespace_contracts import (
    namespace_registry,
    registry_document,
    requirements_for,
)


_REVIEWED_HARNESS_PATHS = (
    "src/verifier/core/run.py",
    "src/verifier/core/run_support.py",
    "src/verifier/core/run_planning.py",
    "src/verifier/core/run_validation.py",
    "src/verifier/core/run_inspection.py",
    "src/verifier/core/run_reproduction.py",
    "src/verifier/core/run_impact.py",
    "src/verifier/core/run_process_observation.py",
    "src/verifier/core/owned_process.py",
    "src/verifier/runtime/language_runners.py",
    "src/verifier/runtime/package_harness_applicability.py",
    "extensions/languages/pyproject.toml",
    "extensions/languages/src/vstd_languages/__init__.py",
    "extensions/languages/src/vstd_languages/extended_batch_two.py",
    "extensions/languages/src/vstd_languages/extended_batch_three.py",
)

_HARNESS_LEDGER_REVIEW_PATHS = (
    "src/verifier/domains/contracts/harness_checks.py",
    "src/verifier/domains/contracts/harness_gap_boundary.py",
    "src/verifier/domains/harness.py",
    *_REVIEWED_HARNESS_PATHS,
)

_HARNESS_TRANSACTION_PATHS = (
    "src/verifier/core/run.py",
    "src/verifier/core/run_reproduction.py",
    "src/verifier/core/run_process_observation.py",
    "src/verifier/core/owned_process.py",
    "src/verifier/runtime/language_runners.py",
    "extensions/languages/src/vstd_languages/__init__.py",
    "extensions/languages/src/vstd_languages/extended_batch_two.py",
    "extensions/languages/src/vstd_languages/extended_batch_three.py",
)

_REVIEWED_DOMAIN_OWNERS = {
    "src/verifier/domains/actor.py": "ACTOR",
    "src/verifier/domains/agent.py": "AGENT",
    "src/verifier/domains/bench.py": "BENCH",
    "src/verifier/domains/bot.py": "BOT",
    "src/verifier/domains/collective.py": "COLLECTIVE",
    "src/verifier/domains/data.py": "DATA",
    "src/verifier/domains/env.py": "ENV",
    "src/verifier/domains/hardware.py": "HARDWARE",
    "src/verifier/domains/harness.py": "HARNESS",
    "src/verifier/domains/human.py": "HUMAN",
    "src/verifier/domains/identity.py": "IDENTITY",
    "src/verifier/domains/model.py": "MODEL",
    "src/verifier/domains/owner.py": "OWNER",
    "src/verifier/domains/role.py": "ROLE",
    "src/verifier/domains/sim.py": "SIM",
    "src/verifier/domains/token.py": "TOKEN",
    "src/verifier/domains/train.py": "TRAIN",
    "src/verifier/domains/verifier.py": "VERIFIER",
    "src/verifier/domains/verifier_bootstrap.py": "VERIFIER",
    "src/verifier/domains/verifier_execution.py": "VERIFIER",
}


def _consequence_compiler_fixture():
    row = {
        "object_id": "subject",
        "kind": "AGENT",
        "specializations": [],
        "payload": {},
        "operands": {},
        "surfaces": ["file:subject.py"],
        "reason": "The subject is represented explicitly.",
        "classification": {
            "FINBOT": {
                "status": "DOES_NOT_APPLY",
                "reason": "The local surface has no financial endpoint.",
                "evidence": [
                    {"path": "subject.py", "sha256": "sha256:" + "a" * 64}
                ],
            }
        },
        "obligations": {},
    }
    observed = {
        "surfaces": [
            {
                "surface_id": "file:subject.py",
                "path": "subject.py",
                "source_kinds": [],
            }
        ],
        "census": {
            "files": [
                {"path": "subject.py", "sha256": "sha256:" + "a" * 64}
            ]
        },
    }
    return {"subject": row}, observed


def test_consequence_compiler_adopts_role_but_leaves_obligations_open():
    rows, observed = _consequence_compiler_fixture()
    registry = namespace_registry()

    migration_module._apply_required_consequence_kinds(
        rows, {}, observed, registry, {"subject": ["FINBOT"]}
    )

    row = rows["subject"]
    assert row["specializations"] == ["FINBOT"]
    assert row["classification"]["FINBOT"] == {
        "status": "APPLIES",
        "reason": migration_module._consequence_retention_reason(
            "subject", "FINBOT"
        ),
        "evidence": [
            {"path": "subject.py", "sha256": "sha256:" + "a" * 64}
        ],
    }
    expected = {
        item["id"]
        for item in requirements_for(registry, ("FINBOT",))
        if item["kind"] == "FINBOT"
    }
    assert set(row["obligations"]) == expected
    assert all(
        binding["reason"] == ""
        and binding["evidence"] == []
        and binding["declaration"]
        and not any(binding["declaration"].values())
        for binding in row["obligations"].values()
    )


def test_documented_retention_compiles_missing_obligation_bindings(
    monkeypatch: pytest.MonkeyPatch,
):
    """One checked reasons.vstd APPLIES answer gets bindings, not a source role."""

    from verifier.runtime.tier_zero_reasoning import integration as reason_integration

    rows, observed = _consequence_compiler_fixture()
    row = rows["subject"]
    row["classification"] = {
        "ACTUATOR": {
            "status": "UNRESOLVED",
            "reason": "The source-role decision remains open.",
            "evidence": [],
        }
    }
    selected = object()
    monkeypatch.setattr(reason_integration, "select_root_reasons", lambda root: selected)
    monkeypatch.setattr(
        reason_integration,
        "documented_applicability_answers",
        lambda selection, objects: (
            {
                "object_id": "subject",
                "object_kind": "ACTUATOR",
                "reason_id": "tier0-actuator-subject",
                "decision": "APPLIES",
            },
        ),
    )

    migration_module._apply_documented_obligation_bindings(
        Path("."), rows, observed, namespace_registry()
    )

    expected = {
        item["id"]
        for item in requirements_for(namespace_registry(), ("ACTUATOR",))
        if item["kind"] == "ACTUATOR"
    }
    assert set(row["obligations"]) == expected
    assert row["classification"]["ACTUATOR"]["status"] == "UNRESOLVED"
    assert row["specializations"] == []
    for binding in row["obligations"].values():
        assert binding["reason"] == (
            "reasons.vstd:tier0-actuator-subject; "
            "fulfillment NOT_ESTABLISHED."
        )
        assert binding["evidence"] == [
            {"path": "subject.py", "sha256": "sha256:" + "a" * 64}
        ]
        assert binding["declaration"]
        assert set(binding["declaration"].values()) == {"NOT_ESTABLISHED"}


def test_documented_retention_does_not_materialize_unselected_lookalike(
    monkeypatch: pytest.MonkeyPatch,
):
    """Only the checked selection returned by the sole ledger can add bindings."""

    from verifier.runtime.tier_zero_reasoning import integration as reason_integration

    rows, observed = _consequence_compiler_fixture()
    rows["subject"]["classification"] = {
        "ACTUATOR": {
            "status": "UNRESOLVED",
            "reason": "Text claiming that a reason selects APPLIES.",
            "evidence": [],
        }
    }
    monkeypatch.setattr(reason_integration, "select_root_reasons", lambda root: object())
    monkeypatch.setattr(
        reason_integration,
        "documented_applicability_answers",
        lambda selection, objects: (),
    )

    migration_module._apply_documented_obligation_bindings(
        Path("."), rows, observed, namespace_registry()
    )

    assert rows["subject"]["obligations"] == {}


def test_documented_retention_fills_graph_selected_blank_bindings(
    monkeypatch: pytest.MonkeyPatch,
):
    """A compiler-selected APPLIES role cannot retain blank Tier-0 fields."""

    from verifier.runtime.tier_zero_reasoning import integration as reason_integration

    rows, observed = _consequence_compiler_fixture()
    migration_module._apply_required_consequence_kinds(
        rows, {}, observed, namespace_registry(), {"subject": ["FINBOT"]}
    )
    monkeypatch.setattr(reason_integration, "select_root_reasons", lambda root: object())
    monkeypatch.setattr(
        reason_integration,
        "documented_applicability_answers",
        lambda selection, objects: (),
    )

    migration_module._apply_documented_obligation_bindings(
        Path("."), rows, observed, namespace_registry()
    )

    bindings = rows["subject"]["obligations"]
    assert bindings
    assert {
        binding["reason"] for binding in bindings.values()
    } == {"objects.vstd APPLIES; fulfillment NOT_ESTABLISHED."}
    assert all(binding["evidence"] for binding in bindings.values())
    assert {
        value
        for binding in bindings.values()
        for value in binding["declaration"].values()
    } == {"NOT_ESTABLISHED"}


def test_documented_retention_rebinds_generated_not_established_rows(
    monkeypatch: pytest.MonkeyPatch,
):
    """A generated complete-looking row follows current owned source bytes."""

    from verifier.runtime.tier_zero_reasoning import integration as reason_integration

    rows, observed = _consequence_compiler_fixture()
    migration_module._apply_required_consequence_kinds(
        rows, {}, observed, namespace_registry(), {"subject": ["FINBOT"]}
    )
    monkeypatch.setattr(reason_integration, "select_root_reasons", lambda root: object())
    monkeypatch.setattr(
        reason_integration,
        "documented_applicability_answers",
        lambda selection, objects: (),
    )
    migration_module._apply_documented_obligation_bindings(
        Path("."), rows, observed, namespace_registry()
    )

    changed = deepcopy(observed)
    changed["census"]["files"][0]["sha256"] = "sha256:" + "b" * 64
    migration_module._apply_documented_obligation_bindings(
        Path("."), rows, changed, namespace_registry()
    )

    assert {
        binding["evidence"][0]["sha256"]
        for binding in rows["subject"]["obligations"].values()
    } == {"sha256:" + "b" * 64}


def test_documented_retention_preserves_independently_completed_rows(
    monkeypatch: pytest.MonkeyPatch,
):
    """Refresh never replaces concrete semantic evidence with a placeholder."""

    from verifier.runtime.tier_zero_reasoning import integration as reason_integration

    rows, observed = _consequence_compiler_fixture()
    migration_module._apply_required_consequence_kinds(
        rows, {}, observed, namespace_registry(), {"subject": ["FINBOT"]}
    )
    obligation_id = sorted(rows["subject"]["obligations"])[0]
    binding = rows["subject"]["obligations"][obligation_id]
    binding["reason"] = "Independent current evidence establishes this declaration."
    binding["evidence"] = [
        {"path": "subject.py", "sha256": "sha256:" + "a" * 64}
    ]
    binding["declaration"] = {
        field: "Bound by the independent fixture."
        for field in binding["declaration"]
    }
    expected = deepcopy(binding)
    monkeypatch.setattr(reason_integration, "select_root_reasons", lambda root: object())
    monkeypatch.setattr(
        reason_integration,
        "documented_applicability_answers",
        lambda selection, objects: (),
    )
    changed = deepcopy(observed)
    changed["census"]["files"][0]["sha256"] = "sha256:" + "b" * 64

    migration_module._apply_documented_obligation_bindings(
        Path("."), rows, changed, namespace_registry()
    )

    assert rows["subject"]["obligations"][obligation_id] == expected


def test_compiled_classification_reason_projection_preserves_identity():
    long_reason = "Current reviewed source boundary. " + "detail " * 120
    rows, _ = _consequence_compiler_fixture()
    rows["subject"]["classification"] = {
        "ACTUATOR": {
            "status": "APPLIES",
            "reason": long_reason,
            "evidence": [
                {"path": "subject.py", "sha256": "sha256:" + "a" * 64}
            ],
        },
        "MARKET": {
            "status": "UNRESOLVED",
            "reason": (
                "Migration retains this applicability question. Static ownership "
                "alone cannot refute a MARKET role."
            ),
            "evidence": [],
        },
    }

    migration_module._compact_compiled_classification_reasons(rows)

    projected = rows["subject"]["classification"]["ACTUATOR"]
    assert projected["status"] == "APPLIES"
    assert projected["evidence"] == [
        {"path": "subject.py", "sha256": "sha256:" + "a" * 64}
    ]
    assert projected["reason"].startswith("Current reviewed source boundary.")
    assert tier_zero_profile.value_digest(long_reason) in projected["reason"]
    assert rows["subject"]["classification"]["MARKET"]["reason"] == (
        "UNRESOLVED."
    )


def test_consequence_compiler_preserves_independent_applicability_review():
    rows, observed = _consequence_compiler_fixture()
    reviewed = {
        "status": "APPLIES",
        "reason": "The exact reviewed endpoint requires FINBOT obligations.",
        "evidence": [
            {"path": "subject.py", "sha256": "sha256:" + "a" * 64}
        ],
    }
    rows["subject"]["classification"]["FINBOT"] = deepcopy(reviewed)

    migration_module._apply_required_consequence_kinds(
        rows, {}, observed, namespace_registry(), {"subject": ["FINBOT"]}
    )

    assert rows["subject"]["classification"]["FINBOT"] == reviewed
    assert rows["subject"]["specializations"] == ["FINBOT"]


def test_consequence_compiler_retains_prior_adoption_after_local_refresh():
    rows, observed = _consequence_compiler_fixture()
    registry = namespace_registry()
    migration_module._apply_required_consequence_kinds(
        rows, {}, observed, registry, {"subject": ["FINBOT"]}
    )
    previous = deepcopy(rows)
    rows["subject"]["classification"]["FINBOT"] = {
        "status": "DOES_NOT_APPLY",
        "reason": "A refreshed local-only review still sees no endpoint.",
        "evidence": [],
    }

    migration_module._apply_required_consequence_kinds(
        rows, previous, observed, registry, {}
    )

    assert rows["subject"]["classification"]["FINBOT"]["status"] == "APPLIES"
    assert rows["subject"]["classification"]["FINBOT"]["reason"] == (
        migration_module._consequence_retention_reason("subject", "FINBOT")
    )


def test_consequence_compiler_retires_prior_adoption_after_current_owned_refutation():
    rows, observed = _consequence_compiler_fixture()
    registry = namespace_registry()
    migration_module._apply_required_consequence_kinds(
        rows, {}, observed, registry, {"subject": ["FINBOT"]}
    )
    previous = deepcopy(rows)
    migration_module._prepare_local_reviews_without_compiled_consequences(
        rows, previous
    )
    reviewed_refutation = {
        "status": "DOES_NOT_APPLY",
        "reason": "The current owned surface has no financial endpoint.",
        "evidence": [
            {"path": "subject.py", "sha256": "sha256:" + "a" * 64}
        ],
    }
    rows["subject"]["classification"]["FINBOT"] = deepcopy(
        reviewed_refutation
    )

    migration_module._apply_required_consequence_kinds(
        rows, previous, observed, registry, {}
    )

    assert rows["subject"]["classification"]["FINBOT"] == reviewed_refutation
    assert "FINBOT" not in rows["subject"]["specializations"]
    assert not any(
        obligation_id.startswith("FINBOT-")
        for obligation_id in rows["subject"]["obligations"]
    )


def test_consequence_compiler_does_not_promote_unselected_role():
    rows, observed = _consequence_compiler_fixture()
    before = deepcopy(rows)

    migration_module._apply_required_consequence_kinds(
        rows, {}, observed, namespace_registry(), {}
    )

    assert rows == before


def test_consequence_compiler_requires_current_owned_evidence():
    rows, observed = _consequence_compiler_fixture()
    observed["surfaces"] = []

    with pytest.raises(
        ValueError, match="PACKAGE_MIGRATION_CONSEQUENCE_EVIDENCE_MISSING:subject"
    ):
        migration_module._apply_required_consequence_kinds(
            rows,
            {},
            observed,
            namespace_registry(),
            {"subject": ["FINBOT"]},
        )


def test_consequence_compiler_uses_implicit_typed_operand_graph():
    rows, observed = _consequence_compiler_fixture()
    rows["subject"]["specializations"] = ["ASSET"]
    registry = namespace_registry()
    derived = migration_module.namespace_consequences.derive_consequences(
        list(rows.values()),
        registry,
        observed,
        migration_module.namespace_consequences.EMPTY,
    )

    assert derived["required_kinds"] == {"subject": ["FINBOT"]}
    migration_module._apply_required_consequence_kinds(
        rows,
        {},
        observed,
        registry,
        derived["required_kinds"],
    )
    assert rows["subject"]["specializations"] == ["ASSET", "FINBOT"]
    assert rows["subject"]["classification"]["FINBOT"]["status"] == "APPLIES"


def test_local_reviews_hide_then_restore_compiler_owned_consequence_role():
    rows, observed = _consequence_compiler_fixture()
    registry = namespace_registry()
    migration_module._apply_required_consequence_kinds(
        rows, {}, observed, registry, {"subject": ["FINBOT"]}
    )
    previous = deepcopy(rows)
    retained_obligation_id = sorted(rows["subject"]["obligations"])[0]
    retained = rows["subject"]["obligations"][retained_obligation_id]
    retained["reason"] = "The exact graph-required boundary remains open."
    retained["evidence"] = [
        {"path": "subject.py", "sha256": "sha256:" + "a" * 64}
    ]
    retained["declaration"] = {
        field: "NOT_ESTABLISHED at Tier 0."
        for field in retained["declaration"]
    }
    previous = deepcopy(rows)

    migration_module._prepare_local_reviews_without_compiled_consequences(
        rows, previous
    )

    assert "FINBOT" not in rows["subject"]["specializations"]
    assert rows["subject"]["classification"]["FINBOT"]["status"] == "UNRESOLVED"
    assert not any(
        obligation_id.startswith("FINBOT-")
        for obligation_id in rows["subject"]["obligations"]
    )

    migration_module._apply_required_consequence_kinds(
        rows, previous, observed, registry, {}
    )

    assert rows["subject"]["specializations"] == ["FINBOT"]
    assert rows["subject"]["classification"]["FINBOT"]["status"] == "APPLIES"
    assert (
        rows["subject"]["obligations"][retained_obligation_id]
        == previous["subject"]["obligations"][retained_obligation_id]
    )


def envelope():
    retained = tier_zero_manifest.manifest_template(
        repository="https://github.com/TimeLordRaps/verifier.git", revision="1" * 40
    )
    rows = []
    for item in tier_zero_manifest._namespace_objects(retained["objects"]):
        rows.append(
            {
                **item.to_dict(),
                "specializations": [],
                "surfaces": [],
                "reason": "Draft retains the original role.",
                "classification": {},
                "obligations": {},
            }
        )
    return {
        **retained,
        "schema_version": package_manifest.SCHEMA,
        "namespace": {
            "schema_version": "verifier-objects-manifest-2",
            "extensions": [],
            "registry_digest": registry_document(namespace_registry())["digest"],
            "objects": rows,
        },
    }


def select(document):
    return package_manifest.select(
        document, repository=document["repository"]["remote"], revision="1" * 40
    )


def test_migration_retains_all_core_obligations_and_graph():
    document = envelope()
    retained, validation, objects = select(document)
    assert validation["slot_count"] == 234
    assert validation["route_count"] == 408
    assert len(objects) == 26
    assert retained["objects"] == document["objects"]
    assert retained["obligation_denominator"] == document["obligation_denominator"]


@pytest.mark.parametrize(
    "mutation,code",
    [
        (lambda d: d["namespace"]["objects"].pop(), "OBJECT_REMOVED"),
        (lambda d: d["obligation_denominator"].update(route_count=407), "DENOMINATOR"),
        (
            lambda d: next(
                r for r in d["namespace"]["objects"] if r["kind"] == "GRAPH"
            )["operands"]["members"].pop(),
            "GRAPH_NOT_COMPLETE",
        ),
        (
            lambda d: next(r for r in d["namespace"]["objects"] if r["kind"] == "SIM")[
                "operands"
            ].update(verifier=["vstd-package-object"]),
            "EDGES_CHANGED",
        ),
        (lambda d: d["namespace"]["objects"][0].update(kind="OBJECT"), "KIND_CHANGED"),
        (
            lambda d: next(
                r for r in d["namespace"]["objects"] if r["kind"] == "GRAPH"
            )["operands"]["members"].reverse(),
            "EDGE_ORDER_CHANGED",
        ),
    ],
)
def test_migration_rejects_denominator_and_graph_loss(mutation, code):
    document = envelope()
    mutation(document)
    with pytest.raises(ValueError, match=code):
        select(document)


def test_additional_kind_is_in_same_graph_and_inherits_base():
    document = envelope()
    extra = {
        "object_id": "history",
        "kind": "LEDGER",
        "specializations": [],
        "payload": {},
        "operands": {},
        "surfaces": ["file:history.py"],
        "reason": "History is represented explicitly.",
        "classification": {},
        "obligations": {},
    }
    document["namespace"]["objects"].append(extra)
    with pytest.raises(ValueError, match="GRAPH_NOT_COMPLETE"):
        select(document)
    next(r for r in document["namespace"]["objects"] if r["kind"] == "GRAPH")[
        "operands"
    ]["members"].append("history")
    _, validation, objects = select(document)
    assert len(objects) == 27
    assert (
        next(obj for obj in objects if obj.object_id == "history").kind.value
        == "OBJECT"
    )
    assert validation["route_count"] == 408
    assert document["namespace"]["objects"][-1]["kind"] == "LEDGER"


def test_public_tier_zero_dispatches_additive_package_contract(tmp_path, monkeypatch):
    from verifier.runtime import tier_zero, package_admission
    from verifier.runtime.tier_zero_profile import canonical_bytes

    (tmp_path / "objects.vstd").write_bytes(canonical_bytes(envelope()) + b"\n")
    monkeypatch.setattr(
        package_admission, "assess", lambda *args, **kwargs: {"selected": "additive"}
    )
    # This test pins which assessor the dispatcher selects.  The original-kind closure
    # binder rewrites a real admission report's obligations and has its own tests.
    monkeypatch.setattr(
        tier_zero, "_bind_package_original_kind_closure", lambda report, *args: report
    )
    assert tier_zero.assess_tier_zero(tmp_path) == {"selected": "additive"}


@pytest.mark.parametrize(
    "core_status,namespace_status,expected",
    [
        ("PASS", "PASS", "PASS"),
        ("UNKNOWN", "PASS", "UNKNOWN"),
        ("PASS", "UNKNOWN", "UNKNOWN"),
        ("FAIL", "PASS", "FAIL"),
        ("PASS", "FAIL", "FAIL"),
    ],
)
def test_admission_requires_both_contracts(
    tmp_path, monkeypatch, core_status, namespace_status, expected
):
    from verifier.runtime import package_admission as gate, tier_zero_profile

    document = envelope()
    raw = tier_zero_profile.canonical_bytes(document) + b"\n"
    (tmp_path / "objects.vstd").write_bytes(raw)
    coordinate = {"repository": document["repository"]["remote"], "revision": "1" * 40}
    census = "sha256:" + "a" * 64
    monkeypatch.setattr(
        gate.self_polish_estate, "_git_coordinate", lambda root: coordinate
    )
    monkeypatch.setattr(
        gate.self_polish_estate,
        "capture_candidate_source_census",
        lambda root: {"census_digest": census},
    )

    def result(status):
        outcomes = [
            {
                "coordinate": "VSTD-T0." + str(index),
                "name": "Retained check",
                "status": status if index == 5 else "PASS",
                "assessment_reason": "Checked selected inputs.",
                "blockers": ["UNRESOLVED_DENOMINATOR"]
                if index == 5 and status != "PASS"
                else [],
            }
            for index in range(1, 10)
        ]
        return {
                "schema_version": "bounded-test-component-report-1",
                "profile_id": "bounded-test-component",
                "profile_digest": "sha256:" + "b" * 64,
                "mechanism_digest": "sha256:" + "c" * 64,
            "obligations": outcomes,
            "status": status,
            "manifest_digest": gate.self_polish_estate.bytes_digest(raw),
            "source_coordinate": coordinate,
            "source_census_digest": census,
                "obligation_count": len(outcomes),
                "obligation_status_counts": {
                    key: sum(row["status"] == key for row in outcomes)
                    for key in ("PASS", "FAIL", "UNKNOWN")
                },
                "blockers": sorted(
                    {code for row in outcomes for code in row["blockers"]}
                ),
                "claim_boundary": "Bounded conjunction fixture only.",
            "finalization": {
                "source_census_digest": census,
                "source_coordinate": coordinate,
            },
            "findings": [],
                "object_assessments": [],
                "required_obligations": [],
                "assessment_executed": True,
            "next_obligation": None,
                "report_digest": "sha256:" + "d" * 64,
        }

    monkeypatch.setattr(
        gate.tier_zero,
        "assess_legacy_tier_zero",
        lambda *args, **kwargs: result(core_status),
    )
    monkeypatch.setattr(
        gate.namespace_admission,
        "assess",
        lambda *args, **kwargs: result(namespace_status),
    )
    # This test isolates the retained/namespace conjunction.  The installed semantic-review
    # replay needs the full reviewed package graph; test_package_admission_semantic_review_replay
    # exercises it against that graph.
    monkeypatch.setattr(
        gate, "_semantic_review_replay",
        lambda *args, **kwargs: {"status": "PASS", "blockers": []},
    )
    report = gate.assess(tmp_path)
    assert report["status"] == expected
    assert report["finalization"]["complete"] is (expected == "PASS")
    assert len(report["obligations"]) == 9
    assert report["verifier_execution"]["object_id"] == "verifier-core-self"
    assert report["verifier_execution"]["subject_id"] == "vstd-package-graph"


def test_optimized_discovery_preserves_all_hint_signals():
    import ast
    from verifier.runtime.namespace_discovery import _hints, _definition_hints

    tree = ast.parse(
        "class Bank:\n def ledger(self):\n  debit = credit\n  def transaction():\n   commit(); rollback()\n  return transaction\n"
    )
    for node, hints in _definition_hints(tree).items():
        assert hints == _hints(node)


def test_nonexecuting_artifacts_are_owned_not_unsupported(tmp_path):
    from verifier.runtime.namespace_discovery import discover
    import subprocess

    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    for name in ("LICENSE", "NOTICE", "CITATION.cff", "receipt.cose", "page.css"):
        (tmp_path / name).write_bytes(b"bounded artifact\n")
    result = discover(tmp_path)
    assert result["gaps"] == []
    assert len(result["surfaces"]) == 5


def test_real_financial_implementations_declare_their_source_roles():
    from pathlib import Path
    from verifier.runtime.namespace_discovery import _python_surfaces

    root = Path(__file__).parents[1]
    for name, expected in (
        ("polish_invocation_ledger.py", {"LEDGER", "TRANSACTION"}),
        ("namespace_cli.py", {"TRANSACTION"}),
    ):
        rows = _python_surfaces(
            name, (root / "src/verifier/runtime" / name).read_bytes()
        )
        assert rows and all(set(row["source_kinds"]) == expected for row in rows)


def test_focused_namespace_gate_cannot_bypass_retained_failure(tmp_path, monkeypatch):
    from verifier.runtime import (
        namespace_admission as gate,
        package_admission,
        tier_zero_profile,
    )

    (tmp_path / "objects.vstd").write_bytes(
        tier_zero_profile.canonical_bytes(envelope()) + b"\n"
    )
    namespace = {
        "object_assessments": [{"object_id": "vstd-package-object"}],
        "required_obligations": [],
        "assessment_executed": True,
        "obligations": [{"coordinate": "VSTD-T0.6", "status": "PASS"}],
    }
    combined = {
        "status": "FAIL",
        "namespace_admission": namespace,
        "findings": [],
        "retained_admission": {
            "obligations": [
                {
                    "coordinate": "VSTD-T0.5",
                    "status": "FAIL",
                    "blockers": ["TIER_ZERO_DENOMINATOR_DIFFERS"],
                    "assessment_reason": "A route was removed.",
                }
            ]
        },
    }
    monkeypatch.setattr(
        package_admission, "assess", lambda *args, **kwargs: deepcopy(combined)
    )
    report = gate.assess_gate(
        "vstd-package-object", "VSTD-T0.6-namespace-admission", tmp_path
    )
    assert report["status"] == report["package_admission_status"] == "FAIL"
    assert report["selected_obligation"]["status"] == "PASS"
    assert any(
        row["code"] == "TIER_ZERO_DENOMINATOR_DIFFERS"
        for row in report["prerequisite_findings"]
    )


@pytest.mark.parametrize("schema", ["retained", "additive"])
def test_independent_package_consumer_accepts_exact_admission_version_and_rejects_changed_mechanism(
    schema,
):
    from verifier.runtime import (
        package_self_polish,
        package_self_polish_recheck as recheck,
    )
    from verifier.runtime import package_admission, tier_zero

    digest = "sha256:" + "a" * 64
    bound = package_self_polish._empty_tier_zero_admission("PASS", "unused")
    bound.update(
        report_schema_version=(
            package_admission.REPORT_SCHEMA
            if schema == "additive"
            else tier_zero.REPORT_SCHEMA
        ),
        report_digest=digest,
        profile_id="vstd-package-admission-3" if schema == "additive" else "retained",
        profile_digest=package_admission.profile_digest()
        if schema == "additive"
        else digest,
        manifest_digest=digest,
        mechanism_digest=package_admission.mechanism_digest()
        if schema == "additive"
        else tier_zero.mechanism_digest(),
        obligation_count=9,
        obligation_status_counts={"PASS": 9, "FAIL": 0, "UNKNOWN": 0},
        assessment_reason_count=9,
        finalization_status="PASS",
        closed_coordinates=["VSTD-T0." + str(i) for i in range(1, 10)],
        unclosed_coordinates=[],
        source_repository="https://github.com/TimeLordRaps/verifier.git",
        source_revision="1" * 40,
        source_census_digest=digest,
        source_binding_status="PASS",
        error=None,
    )
    report = {
        "tier_zero_repository_admission": bound,
        "source_coordinate": {"source_head": "1" * 40},
        "source_recapture_binding": {
            "opening_binding": {
                "observed_source_evidence": {"candidate_source_census_digest": digest}
            }
        },
    }
    invalidators = set()
    recheck._check_tier_zero_repository_admission(report, invalidators)
    assert not invalidators
    bound["mechanism_digest"] = digest
    recheck._check_tier_zero_repository_admission(report, invalidators)
    assert "PACKAGE_RECHECK_TIER_ZERO_ADMISSION_STATUS_DIFFERS" in invalidators


def _migration_fixture(tmp_path, monkeypatch):
    """Synthetic discovery isolates migration decisions from source scanning."""
    from verifier.runtime import namespace_discovery

    observed = {"surfaces": [], "census": {"files": []}}
    for name in (
        "src/verifier/runtime/polish_invocation_ledger.py",
        "src/verifier/runtime/namespace_cli.py",
    ):
        observed["surfaces"].append(
            {
                "path": name,
                "surface_id": "file:" + name,
                "hints": [],
                "source_kinds": [],
            }
        )
        observed["census"]["files"].append(
            {"path": name, "sha256": "sha256:" + "a" * 64}
        )
    monkeypatch.setattr(
        namespace_discovery, "discover", lambda root: deepcopy(observed)
    )
    document = envelope()
    document.pop("namespace")
    document["schema_version"] = "verifier-objects-manifest-1"
    for field in ("node_reconciler", "obligation_reason_provider"):
        selected = tmp_path / document[field]["path"]
        selected.parent.mkdir(parents=True, exist_ok=True)
        selected.write_bytes(b"synthetic migration byte-binding fixture\n")
    return migration_module, document


def _verifier_core_harness_predecessor() -> dict:
    root = Path(__file__).resolve().parents[1]
    document = json.loads((root / "objects.vstd").read_text(encoding="utf-8"))
    document = migration_module.expand_compact_document(document)
    retained = next(
        row
        for row in document["objects"]
        if row["object_id"] == "verifier-core-self"
    )
    namespace = next(
        row
        for row in document["namespace"]["objects"]
        if row["object_id"] == "verifier-core-self"
    )
    retained["edges"] = {}
    namespace["operands"] = {}
    return document


def test_exact_verifier_core_harness_predecessor_upgrades_both_graphs() -> None:
    predecessor = _verifier_core_harness_predecessor()
    before = deepcopy(predecessor)

    upgraded = (
        migration_module._upgrade_current_or_pre_verifier_core_harness_binding(
            predecessor
        )
    )

    assert predecessor == before
    assert next(
        row["edges"]
        for row in upgraded["objects"]
        if row["object_id"] == "verifier-core-self"
    ) == {"harness": ["vstd-harness"]}
    assert next(
        row["operands"]
        for row in upgraded["namespace"]["objects"]
        if row["object_id"] == "verifier-core-self"
    ) == {"harness": ["vstd-harness"]}
    assert migration_module._is_exact_verifier_core_harness_retained_transition(
        package_manifest.retained_contract(before),
        package_manifest.retained_contract(upgraded),
    )


def test_verifier_core_harness_upgrade_refuses_a_namespace_near_miss() -> None:
    predecessor = _verifier_core_harness_predecessor()
    next(
        row
        for row in predecessor["namespace"]["objects"]
        if row["object_id"] == "verifier-core-self"
    )["operands"] = {"harness": ["vstd-agent"]}

    with pytest.raises(ValueError, match="PACKAGE_NAMESPACE_EDGES_CHANGED"):
        migration_module._upgrade_current_or_pre_verifier_core_harness_binding(
            predecessor
        )


def _pre_applicability_registry_digest():
    """Reconstruct the exact installed-registry predecessor independently."""
    contracts = deepcopy(registry_document(namespace_registry())["contracts"])
    for contract in contracts:
        for obligation in contract["obligations"]:
            obligation.pop("applicability")
            obligation.pop("applicability_digest")
    return migration_module.value_digest(contracts)


def _pre_applicability_tier_zero_profile_digest():
    """Reconstruct the exact Tier-0 profile predecessor independently."""
    current = tier_zero_profile.installed_tier_zero_profile()
    body = {
        key: deepcopy(value)
        for key, value in current.items()
        if key != "profile_digest"
    }
    for obligation in body["obligations"]:
        obligation.pop("applicability")
        obligation.pop("applicability_digest")
    return migration_module.value_digest(body)


def _add_forged_extension(document):
    document["namespace"]["extensions"].append(
        {
            "kind": "FORGED",
            "extends": "OBJECT",
            "version": "1",
            "reason": "A locally declared kind must not enter an installed upgrade.",
            "obligations": [
                {
                    "id": "FORGED-0.1-boundary",
                    "name": "Boundary",
                    "reason": "The local boundary would change the registry.",
                    "evidence_requirement": "Bind the local boundary.",
                }
            ],
        }
    )


def _mutate_invocation_ledger_kind(document):
    next(
        row
        for row in document["namespace"]["objects"]
        if row["object_id"] == "vstd-invocation-ledger"
    )["kind"] = "OBJECT"


def _add_invocation_ledger_robot_role(document):
    next(
        row
        for row in document["namespace"]["objects"]
        if row["object_id"] == "vstd-invocation-ledger"
    )["specializations"].append("ROBOT")


def _add_forged_obligation_identity(document):
    next(
        row
        for row in document["namespace"]["objects"]
        if row["object_id"] == "vstd-invocation-ledger"
    )["obligations"]["FORGED-9.9-not-installed"] = {
        "reason": "A syntactically valid binding must not invent an identity.",
        "evidence": [],
        "declaration": {"contract": "forged"},
    }


def _namespace_row(document, object_id):
    return next(
        row
        for row in document["namespace"]["objects"]
        if row["object_id"] == object_id
    )


def _mutate_invocation_ledger_classification_reason(document):
    _namespace_row(document, "vstd-invocation-ledger")["classification"][
        "LEDGER"
    ]["reason"] = "Forged classification rationale."


def _mutate_invocation_ledger_classification_status(document):
    _namespace_row(document, "vstd-invocation-ledger")["classification"][
        "LEDGER"
    ]["status"] = "DOES_NOT_APPLY"


def _mutate_invocation_ledger_obligation_reason(document):
    _namespace_row(document, "vstd-invocation-ledger")["obligations"][
        "LEDGER-0.1-authoritative-history"
    ]["reason"] = "Forged obligation rationale."


def _mutate_invocation_ledger_declaration_value(document):
    _namespace_row(document, "vstd-invocation-ledger")["obligations"][
        "LEDGER-0.1-authoritative-history"
    ]["declaration"]["history"] = "Forged history declaration."


def _mutate_semantic_payload(document):
    _namespace_row(document, "vstd-accelerator-discovery-command")["payload"][
        "representation_role"
    ] = "Forged representation role."


def _mutate_semantic_object_reason(document):
    _namespace_row(document, "vstd-accelerator-discovery-command")["reason"] = (
        "Forged object rationale."
    )


def _add_semantic_surface(document):
    _namespace_row(document, "vstd-accelerator-discovery-command")[
        "surfaces"
    ].append("file:forged.py")


def _mutate_semantic_classification_evidence_path(document):
    _namespace_row(document, "vstd-accelerator-discovery-command")[
        "classification"
    ]["ACTUATOR"]["evidence"][0]["path"] = "forged.py"


def _mutate_semantic_obligation_evidence_path(document):
    _namespace_row(document, "vstd-accelerator-discovery-command")[
        "obligations"
    ]["ACTUATOR-0.1-command-to-effect"]["evidence"][0]["path"] = "forged.py"


def _add_accelerator_semantic_row(module, document):
    """Add one complete non-named catalog row to the small migration fixture."""

    object_id = "vstd-accelerator-discovery-command"
    spec = next(
        item
        for item in module.package_semantic_ownership.SEMANTIC_OWNERSHIP_SPECS
        if item.object_id == object_id
    )
    review = module.package_semantic_review_hardware_cli.review_document()[object_id]
    def evidence_for(kind):
        # Each answer cites exactly the paths its own review decision names.
        return [
            {"path": path, "sha256": "sha256:" + "a" * 64}
            for path in review["classification"][kind]["evidence_paths"]
        ]

    obligations = {
        obligation["id"]: {
            "reason": "",
            "evidence": [],
            "declaration": {
                field: "" for field in obligation["declaration_fields"]
            },
        }
        for obligation in requirements_for(
            namespace_registry(), {spec.primary_kind, *spec.specializations}
        )
    }
    suffix = (
        " This Tier-0 declaration names only the exact reviewed source boundary; "
        "execution and Tier-1-plus fulfillment remain unestablished."
    )
    for obligation_id, declaration in review["declarations"].items():
        kind = obligation_id.split("-", 1)[0]
        obligations[obligation_id] = {
            "reason": review["classification"][kind]["reason"] + suffix,
            "evidence": evidence_for(kind),
            "declaration": deepcopy(declaration),
        }
    row = {
        "object_id": object_id,
        "kind": spec.primary_kind,
        "specializations": list(spec.specializations),
        "payload": {"representation_role": spec.representation_role},
        "operands": {name: list(targets) for name, targets in spec.operands},
        "surfaces": ["file:" + path for path in spec.owned_paths],
        "reason": spec.necessity_reason + " Boundary: " + spec.consequence_boundary,
        "classification": {
            kind: {
                "status": decision["status"],
                "reason": decision["reason"],
                "evidence": evidence_for(kind),
            }
            for kind, decision in review["classification"].items()
        },
        "obligations": obligations,
    }
    document["namespace"]["objects"].append(row)
    next(
        item
        for item in document["namespace"]["objects"]
        if item["kind"] == "GRAPH"
    )["operands"]["members"].append(object_id)


def _add_discovered_files(tmp_path, monkeypatch, paths):
    """Extend the synthetic census without coupling this test to real scanning."""
    from verifier.runtime import namespace_discovery

    observed = namespace_discovery.discover(tmp_path)
    for index, path in enumerate(paths):
        observed["surfaces"].append(
            {
                "path": path,
                "surface_id": "file:" + path,
                "hints": [],
                "source_kinds": [],
            }
        )
        observed["census"]["files"].append(
            {"path": path, "sha256": "sha256:" + format(index + 1, "064x")}
        )
    monkeypatch.setattr(
        namespace_discovery, "discover", lambda root: deepcopy(observed)
    )
    return observed


_PENDING_SEMANTIC_INSTALL_IDS = frozenset(
    {
        "vstd-added-kind-behavioral-verifier",
        "vstd-root-uv-dependency-resolution",
    }
)


def _pending_semantic_install_predecessor(
    tmp_path, monkeypatch, *, legacy_carried
):
    """Build the exact validation-order seam with two catalog rows pending."""
    from verifier.runtime.package_semantic_ownership import SemanticOwnershipSpec
    from verifier.runtime.package_semantic_ownership_model import root_role_decision

    module, document = _migration_fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(
        module.tier_zero_manifest, "MAX_EXTENDED_MANIFEST_BYTES", 1
    )
    pending = tuple(
        spec
        for spec in module.package_semantic_ownership.SEMANTIC_OWNERSHIP_SPECS
        if spec.object_id in _PENDING_SEMANTIC_INSTALL_IDS
    )
    assert {spec.object_id for spec in pending} == _PENDING_SEMANTIC_INSTALL_IDS
    pending_paths = tuple(
        path for spec in pending for path in spec.owned_paths
    )
    assert len(pending_paths) == 5

    installed_path = "src/verifier/runtime/gate_pipeline.py"
    installed = SemanticOwnershipSpec(
        object_id="vstd-already-installed-semantic-owner",
        primary_kind="VERIFIER",
        specializations=(),
        owned_paths=(installed_path,),
        representation_role="Synthetic already-installed semantic owner.",
        necessity_reason=(
            "The predecessor needs one catalog row so partial installation is observable."
        ),
        consequence_boundary="Test-only source ownership; no execution claim.",
        root_role_decisions=tuple(
            root_role_decision(
                kind,
                "DOES_NOT_APPLY",
                "The synthetic owner exercises no " + kind + " consequence.",
            )
            for kind, contract in namespace_registry().items()
            if contract.extends is not None
        ),
    )
    initially_observed = (installed_path, *pending_paths) if legacy_carried else (
        installed_path,
    )
    _add_discovered_files(tmp_path, monkeypatch, initially_observed)
    monkeypatch.setattr(
        module.package_semantic_ownership,
        "SEMANTIC_OWNERSHIP_SPECS",
        (installed,),
    )
    monkeypatch.setattr(
        module.package_semantic_ownership,
        "validate_catalog",
        lambda root: (installed,),
    )
    previous = module.migrate(
        tmp_path, document, install_semantic_ownership=True
    )
    previous["namespace"]["registry_digest"] = (
        _pre_applicability_registry_digest()
    )

    if not legacy_carried:
        _add_discovered_files(tmp_path, monkeypatch, pending_paths)
    complete = (installed, *pending)
    validation_calls = []

    def validate_catalog(root):
        validation_calls.append(root)
        return complete

    monkeypatch.setattr(
        module.package_semantic_ownership,
        "SEMANTIC_OWNERSHIP_SPECS",
        complete,
    )
    monkeypatch.setattr(
        module.package_semantic_ownership,
        "validate_catalog",
        validate_catalog,
    )
    return module, previous, pending, pending_paths, validation_calls


_MANIFEST_WRITE_LEGACY_PAYLOAD = {
    "representation_role": "src/verifier/runtime/namespace_cli.py"
}
_MANIFEST_WRITE_LEGACY_REASON = (
    "The implementation at src/verifier/runtime/namespace_cli.py has an explicit "
    "TRANSACTION boundary."
)


def _manifest_write_named_metadata_predecessor(tmp_path, monkeypatch):
    """Build the exact three-path predecessor for the named metadata upgrade."""

    module, document = _migration_fixture(tmp_path, monkeypatch)
    _add_discovered_files(
        tmp_path,
        monkeypatch,
        (
            "src/verifier/runtime/manifest_write_execution.py",
            "src/verifier/runtime/manifest_write_worker.py",
        ),
    )
    monkeypatch.setattr(module.tier_zero_manifest, "MAX_EXTENDED_MANIFEST_BYTES", 1)
    previous = module.migrate(tmp_path, document)
    row = _namespace_row(previous, "vstd-manifest-write")
    current_metadata = (deepcopy(row["payload"]), row["reason"])
    row["payload"] = deepcopy(_MANIFEST_WRITE_LEGACY_PAYLOAD)
    row["reason"] = _MANIFEST_WRITE_LEGACY_REASON
    previous["namespace"]["registry_digest"] = _pre_applicability_registry_digest()
    return module, previous, current_metadata


def _stub_selected_package_reviews(module, monkeypatch):
    """Keep a metadata lifecycle test independent of every review implementation."""

    original_kind_calls = []

    def preserve(root, rows, files):
        return deepcopy(rows)

    for review_module in module._PACKAGE_REVIEW_MODULES:
        function_name = "apply_" + review_module.__name__.rsplit(".", 1)[-1]
        monkeypatch.setattr(review_module, function_name, preserve)
    def preserve_original_kinds(root, rows, files):
        original_kind_calls.append((root, tuple(sorted(rows)), tuple(sorted(files))))
        return deepcopy(rows)

    monkeypatch.setattr(
        module.package_original_kind_catalog,
        "apply_partial_profiles",
        preserve_original_kinds,
    )
    monkeypatch.setattr(module, "_package_review_refresh_catalog", lambda: {})
    monkeypatch.setattr(
        module, "_retire_transferred_reviews", lambda rows, files, registry: None
    )
    return original_kind_calls


def _apply_complete_source_review_predecessor(module, document, files):
    """Materialize every source-owned review selected by the mature bridge."""

    registry = namespace_registry()
    rows = {
        row["object_id"]: row for row in document["namespace"]["objects"]
    }
    for review_module in module._PACKAGE_REVIEW_MODULES:
        suffix = module._PACKAGE_REVIEW_OBLIGATION_SUFFIXES[review_module]
        for object_id, review in review_module.review_document().items():
            row = rows.get(object_id)
            if row is None:
                continue
            for kind, decision in review["classification"].items():
                reason = decision["reason"]
                if decision["status"] == "UNRESOLVED":
                    # A pre-applicability predecessor predates the review catalogs' own
                    # open-question wording; the bridge accepts only its original text.
                    reason = (
                        "Migration retains this applicability question. Static "
                        "ownership alone cannot refute a " + kind + " role."
                    )
                row["classification"][kind] = {
                    "status": decision["status"],
                    "reason": reason,
                    "evidence": [
                        {"path": path, "sha256": files[path]}
                        for path in decision["evidence_paths"]
                    ],
                }
                if (
                    decision["status"] == "APPLIES"
                    and kind != row["kind"]
                    and registry[kind].extends is not None
                    and kind not in row["specializations"]
                ):
                    row["specializations"].append(kind)
            declarations = review.get("declarations", {})
            expected = {
                requirement["id"]: requirement
                for requirement in requirements_for(
                    registry, {row["kind"], *row["specializations"]}
                )
            }
            rebuilt = {}
            for obligation_id, requirement in expected.items():
                declaration = declarations.get(obligation_id)
                if declaration is None:
                    rebuilt[obligation_id] = deepcopy(
                        row["obligations"].get(
                            obligation_id,
                            {
                                "reason": "",
                                "evidence": [],
                                "declaration": {
                                    field: ""
                                    for field in requirement["declaration_fields"]
                                },
                            },
                        )
                    )
                    continue
                kind = obligation_id.split("-", 1)[0]
                decision = review["classification"][kind]
                reason = decision["reason"] + suffix
                if obligation_id in module.reviewed_declarations(object_id):
                    reason = (
                        "The owned implementation requires this explicit "
                        "boundary; the declaration does not claim execution "
                        "correctness."
                    )
                rebuilt[obligation_id] = {
                    "reason": reason,
                    "evidence": [
                        {"path": path, "sha256": files[path]}
                        for path in decision["evidence_paths"]
                    ],
                    "declaration": deepcopy(declaration),
                }
            row["obligations"] = rebuilt
    for row in rows.values():
        for kind in set(registry) - {"OBJECT"} - set(row["classification"]):
            row["classification"][kind] = {
                "status": "UNRESOLVED",
                "reason": (
                    "Migration retains this applicability question. Static "
                    "ownership alone cannot refute a " + kind + " role."
                ),
                "evidence": [],
            }


def test_migration_selects_and_preserves_bounded_package_transport(
    tmp_path, monkeypatch
):
    module, document = _migration_fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(module.tier_zero_manifest, "MAX_EXTENDED_MANIFEST_BYTES", 1)
    migrated = module.migrate(tmp_path, document)
    assert migrated["schema_version"] == package_manifest.PACKAGE_REPRESENTATION_SCHEMA
    assert migrated["representation_updates"] == []
    repeated = module.migrate(tmp_path, migrated)
    assert repeated["schema_version"] == package_manifest.PACKAGE_REPRESENTATION_SCHEMA
    assert repeated == migrated


def test_migration_upgrades_exact_pre_applicability_registry_digest(
    tmp_path, monkeypatch
):
    module, document = _migration_fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(module.tier_zero_manifest, "MAX_EXTENDED_MANIFEST_BYTES", 1)
    previous = module.migrate(tmp_path, document)
    previous["namespace"]["registry_digest"] = (
        _pre_applicability_registry_digest()
    )

    migrated = module.migrate(tmp_path, previous)

    assert migrated["namespace"]["registry_digest"] == registry_document(
        namespace_registry()
    )["digest"]
    package_manifest.validate_bridge(migrated)


@pytest.mark.parametrize("legacy_carried", [False, True])
def test_explicit_semantic_install_accepts_exact_pending_catalog_predecessor(
    tmp_path, monkeypatch, legacy_carried
):
    module, previous, pending, pending_paths, validation_calls = (
        _pending_semantic_install_predecessor(
            tmp_path, monkeypatch, legacy_carried=legacy_carried
        )
    )

    migrated = module.migrate(
        tmp_path, previous, install_semantic_ownership=True
    )

    rows = {
        row["object_id"]: row for row in migrated["namespace"]["objects"]
    }
    graph = next(row for row in rows.values() if row["kind"] == "GRAPH")
    assert validation_calls == [tmp_path, tmp_path]
    assert _PENDING_SEMANTIC_INSTALL_IDS <= set(graph["operands"]["members"])
    for spec in pending:
        assert set(rows[spec.object_id]["surfaces"]) == {
            "file:" + path for path in spec.owned_paths
        }
    for path in pending_paths:
        owners = [
            object_id
            for object_id, row in rows.items()
            if "file:" + path in row["surfaces"]
        ]
        expected = next(
            spec.object_id for spec in pending if path in spec.owned_paths
        )
        assert owners == [expected]


@pytest.mark.parametrize(
    "legacy_carried,code",
    [
        (
            False,
            "PACKAGE_MIGRATION_PREDECESSOR_SURFACES_DIFFER:vstd-package-object",
        ),
        (True, "PACKAGE_MIGRATION_SEMANTIC_OWNERSHIP_PARTIAL"),
    ],
)
def test_pending_semantic_catalog_predecessor_still_requires_explicit_selector(
    tmp_path, monkeypatch, legacy_carried, code
):
    module, previous, _, _, validation_calls = (
        _pending_semantic_install_predecessor(
            tmp_path, monkeypatch, legacy_carried=legacy_carried
        )
    )

    with pytest.raises(ValueError, match=code):
        module.migrate(tmp_path, previous)
    assert validation_calls == []


def test_pending_semantic_install_does_not_mask_unrelated_surface_deletion(
    tmp_path, monkeypatch
):
    module, previous, _, _, _ = _pending_semantic_install_predecessor(
        tmp_path, monkeypatch, legacy_carried=True
    )
    manifest_write = _namespace_row(previous, "vstd-manifest-write")
    manifest_write["surfaces"].remove(
        "file:src/verifier/runtime/namespace_cli.py"
    )

    with pytest.raises(
        ValueError,
        match=(
            "PACKAGE_MIGRATION_PREDECESSOR_SURFACES_DIFFER:"
            "vstd-manifest-write"
        ),
    ):
        module.migrate(
            tmp_path, previous, install_semantic_ownership=True
        )


def test_selected_manifest_review_upgrades_exact_named_manifest_metadata_once(
    tmp_path, monkeypatch
):
    module, previous, current_metadata = _manifest_write_named_metadata_predecessor(
        tmp_path, monkeypatch
    )
    original_kind_calls = _stub_selected_package_reviews(module, monkeypatch)

    migrated = module.migrate(
        tmp_path,
        previous,
        refresh_reviewed=True,
        select_package_namespace_review=True,
    )

    row = _namespace_row(migrated, "vstd-manifest-write")
    assert (row["payload"], row["reason"]) == current_metadata
    assert len(original_kind_calls) == 1
    assert original_kind_calls[0][0] == tmp_path
    assert module.migrate(
        tmp_path,
        migrated,
        refresh_reviewed=True,
        select_package_namespace_review=True,
    ) == migrated
    assert len(original_kind_calls) == 2


@pytest.mark.parametrize(
    "refresh_reviewed,select_package_namespace_review",
    [(False, False), (True, False), (False, True)],
)
def test_named_manifest_metadata_upgrade_requires_both_explicit_selections(
    tmp_path,
    monkeypatch,
    refresh_reviewed,
    select_package_namespace_review,
):
    module, previous, _ = _manifest_write_named_metadata_predecessor(
        tmp_path, monkeypatch
    )

    with pytest.raises(
        ValueError,
        match="PACKAGE_MIGRATION_PREDECESSOR_PAYLOAD_DIFFERS:vstd-manifest-write",
    ):
        module.migrate(
            tmp_path,
            previous,
            refresh_reviewed=refresh_reviewed,
            select_package_namespace_review=select_package_namespace_review,
        )


@pytest.mark.parametrize(
    "field,value,code",
    [
        (
            "payload",
            {"representation_role": "src/verifier/runtime/manifest_write_worker.py"},
            "PACKAGE_MIGRATION_PREDECESSOR_PAYLOAD_DIFFERS:vstd-manifest-write",
        ),
        (
            "reason",
            "A near-miss legacy rationale.",
            "PACKAGE_MIGRATION_PREDECESSOR_OBJECT_REASON_DIFFERS:vstd-manifest-write",
        ),
    ],
)
def test_selected_named_manifest_metadata_upgrade_refuses_near_miss_pair(
    tmp_path, monkeypatch, field, value, code
):
    module, previous, _ = _manifest_write_named_metadata_predecessor(
        tmp_path, monkeypatch
    )
    _namespace_row(previous, "vstd-manifest-write")[field] = value

    with pytest.raises(ValueError, match=code):
        module.migrate(
            tmp_path,
            previous,
            refresh_reviewed=True,
            select_package_namespace_review=True,
        )


def test_selected_named_manifest_metadata_upgrade_refuses_surface_mismatch(
    tmp_path, monkeypatch
):
    module, previous, _ = _manifest_write_named_metadata_predecessor(
        tmp_path, monkeypatch
    )
    _namespace_row(previous, "vstd-manifest-write")["surfaces"].remove(
        "file:src/verifier/runtime/manifest_write_worker.py"
    )

    with pytest.raises(
        ValueError,
        match="PACKAGE_MIGRATION_PREDECESSOR_SURFACES_DIFFER:vstd-manifest-write",
    ):
        module.migrate(
            tmp_path,
            previous,
            refresh_reviewed=True,
            select_package_namespace_review=True,
        )


def test_named_manifest_metadata_transition_does_not_apply_to_another_named_object(
    tmp_path, monkeypatch
):
    module, previous, _ = _manifest_write_named_metadata_predecessor(
        tmp_path, monkeypatch
    )
    ledger = _namespace_row(previous, "vstd-invocation-ledger")
    ledger["payload"] = deepcopy(_MANIFEST_WRITE_LEGACY_PAYLOAD)
    ledger["reason"] = _MANIFEST_WRITE_LEGACY_REASON

    with pytest.raises(
        ValueError,
        match="PACKAGE_MIGRATION_PREDECESSOR_PAYLOAD_DIFFERS:vstd-invocation-ledger",
    ):
        module.migrate(
            tmp_path,
            previous,
            refresh_reviewed=True,
            select_package_namespace_review=True,
        )


def test_selected_refresh_semantic_install_requires_a_genuine_catalog_row(
    tmp_path, monkeypatch
):
    module, document = _migration_fixture(tmp_path, monkeypatch)
    legacy_named = module.migrate(tmp_path, document)

    assert module.selected_refresh_options(legacy_named)[
        "install_semantic_ownership"
    ] is False

    invocation_spec = next(
        spec
        for spec in module.package_semantic_ownership.SEMANTIC_OWNERSHIP_SPECS
        if spec.object_id == "vstd-invocation-ledger"
    )
    invocation = _namespace_row(legacy_named, invocation_spec.object_id)
    invocation.update(
        kind=invocation_spec.primary_kind,
        specializations=list(invocation_spec.specializations),
        payload={"representation_role": invocation_spec.representation_role},
        reason=(
            invocation_spec.necessity_reason
            + " Boundary: "
            + invocation_spec.consequence_boundary
        ),
        operands={
            role: list(targets) for role, targets in invocation_spec.operands
        },
        surfaces=["file:" + path for path in invocation_spec.owned_paths],
    )
    assert module.selected_refresh_options(legacy_named)[
        "install_semantic_ownership"
    ] is True

    non_named_spec = next(
        spec
        for spec in module.package_semantic_ownership.SEMANTIC_OWNERSHIP_SPECS
        if spec.object_id not in {selection[0] for selection in module._NAMED.values()}
    )
    forged = deepcopy(_namespace_row(legacy_named, "vstd-manifest-write"))
    forged["object_id"] = non_named_spec.object_id
    forged["surfaces"] = []
    legacy_named["namespace"]["objects"] = [forged]
    assert module.selected_refresh_options(legacy_named)[
        "install_semantic_ownership"
    ] is False

    legacy_named["namespace"]["objects"] = [
        {
            "object_id": non_named_spec.object_id,
            "kind": non_named_spec.primary_kind,
            "specializations": list(non_named_spec.specializations),
            "payload": {"representation_role": non_named_spec.representation_role},
            "reason": (
                non_named_spec.necessity_reason
                + " Boundary: "
                + non_named_spec.consequence_boundary
            ),
            "operands": {
                role: list(targets) for role, targets in non_named_spec.operands
            },
            "surfaces": ["file:" + path for path in non_named_spec.owned_paths],
        }
    ]
    assert module.selected_refresh_options(legacy_named)[
        "install_semantic_ownership"
    ] is True


def test_selected_refresh_package_review_requires_genuine_reviewed_shape(
    tmp_path, monkeypatch
):
    module, document = _migration_fixture(tmp_path, monkeypatch)
    unreviewed = module.migrate(tmp_path, document)
    assert module.selected_refresh_options(unreviewed)[
        "select_package_namespace_review"
    ] is False

    live = json.loads((Path(__file__).parents[1] / "objects.vstd").read_bytes())
    reviewed = deepcopy(_namespace_row(live, "vstd-manifest-write"))
    graph = deepcopy(_namespace_row(live, "vstd-package-graph"))
    selected = {"namespace": {"objects": [reviewed, graph]}}
    assert module.selected_refresh_options(selected)[
        "select_package_namespace_review"
    ] is False

    dispatched = {}
    monkeypatch.setattr(
        module,
        "migrate",
        lambda root, document, **options: dispatched.update(options) or document,
    )
    with pytest.raises(
        ValueError, match="PACKAGE_MIGRATION_SOURCE_SEMANTIC_PROFILE_DIFFERS"
    ):
        module.refresh_selected_manifest(tmp_path, selected)
    assert dispatched == {}

    reviewed["classification"]["TRANSACTION"]["reason"] = (
        "Forged package-review rationale."
    )
    assert module.selected_refresh_options(selected)[
        "select_package_namespace_review"
    ] is False
    reviewed = deepcopy(_namespace_row(live, "vstd-manifest-write"))
    reviewed["classification"]["TRANSACTION"]["evidence"] = []
    selected["namespace"]["objects"] = [reviewed]
    assert module.selected_refresh_options(selected)[
        "select_package_namespace_review"
    ] is False

    zero_hash = "sha256:" + "0" * 64
    complete = []
    for review_module in module._PACKAGE_REVIEW_MODULES:
        for object_id, expected in review_module.review_document().items():
            row = {
                "object_id": object_id,
                "kind": expected["primary_kind"],
                "surfaces": ["file:" + path for path in expected["owned_paths"]],
                "classification": {
                    kind: {
                        "status": decision["status"],
                        "reason": decision["reason"],
                        "evidence": [
                            {"path": path, "sha256": zero_hash}
                            for path in decision["evidence_paths"]
                        ],
                    }
                    for kind, decision in expected["classification"].items()
                },
                "obligations": {},
            }
            for obligation_id, declaration in expected["declarations"].items():
                kind = obligation_id.split("-", 1)[0]
                row["obligations"][obligation_id] = {
                    "reason": "Exact selected package-review declaration.",
                    "evidence": [
                        {"path": path, "sha256": zero_hash}
                        for path in expected["classification"][kind]["evidence_paths"]
                    ],
                    "declaration": deepcopy(declaration),
                }
            complete.append(row)
    selected = {"namespace": {"objects": complete}}
    package_graph = _namespace_row(selected, "vstd-package-graph")
    package_graph["payload"] = {
        "source_semantic_profile": deepcopy(
            graph["payload"]["source_semantic_profile"]
        )
    }
    assert module.selected_refresh_options(selected)[
        "select_package_namespace_review"
    ] is False

    empty_body = {
        "schema_version": module.SOURCE_SEMANTIC_PROFILE_SCHEMA,
        "reason": "A nonempty reason cannot replace the selected binding topology.",
        "binding_sets": [],
        "records": [],
    }
    package_graph["payload"]["source_semantic_profile"] = {
        **empty_body,
        "digest": module.value_digest(empty_body),
    }
    assert module.selected_refresh_options(selected)[
        "select_package_namespace_review"
    ] is False

    evidence_paths = {
        reference["path"]
        for row in complete
        for collection in (row["classification"], row["obligations"])
        for binding in collection.values()
        for reference in binding["evidence"]
    }
    evidence_hashes = {}
    for path in evidence_paths:
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("# exact selected review evidence\n", encoding="utf-8")
        evidence_hashes[path] = module.bytes_digest(target.read_bytes())
    for row in complete:
        for collection in (row["classification"], row["obligations"]):
            for binding in collection.values():
                for reference in binding["evidence"]:
                    reference["sha256"] = evidence_hashes[reference["path"]]
    package_graph["payload"]["source_semantic_profile"] = (
        module.source_semantic_profile(
            tmp_path, {row["object_id"]: row for row in complete}
        )
    )
    assert module.selected_refresh_options(selected)[
        "select_package_namespace_review"
    ] is True

    changed_path = next(path for path in evidence_paths if path.endswith(".py"))
    (tmp_path / changed_path).write_text("changed = True\n", encoding="utf-8")
    with pytest.raises(
        ValueError,
        match="PACKAGE_MIGRATION_SOURCE_SEMANTICS_CHANGED:" + changed_path,
    ):
        module._validate_source_semantic_refresh(tmp_path, selected)
    dispatched.clear()
    with pytest.raises(
        ValueError,
        match="PACKAGE_MIGRATION_SOURCE_SEMANTICS_CHANGED:" + changed_path,
    ):
        module.refresh_selected_manifest(tmp_path, selected)
    assert dispatched == {}

    selected["namespace"]["objects"].pop()
    assert module.selected_refresh_options(selected)[
        "select_package_namespace_review"
    ] is False


def test_selected_source_profile_refresh_invokes_semantic_drift_gate(
    tmp_path, monkeypatch
):
    module, document = _migration_fixture(tmp_path, monkeypatch)
    previous = module.migrate(tmp_path, document)

    def refuse_unreviewed_reseal(root, predecessor):
        raise ValueError("PACKAGE_MIGRATION_SOURCE_SEMANTIC_REFRESH_GATE_CALLED")

    monkeypatch.setattr(
        module, "_validate_source_semantic_refresh", refuse_unreviewed_reseal
    )
    with pytest.raises(
        ValueError, match="PACKAGE_MIGRATION_SOURCE_SEMANTIC_REFRESH_GATE_CALLED"
    ):
        module.migrate(
            tmp_path,
            previous,
            select_source_semantic_profile=True,
        )

def test_registry_upgrade_preserves_full_non_object_classification_denominator(
    tmp_path, monkeypatch
):
    module, document = _migration_fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(module.tier_zero_manifest, "MAX_EXTENDED_MANIFEST_BYTES", 1)
    previous = module.migrate(tmp_path, document)
    full_denominator = set(namespace_registry()) - {"OBJECT"}
    assert len(full_denominator) == 37
    for row in previous["namespace"]["objects"]:
        for kind in full_denominator - set(row["classification"]):
            row["classification"][kind] = {
                "status": "UNRESOLVED",
                "reason": (
                    "Migration retains this applicability question. Static "
                    "ownership alone cannot refute a " + kind + " role."
                ),
                "evidence": [],
            }
    previous["namespace"]["registry_digest"] = (
        _pre_applicability_registry_digest()
    )

    migrated = module.migrate(tmp_path, previous)

    assert all(
        set(row["classification"]) == full_denominator
        for row in migrated["namespace"]["objects"]
    )


def test_migration_upgrades_exact_pre_applicability_tier_zero_profile(
    tmp_path, monkeypatch
):
    module, document = _migration_fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(module.tier_zero_manifest, "MAX_EXTENDED_MANIFEST_BYTES", 1)
    previous = module.migrate(tmp_path, document)
    previous["profile_digest"] = (
        _pre_applicability_tier_zero_profile_digest()
    )

    migrated = module.migrate(tmp_path, previous)

    assert migrated["profile_digest"] == (
        tier_zero_profile.installed_tier_zero_profile()["profile_digest"]
    )
    module.tier_zero_manifest.validate_manifest(
        package_manifest.retained_contract(migrated),
        expected_repository=migrated["repository"]["remote"],
        expected_revision=migrated["repository"]["revision"],
    )


@pytest.mark.parametrize(
    "mutate,code",
    [
        (
            lambda document: document.update(
                profile_digest="sha256:" + "0" * 64
            ),
            "TIER_ZERO_MANIFEST_PROFILE_DIFFERS",
        ),
        (
            lambda document: document.update(
                claim_boundary="A forged claim boundary."
            ),
            "TIER_ZERO_MANIFEST_PROFILE_DIFFERS",
        ),
        (
            lambda document: document["obligation_denominator"].update(
                route_count=407
            ),
            "TIER_ZERO_OBLIGATION_DENOMINATOR_DIFFERS",
        ),
    ],
)
def test_profile_upgrade_refuses_unrecognized_digest_and_unrelated_damage(
    tmp_path, monkeypatch, mutate, code
):
    module, document = _migration_fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(module.tier_zero_manifest, "MAX_EXTENDED_MANIFEST_BYTES", 1)
    previous = module.migrate(tmp_path, document)
    previous["profile_digest"] = (
        _pre_applicability_tier_zero_profile_digest()
    )
    mutate(previous)

    with pytest.raises(ValueError, match=code):
        module.migrate(tmp_path, previous)


@pytest.mark.parametrize(
    "mutate,code",
    [
        (
            lambda document: document["namespace"].update(
                registry_digest="sha256:" + "0" * 64
            ),
            "NAMESPACE_REGISTRY_DIGEST_DIFFERS",
        ),
        (
            lambda document: document["namespace"]["objects"][0].update(
                kind="FORGED"
            ),
            "NAMESPACE_KIND_UNREGISTERED",
        ),
        (
            lambda document: document["namespace"]["objects"][0].pop("reason"),
            "NAMESPACE_OBJECT_FIELDS",
        ),
        (
            _add_forged_extension,
            "PACKAGE_MIGRATION_CUSTOM_EXTENSIONS_REQUIRE_EXPLICIT_MERGE",
        ),
        (
            _mutate_invocation_ledger_kind,
            "PACKAGE_MIGRATION_PREDECESSOR_PRIMARY_KIND_DIFFERS",
        ),
        (
            _add_invocation_ledger_robot_role,
            "PACKAGE_MIGRATION_PREDECESSOR_SPECIALIZATIONS_DIFFER",
        ),
        (
            _add_forged_obligation_identity,
            "PACKAGE_MIGRATION_PREDECESSOR_OBLIGATION_IDENTITIES_DIFFER",
        ),
        (
            _mutate_invocation_ledger_classification_reason,
            "PACKAGE_MIGRATION_PREDECESSOR_CLASSIFICATION_DIFFERS",
        ),
        (
            _mutate_invocation_ledger_classification_status,
            "PACKAGE_MIGRATION_PREDECESSOR_CLASSIFICATION_DIFFERS",
        ),
        (
            _mutate_invocation_ledger_obligation_reason,
            "PACKAGE_MIGRATION_PREDECESSOR_OBLIGATION_REASON_DIFFERS",
        ),
        (
            _mutate_invocation_ledger_declaration_value,
            "PACKAGE_MIGRATION_PREDECESSOR_DECLARATION_VALUES_DIFFER",
        ),
        (
            lambda document: next(
                row
                for row in document["namespace"]["objects"]
                if row["kind"] == "GRAPH"
            )["operands"]["members"].pop(),
            "PACKAGE_NAMESPACE_GRAPH_NOT_COMPLETE",
        ),
    ],
)
def test_registry_upgrade_refuses_unrecognized_digest_and_forged_bridge(
    tmp_path, monkeypatch, mutate, code
):
    module, document = _migration_fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(module.tier_zero_manifest, "MAX_EXTENDED_MANIFEST_BYTES", 1)
    previous = module.migrate(tmp_path, document)
    previous["namespace"]["registry_digest"] = (
        _pre_applicability_registry_digest()
    )
    mutate(previous)

    with pytest.raises(ValueError, match=code):
        module.migrate(tmp_path, previous)


@pytest.mark.parametrize(
    "mutate,code",
    [
        (_mutate_semantic_payload, "PACKAGE_MIGRATION_PREDECESSOR_PAYLOAD_DIFFERS"),
        (
            _mutate_semantic_object_reason,
            "PACKAGE_MIGRATION_PREDECESSOR_OBJECT_REASON_DIFFERS",
        ),
        (_add_semantic_surface, "PACKAGE_MIGRATION_PREDECESSOR_SURFACES_DIFFER"),
        (
            _mutate_semantic_classification_evidence_path,
            "PACKAGE_MIGRATION_PREDECESSOR_CLASSIFICATION_EVIDENCE_PATHS_DIFFER",
        ),
        (
            _mutate_semantic_obligation_evidence_path,
            "PACKAGE_MIGRATION_PREDECESSOR_OBLIGATION_EVIDENCE_PATHS_DIFFER",
        ),
    ],
)
def test_registry_upgrade_binds_full_non_named_semantic_row(
    tmp_path, monkeypatch, mutate, code
):
    module, document = _migration_fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(module.tier_zero_manifest, "MAX_EXTENDED_MANIFEST_BYTES", 1)
    previous = module.migrate(tmp_path, document)
    previous["namespace"]["registry_digest"] = (
        _pre_applicability_registry_digest()
    )
    _add_accelerator_semantic_row(module, previous)
    mutate(previous)

    with pytest.raises(ValueError, match=code):
        module.migrate(tmp_path, previous, refresh_reviewed=True)


@pytest.mark.parametrize(
    "mutate,code",
    [
        (
            lambda document: _namespace_row(document, "vstd-human").update(
                reason="Forged retained object reason."
            ),
            "PACKAGE_MIGRATION_PREDECESSOR_OBJECT_REASON_DIFFERS:vstd-human",
        ),
        (
            lambda document: _namespace_row(document, "vstd-human").update(
                surfaces=["file:forged.py"]
            ),
            "PACKAGE_MIGRATION_PREDECESSOR_SURFACES_DIFFER:vstd-human",
        ),
    ],
)
def test_registry_upgrade_binds_retained_object_reason_and_surface_denominator(
    tmp_path, monkeypatch, mutate, code
):
    module, document = _migration_fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(module.tier_zero_manifest, "MAX_EXTENDED_MANIFEST_BYTES", 1)
    previous = module.migrate(tmp_path, document)
    previous["namespace"]["registry_digest"] = (
        _pre_applicability_registry_digest()
    )
    mutate(previous)

    with pytest.raises(ValueError, match=code):
        module.migrate(tmp_path, previous)


def test_registry_upgrade_rejects_named_source_denominator_erasure(
    tmp_path, monkeypatch
):
    module, document = _migration_fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(module.tier_zero_manifest, "MAX_EXTENDED_MANIFEST_BYTES", 1)
    previous = module.migrate(tmp_path, document)
    previous["namespace"]["registry_digest"] = (
        _pre_applicability_registry_digest()
    )
    row = _namespace_row(previous, "vstd-manifest-write")
    row["surfaces"] = []

    with pytest.raises(
        ValueError,
        match="PACKAGE_MIGRATION_PREDECESSOR_SURFACES_DIFFER:vstd-manifest-write",
    ):
        module.migrate(tmp_path, previous)


def test_registry_upgrade_rejects_named_source_evidence_erasure(
    tmp_path, monkeypatch
):
    module, document = _migration_fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(module.tier_zero_manifest, "MAX_EXTENDED_MANIFEST_BYTES", 1)
    previous = module.migrate(tmp_path, document)
    previous["namespace"]["registry_digest"] = (
        _pre_applicability_registry_digest()
    )
    row = _namespace_row(previous, "vstd-manifest-write")
    for decision in row["classification"].values():
        decision["evidence"] = []
    for binding in row["obligations"].values():
        binding["evidence"] = []

    with pytest.raises(
        ValueError,
        match=(
            "PACKAGE_MIGRATION_PREDECESSOR_"
            "OBLIGATION_EVIDENCE_PATHS_DIFFER:vstd-manifest-write:"
            "TRANSACTION-0.1-effects-and-authority"
        ),
    ):
        module.migrate(tmp_path, previous)


def test_registry_upgrade_rejects_coordinated_retained_payload_replacement(
    tmp_path, monkeypatch
):
    from verifier.core.namespace import NamespaceObject
    from verifier.runtime.namespace_contracts import ancestors

    module, document = _migration_fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(module.tier_zero_manifest, "MAX_EXTENDED_MANIFEST_BYTES", 1)
    previous = module.migrate(tmp_path, document)
    previous["namespace"]["registry_digest"] = (
        _pre_applicability_registry_digest()
    )
    retained = {
        item.object_id: item
        for item in module.tier_zero_manifest._namespace_objects(
            previous["objects"]
        )
    }
    registry = namespace_registry()
    updates = []
    for object_id, role in (
        ("vstd-human", "Forged retained human representation."),
        ("vstd-package-graph", "Forged retained graph representation."),
    ):
        row = _namespace_row(previous, object_id)
        row["payload"]["representation_role"] = role
        base = ancestors(registry, row["kind"])[-1]
        payload = deepcopy(row["payload"])
        if base == "GRAPH":
            payload["element_kind"] = ancestors(
                registry, payload["element_kind"]
            )[-1]
        current = NamespaceObject.create(
            object_id, base, payload, row["operands"]
        )
        updates.append(
            {
                "object_id": object_id,
                "retained_object_digest": retained[object_id].digest,
                "current_object_digest": current.digest,
                "reason": "Forged but structurally valid representation transition.",
                "evidence": [],
            }
        )
    previous["representation_updates"] = updates

    with pytest.raises(
        ValueError,
        match="PACKAGE_MIGRATION_PREDECESSOR_PAYLOAD_DIFFERS:vstd-human",
    ):
        module.migrate(tmp_path, previous)


@pytest.mark.parametrize(
    "rollback",
    [
        "decision-only",
        "decision-and-role",
        "complete",
        "complete-and-profile-rewrite",
    ],
)
def test_mature_registry_upgrade_rejects_reviewed_policy_rollback(
    tmp_path, monkeypatch, rollback
):
    from verifier.core.namespace import NamespaceObject

    module, document = _migration_fixture(tmp_path, monkeypatch)
    spec = next(
        item
        for item in module.package_semantic_ownership.SEMANTIC_OWNERSHIP_SPECS
        if item.object_id == "vstd-accelerator-discovery-command"
    )
    human_review = module.package_original_review_people.review_document()[
        "vstd-human"
    ]
    policy_review = human_review["classification"]["POLICY"]
    already_discovered = {
        "src/verifier/runtime/polish_invocation_ledger.py",
        "src/verifier/runtime/namespace_cli.py",
        "src/verifier/domains/contracts/graph_statics.py",
    }
    review_paths = sorted(
        {
            path
            for review_module in module._PACKAGE_REVIEW_MODULES
            for review in review_module.review_document().values()
            for decision in review["classification"].values()
            for path in decision["evidence_paths"]
        }
        - already_discovered
    )
    # Reviews that cite a VERIFIER-core module activate the exact core census, which
    # refuses a partial core, so the fixture carries the complete core denominator.
    review_paths = sorted(
        set(review_paths)
        | set(module._VERIFIER_CORE_PATHS)
        | set(module._CORE_SEMANTIC_PATHS)
        | {path for path in module._HARNESS_PATHS if path.startswith("src/verifier/core/")}
    )
    observed = _add_discovered_files(
        tmp_path, monkeypatch, review_paths
    )
    monkeypatch.setattr(module.tier_zero_manifest, "MAX_EXTENDED_MANIFEST_BYTES", 1)
    previous = module.migrate(tmp_path, document)
    _add_accelerator_semantic_row(module, previous)
    for row in previous["namespace"]["objects"]:
        if row["object_id"] == spec.object_id:
            continue
        row["surfaces"] = [
            surface
            for surface in row["surfaces"]
            if surface.removeprefix("file:") not in spec.owned_paths
        ]
    monkeypatch.setattr(
        module.package_semantic_ownership,
        "SEMANTIC_OWNERSHIP_SPECS",
        (spec,),
    )
    monkeypatch.setattr(
        module.package_semantic_ownership,
        "validate_catalog",
        lambda root: (spec,),
    )
    previous = _enriched_package_graph_adapter_basis(
        module, tmp_path, monkeypatch, previous
    )
    files = {
        row["path"]: row["sha256"]
        for row in module.namespace_discovery.discover(tmp_path)["census"]["files"]
    }
    # The synthetic ownership handoff above changes the predecessor's exact
    # source denominator. Keep each original primary-role decision bound to
    # the same accepted surfaces so this rollback test reaches the reviewed
    # POLICY lifecycle it is intended to exercise.
    registry = namespace_registry()
    for row in previous["namespace"]["objects"]:
        primary = row["kind"]
        if primary == "OBJECT" or registry[primary].extends is not None:
            continue
        decision = row["classification"][primary]
        decision["evidence"] = [
            {"path": path, "sha256": files[path]}
            for path in sorted(
                surface.removeprefix("file:")
                for surface in row["surfaces"]
                if surface.startswith("file:")
            )
        ]
    _apply_complete_source_review_predecessor(module, previous, files)
    human = _namespace_row(previous, "vstd-human")
    evidence = [
        {"path": path, "sha256": files[path]}
        for path in policy_review["evidence_paths"]
    ]
    graph = _namespace_row(previous, "vstd-package-graph")
    graph_only_profile = deepcopy(graph["payload"]["source_semantic_profile"])
    graph_binding = [
        {
            "object_id": graph["object_id"],
            "classifications": ["GRAPH"],
            "obligations": ["GRAPH-3.1-directed-graph"],
        }
    ]
    policy_binding = [
        {
            "object_id": human["object_id"],
            "classifications": ["POLICY"],
            "obligations": sorted(
                key for key in human["obligations"] if key.startswith("POLICY-")
            ),
        }
    ]
    bindings = sorted(
        (graph_binding, policy_binding), key=module.value_digest
    )
    binding_sets = [
        module.canonical_bytes(binding).decode("utf-8")
        for binding in bindings
    ]
    binding_indexes = {
        module.value_digest(binding): index
        for index, binding in enumerate(bindings)
    }
    graph_source = "src/verifier/domains/contracts/graph_statics.py"
    records = [
        graph_source
        + "\tpython-location-free-ast\t"
        + "sha256:"
        + "b" * 64
        + "\t"
        + str(binding_indexes[module.value_digest(graph_binding)])
    ]
    records.extend(
        path
        + "\tpython-location-free-ast\t"
        + files[path]
        + "\t"
        + str(binding_indexes[module.value_digest(policy_binding)])
        for path in policy_review["evidence_paths"]
    )
    profile_body = {
        "schema_version": "verifier-source-semantic-review-profile-1",
        "reason": "Synthetic mature reviewed-role lifecycle binding.",
        "binding_sets": binding_sets,
        "records": sorted(records),
    }
    graph["payload"]["source_semantic_profile"] = {
        **profile_body,
        "digest": module.value_digest(profile_body),
    }
    update = previous["representation_updates"][0]
    update["current_object_digest"] = NamespaceObject.create(
        graph["object_id"], "GRAPH", graph["payload"], graph["operands"]
    ).digest
    previous["namespace"]["registry_digest"] = (
        _pre_applicability_registry_digest()
    )
    # Establish that the fully reviewed mature predecessor itself is admitted.
    module.migrate(tmp_path, deepcopy(previous), refresh_reviewed=True)

    human["classification"]["POLICY"] = {
        "status": "UNRESOLVED",
        "reason": (
            "Migration retains this applicability question. Static ownership "
            "alone cannot refute a POLICY role."
        ),
        "evidence": [],
    }
    if rollback in {
        "decision-and-role",
        "complete",
        "complete-and-profile-rewrite",
    }:
        human["specializations"].remove("POLICY")
    if rollback in {"complete", "complete-and-profile-rewrite"}:
        for obligation_id in [
            key for key in human["obligations"] if key.startswith("POLICY-")
        ]:
            del human["obligations"][obligation_id]
    if rollback == "complete-and-profile-rewrite":
        graph["payload"]["source_semantic_profile"] = graph_only_profile
        update["current_object_digest"] = NamespaceObject.create(
            graph["object_id"], "GRAPH", graph["payload"], graph["operands"]
        ).digest

    with pytest.raises(
        ValueError,
        match="PACKAGE_MIGRATION_PREDECESSOR_CLASSIFICATION_DIFFERS:vstd-human:POLICY",
    ):
        module.migrate(tmp_path, previous, refresh_reviewed=True)


def _harness_transition_rows():
    annotation = {
        "necessity_reason": "The exact reviewed launch is necessary.",
        "observation_disposition": "SOURCE_ENUMERATION_ONLY",
        "unobserved_gaps": ["reachability"],
    }
    coordinate = {
        "launch_id": "runner.py|scope=<module>|callee=subprocess.run|ordinal=1",
        "path": "runner.py",
        "embedded_name": None,
        "source_kind": "python-file",
        "scope": "<module>",
        "callee": "subprocess.run",
        "ordinal": 1,
        "line": 1,
        "source_sha256": "sha256:" + "1" * 64,
        "source_ast_sha256": "sha256:" + "2" * 64,
        "call_sha256": "sha256:" + "3" * 64,
    }
    prior = {**coordinate, **annotation}
    catalog = {key: value for key, value in prior.items() if key != "source_ast_sha256"}
    observed = {key: value for key, value in coordinate.items()}
    refreshed = {**observed, **annotation}
    return [prior], [catalog], [observed], [refreshed]


def test_harness_review_transition_accepts_only_its_exact_four_coordinates(
    monkeypatch,
):
    module = migration_module
    prior, catalog, observed, refreshed = _harness_transition_rows()
    monkeypatch.setattr(
        module,
        "_PACKAGE_HARNESS_REVIEW_TRANSITION",
        {
            "prior": module.value_digest(prior),
            "catalog": module.value_digest(catalog),
            "observed": module.value_digest(observed),
            "refreshed": module.value_digest(refreshed),
        },
    )

    assert module._is_exact_harness_review_transition(
        prior, catalog, {"status": "PASS", "launches": observed}
    )


@pytest.mark.parametrize(
    "target,field,value",
    [
        ("prior", "path", "forged.py"),
        ("prior", "launch_id", "forged-id"),
        ("prior", "source_sha256", "sha256:" + "f" * 64),
        ("prior", "observation_disposition", "PARENT_INTERFACE_OBSERVED"),
        ("catalog", "necessity_reason", "Forged review classification."),
        ("observed", "call_sha256", "sha256:" + "e" * 64),
    ],
)
def test_harness_review_transition_rejects_every_near_miss(
    monkeypatch, target, field, value
):
    module = migration_module
    prior, catalog, observed, refreshed = _harness_transition_rows()
    monkeypatch.setattr(
        module,
        "_PACKAGE_HARNESS_REVIEW_TRANSITION",
        {
            "prior": module.value_digest(prior),
            "catalog": module.value_digest(catalog),
            "observed": module.value_digest(observed),
            "refreshed": module.value_digest(refreshed),
        },
    )
    selected = {"prior": prior, "catalog": catalog, "observed": observed}[target]
    selected[0][field] = value

    assert not module._is_exact_harness_review_transition(
        prior, catalog, {"status": "PASS", "launches": observed}
    )


def test_migration_selects_package_transport_for_the_structure_ceiling(
    tmp_path, monkeypatch
):
    module, document = _migration_fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(module.namespace_manifest, "MAX_NAMESPACE_NODES", 1)
    migrated = module.migrate(tmp_path, document)
    assert migrated["schema_version"] == package_manifest.PACKAGE_REPRESENTATION_SCHEMA
    assert migrated["representation_updates"] == []


def test_migration_refuses_above_the_package_structure_ceiling(
    tmp_path, monkeypatch
):
    module, document = _migration_fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(module.namespace_manifest, "MAX_PACKAGE_NAMESPACE_NODES", 1)
    with pytest.raises(
        ValueError,
        match="PACKAGE_MIGRATION_MANIFEST_STRUCTURE_CAPACITY_EXHAUSTED",
    ):
        module.migrate(tmp_path, document)


def test_migration_recounts_structure_after_package_transport_fields(
    tmp_path, monkeypatch
):
    module, document = _migration_fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(module.tier_zero_manifest, "MAX_EXTENDED_MANIFEST_BYTES", 1)
    migrated = module.migrate(tmp_path, document)
    final_nodes = module.namespace_manifest.structure_node_count(migrated)
    assert migrated["schema_version"] == package_manifest.PACKAGE_REPRESENTATION_SCHEMA
    monkeypatch.setattr(
        module.namespace_manifest,
        "MAX_PACKAGE_NAMESPACE_NODES",
        final_nodes - 1,
    )
    with pytest.raises(
        ValueError,
        match="PACKAGE_MIGRATION_MANIFEST_STRUCTURE_CAPACITY_EXHAUSTED",
    ):
        module.migrate(tmp_path, document)


def test_migration_uses_compact_v6_only_as_exact_namespace_transport(
    tmp_path, monkeypatch
):
    module, document = _migration_fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(module.tier_zero_manifest, "MAX_EXTENDED_MANIFEST_BYTES", 1)
    canonical = module.canonical_bytes

    def force_inline_package_over_transport_limit(value):
        encoded = canonical(value)
        if (
            type(value) is dict
            and value.get("schema_version")
            == package_manifest.PACKAGE_REPRESENTATION_SCHEMA
            and value.get("namespace", {}).get("schema_version")
            == module.namespace_manifest.SCHEMA
        ):
            return encoded + b"x" * module.tier_zero_manifest.MAX_PACKAGE_MANIFEST_BYTES
        return encoded

    monkeypatch.setattr(module, "canonical_bytes", force_inline_package_over_transport_limit)
    migrated = module.migrate(tmp_path, document)

    assert (
        migrated["schema_version"]
        == package_manifest.COMPACT_PACKAGE_REPRESENTATION_SCHEMA
    )
    assert (
        migrated["namespace"]["schema_version"]
        == module.namespace_manifest.COMPACT_SCHEMA
    )
    expanded = module.namespace_manifest.normalize_manifest(migrated["namespace"])
    assert expanded["schema_version"] == module.namespace_manifest.SCHEMA
    assert module.namespace_manifest.compact_manifest(expanded) == migrated["namespace"]
    package_manifest.select(
        migrated,
        repository=migrated["repository"]["remote"],
        revision=migrated["repository"]["revision"],
    )


def test_migration_prefers_smaller_compact_transport_above_extended_envelope(
    tmp_path, monkeypatch
):
    module, document = _migration_fixture(tmp_path, monkeypatch)
    canonical = module.canonical_bytes

    def model_large_inline_package(value):
        encoded = canonical(value)
        if (
            type(value) is dict
            and value.get("schema_version")
            in {
                package_manifest.SCHEMA,
                package_manifest.PACKAGE_REPRESENTATION_SCHEMA,
            }
            and value.get("namespace", {}).get("schema_version")
            == module.namespace_manifest.SCHEMA
        ):
            return encoded + b"x" * (
                module._COMPACT_TRANSPORT_PREFERRED_BYTES + 1
            )
        return encoded

    monkeypatch.setattr(module, "canonical_bytes", model_large_inline_package)
    migrated = module.migrate(tmp_path, document)

    assert (
        migrated["schema_version"]
        == package_manifest.COMPACT_PACKAGE_REPRESENTATION_SCHEMA
    )
    assert module.namespace_manifest.normalize_manifest(
        migrated["namespace"]
    )["schema_version"] == module.namespace_manifest.SCHEMA


def test_migration_refuses_a_package_graph_above_its_finite_transport_bound(
    tmp_path, monkeypatch
):
    module, document = _migration_fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(
        module.tier_zero_manifest,
        "validate_manifest",
        lambda *args, **kwargs: {"status": "PASS"},
    )
    monkeypatch.setattr(module.tier_zero_manifest, "MAX_EXTENDED_MANIFEST_BYTES", 1)
    monkeypatch.setattr(module.tier_zero_manifest, "MAX_PACKAGE_MANIFEST_BYTES", 1)
    with pytest.raises(ValueError, match="PACKAGE_MIGRATION_MANIFEST_CAPACITY_EXHAUSTED"):
        module.migrate(tmp_path, document)


def test_migration_routes_only_the_reviewed_harness_set_to_one_existing_owner(
    tmp_path, monkeypatch
):
    module, document = _migration_fixture(tmp_path, monkeypatch)
    public_cli = "src/verifier/runtime/public_cli.py"
    openshell_paths = (
        "extensions/openshell/pyproject.toml",
        "extensions/openshell/src/vstd_openshell/__init__.py",
        "extensions/openshell/src/vstd_openshell/environment.py",
        "extensions/openshell/src/vstd_openshell/live.py",
    )
    _add_discovered_files(
        tmp_path,
        monkeypatch,
        (
            *_REVIEWED_HARNESS_PATHS,
            *module._CORE_SEMANTIC_PATHS,
            public_cli,
            *openshell_paths,
        ),
    )

    migrated = module.migrate(tmp_path, document)
    owners = {}
    for row in migrated["namespace"]["objects"]:
        for surface in row["surfaces"]:
            owners.setdefault(surface, []).append((row["object_id"], row["kind"]))

    for path in _REVIEWED_HARNESS_PATHS:
        assert owners["file:" + path] == [("vstd-harness", "HARNESS")]
    for path in module._VERIFIER_CORE_PATHS:
        assert owners["file:" + path] == [("verifier-core-self", "VERIFIER")]
    for path in module._CORE_SEMANTIC_PATHS:
        assert owners["file:" + path] == [("verifier-core-self", "VERIFIER")]
    assert owners["file:" + public_cli] == [("verifier-core-self", "VERIFIER")]
    for path in openshell_paths:
        assert owners["file:" + path] == [("vstd-package-object", "OBJECT")]
    assert (
        sum(
            row["object_id"] == "vstd-harness"
            for row in migrated["namespace"]["objects"]
        )
        == 1
    )


def test_real_core_denominator_refuses_an_unreviewed_partial_inventory(
    tmp_path, monkeypatch
):
    module, document = _migration_fixture(tmp_path, monkeypatch)
    _add_discovered_files(tmp_path, monkeypatch, (module._VERIFIER_CORE_PATHS[0],))
    with pytest.raises(ValueError, match="CORE_OWNERSHIP_DENOMINATOR_DIFFERS"):
        module.migrate(tmp_path, document)


def test_migration_routes_reviewed_domain_implementations_to_existing_named_objects(
    tmp_path, monkeypatch
):
    """A domain implementation must not disappear into the generic OBJECT row."""
    module, document = _migration_fixture(tmp_path, monkeypatch)
    generic = "src/verifier/domains/common.py"
    _add_discovered_files(tmp_path, monkeypatch, (*_REVIEWED_DOMAIN_OWNERS, generic))

    migrated = module.migrate(tmp_path, document)
    owners = {}
    for row in migrated["namespace"]["objects"]:
        for surface in row["surfaces"]:
            owners.setdefault(surface, []).append((row["object_id"], row["kind"]))
    by_kind = {
        row["kind"]: row["object_id"] for row in migrated["namespace"]["objects"]
    }

    for path, kind in _REVIEWED_DOMAIN_OWNERS.items():
        assert owners["file:" + path] == [(by_kind[kind], kind)]
    assert owners["file:" + generic] == [(by_kind["OBJECT"], "OBJECT")]


def test_domain_reownership_moves_only_unanswered_candidate_evidence(
    tmp_path, monkeypatch
):
    """A newly corrected owner receives the still-open question and its bytes."""
    module, document = _migration_fixture(tmp_path, monkeypatch)
    path = "src/verifier/domains/actor.py"
    observed = _add_discovered_files(tmp_path, monkeypatch, (path,))
    previous = module.migrate(tmp_path, document)
    rows = {row["object_id"]: row for row in previous["namespace"]["objects"]}
    actor, generic = rows["vstd-actor"], rows["vstd-package-object"]
    surface = "file:" + path
    reference = next(row for row in observed["census"]["files"] if row["path"] == path)

    # Recreate the old coarse ownership coordinate.  Only a blank, unresolved
    # candidate may move automatically; reviewed answers require a new review.
    actor["surfaces"].remove(surface)
    generic["surfaces"].append(surface)
    generic["classification"]["TRANSACTION"]["evidence"] = [deepcopy(reference)]
    generic["obligations"]["TRANSACTION-0.1-effects-and-authority"] = {
        "reason": "",
        "evidence": [deepcopy(reference)],
        "declaration": {
            name: ""
            for name in ("effects", "preconditions", "authorization", "resources")
        },
    }

    updated = module.migrate(tmp_path, previous)
    after = {row["object_id"]: row for row in updated["namespace"]["objects"]}
    assert (
        after["vstd-package-object"]["classification"]["TRANSACTION"]["evidence"] == []
    )
    assert after["vstd-actor"]["classification"]["TRANSACTION"]["evidence"] == [
        reference
    ]
    assert (
        after["vstd-package-object"]["obligations"][
            "TRANSACTION-0.1-effects-and-authority"
        ]["evidence"]
        == []
    )
    assert after["vstd-actor"]["obligations"]["TRANSACTION-0.1-effects-and-authority"][
        "evidence"
    ] == [reference]


def test_semantic_ownership_install_adds_exact_child_and_is_then_idempotent(
    tmp_path, monkeypatch
):
    from verifier.runtime.package_semantic_ownership import SemanticOwnershipSpec

    module, document = _migration_fixture(tmp_path, monkeypatch)
    path = "src/verifier/runtime/gate_pipeline.py"
    _add_discovered_files(tmp_path, monkeypatch, (path,))
    spec = SemanticOwnershipSpec(
        object_id="vstd-test-pipeline-controller",
        primary_kind="CONTROLLER",
        specializations=("ACTUATOR",),
        owned_paths=(path,),
        representation_role="Synthetic exact pipeline ownership fixture.",
        necessity_reason="The effect path must not remain under VERIFIER catch-all ownership.",
        consequence_boundary="Software process submission only; no physical or financial effect claim.",
    )
    monkeypatch.setattr(
        module.package_semantic_ownership,
        "validate_catalog",
        lambda root: (spec,),
    )
    monkeypatch.setattr(
        module.package_semantic_ownership,
        "SEMANTIC_OWNERSHIP_SPECS",
        (spec,),
    )

    migrated = module.migrate(tmp_path, document, install_semantic_ownership=True)
    rows = {row["object_id"]: row for row in migrated["namespace"]["objects"]}
    child = rows[spec.object_id]
    assert child["kind"] == "CONTROLLER"
    assert child["specializations"] == ["ACTUATOR"]
    assert child["surfaces"] == ["file:" + path]
    assert "software process submission" in child["reason"].lower()
    graph = next(row for row in rows.values() if row["kind"] == "GRAPH")
    assert spec.object_id in graph["operands"]["members"]
    assert "file:" + path not in rows["verifier-core-self"]["surfaces"]

    assert module.migrate(tmp_path, migrated) == migrated

    # A reviewed refresh of an already-installed semantic catalog must use the
    # same exact specialization rule as first installation.  A historical label
    # without a materialized independent review is not preserved merely because
    # the catalog was selected in an earlier migration.
    child["specializations"].append("SENSOR")

    from dataclasses import replace

    updated = replace(
        spec,
        necessity_reason=(
            "The reviewed controller has a changed source-owned necessity."
        ),
    )
    monkeypatch.setattr(
        module.package_semantic_ownership,
        "validate_catalog",
        lambda root: (updated,),
    )
    monkeypatch.setattr(
        module.package_semantic_ownership,
        "SEMANTIC_OWNERSHIP_SPECS",
        (updated,),
    )
    refreshed = module.migrate(tmp_path, migrated, refresh_reviewed=True)
    refreshed_child = next(
        row for row in refreshed["namespace"]["objects"]
        if row["object_id"] == updated.object_id
    )
    assert refreshed_child["reason"] == (
        updated.necessity_reason
        + " Boundary: "
        + updated.consequence_boundary
    )
    assert refreshed_child["specializations"] == ["ACTUATOR"]


def test_semantic_ownership_takes_over_named_group_under_same_id_once(
    tmp_path, monkeypatch
):
    from verifier.runtime import local_ledger_execution
    from verifier.runtime.package_semantic_ownership import SemanticOwnershipSpec

    module, document = _migration_fixture(tmp_path, monkeypatch)
    paths = tuple(
        sorted(
            path
            for path, selection in module._NAMED.items()
            if selection[0] == "vstd-invocation-ledger"
        )
    )
    observed = _add_discovered_files(
        tmp_path,
        monkeypatch,
        tuple(
            path
            for path in paths
            if path != "src/verifier/runtime/polish_invocation_ledger.py"
        ),
    )
    spec = SemanticOwnershipSpec(
        object_id="vstd-invocation-ledger",
        primary_kind="LEDGER",
        specializations=("POLICY", "PROTOCOL", "TRANSACTION"),
        owned_paths=paths,
        representation_role="Synthetic exact invocation-ledger transition.",
        necessity_reason="The stable ledger ID accumulates its consequential roles.",
        consequence_boundary="Bounded local nonmonetary fixture only.",
    )
    monkeypatch.setattr(
        module.package_semantic_ownership, "validate_catalog", lambda root: (spec,)
    )
    monkeypatch.setattr(
        module.package_semantic_ownership, "SEMANTIC_OWNERSHIP_SPECS", (spec,)
    )

    legacy = module.migrate(tmp_path, document)
    legacy_rows = [
        row
        for row in legacy["namespace"]["objects"]
        if row["object_id"] == spec.object_id
    ]
    assert len(legacy_rows) == 1
    assert legacy_rows[0]["specializations"] == ["TRANSACTION"]
    implementation = local_ledger_execution.IMPLEMENTATION
    reference = next(
        item for item in observed["census"]["files"] if item["path"] == implementation
    )
    selection = {
        "object_id": spec.object_id,
        "mechanism": local_ledger_execution.ADAPTER,
        "reason": "Retained exact local-ledger execution selection.",
        "evidence": [deepcopy(reference)],
    }
    legacy["namespace"]["execution_checks"] = [deepcopy(selection)]

    migrated = module.migrate(
        tmp_path, legacy, install_semantic_ownership=True
    )
    rows = [
        row
        for row in migrated["namespace"]["objects"]
        if row["object_id"] == spec.object_id
    ]
    assert len(rows) == 1
    assert rows[0]["kind"] == "LEDGER"
    assert rows[0]["specializations"] == ["POLICY", "PROTOCOL", "TRANSACTION"]
    assert rows[0]["payload"] == {"representation_role": spec.representation_role}
    assert rows[0]["reason"] == (
        spec.necessity_reason + " Boundary: " + spec.consequence_boundary
    )
    assert set(rows[0]["surfaces"]) == {"file:" + path for path in paths}
    assert migrated["namespace"]["execution_checks"] == [selection]
    assert module.migrate(tmp_path, migrated) == migrated


def test_semantic_named_takeover_rejects_other_owner_partial_and_duplicate_specs(
    tmp_path, monkeypatch
):
    from dataclasses import replace
    from verifier.runtime.package_semantic_ownership import SemanticOwnershipSpec

    module, document = _migration_fixture(tmp_path, monkeypatch)
    paths = tuple(
        sorted(
            path
            for path, selection in module._NAMED.items()
            if selection[0] == "vstd-invocation-ledger"
        )
    )
    _add_discovered_files(
        tmp_path,
        monkeypatch,
        tuple(
            path
            for path in paths
            if path != "src/verifier/runtime/polish_invocation_ledger.py"
        ),
    )
    valid = SemanticOwnershipSpec(
        object_id="vstd-invocation-ledger",
        primary_kind="LEDGER",
        specializations=("POLICY", "PROTOCOL", "TRANSACTION"),
        owned_paths=paths,
        representation_role="Synthetic exact invocation-ledger transition.",
        necessity_reason="The stable ledger ID accumulates its consequential roles.",
        consequence_boundary="Bounded local nonmonetary fixture only.",
    )

    def select(specs):
        monkeypatch.setattr(
            module.package_semantic_ownership,
            "validate_catalog",
            lambda root: specs,
        )
        monkeypatch.setattr(
            module.package_semantic_ownership,
            "SEMANTIC_OWNERSHIP_SPECS",
            specs,
        )

    different_owner = replace(valid, object_id="vstd-other-ledger-owner")
    select((different_owner,))
    with pytest.raises(ValueError, match="SEMANTIC_OWNERSHIP_RESERVED_PATH"):
        module.migrate(tmp_path, document, install_semantic_ownership=True)

    partial = replace(valid, owned_paths=paths[:-1])
    select((partial,))
    with pytest.raises(ValueError, match="SEMANTIC_OWNERSHIP_NAMED_PARTIAL"):
        module.migrate(tmp_path, document, install_semantic_ownership=True)

    duplicate = replace(
        valid,
        owned_paths=("src/verifier/runtime/namespace_cli.py",),
    )
    select((valid, duplicate))
    with pytest.raises(ValueError, match="SEMANTIC_OWNERSHIP_ID_DUPLICATED"):
        module.migrate(tmp_path, document, install_semantic_ownership=True)


def test_semantic_ownership_installs_current_evidence_cross_root_decision(
    tmp_path, monkeypatch
):
    from verifier.runtime.package_semantic_ownership import SemanticOwnershipSpec
    from verifier.runtime.package_semantic_ownership_model import root_role_decision

    module, document = _migration_fixture(tmp_path, monkeypatch)
    path = "src/verifier/runtime/gate_pipeline.py"
    observed = _add_discovered_files(tmp_path, monkeypatch, (path,))
    spec = SemanticOwnershipSpec(
        object_id="vstd-test-policy-verifier-role",
        primary_kind="POLICY",
        specializations=(),
        owned_paths=(path,),
        representation_role="Synthetic bounded decision policy fixture.",
        necessity_reason="The cross-root decision must not become a structural cast.",
        consequence_boundary="The fixture makes no package-conformance claim.",
        root_role_decisions=(
            root_role_decision(
                "VERIFIER",
                "APPLIES",
                "This selected policy source computes one bounded repository decision.",
            ),
        ),
    )
    monkeypatch.setattr(
        module.package_semantic_ownership, "validate_catalog", lambda root: (spec,)
    )
    monkeypatch.setattr(
        module.package_semantic_ownership, "SEMANTIC_OWNERSHIP_SPECS", (spec,)
    )

    migrated = module.migrate(tmp_path, document, install_semantic_ownership=True)
    row = next(
        item
        for item in migrated["namespace"]["objects"]
        if item["object_id"] == spec.object_id
    )
    reference = next(
        item for item in observed["census"]["files"] if item["path"] == path
    )
    assert row["kind"] == "POLICY" and row["specializations"] == []
    assert row["classification"]["VERIFIER"] == {
        "status": "APPLIES",
        "reason": spec.root_role_decisions[0].reason,
        "evidence": [reference],
    }
    assert module.migrate(tmp_path, migrated) == migrated


def test_reviewed_semantic_specializations_retire_labels_without_materialized_review():
    registry = namespace_registry()
    transaction_obligations = {
        obligation["id"]: {}
        for obligation in requirements_for(registry, ("TRANSACTION",))
    }
    row = {"specializations": ["ACTUATOR"]}
    previous = {
        "specializations": [
            "ACTUATOR",
            "CONTROLLER",
            "LEDGER",
            "SENSOR",
            "TRANSACTION",
        ],
        "classification": {
            "CONTROLLER": {
                "status": "APPLIES",
                "reason": "A prior decision exists but its obligations are incomplete.",
                "evidence": [{"path": "controller.py", "sha256": "sha256:" + "1" * 64}],
            },
            "LEDGER": {
                "status": "DOES_NOT_APPLY",
                "reason": "A refutation cannot retain a specialization label.",
                "evidence": [{"path": "ledger.py", "sha256": "sha256:" + "2" * 64}],
            },
            "SENSOR": {
                "status": "APPLIES",
                "reason": "A label without selected evidence is not reviewed.",
                "evidence": [],
            },
            "TRANSACTION": {
                "status": "APPLIES",
                "reason": "The independently reviewed transaction role remains materialized.",
                "evidence": [{"path": "transaction.py", "sha256": "sha256:" + "3" * 64}],
            },
        },
        "obligations": transaction_obligations,
    }

    assert migration_module._reviewed_semantic_specializations(
        row, previous, registry
    ) == ["ACTUATOR", "TRANSACTION"]


def test_semantic_receipt_child_retains_required_typed_operands(tmp_path, monkeypatch):
    from verifier.runtime.package_semantic_ownership import SemanticOwnershipSpec

    module, document = _migration_fixture(tmp_path, monkeypatch)
    path = "src/verifier/hardware/receipt.py"
    _add_discovered_files(tmp_path, monkeypatch, (path,))
    spec = SemanticOwnershipSpec(
        object_id="vstd-test-receipt-publication",
        primary_kind="RECEIPT",
        specializations=("TRANSACTION",),
        owned_paths=(path,),
        representation_role="Synthetic typed receipt publication fixture.",
        necessity_reason="Receipt persistence must retain its typed graph roles.",
        consequence_boundary="Local fixture only; no external receipt authority.",
        operands=(
            ("hardware", ("vstd-hardware",)),
            ("subject", ("vstd-hardware",)),
        ),
    )
    monkeypatch.setattr(
        module.package_semantic_ownership,
        "validate_catalog",
        lambda root: (spec,),
    )
    monkeypatch.setattr(
        module.package_semantic_ownership,
        "SEMANTIC_OWNERSHIP_SPECS",
        (spec,),
    )

    migrated = module.migrate(tmp_path, document, install_semantic_ownership=True)
    row = next(
        item
        for item in migrated["namespace"]["objects"]
        if item["object_id"] == spec.object_id
    )
    assert row["operands"] == {
        "hardware": ["vstd-hardware"],
        "subject": ["vstd-hardware"],
    }


def test_semantic_ownership_install_rehomes_only_unanswered_candidate_evidence(
    tmp_path, monkeypatch
):
    from verifier.runtime.package_semantic_ownership import SemanticOwnershipSpec

    module, document = _migration_fixture(tmp_path, monkeypatch)
    path = "src/verifier/runtime/gate_pipeline.py"
    observed = _add_discovered_files(tmp_path, monkeypatch, (path,))
    spec = SemanticOwnershipSpec(
        object_id="vstd-test-pipeline-controller",
        primary_kind="CONTROLLER",
        specializations=("TRANSACTION",),
        owned_paths=(path,),
        representation_role="Synthetic exact pipeline ownership fixture.",
        necessity_reason="The effect path must not remain under VERIFIER catch-all ownership.",
        consequence_boundary="Software process submission only; no physical or financial effect claim.",
    )
    monkeypatch.setattr(
        module.package_semantic_ownership,
        "validate_catalog",
        lambda root: (spec,),
    )
    monkeypatch.setattr(
        module.package_semantic_ownership,
        "SEMANTIC_OWNERSHIP_SPECS",
        (spec,),
    )

    previous = module.migrate(tmp_path, document)
    rows = {row["object_id"]: row for row in previous["namespace"]["objects"]}
    generic = rows["verifier-core-self"]
    reference = next(row for row in observed["census"]["files"] if row["path"] == path)
    generic["classification"]["TRANSACTION"]["evidence"] = [deepcopy(reference)]
    generic["obligations"]["TRANSACTION-0.1-effects-and-authority"] = {
        "reason": "",
        "evidence": [deepcopy(reference)],
        "declaration": {
            name: ""
            for name in ("effects", "preconditions", "authorization", "resources")
        },
    }

    migrated = module.migrate(
        tmp_path,
        previous,
        install_semantic_ownership=True,
    )
    rows = {row["object_id"]: row for row in migrated["namespace"]["objects"]}
    assert rows["verifier-core-self"]["classification"]["TRANSACTION"]["evidence"] == []
    assert rows[spec.object_id]["classification"]["TRANSACTION"]["evidence"] == [
        reference
    ]
    assert (
        rows["verifier-core-self"]["obligations"][
            "TRANSACTION-0.1-effects-and-authority"
        ]["evidence"]
        == []
    )
    assert rows[spec.object_id]["obligations"]["TRANSACTION-0.1-effects-and-authority"][
        "evidence"
    ] == [reference]


def test_semantic_ownership_install_does_not_reinterpret_reviewed_parent_answer(
    tmp_path, monkeypatch
):
    from verifier.runtime.package_semantic_ownership import SemanticOwnershipSpec

    module, document = _migration_fixture(tmp_path, monkeypatch)
    path = "src/verifier/runtime/gate_pipeline.py"
    observed = _add_discovered_files(tmp_path, monkeypatch, (path,))
    spec = SemanticOwnershipSpec(
        object_id="vstd-test-pipeline-controller",
        primary_kind="CONTROLLER",
        specializations=("TRANSACTION",),
        owned_paths=(path,),
        representation_role="Synthetic exact pipeline ownership fixture.",
        necessity_reason="The effect path must not remain under VERIFIER catch-all ownership.",
        consequence_boundary="Software process submission only; no physical or financial effect claim.",
    )
    monkeypatch.setattr(
        module.package_semantic_ownership,
        "validate_catalog",
        lambda root: (spec,),
    )
    monkeypatch.setattr(
        module.package_semantic_ownership,
        "SEMANTIC_OWNERSHIP_SPECS",
        (spec,),
    )

    previous = module.migrate(tmp_path, document)
    rows = {row["object_id"]: row for row in previous["namespace"]["objects"]}
    parent = rows["verifier-core-self"]
    reference = next(row for row in observed["census"]["files"] if row["path"] == path)
    reviewed_decision = {
        "status": "APPLIES",
        "reason": "A human reviewed this exact old-owner binding.",
        "evidence": [deepcopy(reference)],
    }
    reviewed_obligation = {
        "reason": "A human reviewed the transaction boundary on the old owner.",
        "evidence": [deepcopy(reference)],
        "declaration": {
            "effects": "Submit one bounded local process request.",
            "preconditions": "Validate the selected request before submission.",
            "authorization": "The local caller authorizes only this submission.",
            "resources": "The selected local process interface.",
        },
    }
    parent["classification"]["TRANSACTION"] = deepcopy(reviewed_decision)
    parent["obligations"]["TRANSACTION-0.1-effects-and-authority"] = deepcopy(
        reviewed_obligation
    )

    migrated = module.migrate(
        tmp_path,
        previous,
        install_semantic_ownership=True,
    )
    rows = {row["object_id"]: row for row in migrated["namespace"]["objects"]}
    assert rows["verifier-core-self"]["classification"]["TRANSACTION"] == (
        reviewed_decision
    )
    assert (
        rows["verifier-core-self"]["obligations"][
            "TRANSACTION-0.1-effects-and-authority"
        ]
        == reviewed_obligation
    )
    assert rows[spec.object_id]["classification"]["TRANSACTION"]["status"] == (
        "UNRESOLVED"
    )
    assert rows[spec.object_id]["classification"]["TRANSACTION"]["evidence"] == []


def test_semantic_install_refreshes_only_current_graph_representation_digest(
    tmp_path, monkeypatch
):
    from verifier.core.namespace import NamespaceObject
    from verifier.runtime.package_semantic_ownership import SemanticOwnershipSpec

    module, document = _migration_fixture(tmp_path, monkeypatch)
    semantic_path = "src/verifier/runtime/gate_pipeline.py"
    graph_source = "src/verifier/domains/contracts/graph_statics.py"
    observed = _add_discovered_files(
        tmp_path,
        monkeypatch,
        (semantic_path, graph_source),
    )
    spec = SemanticOwnershipSpec(
        object_id="vstd-test-pipeline-controller",
        primary_kind="CONTROLLER",
        specializations=("TRANSACTION",),
        owned_paths=(semantic_path,),
        representation_role="Synthetic exact pipeline ownership fixture.",
        necessity_reason="The effect path must not remain under VERIFIER catch-all ownership.",
        consequence_boundary="Software process submission only; no physical or financial effect claim.",
    )
    monkeypatch.setattr(
        module.package_semantic_ownership,
        "validate_catalog",
        lambda root: (spec,),
    )
    monkeypatch.setattr(
        module.package_semantic_ownership,
        "SEMANTIC_OWNERSHIP_SPECS",
        (spec,),
    )

    current = module.migrate(tmp_path, document)
    current["schema_version"] = package_manifest.REPRESENTATION_SCHEMA
    graph = next(
        row for row in current["namespace"]["objects"] if row["kind"] == "GRAPH"
    )
    graph["payload"] = {**graph["payload"], "representation_scope": "current"}
    retained_graph = next(
        item
        for item in tier_zero_manifest._namespace_objects(current["objects"])
        if item.kind.value == "GRAPH"
    )
    old_current_digest = NamespaceObject.create(
        graph["object_id"],
        "GRAPH",
        graph["payload"],
        graph["operands"],
    ).digest
    reference = next(
        item for item in observed["census"]["files"] if item["path"] == graph_source
    )
    reason = "The current package graph payload and complete member set are explicit."
    current["representation_updates"] = [
        {
            "object_id": graph["object_id"],
            "retained_object_digest": retained_graph.digest,
            "current_object_digest": old_current_digest,
            "reason": reason,
            "evidence": [deepcopy(reference)],
        }
    ]
    package_manifest.validate_bridge(current)

    migrated = module.migrate(
        tmp_path,
        current,
        install_semantic_ownership=True,
    )
    update = migrated["representation_updates"][0]
    assert update["retained_object_digest"] == retained_graph.digest
    assert update["current_object_digest"] != old_current_digest
    assert update["reason"] == reason
    assert update["evidence"] == [reference]
    package_manifest.validate_bridge(migrated)


def test_package_namespace_review_is_explicit_and_receives_complete_draft(
    tmp_path, monkeypatch
):
    module, document = _migration_fixture(tmp_path, monkeypatch)
    calls = []
    original_kind_calls = []

    def apply_original_kinds(root, rows, files):
        original_kind_calls.append(
            (root, tuple(sorted(rows)), tuple(sorted(files)))
        )
        return deepcopy(rows)

    monkeypatch.setattr(
        module.package_original_kind_catalog,
        "apply_partial_profiles",
        apply_original_kinds,
    )

    def apply_review(root, rows, files):
        assert root == tmp_path
        assert {
            "vstd-hardware",
            "vstd-simulation",
            "vstd-harness",
            "vstd-invocation-ledger",
            "vstd-manifest-write",
        } <= set(rows)
        assert set(files) == {
            "src/verifier/runtime/polish_invocation_ledger.py",
            "src/verifier/runtime/namespace_cli.py",
        }
        updated = deepcopy(rows)
        updated["vstd-hardware"]["reason"] = "review integration marker"
        calls.append("existing")
        return updated

    def apply_records(root, rows, files):
        assert rows["vstd-hardware"]["reason"] == "review integration marker"
        calls.append("records")
        return deepcopy(rows)

    def apply_operations(root, rows, files):
        assert calls == ["existing", "records"]
        calls.append("operations")
        return deepcopy(rows)

    def apply_subjects(root, rows, files):
        assert calls == ["existing", "records", "operations"]
        calls.append("subjects")
        return deepcopy(rows)

    def apply_verifier(root, rows, files):
        assert calls == ["existing", "records", "operations", "subjects"]
        calls.append("verifier")
        return deepcopy(rows)

    def apply_scripts(root, rows, files):
        assert calls == [
            "existing",
            "records",
            "operations",
            "subjects",
            "verifier",
        ]
        calls.append("scripts")
        return deepcopy(rows)

    def apply_admission(root, rows, files):
        assert calls == [
            "existing",
            "records",
            "operations",
            "subjects",
            "verifier",
            "scripts",
        ]
        calls.append("admission")
        return deepcopy(rows)

    def apply_commands(root, rows, files):
        assert calls == [
            "existing",
            "records",
            "operations",
            "subjects",
            "verifier",
            "scripts",
            "admission",
        ]
        calls.append("commands")
        return deepcopy(rows)

    def apply_hardware_cli(root, rows, files):
        assert calls == [
            "existing",
            "records",
            "operations",
            "subjects",
            "verifier",
            "scripts",
            "admission",
            "commands",
        ]
        calls.append("hardware-cli")
        return deepcopy(rows)

    def apply_partitions(root, rows, files):
        assert calls == [
            "existing",
            "records",
            "operations",
            "subjects",
            "verifier",
            "scripts",
            "admission",
            "commands",
            "hardware-cli",
        ]
        calls.append("partitions")
        return deepcopy(rows)

    def apply_polish(root, rows, files):
        assert calls == [
            "existing",
            "records",
            "operations",
            "subjects",
            "verifier",
            "scripts",
            "admission",
            "commands",
            "hardware-cli",
            "partitions",
        ]
        calls.append("polish")
        return deepcopy(rows)

    def apply_self_polish(root, rows, files):
        assert calls == [
            "existing",
            "records",
            "operations",
            "subjects",
            "verifier",
            "scripts",
            "admission",
            "commands",
            "hardware-cli",
            "partitions",
            "polish",
        ]
        calls.append("self-polish")
        return deepcopy(rows)

    def apply_people(root, rows, files):
        assert calls == [
            "existing",
            "records",
            "operations",
            "subjects",
            "verifier",
            "scripts",
            "admission",
            "commands",
            "hardware-cli",
            "partitions",
            "polish",
            "self-polish",
        ]
        calls.append("people")
        return deepcopy(rows)

    def apply_systems(root, rows, files):
        assert calls == [
            "existing",
            "records",
            "operations",
            "subjects",
            "verifier",
            "scripts",
            "admission",
            "commands",
            "hardware-cli",
            "partitions",
            "polish",
            "self-polish",
            "people",
        ]
        calls.append("systems")
        return deepcopy(rows)

    def apply_computation(root, rows, files):
        assert calls == [
            "existing",
            "records",
            "operations",
            "subjects",
            "verifier",
            "scripts",
            "admission",
            "commands",
            "hardware-cli",
            "partitions",
            "polish",
            "self-polish",
            "people",
            "systems",
        ]
        calls.append("computation")
        return deepcopy(rows)

    def apply_core(root, rows, files):
        assert calls == [
            "existing",
            "records",
            "operations",
            "subjects",
            "verifier",
            "scripts",
            "admission",
            "commands",
            "hardware-cli",
            "partitions",
            "polish",
            "self-polish",
            "people",
            "systems",
            "computation",
        ]
        calls.append("core")
        return deepcopy(rows)

    def apply_package_object(root, rows, files):
        assert calls == [
            "existing",
            "records",
            "operations",
            "subjects",
            "verifier",
            "scripts",
            "admission",
            "commands",
            "hardware-cli",
            "partitions",
            "polish",
            "self-polish",
            "people",
            "systems",
            "computation",
            "core",
        ]
        calls.append("package-object")
        return deepcopy(rows)

    monkeypatch.setattr(
        module.package_namespace_review,
        "apply_package_namespace_review",
        apply_review,
    )
    monkeypatch.setattr(
        module.package_semantic_review_records,
        "apply_package_semantic_review_records",
        apply_records,
    )
    monkeypatch.setattr(
        module.package_semantic_review_operations,
        "apply_package_semantic_review_operations",
        apply_operations,
    )
    monkeypatch.setattr(
        module.package_semantic_review_subjects,
        "apply_package_semantic_review_subjects",
        apply_subjects,
    )
    monkeypatch.setattr(
        module.package_semantic_review_verifier,
        "apply_package_semantic_review_verifier",
        apply_verifier,
    )
    monkeypatch.setattr(
        module.package_semantic_review_scripts,
        "apply_package_semantic_review_scripts",
        apply_scripts,
    )
    monkeypatch.setattr(
        module.package_semantic_review_admission,
        "apply_package_semantic_review_admission",
        apply_admission,
    )
    monkeypatch.setattr(
        module.package_semantic_review_commands,
        "apply_package_semantic_review_commands",
        apply_commands,
    )
    monkeypatch.setattr(
        module.package_semantic_review_hardware_cli,
        "apply_package_semantic_review_hardware_cli",
        apply_hardware_cli,
    )
    monkeypatch.setattr(
        module.package_semantic_review_partitions,
        "apply_package_semantic_review_partitions",
        apply_partitions,
    )
    monkeypatch.setattr(
        module.package_semantic_review_polish,
        "apply_package_semantic_review_polish",
        apply_polish,
    )
    monkeypatch.setattr(
        module.package_semantic_review_self_polish,
        "apply_package_semantic_review_self_polish",
        apply_self_polish,
    )
    monkeypatch.setattr(
        module.package_original_review_people,
        "apply_package_original_review_people",
        apply_people,
    )
    monkeypatch.setattr(
        module.package_original_review_systems,
        "apply_package_original_review_systems",
        apply_systems,
    )
    monkeypatch.setattr(
        module.package_original_review_computation,
        "apply_package_original_review_computation",
        apply_computation,
    )
    monkeypatch.setattr(
        module.package_semantic_review_core,
        "apply_package_semantic_review_core",
        apply_core,
    )
    monkeypatch.setattr(
        module.package_semantic_review_package_object,
        "apply_package_semantic_review_package_object",
        apply_package_object,
    )

    ordinary = module.migrate(tmp_path, document)
    assert calls == []
    assert original_kind_calls == []
    reviewed = module.migrate(
        tmp_path,
        document,
        select_package_namespace_review=True,
    )
    assert calls == [
        "existing",
        "records",
        "operations",
        "subjects",
        "verifier",
        "scripts",
        "admission",
        "commands",
        "hardware-cli",
        "partitions",
        "polish",
        "self-polish",
        "people",
        "systems",
        "computation",
        "core",
        "package-object",
    ]
    assert len(original_kind_calls) == 1
    assert original_kind_calls[0][0] == tmp_path
    assert {
        "vstd-hardware",
        "vstd-simulation",
        "vstd-harness",
        "vstd-invocation-ledger",
        "vstd-manifest-write",
    } <= set(original_kind_calls[0][1])
    hardware = next(
        row
        for row in reviewed["namespace"]["objects"]
        if row["object_id"] == "vstd-hardware"
    )
    assert hardware["reason"] == "review integration marker"
    assert reviewed != ordinary


def _review_transfer_fixture(module):
    rows, files = {}, {}
    first = None
    for index, (parent_id, child_id, kind, path) in enumerate(module._REVIEW_TRANSFERS):
        digest = "sha256:" + format(index + 13, "064x")
        files[path] = digest
        evidence = [{"path": path, "sha256": digest}]
        obligations = {}
        for obligation in requirements_for(namespace_registry(), (kind,)):
            if obligation["kind"] != kind:
                continue
            obligations[obligation["id"]] = {
                "reason": "Prior exact-source review on the old owner.",
                "evidence": deepcopy(evidence),
                "declaration": {
                    field: "Complete prior answer for " + field + "."
                    for field in obligation["declaration_fields"]
                },
            }
        decision = {
            "status": "APPLIES",
            "reason": "Prior exact-source role review on the old owner.",
            "evidence": deepcopy(evidence),
        }
        rows[parent_id] = {
            "object_id": parent_id,
            "surfaces": [],
            "classification": {kind: deepcopy(decision)},
            "obligations": deepcopy(obligations),
        }
        rows[child_id] = {
            "object_id": child_id,
            "surfaces": ["file:" + path],
            "classification": {kind: deepcopy(decision)},
            "obligations": deepcopy(obligations),
        }
        if first is None:
            first = (parent_id, child_id, kind)
    return rows, files, *first


def test_review_transfer_retires_old_owner_only_after_complete_child(
    tmp_path, monkeypatch
):
    module, _ = _migration_fixture(tmp_path, monkeypatch)
    rows, files, parent_id, child_id, kind = _review_transfer_fixture(module)
    child_before = deepcopy(rows[child_id])
    module._retire_transferred_reviews(rows, files, namespace_registry())

    assert rows[child_id] == child_before
    parent = rows[parent_id]
    assert parent["classification"][kind] == {
        "status": "UNRESOLVED",
        "reason": "Migration retains this applicability question. Static ownership alone cannot refute a POLICY role.",
        "evidence": [],
    }
    assert all(
        binding["reason"] == ""
        and binding["evidence"] == []
        and not any(binding["declaration"].values())
        for binding in parent["obligations"].values()
    )
    first = deepcopy(rows)
    module._retire_transferred_reviews(rows, files, namespace_registry())
    assert rows == first


def test_review_transfer_preserves_complete_independent_parent_review(
    tmp_path, monkeypatch
):
    module, _ = _migration_fixture(tmp_path, monkeypatch)
    transfer = next(
        item for item in module._REVIEW_TRANSFERS if item[0] == "verifier-core-self"
    )
    parent_id, child_id, kind, transferred_path = transfer
    transferred_digest = "sha256:" + "1" * 64
    retained_path = "src/verifier/domains/verifier_bootstrap.py"
    retained_digest = "sha256:" + "2" * 64
    files = {
        transferred_path: transferred_digest,
        retained_path: retained_digest,
    }
    retained_evidence = [{"path": retained_path, "sha256": retained_digest}]
    child_evidence = [{"path": transferred_path, "sha256": transferred_digest}]
    obligations = {
        obligation["id"]: {
            "reason": "Complete independent retained-core protocol review.",
            "evidence": deepcopy(retained_evidence),
            "declaration": {
                field: "Complete independent answer for " + field + "."
                for field in obligation["declaration_fields"]
            },
        }
        for obligation in requirements_for(namespace_registry(), (kind,))
        if obligation["kind"] == kind
    }
    child_obligations = deepcopy(obligations)
    for binding in child_obligations.values():
        binding["evidence"] = deepcopy(child_evidence)
    rows = {
        parent_id: {
            "object_id": parent_id,
            "surfaces": ["file:" + retained_path],
            "classification": {
                kind: {
                    "status": "APPLIES",
                    "reason": "Complete independent retained-core role review.",
                    "evidence": deepcopy(retained_evidence),
                }
            },
            "obligations": obligations,
        },
        child_id: {
            "object_id": child_id,
            "surfaces": ["file:" + transferred_path],
            "classification": {
                kind: {
                    "status": "APPLIES",
                    "reason": "Complete transferred child role review.",
                    "evidence": deepcopy(child_evidence),
                }
            },
            "obligations": child_obligations,
        },
    }
    expected = deepcopy(rows)

    module._retire_transferred_reviews(rows, files, namespace_registry())
    assert rows == expected

    damaged = deepcopy(rows)
    damaged[parent_id]["obligations"].pop(next(iter(obligations)))
    with pytest.raises(ValueError, match="PARENT_INDEPENDENT_INCOMPLETE"):
        module._retire_transferred_reviews(damaged, files, namespace_registry())


def test_review_transfer_rejects_incomplete_child_without_mutation(
    tmp_path, monkeypatch
):
    module, _ = _migration_fixture(tmp_path, monkeypatch)
    rows, files, _, child_id, kind = _review_transfer_fixture(module)
    obligation_id = next(iter(rows[child_id]["obligations"]))
    rows[child_id]["obligations"][obligation_id]["declaration"].update(
        {next(iter(rows[child_id]["obligations"][obligation_id]["declaration"])): ""}
    )
    before = deepcopy(rows)
    with pytest.raises(ValueError, match="TRANSFER_CHILD_OBLIGATION_INCOMPLETE"):
        module._retire_transferred_reviews(rows, files, namespace_registry())
    assert rows == before
    assert rows[child_id]["classification"][kind]["status"] == "APPLIES"


def test_review_gap_report_names_exact_object_kind_obligation_and_unowned_path(
    tmp_path, monkeypatch
):
    module, _ = _migration_fixture(tmp_path, monkeypatch)
    rows, files, parent_id, child_id, kind = _review_transfer_fixture(module)
    module._retire_transferred_reviews(rows, files, namespace_registry())
    report = module._review_gap_report({"namespace": {"objects": list(rows.values())}})

    assert report["unresolved_decision_count"] == 2
    assert {tuple(item.values()) for item in report["unresolved_decisions"]} == {
        (parent, transferred_kind)
        for parent, _, transferred_kind, _ in module._REVIEW_TRANSFERS
    }
    assert report["incomplete_obligation_count"] == 6
    assert all(
        set(item) == {"object_id", "obligation_id"}
        for item in report["incomplete_obligations"]
    )
    assert report["unowned_evidence_count"] == 0

    path = module._REVIEW_TRANSFERS[0][3]
    rows[child_id]["classification"][kind]["evidence"].append(
        {"path": "unowned.py", "sha256": files[path]}
    )
    report = module._review_gap_report({"namespace": {"objects": list(rows.values())}})
    assert report["unowned_evidence"] == [
        {
            "object_id": child_id,
            "binding": "classification:" + kind,
            "path": "unowned.py",
        }
    ]


@pytest.mark.usefixtures("original_kind_denominator")
def test_review_gap_report_refuses_pass_for_one_unresolved_original_kind_cell():
    from verifier.runtime import package_manifest_migration as module
    from verifier.runtime import package_original_kind_catalog
    from verifier.runtime.package_original_kind_profiles import (
        ORIGINAL_NON_OBJECT_KINDS,
    )

    rows = []
    for object_id in package_original_kind_catalog.review_document():
        rows.append(
            {
                "object_id": object_id,
                "surfaces": ["file:owned.py"],
                "classification": {
                    kind: {
                        "status": "DOES_NOT_APPLY",
                        "reason": "Explicit synthetic bounded refutation.",
                        "evidence": [
                            {
                                "path": "owned.py",
                                "sha256": "sha256:" + "0" * 64,
                            }
                        ],
                    }
                    for kind in ORIGINAL_NON_OBJECT_KINDS
                },
                "obligations": {},
            }
        )
    first_object = rows[0]["object_id"]
    first_kind = ORIGINAL_NON_OBJECT_KINDS[0]
    rows[0]["classification"][first_kind]["status"] = "UNRESOLVED"

    report = module._review_gap_report(
        {"namespace": {"objects": rows}},
        root=".",
        source_binding=_bound_source({"owned.py": _OWNED_DIGEST}),
    )

    assert report["status"] == "UNKNOWN"
    assert report["unresolved_decision_count"] == 1
    assert report["unresolved_decisions"] == [
        {"object_id": first_object, "kind": first_kind}
    ]
    assert (
        report["original_kind_closure"]["question_count"]
        == ORIGINAL_KIND_QUESTION_DENOMINATOR
    )
    assert report["original_kind_closure"]["unresolved_count"] == 1
    assert report["original_kind_closure"]["diagnostic"] == (
        "PACKAGE_ORIGINAL_KIND_CATALOG_UNRESOLVED:"
        + first_object
        + ":"
        + first_kind
    )


@pytest.mark.usefixtures("original_kind_denominator")
def test_review_gap_report_treats_omitted_original_kind_cell_as_unresolved():
    from verifier.runtime import package_manifest_migration as module
    from verifier.runtime import package_original_kind_catalog
    from verifier.runtime.package_original_kind_profiles import (
        ORIGINAL_NON_OBJECT_KINDS,
    )

    rows = [
        {
            "object_id": object_id,
            "surfaces": ["file:owned.py"],
            "classification": {
                kind: {
                    "status": "DOES_NOT_APPLY",
                    "reason": "Explicit synthetic bounded refutation.",
                    "evidence": [
                        {
                            "path": "owned.py",
                            "sha256": "sha256:" + "0" * 64,
                        }
                    ],
                }
                for kind in ORIGINAL_NON_OBJECT_KINDS
            },
            "obligations": {},
        }
        for object_id in package_original_kind_catalog.review_document()
    ]
    omitted_object = rows[-1]["object_id"]
    omitted_kind = ORIGINAL_NON_OBJECT_KINDS[-1]
    del rows[-1]["classification"][omitted_kind]

    report = module._review_gap_report(
        {"namespace": {"objects": rows}},
        root=".",
        source_binding=_bound_source({"owned.py": _OWNED_DIGEST}),
    )

    assert report["status"] == "UNKNOWN"
    assert {"object_id": omitted_object, "kind": omitted_kind} in report[
        "unresolved_decisions"
    ]
    assert report["original_kind_closure"]["unresolved_count"] == 1


_OWNED_DIGEST = "sha256:" + "0" * 64
_CENSUS_OPENING = "sha256:" + "a" * 64
_CENSUS_DRIFTED = "sha256:" + "b" * 64
_ORIGINAL_KIND_TEST_IDS = tuple(
    "vstd-synthetic-original-kind-" + str(index).zfill(3)
    for index in range(VERIFIER_PACKAGE_OBJECT_DENOMINATOR)
)


@pytest.fixture
def original_kind_denominator(monkeypatch):
    """Freeze the catalog's object denominator to the audited object ids.

    The live catalog refuses the current source partition (seven drifted
    objects), so these tests bind synthetic cells to the audited ids rather than
    to the refused catalog.  The catalog's own refusal is tested separately.
    """
    from verifier.runtime import package_original_kind_catalog
    from verifier.runtime.package_original_kind_profiles import (
        ORIGINAL_NON_OBJECT_KINDS,
    )

    document = {
        object_id: {
            # A refutation is admissible only over the validated owned-file set, whose
            # effect audit must be CLOSED; these synthetic cells own exactly one file.
            "expected_owned_paths": ["owned.py"],
            "questions": {
                kind: {
                    "status": "DOES_NOT_APPLY",
                    "reason": "Synthetic source-validated bounded refutation.",
                }
                for kind in ORIGINAL_NON_OBJECT_KINDS
            },
        }
        for object_id in _ORIGINAL_KIND_TEST_IDS
    }
    monkeypatch.setattr(
        package_original_kind_catalog,
        "_owned_effect_closure",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        package_original_kind_catalog,
        "review_document",
        lambda: deepcopy(document),
    )
    monkeypatch.setattr(
        package_original_kind_catalog,
        "validated_review_document",
        lambda _root, _files: deepcopy(document),
    )


def _census_capture(inventory, census_digest=_CENSUS_OPENING):
    return {
        "inventory": dict(inventory),
        "census_digest": census_digest,
        "unavailable": None,
    }


def _unavailable_capture(code="PACKAGE_MIGRATION_SOURCE_INVENTORY_UNAVAILABLE:OSError"):
    return {"inventory": None, "census_digest": None, "unavailable": code}


def _bound_source(inventory):
    """Bind an unchanged census to itself, as an undrifted run would."""
    capture = _census_capture(inventory)
    return migration_module._bind_source_inventory(capture, deepcopy(capture))


def _census_payload(census_digest):
    return {
        "census_digest": census_digest,
        "files": [{"path": "owned.py", "sha256": _OWNED_DIGEST}],
    }


def _decided_original_kind_rows(owned_digest=_OWNED_DIGEST):
    from verifier.runtime.package_original_kind_profiles import (
        ORIGINAL_NON_OBJECT_KINDS,
    )

    return [
        {
            "object_id": object_id,
            "surfaces": ["file:owned.py"],
            "classification": {
                kind: {
                    "status": "DOES_NOT_APPLY",
                    "reason": "Explicit synthetic bounded refutation.",
                    "evidence": [{"path": "owned.py", "sha256": owned_digest}],
                }
                for kind in ORIGINAL_NON_OBJECT_KINDS
            },
            "obligations": {},
        }
        for object_id in _ORIGINAL_KIND_TEST_IDS
    ]


@pytest.mark.usefixtures("original_kind_denominator")
def test_review_gap_report_binds_decided_original_kind_cells_to_current_inventory():
    from verifier.runtime.package_original_kind_profiles import (
        ORIGINAL_NON_OBJECT_KINDS,
    )

    rows = _decided_original_kind_rows()
    report = migration_module._review_gap_report(
        {"namespace": {"objects": rows}},
        root=".",
        source_binding=_bound_source({"owned.py": _OWNED_DIGEST}),
    )

    closure = report["original_kind_closure"]
    assert closure["status"] == "PASS"
    assert closure["question_count"] == ORIGINAL_KIND_QUESTION_DENOMINATOR
    assert closure["decided_count"] == len(rows) * len(ORIGINAL_NON_OBJECT_KINDS)
    assert closure["unresolved_count"] == 0
    assert report["unresolved_decision_count"] == 0
    assert report["status"] == "PASS"
    assert report["source_binding"]["status"] == "BOUND"
    assert report["source_binding"]["opening_census_digest"] == _CENSUS_OPENING


@pytest.mark.usefixtures("original_kind_denominator")
def test_review_gap_report_without_source_binding_is_unknown_not_a_per_cell_gap_flood():
    report = migration_module._review_gap_report(
        {"namespace": {"objects": _decided_original_kind_rows()}}
    )

    assert report["status"] == "UNKNOWN"
    assert report["unresolved_decision_count"] == 0
    assert report["original_kind_closure"]["unresolved"] == []
    assert report["original_kind_closure"]["diagnostic"] == (
        "PACKAGE_ORIGINAL_KIND_SOURCE_INVENTORY_ABSENT"
    )
    assert report["source_binding"]["status"] == "ABSENT"


@pytest.mark.usefixtures("original_kind_denominator")
def test_review_gap_report_refuses_bound_cells_without_a_validated_root():
    report = migration_module._review_gap_report(
        {"namespace": {"objects": _decided_original_kind_rows()}},
        source_binding=_bound_source({"owned.py": _OWNED_DIGEST}),
    )

    assert report["status"] == "UNKNOWN"
    assert report["unresolved_decision_count"] == 0
    assert report["original_kind_closure"]["diagnostic"] == (
        "PACKAGE_ORIGINAL_KIND_CATALOG_VALIDATED_ROOT_ABSENT"
    )


@pytest.mark.parametrize(
    "opening,closing,status",
    [
        (_census_capture({"owned.py": _OWNED_DIGEST}), _census_capture({"owned.py": _OWNED_DIGEST}, _CENSUS_DRIFTED), "MUTATED"),
        (_census_capture({"owned.py": _OWNED_DIGEST}), _unavailable_capture(), "CLOSING_UNAVAILABLE"),
        (_unavailable_capture(), _census_capture({"owned.py": _OWNED_DIGEST}), "UNAVAILABLE"),
    ],
)
@pytest.mark.usefixtures("original_kind_denominator")
def test_review_gap_report_refuses_pass_when_source_binding_is_not_bound(
    opening, closing, status
):
    binding = migration_module._bind_source_inventory(opening, closing)
    assert binding["status"] == status
    assert "inventory" not in migration_module._public_source_binding(binding)

    report = migration_module._review_gap_report(
        {"namespace": {"objects": _decided_original_kind_rows()}},
        source_binding=binding,
    )

    assert report["status"] == "UNKNOWN"
    assert report["unresolved_decision_count"] == 0
    assert report["original_kind_closure"]["diagnostic"] == (
        "PACKAGE_ORIGINAL_KIND_SOURCE_INVENTORY_" + status
    )


@pytest.mark.usefixtures("original_kind_denominator")
def test_original_kind_evidence_must_be_owned_and_current_in_review_report():
    from verifier.runtime.package_original_kind_profiles import (
        ORIGINAL_NON_OBJECT_KINDS,
    )

    inventory = {"owned.py": _OWNED_DIGEST, "elsewhere.py": _OWNED_DIGEST}
    rows = _decided_original_kind_rows()
    stale_row, unowned_row = rows[0], rows[1]
    stale_kind, unowned_kind = ORIGINAL_NON_OBJECT_KINDS[0], ORIGINAL_NON_OBJECT_KINDS[1]
    stale_row["classification"][stale_kind]["evidence"][0]["sha256"] = (
        "sha256:" + "1" * 64
    )
    unowned_row["classification"][unowned_kind]["evidence"] = [
        {"path": "elsewhere.py", "sha256": _OWNED_DIGEST}
    ]

    report = migration_module._review_gap_report(
        {"namespace": {"objects": rows}},
        root=".",
        source_binding=_bound_source(inventory),
    )

    closure = report["original_kind_closure"]
    assert closure["unresolved_count"] == 2
    assert closure["unresolved_reason_counts"] == {
        "EVIDENCE_DIGEST_STALE": 1,
        "EVIDENCE_PATH_UNOWNED": 1,
    }
    assert {(item["object_id"], item["kind"]) for item in closure["unresolved"]} == {
        (stale_row["object_id"], stale_kind),
        (unowned_row["object_id"], unowned_kind),
    }
    assert report["unowned_evidence"] == [
        {
            "object_id": unowned_row["object_id"],
            "binding": "classification:" + unowned_kind,
            "path": "elsewhere.py",
        }
    ]
    assert report["status"] == "FAIL"


def test_review_gap_report_reports_catalog_refusal_as_unknown_instead_of_crashing(
    monkeypatch,
):
    from verifier.runtime import package_original_kind_catalog

    refusal = "RUNTIME_ORIGINAL_KIND_SOURCE_COORDINATE_DRIFT:vstd-anchor-history-ledger"

    def refused(_root, _files):
        raise ValueError(refusal)

    monkeypatch.setattr(
        package_original_kind_catalog, "validated_review_document", refused
    )
    report = migration_module._review_gap_report(
        {"namespace": {"objects": _decided_original_kind_rows()}},
        root=".",
        source_binding=_bound_source({"owned.py": _OWNED_DIGEST}),
    )

    assert report["status"] == "UNKNOWN"
    assert report["unresolved_decision_count"] == 0
    assert report["original_kind_closure"]["unresolved"] == []
    assert report["original_kind_closure"]["diagnostic"] == (
        "PACKAGE_ORIGINAL_KIND_CATALOG_REFUSED:" + refusal
    )


def test_source_inventory_capture_is_fresh_and_fails_closed(tmp_path, monkeypatch):
    from verifier.runtime import self_polish_estate

    census = _census_payload(_CENSUS_OPENING)
    monkeypatch.setattr(
        self_polish_estate,
        "capture_candidate_source_census",
        lambda root: deepcopy(census),
    )
    assert migration_module._capture_source_inventory(tmp_path) == _census_capture(
        {"owned.py": _OWNED_DIGEST}
    )

    def refused(root):
        raise self_polish_estate.EstateError("CANDIDATE_SOURCE_UNREADABLE")

    monkeypatch.setattr(self_polish_estate, "capture_candidate_source_census", refused)
    assert migration_module._capture_source_inventory(tmp_path) == _unavailable_capture(
        "PACKAGE_MIGRATION_SOURCE_INVENTORY_UNAVAILABLE:CANDIDATE_SOURCE_UNREADABLE"
    )

    def unreadable(root):
        raise OSError("disk gone")

    monkeypatch.setattr(self_polish_estate, "capture_candidate_source_census", unreadable)
    assert migration_module._capture_source_inventory(tmp_path)["inventory"] is None


def _run_migration_main(monkeypatch, root, backup, censuses, *, write):
    from verifier.runtime import self_polish_estate

    captures = iter(censuses)

    def capture(_root):
        value = next(captures)
        if isinstance(value, Exception):
            raise value
        return value

    monkeypatch.setattr(self_polish_estate, "capture_candidate_source_census", capture)
    monkeypatch.setattr(
        migration_module,
        "migrate",
        lambda _root, document, **_kwargs: deepcopy(document),
    )
    argv = ["package_manifest_migration", "--root", str(root)]
    if write:
        argv += ["--write", "--backup", str(backup)]
    monkeypatch.setattr("sys.argv", argv)
    return migration_module.main()


def test_write_aborts_before_backup_or_replace_when_inventory_drifts(
    tmp_path, tmp_path_factory, monkeypatch
):
    from verifier.runtime import tier_zero_profile

    root = tmp_path / "repo"
    root.mkdir()
    raw = tier_zero_profile.canonical_bytes(envelope()) + b"\n"
    (root / "objects.vstd").write_bytes(raw)
    backup = tmp_path_factory.mktemp("outside") / "objects.before.vstd"

    with pytest.raises(ValueError, match="PACKAGE_MIGRATION_SOURCE_INVENTORY_MUTATED"):
        _run_migration_main(
            monkeypatch,
            root,
            backup,
            [_census_payload(_CENSUS_OPENING), _census_payload(_CENSUS_DRIFTED)],
            write=True,
        )

    assert (root / "objects.vstd").read_bytes() == raw
    assert not backup.exists()
    assert list(root.glob(".vstd-migration-*")) == []


def test_write_aborts_when_closing_inventory_is_unreadable(
    tmp_path, tmp_path_factory, monkeypatch
):
    from verifier.runtime import self_polish_estate, tier_zero_profile

    root = tmp_path / "repo"
    root.mkdir()
    raw = tier_zero_profile.canonical_bytes(envelope()) + b"\n"
    (root / "objects.vstd").write_bytes(raw)
    backup = tmp_path_factory.mktemp("outside") / "objects.before.vstd"
    refused = self_polish_estate.EstateError("CANDIDATE_SOURCE_UNREADABLE")

    with pytest.raises(ValueError, match="PACKAGE_MIGRATION_SOURCE_INVENTORY_CLOSING_UNAVAILABLE"):
        _run_migration_main(
            monkeypatch,
            root,
            backup,
            [_census_payload(_CENSUS_OPENING), refused],
            write=True,
        )

    assert (root / "objects.vstd").read_bytes() == raw
    assert not backup.exists()


def test_write_publishes_only_when_stable_inventory_binds_the_report(
    tmp_path, tmp_path_factory, monkeypatch, capsys
):
    from verifier.runtime import tier_zero_profile

    root = tmp_path / "repo"
    root.mkdir()
    raw = tier_zero_profile.canonical_bytes(envelope()) + b"\n"
    (root / "objects.vstd").write_bytes(raw)
    backup = tmp_path_factory.mktemp("outside") / "objects.before.vstd"

    assert _run_migration_main(
        monkeypatch,
        root,
        backup,
        [_census_payload(_CENSUS_OPENING), _census_payload(_CENSUS_OPENING)],
        write=True,
    ) == 0

    assert backup.read_bytes() == raw
    assert (root / "objects.vstd").read_bytes() == raw
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "MIGRATED_DRAFT"
    assert report["tier_zero_review"]["source_binding"]["status"] == "BOUND"
    assert report["tier_zero_review"]["source_binding"]["opening_census_digest"] == (
        _CENSUS_OPENING
    )


def test_preview_reports_unknown_for_drifted_inventory_without_writing(
    tmp_path, monkeypatch, capsys
):
    from verifier.runtime import tier_zero_profile

    root = tmp_path / "repo"
    root.mkdir()
    raw = tier_zero_profile.canonical_bytes(envelope()) + b"\n"
    (root / "objects.vstd").write_bytes(raw)

    assert _run_migration_main(
        monkeypatch,
        root,
        None,
        [_census_payload(_CENSUS_OPENING), _census_payload(_CENSUS_DRIFTED)],
        write=False,
    ) == 0

    assert (root / "objects.vstd").read_bytes() == raw
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "PREVIEW"
    assert report["tier_zero_review"]["status"] == "UNKNOWN"
    assert report["tier_zero_review"]["source_binding"]["status"] == "MUTATED"


def test_harness_financial_review_refutes_ledger_and_declares_transaction_boundary(
    tmp_path, monkeypatch
):
    from verifier.runtime.self_polish_estate import bytes_digest

    module, document = _migration_fixture(tmp_path, monkeypatch)
    observed = _add_discovered_files(
        tmp_path, monkeypatch, _HARNESS_LEDGER_REVIEW_PATHS
    )
    next(
        row
        for row in observed["surfaces"]
        if row["path"] == _HARNESS_LEDGER_REVIEW_PATHS[0]
    )["hints"] = ["LEDGER"]
    for index, path in enumerate(_HARNESS_LEDGER_REVIEW_PATHS):
        selected = tmp_path / path
        selected.parent.mkdir(parents=True, exist_ok=True)
        selected.write_bytes(("reviewed harness source " + str(index) + "\n").encode())
        digest = bytes_digest(selected.read_bytes())
        next(row for row in observed["census"]["files"] if row["path"] == path)[
            "sha256"
        ] = digest
    # _add_discovered_files installs a closure over this mutable observation.
    # Reinstall it explicitly so the intent remains clear if that helper changes.
    from verifier.runtime import namespace_discovery

    monkeypatch.setattr(
        namespace_discovery, "discover", lambda root: deepcopy(observed)
    )

    migrated = module.migrate(
        tmp_path, document, select_harness_financial_classification=True
    )
    harness = next(
        row
        for row in migrated["namespace"]["objects"]
        if row["object_id"] == "vstd-harness"
    )

    ledger = harness["classification"]["LEDGER"]
    assert ledger["status"] == "DOES_NOT_APPLY"
    assert "no authoritative" in ledger["reason"]
    assert {row["path"] for row in ledger["evidence"]} == set(
        _HARNESS_LEDGER_REVIEW_PATHS
    )
    assert not any(name.startswith("LEDGER-") for name in harness["obligations"])
    assert "LEDGER" not in harness["specializations"]

    transaction = harness["classification"]["TRANSACTION"]
    assert transaction["status"] == "APPLIES"
    assert "process exit is not transaction commit" in transaction["reason"]
    assert {row["path"] for row in transaction["evidence"]} == set(
        _HARNESS_TRANSACTION_PATHS
    )
    assert "TRANSACTION" in harness["specializations"]
    transaction_bindings = {
        name: binding
        for name, binding in harness["obligations"].items()
        if name.startswith("TRANSACTION-")
    }
    assert set(transaction_bindings) == {
        "TRANSACTION-0.1-effects-and-authority",
        "TRANSACTION-0.2-commit-and-failure",
        "TRANSACTION-0.3-retry-and-replay",
    }
    assert all(
        binding["reason"]
        and binding["evidence"]
        and all(value for value in binding["declaration"].values())
        for binding in transaction_bindings.values()
    )
    assert (
        "no cross-invocation duplicate guard"
        in (
            transaction_bindings["TRANSACTION-0.3-retry-and-replay"]["declaration"][
                "duplicate_detection"
            ]
        )
    )
    from verifier.runtime import namespace_classification, namespace_contracts

    classification_observed = deepcopy(observed)
    for surface in classification_observed["surfaces"]:
        surface["unresolved_marker"] = False
    classified = namespace_classification.assess_classification(
        migrated["namespace"]["objects"],
        namespace_contracts.namespace_registry(),
        classification_observed,
    )
    harness_required = [
        row
        for row in classified["required_obligations"]
        if row["object_id"] == "vstd-harness"
    ]
    assert all(
        row["status"] == "PASS"
        for row in harness_required
        if row["kind"] == "TRANSACTION"
    )
    # This direct classifier call deliberately supplies no refutation_context.
    # The retained review decision and current source hashes therefore cannot
    # establish non-applicability by themselves: LEDGER obligations stay in the
    # denominator until the executable closure witness is run freshly.
    assert any(row["kind"] == "LEDGER" for row in harness_required)
    assert any(
        row["object_id"] == "vstd-harness"
        and row["code"] == "NAMESPACE_NON_APPLICABILITY_NOT_ESTABLISHED"
        and row["status"] == "UNKNOWN"
        for row in classified["findings"]
    )
    assert not any(
        row["object_id"] == "vstd-harness"
        and row["code"]
        in {
            "NAMESPACE_LABEL_CONTRADICTS_SOURCE",
            "NAMESPACE_OBLIGATION_NOT_APPLICABLE_OR_REGISTERED",
        }
        for row in classified["findings"]
    )
    assert (
        module.migrate(tmp_path, migrated, select_harness_financial_classification=True)
        == migrated
    )


def test_harness_financial_review_refuses_to_erase_reviewed_ledger_answers(
    tmp_path, monkeypatch
):
    from verifier.runtime.self_polish_estate import bytes_digest

    module, document = _migration_fixture(tmp_path, monkeypatch)
    observed = _add_discovered_files(
        tmp_path, monkeypatch, _HARNESS_LEDGER_REVIEW_PATHS
    )
    next(
        row
        for row in observed["surfaces"]
        if row["path"] == _HARNESS_LEDGER_REVIEW_PATHS[0]
    )["hints"] = ["LEDGER"]
    for index, path in enumerate(_HARNESS_LEDGER_REVIEW_PATHS):
        selected = tmp_path / path
        selected.parent.mkdir(parents=True, exist_ok=True)
        selected.write_bytes(("reviewed harness source " + str(index) + "\n").encode())
        next(row for row in observed["census"]["files"] if row["path"] == path)[
            "sha256"
        ] = bytes_digest(selected.read_bytes())
    from verifier.runtime import namespace_discovery

    monkeypatch.setattr(
        namespace_discovery, "discover", lambda root: deepcopy(observed)
    )
    previous = module.migrate(tmp_path, document)
    harness = next(
        row
        for row in previous["namespace"]["objects"]
        if row["object_id"] == "vstd-harness"
    )
    binding = harness["obligations"]["LEDGER-0.1-authoritative-history"]
    binding["reason"] = "A separately reviewed answer must not be erased."
    binding["declaration"] = {
        key: "Reviewed " + key + "." for key in binding["declaration"]
    }

    with pytest.raises(ValueError, match="HARNESS_LEDGER_DECLARATION_CONFLICT"):
        module.migrate(tmp_path, previous, select_harness_financial_classification=True)


def test_harness_rehome_preserves_reviewed_state_and_only_moves_unresolved_candidates(
    tmp_path, monkeypatch
):
    from verifier.domains.contracts import object_facets

    module, document = _migration_fixture(tmp_path, monkeypatch)
    core_path = "src/verifier/core/run.py"
    runtime_path = "src/verifier/runtime/language_runners.py"
    observed = _add_discovered_files(tmp_path, monkeypatch, (core_path, runtime_path))
    for surface in observed["surfaces"]:
        if surface["path"] in {core_path, runtime_path}:
            surface["hints"] = ["LEDGER", "TRANSACTION"]
    previous = module.migrate(tmp_path, document)
    rows = {row["object_id"]: row for row in previous["namespace"]["objects"]}
    package_object = rows["vstd-package-object"]
    verifier = rows["verifier-core-self"]
    harness = rows["vstd-harness"]
    core_ref = next(
        row for row in observed["census"]["files"] if row["path"] == core_path
    )
    runtime_ref = next(
        row for row in observed["census"]["files"] if row["path"] == runtime_path
    )

    # Model a prior manifest whose generic owners still held the now-reviewed
    # HARNESS surfaces and candidate-only financial references.
    for row in rows.values():
        row["surfaces"] = [
            surface
            for surface in row["surfaces"]
            if surface not in {"file:" + core_path, "file:" + runtime_path}
        ]
    package_object["surfaces"].append("file:" + core_path)
    verifier["surfaces"].append("file:" + runtime_path)
    for kind in ("LEDGER", "TRANSACTION"):
        verifier["classification"][kind]["evidence"].append(deepcopy(runtime_ref))
        for name, binding in verifier["obligations"].items():
            if name.startswith(kind + "-"):
                binding["evidence"].append(deepcopy(runtime_ref))

    reviewed_decision = {
        "status": "DOES_NOT_APPLY",
        "reason": "Reviewed independently; ownership migration cannot revise this answer.",
        "evidence": [deepcopy(core_ref)],
    }
    package_object["classification"]["LEDGER"] = deepcopy(reviewed_decision)
    package_object["obligations"]["TRANSACTION-0.1-effects-and-authority"] = deepcopy(
        harness["obligations"]["TRANSACTION-0.1-effects-and-authority"]
    )
    reviewed_binding = package_object["obligations"][
        "TRANSACTION-0.1-effects-and-authority"
    ]
    reviewed_binding["reason"] = (
        "Reviewed declaration must remain byte-for-byte stable."
    )
    reviewed_binding["evidence"] = [deepcopy(core_ref)]
    reviewed_binding["declaration"] = {
        key: "Explicit retained answer for " + key + "."
        for key in reviewed_binding["declaration"]
    }
    retained_binding = deepcopy(reviewed_binding)

    instance_selection = {
        "object_id": "vstd-package-object",
        "coordinate": object_facets.COORDINATE,
        "semantic_version": object_facets.SEMANTIC_VERSION,
        "proposition_digest": object_facets.PROPOSITION_DIGEST,
        "reason": "Exact retained instance selection.",
        "evidence": [],
        **{
            name: {"path": name + ".json", "sha256": "sha256:" + "a" * 64}
            for name in ("request", "policy", "certificate")
        },
    }
    execution_selection = {
        "object_id": "vstd-invocation-ledger",
        "mechanism": "verifier-local-invocation-ledger-1",
        "reason": "Exact retained execution selection.",
        "evidence": [{"path": "prior.py", "sha256": "sha256:" + "b" * 64}],
    }
    previous["namespace"]["instance_checks"] = [deepcopy(instance_selection)]
    previous["namespace"]["execution_checks"] = [deepcopy(execution_selection)]
    denominator = deepcopy(previous["obligation_denominator"])
    retained_objects = deepcopy(previous["objects"])

    updated = module.migrate(tmp_path, previous)
    after = {row["object_id"]: row for row in updated["namespace"]["objects"]}
    assert updated["objects"] == retained_objects
    assert updated["obligation_denominator"] == denominator
    assert updated["namespace"]["instance_checks"] == [instance_selection]
    assert updated["namespace"]["execution_checks"] == [execution_selection]
    assert after["vstd-package-object"]["classification"]["LEDGER"] == reviewed_decision
    assert (
        after["vstd-package-object"]["obligations"][
            "TRANSACTION-0.1-effects-and-authority"
        ]
        == retained_binding
    )

    for kind in ("LEDGER", "TRANSACTION"):
        source_decision = after["verifier-core-self"]["classification"][kind]
        target_decision = after["vstd-harness"]["classification"][kind]
        assert source_decision["status"] == target_decision["status"] == "UNRESOLVED"
        assert runtime_path not in {
            item["path"] for item in source_decision["evidence"]
        }
        assert runtime_ref in target_decision["evidence"]
        for name, source_binding in after["verifier-core-self"]["obligations"].items():
            if name.startswith(kind + "-"):
                assert runtime_path not in {
                    item["path"] for item in source_binding["evidence"]
                }
                assert (
                    runtime_ref
                    in after["vstd-harness"]["obligations"][name]["evidence"]
                )
    assert module.migrate(tmp_path, updated) == updated


def test_harness_rehome_never_discards_candidate_when_target_binding_is_absent_or_reviewed(
    tmp_path, monkeypatch
):
    module, _ = _migration_fixture(tmp_path, monkeypatch)
    path = "src/verifier/core/run.py"
    surface = "file:" + path
    reference = {"path": path, "sha256": "sha256:" + "c" * 64}
    empty_declaration = {"history": "", "state": ""}
    reviewed = {
        "reason": "Independent target review.",
        "evidence": [],
        "declaration": {"history": "Reviewed.", "state": "Reviewed."},
    }
    source = {
        "surfaces": [surface],
        "classification": {
            "LEDGER": {
                "status": "UNRESOLVED",
                "reason": "Unanswered.",
                "evidence": [deepcopy(reference)],
            }
        },
        "obligations": {
            "LEDGER-0.1-authoritative-history": {
                "reason": "",
                "evidence": [deepcopy(reference)],
                "declaration": deepcopy(empty_declaration),
            },
            "LEDGER-0.2-accounting-invariants": {
                "reason": "",
                "evidence": [deepcopy(reference)],
                "declaration": deepcopy(empty_declaration),
            },
        },
    }
    harness = {
        "surfaces": [],
        "classification": {
            "LEDGER": {"status": "UNRESOLVED", "reason": "Unanswered.", "evidence": []}
        },
        "obligations": {"LEDGER-0.2-accounting-invariants": deepcopy(reviewed)},
    }
    rows = {"old-owner": source, "vstd-harness": harness}
    previous = deepcopy(rows)
    observed = {
        "surfaces": [{"path": path, "surface_id": surface}],
        "census": {"files": [deepcopy(reference)]},
    }

    module._rehome_harness_candidate_evidence(rows, previous, observed, "vstd-harness")

    assert source["classification"]["LEDGER"]["evidence"] == []
    assert harness["classification"]["LEDGER"]["evidence"] == [reference]
    created = harness["obligations"]["LEDGER-0.1-authoritative-history"]
    assert created == {
        "reason": "",
        "evidence": [reference],
        "declaration": empty_declaration,
    }
    assert source["obligations"]["LEDGER-0.1-authoritative-history"]["evidence"] == []
    assert harness["obligations"]["LEDGER-0.2-accounting-invariants"] == reviewed
    assert source["obligations"]["LEDGER-0.2-accounting-invariants"]["evidence"] == [
        reference
    ]


def test_migration_asks_about_every_non_object_role_without_inventing_refutations(
    tmp_path, monkeypatch
):
    module, document = _migration_fixture(tmp_path, monkeypatch)
    migrated = module.migrate(tmp_path, document)
    review_kinds = set(namespace_registry()) - {"OBJECT"}
    assert len(review_kinds) == 37
    registry = namespace_registry()
    for row in migrated["namespace"]["objects"]:
        assert set(row["classification"]) == review_kinds
        primary = row["kind"]
        original_primary = (
            primary != "OBJECT" and registry[primary].extends is None
        )
        if original_primary:
            decision = row["classification"][primary]
            assert decision["status"] == "APPLIES"
            assert decision["reason"] == module._primary_original_kind_reason(
                primary, row["reason"]
            )
        for kind in review_kinds - {
            "LEDGER",
            "TRANSACTION",
            *(set((primary,)) if original_primary else set()),
        }:
            assert row["classification"][kind]["status"] == "UNRESOLVED"
            assert row["classification"][kind]["evidence"] == []
    migrated_by_id = {
        row["object_id"]: row for row in migrated["namespace"]["objects"]
    }
    for object_id in ("vstd-invocation-ledger", "vstd-manifest-write"):
        for kind in ("LEDGER", "TRANSACTION"):
            assert migrated_by_id[object_id]["classification"][kind] == {
                "status": "UNRESOLVED",
                    "reason": "UNRESOLVED.",
                "evidence": [],
            }
    assert migrated["objects"] == document["objects"]
    assert migrated["obligation_denominator"] == document["obligation_denominator"]


def test_refresh_preserves_decisions_and_adds_newly_registered_questions(
    tmp_path, monkeypatch
):
    module, document = _migration_fixture(tmp_path, monkeypatch)
    previous = module.migrate(tmp_path, document)
    for row in previous["namespace"]["objects"]:
        row["classification"] = {
            kind: value
            for kind, value in row["classification"].items()
            if kind in {"LEDGER", "TRANSACTION"}
        }
    expected = deepcopy(previous)
    updated = module.migrate(tmp_path, previous)
    review_kinds = set(namespace_registry()) - {"OBJECT"}
    for before, after in zip(
        expected["namespace"]["objects"], updated["namespace"]["objects"]
    ):
        assert set(after["classification"]) == review_kinds
        assert after["classification"]["LEDGER"] == before["classification"]["LEDGER"]
        assert (
            after["classification"]["TRANSACTION"]
            == before["classification"]["TRANSACTION"]
        )
        assert "FINBOT" in after["classification"]
        assert after["classification"]["FINBOT"]["status"] == "UNRESOLVED"
        for name, binding in before["obligations"].items():
            assert after["obligations"][name] == binding


def test_unanswered_refresh_does_not_invent_or_duplicate_source_evidence(
    tmp_path, monkeypatch
):
    module, document = _migration_fixture(tmp_path, monkeypatch)
    previous = module.migrate(tmp_path, document)
    for row in previous["namespace"]["objects"]:
        row["classification"]["FINBOT"] = {
            "status": "UNRESOLVED",
            "reason": "Not yet reviewed.",
            "evidence": [],
        }
    updated = module.migrate(tmp_path, previous, refresh_unresolved=True)
    assert all(
        row["classification"]["FINBOT"]["evidence"] == []
        for row in updated["namespace"]["objects"]
    )


def test_reviewed_refresh_cannot_discard_other_role_decisions(tmp_path, monkeypatch):
    module, document = _migration_fixture(tmp_path, monkeypatch)
    previous = module.migrate(tmp_path, document)
    selected = next(
        row
        for row in previous["namespace"]["objects"]
        if row["object_id"] == "vstd-invocation-ledger"
    )
    decision = {
        "status": "DOES_NOT_APPLY",
        "reason": "Separately reviewed nonmonetary fixture.",
        "evidence": [
            {
                "path": "src/verifier/runtime/polish_invocation_ledger.py",
                "sha256": "sha256:" + "b" * 64,
            }
        ],
    }
    selected["classification"]["FINBOT"] = deepcopy(decision)
    updated = module.migrate(tmp_path, previous, refresh_reviewed=True)
    selected = next(
        row
        for row in updated["namespace"]["objects"]
        if row["object_id"] == "vstd-invocation-ledger"
    )
    # Even stale evidence must survive: a reviewed ledger refresh is not
    # authorization to replace another role's independently selected evidence.
    assert selected["classification"]["FINBOT"] == decision


def test_reviewed_refresh_replaces_only_exact_catalog_binding_keys() -> None:
    from verifier.runtime import package_manifest_migration as module

    row = {
        "classification": {
            "LEDGER": {"status": "UNRESOLVED", "reason": "new", "evidence": []},
            "FINBOT": {"status": "UNRESOLVED", "reason": "new", "evidence": []},
        },
        "obligations": {
            "LEDGER-0.1-authoritative-history": {
                "reason": "",
                "evidence": [],
                "declaration": {"history": ""},
            },
            "FINBOT-0.1-financial-authority": {
                "reason": "",
                "evidence": [],
                "declaration": {"authority": ""},
            },
        },
    }
    prior = {
        "classification": {
            "LEDGER": {"status": "APPLIES", "reason": "stale reviewed", "evidence": []},
            "FINBOT": {"status": "DOES_NOT_APPLY", "reason": "independent", "evidence": []},
        },
        "obligations": {
            "LEDGER-0.1-authoritative-history": {
                "reason": "stale reviewed",
                "evidence": [],
                "declaration": {"history": "prior"},
            },
            "FINBOT-0.1-financial-authority": {
                "reason": "independent",
                "evidence": [],
                "declaration": {"authority": "prior"},
            },
        },
    }
    generated_ledger = deepcopy(row["classification"]["LEDGER"])
    generated_obligation = deepcopy(
        row["obligations"]["LEDGER-0.1-authoritative-history"]
    )
    module._merge_previous_binding_maps(
        row,
        prior,
        {
            "classification": frozenset({"LEDGER"}),
            "obligations": frozenset({"LEDGER-0.1-authoritative-history"}),
        },
    )
    assert row["classification"]["LEDGER"] == generated_ledger
    assert row["obligations"]["LEDGER-0.1-authoritative-history"] == generated_obligation
    assert row["classification"]["FINBOT"] == prior["classification"]["FINBOT"]
    assert (
        row["obligations"]["FINBOT-0.1-financial-authority"]
        == prior["obligations"]["FINBOT-0.1-financial-authority"]
    )


def test_complete_package_review_refresh_catalog_is_disjoint_and_exhaustive() -> None:
    from verifier.runtime import package_manifest_migration as module

    catalog = module._package_review_refresh_catalog()
    registry = namespace_registry()
    primary_by_object = {}
    composed_review_ids = {
        object_id
        for review_module in module._PACKAGE_REVIEW_MODULES
        for object_id in review_module.review_document()
    }
    for review_module in module._PACKAGE_REVIEW_MODULES:
        for object_id, review in review_module.review_document().items():
            assert object_id not in primary_by_object
            primary_by_object[object_id] = review["primary_kind"]
    assert set(catalog) == composed_review_ids
    assert all(binding["classification"] for binding in catalog.values())
    assert all(
        set(binding) == {"classification", "obligations"}
        for binding in catalog.values()
    )
    # A reviewed refutation owns retirement of the formerly active obligations
    # too; otherwise refresh can leave a declaration under DOES_NOT_APPLY.
    assert {
        "CONTROLLER-0.1-feedback-and-authority",
        "CONTROLLER-0.2-timing-and-stability",
        "CONTROLLER-0.3-intervention-and-failure",
    } <= catalog["vstd-actor"]["obligations"]
    for spec in module.package_semantic_ownership.SEMANTIC_OWNERSHIP_SPECS:
        assert {
            decision.kind for decision in spec.root_role_decisions
        } <= catalog[spec.object_id]["classification"]
    original_primaries = {
        object_id: kind
        for object_id, kind in primary_by_object.items()
        if kind != "OBJECT" and registry[kind].extends is None
    }
    assert len(original_primaries) == 258
    assert all(
        kind in catalog[object_id]["classification"]
        for object_id, kind in original_primaries.items()
    )


def test_migration_preserves_consequence_edges_and_stale_evidence(
    tmp_path, monkeypatch
):
    module, document = _migration_fixture(tmp_path, monkeypatch)
    previous = module.migrate(tmp_path, document)
    identifiers = [row["object_id"] for row in previous["namespace"]["objects"]]
    graph = {
        "schema_version": "verifier-consequence-graph-1",
        "effects": [],
        "edges": [
            {
                "source": identifiers[0],
                "target": identifiers[1],
                "relation": "influences",
                "reason": "Retained source selection, deliberately stale for this test.",
                "evidence": [{"path": "prior.py", "sha256": "sha256:" + "e" * 64}],
            }
        ],
    }
    previous["namespace"]["consequence_graph"] = deepcopy(graph)
    updated = module.migrate(
        tmp_path, previous, refresh_unresolved=True, refresh_reviewed=True
    )
    assert updated["namespace"].get("consequence_graph") == graph


def test_migration_retains_exact_instance_selection_even_if_files_are_unavailable(
    tmp_path, monkeypatch
):
    from verifier.domains.contracts import object_facets

    module, document = _migration_fixture(tmp_path, monkeypatch)
    previous = module.migrate(tmp_path, document)
    selection = {
        "object_id": "vstd-package-object",
        "coordinate": object_facets.COORDINATE,
        "semantic_version": object_facets.SEMANTIC_VERSION,
        "proposition_digest": object_facets.PROPOSITION_DIGEST,
        "reason": "Explicit retained fixture selection.",
        "evidence": [],
        **{
            name: {"path": name + ".json", "sha256": "sha256:" + "a" * 64}
            for name in ("request", "policy", "certificate")
        },
    }
    previous["namespace"]["instance_checks"] = [selection]
    updated = module.migrate(
        tmp_path, previous, refresh_unresolved=True, refresh_reviewed=True
    )
    assert updated["namespace"]["instance_checks"] == [selection]


def test_explicit_structural_selection_replacement_retains_graph_evidence(
    tmp_path, monkeypatch
):
    from verifier.domains.contracts import graph_statics, object_facets

    module, document = _migration_fixture(tmp_path, monkeypatch)
    previous = module.migrate(tmp_path, document)

    def selection(object_id, route):
        return {
            "object_id": object_id,
            "coordinate": route.COORDINATE,
            "semantic_version": route.SEMANTIC_VERSION,
            "proposition_digest": route.PROPOSITION_DIGEST,
            "reason": "Exact historical instance selection.",
            "evidence": [],
            **{
                name: {
                    "path": name + ".json",
                    "sha256": "sha256:" + "a" * 64,
                }
                for name in ("request", "policy", "certificate")
            },
        }

    structural = selection("vstd-package-object", object_facets)
    graph = selection("vstd-package-graph", graph_statics)
    previous["namespace"]["instance_checks"] = [structural, graph]

    updated = module.migrate(
        tmp_path, previous, replace_structural_instance_checks=True
    )
    assert updated["namespace"]["instance_checks"] == [graph]
    transition = module._instance_check_transition(previous, updated)
    assert transition["prior_count"] == 2
    assert transition["current_count"] == 1
    assert transition["replaced_count"] == 1
    assert transition["replaced"][0]["object_id"] == "vstd-package-object"
    assert transition["replaced"][0]["coordinate"] == object_facets.COORDINATE
    assert module.migrate(
        tmp_path, updated, replace_structural_instance_checks=True
    ) == updated


def _instance_selection(object_id, route, stem):
    return {
        "object_id": object_id,
        "coordinate": route.COORDINATE,
        "semantic_version": route.SEMANTIC_VERSION,
        "proposition_digest": route.PROPOSITION_DIGEST,
        "reason": "Exact historical instance selection.",
        "evidence": [],
        **{
            name: {
                "path": f"{stem}-{name}.json",
                "sha256": "sha256:" + "a" * 64,
            }
            for name in ("request", "policy", "certificate")
        },
    }


def _enriched_package_graph_adapter_basis(
    module, tmp_path, monkeypatch, previous
):
    """Install the exact synthetic basis consumed by the fresh GRAPH adapter."""
    from verifier.core.namespace import NamespaceObject
    from verifier.runtime import (
        namespace_discovery,
        namespace_manifest,
        package_graph_representation,
    )

    graph_source = "src/verifier/domains/contracts/graph_statics.py"
    source_digest = "sha256:" + "b" * 64
    observed = deepcopy(namespace_discovery.discover(tmp_path))
    observed["surfaces"].append(
        {
            "path": graph_source,
            "surface_id": "file:" + graph_source,
            "hints": [],
            "source_kinds": [],
        }
    )
    observed["census"]["files"].append(
        {"path": graph_source, "sha256": source_digest}
    )
    monkeypatch.setattr(
        namespace_discovery, "discover", lambda root: deepcopy(observed)
    )

    graph = next(
        row
        for row in previous["namespace"]["objects"]
        if row["object_id"] == "vstd-package-graph"
    )
    graph["surfaces"].append("file:" + graph_source)
    binding_set = module.canonical_bytes(
        [
            {
                "object_id": graph["object_id"],
                "classifications": ["GRAPH"],
                "obligations": ["GRAPH-3.1-directed-graph"],
            }
        ]
    ).decode("utf-8")
    profile_body = {
        "schema_version": "verifier-source-semantic-review-profile-1",
        "reason": "Synthetic current-source binding for retirement tests.",
        "binding_sets": [binding_set],
        "records": [
            graph_source
            + "\tpython-location-free-ast\t"
            + source_digest
            + "\t0"
        ],
    }
    graph["payload"] = {
        "element_kind": "OBJECT",
        "scope": "retained_directed_graph",
        "nodes_digest": "sha256:" + "1" * 64,
        "edges_digest": "sha256:" + "2" * 64,
        "source_refresh_coordinate": "sha256:" + "c" * 64,
        "source_semantic_profile": {
            **profile_body,
            "digest": module.value_digest(profile_body),
        },
    }
    registry = namespace_manifest.validate_manifest(previous["namespace"])
    current_objects = []
    for row in previous["namespace"]["objects"]:
        payload = deepcopy(row["payload"])
        kind = module.namespace_contracts.ancestors(registry, row["kind"])[-1]
        if kind == "GRAPH":
            payload["element_kind"] = module.namespace_contracts.ancestors(
                registry, payload["element_kind"]
            )[-1]
        current_objects.append(
            NamespaceObject.create(
                row["object_id"], kind, payload, row["operands"]
            )
        )
    graph_inputs = package_graph_representation.dependency_inputs(
        tuple(current_objects), graph["object_id"]
    )
    graph["payload"]["nodes_digest"] = module.value_digest(graph_inputs["nodes"])
    graph["payload"]["edges_digest"] = module.value_digest(graph_inputs["edges"])
    retained_graph = next(
        item
        for item in tier_zero_manifest._namespace_objects(previous["objects"])
        if item.object_id == graph["object_id"]
    )
    previous["schema_version"] = package_manifest.REPRESENTATION_SCHEMA
    previous["representation_updates"] = [
        {
            "object_id": graph["object_id"],
            "retained_object_digest": retained_graph.digest,
            "current_object_digest": NamespaceObject.create(
                graph["object_id"], "GRAPH", graph["payload"], graph["operands"]
            ).digest,
            "reason": "Fresh package GRAPH adapter test representation.",
            "evidence": [{"path": graph_source, "sha256": source_digest}],
        }
    ]
    package_manifest.validate_bridge(previous)
    return previous


def test_explicit_package_graph_selection_retirement_is_exact_and_idempotent(
    tmp_path, monkeypatch
):
    from verifier.domains.contracts import graph_order, graph_statics, object_facets

    module, document = _migration_fixture(tmp_path, monkeypatch)
    previous = module.migrate(tmp_path, document)
    previous = _enriched_package_graph_adapter_basis(
        module, tmp_path, monkeypatch, previous
    )

    structural = _instance_selection(
        "vstd-package-object", object_facets, "structural"
    )
    package_graph_order = _instance_selection(
        "vstd-package-graph", graph_order, "package-graph-order"
    )
    package_graph_statics = _instance_selection(
        "vstd-package-graph", graph_statics, "package-graph-statics"
    )
    previous["namespace"]["instance_checks"] = [
        structural,
        package_graph_order,
        package_graph_statics,
    ]

    updated = module.migrate(
        tmp_path, previous, retire_package_graph_instance_check=True
    )
    assert updated["namespace"]["instance_checks"] == [
        structural,
        package_graph_order,
    ]
    transition = module._instance_check_transition(previous, updated)
    assert transition == {
        "prior_count": 3,
        "current_count": 2,
        "replaced_count": 1,
        "replaced": [
            {
                "object_id": "vstd-package-graph",
                "coordinate": graph_statics.COORDINATE,
                "semantic_version": graph_statics.SEMANTIC_VERSION,
                "selection_digest": module.value_digest(package_graph_statics),
                "replacement_mechanism": "fresh-source-bound-package-graph-replay",
                "reason": (
                    "The fresh source-bound package GRAPH adapter binds the complete "
                    "current object and collection and explicitly projects only the "
                    "registered four-field statics layout. This retires only the "
                    "package-root GRAPH-3.1 selection; it is not a generic graph "
                    "selection replacement. The historical evidence artifacts remain "
                    "on disk but are no longer an active package selection."
                ),
            }
        ],
    }
    assert module.selected_refresh_options(updated)[
        "retire_package_graph_instance_check"
    ] is False
    assert "advance_harness_launch_profile" not in module.selected_refresh_options(
        updated
    )
    assert module.migrate(
        tmp_path, updated, retire_package_graph_instance_check=True
    ) == updated


def test_package_graph_retirement_refuses_unenriched_additive_manifest(
    tmp_path, monkeypatch
):
    from verifier.domains.contracts import graph_statics

    module, document = _migration_fixture(tmp_path, monkeypatch)
    previous = module.migrate(tmp_path, document)
    previous["namespace"]["instance_checks"] = [
        _instance_selection(
            "vstd-package-graph", graph_statics, "package-graph-statics"
        )
    ]

    with pytest.raises(
        ValueError,
        match="PACKAGE_MIGRATION_PACKAGE_GRAPH_ADAPTER_PAYLOAD_INVALID",
    ):
        module.migrate(
            tmp_path,
            previous,
            retire_package_graph_instance_check=True,
        )


def test_package_graph_retirement_refuses_malformed_source_semantic_profile(
    tmp_path, monkeypatch
):
    from verifier.core.namespace import NamespaceObject
    from verifier.domains.contracts import graph_statics

    module, document = _migration_fixture(tmp_path, monkeypatch)
    previous = _enriched_package_graph_adapter_basis(
        module, tmp_path, monkeypatch, module.migrate(tmp_path, document)
    )
    graph = next(
        row
        for row in previous["namespace"]["objects"]
        if row["object_id"] == "vstd-package-graph"
    )
    graph["payload"]["source_semantic_profile"]["digest"] = (
        "sha256:" + "d" * 64
    )
    previous["representation_updates"][0]["current_object_digest"] = (
        NamespaceObject.create(
            graph["object_id"], "GRAPH", graph["payload"], graph["operands"]
        ).digest
    )
    previous["namespace"]["instance_checks"] = [
        _instance_selection(
            "vstd-package-graph", graph_statics, "package-graph-statics"
        )
    ]

    with pytest.raises(
        ValueError,
        match="PACKAGE_GRAPH_SOURCE_SEMANTIC_PROFILE_INVALID",
    ):
        module.migrate(
            tmp_path,
            previous,
            retire_package_graph_instance_check=True,
        )


@pytest.mark.parametrize("field", ("nodes_digest", "edges_digest"))
def test_package_graph_retirement_refuses_wrong_dependency_commitment(
    tmp_path, monkeypatch, field
):
    from verifier.core.namespace import NamespaceObject
    from verifier.domains.contracts import graph_statics

    module, document = _migration_fixture(tmp_path, monkeypatch)
    previous = _enriched_package_graph_adapter_basis(
        module, tmp_path, monkeypatch, module.migrate(tmp_path, document)
    )
    graph = next(
        row
        for row in previous["namespace"]["objects"]
        if row["object_id"] == "vstd-package-graph"
    )
    graph["payload"][field] = "sha256:" + "f" * 64
    previous["representation_updates"][0]["current_object_digest"] = (
        NamespaceObject.create(
            graph["object_id"], "GRAPH", graph["payload"], graph["operands"]
        ).digest
    )
    previous["namespace"]["instance_checks"] = [
        _instance_selection(
            "vstd-package-graph", graph_statics, "package-graph-statics"
        )
    ]

    with pytest.raises(
        ValueError,
        match="PACKAGE_MIGRATION_PACKAGE_GRAPH_DEPENDENCY_COMMITMENT_DIFFERS",
    ):
        module.migrate(
            tmp_path,
            previous,
            retire_package_graph_instance_check=True,
        )


@pytest.mark.parametrize(
    ("mutation", "error"),
    (
        (
            "digest",
            "PACKAGE_MIGRATION_PACKAGE_GRAPH_REPRESENTATION_INVALID",
        ),
        (
            "no-evidence",
            "PACKAGE_MIGRATION_PACKAGE_GRAPH_REPRESENTATION_INVALID",
        ),
        (
            "unowned-evidence",
            "PACKAGE_MIGRATION_PACKAGE_GRAPH_REPRESENTATION_EVIDENCE_INVALID",
        ),
    ),
)
def test_package_graph_retirement_refuses_invalid_final_representation_update(
    tmp_path, monkeypatch, mutation, error
):
    from verifier.domains.contracts import graph_statics

    module, document = _migration_fixture(tmp_path, monkeypatch)
    previous = _enriched_package_graph_adapter_basis(
        module, tmp_path, monkeypatch, module.migrate(tmp_path, document)
    )
    previous["namespace"]["instance_checks"] = [
        _instance_selection(
            "vstd-package-graph", graph_statics, "package-graph-statics"
        )
    ]
    refresh = module._refreshed_representation_updates

    def invalid_update(*args, **kwargs):
        updates = refresh(*args, **kwargs)
        graph_update = next(
            row
            for row in updates
            if row["object_id"] == "vstd-package-graph"
        )
        if mutation == "digest":
            graph_update["current_object_digest"] = "sha256:" + "e" * 64
        elif mutation == "no-evidence":
            graph_update["evidence"] = []
        else:
            graph_update["evidence"] = [
                {
                    "path": "src/verifier/runtime/namespace_cli.py",
                    "sha256": "sha256:" + "a" * 64,
                }
            ]
        return updates

    monkeypatch.setattr(module, "_refreshed_representation_updates", invalid_update)
    with pytest.raises(ValueError, match=error):
        module.migrate(
            tmp_path,
            previous,
            retire_package_graph_instance_check=True,
        )


def test_structural_selection_replacement_refuses_unclassifiable_route(
    tmp_path, monkeypatch
):
    from verifier.domains.contracts import object_facets

    module, document = _migration_fixture(tmp_path, monkeypatch)
    previous = module.migrate(tmp_path, document)
    check = {
        "object_id": "vstd-package-object",
        "coordinate": object_facets.COORDINATE,
        "semantic_version": "unsupported-route-family",
        "proposition_digest": object_facets.PROPOSITION_DIGEST,
        "reason": "Contrary selection must fail closed.",
        "evidence": [],
        **{
            name: {
                "path": name + ".json",
                "sha256": "sha256:" + "a" * 64,
            }
            for name in ("request", "policy", "certificate")
        },
    }
    previous["namespace"]["instance_checks"] = [check]
    with pytest.raises(ValueError):
        module.migrate(
            tmp_path, previous, replace_structural_instance_checks=True
        )


def test_migration_preserves_execution_opt_in_without_rebinding_source(
    tmp_path, monkeypatch
):
    module, document = _migration_fixture(tmp_path, monkeypatch)
    previous = module.migrate(tmp_path, document)
    selection = {
        "object_id": "vstd-invocation-ledger",
        "mechanism": "verifier-local-invocation-ledger-1",
        "reason": "An explicit operator selection, not permission to refresh stale evidence.",
        "evidence": [{"path": "prior.py", "sha256": "sha256:" + "a" * 64}],
    }
    previous["namespace"]["execution_checks"] = [selection]
    updated = module.migrate(
        tmp_path, previous, refresh_unresolved=True, refresh_reviewed=True
    )
    assert updated["namespace"]["execution_checks"] == [selection]


def test_manifest_execution_selection_requires_exact_source_and_preserves_prior_bindings(
    tmp_path, monkeypatch
):
    from pathlib import Path
    from verifier.runtime import manifest_write_execution, namespace_discovery

    module, document = _migration_fixture(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="PUBLICATION_IMPLEMENTATION_DIFFERS"):
        module.migrate(tmp_path, document, select_manifest_publication=True)
    observed = namespace_discovery.discover(tmp_path)
    source_digest = module.bytes_digest(
        Path(manifest_write_execution.__file__)
        .with_name("namespace_cli.py")
        .read_bytes()
    )
    next(
        row
        for row in observed["census"]["files"]
        if row["path"] == manifest_write_execution.IMPLEMENTATION
    )["sha256"] = source_digest
    monkeypatch.setattr(
        namespace_discovery, "discover", lambda root: deepcopy(observed)
    )
    previous = module.migrate(tmp_path, document)
    assert "execution_checks" not in previous["namespace"], (
        "Ordinary migration must not opt into execution."
    )
    ledger = {
        "object_id": "vstd-manifest-write",
        "mechanism": "verifier-local-invocation-ledger-1",
        "reason": "Preserve this deliberately stale selection.",
        "evidence": [{"path": "prior.py", "sha256": "sha256:" + "a" * 64}],
    }
    previous["namespace"]["execution_checks"] = [ledger]
    updated = module.migrate(tmp_path, previous, select_manifest_publication=True)
    checks = updated["namespace"]["execution_checks"]
    assert len(checks) == 2 and checks[0] == ledger
    assert checks[1]["mechanism"] == manifest_write_execution.ADAPTER
    assert (
        module.migrate(tmp_path, updated, select_manifest_publication=True)[
            "namespace"
        ]["execution_checks"]
        == checks
    )
    checks[1]["evidence"][0]["sha256"] = "sha256:" + "0" * 64
    with pytest.raises(ValueError, match="EXECUTION_SELECTION_CONFLICT"):
        module.migrate(tmp_path, updated, select_manifest_publication=True)


def test_worker_protocol_opt_in_preserves_other_roles_and_refuses_conflicts(
    tmp_path, monkeypatch
):
    from pathlib import Path
    from verifier.runtime import (
        worker_protocol_execution as execution,
        namespace_discovery,
    )

    module, document = _migration_fixture(tmp_path, monkeypatch)
    target = tmp_path / execution.IMPLEMENTATION
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(
        Path(execution.__file__).with_name("package_execution.py").read_bytes()
    )
    observed = namespace_discovery.discover(tmp_path)
    observed["surfaces"].append(
        {
            "path": execution.IMPLEMENTATION,
            "surface_id": "file:" + execution.IMPLEMENTATION,
            "hints": ["PROTOCOL"],
            "source_kinds": ["PROTOCOL"],
        }
    )
    source = {
        "path": execution.IMPLEMENTATION,
        "sha256": module.bytes_digest(target.read_bytes()),
    }
    observed["census"]["files"].append(source)
    monkeypatch.setattr(
        namespace_discovery, "discover", lambda root: deepcopy(observed)
    )
    previous = module.migrate(tmp_path, document)
    owner = next(
        row for row in previous["namespace"]["objects"] if row["kind"] == "VERIFIER"
    )
    prior = {
        "object_id": owner["object_id"],
        "mechanism": "verifier-local-invocation-ledger-1",
        "reason": "Keep another selected mechanism byte-for-byte.",
        "evidence": [],
    }
    previous["namespace"]["execution_checks"] = [prior]
    updated = module.migrate(tmp_path, previous, select_worker_protocol=True)
    selected = next(
        row for row in updated["namespace"]["objects"] if row["kind"] == "VERIFIER"
    )
    assert (
        selected["specializations"] == ["PROTOCOL"]
        and selected["classification"]["PROTOCOL"]["status"] == "APPLIES"
    )
    assert all(
        binding["reason"] and all(binding["declaration"].values())
        for name, binding in selected["obligations"].items()
        if name.startswith("PROTOCOL-")
    )
    assert updated["namespace"]["execution_checks"][0] == prior
    assert module.migrate(tmp_path, updated, select_worker_protocol=True) == updated
    assert (
        updated["objects"] == previous["objects"]
        and updated["obligation_denominator"] == previous["obligation_denominator"]
    )
    for field in ("reason", "evidence"):
        changed = deepcopy(updated)
        check = changed["namespace"]["execution_checks"][-1]
        check[field] = "different" if field == "reason" else []
        with pytest.raises(ValueError, match="EXECUTION_SELECTION_CONFLICT"):
            module.migrate(tmp_path, changed, select_worker_protocol=True)
    for field, code in (("classification", "DECISION"), ("obligations", "DECLARATION")):
        changed = deepcopy(updated)
        row = next(
            row for row in changed["namespace"]["objects"] if row["kind"] == "VERIFIER"
        )
        key = (
            "PROTOCOL"
            if field == "classification"
            else "PROTOCOL-0.1-participants-and-states"
        )
        row[field][key]["reason"] = "Separately selected evidence must survive."
        with pytest.raises(ValueError, match="PROTOCOL_" + code + "_CONFLICT"):
            module.migrate(tmp_path, changed, select_worker_protocol=True)
    target.write_bytes(b"changed implementation")
    source["sha256"] = module.bytes_digest(target.read_bytes())
    with pytest.raises(ValueError, match="PROTOCOL_IMPLEMENTATION_DIFFERS"):
        module.migrate(tmp_path, updated, select_worker_protocol=True)


def _semantic_execution_fixture(tmp_path, monkeypatch):
    """Expose the two selected implementations under exact semantic owners."""
    from pathlib import Path
    from verifier.runtime import (
        namespace_discovery,
        package_semantic_review_operations,
        package_semantic_review_records,
    )
    from verifier.runtime.package_semantic_ownership import SemanticOwnershipSpec

    module, document = _migration_fixture(tmp_path, monkeypatch)
    worker_paths = tuple(
        package_semantic_review_operations.review_document()[
            "vstd-package-worker-exchange"
        ]["owned_paths"]
    )
    policy_paths = tuple(
        package_semantic_review_records.review_document()[
            "vstd-dataset-provenance-policy"
        ]["owned_paths"]
    )
    repository = Path(__file__).resolve().parents[1]
    sources = {
        path: repository / path for path in (*worker_paths, *policy_paths)
    }
    observed = _add_discovered_files(tmp_path, monkeypatch, tuple(sources))
    references = {}
    for path, source in sources.items():
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
        reference = next(
            item for item in observed["census"]["files"] if item["path"] == path
        )
        reference["sha256"] = module.bytes_digest(target.read_bytes())
        references[path] = deepcopy(reference)
    monkeypatch.setattr(
        namespace_discovery, "discover", lambda root: deepcopy(observed)
    )
    specs = (
        SemanticOwnershipSpec(
            object_id="vstd-package-worker-exchange",
            primary_kind="PROTOCOL",
            specializations=(),
            owned_paths=worker_paths,
            representation_role="Exact selected package worker implementation.",
            necessity_reason="The selected exchange needs a source-specific owner.",
            consequence_boundary="No host-authentication or confinement claim.",
        ),
        SemanticOwnershipSpec(
            object_id="vstd-dataset-provenance-policy",
            primary_kind="POLICY",
            specializations=(),
            owned_paths=policy_paths,
            representation_role="Exact selected provenance-policy implementation.",
            necessity_reason="The selected policy needs a source-specific owner.",
            consequence_boundary="No provenance-truth or enforcement claim.",
        ),
    )
    monkeypatch.setattr(
        module.package_semantic_ownership, "validate_catalog", lambda root: specs
    )
    monkeypatch.setattr(
        module.package_semantic_ownership, "SEMANTIC_OWNERSHIP_SPECS", specs
    )
    return module, document, specs, references


def _pre_semantic_execution_checks(references):
    from verifier.runtime import (
        provenance_policy_execution,
        worker_protocol_execution,
    )

    return [
        {
            "object_id": "verifier-core-self",
            "mechanism": worker_protocol_execution.ADAPTER,
            "reason": "Retained exact worker selection.",
            "evidence": [references[worker_protocol_execution.IMPLEMENTATION]],
        },
        {
            "object_id": "vstd-package-object",
            "mechanism": provenance_policy_execution.ADAPTER,
            "reason": "Retained exact policy selection.",
            "evidence": [references[provenance_policy_execution.IMPLEMENTATION]],
        },
    ]


def test_semantic_install_rehomes_retained_execution_checks_without_rewriting_them(
    tmp_path, monkeypatch
):
    module, document, specs, references = _semantic_execution_fixture(
        tmp_path, monkeypatch
    )
    previous = module.migrate(tmp_path, document)
    retained = _pre_semantic_execution_checks(references)
    previous["namespace"]["execution_checks"] = deepcopy(retained)

    migrated = module.migrate(
        tmp_path, previous, install_semantic_ownership=True
    )
    checks = migrated["namespace"]["execution_checks"]
    assert [check["object_id"] for check in checks] == [
        "vstd-package-worker-exchange",
        "vstd-dataset-provenance-policy",
    ]
    for check, before in zip(checks, retained):
        assert {key: value for key, value in check.items() if key != "object_id"} == {
            key: value for key, value in before.items() if key != "object_id"
        }
    assert {spec.object_id for spec in specs} <= {
        row["object_id"] for row in migrated["namespace"]["objects"]
    }
    assert module.migrate(tmp_path, migrated) == migrated


def test_semantic_execution_rehome_refuses_unbound_evidence_and_owner_conflicts(
    tmp_path, monkeypatch
):
    module, document, _, references = _semantic_execution_fixture(
        tmp_path, monkeypatch
    )
    previous = module.migrate(tmp_path, document)
    checks = _pre_semantic_execution_checks(references)
    checks[0]["evidence"] = []
    previous["namespace"]["execution_checks"] = checks
    with pytest.raises(
        ValueError,
        match="EXECUTION_EVIDENCE_DOES_NOT_BIND_IMPLEMENTATION",
    ):
        module.migrate(tmp_path, previous, install_semantic_ownership=True)

    checks = _pre_semantic_execution_checks(references)
    duplicate = deepcopy(checks[0])
    duplicate["object_id"] = "vstd-package-worker-exchange"
    previous["namespace"]["execution_checks"] = [checks[0], duplicate]
    with pytest.raises(
        ValueError,
        match="EXECUTION_SEMANTIC_OWNER_CONFLICT",
    ):
        module.migrate(tmp_path, previous, install_semantic_ownership=True)


def test_semantic_execution_rehome_refuses_ambiguous_or_invalid_ownership(
    tmp_path, monkeypatch
):
    from verifier.runtime import worker_protocol_execution
    from verifier.runtime.package_semantic_ownership import SemanticOwnershipSpec

    module, document, specs, _ = _semantic_execution_fixture(tmp_path, monkeypatch)
    duplicate = SemanticOwnershipSpec(
        object_id="vstd-second-worker-owner",
        primary_kind="PROTOCOL",
        specializations=(),
        owned_paths=(worker_protocol_execution.IMPLEMENTATION,),
        representation_role="Conflicting selected implementation owner.",
        necessity_reason="Synthetic ambiguity must be rejected.",
        consequence_boundary="Test-only invalid catalog.",
    )
    ambiguous = (*specs, duplicate)
    monkeypatch.setattr(
        module.package_semantic_ownership,
        "validate_catalog",
        lambda root: ambiguous,
    )
    monkeypatch.setattr(
        module.package_semantic_ownership,
        "SEMANTIC_OWNERSHIP_SPECS",
        ambiguous,
    )
    with pytest.raises(ValueError, match="OWNERSHIP_PATH_AMBIGUOUS"):
        module.migrate(tmp_path, document, install_semantic_ownership=True)

    path = worker_protocol_execution.IMPLEMENTATION
    with pytest.raises(ValueError, match="SEMANTIC_OWNER_INVALID"):
        module._require_unique_semantic_execution_owner(
            path, "owner", {"owner": {"surfaces": []}}
        )
    with pytest.raises(ValueError, match="SEMANTIC_OWNER_AMBIGUOUS"):
        module._require_unique_semantic_execution_owner(
            path,
            "owner",
            {
                "owner": {"surfaces": ["file:" + path]},
                "other": {"surfaces": ["file:" + path]},
            },
        )


def test_explicit_execution_selectors_use_semantic_owners_when_active(
    tmp_path, monkeypatch
):
    from verifier.runtime import (
        provenance_policy_execution,
        worker_protocol_execution,
    )

    module, document, _, _ = _semantic_execution_fixture(tmp_path, monkeypatch)
    migrated = module.migrate(
        tmp_path,
        document,
        install_semantic_ownership=True,
        select_worker_protocol=True,
        select_provenance_policy=True,
    )
    selected = {
        check["mechanism"]: check["object_id"]
        for check in migrated["namespace"]["execution_checks"]
    }
    assert selected == {
        worker_protocol_execution.ADAPTER: "vstd-package-worker-exchange",
        provenance_policy_execution.ADAPTER: "vstd-dataset-provenance-policy",
    }


def test_semantic_execution_owner_uses_only_an_exact_unique_fallback():
    from verifier.runtime import token_asset_execution

    module = migration_module
    path = token_asset_execution.IMPLEMENTATION
    surface = "file:" + path
    fallback = {"object_id": "vstd-token", "surfaces": [surface]}
    assert module._execution_owner_row(
        {"vstd-token": fallback},
        {},
        semantic_active=True,
        mechanism=token_asset_execution.ADAPTER,
        fallback_owner="vstd-token",
    ) is fallback

    with pytest.raises(ValueError, match="EXECUTION_SEMANTIC_OWNER_INVALID"):
        module._execution_owner_row(
            {"vstd-token": {"object_id": "vstd-token", "surfaces": []}},
            {},
            semantic_active=True,
            mechanism=token_asset_execution.ADAPTER,
            fallback_owner="vstd-token",
        )
    with pytest.raises(ValueError, match="EXECUTION_SEMANTIC_OWNER_INVALID"):
        module._execution_owner_row(
            {
                "vstd-token": {"object_id": "vstd-token", "surfaces": []},
                "wrong": {"object_id": "wrong", "surfaces": [surface]},
            },
            {},
            semantic_active=True,
            mechanism=token_asset_execution.ADAPTER,
            fallback_owner="vstd-token",
        )
    with pytest.raises(ValueError, match="EXECUTION_SEMANTIC_OWNER_AMBIGUOUS"):
        module._execution_owner_row(
            {
                "vstd-token": fallback,
                "wrong": {"object_id": "wrong", "surfaces": [surface]},
            },
            {},
            semantic_active=True,
            mechanism=token_asset_execution.ADAPTER,
            fallback_owner="vstd-token",
        )

    semantic = {"object_id": "semantic-token", "surfaces": [surface]}
    assert module._execution_owner_row(
        {
            "vstd-token": {"object_id": "vstd-token", "surfaces": []},
            "semantic-token": semantic,
        },
        {path: "semantic-token"},
        semantic_active=True,
        mechanism=token_asset_execution.ADAPTER,
        fallback_owner="vstd-token",
    ) is semantic


def _package_graph_commitment_rows(commitments):
    """Synthetic final rows: a GRAPH root over three members with two operand edges."""

    def member(object_id, operands):
        return {
            "object_id": object_id,
            "kind": "OBJECT",
            "specializations": [],
            "payload": {"representation_role": "Synthetic member " + object_id},
            "operands": operands,
            "surfaces": [],
            "reason": "Synthetic member for the dependency commitment tests.",
            "classification": {},
            "obligations": {},
        }

    rows = {
        "root": {
            "object_id": "root",
            "kind": "GRAPH",
            "specializations": [],
            "payload": {
                "element_kind": "OBJECT",
                "scope": "retained_directed_graph",
                **commitments,
                "source_refresh_coordinate": "sha256:" + "c" * 64,
            },
            "operands": {"members": ["a", "b", "c"]},
            "surfaces": [],
            "reason": "Synthetic package root.",
            "classification": {},
            "obligations": {},
        },
        "a": member("a", {"uses": ["b", "c"]}),
        "b": member("b", {"uses": ["c"]}),
        "c": member("c", {}),
    }
    return rows


def _independent_graph_commitments(rows):
    """Recompute the commitments exactly as the fresh GRAPH adapter does."""

    from verifier.core.namespace import NamespaceObject
    from verifier.runtime import package_graph_representation

    registry = migration_module.namespace_contracts.namespace_registry()
    objects = []
    for row in rows.values():
        payload = deepcopy(row["payload"])
        kind = migration_module.namespace_contracts.ancestors(registry, row["kind"])[-1]
        if kind == "GRAPH":
            payload["element_kind"] = migration_module.namespace_contracts.ancestors(
                registry, payload["element_kind"]
            )[-1]
        objects.append(NamespaceObject.create(row["object_id"], kind, payload, row["operands"]))
    inputs = package_graph_representation.dependency_inputs(tuple(objects), "root")
    return {
        "nodes_digest": migration_module.value_digest(inputs["nodes"]),
        "edges_digest": migration_module.value_digest(inputs["edges"]),
    }


def test_refresh_rederives_stale_package_graph_dependency_commitments():
    """A refresh that changes membership must not leave the root declaring old arrays."""

    stale = {"nodes_digest": "sha256:" + "0" * 64, "edges_digest": "sha256:" + "1" * 64}
    rows = _package_graph_commitment_rows(stale)
    registry = migration_module.namespace_contracts.namespace_registry()

    migration_module._refresh_package_graph_dependency_commitments(rows, registry, "root")

    expected = _independent_graph_commitments(rows)
    assert expected["nodes_digest"] != stale["nodes_digest"]
    assert {
        field: rows["root"]["payload"][field] for field in expected
    } == expected
    # Only the two derived commitments move; every other declaration is untouched.
    assert rows["root"]["payload"]["source_refresh_coordinate"] == "sha256:" + "c" * 64
    assert rows["root"]["operands"] == {"members": ["a", "b", "c"]}


def test_refresh_leaves_a_package_graph_without_commitments_untouched():
    rows = _package_graph_commitment_rows({})
    before = deepcopy(rows)
    registry = migration_module.namespace_contracts.namespace_registry()

    migration_module._refresh_package_graph_dependency_commitments(rows, registry, "root")

    assert rows == before


def test_refresh_refuses_to_commit_an_incomplete_package_graph():
    stale = {"nodes_digest": "sha256:" + "0" * 64, "edges_digest": "sha256:" + "1" * 64}
    rows = _package_graph_commitment_rows(stale)
    rows["root"]["operands"]["members"].remove("c")
    before = deepcopy(rows)
    registry = migration_module.namespace_contracts.namespace_registry()

    with pytest.raises(
        ValueError,
        match="PACKAGE_MIGRATION_PACKAGE_GRAPH_DEPENDENCY_COMMITMENT_INVALID",
    ):
        migration_module._refresh_package_graph_dependency_commitments(
            rows, registry, "root"
        )
    assert rows == before
