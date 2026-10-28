"""Capacity boundaries for independent Verifier Standard (VSTD) reconciliation.

JavaScript Object Notation (JSON) receipts distinguish finite resource refusal
from semantic rejection.  Package manifest v5 increases only the transport and
structure envelope; extension review and derived-output work remain bounded.
"""
from __future__ import annotations

import json
from pathlib import Path
import shutil
from typing import Any

import pytest

from verifier.runtime import namespace_admission
from verifier.runtime import namespace_classification
from verifier.runtime import namespace_contracts
from verifier.runtime import namespace_manifest
from verifier.runtime import namespace_refutation
from verifier.runtime import namespace_workflows
from verifier.runtime import package_manifest
from verifier.runtime.tier_zero_manifest import (
    MAX_MANIFEST_NODES,
    MAX_PACKAGE_MANIFEST_BYTES,
    MAX_PACKAGE_MANIFEST_NODES,
)
from verifier.runtime.tier_zero_profile import canonical_bytes, value_digest
from verifier.runtime.tier_zero_reasoning import integration as reason_integration


CAPACITY = {"error": "NAMESPACE_RECONCILIATION_CAPACITY_EXHAUSTED"}
REJECTED = {"error": "NAMESPACE_RECONCILIATION_REJECTED"}
MIB = 1024 * 1024


def _extension(index: int) -> dict[str, Any]:
    kind = f"EXT{index:03d}"
    return {
        "kind": kind,
        "extends": "OBJECT",
        "version": "1",
        "reason": "Exercise the bounded additive extension review denominator.",
        "obligations": [
            {
                "id": f"{kind}-0.1-review",
                "name": "Extension review",
                "reason": "Every additive extension remains in the applicability review set.",
                "evidence_requirement": "Bind the selected source and applicability decision.",
            }
        ],
    }


def _object(
    index: int = 0,
    *,
    specializations: list[str] | None = None,
    surfaces: list[str] | None = None,
    classification: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "object_id": f"object-{index:04d}",
        "kind": "OBJECT",
        "specializations": list(specializations or []),
        "payload": {},
        "operands": {},
        "surfaces": list(surfaces or []),
        "reason": "This bounded synthetic object exercises reconciliation capacity.",
        "classification": dict(classification or {}),
        "obligations": {},
    }


def _manifest(
    *,
    extensions: list[dict[str, Any]] | None = None,
    objects: list[dict[str, Any]] | None = None,
) -> tuple[bytes, dict[str, namespace_contracts.KindContract]]:
    selected_extensions = list(extensions or [])
    registry = namespace_contracts.namespace_registry(selected_extensions)
    document = namespace_contracts.registry_document(registry)
    manifest = {
        "schema_version": namespace_manifest.SCHEMA,
        "registry_digest": document["digest"],
        "extensions": selected_extensions,
        "objects": list(objects or [_object()]),
    }
    return canonical_bytes(manifest) + b"\n", registry


def _payload(
    raw: bytes,
    registry: dict[str, namespace_contracts.KindContract],
    *,
    transport_profile: str = "STANDARD",
) -> dict[str, Any]:
    return {
        "manifest": raw.decode("utf-8"),
        "registry": namespace_contracts.registry_document(registry),
        "transport_profile": transport_profile,
        "javascript_mechanism": None,
        "markup_binding": {},
        "workflow_binding": {},
        "systems_mechanism": None,
        "surfaces": [],
        "files": [],
        "established_non_applicability": [],
        "nonstructural_role_decisions": [],
    }


def _node_executable() -> str:
    node = shutil.which("node")
    if node is None:
        pytest.skip(
            "OPTIONAL_DEPENDENCY_ABSENT: Node is unavailable for the independent "
            "namespace reconciler boundary."
        )
    return node


def _run_node(payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    result = namespace_admission._run_bounded_reconciler(
        [_node_executable(), str(Path(namespace_admission.__file__).with_name("namespace_reconcile.mjs"))],
        canonical_bytes(payload),
        output_limit=64 * MIB,
        stderr_limit=MIB,
        timeout_seconds=20,
    )
    assert result["status"] == "RETURNED"
    return result["returncode"], json.loads(result["stdout"])


def _observed(*, javascript_mechanism: Any = None) -> dict[str, Any]:
    return {
        "surfaces": [],
        "census": {"files": []},
        "export_bindings": [],
        "workflow_binding": dict(namespace_workflows.EMPTY),
        "javascript_mechanism": javascript_mechanism,
    }


def _classified() -> dict[str, Any]:
    return {
        "objects": [
            {
                "object_id": "object-0000",
                "required_obligation_ids": [],
                "effective_kinds": ["OBJECT"],
            }
        ]
    }


def test_v5_package_profile_expands_transport_capacity_without_promoting_unknown() -> None:
    """The package profile admits more structure; the legacy profile stays UNKNOWN."""
    _node_executable()
    assert package_manifest.PACKAGE_REPRESENTATION_SCHEMA == "verifier-objects-manifest-5"
    raw, registry = _manifest()
    mechanism = {"capacity_probe": [None] * MAX_MANIFEST_NODES}
    mechanism_nodes = namespace_manifest.structure_node_count(mechanism)
    assert MAX_MANIFEST_NODES < mechanism_nodes < MAX_PACKAGE_MANIFEST_NODES

    legacy = namespace_admission._reconcile(
        raw,
        registry,
        _observed(javascript_mechanism=mechanism),
        _classified(),
        package_transport=False,
    )
    package = namespace_admission._reconcile(
        raw,
        registry,
        _observed(javascript_mechanism=mechanism),
        _classified(),
        package_transport=True,
    )

    assert legacy == {
        "status": "UNKNOWN",
        "reason": (
            "The independent reconciler exhausted its declared finite work or "
            "output capacity."
        ),
        "receipt": CAPACITY,
    }
    assert package["status"] == "PASS"
    assert package["receipt"]["effective_kinds"] == {"object-0000": ["OBJECT"]}


def test_package_transport_scales_execution_deadline_with_wire_envelope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The 64 MiB package profile remains bounded but is not timed as 16 MiB."""

    _node_executable()
    raw, registry = _manifest()
    calls: list[tuple[int, int]] = []

    def unavailable(command, wire, *, output_limit, stderr_limit, timeout_seconds):
        calls.append((output_limit, timeout_seconds))
        return {"status": "UNKNOWN", "reason": "Synthetic bounded stop."}

    monkeypatch.setattr(
        namespace_admission, "_run_bounded_reconciler", unavailable
    )
    standard = namespace_admission._reconcile(
        raw, registry, _observed(), _classified(), package_transport=False
    )
    package = namespace_admission._reconcile(
        raw, registry, _observed(), _classified(), package_transport=True
    )

    assert standard == {"status": "UNKNOWN", "reason": "Synthetic bounded stop."}
    assert package == standard
    assert calls == [
        (16 * MIB, 20),
        (64 * MIB, 80),
    ]


def test_node_distinguishes_derived_work_capacity_from_semantic_rejection() -> None:
    extensions = [_extension(index) for index in range(128)]
    raw, registry = _manifest(
        extensions=extensions,
        objects=[_object(index) for index in range(509)],
    )
    bounded = _payload(raw, registry)
    assert len(canonical_bytes(bounded)) < 16 * MIB
    assert namespace_manifest.structure_node_count(bounded) < MAX_MANIFEST_NODES
    assert namespace_manifest.structure_node_count(json.loads(raw)) < MAX_MANIFEST_NODES

    capacity_code, capacity_receipt = _run_node(bounded)

    semantic_raw, semantic_registry = _manifest()
    semantic_document = json.loads(semantic_raw)
    semantic_document["registry_digest"] = "sha256:" + "0" * 64
    rejected_raw = canonical_bytes(semantic_document) + b"\n"
    rejected_code, rejected_receipt = _run_node(
        _payload(rejected_raw, semantic_registry)
    )
    mapped_rejection = namespace_admission._reconcile(
        rejected_raw,
        semantic_registry,
        _observed(),
        _classified(),
    )

    assert (capacity_code, capacity_receipt) == (1, CAPACITY)
    assert (rejected_code, rejected_receipt) == (1, REJECTED)
    assert mapped_rejection == {
        "status": "FAIL",
        "reason": "Independent declaration interpretation disagrees.",
        "receipt": REJECTED,
    }


def test_node_refuses_long_identifier_output_amplification_inside_standard_input_bounds() -> None:
    kind = "LONGBOUND"
    prefix = f"{kind}-0.1-"
    obligation_id = prefix + "x" * (8000 - len(prefix))
    extension = {
        "kind": kind,
        "extends": "OBJECT",
        "version": "1",
        "reason": "Exercise bounded derived-output amplification.",
        "obligations": [
            {
                "id": obligation_id,
                "name": "Long bounded identifier",
                "reason": "A valid identifier must not multiply into unbounded output.",
                "evidence_requirement": "Bind the selected source.",
            }
        ],
    }
    raw, registry = _manifest(
        extensions=[extension],
        objects=[_object(index, specializations=[kind]) for index in range(1600)],
    )
    payload = _payload(raw, registry)

    assert len(obligation_id) == 8000
    assert len(canonical_bytes(payload)) < 16 * MIB
    assert namespace_manifest.structure_node_count(payload) < MAX_MANIFEST_NODES
    assert namespace_manifest.structure_node_count(json.loads(raw)) < MAX_MANIFEST_NODES
    returncode, receipt = _run_node(payload)
    assert (returncode, receipt) == (1, CAPACITY)


def test_python_classification_counts_every_non_generic_kind_review_before_materializing_output() -> None:
    registry = namespace_contracts.namespace_registry([_extension(index) for index in range(128)])
    # Every semantic kind except generic OBJECT is an applicability question.
    # Counting only additive refinements would let an original AGENT/BOT/SIM
    # role escape both the capacity bound and the classification denominator.
    review_count = len(registry) - 1
    discovery = {"surfaces": [], "census": {"files": []}}

    with pytest.raises(ValueError, match="^NAMESPACE_DERIVATION_CAPACITY$"):
        namespace_classification.assess_classification(
            [_object()],
            registry,
            discovery,
            derived_item_limit=review_count - 1,
        )

    admitted = namespace_classification.assess_classification(
        [_object()],
        registry,
        discovery,
        derived_item_limit=review_count + 1,
    )
    assert admitted["derived_item_count"] == review_count + 1


def test_python_classification_uses_the_selected_package_manifest_envelope() -> None:
    """One authoritative package envelope bounds both input and derived output."""
    assert namespace_classification.MAX_DERIVED_BYTES is MAX_PACKAGE_MANIFEST_BYTES


def test_trigger_preview_does_not_duplicate_its_adjacent_exact_digest() -> None:
    selected, preview, digest = namespace_classification._trigger_summary(
        ["A repository-authored applicability trigger whose exact identity remains digest-bound. " * 4]
    )

    assert selected == [preview]
    assert digest.startswith("sha256:")
    assert digest not in preview
    assert preview.endswith("[1 triggers; digest adjacent]")
    assert len(preview.encode("utf-8")) <= namespace_classification.MAX_TRIGGER_SUMMARY_BYTES


def test_python_classification_accepts_its_exact_canonical_size_only() -> None:
    registry = namespace_contracts.namespace_registry()
    discovery = {"surfaces": [], "census": {"files": []}}
    baseline = namespace_classification.assess_classification(
        [_object()],
        registry,
        discovery,
        derived_byte_limit=MAX_PACKAGE_MANIFEST_BYTES,
    )
    exact_size = len(canonical_bytes(baseline))

    accepted = namespace_classification.assess_classification(
        [_object()],
        registry,
        discovery,
        derived_byte_limit=exact_size,
    )
    assert accepted == baseline
    with pytest.raises(ValueError, match="^NAMESPACE_DERIVATION_OUTPUT_CAPACITY$"):
        namespace_classification.assess_classification(
            [_object()],
            registry,
            discovery,
            derived_byte_limit=exact_size - 1,
        )


def test_current_package_classification_fits_without_losing_object_specific_rows() -> None:
    """The current graph plus sole-root applicability reasons fits exactly.

    The authored reasons retain obligations without editing the compiled
    registry or establishing semantic source truth.  Capacity must cover that
    real denominator, not a smaller reason-free approximation of it.
    """
    root = Path(__file__).resolve().parents[1]
    _, document = namespace_manifest.read_manifest(root / "objects.vstd")
    package_manifest.validate_bridge(document)
    namespace = json.loads(json.dumps(document["namespace"]))
    if namespace.get("schema_version") == namespace_manifest.COMPACT_SCHEMA:
        namespace = namespace_manifest.normalize_manifest(namespace)
    observed = namespace_admission.discovery.discover(root)
    current_files = {
        row["path"]: row["sha256"]
        for row in observed["census"]["files"]
    }
    for row in namespace["objects"]:
        bindings = [
            *row["classification"].values(),
            *row["obligations"].values(),
        ]
        for binding in bindings:
            for reference in binding["evidence"]:
                if reference["path"] in current_files:
                    reference["sha256"] = current_files[reference["path"]]
    registry = namespace_manifest.validate_manifest(namespace)
    consequence_report = namespace_admission.consequences.assess_consequences(
        namespace["objects"],
        registry,
        observed,
        namespace.get("consequence_graph"),
    )
    reason_selection = reason_integration.select_root_reasons(root)
    documented_answers = reason_integration.documented_applicability_answers(
        reason_selection, namespace["objects"]
    )

    classified = namespace_classification.assess_classification(
        namespace["objects"],
        registry,
        observed,
        consequence_kinds=consequence_report["required_kinds"],
        refutation_context=namespace_classification.refutation_context(
            observed,
            value_digest(namespace_admission.mechanism_binding()),
            root=root,
        ),
        documented_applicability_answers=documented_answers,
    )

    # Every object keeps one cell per installed non-OBJECT kind (37 for the 38-kind
    # namespace).  Without a refutation context no non-applicability is established, so
    # each sole-root APPLIES answer conservatively retains its kind's obligations;
    # these counts pin the current compiled-registry plus authored-reasons shape.
    assert len(classified["objects"]) == len(namespace["objects"]) == 468
    assert sum(len(row["classification"]) for row in classified["objects"]) == 468 * 37
    assert len(documented_answers) == 13_321
    # Retention-only roles stay in the demanded denominator but do not
    # manufacture structural financial agency.  The three sole-ledger APPLIES
    # decisions for the model, owner, and token FINBOT cells conservatively
    # restore nine kind obligations: three non-applicability findings are
    # replaced by nine open obligation-evidence findings.
    assert (
        len(classified["required_obligations"]),
        len(classified["findings"]),
    ) == (13_071, 8_763)
    contracts = {row["id"]: row for row in classified["obligation_contracts"]}
    assert contracts
    assert all(
        row["contract_digest"] == value_digest(contracts[row["id"]])
        for row in classified["required_obligations"]
    )
    assert all(
        row["detail_profile"] == "REQUIRED_OBLIGATION_REFERENCE"
        for row in classified["findings"]
        if row["code"] == "NAMESPACE_OBLIGATION_EVIDENCE_UNRESOLVED"
    )
    assert classified["derived_output_bytes"] == len(canonical_bytes(classified))
    assert classified["derived_output_bytes"] <= MAX_PACKAGE_MANIFEST_BYTES


def test_python_classification_bounds_long_identifier_output() -> None:
    kind = "LONGBOUND"
    prefix = f"{kind}-0.1-"
    obligation_id = prefix + "x" * (8000 - len(prefix))
    extension = {
        "kind": kind,
        "extends": "OBJECT",
        "version": "1",
        "reason": "Exercise bounded derived-output amplification.",
        "obligations": [
            {
                "id": obligation_id,
                "name": "Long bounded identifier",
                "reason": "A valid identifier must not multiply into unbounded output.",
                "evidence_requirement": "Bind the selected source.",
            }
        ],
    }
    registry = namespace_contracts.namespace_registry([extension])
    source_digest = "sha256:" + "1" * 64
    evidence = [{"path": "subject.py", "sha256": source_digest}]
    classification = {
        selected_kind: {
            "status": "APPLIES" if selected_kind == kind else "DOES_NOT_APPLY",
            "reason": "The exact bounded fixture records this applicability decision.",
            "evidence": evidence,
        }
        for selected_kind, contract in registry.items()
        if contract.extends is not None
    }
    row = _object(
        specializations=[kind],
        surfaces=["file:subject.py"],
        classification=classification,
    )
    discovery = {
        "surfaces": [
            {
                "surface_id": "file:subject.py",
                "path": "subject.py",
                "source_kinds": [],
                "hints": [],
                "unresolved_marker": False,
            }
        ],
        "census": {"files": [{"path": "subject.py", "sha256": source_digest}]},
    }

    with pytest.raises(ValueError, match="^NAMESPACE_DERIVATION_OUTPUT_CAPACITY$"):
        namespace_classification.assess_classification(
            [row],
            registry,
            discovery,
            derived_byte_limit=4096,
        )


def test_python_classification_compacts_repeated_pass_detail_by_exact_reference(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """A large green graph keeps identities exact without repeating source prose.

    No installed closure establishes DOES_NOT_APPLY (a clean scan is a bounded UNKNOWN),
    so a green graph of non-applicable kinds needs the stronger mechanism the standard
    reserves.  This test stands one in only to measure the output-compaction path.
    """
    registry = namespace_contracts.namespace_registry()
    established = namespace_refutation.Verdict(
        namespace_refutation.ESTABLISHED, "SYNTHETIC_STRONGER_MECHANISM", "",
        receipt={"receipt_digest": "sha256:" + "3" * 64, "closure_digest": "sha256:" + "4" * 64,
                 "decision_row_digest": "sha256:" + "5" * 64})
    monkeypatch.setattr(
        namespace_classification, "_non_applicability_verdict",
        lambda *_args, **_kwargs: established)
    source_digest = "sha256:" + "2" * 64
    evidence = [{"path": "subject.py", "sha256": source_digest}]
    long_text = "Bounded repository declaration: " + "x" * 4064
    ledger_contracts = namespace_contracts.requirements_for(registry, ["LEDGER"])
    expected_ids = {contract["id"] for contract in ledger_contracts}
    classification = {
        kind: {
            "status": "APPLIES" if kind == "LEDGER" else "DOES_NOT_APPLY",
            "reason": long_text if kind == "LEDGER" else
                "This fixture has no selected role for this installed semantic kind.",
            "evidence": evidence,
        }
        for kind in registry
        if kind != "OBJECT"
    }
    bindings = {
        contract["id"]: {
            "reason": long_text,
            "evidence": evidence,
            "declaration": {
                field: long_text
                for field in contract["declaration_fields"]
            },
        }
        for contract in ledger_contracts
    }
    rows = []
    for index in range(700):
        row = _object(
            index,
            specializations=["LEDGER"],
            surfaces=["file:subject.py"],
            classification=classification,
        )
        row["obligations"] = bindings
        rows.append(row)
    discovery = {
        "surfaces": [{
            "surface_id": "file:subject.py",
            "path": "subject.py",
            "source_kinds": [],
            "hints": [],
            "unresolved_marker": False,
        }],
        "census": {"files": [{"path": "subject.py", "sha256": source_digest}]},
    }
    # Each non-applicability needs its own current executable witness, because a
    # witness binds the object identity.  Decisions are copied per row for that reason.
    from verifier.runtime import namespace_admission
    from verifier.runtime.tier_zero_profile import value_digest
    mechanism = value_digest(namespace_admission.mechanism_binding())
    refutation_context = namespace_classification.refutation_context(discovery, mechanism)
    for row in rows:
        row["classification"] = {kind: dict(decision) for kind, decision in classification.items()}
        for kind, decision in row["classification"].items():
            if decision["status"] != "DOES_NOT_APPLY":
                continue
            expected = namespace_refutation.ExpectedReview(
                object_id=row["object_id"], kind=kind,
                basis=namespace_refutation.BASIS_EXECUTABLE_CLOSURE, review_module="subject_py",
                review_mechanism_digest=mechanism, review_row_digest=value_digest(decision))
            decision["refutation"] = namespace_refutation.build_witness(
                expected=expected, source_paths=["subject.py"], inventory=refutation_context["inventory"])

    # Repeating just the exact declaration maps exceeded the complete derived
    # output budget before compaction; the digest-bound result remains finite.
    repeated_declaration_bytes = sum(
        len(canonical_bytes(binding["declaration"]))
        for _ in rows
        for binding in bindings.values()
    )
    assert repeated_declaration_bytes > namespace_classification.MAX_DERIVED_BYTES

    result = namespace_classification.assess_classification(
        rows, registry, discovery, refutation_context=refutation_context)
    materialized = canonical_bytes(result)

    assert result["findings"] == []
    assert result["derived_output_bytes"] == len(materialized)
    assert len(materialized) < namespace_classification.MAX_DERIVED_BYTES
    assert len(result["required_obligations"]) == 700 * len(expected_ids)
    assert {row["id"] for row in result["required_obligations"]} == expected_ids
    assert {row["status"] for row in result["required_obligations"]} == {"PASS"}
    assert all(row["detail_profile"] == "BOUNDED_PASS_REFERENCE"
               for row in result["required_obligations"])

    by_id = {contract["id"]: contract for contract in ledger_contracts}
    first_object = result["objects"][0]
    for obligation in result["required_obligations"][:len(expected_ids)]:
        exact_binding = bindings[obligation["id"]]
        assert obligation["binding_reference"] == {
            "source": "objects.vstd",
            "object_id": "object-0000",
            "obligation_id": obligation["id"],
        }
        assert obligation["binding_digest"] == value_digest(exact_binding)
        assert obligation["contract_digest"] == value_digest(by_id[obligation["id"]])
        assert obligation["repository_reason_digest"] == value_digest(long_text)
        assert obligation["declaration_digest"] == value_digest(exact_binding["declaration"])
        assert set(obligation["declaration"]) == set(exact_binding["declaration"])
        assert all(len(value.encode("utf-8")) <=
                   namespace_classification.MAX_PASS_DECLARATION_VALUE_SUMMARY_BYTES
                   for value in obligation["declaration"].values())
        assert obligation["applicability_reason_digest"] == (
            first_object["kind_reason_digests"]["LEDGER"]
        )

    assert set(first_object["kind_reason_digests"]) == set(first_object["kind_reasons"])
    assert len(canonical_bytes(first_object["kind_reasons"]["LEDGER"])) <= 300

    # Compaction is never allowed to hide the prose needed to repair a row.
    damaged_id = sorted(expected_ids)[0]
    damaged = _object(
        9999,
        specializations=["LEDGER"],
        surfaces=["file:subject.py"],
        classification=classification,
    )
    damaged["obligations"] = {
        **bindings,
        damaged_id: {**bindings[damaged_id], "reason": ""},
    }
    unresolved = namespace_classification.assess_classification(
        [damaged], registry, discovery
    )
    unresolved_row = next(
        row for row in unresolved["required_obligations"]
        if row["id"] == damaged_id
    )
    assert unresolved_row["status"] == "UNKNOWN"
    assert "detail_profile" not in unresolved_row
    assert unresolved_row["declaration"] == bindings[damaged_id]["declaration"]
    assert long_text in unresolved_row["applicability_reason"]


def test_package_profile_node_ceiling_remains_finite() -> None:
    raw, registry = _manifest()
    payload = _payload(raw, registry, transport_profile="PACKAGE_GRAPH")
    payload["capacity_probe"] = [None] * MAX_PACKAGE_MANIFEST_NODES

    assert len(canonical_bytes(payload)) < 64 * MIB
    with pytest.raises(ValueError, match="NAMESPACE_MANIFEST_STRUCTURE_CAPACITY"):
        namespace_manifest.structure_node_count(payload)
    returncode, receipt = _run_node(payload)
    assert (returncode, receipt) == (1, CAPACITY)
