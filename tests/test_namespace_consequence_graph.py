"""Consequential graph checks without physical or financial execution.

Terminology: JavaScript Object Notation (JSON).

Verifier Standard (VSTD) tests use inert source files and declared edges. A
passing relation check never proves that a deployed system follows the graph.
"""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import json
import re
import shutil
import subprocess

import pytest

from verifier.runtime import (
    namespace_consequences,
    package_manifest_migration,
    package_manifest_refresh,
    package_original_kind_catalog_runtime,
    package_original_kind_catalog_retained,
    package_original_review_people,
    package_semantic_ownership_domains_agency_collective,
    package_semantic_review_commands,
    package_semantic_review_hardware_cli,
    package_semantic_review_partitions,
    package_semantic_review_verifier,
)
from verifier.runtime.namespace_admission import assess, assess_gate, build_template
from verifier.runtime.namespace_manifest import check_composition, validate_manifest
from verifier.runtime.namespace_contracts import namespace_registry
from verifier.runtime.tier_zero_profile import canonical_bytes


def fixture(root: Path) -> dict:
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    ids = {"agent": "AGENT", "harness": "HARNESS", "controller": "CONTROLLER",
           "actuator": "ACTUATOR", "ledger": "LEDGER", "delegate": "OBJECT",
           "bot": "BOT", "sim": "SIM", "model": "MODEL", "env": "ENV",
           "hardware": "HARDWARE", "train": "TRAIN", "data": "DATA",
           "event": "EVENT", "time": "TIME", "space": "SPACE",
           "bench": "BENCH", "arch": "ARCH", "verifier": "VERIFIER"}
    (root / "subject.py").write_text("raise RuntimeError('never execute the subject')\n" +
        "".join("def surface_" + str(index) + "(): pass\n" for index in range(len(ids))), encoding="utf-8")
    draft = build_template(root)
    evidence = draft["source_evidence"]
    operands = {
        "agent": {"model": ["model"], "harness": ["harness"], "env": ["env"]},
        "bot": {"agent": ["agent"], "sim": ["sim"], "env": ["env"]},
        "sim": {"data": ["data"], "verifier": ["verifier"], "objects": ["data"], "env": ["env"]},
        "model": {"train": ["train"], "data": ["data"], "events": ["event"], "bench": ["bench"],
                  "arch": ["arch"], "env": ["env"], "hardware": ["hardware"]},
        "train": {"data": ["data"], "events": ["event"], "bench": ["bench"], "arch": ["arch"]},
        "event": {"time": ["time"], "space": ["space"], "meaning": ["data"]},
        "bench": {"verifier": ["verifier"], "data": ["data"]},
    }
    template = draft["manifest"]["objects"][0]
    rows = []
    for index, (identifier, kind) in enumerate(ids.items()):
        row = deepcopy(template)
        row.update(object_id=identifier, kind=kind, operands=operands.get(identifier, {}),
                   surfaces=["python:subject.py:surface_" + str(index)] +
                            (["file:subject.py", "python:subject.py:<module>"] if identifier == "agent" else []),
                   reason="Inert test declaration; no subject process runs.")
        row["obligations"] = {}
        rows.append(row)
    graph = {"schema_version": "verifier-consequence-graph-1", "edges": [], "effects": []}
    manifest = {**draft["manifest"], "objects": rows, "consequence_graph": graph}
    for source, relation, target in [("agent", "controls", "controller"),
            ("controller", "actuates", "actuator"), ("agent", "influences", "delegate"),
            ("delegate", "influences", "ledger")]:
        graph["edges"].append({"source": source, "relation": relation, "target": target,
            "reason": "This declared path carries the selected effect.", "evidence": evidence})
    for target, domain in [("actuator", "REAL_PHYSICAL"), ("ledger", "REAL_FINANCIAL")]:
        graph["effects"].append({"object_id": target, "domain": domain,
            "reason": "This is the declared external boundary, not proof of deployment.", "evidence": evidence})
    return manifest


def save(root: Path, document: dict) -> None:
    (root / "objects.vstd").write_bytes(canonical_bytes(document) + b"\n")


def graph_assessment(document: dict) -> dict:
    from verifier.runtime.namespace_consequences import assess_consequences
    registry = validate_manifest(document)
    observed = graph_observation(document)
    return assess_consequences(document["objects"], registry, observed, document["consequence_graph"])


def graph_observation(document: dict) -> dict:
    """Return the inert source snapshot shared by consequence test helpers."""
    refs = document["consequence_graph"]["effects"][0]["evidence"]
    return {"surfaces": [{"surface_id": surface, "path": "subject.py",
        "source_kinds": [], "hints": [], "unresolved_marker": False}
        for row in document["objects"] for surface in row["surfaces"]],
        "census": {"files": refs}}


def _compiled_effect_fixture(
    digest: str = "sha256:" + "1" * 64,
) -> tuple[list[dict], dict]:
    evidence = [{"path": "subject.py", "sha256": digest}]
    rows = [
        {
            "object_id": "ledger",
            "kind": "LEDGER",
            "specializations": [],
            "payload": {},
            "operands": {},
            "surfaces": ["file:subject.py"],
            "reason": "An inert source-typed financial endpoint.",
            "classification": {
                "FINBOT": {
                    "status": "APPLIES",
                    "reason": (
                        "The reviewed boundary keeps FINBOT obligations required "
                        "without asserting authority or occurrence."
                    ),
                    "evidence": evidence,
                }
            },
            "obligations": {},
        }
    ]
    observed = {
        "surfaces": [
            {
                "surface_id": "file:subject.py",
                "path": "subject.py",
                "source_kinds": [],
                "hints": [],
                "unresolved_marker": False,
            }
        ],
        "census": {"files": evidence},
    }
    return rows, observed


def test_compiler_projects_exact_reviewed_finbot_evidence_without_runtime_claims() -> None:
    rows, observed = _compiled_effect_fixture()
    graph = namespace_consequences.compile_reviewed_effect_graph(
        rows, namespace_registry(), observed
    )

    assert graph["edges"] == []
    assert graph["effects"] == [
        {
            "object_id": "ledger",
            "domain": "REAL_FINANCIAL",
            "reason": namespace_consequences.compiled_effect_reason(
                "ledger", "REAL_FINANCIAL"
            ),
            "evidence": rows[0]["classification"]["FINBOT"]["evidence"],
        }
    ]
    assert namespace_consequences.is_compiled_effect_graph(graph, rows)
    report = namespace_consequences.assess_consequences(
        rows, namespace_registry(), observed, graph
    )
    assert not any(
        row["code"] == "NAMESPACE_TYPED_ENDPOINT_EFFECT_UNRESOLVED"
        for row in report["findings"]
    )
    assert report["runtime_correspondence_status"] == "NOT_ESTABLISHED"
    assert report["external_confinement_status"] == "NOT_ESTABLISHED"


def _reviewed_core_robot_path_fixture() -> tuple[list[dict], dict]:
    paths = {
        "witness": "src/verifier/runtime/tier_zero_reasoning/witness_runner.py",
        "facade": "src/verifier/runtime/hardware_cli.py",
        "endpoint": "src/verifier/runtime/hardware_discovery_cli.py",
    }
    evidence = {
        name: [{"path": path, "sha256": "sha256:" + digit * 64}]
        for (name, path), digit in zip(paths.items(), "123", strict=True)
    }

    def decision(name: str, reason: str) -> dict:
        return {
            "status": "APPLIES",
            "reason": reason,
            "evidence": deepcopy(evidence[name]),
        }

    rows = [
        {
            "object_id": "verifier-core-self",
            "kind": "VERIFIER",
            "specializations": ["ROBOT"],
            "payload": {},
            "operands": {"harness": ["vstd-harness"]},
            "surfaces": ["file:" + paths["witness"]],
            "reason": "The repository verifier owns its caller-selected witness runner.",
            "classification": {
                "AGENT": decision("witness", "The reviewed verifier is the actual agent."),
                "ROBOT": decision(
                    "witness",
                    "The caller-selected child boundary keeps physical reach applicable.",
                ),
            },
            "obligations": {},
        },
        {
            "object_id": "vstd-harness",
            "kind": "HARNESS",
            "specializations": [],
            "payload": {},
            "operands": {},
            "surfaces": [],
            "reason": "The exact governing harness.",
            "classification": {},
            "obligations": {},
        },
        {
            "object_id": "vstd-hardware-cli-protocol",
            "kind": "PROTOCOL",
            "specializations": ["CONTROLLER"],
            "payload": {},
            "operands": {},
            "surfaces": ["file:" + paths["facade"]],
            "reason": "The reviewed hardware command facade.",
            "classification": {
                "CONTROLLER": decision(
                    "facade",
                    "The facade selects and dispatches one reviewed hardware command.",
                ),
            },
            "obligations": {},
        },
        {
            "object_id": "vstd-accelerator-discovery-command",
            "kind": "SENSOR",
            "specializations": ["ACTUATOR", "ROBOT"],
            "payload": {},
            "operands": {},
            "surfaces": ["file:" + paths["endpoint"]],
            "reason": "The reviewed accelerator discovery command.",
            "classification": {
                "ACTUATOR": decision(
                    "endpoint",
                    "The command invokes the selected vendor adapter mechanism.",
                ),
                "ROBOT": decision(
                    "endpoint",
                    "The PATH-resolved vendor boundary keeps physical reach applicable.",
                ),
            },
            "obligations": {},
        },
    ]
    observed = {
        "surfaces": [
            {
                "surface_id": "file:" + path,
                "path": path,
                "source_kinds": [],
                "hints": [],
                "unresolved_marker": False,
            }
            for path in paths.values()
        ],
        "census": {
            "files": [reference for refs in evidence.values() for reference in refs]
        },
    }
    return rows, observed


def test_compiler_selects_exact_reviewed_core_robot_control_path() -> None:
    rows, observed = _reviewed_core_robot_path_fixture()
    graph = namespace_consequences.compile_reviewed_effect_graph(
        rows, namespace_registry(), observed
    )

    assert [
        (edge["source"], edge["relation"], edge["target"])
        for edge in graph["edges"]
    ] == [
        (
            "verifier-core-self",
            "controls",
            "vstd-hardware-cli-protocol",
        ),
        (
            "vstd-hardware-cli-protocol",
            "actuates",
            "vstd-accelerator-discovery-command",
        ),
    ]
    assert [
        (effect["object_id"], effect["domain"])
        for effect in graph["effects"]
    ] == [("vstd-accelerator-discovery-command", "REAL_PHYSICAL")]
    report = namespace_consequences.assess_consequences(
        rows, namespace_registry(), observed, graph
    )
    assert not any(
        finding["code"] == "NAMESPACE_ROBOT_CONTROL_CHAIN_UNRESOLVED"
        and finding["object_id"] == "verifier-core-self"
        for finding in report["findings"]
    )
    assert report["runtime_correspondence_status"] == "NOT_ESTABLISHED"
    assert report["external_confinement_status"] == "NOT_ESTABLISHED"


def test_reviewed_endpoint_retention_demands_robot_without_inventing_an_agent() -> None:
    rows, observed = _reviewed_core_robot_path_fixture()
    endpoint = next(
        row
        for row in rows
        if row["object_id"] == "vstd-accelerator-discovery-command"
    )
    review = package_semantic_review_hardware_cli._REVIEWS[
        "vstd-accelerator-discovery-command"
    ]
    endpoint["classification"]["ROBOT"]["reason"] = (
        package_semantic_review_hardware_cli._reason(review, "ROBOT")
    )
    original_profile = package_original_kind_catalog_runtime.RUNTIME_PARTIAL_PROFILE
    original_assignment = next(
        row
        for row in original_profile.assignments
        if row.object_id == endpoint["object_id"]
    )
    for kind in ("AGENT", "BOT"):
        original_decision = next(
            row for row in original_assignment.decisions if row.kind == kind
        )
        endpoint["classification"][kind] = {
            "status": "APPLIES",
            "reason": (
                "Audited original-kind profile "
                + original_profile.profile_id
                + " revision "
                + str(original_profile.revision)
                + " ("
                + original_profile.canonical_digest
                + ") binds this object and exact owned source set. "
                + original_assignment.scope_reason
                + " "
                + original_decision.reason
            ),
            "evidence": endpoint["classification"]["ROBOT"]["evidence"],
        }

    decision = endpoint["classification"]["ROBOT"]
    assert namespace_consequences.is_nonstructural_role_decision(
        endpoint["object_id"], "ROBOT", decision
    )
    demanded, structural = namespace_consequences._label_sets(
        rows, namespace_registry(), observed
    )
    assert "ROBOT" in demanded[endpoint["object_id"]]
    assert "ROBOT" not in structural[endpoint["object_id"]]
    assert {"AGENT", "BOT"} <= demanded[endpoint["object_id"]]
    assert not ({"AGENT", "BOT"} & structural[endpoint["object_id"]])

    graph = namespace_consequences.compile_reviewed_effect_graph(
        rows, namespace_registry(), observed
    )
    assert [
        (effect["object_id"], effect["domain"])
        for effect in graph["effects"]
    ] == [("vstd-accelerator-discovery-command", "REAL_PHYSICAL")]
    report = namespace_consequences.assess_consequences(
        rows, namespace_registry(), observed, graph
    )
    assert not any(
        finding["object_id"] == endpoint["object_id"]
        and finding["code"]
        in {
            "NAMESPACE_AGENCY_BINDING_UNRESOLVED",
            "NAMESPACE_AGENCY_HARNESS_UNRESOLVED",
            "NAMESPACE_ROBOT_CONTROL_CHAIN_UNRESOLVED",
        }
        for finding in report["findings"]
    )


@pytest.mark.parametrize(
    "review_module,object_id,kind",
    [
        (
            package_semantic_review_partitions,
            "vstd-accelerator-profile-registry",
            "FINBOT",
        ),
        (
            package_semantic_review_commands,
            "vstd-accessibility-artifact-reader",
            "ROBOT",
        ),
        (package_original_review_people, "vstd-actor", "FINBOT"),
        (
            package_semantic_review_verifier,
            "vstd-added-kind-behavioral-verifier",
            "ROBOT",
        ),
        (
            package_semantic_review_partitions,
            "vstd-agency-surface-crosswalk-assets",
            "FINBOT",
        ),
        (
            package_semantic_review_partitions,
            "vstd-domain-grounding-specimen",
            "FINBOT",
        ),
        (
            package_semantic_review_hardware_cli,
            "vstd-hardware-cli-protocol",
            "ROBOT",
        ),
    ],
)
def test_exact_reviewed_demand_only_decisions_are_nonstructural(
    review_module, object_id: str, kind: str
) -> None:
    decision = {
        "status": "APPLIES",
        "reason": review_module.obligation_retention_reason(object_id, kind),
        "evidence": [{"path": "subject.py", "sha256": "sha256:" + "1" * 64}],
    }

    assert namespace_consequences.is_nonstructural_role_decision(
        object_id, kind, decision
    )


def test_exact_compiled_retention_projection_is_nonstructural() -> None:
    object_id = "vstd-accelerator-profile-registry"
    kind = "FINBOT"
    exact = package_semantic_review_partitions.obligation_retention_reason(
        object_id, kind
    )
    projected = namespace_consequences.compiled_classification_reason(
        "APPLIES", exact
    )
    assert projected != exact
    decision = {
        "status": "APPLIES",
        "reason": projected,
        "evidence": [{"path": "subject.py", "sha256": "sha256:" + "1" * 64}],
    }

    assert namespace_consequences.is_nonstructural_role_decision(
        object_id, kind, decision
    )
    decision["reason"] += " altered"
    assert not namespace_consequences.is_nonstructural_role_decision(
        object_id, kind, decision
    )


def test_demand_only_finbot_does_not_turn_generic_ledger_into_real_finance(
    tmp_path,
) -> None:
    document = fixture(tmp_path)
    endpoint = _row(document, "ledger")
    endpoint_id = "vstd-hardware-cli-protocol"
    endpoint["object_id"] = endpoint_id
    endpoint["specializations"] = ["FINBOT"]
    endpoint["classification"]["FINBOT"] = {
        "status": "APPLIES",
        "reason": package_semantic_review_hardware_cli.obligation_retention_reason(
            endpoint_id, "FINBOT"
        ),
        "evidence": _evidence(document),
    }
    for edge in document["consequence_graph"]["edges"]:
        if edge["target"] == "ledger":
            edge["target"] = endpoint_id
    document["consequence_graph"]["effects"] = [
        effect
        for effect in document["consequence_graph"]["effects"]
        if effect["domain"] != "REAL_FINANCIAL"
    ]

    observed = graph_observation(document)
    demanded, structural = namespace_consequences._label_sets(
        document["objects"], namespace_registry(), observed
    )
    assert "FINBOT" in demanded[endpoint_id]
    assert "FINBOT" not in structural[endpoint_id]
    report = namespace_consequences.assess_consequences(
        document["objects"],
        namespace_registry(),
        observed,
        document["consequence_graph"],
    )
    assert not any(
        finding["code"] == "NAMESPACE_TYPED_ENDPOINT_EFFECT_UNRESOLVED"
        and finding["object_id"] == endpoint_id
        for finding in report["findings"]
    )
    assert "FINBOT" not in report["required_kinds"].get("agent", [])


def test_exact_reviewed_core_control_path_transition_is_bounded() -> None:
    rows, observed = _reviewed_core_robot_path_fixture()
    stable_rows, stable_observed = _compiled_effect_fixture()
    rows.extend(stable_rows)
    observed["surfaces"].extend(stable_observed["surfaces"])
    observed["census"]["files"].extend(stable_observed["census"]["files"])

    current = namespace_consequences.compile_reviewed_effect_graph(
        rows, namespace_registry(), observed
    )
    prior = deepcopy(current)
    prior["edges"] = []
    prior["effects"] = [
        effect
        for effect in prior["effects"]
        if (effect["object_id"], effect["domain"])
        != ("vstd-accelerator-discovery-command", "REAL_PHYSICAL")
    ]
    source_digests = {
        reference["path"]: reference["sha256"]
        for reference in observed["census"]["files"]
    }

    assert namespace_consequences.is_pre_reviewed_control_compiled_effect_graph(
        prior, rows
    )
    assert namespace_consequences.is_compiled_effect_graph(current, rows)
    assert namespace_consequences.is_exact_reviewed_control_path_addition(
        prior, current, rows, rows
    )
    assert package_manifest_migration.selected_refresh_options(
        {"namespace": {"objects": rows, "consequence_graph": prior}}
    )["select_compiled_consequence_graph"]
    assert package_manifest_refresh._compiled_consequence_graph_rebinds_source_only(
        prior, current, rows, rows, source_digests
    )

    for field, replacement in (
        ("target", "vstd-harness"),
        ("reason", "Substituted edge meaning."),
    ):
        substituted = deepcopy(current)
        substituted["edges"][0][field] = replacement
        assert not namespace_consequences.is_exact_reviewed_control_path_addition(
            prior, substituted, rows, rows
        )
        assert not package_manifest_refresh._compiled_consequence_graph_rebinds_source_only(
            prior, substituted, rows, rows, source_digests
        )

    missing_digest = dict(source_digests)
    missing_digest.pop("src/verifier/runtime/hardware_cli.py")
    assert not package_manifest_refresh._compiled_consequence_graph_rebinds_source_only(
        prior, current, rows, rows, missing_digest
    )


def test_compiler_keeps_an_unreviewed_typed_role_out_of_the_effect_graph() -> None:
    rows, observed = _compiled_effect_fixture()
    rows[0]["specializations"] = ["FINBOT"]
    rows[0]["classification"]["FINBOT"]["status"] = "UNRESOLVED"

    graph = namespace_consequences.compile_reviewed_effect_graph(
        rows, namespace_registry(), observed
    )
    assert graph["effects"] == []
    report = namespace_consequences.assess_consequences(
        rows, namespace_registry(), observed, graph
    )
    assert any(
        row["code"] == "NAMESPACE_TYPED_ENDPOINT_EFFECT_UNRESOLVED"
        and row["object_id"] == "ledger"
        for row in report["findings"]
    )


def test_compiler_does_not_treat_its_retained_role_as_review_evidence() -> None:
    rows, observed = _compiled_effect_fixture()
    rows[0]["specializations"] = ["FINBOT"]
    rows[0]["classification"]["FINBOT"]["reason"] = (
        namespace_consequences.compiled_role_reason("ledger", "FINBOT")
    )

    graph = namespace_consequences.compile_reviewed_effect_graph(
        rows, namespace_registry(), observed
    )

    assert graph["effects"] == []
    report = namespace_consequences.assess_consequences(
        rows, namespace_registry(), observed, graph
    )
    demanded, structural = namespace_consequences._label_sets(
        rows, namespace_registry(), observed
    )
    assert "FINBOT" in demanded["ledger"]
    assert "FINBOT" not in structural["ledger"]
    assert not any(
        row["code"] == "NAMESPACE_TYPED_ENDPOINT_EFFECT_UNRESOLVED"
        and row["object_id"] == "ledger"
        for row in report["findings"]
    )


def _retained_original_kind_reason(object_id: str, kind: str) -> str:
    profile = package_original_kind_catalog_retained.RETAINED_PARTIAL_PROFILE
    assignment = next(
        row for row in profile.assignments if row.object_id == object_id
    )
    decision = next(row for row in assignment.decisions if row.kind == kind)
    return (
        "Audited original-kind profile "
        + profile.profile_id
        + " revision "
        + str(profile.revision)
        + " ("
        + profile.canonical_digest
        + ") binds this object and exact owned source set. "
        + assignment.scope_reason
        + " "
        + decision.reason
    )


def test_original_kind_obligation_retention_does_not_invent_financial_agency() -> None:
    rows, observed = _compiled_effect_fixture()
    rows[0].update(
        object_id="vstd-model",
        kind="MODEL",
        specializations=["ASSET"],
    )
    rows[0]["classification"] = {
        "AGENT": {
            "status": "APPLIES",
            "reason": _retained_original_kind_reason("vstd-model", "AGENT"),
            "evidence": rows[0]["classification"]["FINBOT"]["evidence"],
        }
    }

    graph = namespace_consequences.compile_reviewed_effect_graph(
        rows, namespace_registry(), observed
    )
    _derived, demanded, structural, _endpoints, typed = (
        namespace_consequences._derive_state(
            rows, namespace_registry(), observed, namespace_consequences.EMPTY
        )
    )

    assert graph["effects"] == []
    assert "AGENT" in demanded["vstd-model"]
    assert "AGENT" not in structural["vstd-model"]
    assert "vstd-model" not in typed["REAL_FINANCIAL"]


def test_added_kind_obligation_retention_does_not_invent_financial_endpoint() -> None:
    rows, observed = _compiled_effect_fixture()
    rows[0].update(
        object_id="vstd-architecture",
        kind="ARCH",
        specializations=["ASSET", "FINBOT"],
    )
    evidence = rows[0]["classification"]["FINBOT"]["evidence"]
    rows[0]["classification"] = {
        kind: {
            "status": "APPLIES",
            "reason": package_semantic_ownership_domains_agency_collective.obligation_retention_reason(
                "vstd-architecture", kind
            ),
            "evidence": evidence,
        }
        for kind in ("ASSET", "FINBOT")
    }

    graph = namespace_consequences.compile_reviewed_effect_graph(
        rows, namespace_registry(), observed
    )

    assert graph["effects"] == []


def test_obligation_retention_preserves_demand_without_claiming_structure() -> None:
    rows, observed = _compiled_effect_fixture()
    rows[0].update(
        object_id="vstd-architecture",
        kind="ARCH",
        specializations=["ASSET", "FINBOT"],
    )
    evidence = rows[0]["classification"]["FINBOT"]["evidence"]
    rows[0]["classification"] = {
        kind: {
            "status": "APPLIES",
            "reason": package_semantic_ownership_domains_agency_collective.obligation_retention_reason(
                "vstd-architecture", kind
            ),
            "evidence": evidence,
        }
        for kind in ("ASSET", "FINBOT")
    }

    demanded, structural = namespace_consequences._label_sets(
        rows, namespace_registry(), observed
    )

    assert {"ASSET", "FINBOT"} <= demanded["vstd-architecture"]
    assert not ({"ASSET", "FINBOT"} & structural["vstd-architecture"])


def test_retention_recognizer_requires_the_exact_catalog_reason() -> None:
    rows, observed = _compiled_effect_fixture()
    rows[0].update(
        object_id="vstd-model",
        kind="MODEL",
        specializations=["ASSET"],
    )
    rows[0]["classification"] = {"AGENT": {
        "status": "APPLIES",
        "reason": _retained_original_kind_reason("vstd-model", "AGENT")
        + " Substituted.",
        "evidence": rows[0]["classification"]["FINBOT"]["evidence"],
    }}

    _derived, _demanded, structural, _endpoints, typed = (
        namespace_consequences._derive_state(
            rows, namespace_registry(), observed, namespace_consequences.EMPTY
        )
    )

    assert "AGENT" in structural["vstd-model"]
    assert "vstd-model" in typed["REAL_FINANCIAL"]


def test_compiled_graph_recognizer_rejects_retention_only_role_evidence() -> None:
    rows, _observed = _compiled_effect_fixture()
    rows[0].update(
        object_id="vstd-architecture",
        kind="ARCH",
        specializations=["ASSET", "FINBOT"],
    )
    evidence = rows[0]["classification"]["FINBOT"]["evidence"]
    rows[0]["classification"]["FINBOT"] = {
        "status": "APPLIES",
        "reason": package_semantic_ownership_domains_agency_collective.obligation_retention_reason(
            "vstd-architecture", "FINBOT"
        ),
        "evidence": evidence,
    }
    graph = {
        "schema_version": namespace_consequences.SCHEMA,
        "edges": [],
        "effects": [
            {
                "object_id": "vstd-architecture",
                "domain": "REAL_FINANCIAL",
                "reason": namespace_consequences.compiled_effect_reason(
                    "vstd-architecture", "REAL_FINANCIAL"
                ),
                "evidence": evidence,
            }
        ],
    }

    assert not namespace_consequences.is_compiled_effect_graph(graph, rows)
    assert namespace_consequences.is_legacy_compiled_effect_graph(graph, rows)

    changed = deepcopy(graph)
    changed["effects"][0]["reason"] = "Substituted legacy reason."
    assert not namespace_consequences.is_legacy_compiled_effect_graph(changed, rows)

    changed = deepcopy(graph)
    changed["effects"][0]["evidence"] = []
    assert not namespace_consequences.is_legacy_compiled_effect_graph(changed, rows)


def test_exact_retention_prune_removes_only_retention_generated_effects() -> None:
    rows, observed = _compiled_effect_fixture()
    genuine = deepcopy(rows[0])
    genuine["object_id"] = "genuine"
    retained = deepcopy(rows[0])
    retained.update(
        object_id="vstd-architecture",
        kind="ARCH",
        specializations=["ASSET", "FINBOT"],
    )
    retained["classification"]["FINBOT"] = {
        "status": "APPLIES",
        "reason": package_semantic_ownership_domains_agency_collective.obligation_retention_reason(
            "vstd-architecture", "FINBOT"
        ),
        "evidence": retained["classification"]["FINBOT"]["evidence"],
    }
    selected_rows = [genuine, retained]
    before = {
        "schema_version": namespace_consequences.SCHEMA,
        "edges": [],
        "effects": [
            {
                "object_id": object_id,
                "domain": "REAL_FINANCIAL",
                "reason": namespace_consequences.compiled_effect_reason(
                    object_id, "REAL_FINANCIAL"
                ),
                "evidence": row["classification"]["FINBOT"]["evidence"],
            }
            for object_id, row in (("genuine", genuine), ("vstd-architecture", retained))
        ],
    }
    after = namespace_consequences.compile_reviewed_effect_graph(
        selected_rows, namespace_registry(), observed
    )

    assert [row["object_id"] for row in after["effects"]] == ["genuine"]
    assert namespace_consequences.is_exact_retention_prune(
        before, after, selected_rows, selected_rows
    )
    source_digests = {
        "subject.py": genuine["classification"]["FINBOT"]["evidence"][0]["sha256"]
    }
    assert package_manifest_refresh._compiled_consequence_graph_rebinds_source_only(
        before, after, selected_rows, selected_rows, source_digests
    )
    assert package_manifest_migration.selected_refresh_options(
        {"namespace": {"objects": selected_rows, "consequence_graph": before}}
    )["select_compiled_consequence_graph"]

    removed_genuine = deepcopy(after)
    removed_genuine["effects"] = []
    assert not namespace_consequences.is_exact_retention_prune(
        before, removed_genuine, selected_rows, selected_rows
    )
    assert not package_manifest_refresh._compiled_consequence_graph_rebinds_source_only(
        before, removed_genuine, selected_rows, selected_rows, source_digests
    )

    retained_bug = deepcopy(before)
    assert not namespace_consequences.is_exact_retention_prune(
        before, retained_bug, selected_rows, selected_rows
    )


def _compiled_role_retirement_refresh_pair() -> tuple[dict, dict, dict, dict]:
    digest = "sha256:" + "7" * 64

    def evidence(path: str) -> list[dict[str, str]]:
        return [{"path": path, "sha256": digest}]

    def row(
        object_id: str,
        kind: str,
        specializations: list[str],
        classification: dict,
        obligations: dict | None = None,
    ) -> dict:
        return {
            "object_id": object_id,
            "kind": kind,
            "specializations": specializations,
            "payload": {},
            "operands": {},
            "surfaces": ["file:src/" + object_id + ".py"],
            "reason": "The fixture owns one inert source surface.",
            "classification": classification,
            "obligations": obligations or {},
        }

    genuine = row(
        "genuine",
        "FINBOT",
        [],
        {"FINBOT": {
            "status": "APPLIES",
            "reason": "A source review establishes this financial endpoint role.",
            "evidence": evidence("src/genuine.py"),
        }},
    )
    legacy_endpoint = row(
        "vstd-architecture",
        "ARCH",
        ["ASSET", "FINBOT"],
        {"FINBOT": {
            "status": "APPLIES",
            "reason": package_semantic_ownership_domains_agency_collective.obligation_retention_reason(
                "vstd-architecture", "FINBOT"
            ),
            "evidence": evidence("src/vstd-architecture.py"),
        }},
    )
    prior_model = row(
        "vstd-model",
        "MODEL",
        ["FINBOT"],
        {"FINBOT": {
            "status": "APPLIES",
            "reason": namespace_consequences.compiled_role_reason(
                "vstd-model", "FINBOT"
            ),
            "evidence": evidence("src/vstd-model.py"),
        }},
        {"FINBOT-0.1-boundary": {
            "reason": "",
            "evidence": [],
            "declaration": {"scope": ""},
        }},
    )
    current_model = deepcopy(prior_model)
    current_model["specializations"] = []
    current_model["classification"]["FINBOT"] = {
        "status": "DOES_NOT_APPLY",
        "reason": "The current source has no live-money authority or endpoint.",
        "evidence": evidence("src/vstd-model.py"),
    }
    current_model["obligations"] = {}
    before_rows = [genuine, legacy_endpoint, prior_model]
    after_rows = [deepcopy(genuine), deepcopy(legacy_endpoint), current_model]

    def effect(object_id: str, path: str) -> dict:
        return {
            "object_id": object_id,
            "domain": "REAL_FINANCIAL",
            "reason": namespace_consequences.compiled_effect_reason(
                object_id, "REAL_FINANCIAL"
            ),
            "evidence": evidence(path),
        }

    before_graph = {
        "schema_version": namespace_consequences.SCHEMA,
        "edges": [],
        "effects": [
            effect("genuine", "src/genuine.py"),
            effect("vstd-architecture", "src/vstd-architecture.py"),
        ],
    }
    after_graph = {
        "schema_version": namespace_consequences.SCHEMA,
        "edges": [],
        "effects": [effect("genuine", "src/genuine.py")],
    }

    def document(rows: list[dict], graph: dict) -> dict:
        return {
            "schema_version": package_manifest_refresh.package_manifest.REPRESENTATION_SCHEMA,
            "repository": {
                "remote": package_manifest_refresh.VERIFIER_REMOTE,
                "revision": "1" * 40,
            },
            "namespace": {
                "schema_version": "verifier-namespace-manifest-3",
                "extensions": [],
                "instance_checks": [],
                "execution_checks": [],
                "objects": rows,
                "consequence_graph": graph,
            },
            "representation_updates": [],
        }

    observed = {
        "surfaces": [
            {
                "surface_id": row["surfaces"][0],
                "path": "src/" + row["object_id"] + ".py",
                "source_kinds": [row["kind"]],
            }
            for row in after_rows
        ],
        "census": {"files": []},
    }
    source_digests = {
        surface["path"]: digest for surface in observed["surfaces"]
    }
    return (
        document(before_rows, before_graph),
        document(after_rows, after_graph),
        observed,
        source_digests,
    )


def test_nonweakening_allows_only_graph_proved_compiler_role_retirement() -> None:
    before, after, observed, source_digests = (
        _compiled_role_retirement_refresh_pair()
    )
    regenerated: list[dict] = []

    package_manifest_refresh._require_non_weakening(
        before,
        after,
        reopened={},
        regenerated=regenerated,
        source_digests=source_digests,
        observed=observed,
    )

    assert regenerated == [{
        "stage": "regeneration",
        "gap": "COMPILED_CONSEQUENCE_ROLE_RETIRED",
        "object_id": "vstd-model",
        "classification": "FINBOT",
        "was": "APPLIES",
    }]


@pytest.mark.parametrize("mutation", ["unbound", "independently_demanded"])
def test_compiler_role_retirement_never_excuses_an_unproved_drop(mutation) -> None:
    before, after, observed, source_digests = (
        _compiled_role_retirement_refresh_pair()
    )
    current = next(
        row for row in after["namespace"]["objects"]
        if row["object_id"] == "vstd-model"
    )
    if mutation == "unbound":
        current["classification"]["FINBOT"]["evidence"][0]["sha256"] = (
            "sha256:" + "8" * 64
        )
    else:
        surface = next(
            row for row in observed["surfaces"]
            if row["surface_id"] == current["surfaces"][0]
        )
        surface["source_kinds"] = ["MODEL", "FINBOT"]

    with pytest.raises(package_manifest_refresh.ManifestRefreshError):
        package_manifest_refresh._require_non_weakening(
            before,
            after,
            reopened={},
            regenerated=[],
            source_digests=source_digests,
            observed=observed,
        )


def test_selected_profile_recognizer_rejects_reason_or_evidence_substitution() -> None:
    rows, observed = _compiled_effect_fixture()
    graph = namespace_consequences.compile_reviewed_effect_graph(
        rows, namespace_registry(), observed
    )
    changed = deepcopy(graph)
    changed["effects"][0]["reason"] = "A weaker boundary."
    assert not namespace_consequences.is_compiled_effect_graph(changed, rows)

    changed = deepcopy(graph)
    changed["effects"][0]["evidence"] = []
    assert not namespace_consequences.is_compiled_effect_graph(changed, rows)


def test_refresh_allows_only_current_hash_rebinding_of_selected_profile() -> None:
    prior_rows, prior_observed = _compiled_effect_fixture("sha256:" + "1" * 64)
    next_rows, next_observed = _compiled_effect_fixture("sha256:" + "2" * 64)
    prior = namespace_consequences.compile_reviewed_effect_graph(
        prior_rows, namespace_registry(), prior_observed
    )
    current = namespace_consequences.compile_reviewed_effect_graph(
        next_rows, namespace_registry(), next_observed
    )

    assert package_manifest_refresh._compiled_consequence_graph_rebinds_source_only(
        prior,
        current,
        prior_rows,
        next_rows,
        {"subject.py": "sha256:" + "2" * 64},
    )
    current["effects"][0]["reason"] = "Substituted meaning."
    assert not package_manifest_refresh._compiled_consequence_graph_rebinds_source_only(
        prior,
        current,
        prior_rows,
        next_rows,
        {"subject.py": "sha256:" + "2" * 64},
    )


def test_actual_admission_derives_accumulating_roles_and_exact_gate(tmp_path):
    document = fixture(tmp_path)
    # A repository-authored non-applicability answer cannot override a path.
    agent = next(row for row in document["objects"] if row["object_id"] == "agent")
    agent["classification"]["ROBOT"] = {"status": "DOES_NOT_APPLY", "reason": "Only a simulation.",
        "evidence": document["consequence_graph"]["effects"][0]["evidence"]}
    save(tmp_path, document)
    result = assess(tmp_path)
    assert "NAMESPACE_MANIFEST_FIELDS" not in result["blockers"]
    assert result["consequence_graph"]["required_kinds"]["agent"] == ["FINBOT", "ROBOT"]
    assert result["consequence_graph"]["required_kinds"]["bot"] == ["FINBOT", "ROBOT"]
    assert result["consequence_graph"]["external_confinement_status"] == "NOT_ESTABLISHED"
    selected = [row for row in result["required_obligations"] if row["object_id"] == "bot"]
    assert {row["kind"] for row in selected} == {"FINBOT", "ROBOT"}
    assert all(row["necessity"] == "NECESSARY" for row in selected)
    assert any(row["code"] == "NAMESPACE_REFUTATION_CONTRADICTS_DECLARATION"
               and row["object_id"] == "agent" for row in result["findings"])
    assert result["independent_reconciliation"]["status"] == "PASS"
    focused = assess_gate("bot", "ROBOT-0.1-agent-to-actuator-binding", tmp_path)
    assert focused["selection_status"] == "PASS"
    assert focused["selected_obligation"]["necessity"] == "NECESSARY"
    assert focused["status"] != "PASS"


def test_consequence_graph_does_not_change_legacy_base_digest(tmp_path):
    document = fixture(tmp_path)
    before = check_composition(document["objects"], namespace_registry())
    validate_manifest(document)
    after = check_composition(document["objects"], namespace_registry())
    assert before == after and before["status"] == "PASS"


def test_feedback_cycles_terminate_and_keep_both_external_domains(tmp_path):
    document = fixture(tmp_path)
    edge = deepcopy(document["consequence_graph"]["edges"][-1])
    edge.update(source="ledger", target="delegate")
    document["consequence_graph"]["edges"].append(edge)
    result = graph_assessment(document)
    assert result["required_kinds"]["bot"] == ["FINBOT", "ROBOT"]
    assert result["reachable_effects"]["delegate"]["REAL_FINANCIAL"]["effect_object_id"] == "ledger"


def test_indirect_physical_path_does_not_fake_a_controller_chain(tmp_path):
    document = fixture(tmp_path)
    document["consequence_graph"]["edges"][0]["relation"] = "influences"
    result = graph_assessment(document)
    assert "ROBOT" in result["required_kinds"]["agent"]
    assert any(item["code"] == "NAMESPACE_ROBOT_CONTROL_CHAIN_UNRESOLVED" for item in result["findings"])


def test_declared_robot_without_real_endpoint_is_not_verified(tmp_path):
    document = fixture(tmp_path)
    document["objects"][0]["specializations"] = ["ROBOT"]
    document["consequence_graph"]["edges"] = [
        edge for edge in document["consequence_graph"]["edges"]
        if edge["relation"] != "actuates"]
    document["consequence_graph"]["effects"] = [
        effect for effect in document["consequence_graph"]["effects"]
        if effect["domain"] != "REAL_PHYSICAL"]
    result = graph_assessment(document)
    assert any(item["code"] == "NAMESPACE_ROBOT_CONTROL_CHAIN_UNRESOLVED" for item in result["findings"])


def test_simulation_effect_is_not_evidence_of_confinement(tmp_path):
    document = fixture(tmp_path)
    for effect in document["consequence_graph"]["effects"]:
        effect["domain"] = "SIMULATED"
    result = graph_assessment(document)
    assert result["required_kinds"]["agent"] == ["FINBOT", "ROBOT"]
    assert result["status"] == "FAIL"
    assert [(row["object_id"], row["obligation_id"])
            for row in _findings(result, "NAMESPACE_EFFECT_DOMAIN_CONTRADICTS_TYPED_ENDPOINT")] == [
        ("actuator", "ROBOT-0.1-agent-to-actuator-binding"),
        ("ledger", "FINBOT-0.1-agent-and-financial-authority"),
    ]
    assert result["external_confinement_status"] == "NOT_ESTABLISHED"


def test_simulated_label_cannot_erase_robot_from_typed_control_chain(tmp_path):
    document = fixture(tmp_path)
    document["consequence_graph"]["effects"][0]["domain"] = "SIMULATED"
    result = graph_assessment(document)
    assert "ROBOT" in result["required_kinds"]["agent"]
    assert "ROBOT" in result["required_kinds"]["bot"]
    contradictions = _findings(result, "NAMESPACE_EFFECT_DOMAIN_CONTRADICTS_TYPED_ENDPOINT")
    assert [(row["object_id"], row["status"], row["obligation_id"])
            for row in contradictions] == [
        ("actuator", "FAIL", "ROBOT-0.1-agent-to-actuator-binding")]
    assert contradictions[0]["gate_id"] == "namespace-admission"
    assert contradictions[0]["coordinate"] == "VSTD-T0.3"
    assert "SIMULATED" in contradictions[0]["reason"]
    assert "ACTUATOR" in contradictions[0]["reason"]
    assert contradictions[0]["next_action"]


def test_simulated_label_cannot_erase_finbot_from_typed_financial_path(tmp_path):
    document = fixture(tmp_path)
    document["consequence_graph"]["effects"][1]["domain"] = "SIMULATED"
    result = graph_assessment(document)
    assert "FINBOT" in result["required_kinds"]["agent"]
    assert "FINBOT" in result["required_kinds"]["bot"]
    contradictions = _findings(result, "NAMESPACE_EFFECT_DOMAIN_CONTRADICTS_TYPED_ENDPOINT")
    assert [(row["object_id"], row["status"], row["obligation_id"])
            for row in contradictions] == [
        ("ledger", "FAIL", "FINBOT-0.1-agent-and-financial-authority")]
    assert contradictions[0]["gate_id"] == "namespace-admission"
    assert contradictions[0]["coordinate"] == "VSTD-T0.3"
    assert "SIMULATED" in contradictions[0]["reason"]
    assert "LEDGER" in contradictions[0]["reason"]
    assert contradictions[0]["next_action"]


def test_unreachable_typed_simulation_endpoint_does_not_invent_robot(tmp_path):
    document = fixture(tmp_path)
    document["consequence_graph"]["effects"][0]["domain"] = "SIMULATED"
    document["consequence_graph"]["edges"] = [
        edge for edge in document["consequence_graph"]["edges"]
        if edge["relation"] not in {"controls", "actuates"}]
    result = graph_assessment(document)
    assert "ROBOT" not in result["required_kinds"].get("agent", [])
    assert not any(row["object_id"] == "actuator" and row["code"].startswith("NAMESPACE_TYPED_ENDPOINT")
                   for row in result["findings"])


def test_wrong_relation_keeps_typed_simulation_endpoint_unknown_without_promotion(tmp_path):
    document = fixture(tmp_path)
    document["consequence_graph"]["effects"][0]["domain"] = "SIMULATED"
    document["consequence_graph"]["edges"][1]["relation"] = "influences"
    result = graph_assessment(document)
    assert "ROBOT" not in result["required_kinds"].get("agent", [])
    unresolved = _findings(result, "NAMESPACE_TYPED_ENDPOINT_REACHABILITY_UNRESOLVED")
    assert [(row["object_id"], row["status"], row["obligation_id"])
            for row in unresolved] == [
        ("actuator", "UNKNOWN", "ROBOT-0.1-agent-to-actuator-binding")]
    assert "controls/actuates" in unresolved[0]["reason"]
    assert unresolved[0]["next_action"]


def test_effect_attached_to_different_object_cannot_erase_typed_endpoint(tmp_path):
    document = fixture(tmp_path)
    document["consequence_graph"]["effects"][0].update(
        object_id="controller", domain="SIMULATED")
    result = graph_assessment(document)
    assert "ROBOT" in result["required_kinds"]["agent"]
    unresolved = _findings(result, "NAMESPACE_TYPED_ENDPOINT_EFFECT_UNRESOLVED")
    assert [(row["object_id"], row["status"], row["obligation_id"])
            for row in unresolved] == [
        ("actuator", "UNKNOWN", "ROBOT-0.1-agent-to-actuator-binding")]
    assert "REAL_PHYSICAL" in unresolved[0]["reason"]
    assert unresolved[0]["next_action"]


def test_real_domain_substitution_is_a_contradiction_not_an_exemption(tmp_path):
    document = fixture(tmp_path)
    document["consequence_graph"]["effects"][0]["domain"] = "REAL_FINANCIAL"
    result = graph_assessment(document)
    assert result["required_kinds"]["agent"] == ["FINBOT", "ROBOT"]
    contradiction = _findings(result, "NAMESPACE_EFFECT_DOMAIN_CONTRADICTS_TYPED_ENDPOINT")
    assert [(row["object_id"], row["status"], row["obligation_id"])
            for row in contradiction] == [
        ("actuator", "FAIL", "ROBOT-0.1-agent-to-actuator-binding")]
    assert "REAL_FINANCIAL" in contradiction[0]["reason"]


def test_endpoint_kind_substitution_cannot_override_actuates_relation(tmp_path):
    document = fixture(tmp_path)
    _row(document, "actuator")["kind"] = "SENSOR"
    document["consequence_graph"]["effects"][0]["domain"] = "SIMULATED"
    result = graph_assessment(document)
    assert "ROBOT" in result["required_kinds"]["agent"]
    contradiction = _findings(result, "NAMESPACE_EFFECT_DOMAIN_CONTRADICTS_TYPED_ENDPOINT")
    assert [(row["object_id"], row["status"])
            for row in contradiction] == [("actuator", "FAIL")]
    assert "ACTUATOR" in contradiction[0]["reason"]


def test_mixed_simulated_labels_preserve_both_consequential_roles(tmp_path):
    document = fixture(tmp_path)
    for effect in document["consequence_graph"]["effects"]:
        effect["domain"] = "SIMULATED"
    result = graph_assessment(document)
    assert result["required_kinds"]["agent"] == ["FINBOT", "ROBOT"]
    assert result["required_kinds"]["bot"] == ["FINBOT", "ROBOT"]
    assert {(row["object_id"], row["obligation_id"])
            for row in _findings(result, "NAMESPACE_EFFECT_DOMAIN_CONTRADICTS_TYPED_ENDPOINT")} == {
        ("actuator", "ROBOT-0.1-agent-to-actuator-binding"),
        ("ledger", "FINBOT-0.1-agent-and-financial-authority"),
    }


def test_cyclic_financial_influence_terminates_without_label_escape(tmp_path):
    document = fixture(tmp_path)
    document["consequence_graph"]["effects"][1]["domain"] = "SIMULATED"
    document["consequence_graph"]["edges"].append({
        "source": "ledger", "relation": "influences", "target": "delegate",
        "reason": "The financial feedback cycle remains source-bound.",
        "evidence": _evidence(document),
    })
    result = graph_assessment(document)
    assert "FINBOT" in result["required_kinds"]["agent"]
    assert result["reachable_effects"]["delegate"]["REAL_FINANCIAL"]["effect_object_id"] == "ledger"
    assert [(row["object_id"], row["status"])
            for row in _findings(result, "NAMESPACE_EFFECT_DOMAIN_CONTRADICTS_TYPED_ENDPOINT")] == [
        ("ledger", "FAIL")]


def test_bot_inside_sim_crossing_to_typed_actuator_acquires_robot(tmp_path):
    document = fixture(tmp_path)
    document["consequence_graph"]["effects"][0]["domain"] = "SIMULATED"
    document["consequence_graph"]["effects"] = document["consequence_graph"]["effects"][:1]
    document["consequence_graph"]["edges"] = document["consequence_graph"]["edges"][:2]
    result = graph_assessment(document)
    assert result["required_kinds"]["agent"] == ["ROBOT"]
    assert result["required_kinds"]["bot"] == ["ROBOT"]
    contradiction = _findings(result, "NAMESPACE_EFFECT_DOMAIN_CONTRADICTS_TYPED_ENDPOINT")
    assert [(row["object_id"], row["status"])
            for row in contradiction] == [("actuator", "FAIL")]


@pytest.mark.parametrize("domain,expected", [("REAL_PHYSICAL", "ROBOT"), ("REAL_FINANCIAL", "FINBOT")])
def test_simulated_endpoint_cannot_erase_additional_external_effect(tmp_path, domain, expected):
    document = fixture(tmp_path)
    effect = deepcopy(document["consequence_graph"]["effects"][0 if domain == "REAL_PHYSICAL" else 1])
    effect["domain"] = "SIMULATED"
    document["consequence_graph"]["effects"].append(effect)
    assert expected in graph_assessment(document)["required_kinds"]["bot"]


def test_generic_labels_on_controller_and_actuator_do_not_erase_types(tmp_path):
    document = fixture(tmp_path)
    for row in document["objects"]:
        if row["object_id"] in {"controller", "actuator"}:
            row["kind"] = "OBJECT"
    result = graph_assessment(document)
    assert result["required_kinds"]["controller"] == ["CONTROLLER"]
    assert result["required_kinds"]["actuator"] == ["ACTUATOR"]
    save(tmp_path, document)
    report = assess(tmp_path)
    assert any(row["code"] == "NAMESPACE_LABEL_CONTRADICTS_SOURCE" and row["object_id"] == "actuator"
               for row in report["findings"])
    assert report["independent_reconciliation"]["status"] == "PASS"


def test_stale_effect_evidence_fails_without_pruning_obligations(tmp_path):
    document = fixture(tmp_path)
    document["consequence_graph"]["effects"][0]["evidence"] = [{"path": "subject.py", "sha256": "sha256:" + "0" * 64}]
    result = graph_assessment(document)
    assert result["status"] == "FAIL"
    assert "ROBOT" in result["required_kinds"]["agent"]


def test_complete_declared_chain_passes_only_its_bounded_proposition(tmp_path):
    result = graph_assessment(fixture(tmp_path))
    assert result["status"] == "PASS"
    assert result["runtime_correspondence_status"] == "NOT_ESTABLISHED"
    assert result["external_confinement_status"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("source", ["agent", "controller"])
def test_one_valid_chain_cannot_hide_a_parallel_control_bypass(tmp_path, source):
    document = fixture(tmp_path)
    edge = deepcopy(document["consequence_graph"]["edges"][0])
    edge.update(source=source, relation="influences", target="actuator")
    document["consequence_graph"]["edges"].append(edge)
    result = graph_assessment(document)
    assert any(row["code"] == "NAMESPACE_ROBOT_CONTROL_CHAIN_UNRESOLVED" for row in result["findings"])


def test_native_agent_cannot_be_replaced_by_wrapper_embodiment(tmp_path):
    document = fixture(tmp_path)
    edge = deepcopy(document["consequence_graph"]["edges"][0])
    edge.update(source="bot", relation="embodies", target="delegate")
    document["consequence_graph"]["edges"].append(edge)
    result = graph_assessment(document)
    assert any(row["code"] == "NAMESPACE_AGENCY_BINDING_UNRESOLVED" and row["object_id"] == "bot"
               for row in result["findings"])


# A clean finite scan over a clean owned effect audit, with its reason and current owned
# evidence, admits a DOES_NOT_APPLY as DOCUMENTED and never as ESTABLISHED.
DOCUMENTED = ("DOCUMENTED", "DOCUMENTED", "DOCUMENTED_BOUNDED_ABSENCE")
CONTRADICTION_NEXT_ACTION = ("Resolve the witness contradiction with the current source; "
                             "its obligations stay required meanwhile.")


def _admitted(tmp_path: Path) -> dict:
    """Declare the inert fixture's roles and boundaries, with a witness per non-applicability."""
    from verifier.runtime.namespace_contracts import requirements_for
    document = fixture(tmp_path)
    derived = graph_assessment(document)
    registry = namespace_registry()
    evidence = document["consequence_graph"]["effects"][0]["evidence"]
    for row in document["objects"]:
        row["specializations"] = derived["required_kinds"].get(row["object_id"], [])
        kinds = {row["kind"], *row["specializations"]}
        for kind, decision in row["classification"].items():
            decision.update(status="APPLIES" if kind in kinds else "DOES_NOT_APPLY",
                reason="The inert fixture declares only its selected roles and paths; no deployed behavior is claimed.",
                evidence=evidence)
        for obligation in requirements_for(registry, kinds):
            row["obligations"][obligation["id"]] = {
                "reason": "The declared fixture needs this boundary; its operational truth is not established.",
                "evidence": evidence, "declaration": {field: "An inert declared " + field + " boundary, not execution evidence."
                    for field in obligation["declaration_fields"]}}
    # Prose DOES_NOT_APPLY is never sufficient; each declared non-applicability
    # carries a current executable witness on the inert fixture subject.
    from test_namespace_admission import bind_refutations
    bind_refutations(tmp_path, document)
    save(tmp_path, document)
    return document


def _declared_non_applicability(document: dict) -> list[tuple[str, str]]:
    return sorted((row["object_id"], kind) for row in document["objects"]
                  for kind, decision in row["classification"].items() if decision["status"] == "DOES_NOT_APPLY")


def _blocker_identity(finding: dict) -> tuple[str, str]:
    return finding["object_id"], finding["reason"].split(" declares DOES_NOT_APPLY", 1)[0]


def _non_applicability(report: dict) -> dict[tuple[str, str], tuple[str, str, str]]:
    """Each declared non-applicability's admission state, keyed by object and kind."""
    return {(assessment["object_id"], row["kind"]):
            (row["non_applicability"], row["refutation_status"], row["refutation_code"])
            for assessment in report["object_assessments"] for row in assessment["classification"]
            if row["decision"] == "DOES_NOT_APPLY"}


def test_complete_admission_executes_both_interpreters_and_keeps_claim_limits(tmp_path):
    document = _admitted(tmp_path)
    report = assess(tmp_path)
    # Every declared non-applicability is admitted as DOCUMENTED, never ESTABLISHED, so
    # Tier 0 admission passes without any runtime, Tier-1-plus or release claim.
    assert report["status"] == "PASS"
    assert report["blockers"] == []
    # The structural and reconciliation checks keep their own honest statuses.
    assert report["consequence_graph"]["status"] == "PASS"
    assert report["consequence_graph"]["runtime_correspondence_status"] == "NOT_ESTABLISHED"
    assert report["consequence_graph"]["external_confinement_status"] == "NOT_ESTABLISHED"
    # Python and Node reproduced the same derivation; the receipt records the Node mechanism digest.
    assert report["independent_reconciliation"]["status"] == "PASS"
    assert re.fullmatch(r"sha256:[0-9a-f]{64}",
                        report["independent_reconciliation"]["receipt"]["javascript_mechanism_digest"])
    assert report["tier_1_plus_status"] == "NOT_ESTABLISHED"
    assert not report["polished"] and not report["release_authorized"]
    # Each declared non-applicability is DOCUMENTED and none blocks, including consequential
    # roles on objects that do not require them and an ordinary kind.
    assert _findings(report, "NAMESPACE_NON_APPLICABILITY_NOT_ESTABLISHED") == []
    admitted = _non_applicability(report)
    assert sorted(admitted) == _declared_non_applicability(document)
    assert set(admitted.values()) == {DOCUMENTED}
    assert {("actuator", "ROBOT"), ("ledger", "FINBOT"), ("agent", "SIM")} <= set(admitted)


def test_one_tampered_witness_is_the_only_fail_while_clean_neighbors_stay_documented(tmp_path):
    document = _admitted(tmp_path)
    # Changing one bound field without re-digesting forges that witness: a FAIL, never DOCUMENTED.
    _row(document, "ledger")["classification"]["FINBOT"]["refutation"]["review_mechanism_digest"] = "sha256:" + "1" * 64
    save(tmp_path, document)
    report = assess(tmp_path)
    assert report["status"] == "FAIL"
    blockers = _findings(report, "NAMESPACE_NON_APPLICABILITY_NOT_ESTABLISHED")
    assert [_blocker_identity(row) for row in blockers] == [("ledger", "FINBOT")]
    assert blockers[0]["status"] == "FAIL"
    assert blockers[0]["reason"] == ("FINBOT declares DOES_NOT_APPLY, but that claim is FAIL (DIGEST_MISMATCH); "
                                     "it adds no obligation, so no obligation is removed; the unestablished claim still blocks admission.")
    assert blockers[0]["next_action"] == CONTRADICTION_NEXT_ACTION
    # Every other declared non-applicability stays DOCUMENTED; none is established or blocks.
    admitted = _non_applicability(report)
    assert admitted.pop(("ledger", "FINBOT")) == ("NOT_ESTABLISHED", "FAIL", "DIGEST_MISMATCH")
    assert len(admitted) == len(_declared_non_applicability(document)) - 1
    assert set(admitted.values()) == {DOCUMENTED}
    assert report["consequence_graph"]["status"] == "PASS"


def test_untyped_financial_endpoint_cannot_hide_behind_another_valid_endpoint(tmp_path):
    document = fixture(tmp_path)
    effect = deepcopy(document["consequence_graph"]["effects"][1])
    effect["object_id"] = "delegate"
    document["consequence_graph"]["effects"].append(effect)
    result = graph_assessment(document)
    assert result["status"] == "UNKNOWN"
    assert any(row["code"] == "NAMESPACE_FINANCIAL_OBJECT_KIND_UNRESOLVED"
               and row["object_id"] == "delegate" for row in result["findings"])
    assert "FINBOT" in result["required_kinds"]["agent"]


def test_independent_graph_witness_disagreement_is_rejected(tmp_path, monkeypatch):
    import json
    from verifier.runtime import namespace_admission
    document = fixture(tmp_path)
    save(tmp_path, document)
    real_run = namespace_admission._run_bounded_reconciler

    def differing_reader(command, wire, **kwargs):
        result = real_run(command, wire, **kwargs)
        if any(str(part).endswith("namespace_reconcile.mjs") for part in command):
            receipt = json.loads(result["stdout"])
            receipt["consequences"]["reachable_effects"] = {}
            result = {**result, "stdout": canonical_bytes(receipt)}
        return result

    monkeypatch.setattr(namespace_admission, "_run_bounded_reconciler", differing_reader)
    report = assess(tmp_path)
    assert report["independent_reconciliation"]["status"] == "FAIL"
    assert "NAMESPACE_RECONCILIATION_UNRESOLVED" in report["blockers"]


def test_schema_and_runtime_accept_same_consequence_shape(tmp_path):
    import json
    import jsonschema
    document = fixture(tmp_path)
    schema_path = Path(__file__).parents[1] / "src/verifier/schemas/verifier-objects-manifest-2.schema.json"
    schema = json.loads(schema_path.read_bytes())
    jsonschema.Draft202012Validator(schema).validate(document)
    validate_manifest(document)
    document["consequence_graph"]["effects"][0]["domain"] = "CONFINED"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(document)
    with pytest.raises(ValueError, match="NAMESPACE_CONSEQUENCE_DOMAIN_INVALID"):
        validate_manifest(document)


@pytest.mark.parametrize("mutation,code", [
    ("unknown_target", "NAMESPACE_CONSEQUENCE_REFERENCE_UNBOUND"),
    ("duplicate_edge", "NAMESPACE_CONSEQUENCE_EDGE_DUPLICATED"),
    ("unknown_relation", "NAMESPACE_CONSEQUENCE_RELATION_INVALID"),
    ("duplicate_effect", "NAMESPACE_CONSEQUENCE_EFFECT_DUPLICATED"),
    ("unknown_domain", "NAMESPACE_CONSEQUENCE_DOMAIN_INVALID"),
    ("extra_field", "NAMESPACE_CONSEQUENCE_FIELDS"),
])
def test_strict_graph_contract(tmp_path, mutation, code):
    document = fixture(tmp_path)
    graph = document["consequence_graph"]
    if mutation == "unknown_target":
        graph["edges"][0]["target"] = "missing"
    if mutation == "duplicate_edge":
        graph["edges"].append(deepcopy(graph["edges"][0]))
    if mutation == "unknown_relation":
        graph["edges"][0]["relation"] = "control"
    if mutation == "duplicate_effect":
        graph["effects"].append(deepcopy(graph["effects"][0]))
    if mutation == "unknown_domain":
        graph["effects"][0]["domain"] = "SAFE"
    if mutation == "extra_field":
        graph["confined"] = True
    with pytest.raises(ValueError, match=code):
        validate_manifest(document)


NODE_DERIVE = """
const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const input = JSON.parse(Buffer.concat(chunks).toString("utf8"));
const { createHash } = await import("node:crypto");
const { pathToFileURL } = await import("node:url");
const { deriveConsequences } = await import(pathToFileURL(input.module).href);
const compare = (left, right) => {
  const a = Array.from(left, ch => ch.codePointAt(0));
  const b = Array.from(right, ch => ch.codePointAt(0));
  for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
};
const canonical = value => {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value).sort(compare).map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
};
const registry = new Map(input.registry.map(row => [row.kind, row]));
const parents = kind => {
  const result = [];
  while (kind !== null) {
    if (!registry.has(kind) || result.includes(kind)) throw new Error("unregistered or cyclic kind");
    result.push(kind);
    kind = registry.get(kind).extends;
  }
  return result;
};
const surfaces = new Map(input.surfaces.map(row => [row.surface_id, row]));
const digest = value => `sha256:${createHash("sha256").update(canonical(value)).digest("hex")}`;
process.stdout.write(JSON.stringify(deriveConsequences(input.manifest, registry, surfaces, parents, compare, digest,
  input.nonstructural_role_decisions)));
"""


def _findings(result: dict, code: str) -> list[dict]:
    return [row for row in result["findings"] if row["code"] == code]


def _evidence(document: dict) -> list[dict]:
    return document["consequence_graph"]["effects"][0]["evidence"]


def _row(document: dict, identifier: str) -> dict:
    return next(row for row in document["objects"] if row["object_id"] == identifier)


@pytest.mark.parametrize("edge_index", [0, 1])
def test_missing_controls_or_actuates_edge_cannot_drop_declared_physical_effect(tmp_path, edge_index):
    # Omitting either edge used to erase the agent's ROBOT requirement while the
    # REAL_PHYSICAL actuator stayed declared, so the graph passed with no role.
    document = fixture(tmp_path)
    document["consequence_graph"]["edges"].pop(edge_index)
    result = graph_assessment(document)
    assert result["status"] == "UNKNOWN"
    found = _findings(result, "NAMESPACE_EFFECT_UNATTRIBUTED")
    assert [row["object_id"] for row in found] == ["actuator"]
    assert "REAL_PHYSICAL" in found[0]["reason"] and "ACTUATOR" in found[0]["reason"]
    assert found[0]["next_action"]


def test_unattributed_financial_path_through_plain_object_is_unknown(tmp_path):
    # A plain OBJECT is not an agent: the real ledger it influences must not PASS.
    document = fixture(tmp_path)
    document["consequence_graph"]["edges"].pop(2)
    result = graph_assessment(document)
    assert result["status"] == "UNKNOWN"
    assert [row["object_id"] for row in _findings(result, "NAMESPACE_EFFECT_UNATTRIBUTED")] == ["ledger"]
    assert "FINBOT" not in result["required_kinds"].get("agent", [])


def test_mislabeled_object_agent_still_acquires_agency_and_every_applicable_role(tmp_path):
    document = fixture(tmp_path)
    _row(document, "agent")["kind"] = "OBJECT"
    result = graph_assessment(document)
    assert result["status"] == "PASS"
    assert result["required_kinds"]["agent"] == ["AGENT", "FINBOT", "ROBOT"]


def test_finbot_kind_agent_with_physical_path_acquires_robot_and_needs_its_harness(tmp_path):
    document = fixture(tmp_path)
    _row(document, "agent")["kind"] = "FINBOT"
    assert graph_assessment(document)["status"] == "PASS"
    _row(document, "agent")["operands"]["harness"] = []
    result = graph_assessment(document)
    assert result["status"] == "UNKNOWN"
    assert "ROBOT" in result["required_kinds"]["agent"]
    assert any(row["code"] == "NAMESPACE_AGENCY_HARNESS_UNRESOLVED" and row["object_id"] == "agent"
               and "ROBOT" in row["reason"] for row in result["findings"])


def test_robot_kind_agent_with_financial_authority_acquires_finbot_without_physical_endpoint(tmp_path):
    document = fixture(tmp_path)
    document["consequence_graph"]["effects"] = [row for row in document["consequence_graph"]["effects"]
                                               if row["domain"] == "REAL_FINANCIAL"]
    document["consequence_graph"]["edges"] = [
        edge for edge in document["consequence_graph"]["edges"]
        if edge["relation"] != "actuates"]
    _row(document, "agent")["kind"] = "ROBOT"
    result = graph_assessment(document)
    assert result["required_kinds"]["agent"] == ["AGENT", "FINBOT"]
    assert result["status"] == "UNKNOWN"
    assert any(row["code"] == "NAMESPACE_ROBOT_CONTROL_CHAIN_UNRESOLVED" and row["object_id"] == "agent"
               and "ROBOT" in row["reason"] for row in result["findings"])


def test_purely_simulated_bot_without_typed_external_endpoint_acquires_no_role(tmp_path):
    document = fixture(tmp_path)
    document["consequence_graph"]["edges"] = []
    document["consequence_graph"]["effects"] = [{
        "object_id": "sim", "domain": "SIMULATED",
        "reason": "The fixture stays inside its declared simulation.",
        "evidence": _evidence(document),
    }]
    result = graph_assessment(document)
    assert "ROBOT" not in result["required_kinds"].get("bot", [])
    assert "FINBOT" not in result["required_kinds"].get("bot", [])
    assert _findings(result, "NAMESPACE_EFFECT_UNATTRIBUTED") == []


@pytest.mark.parametrize("variant,expected", [
    ("simulation", []),
    ("physical", ["ROBOT"]),
    ("financial", ["FINBOT"]),
    ("mixed", ["FINBOT", "ROBOT"]),
])
def test_pure_and_mixed_real_variants_acquire_exactly_their_applicable_roles(tmp_path, variant, expected):
    document = fixture(tmp_path)
    evidence = _evidence(document)
    keep = {"simulation": set(), "physical": {"physical"}, "financial": {"financial"},
            "mixed": {"physical", "financial"}}[variant]
    if "physical" not in keep:
        document["consequence_graph"]["edges"] = [
            edge for edge in document["consequence_graph"]["edges"]
            if edge["relation"] not in {"controls", "actuates"}]
        document["consequence_graph"]["effects"] = [
            effect for effect in document["consequence_graph"]["effects"]
            if effect["domain"] != "REAL_PHYSICAL"]
    if "financial" not in keep:
        document["consequence_graph"]["edges"] = [
            edge for edge in document["consequence_graph"]["edges"]
            if edge["source"] not in {"agent", "delegate"} or edge["relation"] != "influences"]
        document["consequence_graph"]["effects"] = [
            effect for effect in document["consequence_graph"]["effects"]
            if effect["domain"] != "REAL_FINANCIAL"]
    if not document["consequence_graph"]["effects"]:
        document["consequence_graph"]["effects"] = [{
            "object_id": "sim", "domain": "SIMULATED",
            "reason": "No typed external endpoint exists in this variant.",
            "evidence": evidence,
        }]
    result = graph_assessment(document)
    assert result["required_kinds"].get("agent", []) == expected
    assert result["external_confinement_status"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("index,field,value", [
    (0, "relation", "influences"),
    (0, "target", "delegate"),
    (1, "relation", "influences"),
    (2, "target", "controller"),
    (3, "target", "controller"),
])
def test_count_preserving_edge_substitution_never_passes(tmp_path, index, field, value):
    document = fixture(tmp_path)
    document["consequence_graph"]["edges"][index][field] = value
    assert graph_assessment(document)["status"] != "PASS"


def test_count_preserving_duplicate_substitution_is_rejected(tmp_path):
    document = fixture(tmp_path)
    edges = document["consequence_graph"]["edges"]
    edges[1] = deepcopy(edges[0])
    with pytest.raises(ValueError, match="NAMESPACE_CONSEQUENCE_EDGE_DUPLICATED"):
        graph_assessment(document)


def test_unregistered_kind_is_an_object_level_unknown_not_an_exception(tmp_path):
    from verifier.runtime.namespace_consequences import assess_consequences
    from verifier.runtime.namespace_contracts import namespace_registry
    document = fixture(tmp_path)
    _row(document, "ledger")["kind"] = "NOSUCH"
    result = assess_consequences(document["objects"], namespace_registry(),
                                 graph_observation(document), document["consequence_graph"])
    assert result["status"] == "FAIL"
    found = _findings(result, "NAMESPACE_CONSEQUENCE_KIND_UNREGISTERED")
    assert [row["object_id"] for row in found] == ["ledger"]
    assert "NOSUCH" in found[0]["reason"] and found[0]["next_action"]


def test_feedback_through_controller_keeps_physical_chain_and_terminates(tmp_path):
    document = fixture(tmp_path)
    document["consequence_graph"]["edges"].append({"source": "actuator", "relation": "influences",
        "target": "controller", "reason": "Measured feedback returns to the controller.",
        "evidence": _evidence(document)})
    result = graph_assessment(document)
    assert result["status"] == "PASS"
    assert result["required_kinds"]["agent"] == ["FINBOT", "ROBOT"]


def test_registry_keeps_original_kinds_and_explicit_financial_class():
    from verifier.runtime import namespace_consequences as consequences
    from verifier.runtime.namespace_contracts import ObjectKind, namespace_registry
    registry = namespace_registry()
    original = {kind.value for kind in ObjectKind}
    added = {"LEDGER", "TRANSACTION", "ASSET", "MARKET", "MEASUREMENT", "SENSOR",
             "CONTROLLER", "ACTUATOR", "PROTOCOL", "POLICY", "ROBOT", "FINBOT"}
    assert len(original) == 26 and len(registry) == 38
    assert set(registry) == original | added
    assert consequences.FINANCIAL == {"LEDGER", "TRANSACTION", "ASSET", "MARKET"}
    assert all(registry[kind].extends == "OBJECT" for kind in added)


def _variant(tmp_path, name: str) -> tuple[dict, dict]:
    document = fixture(tmp_path)
    observed = graph_observation(document)
    if name == "no_controls":
        document["consequence_graph"]["edges"].pop(0)
    elif name == "finbot_agent":
        _row(document, "agent")["kind"] = "FINBOT"
    elif name == "mislabeled_actuator_source":
        actuator = _row(document, "actuator")
        actuator["kind"] = "OBJECT"
        for surface in observed["surfaces"]:
            if surface["surface_id"] == actuator["surfaces"][0]:
                surface["source_kinds"] = ["ACTUATOR"]
    elif name == "pure_financial":
        for effect in document["consequence_graph"]["effects"]:
            if effect["domain"] == "REAL_PHYSICAL":
                effect["domain"] = "SIMULATED"
    elif name == "feedback_cycle":
        document["consequence_graph"]["edges"].append({"source": "actuator", "relation": "influences",
            "target": "controller", "reason": "Measured feedback returns to the controller.",
            "evidence": _evidence(document)})
    elif name == "retained_added_financial_role":
        row = _row(document, "arch")
        row.update(
            object_id="vstd-architecture",
            kind="ARCH",
            specializations=["ASSET", "FINBOT"],
        )
        row["classification"] = {
            kind: {
                "status": "APPLIES",
                "reason": package_semantic_ownership_domains_agency_collective.obligation_retention_reason(
                    "vstd-architecture", kind
                ),
                "evidence": _evidence(document),
            }
            for kind in ("ASSET", "FINBOT")
        }
    elif name == "retained_original_agency_role":
        row = _row(document, "arch")
        row.update(
            object_id="vstd-model",
            kind="MODEL",
            specializations=["TRANSACTION"],
        )
        row["classification"] = {
            "AGENT": {
                "status": "APPLIES",
                "reason": _retained_original_kind_reason("vstd-model", "AGENT"),
                "evidence": _evidence(document),
            }
        }
    elif name == "retained_compiler_role":
        row = _row(document, "arch")
        row.update(
            object_id="vstd-hardware",
            kind="HARDWARE",
            specializations=["ASSET", "FINBOT"],
        )
        row["classification"] = {
            "FINBOT": {
                "status": "APPLIES",
                "reason": namespace_consequences.compiled_role_reason(
                    "vstd-hardware", "FINBOT"
                ),
                "evidence": _evidence(document),
            }
        }
    return document, observed


@pytest.mark.skipif(shutil.which("node") is None, reason="Node is not installed; parity is UNKNOWN, not PASS")
@pytest.mark.parametrize("variant", ["base", "no_controls", "finbot_agent", "mislabeled_actuator_source",
                                     "pure_financial", "feedback_cycle",
                                     "retained_added_financial_role",
                                     "retained_original_agency_role",
                                     "retained_compiler_role"])
def test_python_and_node_derive_identical_consequences(tmp_path, variant):
    from verifier.runtime import namespace_consequences
    from verifier.runtime.namespace_contracts import namespace_registry
    document, observed = _variant(tmp_path, variant)
    registry = namespace_registry()
    python = namespace_consequences.derive_consequences(document["objects"], registry, observed,
                                                        document["consequence_graph"])
    payload = {"module": str(Path(namespace_consequences.__file__).with_suffix(".mjs")),
               "manifest": document, "surfaces": observed["surfaces"],
               "registry": [{"kind": kind, "extends": contract.extends} for kind, contract in registry.items()],
               "nonstructural_role_decisions": namespace_consequences.nonstructural_role_binding(
                   document["objects"]
               )}
    node = shutil.which("node")
    assert node is not None
    completed = subprocess.run([node, "--input-type=module", "-e", NODE_DERIVE],
                               input=json.dumps(payload).encode("utf-8"), capture_output=True, timeout=60)
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")
    assert json.loads(completed.stdout) == json.loads(json.dumps(python))


@pytest.mark.skipif(shutil.which("node") is None, reason="Node is not installed; parity is UNKNOWN, not PASS")
def test_node_rejects_stale_nonstructural_role_binding(tmp_path):
    document, observed = _variant(tmp_path, "retained_added_financial_role")
    registry = namespace_registry()
    binding = namespace_consequences.nonstructural_role_binding(document["objects"])
    retained = next(
        row for row in document["objects"]
        if row["object_id"] == "vstd-architecture"
    )
    retained["classification"]["FINBOT"]["reason"] += " Substituted."
    payload = {
        "module": str(Path(namespace_consequences.__file__).with_suffix(".mjs")),
        "manifest": document,
        "surfaces": observed["surfaces"],
        "registry": [
            {"kind": kind, "extends": contract.extends}
            for kind, contract in registry.items()
        ],
        "nonstructural_role_decisions": binding,
    }
    node = shutil.which("node")
    assert node is not None

    completed = subprocess.run(
        [node, "--input-type=module", "-e", NODE_DERIVE],
        input=json.dumps(payload).encode("utf-8"),
        capture_output=True,
        timeout=60,
    )

    assert completed.returncode != 0
    assert b"nonstructural role decision unbound" in completed.stderr
