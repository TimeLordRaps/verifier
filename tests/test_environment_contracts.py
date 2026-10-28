"""Experimental environment boundaries for Verifier Standard (VSTD).

JavaScript Object Notation (JSON) transport must remain inert. Secure Hash
Algorithm 256-bit (SHA-256) identity never establishes runtime correctness.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from verifier.core.evidence import EvidenceStore, VerificationSession
from verifier.core.geometry import CoordinateStatus
from verifier.core.geometry_io import load_verification_geometry
from verifier.environments import (
    ArtifactBinding, ComponentRole, EnvironmentCapability, EnvironmentConnection,
    EnvironmentContractError, EnvironmentDefinition, EnvironmentInstance, EnvironmentRole,
    EnvironmentRunBinding, assess_environment, bind_environment_workload, environment_registry,
    environment_relations, environment_surface, evaluate_environment_run, load_environment_record,
    package_environment, unpack_environment,
)
from verifier.environments.contracts import MAX_RECORD_BYTES, artifact_bindings
from verifier.environments.specimen_checks import MixedSuiteMechanism
from verifier.environments.specimens import build_specimen, specimen_bindings
from verifier.hardware.models import WorkloadIdentity
from verifier.interoperability.catalog import InteractionMode
from verifier.interoperability.storage import load_component_package, save_component_package


def run_checks(definition, instance, run, store, *, register=True, checks=None):
    session = VerificationSession(store)
    if register:
        session.register(MixedSuiteMechanism())
    return evaluate_environment_run(definition, instance, run, session,
        specimen_bindings(definition, instance, run) if checks is None else checks)


@pytest.mark.parametrize("family", ["recall", "reasoning", "counter"])
def test_record_package_and_existing_contract_roundtrip(family, tmp_path):
    definition, instance, run, store = build_specimen(family)
    for record in (definition, instance, run):
        pretty = json.dumps(record.to_dict(), indent=3).encode()
        assert load_environment_record(pretty, expected_digest=record.canonical_digest()) == record
    package = package_environment(definition, store, publisher="fixture", license="Apache-2.0", instance=instance, run=run)
    path = tmp_path / "transport.json"
    save_component_package(package, path)
    loaded = load_component_package(path, expected_digest=package.canonical_digest())
    restored = unpack_environment(loaded)
    assert restored[:3] == (definition, instance, run)
    result = run_checks(*restored)
    assert result.bindings_established
    assert all(row.status is CoordinateStatus.VERIFIED for row in result.evaluations)
    assert len(result.mechanism_results) == len(result.evaluations)
    assert result.to_dict()["mechanism_results"][0]["mechanism_digest"] == MixedSuiteMechanism().mechanism_digest
    assert result.to_dict()["conformance"] == "NOT_ESTABLISHED"
    geometry = environment_surface(definition)
    assert geometry.validate() == []
    assert load_verification_geometry(geometry.to_dict()).canonical_digest() == geometry.canonical_digest()
    assert geometry.judgments == []
    assert environment_registry(definition) == package.registry
    paths = {item.path for item in package.artifacts}
    for relation in environment_relations(definition, instance, run):
        assert relation.source_path in paths and relation.target_path in paths
        assert relation.relation_type == "EVIDENCES"
        assert relation.mechanism_path is None


def test_pure_context_definition_needs_no_model_or_episode():
    definition, _, _, store = build_specimen("reasoning")
    runtime = replace(definition.components[0], roles=(ComponentRole.RUNTIME,))
    context = replace(definition, roles=(EnvironmentRole.CONTEXT,), components=(runtime,), connections=())
    assert assess_environment(context, store).bindings_established
    package = package_environment(context, store, publisher="fixture", license="Apache-2.0")
    restored, instance, run, _ = unpack_environment(package)
    assert restored == context and instance is None and run is None
    assert "model" not in context.to_dict()


def test_records_freeze_mutable_constructor_inputs():
    definition, _, _, _ = build_specimen("counter")
    capabilities = list(definition.capabilities)
    frozen = replace(definition, capabilities=capabilities)
    capabilities.clear()
    assert frozen.capabilities == definition.capabilities
    with pytest.raises(FrozenInstanceError):
        frozen.statement = "mutated"


@pytest.mark.parametrize("mutation", [
    lambda value: value.update(unrecognized=True),
    lambda value: value.update(schema_version=EnvironmentDefinition.SCHEMA.replace("0.1", "99")),
    lambda value: value.update(environment_id=8),
    lambda value: value.update(roles="SUBJECT"),
    lambda value: value.update(capabilities=["MISSING_CAPABILITY"]),
    lambda value: value.update(components=[]),
    lambda value: value.update(limitations=[]),
])
def test_strict_records_refuse_unknown_shapes(mutation):
    definition, _, _, _ = build_specimen("reasoning")
    value = definition.to_dict()
    mutation(value)
    with pytest.raises(EnvironmentContractError):
        load_environment_record(json.dumps(value).encode())


def test_direct_decoding_refuses_a_foreign_schema_version():
    definition, _, _, _ = build_specimen("reasoning")
    value = definition.to_dict()
    value["schema_version"] = EnvironmentDefinition.SCHEMA.replace("0.1", "99")
    with pytest.raises(EnvironmentContractError, match="unsupported environment schema version"):
        EnvironmentDefinition.from_dict(value)


@pytest.mark.parametrize("payload", [b'{"schema_version":"a","schema_version":"b"}', b'[]', b'\xff', b'[' * 2000, b' ' * (MAX_RECORD_BYTES + 1)],
                         ids=["duplicate-field", "wrong-root", "invalid-encoding", "excessive-nesting", "oversized"])
def test_ambiguous_invalid_or_oversized_record_is_refused(payload):
    with pytest.raises(EnvironmentContractError):
        load_environment_record(payload)


def test_record_external_anchor_detects_rebound_metadata():
    definition, _, _, _ = build_specimen("reasoning")
    altered = replace(definition, statement="different proposition")
    with pytest.raises(EnvironmentContractError, match="expected digest"):
        load_environment_record(altered.canonical_json_bytes(), expected_digest=definition.canonical_digest())


@pytest.mark.parametrize("field", ["configuration", "initialization"])
def test_instance_substitution_breaks_previous_run_binding(field):
    definition, instance, run, store = build_specimen("reasoning")
    replacement = ArtifactBinding(getattr(instance, field).path, store.add(b'{"changed":true}')[7:])
    altered = replace(instance, **{field: replacement})
    result = run_checks(definition, altered, run, store)
    assert not result.bindings_established
    assert any(row.status is CoordinateStatus.FALSIFIED for row in result.judgments)
    assert all(row.status is CoordinateStatus.INDETERMINATE for row in result.evaluations)


@pytest.mark.parametrize("component_index", [0, 1])
def test_wrapper_or_evaluator_substitution_breaks_definition_binding(component_index):
    definition, instance, run, store = build_specimen("reasoning")
    components = list(definition.components)
    old = components[component_index]
    artifact = replace(old.artifacts[0], digest=store.add(b"different implementation")[7:])
    mechanisms = tuple(replace(item, implementation=artifact) for item in old.mechanisms)
    components[component_index] = replace(old, artifacts=(artifact,), mechanisms=mechanisms)
    altered = replace(definition, components=components)
    result = run_checks(altered, instance, run, store)
    assert not result.bindings_established


def test_even_fully_rebound_evaluator_cannot_select_old_mechanism():
    definition, instance, run, store = build_specimen("reasoning")
    evaluator = definition.components[1]
    artifact = replace(evaluator.artifacts[0], digest=store.add(b"replacement checker")[7:])
    changed = replace(evaluator, artifacts=(artifact,), mechanisms=(replace(evaluator.mechanisms[0], implementation=artifact),))
    definition = replace(definition, components=(definition.components[0], changed))
    instance = replace(instance, definition_digest=definition.canonical_digest())
    run = replace(run, instance_digest=instance.canonical_digest(), workload=replace(run.workload, environment_digest=instance.canonical_digest()))
    for record in (definition, instance, run):
        store.add(record.canonical_json_bytes())
    result = run_checks(definition, instance, run, store)
    assert result.bindings_established
    assert result.evaluations[0].status is CoordinateStatus.INDETERMINATE
    assert "retained evaluator" in result.evaluations[0].limitations[0]


def test_missing_and_corrupted_evidence_have_distinct_results():
    definition, instance, run, store = build_specimen("recall")
    missing = EvidenceStore()
    for ref in artifact_bindings(definition, instance, run):
        if ref != run.trace:
            missing.add(store.resolve(ref.digest))
    unavailable = assess_environment(definition, missing, instance, run)
    assert any(row.status is CoordinateStatus.INDETERMINATE for row in unavailable.judgments)
    store._payloads["sha256:" + run.trace.digest] = b"corrupted retained bytes"
    corrupted = assess_environment(definition, store, instance, run)
    assert any(row.status is CoordinateStatus.FALSIFIED for row in corrupted.judgments)


def test_unavailable_mechanism_and_empty_check_list_remain_unresolved():
    specimen = build_specimen("reasoning")
    for result in (run_checks(*specimen, register=False), run_checks(*specimen, checks=[])):
        assert result.bindings_established
        assert result.evaluations[0].status is CoordinateStatus.INDETERMINATE
        assert result.to_dict()["conformance"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("change", ["expected", "subject", "mechanism", "evidence", "predicate"])
def test_evaluation_binding_cannot_be_relabelled(change):
    specimen = build_specimen("reasoning")
    definition, instance, run, _ = specimen
    binding = specimen_bindings(definition, instance, run)[0]
    altered = {"expected": {"expected": "a" * 64}, "subject": {"subject_id": "neighbor"},
               "mechanism": {"mechanism_digest": "b" * 64},
               "evidence": {"evidence_refs": binding.evidence_refs[:-1]},
               "predicate": {"predicate": "unrelated"}}[change]
    result = run_checks(*specimen, checks=(replace(binding, **altered),))
    assert result.evaluations[0].status is CoordinateStatus.INDETERMINATE


def test_capability_checks_require_capability_declaration():
    definition, instance, run, store = build_specimen("counter")
    definition = replace(definition, capabilities=(EnvironmentCapability.STEP,))
    instance = replace(instance, definition_digest=definition.canonical_digest())
    run = replace(run, instance_digest=instance.canonical_digest(), workload=replace(run.workload, environment_digest=instance.canonical_digest()))
    for record in (definition, instance, run):
        store.add(record.canonical_json_bytes())
    result = run_checks(definition, instance, run, store)
    by_predicate = {row.coordinate_id.rsplit(":", 1)[-1]: row.status for row in result.evaluations}
    assert by_predicate["environment.step"] is CoordinateStatus.VERIFIED
    assert by_predicate["environment.replay"] is CoordinateStatus.INDETERMINATE
    assert by_predicate["environment.state_restore"] is CoordinateStatus.INDETERMINATE


def test_invalid_connections_modes_and_restore_declarations_are_falsified():
    definition, _, _, store = build_specimen("reasoning")
    variants = [replace(definition, connections=(EnvironmentConnection("producer", "evaluator", "wrong-contract"),)),
                replace(definition, interaction_mode=InteractionMode.SIMULATION),
                replace(definition, capabilities=(EnvironmentCapability.STEP,)),
                replace(definition, capabilities=(EnvironmentCapability.STATE_RESTORE,))]
    for variant in variants:
        assert not assess_environment(variant, store).bindings_established


def test_hidden_input_alias_is_detected():
    definition, instance, _, store = build_specimen("recall")
    hidden = instance.inputs[1]
    alias = replace(hidden, path="input/public-alias.json")
    instance = replace(instance, inputs=(*instance.inputs, alias), model_visible_paths=(alias.path,))
    result = assess_environment(definition, store, instance)
    assert any(row.status is CoordinateStatus.FALSIFIED and "input-alias" in row.coordinate_id for row in result.judgments)


def test_workload_projection_preserves_other_commitments_and_refuses_replacement():
    _, instance, _, _ = build_specimen("reasoning")
    workload = WorkloadIdentity("workload", executable_digest="a" * 64, model_commitments=("b" * 64,))
    bound = bind_environment_workload(instance, workload)
    assert bound.executable_digest == workload.executable_digest and bound.model_commitments == workload.model_commitments
    assert bound.environment_digest == instance.canonical_digest()
    with pytest.raises(EnvironmentContractError, match="another environment"):
        bind_environment_workload(instance, replace(workload, environment_digest="c" * 64))


def test_hostile_entrypoints_remain_inert_during_inspect_and_transport(monkeypatch, tmp_path):
    definition, instance, run, store = build_specimen("reasoning")
    marker = tmp_path / "executed"
    content = f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n".encode()
    component = definition.components[0]
    component = replace(component, descriptor=replace(component.descriptor, implementation_ref="hostile:execute"),
                        artifacts=(replace(component.artifacts[0], digest=store.add(content)[7:]),))
    definition = replace(definition, components=(component, definition.components[1]))
    monkeypatch.setitem(sys.modules, "hostile", None)
    package = package_environment(definition, store, publisher="fixture", license="Apache-2.0")
    path = tmp_path / "package.json"
    save_component_package(package, path)
    loaded, _, _, retained = unpack_environment(load_component_package(path))
    assert assess_environment(loaded, retained).bindings_established
    assert not marker.exists()
    assert sorted(item.name for item in tmp_path.iterdir()) == ["package.json"]


def test_package_artifact_path_substitution_is_refused():
    definition, instance, run, store = build_specimen("reasoning")
    package = package_environment(definition, store, publisher="fixture", license="Apache-2.0", instance=instance, run=run)
    changed = tuple(replace(item, content=b"substitution") if item.path == "run/trace.json" else item for item in package.artifacts)
    with pytest.raises(EnvironmentContractError, match="artifact path"):
        unpack_environment(replace(package, artifacts=changed))


def test_package_catalog_substitution_is_refused():
    definition, _, _, store = build_specimen("reasoning")
    package = package_environment(definition, store, publisher="fixture", license="Apache-2.0")
    descriptors = list(package.registry.components)
    descriptors[0] = replace(descriptors[0], label="relabeled evaluator")
    package = replace(package, registry=replace(package.registry, components=descriptors))
    with pytest.raises(EnvironmentContractError, match="catalog differs"):
        unpack_environment(package)


@pytest.mark.parametrize("path", ["INPUT/task.json", "input/task.json/child"])
def test_path_case_and_prefix_aliases_fail_preflight(path):
    definition, instance, _, store = build_specimen("reasoning")
    alias = replace(instance.inputs[0], path=path)
    instance = replace(instance, inputs=(*instance.inputs, alias))
    result = assess_environment(definition, store, instance)
    assert any(row.status is CoordinateStatus.FALSIFIED for row in result.judgments)


def test_stdlib_only_import_and_installed_entrypoint_shape():
    # The pytest `pythonpath` setting does not reach a child started with -S, so the child
    # receives the source root explicitly instead of relying on the ambient environment.
    environment = {key: os.environ[key] for key in ("SystemRoot", "TEMP", "TMP") if key in os.environ}
    environment["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
    completed = subprocess.run([sys.executable, "-S", "-u", "-m", "verifier.environments.specimens"],
                               check=True, capture_output=True, text=True, timeout=30, env=environment)
    rows = [json.loads(line) for line in completed.stdout.splitlines()]
    assert [row["family"] for row in rows] == ["recall", "reasoning", "counter"]
    assert all(row["bindings_established"] and row["conformance"] == "NOT_ESTABLISHED" for row in rows)
