"""Nonexecuting Verifier Standard (VSTD) environment projections.

JavaScript Object Notation (JSON) packages retain exact bytes. Catalogs,
verification geometry, workload commitments, and artifact relations reuse their
existing contracts; no projection supplies a verdict or execution permission.
"""

from __future__ import annotations

from dataclasses import replace

from verifier.core.evidence import EvidenceStore
from verifier.core.geometry import (
    Coordinate, Facet, Grain, Locus, LocusKind, Seam, Stratum, Subject,
    VerificationGeometry, VerificationSurface,
)
from verifier.hardware.models import WorkloadIdentity
from verifier.interoperability.catalog import InteroperabilityComponentRegistry
from verifier.interoperability.network import ArtifactRelation
from verifier.interoperability.storage import ImplementationBinding, PackageArtifact, StoredComponentPackage

from .contracts import (
    EnvironmentContractError, EnvironmentDefinition, EnvironmentInstance,
    EnvironmentRunBinding, artifact_bindings, load_environment_record,
)


RECORD_PATHS = ("environment/definition.json", "environment/instance.json", "environment/run.json")


def environment_registry(definition: EnvironmentDefinition) -> InteroperabilityComponentRegistry:
    return InteroperabilityComponentRegistry(definition.version,
                                            tuple(item.descriptor for item in definition.components))


def environment_surface(definition: EnvironmentDefinition, instance: EnvironmentInstance | None = None,
                        run: EnvironmentRunBinding | None = None) -> VerificationGeometry:
    """Describe selected component and interface questions without asserting answers."""
    subject_id = "environment:" + definition.canonical_digest()
    subject = Subject(subject_id, definition.environment_id, definition.version)
    facets = [Facet("binding", "Artifact binding", "Which exact bytes define this component?"),
              Facet("behavior", "Declared behavior", "Does the component satisfy its declared behavior?")]
    loci = [Locus(item.descriptor.component_id, subject_id, item.descriptor.label,
                  LocusKind.OBJECT, Grain.MODULE, Stratum.SOURCE,
                  "sha256:" + item.artifacts[0].digest) for item in definition.components]
    seams = [Seam(f"connection:{index}", edge.contract, edge.source_component_id,
                  edge.target_component_id, "declared-contract:" + edge.contract)
             for index, edge in enumerate(definition.connections)]
    if instance is not None:
        if instance.definition_digest != definition.canonical_digest():
            raise EnvironmentContractError("geometry instance binds a different definition")
        instance_id = subject_id + ":instance"
        loci.append(Locus(instance_id, subject_id, "Configured environment", LocusKind.OBJECT,
                          Grain.SUBJECT, Stratum.REQUIREMENT, "sha256:" + instance.canonical_digest()))
        for item in definition.components:
            seams.append(Seam(instance_id + ":" + item.descriptor.component_id, "Configured component",
                              item.descriptor.component_id, instance_id, "declared-configuration"))
    if run is not None:
        if instance is None or run.instance_digest != instance.canonical_digest():
            raise EnvironmentContractError("geometry run requires its exact configured instance")
        run_id = subject_id + ":run"
        loci.append(Locus(run_id, subject_id, "Recorded execution", LocusKind.PROCESS,
                          Grain.SUBJECT, Stratum.EXECUTION, "sha256:" + run.canonical_digest()))
        seams.append(Seam(run_id + ":instance", "Execution context", instance_id, run_id, "declared-instance-binding"))
    if instance is not None:
        retained: dict[str, str] = {}
        for ref in artifact_bindings(definition, instance, run):
            if ref.path in retained:
                if retained[ref.path] != ref.digest:
                    raise EnvironmentContractError("geometry artifact path has contradictory bindings")
                continue
            retained[ref.path] = ref.digest
            locus_id = subject_id + ":artifact:" + ref.path
            kind = LocusKind.MODEL if run and run.model_interaction and ref == run.model_interaction.model else LocusKind.OBJECT
            loci.append(Locus(locus_id, subject_id, ref.path, kind, Grain.FILE, Stratum.OUTPUT, "sha256:" + ref.digest))
            target = subject_id + (":run" if run else ":instance")
            seams.append(Seam(locus_id + ":retained", "Retained context or evidence", locus_id, target, "declared-artifact-binding"))
    coordinates = [Coordinate(locus.locus_id + ":" + facet.facet_id, locus.locus_id, facet.facet_id)
                   for locus in loci for facet in facets]
    geometry = VerificationGeometry(subject_id + ":surface", subject_id, [subject], loci, facets,
                                    coordinates, VerificationSurface(subject_id + ":selected", subject_id,
                                    tuple(item.coordinate_id for item in coordinates),
                                    tuple(item.seam_id for item in seams), definition.statement), seams=seams)
    errors = geometry.validate()
    if errors:
        raise EnvironmentContractError("; ".join(errors))
    return geometry


def bind_environment_workload(instance: EnvironmentInstance, workload: WorkloadIdentity) -> WorkloadIdentity:
    """Add an instance commitment; refuse to overwrite a different commitment."""
    digest = instance.canonical_digest()
    if workload.environment_digest and workload.environment_digest != digest:
        raise EnvironmentContractError("workload already binds another environment instance")
    return replace(workload, environment_digest=digest)


def environment_relations(definition: EnvironmentDefinition, instance: EnvironmentInstance | None = None,
                          run: EnvironmentRunBinding | None = None) -> tuple[ArtifactRelation, ...]:
    """Declared supporting relations only; no derived Graph ratings or conformance."""
    pairs = [(ref.path, RECORD_PATHS[0], "implementation-binding")
             for item in definition.components for ref in item.artifacts + item.lineage]
    if instance is not None:
        pairs.append((RECORD_PATHS[0], RECORD_PATHS[1], "definition-binding"))
        pairs.extend((ref.path, RECORD_PATHS[1], "instance-input")
                     for ref in (instance.configuration, instance.initialization, *instance.inputs))
    if run is not None:
        if instance is None:
            raise EnvironmentContractError("a run requires its configured instance")
        pairs.append((RECORD_PATHS[1], RECORD_PATHS[2], "instance-binding"))
        pairs.extend((ref.path, RECORD_PATHS[2], "recorded-run-evidence")
                     for ref in artifact_bindings(definition, instance, run)
                     if ref not in artifact_bindings(definition, instance))
    return tuple(ArtifactRelation("EVIDENCES", source, target, None, coordinate)
                 for source, target, coordinate in dict.fromkeys(pairs))


def package_environment(definition: EnvironmentDefinition, evidence: EvidenceStore, *,
                        publisher: str, license: str, instance: EnvironmentInstance | None = None,
                        run: EnvironmentRunBinding | None = None) -> StoredComponentPackage:
    """Capture records and retained artifacts through the existing inert envelope."""
    if run is not None and instance is None:
        raise EnvironmentContractError("a run package requires an instance")
    artifacts: dict[str, PackageArtifact] = {}
    for path, record in zip(RECORD_PATHS, (definition, instance, run)):
        if record is not None:
            artifacts[path] = PackageArtifact(path, "application/json", record.canonical_json_bytes())
    for ref in artifact_bindings(definition, instance, run):
        if ref.path in RECORD_PATHS:
            raise EnvironmentContractError("artifact collides with reserved environment record path")
        content = evidence.resolve(ref.digest)
        if ref.path in artifacts and artifacts[ref.path].content != content:
            raise EnvironmentContractError("artifact path binds inconsistent bytes")
        artifacts[ref.path] = PackageArtifact(ref.path, "application/octet-stream", content)
    return StoredComponentPackage(
        "environment:" + definition.environment_id, definition.version, publisher, license,
        definition.statement, environment_registry(definition), tuple(artifacts.values()),
        tuple(ImplementationBinding(item.descriptor.component_id, item.descriptor.implementation_ref,
                                    tuple(ref.path for ref in item.artifacts)) for item in definition.components),
    )


def unpack_environment(package: StoredComponentPackage) -> tuple[
    EnvironmentDefinition, EnvironmentInstance | None, EnvironmentRunBinding | None, EvidenceStore
]:
    """Inspect an already loaded package. No paths are materialized or code imported."""
    artifacts = {item.path: item.content for item in package.artifacts}
    records = [load_environment_record(artifacts[path]) if path in artifacts else None for path in RECORD_PATHS]
    definition, instance, run = records
    if (not isinstance(definition, EnvironmentDefinition)
            or (instance is not None and not isinstance(instance, EnvironmentInstance))
            or (run is not None and not isinstance(run, EnvironmentRunBinding))):
        raise EnvironmentContractError("environment records occupy incorrect package slots")
    if run is not None and instance is None:
        raise EnvironmentContractError("run package omits its instance")
    if package.registry != environment_registry(definition):
        raise EnvironmentContractError("package catalog differs from the environment definition")
    expected = {item.descriptor.component_id: (item.descriptor.implementation_ref,
                set(ref.path for ref in item.artifacts)) for item in definition.components}
    if any((binding.implementation_ref, set(binding.artifact_paths)) != expected[binding.component_id]
           for binding in package.implementations):
        raise EnvironmentContractError("package implementation binding differs from definition")
    store = EvidenceStore()
    for content in artifacts.values():
        store.add(content)
    for ref in artifact_bindings(definition, instance, run):
        if ref.path in RECORD_PATHS or ref.path not in artifacts or store.add(artifacts[ref.path]) != "sha256:" + ref.digest:
            raise EnvironmentContractError("package artifact path differs from the environment binding")
    return definition, instance, run, store
