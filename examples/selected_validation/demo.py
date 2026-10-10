"""Experimental Verifier Standard (VSTD) selected validation and bounded loops.

Secure Hash Algorithm 256-bit (SHA-256) equality checks a retained grocery-list
file against a pinned expectation, optionally followed by retained pantry notes.
It does not check the shopping list's quality.
The output is JavaScript Object Notation (JSON), not a conformance receipt.
"""

from __future__ import annotations

import argparse
from dataclasses import replace
import json
from pathlib import Path
from typing import Any

from verifier.core.evidence import BytesDigestMechanism, EvidenceBounds, EvidenceStore
from verifier.core.geometry import (
    Coordinate, CoordinateJudgment, CoordinateStatus, Facet, Grain, Locus,
    LocusKind, Stratum, Subject, VerificationGeometry, VerificationMechanism,
    VerificationSurface,
)
from verifier.interoperability import (
    ComponentAvailability, ComponentKind, ComponentLifecycle,
    InteroperabilityComponentDescriptor, InteroperabilityComponentRegistry,
    analyze_verification_surface, plan_validation,
)
from verifier.interoperability.selected_execution import (
    DIGEST_FACET_DESCRIPTION, DigestHostPolicy, execute_selected_validation,
    prepare_digest_validation, replay_selected_validation,
)
from verifier.interoperability.storage import (
    ImplementationBinding, PackageArtifact, StoredComponentPackage,
)


# Declared before runtime input acquisition; never recomputed from checked bytes.
EXPECTED_DIGEST = "sha256:51528c18af66b4150ebb77dd2392a1db2a4d1b55f182e7626ac4830b5ba951a8"
SELECTED = "coordinate:grocery-byte-digest"
UNSELECTED = "coordinate:grocery-list-completeness"
PANTRY = "coordinate:pantry-byte-digest"
PANTRY_EXPECTED_DIGEST = "sha256:7fc4fd6f9214ff1a2f0e0f1f83b977dae43db13fc30208d6590236fc51433915"


def build_geometry() -> VerificationGeometry:
    """Keep a second, unrelated coordinate visibly unresolved."""
    mechanism = BytesDigestMechanism.mechanism_id
    return VerificationGeometry(
        geometry_id="geometry:retained-grocery-list",
        primary_subject_id="subject:grocery-list",
        subjects=[Subject("subject:grocery-list", "Grocery-list bytes", "1")],
        loci=[Locus("locus:grocery-file", "subject:grocery-list", "Retained file",
                    LocusKind.FILE, Grain.FILE, Stratum.OUTPUT,
                    "examples/selected_validation/artifact.txt")],
        facets=[Facet("bytes.sha256", "Byte digest equality", DIGEST_FACET_DESCRIPTION),
                Facet("list.completeness", "Shopping-list completeness",
                      "Whether this list contains everything its author needs; not checked.")],
        coordinates=[Coordinate(SELECTED, "locus:grocery-file", "bytes.sha256"),
                     Coordinate(UNSELECTED, "locus:grocery-file", "list.completeness")],
        surface=VerificationSurface("surface:grocery-file", "subject:grocery-list",
                                    (SELECTED, UNSELECTED), scope_statement=
                                    "Byte identity and a deliberately unresolved completeness question."),
        mechanisms=[VerificationMechanism(mechanism, "Builtin byte-digest checker", "1",
                                           post_verified=False)],
        judgments=[CoordinateJudgment(SELECTED, CoordinateStatus.INDETERMINATE,
                                      mechanism_ids=(mechanism,),
                                      assumptions=("The host pins the expected digest and supplied-byte association.",),
                                      limitations=("Byte identity does not establish shopping-list completeness.",)),
                   CoordinateJudgment(UNSELECTED, CoordinateStatus.INDETERMINATE,
                                      limitations=("No completeness evidence or checker supplied.",))],
        focus_coordinate_ids=(SELECTED, UNSELECTED),
    )


def build_registry() -> InteroperabilityComponentRegistry:
    """Describe one builtin checker; this is not the seed catalog or a package."""
    return InteroperabilityComponentRegistry("example:selected-digest:1", (
        InteroperabilityComponentDescriptor(
            component_id="component:builtin-byte-digest", label="Builtin byte-digest checker",
            kind=ComponentKind.VERIFIER, lifecycle=ComponentLifecycle.EXPERIMENTAL,
            implementation_ref="verifier.core.evidence:BytesDigestMechanism",
            accepted_schema_ids=(), planning_surface_schema_ids=("VSTD-2",),
            mechanism_ids=(BytesDigestMechanism.mechanism_id,),
            trust_roots=("host-pinned-digest-expectation",),
            availability=ComponentAvailability.AVAILABLE,
            claim_boundary="Exact supplied-byte digest equality only; no completeness or safety claim.",
        ),
    ))


def build_package() -> StoredComponentPackage:
    """Retain this checkout's builtin source without loading code from a package.

    Matching this primary source file does not qualify the interpreter or its
    imported dependencies. The host's installed runtime remains a trust boundary.
    """
    source_path = "src/verifier/core/evidence.py"
    artifacts = []
    for path, media_type in ((source_path, "text/x-python"), ("LICENSE", "text/plain")):
        with (Path(__file__).resolve().parents[2] / path).open("rb") as source:
            content = source.read(1024 * 1024 + 1)
        if len(content) > 1024 * 1024:
            raise ValueError("example file exceeds the one-megabyte acquisition limit")
        artifacts.append(PackageArtifact(path, media_type, content))
    return StoredComponentPackage(
        package_id="example:builtin-byte-digest", package_version="1",
        publisher="Local example host (unsigned declaration)", license="Apache-2.0",
        description="Primary source retained for correspondence to the host builtin; not runtime qualification.",
        registry=build_registry(),
        artifacts=tuple(artifacts),
        implementations=(ImplementationBinding(
            "component:builtin-byte-digest", "verifier.core.evidence:BytesDigestMechanism",
            (source_path,),
        ),),
    )


def build_demo(payload: bytes | None = None, *, package: StoredComponentPackage | None = None) -> dict[str, Any]:
    """Acquire bounded local evidence, execute one selection, and replay it."""
    if payload is None:
        with Path(__file__).with_name("artifact.txt").open("rb") as source:
            payload = source.read(4097)
    if len(payload) > 4096:
        raise ValueError("example input exceeds the 4096-byte acquisition limit")
    geometry = build_geometry()
    registry = package.registry if package is not None else build_registry()
    analysis = analyze_verification_surface(geometry)
    plan = plan_validation(analysis, registry, package=package)
    evidence = EvidenceStore()
    request = prepare_digest_validation(
        geometry, registry, plan, coordinate_id=SELECTED,
        expected_digest=EXPECTED_DIGEST, evidence_ref=evidence.add(payload),
        bounds=EvidenceBounds(max_evidence_items=1, max_evidence_bytes=4096),
        **({"package": package} if package is not None else {}),
    )
    # This local demo is the host: permission is configured here, not read from output.
    policy = DigestHostPolicy((request,), mechanism=BytesDigestMechanism())
    record = execute_selected_validation(request, evidence, policy=policy)
    replay_policy = DigestHostPolicy((request,), mechanism=BytesDigestMechanism())
    replay_selected_validation(record, policy=replay_policy)
    return record


def build_loop_demo(
    first_payload: bytes | None = None, second_payload: bytes | None = None, *,
    package: StoredComponentPackage | None = None, max_steps: int = 2,
    max_reserved_evidence_bytes: int = 8192,
) -> dict[str, Any]:
    """Validate two declared byte coordinates while completeness stays unresolved."""
    from verifier.interoperability.validation_loop import (
        DigestLoopBounds, DigestLoopPolicy, DigestValidationTarget,
        execute_digest_validation_loop, prepare_digest_validation_loop,
        replay_digest_validation_loop,
    )

    geometry = build_geometry()
    geometry.geometry_id = "geometry:shopping-notes-validation-loop"
    geometry.subjects[0] = replace(geometry.subjects[0], label="Grocery-list and pantry-note bytes")
    geometry.loci.append(Locus("locus:pantry-file", geometry.primary_subject_id,
                               "Retained pantry notes", LocusKind.FILE, Grain.FILE,
                               Stratum.OUTPUT, "examples/selected_validation/pantry.txt"))
    geometry.coordinates.append(Coordinate(PANTRY, "locus:pantry-file", "bytes.sha256"))
    geometry.surface = replace(geometry.surface, coordinate_ids=(*geometry.surface.coordinate_ids, PANTRY))
    geometry.judgments.append(CoordinateJudgment(
        PANTRY, CoordinateStatus.INDETERMINATE, mechanism_ids=(BytesDigestMechanism.mechanism_id,),
        assumptions=("The host pins the expected digest and supplied-byte association.",),
        limitations=("Byte identity does not establish pantry-note completeness.",),
    ))
    geometry.focus_coordinate_ids = (*geometry.focus_coordinate_ids, PANTRY)
    evidence = EvidenceStore()
    targets = []
    for payload, name, coordinate, expected in (
        (first_payload, "artifact.txt", SELECTED, EXPECTED_DIGEST),
        (second_payload, "pantry.txt", PANTRY, PANTRY_EXPECTED_DIGEST),
    ):
        if payload is None:
            with Path(__file__).with_name(name).open("rb") as source:
                payload = source.read(4097)
        if len(payload) > 4096:
            raise ValueError("example input exceeds the 4096-byte acquisition limit")
        targets.append(DigestValidationTarget(coordinate, expected, evidence.add(payload), 4096))
    registry = package.registry if package is not None else build_registry()
    request = prepare_digest_validation_loop(
        geometry, registry, tuple(targets),
        bounds=DigestLoopBounds(max_steps, max_reserved_evidence_bytes), package=package,
    )
    # This host approves the exact bounded sequence, not arbitrary future requests.
    policy = DigestLoopPolicy((request,), mechanism=BytesDigestMechanism())
    record = execute_digest_validation_loop(request, evidence, policy=policy)
    replay_digest_validation_loop(record, policy=policy)
    return record


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", action="store_true", help="retain and bind the local builtin's primary source")
    parser.add_argument("--loop", action="store_true", help="run two bounded selected checks with full reassessment")
    arguments = parser.parse_args()
    run_demo = build_loop_demo if arguments.loop else build_demo
    print(json.dumps(run_demo(package=build_package() if arguments.package else None),
                     indent=2, sort_keys=True, allow_nan=False))
