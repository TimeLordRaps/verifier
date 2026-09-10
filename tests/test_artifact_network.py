"""Experimental Verifier Standard (VSTD) artifact-network invariants.

Terminology: Hypertext Transfer Protocol Secure (HTTPS); JavaScript Object
Notation (JSON); Privacy-Enhanced Mail (PEM); Secure Hash Algorithm 256-bit
(SHA-256); uniform resource locator (URL). Tests establish only the bounded
mechanisms they execute.
"""

from __future__ import annotations

import base64
from dataclasses import replace
import importlib.util
import json
from pathlib import Path

import pytest

from verifier.interoperability.network import (
    AUTHORITY_AXIOM_AGENCY,
    AUTHORITY_AXIOM_AGENCY_VERSION,
    AUTHORITY_ACTOR_SCOPE_VERSION,
    AUTHORITY_MODEL_SCHEMA,
    ArtifactRelation,
    AuthorityModel,
    AuthorityState,
    AuthorityTransition,
    CensusEntry,
    ContentAddressedStore,
    DerivationEdge,
    DirectoryEntry,
    MAX_PRIVATE_KEY_BYTES,
    MAX_RECORD_BYTES,
    LocalAuthorityAddition,
    NetworkError,
    ObjectRecord,
    SelfDerivationRecord,
    SiloAssessment,
    SiloCommit,
    assess_composition,
    assess_silo,
    authority_axiom_agency_digest,
    authority_actor_scope_digest,
    build_silo_assessment_receipt,
    build_silo_transfer,
    canonical_bytes,
    census_boundary_members,
    clone_silo,
    create_key_continuity,
    diff_commits,
    download_silo_transfer,
    export_silo,
    materialize_silo_transfer,
    publisher_from_private_key,
    rebuild_silo,
    sign_directory_snapshot,
    sign_head,
    self_derivation_mechanism_bytes,
    verify_directory_snapshot,
    verify_head,
    verify_key_continuity,
)
from verifier.runtime.public_cli import build_parser, main
import verifier.interoperability.network as network_module
import verifier.runtime.network_cli as network_cli_module
from verifier.interoperability.claim_garden import (
    ClaimGardenClientError,
    TransportRequest,
    TransportResponse,
    register_publisher,
    submit_candidate,
)


def _private_key(path: Path) -> Path:
    cryptography = pytest.importorskip("cryptography")
    assert cryptography
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    return path


def _complete_silo(
    tmp_path: Path, *, hostile: bool = False, kind: str = "SILO_CENSUS",
    additions: tuple[LocalAuthorityAddition, ...] = (), with_authority_model: bool = True,
) -> tuple[ContentAddressedStore, SiloCommit]:
    store = ContentAddressedStore(tmp_path / ("hostile" if hostile else "silo"))
    ground = store.add_object(b"declared ground", "text/plain", "ground", "GROUND-1")
    mechanism = store.add_object(self_derivation_mechanism_bytes(), "application/json", "derivation-mechanism", "VSTD-SELF-DERIVATION-MECHANISM-0.1")
    result = store.add_object(b"bounded result", "application/json", "self-derivation-status", "RESULT-1")
    evidence_paths = (
        "evidence/ground-self.json", "evidence/derivation-reflexivity.json",
        "evidence/reflexion-identity.json", "evidence/deriver-cycle-closed.json",
    )
    predicates = ("ground_self", "derivation_reflexivity", "reflexion_identity", "deriver_cycle_closed")
    evidence_records = tuple(
        store.add_object(
            canonical_bytes({
                "schema_version": "VSTD-SELF-DERIVATION-EVIDENCE-0.1",
                "predicate": predicate,
                "subject_path": "result.json",
                "mechanism_digest": mechanism.object_digest,
            }),
            "application/json", "self-derivation-evidence",
            "VSTD-SELF-DERIVATION-EVIDENCE-0.1",
        )
        for predicate in predicates
    )
    entries: tuple[CensusEntry, ...] = (
        CensusEntry("ground.txt", ground, "NECESSARY"),
        CensusEntry("mechanism.bin", mechanism, "NECESSARY"),
        CensusEntry("result.json", result, "NECESSARY"),
        *(CensusEntry(path, record, "NECESSARY") for path, record in zip(evidence_paths, evidence_records)),
    )
    publisher_id = "publisher:sha256:" + "a" * 64
    agency = tuple(action for action in AUTHORITY_AXIOM_AGENCY if not hostile or action != "EXIT_COMPOSITION")
    authority_model = AuthorityModel(
        authority_axiom_agency_version=AUTHORITY_AXIOM_AGENCY_VERSION,
        authority_axiom_agency_digest=authority_axiom_agency_digest(),
        actor_scope_version=AUTHORITY_ACTOR_SCOPE_VERSION,
        actor_scope_digest=authority_actor_scope_digest(),
        initial_state_ids=("initial",), state_universe=("initial", "steady"),
        transition_universe=("settle",),
        states=(
            AuthorityState("initial", agency, additions),
            AuthorityState("steady", agency, additions),
        ),
        transitions=(AuthorityTransition("settle", "initial", "steady", "ANY_ACTOR", "SETTLE"),),
        closure_status="CLOSED", residual_obligations=(),
    )
    if with_authority_model:
        authority_record = store.add_object(
            canonical_bytes(authority_model.to_dict()), "application/json",
            "authority-model", AUTHORITY_MODEL_SCHEMA,
        )
        entries = (*entries, CensusEntry("authority/model.json", authority_record, "NECESSARY"))
    derivations = (
        *(DerivationEdge(path, ("ground.txt",), "mechanism.bin") for path in evidence_paths),
        DerivationEdge("result.json", ("ground.txt", *evidence_paths), "mechanism.bin"),
        *((DerivationEdge("authority/model.json", ("ground.txt",), "mechanism.bin"),) if with_authority_model else ()),
    )
    self_record = SelfDerivationRecord(
        subject_path="result.json", ground_paths=("ground.txt",),
        mechanism_path="mechanism.bin",
        retained_path=("ground.txt", "mechanism.bin", *evidence_paths, "result.json"),
        relation_strength="DERIVES", ground_self=True,
        derivation_reflexivity=True, reflexion_identity=True,
        deriver_cycle_closed=True,
        ground_self_evidence_path=evidence_paths[0],
        derivation_reflexivity_evidence_path=evidence_paths[1],
        reflexion_identity_evidence_path=evidence_paths[2],
        deriver_cycle_closure_evidence_path=evidence_paths[3],
        residual_obligations=(),
    )
    agency_digest = authority_axiom_agency_digest(agency)
    created_at = "2026-09-08T00:00:00Z"
    coverage_universe = census_boundary_members(
        entries, ("ground.txt", "mechanism.bin"), derivations, (), agency, (), (),
        publisher_id=publisher_id, parents=(), completeness_kind=kind,
        authority_version=AUTHORITY_AXIOM_AGENCY_VERSION,
        authority_digest=agency_digest, self_derivation_record=self_record,
        created_at=created_at,
        authority_model_path="authority/model.json" if with_authority_model else None,
        authority_model=authority_model if with_authority_model else None,
    )
    commit = SiloCommit(
        publisher_id=publisher_id,
        parents=(),
        census=entries,
        ground_paths=("ground.txt", "mechanism.bin"),
        derivations=derivations,
        relations=(),
        residual_obligations=(),
        exclusions=(),
        completeness_kind=kind,
        coverage_universe=coverage_universe,
        authority_axiom_agency=agency,
        authority_axiom_agency_version=AUTHORITY_AXIOM_AGENCY_VERSION,
        authority_axiom_agency_digest=agency_digest,
        authority_model_path="authority/model.json" if with_authority_model else None,
        self_derivation_record=self_record,
        created_at=created_at,
    )
    return store, commit


def _boundary(
    commit: SiloCommit,
    store: ContentAddressedStore,
    *,
    census: tuple[CensusEntry, ...] | None = None,
    derivations: tuple[DerivationEdge, ...] | None = None,
    relations: tuple[ArtifactRelation, ...] | None = None,
    agency: tuple[str, ...] | None = None,
    residuals: tuple[str, ...] | None = None,
    exclusions: tuple[str, ...] | None = None,
    agency_digest: str | None = None,
    publisher_id: str | None = None,
    ground_paths: tuple[str, ...] | None = None,
) -> tuple[str, ...]:
    selected_agency = commit.authority_axiom_agency if agency is None else agency
    selected_digest = commit.authority_axiom_agency_digest if agency_digest is None else agency_digest
    authority_model = network_module._load_authority_model(commit, store)
    return census_boundary_members(
        commit.census if census is None else census,
        commit.ground_paths if ground_paths is None else ground_paths,
        commit.derivations if derivations is None else derivations,
        commit.relations if relations is None else relations,
        selected_agency,
        commit.residual_obligations if residuals is None else residuals,
        commit.exclusions if exclusions is None else exclusions,
        publisher_id=commit.publisher_id if publisher_id is None else publisher_id,
        parents=commit.parents,
        completeness_kind=commit.completeness_kind,
        authority_version=commit.authority_axiom_agency_version,
        authority_digest=selected_digest,
        self_derivation_record=commit.self_derivation_record,
        created_at=commit.created_at,
        authority_model_path=commit.authority_model_path,
        authority_model=authority_model,
    )


def _replace_authority_model(
    store: ContentAddressedStore, commit: SiloCommit, model: AuthorityModel,
) -> SiloCommit:
    record = store.add_object(
        canonical_bytes(model.to_dict()), "application/json", "authority-model",
        AUTHORITY_MODEL_SCHEMA,
    )
    census = tuple(
        replace(entry, object_record=record) if entry.path == commit.authority_model_path else entry
        for entry in commit.census
    )
    candidate = replace(commit, census=census)
    return replace(candidate, coverage_universe=_boundary(candidate, store))


def test_assessment_axes_are_independent_and_complete_silo_is_established(tmp_path: Path) -> None:
    store, commit = _complete_silo(tmp_path)
    result = assess_silo(commit, store)
    assert result.reconstructibility == "COMPLETE"
    assert result.derivation_closure == "CLOSED"
    assert result.self_derivability == "ESTABLISHED"
    assert result.completeness == "COMPLETE"
    assert result.completeness_kind == "SILO_CENSUS"
    assert result.silo_grounding == "ESTABLISHED"
    assert result.authority_axiom_agency == "PRESERVED"
    assert "Allowability does not establish access" in result.to_dict()["claim_boundary"]


def test_static_ground_binding_without_checked_model_remains_unknown(tmp_path: Path) -> None:
    store, commit = _complete_silo(tmp_path, with_authority_model=False)
    result = assess_silo(commit, store)
    assert result.completeness == "UNKNOWN"
    assert result.silo_grounding == "UNKNOWN"
    assert result.authority_axiom_agency == "UNKNOWN"
    assert any("completeness denominator is unknown" in reason for reason in result.reasons)
    assert any("static ground binding" in reason for reason in result.reasons)


def test_reachable_ground_removal_is_violated(tmp_path: Path) -> None:
    store, commit = _complete_silo(tmp_path)
    model = network_module._load_authority_model(commit, store)
    assert model is not None
    reduced = tuple(action for action in AUTHORITY_AXIOM_AGENCY if action != "EXIT_COMPOSITION")
    hostile = replace(
        model,
        states=(model.states[0], replace(model.states[1], ground_actions=reduced)),
    )
    result = assess_silo(_replace_authority_model(store, commit, hostile), store)
    assert result.silo_grounding == "ESTABLISHED"
    assert result.authority_axiom_agency == "VIOLATED"
    assert any("removes a ground action" in reason for reason in result.reasons)


@pytest.mark.parametrize("open_surface", ["closure", "residual", "both", "unreachable_extra_state"])
def test_authority_reachable_withdrawal_survives_open_positive_coverage(
    open_surface: str, tmp_path: Path,
) -> None:
    store, commit = _complete_silo(tmp_path)
    model = network_module._load_authority_model(commit, store)
    assert model is not None
    reduced = tuple(action for action in AUTHORITY_AXIOM_AGENCY if action != "EXIT_COMPOSITION")
    states = (model.states[0], replace(model.states[1], ground_actions=reduced))
    if open_surface == "unreachable_extra_state":
        states = (*states, AuthorityState("unvisited", AUTHORITY_AXIOM_AGENCY, ()))
    hostile = replace(
        model, states=states, state_universe=tuple(state.state_id for state in states),
        closure_status="OPEN" if open_surface in {"closure", "both"} else "CLOSED",
        residual_obligations=("unrelated branch remains open",) if open_surface in {"residual", "both"} else (),
    )
    result = assess_silo(_replace_authority_model(store, commit, hostile), store)
    assert result.authority_axiom_agency == "VIOLATED"
    assert result.silo_grounding == "NOT_ESTABLISHED"
    assert result.completeness == "INCOMPLETE"
    assert any("reachable authority state steady removes a ground action" in reason for reason in result.reasons)


def test_authority_unreachable_withdrawal_is_not_a_counterexample(tmp_path: Path) -> None:
    store, commit = _complete_silo(tmp_path)
    model = network_module._load_authority_model(commit, store)
    assert model is not None
    reduced = tuple(action for action in AUTHORITY_AXIOM_AGENCY if action != "EXIT_COMPOSITION")
    disconnected = replace(
        model, states=(model.states[0], replace(model.states[1], ground_actions=reduced)),
        transitions=(), transition_universe=(), closure_status="OPEN",
        residual_obligations=("no retained path to steady",),
    )
    result = assess_silo(_replace_authority_model(store, commit, disconnected), store)
    assert result.authority_axiom_agency == "UNKNOWN"
    assert result.silo_grounding == "NOT_ESTABLISHED"
    assert not any("removes a ground action" in reason for reason in result.reasons)


@pytest.mark.parametrize("binding", [
    "commit_version", "commit_digest", "model_version", "model_digest",
    "actor_scope_version", "actor_scope_digest", "transition_scope", "local_addition_scope",
])
def test_authority_withdrawal_requires_exact_model_and_actor_binding(
    binding: str, tmp_path: Path,
) -> None:
    store, commit = _complete_silo(tmp_path)
    model = network_module._load_authority_model(commit, store)
    assert model is not None
    reduced = tuple(action for action in AUTHORITY_AXIOM_AGENCY if action != "EXIT_COMPOSITION")
    hostile = replace(
        model, states=(model.states[0], replace(model.states[1], ground_actions=reduced)),
        closure_status="OPEN", residual_obligations=("unrelated open branch",),
    )
    if binding == "model_version":
        hostile = replace(hostile, authority_axiom_agency_version="VSTD-AUTHORITY-AXIOM-AGENCY-9")
    elif binding == "model_digest":
        hostile = replace(hostile, authority_axiom_agency_digest="sha256:" + "0" * 64)
    elif binding == "actor_scope_version":
        hostile = replace(hostile, actor_scope_version="VSTD-AUTHORITY-ACTOR-SCOPE-9")
    elif binding == "actor_scope_digest":
        hostile = replace(hostile, actor_scope_digest="sha256:" + "0" * 64)
    elif binding == "transition_scope":
        hostile = replace(hostile, transitions=(replace(hostile.transitions[0], actor_scope="UNKNOWN_ACTOR"),))
    elif binding == "local_addition_scope":
        addition = LocalAuthorityAddition("UNKNOWN_ACTOR", "ANNOTATE_LOCAL_COPY", "LOCAL_ONLY")
        hostile = replace(hostile, states=(replace(hostile.states[0], local_authority_additions=(addition,)), hostile.states[1]))
    candidate = _replace_authority_model(store, commit, hostile)
    if binding == "commit_version":
        candidate = replace(candidate, authority_axiom_agency_version="VSTD-AUTHORITY-AXIOM-AGENCY-9")
    elif binding == "commit_digest":
        candidate = replace(candidate, authority_axiom_agency_digest="sha256:" + "0" * 64)
    assert assess_silo(candidate, store).authority_axiom_agency == "UNKNOWN"


@pytest.mark.parametrize("malformation", [
    "state_denominator", "transition_denominator", "transition_name",
    "source_name", "target_name", "initial_absent", "initial_name",
])
def test_authority_withdrawal_requires_valid_named_reachability_witness(
    malformation: str, tmp_path: Path,
) -> None:
    store, commit = _complete_silo(tmp_path)
    model = network_module._load_authority_model(commit, store)
    assert model is not None
    reduced = tuple(action for action in AUTHORITY_AXIOM_AGENCY if action != "EXIT_COMPOSITION")
    hostile = replace(
        model, states=(model.states[0], replace(model.states[1], ground_actions=reduced)),
        closure_status="OPEN", residual_obligations=("unrelated open branch",),
    )
    if malformation == "state_denominator":
        hostile = replace(hostile, state_universe=("initial",))
    elif malformation == "transition_denominator":
        hostile = replace(hostile, transition_universe=())
    elif malformation == "transition_name":
        hostile = replace(hostile, transitions=(replace(hostile.transitions[0], transition_id="unlisted"),))
    elif malformation == "source_name":
        hostile = replace(hostile, transitions=(replace(hostile.transitions[0], source_state_id="unlisted"),))
    elif malformation == "target_name":
        hostile = replace(hostile, transitions=(replace(hostile.transitions[0], target_state_id="unlisted"),))
    elif malformation == "initial_absent":
        hostile = replace(hostile, initial_state_ids=())
    else:
        hostile = replace(hostile, initial_state_ids=("unlisted",))
    assert assess_silo(_replace_authority_model(store, commit, hostile), store).authority_axiom_agency == "UNKNOWN"


def test_authority_withdrawal_requires_retained_canonical_ground_reachable_model(tmp_path: Path) -> None:
    store, commit = _complete_silo(tmp_path)
    model = network_module._load_authority_model(commit, store)
    assert model is not None
    reduced = tuple(action for action in AUTHORITY_AXIOM_AGENCY if action != "EXIT_COMPOSITION")
    hostile = replace(model, states=(model.states[0], replace(model.states[1], ground_actions=reduced)), closure_status="OPEN")
    candidate = _replace_authority_model(store, commit, hostile)
    ungrounded = replace(candidate, derivations=tuple(edge for edge in candidate.derivations if edge.target_path != candidate.authority_model_path))
    assert assess_silo(ungrounded, store).authority_axiom_agency == "UNKNOWN"
    malformed = store.add_object(b"{malformed", "application/json", "authority-model", AUTHORITY_MODEL_SCHEMA)
    invalid = replace(candidate, census=tuple(
        replace(entry, object_record=malformed) if entry.path == candidate.authority_model_path else entry
        for entry in candidate.census
    ))
    assert assess_silo(invalid, store).authority_axiom_agency == "UNKNOWN"


def test_composition_keeps_reachable_withdrawal_despite_incomplete_positive_coverage(tmp_path: Path) -> None:
    first_store, first = _complete_silo(tmp_path / "first")
    second_store, second = _complete_silo(tmp_path / "second")
    model = network_module._load_authority_model(second, second_store)
    assert model is not None
    reduced = tuple(action for action in AUTHORITY_AXIOM_AGENCY if action != "EXIT_COMPOSITION")
    hostile = replace(
        model, states=(model.states[0], replace(model.states[1], ground_actions=reduced)),
        closure_status="OPEN", residual_obligations=("unrelated open branch",),
    )
    candidate = _replace_authority_model(second_store, second, hostile)
    result = assess_composition((first, candidate), (first_store, second_store))
    assert result["result"] == "NOT_ADMISSIBLE"
    assert result["authority_axiom_agency"] == "VIOLATED"
    assert result["silos"][1]["authority_axiom_agency"] == "VIOLATED"
    assert result["silos"][1]["silo_grounding"] == "NOT_ESTABLISHED"
    assert result["composition_completeness"] == "UNKNOWN"
    assert result["effective_authority_axiom_agency"] == list(AUTHORITY_AXIOM_AGENCY)


@pytest.mark.parametrize(
    ("field", "value"),
    (("closure_status", "OPEN"), ("residual_obligations", ("unclosed authority transition",))),
)
def test_open_or_residual_authority_model_remains_unknown(
    field: str, value: object, tmp_path: Path,
) -> None:
    store, commit = _complete_silo(tmp_path)
    model = network_module._load_authority_model(commit, store)
    assert model is not None
    result = assess_silo(_replace_authority_model(store, commit, replace(model, **{field: value})), store)
    assert result.completeness == "INCOMPLETE"
    assert result.silo_grounding == "NOT_ESTABLISHED"
    assert result.authority_axiom_agency == "UNKNOWN"


def test_mismatched_authority_universe_is_census_incomplete(tmp_path: Path) -> None:
    store, commit = _complete_silo(tmp_path)
    model = network_module._load_authority_model(commit, store)
    assert model is not None
    mismatched = replace(model, state_universe=("initial",))
    result = assess_silo(_replace_authority_model(store, commit, mismatched), store)
    assert result.completeness == "INCOMPLETE"
    assert result.silo_grounding == "NOT_ESTABLISHED"
    assert result.authority_axiom_agency == "UNKNOWN"


def test_unreachable_declared_authority_state_is_census_incomplete(tmp_path: Path) -> None:
    store, commit = _complete_silo(tmp_path)
    model = network_module._load_authority_model(commit, store)
    assert model is not None
    unreachable = replace(model, transitions=())
    result = assess_silo(_replace_authority_model(store, commit, unreachable), store)
    assert result.completeness == "INCOMPLETE"
    assert result.silo_grounding == "NOT_ESTABLISHED"
    assert result.authority_axiom_agency == "UNKNOWN"


def test_local_authority_addition_is_scoped_and_does_not_redefine_ground(tmp_path: Path) -> None:
    addition = LocalAuthorityAddition("ANY_ACTOR", "ANNOTATE_LOCAL_COPY", "COMPOSITION_PRESERVED")
    store, commit = _complete_silo(tmp_path, additions=(addition,))
    result = assess_silo(commit, store)
    assert result.authority_axiom_agency == "PRESERVED"
    assert commit.authority_axiom_agency == AUTHORITY_AXIOM_AGENCY
    assert commit.authority_axiom_agency_digest == authority_axiom_agency_digest()
    assert any(member == "local-authority-addition:" + addition.canonical_digest() for member in commit.coverage_universe)
    with pytest.raises(NetworkError, match="propagation"):
        LocalAuthorityAddition("ANY_ACTOR", "DENY_EXIT", "REVOKE")


def test_unsupported_local_actor_scope_remains_unknown(tmp_path: Path) -> None:
    unsupported = LocalAuthorityAddition("UNREGISTERED_ACTOR", "ANNOTATE_LOCAL_COPY", "LOCAL_ONLY")
    store, commit = _complete_silo(tmp_path, additions=(unsupported,))
    result = assess_silo(commit, store)
    assert result.silo_grounding == "UNKNOWN"
    assert result.authority_axiom_agency == "UNKNOWN"
    assert any("unsupported actor scope" in reason for reason in result.reasons)


def test_self_derivability_does_not_imply_completeness(tmp_path: Path) -> None:
    store, commit = _complete_silo(tmp_path)
    incomplete = replace(commit, residual_obligations=("independent semantic comparison remains",))
    result = assess_silo(incomplete, store)
    assert result.self_derivability == "ESTABLISHED"
    assert result.completeness == "INCOMPLETE"


def test_self_derivability_does_not_imply_silo_grounding(tmp_path: Path) -> None:
    store, commit = _complete_silo(tmp_path, with_authority_model=False)
    result = assess_silo(commit, store)
    assert result.self_derivability == "ESTABLISHED"
    assert result.silo_grounding == "UNKNOWN"


@pytest.mark.parametrize(
    "kind", ["DERIVATIONAL_COVERAGE", "SEMANTIC_COVERAGE", "LOGICAL_DECIDABILITY"]
)
def test_silo_grounding_does_not_claim_unsupported_completeness(
    kind: str, tmp_path: Path,
) -> None:
    store, commit = _complete_silo(tmp_path, kind=kind)
    result = assess_silo(commit, store)
    assert result.silo_grounding == "ESTABLISHED"
    assert result.completeness == "UNKNOWN"


def test_partial_denominator_cannot_claim_complete_census(tmp_path: Path) -> None:
    store, commit = _complete_silo(tmp_path)
    partial = replace(commit, coverage_universe=("ground.txt",))
    assert assess_silo(partial, store).completeness == "INCOMPLETE"


def test_ungrounded_mechanism_leaves_derivation_open(tmp_path: Path) -> None:
    store, commit = _complete_silo(tmp_path)
    ungrounded = replace(
        commit,
        ground_paths=("ground.txt",),
        self_derivation_record=replace(commit.self_derivation_record, ground_paths=("ground.txt",)),
    )
    result = assess_silo(ungrounded, store)
    assert result.derivation_closure == "OPEN"
    assert result.completeness == "INCOMPLETE"
    assert result.self_derivability == "NOT_ESTABLISHED"


def test_open_necessary_path_prevents_exact_silo_census_from_claiming_complete(tmp_path: Path) -> None:
    store, commit = _complete_silo(tmp_path)
    ground_paths = ("ground.txt",)
    candidate = replace(
        commit,
        ground_paths=ground_paths,
        self_derivation_record=replace(commit.self_derivation_record, ground_paths=ground_paths),
    )
    candidate = replace(candidate, coverage_universe=_boundary(candidate, store, ground_paths=ground_paths))
    result = assess_silo(candidate, store)
    assert not candidate.residual_obligations
    assert result.reconstructibility == "COMPLETE"
    assert result.derivation_closure == "OPEN"
    assert result.completeness == "INCOMPLETE"


def test_dispensable_ground_cannot_establish_self_derivability(tmp_path: Path) -> None:
    store, commit = _complete_silo(tmp_path)
    census = tuple(
        replace(entry, necessity="DISPENSABLE") if entry.path == "ground.txt" else entry
        for entry in commit.census
    )
    candidate = replace(commit, census=census)
    candidate = replace(candidate, coverage_universe=_boundary(candidate, store, census=census))
    result = assess_silo(candidate, store)
    assert result.reconstructibility == "COMPLETE"
    assert result.self_derivability == "NOT_ESTABLISHED"


def test_boolean_assertions_without_bound_evidence_do_not_establish_self_derivability(tmp_path: Path) -> None:
    store, commit = _complete_silo(tmp_path)
    evidence_path = commit.self_derivation_record.ground_self_evidence_path
    census = tuple(
        replace(entry, object_record=replace(entry.object_record, artifact_kind="publisher-assertion"))
        if entry.path == evidence_path else entry
        for entry in commit.census
    )
    assert assess_silo(replace(commit, census=census), store).self_derivability == "NOT_ESTABLISHED"


def test_relation_strength_and_retained_path_are_mechanically_bound(tmp_path: Path) -> None:
    _, commit = _complete_silo(tmp_path)
    with pytest.raises(NetworkError, match="relation_strength"):
        replace(commit.derivations[-1], relation_strength="IMPLIES")
    disconnected = replace(
        commit.self_derivation_record,
        retained_path=("ground.txt", "evidence/ground-self.json", "mechanism.bin", "evidence/derivation-reflexivity.json", "evidence/reflexion-identity.json", "evidence/deriver-cycle-closed.json", "result.json"),
    )
    assert assess_silo(replace(commit, self_derivation_record=disconnected), _complete_silo(tmp_path / "fresh")[0]).self_derivability == "NOT_ESTABLISHED"


@pytest.mark.parametrize("kind", ["DERIVATIONAL_COVERAGE", "SEMANTIC_COVERAGE", "LOGICAL_DECIDABILITY"])
def test_unsupported_completeness_kinds_remain_unknown(kind: str, tmp_path: Path) -> None:
    store, commit = _complete_silo(tmp_path, kind=kind)
    result = assess_silo(commit, store)
    assert result.self_derivability == "ESTABLISHED"
    assert result.completeness == "UNKNOWN"
    assert kind in result.completeness_kind


def test_missing_bytes_do_not_become_unknown_success(tmp_path: Path) -> None:
    store, commit = _complete_silo(tmp_path)
    record = commit.census[-1].object_record
    store._object_path(record.object_digest).unlink()
    result = assess_silo(commit, store)
    assert result.reconstructibility == "INCOMPLETE"
    assert result.completeness == "INCOMPLETE"
    assert result.self_derivability == "NOT_ESTABLISHED"


def test_hostile_local_silo_cannot_erase_ground_agency(tmp_path: Path) -> None:
    first_store, first = _complete_silo(tmp_path / "first")
    hostile_store, hostile = _complete_silo(tmp_path / "second", hostile=True)
    result = assess_composition((first, hostile), (first_store, hostile_store))
    assert result["result"] == "NOT_ADMISSIBLE"
    assert result["silos"][0]["silo_grounding"] == "ESTABLISHED"
    assert result["silos"][1]["silo_grounding"] == "UNKNOWN"
    assert result["authority_axiom_agency"] == "VIOLATED"
    assert result["effective_authority_axiom_agency"] == list(AUTHORITY_AXIOM_AGENCY)
    assert "intersection" in result["claim_boundary"]


def test_member_completeness_does_not_imply_composite_completeness(tmp_path: Path) -> None:
    first_store, first = _complete_silo(tmp_path / "first")
    second_store, second = _complete_silo(tmp_path / "second")
    result = assess_composition((first, second), (first_store, second_store))
    assert result["result"] == "NOT_ADMISSIBLE"
    assert result["composition_completeness"] == "UNKNOWN"
    assert result["authority_axiom_agency"] == "UNKNOWN"


def test_restrictive_composite_policy_cannot_erase_ground_agency(tmp_path: Path) -> None:
    first_store, first = _complete_silo(tmp_path / "first")
    second_store, second = _complete_silo(tmp_path / "second")
    second = replace(second, created_at="2026-09-08T00:00:01Z")
    second = replace(second, coverage_universe=_boundary(second, second_store))
    composite_store, composite = _complete_silo(tmp_path / "composite")
    extras = (
        ("members/first.json", canonical_bytes(first.to_dict()), "member-commit"),
        ("members/second.json", canonical_bytes(second.to_dict()), "member-commit"),
        ("adapter.bin", b"adapter", "composition-adapter"),
        ("policy.json", b"restrictive policy", "composition-policy"),
        ("bridge.json", b"bridge relation", "composition-relation"),
    )
    extra_entries = tuple(
        CensusEntry(path, composite_store.add_object(content, "application/json", kind), "NECESSARY")
        for path, content, kind in extras
    )
    extra_derivations = tuple(
        DerivationEdge(entry.path, ("ground.txt",), "mechanism.bin") for entry in extra_entries
    )
    hostile_agency = tuple(action for action in AUTHORITY_AXIOM_AGENCY if action != "EXIT_COMPOSITION")
    hostile_digest = authority_axiom_agency_digest(hostile_agency)
    composite_census = (*composite.census, *extra_entries)
    composite_derivations = (*composite.derivations, *extra_derivations)
    composite_relations = (ArtifactRelation("CHECKS", "members/first.json", "members/second.json", "adapter.bin", "member-compatibility"),)
    composite = replace(
        composite,
        census=composite_census,
        coverage_universe=_boundary(composite, composite_store, census=composite_census, derivations=composite_derivations, relations=composite_relations, agency=hostile_agency, agency_digest=hostile_digest),
        derivations=composite_derivations,
        relations=composite_relations,
        authority_axiom_agency=hostile_agency,
        authority_axiom_agency_digest=hostile_digest,
    )
    result = assess_composition((first, second), (first_store, second_store), composite, composite_store)
    assert result["composition_member_binding"] == "COMPLETE"
    assert result["composite_silo"]["authority_axiom_agency"] == "VIOLATED"
    assert result["result"] == "NOT_ADMISSIBLE"
    assert result["effective_authority_axiom_agency"] == list(AUTHORITY_AXIOM_AGENCY)


def test_composition_must_preserve_required_local_authority_additions(tmp_path: Path) -> None:
    addition = LocalAuthorityAddition("ANY_ACTOR", "ANNOTATE_LOCAL_COPY", "COMPOSITION_PRESERVED")
    first_store, first = _complete_silo(tmp_path / "first", additions=(addition,))
    second_store, second = _complete_silo(tmp_path / "second")
    composite_store, composite = _complete_silo(tmp_path / "composite")
    extras = (
        ("members/first.json", canonical_bytes(first.to_dict()), "member-commit"),
        ("members/second.json", canonical_bytes(second.to_dict()), "member-commit"),
        ("adapter.bin", b"adapter", "composition-adapter"),
        ("policy.json", b"additive composition policy", "composition-policy"),
        ("bridge.json", b"bridge relation", "composition-relation"),
    )
    extra_entries = tuple(
        CensusEntry(path, composite_store.add_object(content, "application/json", kind), "NECESSARY")
        for path, content, kind in extras
    )
    extra_derivations = tuple(
        DerivationEdge(entry.path, ("ground.txt",), "mechanism.bin") for entry in extra_entries
    )
    census = (*composite.census, *extra_entries)
    derivations = (*composite.derivations, *extra_derivations)
    relations = (ArtifactRelation("CHECKS", "members/first.json", "members/second.json", "adapter.bin", "member-compatibility"),)
    candidate = replace(composite, census=census, derivations=derivations, relations=relations)
    candidate = replace(candidate, coverage_universe=_boundary(candidate, composite_store))
    result = assess_composition((first, second), (first_store, second_store), candidate, composite_store)
    assert result["local_authority_addition_preservation"] == "INCOMPLETE"
    assert result["result"] == "NOT_ADMISSIBLE"

    model = network_module._load_authority_model(candidate, composite_store)
    assert model is not None
    preserving = replace(
        model,
        states=tuple(replace(state, local_authority_additions=(addition,)) for state in model.states),
    )
    candidate = _replace_authority_model(composite_store, candidate, preserving)
    result = assess_composition((first, second), (first_store, second_store), candidate, composite_store)
    assert result["local_authority_addition_preservation"] == "COMPLETE"
    assert result["result"] == "ADMISSIBLE"


def test_incomplete_member_binding_cannot_claim_composed_grounding(tmp_path: Path) -> None:
    first_store, first = _complete_silo(tmp_path / "first")
    second_store, second = _complete_silo(tmp_path / "second")
    second = replace(second, created_at="2026-09-08T00:00:01Z")
    second = replace(second, coverage_universe=_boundary(second, second_store))
    composite_store, composite = _complete_silo(tmp_path / "composite")
    extras = (
        ("members/first.json", canonical_bytes(first.to_dict()), "member-commit"),
        ("adapter.bin", b"adapter", "composition-adapter"),
        ("policy.json", b"policy", "composition-policy"),
        ("bridge.json", b"relation", "composition-relation"),
    )
    extra_entries = tuple(
        CensusEntry(path, composite_store.add_object(content, "application/json", kind), "NECESSARY")
        for path, content, kind in extras
    )
    derivations = (*composite.derivations, *(DerivationEdge(entry.path, ("ground.txt",), "mechanism.bin") for entry in extra_entries))
    candidate = replace(composite, census=(*composite.census, *extra_entries), derivations=derivations)
    candidate = replace(candidate, coverage_universe=_boundary(candidate, composite_store))
    result = assess_composition((first, second), (first_store, second_store), candidate, composite_store)
    assert result["composite_silo"]["authority_axiom_agency"] == "PRESERVED"
    assert result["composition_member_binding"] == "INCOMPLETE"
    assert result["authority_axiom_agency"] == "UNKNOWN"
    assert result["result"] == "NOT_ADMISSIBLE"


def test_unknown_agency_binding_blocks_composition_without_calling_it_a_removal(tmp_path: Path) -> None:
    first_store, first = _complete_silo(tmp_path / "first")
    second_store, second = _complete_silo(tmp_path / "second")
    unknown = replace(second, authority_axiom_agency_version="VSTD-AUTHORITY-AXIOM-AGENCY-9")
    assessment = assess_silo(unknown, second_store)
    assert assessment.authority_axiom_agency == "UNKNOWN"
    result = assess_composition((first, unknown), (first_store, second_store))
    assert result["authority_axiom_agency"] == "UNKNOWN"
    assert result["result"] == "NOT_ADMISSIBLE"

    mismatched = replace(second, authority_axiom_agency_digest="sha256:" + "0" * 64)
    assert assess_silo(mismatched, second_store).authority_axiom_agency == "UNKNOWN"

    extended_actions = (*AUTHORITY_AXIOM_AGENCY, "LOCAL_ADMINISTRATIVE_ACTION")
    extended = replace(
        second,
        authority_axiom_agency=extended_actions,
        authority_axiom_agency_digest=authority_axiom_agency_digest(extended_actions),
    )
    assert assess_silo(extended, second_store).authority_axiom_agency == "UNKNOWN"
    assert assess_composition((first, extended), (first_store, second_store))["result"] == "NOT_ADMISSIBLE"


def test_arbitrary_mechanism_or_evidence_substitution_cannot_establish_self_derivability(tmp_path: Path) -> None:
    store, commit = _complete_silo(tmp_path)
    arbitrary_mechanism = store.add_object(b"publisher assertion", "application/json", "derivation-mechanism", "MECHANISM-OTHER")
    census = tuple(
        replace(entry, object_record=arbitrary_mechanism) if entry.path == "mechanism.bin" else entry
        for entry in commit.census
    )
    substituted = replace(
        commit,
        census=census,
        coverage_universe=_boundary(commit, store, census=census),
    )
    assert assess_silo(substituted, store).self_derivability == "NOT_ESTABLISHED"

    arbitrary_evidence = store.add_object(b"{}", "application/json", "self-derivation-evidence", "VSTD-SELF-DERIVATION-EVIDENCE-0.1")
    census = tuple(
        replace(entry, object_record=arbitrary_evidence) if entry.path == "evidence/ground-self.json" else entry
        for entry in commit.census
    )
    substituted = replace(
        commit,
        census=census,
        coverage_universe=_boundary(commit, store, census=census),
    )
    assert assess_silo(substituted, store).self_derivability == "NOT_ESTABLISHED"


def test_typed_census_boundary_detects_omitted_category_members(tmp_path: Path) -> None:
    store, base = _complete_silo(tmp_path)
    relation = ArtifactRelation("CHECKS", "ground.txt", "result.json", "mechanism.bin", "fixture-coordinate")
    residuals = ("open semantic obligation",)
    exclusions = ("explicitly excluded external namespace",)
    candidate_without_boundary = replace(base, parents=("sha256:" + "b" * 64,), relations=(relation,), residual_obligations=residuals, exclusions=exclusions)
    complete_boundary = _boundary(candidate_without_boundary, store)
    candidate = replace(candidate_without_boundary, coverage_universe=complete_boundary)
    assert not any("typed census boundary" in reason for reason in assess_silo(candidate, store).reasons)
    prefixes = (
        "object:", "necessity:", "ground-path:", "derivation:",
        "mechanism-dependency:", "premise-dependency:", "relation:",
        "authority-action:", "residual:", "exclusion:",
        "publisher:", "parent:", "completeness-kind:",
        "self-derivation-record:", "created-at:", "authority-binding:",
        "authority-model-path:", "authority-model:",
        "authority-actor-scope-binding:", "authority-initial-state:",
        "authority-state-universe:", "authority-transition-universe:",
        "authority-state:", "authority-state-ground-action:",
        "authority-transition:",
    )
    for prefix in prefixes:
        omitted = next(member for member in complete_boundary if member.startswith(prefix))
        assessment = assess_silo(replace(candidate, coverage_universe=tuple(member for member in complete_boundary if member != omitted)), store)
        assert any("typed census boundary" in reason for reason in assessment.reasons), prefix


def test_authority_addition_and_residual_are_census_members(tmp_path: Path) -> None:
    addition = LocalAuthorityAddition("ANY_ACTOR", "ANNOTATE_LOCAL_COPY", "COMPOSITION_PRESERVED")
    store, commit = _complete_silo(tmp_path, additions=(addition,))
    addition_member = "local-authority-addition:" + addition.canonical_digest()
    assert addition_member in commit.coverage_universe
    omitted = replace(commit, coverage_universe=tuple(item for item in commit.coverage_universe if item != addition_member))
    assert assess_silo(omitted, store).completeness == "INCOMPLETE"

    model = network_module._load_authority_model(commit, store)
    assert model is not None
    residual = _replace_authority_model(
        store, commit, replace(model, residual_obligations=("unclosed authority branch",)),
    )
    residual_member = next(item for item in residual.coverage_universe if item.startswith("authority-residual:"))
    omitted = replace(residual, coverage_universe=tuple(item for item in residual.coverage_universe if item != residual_member))
    assert assess_silo(omitted, store).completeness == "INCOMPLETE"


def test_content_store_is_non_overwriting_and_detects_substitution(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path / "store")
    record = store.add_object(b"first", "text/plain", "evidence")
    assert store.add_object(b"first", "text/plain", "evidence") == record
    store._object_path(record.object_digest).write_bytes(b"wrong")
    with pytest.raises(NetworkError, match="do not match"):
        store.read_object(record)


def test_record_and_private_key_reads_are_bounded(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path / "store")
    store.initialize()
    with pytest.raises(NetworkError, match="record"):
        store.put_record("heads", {"payload": "x" * MAX_RECORD_BYTES})
    digest = "sha256:" + "0" * 64
    record_path = store.root / "records" / "heads" / ("0" * 64 + ".json")
    record_path.write_bytes(b"x" * (MAX_RECORD_BYTES + 1))
    with pytest.raises(NetworkError, match="byte bound"):
        store.read_record("heads", digest)
    key_path = tmp_path / "oversized.pem"
    key_path.write_bytes(b"x" * (MAX_PRIVATE_KEY_BYTES + 1))
    with pytest.raises(NetworkError, match="byte bound"):
        publisher_from_private_key(key_path, "Oversized", "Rejected before parsing.")


def test_commit_identity_and_diff_are_path_and_digest_only(tmp_path: Path) -> None:
    store, first = _complete_silo(tmp_path)
    changed_record = store.add_object(b"changed", "application/json", "receipt", "RESULT-1")
    changed_entries = tuple(replace(item, object_record=changed_record) if item.path == "result.json" else item for item in first.census)
    second = replace(first, census=changed_entries)
    assert first.canonical_digest() != second.canonical_digest()
    assert diff_commits(first, second)["changed"] == ["result.json"]
    assert "do not establish" in diff_commits(first, second)["claim_boundary"]


def test_signed_head_key_continuity_directory_and_export_rebuild(tmp_path: Path) -> None:
    old_key = _private_key(tmp_path / "old.pem")
    new_key = _private_key(tmp_path / "new.pem")
    publisher = publisher_from_private_key(old_key, "Specimen", "Test publisher; not real-world identity evidence.")
    store, template = _complete_silo(tmp_path / "content")
    commit = replace(template, publisher_id=publisher.publisher_id, coverage_universe=_boundary(template, store, publisher_id=publisher.publisher_id))
    head = sign_head(commit, old_key, 0, None, "2026-09-08T00:00:00Z")
    verify_head(head, publisher)

    continuity = create_key_continuity(publisher.publisher_id, old_key, new_key, 1)
    new_key_id = verify_key_continuity(continuity, publisher.active_key_ids[0])
    assert new_key_id != publisher.active_key_ids[0]
    tampered = replace(continuity, new_signature_base64url=base64.urlsafe_b64encode(b"\0" * 64).decode("ascii").rstrip("="))
    with pytest.raises(NetworkError, match="old-key and new-key"):
        verify_key_continuity(tampered, publisher.active_key_ids[0])

    entry = DirectoryEntry(publisher.publisher_id, head.canonical_digest(), "https://publisher.invalid/silo/", "LISTED")
    directory = sign_directory_snapshot((entry,), old_key, 0, None, "2026-09-08T00:00:00Z")
    verify_directory_snapshot(directory)
    assert "visibility" in directory.to_dict()["entries"][0]

    exported = export_silo(commit, head, publisher, store, tmp_path / "export")
    assert "assessment_receipt_digest" in exported
    assert "assessment" not in exported
    rebuilt = rebuild_silo(tmp_path / "export", tmp_path / "rebuilt")
    assert rebuilt == exported
    assert (tmp_path / "export" / "objects").is_dir()

    extra_export = tmp_path / "extra-export"
    export_silo(commit, head, publisher, store, extra_export)
    (extra_export / "untracked.bin").write_bytes(b"not in the manifest")
    with pytest.raises(NetworkError, match="exactly match"):
        rebuild_silo(extra_export, tmp_path / "extra-rebuild")

    oversized_export = tmp_path / "oversized-export"
    export_silo(commit, head, publisher, store, oversized_export)
    (oversized_export / "oversized.bin").write_bytes(b"x" * (MAX_RECORD_BYTES + 1))
    with pytest.raises(NetworkError, match="byte bound"):
        rebuild_silo(oversized_export, tmp_path / "oversized-rebuild")


def _transfer_fixture(tmp_path: Path) -> tuple[dict[str, object], dict[str, object]]:
    key = _private_key(tmp_path / "transfer.pem")
    publisher = publisher_from_private_key(key, "Transfer specimen", "Test-only transfer identity.")
    store, template = _complete_silo(tmp_path / "content")
    commit = replace(
        template, publisher_id=publisher.publisher_id,
        coverage_universe=_boundary(template, store, publisher_id=publisher.publisher_id),
    )
    head = sign_head(commit, key, 0, None, "2026-09-09T00:00:00Z")
    return build_silo_transfer(commit, head, publisher, store), {
        "commit": commit, "head": head, "publisher": publisher, "store": store,
    }


def _claim_garden_export(tmp_path: Path) -> tuple[Path, Path, PublisherRecord, dict[str, object]]:
    key = _private_key(tmp_path / "claim-garden.pem")
    publisher = publisher_from_private_key(key, "Claim Garden specimen", "Test-only publisher.")
    store, template = _complete_silo(tmp_path / "claim-garden-source")
    commit = replace(template, publisher_id=publisher.publisher_id,
                     coverage_universe=_boundary(template, store, publisher_id=publisher.publisher_id))
    head = sign_head(commit, key, 0, None, "2026-09-09T00:00:00Z")
    export_root = tmp_path / "claim-garden-export"
    manifest = export_silo(commit, head, publisher, store, export_root)
    return export_root, key, publisher, manifest


def test_claim_garden_registration_and_submission_stop_at_pending_review(tmp_path: Path) -> None:
    export_root, key, publisher, manifest = _claim_garden_export(tmp_path)
    token = "A" * 43
    requests: list[TransportRequest] = []

    def transport(request: TransportRequest) -> TransportResponse:
        requests.append(request)
        headers = {"Content-Type": "application/json"}
        if request.url.endswith("/v1/publishers/register"):
            body = {"access_token": token, "publisher_id": publisher.publisher_id}
            return TransportResponse(201, headers, canonical_bytes(body))
        if request.url.endswith("/v1/pushes"):
            body = {"expires_at": "2026-09-16T00:00:00.000Z", "id": "11111111-1111-4111-8111-111111111111", "state": "OPEN"}
            return TransportResponse(201, headers, canonical_bytes(body))
        if "/objects/" in request.url:
            body = {"digest": request.url.rsplit("/", 1)[1], "state": "QUARANTINED"}
            return TransportResponse(201, headers, canonical_bytes(body))
        if request.url.endswith("/finalize"):
            body = {"commit_digest": manifest["commit_digest"], "head_digest": manifest["head_digest"], "state": "PENDING_REVIEW"}
            return TransportResponse(202, headers, canonical_bytes(body))
        raise AssertionError(request.url)

    credential = tmp_path / "publisher.credential"
    registered = register_publisher(export_root, "https://hub.invalid", key,
                                    "2026-09-09T00:00:00Z", credential, transport=transport)
    assert registered["publication"] == "NOT_ESTABLISHED"
    assert credential.read_text(encoding="ascii") == token
    assert json.loads(requests[0].body)["publisher"] == publisher.to_dict()
    assert "access_token" not in str(registered)
    submitted = submit_candidate(export_root, "https://hub.invalid", credential,
                                 expected_head_digest=None, genesis=True, transport=transport)
    assert submitted["state"] == "PENDING_REVIEW"
    assert submitted["publication"] == "NOT_ESTABLISHED"
    assert submitted["commit_digest"] == manifest["commit_digest"]
    assert submitted["head_digest"] == manifest["head_digest"]
    assert all("moderation" not in request.url for request in requests)
    assert all(token not in request.url and token not in request.body.decode("utf-8", errors="ignore") for request in requests)


def test_claim_garden_submission_preserves_transaction_after_ambiguous_failure(tmp_path: Path) -> None:
    export_root, _, _, _ = _claim_garden_export(tmp_path)
    credential = tmp_path / "failure.credential"
    credential.write_text("B" * 43, encoding="ascii")
    calls = 0

    def transport(request: TransportRequest) -> TransportResponse:
        nonlocal calls
        calls += 1
        if calls == 1:
            body = {"expires_at": "2026-09-16T00:00:00.000Z", "id": "22222222-2222-4222-8222-222222222222", "state": "OPEN"}
            return TransportResponse(201, {"Content-Type": "application/json"}, canonical_bytes(body))
        raise OSError("ambiguous test transport failure")

    result = submit_candidate(export_root, "https://hub.invalid", credential,
                              expected_head_digest=None, genesis=True, transport=transport)
    assert result["result"] == "INDETERMINATE"
    assert result["state"] == "UNKNOWN"
    assert result["transaction_id"] == "22222222-2222-4222-8222-222222222222"
    assert result["publication"] == "NOT_ESTABLISHED"
    assert calls == 2
    with pytest.raises(ClaimGardenClientError, match="credential-free HTTPS"):
        submit_candidate(export_root, "http://hub.invalid", credential,
                         expected_head_digest=None, genesis=True, transport=transport)


def test_claim_garden_preflight_refuses_external_state_before_transport(tmp_path: Path) -> None:
    export_root, key, _, _ = _claim_garden_export(tmp_path)
    calls = 0

    def transport(_: TransportRequest) -> TransportResponse:
        nonlocal calls
        calls += 1
        raise AssertionError("transport must remain unused")

    occupied = tmp_path / "occupied.credential"
    occupied.write_text("preserve", encoding="utf-8")
    with pytest.raises(ClaimGardenClientError, match="destination must be absent"):
        register_publisher(export_root, "https://hub.invalid", key,
                           "2026-09-09T00:00:00Z", occupied, transport=transport)
    assert occupied.read_text(encoding="utf-8") == "preserve"
    candidate = tmp_path / "candidate.credential"
    with pytest.raises(ClaimGardenClientError, match="credential-free HTTPS"):
        register_publisher(export_root, "http://hub.invalid", key,
                           "2026-09-09T00:00:00Z", candidate, transport=transport)
    assert not candidate.exists()
    credential = tmp_path / "publisher.credential"
    credential.write_text("C" * 43, encoding="ascii")
    with pytest.raises(ClaimGardenClientError, match="declared expected head"):
        submit_candidate(export_root, "https://hub.invalid", credential,
                         expected_head_digest="sha256:" + "a" * 64, genesis=False,
                         transport=transport)
    assert calls == 0


def test_transfer_materializes_native_tree_and_supports_offline_rebuild(tmp_path: Path) -> None:
    transfer, _ = _transfer_fixture(tmp_path)
    encoded = canonical_bytes(transfer)
    materialized = tmp_path / "materialized"
    manifest = materialize_silo_transfer(encoded, materialized)
    assert manifest == transfer["portable_manifest"]
    assert rebuild_silo(materialized, tmp_path / "offline-rebuild") == manifest
    assert clone_silo(str(materialized), tmp_path / "path-clone") == manifest
    transfer_file = tmp_path / "transfer.json"
    transfer_file.write_bytes(encoded)
    assert clone_silo(transfer_file, tmp_path / "file-clone") == manifest
    with pytest.raises(NetworkError, match="absent"):
        materialize_silo_transfer(encoded, materialized)


def test_local_transfer_clone_rejects_link_oversize_noncanonical_and_existing_destination(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    transfer, _ = _transfer_fixture(tmp_path)
    valid = tmp_path / "valid-transfer.json"
    valid.write_bytes(canonical_bytes(transfer))

    existing = tmp_path / "existing"
    existing.mkdir()
    with pytest.raises(NetworkError, match="absent"):
        clone_silo(valid, existing)

    noncanonical = tmp_path / "noncanonical-transfer.json"
    noncanonical.write_text(json.dumps(transfer, indent=2), encoding="utf-8")
    with pytest.raises(NetworkError, match="canonical JSON"):
        clone_silo(noncanonical, tmp_path / "noncanonical-clone")

    oversized = tmp_path / "oversized-transfer.json"
    oversized.write_bytes(b"x" * (network_module.MAX_TRANSFER_BYTES + 1))
    with pytest.raises(NetworkError, match="byte bound"):
        clone_silo(oversized, tmp_path / "oversized-clone")

    simulated_link = tmp_path / "linked-transfer.json"
    original_lstat = Path.lstat

    def link_lstat(path: Path) -> object:
        if path == simulated_link:
            return type("LinkStat", (), {"st_mode": 0o120777, "st_file_attributes": 0})()
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", link_lstat)
    with pytest.raises(NetworkError, match="ordinary non-link file"):
        clone_silo(simulated_link, tmp_path / "linked-clone")
    with pytest.raises(NetworkError, match="must use HTTPS"):
        clone_silo("http://hub.invalid/transfer", tmp_path / "insecure-remote-clone")


def test_transfer_carries_and_verifies_complete_key_continuity(tmp_path: Path) -> None:
    old_key = _private_key(tmp_path / "old-transfer.pem")
    new_key = _private_key(tmp_path / "new-transfer.pem")
    publisher = publisher_from_private_key(old_key, "Rotated specimen", "Test-only rotated transfer identity.")
    store, template = _complete_silo(tmp_path / "rotated-content")
    commit = replace(
        template, publisher_id=publisher.publisher_id,
        coverage_universe=_boundary(template, store, publisher_id=publisher.publisher_id),
    )
    continuity = create_key_continuity(publisher.publisher_id, old_key, new_key, 1)
    continuity_digest = store.put_record("keys", continuity.to_dict())
    publisher = replace(
        publisher,
        active_key_ids=(verify_key_continuity(continuity, publisher.active_key_ids[0]),),
        key_continuity_digests=(continuity_digest,),
    )
    head = sign_head(commit, new_key, 0, None, "2026-09-09T00:00:00Z")
    transfer = build_silo_transfer(commit, head, publisher, store)
    assert transfer["key_continuity"] == [continuity.to_dict()]
    assert materialize_silo_transfer(transfer, tmp_path / "rotated-materialized") == transfer["portable_manifest"]


@pytest.mark.parametrize("mutation", ["extra", "missing", "duplicate", "digest", "base64", "signature", "assessment", "continuity"])
def test_transfer_substitution_and_inventory_attacks_fail_closed(
    mutation: str, tmp_path: Path,
) -> None:
    transfer, _ = _transfer_fixture(tmp_path)
    if mutation == "extra":
        raw = b"unselected"
        transfer["objects"].append({"digest": network_module.digest_bytes(raw), "bytes_base64url": network_module._base64url_encode(raw)})
    elif mutation == "missing":
        transfer["objects"].pop()
    elif mutation == "duplicate":
        transfer["objects"].append(dict(transfer["objects"][0]))
    elif mutation == "digest":
        transfer["objects"][0]["digest"] = "sha256:" + "0" * 64
    elif mutation == "base64":
        transfer["objects"][0]["bytes_base64url"] += "="
    elif mutation == "signature":
        transfer["signed_head"]["signature_base64url"] = base64.urlsafe_b64encode(b"\0" * 64).decode("ascii").rstrip("=")
        transfer["portable_manifest"]["head_digest"] = network_module.digest_bytes(canonical_bytes(transfer["signed_head"]))
    elif mutation == "assessment":
        transfer["assessment_receipt"]["assessment"]["claim_boundary"] = "substituted"
        transfer["portable_manifest"]["assessment_receipt_digest"] = network_module.digest_bytes(canonical_bytes(transfer["assessment_receipt"]))
    else:
        transfer["publisher"]["key_continuity_digests"] = ["sha256:" + "1" * 64]
        transfer["portable_manifest"]["publisher_digest"] = network_module.digest_bytes(canonical_bytes(transfer["publisher"]))
    destination = tmp_path / mutation
    with pytest.raises(NetworkError):
        materialize_silo_transfer(transfer, destination)
    assert not destination.exists()


def test_transfer_rejects_noncanonical_json_before_writing(tmp_path: Path) -> None:
    transfer, _ = _transfer_fixture(tmp_path)
    destination = tmp_path / "noncanonical"
    with pytest.raises(NetworkError, match="canonical JSON"):
        materialize_silo_transfer(json.dumps(transfer, indent=2).encode(), destination)
    duplicate_key = b'{"schema_version":"VSTD-SILO-TRANSFER-0.1",' + canonical_bytes(transfer)[1:]
    with pytest.raises(NetworkError, match="duplicate JSON key"):
        materialize_silo_transfer(duplicate_key, destination)
    assert not destination.exists()


def test_transfer_download_is_bounded_https_and_injectable(tmp_path: Path) -> None:
    transfer, _ = _transfer_fixture(tmp_path)
    payload = canonical_bytes(transfer)

    class Response:
        status = 200

        def __init__(self, body: bytes, headers: dict[str, str], final_url: str = "https://hub.invalid/export") -> None:
            self.body = body
            self.headers = headers
            self.final_url = final_url
            self.offset = 0

        def __enter__(self) -> "Response":
            return self

        def __exit__(self, *_: object) -> None:
            return None

        def geturl(self) -> str:
            return self.final_url

        def read(self, amount: int) -> bytes:
            chunk = self.body[self.offset:self.offset + amount]
            self.offset += len(chunk)
            return chunk

    class Opener:
        def __init__(self, response: Response) -> None:
            self.response = response
            self.request: object | None = None
            self.timeout: object | None = None

        def open(self, request: object, timeout: object) -> Response:
            self.request = request
            self.timeout = timeout
            return self.response

    opener = Opener(Response(payload, {"Content-Type": "application/vnd.vstd.silo-transfer+json", "Content-Length": str(len(payload))}))
    assert download_silo_transfer("https://hub.invalid/export", tmp_path / "download", opener=opener) == transfer["portable_manifest"]
    assert opener.timeout == 10
    assert opener.request.get_header("Authorization") is None
    assert opener.request.get_header("Cookie") is None
    assert opener.request.get_header("Accept-encoding") == "identity"
    with pytest.raises(NetworkError, match="credential-free HTTPS"):
        download_silo_transfer("http://hub.invalid/export", tmp_path / "http", opener=opener)
    with pytest.raises(NetworkError, match="truncated"):
        download_silo_transfer("https://hub.invalid/export", tmp_path / "truncated", opener=Opener(Response(payload[:-1], {"Content-Type": "application/json", "Content-Length": str(len(payload))})))
    with pytest.raises(NetworkError, match="content type"):
        download_silo_transfer("https://hub.invalid/export", tmp_path / "type", opener=Opener(Response(payload, {"Content-Type": "text/html"})))
    with pytest.raises(NetworkError, match="declared byte bound"):
        download_silo_transfer("https://hub.invalid/export", tmp_path / "large", opener=Opener(Response(b"", {"Content-Type": "application/json", "Content-Length": str(network_module.MAX_TRANSFER_BYTES + 1)})))
    with pytest.raises(NetworkError, match="final URL is not HTTPS"):
        download_silo_transfer("https://hub.invalid/export", tmp_path / "downgrade", opener=Opener(Response(payload, {"Content-Type": "application/json"}, "http://hub.invalid/export")))
    with pytest.raises(NetworkError, match="identity content encoding"):
        download_silo_transfer("https://hub.invalid/export", tmp_path / "encoded", opener=Opener(Response(payload, {"Content-Type": "application/json", "Content-Encoding": "gzip"})))
    redirect_handler = network_module._BoundedHttpsRedirectHandler()
    redirect_handler.redirects = network_module.MAX_TRANSFER_REDIRECTS
    with pytest.raises(NetworkError, match="bounded HTTPS"):
        redirect_handler.redirect_request(object(), None, 302, "redirect", {}, "https://hub.invalid/next")


def test_transfer_materialization_propagates_post_write_validation_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    transfer, _ = _transfer_fixture(tmp_path)
    destination = tmp_path / "destination"
    original = network_module._read_bounded_regular

    def corrupt(path: Path, maximum: int, label: str) -> bytes:
        data = original(path, maximum, label)
        if Path(path).is_relative_to(destination) and Path(path).name == "export.json":
            return data + b"\n"
        return data

    monkeypatch.setattr(network_module, "_read_bounded_regular", corrupt)
    with pytest.raises(NetworkError, match="rebuilt destination bytes differ"):
        materialize_silo_transfer(transfer, destination)
    assert not destination.exists()


def test_rebuild_revalidates_destination_and_cleans_post_write_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    key = _private_key(tmp_path / "publisher.pem")
    publisher = publisher_from_private_key(key, "Specimen", "Post-copy validation specimen.")
    store, template = _complete_silo(tmp_path / "content")
    commit = replace(
        template,
        publisher_id=publisher.publisher_id,
        coverage_universe=_boundary(template, store, publisher_id=publisher.publisher_id),
    )
    head = sign_head(commit, key, 0, None, "2026-09-08T00:00:00Z")
    source = tmp_path / "export"
    destination = tmp_path / "rebuilt"
    export_silo(commit, head, publisher, store, source)
    original_read = network_module._read_bounded_regular

    def corrupt_post_copy_read(path: Path, maximum: int, label: str) -> bytes:
        data = original_read(path, maximum, label)
        if Path(path).is_relative_to(destination) and Path(path).name == "export.json":
            return data + b"\n"
        return data

    monkeypatch.setattr(network_module, "_read_bounded_regular", corrupt_post_copy_read)
    with pytest.raises(NetworkError, match="rebuilt destination bytes differ"):
        rebuild_silo(source, destination)
    assert not destination.exists()



def test_export_inventory_rejects_link_or_reparse_entry(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    class LinkEntry:
        path = str(tmp_path / "link")

        @staticmethod
        def stat(*, follow_symlinks: bool) -> object:
            assert follow_symlinks is False
            return type("Info", (), {"st_file_attributes": 0})()

        @staticmethod
        def is_symlink() -> bool:
            return True

    class Scan:
        def __enter__(self) -> "Scan":
            return self

        def __exit__(self, *_: object) -> None:
            return None

        def __iter__(self) -> object:
            return iter((LinkEntry(),))

    monkeypatch.setattr(network_module.os, "scandir", lambda _: Scan())
    with pytest.raises(NetworkError, match="symbolic links or reparse points"):
        network_module._export_inventory(tmp_path)


def test_unknown_fields_and_nonportable_paths_fail_closed(tmp_path: Path) -> None:
    _, commit = _complete_silo(tmp_path)
    value = commit.to_dict()
    value["silent_authority"] = True
    with pytest.raises(NetworkError, match="exactly"):
        SiloCommit.from_dict(value)
    with pytest.raises(NetworkError, match="portable"):
        replace(commit.census[0], path="../escape")


@pytest.mark.parametrize("value", [-1, 1.5, 2**53, "e\u0301", {"Not_Snake": 1}])
def test_cross_runtime_canonical_json_rejects_ambiguous_values(value: object) -> None:
    with pytest.raises(NetworkError):
        canonical_bytes({"value": value})


def test_wire_from_dict_rejects_member_orders_that_typescript_rejects(
    tmp_path: Path,
) -> None:
    store, commit = _complete_silo(tmp_path)

    reversed_census = commit.to_dict()
    reversed_census["census"] = list(reversed(reversed_census["census"]))
    with pytest.raises(NetworkError, match="canonical member order"):
        SiloCommit.from_dict(reversed_census)

    reversed_authority = commit.to_dict()
    reversed_authority["authority_axiom_agency"] = list(
        reversed(reversed_authority["authority_axiom_agency"])
    )
    with pytest.raises(NetworkError, match="canonical member order"):
        SiloCommit.from_dict(reversed_authority)

    reversed_premises = commit.to_dict()
    target = next(
        edge for edge in reversed_premises["derivations"]
        if len(edge["premise_paths"]) > 1
    )
    target["premise_paths"] = list(reversed(target["premise_paths"]))
    with pytest.raises(NetworkError, match="canonical member order"):
        SiloCommit.from_dict(reversed_premises)

    authority_model = network_module._load_authority_model(commit, store)
    assert authority_model is not None
    reversed_states = authority_model.to_dict()
    reversed_states["states"] = list(reversed(reversed_states["states"]))
    with pytest.raises(NetworkError, match="canonical member order"):
        AuthorityModel.from_dict(reversed_states)


def test_assessment_receipt_binds_exact_commit_and_mechanism(tmp_path: Path) -> None:
    store, commit = _complete_silo(tmp_path)
    receipt = build_silo_assessment_receipt(commit, store)
    assert receipt.commit_digest == commit.canonical_digest()
    mechanism = next(entry for entry in commit.census if entry.path == "mechanism.bin")
    assert receipt.mechanism_digest == mechanism.object_record.object_digest
    assert receipt.to_dict()["assessment"]["self_derivability"] == "ESTABLISHED"


def test_assessment_wire_rejects_retired_property_and_authority_verdicts(tmp_path: Path) -> None:
    store, commit = _complete_silo(tmp_path)
    assessment = assess_silo(commit, store)
    wire = assessment.to_dict()
    assert wire["self_derivability"] == "ESTABLISHED"
    assert "self_derivation" not in wire
    assert wire["authority_axiom_agency"] == "PRESERVED"

    retired_property = dict(wire)
    retired_property["self_derivation"] = retired_property.pop("self_derivability")
    with pytest.raises(NetworkError, match="silo assessment must have exactly its defined fields"):
        SiloAssessment.from_dict(retired_property)

    retired_verdict = dict(wire)
    retired_verdict["authority_axiom_agency"] = "GROUNDED"
    with pytest.raises(NetworkError, match="authority_axiom_agency result"):
        SiloAssessment.from_dict(retired_verdict)


def test_published_schema_accepts_canonical_record_variants(tmp_path: Path) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    referencing = pytest.importorskip("referencing")
    key = _private_key(tmp_path / "key.pem")
    new_key = _private_key(tmp_path / "new.pem")
    publisher = publisher_from_private_key(key, "Specimen", "Schema specimen only.")
    store, template = _complete_silo(tmp_path / "silo")
    commit = replace(template, publisher_id=publisher.publisher_id, coverage_universe=_boundary(template, store, publisher_id=publisher.publisher_id))
    head = sign_head(commit, key, 0, None, "2026-09-08T00:00:00Z")
    continuity = create_key_continuity(publisher.publisher_id, key, new_key, 1)
    directory = sign_directory_snapshot(
        (DirectoryEntry(publisher.publisher_id, head.canonical_digest(), "https://publisher.invalid/silo/", "LISTED"),),
        key, 0, None, "2026-09-08T00:00:00Z",
    )
    schema = json.loads(Path("standard/schemas/vstd-artifact-network-0.1.schema.json").read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    receipt = build_silo_assessment_receipt(commit, store)
    authority_model = network_module._load_authority_model(commit, store)
    assert authority_model is not None
    for record in (commit.census[0].object_record, authority_model, commit, head, publisher, continuity, directory, receipt):
        validator.validate(record.to_dict())
    for schema_path in Path("standard/schemas").glob("vstd-*0.1.schema.json"):
        jsonschema.Draft202012Validator.check_schema(json.loads(schema_path.read_text(encoding="utf-8")))
    mechanism_schema = json.loads(Path("standard/schemas/vstd-self-derivation-mechanism-0.1.schema.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(mechanism_schema).validate(json.loads(self_derivation_mechanism_bytes()))
    transfer_schema = json.loads(Path("standard/schemas/vstd-silo-transfer-0.1.schema.json").read_text(encoding="utf-8"))
    registry = referencing.Registry().with_resource(
        schema["$id"], referencing.Resource.from_contents(schema)
    )
    jsonschema.Draft202012Validator(transfer_schema, registry=registry).validate(
        build_silo_transfer(commit, head, publisher, store)
    )


def test_cli_exposes_complete_alpha_surface() -> None:
    network = next(action for action in build_parser()._actions if isinstance(action, __import__("argparse")._SubParsersAction)).choices["network"]
    commands = next(action for action in network._actions if isinstance(action, __import__("argparse")._SubParsersAction)).choices
    assert set(commands) == {"init", "object", "commit", "inspect", "diff", "clone", "compose", "export", "rebuild", "register", "push"}


def test_cli_register_forwards_only_explicit_paths_and_never_prints_token(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch,
) -> None:
    export_root = tmp_path / "export"
    private_key = tmp_path / "publisher.pem"
    credential = tmp_path / "publisher.credential"
    calls: list[dict[str, object]] = []
    token = "SECRET" + "A" * 43

    def fake_register(
        received_export_root: str, endpoint: str, received_private_key: str,
        issued_at: str, credential_output: str, *, endpoints: tuple[str, ...],
    ) -> dict[str, object]:
        calls.append({
            "export_root": received_export_root,
            "endpoint": endpoint,
            "private_key": received_private_key,
            "issued_at": issued_at,
            "credential_output": credential_output,
            "endpoints": endpoints,
        })
        return {
            "result": "REGISTERED", "publisher_id": "publisher:sha256:" + "a" * 64,
            "credential_path": str(credential), "transport_performed": True,
            "publication": "NOT_ESTABLISHED", "access_token": token,
        }

    monkeypatch.setattr(network_cli_module, "register_publisher", fake_register)
    assert main([
        "network", "register", str(export_root), "--endpoint", "https://hub.invalid",
        "--private-key", str(private_key), "--issued-at", "2026-09-09T00:00:00Z",
        "--credential-output", str(credential), "--publisher-endpoint",
        "https://publisher.invalid/silo/",
    ]) == 0
    output = capsys.readouterr().out
    assert token not in output
    assert "access_token" not in output
    assert json.loads(output)["publication"] == "NOT_ESTABLISHED"
    assert calls == [{
        "export_root": str(export_root),
        "endpoint": "https://hub.invalid",
        "private_key": str(private_key),
        "issued_at": "2026-09-09T00:00:00Z",
        "credential_output": str(credential),
        "endpoints": ("https://publisher.invalid/silo/",),
    }]


def test_cli_push_is_inert_without_transmit_and_authenticated_mode_is_fail_closed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch,
) -> None:
    export_root, _, _, manifest = _claim_garden_export(tmp_path)
    credential = tmp_path / "publisher.credential"
    credential.write_text("A" * 43, encoding="ascii")
    calls: list[dict[str, object]] = []
    token = "SECRET" + "B" * 43

    def fake_submit(
        received_export_root: str, endpoint: str, received_credential: str,
        *, expected_head_digest: str | None, genesis: bool,
    ) -> dict[str, object]:
        calls.append({
            "export_root": received_export_root, "endpoint": endpoint,
            "credential": received_credential, "expected_head": expected_head_digest,
            "genesis": genesis,
        })
        return {
            "result": "SUBMITTED", "state": "PENDING_REVIEW",
            "transaction_id": "11111111-1111-4111-8111-111111111111",
            "publisher_id": "publisher:sha256:" + "a" * 64,
            "commit_digest": manifest["commit_digest"], "head_digest": manifest["head_digest"],
            "transport_performed": True, "publication": "NOT_ESTABLISHED",
            "access_token": token,
        }

    monkeypatch.setattr(network_cli_module, "submit_candidate", fake_submit)

    assert main([
        "network", "push", str(export_root), "--endpoint", "https://hub.invalid/v1/pushes",
        "--expected-head", "sha256:" + "c" * 64,
    ]) == 0
    dry_run = json.loads(capsys.readouterr().out)
    assert dry_run["transport_performed"] is False
    assert dry_run["expected_head_digest"] == "sha256:" + "c" * 64
    assert calls == []

    for arguments, expected_error in (
        (["--transmit", "--genesis"], "credential-file"),
        (["--transmit", "--credential-file", str(credential)], "exactly one"),
        (["--transmit", "--credential-file", str(credential), "--genesis", "--expected-head", "sha256:" + "d" * 64], "exactly one"),
        (["--credential-file", str(credential)], "explicit --transmit"),
        (["--genesis"], "only valid with explicit --transmit"),
    ):
        assert main(["network", "push", str(export_root), "--endpoint", "https://hub.invalid", *arguments]) == 1
        assert expected_error in capsys.readouterr().err
        assert calls == []

    assert main([
        "network", "push", str(export_root), "--endpoint", "https://hub.invalid",
        "--transmit", "--credential-file", str(credential), "--genesis",
    ]) == 0
    output = capsys.readouterr().out
    assert token not in output
    assert "access_token" not in output
    assert json.loads(output)["state"] == "PENDING_REVIEW"
    assert calls == [{
        "export_root": str(export_root), "endpoint": "https://hub.invalid",
        "credential": str(credential), "expected_head": None, "genesis": True,
    }]

    calls.clear()
    expected_head = "sha256:" + "e" * 64
    assert main([
        "network", "push", str(export_root), "--endpoint", "https://hub.invalid",
        "--transmit", "--credential-file", str(credential),
        "--expected-head", expected_head,
    ]) == 0
    capsys.readouterr()
    assert calls == [{
        "export_root": str(export_root), "endpoint": "https://hub.invalid",
        "credential": str(credential), "expected_head": expected_head, "genesis": False,
    }]

    def indeterminate_submit(*_: object, **__: object) -> dict[str, object]:
        return {
            "result": "INDETERMINATE", "state": "UNKNOWN",
            "transaction_id": "22222222-2222-4222-8222-222222222222",
            "transport_performed": True, "publication": "NOT_ESTABLISHED",
            "reason": "ClaimGardenClientError", "access_token": token,
        }

    monkeypatch.setattr(network_cli_module, "submit_candidate", indeterminate_submit)
    assert main([
        "network", "push", str(export_root), "--endpoint", "https://hub.invalid",
        "--transmit", "--credential-file", str(credential), "--genesis",
    ]) == 2
    indeterminate_output = capsys.readouterr().out
    assert token not in indeterminate_output
    assert "access_token" not in indeterminate_output
    assert json.loads(indeterminate_output)["state"] == "UNKNOWN"


def test_supported_newcomer_builder_materializes_exact_specimen(tmp_path: Path) -> None:
    builder_path = Path("examples/artifact-network/build_specimen.py")
    specification = importlib.util.spec_from_file_location(
        "artifact_network_newcomer_builder", builder_path
    )
    assert specification is not None and specification.loader is not None
    builder = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(builder)

    destination = tmp_path / "newcomer-silo"
    first = builder.build_specimen(destination)
    manifest = json.loads((destination / "export.json").read_bytes())
    commit = SiloCommit.from_dict(
        json.loads((destination / first["commit_path"]).read_bytes())
    )

    assert first["result"] == "SPECIMEN_BUILT"
    assert first["commit_digest"] == manifest["commit_digest"]
    assert first["assessment"] == assess_silo(
        commit, ContentAddressedStore(destination)
    ).to_dict()
    assert first["assessment"]["reconstructibility"] == "COMPLETE"
    assert first["assessment"]["completeness"] == "COMPLETE"
    assert first["assessment"]["authority_axiom_agency"] == "PRESERVED"
    assert main([
        "network", "inspect", str(destination), str(destination / first["commit_path"]),
        "--head", str(destination / first["head_path"]),
    ]) == 0
    with pytest.raises(NetworkError, match="destination must be absent"):
        builder.build_specimen(destination)


def test_cli_local_publish_inspect_export_rebuild_and_push_contract(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    key = _private_key(tmp_path / "publisher.pem")
    root = tmp_path / "publisher"
    assert main(["network", "init", str(root), "--private-key", str(key), "--display-name", "Specimen"]) == 0
    initialized = json.loads(capsys.readouterr().out)
    publisher_id = initialized["publisher_id"]

    records: list[ObjectRecord] = []
    for name, content, media, kind in (
        ("ground.txt", b"ground", "text/plain", "ground"),
        ("mechanism.bin", b"mechanism", "application/octet-stream", "derivation-mechanism"),
        ("result.json", b"{}", "application/json", "receipt"),
    ):
        source = tmp_path / name
        source.write_bytes(content)
        assert main(["network", "object", "add", str(root), str(source), "--media-type", media, "--artifact-kind", kind]) == 0
        records.append(ObjectRecord.from_dict(json.loads(capsys.readouterr().out)))
    template_store, template = _complete_silo(tmp_path / "template")
    for entry in template.census:
        ContentAddressedStore(root).add_object(
            template_store.read_object(entry.object_record),
            entry.object_record.media_type,
            entry.object_record.artifact_kind,
            entry.object_record.declared_schema_id,
        )
    commit = replace(template, publisher_id=publisher_id, coverage_universe=_boundary(template, template_store, publisher_id=publisher_id))
    manifest = tmp_path / "commit.json"
    manifest.write_bytes(canonical_bytes(commit.to_dict()))
    assert main(["network", "commit", str(root), str(manifest), "--private-key", str(key), "--issued-at", "2026-09-08T00:00:00Z"]) == 0
    committed = json.loads(capsys.readouterr().out)
    head_path = root / "current-head.json"
    assert committed["assessment"]["completeness"] == "COMPLETE"
    receipt_path = root / "records" / "assessments" / (committed["assessment_receipt_digest"].split(":", 1)[1] + ".json")
    assert receipt_path.is_file()

    original_head_bytes = head_path.read_bytes()
    tampered_head = json.loads(original_head_bytes)
    tampered_head["sequence"] += 1
    head_path.write_bytes(canonical_bytes(tampered_head))
    assert main(["network", "commit", str(root), str(manifest), "--private-key", str(key), "--issued-at", "2026-09-08T00:00:01Z"]) == 1
    assert "signature" in capsys.readouterr().err
    head_path.write_bytes(original_head_bytes)

    prior_record = root / "records" / "heads" / (committed["head_digest"].split(":", 1)[1] + ".json")
    original_prior_record = prior_record.read_bytes()
    prior_record.unlink()
    assert main(["network", "commit", str(root), str(manifest), "--private-key", str(key), "--issued-at", "2026-09-08T00:00:01Z"]) == 1
    capsys.readouterr()
    prior_record.write_bytes(b"{}")
    assert main(["network", "commit", str(root), str(manifest), "--private-key", str(key), "--issued-at", "2026-09-08T00:00:01Z"]) == 1
    capsys.readouterr()
    prior_record.write_bytes(original_prior_record)
    temporary_head = root / "current-head.tmp"
    temporary_head.write_bytes(b"occupied")
    assert main(["network", "commit", str(root), str(manifest), "--private-key", str(key), "--issued-at", "2026-09-08T00:00:01Z"]) == 1
    assert "temporary head path" in capsys.readouterr().err
    temporary_head.unlink()

    assert main(["network", "inspect", str(root), str(manifest), "--head", str(head_path)]) == 0
    assert json.loads(capsys.readouterr().out)["head_signature"] == "VALID"
    destination = tmp_path / "export"
    assert main(["network", "export", str(root), str(manifest), str(head_path), str(destination)]) == 0
    capsys.readouterr()
    assert main(["network", "diff", str(manifest), str(manifest)]) == 0
    difference = json.loads(capsys.readouterr().out)
    assert difference["added"] == difference["removed"] == difference["changed"] == []
    cloned = tmp_path / "cloned"
    assert main(["network", "clone", str(destination), str(cloned)]) == 0
    cloned_manifest = json.loads(capsys.readouterr().out)
    assert cloned_manifest["commit_digest"] == commit.canonical_digest()
    assert main(["network", "compose", "--silo", str(root), str(manifest)]) == 0
    composition = json.loads(capsys.readouterr().out)
    assert composition["result"] == "NOT_ADMISSIBLE"
    assert composition["composition_completeness"] == "UNKNOWN"
    assert composition["composition_member_binding"] == "UNKNOWN"
    rebuilt = tmp_path / "rebuilt"
    assert main(["network", "rebuild", str(destination), str(rebuilt)]) == 0
    capsys.readouterr()
    assert main(["network", "push", str(destination), "--endpoint", "https://hub.invalid/v1/pushes"]) == 0
    push = json.loads(capsys.readouterr().out)
    assert push["schema_version"] == "VSTD-PUSH-REQUEST-0.1"
    assert push["transport_performed"] is False
