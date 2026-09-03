"""Terminology: JavaScript Object Notation (JSON); Verifier Standard (VSTD).

Adversarial tests for the domain-neutral VSTD interoperability catalog.
"""

from dataclasses import FrozenInstanceError, replace

import pytest

from verifier.interoperability.catalog import (
    CatalogError,
    ComponentAvailability,
    ComponentKind,
    ComponentLifecycle,
    InteractionMode,
    InteroperabilityComponentDescriptor,
    InteroperabilityComponentRegistry,
)


def component(
    component_id: str,
    *,
    schema_id: str = "VSTD-2",
    relation_id: str = "HAS_EXACT_EVIDENCE",
    mechanism_id: str = "mechanism:exact",
    interaction_mode: InteractionMode = InteractionMode.STATIC,
    domain_tags: tuple[str, ...] = (),
) -> InteroperabilityComponentDescriptor:
    return InteroperabilityComponentDescriptor(
        component_id=component_id,
        label=component_id,
        kind=ComponentKind.VERIFIER,
        lifecycle=ComponentLifecycle.IMPLEMENTED,
        implementation_ref=f"verifier.example:{component_id}",
        accepted_schema_ids=(schema_id,),
        verifier_family_ids=("schema-contract",),
        native_system="example",
        native_objects=("record",),
        native_versions=("1",),
        native_inputs=("application/json",),
        native_outputs=("example-result",),
        native_result_vocabulary=("PASS", "FAIL", "UNKNOWN"),
        supported_relations=(relation_id,),
        mechanism_ids=(mechanism_id,),
        interaction_modes=(interaction_mode,),
        domain_tags=domain_tags,
        trust_roots=("local-fixture",),
        freshness_behavior="Caller supplies the observation coordinate.",
        transformation_loss="No transformation is performed by the descriptor.",
        failure_behavior="Native non-passing states remain native.",
        availability=ComponentAvailability.AVAILABLE,
        claim_boundary="Catalog membership does not establish a native result.",
    )


def test_descriptor_and_registry_are_frozen() -> None:
    descriptor = component("component:a")
    registry = InteroperabilityComponentRegistry("1.3.0", (descriptor,))

    with pytest.raises(FrozenInstanceError):
        descriptor.label = "changed"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        registry.registry_version = "changed"  # type: ignore[misc]


def test_matching_is_exact_on_schema_relation_mechanism_and_interaction_mode() -> None:
    registry = InteroperabilityComponentRegistry("1.3.0", (component("component:a"),))

    assert [
        item.component_id
        for item in registry.match_exact(
            schema_id="VSTD-2",
            relation_id="HAS_EXACT_EVIDENCE",
            mechanism_id="mechanism:exact",
            interaction_mode=InteractionMode.STATIC,
        )
    ] == ["component:a"]
    assert (
        registry.match_exact(
            schema_id="vstd-2",
            relation_id="HAS_EXACT_EVIDENCE",
            mechanism_id="mechanism:exact",
            interaction_mode=InteractionMode.STATIC,
        )
        == ()
    )
    assert (
        registry.match_exact(
            schema_id="VSTD-2",
            relation_id="has_exact_evidence",
            mechanism_id="mechanism:exact",
            interaction_mode=InteractionMode.STATIC,
        )
        == ()
    )
    assert (
        registry.match_exact(
            schema_id="VSTD-2",
            relation_id="HAS_EXACT_EVIDENCE",
            mechanism_id="mechanism:other",
            interaction_mode=InteractionMode.STATIC,
        )
        == ()
    )
    assert (
        registry.match_exact(
            schema_id="VSTD-2",
            relation_id="HAS_EXACT_EVIDENCE",
            mechanism_id="mechanism:exact",
            interaction_mode=InteractionMode.OFFLINE_REPLAY,
        )
        == ()
    )


def test_descriptor_relations_and_mechanisms_form_an_explicit_cartesian_product() -> None:
    descriptor = replace(
        component("component:a"),
        supported_relations=("RELATION:A", "RELATION:B"),
        mechanism_ids=("mechanism:a", "mechanism:b"),
    )

    for relation_id in descriptor.supported_relations:
        for mechanism_id in descriptor.mechanism_ids:
            assert descriptor.matches_exact(
                schema_id="VSTD-2",
                interaction_mode=InteractionMode.STATIC,
                relation_id=relation_id,
                mechanism_id=mechanism_id,
            )


def test_domain_tags_are_metadata_and_do_not_change_match_results() -> None:
    software = InteroperabilityComponentRegistry(
        "1.3.0", (component("component:a", domain_tags=("software",)),)
    )
    biological = InteroperabilityComponentRegistry(
        "1.3.0", (component("component:a", domain_tags=("biological",)),)
    )
    query = {
        "schema_id": "VSTD-2",
        "relation_id": "HAS_EXACT_EVIDENCE",
        "interaction_mode": InteractionMode.STATIC,
    }

    assert [item.component_id for item in software.match_exact(**query)] == [
        item.component_id for item in biological.match_exact(**query)
    ]
    assert software.components[0].domain_tags != biological.components[0].domain_tags


def test_registry_retains_multiple_matches_and_returns_zero_without_substitution() -> None:
    registry = InteroperabilityComponentRegistry(
        "1.3.0",
        (
            component("component:z"),
            component("component:a"),
            component("component:other", relation_id="OTHER_RELATION"),
        ),
    )

    matches = registry.match_exact(
        schema_id="VSTD-2",
        relation_id="HAS_EXACT_EVIDENCE",
        interaction_mode=InteractionMode.STATIC,
    )
    none = registry.match_exact(
        schema_id="VSTD-2",
        relation_id="SIMILAR_LOOKING_RELATION",
        interaction_mode=InteractionMode.STATIC,
    )

    assert [item.component_id for item in matches] == ["component:a", "component:z"]
    assert none == ()


def test_registry_serialization_is_deterministic_and_strictly_round_trips() -> None:
    first = InteroperabilityComponentRegistry(
        "1.3.0",
        (
            component("component:z", domain_tags=("zeta", "alpha")),
            component("component:a"),
        ),
    )
    second = InteroperabilityComponentRegistry(
        "1.3.0",
        (
            component("component:a"),
            component("component:z", domain_tags=("alpha", "zeta")),
        ),
    )

    assert first.canonical_json_bytes() == second.canonical_json_bytes()
    assert first.canonical_digest() == second.canonical_digest()
    assert (
        InteroperabilityComponentRegistry.from_dict(first.to_dict()).canonical_json_bytes()
        == first.canonical_json_bytes()
    )

    malformed = first.to_dict()
    malformed["unexpected"] = True
    with pytest.raises(CatalogError, match="extra=.*unexpected"):
        InteroperabilityComponentRegistry.from_dict(malformed)


def test_public_loaders_reject_non_objects_with_catalog_errors() -> None:
    for malformed in (None, [], "not-an-object"):
        with pytest.raises(CatalogError, match="descriptor must be an object"):
            InteroperabilityComponentDescriptor.from_dict(malformed)  # type: ignore[arg-type]
        with pytest.raises(CatalogError, match="registry must be an object"):
            InteroperabilityComponentRegistry.from_dict(malformed)  # type: ignore[arg-type]


def test_semantic_identifiers_reject_surrounding_whitespace() -> None:
    baseline = component("component:a")
    malformed_descriptors = (
        {"component_id": " component:a"},
        {"label": "component a "},
        {"implementation_ref": " verifier.example:component:a"},
        {"accepted_schema_ids": ("VSTD-2 ",)},
        {"supported_relations": (" HAS_EXACT_EVIDENCE",)},
        {"mechanism_ids": ("mechanism:exact ",)},
        {"domain_tags": (" software",)},
    )

    for changes in malformed_descriptors:
        with pytest.raises(CatalogError, match="surrounding whitespace"):
            replace(baseline, **changes)

    with pytest.raises(CatalogError, match="surrounding whitespace"):
        InteroperabilityComponentRegistry(" 1.3.0", (baseline,))
    with pytest.raises(CatalogError, match="surrounding whitespace"):
        InteroperabilityComponentRegistry("1.3.0", (baseline,)).get("component:a ")
