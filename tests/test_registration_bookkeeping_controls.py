"""Independent registration identities remain separate from census bookkeeping.

Verifier Standard (VSTD); command-line interface (CLI). Counts are dimensionless.
Only temporary in-memory mutations are used; no source file or Git object changes.
These controls do not establish exhaustive certificate obligations or tier closure.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest

import test_current_certificate_emission as emission_tests
import test_current_object_routes as route_tests
import test_inventory as inventory_tests
import test_subject_security_disclosure_guard as disclosure_tests
from test_current_subject_security import fixture
from verifier.domains.contracts import current_object_routes as routes
from verifier.domains.contracts import subject_security, receipt_chain
from verifier.domains.inventory import SlotRequirement
from verifier.privacy import engine


_SELECTED_TEST_ROOT = Path(routes.__file__).resolve().parents[4] / "tests"
for _module, _filename in (
    (route_tests, "test_current_object_routes.py"),
    (inventory_tests, "test_inventory.py"),
    (emission_tests, "test_current_certificate_emission.py"),
    (disclosure_tests, "test_subject_security_disclosure_guard.py"),
):
    assert Path(_module.__file__).resolve() == (_SELECTED_TEST_ROOT / _filename).resolve()


SEMANTIC = "verifier-current-object-obligations-1"
KINDS = tuple("HUMAN ACTOR COLLECTIVE ROLE IDENTITY OWNER HARDWARE RECEIPT OBJECT GRAPH SPACE TIME EVENT ENV DATA VERIFIER BENCH ARCH TRAIN HYPER MODEL HARNESS AGENT SIM BOT TOKEN".split())
EXPECTED_ADDITIONS = (
    *( (kind + "-8.1", kind, "verifier-current-object-governance-certificate-1",
        "verifier.domains.contracts.object_governance.recheck_governance_certificate",
        "KindGovernanceDescriptor") for kind in KINDS if kind != "OBJECT" ),
    *( ("RECEIPT-9.3" if kind == "RECEIPT" else kind + "-9.1", kind,
        "verifier-current-subject-security-certificate-1",
        "verifier.domains.contracts.subject_security.recheck_subject_security_certificate",
        "SubjectSecurityDescriptor") for kind in KINDS ),
)
EXPECTED_PRESERVED_RECEIPT_AND_DEFAULT = (
    ("EVENT-4.1", "EVENT", "verifier-current-event-closure-certificate-1",
     "verifier.domains.contracts.event_closure.recheck_event_closure_certificate", "EventClosureDescriptor"),
    ("GRAPH-4.1", "GRAPH", "verifier-current-graph-closure-certificate-1",
     "verifier.domains.contracts.graph_closure.recheck_graph_closure_certificate",
     "GraphClosureDescriptor"),
    ("RECEIPT-9.1", "RECEIPT", "verifier-current-receipt-chain-certificate-1",
     "verifier.domains.contracts.receipt_chain.recheck_receipt_chain_certificate", "module"),
    ("RECEIPT-9.2", "RECEIPT", "verifier-current-receipt-authenticity-certificate-1",
     "verifier.domains.contracts.receipt_authenticity.recheck_receipt_authenticity_certificate", "ReceiptAuthenticityDescriptor"),
    ("OBJECT-8.1", "OBJECT", "verifier-current-object-governance-certificate-1",
     "verifier.domains.contracts.object_governance.recheck_governance_certificate", "GovernanceDescriptor"),
)


def _assert_exact_native_binding(expected):
    objective, kind, certificate_schema, native_checker, descriptor = expected
    selected = routes.select_current_object_route(
        semantic_version=SEMANTIC, objective=objective, represented_kind=kind)
    assert selected.fixed_kind == kind
    assert selected.module.CERTIFICATE_VERSION == certificate_schema
    assert selected.replay.__module__ + "." + selected.replay.__name__ == native_checker
    assert type(selected.module).__name__ == descriptor
    if descriptor in ("KindGovernanceDescriptor", "SubjectSecurityDescriptor"):
        assert selected.module.kind == kind


@pytest.mark.parametrize("expected", EXPECTED_ADDITIONS + EXPECTED_PRESERVED_RECEIPT_AND_DEFAULT)
def test_independently_specified_native_bindings(expected):
    # Neither this expected tuple nor the complete reviewed route key set comes
    # from the production catalogue. Newly registered GRAPH/EVENT routes need
    # independent expectation additions and actual native replay qualification.
    _assert_exact_native_binding(expected)


def test_valid_catalogue_inventory_and_canonical_guard_characterize_unchanged_source():
    route_tests.test_catalog_has_registered_objectives_without_profile_stamps()
    inventory_tests.test_registered_objectives_preserve_exact_slot_inventory()
    emission_tests.test_every_registered_canonical_schema_has_a_disclosure_guard()


def test_missing_route_is_rejected_by_independent_key_oracle(monkeypatch):
    route_tests.test_catalog_has_registered_objectives_without_profile_stamps()
    monkeypatch.delitem(routes._ROUTES, (SEMANTIC, "MODEL-9.1"))
    with pytest.raises(AssertionError):
        route_tests.test_catalog_has_registered_objectives_without_profile_stamps()
    with pytest.raises(routes.CurrentObjectRouteRefusal):
        routes.select_current_object_route(semantic_version=SEMANTIC,
            objective="MODEL-9.1", represented_kind="MODEL")


def test_duplicate_catalogue_entry_is_rejected_through_actual_catalogue_iteration(monkeypatch):
    route_tests.test_catalog_has_registered_objectives_without_profile_stamps()
    class DuplicateItems(dict):
        def items(self):
            values = list(super().items())
            return values + [values[0]]
    monkeypatch.setattr(routes, "_ROUTES", DuplicateItems(routes._ROUTES))
    rows = routes.current_object_route_catalog()
    assert len(rows) > len({(row["semantic_version"], row["objective"]) for row in rows})
    with pytest.raises(AssertionError):
        route_tests.test_catalog_has_registered_objectives_without_profile_stamps()


@pytest.mark.parametrize("change", ["kind", "descriptor", "checker"])
def test_unchanged_counts_cannot_hide_misbound_native_routes(change, monkeypatch):
    expected = next(row for row in EXPECTED_ADDITIONS if row[0] == "MODEL-9.1")
    _assert_exact_native_binding(expected)
    key = (SEMANTIC, "MODEL-9.1")
    original = routes._ROUTES[key]
    wrong = (replace(original, fixed_kind="HUMAN") if change == "kind"
             else replace(original, module=subject_security.SubjectSecurityDescriptor("HUMAN")) if change == "descriptor"
             else replace(original, replay=receipt_chain.recheck_receipt_chain_certificate))
    monkeypatch.setitem(routes._ROUTES, key, wrong)
    # The independently enumerated key set can still be intact. Native binding
    # is an additional obligation; counting registrations cannot discharge it.
    route_tests.test_catalog_has_registered_objectives_without_profile_stamps()
    if change == "kind":
        # Native selection already refuses this independently mismatched kind.
        # Preserve its exact refusal instead of calling that guard a defect.
        with pytest.raises(routes.CurrentObjectRouteRefusal,
                           match=r"^represented kind differs from selected objective$") as refusal:
            _assert_exact_native_binding(expected)
        assert type(refusal.value) is routes.CurrentObjectRouteRefusal
    else:
        # Descriptor and callback identity remain separate assertion obligations.
        with pytest.raises(AssertionError):
            _assert_exact_native_binding(expected)


def test_literal_certificate_schema_refuses_coordinated_module_alias(monkeypatch):
    expected = next(row for row in EXPECTED_ADDITIONS if row[0] == "MODEL-9.1")
    _assert_exact_native_binding(expected)
    monkeypatch.setattr(subject_security, "CERTIFICATE_VERSION", "other-certificate-schema")
    route_tests.test_catalog_has_registered_objectives_without_profile_stamps()
    with pytest.raises(AssertionError):
        _assert_exact_native_binding(expected)


def test_wrong_semantic_version_cannot_pass_with_unchanged_route_count(monkeypatch):
    route_tests.test_catalog_has_registered_objectives_without_profile_stamps()
    selected = routes._ROUTES[(SEMANTIC, "MODEL-9.1")]
    monkeypatch.delitem(routes._ROUTES, (SEMANTIC, "MODEL-9.1"))
    monkeypatch.setitem(routes._ROUTES, ("verifier-domain-obligations-1", "MODEL-9.1"), selected)
    with pytest.raises(AssertionError):
        route_tests.test_catalog_has_registered_objectives_without_profile_stamps()
    with pytest.raises(routes.CurrentObjectRouteRefusal):
        routes.select_current_object_route(semantic_version="verifier-domain-obligations-1",
            objective="MODEL-9.1", represented_kind="MODEL")


@pytest.mark.parametrize("unreviewed_coordinate", ["GRAPH-4.2", "EVENT-4.999999999"])
def test_unreviewed_producer_identity_requires_an_independent_contract_addition(unreviewed_coordinate, monkeypatch):
    route_tests.test_catalog_has_registered_objectives_without_profile_stamps()
    assert (SEMANTIC, unreviewed_coordinate) not in routes._ROUTES
    # A deliberate registry alias models an undeclared addition. It is not an
    # implementation or certificate for either pending future producer.
    monkeypatch.setitem(routes._ROUTES, (SEMANTIC, unreviewed_coordinate),
                        routes._ROUTES[(SEMANTIC, "GRAPH-3.1")])
    assert (SEMANTIC, unreviewed_coordinate) in {
        (row["semantic_version"], row["objective"]) for row in routes.current_object_route_catalog()}
    with pytest.raises(AssertionError):
        route_tests.test_catalog_has_registered_objectives_without_profile_stamps()


@pytest.mark.parametrize("change", ["missing", "duplicate"])
def test_actual_inventory_serialization_must_preserve_each_registration(change, monkeypatch):
    inventory_tests.test_registered_objectives_preserve_exact_slot_inventory()
    original = SlotRequirement.to_dict
    def altered(instance):
        value = original(instance)
        if value["object_kind"] == "MODEL" and value["tier"] == 9:
            value = deepcopy(value)
            if change == "missing":
                value["registered_objectives"].pop()
            else:
                value["registered_objectives"].append(deepcopy(value["registered_objectives"][0]))
        return value
    monkeypatch.setattr(SlotRequirement, "to_dict", altered)
    with pytest.raises(AssertionError):
        inventory_tests.test_registered_objectives_preserve_exact_slot_inventory()


def test_registered_but_unreachable_checker_fails_actual_native_replay(monkeypatch):
    request, policy, evidence, _ = fixture("MODEL")
    certificate = subject_security.build_subject_security_certificate(request, evidence, policy=policy)
    arguments = dict(semantic_version=SEMANTIC, objective="MODEL-9.1",
                     represented_kind="MODEL", expected_request=request, policy=policy)
    assert routes.replay_current_object_certificate(certificate, **arguments)["computational_status"] == "PASS"
    def unreachable(*args, **kwargs):
        raise ValueError("independent-unreachable-checker-control")
    key = (SEMANTIC, "MODEL-9.1")
    monkeypatch.setitem(routes._ROUTES, key, replace(routes._ROUTES[key], replay=unreachable))
    route_tests.test_catalog_has_registered_objectives_without_profile_stamps()
    with pytest.raises(routes.CurrentObjectRouteRefusal) as error:
        routes.replay_current_object_certificate(certificate, **arguments)
    assert isinstance(error.value.__cause__, ValueError)
    assert str(error.value.__cause__) == "independent-unreachable-checker-control"


def test_omitted_canonical_schema_breaks_registry_and_actual_disclosure_refusal(monkeypatch):
    emission_tests.test_every_registered_canonical_schema_has_a_disclosure_guard()
    disclosure_tests.test_full_native_subject_security_certificate_preserves_exact_bytes("MODEL", "PASS")
    disclosure_tests.test_retained_subject_chain_witness_cannot_be_withheld("MODEL", "PASS")
    omitted = "verifier-current-subject-security-certificate-1"
    assert omitted in engine._CANONICAL_CERTIFICATE_SCHEMAS
    monkeypatch.setattr(engine, "_CANONICAL_CERTIFICATE_SCHEMAS",
                        tuple(schema for schema in engine._CANONICAL_CERTIFICATE_SCHEMAS if schema != omitted))
    route_tests.test_catalog_has_registered_objectives_without_profile_stamps()
    with pytest.raises(AssertionError):
        emission_tests.test_every_registered_canonical_schema_has_a_disclosure_guard()
    with pytest.raises(pytest.fail.Exception):
        disclosure_tests.test_retained_subject_chain_witness_cannot_be_withheld("MODEL", "PASS")


@pytest.mark.parametrize("change", ["kind", "descriptor", "checker"])
def test_reviewed_event_identity_requires_exact_native_binding(change, monkeypatch):
    expected = next(row for row in EXPECTED_PRESERVED_RECEIPT_AND_DEFAULT if row[0] == "EVENT-4.1")
    _assert_exact_native_binding(expected)
    key = (SEMANTIC, "EVENT-4.1")
    original = routes._ROUTES[key]
    other = routes._ROUTES[(SEMANTIC, "GRAPH-3.1")]
    wrong = (replace(original, fixed_kind="GRAPH") if change == "kind"
             else replace(original, module=other.module) if change == "descriptor"
             else replace(original, replay=other.replay))
    monkeypatch.setitem(routes._ROUTES, key, wrong)
    route_tests.test_catalog_has_registered_objectives_without_profile_stamps()
    if change == "kind":
        with pytest.raises(routes.CurrentObjectRouteRefusal,
                           match=r"^represented kind differs from selected objective$"):
            _assert_exact_native_binding(expected)
    else:
        with pytest.raises(AssertionError):
            _assert_exact_native_binding(expected)
