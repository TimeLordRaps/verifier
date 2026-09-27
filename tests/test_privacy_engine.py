"""Local level 6 disclosure-helper tests, not normative conformance evidence.

Acronyms:
    differential privacy (DP);
    JavaScript Object Notation (JSON);
    Secure Hash Algorithm 256-bit (SHA-256);
    Verifier Standard (VSTD).
"""

from __future__ import annotations

import copy
import pytest

from verifier.privacy import (
    BudgetExhaustedError,
    CompositionDeltaEvaluator,
    ContextualIntegrityEvaluator,
    ContextualTransmissionNorm,
    DifferentialPrivacyBudget,
    DisclosureBound,
    DisclosureSurface,
    EmissionContext,
    EmissionEvaluator,
    EmissionRefusalError,
    MalformedRedactionError,
    ObserverParty,
    SafeHarborPartition,
    SelectiveMerkleDisclosure,
    TransparencyCommitment,
    assert_verdict_independence,
)



# Normative 6.2 admits no implicit public structural field. These illustrative
# fixtures declare their complete structural surface and explicit reader bounds.
PUBLIC_FIELDS = ("schema_version", "object_name", "domain", "verdict", "results",
                 "request", "result", "certificate_digest", "specification_digest",
                 "policy_digest", "mechanism_digest") + tuple(
                     f"tier_{tier}_verdict" for tier in range(1, 6))


def public_surface(*, object_name: str, disclosed_fields: tuple, withheld_fields: tuple) -> DisclosureSurface:
    return DisclosureSurface(object_name, tuple(dict.fromkeys(PUBLIC_FIELDS + disclosed_fields)), withheld_fields)


def public_bounds() -> tuple[DisclosureBound, ...]:
    return tuple(DisclosureBound("public:" + key, key, admitted_roles=("auditor", "analyst"))
                 for key in PUBLIC_FIELDS)


@pytest.fixture
def mock_certificate() -> dict:
    """Create a realistic domain certificate with Tiers 1-5 verdicts and sensitive payload fields."""
    return {
        "schema_version": "privacy-test-fixture",
        "object_name": "DATA",
        "domain": "DATA",
        "subject_id": "example:data-retained",
        "verdict": "PASS",
        "tier_1_verdict": "PASS",
        "tier_2_verdict": "PASS",
        "tier_3_verdict": "PASS",
        "tier_4_verdict": "PASS",
        "tier_5_verdict": "PASS",
        "results": {
            "DATA-1.1": "PASS",
            "DATA-2.1": "PASS",
            "DATA-3.1": "PASS",
            "DATA-4.1": "PASS",
            "DATA-5.1": "PASS",
        },
        # Public metadata
        "shard_count": 8,
        "record_count": 100000,
        "split_names": ["train", "validation", "test"],
        # Sensitive / withheld fields
        "raw_record_samples": [{"id": 1, "text": "secret patient data"}],
        "curator_private_locator": "locator:internal-curator-99",
        "genesis_seed": "0xdeadbeef1234",
    }


def test_obligation_6_1_disclosure_surface_partitioning_and_commitments(mock_certificate: dict) -> None:
    """Test [OBJECT]-6.1: Disclosure surface partitions emitted fields and creates transparency commitments."""
    surface = public_surface(
        object_name="DATA",
        disclosed_fields=("shard_count", "record_count", "split_names"),
        withheld_fields=("raw_record_samples", "curator_private_locator", "genesis_seed"),
    )
    bounds = (
        DisclosureBound(bound_id="b-public-1", field_name="shard_count", admitted_roles=("auditor", "analyst")),
        DisclosureBound(bound_id="b-public-2", field_name="record_count", admitted_roles=("auditor", "analyst")),
        DisclosureBound(bound_id="b-public-3", field_name="split_names", admitted_roles=("auditor", "analyst")),
    )
    bounds += public_bounds()
    observer = ObserverParty(actor_id="actor:alice", role="analyst", purpose="metrics_review")
    context = EmissionContext(observer=observer, timestamp="2026-09-24T13:30:00Z")

    evaluator = EmissionEvaluator()
    result = evaluator.evaluate_emission(mock_certificate, surface, bounds, context)

    emitted = result.emitted_certificate
    # Disclosed fields are present
    assert emitted["shard_count"] == 8
    assert emitted["record_count"] == 100000
    assert emitted["split_names"] == ["train", "validation", "test"]

    # Withheld fields are absent from top level
    assert "raw_record_samples" not in emitted
    assert "curator_private_locator" not in emitted
    assert "genesis_seed" not in emitted

    # Negative space is transparently committed
    assert "transparency_commitments" not in emitted
    committed_names = {c.field_name for c in result.transparency_commitments}
    assert "raw_record_samples" in committed_names
    assert "curator_private_locator" in committed_names
    assert "genesis_seed" in committed_names

    # Tiers 1-5 verdicts remain intact
    assert emitted["verdict"] == "PASS"
    assert emitted["tier_1_verdict"] == "PASS"


def test_obligation_6_2_bound_declaration_fails_closed(mock_certificate: dict) -> None:
    """Test [OBJECT]-6.2: Fields emitted without an explicit bound fail closed."""
    # Surface does not declare 'unbounded_diagnostic' as withheld, but no bound permits it
    cert = copy.deepcopy(mock_certificate)
    cert["unbounded_diagnostic"] = "sensitive internal stack trace"

    surface = public_surface(
        object_name="DATA",
        disclosed_fields=("shard_count",),
        withheld_fields=(),
    )
    bounds = (
        DisclosureBound(bound_id="b-1", field_name="shard_count", admitted_roles=("analyst",)),
    )
    bounds += public_bounds()
    observer = ObserverParty(actor_id="actor:bob", role="analyst", purpose="review")
    context = EmissionContext(observer=observer, timestamp="2026-09-24T13:30:00Z")

    evaluator = EmissionEvaluator()
    result = evaluator.evaluate_emission(cert, surface, bounds, context)

    # Unbounded field must fail closed and be withheld with a commitment
    assert "unbounded_diagnostic" not in result.emitted_certificate
    assert "unbounded_diagnostic" in result.redacted_fields
    committed_names = {c.field_name for c in result.transparency_commitments}
    assert "unbounded_diagnostic" in committed_names


def test_obligation_6_3_observer_must_be_identified_party(mock_certificate: dict) -> None:
    """Test [OBJECT]-6.3: Observers must be identified as accountable parties, not relayable channels."""
    surface = public_surface(object_name="DATA", disclosed_fields=(), withheld_fields=())
    bounds = ()
    bounds += public_bounds()
    evaluator = EmissionEvaluator()

    # Anonymous or channel-like observer (empty actor_id) fails closed
    anonymous_observer = ObserverParty(actor_id="", role="analyst", purpose="leak")
    context_anon = EmissionContext(observer=anonymous_observer, timestamp="2026-09-24T13:30:00Z")
    with pytest.raises(EmissionRefusalError, match="obligation 6.3"):
        evaluator.evaluate_emission(mock_certificate, surface, bounds, context_anon)

    # Missing role fails closed
    no_role_observer = ObserverParty(actor_id="actor:anon", role="", purpose="leak")
    context_no_role = EmissionContext(observer=no_role_observer, timestamp="2026-09-24T13:30:00Z")
    with pytest.raises(EmissionRefusalError, match="obligation 6.3"):
        evaluator.evaluate_emission(mock_certificate, surface, bounds, context_no_role)


def test_obligation_6_4_dynamic_emission_time_receipt(mock_certificate: dict) -> None:
    """Test [OBJECT]-6.4: Evaluated per emission and generates verifier-privacy-assessment-receipt-1."""
    surface = public_surface(object_name="DATA", disclosed_fields=("shard_count",), withheld_fields=())
    bounds = (DisclosureBound(bound_id="b-1", field_name="shard_count", admitted_roles=("auditor",)),)
    bounds += public_bounds()
    observer = ObserverParty(actor_id="actor:eve", role="auditor", purpose="audit")
    context = EmissionContext(observer=observer, timestamp="2026-09-24T13:35:00Z")

    evaluator = EmissionEvaluator()
    result = evaluator.evaluate_emission(mock_certificate, surface, bounds, context)

    receipt = result.receipt
    assert receipt["schema_version"] == "verifier-privacy-assessment-receipt-1"
    assert receipt["object_name"] == "DATA"
    assert receipt["observer"]["actor_id"] == "actor:eve"
    assert receipt["emission_timestamp"] == "2026-09-24T13:35:00Z"
    assert receipt["verdict_independence"] == "PASS"
    assert "receipt_digest" in receipt


def test_obligation_6_5_composition_delta_relational_join_detection(mock_certificate: dict) -> None:
    """Test [OBJECT]-6.5: Co-emitting certificates triggers relational join leakage analysis."""
    surface = public_surface(object_name="DATA", disclosed_fields=(), withheld_fields=())
    bounds = ()
    bounds += public_bounds()

    # Co-emitting DATA beside TRAIN discloses training set distribution
    co_emitted_train = {
        "schema_version": "verifier-domain-certification-1",
        "object_name": "TRAIN",
        "domain": "TRAIN",
        "verdict": "PASS",
    }

    # Standard analyst observer is rejected from performing high-risk join
    analyst = ObserverParty(actor_id="actor:charlie", role="analyst", purpose="analytics")
    context_analyst = EmissionContext(
        observer=analyst,
        timestamp="2026-09-24T13:30:00Z",
        co_emitted_certificates=(co_emitted_train,),
    )

    evaluator = EmissionEvaluator()
    with pytest.raises(EmissionRefusalError, match="Composition delta violation.*DATA\\+TRAIN"):
        evaluator.evaluate_emission(mock_certificate, surface, bounds, context_analyst)

    # A self-declared auditor role cannot waive an unresolved composition risk
    auditor = ObserverParty(actor_id="actor:diana", role="auditor", purpose="regulatory_audit")
    context_auditor = EmissionContext(
        observer=auditor,
        timestamp="2026-09-24T13:30:00Z",
        co_emitted_certificates=(co_emitted_train,),
    )
    with pytest.raises(EmissionRefusalError, match="Composition delta violation"):
        evaluator.evaluate_emission(mock_certificate, surface, bounds, context_auditor)


def test_obligation_6_6_verdict_independence_adversarial_tamper(mock_certificate: dict) -> None:
    """Test [OBJECT]-6.6: Tampering with a Tier 1-5 verdict during redaction fails closed."""
    valid_redacted = copy.deepcopy(mock_certificate)
    del valid_redacted["genesis_seed"]
    # Normal redaction preserves verdicts
    assert_verdict_independence(mock_certificate, valid_redacted)

    # Adversarial tamper: altering root verdict fails closed
    tampered_root = copy.deepcopy(valid_redacted)
    tampered_root["verdict"] = "FAIL"
    with pytest.raises(MalformedRedactionError, match="Root computational verdict moved"):
        assert_verdict_independence(mock_certificate, tampered_root)

    # Adversarial tamper: moving a tier verdict upward or downward fails closed
    tampered_tier = copy.deepcopy(valid_redacted)
    tampered_tier["tier_3_verdict"] = "UNKNOWN"
    with pytest.raises(MalformedRedactionError, match="Tier 3 verdict moved"):
        assert_verdict_independence(mock_certificate, tampered_tier)

    # Adversarial tamper: moving an obligation verdict fails closed
    tampered_ob = copy.deepcopy(valid_redacted)
    tampered_ob["results"]["DATA-1.1"] = "FAIL"
    with pytest.raises(MalformedRedactionError, match="Obligation DATA-1.1 verdict moved"):
        assert_verdict_independence(mock_certificate, tampered_ob)


def test_differential_privacy_budget_exhaustion() -> None:
    """Test Differential Privacy meta-adapter budget accumulation and fail-closed exhaustion."""
    budget = DifferentialPrivacyBudget(max_epsilon=1.0, max_delta=1e-5)

    # Consume within budget
    r1 = budget.consume(epsilon=0.4, delta=1e-6)
    assert r1["consumed_epsilon"] == 0.4
    assert r1["remaining_epsilon"] == pytest.approx(0.6)

    r2 = budget.consume(epsilon=0.5, delta=1e-6)
    assert r2["consumed_epsilon"] == pytest.approx(0.9)

    # Over-consumption must raise BudgetExhaustedError
    with pytest.raises(BudgetExhaustedError, match="Differential privacy budget exhausted"):
        budget.consume(epsilon=0.2, delta=0.0)


def test_contextual_integrity_transmission_norms() -> None:
    """Test Contextual Integrity meta-adapter 5-tuple evaluation."""
    norm = ContextualTransmissionNorm(
        sender="org:hospital",
        recipient="auditor",
        subject="patient_records",
        information_type="statistical_aggregate",
        transmission_principle="audit_only",
    )
    evaluator = ContextualIntegrityEvaluator(admitted_norms=(norm,))

    auditor = ObserverParty(actor_id="actor:auditor-1", role="auditor", purpose="audit")
    admissible, reason = evaluator.evaluate(
        sender="org:hospital",
        recipient=auditor,
        subject="patient_records",
        information_type="statistical_aggregate",
        requested_principle="audit_only",
    )
    assert admissible is True
    assert reason == ""

    # Violation of transmission principle
    admissible_fail, reason_fail = evaluator.evaluate(
        sender="org:hospital",
        recipient=auditor,
        subject="patient_records",
        information_type="statistical_aggregate",
        requested_principle="non_relaying",
    )
    assert admissible_fail is False
    assert "No matching contextual transmission norm" in reason_fail


def test_selective_merkle_disclosure_root_invariance() -> None:
    """Test Selective Merkle leaf disclosure preserving global root commitment."""
    fields = {
        "field_a": 100,
        "field_b": "public info",
        "secret_c": "private patient id 999",
        "salt_d": "random_salt_xyz",
    }
    original_root = SelectiveMerkleDisclosure.compute_root(fields)

    # Selectively disclose only field_a and field_b
    disclosed, commitments, root = SelectiveMerkleDisclosure.disclose_selectively(
        fields, disclosed_keys={"field_a", "field_b"}
    )
    assert root == original_root
    assert disclosed["field_a"] == 100
    assert disclosed["field_b"] == "public info"
    assert "secret_c" not in disclosed
    assert "salt_d" not in disclosed
    assert len(commitments) == 2


def test_safe_harbor_partition() -> None:
    """Test Safe Harbor attribute partitioning suppresses direct identifiers."""
    raw_data = {
        "name": "Jane Doe",
        "email": "user-account-identifier",
        "record_count": 42,
        "status": "active",
        "private_key": "0x123",
    }
    disclosed, withheld = SafeHarborPartition.partition(raw_data)
    assert "name" not in disclosed
    assert "email" not in disclosed
    assert "private_key" not in disclosed
    assert disclosed["record_count"] == 42
    assert disclosed["status"] == "active"
    assert set(withheld) == {"name", "email", "private_key"}


def test_real_domain_certificate_emission_evaluation() -> None:
    """Test Level 6 emission evaluation over an authentic certified DATA specimen."""
    import importlib.util
    from pathlib import Path
    from verifier.domains.certification import build_domain_certificate, domain_policy, domain_request

    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("domain_example", root / "examples/domain_grounding.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    bundles = module.specimens()
    policy = domain_policy(
        trust_roots=["test:retained-inputs", "test:checker"],
        witness_keys=module.token_witness_keys(),
    )
    req = domain_request(bundles["DATA"], target_depth=2)
    cert = build_domain_certificate(req, bundles["DATA"], policy=policy)
    assert cert["result"]["status"] == "PASS"

    # Define disclosure surface where evidence is governed by an explicit disclosure bound
    surface = public_surface(
        object_name="DATA",
        disclosed_fields=(
            "schema_version", "request", "result", "specification_digest",
            "policy_digest", "mechanism_digest", "certificate_digest", "evidence",
        ),
        withheld_fields=(),
    )
    bounds = (
        DisclosureBound(bound_id="b-audit-1", field_name="evidence", admitted_roles=("auditor",)),
    )
    bounds += public_bounds()

    # A strict native certificate requires retained evidence to reproduce; hiding
    # it cannot produce another valid native certificate without a selective proof.
    analyst = ObserverParty(actor_id="actor:analyst-1", role="analyst", purpose="metrics")
    context_analyst = EmissionContext(observer=analyst, timestamp="2026-09-24T13:40:00Z")
    evaluator = EmissionEvaluator()
    with pytest.raises(EmissionRefusalError, match="canonical certificate"):
        evaluator.evaluate_emission(cert, surface, bounds, context_analyst)

    # Auditor is admitted and sees evidence
    auditor = ObserverParty(actor_id="actor:auditor-1", role="auditor", purpose="compliance")
    context_auditor = EmissionContext(observer=auditor, timestamp="2026-09-24T13:40:00Z")
    result_auditor = evaluator.evaluate_emission(cert, surface, bounds, context_auditor)
    assert "evidence" in result_auditor.emitted_certificate
    assert result_auditor.emitted_certificate["result"]["status"] == "PASS"

