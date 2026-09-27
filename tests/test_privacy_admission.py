"""Independent admission and replay counterexamples; no normative conformance claim.

Callback tests allow either explicit refusal or an unchanged, truthful emission;
they never accept a changed source verdict or mutation of caller data.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from typing import Any
import pytest

from verifier.privacy import (
    CompositionDeltaEvaluator,
    DisclosureBound,
    DisclosureSurface,
    EmissionContext,
    EmissionEvaluator,
    EmissionResult,
    ObserverParty,
    TransparencyCommitment,
)


def context(*, credentials: Any = (), co_emitted: tuple[dict[str, Any], ...] = ()) -> EmissionContext:
    return EmissionContext(
        ObserverParty('actor:reader', 'reader', 'audit', credentials),
        '2026-09-26T00:00:00Z',
        co_emitted,
    )


def evaluate_secret(bound: DisclosureBound, *, observer_context: EmissionContext | None = None,
                    surface: DisclosureSurface | None = None) -> EmissionResult:
    return EmissionEvaluator().evaluate_emission(
        {'secret': 'synthetic-private'},
        surface or DisclosureSurface('DATA', ('secret',), ()),
        (bound,),
        observer_context or context(),
    )


def test_review_custom_callback_cannot_upgrade_bound_fail_or_mutate_caller() -> None:
    class MutatingComposer(CompositionDeltaEvaluator):
        def evaluate_composition_delta(self, *, primary_cert: dict, co_emitted: tuple,
                                       observer: ObserverParty) -> tuple:
            primary_cert['verdict'] = 'PASS'
            return True, '', {}

    certificate = {'verdict': 'FAIL', 'value': 7}
    original = deepcopy(certificate)
    surface = DisclosureSurface('DATA', tuple(certificate), ())
    bounds = tuple(DisclosureBound('b:' + key, key, admitted_roles=('reader',))
                   for key in certificate)
    try:
        evaluator = EmissionEvaluator(MutatingComposer())
        result = evaluator.evaluate_emission(certificate, surface, bounds, context())
    except ValueError:
        assert certificate == original
        return
    assert certificate == original, 'composition callback mutated the caller input'
    assert result.emitted_certificate['verdict'] == 'FAIL'
    assert evaluator.recheck_emission(result, original, surface, bounds, context()) is True


def test_review_custom_non_boolean_denial_is_not_admission() -> None:
    class MalformedAdmission(CompositionDeltaEvaluator):
        def evaluate_composition_delta(self, **kwargs: Any) -> tuple:
            return 'DENIED', 'composition refused', {}

    with pytest.raises(ValueError):
        EmissionEvaluator(MalformedAdmission()).evaluate_emission(
            {'secret': 'synthetic-private'}, DisclosureSurface('DATA', ('secret',), ()),
            (DisclosureBound('b', 'secret', admitted_roles=('reader',)),), context(),
        )


def test_review_string_role_container_cannot_grant_substring_permission() -> None:
    try:
        result = evaluate_secret(DisclosureBound('b', 'secret', admitted_roles='nonreader'))
    except ValueError:
        return
    assert 'secret' not in result.emitted_certificate


def test_review_string_credentials_cannot_grant_substring_permission() -> None:
    bound = DisclosureBound('b', 'secret', admitted_roles=('reader',),
                            conditions=(('credential', 'admin'),))
    try:
        result = evaluate_secret(bound, observer_context=context(credentials='not-admin'))
    except ValueError:
        return
    assert 'secret' not in result.emitted_certificate


def test_review_supported_exact_role_and_credential_are_still_admitted() -> None:
    bound = DisclosureBound('b', 'secret', admitted_roles=('reader',),
                            conditions=(('purpose', 'audit'), ('credential', 'admin')))
    result = evaluate_secret(bound, observer_context=context(credentials=('admin',)))
    assert result.emitted_certificate == {'secret': 'synthetic-private'}
    assert result.receipt['level_6_conformance'] == 'UNKNOWN'
    assert result.receipt['observer_authentication'] == 'NOT_CHECKED'


def test_review_exact_credentials_do_not_match_partial_strings() -> None:
    bound = DisclosureBound('b', 'secret', admitted_roles=('reader',),
                            conditions=(('credential', 'admin'),))
    result = evaluate_secret(bound, observer_context=context(credentials=('not-admin',)))
    assert result.emitted_certificate == {}


def test_review_explicit_observer_grant_survives_unmatched_role() -> None:
    bound = DisclosureBound('b', 'secret', admitted_observers=('actor:reader',),
                            admitted_roles=('unmatched-role',))
    assert evaluate_secret(bound).emitted_certificate == {'secret': 'synthetic-private'}


def test_review_declarative_custom_rule_blocks_its_named_join() -> None:
    evaluator = EmissionEvaluator(CompositionDeltaEvaluator((('DATA', 'BENCH', 'test risk'),)))
    cert = {'domain': 'DATA', 'secret': 'synthetic-private'}
    with pytest.raises(ValueError):
        evaluator.evaluate_emission(
            cert, DisclosureSurface('DATA', tuple(cert), ()),
            tuple(DisclosureBound('b:' + key, key, admitted_roles=('reader',)) for key in cert),
            context(co_emitted=({'domain': 'BENCH'},)),
        )


def test_review_empty_declarative_rule_set_is_supported_and_bound() -> None:
    cert = {'domain': 'DATA', 'secret': 'synthetic-private'}
    surface = DisclosureSurface('DATA', tuple(cert), ())
    bounds = tuple(DisclosureBound('b:' + key, key, admitted_roles=('reader',)) for key in cert)
    ctx = context(co_emitted=({'domain': 'TRAIN'},))
    evaluator = EmissionEvaluator(CompositionDeltaEvaluator(()))
    result = evaluator.evaluate_emission(cert, surface, bounds, ctx)
    assert result.emitted_certificate == cert
    assert result.receipt['composition_join_check'] == 'UNKNOWN'
    assert evaluator.recheck_emission(result, cert, surface, bounds, ctx) is True
    assert EmissionEvaluator().recheck_emission(result, cert, surface, bounds, ctx) is False


def test_review_bundled_callback_result_must_be_boolean(monkeypatch: pytest.MonkeyPatch) -> None:
    # Reach the result-shape guard independently of rejection of custom types.
    # This is a controlled branch probe, not a loaded-code attestation claim.
    monkeypatch.setattr(CompositionDeltaEvaluator, 'evaluate_composition_delta',
                        lambda self, **kwargs: ('DENIED', 'composition refused', {}))
    with pytest.raises(ValueError):
        evaluate_secret(DisclosureBound('b', 'secret', admitted_roles=('reader',)))


def test_review_bundled_callback_cannot_mutate_authoritative_inputs(monkeypatch: pytest.MonkeyPatch) -> None:
    # Reach snapshot/mutation protection independently of custom-type rejection.
    def mutate(self: CompositionDeltaEvaluator, *, primary_cert: dict, co_emitted: tuple,
               observer: ObserverParty) -> tuple:
        primary_cert['verdict'] = 'PASS'
        return True, '', {}
    monkeypatch.setattr(CompositionDeltaEvaluator, 'evaluate_composition_delta', mutate)
    cert = {'verdict': 'FAIL', 'value': 7}
    original = deepcopy(cert)
    try:
        result = EmissionEvaluator().evaluate_emission(
            cert, DisclosureSurface('DATA', tuple(cert), ()),
            tuple(DisclosureBound('b:' + key, key, admitted_roles=('reader',)) for key in cert),
            context(),
        )
    except ValueError:
        assert cert == original
        return
    assert cert == original
    assert result.emitted_certificate['verdict'] == 'FAIL'


def test_review_string_surface_cannot_grant_substring_disclosure() -> None:
    try:
        result = EmissionEvaluator().evaluate_emission(
            {'sec': 'synthetic-private'}, DisclosureSurface('DATA', 'secret', ()),
            (DisclosureBound('b', 'sec', admitted_roles=('reader',)),), context(),
        )
    except ValueError:
        return
    assert 'sec' not in result.emitted_certificate


def test_unregistered_bound_predicate_cannot_override_empty_admission() -> None:
    class AdmittingBound(DisclosureBound):
        def permits(self, observer: ObserverParty) -> bool:
            return True

    with pytest.raises(ValueError):
        evaluate_secret(AdmittingBound('denied', 'secret'))


def specimen() -> tuple[dict[str, Any], DisclosureSurface, tuple[DisclosureBound, ...], EmissionContext]:
    certificate = {'value': 7, 'hidden': 'synthetic-private'}
    surface = DisclosureSurface('DATA', ('value',), ('hidden',))
    bounds = (DisclosureBound('value-bound', 'value', admitted_roles=('reader',)),)
    context = EmissionContext(ObserverParty('actor:reader', 'reader', 'audit'),
                              '2026-09-26T00:00:00Z')
    return certificate, surface, bounds, context


def test_review_result_subclass_cannot_hide_changed_projection() -> None:
    inputs = specimen()
    evaluator = EmissionEvaluator()
    original = evaluator.evaluate_emission(*inputs)

    class AlternateSerialization(EmissionResult):
        def to_dict(self) -> dict[str, Any]:
            return original.to_dict()

    forged = AlternateSerialization(
        {'value': 999}, original.redacted_fields, original.transparency_commitments,
        deepcopy(original.receipt),
    )
    assert forged.emitted_certificate != original.emitted_certificate
    assert evaluator.recheck_emission(forged, *inputs) is False


def test_review_commitment_subclass_cannot_hide_changed_commitment() -> None:
    inputs = specimen()
    evaluator = EmissionEvaluator()
    original = evaluator.evaluate_emission(*inputs)
    commitment = original.transparency_commitments[0]

    class AlternateCommitmentSerialization(TransparencyCommitment):
        def to_dict(self) -> dict[str, Any]:
            return commitment.to_dict()

    forged_commitment = AlternateCommitmentSerialization(
        'changed-hidden-coordinate', commitment.schema_type, '0' * 64,
    )
    forged = replace(original, transparency_commitments=(forged_commitment,))
    assert forged.transparency_commitments[0].field_name != commitment.field_name
    assert evaluator.recheck_emission(forged, *inputs) is False


def test_review_genuine_bundled_records_replay_with_private_commitment() -> None:
    inputs = specimen()
    original_inputs = deepcopy(inputs)
    evaluator = EmissionEvaluator()
    result = evaluator.evaluate_emission(*inputs)
    assert type(result) is EmissionResult
    assert all(type(c) is TransparencyCommitment for c in result.transparency_commitments)
    assert result.emitted_certificate == {'value': 7}
    assert result.redacted_fields == ('hidden',)
    assert evaluator.recheck_emission(result, *inputs) is True
    assert inputs == original_inputs
    assert result.receipt['level_6_conformance'] == 'UNKNOWN'


@pytest.mark.parametrize('location', ['certificate', 'certificate_value', 'policy', 'co_emitted', 'commitment'])
def test_input_copy_hooks_cannot_rewrite_original_declarations(location: str) -> None:
    calls = []

    class ChangedByCopy(dict):
        def __deepcopy__(self, memo: Any) -> dict[str, str]:
            calls.append('certificate')
            return {'verdict': 'PASS'}

    class ReplacedByCopy:
        def __init__(self, replacement: Any) -> None:
            self.replacement = replacement

        def __deepcopy__(self, memo: Any) -> Any:
            calls.append('field')
            return self.replacement

    certificate, surface, bounds, observer_context = specimen()
    if location == 'certificate':
        certificate = ChangedByCopy(verdict='FAIL')
        surface = DisclosureSurface('DATA', ('verdict',), ())
        bounds = (DisclosureBound('b', 'verdict', admitted_roles=('reader',)),)
    elif location == 'certificate_value':
        certificate['value'] = ReplacedByCopy(7)
    elif location == 'policy':
        bounds = (replace(bounds[0], admitted_roles=ReplacedByCopy(('reader',))),)
    elif location == 'co_emitted':
        observer_context = replace(observer_context, co_emitted_certificates=(ChangedByCopy(verdict='FAIL'),))
    else:
        surface = replace(surface, commitments=(TransparencyCommitment(
            'hidden', 'str', ReplacedByCopy('0' * 64)),))
    with pytest.raises(ValueError):
        EmissionEvaluator().evaluate_emission(certificate, surface, bounds, observer_context)
    assert calls == []


def test_result_commitment_copy_hook_cannot_hide_changed_value() -> None:
    inputs = specimen()
    evaluator = EmissionEvaluator()
    result = evaluator.evaluate_emission(*inputs)
    original = result.transparency_commitments[0]
    calls = []

    class AlternateDigest:
        def __deepcopy__(self, memo: Any) -> str:
            calls.append('digest')
            return original.commitment_digest

    forged = replace(result, transparency_commitments=(replace(original, commitment_digest=AlternateDigest()),))
    assert evaluator.recheck_emission(forged, *inputs) is False
    assert calls == []
