"""Supplemental malformed-input checks for the frozen cooperative control gate."""
from __future__ import annotations
import pytest
from verifier.corrigibility import controlled_operation as gate
from verifier.corrigibility.contracts import InterruptibilityProtocol, VacuityFalsificationCheck, ContainmentViolationError

@pytest.mark.parametrize('value',[-1,3600.1,True,None,'1',float('nan'),float('inf'),float('-inf')])
def test_invalid_wait_deadline_cannot_claim_quiescence(value: object) -> None:
    session=gate.ControlledEmissionSession()
    with pytest.raises(ValueError):session.wait_for_quiescence(value)

@pytest.mark.parametrize('mode',['list_inputs','subclass_inputs','noncallable_effect'])
def test_invalid_invocation_refuses_before_authority_evaluation(monkeypatch: pytest.MonkeyPatch,mode: str) -> None:
    class Inputs(dict):pass
    def forbidden(**kwargs: object) -> object:raise AssertionError('Invalid call reached admission evaluation')
    monkeypatch.setattr(gate,'evaluate_controlled_emission',forbidden)
    inputs=[] if mode=='list_inputs' else Inputs() if mode=='subclass_inputs' else {}
    effect=None if mode=='noncallable_effect' else lambda value: value
    with pytest.raises(TypeError):gate.ControlledEmissionSession().invoke(inputs,effect)

@pytest.mark.parametrize('response',[None,[],{'admission':'MAYBE'},{'admission':True},{'admission':'PASS','emitted_certificate':[]}])
def test_invalid_internal_admission_output_never_calls_effect(monkeypatch: pytest.MonkeyPatch,response: object) -> None:
    monkeypatch.setattr(gate,'evaluate_controlled_emission',lambda **kwargs: response)
    called=[];session=gate.ControlledEmissionSession()
    result=session.invoke({},lambda value:called.append(value))
    assert result.admission=='UNKNOWN' and not result.effect_called and not called
    assert session.request_stop().state=='QUIESCENT'

@pytest.mark.parametrize('value',[1,0,'true',None])
def test_declared_process_group_flag_requires_a_real_boolean(value: object) -> None:
    with pytest.raises(ContainmentViolationError):InterruptibilityProtocol('p',1,enforce_process_group_kill=value)

@pytest.mark.parametrize('premises',[('',),(1,),('valid','')])
def test_declared_premises_require_nonempty_text(premises: tuple[object,...]) -> None:
    with pytest.raises(ContainmentViolationError):VacuityFalsificationCheck('p',premises,True)

def test_valid_boundary_controls_remain_accepted() -> None:
    InterruptibilityProtocol('p',1,enforce_process_group_kill=True)
    VacuityFalsificationCheck('p',('declared premise',),True)
    # Nonempty text is a shape requirement, not a grammar or satisfiability proof.
    declared=VacuityFalsificationCheck('p',('valid',' '),True)
    assert declared.to_dict()['premises']==['valid',' ']
    session=gate.ControlledEmissionSession()
    assert session.request_stop().state=='QUIESCENT'
    assert session.wait_for_quiescence(0) is True
