"""Independent finite multilinear oracles for simulation (SIM) hidden changes.

On the complete Boolean endpoint cube, distinct square-free monomials are
linearly independent. A variable has an observable influence exactly when
some nonzero coefficient multiplies a monomial containing it. This oracle
uses coefficient support, not the implementation's endpoint-enumeration code.
Values and step indices here are dimensionless test coordinates.
"""
from itertools import combinations, product
import pytest
from verifier.domains.common import Budget, Refuted, Unavailable
from verifier.domains.contracts.sim_internal_core import enumerate_hidden_changes


def polynomial(names, coefficients):
    monomials=[subset for width in range(1,len(names)+1)
               for subset in combinations(names,width)]
    expression=0.0
    visible=set()
    for coefficient,variables in zip(coefficients,monomials):
        if not coefficient:continue
        visible.update(variables)
        term=float(coefficient)
        for name in variables:
            term={'op':'mul','args':[term,{'var':name}]}
        expression={'op':'add','args':[expression,term]}
    return expression,visible


@pytest.mark.parametrize('coefficients',list(product((0,1),repeat=7)))
def test_three_variable_multilinear_support(coefficients):
    names=('x','y','z')
    expression,visible=polynomial(names,coefficients)
    states=[dict.fromkeys(names,0.0),dict.fromkeys(names,1.0)]
    expected=[{'step':0,'state_key':name,'before':0.0,'after':1.0}
              for name in names if name not in visible]
    assert enumerate_hidden_changes(states,{'channel':expression},Budget(100000))==expected


@pytest.mark.parametrize('coefficients',list(product((-1,0,1),repeat=3)))
def test_signed_two_variable_polynomial_support(coefficients):
    names=('x','y')
    expression,visible=polynomial(names,coefficients)
    states=[dict.fromkeys(names,0.0),dict.fromkeys(names,1.0)]
    expected=[{'step':0,'state_key':name,'before':0.0,'after':1.0}
              for name in names if name not in visible]
    assert enumerate_hidden_changes(states,{'channel':expression},Budget(100000))==expected


def test_selected_state_item_exhaustion_is_unavailable_not_refuted():
    states=[dict.fromkeys(('x','y','z'),0.0),dict.fromkeys(('x','y','z'),1.0)]
    with pytest.raises(Unavailable):
        enumerate_hidden_changes(states,{'constant':0.0},Budget(100000,max_items=2))


def test_same_complete_trace_with_sufficient_items_enumerates_all_hidden_changes():
    names=('x','y','z')
    states=[dict.fromkeys(names,0.0),dict.fromkeys(names,1.0)]
    assert enumerate_hidden_changes(states,{'constant':0.0},Budget(100000,max_items=3))==[
        {'step':0,'state_key':name,'before':0.0,'after':1.0} for name in names]


def test_empty_state_is_invalid_independently_of_item_budget():
    with pytest.raises(Refuted):
        enumerate_hidden_changes([{},{}],{'constant':0.0},Budget(100000,max_items=2))
