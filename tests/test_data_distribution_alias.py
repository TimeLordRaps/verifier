"""Distinct canonical values cannot share a passing legacy distribution class.

Verifier Standard (VSTD); JavaScript Object Notation (JSON). Counts are
dimensionless; Shannon entropy is measured in bits per retained observation.
"""
import pytest

from verifier.domains.common import Budget, Refuted, Unavailable, digest
from verifier.domains.statics import evaluate


@pytest.mark.parametrize("value", [1, True, None, [1], {"x": 1}])
def test_two_distinct_values_cannot_establish_one_class(value):
    label = digest(value)
    artifact = {"distribution": {"class": {"cardinality": 1,
                "balance": {label: 1.0}, "entropy_bits": 0.0}}}
    inputs = {"shards": {"s": [{"class": value}, {"class": label}]}}
    with pytest.raises(Refuted, match="cardinality"):
        evaluate("DATA", "distribution", artifact, inputs, Budget(10000))


@pytest.mark.parametrize("value", [1, True, None, [1], {"x": 1}])
def test_correct_cardinality_with_ambiguous_legacy_labels_is_unavailable(value):
    label = digest(value)
    artifact = {"distribution": {"class": {"cardinality": 2,
                "balance": {label: 1.0}, "entropy_bits": 1.0}}}
    inputs = {"shards": {"s": [{"class": value}, {"class": label}]}}
    with pytest.raises(Unavailable, match="ambiguous"):
        evaluate("DATA", "distribution", artifact, inputs, Budget(10000))


@pytest.mark.parametrize("values,labels", [
    (["red", "blue"], ["red", "blue"]),
    ([1, True], [digest(1), digest(True)]),
    ([None, "null"], [digest(None), "null"]),
])
def test_unambiguous_legacy_wire_labels_remain_compatible(values, labels):
    artifact = {"distribution": {"class": {"cardinality": 2,
                "balance": dict.fromkeys(labels, 0.5), "entropy_bits": 1.0}}}
    inputs = {"shards": {"s": [{"class": v} for v in values]}}
    assert evaluate("DATA", "distribution", artifact, inputs, Budget(10000)) == {
        "fields": ["class"], "records": 2}
