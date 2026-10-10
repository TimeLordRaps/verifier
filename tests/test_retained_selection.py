"""Shared retained selection preserves capture, errors and source binding.

Verifier Standard (VSTD); Secure Hash Algorithm 256-bit (SHA-256).
Certificate sizes use bytes; checker limits and identifiers are dimensionless.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from verifier.core.certificate import canonical_digest
from verifier.domains.contracts import event_prerequisites, space_layout, time_order
from verifier.runtime import polish

ADAPTERS = (time_order, space_layout, event_prerequisites)


class ArmedString(str):
    def __eq__(self, other: Any) -> bool:
        raise AssertionError("untrusted comparison executed")

    def __ne__(self, other: Any) -> bool:
        raise AssertionError("untrusted comparison executed")

    def strip(self, *args: Any) -> str:
        raise AssertionError("untrusted strip executed")

    __hash__ = str.__hash__


class ArmedDict(dict):
    def __iter__(self) -> Any:
        raise AssertionError("untrusted iteration executed")


class ForeignInt(int):
    pass


def selection(adapter: Any) -> tuple[dict[str, Any], type[ValueError]]:
    stem = adapter.__name__.rsplit(".", 1)[-1]
    policy = getattr(adapter, stem + "_policy")(trust_roots=["selected-root"])
    error = next(value for name, value in vars(adapter).items()
                 if name.endswith("Error") and isinstance(value, type)
                 and issubclass(value, ValueError))
    return policy, error


@pytest.mark.parametrize("adapter", ADAPTERS)
@pytest.mark.parametrize("field", ["schema_version", "mechanism_id", "mechanism_digest",
                                   "trust_roots", "max_certificate_bytes"])
def test_policy_capture_refuses_foreign_values_before_callbacks(adapter: Any, field: str) -> None:
    policy, error = selection(adapter)
    if field == "trust_roots":
        policy[field] = [ArmedString(policy[field][0])]
    elif field == "max_certificate_bytes":
        policy[field] = ForeignInt(policy[field])
    else:
        policy[field] = ArmedString(policy[field])
    with pytest.raises(error):
        adapter._policy(policy)


@pytest.mark.parametrize("adapter", ADAPTERS)
def test_policy_capture_refuses_foreign_keys_before_set_operations(adapter: Any) -> None:
    policy, error = selection(adapter)
    policy[ArmedString("schema_version")] = policy.pop("schema_version")
    with pytest.raises(error):
        adapter._policy(policy)


@pytest.mark.parametrize("adapter", ADAPTERS)
def test_policy_capture_refuses_mapping_subclasses_before_iteration(adapter: Any) -> None:
    policy, error = selection(adapter)
    with pytest.raises(error):
        adapter._policy(ArmedDict(policy))


@pytest.mark.parametrize("adapter", ADAPTERS)
def test_policy_capture_owns_roots_and_retains_exact_values(adapter: Any) -> None:
    policy, _ = selection(adapter)
    captured = adapter._policy(policy)
    assert captured == policy and captured is not policy
    assert captured["trust_roots"] is not policy["trust_roots"]
    policy["trust_roots"].append("later-mutation")
    assert captured["trust_roots"] == ["selected-root"]


@pytest.mark.parametrize("adapter", ADAPTERS)
def test_malformed_policy_rejects_before_source_lookup(adapter: Any, monkeypatch: Any) -> None:
    policy, error = selection(adapter)
    policy["schema_version"] = "wrong-selected-version"

    def unexpected_lookup() -> str:
        raise AssertionError("source lookup preceded known policy rejection")

    monkeypatch.setattr(adapter, "mechanism_digest", unexpected_lookup)
    with pytest.raises(error):
        adapter._policy(policy)


@pytest.mark.parametrize("adapter", ADAPTERS)
@pytest.mark.parametrize("bad", [0, True, 2**53, ForeignInt(3)])
def test_limit_capture_preserves_plain_integer_and_finite_bounds(adapter: Any, bad: Any) -> None:
    _, error = selection(adapter)
    limits = dict(adapter._CEILINGS)
    limits["max_objects"] = bad
    with pytest.raises(error):
        adapter._limits(limits)


@pytest.mark.parametrize("adapter", ADAPTERS)
def test_bound_parameters_keep_every_selected_commitment(adapter: Any) -> None:
    fields = ("semantic_version", "proposition_digest", "object_kind",
              "object_digest", "collection_digest", "policy_digest")
    selected = {name: "selected-" + name for name in fields}
    selected["limits"] = {"max_objects": 3}
    expected = {name: selected[name] for name in fields}
    expected["limits_digest"] = "sha256:" + canonical_digest(selected["limits"])
    assert adapter._parameters(selected) == expected


@pytest.mark.parametrize("adapter", (*ADAPTERS, polish))
def test_shared_selection_source_invalidates_every_consuming_descriptor(adapter: Any, monkeypatch: Any) -> None:
    selected = Path(time_order.__file__).with_name("retained_selection.py").resolve()
    before = adapter.mechanism_digest()
    original = Path.read_bytes

    def substituted(path: Path) -> bytes:
        if path.resolve() == selected:
            return b"independent shared-selection source substitution\n"
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", substituted)
    assert adapter.mechanism_digest() != before
