from __future__ import annotations

import ast
import hashlib
import json
import re
from pathlib import Path

import pytest

from verifier.runtime import tier_zero_profile as profile


def _resource_chain(call: ast.Call) -> tuple[str, ...]:
    """Return the package-anchored literal path of one ``files(...)...read_bytes()``.

    Raises AssertionError unless the receiver is exactly that chain with literal
    segments, so any constructed or __file__-derived read is rejected.
    """
    segments: list[str] = []
    node = call.func.value  # type: ignore[attr-defined]
    while (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "joinpath"
    ):
        assert not node.keywords
        assert all(
            isinstance(arg, ast.Constant) and isinstance(arg.value, str)
            for arg in node.args
        )
        segments[:0] = [arg.value for arg in node.args]
        node = node.func.value
    assert isinstance(node, ast.Call)
    assert isinstance(node.func, ast.Name) and node.func.id == "files"
    assert not node.keywords and len(node.args) == 1
    root = node.args[0]
    assert isinstance(root, ast.Constant) and isinstance(root.value, str)
    return (root.value, *segments)


def test_installed_tier_zero_profile_is_complete_reasoned_and_digest_bound() -> None:
    value = profile.installed_tier_zero_profile()

    assert value["schema_version"] == profile.PROFILE_SCHEMA
    assert value["profile_id"] == profile.PROFILE_ID
    assert value["object_kind_count"] == 26
    assert value["core_slot_count"] == 234
    assert value["core_route_count"] == 408
    assert value["obligation_count"] == len(value["obligations"]) == 9
    assert [row["coordinate"] for row in value["obligations"]] == [
        f"VSTD-T0.{index}" for index in range(1, 10)
    ]
    assert len(value["closure_dimensions"]) == len(
        set(value["closure_dimensions"])
    ) == 9
    for row in value["obligations"]:
        assert all(
            isinstance(row[name], str) and row[name].strip()
            for name in (
                "name", "question", "rationale", "pass_condition",
                "unknown_condition", "failure_condition", "claim_boundary",
            )
        )
        assert isinstance(row["required_evidence"], list)
        assert row["required_evidence"]
        assert len(row["required_evidence"]) == len(set(row["required_evidence"]))
    body = {key: item for key, item in value.items() if key != "profile_digest"}
    assert value["profile_digest"] == profile.value_digest(body)
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", value["profile_digest"])
    assert json.loads(profile.canonical_bytes(value)) == value


def test_tier_zero_mechanism_binds_profile_module_and_specification() -> None:
    assert re.fullmatch(
        r"sha256:[0-9a-f]{64}", profile.mechanism_digest(b"module", b"specification")
    )


def test_tier_zero_mechanism_digest_equals_exact_supplied_bytes() -> None:
    module = Path(profile.__file__).resolve()
    specification = module.parents[1] / "standard" / "TIER_ZERO.md"
    expected = profile.value_digest({
        "schema_version": "verifier-tier-zero-profile-mechanism-1",
        "module_digest": "sha256:" + hashlib.sha256(module.read_bytes()).hexdigest(),
        "specification_digest": "sha256:" + hashlib.sha256(
            specification.read_bytes()
        ).hexdigest(),
        "profile_digest": profile.installed_tier_zero_profile()["profile_digest"],
    })
    assert profile.mechanism_digest(
        module.read_bytes(), specification.read_bytes()
    ) == expected


def test_tier_zero_mechanism_digest_changes_with_each_supplied_byte_sequence() -> None:
    base = profile.mechanism_digest(b"module", b"specification")
    assert profile.mechanism_digest(b"module\n", b"specification") != base
    assert profile.mechanism_digest(b"module", b"specification\n") != base


@pytest.mark.parametrize(
    "module_bytes, specification_bytes",
    [
        ("module", b"specification"),
        (bytearray(b"module"), b"specification"),
        (b"module", None),
        (memoryview(b"module"), b"specification"),
    ],
)
def test_tier_zero_mechanism_refuses_non_bytes_inputs_closed(
    module_bytes: object, specification_bytes: object
) -> None:
    with pytest.raises(ValueError, match="TIER_ZERO_PROFILE_MECHANISM_BYTES_INVALID"):
        profile.mechanism_digest(module_bytes, specification_bytes)


def test_tier_zero_profile_imports_only_pure_admitted_modules() -> None:
    tree = ast.parse(Path(profile.__file__).read_bytes())
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
    assert imported == {"__future__", "hashlib", "json", "typing"}


def test_tier_zero_coordinates_and_slugs_are_the_canonical_nine() -> None:
    value = profile.installed_tier_zero_profile()
    observed = [
        (row["coordinate"], row["name"].lower().replace(" ", "-"))
        for row in value["obligations"]
    ]
    assert observed == [
        ("VSTD-T0.1", "canonical-manifest-admission"),
        ("VSTD-T0.2", "object-denominator-closure"),
        ("VSTD-T0.3", "typed-relation-closure"),
        ("VSTD-T0.4", "exposed-surface-closure"),
        ("VSTD-T0.5", "obligation-denominator-closure"),
        ("VSTD-T0.6", "reason-and-realization-closure"),
        ("VSTD-T0.7", "source-and-mechanism-freshness"),
        ("VSTD-T0.8", "independent-implementation-agreement"),
        ("VSTD-T0.9", "conservative-verdict-and-authority-boundary"),
    ]


def test_tier_zero_mechanism_has_no_constructed_path_read() -> None:
    # Prevention: the refuted owner must not derive a path from __file__, and any
    # byte read it keeps must be one literal package-anchored resource chain.
    tree = ast.parse(Path(profile.__file__).read_bytes())
    assert not [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Name) and node.id == "__file__"
    ]
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "read_bytes"
        ):
            _resource_chain(node)
