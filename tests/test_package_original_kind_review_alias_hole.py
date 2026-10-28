"""Regression coverage for injected receivers hidden behind local aliases."""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path

import pytest

from verifier.runtime import namespace_classification as classification
from verifier.runtime import package_original_kind_review as audit


@pytest.mark.parametrize(
    ("label", "source"),
    (
        ("direct", "def keep(store, items):\n    store.update(items)\n"),
        ("local_alias", "def keep(store, items):\n    sink = store\n    sink.update(items)\n"),
        (
            "parameter_attribute_alias",
            "def keep(owner, items):\n    sink = owner.store\n    sink.update(items)\n",
        ),
        (
            "transitive_alias",
            "def keep(store, items):\n    first = store\n    sink = first\n    sink.update(items)\n",
        ),
        (
            "callback_alias",
            "def keep(callback, items):\n    local = callback\n    return list(map(local, items))\n",
        ),
        (
            "lambda_parameter_shadows_known_outer_receiver",
            "def keep():\n"
            "    sink = {}\n"
            "    return lambda sink: sink.update({'x': 1})\n",
        ),
    ),
)
def test_injected_receiver_stays_blocked_through_alias(
    tmp_path: Path,
    label: str,
    source: str,
) -> None:
    root = tmp_path / label
    target = root / "pkg" / "mod.py"
    target.parent.mkdir(parents=True)
    target.write_text(source, encoding="utf-8", newline="")
    relative = "pkg/mod.py"
    digest = "sha256:" + sha256(target.read_bytes()).hexdigest()

    result = audit.audit_closed_effects(root, (relative,))
    context = {
        "root": root,
        "files": {relative: digest},
        "inventory": {},
        "audit_memo": {},
    }
    verdict = classification._closed_effect_blocker(context, None, {relative})

    assert verdict is not None, (
        f"{label} was admitted as closed: audit_status={result.status} "
        f"blockers={result.blockers}"
    )
    assert any("INJECTED_CALLABLE_UNRESOLVED" in blocker for blocker in result.blockers)


@pytest.mark.parametrize(
    ("label", "source", "expected_closed", "unresolved_target"),
    (
        (
            "known_literal",
            "def keep(items):\n    sink = {}\n    sink.update(items)\n",
            True,
            None,
        ),
        (
            "known_constructor",
            "def keep(items):\n    sink = dict()\n    sink.update(items)\n",
            True,
            None,
        ),
        (
            "known_conditional_constructor",
            "def keep(items):\n"
            "    sink = {} if items is None else dict(items)\n"
            "    return sink.get('key')\n",
            True,
            None,
        ),
        (
            "unknown_receiver",
            "def keep(items):\n    sink = make_sink()\n    sink.update(items)\n",
            False,
            "sink.update",
        ),
        (
            "wrong_builtin_method",
            "def keep():\n    sink = []\n    return sink.lower()\n",
            False,
            "sink.lower",
        ),
    ),
)
def test_pure_method_requires_a_known_compatible_builtin_receiver(
    tmp_path: Path,
    label: str,
    source: str,
    expected_closed: bool,
    unresolved_target: str | None,
) -> None:
    root = tmp_path / label
    target = root / "pkg" / "mod.py"
    target.parent.mkdir(parents=True)
    target.write_text(source, encoding="utf-8", newline="")

    result = audit.audit_closed_effects(root, ("pkg/mod.py",))

    if expected_closed:
        assert result.status == "CLOSED", result.blockers
        assert result.blockers == ()
    else:
        assert result.status == "UNKNOWN"
        assert unresolved_target is not None
        assert any(
            blocker.startswith("CALL_TARGET_UNRESOLVED:")
            and blocker.endswith(":" + unresolved_target)
            for blocker in result.blockers
        )
