from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
from pathlib import Path

import pytest

from verifier.runtime import package_semantic_review_core as review
from verifier.runtime.namespace_contracts import namespace_registry, requirements_for


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_PATHS = (
    "src/verifier/domains/verifier.py",
    "src/verifier/domains/verifier_bootstrap.py",
    "src/verifier/domains/contracts/verifier_coverage_closure.py",
    "src/verifier/domains/contracts/verifier_composed_security.py",
    "src/verifier/domains/contracts/verifier_replacement.py",
    "src/verifier/runtime/package_review_stage_gaps.py",
    "src/verifier/runtime/package_verifier_graph.py",
    "src/verifier/runtime/tier_zero_reasoning/__init__.py",
    "src/verifier/runtime/tier_zero_reasoning/binding_registry.py",
    "src/verifier/runtime/tier_zero_reasoning/cli.py",
    "src/verifier/runtime/tier_zero_reasoning/conditional_dispatch.py",
    "src/verifier/runtime/tier_zero_reasoning/effect_reach_prototype.py",
    "src/verifier/runtime/tier_zero_reasoning/integration.py",
    "src/verifier/runtime/tier_zero_reasoning/project_effect_first.py",
    "src/verifier/runtime/tier_zero_reasoning/reasons_check.py",
    "src/verifier/runtime/tier_zero_reasoning/reasons_dsl.py",
    "src/verifier/runtime/tier_zero_reasoning/redundancy_obligations.py",
    "src/verifier/runtime/tier_zero_reasoning/replace_codec_probe.py",
    "src/verifier/runtime/tier_zero_reasoning/witness_runner.py",
)
EXPECTED_APPLICABILITY = {
    "LEDGER",
    "TRANSACTION",
    "ASSET",
    "MARKET",
    "MEASUREMENT",
    "SENSOR",
    "CONTROLLER",
    "ACTUATOR",
    "PROTOCOL",
    "POLICY",
    "ROBOT",
    "FINBOT",
}
EXPECTED_ROLE_PATHS = {
    "LEDGER": (
        "src/verifier/runtime/package_review_stage_gaps.py",
        "src/verifier/runtime/tier_zero_reasoning/integration.py",
        "src/verifier/runtime/tier_zero_reasoning/reasons_check.py",
    ),
    "TRANSACTION": (
        "src/verifier/domains/contracts/verifier_coverage_closure.py",
    ),
    "ASSET": EXPECTED_PATHS,
    "MARKET": (
        "src/verifier/runtime/tier_zero_reasoning/conditional_dispatch.py",
        "src/verifier/runtime/tier_zero_reasoning/integration.py",
        "src/verifier/runtime/tier_zero_reasoning/witness_runner.py",
    ),
    "MEASUREMENT": EXPECTED_PATHS,
    "SENSOR": EXPECTED_PATHS,
    "CONTROLLER": (
        "src/verifier/domains/contracts/verifier_coverage_closure.py",
    ),
    "ACTUATOR": (
        "src/verifier/domains/contracts/verifier_coverage_closure.py",
    ),
    "PROTOCOL": (
        "src/verifier/domains/verifier_bootstrap.py",
        "src/verifier/domains/contracts/verifier_composed_security.py",
        "src/verifier/domains/contracts/verifier_replacement.py",
    ),
    "POLICY": EXPECTED_PATHS,
    "ROBOT": (
        "src/verifier/runtime/tier_zero_reasoning/conditional_dispatch.py",
        "src/verifier/runtime/tier_zero_reasoning/integration.py",
        "src/verifier/runtime/tier_zero_reasoning/witness_runner.py",
    ),
    "FINBOT": (
        "src/verifier/runtime/tier_zero_reasoning/conditional_dispatch.py",
        "src/verifier/runtime/tier_zero_reasoning/integration.py",
        "src/verifier/runtime/tier_zero_reasoning/witness_runner.py",
    ),
}
EXPECTED_UNRESOLVED: set[str] = set()
EXPECTED_COUNTS = {
    "objects": 1,
    "paths": 19,
    "decisions": 12,
    "applies": 12,
    "does_not_apply": 0,
    "unresolved": 0,
    "declarations": 36,
    "declaration_fields": 145,
}


def _digest(raw: bytes) -> str:
    return "sha256:" + sha256(raw).hexdigest()


def _requirements() -> dict[str, dict[str, tuple[str, ...]]]:
    registry = namespace_registry()
    return {
        kind: {
            item["id"]: tuple(item["declaration_fields"])
            for item in requirements_for(registry, (kind,))
            if item["kind"] == kind
        }
        for kind in review.REVIEW_KINDS
    }


def _all_obligations() -> dict[str, dict]:
    return {
        obligation_id: {
            "reason": "",
            "evidence": [],
            "declaration": {field: "" for field in fields},
        }
        for obligations in _requirements().values()
        for obligation_id, fields in obligations.items()
    }


def _row() -> dict[str, dict]:
    return {
        review.CORE_OBJECT_ID: {
            "object_id": review.CORE_OBJECT_ID,
            "kind": "VERIFIER",
            "specializations": [],
            "payload": {},
            "operands": {},
            "surfaces": ["file:" + path for path in EXPECTED_PATHS],
            "reason": "Synthetic retained VERIFIER core owner.",
            "classification": {
                kind: {
                    "status": "UNRESOLVED",
                    "reason": "Current source has not yet been reviewed.",
                    "evidence": [],
                }
                for kind in review.REVIEW_KINDS
            },
            "obligations": _all_obligations(),
        }
    }


def _repository_files() -> dict[str, str]:
    return {path: _digest((ROOT / path).read_bytes()) for path in EXPECTED_PATHS}


def _workspace(tmp_path: Path) -> tuple[Path, dict[str, dict], dict[str, str]]:
    files = {}
    for path in EXPECTED_PATHS:
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        raw = (review.CORE_OBJECT_ID + "\0" + path + "\n").encode("utf-8")
        target.write_bytes(raw)
        files[path] = _digest(raw)
    return tmp_path, _row(), files


def _line_digest(lines: list[str]) -> str:
    return sha256("\n".join(sorted(lines)).encode("utf-8")).hexdigest()


def test_review_document_has_exact_complete_retained_core_denominator() -> None:
    first = review.review_document()
    second = review.review_document()
    assert first == second
    assert first is not second
    assert tuple(first) == (review.CORE_OBJECT_ID,)
    assert review.CORE_PATHS == EXPECTED_PATHS
    assert review.review_counts() == EXPECTED_COUNTS

    item = first[review.CORE_OBJECT_ID]
    assert item["primary_kind"] == "VERIFIER"
    assert tuple(item["owned_paths"]) == EXPECTED_PATHS
    assert set(item["classification"]) == set(review.REVIEW_KINDS)
    assert {
        kind
        for kind, decision in item["classification"].items()
        if decision["status"] == "APPLIES"
    } == EXPECTED_APPLICABILITY
    assert {
        kind
        for kind, decision in item["classification"].items()
        if decision["status"] == "DOES_NOT_APPLY"
    } == set(review.REFUTED_KINDS) == set()
    assert {
        kind
        for kind, decision in item["classification"].items()
        if decision["status"] == "UNRESOLVED"
    } == EXPECTED_UNRESOLVED
    # Each kind carries its own reason: APPLIES prose, or an UNRESOLVED reason
    # that names the kind it leaves open.
    assert len(
        {decision["reason"] for decision in item["classification"].values()}
    ) == 12

    for kind, decision in item["classification"].items():
        assert decision["status"] in {"APPLIES", "UNRESOLVED"}
        assert decision["reason"].strip()
        if kind in EXPECTED_APPLICABILITY:
            assert tuple(decision["evidence_paths"]) == EXPECTED_ROLE_PATHS[kind]
        else:
            assert decision["evidence_paths"] == []

    requirements = _requirements()
    expected = {
        obligation_id: fields
        for kind in EXPECTED_APPLICABILITY
        for obligation_id, fields in requirements[kind].items()
    }
    assert len(expected) == 36
    assert set(item["declarations"]) == set(expected)
    for obligation_id, declaration in item["declarations"].items():
        assert set(declaration) == set(expected[obligation_id])
        assert all(
            type(value) is str and value.strip() and len(value) <= 8192
            for value in declaration.values()
        )
    assert "Tier-0" in item["claim_boundary"]
    assert "general verifier soundness" in item["claim_boundary"]

    first[review.CORE_OBJECT_ID]["declarations"].clear()
    assert review.review_document() == second


def test_review_paths_are_current_ordinary_files_with_pinned_inventory() -> None:
    assert _line_digest(list(EXPECTED_PATHS)) == (
        "dc9d2cb6d5b8e4afb455c8b62da098956e3f30be981ac97d50b2c00bb830fe7b"
    )
    inventory = []
    for path in EXPECTED_PATHS:
        target = ROOT / path
        assert target.is_file(), path
        assert not target.is_symlink(), path
        assert target.resolve(strict=True).is_relative_to(ROOT.resolve())
        raw = target.read_bytes()
        inventory.append(f"{path}\t{len(raw)}\t{sha256(raw).hexdigest()}")
    assert _line_digest(inventory) == (
        "6e1e30cddbe47d434b2627acad8a4921d072419d03071c8ede7d322f3a02945e"
    )


def test_apply_populates_exact_current_evidence_and_consequence_labels() -> None:
    rows = _row()
    files = _repository_files()
    before = deepcopy(rows)

    first = review.apply_package_semantic_review_core(ROOT, rows, files)
    second = review.apply_package_semantic_review_core(ROOT, first, files)

    assert rows == before
    assert first == second
    item = first[review.CORE_OBJECT_ID]
    assert set(item["specializations"]) == EXPECTED_APPLICABILITY
    assert set(item["classification"]) == set(review.REVIEW_KINDS)
    assert len(item["obligations"]) == 36
    for kind, decision in item["classification"].items():
        assert decision["status"] == (
            "APPLIES" if kind in EXPECTED_APPLICABILITY else "UNRESOLVED"
        )
        if kind in EXPECTED_APPLICABILITY:
            assert decision["evidence"] == [
                {"path": path, "sha256": files[path]}
                for path in EXPECTED_ROLE_PATHS[kind]
            ]
        else:
            assert decision["evidence"] == []

    requirements = _requirements()
    for obligation_id, binding in item["obligations"].items():
        kind = obligation_id.split("-", 1)[0]
        assert kind in EXPECTED_APPLICABILITY
        assert set(binding["declaration"]) == set(requirements[kind][obligation_id])
        assert all(value.strip() for value in binding["declaration"].values())
        assert tuple(ref["path"] for ref in binding["evidence"]) == (
            EXPECTED_ROLE_PATHS[kind]
        )
        assert "Tier-0 declaration" in binding["reason"]


def test_apply_preserves_complete_compatible_current_bindings() -> None:
    files = _repository_files()
    selected = review.apply_package_semantic_review_core(ROOT, _row(), files)
    item = selected[review.CORE_OBJECT_ID]

    expected = deepcopy(item)

    result = review.apply_package_semantic_review_core(ROOT, selected, files)
    assert result[review.CORE_OBJECT_ID] == expected


def test_unreviewed_extra_object_is_not_classified_by_catalog_complement() -> None:
    files = _repository_files()
    rows = _row()
    future = deepcopy(rows[review.CORE_OBJECT_ID])
    future["object_id"] = "future-core-neighbor"
    future["surfaces"] = []
    rows[future["object_id"]] = future

    result = review.apply_package_semantic_review_core(ROOT, rows, files)

    assert result[future["object_id"]] == future
    assert {
        decision["status"] for decision in future["classification"].values()
    } == {"UNRESOLVED"}


def test_foreign_operand_and_negative_text_cannot_decide_core_roles() -> None:
    files = _repository_files()
    rows = _row()
    selected = rows[review.CORE_OBJECT_ID]
    selected["operands"] = {
        "ROBOT": ["foreign-robot-owner"],
        "FINBOT": ["foreign-financial-owner"],
    }
    selected["payload"] = {
        "LEDGER": "does not exist",
        "ASSET": "not applicable",
        "MARKET": "no orders or settlement",
    }
    selected["reason"] = "OBJECT label excludes every unlisted consequence."

    result = review.apply_package_semantic_review_core(ROOT, rows, files)
    item = result[review.CORE_OBJECT_ID]

    assert item["operands"] == selected["operands"]
    assert item["payload"] == selected["payload"]
    assert {
        kind: item["classification"][kind]["status"]
        for kind in review.REVIEW_KINDS
    } == {kind: "APPLIES" for kind in review.REVIEW_KINDS}
    assert set(item["obligations"]) == {
        obligation_id
        for kind in review.REVIEW_KINDS
        for obligation_id in _requirements()[kind]
    }


@pytest.mark.parametrize(
    "failure",
    [
        "stale_census",
        "missing_source",
        "unowned_source",
        "extra_owned_source",
        "tampered_status",
        "tampered_evidence",
        "narrowed_evidence",
        "partial_declaration",
        "refuted_declaration",
        "refuted_specialization",
        "reason_substitution",
        "refutation_substitution",
        "obligation_reason_substitution",
        "unknown_obligation",
    ],
)
def test_apply_rejects_stale_missing_or_tampered_state_atomically(
    tmp_path: Path,
    failure: str,
) -> None:
    root, rows, files = _workspace(tmp_path)
    if failure in {
        "tampered_status",
        "tampered_evidence",
        "narrowed_evidence",
        "partial_declaration",
        "refuted_declaration",
        "refuted_specialization",
        "reason_substitution",
        "refutation_substitution",
        "obligation_reason_substitution",
        "unknown_obligation",
    }:
        rows = review.apply_package_semantic_review_core(root, rows, files)
    item = rows[review.CORE_OBJECT_ID]

    if failure == "stale_census":
        files[EXPECTED_PATHS[0]] = "sha256:" + "0" * 64
    elif failure == "missing_source":
        (root / EXPECTED_PATHS[0]).unlink()
    elif failure == "unowned_source":
        item["surfaces"].pop()
    elif failure == "extra_owned_source":
        item["surfaces"].append("file:unreviewed/extra.py")
    elif failure == "tampered_status":
        item["classification"]["TRANSACTION"]["status"] = "DOES_NOT_APPLY"
    elif failure == "tampered_evidence":
        item["classification"]["PROTOCOL"]["evidence"][0]["sha256"] = (
            "sha256:" + "f" * 64
        )
    elif failure == "narrowed_evidence":
        item["classification"]["MEASUREMENT"]["evidence"].pop()
    elif failure == "partial_declaration":
        item["obligations"]["POLICY-0.1-rules-and-precedence"]["declaration"][
            "scope"
        ] = ""
    elif failure == "refuted_declaration":
        item["obligations"]["LEDGER-0.1-authoritative-history"] = {
            "reason": "Contradictory retained ledger declaration.",
            "evidence": deepcopy(item["classification"]["LEDGER"]["evidence"]),
            "declaration": {
                "history": "Contradictory history.",
                "state": "Contradictory state.",
                "ordering": "Contradictory ordering.",
                "authority": "Contradictory authority.",
            },
        }
    elif failure == "refuted_specialization":
        item["specializations"].append("LEDGER")
    elif failure == "reason_substitution":
        item["classification"]["PROTOCOL"]["reason"] = (
            "Different same-status reason."
        )
    elif failure == "refutation_substitution":
            # A refutation substituted for an audited APPLIES decision is stale or
            # forged and must fail closed, not be erased.
        item["classification"]["LEDGER"] = {
            "status": "DOES_NOT_APPLY",
            "reason": "Forged refutation carried over from an older table.",
            "evidence": deepcopy(item["classification"]["MEASUREMENT"]["evidence"]),
        }
    elif failure == "obligation_reason_substitution":
        item["obligations"]["PROTOCOL-0.1-participants-and-states"][
            "reason"
        ] = "Different same-shape declaration reason."
    else:
        item["obligations"]["POLICY-0.99-invented"] = {
            "reason": "Invented.",
            "evidence": [],
            "declaration": {},
        }

    before = deepcopy(rows)
    with pytest.raises(ValueError) as caught:
        review.apply_package_semantic_review_core(root, rows, files)
    assert str(caught.value) == EXPECTED_TAMPER_CODE[failure]
    assert rows == before


def test_apply_rechecks_complete_source_denominator_before_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, rows, files = _workspace(tmp_path)
    target = EXPECTED_PATHS[-1]
    original = review._shared._read_digest
    calls = 0

    def drifting_digest(selected_root: Path, path: str) -> str:
        nonlocal calls
        value = original(selected_root, path)
        if path == target:
            calls += 1
            if calls == 2:
                return "sha256:" + "a" * 64
        return value

    monkeypatch.setattr(review._shared, "_read_digest", drifting_digest)
    before = deepcopy(rows)
    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_SOURCE_CHANGED"):
        review.apply_package_semantic_review_core(root, rows, files)
    assert rows == before


def test_apply_rejects_symlink_source_substitution_atomically(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, rows, files = _workspace(tmp_path)
    target = root / EXPECTED_PATHS[0]
    substitute = root / "foreign-source.py"
    substitute.write_bytes(target.read_bytes())
    target.unlink()
    try:
        target.symlink_to(substitute)
    except OSError:
        # Some Windows policies refuse creation even though the verifier must
        # still exercise its explicit substitution branch on every test host.
        target.write_bytes(substitute.read_bytes())
        original = Path.is_symlink
        monkeypatch.setattr(
            Path,
            "is_symlink",
            lambda candidate: candidate == target or original(candidate),
        )
    before = deepcopy(rows)

    with pytest.raises(ValueError) as caught:
        review.apply_package_semantic_review_core(root, rows, files)

    assert str(caught.value) == (
        "PACKAGE_SEMANTIC_REVIEW_SOURCE_UNAVAILABLE:" + EXPECTED_PATHS[0]
    )
    assert rows == before


# Second-pass regressions: exact tamper diagnostics for the retained core, and
# a foreign-prefixed obligation that must not survive the complete review.
EXPECTED_TAMPER_CODE = {
    "stale_census": "PACKAGE_SEMANTIC_REVIEW_SOURCE_DIFFERS:verifier-core-self:"
    + EXPECTED_PATHS[0],
    "missing_source": "PACKAGE_SEMANTIC_REVIEW_SOURCE_UNAVAILABLE:" + EXPECTED_PATHS[0],
    "unowned_source": "PACKAGE_SEMANTIC_REVIEW_OWNERSHIP_DIFFERS:verifier-core-self",
    "extra_owned_source": "PACKAGE_SEMANTIC_REVIEW_OWNERSHIP_DIFFERS:verifier-core-self",
    "tampered_status": "PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT:verifier-core-self:TRANSACTION",
    "tampered_evidence": "PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT:verifier-core-self:PROTOCOL",
    "narrowed_evidence": "PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT:verifier-core-self:MEASUREMENT",
    "partial_declaration": (
        "PACKAGE_SEMANTIC_REVIEW_DECLARATION_CONFLICT:verifier-core-self:"
        "POLICY-0.1-rules-and-precedence"
    ),
    "refuted_declaration": (
        "PACKAGE_SEMANTIC_REVIEW_DECLARATION_CONFLICT:verifier-core-self:"
        "LEDGER-0.1-authoritative-history"
    ),
    "refuted_specialization": "PACKAGE_SEMANTIC_REVIEW_SPECIALIZATIONS_INVALID:verifier-core-self",
    "reason_substitution": "PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT:verifier-core-self:PROTOCOL",
    "refutation_substitution": "PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT:verifier-core-self:LEDGER",
    "obligation_reason_substitution": (
        "PACKAGE_SEMANTIC_REVIEW_DECLARATION_CONFLICT:verifier-core-self:"
        "PROTOCOL-0.1-participants-and-states"
    ),
    "unknown_obligation": (
        "PACKAGE_SEMANTIC_REVIEW_OBLIGATION_UNKNOWN:verifier-core-self:POLICY-0.99-invented"
    ),
}


def test_foreign_prefixed_obligation_fails_closed_without_mutation(tmp_path: Path) -> None:
    root, rows, files = _workspace(tmp_path)
    rows[review.CORE_OBJECT_ID]["obligations"]["BOGUS-0.1-foreign"] = {
        "reason": "",
        "evidence": [],
        "declaration": {},
    }
    before = deepcopy(rows)

    with pytest.raises(ValueError) as caught:
        review.apply_package_semantic_review_core(root, rows, files)
    assert str(caught.value) == (
        "PACKAGE_SEMANTIC_REVIEW_OBLIGATION_UNKNOWN:verifier-core-self:BOGUS-0.1-foreign"
    )
    assert rows == before


@pytest.mark.parametrize(
    ("name", "source", "expected_bucket"),
    [
        (
            "module_alias_process",
            "import subprocess as sp\nsp.run(['tool'])\n",
            "open_sites",
        ),
        (
            "from_alias_network",
            "from socket import create_connection as connect\nconnect(('x', 1))\n",
            "open_sites",
        ),
        (
            "dynamic_import",
            "import importlib\nimportlib.import_module('subprocess')\n",
            "open_sites",
        ),
        (
            "reflection",
            "def run(obj):\n    return getattr(obj, 'effect')()\n",
            "open_sites",
        ),
        (
            "effect_callback",
            "import os\nlist(map(os.system, ['tool']))\n",
            "flow_findings",
        ),
        (
            "container_callback",
            "def run(callback, items):\n    items.sort(key=callback)\n",
            "flow_findings",
        ),
        (
            "filesystem_effect",
            "from pathlib import Path\nPath('out').write_text('x')\n",
            "write_sites",
        ),
        (
            "constructed_path",
            "def run():\n    return open('/de' + 'v/ttyS0', 'rb').read()\n",
            "flow_findings",
        ),
    ],
)
def test_refutation_surface_is_open_for_transitive_effect_and_flow_escapes(
    tmp_path: Path,
    name: str,
    source: str,
    expected_bucket: str,
) -> None:
    """A future DNE needs CLOSED source flow, not lexical absence or prose."""
    package = tmp_path / "src/verifier"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    target = package / "core_candidate.py"
    target.write_text(source, encoding="utf-8")

    surface = review._refutation_surface(  # type: ignore[attr-defined]
        tmp_path,
        ("src/verifier/core_candidate.py",),
    )

    assert surface["status"] == "OPEN", name
    assert surface[expected_bucket], name
    assert set(surface["blocked_kinds"]) == set(review.REVIEW_KINDS)


def test_current_core_open_surface_justifies_retaining_every_kind() -> None:
    """The live effect-capable surface cannot support a negative kind claim."""
    surface = review._refutation_surface(ROOT)  # type: ignore[attr-defined]

    assert surface["status"] == "OPEN"
    assert len(surface["closure"]) >= len(EXPECTED_PATHS)
    assert set(review.REVIEW_KINDS) == set(surface["blocked_kinds"])
    assert surface["open_sites"] or surface["write_sites"] or surface["flow_findings"]


def test_future_refutation_candidate_requires_closed_transitive_surface(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, rows, files = _workspace(tmp_path)
    target = root / EXPECTED_PATHS[0]
    raw = target.read_bytes() + b"\nimport subprocess\nsubprocess.run(['tool'])\n"
    target.write_bytes(raw)
    files[EXPECTED_PATHS[0]] = _digest(raw)
    monkeypatch.setattr(review, "REFUTED_KINDS", ("LEDGER",))
    before = deepcopy(rows)

    with pytest.raises(ValueError) as caught:
        review.apply_package_semantic_review_core(root, rows, files)

    assert str(caught.value) == (
        "PACKAGE_SEMANTIC_REVIEW_REFUTATION_SURFACE_OPEN:"
        + review.CORE_OBJECT_ID
        + ":LEDGER"
    )
    assert rows == before


@pytest.mark.parametrize(
    "failure",
    ["foreign_row", "foreign_row_first", "within_row", "self_cycle"],
)
def test_apply_rejects_shared_or_cyclic_mutable_referents_atomically(
    tmp_path: Path,
    failure: str,
) -> None:
    """One mutable referent may not stand for two manifest coordinates."""
    root, rows, files = _workspace(tmp_path)
    selected = rows[review.CORE_OBJECT_ID]
    if failure == "foreign_row":
        rows["foreign-neighbor"] = selected
    elif failure == "foreign_row_first":
        rows = {"foreign-neighbor": selected, **rows}
    elif failure == "within_row":
        selected["classification"]["LEDGER"] = selected["classification"]["ASSET"]
    else:
        selected["operands"]["self"] = selected["operands"]

    # Cyclic structures cannot be compared by value; preserve an identity receipt
    # proving the original graph was not rewritten during the rejected application.
    if failure == "self_cycle":
        with pytest.raises(
            ValueError,
            match="PACKAGE_SEMANTIC_REVIEW_ALIAS_CONFLICT:verifier-core-self",
        ):
            review.apply_package_semantic_review_core(root, rows, files)
        assert selected["operands"]["self"] is selected["operands"]
        return

    before = deepcopy(rows)
    with pytest.raises(
        ValueError,
        match="PACKAGE_SEMANTIC_REVIEW_ALIAS_CONFLICT:verifier-core-self",
    ):
        review.apply_package_semantic_review_core(root, rows, files)
    assert rows == before
