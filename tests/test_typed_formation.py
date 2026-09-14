"""Bounded experimental Verifier Standard (VSTD) typed-formation checks.

Tests distinguish checked formal syntax from source interpretation, agency,
completeness, execution, or an established Hypermath self-return proposition.
An integer identifier (ID) selects a node; the ID tag constructs an identity path.
"""

from __future__ import annotations

import ast
from copy import deepcopy
import hashlib
import importlib
import json
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest


DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64
REF_FIELDS = {
    "ATOM": (), "APPLY": ("argument",), "ID": ("at",),
    "APPLY_STEP": ("source", "target"), "COMPOSE": ("left", "right"),
    "QUOTE": ("value",), "READ": ("code",),
}
OBSERVATION_FIELDS = {
    "type", "denotation_digest", "source_digest", "target_digest", "path_steps",
    "quote_rank", "required_depth", "formation_digest", "dependency_nodes", "quote_origins",
}


@pytest.fixture
def formation() -> tuple[ModuleType, ModuleType, ModuleType]:
    return tuple(importlib.import_module("verifier.interoperability." + name) for name in (
        "formation_wire", "formation_producer", "formation_checker",
    ))


def _bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _subject(wire: ModuleType, nodes: list[dict[str, Any]], root: int | None = None) -> dict[str, Any]:
    return {
        "schema_version": "VSTD-TYPED-FORMATION-0.1", "profile_digest": wire.profile_digest(),
        "context": {"ground_artifact_digest": DIGEST_B, "authority_axiom_agency_digest": DIGEST_C},
        "nodes": nodes, "root": len(nodes) - 1 if root is None else root,
    }


def _certificate(subject: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "VSTD-TYPED-FORMATION-CERTIFICATE-0.1",
        "subject_digest": _digest(_bytes(subject)), "profile_digest": subject["profile_digest"],
        "steps": [
            {"node": index, "rule": node["tag"], "premises": [node[field] for field in REF_FIELDS.get(node["tag"], ())]}
            for index, node in enumerate(subject["nodes"])
        ], "root": subject["root"],
    }


def _check(checker: ModuleType, subject: dict[str, Any], certificate: dict[str, Any] | None = None) -> dict[str, Any]:
    return checker.check_formation(_bytes(subject), _bytes(_certificate(subject) if certificate is None else certificate))


def _observed(checker: ModuleType, subject: dict[str, Any]) -> dict[str, Any]:
    result = _check(checker, subject)
    assert result["status"] == "CHECKED", result
    assert result["reason_codes"] == []
    observation = result["observation"]
    assert set(observation) == OBSERVATION_FIELDS
    return observation


def _assert_failure(result: dict[str, Any], status: str, reason: str) -> None:
    assert result["status"] == status, result
    assert result["observation"] is None
    assert result["reason_codes"] == [reason]


def _two_steps() -> list[dict[str, Any]]:
    return [
        {"tag": "ATOM", "payload_digest": DIGEST_A},
        {"tag": "APPLY", "argument": 0},
        {"tag": "APPLY_STEP", "source": 0, "target": 1},
        {"tag": "APPLY", "argument": 1},
        {"tag": "APPLY_STEP", "source": 1, "target": 3},
        {"tag": "COMPOSE", "left": 2, "right": 4},
    ]


def test_typed_formation_producer_and_independent_checker_are_available() -> None:
    producer = importlib.import_module("verifier.interoperability.formation_producer")
    checker = importlib.import_module("verifier.interoperability.formation_checker")
    assert callable(producer.produce_formation_certificate)
    assert callable(checker.check_formation)


def test_typed_formation_atom_is_an_opaque_symbol_not_an_agency_claim(formation) -> None:
    wire, producer, checker = formation
    subject = _subject(wire, [{"tag": "ATOM", "payload_digest": DIGEST_A}])
    certificate = producer.produce_formation_certificate(_bytes(subject))
    assert certificate == _bytes(_certificate(subject))
    result = checker.check_formation(_bytes(subject), certificate)
    assert result["status"] == "CHECKED"
    assert result["residual_obligations"] == list(wire.RESIDUAL_OBLIGATIONS)
    assert set(result["residual_obligations"]) == {
        "SOURCE_INTERPRETATION_NOT_ESTABLISHED", "GROUND_DERIVATION_NOT_ESTABLISHED",
        "SOURCE_TRACE_RELATION_NOT_ESTABLISHED", "SOURCE_LAYER_BOUNDARY_NOT_ESTABLISHED",
        "SELF_STATUS_NOT_ESTABLISHED", "GLOBAL_CYCLE_NOT_ESTABLISHED",
        "COMPLETENESS_NOT_ESTABLISHED", "AGENCY_NOT_CHECKED",
    }
    observed = _observed(checker, subject)
    assert observed["type"] == "FORM"
    assert observed["source_digest"] is None and observed["target_digest"] is None
    assert observed["path_steps"] == []
    assert observed["quote_rank"] == 0 and observed["required_depth"] == 1
    assert observed["dependency_nodes"] == [0] and observed["quote_origins"] == []


def test_typed_formation_apply_step_checks_the_actual_apply_target(formation) -> None:
    wire, _producer, checker = formation
    nodes = _two_steps()
    source = _observed(checker, _subject(wire, nodes, 0))
    target = _observed(checker, _subject(wire, nodes, 1))
    observed = _observed(checker, _subject(wire, nodes, 2))
    assert observed["type"] == "PATH"
    assert observed["source_digest"] == source["denotation_digest"]
    assert observed["target_digest"] == target["denotation_digest"]
    assert observed["path_steps"] == [{"source_digest": source["denotation_digest"], "target_digest": target["denotation_digest"]}]
    assert observed["dependency_nodes"] == [0, 1, 2]
    assert observed["required_depth"] == 3
    wrong = _subject(wire, [
        nodes[0], {"tag": "ATOM", "payload_digest": DIGEST_B},
        {"tag": "APPLY_STEP", "source": 0, "target": 1},
    ])
    _assert_failure(_check(checker, wrong), "INVALID", "FORMATION_RULE_INVALID")


def test_typed_formation_composition_checks_endpoints_and_exact_path_steps(formation) -> None:
    wire, _producer, checker = formation
    subject = _subject(wire, _two_steps())
    observed = _observed(checker, subject)
    first = _observed(checker, _subject(wire, subject["nodes"], 2))
    second = _observed(checker, _subject(wire, subject["nodes"], 4))
    assert observed["path_steps"] == first["path_steps"] + second["path_steps"]
    assert observed["source_digest"] == first["source_digest"]
    assert observed["target_digest"] == second["target_digest"]
    assert observed["dependency_nodes"] == list(range(6))
    subject["nodes"][-1] = {"tag": "COMPOSE", "left": 4, "right": 2}
    _assert_failure(_check(checker, subject), "INVALID", "FORMATION_RULE_INVALID")


def test_typed_formation_identity_normalizes_denotation_without_erasing_formation(formation) -> None:
    wire, _producer, checker = formation
    nodes = _two_steps()[:3] + [
        {"tag": "ID", "at": 0}, {"tag": "COMPOSE", "left": 3, "right": 2},
        {"tag": "ID", "at": 1}, {"tag": "COMPOSE", "left": 4, "right": 5},
    ]
    original = _observed(checker, _subject(wire, nodes, 2))
    normalized = _observed(checker, _subject(wire, nodes, 6))
    for field in ("type", "denotation_digest", "source_digest", "target_digest", "path_steps"):
        assert normalized[field] == original[field]
    assert normalized["formation_digest"] != original["formation_digest"]
    assert normalized["required_depth"] > original["required_depth"]
    assert normalized["dependency_nodes"] == list(range(7))


def test_typed_formation_quote_read_preserves_original_value_and_accumulated_provenance(formation) -> None:
    wire, _producer, checker = formation
    nodes = [
        {"tag": "ATOM", "payload_digest": DIGEST_A}, {"tag": "QUOTE", "value": 0},
        {"tag": "READ", "code": 1}, {"tag": "QUOTE", "value": 1},
        {"tag": "READ", "code": 3}, {"tag": "READ", "code": 4},
        {"tag": "QUOTE", "value": 2},
    ]
    observed = [_observed(checker, _subject(wire, nodes, index)) for index in range(len(nodes))]
    assert [item["type"] for item in observed] == ["FORM", "CODE(FORM)", "FORM", "CODE(CODE(FORM))", "CODE(FORM)", "FORM", "CODE(FORM)"]
    for index in (2, 5):
        assert observed[index]["denotation_digest"] == observed[0]["denotation_digest"]
        assert observed[index]["formation_digest"] != observed[0]["formation_digest"]
    assert [item["quote_rank"] for item in observed] == [0, 1, 1, 2, 2, 2, 2]
    assert observed[2]["quote_origins"] == [1]
    assert observed[5]["quote_origins"] == [1, 3]
    assert observed[5]["dependency_nodes"] == [0, 1, 3, 4, 5]
    assert observed[5]["required_depth"] == 5
    assert observed[6]["quote_origins"] == [1, 6]
    assert observed[6]["dependency_nodes"] == [0, 1, 2, 6]


def test_typed_formation_quote_read_of_path_retains_endpoints_and_steps(formation) -> None:
    wire, _producer, checker = formation
    nodes = _two_steps() + [{"tag": "QUOTE", "value": 5}, {"tag": "READ", "code": 6}]
    original = _observed(checker, _subject(wire, nodes, 5))
    quoted = _observed(checker, _subject(wire, nodes, 6))
    restored = _observed(checker, _subject(wire, nodes, 7))
    assert quoted["type"] == "CODE(PATH)"
    for field in ("type", "denotation_digest", "source_digest", "target_digest", "path_steps"):
        assert restored[field] == original[field]
    assert restored["dependency_nodes"] == list(range(8))
    assert restored["quote_origins"] == [6] and restored["quote_rank"] == 1


def test_typed_formation_denotation_and_formation_have_independent_byte_oracles(formation) -> None:
    wire, _producer, checker = formation
    nodes = _two_steps()[:3] + [{"tag": "QUOTE", "value": 2}]
    atom_digest = _digest(_bytes({"kind": "ATOM", "payload_digest": DIGEST_A}))
    apply_digest = _digest(_bytes({"kind": "APPLY", "argument_digest": atom_digest}))
    path_digest = _digest(_bytes({
        "kind": "PATH", "source_digest": atom_digest, "target_digest": apply_digest,
        "path_steps": [{"source_digest": atom_digest, "target_digest": apply_digest}],
    }))
    for root, expected in enumerate((atom_digest, apply_digest, path_digest)):
        subject = _subject(wire, nodes, root)
        observed = _observed(checker, subject)
        assert observed["denotation_digest"] == expected
        assert observed["formation_digest"] == _digest(_bytes({
            "subject_digest": _digest(_bytes(subject)), "node": root,
        }))
    quoted_subject = _subject(wire, nodes)
    quoted = _observed(checker, quoted_subject)
    assert quoted["denotation_digest"] == _digest(_bytes({
        "kind": "CODE", "subject_digest": _digest(_bytes(quoted_subject)),
        "node": 2, "dependency_nodes": [0, 1, 2],
    }))


@pytest.mark.parametrize("field", ["ground_artifact_digest", "authority_axiom_agency_digest"])
def test_typed_formation_rebound_context_changes_identity_not_agency_evidence(formation, field) -> None:
    wire, producer, checker = formation
    subject = _subject(wire, [
        {"tag": "ATOM", "payload_digest": DIGEST_A}, {"tag": "QUOTE", "value": 0},
    ])
    before = _observed(checker, subject)
    subject["context"][field] = DIGEST_A
    # Fresh syntax can check under different declared coordinates. No authority
    # evidence is gained merely by rebuilding the certificate for those bytes.
    certificate = producer.produce_formation_certificate(_bytes(subject))
    result = checker.check_formation(_bytes(subject), certificate)
    assert result["status"] == "CHECKED"
    after = result["observation"]
    assert after["denotation_digest"] != before["denotation_digest"]
    assert after["formation_digest"] != before["formation_digest"]
    assert result["residual_obligations"] == list(wire.RESIDUAL_OBLIGATIONS)


@pytest.mark.parametrize("node", [
    {"tag": "APPLY", "argument": 1}, {"tag": "ID", "at": 1},
    {"tag": "READ", "code": 2},
])
def test_typed_formation_code_is_not_form_and_path_is_not_code(formation, node) -> None:
    wire, _producer, checker = formation
    subject = _subject(wire, [
        {"tag": "ATOM", "payload_digest": DIGEST_A}, {"tag": "QUOTE", "value": 0},
        {"tag": "ID", "at": 0}, node,
    ])
    _assert_failure(_check(checker, subject), "INVALID", "FORMATION_RULE_INVALID")


@pytest.mark.parametrize("node", [
    {"tag": "READ", "code": 0}, {"tag": "COMPOSE", "left": 0, "right": 0},
    {"tag": "APPLY_STEP", "source": 0, "target": 0},
])
def test_typed_formation_rejects_ill_typed_constructors(formation, node) -> None:
    wire, _producer, checker = formation
    subject = _subject(wire, [{"tag": "ATOM", "payload_digest": DIGEST_A}, node])
    _assert_failure(_check(checker, subject), "INVALID", "FORMATION_RULE_INVALID")


def test_typed_formation_checks_unused_nodes_but_reports_only_root_dependency_closure(formation) -> None:
    wire, _producer, checker = formation
    nodes = [{"tag": "ATOM", "payload_digest": DIGEST_A}, {"tag": "ATOM", "payload_digest": DIGEST_B}]
    assert _observed(checker, _subject(wire, nodes, 1))["dependency_nodes"] == [1]
    nodes.append({"tag": "READ", "code": 0})
    _assert_failure(_check(checker, _subject(wire, nodes, 1)), "INVALID", "FORMATION_RULE_INVALID")


@pytest.mark.parametrize("change", ["payload", "ground_context", "agency_context", "root", "profile", "certificate_root", "certificate_subject"])
def test_typed_formation_certificate_cannot_be_reused_for_changed_subject(formation, change) -> None:
    wire, _producer, checker = formation
    subject = _subject(wire, _two_steps())
    certificate = _certificate(subject)
    if change == "payload":
        subject["nodes"][0]["payload_digest"] = DIGEST_B
    elif change == "ground_context":
        subject["context"]["ground_artifact_digest"] = DIGEST_C
    elif change == "agency_context":
        subject["context"]["authority_axiom_agency_digest"] = DIGEST_B
    elif change == "root":
        subject["root"] = 0
    elif change == "certificate_root":
        certificate["root"] = 0
    elif change == "certificate_subject":
        certificate["subject_digest"] = DIGEST_A
    else:
        certificate["profile_digest"] = DIGEST_A
    _assert_failure(_check(checker, subject, certificate), "INVALID", "FORMATION_CERTIFICATE_BINDING_INVALID")


@pytest.mark.parametrize("change", ["omit", "reverse", "duplicate", "wrong_rule", "wrong_node", "extra_step"])
def test_typed_formation_certificate_steps_are_exact_not_status_assertions(formation, change) -> None:
    wire, _producer, checker = formation
    subject = _subject(wire, _two_steps()); certificate = _certificate(subject)
    if change == "omit":
        certificate["steps"][-1]["premises"] = [2]
    elif change == "reverse":
        certificate["steps"][-1]["premises"] = [4, 2]
    elif change == "duplicate":
        certificate["steps"][-1]["premises"] = [2, 2]
    elif change == "wrong_rule":
        certificate["steps"][-1]["rule"] = "ID"
    elif change == "wrong_node":
        certificate["steps"][-1]["node"] = 4
    else:
        certificate["steps"].append(deepcopy(certificate["steps"][-1]))
    _assert_failure(_check(checker, subject, certificate), "INVALID", "FORMATION_CERTIFICATE_STEP_INVALID")


@pytest.mark.parametrize("location", ["subject", "context", "node", "certificate", "step"])
def test_typed_formation_rejects_extra_status_claim_fields(formation, location) -> None:
    wire, _producer, checker = formation
    subject = _subject(wire, [{"tag": "ATOM", "payload_digest": DIGEST_A}])
    certificate = _certificate(subject)
    target = {"subject": subject, "context": subject["context"], "node": subject["nodes"][0], "certificate": certificate, "step": certificate["steps"][0]}[location]
    target["claimed_status"] = "CHECKED"
    _assert_failure(_check(checker, subject, certificate), "INVALID", "FORMATION_RECORD_INVALID")


@pytest.mark.parametrize("target", ["root", "reference", "certificate_node", "certificate_premise"])
def test_typed_formation_indices_reject_booleans(formation, target) -> None:
    wire, _producer, checker = formation
    subject = _subject(wire, _two_steps()[:2]); certificate = _certificate(subject)
    if target == "root":
        subject["root"] = True
    elif target == "reference":
        subject["nodes"][1]["argument"] = False
    elif target == "certificate_node":
        certificate["steps"][0]["node"] = False
    else:
        certificate["steps"][1]["premises"] = [False]
    _assert_failure(_check(checker, subject, certificate), "INVALID", "FORMATION_RECORD_INVALID")


@pytest.mark.parametrize("nodes", [
    [{"tag": "APPLY", "argument": 0}],
    [{"tag": "APPLY", "argument": 1}, {"tag": "APPLY", "argument": 0}],
    [{"tag": "ATOM", "payload_digest": DIGEST_A}, {"tag": "APPLY", "argument": 2}],
    [{"tag": "ATOM", "payload_digest": DIGEST_A}, {"tag": "==", "left": 0, "right": 0}],
    [{"tag": "ATOM", "payload_digest": "CHECKED"}],
])
def test_typed_formation_rejects_forward_cycles_alias_rules_and_literal_verdicts(formation, nodes) -> None:
    wire, _producer, checker = formation
    _assert_failure(_check(checker, _subject(wire, nodes)), "INVALID", "FORMATION_RECORD_INVALID")


@pytest.mark.parametrize("target", ["subject", "certificate"])
@pytest.mark.parametrize("malformation", ["duplicate", "whitespace", "bom", "bad_utf8"])
def test_typed_formation_admission_requires_exact_canonical_bytes(formation, target, malformation) -> None:
    wire, _producer, checker = formation
    subject = _subject(wire, [{"tag": "ATOM", "payload_digest": DIGEST_A}])
    subject_bytes = _bytes(subject); certificate_bytes = _bytes(_certificate(subject))
    value = subject_bytes if target == "subject" else certificate_bytes
    if malformation == "duplicate":
        value = value[:-1] + b',"root":0}'
    elif malformation == "whitespace":
        value += b"\n"
    elif malformation == "bom":
        value = b"\xef\xbb\xbf" + value
    else:
        value = b"\xff"
    result = checker.check_formation(value if target == "subject" else subject_bytes, value if target == "certificate" else certificate_bytes)
    _assert_failure(result, "INVALID", "FORMATION_RECORD_INVALID")


@pytest.mark.parametrize("unsupported", ["profile", "schema"])
def test_typed_formation_unsupported_profile_is_unknown_not_checked(formation, unsupported) -> None:
    wire, _producer, checker = formation
    subject = _subject(wire, [{"tag": "ATOM", "payload_digest": DIGEST_A}])
    if unsupported == "profile":
        subject["profile_digest"] = DIGEST_A
    else:
        subject["schema_version"] = "VSTD-TYPED-FORMATION-9"
    result = _check(checker, subject)
    _assert_failure(result, "UNKNOWN", "FORMATION_PROFILE_UNSUPPORTED")
    assert result["residual_obligations"] == list(wire.RESIDUAL_OBLIGATIONS)


@pytest.mark.parametrize("which", ["subject", "certificate"])
def test_typed_formation_byte_budget_exhaustion_is_unknown(formation, which) -> None:
    wire, _producer, checker = formation
    subject = _subject(wire, [{"tag": "ATOM", "payload_digest": DIGEST_A}])
    subject_bytes = _bytes(subject); certificate_bytes = _bytes(_certificate(subject))
    oversized = b" " * 262_145
    result = checker.check_formation(oversized if which == "subject" else subject_bytes, oversized if which == "certificate" else certificate_bytes)
    _assert_failure(result, "UNKNOWN", "FORMATION_LIMIT_EXCEEDED")


def test_typed_formation_node_budget_exhaustion_is_unknown(formation) -> None:
    wire, _producer, checker = formation
    subject = _subject(wire, [{"tag": "ATOM", "payload_digest": DIGEST_A} for _ in range(1025)])
    _assert_failure(_check(checker, subject), "UNKNOWN", "FORMATION_LIMIT_EXCEEDED")


def test_typed_formation_exact_node_bound_accepts_independent_atoms(formation) -> None:
    wire, _producer, checker = formation
    subject = _subject(wire, [{"tag": "ATOM", "payload_digest": DIGEST_A} for _ in range(1024)])
    observed = _observed(checker, subject)
    assert observed["dependency_nodes"] == [1023]
    assert observed["required_depth"] == 1


@pytest.mark.parametrize("wrapper", [bytearray, memoryview, "bytes_subclass"])
def test_typed_formation_only_admits_exact_immutable_bytes(formation, wrapper) -> None:
    wire, _producer, checker = formation
    subject = _subject(wire, [{"tag": "ATOM", "payload_digest": DIGEST_A}])

    class UntrustedBytes(bytes):
        def __len__(self):
            raise AssertionError("input subclass hook must not be executed")

    subject_bytes = (UntrustedBytes if wrapper == "bytes_subclass" else wrapper)(_bytes(subject))
    _assert_failure(
        checker.check_formation(subject_bytes, _bytes(_certificate(subject))),
        "INVALID", "FORMATION_RECORD_INVALID",
    )


@pytest.mark.parametrize("syntax", [
    pytest.param(b"[" * 17 + b"0" + b"]" * 17, id="nesting_depth"),
    pytest.param(b"[" + b"[]," * 8192 + b"[]]", id="container_count"),
])
def test_typed_formation_syntax_budget_refuses_before_unbounded_decode(formation, syntax) -> None:
    wire, _producer, checker = formation
    subject = _subject(wire, [{"tag": "ATOM", "payload_digest": DIGEST_A}])
    _assert_failure(
        checker.check_formation(syntax, _bytes(_certificate(subject))),
        "UNKNOWN", "FORMATION_LIMIT_EXCEEDED",
    )


def test_typed_formation_dependency_depth_bound_and_cheap_negative_precedence(formation) -> None:
    wire, _producer, checker = formation
    nodes = [{"tag": "ATOM", "payload_digest": DIGEST_A}] + [{"tag": "APPLY", "argument": index - 1} for index in range(1, 64)]
    assert _observed(checker, _subject(wire, nodes))["required_depth"] == 64
    nodes.append({"tag": "APPLY", "argument": 63})
    subject = _subject(wire, nodes)
    _assert_failure(_check(checker, subject), "UNKNOWN", "FORMATION_LIMIT_EXCEEDED")
    certificate = _certificate(subject); certificate["steps"][0]["rule"] = "READ"
    _assert_failure(_check(checker, subject, certificate), "INVALID", "FORMATION_CERTIFICATE_STEP_INVALID")


def test_typed_formation_expanded_path_budget_with_explicit_test_only_limit(formation, monkeypatch) -> None:
    # A smaller checker budget exercises refusal without inventing an impossible
    # exponentially self-composable nonempty unary-application path.
    wire, _producer, checker = formation
    subject = _subject(wire, _two_steps())
    assert len(_observed(checker, subject)["path_steps"]) == 2
    monkeypatch.setattr(checker, "MAX_PATH_STEPS", 1)
    _assert_failure(_check(checker, subject), "UNKNOWN", "FORMATION_LIMIT_EXCEEDED")


def test_typed_formation_checker_imports_no_producer_and_survives_disabled_producer(formation, monkeypatch) -> None:
    wire, producer, checker = formation
    source = Path(checker.__file__).read_text(encoding="utf-8")
    syntax = ast.parse(source)
    for node in ast.walk(syntax):
        if isinstance(node, ast.Import):
            assert all("formation_producer" not in alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert "formation_producer" not in (node.module or "")
            assert all("formation_producer" not in alias.name for alias in node.names)
            if (node.module or "").endswith("formation_wire"):
                assert {alias.name for alias in node.names} <= {
                    "FormationError", "FormationLimitError", "UnsupportedFormation",
                    "MAX_DEPTH", "MAX_PATH_STEPS", "RESIDUAL_OBLIGATIONS",
                    "canonical_bytes", "decode_certificate", "decode_subject",
                    "digest_bytes", "profile_digest", "references",
                }, "shared wire imports must remain codecs, bounds and literal profile metadata, not inference"
    subject = _subject(wire, _two_steps())
    certificate = producer.produce_formation_certificate(_bytes(subject))
    assert certificate == _bytes(_certificate(subject))

    def forbidden(*args, **kwargs):
        raise AssertionError("independent checker invoked producer inference")

    for name, value in vars(producer).copy().items():
        if callable(value) and getattr(value, "__module__", None) == producer.__name__:
            monkeypatch.setattr(producer, name, forbidden)
    assert checker.check_formation(_bytes(subject), certificate)["status"] == "CHECKED"
    forged = _certificate(subject); forged["steps"][-1]["premises"] = [4, 2]
    _assert_failure(_check(checker, subject, forged), "INVALID", "FORMATION_CERTIFICATE_STEP_INVALID")
