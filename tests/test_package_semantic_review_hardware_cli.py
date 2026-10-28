# Terminology: command-line interface (CLI).
from __future__ import annotations

import ast
from copy import deepcopy
import re
from dataclasses import replace
from hashlib import sha256
from pathlib import Path

import pytest

from verifier.runtime import package_semantic_review_hardware_cli as review
from verifier.runtime.namespace_contracts import namespace_registry, requirements_for
from verifier.runtime.package_semantic_ownership import SEMANTIC_OWNERSHIP_SPECS

ROOT = Path(__file__).resolve().parents[1]


# Audited source verdicts.  Every DOES_NOT_APPLY below is a source-bound closure witness
# (see package_semantic_review_hardware_cli): the owner's static execution closure must
# be CLOSED and reach none of the effects the refuted role forbids. The discovery
# command retains every added role: it delegates through caller-selected
# adapters to PATH-resolved vendor executables whose downstream effect envelope is not
# established closed. The public profile reader likewise dispatches through a
# caller-supplied Python registry without a runtime type seal. These retain obligations
# without asserting that a physical, market, financial, or other external effect occurred.
# The receipt assessor's grammar-bearing PROTOCOL remains unresolved.
EXPECTED = {
    "vstd-hardware-cli-protocol": (
        "PROTOCOL",
        (
            "src/verifier/runtime/hardware_cli.py",
            "src/verifier/runtime/hardware_cli_support.py",
        ),
        set(review.REVIEW_KINDS),
    ),
    "vstd-accelerator-profile-reader": (
        "VERIFIER",
        ("src/verifier/runtime/hardware_registry_cli.py",),
        set(review.REVIEW_KINDS),
    ),
    "vstd-accelerator-discovery-command": (
        "SENSOR",
        ("src/verifier/runtime/hardware_discovery_cli.py",),
        set(review.REVIEW_KINDS),
    ),
    "vstd-virtual-firmware-probe-harness": (
        "HARNESS",
        ("src/verifier/runtime/hardware_probe_cli.py",),
        {"ACTUATOR", "MEASUREMENT", "POLICY", "PROTOCOL", "TRANSACTION"},
    ),
    "vstd-hardware-receipt-assessor": (
        "VERIFIER",
        ("src/verifier/runtime/hardware_receipt_cli.py",),
        {"MEASUREMENT", "POLICY"},
    ),
}
EXPECTED_UNRESOLVED = {
    "vstd-hardware-receipt-assessor": {"PROTOCOL"},
}
EXPECTED_DECLARATIONS = 129

FACADE_PATH = ("src/verifier/runtime/hardware_cli.py",)
EXPECTED_ROLE_PATHS = {
    object_id: {kind: paths for kind in applicable}
    for object_id, (_, paths, applicable) in EXPECTED.items()
}
EXPECTED_REFUTED = {
    object_id: set(review.REVIEW_KINDS)
    - applicable
    - EXPECTED_UNRESOLVED.get(object_id, set())
    for object_id, (_, _, applicable) in EXPECTED.items()
}
for _kind in (
    "ACTUATOR",
    "ASSET",
    "CONTROLLER",
    "FINBOT",
    "LEDGER",
    "MARKET",
    "MEASUREMENT",
    "ROBOT",
    "SENSOR",
    "TRANSACTION",
):
    EXPECTED_ROLE_PATHS["vstd-hardware-cli-protocol"][_kind] = FACADE_PATH


def _digest(raw: bytes) -> str:
    return "sha256:" + sha256(raw).hexdigest()


def _all_obligations() -> dict[str, dict]:
    result = {}
    registry = namespace_registry()
    for kind in review.REVIEW_KINDS:
        for obligation in requirements_for(registry, (kind,)):
            if obligation["kind"] != kind:
                continue
            result[obligation["id"]] = {
                "reason": "",
                "evidence": [],
                "declaration": {
                    field: "" for field in obligation["declaration_fields"]
                },
            }
    return result


def _real_closure_files() -> dict[str, bytes]:
    """Exact bytes of every source and data file the five owners' closures read."""
    files: dict[str, bytes] = {}
    for item in review._REVIEWS.values():
        closure = review._owner_closure(ROOT, item.owned_paths)
        for rel, _ in closure.files:
            files[rel] = (ROOT / rel).read_bytes()
    return files


def _workspace(tmp_path: Path) -> tuple[Path, dict[str, dict], dict[str, str]]:
    rows = {}
    files = {}
    for rel, raw in _real_closure_files().items():
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    for object_id, item in review.review_document().items():
        for path in item["owned_paths"]:
            files[path] = _digest((tmp_path / path).read_bytes())
        rows[object_id] = {
            "object_id": object_id,
            "kind": item["primary_kind"],
            "specializations": [],
            "payload": {},
            "operands": {},
            "surfaces": ["file:" + path for path in item["owned_paths"]],
            "reason": "Synthetic exact owner for hardware CLI review tests.",
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
    return tmp_path, rows, files


def test_document_closes_exact_five_by_six_by_twelve_denominator() -> None:
    catalog = review.review_document()
    registry = namespace_registry()

    assert tuple(catalog) == review.HARDWARE_CLI_OBJECT_IDS
    assert set(catalog) == set(EXPECTED)
    assert len(catalog) == 5
    assert sum(len(item["owned_paths"]) for item in catalog.values()) == 6
    assert sum(len(item["classification"]) for item in catalog.values()) == 60
    assert sum(len(item["declarations"]) for item in catalog.values()) == (
        EXPECTED_DECLARATIONS
    )

    owned_paths = []
    for object_id, item in catalog.items():
        primary, paths, applicable = EXPECTED[object_id]
        assert item["primary_kind"] == primary
        assert item["owned_paths"] == list(paths)
        owned_paths.extend(paths)
        assert set(item["classification"]) == set(review.REVIEW_KINDS)
        assert {
            kind
            for kind, decision in item["classification"].items()
            if decision["status"] == "APPLIES"
        } == applicable
        assert {
            kind
            for kind, decision in item["classification"].items()
            if decision["status"] == "UNRESOLVED"
        } == EXPECTED_UNRESOLVED.get(object_id, set())
        for kind, decision in item["classification"].items():
            assert decision["status"] in {
                "APPLIES",
                "DOES_NOT_APPLY",
                "UNRESOLVED",
            }
            assert decision["reason"].strip()
            assert tuple(decision["evidence_paths"]) == (
                EXPECTED_ROLE_PATHS[object_id][kind]
                if kind in applicable
                else paths
                if kind in EXPECTED_REFUTED[object_id]
                else ()
            )
        expected_declarations = {
            obligation["id"]: set(obligation["declaration_fields"])
            for kind in applicable
            for obligation in requirements_for(registry, (kind,))
            if obligation["kind"] == kind
        }
        assert set(item["declarations"]) == set(expected_declarations)
        for obligation_id, declaration in item["declarations"].items():
            assert set(declaration) == expected_declarations[obligation_id]
            assert all(value.strip() for value in declaration.values())
        for excluded in (
            "physical attestation",
            "sandboxing",
            "financial effect",
            "external authority",
            "release",
            "Tier-1-plus",
        ):
            assert excluded in item["claim_boundary"]
    assert len(owned_paths) == len(set(owned_paths))

    catalog["vstd-hardware-cli-protocol"]["owned_paths"].clear()
    assert review.review_document()["vstd-hardware-cli-protocol"]["owned_paths"]


def test_document_matches_semantic_ownership_and_keeps_operands_empty() -> None:
    catalog = review.review_document()
    ownership = {
        spec.object_id: spec
        for spec in SEMANTIC_OWNERSHIP_SPECS
        if spec.object_id in catalog
    }

    assert set(ownership) == set(catalog)
    for object_id, item in catalog.items():
        spec = ownership[object_id]
        assert item["primary_kind"] == spec.primary_kind
        assert item["owned_paths"] == list(spec.owned_paths)
        assert spec.operands == ()
        assert {
            kind
            for kind, decision in item["classification"].items()
            if decision["status"] == "APPLIES"
        } == {
            kind
            for kind in (spec.primary_kind, *spec.specializations)
            if kind in review.REVIEW_KINDS
        }


def test_review_paths_are_current_ordinary_repository_files() -> None:
    root = Path(__file__).resolve().parents[1]
    for _, paths, _ in EXPECTED.values():
        for path in paths:
            candidate = root / path
            assert candidate.is_file(), path
            assert not candidate.is_symlink(), path
            assert candidate.resolve(strict=True).is_relative_to(root.resolve())


def test_role_evidence_and_non_promotions_preserve_consequence_boundaries() -> None:
    catalog = review.review_document()
    facade = catalog["vstd-hardware-cli-protocol"]

    assert tuple(facade["classification"]["ACTUATOR"]["evidence_paths"]) == FACADE_PATH
    for kind in ("MEASUREMENT", "SENSOR", "TRANSACTION"):
        assert facade["classification"][kind]["status"] == "APPLIES"
        assert tuple(facade["classification"][kind]["evidence_paths"]) == FACADE_PATH
        assert "Dispatch reaches" in facade["classification"][kind]["reason"]
    assert facade["classification"]["LEDGER"]["status"] == "APPLIES"
    assert "Dispatch reaches discovery result files" in facade["classification"][
        "LEDGER"
    ]["reason"]
    assert "observe_execution" in catalog["vstd-virtual-firmware-probe-harness"][
        "classification"
    ]["MEASUREMENT"]["reason"]
    for kind in ("POLICY", "PROTOCOL"):
        assert tuple(facade["classification"][kind]["evidence_paths"]) == EXPECTED[
            "vstd-hardware-cli-protocol"
        ][1]

    for object_id, kinds in EXPECTED_REFUTED.items():
        for kind in kinds:
            assert catalog[object_id]["classification"][kind]["status"] == (
                "DOES_NOT_APPLY"
            )

    for object_id, item in catalog.items():
        for kind in ("ASSET", "MARKET", "ROBOT", "FINBOT"):
            expected = (
                "APPLIES"
                if object_id in {
                    "vstd-hardware-cli-protocol",
                    "vstd-accelerator-profile-reader",
                    "vstd-accelerator-discovery-command",
                }
                else "DOES_NOT_APPLY"
            )
            assert item["classification"][kind]["status"] == expected

    # Every refutation names the owned source it audited and is owner-specific.
    refutation_reasons = []
    for object_id, item in catalog.items():
        names = [Path(path).name for path in item["owned_paths"]]
        for kind in EXPECTED_REFUTED[object_id]:
            reason = item["classification"][kind]["reason"]
            assert " does not apply as " + kind + ". " in reason
            assert any(name in reason for name in names), (object_id, kind)
            refutation_reasons.append(reason)
    assert len(refutation_reasons) == len(set(refutation_reasons))
    assert "open-loop" in catalog["vstd-virtual-firmware-probe-harness"][
        "classification"
    ]["CONTROLLER"]["reason"]
    profile_policy = catalog["vstd-accelerator-profile-reader"]["classification"][
        "POLICY"
    ]
    assert profile_policy["status"] == "APPLIES"
    assert profile_policy["evidence_paths"] == [
        "src/verifier/runtime/hardware_registry_cli.py"
    ]
    assert "Operation selection" in profile_policy["reason"]
    assert "physical attestation" in catalog["vstd-hardware-receipt-assessor"][
        "classification"
    ]["MEASUREMENT"]["reason"]


def test_apply_is_pure_complete_deterministic_and_idempotent(tmp_path: Path) -> None:
    root, rows, files = _workspace(tmp_path)
    before = deepcopy(rows)

    first = review.apply_package_semantic_review_hardware_cli(root, rows, files)
    second = review.apply_package_semantic_review_hardware_cli(root, first, files)

    assert rows == before
    assert first == second
    assert sum(len(row["classification"]) for row in first.values()) == 60
    assert sum(len(row["obligations"]) for row in first.values()) == (
        EXPECTED_DECLARATIONS
    )
    for object_id, row in first.items():
        applicable = EXPECTED[object_id][2]
        assert row["operands"] == {}
        assert {
            kind
            for kind, decision in row["classification"].items()
            if decision["status"] == "APPLIES"
        } == applicable
        assert applicable - {row["kind"]} <= set(row["specializations"])
        assert all(name.split("-", 1)[0] in applicable for name in row["obligations"])
        for kind, decision in row["classification"].items():
            expected_paths = (
                EXPECTED_ROLE_PATHS[object_id][kind]
                if kind in applicable
                else EXPECTED[object_id][1]
                if kind in EXPECTED_REFUTED[object_id]
                else ()
            )
            assert tuple(entry["path"] for entry in decision["evidence"]) == (
                expected_paths
            )
        for obligation_id, binding in row["obligations"].items():
            kind = obligation_id.split("-", 1)[0]
            assert tuple(entry["path"] for entry in binding["evidence"]) == (
                EXPECTED_ROLE_PATHS[object_id][kind]
            )
            assert binding["reason"].strip()
            assert all(value.strip() for value in binding["declaration"].values())


def test_apply_preserves_only_exact_current_bindings_byte_for_byte(
    tmp_path: Path,
) -> None:
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_hardware_cli(root, rows, files)
    expected = deepcopy(selected)
    assert (
        review.apply_package_semantic_review_hardware_cli(root, selected, files)
        == expected
    )

    object_id = "vstd-hardware-cli-protocol"
    selected[object_id]["classification"]["ACTUATOR"]["reason"] = (
        "Prior complete exact current-source dispatch review."
    )
    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT"):
        review.apply_package_semantic_review_hardware_cli(root, selected, files)


REFUTED_PAIRS = [
    (object_id, kind)
    for object_id, kinds in EXPECTED_REFUTED.items()
    for kind in sorted(kinds)
]


@pytest.mark.parametrize(("object_id", "kind"), REFUTED_PAIRS)
def test_dropped_refutation_becomes_unresolved_never_complement_refuted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    object_id: str,
    kind: str,
) -> None:
    # Removing one literal refutation must leave that kind UNRESOLVED: the
    # remaining refutations never imply it by complement with the applications.
    original = review._REVIEWS[object_id]
    monkeypatch.setitem(
        review._REVIEWS,
        object_id,
        replace(
            original,
            refutations={
                name: text
                for name, text in original.refutations.items()
                if name != kind
            },
        ),
    )
    document = review.review_document()[object_id]["classification"][kind]
    assert document == {
        "status": "UNRESOLVED",
        "reason": review._unresolved_reason(kind),
        "evidence_paths": [],
    }

    root, rows, files = _workspace(tmp_path)
    result = review.apply_package_semantic_review_hardware_cli(root, rows, files)
    assert result[object_id]["classification"][kind] == {
        "status": "UNRESOLVED",
        "reason": review._unresolved_reason(kind),
        "evidence": [],
    }


def test_unknown_object_is_never_reviewed_or_refuted(tmp_path: Path) -> None:
    root, rows, files = _workspace(tmp_path)
    rows["unknown-future-owner"] = {
        "object_id": "unknown-future-owner",
        "kind": "OBJECT",
        "specializations": [],
        "surfaces": [],
        "classification": {
            "LEDGER": {
                "status": "UNRESOLVED",
                "reason": "No audited basis exists.",
                "evidence": [],
            }
        },
        "obligations": {},
    }
    result = review.apply_package_semantic_review_hardware_cli(root, rows, files)
    assert result["unknown-future-owner"] == rows["unknown-future-owner"]
    assert set(result) == set(review.HARDWARE_CLI_OBJECT_IDS) | {
        "unknown-future-owner"
    }


@pytest.mark.parametrize("failure", ["stale", "missing", "unowned", "extra_owned"])
def test_apply_rejects_source_or_ownership_drift_atomically(
    tmp_path: Path, failure: str
) -> None:
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-hardware-cli-protocol"
    path = EXPECTED[object_id][1][-1]
    if failure == "stale":
        files[path] = "sha256:" + "0" * 64
    elif failure == "missing":
        (root / path).unlink()
    elif failure == "unowned":
        rows[object_id]["surfaces"].remove("file:" + path)
    else:
        rows[object_id]["surfaces"].append("file:unreviewed/extra.py")
    before = deepcopy(rows)

    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_"):
        review.apply_package_semantic_review_hardware_cli(root, rows, files)
    assert rows == before


@pytest.mark.parametrize(
    "failure",
    [
        "status",
        "reason_substitution",
        "refutation_evidence_substitution",
        "obligation_reason_substitution",
        "stale_decision",
        "partial_declaration",
        "refuted_declaration",
        "malformed_unresolved",
        "label_conflict",
        "unknown_obligation",
        "stale_applied_now_refuted",
    ],
)
def test_apply_rejects_conflicting_or_partial_reviews_atomically(
    tmp_path: Path, failure: str
) -> None:
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_hardware_cli(root, rows, files)
    row = selected["vstd-virtual-firmware-probe-harness"]
    if failure == "status":
        row["classification"]["TRANSACTION"]["status"] = "DOES_NOT_APPLY"
    elif failure == "reason_substitution":
        row["classification"]["ASSET"]["reason"] = selected[
            "vstd-hardware-receipt-assessor"
        ]["classification"]["ASSET"]["reason"]
    elif failure == "refutation_evidence_substitution":
        row["classification"]["ASSET"]["evidence"] = deepcopy(
            selected["vstd-hardware-receipt-assessor"]["classification"]["ASSET"][
                "evidence"
            ]
        )
    elif failure == "obligation_reason_substitution":
        row["obligations"]["ACTUATOR-0.1-command-to-effect"]["reason"] = (
            "Substituted noncanonical obligation reason."
        )
    elif failure == "stale_decision":
        row["classification"]["TRANSACTION"]["evidence"][0]["sha256"] = (
            "sha256:" + "f" * 64
        )
    elif failure == "partial_declaration":
        declaration = row["obligations"]["ACTUATOR-0.1-command-to-effect"][
            "declaration"
        ]
        declaration[next(iter(declaration))] = ""
    elif failure == "stale_applied_now_refuted":
        # A row written before CONTROLLER was refuted cannot keep its APPLIES basis.
        row["classification"]["CONTROLLER"] = {
            "status": "APPLIES",
            "reason": "Stale application from a superseded catalog.",
            "evidence": deepcopy(row["classification"]["TRANSACTION"]["evidence"]),
        }
    elif failure == "refuted_declaration":
        # Use the real contract id; a misspelled id would fail as an unknown
        # obligation and never reach the refuted-declaration branch under test.
        row["obligations"]["ASSET-0.1-identity-and-quantity"] = {
            "reason": "Contradictory ASSET declaration.",
            "evidence": deepcopy(row["classification"]["ASSET"]["evidence"]),
            "declaration": {
                field: "Contradictory value for " + field + "."
                for field in _all_obligations()["ASSET-0.1-identity-and-quantity"][
                    "declaration"
                ]
            },
        }
    elif failure == "malformed_unresolved":
        row["classification"]["ASSET"] = {
            "status": "UNRESOLVED",
            "reason": "",
            "evidence": [],
        }
    elif failure == "label_conflict":
        row["specializations"].append("ASSET")
    else:
        row["obligations"]["CONTROLLER-0.99-invented"] = {
            "reason": "Invented.",
            "evidence": [],
            "declaration": {},
        }
    before = deepcopy(selected)

    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_"):
        review.apply_package_semantic_review_hardware_cli(root, selected, files)
    assert selected == before


@pytest.mark.parametrize("stale", ["applies", "refutes", "label"])
def test_stale_basis_for_unresolved_kind_fails_closed_not_erased(
    tmp_path: Path, stale: str
) -> None:
    # The receipt assessor's PROTOCOL role is UNRESOLVED. A complete row decision or label
    # written under an older catalog must be rejected, never silently rewritten.
    object_id = "vstd-hardware-receipt-assessor"
    kind = "PROTOCOL"
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_hardware_cli(root, rows, files)
    row = selected[object_id]
    evidence = [
        {"path": path, "sha256": files[path]} for path in EXPECTED[object_id][1]
    ]
    if stale == "label":
        row["specializations"].append(kind)
        code = "PACKAGE_SEMANTIC_REVIEW_LABEL_CONFLICT:" + object_id + ":" + kind
    else:
        status = "APPLIES" if stale == "applies" else "DOES_NOT_APPLY"
        row["classification"][kind] = {
            "status": status,
            "reason": "Stale complete decision from a superseded catalog.",
            "evidence": deepcopy(evidence),
        }
        code = "PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT:" + object_id + ":" + kind
    before = deepcopy(selected)

    with pytest.raises(ValueError, match=code):
        review.apply_package_semantic_review_hardware_cli(root, selected, files)
    assert selected == before


def test_apply_rejects_missing_object_and_invalid_digest_census(
    tmp_path: Path,
) -> None:
    root, rows, files = _workspace(tmp_path)
    missing = deepcopy(rows)
    missing.pop("vstd-hardware-receipt-assessor")
    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_OBJECT_MISSING"):
        review.apply_package_semantic_review_hardware_cli(root, missing, files)

    invalid_files = dict(files)
    invalid_files[next(iter(invalid_files))] = "not-a-digest"
    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_FILES_INVALID"):
        review.apply_package_semantic_review_hardware_cli(root, rows, invalid_files)


def test_apply_rechecks_complete_source_denominator_before_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, rows, files = _workspace(tmp_path)
    target = EXPECTED["vstd-hardware-receipt-assessor"][1][0]
    original = review._read_digest
    calls = 0

    def drifting_digest(selected_root: Path, path: str) -> str:
        nonlocal calls
        value = original(selected_root, path)
        if path == target:
            calls += 1
            if calls == 2:
                return "sha256:" + "a" * 64
        return value

    monkeypatch.setattr(review, "_read_digest", drifting_digest)
    before = deepcopy(rows)
    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_SOURCE_CHANGED"):
        review.apply_package_semantic_review_hardware_cli(root, rows, files)
    assert rows == before


# Failure-class regressions from the second-pass source audit.  Each invariant is
# checked on the real catalog and on a mutated copy, so a passing result cannot be
# produced by an invariant that never fires.
HANDLER_PATHS = (
    "src/verifier/runtime/hardware_discovery_cli.py",
    "src/verifier/runtime/hardware_probe_cli.py",
    "src/verifier/runtime/hardware_receipt_cli.py",
    "src/verifier/runtime/hardware_registry_cli.py",
)
DEFERRAL_PHRASES = (
    "outside this owned file",
    "lies outside",
    "belong to hardware_",
    "owned by hardware_",
    "would need its own",
)


def _sources() -> dict[str, str]:
    return {
        path: (ROOT / path).read_text(encoding="utf-8")
        for _, paths, _ in EXPECTED.values()
        for path in paths
    }


def _owners(catalog: dict) -> dict[str, str]:
    return {
        path: object_id
        for object_id, item in catalog.items()
        for path in item["owned_paths"]
    }


def _handler_imports(source: str) -> set[str]:
    """Repository paths of the hardware handler modules a source file imports."""
    paths: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.ImportFrom) and node.module:
            if node.module.startswith("verifier.runtime.hardware_"):
                paths.add("src/verifier/runtime/" + node.module.rsplit(".", 1)[-1] + ".py")
    return paths & set(HANDLER_PATHS)


def _dispatch_violations(catalog: dict, sources: dict[str, str]) -> list[tuple[str, str, str]]:
    """Roles a dispatching owner refutes although a handler it imports applies them."""
    owners = _owners(catalog)
    violations = []
    for object_id, item in catalog.items():
        for path in item["owned_paths"]:
            for handler in sorted(_handler_imports(sources[path])):
                handler_owner = owners[handler]
                for kind, decision in catalog[handler_owner]["classification"].items():
                    if (
                        decision["status"] == "APPLIES"
                        and item["classification"][kind]["status"] == "DOES_NOT_APPLY"
                    ):
                        violations.append((object_id, kind, handler))
    return violations


GRAMMAR_CALLS = frozenset(
    {"ArgumentParser", "add_parser", "add_subparsers", "add_argument"}
)


def _grammar_owners(sources: dict[str, str]) -> set[str]:
    """Owned files that construct argparse grammar, by call structure rather than names."""
    return {
        path
        for path, source in sources.items()
        if any(
            isinstance(node, ast.Call)
            and (
                (isinstance(node.func, ast.Name) and node.func.id in GRAMMAR_CALLS)
                or (isinstance(node.func, ast.Attribute) and node.func.attr in GRAMMAR_CALLS)
            )
            for node in ast.walk(ast.parse(source))
        )
    }


def _grammar_violations(catalog: dict, sources: dict[str, str]) -> list[str]:
    owners = _owners(catalog)
    return sorted(
        owners[path]
        for path in _grammar_owners(sources)
        if catalog[owners[path]]["classification"]["PROTOCOL"]["status"]
        == "DOES_NOT_APPLY"
    )


def _deferral_violations(catalog: dict) -> list[tuple[str, str]]:
    return [
        (object_id, kind)
        for object_id, item in catalog.items()
        for kind, decision in item["classification"].items()
        if decision["status"] == "DOES_NOT_APPLY"
        and any(phrase in decision["reason"] for phrase in DEFERRAL_PHRASES)
    ]


def test_dispatching_facade_never_refutes_a_role_its_handler_applies() -> None:
    catalog = review.review_document()
    sources = _sources()
    assert _dispatch_violations(catalog, sources) == []

    mutated = deepcopy(catalog)
    mutated["vstd-hardware-cli-protocol"]["classification"]["TRANSACTION"][
        "status"
    ] = "DOES_NOT_APPLY"
    assert (
        "vstd-hardware-cli-protocol",
        "TRANSACTION",
        "src/verifier/runtime/hardware_probe_cli.py",
    ) in _dispatch_violations(mutated, sources)


def test_grammar_bearing_owner_never_refutes_protocol_parser_leg() -> None:
    catalog = review.review_document()
    sources = _sources()
    assert _grammar_owners(sources) == {
        "src/verifier/runtime/hardware_cli.py",
        "src/verifier/runtime/hardware_cli_support.py",
        "src/verifier/runtime/hardware_discovery_cli.py",
        "src/verifier/runtime/hardware_probe_cli.py",
        "src/verifier/runtime/hardware_receipt_cli.py",
        "src/verifier/runtime/hardware_registry_cli.py",
    }
    assert _grammar_violations(catalog, sources) == []

    mutated = deepcopy(catalog)
    mutated["vstd-accelerator-profile-reader"]["classification"]["PROTOCOL"][
        "status"
    ] = "DOES_NOT_APPLY"
    assert _grammar_violations(mutated, sources) == [
        "vstd-accelerator-profile-reader"
    ]


def test_refutations_never_defer_a_role_to_another_owner() -> None:
    catalog = review.review_document()
    assert _deferral_violations(catalog) == []

    mutated = deepcopy(catalog)
    mutated["vstd-hardware-receipt-assessor"]["classification"]["ROBOT"][
        "reason"
    ] += " Any actuation lies outside this owned file."
    assert _deferral_violations(mutated) == [
        ("vstd-hardware-receipt-assessor", "ROBOT")
    ]


# Adversarial closure regressions.  Each fixture is a self-contained owner source written
# into a scratch root, so the scan's verdict is exercised on exactly the text below and
# never on the real repository, whose closure must stay untouched by these probes.
FIXTURE_REL = "src/verifier/runtime/fixture_owner.py"
CLEAN_FIXTURE = "import math\n\ndef run(x):\n    return math.sqrt(x)\n"


def _fixture_closure(root: Path, source: str) -> review._Closure:
    target = root / FIXTURE_REL
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(source, encoding="utf-8")
    return review._owner_closure(root, (FIXTURE_REL,))


# (source, effect the scan must reach, role whose DOES_NOT_APPLY that effect forbids)
EFFECT_ESCAPES = [
    pytest.param(
        "import subprocess\n\ndef run():\n    subprocess.run(['x'])\n",
        "PROCESS",
        "ROBOT",
        id="process-direct",
    ),
    pytest.param(
        "import subprocess as sp\n\ndef run():\n    sp.run(['x'])\n",
        "PROCESS",
        "ROBOT",
        id="process-module-alias",
    ),
    pytest.param(
        "from subprocess import run as go\n\ndef run():\n    go(['x'])\n",
        "PROCESS",
        "ROBOT",
        id="process-from-alias",
    ),
    pytest.param(
        "import os\n\ndef run():\n    os.system('x')\n",
        "PROCESS",
        "ROBOT",
        id="process-os-system",
    ),
    pytest.param(
        "import subprocess\n\ndef run():\n    return subprocess.run\n",
        "PROCESS",
        "ROBOT",
        id="process-reference-escape",
    ),
    pytest.param(
        "import subprocess\n\ndef apply(fn):\n    fn(['x'])\n\ndef run():\n"
        "    apply(subprocess.run)\n",
        "PROCESS",
        "ROBOT",
        id="process-callback-escape",
    ),
    pytest.param(
        "import subprocess\n\ndef run():\n    call = subprocess.run\n    call(['x'])\n",
        "PROCESS",
        "ROBOT",
        id="process-local-binding",
    ),
    pytest.param(
        "import subprocess\n\nTABLE = {'go': subprocess.run}\n\ndef run():\n"
        "    return TABLE['go'](['x'])\n",
        "PROCESS",
        "ROBOT",
        id="process-container-escape",
    ),
    pytest.param(
        "import subprocess\n\ndef run():\n    return (lambda: subprocess.run(['x']))()\n",
        "PROCESS",
        "ROBOT",
        id="process-lambda-escape",
    ),
    pytest.param(
        "import subprocess\n\ndef run():\n    module = subprocess\n    module.run(['x'])\n",
        "PROCESS",
        "ROBOT",
        id="process-module-value-escape",
    ),
    pytest.param(
        "import subprocess\n\ndef run():\n    return getattr(subprocess, 'run')(['x'])\n",
        "PROCESS",
        "ROBOT",
        id="process-getattr-literal",
    ),
    pytest.param(
        "import socket\n\ndef run():\n    socket.socket()\n",
        "NETWORK",
        "ROBOT",
        id="network-direct",
    ),
    pytest.param(
        "import socket as net\n\ndef run():\n    net.create_connection(('h', 1))\n",
        "NETWORK",
        "ROBOT",
        id="network-module-alias",
    ),
    pytest.param(
        "def run(sock):\n    sock.connect(('h', 1))\n",
        "NETWORK",
        "ROBOT",
        id="network-method",
    ),
    pytest.param(
        "import pdb\n\ndef run():\n    pdb.set_trace()\n",
        "TRACE",
        "ROBOT",
        id="debugger-pdb",
    ),
    pytest.param(
        "def run():\n    breakpoint()\n",
        "TRACE",
        "ROBOT",
        id="debugger-breakpoint",
    ),
    pytest.param(
        "import sys\n\ndef run():\n    sys.settrace(None)\n",
        "TRACE",
        "ROBOT",
        id="debugger-settrace",
    ),
    pytest.param(
        "import ctypes\n\ndef run():\n    ctypes.CDLL('x')\n",
        "HARDWARE",
        "ROBOT",
        id="hardware-ctypes",
    ),
    pytest.param(
        "def run():\n    return '/dev/ttyUSB0'\n",
        "HARDWARE",
        "ROBOT",
        id="hardware-dev-literal",
    ),
    pytest.param(
        "from pathlib import Path\n\ndef run():\n    Path('x').write_text('y')\n",
        "FS_WRITE",
        "TRANSACTION",
        id="fs-write-text",
    ),
    pytest.param(
        "def run():\n    open('x', 'w')\n",
        "FS_WRITE",
        "TRANSACTION",
        id="fs-open-write",
    ),
    pytest.param(
        "def run():\n    with open('x', 'a') as handle:\n        handle.write('y')\n",
        "FS_APPEND",
        "LEDGER",
        id="fs-open-append",
    ),
]


@pytest.mark.parametrize(("source", "effect", "kind"), EFFECT_ESCAPES)
def test_effect_is_reached_through_every_spelling_and_blocks_dne(
    tmp_path: Path, source: str, effect: str, kind: str
) -> None:
    closure = _fixture_closure(tmp_path, source)
    # Either the effect is seen, or the scan fails closed on the construct; a CLOSED
    # closure that misses the effect is the only outcome that could witness a DNE.
    assert closure.status == "OPEN" or effect in closure.effects, closure.open_reasons
    assert not review._dne_allowed(kind, closure)


# Reflection, dynamic import, unresolved and external sources cannot be enumerated, so
# the closure must be OPEN and no DOES_NOT_APPLY may rest on it.
OPEN_FIXTURES = [
    pytest.param(
        "import importlib\n\ndef run():\n    return importlib.import_module('json')\n",
        id="reflection-import-module",
    ),
    pytest.param("def run():\n    return eval('1')\n", id="reflection-eval"),
    pytest.param("def run():\n    return __import__('os')\n", id="reflection-dunder-import"),
    pytest.param(
        "import socket\n\ndef run():\n    return getattr(socket, ''.join(['so', 'cket']))\n",
        id="reflection-nonliteral-getattr",
    ),
    pytest.param("import requests\n\ndef run():\n    return requests\n", id="external-import"),
    pytest.param(
        "from verifier.nowhere import thing\n\ndef run():\n    return thing\n",
        id="unresolved-internal-import",
    ),
]


@pytest.mark.parametrize("source", OPEN_FIXTURES)
def test_unenumerable_source_is_open_and_witnesses_no_dne(tmp_path: Path, source: str) -> None:
    closure = _fixture_closure(tmp_path, source)
    assert closure.status == "OPEN"
    assert not any(review._dne_allowed(kind, closure) for kind in review.REVIEW_KINDS)


def test_clean_fixture_is_closed_and_witnesses_only_its_own_dne(tmp_path: Path) -> None:
    closure = _fixture_closure(tmp_path, CLEAN_FIXTURE)
    assert closure.status == "CLOSED"
    assert closure.effects == frozenset()
    assert review._dne_allowed("ROBOT", closure)
    assert not review._dne_allowed("POLICY", closure)
    assert not review._dne_allowed("PROTOCOL", closure)


def test_closure_goes_stale_when_a_pinned_source_changes(tmp_path: Path) -> None:
    closure = _fixture_closure(tmp_path, CLEAN_FIXTURE)
    assert review._closure_is_current(tmp_path, closure)
    (tmp_path / FIXTURE_REL).write_text("def run(x):\n    return x\n", encoding="utf-8")
    assert not review._closure_is_current(tmp_path, closure)


def test_closure_goes_stale_when_a_probed_absent_candidate_appears(tmp_path: Path) -> None:
    closure = _fixture_closure(tmp_path, CLEAN_FIXTURE)
    assert "src/verifier/__init__.py" in closure.absent
    assert review._closure_is_current(tmp_path, closure)
    (tmp_path / "src" / "verifier" / "__init__.py").write_text("", encoding="utf-8")
    assert not review._closure_is_current(tmp_path, closure)


def test_substituted_owned_source_fails_closed_and_never_poisons_the_memo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    closure = _fixture_closure(tmp_path, CLEAN_FIXTURE)
    assert closure.status == "CLOSED"
    monkeypatch.setattr(Path, "is_symlink", lambda _path: True)
    assert not review._closure_is_current(tmp_path, closure)
    substituted = review._owner_closure(tmp_path, (FIXTURE_REL,))
    assert substituted.status == "OPEN"
    assert "unreadable source " + FIXTURE_REL in substituted.open_reasons
    monkeypatch.undo()
    restored = review._owner_closure(tmp_path, (FIXTURE_REL,))
    assert restored.status == "CLOSED"
    assert restored.fingerprint == closure.fingerprint


def test_negative_text_cannot_substitute_for_a_closed_witness() -> None:
    every_effect = frozenset(
        {
            "CLOCK",
            "FS_APPEND",
            "FS_READ",
            "FS_TEMP",
            "FS_UNKNOWN",
            "FS_WRITE",
            "GLOBAL_STATE",
            "HARDWARE",
            "NETWORK",
            "PROCESS",
            "PROCESS_QUERY",
            "TRACE",
        }
    )
    for item in review._REVIEWS.values():
        saturated = review._Closure(
            status="CLOSED",
            fingerprint="sha256:" + "0" * 64,
            effects=every_effect,
            sites=(),
            open_reasons=(),
            files=(),
            absent=(),
        )
        opened = replace(saturated, status="OPEN", effects=frozenset())
        for kind in item.refutations:
            assert review._basis(item, kind, saturated) == "UNRESOLVED"
            assert review._basis(item, kind, opened) == "UNRESOLVED"
            assert review._basis(item, kind, None) == "UNRESOLVED"


DNE_GATE_CASES = [
    pytest.param("ROBOT", "CLOSED", set(), True, id="robot-clean"),
    pytest.param("ROBOT", "CLOSED", {"CLOCK"}, True, id="robot-clock-is-not-forbidden"),
    pytest.param("ROBOT", "CLOSED", {"NETWORK"}, False, id="robot-network-reached"),
    pytest.param("ROBOT", "OPEN", set(), False, id="robot-open-closure"),
    pytest.param("POLICY", "CLOSED", set(), False, id="policy-has-no-witness"),
    pytest.param("PROTOCOL", "CLOSED", set(), False, id="protocol-has-no-witness"),
    pytest.param("SENSOR", "CLOSED", {"CLOCK"}, False, id="sensor-clock-reached"),
    pytest.param("LEDGER", "CLOSED", {"FS_WRITE"}, True, id="ledger-overwrite-only"),
    pytest.param("LEDGER", "CLOSED", {"FS_APPEND"}, False, id="ledger-append-reached"),
    pytest.param(
        "CONTROLLER", "CLOSED", {"PROCESS", "FS_WRITE"}, False, id="controller-loop-closed"
    ),
    pytest.param("CONTROLLER", "CLOSED", {"CLOCK"}, True, id="controller-no-actuation"),
    pytest.param("CONTROLLER", "CLOSED", {"FS_WRITE"}, True, id="controller-no-acquisition"),
]


@pytest.mark.parametrize(("kind", "status", "effects", "allowed"), DNE_GATE_CASES)
def test_dne_gate_requires_closed_and_unreached_forbidden_effects(
    kind: str, status: str, effects: set[str], allowed: bool
) -> None:
    closure = review._Closure(
        status=status,
        fingerprint="sha256:" + "0" * 64,
        effects=frozenset(effects),
        sites=(),
        open_reasons=(),
        files=(),
        absent=(),
    )
    assert review._dne_allowed(kind, closure) is allowed


def test_dne_reasons_bind_their_own_owner_closure_fingerprint() -> None:
    catalog = review.review_document()
    fingerprints = {
        object_id: review._owner_closure(ROOT, tuple(item["owned_paths"])).fingerprint
        for object_id, item in catalog.items()
    }
    assert len(set(fingerprints.values())) == len(fingerprints)
    for object_id, item in catalog.items():
        closure = review._owner_closure(ROOT, tuple(item["owned_paths"]))
        allowed_paths = set(item["owned_paths"]) | {rel for rel, _ in closure.files}
        for kind, row in item["classification"].items():
            if row["status"] != "DOES_NOT_APPLY":
                continue
            assert closure.fingerprint in row["reason"], (object_id, kind)
            for other, fingerprint in fingerprints.items():
                if other != object_id:
                    assert fingerprint not in row["reason"], (object_id, kind, other)
            cited = set(re.findall(r"src/[\w/]+\.py", row["reason"]))
            assert cited <= allowed_paths, (object_id, kind, cited - allowed_paths)


def test_stale_closure_fingerprint_in_applied_dne_reason_is_rejected_atomically(
    tmp_path: Path,
) -> None:
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_hardware_cli(root, rows, files)
    object_id, kind = next(
        (oid, kind)
        for oid, item in selected.items()
        for kind, row in item["classification"].items()
        if row["status"] == "DOES_NOT_APPLY"
    )
    stale = deepcopy(selected)
    reason = stale[object_id]["classification"][kind]["reason"]
    live = re.search(r"sha256:[0-9a-f]{64}", reason)
    assert live is not None
    stale[object_id]["classification"][kind]["reason"] = reason.replace(
        live.group(0), "sha256:" + "0" * 64
    )
    before = deepcopy(stale)
    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_"):
        review.apply_package_semantic_review_hardware_cli(root, stale, files)
    assert stale == before


def test_object_primary_kind_is_rejected_atomically(tmp_path: Path) -> None:
    root, rows, files = _workspace(tmp_path)
    rows["vstd-hardware-cli-protocol"]["kind"] = "OBJECT"
    before = deepcopy(rows)
    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_PRIMARY_KIND_DIFFERS"):
        review.apply_package_semantic_review_hardware_cli(root, rows, files)
    assert rows == before
