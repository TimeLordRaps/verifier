# Terminology: abstract syntax tree (AST).
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
from pathlib import Path

import pytest

from verifier.runtime import package_semantic_review_self_polish as review
from verifier.runtime.namespace_contracts import namespace_registry, requirements_for
from verifier.runtime.package_semantic_ownership import SEMANTIC_OWNERSHIP_SPECS
from verifier.runtime.package_semantic_review_polish import (
    REFUTABLE_CHANNELS,
    channel_census,
    surface_findings,
)


EXPECTED = {
    "vstd-self-polish-dynamics-controller": (
        "VERIFIER",
        (
            "src/verifier/runtime/self_polish_dynamics.py",
        ),
        {"TRANSACTION", "MEASUREMENT", "SENSOR", "CONTROLLER", "ACTUATOR", "PROTOCOL", "POLICY"},
    ),
    "vstd-self-polish-estate-authority": (
        "PROTOCOL",
        (
            "src/verifier/runtime/self_polish_estate_authority.py",
        ),
        {"PROTOCOL", "POLICY"},
    ),
    "vstd-self-polish-estate-evidence": (
        "VERIFIER",
        (
            "src/verifier/runtime/self_polish_estate_evidence.py",
        ),
        {"MEASUREMENT", "SENSOR", "PROTOCOL", "POLICY"},
    ),
    "vstd-self-polish-estate-native-sensor": (
        "SENSOR",
        (
            "src/verifier/runtime/self_polish_estate_native_evidence.py",
        ),
        {"MEASUREMENT", "SENSOR", "POLICY"},
    ),
    "vstd-self-polish-facet-reason-ledger": (
        "LEDGER",
        (
            "src/verifier/runtime/self_polish_facet_reasons.py",
        ),
        {"LEDGER", "MEASUREMENT", "SENSOR", "POLICY"},
    ),
    "vstd-self-polish-native-adapters": (
        "VERIFIER",
        (
            "src/verifier/runtime/self_polish_native_adapters.py",
        ),
        {"ACTUATOR", "POLICY"},
    ),
    "vstd-self-polish-native-case-registry": (
        "DATA",
        (
            "src/verifier/runtime/self_polish_native_cases.py",
            "src/verifier/runtime/self_polish_native_sim_case_patch.py",
            "src/verifier/runtime/self_polish_native_tier3_cases.py",
            "src/verifier/runtime/self_polish_native_tier4_cases.py",
            "src/verifier/runtime/self_polish_native_tier5_cases.py",
            "src/verifier/runtime/self_polish_native_tier6_cases.py",
            "src/verifier/runtime/self_polish_native_tier7_cases.py",
            "src/verifier/runtime/self_polish_native_tier8_cases.py",
            "src/verifier/runtime/self_polish_native_tier9_cases.py",
        ),
        {"POLICY"},
    ),
    "vstd-self-polish-native-extension-registry": (
        "DATA",
        (
            "src/verifier/runtime/self_polish_native_extensions.py",
        ),
        {"MEASUREMENT", "SENSOR", "POLICY"},
    ),
    "vstd-self-polish-native-replay-controller": (
        "VERIFIER",
        (
            "src/verifier/runtime/self_polish_native_extension_replay.py",
            "src/verifier/runtime/self_polish_native_full_candidate.py",
            "src/verifier/runtime/self_polish_native_replay.py",
        ),
        {"TRANSACTION", "MEASUREMENT", "SENSOR", "ACTUATOR", "PROTOCOL", "POLICY"},
    ),
    "vstd-self-polish-statics-controller": (
        "VERIFIER",
        (
            "src/verifier/runtime/self_polish_statics.py",
        ),
        {"TRANSACTION", "MEASUREMENT", "SENSOR", "CONTROLLER", "ACTUATOR", "PROTOCOL", "POLICY"},
    ),
    "vstd-self-polish-tier-controller": (
        "VERIFIER",
        (
            "src/verifier/runtime/self_polish_tiers.py",
        ),
        {"MEASUREMENT", "SENSOR", "CONTROLLER", "ACTUATOR", "PROTOCOL", "POLICY"},
    ),
    "vstd-tier-zero-orchestrator": (
        "VERIFIER",
        (
            "src/verifier/runtime/tier_zero.py",
        ),
        {"MEASUREMENT", "SENSOR", "ACTUATOR", "PROTOCOL", "POLICY"},
    ),
    "vstd-tier-zero-profile-policy": (
        "POLICY",
        (
            "src/verifier/runtime/tier_zero_profile.py",
        ),
        {"POLICY"},
    ),
    "vstd-tier-zero-reason-ledger": (
        "LEDGER",
        (
            "src/verifier/runtime/tier_zero_reasons.py",
        ),
        {"LEDGER", "MEASUREMENT", "SENSOR", "POLICY"},
    ),
}

# Audited refutations: each must be backed by an exact AST channel census.
REFUTED = {
    "vstd-tier-zero-profile-policy": {"LEDGER", "TRANSACTION", "ROBOT", "FINBOT"},
}

# No applicable self-polish kind is blocked after the second-pass audit.
BLOCKED: dict[str, set[str]] = {}

# Any remaining entry here is an intentional central role whose source audit is
# still unresolved.  Reconciled source-established roles must not remain hidden.
OWNERSHIP_UNESTABLISHED = {
}

OBJECT = "vstd-self-polish-dynamics-controller"


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


def _workspace(tmp_path: Path) -> tuple[Path, dict[str, dict], dict[str, str]]:
    rows = {}
    files = {}
    for object_id, item in review.review_document().items():
        for path in item["owned_paths"]:
            target = tmp_path / path
            target.parent.mkdir(parents=True, exist_ok=True)
            raw = ("# synthetic exact owner " + object_id + " " + path + "\n").encode()
            target.write_bytes(raw)
            files[path] = _digest(raw)
        rows[object_id] = {
            "object_id": object_id,
            "kind": item["primary_kind"],
            "specializations": [],
            "payload": {},
            "operands": {},
            "surfaces": ["file:" + path for path in item["owned_paths"]],
            "reason": "Synthetic exact owner for self-polish review tests.",
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


def test_document_closes_exact_14_by_24_by_12_denominator() -> None:
    catalog = review.review_document()
    registry = namespace_registry()

    assert tuple(catalog) == review.SELF_POLISH_OBJECT_IDS
    assert set(catalog) == set(EXPECTED)
    assert len(catalog) == 14
    assert sum(len(item["owned_paths"]) for item in catalog.values()) == 24
    assert sum(len(item["classification"]) for item in catalog.values()) == 168
    assert sum(len(item["declarations"]) for item in catalog.values()) == 165

    owned_paths = []
    for object_id, item in catalog.items():
        primary, paths, applicable = EXPECTED[object_id]
        refuted = REFUTED.get(object_id, set())
        blocked = BLOCKED.get(object_id, set())
        assert item["primary_kind"] == primary
        assert item["owned_paths"] == list(paths)
        owned_paths.extend(paths)
        assert set(item["classification"]) == set(review.REVIEW_KINDS)
        for kind, decision in item["classification"].items():
            if kind in applicable:
                expected_status = "APPLIES"
            elif kind in refuted:
                expected_status = "DOES_NOT_APPLY"
            else:
                expected_status = "UNRESOLVED"
            assert decision["status"] == expected_status, (object_id, kind)
            assert decision["reason"].strip()
            if expected_status == "UNRESOLVED":
                assert decision["evidence_paths"] == []
                assert "cannot refute a " + kind + " role" in decision["reason"]
            elif expected_status == "DOES_NOT_APPLY":
                assert decision["evidence_paths"] == list(paths)
                assert "AST census" in decision["reason"]
            else:
                assert decision["evidence_paths"]
                assert set(decision["evidence_paths"]) <= set(paths)
                assert ("did not establish this kind" in decision["reason"]) == (
                    kind in blocked
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
        assert "Tier-1-plus" in item["claim_boundary"]
        assert "ROBOT" in item["claim_boundary"]
        assert "FINBOT" in item["claim_boundary"]
    assert len(owned_paths) == len(set(owned_paths))

    catalog["vstd-self-polish-native-case-registry"]["owned_paths"].clear()
    assert review.review_document()["vstd-self-polish-native-case-registry"][
        "owned_paths"
    ]


def test_document_matches_exact_semantic_ownership_partition() -> None:
    catalog = review.review_document()
    ownership = {
        spec.object_id: spec
        for spec in SEMANTIC_OWNERSHIP_SPECS
        if spec.object_id in catalog
    }

    assert set(ownership) == set(catalog)
    for object_id, item in catalog.items():
        spec = ownership[object_id]
        declared = {
            kind
            for kind in (spec.primary_kind, *spec.specializations)
            if kind in review.REVIEW_KINDS
        }
        applies = {
            kind
            for kind, decision in item["classification"].items()
            if decision["status"] == "APPLIES"
        }
        assert item["primary_kind"] == spec.primary_kind
        assert item["owned_paths"] == list(spec.owned_paths)
        assert applies <= declared, object_id
        assert declared - applies == OWNERSHIP_UNESTABLISHED.get(object_id, set())


def test_self_polish_boundaries_preserve_installation_and_consequence_types() -> None:
    catalog = review.review_document()

    cases = catalog["vstd-self-polish-native-case-registry"]
    assert cases["classification"]["POLICY"]["status"] == "APPLIES"
    assert cases["classification"]["PROTOCOL"]["status"] == "UNRESOLVED"
    assert cases["declarations"]
    assert all(name.startswith("POLICY-") for name in cases["declarations"])

    extensions = catalog["vstd-self-polish-native-extension-registry"]
    assert "uninstalled" in extensions["classification"]["POLICY"]["reason"]
    assert (
        "install nothing"
        in extensions["declarations"]["POLICY-0.3-enforcement-and-decisions"][
            "enforcement_points"
        ]
    )

    replay = catalog["vstd-self-polish-native-replay-controller"]
    assert replay["classification"]["CONTROLLER"]["status"] == "UNRESOLVED"
    assert not any(name.startswith("CONTROLLER-") for name in replay["declarations"])

    tier_zero = catalog["vstd-tier-zero-orchestrator"]
    assert tier_zero["classification"]["CONTROLLER"]["status"] == "UNRESOLVED"
    assert tier_zero["classification"]["CONTROLLER"]["evidence_paths"] == []

    profile = catalog["vstd-tier-zero-profile-policy"]
    assert {
        kind
        for kind, decision in profile["classification"].items()
        if decision["status"] == "APPLIES"
    } == {"POLICY"}

    for object_id, item in catalog.items():
        assert item["classification"]["ASSET"]["status"] == "UNRESOLVED"
        assert item["classification"]["MARKET"]["status"] == "UNRESOLVED"
        for kind in ("ROBOT", "FINBOT"):
            decision = item["classification"][kind]
            if kind in REFUTED.get(object_id, set()):
                assert decision["status"] == "DOES_NOT_APPLY"
                assert "does not apply as " + kind in decision["reason"]
                assert "AST census" in decision["reason"]
            else:
                assert decision["status"] == "UNRESOLVED"


def test_apply_is_pure_complete_deterministic_and_idempotent(tmp_path: Path) -> None:
    root, rows, files = _workspace(tmp_path)
    before = deepcopy(rows)

    first = review.apply_package_semantic_review_self_polish(root, rows, files)
    second = review.apply_package_semantic_review_self_polish(root, first, files)

    assert rows == before
    assert first == second
    for object_id, row in first.items():
        paths = set(EXPECTED[object_id][1])
        applicable = EXPECTED[object_id][2]
        assert {
            kind
            for kind, decision in row["classification"].items()
            if decision["status"] == "APPLIES"
        } == applicable
        assert applicable - {row["kind"]} <= set(row["specializations"])
        assert all(name.split("-", 1)[0] in applicable for name in row["obligations"])
        assert all(
            binding["reason"].strip()
            and {entry["path"] for entry in binding["evidence"]} == paths
            and all(value.strip() for value in binding["declaration"].values())
            for binding in row["obligations"].values()
        )
        for decision in row["classification"].values():
            if decision["status"] == "UNRESOLVED":
                assert decision["evidence"] == []
            else:
                assert {entry["path"] for entry in decision["evidence"]} == paths


def test_apply_preserves_only_exact_complete_current_bindings(tmp_path: Path) -> None:
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_self_polish(root, rows, files)
    assert (
        review.apply_package_semantic_review_self_polish(root, selected, files)
        == selected
    )

    object_id = "vstd-tier-zero-profile-policy"
    row = selected[object_id]
    row["classification"]["FINBOT"]["reason"] = (
        "Substituted noncanonical FINBOT refutation."
    )
    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT"):
        review.apply_package_semantic_review_self_polish(root, selected, files)


def test_unlisted_basis_and_unknown_object_never_acquire_complement_refutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    object_id = "vstd-tier-zero-profile-policy"
    original = review._REVIEWS[object_id]
    monkeypatch.setitem(
        review._REVIEWS,
        object_id,
        replace(original, refuted=tuple(k for k in original.refuted if k != "LEDGER")),
    )
    assert review.review_document()[object_id]["classification"]["LEDGER"] == {
        "status": "UNRESOLVED",
        "reason": review._unresolved_reason("LEDGER"),
        "evidence_paths": [],
    }
    root, rows, files = _workspace(tmp_path)
    rows["unknown-future-owner"] = {
        "object_id": "unknown-future-owner",
        "kind": "OBJECT",
        "specializations": [],
        "surfaces": [],
        "classification": {
            "LEDGER": {"status": "UNRESOLVED", "reason": "Unaudited.", "evidence": []}
        },
        "obligations": {},
    }
    result = review.apply_package_semantic_review_self_polish(root, rows, files)
    assert result[object_id]["classification"]["LEDGER"] == {
        "status": "UNRESOLVED",
        "reason": review._unresolved_reason("LEDGER"),
        "evidence": [],
    }
    assert result["unknown-future-owner"] == rows["unknown-future-owner"]


def _complement_table(original: review._Review) -> review._Review:
    applicable = tuple(k for k in review.REVIEW_KINDS if k not in {"ROBOT", "FINBOT"})
    return replace(
        original,
        applicable=applicable,
        role_paths={kind: original.owned_paths for kind in applicable},
        refuted=("ROBOT", "FINBOT"),
        anchors={kind: "self_polish_dynamics.py:1" for kind in applicable},
        blocked=(),
    )


def _unaudited_table(original: review._Review) -> review._Review:
    applicable = ("TRANSACTION", "POLICY")
    return replace(
        original,
        applicable=applicable,
        role_paths={kind: original.owned_paths for kind in applicable},
        refuted=("MEASUREMENT", "ROBOT", "FINBOT"),
        anchors={kind: "self_polish_dynamics.py:1" for kind in applicable},
        blocked=(),
    )


@pytest.mark.parametrize(
    ("failure", "message"),
    [
        ("complement", "refutation table is complement-shaped"),
        ("unaudited", "without an audited channel census"),
        ("blocked_not_primary", "blocks a kind other than its primary kind"),
        ("missing_anchor", "APPLIES lacks an exact source anchor"),
    ],
)
def test_catalog_check_rejects_complement_unaudited_or_unanchored_tables(
    monkeypatch: pytest.MonkeyPatch, failure: str, message: str
) -> None:
    original = review._REVIEWS[OBJECT]
    if failure == "complement":
        replacement = _complement_table(original)
    elif failure == "unaudited":
        replacement = _unaudited_table(original)
    elif failure == "blocked_not_primary":
        replacement = replace(original, blocked=("TRANSACTION",))
    else:
        replacement = replace(
            original,
            anchors={k: v for k, v in original.anchors.items() if k != "TRANSACTION"},
        )
    monkeypatch.setitem(review._REVIEWS, OBJECT, replacement)
    with pytest.raises(AssertionError, match=message):
        review._catalog_check()


@pytest.mark.parametrize(
    "source",
    [
        "import socket\n",
        "import subprocess\n",
        "open('state.txt', 'w')\n",
    ],
)
def test_refutation_fails_closed_when_owned_source_contains_its_channel(
    tmp_path: Path, source: str
) -> None:
    root, rows, files = _workspace(tmp_path)
    target = "src/verifier/runtime/tier_zero_profile.py"
    raw = source.encode()
    (root / target).write_bytes(raw)
    files[target] = _digest(raw)
    before = deepcopy(rows)

    with pytest.raises(
        ValueError,
        match="PACKAGE_SEMANTIC_REVIEW_REFUTATION_CHANNEL_PRESENT:vstd-tier-zero-profile-policy:",
    ):
        review.apply_package_semantic_review_self_polish(root, rows, files)
    assert rows == before


def test_apply_rejects_prior_complete_decision_on_now_unresolved_kind(
    tmp_path: Path,
) -> None:
    root, rows, files = _workspace(tmp_path)
    path = "src/verifier/runtime/tier_zero.py"
    rows["vstd-tier-zero-orchestrator"]["classification"]["CONTROLLER"] = {
        "status": "DOES_NOT_APPLY",
        "reason": "Earlier audit refuted CONTROLLER.",
        "evidence": [{"path": path, "sha256": files[path]}],
    }
    before = deepcopy(rows)

    with pytest.raises(
        ValueError,
        match="PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT:vstd-tier-zero-orchestrator:CONTROLLER",
    ):
        review.apply_package_semantic_review_self_polish(root, rows, files)
    assert rows == before


def test_apply_rejects_refutation_copied_from_sibling_onto_unresolved_kind(
    tmp_path: Path,
) -> None:
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_self_polish(root, rows, files)
    assert selected["vstd-tier-zero-profile-policy"]["classification"]["ROBOT"][
        "status"
    ] == "DOES_NOT_APPLY"
    assert selected[OBJECT]["classification"]["ROBOT"]["status"] == "UNRESOLVED"
    selected[OBJECT]["classification"]["ROBOT"] = deepcopy(
        selected["vstd-tier-zero-profile-policy"]["classification"]["ROBOT"]
    )
    before = deepcopy(selected)

    with pytest.raises(
        ValueError,
        match="PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT:" + OBJECT + ":ROBOT",
    ):
        review.apply_package_semantic_review_self_polish(root, selected, files)
    assert selected == before


@pytest.mark.parametrize("failure", ["stale", "missing", "unowned", "extra_owned"])
def test_apply_rejects_source_or_ownership_drift_atomically(
    tmp_path: Path, failure: str
) -> None:
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-self-polish-native-case-registry"
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
        review.apply_package_semantic_review_self_polish(root, rows, files)
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
    ],
)
def test_apply_rejects_conflicting_or_partial_reviews_atomically(
    tmp_path: Path, failure: str
) -> None:
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_self_polish(root, rows, files)
    row = selected[OBJECT]
    if failure == "status":
        row["classification"]["TRANSACTION"]["status"] = "DOES_NOT_APPLY"
    elif failure == "reason_substitution":
        row["classification"]["POLICY"]["reason"] = (
            "Substituted noncanonical POLICY applicability."
        )
    elif failure == "refutation_evidence_substitution":
        row["classification"]["FINBOT"]["evidence"] = deepcopy(
            selected["vstd-tier-zero-profile-policy"]["classification"]["FINBOT"][
                "evidence"
            ]
        )
    elif failure == "obligation_reason_substitution":
        row["obligations"]["TRANSACTION-0.1-effects-and-authority"]["reason"] = (
            "Substituted noncanonical obligation reason."
        )
    elif failure == "stale_decision":
        row["classification"]["TRANSACTION"]["evidence"][0]["sha256"] = (
            "sha256:" + "f" * 64
        )
    elif failure == "partial_declaration":
        row["obligations"]["TRANSACTION-0.1-effects-and-authority"]["declaration"][
            "effects"
        ] = ""
    elif failure == "refuted_declaration":
        row["obligations"]["MARKET-0.1-orders-and-access"] = {
            "reason": "Contradictory MARKET declaration.",
            "evidence": deepcopy(row["classification"]["MARKET"]["evidence"]),
            "declaration": {
                "participant_access": "Contradictory access.",
                "order_states": "Contradictory states.",
                "validation": "Contradictory validation.",
                "cancellation": "Contradictory cancellation.",
            },
        }
    elif failure == "malformed_unresolved":
        row["classification"]["MARKET"] = {
            "status": "UNRESOLVED",
            "reason": "",
            "evidence": [],
        }
    elif failure == "label_conflict":
        row["specializations"].append("MARKET")
    else:
        row["obligations"]["TRANSACTION-0.99-invented"] = {
            "reason": "Invented.",
            "evidence": [],
            "declaration": {},
        }
    before = deepcopy(selected)

    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_"):
        review.apply_package_semantic_review_self_polish(root, selected, files)
    assert selected == before


@pytest.mark.parametrize(
    "source",
    [
        "import socket\n",
        "from urllib.request import urlopen\n",
        "import subprocess\n",
        "import serial\n",
        "path = '/dev/ttyUSB0'\n",
        "open('out.txt', 'w')\n",
        "open(name, mode)\n",
        "open('in.txt')\n",
        "import json\nvalue = json.dumps({})\n",
    ],
)
def test_channel_census_detects_exact_owned_bytes_only(
    tmp_path: Path, source: str
) -> None:
    (tmp_path / "owned.py").write_text(source, encoding="utf-8")
    census = channel_census(tmp_path, ("owned.py",))
    expected = {
        "import socket\n": {"NET"},
        "from urllib.request import urlopen\n": {"NET"},
        "import subprocess\n": {"PROC"},
        "import serial\n": {"DEV"},
        "path = '/dev/ttyUSB0'\n": {"DEV"},
        "open('out.txt', 'w')\n": {"WRITE"},
        "open(name, mode)\n": {"WRITE"},
        "open('in.txt')\n": set(),
        "import json\nvalue = json.dumps({})\n": set(),
    }[source]
    assert {name for name, present in census.items() if present} == expected


@pytest.mark.parametrize(
    "source",
    [
        "import importlib\nimportlib.import_module(name)\n",
        "def broken(:\n",
    ],
)
def test_channel_census_rejects_unverifiable_sources(
    tmp_path: Path, source: str
) -> None:
    (tmp_path / "owned.py").write_text(source, encoding="utf-8")
    with pytest.raises(
        ValueError, match="PACKAGE_SEMANTIC_REVIEW_CHANNEL_UNVERIFIABLE:owned.py"
    ):
        channel_census(tmp_path, ("owned.py",))


def test_refutations_match_exact_repository_channel_census() -> None:
    repo = Path(__file__).resolve().parents[1]
    catalog = review.review_document()
    for object_id, item in catalog.items():
        census = channel_census(repo, tuple(item["owned_paths"]))
        for kind in REFUTED.get(object_id, set()):
            present = [channel for channel in REFUTABLE_CHANNELS[kind] if census[channel]]
            assert present == [], (object_id, kind, present)


def test_apply_rejects_missing_object_and_invalid_digest_census(
    tmp_path: Path,
) -> None:
    root, rows, files = _workspace(tmp_path)
    missing = deepcopy(rows)
    missing.pop("vstd-tier-zero-reason-ledger")
    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_OBJECT_MISSING"):
        review.apply_package_semantic_review_self_polish(root, missing, files)

    invalid_files = dict(files)
    invalid_files[next(iter(invalid_files))] = "not-a-digest"
    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_FILES_INVALID"):
        review.apply_package_semantic_review_self_polish(root, rows, invalid_files)


def test_apply_rejects_refutation_whose_surface_is_open(
    tmp_path: Path,
) -> None:
    root, rows, files = _workspace(tmp_path)
    target = "src/verifier/runtime/tier_zero_profile.py"
    raw = b"import importlib\n"
    (root / target).write_bytes(raw)
    files[target] = "sha256:" + sha256(raw).hexdigest()
    before = deepcopy(rows)

    with pytest.raises(
        ValueError,
        match="PACKAGE_SEMANTIC_REVIEW_REFUTATION_SURFACE_OPEN:vstd-tier-zero-profile-policy",
    ):
        review.apply_package_semantic_review_self_polish(root, rows, files)
    assert rows == before


def test_apply_rechecks_all_sources_after_semantic_preflight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, rows, files = _workspace(tmp_path)
    target = EXPECTED["vstd-tier-zero-reason-ledger"][1][0]
    original = review._read_exact
    calls = 0

    def drifting_read(selected_root: Path, path: str) -> bytes:
        nonlocal calls
        value = original(selected_root, path)
        if path == target:
            calls += 1
            if calls == 2:
                return b"# drifted after the opening digest\n"
        return value

    monkeypatch.setattr(review, "_read_exact", drifting_read)
    before = deepcopy(rows)
    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_SOURCE_CHANGED"):
        review.apply_package_semantic_review_self_polish(root, rows, files)
    assert rows == before


@pytest.mark.parametrize(
    "failure",
    ["specializations", "obligations", "classification", "decision", "within_row", "cycle"],
)
def test_apply_rejects_aliased_containers_atomically(
    tmp_path: Path, failure: str
) -> None:
    """One mutable container reachable from two places fails closed before writes."""
    root, rows, files = _workspace(tmp_path)
    first = OBJECT
    second = "vstd-self-polish-estate-authority"
    if failure == "specializations":
        rows[second]["specializations"] = rows[first]["specializations"]
    elif failure == "obligations":
        rows[second]["obligations"] = rows[first]["obligations"]
    elif failure == "classification":
        rows[second]["classification"] = rows[first]["classification"]
    elif failure == "decision":
        rows[second]["classification"]["POLICY"] = rows[first]["classification"]["POLICY"]
    elif failure == "within_row":
        rows[first]["classification"]["ROBOT"] = rows[first]["classification"]["FINBOT"]
    else:
        rows[first]["obligations"]["self-loop"] = rows[first]["obligations"]
        with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_ALIAS_CONFLICT"):
            review.apply_package_semantic_review_self_polish(root, rows, files)
        # A cyclic row cannot be compared by value; its self-reference must survive.
        assert rows[first]["obligations"]["self-loop"] is rows[first]["obligations"]
        return
    before = deepcopy(rows)

    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_ALIAS_CONFLICT"):
        review.apply_package_semantic_review_self_polish(root, rows, files)
    assert rows == before


ADVERSARIAL_REFUTED_SOURCES = {
    "repl_callback_into_re_sub": (
        "import re\n\ndef run(cb, text):\n    return re.sub('a', cb, text)\n"
    ),
    "compiled_pattern_callback": (
        "import re\n\ndef run(cb, text):\n    return re.compile('a').sub(cb, text)\n"
    ),
    "sort_key_callback": "def run(cb, items):\n    items.sort(key=cb)\n",
    "constructed_device_path_read": (
        "def run():\n    return open('/de' + 'v/ttyS0', 'rb').read()\n"
    ),
    "constructed_com_name_read": (
        "def run():\n    return open('CO' + 'M1', 'rb').read()\n"
    ),
    "parameter_path_read_text": "def run(path):\n    return path.read_text()\n",
    "parameter_path_open_method": "def run(path):\n    return path.open('rb').read()\n",
    "module_alias_path_constructor_variable": (
        "import pathlib as pl\n\ndef run(name):\n    return pl.Path(name).read_bytes()\n"
    ),
    "from_import_alias_path_constructor": (
        "from pathlib import Path as P\n\ndef run(name):\n    return P(name).read_text()\n"
    ),
    "device_path_held_in_local_variable": (
        "def run():\n    path = '/de' + 'v/ttyS0'\n    return open(path, 'rb').read()\n"
    ),
    "parameter_shadows_local_helper": (
        "def helper(value):\n    return value\n\n"
        "def run(helper, text):\n    return helper(text)\n"
    ),
    "parameter_invoked_directly": "def run(cb):\n    return cb()\n",
    "json_default_callback": (
        "import json\n\ndef run(cb, value):\n    return json.dumps(value, default=cb)\n"
    ),
    "json_default_callback_in_literal": (
        "import json\n\ndef run(cb, value):\n    return json.dumps(value, default=[cb][0])\n"
    ),
    "json_splatted_keyword_mapping": (
        "import json\n\ndef run(kwargs, value):\n    return json.dumps(value, **kwargs)\n"
    ),
    "sorted_key_callback_parameter": "def run(cb, items):\n    return sorted(items, key=cb)\n",
    "iter_sentinel_invokes_parameter": "def run(cb):\n    return list(iter(cb, None))\n",
    "rebound_module_name_hides_callable": (
        "import json\n\ndef run(obj, value):\n    json = obj\n    return json.dumps(value)\n"
    ),
    "rebound_builtin_name_hides_callable": (
        "def run(cb, value):\n    list = cb\n    return list(value)\n"
    ),
    "rebound_local_def_name_hides_callable": (
        "def helper(x):\n    return x\n\ndef run(cb, value):\n"
        "    helper = cb\n    return helper(value)\n"
    ),
}

CLOSED_REFUTED_SOURCES = {
    "arithmetic_on_parameter": "def run(value):\n    return value + 1\n",
    "literal_path_read": (
        "from pathlib import Path\n\ndef run():\n"
        "    return Path('settings.json').read_text()\n"
    ),
    "builtin_key_over_literal_data": "def run():\n    return sorted([3, 1], key=len)\n",
    "local_helper_called_with_literal": (
        "def helper(x):\n    return x\n\ndef run():\n    return helper(3)\n"
    ),
    "json_dumps_of_parameter_is_data": (
        "import json\n\ndef run(value):\n    return json.dumps(value, sort_keys=True)\n"
    ),
    "builtin_list_of_parameter_is_data": "def run(value):\n    return list(value)\n",
    "from_import_dumps_of_parameter_is_data": (
        "from json import dumps\n\ndef run(value):\n    return dumps(value)\n"
    ),
    "local_helper_passes_parameter_as_data": (
        "import json\n\ndef encode(value):\n    return json.dumps(value)\n\n"
        "def run(value):\n    return encode(value)\n"
    ),
}


@pytest.mark.parametrize("name", sorted(CLOSED_REFUTED_SOURCES))
def test_closed_refuted_sources_remain_refutable(tmp_path: Path, name: str) -> None:
    """The closure guard narrows DOES_NOT_APPLY; it does not block closed bodies."""
    root, rows, files = _workspace(tmp_path)
    target = "src/verifier/runtime/tier_zero_profile.py"
    raw = CLOSED_REFUTED_SOURCES[name].encode()
    (root / target).write_bytes(raw)
    files[target] = _digest(raw)

    selected = review.apply_package_semantic_review_self_polish(root, rows, files)
    profile = selected["vstd-tier-zero-profile-policy"]["classification"]
    for kind in REFUTED["vstd-tier-zero-profile-policy"]:
        assert profile[kind]["status"] == "DOES_NOT_APPLY", kind


@pytest.mark.parametrize("name", sorted(ADVERSARIAL_REFUTED_SOURCES))
def test_refutation_fails_closed_for_callback_and_constructed_flow(
    tmp_path: Path, name: str
) -> None:
    """A DOES_NOT_APPLY needs a closed flow, not only an absent channel name."""
    root, rows, files = _workspace(tmp_path)
    target = "src/verifier/runtime/tier_zero_profile.py"
    raw = ADVERSARIAL_REFUTED_SOURCES[name].encode()
    (root / target).write_bytes(raw)
    files[target] = _digest(raw)
    before = deepcopy(rows)

    with pytest.raises(
        ValueError,
        match="PACKAGE_SEMANTIC_REVIEW_REFUTATION_SURFACE_OPEN:vstd-tier-zero-profile-policy",
    ):
        review.apply_package_semantic_review_self_polish(root, rows, files)
    assert rows == before


def test_clean_refuted_source_still_applies_and_text_does_not_decide(
    tmp_path: Path,
) -> None:
    """Disclaimer text is inert: a clean closed body applies, a channel does not."""
    root, rows, files = _workspace(tmp_path)
    target = "src/verifier/runtime/tier_zero_profile.py"
    raw = (
        '"""This owner has no network, subprocess, device, or write channel."""\n'
        "def run(value):\n    return value + 1\n"
    ).encode()
    (root / target).write_bytes(raw)
    files[target] = _digest(raw)

    selected = review.apply_package_semantic_review_self_polish(root, rows, files)
    decision = selected["vstd-tier-zero-profile-policy"]["classification"]["ROBOT"]
    assert decision["status"] == "DOES_NOT_APPLY"

    (root / target).write_bytes(b"import socket\n")
    files[target] = _digest(b"import socket\n")
    with pytest.raises(ValueError, match="REFUTATION_CHANNEL_PRESENT"):
        review.apply_package_semantic_review_self_polish(root, rows, files)


def test_negative_reason_text_cannot_promote_unresolved_kind(tmp_path: Path) -> None:
    """A disclaimer on an UNRESOLVED candidate is a conflict, not a refutation."""
    root, rows, files = _workspace(tmp_path)
    path = "src/verifier/runtime/self_polish_dynamics.py"
    rows[OBJECT]["classification"]["ROBOT"] = {
        "status": "UNRESOLVED",
        "reason": "No network, subprocess, device, or write channel; does not apply as ROBOT.",
        "evidence": [{"path": path, "sha256": files[path]}],
    }
    before = deepcopy(rows)

    with pytest.raises(
        ValueError,
        match="PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT:" + OBJECT + ":ROBOT",
    ):
        review.apply_package_semantic_review_self_polish(root, rows, files)
    assert rows == before


def test_object_label_never_exempts_unresolved_kinds(tmp_path: Path) -> None:
    """An OBJECT specialization is a general label; it neither refutes nor exempts."""
    root, rows, files = _workspace(tmp_path)
    baseline = review.apply_package_semantic_review_self_polish(root, rows, files)

    labelled = deepcopy(rows)
    labelled[OBJECT]["specializations"] = ["OBJECT"]
    selected = review.apply_package_semantic_review_self_polish(root, labelled, files)

    for kind in review.REVIEW_KINDS:
        assert (
            selected[OBJECT]["classification"][kind]["status"]
            == baseline[OBJECT]["classification"][kind]["status"]
        ), kind
    assert "OBJECT" in selected[OBJECT]["specializations"]
    assert set(selected[OBJECT]["obligations"]) == set(baseline[OBJECT]["obligations"])


def test_roles_accumulate_without_removing_existing_labels(tmp_path: Path) -> None:
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-self-polish-estate-authority"
    rows[object_id]["specializations"] = ["LOCAL-ROLE"]

    selected = review.apply_package_semantic_review_self_polish(root, rows, files)
    specializations = selected[object_id]["specializations"]
    assert specializations[0] == "LOCAL-ROLE"
    assert "POLICY" in specializations
    assert len(specializations) == len(set(specializations))
    again = review.apply_package_semantic_review_self_polish(root, selected, files)
    assert again[object_id]["specializations"] == specializations


def test_sibling_digest_substituted_into_evidence_is_rejected(tmp_path: Path) -> None:
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_self_polish(root, rows, files)
    own = EXPECTED[OBJECT][1][0]
    other = "src/verifier/runtime/tier_zero.py"
    assert files[own] != files[other]
    selected[OBJECT]["classification"]["MEASUREMENT"]["evidence"][0]["sha256"] = files[
        other
    ]
    before = deepcopy(selected)

    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT"):
        review.apply_package_semantic_review_self_polish(root, selected, files)
    assert selected == before


def test_owned_source_replaced_by_out_of_root_link_fails_closed(tmp_path: Path) -> None:
    root, rows, files = _workspace(tmp_path)
    outside = tmp_path.parent / (tmp_path.name + "-outside.py")
    outside.write_bytes(b"import socket\n")
    target = root / "src/verifier/runtime/tier_zero_profile.py"
    target.unlink()
    try:
        target.symlink_to(outside)
    except (OSError, NotImplementedError):
        outside.unlink(missing_ok=True)
        pytest.skip(
            "OS_CAPABILITY_GUARD: symbolic-link creation (Path.symlink_to) unavailable: "
            "Windows requires SeCreateSymbolicLinkPrivilege or Developer Mode"
        )
    try:
        with pytest.raises(ValueError, match="SOURCE_UNAVAILABLE"):
            review.apply_package_semantic_review_self_polish(root, rows, files)
    finally:
        outside.unlink(missing_ok=True)


def test_live_refuted_source_has_closed_surface() -> None:
    repo = Path(__file__).resolve().parents[1]
    path = "src/verifier/runtime/tier_zero_profile.py"
    assert surface_findings(repo, (path,))[path] == ()


def test_live_refuted_source_has_no_constructed_path_residual() -> None:
    repo = Path(__file__).resolve().parents[1]
    path = "src/verifier/runtime/tier_zero_profile.py"
    raw = (repo / path).read_bytes()
    assert review._closure_findings(raw, path) == set()
