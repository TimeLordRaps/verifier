# Terminology: abstract syntax tree (AST).
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
from pathlib import Path

import pytest

from verifier.runtime.namespace_contracts import namespace_registry, requirements_for
from verifier.runtime import package_semantic_review_polish as review
from verifier.runtime.package_semantic_review_polish import (
    REFUTABLE_CHANNELS,
    channel_census,
    surface_findings,
)


EXPECTED = {
    "vstd-tier-progression-controller": {
        "paths": (
            "src/verifier/runtime/core_tier_progression.py",
            "src/verifier/runtime/tier_progression.py",
        ),
        "kinds": {"MEASUREMENT", "CONTROLLER", "ACTUATOR", "POLICY"},
        "refuted": set(),
        "blocked": set(),
    },
    "vstd-application-release-controller": {
        "paths": (
            "src/verifier/runtime/application_release.py",
            "src/verifier/runtime/core_application_release.py",
        ),
        "kinds": {"TRANSACTION", "MEASUREMENT", "SENSOR", "CONTROLLER", "ACTUATOR", "POLICY"},
        "refuted": set(),
        "blocked": set(),
    },
    "vstd-package-polish-controller": {
        "paths": (
            "src/verifier/runtime/package_polish.py",
            "src/verifier/runtime/package_polish_schema_validation.py",
            "src/verifier/runtime/package_source_contracts.py",
        ),
        "kinds": {"TRANSACTION", "MEASUREMENT", "SENSOR", "CONTROLLER", "ACTUATOR", "PROTOCOL", "POLICY"},
        "refuted": set(),
        "blocked": set(),
    },
    "vstd-package-self-polish-controller": {
        "paths": (
            "src/verifier/runtime/package_self_polish.py",
        ),
        "kinds": {"MEASUREMENT", "SENSOR", "CONTROLLER", "ACTUATOR", "PROTOCOL", "POLICY"},
        "refuted": set(),
        "blocked": set(),
    },
    "vstd-package-self-polish-rechecker": {
        "paths": (
            "src/verifier/runtime/package_self_polish_recheck.py",
        ),
        "kinds": {"MEASUREMENT", "SENSOR", "CONTROLLER", "ACTUATOR", "PROTOCOL", "POLICY"},
        "refuted": set(),
        "blocked": set(),
    },
    "vstd-polish-assessment-engine": {
        "paths": (
            "src/verifier/runtime/polish.py",
        ),
        "kinds": {"MEASUREMENT", "ACTUATOR", "POLICY"},
        "refuted": set(),
        "blocked": set(),
    },
    "vstd-polish-command-controller": {
        "paths": (
            "src/verifier/runtime/polish_cli.py",
        ),
        "kinds": {"TRANSACTION", "MEASUREMENT", "SENSOR", "CONTROLLER", "ACTUATOR", "POLICY"},
        "refuted": set(),
        "blocked": {"CONTROLLER"},
    },
    "vstd-polish-capacity-policy": {
        "paths": (
            "src/verifier/runtime/polish_capacity.py",
        ),
        "kinds": {"POLICY"},
        "refuted": set(),
        "blocked": set(),
    },
    "vstd-polish-findings-projection": {
        "paths": (
            "src/verifier/runtime/polish_findings.py",
        ),
        "kinds": {"MEASUREMENT", "POLICY"},
        "refuted": set(),
        "blocked": set(),
    },
    "vstd-polish-inventory-policy": {
        "paths": (
            "src/verifier/runtime/polish_inventory.py",
        ),
        "kinds": {"POLICY"},
        "refuted": set(),
        "blocked": set(),
    },
    "vstd-polish-inventory-authority": {
        "paths": (
            "src/verifier/runtime/polish_inventory_authority.py",
        ),
        "kinds": {"PROTOCOL", "POLICY"},
        "refuted": set(),
        "blocked": set(),
    },
    "vstd-polish-public-authority": {
        "paths": (
            "src/verifier/runtime/polish_public_authority.py",
        ),
        "kinds": {"PROTOCOL", "POLICY"},
        "refuted": set(),
        "blocked": set(),
    },
    "vstd-prdel-coverage-policy": {
        "paths": (
            "src/verifier/runtime/prdel_coverage.py",
        ),
        "kinds": {"POLICY"},
        "refuted": set(),
        "blocked": set(),
    },
    "vstd-prdel-impact-graph": {
        "paths": (
            "src/verifier/runtime/prdel_graph.py",
        ),
        "kinds": {"POLICY"},
        "refuted": set(),
        "blocked": set(),
    },
    "vstd-prdel-source-compiler": {
        "paths": (
            "src/verifier/runtime/prdel_rules.py",
        ),
        "kinds": {"MEASUREMENT", "SENSOR", "ACTUATOR", "PROTOCOL", "POLICY"},
        "refuted": set(),
        "blocked": set(),
    },
    "vstd-prdel-shard-protocol": {
        "paths": (
            "src/verifier/runtime/prdel_shards.py",
            "src/verifier/runtime/prdel_shard_index.py",
        ),
        "kinds": {"MEASUREMENT", "SENSOR", "ACTUATOR", "PROTOCOL", "POLICY"},
        "refuted": set(),
        "blocked": set(),
    },
    "vstd-prdel-v2-shard-protocol": {
        "paths": (
            "src/verifier/runtime/prdel_v2_shards.py",
        ),
        "kinds": {"PROTOCOL", "POLICY"},
        "refuted": set(),
        "blocked": set(),
    },
    "vstd-public-checkability-protocol": {
        "paths": (
            "src/verifier/runtime/public_checkability.py",
        ),
        "kinds": {"PROTOCOL", "POLICY"},
        "refuted": set(),
        "blocked": set(),
    },
}

# Any remaining entry here is an intentional central role whose source audit is
# still unresolved.  Reconciled source-established roles must not remain hidden.
OWNERSHIP_UNESTABLISHED = {
}


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
            "reason": "Synthetic exact owner for polish semantic-review tests.",
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


def test_review_document_is_complete_exact_and_defensive():
    catalog = review.review_document()
    registry = namespace_registry()

    assert tuple(catalog) == review.POLISH_OBJECT_IDS
    assert set(catalog) == set(EXPECTED)
    assert len(catalog) == 18
    assert sum(len(item["owned_paths"]) for item in catalog.values()) == 23
    assert sum(len(item["classification"]) for item in catalog.values()) == 216
    assert sum(len(item["declarations"]) for item in catalog.values()) == 186

    statuses = [
        decision["status"]
        for item in catalog.values()
        for decision in item["classification"].values()
    ]
    assert statuses.count("APPLIES") == 62
    assert statuses.count("DOES_NOT_APPLY") == 0
    assert statuses.count("UNRESOLVED") == 154

    all_paths = []
    for object_id, item in catalog.items():
        expected = EXPECTED[object_id]
        assert tuple(item["owned_paths"]) == expected["paths"]
        all_paths.extend(item["owned_paths"])
        assert set(item["classification"]) == set(review.REVIEW_KINDS)
        for kind, decision in item["classification"].items():
            if kind in expected["kinds"]:
                status = "APPLIES"
            elif kind in expected["refuted"]:
                status = "DOES_NOT_APPLY"
            else:
                status = "UNRESOLVED"
            assert decision["status"] == status, (object_id, kind)
            assert decision["reason"].strip()
            if status == "UNRESOLVED":
                assert decision["evidence_paths"] == []
                assert "cannot refute a " + kind + " role" in decision["reason"]
            elif status == "DOES_NOT_APPLY":
                assert decision["evidence_paths"] == list(expected["paths"])
                assert "AST census" in decision["reason"]
            else:
                assert decision["evidence_paths"]
                assert set(decision["evidence_paths"]) <= set(item["owned_paths"])
                assert ("did not establish this kind" in decision["reason"]) == (
                    kind in expected["blocked"]
                )
        expected_declarations = {
            obligation["id"]: set(obligation["declaration_fields"])
            for kind in expected["kinds"]
            for obligation in requirements_for(registry, (kind,))
            if obligation["kind"] == kind
        }
        assert set(item["declarations"]) == set(expected_declarations)
        for obligation_id, declaration in item["declarations"].items():
            assert set(declaration) == expected_declarations[obligation_id]
            assert all(value.strip() for value in declaration.values())
        assert "Tier-0" in item["claim_boundary"]
        assert "Tier-1-plus" in item["claim_boundary"]

    assert len(all_paths) == len(set(all_paths)) == 23
    catalog["vstd-tier-progression-controller"]["owned_paths"].clear()
    assert review.review_document()["vstd-tier-progression-controller"]["owned_paths"]


def test_ownership_gaps_are_pinned_not_silently_granted():
    from verifier.runtime.package_semantic_ownership import SEMANTIC_OWNERSHIP_SPECS

    catalog = review.review_document()
    specs = {
        spec.object_id: spec
        for spec in SEMANTIC_OWNERSHIP_SPECS
        if spec.object_id in catalog
    }
    assert set(specs) == set(catalog)
    for object_id, item in catalog.items():
        spec = specs[object_id]
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
        assert set(item["owned_paths"]) == set(spec.owned_paths)
        assert applies <= declared, object_id
        assert declared - applies == OWNERSHIP_UNESTABLISHED.get(object_id, set())


def test_role_evidence_is_exact_for_shards_and_all_other_owners():
    catalog = review.review_document()
    shards = catalog["vstd-prdel-shard-protocol"]
    active = ["src/verifier/runtime/prdel_shards.py"]
    both = set(shards["owned_paths"])

    for kind in ("MEASUREMENT", "ACTUATOR"):
        assert shards["classification"][kind]["evidence_paths"] == active
    for kind in ("PROTOCOL", "POLICY"):
        assert set(shards["classification"][kind]["evidence_paths"]) == both
    for kind in ("TRANSACTION",):
        assert shards["classification"][kind]["status"] == "UNRESOLVED"

    for object_id, item in catalog.items():
        for kind, decision in item["classification"].items():
            if (
                decision["status"] == "APPLIES"
                and object_id != "vstd-prdel-shard-protocol"
            ):
                assert set(decision["evidence_paths"]) == set(item["owned_paths"])


def test_claim_boundaries_never_promote_assessment_or_authority():
    catalog = review.review_document()

    progression = catalog["vstd-tier-progression-controller"]
    assert (
        "never authorizes release" in progression["classification"]["POLICY"]["reason"]
    )
    release = catalog["vstd-application-release-controller"]
    assert "never authorizes release" in release["classification"]["POLICY"]["reason"]
    recheck = catalog["vstd-package-self-polish-rechecker"]
    assert "never promotes" in recheck["classification"]["POLICY"]["reason"]
    engine = catalog["vstd-polish-assessment-engine"]
    assert engine["primary_kind"] == "VERIFIER"
    assert (
        "polished remains false"
        in engine["classification"]["POLICY"]["reason"].lower()
    )
    command = catalog["vstd-polish-command-controller"]
    assert command["primary_kind"] == "CONTROLLER"
    assert "not a sandbox" in command["classification"]["POLICY"]["reason"]
    inventory = catalog["vstd-polish-inventory-authority"]
    assert "legal authority" in inventory["classification"]["PROTOCOL"]["reason"]
    public = catalog["vstd-public-checkability-protocol"]
    assert "does not publish" in public["classification"]["PROTOCOL"]["reason"]
    compiler = catalog["vstd-prdel-source-compiler"]
    assert "explanation truth" in compiler["classification"]["POLICY"]["reason"]

    for object_id, item in catalog.items():
        assert item["classification"]["ASSET"]["status"] == "UNRESOLVED"
        assert item["classification"]["MARKET"]["status"] == "UNRESOLVED"
        for kind in ("ROBOT", "FINBOT"):
            decision = item["classification"][kind]
            if kind in EXPECTED[object_id]["refuted"]:
                assert decision["status"] == "DOES_NOT_APPLY"
                assert "does not apply as " + kind in decision["reason"]
                assert "AST census" in decision["reason"]
            else:
                assert decision["status"] == "UNRESOLVED"


def test_apply_is_pure_deterministic_complete_and_idempotent(tmp_path):
    root, rows, files = _workspace(tmp_path)
    before = deepcopy(rows)

    first = review.apply_package_semantic_review_polish(root, rows, files)
    second = review.apply_package_semantic_review_polish(root, first, files)

    assert rows == before
    assert first == second
    for object_id, row in first.items():
        applies = EXPECTED[object_id]["kinds"]
        paths = set(EXPECTED[object_id]["paths"])
        assert {
            kind
            for kind, decision in row["classification"].items()
            if decision["status"] == "APPLIES"
        } == applies
        assert applies - {row["kind"]} <= set(row["specializations"])
        assert all(name.split("-", 1)[0] in applies for name in row["obligations"])
        assert all(
            binding["reason"].strip()
            and binding["evidence"]
            and all(value.strip() for value in binding["declaration"].values())
            for binding in row["obligations"].values()
        )
        for decision in row["classification"].values():
            evidence = {entry["path"] for entry in decision["evidence"]}
            if decision["status"] == "UNRESOLVED":
                assert evidence == set()
            elif decision["status"] == "DOES_NOT_APPLY":
                assert evidence == paths
            else:
                assert evidence and evidence <= paths


def test_apply_preserves_only_exact_complete_current_reviews(tmp_path):
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_polish(root, rows, files)
    assert review.apply_package_semantic_review_polish(root, selected, files) == selected

    item = selected["vstd-prdel-shard-protocol"]
    item["classification"]["MEASUREMENT"]["reason"] = (
        "Substituted noncanonical MEASUREMENT applicability."
    )
    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT"):
        review.apply_package_semantic_review_polish(root, selected, files)


def test_unlisted_basis_and_unknown_object_never_acquire_complement_refutation(
    tmp_path, monkeypatch
):
    object_id = "vstd-tier-progression-controller"
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
    result = review.apply_package_semantic_review_polish(root, rows, files)
    assert result[object_id]["classification"]["LEDGER"] == {
        "status": "UNRESOLVED",
        "reason": review._unresolved_reason("LEDGER"),
        "evidence": [],
    }
    assert result["unknown-future-owner"] == rows["unknown-future-owner"]


def _complement_table(original):
    refuted = ("FINBOT", "LEDGER", "ROBOT", "TRANSACTION")
    applicable = tuple(k for k in review.REVIEW_KINDS if k not in refuted)
    return replace(
        original,
        applicable=applicable,
        role_paths={kind: original.owned_paths for kind in applicable},
        refuted=refuted,
        anchors={kind: "polish.py:1" for kind in applicable},
        blocked=(),
    )


def _unaudited_table(original):
    applicable = ("POLICY",)
    return replace(
        original,
        applicable=applicable,
        role_paths={kind: original.owned_paths for kind in applicable},
        refuted=("MEASUREMENT", "ROBOT", "FINBOT"),
        anchors={kind: "polish_findings.py:1" for kind in applicable},
        blocked=(),
    )


@pytest.mark.parametrize(
    ("object_id", "failure", "message"),
    [
        (
            "vstd-polish-capacity-policy",
            "complement",
            "refutation table is complement-shaped",
        ),
        (
            "vstd-polish-findings-projection",
            "unaudited",
            "without an audited channel census",
        ),
        (
            "vstd-tier-progression-controller",
            "blocked_not_primary",
            "blocks a kind other than its primary kind",
        ),
        (
            "vstd-tier-progression-controller",
            "missing_anchor",
            "APPLIES lacks an exact source anchor",
        ),
    ],
)
def test_catalog_check_rejects_complement_unaudited_or_unanchored_tables(
    monkeypatch, object_id, failure, message
):
    original = review._REVIEWS[object_id]
    if failure == "complement":
        replacement = _complement_table(original)
    elif failure == "unaudited":
        replacement = _unaudited_table(original)
    elif failure == "blocked_not_primary":
        replacement = replace(
            original,
            blocked=("ACTUATOR",),
            anchors={k: v for k, v in original.anchors.items() if k != "ACTUATOR"},
        )
    else:
        replacement = replace(
            original,
            anchors={k: v for k, v in original.anchors.items() if k != "POLICY"},
        )
    monkeypatch.setitem(review._REVIEWS, object_id, replacement)
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
    tmp_path, monkeypatch, source
):
    # The reviewed table refutes no polish kind, so refute ROBOT here to exercise
    # the census gate on a synthetic owner.
    original = review._REVIEWS["vstd-polish-capacity-policy"]
    monkeypatch.setitem(
        review._REVIEWS,
        "vstd-polish-capacity-policy",
        replace(original, refuted=("ROBOT",)),
    )
    root, rows, files = _workspace(tmp_path)
    target = "src/verifier/runtime/polish_capacity.py"
    raw = source.encode()
    (root / target).write_bytes(raw)
    files[target] = _digest(raw)
    before = deepcopy(rows)

    with pytest.raises(
        ValueError,
        match="PACKAGE_SEMANTIC_REVIEW_REFUTATION_CHANNEL_PRESENT:vstd-polish-capacity-policy:",
    ):
        review.apply_package_semantic_review_polish(root, rows, files)
    assert rows == before


def test_apply_rejects_prior_complete_decision_on_now_unresolved_kind(tmp_path):
    root, rows, files = _workspace(tmp_path)
    path = "src/verifier/runtime/prdel_graph.py"
    rows["vstd-prdel-impact-graph"]["classification"]["MEASUREMENT"] = {
        "status": "DOES_NOT_APPLY",
        "reason": "Earlier audit refuted MEASUREMENT.",
        "evidence": [{"path": path, "sha256": files[path]}],
    }
    before = deepcopy(rows)

    with pytest.raises(
        ValueError,
        match="PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT:vstd-prdel-impact-graph:MEASUREMENT",
    ):
        review.apply_package_semantic_review_polish(root, rows, files)
    assert rows == before


def test_apply_rejects_same_status_refutation_copied_from_sibling(
    tmp_path, monkeypatch
):
    original = review._REVIEWS["vstd-polish-capacity-policy"]
    monkeypatch.setitem(
        review._REVIEWS,
        "vstd-polish-capacity-policy",
        replace(original, refuted=("ROBOT",)),
    )
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_polish(root, rows, files)
    assert selected["vstd-polish-capacity-policy"]["classification"]["ROBOT"][
        "status"
    ] == "DOES_NOT_APPLY"
    selected["vstd-prdel-impact-graph"]["classification"]["ROBOT"] = deepcopy(
        selected["vstd-polish-capacity-policy"]["classification"]["ROBOT"]
    )
    before = deepcopy(selected)

    with pytest.raises(
        ValueError,
        match="PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT:vstd-prdel-impact-graph:ROBOT",
    ):
        review.apply_package_semantic_review_polish(root, selected, files)
    assert selected == before


@pytest.mark.parametrize("failure", ["stale", "missing", "unowned", "extra_owned"])
def test_apply_rejects_source_or_ownership_drift_without_mutation(tmp_path, failure):
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-public-checkability-protocol"
    path = review.review_document()[object_id]["owned_paths"][0]
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
        review.apply_package_semantic_review_polish(root, rows, files)
    assert rows == before


@pytest.mark.parametrize(
    "failure",
    [
        "status",
        "applies_reason_substitution",
        "applies_evidence_substitution",
        "obligation_reason_substitution",
        "stale_decision",
        "unowned_decision",
        "partial_declaration",
        "refuted_declaration",
        "malformed_unresolved",
        "label_conflict",
        "unknown_obligation",
    ],
)
def test_apply_rejects_conflicting_partial_or_unowned_reviews_atomically(
    tmp_path, failure
):
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_polish(root, rows, files)
    progression = selected["vstd-tier-progression-controller"]
    shards = selected["vstd-prdel-shard-protocol"]
    if failure == "status":
        progression["classification"]["POLICY"]["status"] = "DOES_NOT_APPLY"
    elif failure == "applies_reason_substitution":
        progression["classification"]["POLICY"]["reason"] = (
            "Substituted noncanonical POLICY applicability."
        )
    elif failure == "applies_evidence_substitution":
        progression["classification"]["POLICY"]["evidence"] = deepcopy(
            shards["classification"]["POLICY"]["evidence"]
        )
    elif failure == "obligation_reason_substitution":
        progression["obligations"]["POLICY-0.1-rules-and-precedence"]["reason"] = (
            "Substituted noncanonical obligation reason."
        )
    elif failure == "stale_decision":
        progression["classification"]["POLICY"]["evidence"][0]["sha256"] = (
            "sha256:" + "f" * 64
        )
    elif failure == "unowned_decision":
        foreign = review.review_document()["vstd-polish-capacity-policy"][
            "owned_paths"
        ][0]
        shards["classification"]["MEASUREMENT"]["evidence"] = [
            {"path": foreign, "sha256": files[foreign]}
        ]
    elif failure == "partial_declaration":
        progression["obligations"]["POLICY-0.1-rules-and-precedence"]["declaration"][
            "scope"
        ] = ""
    elif failure == "refuted_declaration":
        progression["obligations"]["ASSET-0.1-identity-and-quantity"] = {
            "reason": "Contradictory ASSET declaration.",
            "evidence": deepcopy(progression["classification"]["ASSET"]["evidence"]),
            "declaration": {
                field: "Contradictory " + field
                for field in ("identity", "rights", "units", "precision")
            },
        }
    elif failure == "malformed_unresolved":
        progression["classification"]["ASSET"] = {
            "status": "UNRESOLVED",
            "reason": "",
            "evidence": [],
        }
    elif failure == "label_conflict":
        progression["specializations"].append("ASSET")
    else:
        progression["obligations"]["POLICY-0.99-invented"] = {
            "reason": "Invented.",
            "evidence": [],
            "declaration": {},
        }
    before = deepcopy(selected)

    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_"):
        review.apply_package_semantic_review_polish(root, selected, files)
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
def test_channel_census_detects_exact_owned_bytes_only(tmp_path, source):
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
def test_channel_census_rejects_unverifiable_sources(tmp_path, source):
    (tmp_path / "owned.py").write_text(source, encoding="utf-8")
    with pytest.raises(
        ValueError, match="PACKAGE_SEMANTIC_REVIEW_CHANNEL_UNVERIFIABLE:owned.py"
    ):
        channel_census(tmp_path, ("owned.py",))


def test_refutations_match_exact_repository_channel_census():
    repo = Path(__file__).resolve().parents[1]
    catalog = review.review_document()
    for object_id, item in catalog.items():
        census = channel_census(repo, tuple(item["owned_paths"]))
        for kind in EXPECTED[object_id]["refuted"]:
            present = [channel for channel in REFUTABLE_CHANNELS[kind] if census[channel]]
            assert present == [], (object_id, kind, present)


def test_apply_rechecks_all_sources_after_semantic_preflight(tmp_path, monkeypatch):
    root, rows, files = _workspace(tmp_path)
    target = review.review_document()["vstd-public-checkability-protocol"][
        "owned_paths"
    ][0]
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
        review.apply_package_semantic_review_polish(root, rows, files)
    assert rows == before


@pytest.mark.parametrize(
    ("root_value", "rows_value", "files_value", "code"),
    [
        ("missing", {}, {}, "ROOT_INVALID"),
        (None, [], {}, "ROWS_INVALID"),
        (None, {}, {"x": "not-a-digest"}, "FILES_INVALID"),
    ],
)
def test_apply_rejects_invalid_top_level_inputs(
    tmp_path, root_value, rows_value, files_value, code
):
    root = tmp_path / "missing" if root_value == "missing" else tmp_path
    with pytest.raises(
        (FileNotFoundError, ValueError), match=code if code != "ROOT_INVALID" else None
    ):
        review.apply_package_semantic_review_polish(root, rows_value, files_value)


@pytest.mark.parametrize(
    ("source", "open_surface", "channels"),
    [
        ("import importlib\nimportlib.util\n", True, set()),
        ("from verifier.runtime import tier_zero\n", True, set()),
        ("x = list(map(getattr, [object], ['__class__']))\n", True, set()),
        ("f = filter\nf(None, [])\n", True, set()),
        ("import os\nos.getcwd()\n", False, set()),
        ("import subprocess as sp\n", True, {"PROC"}),
        ("from subprocess import Popen\n", True, {"PROC"}),
        ("from os import system\nsystem('x')\n", True, {"PROC"}),
        ("import os\nos.system('x')\n", True, {"PROC"}),
        ("def run(fn):\n    return fn()\n", True, set()),
        (
            "class A:\n    def go(self):\n        return self.missing()\n",
            True,
            set(),
        ),
    ],
)
def test_surface_census_closes_only_pure_or_censused_imports(
    tmp_path, source, open_surface, channels
):
    (tmp_path / "owned.py").write_text(source, encoding="utf-8")
    findings = surface_findings(tmp_path, ("owned.py",))["owned.py"]
    census = channel_census(tmp_path, ("owned.py",))
    assert bool(findings) == open_surface, (source, findings)
    assert {name for name, present in census.items() if present} == channels


@pytest.mark.parametrize(
    ("source", "accepted"),
    [
        ("import importlib\n", False),
        ("import os\nos.getcwd()\n", True),
    ],
)
def test_refutation_requires_closed_surface_at_application(
    tmp_path, monkeypatch, source, accepted
):
    original = review._REVIEWS["vstd-polish-capacity-policy"]
    monkeypatch.setitem(
        review._REVIEWS,
        "vstd-polish-capacity-policy",
        replace(original, refuted=("ROBOT",)),
    )
    root, rows, files = _workspace(tmp_path)
    target = "src/verifier/runtime/polish_capacity.py"
    raw = source.encode()
    (root / target).write_bytes(raw)
    files[target] = _digest(raw)
    before = deepcopy(rows)

    if accepted:
        selected = review.apply_package_semantic_review_polish(root, rows, files)
        assert selected["vstd-polish-capacity-policy"]["classification"]["ROBOT"][
            "status"
        ] == "DOES_NOT_APPLY"
    else:
        with pytest.raises(
            ValueError,
            match="PACKAGE_SEMANTIC_REVIEW_REFUTATION_SURFACE_OPEN:vstd-polish-capacity-policy",
        ):
            review.apply_package_semantic_review_polish(root, rows, files)
        assert rows == before


def _census_of(tmp_path, source):
    (tmp_path / "owned.py").write_text(source, encoding="utf-8")
    census = channel_census(tmp_path, ("owned.py",))
    return {name for name, present in census.items() if present}


@pytest.mark.parametrize(
    ("source", "channels"),
    [
        # Effects reached as values, not calls, still exist in the owned bytes.
        ("import os\nlist(map(os.system, ['x']))\n", {"PROC"}),
        ("import os as o\nlist(map(o.popen, ['x']))\n", {"PROC"}),
        ("from os import popen as p\nalias = p\n", {"PROC"}),
        ("import os\nf = map(getattr(os, 'system'), ['x'])\n", {"PROC"}),
        ("import os\nsystem = getattr(os, 'system')\n", {"PROC"}),
        ("from pathlib import Path\nlist(map(Path.unlink, []))\n", {"WRITE"}),
        ("list(map(open, ['a']))\n", {"WRITE"}),
        ("import builtins\nopener = builtins.open\n", {"WRITE"}),
        ("import os\nx = os.system\n", {"PROC"}),
        ("import os\nlst = [os.system][0]\n", {"PROC"}),
        ("import os\nclass A:\n    run = os.system\n", {"PROC"}),
        ("import os\nlam = lambda: os.system('x')\n", {"PROC"}),
        ("import pathlib\nf = pathlib.Path.unlink\n", {"WRITE"}),
        ("import io\nlist(map(io.FileIO, ['x']))\n", {"WRITE"}),
        # Pure references stay channel-free.
        ("import json\nlist(map(json.loads, ['1']))\n", set()),
        ("import os\nsep = os.sep\n", set()),
    ],
)
def test_effect_references_without_a_call_are_channels(tmp_path, source, channels):
    assert _census_of(tmp_path, source) == channels


@pytest.mark.parametrize(
    "source",
    [
        "open(b'/dev/ttyS0', 'rb')\n",
        "open('COM3', 'rb')\n",
        "device = '//./PhysicalDrive0'\n",
        "device = 'LPT1'\n",
        "import os\nos.path.join('/dev', 'tty')\n",
        "from os import devnull\nopen(devnull, 'rb')\n",
        "import os\nopen(os.devnull, 'rb')\n",
    ],
)
def test_device_names_in_bytes_and_windows_forms_are_dev(tmp_path, source):
    assert _census_of(tmp_path, source) == {"DEV"}


@pytest.mark.parametrize(
    ("source", "channels"),
    [
        ("__import__('socket')\n", {"NET"}),
        ("import importlib as il\nil.import_module('subprocess')\n", {"PROC"}),
    ],
)
def test_literal_dynamic_imports_name_their_channel(tmp_path, source, channels):
    assert _census_of(tmp_path, source) == channels


@pytest.mark.parametrize(
    "source",
    [
        "__import__('os').system('x')\n",
        "import builtins\nbuiltins.__import__('io')\n",
    ],
)
def test_dynamic_import_of_censused_module_is_unverifiable(tmp_path, source):
    # A censused module reached dynamically cannot be classified call by call.
    (tmp_path / "owned.py").write_text(source, encoding="utf-8")
    with pytest.raises(
        ValueError, match="PACKAGE_SEMANTIC_REVIEW_CHANNEL_UNVERIFIABLE:owned.py"
    ):
        channel_census(tmp_path, ("owned.py",))


@pytest.mark.parametrize(
    "source",
    [
        "import os\nholder = [os]\n",
        "def run(cb, xs):\n    return sorted(xs, key=cb)\n",
        "import functools\n\n\ndef run(cb, xs):\n    return functools.reduce(cb, xs)\n",
        "def run(cb, xs):\n    return pool.submit(cb, xs)\n",
        "def run(cb, items):\n    items.sort(key=cb)\n",
        "import re\n\n\ndef run(cb, text):\n    return re.sub('a', cb, text)\n",
        "import json\n\n\ndef run(cb, text):\n    return json.loads(text, object_hook=cb)\n",
        "import unknown_lib\n\n\ndef run(value):\n    return unknown_lib.call(value)\n",
    ],
)
def test_module_objects_and_callable_values_open_the_surface(tmp_path, source):
    (tmp_path / "owned.py").write_text(source, encoding="utf-8")
    assert surface_findings(tmp_path, ("owned.py",))["owned.py"] != ()


@pytest.mark.parametrize(
    "source",
    [
        "def run(xs):\n    return len(xs)\n",
        "def run(xs):\n    return sorted(xs)\n",
        "def run(items):\n    items.sort()\n",
        "import json\nvalue = json.dumps({'a': 1})\n",
        "import os\nlocation = os.path.join('a', 'b')\n",
        # Data parameters handed to known data callees never invoke them.
        "import json\n\n\ndef run(value):\n    return json.dumps(value)\n",
        "import hashlib\n\n\ndef run(data):\n    return hashlib.sha256(data).hexdigest()\n",
        "def run(path):\n    return open(path).read()\n",
    ],
)
def test_pure_references_keep_the_surface_closed(tmp_path, source):
    (tmp_path / "owned.py").write_text(source, encoding="utf-8")
    assert surface_findings(tmp_path, ("owned.py",))["owned.py"] == ()


def test_refutation_rejected_when_a_value_reference_reaches_a_channel(
    tmp_path, monkeypatch
):
    # The exact counterexample: the surface gate was closed while os.system ran.
    original = review._REVIEWS["vstd-polish-capacity-policy"]
    monkeypatch.setitem(
        review._REVIEWS,
        "vstd-polish-capacity-policy",
        replace(original, refuted=("ROBOT",)),
    )
    root, rows, files = _workspace(tmp_path)
    target = "src/verifier/runtime/polish_capacity.py"
    raw = b"import os\nlist(map(os.system, ['x']))\n"
    (root / target).write_bytes(raw)
    files[target] = _digest(raw)
    before = deepcopy(rows)

    with pytest.raises(
        ValueError,
        match="PACKAGE_SEMANTIC_REVIEW_REFUTATION_CHANNEL_PRESENT:vstd-polish-capacity-policy:",
    ):
        review.apply_package_semantic_review_polish(root, rows, files)
    assert rows == before


@pytest.mark.parametrize("failure", ["sibling_specialization", "own_specialization"])
def test_refuted_role_cannot_accumulate_as_a_specialization(
    tmp_path, monkeypatch, failure
):
    original = review._REVIEWS["vstd-polish-capacity-policy"]
    monkeypatch.setitem(
        review._REVIEWS,
        "vstd-polish-capacity-policy",
        replace(original, refuted=("ROBOT",)),
    )
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_polish(root, rows, files)
    target = (
        "vstd-prdel-impact-graph"
        if failure == "sibling_specialization"
        else "vstd-polish-capacity-policy"
    )
    selected[target]["specializations"].append("ROBOT")
    before = deepcopy(selected)

    with pytest.raises(
        ValueError,
        match="PACKAGE_SEMANTIC_REVIEW_LABEL_CONFLICT:" + target + ":ROBOT",
    ):
        review.apply_package_semantic_review_polish(root, selected, files)
    assert selected == before


@pytest.mark.parametrize("failure", ["reason", "foreign_referent"])
def test_refutation_decision_rejects_reason_or_referent_substitution(
    tmp_path, monkeypatch, failure
):
    original = review._REVIEWS["vstd-polish-capacity-policy"]
    monkeypatch.setitem(
        review._REVIEWS,
        "vstd-polish-capacity-policy",
        replace(original, refuted=("ROBOT",)),
    )
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_polish(root, rows, files)
    decision = selected["vstd-polish-capacity-policy"]["classification"]["ROBOT"]
    if failure == "reason":
        decision["reason"] = "Recorded refutation of ROBOT."
    else:
        # A byte-identical sibling owner is a different referent, not this object.
        foreign = review.review_document()["vstd-prdel-impact-graph"]["owned_paths"][0]
        decision["evidence"] = [{"path": foreign, "sha256": files[foreign]}]
    before = deepcopy(selected)

    with pytest.raises(
        ValueError,
        match="PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT:vstd-polish-capacity-policy:ROBOT",
    ):
        review.apply_package_semantic_review_polish(root, selected, files)
    assert selected == before


@pytest.mark.parametrize(
    ("source", "code"),
    [
        ("import socket\n", "REFUTATION_CHANNEL_PRESENT"),
        ("import importlib\n", "REFUTATION_SURFACE_OPEN"),
    ],
)
def test_refutation_covers_every_owned_path_of_the_accumulated_role(
    tmp_path, monkeypatch, source, code
):
    object_id = "vstd-prdel-shard-protocol"
    original = review._REVIEWS[object_id]
    monkeypatch.setitem(review._REVIEWS, object_id, replace(original, refuted=("ROBOT",)))
    root, rows, files = _workspace(tmp_path)
    target = review.review_document()[object_id]["owned_paths"][1]
    raw = source.encode()
    (root / target).write_bytes(raw)
    files[target] = _digest(raw)

    with pytest.raises(
        ValueError, match="PACKAGE_SEMANTIC_REVIEW_" + code + ":" + object_id
    ):
        review.apply_package_semantic_review_polish(root, rows, files)


@pytest.mark.parametrize("name", ["VENDOR-1-extra", "POLICY-0.99-invented"])
def test_apply_rejects_obligations_outside_the_contract_vocabulary(tmp_path, name):
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-tier-progression-controller"
    rows[object_id]["obligations"][name] = {
        "reason": "Invented.",
        "evidence": [],
        "declaration": {},
    }
    before = deepcopy(rows)

    with pytest.raises(
        ValueError,
        match="PACKAGE_SEMANTIC_REVIEW_OBLIGATION_UNKNOWN:" + object_id + ":" + name,
    ):
        review.apply_package_semantic_review_polish(root, rows, files)
    assert rows == before


@pytest.mark.parametrize("kind", ["ROBOT", "TRANSACTION"])
def test_device_refutation_states_its_literal_only_boundary(kind):
    profile = review._REVIEWS["vstd-polish-capacity-policy"].profile
    reason = review.refutation_reason(profile, kind)
    assert "device-path literal" in reason
    assert "a runtime-built path is outside this census" in reason


def test_applies_anchors_name_owned_sources_and_existing_line_spans():
    # Stale or foreign anchors are rejected: each names an owned source and spans
    # lines that exist in it.  The anchor text itself is reviewed content.
    repo = Path(__file__).resolve().parents[1]
    for object_id, owner in review._REVIEWS.items():
        owned = {Path(path).name: path for path in owner.owned_paths}
        for kind, anchor in owner.anchors.items():
            assert kind in owner.applicable, (object_id, kind)
            for part in anchor.split("; "):
                name, _, spans = part.partition(":")
                assert name in owned, (object_id, kind, part)
                lines = (repo / owned[name]).read_text(encoding="utf-8").splitlines()
                for span in spans.split(","):
                    start, _, end = span.strip().partition("-")
                    first, last = int(start), int(end or start)
                    assert 1 <= first <= last <= len(lines), (object_id, kind, span)
