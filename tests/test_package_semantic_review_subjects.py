# Terminology: CBOR Object Signing and Encryption (COSE); JavaScript Object Notation (JSON);
# Supply Chain Integrity, Transparency, and Trust (SCITT).
from __future__ import annotations

from copy import deepcopy
import dataclasses
from hashlib import sha256
import json
import os
from pathlib import Path
import re

import pytest

from verifier.runtime.namespace_contracts import namespace_registry, requirements_for
from verifier.runtime import package_semantic_review_subjects as review


EXPECTED_PATHS = {
    "vstd-artifact-control-lifecycle": {
        "src/verifier/artifact_control/__init__.py",
        "src/verifier/artifact_control/artifact-control-1.schema.json",
        "src/verifier/schemas/artifact-control-1.schema.json",
    },
    "vstd-privacy-emission-policy": {
        "src/verifier/controlled_emission.py",
        "src/verifier/privacy/__init__.py",
        "src/verifier/privacy/adapters.py",
        "src/verifier/privacy/composition.py",
        "src/verifier/privacy/current_certificate_emission.py",
        "src/verifier/privacy/engine.py",
        "src/verifier/privacy/independence.py",
        "src/verifier/privacy/models.py",
    },
    "vstd-logit-constraint-controller": {
        "src/verifier/constraints/__init__.py",
        "src/verifier/constraints/kernel.py",
        "src/verifier/constraints/llguidance_backend.py",
        "src/verifier/constraints/postvalidate.py",
        "src/verifier/constraints/torch_mask.py",
    },
    "vstd-hardware-resource-accounting": {"src/verifier/hardware/fleet.py"},
    "vstd-software-diode-effect": {"src/verifier/hardware/diode_emulator.py"},
    "vstd-component-package-storage": {
        "src/verifier/interoperability/storage.py",
        "src/verifier/schemas/verifier-component-package-1.schema.json",
        "src/verifier/schemas/verifier-component-package-2.schema.json",
    },
    "vstd-hardware-receipt-publication": {"src/verifier/hardware/receipt.py"},
    "vstd-deriver-process-exchange": {
        "src/verifier/interoperability/deriver_self_status.py"
    },
    "vstd-scitt-evidence-protocol": {
        "src/verifier/interoperability/scitt/__init__.py",
        "src/verifier/interoperability/scitt/adapter.py",
        "src/verifier/interoperability/scitt/derived_subjects.py",
        "src/verifier/interoperability/scitt/evidence_profiles.py",
    },
}

EXPECTED_APPLICABILITY = {
    "vstd-artifact-control-lifecycle": {"TRANSACTION", "PROTOCOL"},
    "vstd-privacy-emission-policy": {"LEDGER", "TRANSACTION", "POLICY"},
    "vstd-logit-constraint-controller": {
        "TRANSACTION",
        "MEASUREMENT",
        "SENSOR",
        "CONTROLLER",
        "ACTUATOR",
        "PROTOCOL",
        "POLICY",
    },
    "vstd-hardware-resource-accounting": {"ASSET", "MEASUREMENT", "POLICY"},
    "vstd-software-diode-effect": {
        "TRANSACTION",
        "MEASUREMENT",
        "SENSOR",
        "ACTUATOR",
        "PROTOCOL",
    },
    "vstd-component-package-storage": {"TRANSACTION"},
    "vstd-hardware-receipt-publication": {"TRANSACTION"},
    "vstd-deriver-process-exchange": {
        "TRANSACTION",
        "MEASUREMENT",
        "SENSOR",
        "CONTROLLER",
        "ACTUATOR",
        "PROTOCOL",
    },
    "vstd-scitt-evidence-protocol": {"PROTOCOL", "POLICY"},
}

# Literal per-object DOES_NOT_APPLY catalog.  The deriver exchange has only a MARKET
# refutation: its effect domain is not sandboxed, so ROBOT and FINBOT stay UNRESOLVED.
# The privacy emitter reaches the same unsandboxed effect surface through the
# certificate recheck, so its PROTOCOL, ROBOT, and FINBOT are UNRESOLVED too.
EXPECTED_REFUTED = {
    "vstd-artifact-control-lifecycle": {"ASSET", "FINBOT", "ROBOT", "MARKET"},
    "vstd-privacy-emission-policy": {"ASSET", "MARKET"},
    "vstd-logit-constraint-controller": {"ASSET", "FINBOT", "ROBOT", "MARKET"},
    "vstd-hardware-resource-accounting": {"SENSOR", "TRANSACTION", "ROBOT", "FINBOT", "MARKET"},
    "vstd-software-diode-effect": {"ASSET", "FINBOT", "ROBOT", "MARKET"},
    "vstd-component-package-storage": {"FINBOT", "PROTOCOL", "ROBOT", "MARKET"},
    "vstd-hardware-receipt-publication": {"LEDGER", "PROTOCOL", "ROBOT", "FINBOT", "MARKET"},
    "vstd-deriver-process-exchange": {"MARKET"},
    "vstd-scitt-evidence-protocol": {"LEDGER", "TRANSACTION", "ROBOT", "FINBOT", "MARKET"},
}
# Output-level DOES_NOT_APPLY cells after the static demotions and the live closed-surface
# screen.  Every owned closure is OPEN (reflection, fixed-argument process launch, filesystem
# writes, or a package __init__ that reaches one), so no refutation is decided DOES_NOT_APPLY.
EXPECTED_DOES_NOT_APPLY = {object_id: set() for object_id in EXPECTED_REFUTED}
CANONICAL_UNRESOLVED = (
    "Migration retains this applicability question. Static ownership alone cannot "
    "refute a {kind} role."
)


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


def _synthetic_bytes(object_id: str, path: str) -> bytes:
    """Valid, import-free owned bytes: a Python comment for .py and JSON for schemas.

    NUL bytes would be PYTHON_SYNTAX_ERROR blockers in the closed-surface screen, so
    synthetic sources must parse; their closure is then exactly the owned file.
    """
    if path.endswith(".json"):
        return (json.dumps({"object_id": object_id, "path": path}, sort_keys=True) + "\n").encode()
    return ("# Synthetic owned source for " + object_id + " at " + path + ".\n").encode()


def _exact_evidence(object_id: str, files: dict[str, str]) -> list[dict[str, str]]:
    """Current evidence for every owned path of one object, in catalog order."""
    return [
        {"path": path, "sha256": files[path]}
        for path in review._REVIEWS[object_id].owned_paths
    ]


def _workspace(tmp_path: Path) -> tuple[Path, dict[str, dict], dict[str, str]]:
    rows = {}
    files = {}
    for object_id, item in review.review_document().items():
        for path in item["owned_paths"]:
            target = tmp_path / path
            target.parent.mkdir(parents=True, exist_ok=True)
            raw = _synthetic_bytes(object_id, path)
            target.write_bytes(raw)
            files[path] = _digest(raw)
        rows[object_id] = {
            "object_id": object_id,
            "kind": item["primary_kind"],
            "specializations": [],
            "payload": {},
            "operands": {},
            "surfaces": ["file:" + path for path in item["owned_paths"]],
            "reason": "Synthetic exact owner for subject-review tests.",
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


def test_review_document_closes_exact_object_kind_and_path_denominators() -> None:
    catalog = review.review_document()
    registry = namespace_registry()

    assert tuple(catalog) == review.SUBJECT_OBJECT_IDS
    assert set(catalog) == set(EXPECTED_PATHS) == set(EXPECTED_APPLICABILITY)
    assert len(catalog) == 9
    assert sum(len(item["owned_paths"]) for item in catalog.values()) == 27
    assert sum(len(item["classification"]) for item in catalog.values()) == 108
    assert sum(len(item["declarations"]) for item in catalog.values()) == 90

    all_paths = []
    for object_id, item in catalog.items():
        assert set(item["owned_paths"]) == EXPECTED_PATHS[object_id]
        all_paths.extend(item["owned_paths"])
        assert set(item["classification"]) == set(review.REVIEW_KINDS)
        applies = {
            kind
            for kind, decision in item["classification"].items()
            if decision["status"] == "APPLIES"
        }
        assert applies == EXPECTED_APPLICABILITY[object_id]
        assert {
            kind
            for kind, decision in item["classification"].items()
            if decision["status"] == "DOES_NOT_APPLY"
        } == EXPECTED_DOES_NOT_APPLY[object_id]
        for kind, decision in item["classification"].items():
            assert decision["reason"].strip()
            if decision["status"] == "UNRESOLVED":
                assert decision["reason"] == CANONICAL_UNRESOLVED.format(kind=kind)
                assert decision["evidence_paths"] == []
            else:
                assert decision["status"] in {"APPLIES", "DOES_NOT_APPLY"}
                assert decision["evidence_paths"]
                assert set(decision["evidence_paths"]) <= set(item["owned_paths"])
        expected = {
            obligation["id"]: set(obligation["declaration_fields"])
            for kind in applies
            for obligation in requirements_for(registry, (kind,))
            if obligation["kind"] == kind
        }
        assert set(item["declarations"]) == set(expected)
        for obligation_id, declaration in item["declarations"].items():
            assert set(declaration) == expected[obligation_id]
            assert all(value.strip() for value in declaration.values())
        assert "application-wide" in item["claim_boundary"]
        assert "Tier-1-plus" in item["claim_boundary"]
    assert len(all_paths) == len(set(all_paths))

    catalog["vstd-privacy-emission-policy"]["owned_paths"].clear()
    assert review.review_document()["vstd-privacy-emission-policy"]["owned_paths"]


def test_role_evidence_and_consequence_boundaries_remain_narrow() -> None:
    catalog = review.review_document()

    privacy = catalog["vstd-privacy-emission-policy"]
    assert privacy["classification"]["LEDGER"]["evidence_paths"] == [
        "src/verifier/privacy/adapters.py"
    ]
    assert (
        "in-memory"
        in privacy["declarations"]["LEDGER-0.1-authoritative-history"]["authority"]
    )

    logits = catalog["vstd-logit-constraint-controller"]
    assert set(logits["classification"]["ACTUATOR"]["evidence_paths"]) == {
        "src/verifier/constraints/llguidance_backend.py",
        "src/verifier/constraints/torch_mask.py",
    }
    assert (
        "IN_PROCESS_LOGIT_TENSOR"
        in logits["declarations"]["ACTUATOR-0.1-command-to-effect"]["effect_domains"]
    )

    accounting = catalog["vstd-hardware-resource-accounting"]
    assert accounting["classification"]["ASSET"]["status"] == "APPLIES"
    assert "not legal title" in accounting["classification"]["ASSET"]["reason"]

    storage = catalog["vstd-component-package-storage"]
    assert storage["classification"]["TRANSACTION"]["evidence_paths"] == [
        "src/verifier/interoperability/storage.py"
    ]
    assert storage["classification"]["ROBOT"] == {
        "status": "UNRESOLVED",
        "reason": CANONICAL_UNRESOLVED.format(kind="ROBOT"),
        "evidence_paths": [],
    }
    assert storage["classification"]["ASSET"]["status"] == "UNRESOLVED"

    diode = catalog["vstd-software-diode-effect"]
    assert (
        "NOT_PHYSICAL_ISOLATION"
        in diode["declarations"]["ACTUATOR-0.1-command-to-effect"]["effect_domains"]
    )
    # "imports only" describes the owned diode text (representation).  The package
    # __init__ closure it reaches is open, so the ROBOT cell is withheld (behavior).
    assert "imports only" in review._REVIEWS["vstd-software-diode-effect"].refuted["ROBOT"]
    assert diode["classification"]["ROBOT"]["status"] == "UNRESOLVED"
    deriver = catalog["vstd-deriver-process-exchange"]
    assert deriver["classification"]["ROBOT"]["status"] == "UNRESOLVED"
    assert deriver["classification"]["FINBOT"]["status"] == "UNRESOLVED"
    scitt = catalog["vstd-scitt-evidence-protocol"]
    assert "NOT_EVALUATED" in review._REVIEWS["vstd-scitt-evidence-protocol"].refuted["FINBOT"]
    assert scitt["classification"]["FINBOT"]["status"] == "UNRESOLVED"

    # ROBOT and FINBOT are emitted DOES_NOT_APPLY only where the catalog refutes them and
    # the live closed-surface screen has not withheld them.
    for object_id, item in catalog.items():
        for kind in ("ROBOT", "FINBOT"):
            expected = (
                "DOES_NOT_APPLY"
                if kind in EXPECTED_DOES_NOT_APPLY[object_id]
                else "UNRESOLVED"
            )
            assert item["classification"][kind]["status"] == expected


def test_apply_is_pure_deterministic_complete_and_idempotent(tmp_path: Path) -> None:
    root, rows, files = _workspace(tmp_path)
    before = deepcopy(rows)

    first = review.apply_package_semantic_review_subjects(root, rows, files)
    second = review.apply_package_semantic_review_subjects(root, first, files)

    assert rows == before
    assert first == second
    for object_id, row in first.items():
        applies = EXPECTED_APPLICABILITY[object_id]
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


def test_apply_preserves_compatible_complete_current_bindings(tmp_path: Path) -> None:
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_subjects(root, rows, files)
    privacy = selected["vstd-privacy-emission-policy"]
    decisions = deepcopy(privacy["classification"])
    obligation_id = "LEDGER-0.1-authoritative-history"
    custom_binding = deepcopy(privacy["obligations"][obligation_id])
    custom_binding["declaration"] = {
        field: "Prior exact nonblank " + field + "."
        for field in custom_binding["declaration"]
    }
    privacy["obligations"][obligation_id] = deepcopy(custom_binding)

    result = review.apply_package_semantic_review_subjects(root, selected, files)

    assert result["vstd-privacy-emission-policy"]["classification"] == decisions
    assert result["vstd-privacy-emission-policy"]["obligations"][obligation_id] == (
        custom_binding
    )


@pytest.mark.parametrize("failure", ["stale", "missing", "unowned", "extra_owned"])
def test_apply_rejects_source_or_ownership_drift_atomically(
    tmp_path: Path, failure: str
) -> None:
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-logit-constraint-controller"
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
        review.apply_package_semantic_review_subjects(root, rows, files)
    assert rows == before


@pytest.mark.parametrize(
    "failure",
    [
        "status",
        "stale_decision",
        "partial_declaration",
        "refuted_declaration",
        "malformed_unresolved",
        "label_conflict",
        "unknown_obligation",
        "same_status_reason",
        "same_status_evidence",
        "same_status_stale_digest",
        "other_object_refutation",
        "forged_applies_on_unlisted",
        "forged_refutation_on_unlisted",
    ],
)
def test_apply_rejects_conflicting_or_partial_reviews_atomically(
    tmp_path: Path, failure: str
) -> None:
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_subjects(root, rows, files)
    artifact = selected["vstd-artifact-control-lifecycle"]
    if failure == "status":
        artifact["classification"]["TRANSACTION"]["status"] = "DOES_NOT_APPLY"
    elif failure == "stale_decision":
        artifact["classification"]["TRANSACTION"]["evidence"][0]["sha256"] = (
            "sha256:" + "f" * 64
        )
    elif failure == "partial_declaration":
        artifact["obligations"]["TRANSACTION-0.1-effects-and-authority"]["declaration"][
            "effects"
        ] = ""
    elif failure == "refuted_declaration":
        artifact["obligations"]["MARKET-0.1-orders-and-access"] = {
            "reason": "Contradictory MARKET declaration.",
            "evidence": deepcopy(artifact["classification"]["MARKET"]["evidence"]),
            "declaration": {
                "participant_access": "Contradictory access.",
                "order_states": "Contradictory states.",
                "validation": "Contradictory validation.",
                "cancellation": "Contradictory cancellation.",
            },
        }
    elif failure == "malformed_unresolved":
        artifact["classification"]["MARKET"] = {
            "status": "UNRESOLVED",
            "reason": "",
            "evidence": [],
        }
    elif failure == "label_conflict":
        artifact["specializations"].append("MARKET")
    # artifact-control ROBOT is statically withheld, so the selected row is UNRESOLVED.
    # Each forgery restates it as DOES_NOT_APPLY, which only the exact historic refutation
    # with current bytes may do; every other restatement must abort the whole operation.
    elif failure == "same_status_reason":
        artifact["classification"]["ROBOT"].update(
            status="DOES_NOT_APPLY",
            reason="Prior review found no physical path.",
            evidence=_exact_evidence("vstd-artifact-control-lifecycle", files),
        )
    elif failure == "same_status_evidence":
        artifact["classification"]["ROBOT"].update(
            status="DOES_NOT_APPLY",
            reason=review._REVIEWS["vstd-artifact-control-lifecycle"].refuted["ROBOT"],
            evidence=[{"path": "src/unowned.py", "sha256": "sha256:" + "0" * 64}],
        )
    elif failure == "same_status_stale_digest":
        artifact["classification"]["ROBOT"].update(
            status="DOES_NOT_APPLY",
            reason=review._REVIEWS["vstd-artifact-control-lifecycle"].refuted["ROBOT"],
            evidence=[
                {"path": path, "sha256": "sha256:" + "0" * 64}
                for path in review._REVIEWS["vstd-artifact-control-lifecycle"].owned_paths
            ],
        )
    elif failure == "other_object_refutation":
        artifact["classification"]["ROBOT"].update(
            status="DOES_NOT_APPLY",
            reason=review._REVIEWS["vstd-logit-constraint-controller"].refuted["ROBOT"],
            evidence=_exact_evidence("vstd-artifact-control-lifecycle", files),
        )
    elif failure == "forged_applies_on_unlisted":
        artifact["classification"]["MARKET"] = {
            "status": "APPLIES",
            "reason": "Forged market applicability.",
            "evidence": deepcopy(artifact["classification"]["TRANSACTION"]["evidence"]),
        }
    elif failure == "forged_refutation_on_unlisted":
        artifact["classification"]["MARKET"] = {
            "status": "DOES_NOT_APPLY",
            "reason": artifact["classification"]["ROBOT"]["reason"],
            "evidence": deepcopy(artifact["classification"]["ROBOT"]["evidence"]),
        }
    else:
        artifact["obligations"]["TRANSACTION-0.99-invented"] = {
            "reason": "Invented.",
            "evidence": [],
            "declaration": {},
        }
    before = deepcopy(selected)

    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_"):
        review.apply_package_semantic_review_subjects(root, selected, files)
    assert selected == before


def test_apply_rechecks_complete_source_set_after_preflight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, rows, files = _workspace(tmp_path)
    target = review.review_document()["vstd-scitt-evidence-protocol"]["owned_paths"][-1]
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
        review.apply_package_semantic_review_subjects(root, rows, files)
    assert rows == before


def test_unlisted_objects_and_kinds_never_inherit_refutations(tmp_path: Path) -> None:
    root, rows, files = _workspace(tmp_path)
    neighbor = deepcopy(rows["vstd-deriver-process-exchange"])
    neighbor["object_id"] = "vstd-unlisted-neighbor"
    rows["vstd-unlisted-neighbor"] = neighbor
    before = deepcopy(neighbor)

    result = review.apply_package_semantic_review_subjects(root, rows, files)

    assert result["vstd-unlisted-neighbor"] == before
    assert "vstd-unlisted-neighbor" not in review.review_document()
    deriver = result["vstd-deriver-process-exchange"]["classification"]
    assert deriver["ROBOT"] == {
        "status": "UNRESOLVED",
        "reason": CANONICAL_UNRESOLVED.format(kind="ROBOT"),
        "evidence": [],
    }
    assert deriver["FINBOT"]["status"] == "UNRESOLVED"
    assert deriver["LEDGER"]["status"] == "UNRESOLVED"


# Refuted reasons must be positive, object-specific source facts.  Each cited
# path:line must resolve inside this object's owned bytes, and each ALL_CAPS
# evidence token must occur in those bytes.  Future-endpoint, complement, and
# "not established" clauses are generic absence rationales and must not return.
REPO_ROOT = Path(__file__).resolve().parents[1]
CITATION = re.compile(r"((?:[\w.-]+/)*[\w.-]+\.(?:py|json|md)):(\d+)(?:-(\d+))?")
EVIDENCE_TOKEN = re.compile(r"\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\b")
GENERIC_ABSENCE = (
    "later ",
    "would separately",
    "could be composed",
    "not established",
    "neither identif",
    "no endpoint",
    "not promoted",
    "observing hardware",
    "sim-to-real",
    "does not authenticate",
    "separately accumulate",
    "enforces no exposure",
    "future",
)


def test_refuted_reasons_cite_exact_owned_source_without_generic_absence() -> None:
    for object_id, review_item in review._REVIEWS.items():
        owned_text = "\n".join(
            (REPO_ROOT / path).read_text(encoding="utf-8")
            for path in review_item.owned_paths
        )
        for kind, reason in review_item.refuted.items():
            where = object_id + ":" + kind
            lowered = reason.lower()
            assert not [term for term in GENERIC_ABSENCE if term in lowered], where
            citations = CITATION.findall(reason)
            assert citations, where
            for cited, first, last in citations:
                matches = [
                    path
                    for path in review_item.owned_paths
                    if path == cited or path.endswith("/" + cited)
                ]
                assert len(matches) == 1, where + " cites unowned " + cited
                lines = (REPO_ROOT / matches[0]).read_text(encoding="utf-8")
                count = len(lines.splitlines())
                assert 1 <= int(first) <= int(last or first) <= count, where
            for token in set(EVIDENCE_TOKEN.findall(reason)):
                assert token in owned_text, where + " cites absent token " + token


def test_removing_a_refuted_cell_yields_unresolved_never_the_complement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    object_id = "vstd-hardware-resource-accounting"
    original = review._REVIEWS[object_id]
    weakened = dataclasses.replace(
        original,
        refuted={kind: reason for kind, reason in original.refuted.items() if kind != "SENSOR"},
    )
    monkeypatch.setitem(review._REVIEWS, object_id, weakened)

    decision = review.review_document()[object_id]["classification"]["SENSOR"]

    assert decision["status"] == "UNRESOLVED"
    assert decision["reason"] == CANONICAL_UNRESOLVED.format(kind="SENSOR")
    assert decision["evidence_paths"] == []


def test_catalogued_primary_or_specialized_role_cannot_be_demoted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    object_id = "vstd-privacy-emission-policy"
    original = review._REVIEWS[object_id]
    demoted = dataclasses.replace(
        original,
        applicable=tuple(kind for kind in original.applicable if kind != "LEDGER"),
        role_paths={
            kind: paths
            for kind, paths in original.role_paths.items()
            if kind != "LEDGER"
        },
    )
    monkeypatch.setitem(review._REVIEWS, object_id, demoted)

    with pytest.raises(AssertionError, match="demotes a catalogued"):
        review._catalog_check()


# Closed-surface regressions.  These cells reach a subprocess, network, or remote
# consequence that no owned source closes, so a refutation must be rejected rather
# than preserved, forged, or inherited from a stale earlier review.
UNCLOSED_EFFECT_CELLS = (
    ("vstd-privacy-emission-policy", "PROTOCOL"),
    ("vstd-privacy-emission-policy", "ROBOT"),
    ("vstd-privacy-emission-policy", "FINBOT"),
    ("vstd-deriver-process-exchange", "ROBOT"),
    ("vstd-deriver-process-exchange", "FINBOT"),
)


@pytest.mark.parametrize(("object_id", "kind"), UNCLOSED_EFFECT_CELLS)
def test_unclosed_effect_cells_reject_forged_or_stale_refutations(
    tmp_path: Path, object_id: str, kind: str
) -> None:
    assert review.review_document()[object_id]["classification"][kind]["status"] == (
        "UNRESOLVED"
    )
    root, rows, files = _workspace(tmp_path)
    owned = review._REVIEWS[object_id].owned_paths
    rows[object_id]["classification"][kind] = {
        "status": "DOES_NOT_APPLY",
        "reason": "Forged or stale refutation of an unclosed effect surface.",
        "evidence": [{"path": path, "sha256": files[path]} for path in owned],
    }
    before = deepcopy(rows)

    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT"):
        review.apply_package_semantic_review_subjects(root, rows, files)
    assert rows == before


def test_injected_sink_in_owned_subject_source_makes_the_review_stale(
    tmp_path: Path,
) -> None:
    root, rows, files = _workspace(tmp_path)
    target = root / "src/verifier/controlled_emission.py"
    target.write_bytes(target.read_bytes() + b"\nimport subprocess\n")

    with pytest.raises(
        ValueError,
        match="PACKAGE_SEMANTIC_REVIEW_SOURCE_DIFFERS:vstd-privacy-emission-policy",
    ):
        review.apply_package_semantic_review_subjects(root, rows, files)


def test_symlinked_owned_subject_source_is_unavailable_not_followed(
    tmp_path: Path,
) -> None:
    root, rows, files = _workspace(tmp_path)
    owned = root / "src/verifier/hardware/receipt.py"
    outside = root / "outside_receipt.py"
    outside.write_bytes(owned.read_bytes())
    owned.unlink()
    try:
        os.symlink(outside, owned)
    except OSError as exc:
        # OS_CAPABILITY_GUARD: unprivileged Windows symlink creation is unavailable.
        pytest.skip("OS_CAPABILITY_GUARD: symlink creation unavailable: " + str(exc))

    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_SOURCE_UNAVAILABLE"):
        review.apply_package_semantic_review_subjects(root, rows, files)


def test_duplicate_owned_subject_surface_is_rejected(tmp_path: Path) -> None:
    root, rows, files = _workspace(tmp_path)
    surfaces = rows["vstd-hardware-receipt-publication"]["surfaces"]
    surfaces.append(surfaces[0])

    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_SURFACES_INVALID"):
        review.apply_package_semantic_review_subjects(root, rows, files)


def test_privacy_budget_is_scalar_counter_state_not_claimed_history() -> None:
    privacy = review.review_document()["vstd-privacy-emission-policy"]
    history = privacy["declarations"]["LEDGER-0.1-authoritative-history"]["history"]

    assert "no per-entry journal" in history
    assert "durable history" in history
    assert privacy["classification"]["LEDGER"]["status"] == "APPLIES"


def test_external_refutations_in_the_catalog_require_a_closed_live_screen() -> None:
    catalog = review.review_document()
    for object_id, item in catalog.items():
        screen = review.closed_surface_screen(REPO_ROOT, item["owned_paths"])
        for kind in review.EXTERNAL_EFFECT_KINDS:
            if item["classification"][kind]["status"] == "DOES_NOT_APPLY":
                assert not review.screen_blocks(screen, kind), (
                    object_id
                    + ":"
                    + kind
                    + " refuted while the live screen withholds it: "
                    + screen.status
                    + " "
                    + repr(screen.open_sites[:2])
                )


def test_effect_guard_fires_on_a_reinstated_closure_refutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    object_id = "vstd-privacy-emission-policy"
    original = review._REVIEWS[object_id]
    reinstated = dataclasses.replace(
        original,
        refuted={**original.refuted, "ROBOT": "Reinstated lexical refutation of a sink."},
        demoted=original.demoted - {"ROBOT"},
    )
    monkeypatch.setitem(review._REVIEWS, object_id, reinstated)

    with pytest.raises(AssertionError, match="refuted while the live screen withholds it"):
        test_external_refutations_in_the_catalog_require_a_closed_live_screen()


def test_demotion_must_withhold_a_refuted_kind_only(monkeypatch: pytest.MonkeyPatch) -> None:
    object_id = "vstd-software-diode-effect"
    original = review._REVIEWS[object_id]
    widened = dataclasses.replace(original, demoted=frozenset({"TRANSACTION"}))
    monkeypatch.setitem(review._REVIEWS, object_id, widened)

    with pytest.raises(AssertionError, match="withholds a kind it does not refute"):
        review._catalog_check()


def test_software_diode_robot_is_withheld_by_package_behavior_not_owned_text() -> None:
    # Representation versus behavior: the owned diode text names no effect module, but
    # the live screen reaches package-level behavior outside the owned paths.
    object_id = "vstd-software-diode-effect"
    spec = review._REVIEWS[object_id]
    owned_text = "".join(
        (REPO_ROOT / path).read_text(encoding="utf-8")
        for path in spec.owned_paths
        if path.endswith(".py")
    )
    assert not any(name in owned_text for name in ("subprocess", "ctypes", "socket"))

    screen = review.closed_surface_screen(REPO_ROOT, spec.owned_paths)
    behavior = [site for site in screen.open_sites if site[0] not in spec.owned_paths]

    assert screen.status == "OPEN"
    assert behavior, "clean owned text must not close a package-reachable effect surface"
    assert review.review_document()[object_id]["classification"]["ROBOT"]["status"] == "UNRESOLVED"


def test_exact_historic_diode_refutation_is_demoted_not_restored(tmp_path: Path) -> None:
    # An exact historic refutation with current bytes is accepted as prior record, but the
    # live screen withholds it: the output cell is UNRESOLVED, never DOES_NOT_APPLY.
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-software-diode-effect"
    rows[object_id]["classification"]["ROBOT"] = {
        "status": "DOES_NOT_APPLY",
        "reason": review._REVIEWS[object_id].refuted["ROBOT"],
        "evidence": _exact_evidence(object_id, files),
    }

    result = review.apply_package_semantic_review_subjects(root, rows, files)

    assert result[object_id]["classification"]["ROBOT"] == {
        "status": "UNRESOLVED",
        "reason": CANONICAL_UNRESOLVED.format(kind="ROBOT"),
        "evidence": [],
    }


def test_closure_drift_after_planning_aborts_the_whole_subject_apply(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Owned bytes are unchanged; a transitive closure digest moves between the planning
    # screen and the closing screen.  The whole subject apply must abort atomically.
    root, rows, files = _workspace(tmp_path)
    real_screen = review.closed_surface_screen
    calls: list[tuple[str, ...]] = []

    def drifting(root_arg: str | Path, owned: tuple[str, ...]) -> review.SurfaceScreen:
        screen = real_screen(root_arg, owned)
        calls.append(tuple(owned))
        if len(calls) > len(review._REVIEWS):
            moved = screen.closure + (("src/verifier/late_helper.py", "sha256:" + "1" * 64),)
            return dataclasses.replace(screen, closure=moved)
        return screen

    monkeypatch.setattr(review, "closed_surface_screen", drifting)
    before = deepcopy(rows)

    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_SOURCE_CHANGED"):
        review.apply_package_semantic_review_subjects(root, rows, files)
    assert rows == before


def test_every_refutation_of_every_kind_requires_a_closed_live_screen() -> None:
    import verifier.runtime.package_semantic_review_records as records_review

    repo = Path(__file__).resolve().parents[1]
    catalog = review.review_document()
    for object_id, item in catalog.items():
        screen = records_review.closed_surface_screen(repo, item["owned_paths"])
        for kind, decision in item["classification"].items():
            if decision["status"] == "DOES_NOT_APPLY":
                assert not records_review.screen_blocks(screen, kind), (
                    object_id + ":" + kind + " refuted while the live screen is " + screen.status
                )
