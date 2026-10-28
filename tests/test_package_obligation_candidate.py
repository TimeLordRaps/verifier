"""Candidate-only 408-route JavaScript Object Notation (JSON) ledger tests."""
from __future__ import annotations

import json
import os
from pathlib import Path
import time

from jsonschema import Draft202012Validator
import pytest

from verifier.core.namespace import ObjectKind
from verifier.runtime import core_obligation_union
from verifier.runtime import core_tier_progression
from verifier.runtime import package_obligation_candidate as candidate
from verifier.runtime import package_owner_decision as owner_decision
from verifier.runtime import package_self_polish as package


def _source_coordinate() -> dict[str, str]:
    return {
        "source_head": "1" * 40,
        "source_tree": "2" * 40,
        "source_worktree_status_digest": "sha256:" + "3" * 64,
        "source_manifest_digest": "sha256:" + "4" * 64,
    }


def _write_owner_adoption(
        tmp_path: Path, ledger: dict, source_digest: str,
        ) -> tuple[Path, str, Path, str]:
    cryptography = pytest.importorskip("cryptography", reason="OPTIONAL_DEPENDENCY_ABSENT: cryptography (seal extra) is absent, so the Ed25519 owner-adoption signing fixture _write_owner_adoption and every test that calls it stay unexecuted here; the platform-python-contracts workflow job installs the seal extra and runs the complete suite, including this file")
    assert cryptography.__version__ == "50.0.0"
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    now = int(time.time())
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    policy = {
        "schema_version": owner_decision.POLICY_SCHEMA,
        "mechanism_digest": owner_decision.mechanism_digest(),
        "policy_id": "package-owner-integration-policy",
        "revision": 1,
        "owner_id": "test-owner",
        "key_id": "test-owner-key-1",
        "public_key": public.hex(),
        "effective_from": now - 600,
        "effective_until": now + 600,
        "max_decision_age_seconds": 600,
    }
    policy_raw = core_obligation_union.canonical_bytes(policy)
    policy_path = tmp_path / "owner-policy.json"
    policy_path.write_bytes(policy_raw)
    decisions = owner_decision.expected_owner_decisions(ledger)
    payload = {
        "schema_version": owner_decision.PAYLOAD_SCHEMA,
        "policy_id": policy["policy_id"],
        "policy_revision": policy["revision"],
        "owner_id": policy["owner_id"],
        "candidate_selection_digest": ledger["selection_digest"],
        "source_coordinate_digest": source_digest,
        "decision_set_digest": core_obligation_union.value_digest(decisions),
        "decisions": decisions,
        "issued_at": now - 1,
        "valid_until": now + 600,
        "nonce": "package-owner-integration-1",
    }
    payload_raw = core_obligation_union.canonical_bytes(payload)
    envelope = {
        "schema_version": owner_decision.ENVELOPE_SCHEMA,
        "algorithm": "Ed25519",
        "key_id": policy["key_id"],
        "payload": payload,
        "payload_digest": core_obligation_union.bytes_digest(payload_raw),
        "signature": private.sign(owner_decision.decision_signing_bytes(
            payload_raw, key_id=policy["key_id"]
        )).hex(),
    }
    envelope_raw = core_obligation_union.canonical_bytes(envelope)
    envelope_path = tmp_path / "owner-decisions.json"
    envelope_path.write_bytes(envelope_raw)
    return (
        policy_path, core_obligation_union.bytes_digest(policy_raw),
        envelope_path, core_obligation_union.bytes_digest(envelope_raw),
    )


def test_checker_path_escape_is_a_candidate_contradiction(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    coordinate = "ACTOR-1.1"
    binding = candidate.domain_inventory.MECHANIZED_12_POINT_BINDINGS[
        coordinate
    ]
    module_name = binding["checking_mechanism"].rsplit(".", 1)[0]
    root = tmp_path / "selected"
    selected = root / "src" / Path(*module_name.split(".")).with_suffix(".py")
    selected.parent.mkdir(parents=True)
    selected.write_text("# selected placeholder\n", encoding="utf-8")
    outside = tmp_path / "outside.py"
    outside.write_text("# escaped bytes\n", encoding="utf-8")
    original_resolve = Path.resolve

    def escaped_resolve(path: Path, strict: bool = False) -> Path:
        if path == selected:
            return outside
        return original_resolve(path, strict=strict)

    monkeypatch.setattr(candidate, "_selected_source_root", lambda _root: root)
    monkeypatch.setattr(Path, "resolve", escaped_resolve)

    with pytest.raises(
        candidate.CandidateLedgerError,
        match="PACKAGE_REASON_LEDGER_MECHANISM_ESCAPES_SOURCE_ROOT",
    ):
        candidate._checking_mechanism_digest(coordinate, source_root=root)


@pytest.mark.parametrize("layout", ("src", "site-packages"))
def test_default_checker_binding_uses_loaded_distribution_bytes(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, layout: str) -> None:
    coordinate = "ACTOR-1.1"
    mechanism = candidate.domain_inventory.MECHANIZED_12_POINT_BINDINGS[
        coordinate
    ]["checking_mechanism"]
    module_name = mechanism.rsplit(".", 1)[0]
    distribution_root = tmp_path / layout
    selected = distribution_root.joinpath(
        *module_name.split(".")
    ).with_suffix(".py")
    selected.parent.mkdir(parents=True)
    selected.write_bytes(b"# exact loaded checker bytes\n")
    module_file = distribution_root / "verifier/runtime/package_obligation_candidate.py"
    module_file.parent.mkdir(parents=True, exist_ok=True)
    module_file.write_bytes(b"# layout marker\n")
    monkeypatch.setattr(candidate, "__file__", str(module_file))

    binding = candidate._checking_mechanism_binding(coordinate)

    assert binding == {
        "checking_mechanism": mechanism,
        "source_path": "src/" + selected.relative_to(distribution_root).as_posix(),
        "source_digest": core_obligation_union.bytes_digest(selected.read_bytes()),
        "symbol": mechanism.rsplit(".", 1)[1],
    }


def test_explicit_checker_selection_never_falls_back_to_loaded_distribution(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    coordinate = "ACTOR-1.1"
    mechanism = candidate.domain_inventory.MECHANIZED_12_POINT_BINDINGS[
        coordinate
    ]["checking_mechanism"]
    relative = Path(*mechanism.rsplit(".", 1)[0].split(".")).with_suffix(".py")
    distribution_root = tmp_path / "site-packages"
    installed = distribution_root / relative
    installed.parent.mkdir(parents=True)
    installed.write_bytes(b"# installed selection\n")
    module_file = distribution_root / "verifier/runtime/package_obligation_candidate.py"
    module_file.parent.mkdir(parents=True, exist_ok=True)
    module_file.write_bytes(b"# layout marker\n")
    repository_root = tmp_path / "repository"
    repository = repository_root / "src" / relative
    repository.parent.mkdir(parents=True)
    repository.write_bytes(b"# different repository selection\n")
    monkeypatch.setattr(candidate, "__file__", str(module_file))

    installed_binding = candidate._checking_mechanism_binding(coordinate)
    repository_binding = candidate._checking_mechanism_binding(
        coordinate, source_root=repository_root
    )

    assert installed_binding["source_path"] == repository_binding["source_path"]
    assert installed_binding["source_digest"] != repository_binding["source_digest"]
    repository.unlink()
    with pytest.raises(
        candidate.CandidateLedgerUnavailable,
        match="PACKAGE_REASON_LEDGER_MECHANISM_UNAVAILABLE",
    ):
        candidate._checking_mechanism_binding(
            coordinate, source_root=repository_root
        )


def test_default_checker_selection_ignores_working_directory_shadow(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    coordinate = "ACTOR-1.1"
    mechanism = candidate.domain_inventory.MECHANIZED_12_POINT_BINDINGS[
        coordinate
    ]["checking_mechanism"]
    relative = Path(*mechanism.rsplit(".", 1)[0].split(".")).with_suffix(".py")
    distribution_root = tmp_path / "site-packages"
    selected = distribution_root / relative
    selected.parent.mkdir(parents=True)
    selected.write_bytes(b"# loaded distribution bytes\n")
    module_file = distribution_root / "verifier/runtime/package_obligation_candidate.py"
    module_file.parent.mkdir(parents=True, exist_ok=True)
    module_file.write_bytes(b"# layout marker\n")
    shadow_root = tmp_path / "shadow"
    shadow = shadow_root / "src" / relative
    shadow.parent.mkdir(parents=True)
    shadow.write_bytes(b"# cwd shadow bytes\n")
    monkeypatch.setattr(candidate, "__file__", str(module_file))
    monkeypatch.chdir(shadow_root)

    binding = candidate._checking_mechanism_binding(coordinate)
    assert binding["source_digest"] == core_obligation_union.bytes_digest(
        selected.read_bytes()
    )
    selected.unlink()
    with pytest.raises(
        candidate.CandidateLedgerUnavailable,
        match="PACKAGE_REASON_LEDGER_MECHANISM_UNAVAILABLE",
    ):
        candidate._checking_mechanism_binding(coordinate)


def _write_bundle(
        tmp_path: Path, *, mechanism: str = "NOT_ASSESSED",
        omit_last: bool = False,
        ) -> tuple[Path, Path, str]:
    inventory = core_tier_progression.installed_core_route_inventory()
    by_kind = {kind.value: [] for kind in ObjectKind}
    for cell in inventory["family_cells"]:
        for route in cell["registered_route_memberships"]:
            by_kind[cell["object_kind"]].append({
                "objective": route["coordinate"],
                "tier": cell["tier"],
                "serves": [],
                "role": "cross-cutting",
                "rev3_class": "NECESSARY",
                "rev4_class": "NECESSARY",
                "rev4_condition": None,
                "mechanism": mechanism,
                "reason_verdict": "ADEQUATE",
                "failed_tests": [],
                "reason_rewrite": None,
                "note": "candidate fixture",
            })
    if omit_last:
        by_kind["VERIFIER"].pop()

    cards = tmp_path / "cards"
    cards.mkdir()
    manifest_rows = ["# candidate fixture"]
    for kind in sorted(by_kind):
        card = {
            "definition": {
                "user_stated": [],
                "standard_description": "Fixture standard description.",
                "reading": "Fixture inferred reading.",
            },
            "facet_coverage": [{
                "facet": f"{kind}.F1",
                "objectives": [row["objective"] for row in by_kind[kind]],
                "mechanism": mechanism,
                "note": "Fixture facet coverage.",
            }],
            "facets": [{
                "id": f"{kind}.F1",
                "name": "fixture facet",
                "defined": "Fixture facet definition.",
                "reason": "Fixture facet reason.",
                "class": "NECESSARY",
                "condition": None,
                "basis": "INFERRED",
                "quote_ref": None,
                "contained_kind": None,
            }],
            "findings": [],
            "kind": kind,
            "obligation_map": by_kind[kind],
            "questions": [
                {"q": f"{kind} question {index}", "default": "UNRESOLVED"}
                for index in range(1, 5)
            ],
        }
        raw = (json.dumps(
            card, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        ) + "\n").encode("utf-8")
        (cards / f"{kind}.json").write_bytes(raw)
        digest = core_obligation_union.bytes_digest(raw).removeprefix("sha256:")
        manifest_rows.append(f"{digest}  out/cards/{kind}.json")
    manifest = tmp_path / "FINAL_SHA256SUMS_REV7.txt"
    manifest_raw = ("\n".join(manifest_rows) + "\n").encode("utf-8")
    manifest.write_bytes(manifest_raw)
    return cards, manifest, core_obligation_union.bytes_digest(manifest_raw)


def _selection_schema() -> dict:
    return json.loads(Path(
        "src/verifier/schemas/"
        "verifier-package-obligation-candidate-selection-1.schema.json"
    ).read_text(encoding="utf-8"))


def _package_schema() -> dict:
    return json.loads(Path(
        "src/verifier/schemas/"
        "verifier-package-graph-self-polish-assessment-1.schema.json"
    ).read_text(encoding="utf-8"))


def _repin_card(cards: Path, manifest: Path, kind: str) -> str:
    raw = (cards / f"{kind}.json").read_bytes()
    digest = core_obligation_union.bytes_digest(raw).removeprefix("sha256:")
    rows = manifest.read_text(encoding="utf-8").splitlines()
    suffix = f"  out/cards/{kind}.json"
    rows = [
        digest + suffix if row.endswith(suffix) else row
        for row in rows
    ]
    manifest.write_text("\n".join(rows) + "\n", encoding="utf-8")
    return core_obligation_union.bytes_digest(manifest.read_bytes())


def _write_reason_ledger(tmp_path: Path) -> tuple[Path, str]:
    inventory = core_tier_progression.installed_core_route_inventory()
    installed = candidate._installed_routes(inventory)
    objectives = {}
    for (_kind, coordinate), route in sorted(installed.items()):
        bound_digest = candidate._obligation_semantic_identity(
            coordinate, route
        )
        mechanism = candidate._checking_mechanism_binding(coordinate)
        objectives[coordinate] = {
            "reason": f"Fixture reason for {coordinate}.",
            "reason_source": "fixture source",
            "disposition": "INFERRED",
            "author": "fixture author",
            "bound_digest": bound_digest,
            "repository_realization": {
                "class": "DIRECT",
                "explanation": (
                    f"The installed mechanism directly checks {coordinate}."
                ),
                "adaptation_necessity": None,
                "obligation_semantic_digest": bound_digest,
                "discovered_surface_ids": [
                    "mechanism:" + mechanism["checking_mechanism"]
                ],
                "mechanism_bindings": [mechanism],
                "evidence_requirements": [
                    "Replay positive, negative, and UNKNOWN cases."
                ],
                "preserved_semantics": [
                    "The installed proposition and checking mechanism are bound."
                ],
                "unpreserved_semantics": [],
                "residual_obligations": [
                    "Independent repository-surface reconciliation remains required."
                ],
                "falsifiers": [
                    "A changed mechanism byte digest refutes this realization binding."
                ],
                "decision_authority": "fixture declaration only",
            },
        }
    slots = {}
    for kind in ObjectKind:
        for tier in range(1, 10):
            coordinate = f"{kind.value}-{tier}"
            bound_digest = candidate._slot_semantic_identity(coordinate)
            slots[coordinate] = {
                "reason": f"Fixture slot reason for {coordinate}.",
                "reason_source": "fixture source",
                "disposition": "INFERRED",
                "author": "fixture author",
                "bound_digest": bound_digest,
                "repository_realization": {
                    "class": "UNREALIZED",
                    "explanation": (
                        "The abstract slot rationale is retained separately from "
                        "repository route realization."
                    ),
                    "adaptation_necessity": None,
                    "obligation_semantic_digest": bound_digest,
                    "discovered_surface_ids": [],
                    "mechanism_bindings": [],
                    "evidence_requirements": [
                        "Bind the slot to realized installed obligations."
                    ],
                    "preserved_semantics": [
                        "The slot governing question and rationale are digest-bound."
                    ],
                    "unpreserved_semantics": [],
                    "residual_obligations": [
                        "Concrete repository realization is not established."
                    ],
                    "falsifiers": [
                        "A changed slot semantic digest refutes this annotation."
                    ],
                    "decision_authority": "fixture declaration only",
                },
            }
    value = {
        "schema_version": candidate.REASON_LEDGER_SCHEMA,
        "authored": "fixture",
        "rule": "Every obligation requires a reason.",
        "objectives": objectives,
        "slots": slots,
    }
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    path = tmp_path / "OBLIGATION_REASONS.json"
    path.write_bytes(raw)
    return path, core_obligation_union.bytes_digest(raw)


def test_reason_row_requires_repository_realization_annotation() -> None:
    with pytest.raises(
            candidate.CandidateLedgerError,
            match="PACKAGE_REASON_LEDGER_REPOSITORY_REALIZATION_FIELDS_DIFFER"):
        candidate._reason_row({
            "reason": "The obligation has a standard rationale.",
            "reason_source": "fixture source",
            "disposition": "INFERRED",
            "author": "fixture author",
            "bound_digest": "sha256:" + "1" * 64,
        }, expected_digest="sha256:" + "1" * 64)


def test_candidate_bundle_binds_exact_installed_408_without_promotion(
        tmp_path: Path) -> None:
    cards, manifest, digest = _write_bundle(tmp_path, mechanism="UNSOUND")
    inventory = core_tier_progression.installed_core_route_inventory()

    result = candidate.load_candidate_obligation_ledger(
        cards, manifest, inventory, expected_manifest_digest=digest,
    )

    assert result["status"] == "PASS"
    assert result["candidate_epistemic_status"] == "INFERRED"
    assert result["semantic_identity_status"] == "NOT_ESTABLISHED"
    assert result["reason_ledger_selection_status"] == "NOT_SELECTED"
    assert result["owner_adoption_status"] == "NOT_ESTABLISHED"
    assert result["normative_closure"] == "NOT_ESTABLISHED"
    assert result["card_count"] == 26
    assert result["objective_count"] == len(result["rows"]) == 408
    assert result["card_question_count"] == 104
    assert result["cross_kind_decision_count"] == 6
    assert result["owner_decision_count"] == len(result["owner_decisions"]) == 110
    assert result["candidate_mechanism_counts"] == {"UNSOUND": 408}
    assert all(row["status"] == "UNKNOWN" for row in result["rows"])
    assert all(row["owner_disposition_status"] == "NOT_ESTABLISHED"
               for row in result["rows"])
    Draft202012Validator.check_schema(_selection_schema())
    Draft202012Validator(_selection_schema()).validate(result)


def test_package_gate_joins_candidate_rows_but_stays_unknown(
        tmp_path: Path) -> None:
    cards, manifest, digest = _write_bundle(tmp_path)
    reasons, reasons_digest = _write_reason_ledger(tmp_path)

    report = package.assess_package_self_polish(
        _source_coordinate(),
        candidate_obligation_cards_root=cards,
        candidate_obligation_manifest_path=manifest,
        expected_candidate_obligation_manifest_digest=digest,
        candidate_obligation_reason_ledger_path=reasons,
        expected_candidate_obligation_reason_ledger_digest=reasons_digest,
    )

    ledger = report["candidate_obligation_ledger"]
    assert report["status"] == "UNKNOWN", ledger
    assert ledger["status"] == "PASS"
    assert ledger["objective_count"] == 408
    assert ledger["owner_decision_count"] == 110
    assert ledger["semantic_identity_status"] == "PASS"
    assert ledger["reason_identity_count"] == 408
    assert ledger["reason_slot_identity_count"] == 234
    assert "PACKAGE_OBLIGATION_CANDIDATE_NOT_OWNER_ADOPTED" in report["blockers"]
    assert "PACKAGE_OBLIGATION_CANDIDATE_NOT_SELECTED" not in report["blockers"]
    assert all(row["candidate_obligation_identity_status"] == "PASS"
               for row in report["core_route_memberships"])
    assert all(row["candidate_obligation_row_digest"] is not None
               for row in report["core_route_memberships"])
    assert all(row["status"] == "UNKNOWN"
               for row in report["core_route_memberships"])


def test_package_gate_projects_only_authenticated_owner_decisions(
        tmp_path: Path) -> None:
    cards, manifest, digest = _write_bundle(tmp_path)
    reasons, reasons_digest = _write_reason_ledger(tmp_path)
    coordinate = _source_coordinate()
    common = {
        "candidate_obligation_cards_root": cards,
        "candidate_obligation_manifest_path": manifest,
        "expected_candidate_obligation_manifest_digest": digest,
        "candidate_obligation_reason_ledger_path": reasons,
        "expected_candidate_obligation_reason_ledger_digest": reasons_digest,
    }

    unadopted = package.assess_package_self_polish(coordinate, **common)

    assert unadopted["owner_decision_admission"]["status"] == "NOT_SELECTED"
    assert "PACKAGE_OBLIGATION_CANDIDATE_NOT_OWNER_ADOPTED" \
        in unadopted["blockers"]
    assert all(
        not row["owner_decision_refs"]
        for row in unadopted["core_route_memberships"]
    )
    policy, policy_digest, decisions, decisions_digest = (
        _write_owner_adoption(
            tmp_path,
            unadopted["candidate_obligation_ledger"],
            core_obligation_union.value_digest(coordinate),
        )
    )

    adopted = package.assess_package_self_polish(
        coordinate,
        owner_decision_policy_path=policy,
        expected_owner_decision_policy_digest=policy_digest,
        owner_decision_path=decisions,
        expected_owner_decision_digest=decisions_digest,
        **common,
    )

    admission = adopted["owner_decision_admission"]
    assert admission["status"] == "PASS"
    assert admission["decision_count"] == 110
    assert "PACKAGE_OBLIGATION_CANDIDATE_NOT_OWNER_ADOPTED" \
        not in adopted["blockers"]
    assert all(
        "CTC-5" in cell["owner_decision_refs"]
        for cell in adopted["tier_zero_representation_cells"]
    )
    assert all(
        "CTC-4" in cell["owner_decision_refs"]
        for cell in adopted["corrigibility_extension_cells"]
    )
    assert any(
        row["owner_decision_refs"]
        for row in adopted["core_route_memberships"]
    )
    assert adopted["status"] == "UNKNOWN"
    Draft202012Validator(_selection_schema()).validate(
        adopted["candidate_obligation_ledger"]
    )
    Draft202012Validator(_package_schema()).validate(adopted)


def test_reason_ledger_semantic_substitution_fails_without_retaining_rows(
        tmp_path: Path) -> None:
    cards, manifest, digest = _write_bundle(tmp_path)
    reasons, reasons_digest = _write_reason_ledger(tmp_path)
    value = json.loads(reasons.read_text(encoding="utf-8"))
    value["objectives"]["ACTOR-1.1"]["bound_digest"] = "sha256:" + "0" * 64
    reasons.write_text(json.dumps(value), encoding="utf-8")
    reasons_digest = core_obligation_union.bytes_digest(reasons.read_bytes())

    report = package.assess_package_self_polish(
        _source_coordinate(),
        candidate_obligation_cards_root=cards,
        candidate_obligation_manifest_path=manifest,
        expected_candidate_obligation_manifest_digest=digest,
        candidate_obligation_reason_ledger_path=reasons,
        expected_candidate_obligation_reason_ledger_digest=reasons_digest,
    )

    ledger = report["candidate_obligation_ledger"]
    assert ledger["status"] == "FAIL"
    assert ledger["rows"] == []
    assert ledger["error"] == "PACKAGE_REASON_LEDGER_SEMANTIC_IDENTITY_DIFFERS"


def test_manifest_hash_mismatch_fails_project_without_retaining_rows(
        tmp_path: Path) -> None:
    cards, manifest, digest = _write_bundle(tmp_path)
    original = (cards / "EVENT.json").read_bytes()
    (cards / "EVENT.json").write_bytes(original + b"\n")

    report = package.assess_package_self_polish(
        _source_coordinate(),
        candidate_obligation_cards_root=cards,
        candidate_obligation_manifest_path=manifest,
        expected_candidate_obligation_manifest_digest=digest,
    )

    ledger = report["candidate_obligation_ledger"]
    assert report["status"] == "FAIL"
    assert ledger["status"] == "FAIL"
    assert ledger["error"] == "PACKAGE_CANDIDATE_CARD_DIGEST_DIFFERS"
    assert ledger["rows"] == []
    assert "PACKAGE_OBLIGATION_CANDIDATE_SELECTION_FAILED" in report["blockers"]
    assert all(row["candidate_obligation_identity_status"] == "NOT_RETAINED"
               for row in report["core_route_memberships"])
    Draft202012Validator(_selection_schema()).validate(ledger)


def test_missing_installed_objective_is_rejected_even_with_matching_manifest(
        tmp_path: Path) -> None:
    cards, manifest, digest = _write_bundle(tmp_path, omit_last=True)

    with pytest.raises(
        candidate.CandidateLedgerError,
        match="PACKAGE_CANDIDATE_OBJECTIVE_SET_DIFFERS",
    ):
        candidate.load_candidate_obligation_ledger(
            cards, manifest,
            core_tier_progression.installed_core_route_inventory(),
            expected_manifest_digest=digest,
        )


def test_malformed_manifest_card_row_is_rejected_not_ignored(
        tmp_path: Path) -> None:
    cards, manifest, _digest = _write_bundle(tmp_path)
    raw = manifest.read_text(encoding="utf-8")
    raw += "not-a-digest  out/cards/ACTOR.json\n"
    manifest.write_text(raw, encoding="utf-8")
    digest = core_obligation_union.bytes_digest(manifest.read_bytes())

    with pytest.raises(
            candidate.CandidateLedgerError,
            match="PACKAGE_CANDIDATE_MANIFEST_CARD_ROW_INVALID"):
        candidate.load_candidate_obligation_ledger(
            cards,
            manifest,
            core_tier_progression.installed_core_route_inventory(),
            expected_manifest_digest=digest,
        )


def test_unhashable_candidate_enum_is_a_fail_not_an_exception_leak(
        tmp_path: Path) -> None:
    cards, manifest, _digest = _write_bundle(tmp_path)
    path = cards / "EVENT.json"
    card = json.loads(path.read_text(encoding="utf-8"))
    card["obligation_map"][0]["rev3_class"] = []
    path.write_text(
        json.dumps(card, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    digest = _repin_card(cards, manifest, "EVENT")

    report = package.assess_package_self_polish(
        _source_coordinate(),
        candidate_obligation_cards_root=cards,
        candidate_obligation_manifest_path=manifest,
        expected_candidate_obligation_manifest_digest=digest,
    )

    assert report["status"] == "FAIL"
    assert report["candidate_obligation_ledger"]["error"] \
        == "PACKAGE_CANDIDATE_CLASS_INVALID"


def test_json_integer_digit_limit_is_a_candidate_failure() -> None:
    raw = ('{"value":' + '1' * 5000 + '}').encode("ascii")

    with pytest.raises(
        candidate.CandidateLedgerError,
        match="PACKAGE_CANDIDATE_JSON_INVALID",
    ):
        candidate._strict_json(raw)


def test_differently_cased_json_card_is_rejected_on_every_platform(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cards, manifest, digest = _write_bundle(tmp_path)
    original = Path.iterdir

    class UppercaseEntry:
        suffix = ".JSON"
        name = "EVENT.JSON"

        @staticmethod
        def is_file() -> bool:
            return True

    def with_uppercase_entry(path: Path):
        entries = list(original(path))
        return [*entries, UppercaseEntry()] if path == cards else entries

    monkeypatch.setattr(Path, "iterdir", with_uppercase_entry)

    with pytest.raises(
        candidate.CandidateLedgerError,
        match="PACKAGE_CANDIDATE_CARD_FILE_SET_DIFFERS",
    ):
        candidate.load_candidate_obligation_ledger(
            cards,
            manifest,
            core_tier_progression.installed_core_route_inventory(),
            expected_manifest_digest=digest,
        )


def test_cards_root_permission_outage_is_unavailable(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cards, manifest, digest = _write_bundle(tmp_path)
    original = Path.is_symlink

    def permission_guard(path: Path) -> bool:
        if path == cards:
            raise PermissionError("synthetic cards root outage")
        return original(path)

    monkeypatch.setattr(Path, "is_symlink", permission_guard)

    with pytest.raises(candidate.CandidateLedgerUnavailable):
        candidate.load_candidate_obligation_ledger(
            cards,
            manifest,
            core_tier_progression.installed_core_route_inventory(),
            expected_manifest_digest=digest,
        )


def test_no_candidate_selection_is_explicit_and_schema_valid() -> None:
    report = package.assess_package_self_polish(_source_coordinate())
    ledger = report["candidate_obligation_ledger"]

    assert ledger["status"] == "NOT_SELECTED"
    assert ledger["rows"] == []
    assert "PACKAGE_OBLIGATION_CANDIDATE_NOT_SELECTED" in report["blockers"]
    assert "PACKAGE_OBLIGATION_CANDIDATE_NOT_OWNER_ADOPTED" \
        not in report["blockers"]
    Draft202012Validator(_selection_schema()).validate(ledger)


def test_selected_owner_evidence_failure_is_not_hidden_by_absent_candidate(
        tmp_path: Path) -> None:
    digest = "sha256:" + "0" * 64
    report = package.assess_package_self_polish(
        _source_coordinate(),
        owner_decision_policy_path=tmp_path / "missing-policy.json",
        expected_owner_decision_policy_digest=digest,
        owner_decision_path=tmp_path / "missing-decisions.json",
        expected_owner_decision_digest=digest,
    )

    assert report["owner_decision_admission"]["status"] == "UNKNOWN"
    assert "PACKAGE_OBLIGATION_CANDIDATE_NOT_SELECTED" in report["blockers"]
    assert "PACKAGE_OWNER_DECISION_ADMISSION_UNAVAILABLE" \
        in report["blockers"]


def test_selected_missing_manifest_preserves_unknown(tmp_path: Path) -> None:
    cards, _manifest, digest = _write_bundle(tmp_path)

    report = package.assess_package_self_polish(
        _source_coordinate(),
        candidate_obligation_cards_root=cards,
        candidate_obligation_manifest_path=tmp_path / "missing.txt",
        expected_candidate_obligation_manifest_digest=digest,
    )

    ledger = report["candidate_obligation_ledger"]
    assert report["status"] == "UNKNOWN"
    assert ledger["status"] == "UNKNOWN"
    assert ledger["rows"] == []
    assert "PACKAGE_OBLIGATION_CANDIDATE_UNAVAILABLE" in report["blockers"]
    assert all(row["candidate_obligation_identity_status"] == "NOT_RETAINED"
               for row in report["core_route_memberships"])
    Draft202012Validator(_selection_schema()).validate(ledger)


def test_selected_bundle_requires_manifest_digest(tmp_path: Path) -> None:
    cards, manifest, _digest = _write_bundle(tmp_path)

    report = package.assess_package_self_polish(
        _source_coordinate(),
        candidate_obligation_cards_root=cards,
        candidate_obligation_manifest_path=manifest,
    )

    assert report["status"] == "FAIL"
    assert report["candidate_obligation_ledger"]["error"] \
        == "PACKAGE_CANDIDATE_EXPECTED_MANIFEST_DIGEST_REQUIRED"


@pytest.mark.skipif(
    "VSTD_TRIAGE_ROOT" not in os.environ,
    reason="set VSTD_TRIAGE_ROOT to exercise the exact external REV7 cards",
)
def test_selected_real_revision7_cards_preserve_exact_counts() -> None:
    root = Path(os.environ["VSTD_TRIAGE_ROOT"])
    cards = root / "out" / "cards"
    manifest = cards / "FINAL_SHA256SUMS_REV7.txt"
    digest = core_obligation_union.bytes_digest(manifest.read_bytes())

    result = candidate.load_candidate_obligation_ledger(
        cards,
        manifest,
        core_tier_progression.installed_core_route_inventory(),
        expected_manifest_digest=digest,
    )

    assert result["candidate_rev4_class_counts"] == {
        "CONDITIONALLY_NECESSARY": 17,
        "NECESSARY": 390,
        "REASON_PENDING": 1,
    }
    assert result["candidate_mechanism_counts"] == {
        "BOUNDED": 6,
        "COVERS": 8,
        "DEFECTIVE": 76,
        "NOT_ASSESSED": 31,
        "PARTIAL": 184,
        "UNSOUND": 103,
    }
    assert result["card_question_count"] == 104
    assert result["owner_decision_count"] == 110
