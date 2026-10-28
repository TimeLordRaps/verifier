"""Admission boundaries for DOES_NOT_APPLY decisions, with or without a stored witness.

Nothing removes an obligation.  A fresh closure run yields at most a bounded clean-scan
observation, which never establishes non-applicability.  Without a stored witness the
run covers the object's exact current owned census, every owned file; a stored
executable witness must instead bind the exact object, kind, reviewing module, installed
mechanism, decision row and anchored bytes.  Together with the decision's reason and
current owned evidence and a clean owned closed-effect audit of the same bytes, that
observation admits the DOES_NOT_APPLY as DOCUMENTED, never ESTABLISHED.  A boundary
reference, a gate hit, an open effect census, audited review, and stale, forged,
unavailable or unclosed witnesses are not admitted, and no claim, DOCUMENTED or not,
removes an obligation that its hints, sources, consequences and declarations require.
"""
from __future__ import annotations

import dataclasses
import os
import subprocess
from pathlib import Path

import pytest

from verifier.runtime import namespace_admission as admission
from verifier.runtime import namespace_classification as classification
from verifier.runtime import namespace_contracts as contracts
from verifier.runtime import namespace_discovery as discovery
from verifier.runtime import namespace_manifest as manifests
from verifier.runtime import namespace_refutation as nr
from verifier.runtime.tier_zero_profile import canonical_bytes, value_digest


LEDGER_SOURCE = "def append_ledger_entry(entry):\n    return entry\n"
# A ledger hint without the registered write boundary: the benign LEDGER subject.
LEDGER_BENIGN = "def ledger_summary(entry):\n    return entry\n"
OTHER_SOURCE = "def helper():\n    return 1\n"
REASON = "The bounded source defines a single retained-record boundary."
PROSE = "The selected source has no authoritative ledger history."


def repository(tmp_path: Path, files: dict[str, str]) -> Path:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    for name, source in files.items():
        (tmp_path / name).write_text(source, encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", *files], check=True)
    return tmp_path


def save(root: Path, manifest: dict) -> None:
    (root / "objects.vstd").write_bytes(canonical_bytes(manifest) + b"\n")


def ledger_subject(tmp_path: Path, files: dict[str, str] | None = None) -> tuple[Path, dict]:
    """One object whose only classification decision is a prose LEDGER refutation."""
    root = repository(tmp_path, files or {"accounts.py": LEDGER_BENIGN})
    draft = admission.build_template(root)
    manifest = draft["manifest"]
    for row in manifest["objects"]:
        row["reason"] = REASON
    subject = next(row for row in manifest["objects"] if row["object_id"] == "accounts.py")
    subject["classification"]["LEDGER"].update(
        status="DOES_NOT_APPLY", reason=PROSE, evidence=draft["source_evidence"])
    save(root, manifest)
    return root, manifest


def subject_row(manifest: dict) -> dict:
    return next(row for row in manifest["objects"] if row["object_id"] == "accounts.py")


def census(root: Path) -> dict[str, dict]:
    return {row["path"]: row for row in discovery.discover(root)["census"]["files"]}


def mechanism_digest() -> str:
    return value_digest(admission.mechanism_binding())


def context_for(root: Path) -> dict:
    return classification.refutation_context(discovery.discover(root), mechanism_digest(), root=root)


def build(root: Path, manifest: dict, kind: str = "LEDGER", *, sources=("accounts.py",),
          callees=(), inventory: dict | None = None, row: dict | None = None) -> dict:
    """Build a witness exactly as a reviewer would: bound to the current decision row."""
    subject = row or subject_row(manifest)
    decision = subject["classification"][kind]
    expected = nr.ExpectedReview(
        object_id=subject["object_id"],
        kind=kind,
        basis=nr.BASIS_EXECUTABLE_CLOSURE,
        review_module="accounts_py",
        review_mechanism_digest=mechanism_digest(),
        review_row_digest=value_digest({key: item for key, item in decision.items() if key != "refutation"}),
    )
    inventory = inventory if inventory is not None else context_for(root)["inventory"]
    return nr.build_witness(expected=expected, source_paths=list(sources),
                            callee_paths=list(callees), inventory=inventory)


def classify(root: Path, manifest: dict, *, context: dict | None) -> dict:
    observed = discovery.discover(root)
    registry = contracts.namespace_registry(manifest["extensions"])
    return classification.assess_classification(
        manifest["objects"], registry, observed, refutation_context=context)


def ledger_row(result: dict) -> dict:
    return next(row for row in result["objects"][0]["classification"] if row["kind"] == "LEDGER")


def retained_ledger(result: dict) -> list[dict]:
    return [row for row in result["required_obligations"]
            if row["object_id"] == "accounts.py" and row["kind"] == "LEDGER"]


def witness_finding(result: dict) -> dict:
    return next(row for row in result["findings"]
                if row["code"] == "NAMESPACE_NON_APPLICABILITY_NOT_ESTABLISHED"
                and row["object_id"] == "accounts.py")


# --- Exploit: hint-only LEDGER with a prose refutation must keep its obligations.


def test_source_hint_with_prose_refutation_keeps_ledger_obligations(tmp_path):
    root, _ = ledger_subject(tmp_path, {"accounts.py": LEDGER_SOURCE})
    report = admission.assess(root)
    registry = contracts.namespace_registry()
    expected = {row["id"] for row in contracts.requirements_for(registry, ["LEDGER"])}
    retained = {row["id"] for row in report["required_obligations"]
                if row["object_id"] == "accounts.py" and row["kind"] == "LEDGER"}
    assert retained == expected
    assert report["status"] != "PASS"
    finding = next(row for row in report["findings"]
                   if row["code"] == "NAMESPACE_NON_APPLICABILITY_NOT_ESTABLISHED")
    assert finding["status"] == "UNKNOWN"
    # No witness is stored, so the closure runs now over the owned census and finds the
    # registered boundary: the claim stays unadmitted and names what it found.
    assert "BOUNDARY_IDENTIFIER_REFERENCED" in finding["reason"]
    assert "append_ledger_entry" in finding["reason"]
    assert finding["next_action"]


DOCUMENTED = "DOCUMENTED"
DOCUMENTED_CODE = "DOCUMENTED_BOUNDED_ABSENCE"


def test_clean_executable_witness_is_documented_and_keeps_hint_obligations(tmp_path):
    # LEDGER_BENIGN is clean, yet a finite scan never establishes non-applicability:
    # the claim is admitted only as DOCUMENTED and the hint-selected obligations stay required.
    root, manifest = ledger_subject(tmp_path)
    subject_row(manifest)["classification"]["LEDGER"]["refutation"] = build(root, manifest)
    save(root, manifest)
    report = admission.assess(root)
    registry = contracts.namespace_registry()
    expected = {row["id"] for row in contracts.requirements_for(registry, ["LEDGER"])}
    retained = {row["id"] for row in report["required_obligations"]
                if row["object_id"] == "accounts.py" and row["kind"] == "LEDGER"}
    assert retained == expected
    assert report["status"] != "PASS"
    assert not any(row["code"] == "NAMESPACE_NON_APPLICABILITY_NOT_ESTABLISHED"
                   and row["reason"].startswith("LEDGER ") for row in report["findings"])
    decision = next(row for row in report["object_assessments"][0]["classification"]
                    if row["kind"] == "LEDGER")
    assert decision["non_applicability"] == DOCUMENTED
    assert decision["refutation_status"] == DOCUMENTED
    assert decision["refutation_code"] == DOCUMENTED_CODE


def test_witness_cannot_remove_a_source_declared_kind_behind_object(tmp_path):
    root, manifest = ledger_subject(tmp_path, {"accounts.py": '__vstd_kinds__ = ("LEDGER",)\n' + LEDGER_SOURCE})
    subject_row(manifest)["kind"] = "OBJECT"
    subject_row(manifest)["specializations"] = []
    subject_row(manifest)["classification"]["LEDGER"]["refutation"] = build(root, manifest)
    save(root, manifest)
    report = admission.assess(root)
    assert report["status"] == "FAIL"
    assert any(row["code"] == "NAMESPACE_REFUTATION_CONTRADICTS_DECLARATION" for row in report["findings"])
    assert any(row["kind"] == "LEDGER" for row in report["required_obligations"])


# --- Classification-level verdict matrix: every non-establishing input retains obligations.


def _with_context(root: Path, mutate) -> dict:
    context = context_for(root)
    mutate(context)
    return context


CASES = {
    # Without a witness the closure runs over the owned census, which names the boundary.
    "missing": ("UNKNOWN", "BOUNDARY_IDENTIFIER_REFERENCED", lambda root, manifest: None,
                lambda root: context_for(root)),
    "no_context": ("UNKNOWN", "REFUTATION_CONTEXT_ABSENT", lambda root, manifest: build(root, manifest), lambda root: None),
    "stale_anchor": ("UNKNOWN", "STALE_ANCHOR",
                     lambda root, manifest: build(root, manifest, inventory={
                         "accounts.py": {"owner": "accounts_py", "sha256": "sha256:" + "1" * 64, "available": True}}),
                     lambda root: context_for(root)),
    "unavailable_anchor": ("UNKNOWN", "ANCHOR_UNAVAILABLE",
                           lambda root, manifest: build(root, manifest),
                           lambda root: _with_context(root, lambda c: c["inventory"]["accounts.py"].update(available=False))),
    "unclosed_callee": ("UNKNOWN", "ANCHOR_NOT_IN_INVENTORY",
                        lambda root, manifest: build(root, manifest, callees=("helper.py",), inventory={
                            **context_for(root)["inventory"],
                            "helper.py": {"owner": "helper_py", "sha256": census(root)["accounts.py"]["sha256"],
                                          "available": True}}),
                        lambda root: _with_context(root, lambda c: c["inventory"].pop("helper.py", None))),
    "forged_digest": ("FAIL", "DIGEST_MISMATCH",
                      lambda root, manifest: {**build(root, manifest), "witness_digest": "sha256:" + "0" * 64},
                      lambda root: context_for(root)),
    "wrong_owner": ("FAIL", "WRONG_OWNER",
                    lambda root, manifest: build(root, manifest, sources=("accounts.py", "other.py"), inventory={
                        **context_for(root)["inventory"],
                        "other.py": {"owner": "accounts_py", "sha256": census(root)["other.py"]["sha256"],
                                     "available": True}}),
                    lambda root: context_for(root)),
    "wrong_mechanism": ("FAIL", "WRONG_MECHANISM",
                        lambda root, manifest: build(root, manifest),
                        lambda root: _with_context(root, lambda c: c.update(mechanism_digest="sha256:" + "2" * 64))),
    "wrong_kind": ("FAIL", "WRONG_KIND",
                   lambda root, manifest: _claims_other_kind(root, manifest),
                   lambda root: context_for(root)),
    "malformed": ("FAIL", "EXTRA_KEY",
                  lambda root, manifest: {**build(root, manifest), "extra": True},
                  lambda root: context_for(root)),
    "audited_basis": ("UNKNOWN", "AUDITED_SOURCE_NOT_EXECUTABLE",
                      lambda root, manifest: _audited(root, manifest),
                      lambda root: context_for(root)),
    "closure_refuted": ("FAIL", "BOUNDARY_IDENTIFIER_REFERENCED",
                        lambda root, manifest: build(root, manifest),
                        lambda root: context_for(root)),
}


def _claims_other_kind(root: Path, manifest: dict) -> dict:
    """A witness for TRANSACTION presented under the LEDGER decision row."""
    subject = subject_row(manifest)
    decision = subject["classification"]["LEDGER"]
    expected = nr.ExpectedReview(
        object_id="accounts.py", kind="TRANSACTION", basis=nr.BASIS_EXECUTABLE_CLOSURE,
        review_module="accounts_py", review_mechanism_digest=mechanism_digest(),
        review_row_digest=value_digest({key: item for key, item in decision.items() if key != "refutation"}),
    )
    return nr.build_witness(expected=expected, source_paths=["accounts.py"], inventory=context_for(root)["inventory"])


def _audited(root: Path, manifest: dict) -> dict:
    subject = subject_row(manifest)
    decision = subject["classification"]["LEDGER"]
    expected = nr.ExpectedReview(
        object_id="accounts.py", kind="LEDGER", basis=nr.BASIS_AUDITED_SOURCE,
        review_module="accounts_py", review_mechanism_digest=mechanism_digest(),
        review_row_digest=value_digest({key: item for key, item in decision.items() if key != "refutation"}),
    )
    return nr.build_witness(expected=expected, source_paths=["accounts.py"], inventory=context_for(root)["inventory"])


@pytest.mark.parametrize("case", sorted(CASES))
def test_non_establishing_witness_retains_every_hint_obligation(tmp_path, case):
    status, code, make_witness, make_context = CASES[case]
    root, manifest = ledger_subject(tmp_path, {"accounts.py": LEDGER_SOURCE, "other.py": OTHER_SOURCE})
    witness = make_witness(root, manifest)
    if witness is not None:
        subject_row(manifest)["classification"]["LEDGER"]["refutation"] = witness
        save(root, manifest)
    result = classify(root, manifest, context=make_context(root))
    row = ledger_row(result)
    assert row["non_applicability"] == "NOT_ESTABLISHED"
    assert row["refutation_status"] != "ESTABLISHED"
    assert retained_ledger(result), case
    finding = witness_finding(result)
    assert finding["status"] == status, case
    assert code in finding["reason"], (case, finding["reason"])
    assert finding["next_action"]


def test_executable_witness_never_establishes_non_applicability_at_classification_level(tmp_path):
    root, manifest = ledger_subject(tmp_path, {"accounts.py": LEDGER_BENIGN, "other.py": OTHER_SOURCE})
    subject_row(manifest)["classification"]["LEDGER"]["refutation"] = build(root, manifest)
    save(root, manifest)
    result = classify(root, manifest, context=context_for(root))
    row = ledger_row(result)
    assert row["non_applicability"] == DOCUMENTED
    assert row["refutation_status"] == DOCUMENTED
    assert row["refutation_code"] == DOCUMENTED_CODE
    assert result["non_applicability_verdicts"] == []
    assert retained_ledger(result)


# --- Owner, identity and inventory derivation.


def test_owner_is_a_dotted_identity_that_keeps_the_extension_distinct():
    assert classification.witness_owner("accounts.py") == "accounts_py"
    assert classification.witness_owner("src/verifier/x.mjs") == "src.verifier.x_mjs"
    assert classification.witness_owner(".gitignore") is None
    assert classification.witness_owner("docs/my-file.md") is None


def test_inventory_admits_only_paths_the_witness_validator_accepts():
    # A reserved Windows device name cannot be staged in git, so the census is
    # supplied directly.  The validator, not a copied regex, decides admission.
    observed = {"census": {"files": [
        {"path": "accounts.py", "sha256": "sha256:" + "a" * 64},
        {"path": "con.py", "sha256": "sha256:" + "b" * 64},
        {"path": "docs/my-file.md", "sha256": "sha256:" + "c" * 64},
    ]}}
    context = classification.refutation_context(observed, mechanism_digest())
    assert set(context["inventory"]) == {"accounts.py"}
    assert context["inventory"]["accounts.py"] == {
        "owner": "accounts_py", "sha256": "sha256:" + "a" * 64, "available": True}


def test_object_without_a_single_owner_cannot_bind_a_witness(tmp_path):
    root = repository(tmp_path, {"accounts.py": LEDGER_SOURCE})
    verdict = classification._non_applicability_verdict(
        "accounts.py", "LEDGER", {"status": "DOES_NOT_APPLY", "reason": PROSE, "evidence": [],
                                  "refutation": {}},
        set(), context_for(root))
    assert verdict.status == "UNKNOWN"
    assert verdict.code == "REVIEW_MODULE_UNBOUND"


def test_unbindable_object_identifier_is_unknown_not_a_forged_witness(tmp_path):
    root, manifest = ledger_subject(tmp_path)
    decision = subject_row(manifest)["classification"]["LEDGER"]
    verdict = classification._non_applicability_verdict(
        "account ledger", "LEDGER", {**decision, "refutation": {}}, {"accounts.py"}, context_for(root))
    assert verdict.status == "UNKNOWN"
    assert verdict.code == "REVIEW_IDENTITY_UNBINDABLE"


# --- Manifest representation: typed, optional, and only on DOES_NOT_APPLY.


def test_manifest_accepts_refutation_only_on_does_not_apply(tmp_path):
    root, manifest = ledger_subject(tmp_path)
    decision = subject_row(manifest)["classification"]["LEDGER"]
    decision["refutation"] = build(root, manifest)
    manifests.validate_manifest(manifest)

    decision["status"] = "APPLIES"
    with pytest.raises(ValueError, match="NAMESPACE_CLASSIFICATION_FIELDS"):
        manifests.validate_manifest(manifest)


def test_manifest_rejects_a_non_object_refutation(tmp_path):
    root, manifest = ledger_subject(tmp_path)
    subject_row(manifest)["classification"]["LEDGER"]["refutation"] = "prose"
    with pytest.raises(ValueError, match="NAMESPACE_CLASSIFICATION_FIELDS"):
        manifests.validate_manifest(manifest)


def test_compact_transport_round_trips_an_inline_refutation(tmp_path):
    root, manifest = ledger_subject(tmp_path)
    subject_row(manifest)["classification"]["LEDGER"]["refutation"] = build(root, manifest)
    compact = manifests.compact_manifest(manifest)
    assert manifests.normalize_manifest(compact) == manifest


def test_compact_transport_rejects_a_non_object_refutation(tmp_path):
    root, manifest = ledger_subject(tmp_path)
    subject_row(manifest)["classification"]["LEDGER"]["refutation"] = build(root, manifest)
    compact = manifests.compact_manifest(manifest)
    binding = next(row for row in compact["objects"] if row["object_id"] == "accounts.py")["classification"]["LEDGER"]
    binding["refutation"] = "prose"
    with pytest.raises(ValueError, match="NAMESPACE_COMPACT_BINDING"):
        manifests.normalize_manifest(compact)


# --- Fresh closure execution through admission, forgeries and the independent reconciler.


def _benign_with_witness(tmp_path: Path) -> tuple[Path, dict]:
    root, manifest = ledger_subject(tmp_path)
    subject_row(manifest)["classification"]["LEDGER"]["refutation"] = build(root, manifest)
    save(root, manifest)
    return root, manifest


def _verdicts(root: Path, manifest: dict) -> list[dict]:
    return classify(root, manifest, context=context_for(root))["non_applicability_verdicts"]


def _reconcile_with(root: Path, manifest: dict, verdicts) -> dict:
    observed = discovery.discover(root)
    registry = contracts.namespace_registry(manifest["extensions"])
    classified = classify(root, manifest, context=context_for(root))
    raw = canonical_bytes(manifest) + b"\n"
    return admission._reconcile(raw, registry, observed, classified,
                                established_non_applicability=verdicts)


def test_fake_executable_closure_on_a_boundary_source_retains_every_ledger_obligation(tmp_path):
    root, manifest = ledger_subject(tmp_path, {"accounts.py": LEDGER_SOURCE})
    subject_row(manifest)["classification"]["LEDGER"]["refutation"] = build(root, manifest)
    save(root, manifest)
    report = admission.assess(root)
    registry = contracts.namespace_registry()
    expected = {row["id"] for row in contracts.requirements_for(registry, ["LEDGER"])}
    retained = {row["id"] for row in report["required_obligations"]
                if row["object_id"] == "accounts.py" and row["kind"] == "LEDGER"}
    assert retained == expected
    assert report["status"] == "FAIL"
    finding = next(row for row in report["findings"]
                   if row["code"] == "NAMESPACE_NON_APPLICABILITY_NOT_ESTABLISHED")
    assert "BOUNDARY_IDENTIFIER_REFERENCED" in finding["reason"]
    assert _verdicts(root, manifest) == []


def test_receipt_injected_into_a_witness_is_a_contract_violation_not_a_pass(tmp_path):
    root, manifest = ledger_subject(tmp_path)
    witness = build(root, manifest)
    subject_row(manifest)["classification"]["LEDGER"]["refutation"] = {
        **witness, "receipt": {"status": "PASS", "code": "NO_BOUNDARY_IDENTIFIER_REFERENCED"}}
    save(root, manifest)
    result = classify(root, manifest, context=context_for(root))
    assert result["objects"][0]["classification"][0]["non_applicability"] == "NOT_ESTABLISHED"
    assert any(row["kind"] == "LEDGER" for row in result["required_obligations"])
    assert result["non_applicability_verdicts"] == []


def test_receipt_injected_into_a_decision_row_is_rejected_by_the_manifest(tmp_path):
    root, manifest = ledger_subject(tmp_path)
    subject_row(manifest)["classification"]["LEDGER"]["receipt"] = {"status": "PASS"}
    save(root, manifest)
    report = admission.assess(root)
    assert report["status"] == "FAIL"
    assert report["assessment_executed"] is False
    assert not report.get("non_applicability_verdicts")


def test_closure_run_during_admission_fails_closed_on_a_timeout(tmp_path, monkeypatch):
    root, manifest = _benign_with_witness(tmp_path)

    def timed_out(*args, **kwargs):
        raise TimeoutError("closure budget")

    monkeypatch.setattr(nr, "_scan_boundary_references", timed_out)
    report = admission.assess(root)
    assert any(row["kind"] == "LEDGER" for row in report["required_obligations"])
    finding = next(row for row in report["findings"]
                   if row["code"] == "NAMESPACE_NON_APPLICABILITY_NOT_ESTABLISHED")
    assert finding["status"] == "UNKNOWN" and "EXECUTION_TIMEOUT" in finding["reason"]
    assert _verdicts(root, manifest) == []


def test_witness_bound_to_earlier_bytes_is_stale_after_a_boundary_is_added(tmp_path):
    root, manifest = _benign_with_witness(tmp_path)
    (root / "accounts.py").write_text(LEDGER_SOURCE, encoding="utf-8")
    report = admission.assess(root)
    assert any(row["kind"] == "LEDGER" for row in report["required_obligations"])
    finding = next(row for row in report["findings"]
                   if row["code"] == "NAMESPACE_NON_APPLICABILITY_NOT_ESTABLISHED")
    assert "STALE_ANCHOR" in finding["reason"] or "BOUNDARY_IDENTIFIER_REFERENCED" in finding["reason"]
    assert report["status"] != "PASS"


def test_classification_publishes_no_typed_verdict_for_a_clean_bounded_scan(tmp_path):
    # No installed closure establishes, so no typed verdict is ever published.
    root, manifest = _benign_with_witness(tmp_path)
    assert _verdicts(root, manifest) == []


def test_independent_reconciler_agrees_that_no_typed_verdict_is_published(tmp_path):
    root, manifest = _benign_with_witness(tmp_path)
    assert _reconcile_with(root, manifest, _verdicts(root, manifest))["status"] == "PASS"


@pytest.mark.parametrize("case", [
    "legacy_pair", "unknown_status", "witness_digest_only", "row_digest_mismatch",
    "bad_receipt_digest", "other_object",
])
# An omitted verdict key is refused at the reconciler boundary by
# test_reconciler_rejects_a_payload_that_omits_the_verdict_key_entirely: the Python
# caller always sends a list, so a None here is normalized to [] before the wire.
def test_independent_reconciler_fails_closed_on_untyped_or_forged_verdicts(tmp_path, case):
    root, manifest = _benign_with_witness(tmp_path)
    # A shape-valid verdict that no fresh run produced; every defect below must still be refused.
    decision = subject_row(manifest)["classification"]["LEDGER"]
    verdict = {"object_id": "accounts.py", "kind": "LEDGER", "status": nr.ESTABLISHED,
               "receipt_digest": "sha256:" + "e" * 64, "closure_digest": nr.closure_digest("LEDGER"),
               "decision_row_digest": value_digest({key: item for key, item in decision.items()
                                                    if key != "refutation"})}
    witness_digest = subject_row(manifest)["classification"]["LEDGER"]["refutation"]["witness_digest"]
    forged = {
        "legacy_pair": [["accounts.py", "LEDGER"]],
        "unknown_status": [{**verdict, "status": "UNKNOWN"}],
        "witness_digest_only": [{"witness_digest": witness_digest}],
        "row_digest_mismatch": [{**verdict, "decision_row_digest": "sha256:" + "1" * 64}],
        "bad_receipt_digest": [{**verdict, "receipt_digest": "sha256:xyz"}],
        "other_object": [{**verdict, "object_id": "elsewhere.py"}],
    }[case]
    assert _reconcile_with(root, manifest, forged)["status"] == "FAIL"


def test_source_reader_refuses_a_census_path_that_escapes_the_root(tmp_path):
    from verifier.runtime import namespace_classification as classification_module

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "x.py").write_text("def ledger_summary(): pass\n", encoding="utf-8")
    root = tmp_path / "repo"
    root.mkdir()
    try:
        (root / "linked").symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation requires a privilege this host does not grant")
    read = classification_module._source_reader(root)
    with pytest.raises(OSError, match="CENSUS_PATH_ESCAPES_ROOT|NOT_A_REGULAR_FILE"):
        read("linked/x.py")


def test_reconciler_rejects_a_payload_that_omits_the_verdict_key_entirely(tmp_path, monkeypatch):
    import json
    import shutil

    root, manifest = _benign_with_witness(tmp_path)
    captured: dict[str, bytes] = {}
    original = admission._run_bounded_reconciler

    def capture(command, wire, **kwargs):
        if any(str(part).endswith("namespace_reconcile.mjs") for part in command):
            captured["wire"] = wire
        return original(command, wire, **kwargs)

    monkeypatch.setattr(admission, "_run_bounded_reconciler", capture)
    assert _reconcile_with(root, manifest, _verdicts(root, manifest))["status"] == "PASS"

    node = shutil.which("node")
    script = str(Path(admission.__file__).with_name("namespace_reconcile.mjs"))
    limits = dict(output_limit=16 * 1024 * 1024, stderr_limit=1024 * 1024, timeout_seconds=20)
    positive = original([node, script], captured["wire"], **limits)
    assert positive["returncode"] == 0

    payload = json.loads(captured["wire"])
    del payload["established_non_applicability"]
    omitted = original([node, script], canonical_bytes(payload), **limits)
    assert omitted["returncode"] != 0
    assert b"NAMESPACE_RECONCILIATION_REJECTED" in omitted["stdout"]


# --- per-kind closures through classification, and the Option A blocking rule ---

ADDED_KINDS = ("TRANSACTION", "ASSET", "MARKET", "MEASUREMENT", "SENSOR", "CONTROLLER",
               "ACTUATOR", "PROTOCOL", "POLICY", "ROBOT", "FINBOT")
ORIGINAL_KINDS = ("HUMAN", "ACTOR", "COLLECTIVE", "ROLE", "IDENTITY", "OWNER",
                  "HARDWARE", "RECEIPT", "OBJECT", "GRAPH", "SPACE", "TIME", "EVENT",
                  "ENV", "DATA", "VERIFIER", "BENCH", "ARCH", "TRAIN", "HYPER",
                  "MODEL", "HARNESS", "AGENT", "SIM", "BOT", "TOKEN")


def declared_subject(tmp_path: Path, kind: str, source: str, *, witness: bool) -> tuple[Path, dict]:
    """One object whose ``kind`` is DOES_NOT_APPLY, optionally bound to a fresh-run witness."""
    root = repository(tmp_path, {"accounts.py": source})
    draft = admission.build_template(root)
    manifest = draft["manifest"]
    for row in manifest["objects"]:
        row["reason"] = REASON
    subject = subject_row(manifest)
    subject["classification"][kind].update(
        status="DOES_NOT_APPLY", reason=PROSE, evidence=draft["source_evidence"])
    save(root, manifest)
    if witness:
        subject["classification"][kind]["refutation"] = build(root, manifest, kind)
        save(root, manifest)
    return root, manifest


@pytest.mark.parametrize("kind", [*(kind for kind in ORIGINAL_KINDS if kind != "OBJECT"),
                                  "LEDGER", *ADDED_KINDS])
def test_clean_bound_witness_is_documented_for_each_installed_kind(tmp_path, kind):
    root, manifest = declared_subject(tmp_path / kind, kind, OTHER_SOURCE, witness=True)
    result = classify(root, manifest, context=context_for(root))
    assert [row for row in result["non_applicability_verdicts"] if row["object_id"] == "accounts.py"] == []
    decision = _decision(result, kind)
    assert (decision["non_applicability"], decision["refutation_code"]) == (DOCUMENTED, DOCUMENTED_CODE)
    assert _blocking(result, kind) == []


@pytest.mark.parametrize(("kind", "source", "status", "marker"), [
    ("MARKET", "def submit_order(entry):\n    return entry\n", "FAIL", "BOUNDARY_IDENTIFIER_REFERENCED"),
    ("LEDGER", "def submit_order(entry):\n    return entry\n", DOCUMENTED, DOCUMENTED_CODE),
])
def test_boundary_reference_refutes_only_the_kind_that_owns_it(tmp_path, kind, source, status, marker):
    root, manifest = declared_subject(tmp_path, kind, source, witness=True)
    result = classify(root, manifest, context=context_for(root))
    assert result["non_applicability_verdicts"] == []
    if status == DOCUMENTED:
        assert _decision(result, kind)["refutation_code"] == marker
        assert _blocking(result, kind) == []
        return
    finding = next(row for row in result["findings"]
                   if row["code"] == "NAMESPACE_NON_APPLICABILITY_NOT_ESTABLISHED"
                   and row["reason"].startswith(kind + " "))
    assert finding["status"] == status
    assert marker in finding["reason"]


def test_unestablished_non_applicability_blocks_even_when_it_adds_no_obligation(tmp_path):
    """Option A: an unestablished DOES_NOT_APPLY is blocking even with no obligation to remove."""
    # An injected callable leaves the owned effect census open, so the claim is not admitted.
    root, manifest = declared_subject(tmp_path, "ASSET", "def helper(callback):\n    return callback()\n",
                                      witness=False)
    result = classify(root, manifest, context=context_for(root))
    assert "ASSET" not in result["objects"][0]["effective_kinds"]
    assert not any(row["obligation_id"] and row["obligation_id"].startswith("ASSET-")
                   for row in result["required_obligations"])
    finding = next(row for row in result["findings"]
                   if row["code"] == "NAMESPACE_NON_APPLICABILITY_NOT_ESTABLISHED"
                   and row["reason"].startswith("ASSET "))
    assert finding["status"] == "UNKNOWN"
    assert CLOSED_EFFECT_CODE in finding["reason"]
    assert "still blocks admission" in finding["reason"]


def test_core_kind_non_applicability_is_documented_under_its_own_closure_and_never_published(tmp_path):
    root, manifest = declared_subject(tmp_path, "BOT", OTHER_SOURCE, witness=True)
    result = classify(root, manifest, context=context_for(root))
    assert not [row for row in result["non_applicability_verdicts"] if row["kind"] == "BOT"]
    decision = next(row for row in result["objects"][0]["classification"] if row["kind"] == "BOT")
    assert decision["non_applicability"] == DOCUMENTED
    assert decision["refutation_code"] == DOCUMENTED_CODE
    assert _blocking(result, "BOT") == []


def _link_directory(link: Path, target: Path) -> bool:
    """Create a symbolic link or, on Windows, a junction; return False when neither is available."""
    try:
        os.symlink(target, link, target_is_directory=True)
        return True
    except OSError:
        pass
    if os.name == "nt":
        completed = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)],
                                   capture_output=True, check=False)
        return completed.returncode == 0
    return False


def test_source_reader_refuses_a_linked_or_junctioned_census_directory(tmp_path):
    from verifier.runtime import namespace_classification as classification

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "accounts.py").write_bytes(b"x = 1\n")
    root = tmp_path / "repo"
    root.mkdir()
    (root / "inside.py").write_bytes(b"x = 2\n")
    if not _link_directory(root / "linked", outside):
        pytest.skip("neither a symbolic link nor a junction can be created here")
    read = classification._source_reader(root)
    assert read("inside.py") == b"x = 2\n"
    with pytest.raises(OSError, match="CENSUS_PATH_REPARSE_POINT"):
        read("linked/accounts.py")


# --- closed-effect precondition: a bound witness establishes only over a CLOSED, non-empty census ---

HELPER_CALLER = "from ledger_helper import persist\n\n\ndef record(entry):\n    return persist(entry)\n"
HELPER_WRITER = ("def persist(entry):\n    return append_ledger_entry(entry)\n\n\n"
                 "def append_ledger_entry(entry):\n    return entry\n")
# A renamed method: no registered LEDGER identifier, but an append-only file write.
RENAMED_JOURNAL = ("def persist_entry(path, entry):\n"
                   "    with open(path, 'a', encoding='utf-8') as handle:\n"
                   "        handle.write(entry)\n")
CLOSED_EFFECT_CODE = "CLOSED_EFFECT_AUDIT_NOT_CLOSED"


def _ledger_finding(result, object_id="accounts.py"):
    return next(row for row in result["findings"]
                if row["code"] == "NAMESPACE_NON_APPLICABILITY_NOT_ESTABLISHED"
                and row["object_id"] == object_id and row["reason"].startswith("LEDGER "))


def _ledger_established(result, object_id="accounts.py"):
    return any(row["kind"] == "LEDGER" and row["status"] == nr.ESTABLISHED
               for row in result["non_applicability_verdicts"] if row["object_id"] == object_id)


def _forged_audit(monkeypatch, **fields):
    """Replace only the audit's reported state; the real audit still reads the census."""
    from verifier.runtime import package_original_kind_review as review

    real = review.audit_closed_effects

    def forged(root, owned_paths, **kwargs):
        return dataclasses.replace(real(root, owned_paths, **kwargs), **fields)

    monkeypatch.setattr(review, "audit_closed_effects", forged)


def test_omitted_helper_escape_cannot_establish_ledger_non_applicability(tmp_path):
    from verifier.runtime import package_original_kind_review as review

    root, manifest = ledger_subject(tmp_path, {"accounts.py": HELPER_CALLER, "ledger_helper.py": HELPER_WRITER})
    subject_row(manifest)["classification"]["LEDGER"]["refutation"] = build(root, manifest)
    result = classify(root, manifest, context=context_for(root))
    assert not _ledger_established(result)
    finding = _ledger_finding(result)
    assert finding["status"] == "UNKNOWN"
    reason = finding["reason"]
    assert CLOSED_EFFECT_CODE in reason
    blockers = sorted(review.audit_closed_effects(root, ["accounts.py"]).blockers)
    assert "IMPORT_ESCAPES_OWNERSHIP:accounts.py:1:ledger_helper.py" in blockers
    assert blockers[0] in reason


def test_renamed_journal_write_cannot_establish_ledger_non_applicability(tmp_path):
    root, manifest = ledger_subject(tmp_path, {"accounts.py": RENAMED_JOURNAL})
    subject_row(manifest)["classification"]["LEDGER"]["refutation"] = build(root, manifest)
    result = classify(root, manifest, context=context_for(root))
    assert not _ledger_established(result)
    finding = _ledger_finding(result)
    assert finding["status"] == "UNKNOWN"
    reason = finding["reason"]
    assert CLOSED_EFFECT_CODE in reason
    assert "EXTERNAL_WRITE_CONSEQUENCE:filesystem_write:accounts.py:2" in reason


def test_package_marker_census_cannot_establish_ledger_non_applicability(tmp_path):
    marker = "pkg/__init__.py"
    (tmp_path / "pkg").mkdir()
    root = repository(tmp_path, {marker: "", "accounts.py": LEDGER_BENIGN})
    draft = admission.build_template(root)
    manifest = draft["manifest"]
    for row in manifest["objects"]:
        row["reason"] = REASON
    subject = next(row for row in manifest["objects"] if row["object_id"] == marker)
    subject["classification"]["LEDGER"].update(status="DOES_NOT_APPLY", reason=PROSE, evidence=draft["source_evidence"])
    save(root, manifest)
    module = classification.witness_owner(marker)
    assert module is not None
    decision = subject["classification"]["LEDGER"]
    expected = nr.ExpectedReview(
        object_id=marker, kind="LEDGER", basis=nr.BASIS_EXECUTABLE_CLOSURE, review_module=module,
        review_mechanism_digest=mechanism_digest(),
        review_row_digest=value_digest({key: item for key, item in decision.items() if key != "refutation"}))
    decision["refutation"] = nr.build_witness(expected=expected, source_paths=[marker], callee_paths=[],
                                              inventory=context_for(root)["inventory"])
    result = classify(root, manifest, context=context_for(root))
    assert not _ledger_established(result, object_id=marker)
    assert "EMPTY_CENSUS" in _ledger_finding(result, object_id=marker)["reason"]


def test_closed_benign_census_is_documented_not_demoted_by_the_precondition(tmp_path):
    """Guard: a genuinely closed, non-empty census reaches DOCUMENTED, not a demotion."""
    root, manifest = ledger_subject(tmp_path, {"accounts.py": LEDGER_BENIGN, "other.py": OTHER_SOURCE})
    subject_row(manifest)["classification"]["LEDGER"]["refutation"] = build(root, manifest)
    result = classify(root, manifest, context=context_for(root))
    assert not _ledger_established(result)
    assert CLOSED_EFFECT_CODE not in str(result["findings"])
    assert _decision(result, "LEDGER")["non_applicability"] == DOCUMENTED
    assert _blocking(result, "LEDGER") == []


@pytest.mark.parametrize(("fields", "fragment"), [
    # Bypassed CLOSED state: the reported status is not CLOSED although no blocker is listed.
    ({"status": "UNKNOWN", "blockers": ()}, "STATUS:UNKNOWN"),
    # Ignored blocker: CLOSED is reported while a blocker is still listed.
    ({"status": "CLOSED", "blockers": ("IMPORT_ESCAPES_OWNERSHIP:accounts.py:1:ledger_helper.py",)},
     "IMPORT_ESCAPES_OWNERSHIP:accounts.py:1:ledger_helper.py"),
    # Empty-census guard: CLOSED with no blocker but no owned source bytes at all.
    ({"status": "CLOSED", "blockers": (), "sources": ()}, "EMPTY_CENSUS"),
])
def test_forged_closed_effect_state_cannot_establish_ledger(tmp_path, monkeypatch, fields, fragment):
    root, manifest = ledger_subject(tmp_path, {"accounts.py": LEDGER_BENIGN, "other.py": OTHER_SOURCE})
    subject_row(manifest)["classification"]["LEDGER"]["refutation"] = build(root, manifest)
    _forged_audit(monkeypatch, **fields)
    result = classify(root, manifest, context=context_for(root))
    assert not _ledger_established(result)
    reason = _ledger_finding(result)["reason"]
    assert fragment in reason


def test_closed_effect_blocker_detail_is_bounded(tmp_path, monkeypatch):
    root, manifest = ledger_subject(tmp_path, {"accounts.py": LEDGER_BENIGN, "other.py": OTHER_SOURCE})
    subject_row(manifest)["classification"]["LEDGER"]["refutation"] = build(root, manifest)
    _forged_audit(monkeypatch, status="UNKNOWN", blockers=("CALL_TARGET_UNRESOLVED:" + "x" * 1000,))
    context = context_for(root)
    verdict = classification._closed_effect_blocker(context, "accounts_py", {"accounts.py"})
    assert verdict is not None
    assert verdict.code == CLOSED_EFFECT_CODE
    assert len(verdict.detail.encode("utf-8")) <= 256


def test_forged_open_census_never_masks_a_boundary_refutation_fail(tmp_path, monkeypatch):
    """FAIL outranks UNKNOWN: the precondition must not demote a registered boundary refutation."""
    _forged_audit(monkeypatch, status="UNKNOWN", blockers=("IMPORT_ESCAPES_OWNERSHIP:accounts.py:1:x.py",))
    root, manifest = ledger_subject(tmp_path, {"accounts.py": LEDGER_SOURCE})
    subject_row(manifest)["classification"]["LEDGER"]["refutation"] = build(root, manifest)
    result = classify(root, manifest, context=context_for(root))
    finding = _ledger_finding(result)
    assert finding["status"] == "FAIL"
    assert "BOUNDARY_IDENTIFIER_REFERENCED" in finding["reason"]
    assert CLOSED_EFFECT_CODE not in finding["reason"]


def test_empty_owned_census_is_empty_census_without_running_the_audit(monkeypatch):
    from verifier.runtime import package_original_kind_review as review

    def refuse(*args, **kwargs):
        raise AssertionError("an empty census must not reach the audit")

    monkeypatch.setattr(review, "audit_closed_effects", refuse)
    verdict = classification._closed_effect_blocker({"root": Path("."), "inventory": {}}, "accounts_py", set())
    assert verdict is not None
    assert (verdict.status, verdict.code) == (nr.UNKNOWN, "EMPTY_CENSUS")


def test_closed_effect_mechanism_drift_never_yields_establishment(tmp_path, monkeypatch):
    """A witness bound before the mechanism changed cannot establish under the new mechanism."""
    root, manifest = ledger_subject(tmp_path, {"accounts.py": LEDGER_BENIGN, "other.py": OTHER_SOURCE})
    subject_row(manifest)["classification"]["LEDGER"]["refutation"] = build(root, manifest)
    drifted = {**admission.mechanism_binding(), "runtime/package_original_kind_review.py": "sha256:" + "0" * 64}
    monkeypatch.setattr(admission, "mechanism_binding", lambda: drifted)
    result = classify(root, manifest, context=context_for(root))
    assert not _ledger_established(result)


# --- call-free exemplars: realistic effects with no registered boundary identifier ---
# Each subject performs its effect directly, so the finite scan and the owned effect audit
# are clean.  That may only ever be DOCUMENTED: no clean scan may remove a hint-selected
# obligation, because these subjects really are the kind their DOES_NOT_APPLY denies.

CALL_FREE_EXEMPLARS = {
    "FINBOT": "def finbot_adjust_balance(account, amount):\n    account['balance'] -= amount\n    return account\n",
    "VERIFIER": "def verifier_build_verdict(claim):\n    return {'verdict': 'PASS', 'claim': claim}\n",
    "AGENT": "class Agent:\n    def plan(self, goal):\n        return [goal]\n\n    def act(self, step):\n        return step\n",
    "TIME": "import time\n\n\ndef time_stamp():\n    return time.time()\n",
    "LEDGER": "def ledger_post(account, amount):\n    account['balance'] += amount\n    return account\n",
}


def _kind_exemplar(kind: str) -> str:
    # Closed by construction: no call on a parameter, so the audit reaches the closure.
    word = kind.lower()
    return (f"def {word}_step(value):\n"
            f"    {word}_total = value + 1\n"
            f"    return {word}_total\n")


@pytest.mark.parametrize("kind", sorted(CALL_FREE_EXEMPLARS))
def test_call_free_exemplar_is_only_documented_and_keeps_its_required_obligations(tmp_path, kind):
    from verifier.runtime.namespace_admission import assess

    root, _manifest = declared_subject(tmp_path, kind, CALL_FREE_EXEMPLARS[kind], witness=True)
    report = assess(root)
    assert report["status"] != "PASS"
    # The hint keeps the role effective; kinds with registered obligations keep those rows too.
    assert kind in report["object_assessments"][0]["effective_kinds"], kind
    if contracts.requirements_for(contracts.namespace_registry(), [kind]):
        retained = [row for row in report["required_obligations"]
                    if row["object_id"] == "accounts.py" and row["kind"] == kind]
        assert retained, kind
    decision = next(row for row in report["object_assessments"][0]["classification"] if row["kind"] == kind)
    assert (decision["non_applicability"], decision["refutation_status"]) == (DOCUMENTED, DOCUMENTED)
    assert not any(row["code"] == "NAMESPACE_NON_APPLICABILITY_NOT_ESTABLISHED"
                   and row["reason"].startswith(kind + " ") for row in report["findings"])


@pytest.mark.parametrize("kind", [kind for kind in (*ORIGINAL_KINDS, *ADDED_KINDS) if kind != "OBJECT"])
def test_call_free_exemplar_for_each_installed_kind_never_establishes(tmp_path, kind):
    # OBJECT has no classification row in the template; its generic behaviour is tested below.
    root, manifest = declared_subject(tmp_path / kind, kind, _kind_exemplar(kind), witness=True)
    result = classify(root, manifest, context=context_for(root))
    assert [row for row in result["non_applicability_verdicts"] if row["object_id"] == "accounts.py"] == []
    assert _decision(result, kind)["non_applicability"] == DOCUMENTED
    assert _blocking(result, kind) == []
    assert kind in result["objects"][0]["effective_kinds"], kind
    if contracts.requirements_for(contracts.namespace_registry(), [kind]):
        assert [row for row in result["required_obligations"] if row["kind"] == kind], kind


def test_generic_object_primary_cannot_erase_an_inferred_hint_role(tmp_path):
    # OBJECT remains a valid primary label, but it never erases a role the source implies.
    root, manifest = declared_subject(tmp_path, "FINBOT", CALL_FREE_EXEMPLARS["FINBOT"], witness=True)
    subject_row(manifest)["kind"] = "OBJECT"
    subject_row(manifest)["specializations"] = []
    result = classify(root, manifest, context=context_for(root))
    row = result["objects"][0]
    assert row["declared_kinds"] == ["OBJECT"]
    assert "FINBOT" in row["effective_kinds"]
    assert [item for item in result["required_obligations"] if item["kind"] == "FINBOT"]
    assert result["non_applicability_verdicts"] == []


# --- D1: a DOES_NOT_APPLY is admitted as DOCUMENTED, never ESTABLISHED ---
# Admission needs all four: a repository-specific reason, current owned evidence, a
# fresh clean closure scan of the exact census, and a clean owned closed-effect audit.
# DOCUMENTED answers the classification question.  It is not proof, so it never removes
# an obligation a source hint selected and never overrides a declared role.


def _decision(result: dict, kind: str, object_id: str = "accounts.py") -> dict:
    row = next(row for row in result["objects"] if row["object_id"] == object_id)
    return next(item for item in row["classification"] if item["kind"] == kind)


def _blocking(result: dict, kind: str, object_id: str = "accounts.py") -> list[dict]:
    return [row for row in result["findings"]
            if row["object_id"] == object_id
            and row["code"] in ("NAMESPACE_NON_APPLICABILITY_NOT_ESTABLISHED", "NAMESPACE_CLASSIFICATION_UNRESOLVED")
            and row["reason"].startswith((kind + " ", kind + ":"))]


def test_d1_unhinted_kind_with_all_four_conditions_is_documented_and_unblocked(tmp_path):
    root, manifest = declared_subject(tmp_path, "ASSET", OTHER_SOURCE, witness=True)
    result = classify(root, manifest, context=context_for(root))
    decision = _decision(result, "ASSET")
    assert decision["non_applicability"] == DOCUMENTED
    assert decision["refutation_status"] == DOCUMENTED
    assert decision["refutation_code"] == DOCUMENTED_CODE
    assert decision["refutation_receipt_digest"].startswith("sha256:")
    assert decision["semantic_classification_status"] == "NOT_ESTABLISHED"
    assert _blocking(result, "ASSET") == []
    assert "ASSET" not in result["objects"][0]["effective_kinds"]
    # DOCUMENTED is never ESTABLISHED: nothing is published to the reconciler as one.
    assert result["non_applicability_verdicts"] == []


def test_d1_documented_never_removes_a_hint_selected_obligation(tmp_path):
    # ledger_post really posts to a ledger, yet its scan and its effect audit are clean.
    # DOCUMENTED answers the question; the LEDGER hint keeps every LEDGER obligation.
    root, manifest = declared_subject(tmp_path, "LEDGER", CALL_FREE_EXEMPLARS["LEDGER"], witness=True)
    result = classify(root, manifest, context=context_for(root))
    assert _decision(result, "LEDGER")["non_applicability"] == DOCUMENTED
    assert _blocking(result, "LEDGER") == []
    assert "LEDGER" in result["objects"][0]["effective_kinds"]
    expected = {row["id"] for row in contracts.requirements_for(contracts.namespace_registry(), ["LEDGER"])}
    assert {row["id"] for row in retained_ledger(result)} == expected
    assert result["non_applicability_verdicts"] == []


def test_d1_documented_never_overrides_a_source_declared_role(tmp_path):
    root, manifest = declared_subject(
        tmp_path, "LEDGER", '__vstd_kinds__ = ("LEDGER",)\n' + LEDGER_BENIGN, witness=True)
    subject_row(manifest)["kind"] = "OBJECT"
    subject_row(manifest)["specializations"] = []
    save(root, manifest)
    report = admission.assess(root)
    assert report["status"] == "FAIL"
    assert any(row["code"] == "NAMESPACE_REFUTATION_CONTRADICTS_DECLARATION" for row in report["findings"])
    assert any(row["kind"] == "LEDGER" for row in report["required_obligations"])


@pytest.mark.parametrize(("damage", "status"), [("unowned_evidence", "UNKNOWN"), ("stale_evidence", "FAIL")])
def test_d1_clean_scan_and_audit_without_current_owned_evidence_is_not_admitted(tmp_path, damage, status):
    root = repository(tmp_path, {"accounts.py": OTHER_SOURCE, "other.py": OTHER_SOURCE})
    draft = admission.build_template(root)
    manifest = draft["manifest"]
    for row in manifest["objects"]:
        row["reason"] = REASON
    evidence = {"unowned_evidence": [ref for ref in draft["source_evidence"] if ref["path"] == "other.py"],
                "stale_evidence": [{"path": "accounts.py", "sha256": "sha256:" + "0" * 64}]}[damage]
    decision = subject_row(manifest)["classification"]["ASSET"]
    decision.update(status="DOES_NOT_APPLY", reason=PROSE, evidence=evidence)
    decision["refutation"] = build(root, manifest, "ASSET")
    save(root, manifest)
    result = classify(root, manifest, context=context_for(root))
    assert _decision(result, "ASSET")["non_applicability"] == "NOT_ESTABLISHED"
    finding = next(row for row in _blocking(result, "ASSET")
                   if row["code"] == "NAMESPACE_NON_APPLICABILITY_NOT_ESTABLISHED")
    assert finding["status"] == status
    assert "not admitted" in finding["reason"]


def test_d1_no_reader_means_no_fresh_scan_or_audit_and_no_admission(tmp_path):
    root, manifest = declared_subject(tmp_path, "ASSET", OTHER_SOURCE, witness=True)
    context = context_for(root)
    context["read"] = None
    result = classify(root, manifest, context=context)
    assert _decision(result, "ASSET")["non_applicability"] == "NOT_ESTABLISHED"
    finding = next(row for row in _blocking(result, "ASSET")
                   if row["code"] == "NAMESPACE_NON_APPLICABILITY_NOT_ESTABLISHED")
    assert finding["status"] == "UNKNOWN"
    assert "READER_ABSENT" in finding["reason"]


def test_d1_independent_reconciler_refuses_a_documented_verdict_as_an_establishment(tmp_path):
    # DOCUMENTED never refutes a hint, so the reconciler must never accept one as ESTABLISHED.
    root, manifest = _benign_with_witness(tmp_path)
    decision = subject_row(manifest)["classification"]["LEDGER"]
    forged = [{"object_id": "accounts.py", "kind": "LEDGER", "status": DOCUMENTED,
               "receipt_digest": "sha256:" + "e" * 64, "closure_digest": nr.closure_digest("LEDGER"),
               "decision_row_digest": value_digest({key: item for key, item in decision.items()
                                                    if key != "refutation"})}]
    assert _reconcile_with(root, manifest, forged)["status"] == "FAIL"
    assert _reconcile_with(root, manifest, _verdicts(root, manifest))["status"] == "PASS"


# --- D1 as worded: no stored witness ---
# The four conditions are a reason, current owned evidence, a fresh clean closure scan and
# a clean effect audit.  Without a witness, polish runs the closure now over the object's
# exact current owned census, every owned file, and audits the same bytes.  Nothing is
# stored and nothing is authored: the reviewer's DOES_NOT_APPLY row is only admitted.

NOTES_MD = "# Accounts\nPlain notes about the bounded helper.\n"


def merged_subject(tmp_path: Path, files: dict[str, str], kind: str = "ASSET",
                   object_id: str = "accounts.py") -> tuple[Path, dict]:
    """One object that owns every file below, with ``kind`` DOES_NOT_APPLY and no witness."""
    root = repository(tmp_path, files)
    draft = admission.build_template(root)
    manifest = draft["manifest"]
    subject = next(row for row in manifest["objects"] if row["object_id"] == object_id)
    for row in [row for row in manifest["objects"] if row is not subject]:
        subject["surfaces"] = sorted({*subject["surfaces"], *row["surfaces"]})
        manifest["objects"].remove(row)
    subject["reason"] = REASON
    subject["classification"][kind].update(status="DOES_NOT_APPLY", reason=PROSE,
                                           evidence=draft["source_evidence"])
    save(root, manifest)
    return root, manifest


def _census_verdict(root: Path, manifest: dict, kind: str = "ASSET", object_id: str = "accounts.py"):
    observed = discovery.discover(root)
    surfaces = {row["surface_id"]: row["path"] for row in observed["surfaces"]}
    subject = next(row for row in manifest["objects"] if row["object_id"] == object_id)
    owned = {surfaces[surface] for surface in subject["surfaces"] if surface in surfaces}
    context = classification.refutation_context(observed, mechanism_digest(), root=root)
    return classification._non_applicability_verdict(
        object_id, kind, subject["classification"][kind], owned, context), owned


def test_d1_without_a_witness_is_documented_by_a_fresh_census_scan_and_audit(tmp_path):
    root, manifest = declared_subject(tmp_path, "ASSET", OTHER_SOURCE, witness=False)
    result = classify(root, manifest, context=context_for(root))
    decision = _decision(result, "ASSET")
    assert decision["non_applicability"] == DOCUMENTED
    assert (decision["refutation_status"], decision["refutation_code"]) == (DOCUMENTED, DOCUMENTED_CODE)
    assert decision["refutation_receipt_digest"].startswith("sha256:")
    assert decision["semantic_classification_status"] == "NOT_ESTABLISHED"
    assert _blocking(result, "ASSET") == []
    assert "ASSET" not in result["objects"][0]["effective_kinds"]
    assert result["non_applicability_verdicts"] == []
    # Nothing was stored: the reviewer's row is unchanged and carries no witness.
    assert "refutation" not in subject_row(manifest)["classification"]["ASSET"]


def test_d1_without_a_witness_never_removes_a_hint_selected_obligation(tmp_path):
    root, manifest = declared_subject(tmp_path, "LEDGER", CALL_FREE_EXEMPLARS["LEDGER"], witness=False)
    result = classify(root, manifest, context=context_for(root))
    assert _decision(result, "LEDGER")["non_applicability"] == DOCUMENTED
    assert _blocking(result, "LEDGER") == []
    assert "LEDGER" in result["objects"][0]["effective_kinds"]
    expected = {row["id"] for row in contracts.requirements_for(contracts.namespace_registry(), ["LEDGER"])}
    assert {row["id"] for row in retained_ledger(result)} == expected
    assert result["non_applicability_verdicts"] == []


def test_d1_without_a_witness_never_overrides_a_source_declared_role(tmp_path):
    root, manifest = declared_subject(
        tmp_path, "LEDGER", '__vstd_kinds__ = ("LEDGER",)\n' + LEDGER_BENIGN, witness=False)
    subject_row(manifest)["kind"] = "OBJECT"
    subject_row(manifest)["specializations"] = []
    save(root, manifest)
    report = admission.assess(root)
    assert report["status"] == "FAIL"
    assert any(row["code"] == "NAMESPACE_REFUTATION_CONTRADICTS_DECLARATION" for row in report["findings"])
    assert any(row["kind"] == "LEDGER" for row in report["required_obligations"])


@pytest.mark.parametrize(("damage", "status"), [("unowned_evidence", "UNKNOWN"), ("stale_evidence", "FAIL"),
                                                ("blank_reason", "UNKNOWN")])
def test_d1_without_a_witness_needs_a_reason_and_current_owned_evidence(tmp_path, damage, status):
    root = repository(tmp_path, {"accounts.py": OTHER_SOURCE, "other.py": OTHER_SOURCE})
    draft = admission.build_template(root)
    manifest = draft["manifest"]
    for row in manifest["objects"]:
        row["reason"] = REASON
    evidence = {"unowned_evidence": [ref for ref in draft["source_evidence"] if ref["path"] == "other.py"],
                "stale_evidence": [{"path": "accounts.py", "sha256": "sha256:" + "0" * 64}],
                "blank_reason": draft["source_evidence"]}[damage]
    decision = subject_row(manifest)["classification"]["ASSET"]
    decision.update(status="DOES_NOT_APPLY", reason=" " if damage == "blank_reason" else PROSE, evidence=evidence)
    save(root, manifest)
    result = classify(root, manifest, context=context_for(root))
    assert _decision(result, "ASSET")["non_applicability"] == "NOT_ESTABLISHED"
    finding = next(row for row in _blocking(result, "ASSET")
                   if row["code"] == "NAMESPACE_NON_APPLICABILITY_NOT_ESTABLISHED")
    assert finding["status"] == status
    assert "not admitted" in finding["reason"]


def test_d1_without_a_witness_needs_a_reader_for_the_fresh_scan(tmp_path):
    root, manifest = declared_subject(tmp_path, "ASSET", OTHER_SOURCE, witness=False)
    context = context_for(root)
    context["read"] = None
    result = classify(root, manifest, context=context)
    assert _decision(result, "ASSET")["non_applicability"] == "NOT_ESTABLISHED"
    finding = next(row for row in _blocking(result, "ASSET")
                   if row["code"] == "NAMESPACE_NON_APPLICABILITY_NOT_ESTABLISHED")
    assert finding["status"] == "UNKNOWN"
    assert "READER_ABSENT" in finding["reason"]


def test_d1_without_a_witness_a_boundary_mention_is_unknown_with_a_review_action(tmp_path):
    root, manifest = declared_subject(tmp_path, "LEDGER", LEDGER_SOURCE, witness=False)
    result = classify(root, manifest, context=context_for(root))
    assert _decision(result, "LEDGER")["non_applicability"] == "NOT_ESTABLISHED"
    finding = _ledger_finding(result)
    assert finding["status"] == "UNKNOWN"
    assert "BOUNDARY_IDENTIFIER_REFERENCED" in finding["reason"]
    assert "append_ledger_entry" in finding["reason"]
    assert "witness" not in finding["next_action"].lower()
    assert "APPLIES" in finding["next_action"]
    assert retained_ledger(result)


def test_d1_census_scan_covers_every_owned_file_of_a_multi_file_object(tmp_path):
    files = {"accounts.py": OTHER_SOURCE, "helper.py": "def other_helper():\n    return 2\n",
             "notes.md": NOTES_MD}
    root, manifest = merged_subject(tmp_path, files)
    verdict, owned = _census_verdict(root, manifest)
    assert owned == set(files)
    assert (verdict.status, verdict.code) == (DOCUMENTED, DOCUMENTED_CODE)
    assert [anchor["path"] for anchor in verdict.receipt["anchors"]] == sorted(files)
    result = classify(root, manifest, context=context_for(root))
    assert _decision(result, "ASSET")["non_applicability"] == DOCUMENTED
    assert _blocking(result, "ASSET") == []


@pytest.mark.parametrize(("name", "source", "fragment"), [
    ("helper.py", "def mint_asset(value):\n    return value\n", "helper.py references mint_asset"),
    ("notes.md", "# Notes\nThe old code called mint_asset here.\n", "notes.md references mint_asset"),
])
def test_d1_a_boundary_mention_in_any_owned_file_keeps_the_claim_unadmitted(tmp_path, name, source, fragment):
    files = {"accounts.py": OTHER_SOURCE, "helper.py": "def other_helper():\n    return 2\n",
             "notes.md": NOTES_MD, name: source}
    root, manifest = merged_subject(tmp_path, files)
    verdict, _ = _census_verdict(root, manifest)
    assert (verdict.status, verdict.code) == ("UNKNOWN", "BOUNDARY_IDENTIFIER_REFERENCED")
    assert fragment in verdict.detail


def test_d1_effect_audit_covers_every_owned_python_file(tmp_path):
    files = {"accounts.py": OTHER_SOURCE, "journal.py": RENAMED_JOURNAL, "notes.md": NOTES_MD}
    root, manifest = merged_subject(tmp_path, files)
    verdict, _ = _census_verdict(root, manifest)
    assert (verdict.status, verdict.code) == ("UNKNOWN", CLOSED_EFFECT_CODE)
    assert verdict.detail == "EXTERNAL_WRITE_CONSEQUENCE:filesystem_write:journal.py:2"


def test_d1_data_files_are_scanned_but_never_sent_to_the_python_audit(tmp_path, monkeypatch):
    from verifier.runtime import package_original_kind_review as review

    audited: list[list[str]] = []
    real = review.audit_closed_effects

    def recording(root, owned_paths, **kwargs):
        audited.append(sorted(owned_paths))
        return real(root, owned_paths, **kwargs)

    monkeypatch.setattr(review, "audit_closed_effects", recording)
    files = {"accounts.py": OTHER_SOURCE, "notes.md": NOTES_MD, "table.csv": "a,b\n1,2\n",
             "config.toml": "name = 'plain'\n", "schema.json": '{"type": "object"}\n', "readme.txt": "plain\n"}
    root, manifest = merged_subject(tmp_path, files)
    verdict, _ = _census_verdict(root, manifest)
    assert (verdict.status, verdict.code) == (DOCUMENTED, DOCUMENTED_CODE)
    assert audited == [["accounts.py"]]


def test_d1_data_only_object_is_documented_without_an_executable_audit(tmp_path, monkeypatch):
    from verifier.runtime import package_original_kind_review as review

    def refuse(*args, **kwargs):
        raise AssertionError("a data-only census has no executable source to audit")

    root, manifest = merged_subject(tmp_path, {"schema.json": '{"type": "object"}\n', "notes.md": NOTES_MD},
                                    object_id="schema.json")
    monkeypatch.setattr(review, "audit_closed_effects", refuse)
    verdict, owned = _census_verdict(root, manifest, object_id="schema.json")
    assert owned == {"schema.json", "notes.md"}
    assert (verdict.status, verdict.code) == (DOCUMENTED, DOCUMENTED_CODE)
    result = classify(root, manifest, context=context_for(root))
    assert _decision(result, "ASSET", object_id="schema.json")["non_applicability"] == DOCUMENTED
    assert _blocking(result, "ASSET", object_id="schema.json") == []


def test_d1_census_of_only_empty_files_and_package_markers_is_empty(tmp_path):
    (tmp_path / "pkg").mkdir()
    root, manifest = merged_subject(tmp_path, {"accounts.py": "", "pkg/__init__.py": "", "empty.json": ""})
    verdict, _ = _census_verdict(root, manifest)
    assert (verdict.status, verdict.code) == ("UNKNOWN", "EMPTY_CENSUS")


def _non_applicability_blocker(result: dict, kind: str = "ASSET") -> dict:
    return next(row for row in _blocking(result, kind) if row["code"] == "NAMESPACE_NON_APPLICABILITY_NOT_ESTABLISHED")


def test_d1_unclosed_audit_next_action_offers_applies_and_names_the_audit_limit(tmp_path):
    # Moving another object's helper into this object, or deleting a needed write, is not a
    # repository action; the honest next steps are APPLIES or a reviewed audit change.
    root, manifest = merged_subject(tmp_path, {"accounts.py": OTHER_SOURCE, "journal.py": RENAMED_JOURNAL})
    finding = _non_applicability_blocker(classify(root, manifest, context=context_for(root)))
    assert CLOSED_EFFECT_CODE in finding["reason"]
    assert finding["next_action"].startswith("Record APPLIES if this object does this kind's work")
    assert "reviewed change" in finding["next_action"]


def test_d1_empty_census_next_action_asks_for_the_object_real_surfaces(tmp_path):
    (tmp_path / "pkg").mkdir()
    root, manifest = merged_subject(tmp_path, {"accounts.py": "", "pkg/__init__.py": "", "empty.json": ""})
    finding = _non_applicability_blocker(classify(root, manifest, context=context_for(root)))
    assert "EMPTY_CENSUS" in finding["reason"]
    assert finding["next_action"].startswith("Bind this object's real surfaces")


@pytest.mark.parametrize(("name", "source", "code", "fragment"), [
    # JavaScript passes the scan's gates but the Python audit cannot read it.
    ("app.js", "export const value = 1;\n", CLOSED_EFFECT_CODE, "UNSUPPORTED_LANGUAGE:app.js"),
    # An unregistered suffix is refused by the scan itself.
    ("tool.sh", "echo plain\n", "UNSUPPORTED_LANGUAGE", "tool.sh"),
])
def test_d1_non_python_code_still_blocks_admission(tmp_path, name, source, code, fragment):
    root, manifest = merged_subject(tmp_path, {"accounts.py": OTHER_SOURCE, name: source})
    verdict, owned = _census_verdict(root, manifest)
    assert owned == {"accounts.py", name}
    assert (verdict.status, verdict.code) == ("UNKNOWN", code)
    assert fragment in verdict.detail


def test_d1_effect_audit_is_bound_to_the_census_bytes(tmp_path):
    root, manifest = declared_subject(tmp_path, "ASSET", OTHER_SOURCE, witness=False)
    context = context_for(root)
    context["files"] = {**context["files"], "accounts.py": "sha256:" + "0" * 64}
    verdict = classification._closed_effect_blocker(context, None, {"accounts.py"})
    assert verdict is not None
    assert verdict.code == CLOSED_EFFECT_CODE
    assert verdict.detail.startswith("SOURCE_DIGEST_DIFFERS:accounts.py")


def test_d1_one_effect_audit_per_object_census_across_kinds(tmp_path, monkeypatch):
    from verifier.runtime import package_original_kind_review as review

    calls: list[tuple[str, ...]] = []
    real = review.audit_closed_effects

    def counting(root, owned_paths, **kwargs):
        calls.append(tuple(sorted(owned_paths)))
        return real(root, owned_paths, **kwargs)

    monkeypatch.setattr(review, "audit_closed_effects", counting)
    root = repository(tmp_path, {"accounts.py": OTHER_SOURCE})
    draft = admission.build_template(root)
    manifest = draft["manifest"]
    subject = subject_row(manifest)
    subject["reason"] = REASON
    for kind in ("ASSET", "ROBOT", "FINBOT", "MARKET"):
        subject["classification"][kind].update(status="DOES_NOT_APPLY", reason=PROSE,
                                               evidence=draft["source_evidence"])
    save(root, manifest)
    result = classify(root, manifest, context=context_for(root))
    assert all(_decision(result, kind)["non_applicability"] == DOCUMENTED
               for kind in ("ASSET", "ROBOT", "FINBOT", "MARKET"))
    assert calls == [("accounts.py",)]
