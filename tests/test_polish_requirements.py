"""Independent finite requirements gate tests using real native certificates.

JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256);
Unicode Transformation Format, 8-bit (UTF-8). OBJECT is a generic namespace
object; RECEIPT is a retained receipt record. Coordinates select a represented
kind, numbered meta-tier and internal grounding objective. Counts have no
physical unit; transport lengths count encoded bytes.

Test-only inventory construction describes the external selection fixture; no
production inventory-from-submission helper or fake authority callback is used.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, ObjectKind, composition_digest
from verifier.domains.contracts import object_facets, typed_facets
from verifier.domains.contracts.current_object_routes import current_object_route_catalog
from verifier.runtime import polish, polish_requirements as gate
from verifier.runtime.polish_capacity import CEILINGS


ZERO = "sha256:" + "0" * 64


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def fixture(version="1"):
    item = NamespaceObject.create("root", "OBJECT", {"private_value": "inventory-witness-must-not-echo"})
    policy = object_facets.object_facets_policy(trust_roots=("independent-test-selection",))
    intent = object_facets.object_facets_request(item, policy=policy)
    certificate = object_facets.build_object_facets_certificate(intent, canonical_bytes(item.to_dict()), policy=policy)
    second_policy = typed_facets.typed_facets_policy(trust_roots=["independent-test-selection"])
    evidence = canonical_bytes({"schema_version": typed_facets.COLLECTION_VERSION, "objects": [item.to_dict()]})
    second_intent = typed_facets.typed_facets_request(object_kind="OBJECT", subject_id="root",
        object_digest=item.digest, collection_digest=composition_digest([item]),
        evidence_ref=digest(evidence), policy=second_policy)
    second_certificate = typed_facets.build_typed_facets_certificate(second_intent, evidence, policy=second_policy)
    certificates = {digest(certificate): certificate.decode("utf-8"),
                    digest(second_certificate): second_certificate.decode("utf-8")}
    bundle = {"schema_version": "verifier-polish-bundle-" + version,
              "objects": [item.to_dict()], "certificates": certificates}
    request = {"schema_version": "verifier-polish-request-" + version, "root_id": "root",
        "collection_digest": composition_digest([item]), "bundle_digest": "",
        "requirements": [{"object_id": "root", "tier": tier, "applicability": "REQUIRED",
            "rationale": "Externally selected finite test scope", "objectives": []} for tier in range(1, 10)]}
    request["requirements"][0]["objectives"] = [
        {"semantic_version": object_facets.SEMANTIC_VERSION, "coordinate": "OBJECT-1.1",
            "request": intent, "policy": policy, "certificate_digest": digest(certificate)},
        {"semantic_version": typed_facets.SEMANTIC_VERSION, "coordinate": "OBJECT-1.2",
            "request": second_intent, "policy": second_policy, "certificate_digest": digest(second_certificate)}]
    if version == "2":
        bundle["certificates"] = {key: {"encoding": "utf8", "text": value} for key, value in certificates.items()}
        bundle["evidence_payloads"] = {}
        request["limits"] = dict(CEILINGS)
    rebind(bundle, request)
    inventory = {"schema_version": gate.INVENTORY_VERSION,
        "semantic_version": object_facets.SEMANTIC_VERSION, "catalog_digest": gate.requirements_catalog_digest(),
        "root_id": "root", "collection_digest": composition_digest([item]),
        "subjects": [{"object_id": "root", "object_kind": "OBJECT", "object_digest": item.digest}],
        "requirements": []}
    for row in request["requirements"]:
        selected = {"object_id": row["object_id"], "tier": row["tier"], "applicability": row["applicability"],
            "rationale_digest": digest(canonical_bytes(row["rationale"])), "objectives": []}
        for objective in row["objectives"]:
            selected["objectives"].append({"coordinate": objective["coordinate"],
                **gate.registered_objective_binding(objective["semantic_version"], objective["coordinate"], "OBJECT"),
                "request_digest": digest(canonical_bytes(objective["request"])),
                "policy_digest": digest(canonical_bytes(objective["policy"])),
                "certificate_digest": objective["certificate_digest"]})
        inventory["requirements"].append(selected)
    return bundle, request, inventory


def rebind(bundle, request):
    request["bundle_digest"] = digest(canonical_bytes(bundle))


def assess(bundle, request, inventory, *, version="1", expected=None):
    raw = canonical_bytes(inventory)
    return gate.assess_polish_inventory(canonical_bytes(bundle), request_bytes=canonical_bytes(request),
        inventory_bytes=raw, expected_inventory_digest=expected or digest(raw), contract_version=version)


def assert_not_closed(report):
    assert report["polished"] is False
    assert report["objective_inventory_closure"] == "NOT_ESTABLISHED"
    assert report["inventory_authentication"] == "NOT_ESTABLISHED"
    assert report["status"] != "PASS"


@pytest.mark.parametrize("version", ["1", "2"])
def test_actual_native_pass_covers_only_selected_finite_objectives(version):
    bundle, request, inventory = fixture(version)
    report = assess(bundle, request, inventory, version=version)
    assert report["declared_coverage"] == "PASS"
    assert report["status"] == "UNKNOWN"
    assert report["selected_objective_count"] == 2
    assert len(report["open_required_slots"]) == 8
    assert [row["status"] for row in report["native_assessment"]["objectives"]] == ["PASS", "PASS"]
    assert all(row["public_checkability"] == "NOT_ESTABLISHED" for row in report["native_assessment"]["objectives"])
    assert "inventory-witness-must-not-echo" not in json.dumps(report)
    assert report == assess(bundle, request, inventory, version=version)
    assert_not_closed(report)


def test_request_cannot_omit_independently_selected_objective_while_other_native_replay_passes():
    bundle, request, inventory = fixture()
    request["requirements"][0]["objectives"].pop()
    native = polish.assess_polish(canonical_bytes(bundle), request_bytes=canonical_bytes(request))
    assert native["objectives"][0]["status"] == "PASS"
    report = assess(bundle, request, inventory)
    assert report["status"] == report["declared_coverage"] == "FAIL"
    assert report["reason"] == "REQUEST_OBJECTIVE_SET_DIFFERS"


def test_self_selected_omission_cannot_replace_the_external_pin():
    bundle, request, inventory = fixture()
    selected_pin = digest(canonical_bytes(inventory))
    request["requirements"][0]["objectives"].pop()
    inventory["requirements"][0]["objectives"].pop()
    report = assess(bundle, request, inventory, expected=selected_pin)
    assert report["reason"] == "EXTERNAL_INVENTORY_DIGEST_DIFFERS"
    assert report["declared_coverage"] == "FAIL"


@pytest.mark.parametrize("field", ["mechanism_id", "mechanism_digest", "proposition_digest"])
def test_registered_mechanism_cannot_be_substituted_even_in_reselected_inventory(field):
    bundle, request, inventory = fixture()
    inventory["requirements"][0]["objectives"][0][field] = "other-checker" if field == "mechanism_id" else ZERO
    report = assess(bundle, request, inventory)
    assert report["reason"] == "REGISTERED_MECHANISM_OR_PROPOSITION_DIFFERS"
    assert report["declared_coverage"] == "FAIL"


@pytest.mark.parametrize("field", ["request", "policy", "certificate_digest"])
def test_external_evidence_selection_cannot_be_rebound_by_submitter(field):
    bundle, request, inventory = fixture()
    objective = request["requirements"][0]["objectives"][0]
    if field == "certificate_digest":
        objective[field] = ZERO
    else:
        objective[field]["unselected_value"] = True
    report = assess(bundle, request, inventory)
    assert report["reason"] == "OBJECTIVE_EVIDENCE_SELECTION_DIFFERS"


@pytest.mark.parametrize("mutation,reason", [
    ("subject-digest", "INVENTORY_SUBJECT_BINDING_DIFFERS"),
    ("subject-kind", "INVENTORY_SUBJECT_BINDING_DIFFERS"),
    ("semantic-version", "SEMANTIC_VERSION_UNSUPPORTED"),
    ("request-semantic-version", "SEMANTIC_VERSION_DIFFERS"),
    ("catalog", "REGISTERED_CATALOG_DIFFERS"),
    ("missing-tier", "INVENTORY_TIER_OMISSION"),
    ("missing-request-tier", "REQUEST_TIER_SET_DIFFERS"),
    ("duplicate-tier", "DUPLICATE_REQUIREMENT_ROW"),
    ("duplicate-objective", "DUPLICATE_OBJECTIVE"),
    ("wrong-tier", "OBJECTIVE_KIND_OR_TIER_DIFFERS"),
    ("wrong-kind", "OBJECTIVE_KIND_OR_TIER_DIFFERS"),
    ("applicability", "APPLICABILITY_DECLARATION_DIFFERS"),
    ("rationale", "APPLICABILITY_DECLARATION_DIFFERS"),
])
def test_selection_mutations_have_fixed_refutations(mutation, reason):
    bundle, request, inventory = fixture()
    if mutation == "subject-digest":
        inventory["subjects"][0]["object_digest"] = ZERO
    elif mutation == "subject-kind":
        inventory["subjects"][0]["object_kind"] = "RECEIPT"
    elif mutation == "semantic-version":
        inventory["semantic_version"] = "unregistered-version"
    elif mutation == "request-semantic-version":
        request["requirements"][0]["objectives"][0]["semantic_version"] = "unregistered-version"
    elif mutation == "catalog":
        inventory["catalog_digest"] = ZERO
    elif mutation == "missing-tier":
        inventory["requirements"].pop()
    elif mutation == "missing-request-tier":
        request["requirements"].pop()
    elif mutation == "duplicate-tier":
        inventory["requirements"].append(deepcopy(inventory["requirements"][0]))
    elif mutation == "duplicate-objective":
        request["requirements"][0]["objectives"].append(deepcopy(request["requirements"][0]["objectives"][0]))
    elif mutation in ("wrong-tier", "wrong-kind"):
        inventory["requirements"][0]["objectives"][0]["coordinate"] = "OBJECT-2.1" if mutation == "wrong-tier" else "RECEIPT-1.1"
    elif mutation == "applicability":
        request["requirements"][-1]["applicability"] = "NOT_APPLICABLE"
    elif mutation == "rationale":
        request["requirements"][-1]["rationale"] = "Submitter waived security"
    report = assess(bundle, request, inventory)
    assert report["status"] == report["declared_coverage"] == "FAIL"
    assert report["reason"] == reason
    assert_not_closed(report)


def test_missing_certificate_retains_native_unknown():
    bundle, request, inventory = fixture()
    bundle["certificates"] = {}
    rebind(bundle, request)
    report = assess(bundle, request, inventory)
    assert report["status"] == report["declared_coverage"] == "UNKNOWN"
    assert all(row["reason"] == "PUBLIC_REPLAY_EVIDENCE_MISSING" for row in report["native_assessment"]["objectives"])


def test_certificate_bytes_are_checked_by_native_assessment():
    bundle, request, inventory = fixture()
    key = next(iter(bundle["certificates"]))
    bundle["certificates"][key] += " "
    rebind(bundle, request)
    report = assess(bundle, request, inventory)
    assert report["status"] == report["declared_coverage"] == "FAIL"
    assert report["native_assessment"]["status"] == "FAIL"


def test_unknown_numbered_objective_does_not_manufacture_coverage():
    bundle, request, inventory = fixture()
    request_row = request["requirements"][-1]
    inventory_row = inventory["requirements"][-1]
    submitted = deepcopy(request["requirements"][0]["objectives"][0])
    selected = deepcopy(inventory["requirements"][0]["objectives"][0])
    submitted["coordinate"] = selected["coordinate"] = "OBJECT-9.999999"
    request_row["objectives"] = [submitted]
    inventory_row["objectives"] = [selected]
    report = assess(bundle, request, inventory)
    assert report["status"] == report["declared_coverage"] == "UNKNOWN"
    assert report["unregistered_objectives"] == [{"object_id": "root", "tier": 9,
        "coordinate": "OBJECT-9.999999", "reason": "UNREGISTERED_OBJECTIVE"}]
    assert_not_closed(report)


@pytest.mark.parametrize("applicability", ["REQUIRED", "NOT_APPLICABLE", "UNKNOWN"])
def test_empty_or_waived_inventory_cannot_produce_positive_coverage(applicability):
    bundle, request, inventory = fixture()
    for rows in (request["requirements"], inventory["requirements"]):
        for row in rows:
            row["applicability"] = applicability
            row["objectives"] = []
    report = assess(bundle, request, inventory)
    assert report["status"] == report["declared_coverage"] == "UNKNOWN"
    assert report["selected_objective_count"] == 0
    assert_not_closed(report)


def test_selected_version_two_capacity_stops_before_native_assessment():
    bundle, request, inventory = fixture("2")
    request["limits"]["objectives"] = 1
    report = assess(bundle, request, inventory, version="2")
    assert report["status"] == report["declared_coverage"] == "UNKNOWN"
    assert report["reason"] == "RESOURCE_LIMIT_EXCEEDED"
    assert report["exhausted_resource"] == "objectives"
    assert report["resource_stage"] == "REQUIREMENTS_PREFLIGHT"
    assert "native_assessment" not in report


def test_preflight_failure_does_not_execute_native_replay(monkeypatch):
    bundle, request, inventory = fixture()
    request["requirements"][0]["objectives"].pop()
    def forbidden(*args, **kwargs):
        raise AssertionError("native assessment executed after refuted selection")
    monkeypatch.setattr(polish, "assess_polish", forbidden)
    assert assess(bundle, request, inventory)["reason"] == "REQUEST_OBJECTIVE_SET_DIFFERS"


def test_duplicate_json_and_transport_bound_fail_closed():
    bundle, request, inventory = fixture()
    for raw in (b'{"subjects":[],"subjects":[]}', b" " * (gate.MAX_INVENTORY_BYTES + 1)):
        report = gate.assess_polish_inventory(canonical_bytes(bundle), request_bytes=canonical_bytes(request),
            inventory_bytes=raw, expected_inventory_digest=digest(raw))
        assert report["status"] == report["declared_coverage"] == "FAIL"
        assert_not_closed(report)


CATALOG_BINDINGS = [
    (row, kind.value if row["represented_kind_rule"] == "externally_selected_admitted_kind" else row["represented_kind_rule"])
    for row in current_object_route_catalog()
    for kind in (list(ObjectKind) if row["represented_kind_rule"] == "externally_selected_admitted_kind" else [ObjectKind.OBJECT])
]


@pytest.mark.parametrize("row,kind", CATALOG_BINDINGS,
    ids=[row["objective"] + "/" + kind for row, kind in CATALOG_BINDINGS])
def test_every_registered_objective_has_an_installed_binding_for_each_admitted_kind(row, kind):
    binding = gate.registered_objective_binding(row["semantic_version"], row["objective"], kind)
    assert set(binding) == {"mechanism_id", "mechanism_digest", "proposition_digest"}
    assert binding["proposition_digest"] == row["proposition_digest"]
    assert binding["mechanism_id"]
    assert len(binding["mechanism_digest"]) == 71
    assert binding["mechanism_digest"].startswith("sha256:")
    assert binding["mechanism_digest"] != ZERO


def test_registered_subject_security_digest_is_bound_to_selected_kind():
    # This intentionally requires the paired new security packet at integration.
    from verifier.domains.contracts import subject_security
    first = gate.registered_objective_binding(subject_security.SEMANTIC_VERSION,
        subject_security.coordinate("OBJECT"), "OBJECT")
    second = gate.registered_objective_binding(subject_security.SEMANTIC_VERSION,
        subject_security.coordinate("RECEIPT"), "RECEIPT")
    assert first["mechanism_digest"] == subject_security.mechanism_digest("OBJECT")
    assert second["mechanism_digest"] == subject_security.mechanism_digest("RECEIPT")
    assert first["mechanism_digest"] != second["mechanism_digest"]


def test_unavailable_installed_binding_is_unknown_not_fabricated(monkeypatch):
    bundle, request, inventory = fixture()
    def unavailable(*args, **kwargs):
        raise gate.MechanismBindingUnavailable("test unavailable installed signature")
    monkeypatch.setattr(gate, "registered_objective_binding", unavailable)
    report = assess(bundle, request, inventory)
    assert report["declared_coverage"] == "UNKNOWN"
    assert len(report["mechanism_binding_gaps"]) == 2
    assert all(row["reason"] == "NATIVE_MECHANISM_BINDING_UNAVAILABLE" for row in report["mechanism_binding_gaps"])
    assert [row["status"] for row in report["native_assessment"]["objectives"]] == ["PASS", "PASS"]
    assert_not_closed(report)


@pytest.fixture(scope="module")
def core_self_polish_case(tmp_path_factory):
    installed = Path(__file__).resolve().parents[1]
    root = tmp_path_factory.mktemp("core-self-polish-source")
    selected_paths = {"AGENTS.md", "TIME.md", "pyproject.toml",
                      *gate.core_self_polish_source_bindings()}
    for name in sorted(selected_paths):
        target = root.joinpath(*name.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(installed.joinpath(*name.split("/")), target)
    for arguments in (("init", "-q"), ("config", "user.name", "Fixture"),
            ("config", "user.email", "fixture" + chr(64) + "example.invalid"),
            ("config", "commit.gpgsign", "false"),
            ("config", "core.autocrlf", "false"), ("add", "."),
            ("commit", "-qm", "Exact selected self-polish source")):
        subprocess.run(["git", "-C", str(root), *arguments], check=True,
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=30)
    prepared = gate.prepare_core_self_polish_inputs(root)
    selection = prepared.pop("selection_bytes")
    expected = prepared.pop("selection_digest")
    report = gate.assess_core_self_polish(
        selection, expected_selection_digest=expected, source_root=root, **prepared)
    return {"root": root, "selection_bytes": selection,
            "expected_selection_digest": expected, "inputs": prepared,
            "report": report}


def _core_assess(case, *, selection_bytes=None, expected_selection_digest=None, **changes):
    inputs = dict(case["inputs"])
    inputs.update(changes)
    return gate.assess_core_self_polish(
        selection_bytes or case["selection_bytes"],
        expected_selection_digest=(expected_selection_digest
            or case["expected_selection_digest"]),
        source_root=case["root"], **inputs)


def _reselected(case, selection, **changes):
    raw = canonical_bytes(selection)
    return _core_assess(case, selection_bytes=raw,
        expected_selection_digest=digest(raw), **changes)


def test_real_core_self_polish_selector_and_source_bound_replay_issue_narrow_receipt(
        core_self_polish_case):
    report = core_self_polish_case["report"]
    coordinate = gate.core_application_release.full_gate_coordinate("CORE_SELF_POLISH")
    binding = gate.registered_objective_binding(
        coordinate["semantic_version"], coordinate["objective"], "VERIFIER")
    assert binding == {"mechanism_id": gate.CORE_SELF_POLISH_MECHANISM_ID,
                       "mechanism_digest": gate.core_self_polish_mechanism_digest(),
                       "proposition_digest": coordinate["proposition_digest"]}
    assert report["status"] == report["gate_status"] == "PASS"
    assert report["receipt_status"] == "ISSUED"
    assert report["source_replay"] == report["application_compiler_replay"] == "REPRODUCED"
    assert report["selected_native_replay"] == "PASS"
    assert (report["installed_definition_count"], report["installed_membership_count"],
            report["instantiated_obligation_count"]) == (27, 52, 2)
    receipt = report["receipt"]
    assert receipt["semantic_version"] == coordinate["semantic_version"]
    assert receipt["objective"] == coordinate["objective"]
    assert receipt["proposition_digest"] == coordinate["proposition_digest"]
    assert receipt["status"] == "PASS"
    assert receipt["polished"] is False
    assert receipt["full_application_status"] == "UNKNOWN"
    assert receipt["selection_authority"] == "NOT_ESTABLISHED"

    replay = gate.recheck_core_self_polish_receipt(
        canonical_bytes(report), expected_assessment_digest=report["assessment_digest"],
        expected_receipt_digest=receipt["receipt_digest"],
        selection_bytes=core_self_polish_case["selection_bytes"],
        expected_selection_digest=core_self_polish_case["expected_selection_digest"],
        source_root=core_self_polish_case["root"], **core_self_polish_case["inputs"])
    assert replay["status"] == "PASS"
    assert replay["replay_status"] == "REPRODUCED"


def test_core_self_polish_stale_source_manifest_is_refuted_even_when_reselected(
        core_self_polish_case):
    source = json.loads(core_self_polish_case["inputs"]["source_manifest_bytes"])
    source["worktree_clean"] = not source["worktree_clean"]
    source_bytes = canonical_bytes(source)
    selection = json.loads(core_self_polish_case["selection_bytes"])
    selection["source_manifest_digest"] = digest(source_bytes)
    report = _reselected(core_self_polish_case, selection,
                         source_manifest_bytes=source_bytes)
    assert report["status"] == report["gate_status"] == "FAIL"
    assert report["receipt_status"] == "NOT_ISSUED"
    assert report["reason"] == "SOURCE_STATE_DIFFERS"


def test_core_self_polish_application_identity_substitution_is_refuted_after_reselection(
        core_self_polish_case):
    selection = json.loads(core_self_polish_case["selection_bytes"])
    selection["application_id"] = "substituted-application"
    report = _reselected(core_self_polish_case, selection)
    assert report["status"] == "FAIL"
    assert report["reason"] == "SELF_POLISH_ROOT_PAYLOAD_DIFFERS"


def test_core_self_polish_compiler_manifest_substitution_is_refuted_after_reselection(
        core_self_polish_case):
    manifest = json.loads(core_self_polish_case["inputs"]["compiler_manifest_bytes"])
    manifest["status"] = "UNKNOWN"
    manifest_bytes = canonical_bytes(manifest)
    selection = json.loads(core_self_polish_case["selection_bytes"])
    selection["compiler_manifest_digest"] = digest(manifest_bytes)
    report = _reselected(core_self_polish_case, selection,
                         compiler_manifest_bytes=manifest_bytes)
    assert report["status"] == "FAIL"
    assert report["reason"] == "APPLICATION_COMPILER_REPLAY_DIFFERS"


def test_core_self_polish_tampered_native_certificate_cannot_pass_after_reselection(
        core_self_polish_case):
    bundle = json.loads(core_self_polish_case["inputs"]["polish_bundle_bytes"])
    selected = next(iter(bundle["certificates"]))
    bundle["certificates"][selected]["text"] += " "
    bundle_bytes = canonical_bytes(bundle)
    request = json.loads(core_self_polish_case["inputs"]["polish_request_bytes"])
    request["bundle_digest"] = digest(bundle_bytes)
    request_bytes = canonical_bytes(request)
    native = gate.assess_polish_inventory(bundle_bytes, request_bytes=request_bytes,
        inventory_bytes=core_self_polish_case["inputs"]["polish_inventory_bytes"],
        expected_inventory_digest=core_self_polish_case["inputs"]["expected_polish_inventory_digest"],
        contract_version="2")
    assert native["status"] == "FAIL"
    selection = json.loads(core_self_polish_case["selection_bytes"])
    selection["polish_bundle_digest"] = digest(bundle_bytes)
    selection["polish_request_digest"] = digest(request_bytes)
    selection["native_assessment_digest"] = native["assessment_digest"]
    report = _reselected(core_self_polish_case, selection,
        polish_bundle_bytes=bundle_bytes, polish_request_bytes=request_bytes)
    assert report["status"] == "FAIL"
    assert report["reason"] == "SELECTED_NATIVE_REPLAY_NOT_CLOSED"


def test_core_self_polish_mechanism_substitution_and_cancellation_never_issue(
        core_self_polish_case):
    selection = json.loads(core_self_polish_case["selection_bytes"])
    selection["self_polish_mechanism_digest"] = ZERO
    changed = _reselected(core_self_polish_case, selection)
    assert changed["status"] == "FAIL"
    assert changed["reason"] == "SELF_POLISH_MECHANISM_DIFFERS"
    cancelled = _core_assess(core_self_polish_case, cancelled=True)
    assert cancelled["status"] == cancelled["gate_status"] == "UNKNOWN"
    assert cancelled["receipt_status"] == "NOT_ISSUED"
    assert cancelled["reason"] == "SELF_POLISH_REPLAY_CANCELLED"


def test_core_self_polish_replay_rejects_rehashed_receipt_substitution(
        core_self_polish_case):
    stored = deepcopy(core_self_polish_case["report"])
    stored["receipt"]["status"] = "UNKNOWN"
    stored["receipt"]["receipt_digest"] = digest(canonical_bytes({
        key: value for key, value in stored["receipt"].items()
        if key != "receipt_digest"}))
    stored["assessment_digest"] = digest(canonical_bytes({
        key: value for key, value in stored.items() if key != "assessment_digest"}))
    replay = gate.recheck_core_self_polish_receipt(
        canonical_bytes(stored), expected_assessment_digest=stored["assessment_digest"],
        expected_receipt_digest=stored["receipt"]["receipt_digest"],
        selection_bytes=core_self_polish_case["selection_bytes"],
        expected_selection_digest=core_self_polish_case["expected_selection_digest"],
        source_root=core_self_polish_case["root"], **core_self_polish_case["inputs"])
    assert replay["status"] == "FAIL"
    assert replay["replay_status"] == "REJECTED"


def _candidate_source_repository(tmp_path: Path) -> Path:
    root = tmp_path / "candidate-source"
    root.mkdir()
    (root / "pyproject.toml").write_text(
        '[project]\nname = "candidate-source"\nversion = "1.0.0"\n',
        encoding="utf-8",
    )
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(
        [
            "git", "-C", str(root), "config", "user.email",
            "test" + "@" + "example.invalid",
        ],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(root), "config", "user.name", "Verifier Test"],
        check=True,
    )
    subprocess.run(["git", "-C", str(root), "add", "pyproject.toml"], check=True)
    subprocess.run(
        ["git", "-C", str(root), "commit", "-q", "-m", "fixture"],
        check=True,
    )
    return root


def test_core_source_manifest_binds_nonignored_untracked_candidate_bytes(
        tmp_path: Path) -> None:
    root = _candidate_source_repository(tmp_path)
    candidate = root / "src" / "verifier" / "new_mechanism.py"
    candidate.parent.mkdir(parents=True)
    candidate.write_text("VALUE = 1\n", encoding="utf-8")

    first = gate.capture_core_self_polish_source(root)
    rows = {
        row["path"]: row
        for row in first["candidate_source_census"]["files"]
    }
    assert first["schema_version"] == gate.CORE_SELF_POLISH_SOURCE
    assert first["untracked_nonignored_file_count"] == 1
    assert rows["src/verifier/new_mechanism.py"]["provenance"] \
        == "WORKTREE_UNTRACKED_NONIGNORED"
    assert rows["src/verifier/new_mechanism.py"]["git_mode"] \
        == "UNTRACKED_REGULAR"

    candidate.write_text("VALUE = 2\n", encoding="utf-8")
    second = gate.capture_core_self_polish_source(root)
    assert second["candidate_source_census_digest"] \
        != first["candidate_source_census_digest"]


def test_core_source_manifest_rejects_ignored_discoverable_source(
        tmp_path: Path) -> None:
    root = _candidate_source_repository(tmp_path)
    ignore = root / ".gitignore"
    ignore.write_text("src/verifier/ignored.py\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", ".gitignore"], check=True)
    subprocess.run(
        ["git", "-C", str(root), "commit", "-q", "-m", "ignore rule"],
        check=True,
    )
    ignored = root / "src" / "verifier" / "ignored.py"
    ignored.parent.mkdir(parents=True)
    ignored.write_text("VALUE = 'hidden'\n", encoding="utf-8")

    with pytest.raises(
        gate.RequirementRefusal,
        match="IGNORED_DISCOVERABLE_SOURCE_PRESENT",
    ):
        gate.capture_core_self_polish_source(root)
