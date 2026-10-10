"""Exact release binding refusals, without pretending to qualify the application.

Terminology: command-line interface (CLI); application programming interface (API).
Controlled byte fixtures establish only the selected source-binding predicate.
"""
from copy import deepcopy

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.runtime import release_source_binding as binding


def fixture():
    names = ["subject.json", "pyproject.toml", "src/verifier/__init__.py", "src/verifier/runtime/public_cli.py",
             "surface.json", "applicability.json", "request.json", "policy.json", "mechanism.py", "certificate.json", "execution.json"]
    names += [role + ".artifact" for role in binding.RELEASE_ROLES]
    files = {name: ("controlled fixture: " + name).encode() for name in names}
    files["pyproject.toml"] = b'[project.scripts]\nvstd = "verifier.runtime.public_cli:main"\nverifier = "verifier.runtime.public_cli:main"\nverifiable = "verifier.runtime.public_cli:main"\n'
    ref = lambda name: {"path": name, "sha256": binding.digest(files[name])}
    revision = "sha256:" + "1" * 64
    subject = {"object_id": "verifier", "object_kind": "VERIFIER", "record": ref("subject.json"),
               "instruction_revision": revision, "context_revision": revision}
    run = {"subject_record_digest": subject["record"]["sha256"], "instruction_revision": revision, "context_revision": revision,
           **{name: ref(name + (".py" if name == "mechanism" else ".json")) for name in ("request", "policy", "mechanism", "certificate", "execution")}}
    selection = {"schema_version": binding.SCHEMA, "subject": subject,
        "release_tuple": {role: ref(role + ".artifact") for role in binding.RELEASE_ROLES},
        "source_inventory": [ref(name) for name in sorted(["pyproject.toml", "src/verifier/__init__.py", "src/verifier/runtime/public_cli.py"])],
        "console_scripts": dict(binding.ALIASES), "public_surface_inventory": ref("surface.json"),
        "applicability_inventory": ref("applicability.json"), "harness_executions": [run]}
    return selection, files


def assess(value, files, **kwargs):
    raw = canonical_bytes(value)
    return binding.assess_release_source_binding(raw, files, expected_selection_digest=binding.digest(raw),
        expected_mechanism_digest=binding.mechanism_digest(), **kwargs)


def test_exact_finite_byte_binding_does_not_become_application_polish():
    selection, files = fixture()
    result = assess(selection, files)
    assert result["binding_status"] == "PASS" and result["status"] == "UNKNOWN"
    assert result["polished"] is False and result["full_application_status"] == "UNKNOWN"
    assert result["application_profile"] == "UNADOPTED" and result["native_objective_replay"] == "NOT_RUN"
    assert result["public_surface_completeness"] == "NOT_ESTABLISHED" and result["required_certificate_instances"] == "UNKNOWN"


@pytest.mark.parametrize("name", ["wheel.artifact", "external_manifest.artifact", "src/verifier/runtime/public_cli.py", "certificate.json"])
def test_missing_selected_dependency_is_unknown_and_tampering_is_fail(name):
    selection, files = fixture()
    missing = dict(files)
    missing.pop(name)
    assert assess(selection, missing)["binding_status"] == "UNKNOWN"
    changed = {**files, name: b"tampered"}
    result = assess(selection, changed)
    assert result["status"] == "FAIL" and any(row["code"] == "SELECTED_FILE_DIGEST_DIFFERS" for row in result["findings"])


@pytest.mark.parametrize("mode", ["empty", "toy", "duplicate", "missing_tuple", "split_alias", "missing_alias", "invented_pass", "no_harness"])
def test_narrowed_or_forged_selection_cannot_claim_full_binding(mode):
    selection, files = fixture()
    if mode == "empty": selection["source_inventory"] = []
    elif mode == "toy": selection["source_inventory"] = selection["source_inventory"][:1]
    elif mode == "duplicate": selection["source_inventory"].append(selection["source_inventory"][0])
    elif mode == "missing_tuple": selection["release_tuple"].pop("sdist")
    elif mode == "split_alias": selection["console_scripts"]["verifier"] = "foreign:main"
    elif mode == "missing_alias": selection["console_scripts"].pop("verifiable")
    elif mode == "invented_pass": selection["status"] = "PASS"
    else: selection["harness_executions"] = []
    assert assess(selection, files)["status"] == "FAIL"


@pytest.mark.parametrize("key", ["subject_record_digest", "instruction_revision", "context_revision"])
def test_harness_subject_or_revision_substitution_is_refuted(key):
    selection, files = fixture()
    selection["harness_executions"][0][key] = "sha256:" + "2" * 64
    assert assess(selection, files)["status"] == "FAIL"


def test_cancellation_or_missing_anchor_never_masks_present_tampering():
    selection, files = fixture()
    raw = canonical_bytes(selection)
    result = binding.assess_release_source_binding(raw, {**files, "wheel.artifact": b"bad"},
        expected_selection_digest=None, expected_mechanism_digest=None, cancelled=True)
    assert result["status"] == "FAIL"
    assert {"CANCELLED", "EXTERNAL_SELECTION_PIN_MISSING", "SELECTED_FILE_DIGEST_DIFFERS"} <= {row["code"] for row in result["findings"]}
    assert assess(selection, files, cancelled=True)["binding_status"] == "UNKNOWN"


def test_changed_source_requires_new_external_selection_and_harness_context():
    selection, files = fixture()
    old = binding.digest(canonical_bytes(selection))
    changed = deepcopy(selection)
    changed["subject"]["context_revision"] = "sha256:" + "3" * 64
    raw = canonical_bytes(changed)
    result = binding.assess_release_source_binding(raw, files, expected_selection_digest=old,
        expected_mechanism_digest=binding.mechanism_digest())
    assert {"EXTERNAL_SELECTION_PIN_DIFFERS", "HARNESS_SUBJECT_OR_REVISION_SUBSTITUTED"} <= {row["code"] for row in result["findings"]}


def test_release_roles_cannot_be_satisfied_by_one_reused_artifact():
    selection, files = fixture()
    selection["release_tuple"]["sdist"] = selection["release_tuple"]["wheel"]
    assert assess(selection,files)["status"] == "FAIL"


def test_release_roles_cannot_use_casefold_alias_paths():
    selection, files = fixture()
    files["WHEEL.ARTIFACT"] = files["wheel.artifact"]
    selection["release_tuple"]["sdist"] = {
        "path": "WHEEL.ARTIFACT",
        "sha256": binding.digest(files["WHEEL.ARTIFACT"]),
    }
    assert assess(selection, files)["status"] == "FAIL"


def test_source_inventory_rejects_casefold_alias_paths():
    selection, files = fixture()
    for name in ("Docs/A.txt", "docs/a.txt"):
        files[name] = name.encode("utf-8")
        selection["source_inventory"].append(
            {"path": name, "sha256": binding.digest(files[name])}
        )
    selection["source_inventory"].sort(key=lambda row: row["path"])
    assert assess(selection, files)["status"] == "FAIL"


def test_source_inventory_rejects_non_nfc_path_instead_of_rewriting_it():
    selection, files = fixture()
    path = "docs/cafe\u0301.txt"
    files[path] = b"decomposed path"
    selection["source_inventory"].append(
        {"path": path, "sha256": binding.digest(files[path])}
    )
    selection["source_inventory"].sort(key=lambda row: row["path"])
    assert assess(selection, files)["status"] == "FAIL"


def test_capacity_exhaustion_is_unknown(monkeypatch):
    selection, files = fixture()
    monkeypatch.setattr(binding,"MAX_FILE_BYTES",3)
    result=assess(selection,files)
    assert result["status"] == "UNKNOWN" and result["binding_status"] == "UNKNOWN"
    assert any(row["code"] == "SOURCE_BINDING_CAPACITY_EXHAUSTED" for row in result["findings"])


@pytest.mark.parametrize("replacement", [b'foreign:main', b'verifier.runtime.public_cli:foreign'])
def test_pinned_source_alias_substitution_is_refuted_even_with_current_selection_pin(replacement):
    selection, files = fixture()
    files["pyproject.toml"] = files["pyproject.toml"].replace(b'verifier.runtime.public_cli:main', replacement)
    next(row for row in selection["source_inventory"] if row["path"] == "pyproject.toml")["sha256"] = binding.digest(files["pyproject.toml"])
    result = assess(selection, files)
    assert result["status"] == "FAIL"
    assert any(row["code"] == "SOURCE_CONSOLE_ALIASES_DIFFER" for row in result["findings"])


def test_unsupported_script_grammar_is_unknown_rather_than_declared_alias_pass():
    selection, files = fixture()
    files["pyproject.toml"] = b'[project.scripts]\n"vstd" = "verifier.runtime.public_cli:main"\n'
    next(row for row in selection["source_inventory"] if row["path"] == "pyproject.toml")["sha256"] = binding.digest(files["pyproject.toml"])
    result = assess(selection, files)
    assert result["binding_status"] == "UNKNOWN"
    assert any(row["code"] == "SOURCE_CONSOLE_ALIASES_UNASSESSED" for row in result["findings"])


def test_table_looking_multiline_string_cannot_supply_source_aliases():
    selection, files = fixture()
    files["pyproject.toml"] = b'[project]\ndescription = """\n' + files["pyproject.toml"] + b'[tool.decoy]\n"""\n'
    next(row for row in selection["source_inventory"] if row["path"] == "pyproject.toml")["sha256"] = binding.digest(files["pyproject.toml"])
    result = assess(selection, files)
    assert result["binding_status"] == "UNKNOWN" and result["status"] == "UNKNOWN"
    assert any(row["code"] == "SOURCE_CONSOLE_ALIASES_UNASSESSED" for row in result["findings"])


@pytest.mark.parametrize("invalid", [object(), {"status": "PASS"}, "x" * (9 * 1024 * 1024), "\ud800"],
                         ids=["object", "mapping", "oversized", "surrogate"])
def test_malformed_external_pin_has_bounded_serializable_refusal(invalid):
    selection, files = fixture()
    raw = canonical_bytes(selection)
    result = binding.assess_release_source_binding(raw, files, expected_selection_digest=invalid,
        expected_mechanism_digest=binding.mechanism_digest())
    assert result["status"] == "FAIL" and len(canonical_bytes(result)) < 8192
    assert any(row["code"] == "EXTERNAL_SELECTION_PIN_INVALID" for row in result["findings"])


def test_unpaired_unicode_cannot_escape_report_refusal():
    selection, files = fixture()
    selection["subject"]["object_id"] = "\ud800"
    import json
    raw = json.dumps(selection, ensure_ascii=True).encode()
    result = binding.assess_release_source_binding(raw, files, expected_selection_digest=binding.digest(raw),
        expected_mechanism_digest=binding.mechanism_digest())
    assert result["status"] == "FAIL" and len(canonical_bytes(result)) < 8192


def test_count_refusal_precedes_file_value_scan(monkeypatch):
    selection, files = fixture()
    monkeypatch.setattr(binding, "MAX_FILES", 1)
    result = assess(selection, {**files, "not-immutable": object()})
    assert result["status"] == "UNKNOWN"
    assert result["findings"][0]["code"] == "SOURCE_BINDING_CAPACITY_EXHAUSTED"


def test_repeated_harness_references_hash_each_immutable_file_once(monkeypatch):
    selection, files = fixture()
    selection["harness_executions"] = [deepcopy(selection["harness_executions"][0]) for _ in range(256)]
    actual_digest = binding.digest
    observed = []
    def counting_digest(raw):
        observed.append(raw)
        return actual_digest(raw)
    monkeypatch.setattr(binding, "digest", counting_digest)
    result = assess(selection, files)
    assert result["binding_status"] == "PASS" and result["status"] == "UNKNOWN"
    assert all(sum(raw is file for raw in observed) == 1 for file in files.values())


@pytest.mark.parametrize("tampered", [False, True])
def test_report_capacity_refusal_preserves_observed_refutation(monkeypatch, tampered):
    selection, files = fixture()
    monkeypatch.setattr(binding, "MAX_REPORT_BYTES", 1024)
    if tampered:
        files["wheel.artifact"] = b"tampered"
    result = assess(selection, files)
    assert result["status"] == ("FAIL" if tampered else "UNKNOWN")
    assert result["report_complete"] is False and result["findings_complete"] == "NOT_ESTABLISHED"
    assert len(canonical_bytes(result)) <= binding.MAX_REPORT_BYTES
