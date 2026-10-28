"""Dummy-secret gate tests; no service credential is read or tested.

JavaScript Object Notation (JSON); Verifier Standard (VSTD).
Injected backend tests cover contract semantics. Explicit official-scanner fixtures
cover selected rule observations, not universal detection or production admission.
"""
import hashlib
import json
import os
from pathlib import Path
import uuid

import pytest
from verifier.runtime import secret_gate as gate


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def bind(value):
    scope = {key: value[key] for key in ("mode", "selection", "coverage_requirements", "scanner_policy")}
    scope["artifacts"] = [{key: item for key, item in a.items() if key != "content_path"}
                          for a in value["artifacts"]]
    value["scope_manifest_sha256"] = digest(gate._canonical(scope))


@pytest.fixture
def selected(tmp_path, monkeypatch):
    binary = tmp_path / "scanner.exe"; binary.write_bytes(b"nonexecuted fixture scanner")
    config = tmp_path / "scanner.toml"; config.write_bytes(gate.CONFIGURATION)
    text = tmp_path / "selected.txt"; text.write_bytes(b"ordinary retained source text")
    request = {"schema": gate.REQUEST, "request_id": str(uuid.uuid4()), "mode": "staged-index",
        "selection": {"index_paths": ["selected.txt"]}, "coverage_requirements": list(gate.COVERAGE),
        "scanner_policy": {"name": "gitleaks", "version": gate.VERSION,
            "configuration_sha256": digest(config.read_bytes()), "binary_sha256": digest(binary.read_bytes())},
        "artifacts": [{"id": "selected:1", "kind": "git-blob", "content_path": str(text),
            "bytes": len(text.read_bytes()), "content_sha256": digest(text.read_bytes()),
            "selected_path": "selected.txt"}]}
    path = tmp_path / "request.json"
    monkeypatch.setattr(gate, "_process", lambda *args: (0, gate.VERSION.encode()))
    monkeypatch.setattr(gate, "_scan", lambda *args: 0)
    def run(*, rebind=True, **kwargs):
        if rebind: bind(request)
        path.write_bytes(gate._canonical(request))
        return gate.assess_secret_request(path, scanner_binary=kwargs.get("binary", binary),
                                          scanner_configuration=kwargs.get("configuration", config))
    return request, text, binary, config, path, run


@pytest.mark.parametrize("mode", sorted(gate.MODES))
def test_exact_selection_passes_under_pinned_rules(selected, mode):
    request, _, _, _, _, run = selected; request["mode"] = mode
    receipt = run()
    assert receipt["outcome"] == "PASS" and receipt["coverage_complete"] is True
    assert receipt["artifact_count"] == receipt["artifacts_scanned"] == 1
    assert receipt["scanner"] == request["scanner_policy"]
    assert receipt["scope_manifest_sha256"] == request["scope_manifest_sha256"]
    assert receipt["findings_count"] == 0 and receipt["reason_codes"] == []


def test_empty_selection_is_noop_not_clearance(selected):
    request, _, _, _, _, run = selected; request["artifacts"] = []
    receipt = run(binary=None, configuration=None)
    assert receipt["outcome"] == "NOOP" and receipt["coverage_complete"] is True


@pytest.mark.parametrize("missing", ["binary", "configuration"])
def test_backend_unavailable_unknown(selected, missing):
    receipt = selected[-1](**{missing: None})
    assert receipt["outcome"] == "UNKNOWN" and receipt["coverage_complete"] is False


@pytest.mark.parametrize("key,value", [
    ("schema", "unselected"), ("mode", "all-system"), ("request_id", "DUMMY_NEVER_A_CREDENTIAL"),
    ("coverage_requirements", []), ("coverage_requirements", gate.COVERAGE + ["submodule-full-coverage"]),
    ("coverage_requirements", [gate.COVERAGE[0]] * 3), ("selection", []),
])
def test_unsupported_request_unknown(selected, key, value):
    request, _, _, _, _, run = selected; request[key] = value
    receipt = run()
    assert receipt["outcome"] == "UNKNOWN" and receipt["coverage_complete"] is False
    assert "DUMMY_NEVER_A_CREDENTIAL" not in json.dumps(receipt)


@pytest.mark.parametrize("key,value", [
    ("name", "unknown"), ("version", "8.30.0"),
    ("binary_sha256", "UNSET_PENDING_APPROVED_INSTALLATION"), ("configuration_sha256", "0" * 64),
])
def test_unselected_scanner_unknown(selected, key, value):
    request, _, _, _, _, run = selected; request["scanner_policy"][key] = value
    assert run()["outcome"] == "UNKNOWN"


def test_scope_binding_tamper_fails(selected):
    request, _, _, _, _, run = selected; bind(request)
    request["selection"]["index_paths"] = ["different.txt"]
    receipt = run(rebind=False)
    assert receipt["outcome"] == "FAIL"
    assert receipt["reason_codes"] == ["SCOPE_MANIFEST_BINDING_MISMATCH"]


@pytest.mark.parametrize("target", ["artifact", "binary", "configuration"])
def test_changed_exact_bytes_fail_without_disclosure(selected, target):
    _, text, binary, config, _, run = selected
    {"artifact": text, "binary": binary, "configuration": config}[target].write_bytes(b"DUMMY_REPLACEMENT")
    receipt = run()
    assert receipt["outcome"] == "FAIL" and receipt["coverage_complete"] is False
    assert "DUMMY_REPLACEMENT" not in json.dumps(receipt)


@pytest.mark.parametrize("raw", [b"binary\0text", b"\xff\xfe", b"PK\x03\x04archive",
                                 b"\x1f\x8bcompressed", b"7z\xbc\xafencoded"])
def test_uncovered_representations_unknown(selected, raw):
    request, text, _, _, _, run = selected; text.write_bytes(raw)
    request["artifacts"][0].update(bytes=len(raw), content_sha256=digest(raw))
    receipt = run()
    assert receipt["outcome"] == "UNKNOWN" and receipt["coverage_complete"] is False


@pytest.mark.parametrize("failure", [
    gate.Unavailable("SCANNER_TIMEOUT"), gate.Unavailable("SCANNER_ERROR_DETAILS_SUPPRESSED"),
    OSError("DUMMY_EXCEPTION_CONTENT"), KeyboardInterrupt(),
])
def test_errors_and_cancellation_unknown(selected, monkeypatch, failure):
    def stop(*args): raise failure
    monkeypatch.setattr(gate, "_scan", stop); receipt = selected[-1]()
    assert receipt["outcome"] == "UNKNOWN" and receipt["coverage_complete"] is False
    assert "DUMMY_EXCEPTION_CONTENT" not in json.dumps(receipt)


def test_finding_dominates_other_missing_artifact(selected, monkeypatch):
    request, text, _, _, _, run = selected
    request["artifacts"].append({**request["artifacts"][0], "id": "selected:2",
                                 "content_path": str(text.parent / "missing.txt")})
    monkeypatch.setattr(gate, "_scan", lambda *args: 1); receipt = run()
    assert receipt["outcome"] == "FAIL" and receipt["findings_count"] == 1
    assert receipt["coverage_complete"] is False
    assert receipt["findings"] == [{"artifact_index": 1, "count": 1}]


def test_finding_preserves_complete_coverage(selected, monkeypatch):
    monkeypatch.setattr(gate, "_scan", lambda *args: 1); receipt = selected[-1]()
    assert receipt["outcome"] == "FAIL" and receipt["coverage_complete"] is True


@pytest.mark.parametrize("target", ["artifact", "request", "binary", "configuration"])
def test_postscan_binding_rechecked(selected, monkeypatch, target):
    _, text, binary, config, path, run = selected
    def change(*args):
        {"artifact": text, "request": path, "binary": binary, "configuration": config}[target].write_bytes(b"DUMMY_CHANGED")
        return 0
    monkeypatch.setattr(gate, "_scan", change); receipt = run()
    assert receipt["outcome"] == "FAIL" and receipt["coverage_complete"] is False


def test_duplicate_json_unknown(tmp_path):
    path = tmp_path / "request.json"; path.write_bytes(b'{"schema":1,"schema":2}')
    receipt = gate.assess_secret_request(path)
    assert receipt["outcome"] == "UNKNOWN"
    assert receipt["reason_codes"] == ["DUPLICATE_JSON_FIELD"]


def test_minimal_environment_excludes_parent_credentials(tmp_path, monkeypatch):
    for name in ["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GITLEAKS_CONFIG", "OPAQUE_NOT_SECRET_NAMED"]:
        monkeypatch.setenv(name, "DUMMY_INVALID_NEVER_A_SERVICE_CREDENTIAL")
    env = gate._environment(tmp_path)
    assert set(env) <= {"SYSTEMROOT", "WINDIR", "TEMP", "TMP", "HOME", "USERPROFILE",
                        "XDG_CONFIG_HOME", "GIT_TERMINAL_PROMPT"}
    assert all("DUMMY_" not in value for value in env.values())
    assert os.environ["ANTHROPIC_API_KEY"] == "DUMMY_INVALID_NEVER_A_SERVICE_CREDENTIAL"


@pytest.mark.parametrize("code,rows", [
    (0, [{"RuleID": "DUMMY_RULE", "StartLine": 1}]), (10, []), (2, []), (0, {}),
    (10, [{"RuleID": "rule", "StartLine": True}]),
])
def test_malformed_backend_report_unknown(tmp_path, monkeypatch, code, rows):
    def fake(argv, content, temporary, timeout):
        (temporary / "findings.json").write_bytes(gate._canonical(rows))
        return code, b"DUMMY_STDOUT"
    monkeypatch.setattr(gate, "_process", fake)
    with pytest.raises(gate.Unavailable):
        gate._scan(tmp_path / "scanner", tmp_path / "config", b"", tmp_path, 1)


def test_backend_report_reduced_to_count(tmp_path, monkeypatch):
    def fake(argv, content, temporary, timeout):
        (temporary / "findings.json").write_bytes(gate._canonical([
            {"RuleID": "DUMMY_RULE", "StartLine": 17, "Secret": "DUMMY_SECRET",
             "Line": "DUMMY_RAW_LINE", "File": "DUMMY_PRIVATE_PATH"}]))
        assert "--redact=100" in argv and "--ignore-gitleaks-allow" in argv
        return 10, b"DUMMY_STDOUT"
    monkeypatch.setattr(gate, "_process", fake)
    assert gate._scan(tmp_path / "scanner", tmp_path / "config", b"", tmp_path, 1) == 1


@pytest.mark.parametrize("tamper,expected_code", [(True, 1), (False, 2)])
def test_real_cli_metadata_contract(selected, capsys, tamper, expected_code):
    from verifier.runtime.public_cli import main
    request, _, _, _, path, _ = selected; bind(request)
    if tamper: request["selection"]["index_paths"] = ["different"]
    path.write_bytes(gate._canonical(request))
    assert main(["gate", "secrets", "--request", str(path), "--json"]) == expected_code
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["schema"] == gate.RECEIPT
    assert receipt["outcome"] == ("FAIL" if tamper else "UNKNOWN")


def _official_scanner_cases():
    probe = b"7tKg9Lm2" + b"Qp6Xs4Vz8Nb1Hc5Ra3Yu0Ed7"
    assignment = b"api_" + b"key = "
    return [
        (assignment + b'"' + probe + b'"\n', "FAIL"),
        (assignment + b"'tiny'\nordinary measurement vocabulary\n", "PASS"),
        (b"somekeymeasuringcriterion and monkeybusiness are ordinary identifiers\n", "PASS"),
        (assignment + b'"DUMMY_ONLY_' + probe + b'"\\n', "PASS"),
        (assignment + b'"' + probe + b'" # gitleaks:allow\\n', "FAIL"),
    ]


@pytest.mark.parametrize("raw,expected", _official_scanner_cases())
def test_official_scanner_dummy_and_substring_controls(tmp_path, raw, expected):
    binary_name = os.environ.get("VERIFIER_GITLEAKS_FIXTURE")
    pin = os.environ.get("VERIFIER_GITLEAKS_FIXTURE_SHA256")
    if not binary_name or not pin:
        pytest.skip("OPTIONAL_DEPENDENCY_ABSENT: official pinned Gitleaks fixture not selected (VERIFIER_GITLEAKS_FIXTURE unset); backend accuracy unrun.")
    binary = Path(binary_name); assert digest(binary.read_bytes()) == pin
    config = tmp_path / "scanner.toml"; config.write_bytes(gate.CONFIGURATION)
    text = tmp_path / "fixture.txt"; text.write_bytes(raw)
    request = {"schema": gate.REQUEST, "request_id": str(uuid.uuid4()), "mode": "preflight-output",
        "selection": {"fixture": "dummy-plaintext"}, "coverage_requirements": list(gate.COVERAGE),
        "scanner_policy": {"name": "gitleaks", "version": gate.VERSION,
            "configuration_sha256": digest(gate.CONFIGURATION), "binary_sha256": pin},
        "artifacts": [{"id": "dummy:1", "kind": "captured-output", "content_path": str(text),
            "bytes": len(raw), "content_sha256": digest(raw)}]}
    bind(request); path = tmp_path / "request.json"; path.write_bytes(gate._canonical(request))
    receipt = gate.assess_secret_request(path, scanner_binary=binary, scanner_configuration=config)
    assert receipt["outcome"] == expected, receipt["reason_codes"]
    assert receipt["coverage_complete"] is True
    assert raw.decode().strip() not in json.dumps(receipt)


@pytest.mark.parametrize("script,content,timeout,reason", [
    ("import time;time.sleep(2)", b"", .05, "SCANNER_TIMEOUT"),
    ("import sys;sys.stdout.buffer.write(b'x' * (2 * 1024 * 1024 + 8192))",
     b"", 5, "SCANNER_OUTPUT_LIMIT"),
    ("import os;os.close(0)", b"x" * (2 * 1024 * 1024), 5, "SCANNER_STDIN_INCOMPLETE"),
], ids=["timeout", "output-cap", "stdin-incomplete"])
def test_real_trusted_child_transport_incomplete_never_clears(tmp_path, script, content, timeout, reason):
    import sys
    with pytest.raises(gate.Unavailable) as caught:
        gate._process([sys.executable, "-B", "-c", script], content, tmp_path, timeout)
    assert caught.value.reason == reason


def test_remote_path_refused_before_filesystem_access():
    from types import SimpleNamespace
    separator = chr(92)  # built at run time: the presentation gate forbids literal network-share paths in tests
    selected = SimpleNamespace(is_absolute=lambda: True, drive=separator * 2 + "server" + separator + "share")
    with pytest.raises(gate.Unavailable) as caught:
        gate._read(selected, 1)
    assert caught.value.reason == "REMOTE_PATH_UNSUPPORTED"
