"""Supply Chain Integrity, Transparency, and Trust (SCITT) recorded comparison tests.

Concise Binary Object Representation (CBOR); CBOR Object Signing and Encryption (COSE).
Synthetic process outputs test reconstruction only, not native interoperability.
"""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from examples.scitt_native_interop import package_comparison as comparison

from verifier.interoperability.storage import ImplementationBinding, PackageArtifact, PackageDependency, StoredComponentPackage
from test_scitt_native_runner import public_specimen, runner


ROOT = Path(__file__).resolve().parents[1]
HERE = ROOT / "examples/scitt_native_interop"


def native_output(language: str, facet: str, accepted: bool, root: str) -> dict:
    inclusion = {"ok": accepted, "root": root, "tree_size": 1, "leaf_index": 0}
    if language == "python":
        return {"draft_tracking": "Unexamined upstream prose", "statement":
                {"signature_verified": accepted, "issuer": None, "subject": None, "content_type": None,
                 "alg": "EdDSA" if accepted else None, "unverified": None, "payload_len": None} if facet == "statement" else None,
                "receipt": {**inclusion, "errors": [] if accepted else ["receipt signature did not verify: signature verification FAILED (InvalidSignature)"]} if facet == "receipt" else None}
    result = {"valid": accepted, "alg": "EdDSA", "content_type": "", "iss": "", "sub": ""}
    if facet == "receipt":
        result["receipt"] = inclusion
        if not accepted:
            inclusion["error"] = "receipt signature did not verify over reconstructed root: verification error"
    elif not accepted:
        result["error"] = "signature verification failed: verification error"
    return result


@pytest.fixture
def specimen(monkeypatch: pytest.MonkeyPatch) -> StoredComponentPackage:
    corpus, artifacts = runner.build_corpus(public_specimen())
    go = {name: ("synthetic source " + name).encode() for name in comparison.GO_SOURCES}
    py = {"scitt_cose/cli.py": b"synthetic Python source, not execution"}
    monkeypatch.setattr(comparison, "GO_SOURCES", {name: comparison.sha(data) for name, data in go.items()})
    monkeypatch.setattr(comparison, "PYTHON_SOURCE_PINS", {name: comparison.sha(data) for name, data in py.items()})
    artifacts.update({"sources/go/" + name: data for name, data in go.items()})
    artifacts.update({"sources/python/" + name: data for name, data in py.items()})
    artifacts.update({"sources/python/" + name: go[name] for name in ("LICENSE", "NOTICE")})
    artifacts.update({"runners/" + name: (HERE / name).read_bytes() for name in ("native_runner.py", "package_comparison.py")})
    artifacts.update({"runners/" + name: (ROOT / name).read_bytes() for name in ("LICENSE", "NOTICE")})
    artifacts["runtime.json"] = comparison.canonical({
        "schema_version": "SCITT-NATIVE-RUNTIME-1", "platform_system": "Synthetic", "platform_machine": "Synthetic",
        "python_version": "Synthetic", "python_executable_sha256": "1" * 64,
        "python_distributions": comparison.PYTHON_DISTRIBUTION_PINS, "python_source_sha256": comparison.PYTHON_SOURCE_PINS,
        "go_checker_sha256": "2" * 64, "source_state_unchanged": True,
        "runner_sha256": comparison.sha(artifacts["runners/native_runner.py"]),
    })
    observations = []
    for case in corpus["cases"]:
        for language in comparison.COMPONENTS:
            output = comparison.canonical(native_output(language, case["facet"], case["expected_accept"], comparison.sha(b"\x00" + artifacts[case["leaf_path"]]) if case["leaf_path"] else "0" * 64))
            prefix = "outputs/" + case["case_id"] + "-" + language
            artifacts[prefix + ".stdout"], artifacts[prefix + ".stderr"] = output, b""
            observations.append({"case_id": case["case_id"], "implementation": language,
                "exit_code": 0 if case["expected_accept"] else 1, "stop_reason": None,
                "stdout_path": prefix + ".stdout", "stderr_path": prefix + ".stderr",
                "stdout_sha256": comparison.sha(output), "stderr_sha256": comparison.sha(b"")})
    artifacts["corpus.json"] = comparison.canonical(corpus)
    artifacts["observations.json"] = comparison.canonical({"schema_version": "SCITT-NATIVE-OBSERVATIONS-1", "observations": observations})
    registry = comparison.registry()
    return StoredComponentPackage("synthetic", "1", "Synthetic test", "Synthetic", "Not native evidence", registry,
        tuple(PackageArtifact(path, "application/octet-stream", data) for path, data in artifacts.items()),
        tuple(ImplementationBinding(component, registry.get(component).implementation_ref,
              tuple(path for path in artifacts if path.startswith("sources/" + language + "/")), ("runtime:" + language,))
              for language, component in comparison.COMPONENTS.items()),
        tuple(PackageDependency("runtime:" + language, "Synthetic unresolved runtime", ("runtime.json",)) for language in comparison.COMPONENTS))


def change_artifact(package: StoredComponentPackage, path: str, content: bytes) -> StoredComponentPackage:
    return replace(package, artifacts=tuple(replace(item, content=content) if item.path == path else item for item in package.artifacts))


def change_json(package: StoredComponentPackage, path: str, mutate) -> StoredComponentPackage:
    value = json.loads(next(item.content for item in package.artifacts if item.path == path))
    mutate(value)
    return change_artifact(package, path, comparison.canonical(value))


def report(package: StoredComponentPackage) -> dict:
    return comparison.compare_package(package, expected_digest=package.canonical_digest())


@pytest.mark.parametrize("name", ["LICENSE", "NOTICE"])
@pytest.mark.parametrize("mutation", ["missing", "substituted"])
def test_runner_redistribution_terms_required_with_fresh_package_digest(specimen: StoredComponentPackage, name: str, mutation: str) -> None:
    path = "runners/" + name
    if mutation == "missing":
        changed = replace(specimen, artifacts=tuple(item for item in specimen.artifacts if item.path != path))
    else:
        changed = change_artifact(specimen, path, b"substituted license or notice")
    with pytest.raises(ValueError, match="runner license or notice"):
        report(changed)


def test_export_retains_exact_public_runner_license_and_notice(
    specimen: StoredComponentPackage, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    capture, upstream, installed = (tmp_path / name for name in ("capture", "upstream", "installed"))
    for directory in (capture, upstream, installed):
        directory.mkdir()
    distribution_files = []
    for artifact in specimen.artifacts:
        if artifact.path in ("corpus.json", "observations.json", "runtime.json") or artifact.path.startswith(("inputs/", "outputs/")):
            destination = capture / artifact.path
        elif artifact.path.startswith("sources/go/"):
            destination = upstream / artifact.path.removeprefix("sources/go/")
        elif artifact.path.startswith("sources/python/"):
            relative = artifact.path.removeprefix("sources/python/")
            if relative in ("LICENSE", "NOTICE"):
                relative = "synthetic.dist-info/licenses/" + relative
            distribution_files.append(relative)
            destination = installed / relative
        else:
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(artifact.content)
    dist = SimpleNamespace(files=distribution_files, locate_file=lambda name: installed / name)
    monkeypatch.setattr(comparison, "distribution", lambda name: dist)
    monkeypatch.setattr(runner, "_run_process", lambda *a, **k: pytest.fail("export invoked native checker"))
    package = comparison.build_package(capture, upstream)
    retained = {item.path: item.content for item in package.artifacts}
    for name in ("LICENSE", "NOTICE"):
        assert retained["runners/" + name] == (ROOT / name).read_bytes()
    assert report(package)["native_execution_performed"] is False


def test_complete_recorded_comparison_is_not_native_execution_or_qualification(specimen: StoredComponentPackage, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runner, "capture_comparison", lambda *a, **k: pytest.fail("reconstruction invoked native capture"))
    result = report(specimen)
    assert len(result["cases"]) == 12
    assert result["agreement"] == result["expectations"] == "MATCHED"
    assert result["native_execution_performed"] is False
    assert result["native_qualification"] == result["actor_independence"] == "NOT_ESTABLISHED"
    assert comparison.reconstruct_sidecar(specimen, result, expected_digest=specimen.canonical_digest()) == result
    assert specimen.inspect()["native_qualification"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("field", ["agreement", "expectations", "recorded_observation_count", "native_execution_performed", "cases", "components"])
def test_forged_sidecar_is_not_trusted(specimen: StoredComponentPackage, field: str) -> None:
    result = report(specimen)
    result[field] = "forged"
    with pytest.raises(ValueError, match="reconstruct"):
        comparison.reconstruct_sidecar(specimen, result, expected_digest=specimen.canonical_digest())


@pytest.mark.parametrize("path", ["runtime.json", "inputs/artifact.txt", "sources/go/main.go", "sources/python/LICENSE"])
def test_changed_package_does_not_reuse_external_coordinate(specimen: StoredComponentPackage, path: str) -> None:
    changed = change_artifact(specimen, path, b"substitution")
    with pytest.raises(ValueError, match="coordinate"):
        comparison.compare_package(changed, expected_digest=specimen.canonical_digest())


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "reorder", "swapped_path", "wrong_hash", "unknown_stop"])
def test_observation_attribution_and_completeness_are_checked(specimen: StoredComponentPackage, mutation: str) -> None:
    def mutate(value):
        rows = value["observations"]
        if mutation == "missing": rows.pop()
        elif mutation == "duplicate": rows[1] = rows[0]
        elif mutation == "reorder": rows.reverse()
        elif mutation == "swapped_path": rows[0]["stdout_path"] = rows[1]["stdout_path"]
        elif mutation == "wrong_hash": rows[0]["stdout_sha256"] = "0" * 64
        else: rows[0]["stop_reason"] = "FORGED"
    with pytest.raises(ValueError):
        report(change_json(specimen, "observations.json", mutate))


@pytest.mark.parametrize("stop", ["TIMEOUT", "OUTPUT_LIMIT", "LAUNCH_ERROR"])
def test_operational_failure_does_not_become_semantic_rejection(specimen: StoredComponentPackage, stop: str) -> None:
    changed = change_json(specimen, "observations.json", lambda value: value["observations"][0].update(stop_reason=stop))
    result = report(changed)
    assert result["cases"][0]["results"]["python"]["outcome"] == "UNKNOWN"
    assert result["agreement"] == result["expectations"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("payload", [b"{}", b"not json", b'{"valid":true,"valid":false}', b"null"])
def test_malformed_native_output_is_not_a_result(payload: bytes) -> None:
    assert comparison.decode_output("go", "statement", payload, b"", 0, None)["outcome"] == "UNKNOWN"


def test_operational_go_error_and_python_stderr_remain_unknown() -> None:
    raw = native_output("go", "statement", False, "0" * 64)
    raw["error"] = "cannot read selected public key"
    assert comparison.decode_output("go", "statement", comparison.canonical(raw), b"", 1, None)["outcome"] == "UNKNOWN"
    assert comparison.decode_output("python", "statement", b"", b"error: cannot import runtime", 1, None)["outcome"] == "UNKNOWN"


def test_selected_source_cannot_be_supplied_only_as_unbound_inventory(specimen: StoredComponentPackage) -> None:
    changed = replace(specimen, implementations=tuple(replace(item, artifact_paths=("runtime.json",)) if item.component_id == comparison.COMPONENTS["go"] else item for item in specimen.implementations))
    with pytest.raises(ValueError, match="attribution"):
        report(changed)


def replace_observation(package: StoredComponentPackage, index: int, accepted: bool) -> StoredComponentPackage:
    observations = json.loads(next(item.content for item in package.artifacts if item.path == "observations.json"))
    corpus = json.loads(next(item.content for item in package.artifacts if item.path == "corpus.json"))
    observation, case = observations["observations"][index], corpus["cases"][index // 2]
    raw = comparison.canonical(native_output(observation["implementation"], case["facet"], accepted, "0" * 64))
    observation.update(exit_code=0 if accepted else 1, stdout_sha256=comparison.sha(raw))
    package = change_artifact(package, observation["stdout_path"], raw)
    return change_artifact(package, "observations.json", comparison.canonical(observations))


def test_same_wrong_answer_agrees_but_fails_fixture_expectations(specimen: StoredComponentPackage) -> None:
    changed = replace_observation(replace_observation(specimen, 4, True), 5, True)
    result = report(changed)
    assert result["agreement"] == "MATCHED"
    assert result["expectations"] == "MISMATCHED"
    assert result["cases"][2]["agreement"] == "MATCHED"
    assert result["cases"][2]["expectations"] == "MISMATCHED"


def test_genuine_comparable_disagreement_remains_conflicted(specimen: StoredComponentPackage) -> None:
    result = report(replace_observation(specimen, 4, True))
    assert result["agreement"] == "CONFLICTED"
    assert result["expectations"] == "MISMATCHED"


def test_missing_positive_control_does_not_erase_other_recorded_flags(specimen: StoredComponentPackage) -> None:
    changed = change_json(specimen, "observations.json", lambda value: value["observations"][0].update(stop_reason="TIMEOUT"))
    result = report(changed)
    assert result["cases"][0]["results"]["python"]["outcome"] == "UNKNOWN"
    assert result["cases"][2]["results"]["python"]["outcome"] == "NATIVE_FALSE"
    assert result["expectations"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("language", ["python", "go"])
def test_success_with_contradictory_native_errors_is_unknown(language: str) -> None:
    raw = native_output(language, "receipt", True, "0" * 64)
    raw["receipt"]["errors" if language == "python" else "error"] = ["receipt rejected: the COSE_Sign1 message is not valid CBOR (CBORDecodeEOF)"] if language == "python" else "could not read key"
    assert comparison.decode_output(language, "receipt", comparison.canonical(raw), b"", 0, None)["outcome"] == "UNKNOWN"


def test_returned_sidecar_cannot_mutate_decoder_contract(specimen: StoredComponentPackage) -> None:
    initial = list(comparison.LIMITATIONS)
    sidecar = report(specimen)
    try:
        sidecar["limitations"].clear()
        assert comparison.LIMITATIONS == initial
        with pytest.raises(ValueError, match="reconstruct"):
            comparison.reconstruct_sidecar(specimen, sidecar, expected_digest=specimen.canonical_digest())
    finally:
        comparison.LIMITATIONS[:] = initial


def test_other_implementation_failure_does_not_erase_python_flags(specimen: StoredComponentPackage) -> None:
    changed = change_json(specimen, "observations.json", lambda value: value["observations"][3].update(stop_reason="TIMEOUT"))
    result = report(changed)
    assert result["cases"][1]["agreement"] == "NOT_ESTABLISHED"
    assert result["cases"][2]["results"]["python"]["outcome"] == "NATIVE_FALSE"


def test_corpus_boolean_cannot_be_replaced_by_integer(specimen: StoredComponentPackage) -> None:
    changed = change_json(specimen, "corpus.json", lambda value: value["cases"][0].update(expected_accept=1))
    with pytest.raises(ValueError, match="corpus"):
        report(changed)


def test_pinned_go_truncation_shape_records_false_without_an_algorithm_claim() -> None:
    raw = {"valid": False, "alg": "", "content_type": "", "iss": "", "sub": "",
           "error": "decode COSE_Sign1: unexpected EOF"}
    assert comparison.decode_output("go", "statement", comparison.canonical(raw), b"", 1, None)["outcome"] == "NATIVE_FALSE"
