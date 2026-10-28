# Terminology: JavaScript Object Notation (JSON).
from __future__ import annotations

import copy
import json
from pathlib import Path
import re
import subprocess

import pytest

from verifier.runtime import package_self_polish_recheck
from verifier.runtime import tier_zero_manifest as manifest
from verifier.runtime import tier_zero_profile


REPOSITORY = "https://github.com/TimeLordRaps/verifier.git"
REVISION = "52550135f67559e37625b398a49ec2e103b65178"


def _value() -> dict:
    return manifest.manifest_template(repository=REPOSITORY, revision=REVISION)


def test_installed_graph_matches_independent_package_recheck_template() -> None:
    rows = manifest.installed_object_declarations()
    expected = package_self_polish_recheck._GRAPH_TEMPLATE
    assert len(rows) == 26 == len(expected)
    for row in rows:
        object_id, role, edges = expected[row["object_kind"]]
        assert row["object_id"] == object_id
        assert row["role"] == role
        if row["object_kind"] == "GRAPH":
            assert row["edges"] == {"members": sorted(
                value[0] for kind, value in expected.items() if kind != "GRAPH"
            )}
        else:
            assert row["edges"] == edges


def test_verifier_core_retained_graph_binds_one_governing_harness() -> None:
    verifier = next(
        row
        for row in manifest.installed_object_declarations()
        if row["object_id"] == "verifier-core-self"
    )

    assert verifier["edges"] == {"harness": ["vstd-harness"]}


def test_manifest_template_validates_structural_tier_zero_subset() -> None:
    result = manifest.validate_manifest(
        _value(), expected_repository=REPOSITORY, expected_revision=REVISION,
    )
    assert result["status"] == "PASS"
    assert result["object_count"] == 26
    assert result["surface_rule_count"] == 23
    assert result["slot_count"] == 234
    assert result["route_count"] == 408
    assert result["adversarial_corpus_status"] == "PASS"
    assert result["reason_provider_selection_status"] == "SELECTED"
    assert result["node_reconciler_selection_status"] == "SELECTED"


@pytest.mark.parametrize("mutation,code", [
    (lambda value: value["objects"].pop(), "TIER_ZERO_OBJECT_DENOMINATOR_DIFFERS"),
    (lambda value: value["objects"][0].update(object_id="substituted"),
     "TIER_ZERO_OBJECT_GRAPH_DIFFERS"),
    (lambda value: value["objects"][12]["edges"].update(
        representation=["vstd-role"]), "TIER_ZERO_OBJECT_GRAPH_DIFFERS"),
    (lambda value: value["surface_rules"].pop(),
     "TIER_ZERO_SURFACE_RULE_DENOMINATOR_DIFFERS"),
])
def test_manifest_refuses_denominator_and_graph_drift(mutation, code: str) -> None:
    value = copy.deepcopy(_value())
    mutation(value)
    with pytest.raises(manifest.TierZeroManifestError, match=code):
        manifest.validate_manifest(
            value, expected_repository=REPOSITORY, expected_revision=REVISION,
        )


def test_manifest_loader_refuses_duplicate_nonfinite_and_noncanonical_bytes(
        tmp_path) -> None:
    cases = (
        (b'{"schema_version":1,"schema_version":2}\n',
         "TIER_ZERO_MANIFEST_DUPLICATE_KEY"),
        (b'{"value":NaN}\n', "TIER_ZERO_MANIFEST_NONFINITE_NUMBER"),
        (b'{ "value":1}\n', "TIER_ZERO_MANIFEST_NOT_CANONICAL"),
    )
    for raw, code in cases:
        path = tmp_path / "objects.vstd"
        path.write_bytes(raw)
        with pytest.raises(manifest.TierZeroManifestError, match=code):
            manifest.load_manifest(
                path, expected_repository=REPOSITORY,
                expected_revision=REVISION,
            )


@pytest.mark.parametrize("version", (2, 3, 4))
def test_extended_manifest_capacity_preserves_complete_surface_inventory(tmp_path, version: int) -> None:
    from verifier.runtime import namespace_manifest, package_polish
    value = {"schema_version": "verifier-objects-manifest-" + str(version),
             "padding": "x" * manifest.MAX_MANIFEST_BYTES}
    raw = manifest._document_bytes(value)
    assert len(raw) > manifest.MAX_MANIFEST_BYTES
    path = tmp_path / "objects.vstd"
    path.write_bytes(raw)
    assert namespace_manifest.read_manifest(path) == (raw, value)
    assert package_polish._read_manifest(tmp_path) == raw


def test_legacy_manifest_capacity_is_not_widened() -> None:
    value = {"schema_version": manifest.MANIFEST_SCHEMA,
             "padding": "x" * manifest.MAX_MANIFEST_BYTES}
    with pytest.raises(manifest.TierZeroManifestError, match="CAPACITY_EXHAUSTED"):
        manifest._strict_json_document(manifest._document_bytes(value))


def test_extended_manifest_still_has_a_finite_byte_bound() -> None:
    value = {"schema_version": "verifier-objects-manifest-4", "padding": "x" * (8 * 1024 * 1024)}
    with pytest.raises(manifest.TierZeroManifestError, match="CAPACITY_EXHAUSTED"):
        manifest._strict_json_document(manifest._document_bytes(value))


def test_package_graph_manifest_has_a_distinct_finite_capacity(tmp_path) -> None:
    from verifier.runtime import namespace_manifest, package_polish
    value = {
        "schema_version": "verifier-objects-manifest-5",
        "padding": "x" * manifest.MAX_EXTENDED_MANIFEST_BYTES,
    }
    raw = manifest._document_bytes(value)
    assert manifest.MAX_EXTENDED_MANIFEST_BYTES < len(raw) < manifest.MAX_PACKAGE_MANIFEST_BYTES
    path = tmp_path / "objects.vstd"
    path.write_bytes(raw)
    assert namespace_manifest.read_manifest(path) == (raw, value)
    assert package_polish._read_manifest(tmp_path) == raw


def test_package_graph_manifest_capacity_is_finite() -> None:
    value = {
        "schema_version": "verifier-objects-manifest-5",
        "padding": "x" * manifest.MAX_PACKAGE_MANIFEST_BYTES,
    }
    with pytest.raises(manifest.TierZeroManifestError, match="CAPACITY_EXHAUSTED"):
        manifest._strict_json_document(manifest._document_bytes(value))


@pytest.mark.parametrize("version,accepted", [(4, False), (5, True)])
def test_package_structure_profile_does_not_widen_version_four(
    tmp_path, version: int, accepted: bool
) -> None:
    from verifier.runtime import namespace_manifest
    value = {
        "schema_version": "verifier-objects-manifest-" + str(version),
        "padding": [None] * namespace_manifest.MAX_NAMESPACE_NODES,
    }
    path = tmp_path / "objects.vstd"
    path.write_bytes(manifest._document_bytes(value))
    if accepted:
        assert namespace_manifest.read_manifest(path)[1] == value
    else:
        with pytest.raises(ValueError, match="NAMESPACE_MANIFEST_STRUCTURE_CAPACITY"):
            namespace_manifest.read_manifest(path)


def _node_reconciler() -> Path:
    return Path(manifest.__file__).with_name("tier_zero_reconcile.mjs")


def _run_node(path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run([
        "node", str(_node_reconciler()), "--manifest", str(path),
        "--repository", REPOSITORY, "--revision", REVISION,
        "--source-root", str(Path(__file__).parents[1]),
    ], capture_output=True, text=True, check=False, timeout=30)


@pytest.mark.parametrize("version", (1, 3, 4, 5, 6))
def test_node_and_python_preserve_legacy_cap_with_larger_envelopes(tmp_path, version: int) -> None:
    value = _value()
    value.update(schema_version="verifier-objects-manifest-" + str(version),
                 namespace={"padding": "x" * manifest.MAX_MANIFEST_BYTES})
    if version in (4, 5, 6):
        value["representation_updates"] = []
    path = tmp_path / "objects.vstd"
    path.write_bytes(manifest._document_bytes(value))
    completed = _run_node(path)
    if version == 1:
        assert completed.returncode == 1
        assert json.loads(completed.stdout)["error"] == "TIER_ZERO_MANIFEST_CAPACITY_EXHAUSTED"
    else:
        assert completed.returncode == 0, completed.stdout + completed.stderr
        _, result = manifest.load_manifest(path, expected_repository=REPOSITORY, expected_revision=REVISION)
        assert result["manifest_digest"] == json.loads(completed.stdout)["manifest_digest"]
        assert result["slot_count"] == 234 and result["route_count"] == 408


@pytest.mark.parametrize("version,exit_code", [(4, 1), (5, 0), (6, 0)])
def test_node_package_transport_does_not_widen_version_four(
    tmp_path, version: int, exit_code: int
) -> None:
    value = _value()
    value.update(
        schema_version="verifier-objects-manifest-" + str(version),
        namespace={"padding": "x" * manifest.MAX_EXTENDED_MANIFEST_BYTES},
        representation_updates=[],
    )
    raw = manifest._document_bytes(value)
    assert manifest.MAX_EXTENDED_MANIFEST_BYTES < len(raw) < manifest.MAX_PACKAGE_MANIFEST_BYTES
    path = tmp_path / "objects.vstd"
    path.write_bytes(raw)
    completed = _run_node(path)
    assert completed.returncode == exit_code
    if version == 4:
        assert json.loads(completed.stdout)["error"] == "TIER_ZERO_MANIFEST_CAPACITY_EXHAUSTED"
    else:
        assert json.loads(completed.stdout)["status"] == "PASS"


def test_node_reconciler_independently_matches_python_structural_digests(
        tmp_path) -> None:
    value = _value()
    path = tmp_path / "objects.vstd"
    path.write_bytes(manifest._document_bytes(value))
    _, python_result = manifest.load_manifest(
        path, expected_repository=REPOSITORY, expected_revision=REVISION,
    )
    completed = _run_node(path)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    node_result = json.loads(completed.stdout)
    for field in (
        "status", "profile_digest", "object_count", "object_kind_digest",
        "graph_digest", "surface_rule_count", "surface_rule_digest",
        "semantic_version", "slot_count", "route_count", "slot_digest",
        "route_identity_digest", "adversarial_corpus_status",
        "adversarial_corpus_digest", "attachment_selection_digest",
        "reason_provider_selection_status", "node_reconciler_selection_status",
        "manifest_digest", "manifest_value_digest",
    ):
        assert node_result[field] == python_result[field]


def _node_profile_constants() -> tuple[str, list[list[str]]]:
    """Read the literal Node profile pin and obligation mirror from source.

    The reconciler stays Node-only, so the binding is inspected in its source
    text rather than by executing Python.  Each literal is valid JSON.
    """
    source = _node_reconciler().read_text(encoding="utf-8")
    digest = re.search(
        r'^const PROFILE_DIGEST = ("sha256:[0-9a-f]{64}");$', source, re.M,
    )
    obligations = re.search(
        r"^const PROFILE_OBLIGATIONS = (\[.*?\]);$", source, re.M | re.S,
    )
    assert digest is not None, "PROFILE_DIGEST literal not found"
    assert obligations is not None, "PROFILE_OBLIGATIONS literal not found"
    return json.loads(digest.group(1)), json.loads(obligations.group(1))


def test_node_profile_pin_and_nine_obligations_match_installed_python_profile() -> None:
    profile = tier_zero_profile.installed_tier_zero_profile()
    node_digest, node_obligations = _node_profile_constants()
    assert node_digest == profile["profile_digest"]
    assert len(node_obligations) == 9 == len(profile["obligations"])
    assert node_obligations == [
        [row["coordinate"], row["name"]] for row in profile["obligations"]
    ]


def test_node_refuses_profile_digest_mismatch_without_weakening(tmp_path) -> None:
    value = _value()
    value["profile_digest"] = "sha256:" + "0" * 64
    path = tmp_path / "objects.vstd"
    path.write_bytes(manifest._document_bytes(value))
    completed = _run_node(path)
    assert completed.returncode == 1
    assert json.loads(completed.stdout) == {
        "error": "TIER_ZERO_MANIFEST_PROFILE_DIFFERS",
        "schema_version": "verifier-tier-zero-node-error-1",
        "status": "FAIL",
    }


@pytest.mark.parametrize("raw,code", [
    (b'{"schema_version":1,"schema_version":2}\n',
     "TIER_ZERO_MANIFEST_DUPLICATE_KEY"),
    (b'{"value":NaN}\n', "TIER_ZERO_MANIFEST_NONFINITE_NUMBER"),
    (b'{"value":1e10000}\n', "TIER_ZERO_MANIFEST_NONFINITE_NUMBER"),
    (b'{"value":' + (b'9' * 5000) + b'}\n',
     "TIER_ZERO_MANIFEST_NONFINITE_NUMBER"),
    ('{"𐀀":2,"":1}\n'.encode("utf-8"),
     "TIER_ZERO_MANIFEST_NOT_CANONICAL"),
    (b'{ "value":1}\n', "TIER_ZERO_MANIFEST_NOT_CANONICAL"),
])
def test_node_reconciler_matches_python_parser_refusals(
        tmp_path, raw: bytes, code: str) -> None:
    path = tmp_path / "objects.vstd"
    path.write_bytes(raw)
    completed = _run_node(path)
    assert completed.returncode == 1
    assert json.loads(completed.stdout) == {
        "error": code,
        "schema_version": "verifier-tier-zero-node-error-1",
        "status": "FAIL",
    }


def test_node_and_python_apply_byte_capacity_before_structure_capacity(
    tmp_path,
) -> None:
    value = {
        "schema_version": "verifier-objects-manifest-4",
        "padding": [None] * (manifest.MAX_MANIFEST_NODES + 1),
        "bytes": "x" * manifest.MAX_EXTENDED_MANIFEST_BYTES,
    }
    raw = manifest._document_bytes(value)
    assert len(raw) > manifest.MAX_EXTENDED_MANIFEST_BYTES
    with pytest.raises(
        manifest.TierZeroManifestError,
        match="TIER_ZERO_MANIFEST_CAPACITY_EXHAUSTED",
    ):
        manifest._strict_json_document(raw)
    path = tmp_path / "objects.vstd"
    path.write_bytes(raw)
    completed = _run_node(path)
    assert completed.returncode == 1
    assert json.loads(completed.stdout)["error"] == (
        "TIER_ZERO_MANIFEST_CAPACITY_EXHAUSTED"
    )


def test_node_and_python_apply_global_structure_before_version_byte_capacity(
    tmp_path,
) -> None:
    value = {
        "schema_version": "verifier-objects-manifest-4",
        "padding": [None] * (manifest.MAX_PACKAGE_MANIFEST_NODES + 1),
        "bytes": "x" * manifest.MAX_MANIFEST_BYTES,
    }
    raw = manifest._document_bytes(value)
    assert len(raw) > manifest.MAX_EXTENDED_MANIFEST_BYTES
    with pytest.raises(
        manifest.TierZeroManifestError,
        match="TIER_ZERO_MANIFEST_STRUCTURE_CAPACITY_EXHAUSTED",
    ):
        manifest._strict_json_document(raw)
    path = tmp_path / "objects.vstd"
    path.write_bytes(raw)
    completed = _run_node(path)
    assert completed.returncode == 1
    assert json.loads(completed.stdout)["error"] == (
        "TIER_ZERO_MANIFEST_STRUCTURE_CAPACITY_EXHAUSTED"
    )


def test_root_manifest_is_exact_current_template_and_schema_valid() -> None:
    root = Path(__file__).parents[1]
    value, result = manifest.load_manifest(
        root / "objects.vstd", expected_repository=REPOSITORY,
        expected_revision=REVISION,
    )
    assert value == _value()
    assert result["status"] == "PASS"
    import jsonschema
    schema = json.loads((
        root / "src/verifier/schemas/verifier-objects-manifest-1.schema.json"
    ).read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(value)
