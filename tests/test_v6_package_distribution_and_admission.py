"""Version-6 compact package transport and retained-admission regressions."""
from __future__ import annotations

from copy import deepcopy
import json
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Any

import jsonschema
import pytest
import referencing

from verifier.runtime import namespace_manifest, package_manifest, tier_zero_manifest
from verifier.runtime.namespace_contracts import namespace_registry, registry_document
from verifier.runtime.tier_zero_profile import canonical_bytes, value_digest


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOT = ROOT / "src" / "verifier" / "schemas"
SCHEMA_NAME = "verifier-objects-manifest-6.schema.json"
REMOTE = "https://github.com/TimeLordRaps/verifier.git"
REVISION = "6" * 40


def _v5_manifest() -> dict[str, Any]:
    retained = tier_zero_manifest.manifest_template(
        repository=REMOTE,
        revision=REVISION,
    )
    objects = [
        {
            **item.to_dict(),
            "specializations": [],
            "surfaces": [],
            "reason": "The package declaration retains this exact bounded role.",
            "classification": {},
            "obligations": {},
        }
        for item in tier_zero_manifest._namespace_objects(retained["objects"])
    ]
    subject = next(row for row in objects if row["kind"] == "OBJECT")
    evidence = [{
        "path": "src/verifier/core/namespace.py",
        "sha256": "sha256:" + "a" * 64,
    }]
    subject["classification"] = {
        "OBJECT": {
            "status": "APPLIES",
            "reason": "The retained package subject carries the OBJECT role.",
            "evidence": deepcopy(evidence),
        }
    }
    subject["obligations"] = {
        "OBJECT-0.1-subject-boundary": {
            "reason": "The retained package subject boundary must remain explicit.",
            "declaration": {"contract": "vstd-package-object"},
            "evidence": deepcopy(evidence),
        }
    }
    return {
        **retained,
        "schema_version": package_manifest.PACKAGE_REPRESENTATION_SCHEMA,
        "namespace": {
            "schema_version": namespace_manifest.SCHEMA,
            "extensions": [],
            "registry_digest": registry_document(namespace_registry())["digest"],
            "objects": objects,
        },
        "representation_updates": [],
    }


def _v6_manifest() -> dict[str, Any]:
    document = deepcopy(_v5_manifest())
    document["schema_version"] = package_manifest.COMPACT_PACKAGE_REPRESENTATION_SCHEMA
    namespace = document["namespace"]
    namespace["schema_version"] = namespace_manifest.COMPACT_SCHEMA
    for row in namespace["objects"]:
        evidence_sets: dict[str, list[dict[str, str]]] = {}
        for decision in row["classification"].values():
            evidence = decision.pop("evidence")
            digest = value_digest(evidence)
            evidence_sets.setdefault(digest, deepcopy(evidence))
            decision["evidence_set_digest"] = digest
        for binding in row["obligations"].values():
            evidence = binding.pop("evidence")
            digest = value_digest(evidence)
            evidence_sets.setdefault(digest, deepcopy(evidence))
            binding["evidence_set_digest"] = digest
        row["evidence_sets"] = evidence_sets
    return document


def _schema_registry() -> tuple[dict[str, Any], referencing.Registry]:
    names = [
        *(f"verifier-objects-manifest-{version}.schema.json" for version in range(2, 7)),
        "verifier-namespace-manifest-3.schema.json",
    ]
    schemas = [json.loads((SCHEMA_ROOT / name).read_text(encoding="utf-8")) for name in names]
    registry = referencing.Registry().with_resources(
        (schema["$id"], referencing.Resource.from_contents(schema))
        for schema in schemas
    )
    return schemas[-2], registry


def test_v6_schema_is_closed_and_keeps_v5_transport_distinct() -> None:
    schema, registry = _schema_registry()
    jsonschema.Draft202012Validator.check_schema(schema)
    v6_validator = jsonschema.Draft202012Validator(schema, registry=registry)
    v5_schema = json.loads(
        (SCHEMA_ROOT / "verifier-objects-manifest-5.schema.json").read_text(encoding="utf-8")
    )
    v5_validator = jsonschema.Draft202012Validator(v5_schema, registry=registry)

    v6_validator.validate(_v6_manifest())
    v5_validator.validate(_v5_manifest())
    assert not v6_validator.is_valid(_v5_manifest())
    assert not v5_validator.is_valid(_v6_manifest())
    assert schema["properties"]["namespace"]["$ref"] == (
        "verifier-namespace-manifest-3.schema.json"
    )


def test_v5_and_compact_v6_select_identical_retained_contract_and_objects() -> None:
    v5 = _v5_manifest()
    v6 = _v6_manifest()

    retained_v5, validation_v5, objects_v5 = package_manifest.select(
        v5, repository=REMOTE, revision=REVISION
    )
    retained_v6, validation_v6, objects_v6 = package_manifest.select(
        v6, repository=REMOTE, revision=REVISION
    )

    expected_retained = tier_zero_manifest.manifest_template(
        repository=REMOTE,
        revision=REVISION,
    )
    assert retained_v5 == retained_v6 == expected_retained
    assert package_manifest.retained_contract(v5) == expected_retained
    assert package_manifest.retained_contract(v6) == expected_retained
    assert validation_v5 == validation_v6
    assert [item.to_dict() for item in objects_v5] == [
        item.to_dict() for item in objects_v6
    ]


def test_v6_bridge_normalizes_before_semantics_without_field_loss(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    v5 = _v5_manifest()
    v6 = _v6_manifest()
    original = deepcopy(v6)
    observed: list[dict[str, Any]] = []
    normalize = namespace_manifest.normalize_manifest

    def record(value: dict[str, Any]) -> dict[str, Any]:
        result = normalize(value)
        observed.append(deepcopy(result))
        return result

    monkeypatch.setattr(namespace_manifest, "normalize_manifest", record)
    package_manifest.validate_bridge(v6)

    assert observed == [v5["namespace"]]
    assert v6 == original
    subject = next(
        row for row in observed[0]["objects"] if row["kind"] == "OBJECT"
    )
    assert set(subject) == namespace_manifest.OBJECT_FIELDS
    assert subject["classification"]["OBJECT"]["evidence"] == [
        {
            "path": "src/verifier/core/namespace.py",
            "sha256": "sha256:" + "a" * 64,
        }
    ]
    assert subject["obligations"]["OBJECT-0.1-subject-boundary"]["declaration"] == {
        "contract": "vstd-package-object"
    }


def test_v6_rejects_missing_and_mismatched_compact_evidence_sets() -> None:
    missing = _v6_manifest()
    subject = next(
        row for row in missing["namespace"]["objects"] if row["kind"] == "OBJECT"
    )
    subject["evidence_sets"].clear()
    with pytest.raises(ValueError, match="^NAMESPACE_COMPACT_EVIDENCE_SET_REFERENCE_MISSING$"):
        package_manifest.validate_bridge(missing)

    mismatched = _v6_manifest()
    subject = next(
        row for row in mismatched["namespace"]["objects"] if row["kind"] == "OBJECT"
    )
    digest = next(iter(subject["evidence_sets"]))
    subject["evidence_sets"][digest][0]["path"] = "src/verifier/core/substituted.py"
    with pytest.raises(ValueError, match="^NAMESPACE_COMPACT_EVIDENCE_SET_DIGEST_DIFFERS$"):
        package_manifest.validate_bridge(mismatched)


def test_v6_uses_the_existing_finite_package_admission_envelope() -> None:
    document = _v6_manifest()
    raw = canonical_bytes(document) + b"\n"

    assert tier_zero_manifest.MAX_PACKAGE_MANIFEST_BYTES == 32 * 1024 * 1024
    assert package_manifest.COMPACT_PACKAGE_REPRESENTATION_SCHEMA in (
        tier_zero_manifest._PACKAGE_SCHEMAS
    )
    assert tier_zero_manifest._strict_json_document(raw) == document
    retained = package_manifest.retained_contract(document)
    assert tier_zero_manifest.validate_manifest(
        retained,
        expected_repository=REMOTE,
        expected_revision=REVISION,
    )["status"] == "PASS"

    with pytest.raises(
        tier_zero_manifest.TierZeroManifestError,
        match="^TIER_ZERO_MANIFEST_CAPACITY_EXHAUSTED$",
    ):
        tier_zero_manifest._strict_json_document(
            b"x" * (tier_zero_manifest.MAX_PACKAGE_MANIFEST_BYTES + 1)
        )


def test_v6_schema_is_in_built_wheel_and_source_distribution(tmp_path: Path) -> None:
    source = tmp_path / "source"
    artifacts = tmp_path / "artifacts"
    shutil.copytree(
        ROOT,
        source,
        ignore=shutil.ignore_patterns(
            ".git", ".pytest_cache", ".venv", "*.egg-info", "__pycache__",
            "artifacts_tmp", "build", "dist",
        ),
    )
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "build",
            "--wheel",
            "--sdist",
            "--outdir",
            str(artifacts),
            ".",
        ],
        cwd=source,
        check=False,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert completed.returncode == 0, completed.stdout[-4000:] + completed.stderr[-4000:]
    wheels = list(artifacts.glob("*.whl"))
    source_distributions = list(artifacts.glob("*.tar.gz"))
    assert len(wheels) == len(source_distributions) == 1

    expected = (source / "src" / "verifier" / "schemas" / SCHEMA_NAME).read_bytes()
    wheel_member = "verifier/schemas/" + SCHEMA_NAME
    with zipfile.ZipFile(wheels[0]) as archive:
        assert archive.namelist().count(wheel_member) == 1
        assert archive.read(wheel_member) == expected

    with tarfile.open(source_distributions[0], "r:gz") as archive:
        matches = [
            member
            for member in archive.getmembers()
            if member.name.replace("\\", "/").endswith(
                "/src/verifier/schemas/" + SCHEMA_NAME
            )
        ]
        assert len(matches) == 1 and matches[0].isfile()
        stream = archive.extractfile(matches[0])
        assert stream is not None and stream.read() == expected
