"""Versioned package capacity and exact byte identity; no native qualification.

Terminology: JavaScript Object Notation (JSON).
"""
from dataclasses import replace
import json
from pathlib import Path

import pytest
from verifier.interoperability import storage
from test_component_package_storage import sample_package

V2=storage.COMPONENT_PACKAGE_V2_SCHEMA_VERSION

def package(count,version):
    original=sample_package()
    artifacts=tuple(storage.PackageArtifact('src/f%04d.py'%n,'text/plain',b'x') for n in range(count))
    binding=storage.ImplementationBinding(original.implementations[0].component_id,
        original.implementations[0].implementation_ref,tuple(a.path for a in artifacts),
        schema_version=version)
    return replace(original,artifacts=artifacts,implementations=(binding,),dependencies=(),schema_version=version)

@pytest.mark.parametrize('version,limit',[(storage.COMPONENT_PACKAGE_SCHEMA_VERSION,256),(V2,512)])
def test_independent_artifact_and_implementation_path_boundaries(version,limit):
    value=package(limit,version)
    assert storage.StoredComponentPackage.from_dict(value.to_dict())==value
    with pytest.raises(storage.ComponentPackageError): package(limit+1,version)
    surplus=replace(value.artifacts[0],path='src/extra.py')
    with pytest.raises(storage.ComponentPackageError): replace(value,artifacts=value.artifacts+(surplus,))

def test_v2_large_binding_cannot_be_downgraded_into_v1():
    value=package(270,V2)
    with pytest.raises(storage.ComponentPackageError): replace(value,schema_version=storage.COMPONENT_PACKAGE_SCHEMA_VERSION)
    document=value.to_dict()
    document['schema_version']=storage.COMPONENT_PACKAGE_SCHEMA_VERSION
    with pytest.raises(storage.ComponentPackageError): storage.StoredComponentPackage.from_dict(document)

def test_v2_preserves_other_array_limits():
    value=package(270,V2)
    with pytest.raises(storage.ComponentPackageError):
        replace(value,dependencies=tuple(storage.PackageDependency('dep%04d'%n,'declared') for n in range(257)))
    with pytest.raises(storage.ComponentPackageError):
        storage.PackageDependency('dep','declared',tuple('src/f%04d.py'%n for n in range(257)))
    with pytest.raises(storage.ComponentPackageError):
        replace(value.implementations[0],dependency_ids=tuple('dep%04d'%n for n in range(257)))
    with pytest.raises(storage.ComponentPackageError): replace(value,implementations=value.implementations*257)

def test_v2_preserves_total_content_and_encoded_byte_limits(monkeypatch):
    value=package(270,V2)
    monkeypatch.setattr(storage,'MAX_CONTENT_BYTES',269)
    with pytest.raises(storage.ComponentPackageError,match='total retained'): replace(value)
    monkeypatch.setattr(storage,'MAX_CONTENT_BYTES',16*1024*1024)
    monkeypatch.setattr(storage,'MAX_PACKAGE_BYTES',len(value.canonical_json_bytes())-1)
    with pytest.raises(storage.ComponentPackageError,match='encoded package'): replace(value)

def test_v1_canonical_fixture_bytes_remain_identical():
    value=sample_package()
    assert value.canonical_digest()=='ee2568bafba54afafc31d924fa6b398054459449b8aeed57cfce513116874f4f'
    assert value.schema_version==storage.COMPONENT_PACKAGE_SCHEMA_VERSION

def test_exact_v2_schema_selection_and_v1_schema_rejection():
    import jsonschema
    root=Path(storage.__file__).parents[3]
    schema1=json.loads((root/'src/verifier/schemas/verifier-component-package-1.schema.json').read_bytes())
    schema2=json.loads((Path(storage.__file__).parents[1]/'schemas/verifier-component-package-2.schema.json').read_bytes())
    document=package(270,V2).to_dict()
    assert not jsonschema.Draft202012Validator(schema1).is_valid(document)
    jsonschema.Draft202012Validator(schema2).validate(document)
    assert schema2['$defs']['pathList']['maxItems']==256
    assert schema2['$defs']['implementationPathList']['maxItems']==512
    document['implementations'][0]['artifact_paths']=[]
    assert not jsonschema.Draft202012Validator(schema2).is_valid(document)
    with pytest.raises(storage.ComponentPackageError): storage.StoredComponentPackage.from_dict(document)
