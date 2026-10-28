"""Packaged JavaScript Object Notation (JSON) schemas have unambiguous keys."""
import json
from pathlib import Path

def _unique_object(pairs):
    result={}
    for key,value in pairs:
        if key in result:
            raise ValueError("duplicate schema key: "+key)
        result[key]=value
    return result

def test_packaged_schema_keys_are_unambiguous():
    root=Path(__file__).resolve().parents[1]
    paths=sorted((root/"src/verifier/schemas").glob("*.json"))
    paths+=sorted((root/"receipts/schema").glob("*.json"))
    assert paths
    for path in paths:
        try:
            json.loads(path.read_text(encoding="utf-8"),object_pairs_hook=_unique_object)
        except ValueError as error:
            raise AssertionError(str(path.relative_to(root))+": "+str(error)) from error
