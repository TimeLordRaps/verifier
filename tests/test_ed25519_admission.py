"""Refutable public-key admission across actual native signature consumers.

Ed25519 is the Edwards-curve digital signature algorithm with a 255-bit field.
Secure Hash Algorithm 256-bit (SHA-256); JavaScript Object Notation (JSON).
Generated private keys are disposable test fixtures. The encoded identity point
is public data, not a secret key; it must never authenticate an arbitrary message.
"""
from __future__ import annotations

import base64
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

import pytest
from examples import domain_grounding as domain_example

pytest.importorskip("cryptography", reason="OPTIONAL_DEPENDENCY_ABSENT: signature admission requires the seal extra")
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from verifier.core.certificate import canonical_bytes
from verifier.domains import actor, sim, token
from verifier.domains.common import Budget, Refuted, digest
from verifier.interoperability import network

IDENTITY_KEY = b"\x01" + b"\x00" * 31
IDENTITY_SIGNATURE = b"\x01" + b"\x00" * 63


def public_bytes(key: Any) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def url64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


@pytest.mark.parametrize("forged,backend_missing", [(False, False), (True, False), (True, True)],
    ids=["generated-key-control", "identity-key-forgery", "bad-key-without-backend"])
def test_actor_witness_key_admission(forged: bool, backend_missing: bool, monkeypatch: Any) -> None:
    from test_domain_actor import _sample_actor_bundle, _witnessed
    artifact, inputs = _sample_actor_bundle()
    inputs, keys = _witnessed(artifact, inputs)
    if forged:
        keys = dict.fromkeys(keys, IDENTITY_KEY.hex())
        for row in inputs["witness_attributions"]:
            row["signature"] = b64(IDENTITY_SIGNATURE)
        if backend_missing:
            deny_backend_imports(monkeypatch)
        with pytest.raises(Refuted):
            actor.evaluate("accountability", artifact, inputs, Budget(10000), witness_keys=keys)
    else:
        assert actor.evaluate("accountability", artifact, inputs, Budget(10000), witness_keys=keys)["witnesses_verified"] == 2


@pytest.mark.parametrize("forged,backend_missing", [(False, False), (True, False), (True, True)],
    ids=["generated-key-control", "identity-key-forgery", "bad-key-without-backend"])
def test_sim_shard_key_admission(forged: bool, backend_missing: bool, monkeypatch: Any) -> None:
    from test_sim_check_selection import specimen
    artifact, inputs = specimen()
    artifact["shards"]["require_signatures"] = True
    keys = {}
    for name, rows in inputs["shards"].items():
        private = Ed25519PrivateKey.generate()
        keys[name] = (IDENTITY_KEY if forged else public_bytes(private)).hex()
        for index, row in enumerate(rows):
            message = {"artifact_digest": digest(artifact), "shard": name,
                       "step": index, "time": inputs["times"][index], "state": row["state"]}
            row["signature"] = b64(IDENTITY_SIGNATURE if forged else private.sign(canonical_bytes(message)))
    if forged:
        if backend_missing:
            deny_backend_imports(monkeypatch)
        with pytest.raises(Refuted):
            sim.evaluate("shards", artifact, inputs, Budget(10000), witness_keys=keys)
    else:
        assert sim.evaluate("shards", artifact, inputs, Budget(10000), witness_keys=keys)["states"] == 2


@pytest.mark.parametrize("forged,backend_missing", [(False, False), (True, False), (True, True)],
    ids=["generated-key-control", "identity-key-forgery", "bad-key-without-backend"])
def test_token_issuer_key_admission(forged: bool, backend_missing: bool, monkeypatch: Any) -> None:
    bundle = deepcopy(domain_example.specimens()["TOKEN"])
    artifact, inputs = bundle["artifact"], bundle["inputs"]
    keys = domain_example.token_witness_keys()
    if forged:
        key_id = digest(IDENTITY_KEY.hex())
        artifact["issuing_keys"] = [{"key_id": key_id, "key_bytes": IDENTITY_KEY.hex()}]
        artifact["key_retirements"] = {key_id: 9000}
        keys = {key_id: IDENTITY_KEY.hex()}
        for row in inputs["tokens"]:
            row["issuing_key_id"], row["signature"] = key_id, b64(IDENTITY_SIGNATURE)
        artifact["tokens_digest"] = digest(inputs["tokens"])
        if backend_missing:
            deny_backend_imports(monkeypatch)
        with pytest.raises(Refuted):
            token.evaluate("signatures", artifact, inputs, Budget(100000), witness_keys=keys)
    else:
        assert token.evaluate("signatures", artifact, inputs, Budget(100000), witness_keys=keys)["verified"] == 4


@pytest.mark.parametrize("forged,backend_missing", [(False, False), (True, False), (True, True)],
    ids=["generated-key-control", "identity-key-forgery", "bad-key-without-backend"])
def test_bootstrap_key_admission(forged: bool, backend_missing: bool, monkeypatch: Any) -> None:
    from test_verifier_bootstrap import signed_bundle, assessment
    artifact, inputs, keys = signed_bundle()
    if forged:
        keys = dict.fromkeys(keys, IDENTITY_KEY.hex())
        inputs["bootstrap_receipt"]["signature"] = IDENTITY_SIGNATURE.hex()
        artifact["bootstrap_digest"] = digest(inputs["bootstrap_receipt"])
    if backend_missing:
        deny_backend_imports(monkeypatch)
    result = assessment(artifact, inputs, keys)
    assert result["checks"]["VERIFIER-1.5"]["evaluation"]["outcome"] == ("FAIL" if forged else "PASS")


@pytest.mark.parametrize("forged", [False, True], ids=["generated-key-control", "identity-key-forgery"])
def test_frozen_artifact_seal_key_admission(tmp_path: Path, forged: bool) -> None:
    import verifier.artifact_control as seal_module
    from test_artifact_control import _sealed_file, _seal_path, _writable
    bundle, seal = _sealed_file(tmp_path)
    if forged:
        freeze_bytes = (bundle / "freeze.json").read_bytes()
        freeze = json.loads(freeze_bytes)
        key_id = "vstd-seal-key-1:sha256:" + hashlib.sha256(IDENTITY_KEY).hexdigest()
        seal["public_key_base64"] = b64(IDENTITY_KEY)
        seal["signature_base64"] = b64(IDENTITY_SIGNATURE)
        seal["seal_payload"] = seal_module._seal_payload(freeze, freeze_bytes, key_id)
        seal["seal_id"] = seal_module._identity("vstd-seal-1", seal_module._canonical_bytes(seal_module._seal_identity_projection(seal)))
        path = _seal_path(bundle)
        mode = path.stat().st_mode
        _writable(path)
        path.write_bytes(seal_module._canonical_bytes(seal))
        path.chmod(mode)
    result = seal_module.verify_frozen_artifact(bundle, expected_key_id=seal["seal_payload"]["key_id"])
    assert result.state == ("FAIL" if forged else "SEALED")


@pytest.mark.parametrize("forged", [False, True], ids=["generated-key-control", "identity-key-forgery"])
def test_network_head_key_admission(forged: bool) -> None:
    private = Ed25519PrivateKey.generate()
    raw = IDENTITY_KEY if forged else public_bytes(private)
    identifier = network.digest_bytes(raw)
    publisher = network.PublisherRecord("publisher:" + identifier, url64(raw), (identifier,), (), "Test", "Local fixture")
    head = network.SignedHead(publisher.publisher_id, 0, "sha256:" + "0" * 64, None, identifier,
                              "2026-09-28T00:00:00Z", url64(raw), url64(IDENTITY_SIGNATURE))
    if forged:
        with pytest.raises(network.NetworkError):
            network.verify_head(head, publisher)
    else:
        head = replace(head, signature_base64url=url64(private.sign(canonical_bytes(head.signing_dict()))))
        assert network.verify_head(head, publisher) is None


@pytest.mark.parametrize("forged", [False, True], ids=["generated-key-control", "identity-key-forgery"])
def test_network_directory_key_admission(forged: bool) -> None:
    private = Ed25519PrivateKey.generate()
    raw = IDENTITY_KEY if forged else public_bytes(private)
    snapshot = network.SignedDirectorySnapshot("publisher:" + network.digest_bytes(raw), 0, None, (),
        "2026-09-28T00:00:00Z", url64(raw), url64(IDENTITY_SIGNATURE))
    if forged:
        with pytest.raises(network.NetworkError):
            network.verify_directory_snapshot(snapshot)
    else:
        snapshot = replace(snapshot, signature_base64url=url64(private.sign(canonical_bytes(snapshot.signing_dict()))))
        assert network.verify_directory_snapshot(snapshot) is None


@pytest.mark.parametrize("bad_role", [None, "old", "new"], ids=["generated-keys-control", "old-key-forgery", "new-key-forgery"])
def test_network_continuity_key_admission(bad_role: str | None) -> None:
    old, new = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    old_raw = IDENTITY_KEY if bad_role == "old" else public_bytes(old)
    new_raw = IDENTITY_KEY if bad_role == "new" else public_bytes(new)
    record = network.KeyContinuityRecord("publisher:" + network.digest_bytes(old_raw), url64(old_raw),
        url64(new_raw), 1, None, url64(IDENTITY_SIGNATURE), url64(IDENTITY_SIGNATURE))
    message = canonical_bytes(record.signing_dict())
    record = replace(record, old_signature_base64url=url64(IDENTITY_SIGNATURE if bad_role == "old" else old.sign(message)),
                     new_signature_base64url=url64(IDENTITY_SIGNATURE if bad_role == "new" else new.sign(message)))
    if bad_role:
        with pytest.raises(network.NetworkError):
            network.verify_key_continuity(record, network.digest_bytes(old_raw))
    else:
        assert network.verify_key_continuity(record, network.digest_bytes(old_raw)) == network.digest_bytes(new_raw)


@pytest.mark.parametrize("surface", ["domain", "sim_checker", "consent", "polish"])
def test_shared_key_admission_source_invalidates_mechanism(surface: str, monkeypatch: Any) -> None:
    from verifier.domains import certification
    from verifier.domains.contracts import sim_checker
    from verifier.consent import public
    from verifier.runtime import polish
    function = {"domain": certification.implementation_digest, "sim_checker": sim_checker.mechanism_digest,
                "consent": public.mechanism_digest, "polish": polish.mechanism_digest}[surface]
    target = Path(actor.__file__).parents[1] / "core/signature_keys.py"
    original = Path.read_bytes
    before = function()
    def changed(path: Path) -> bytes:
        data = original(path)
        return data + b"\n# changed key admission\n" if path == target else data
    monkeypatch.setattr(Path, "read_bytes", changed)
    assert function() != before


def deny_backend_imports(monkeypatch: Any) -> None:
    monkeypatch.setitem(sys.modules, "cryptography", None)


@pytest.mark.parametrize("raw", [None, "00" * 32, b"", b"x" * 31, b"x" * 33,
    bytearray(b"x" * 32), memoryview(b"x" * 32)])
def test_key_screen_refuses_nonplain_or_wrong_length_input(raw: Any) -> None:
    from verifier.core.signature_keys import admit_ed25519_public_key
    with pytest.raises(ValueError):
        admit_ed25519_public_key(raw)


def test_key_screen_refuses_subclass_before_callbacks() -> None:
    from verifier.core.signature_keys import admit_ed25519_public_key
    class CandidateBytes(bytes):
        def __len__(self) -> int:
            raise AssertionError("candidate byte callback executed")
    with pytest.raises(ValueError):
        admit_ed25519_public_key(CandidateBytes(b"x" * 32))
