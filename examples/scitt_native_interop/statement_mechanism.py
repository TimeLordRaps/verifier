"""Live Supply Chain Integrity, Transparency, and Trust (SCITT) native acceptance.

Secure Hash Algorithm 256-bit (SHA-256) binds exact bytes. JavaScript Object
Notation (JSON) observations retain one host-selected Go checker invocation.
Each mechanism identifier (ID) names a dimensionless computational predicate.
Edwards-curve Digital Signature Algorithm (EdDSA) is the fixed checker argument,
not a claim that this adapter independently establishes signature validity.
The dimensionless predicate is only that the pinned native statement checker
accepts the exact statement and key bytes. No payload truth, authority, runtime
qualification, geometry closure, or independence follows. Host approval is local,
reusable, and separately supplied; no expiry or revocation mechanism is provided.
Source-location and pre/post byte checks are not loaded-code attestation, an atomic
filesystem snapshot, or a hostile-process sandbox. Limits cover the direct child
and retained inputs/channels. Partial output directories remain after failures.
Replay requires a new explicit host invocation over retained inputs, never an
output-only verdict reader or a stored execution authorization.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import re
import tempfile
from typing import Any, Sequence

import native_runner as runner
import package_comparison as decoder
from verifier.core.evidence import (
    BoundProposition, EvidenceBounds, MechanismDecision, MechanismOutcome,
)


HERE = Path(__file__).absolute().parent
MECHANISM_ID = "scitt:go-statement-native-acceptance"
STATEMENT_PREDICATE = "scitt.go.statement-native-acceptance"
STATEMENT_PREDICATE_DESCRIPTION = (
    "The pinned native statement verifier accepts these exact statement and public-key bytes."
)
MAX_INPUT_BYTES = 128 * 1024
MAX_APPROVALS = 256
MAX_BINDING_BYTES = 16 * 1024
ARGUMENTS = ("--statement", "statement.cose", "--pubkey", "public-key.pem", "--alg", "EdDSA")


def _json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def _hash(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _coordinate(go_checker: Path, expected_go_sha256: str) -> dict[str, Any]:
    if type(expected_go_sha256) is not str or not re.fullmatch("[0-9a-f]{64}", expected_go_sha256):
        raise ValueError("host executable digest must be canonical")
    sources = {}
    for name, module in (("native_runner.py", runner), ("package_comparison.py", decoder)):
        if Path(module.__file__).absolute() != HERE / name:
            raise ValueError("shadowed checking source")
    for name in ("statement_mechanism.py", "native_runner.py", "package_comparison.py"):
        sources[name] = _hash(runner.read_regular(HERE / name, 2 * 1024 * 1024))
    actual = _hash(runner.read_regular(go_checker, 64 * 1024 * 1024))
    if actual != expected_go_sha256:
        raise ValueError("selected executable changed")
    return {"mechanism_id": MECHANISM_ID, "source_sha256": sources,
            "go_checker_sha256": actual, "predicate": STATEMENT_PREDICATE}


def mechanism_digest(go_checker: Path, expected_go_sha256: str) -> str:
    """Calculate the source/executable coordinate before constructing approvals."""
    return "sha256:" + _hash(_json(_coordinate(go_checker, expected_go_sha256)))


def _binding_bytes(binding: BoundProposition, digest: str) -> bytes:
    if type(binding) is not BoundProposition or type(binding.bounds) is not EvidenceBounds:
        raise ValueError("exact proposition and bounds types required")
    if (binding.expected is not True or type(binding.predicate) is not str
            or binding.predicate != STATEMENT_PREDICATE or type(binding.mechanism_id) is not str
            or binding.mechanism_id != MECHANISM_ID or type(binding.mechanism_digest) is not str
            or binding.mechanism_digest != digest):
        raise ValueError("native acceptance proposition mismatch")
    refs = binding.evidence_refs
    if (type(refs) is not tuple or len(refs) != 2 or refs[0] == refs[1]
            or any(type(ref) is not str or not re.fullmatch("sha256:[0-9a-f]{64}", ref) for ref in refs)
            or type(binding.subject_id) is not str or binding.subject_id != refs[0]):
        raise ValueError("subject and ordered statement/key references must be exact")
    if (type(binding.parameters) is not dict or binding.parameters != {
            "algorithm": "EdDSA", "statement_ref": refs[0], "public_key_ref": refs[1]}
            or any(type(key) is not str or type(value) is not str for key, value in binding.parameters.items())):
        raise ValueError("fixed statement/key roles and algorithm required")
    roots = binding.trust_roots
    if (type(roots) is not tuple or not 1 <= len(roots) <= 16
            or any(type(item) is not str or not 1 <= len(item) <= 256 for item in roots)
            or tuple(sorted(set(roots))) != roots):
        raise ValueError("bounded canonical host trust roots required")
    bounds = binding.bounds
    if (type(bounds.max_evidence_items) is not int or bounds.max_evidence_items != 2
            or type(bounds.max_evidence_bytes) is not int
            or not 0 <= bounds.max_evidence_bytes <= 2 * MAX_INPUT_BYTES):
        raise ValueError("bounded exact evidence ceilings required")
    result = _json(binding.to_dict())
    if len(result) > MAX_BINDING_BYTES:
        raise ValueError("proposition exceeds byte bound")
    return result


class GoStatementAcceptanceMechanism:
    """Host-owned exact approvals; no path or authority comes from artifacts."""

    mechanism_id = MECHANISM_ID

    def __init__(self, go_checker: Path, expected_go_sha256: str, *, output_root: Path,
                 approved_bindings: tuple[BoundProposition, ...] = ()) -> None:
        if type(approved_bindings) is not tuple or len(approved_bindings) > MAX_APPROVALS:
            raise ValueError("bounded explicit approval tuple required")
        self._go_checker = Path(go_checker).absolute()
        self._output_root = Path(output_root).absolute()
        runner._ordinary(self._output_root, directory=True)
        self._coordinate = _coordinate(self._go_checker, expected_go_sha256)
        self._coordinate_bytes = _json(self._coordinate)
        self.mechanism_digest = "sha256:" + _hash(self._coordinate_bytes)
        self._approved = frozenset(_binding_bytes(item, self.mechanism_digest) for item in approved_bindings)

    def _unchanged(self) -> None:
        if (self.mechanism_id != MECHANISM_ID
                or self.mechanism_digest != "sha256:" + _hash(self._coordinate_bytes)
                or _json(_coordinate(self._go_checker, self._coordinate["go_checker_sha256"])) != self._coordinate_bytes):
            raise ValueError("checking coordinate changed")
        runner._ordinary(self._output_root, directory=True)

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        """Check direct-call admission too; unsupported/operational results stay unknown."""
        observations: dict[str, Any] = {"native_invocation_attempted": False}
        try:
            approved = _binding_bytes(binding, self.mechanism_digest)
            if approved not in self._approved:
                raise ValueError("host approval missing")
            if type(evidence) not in (tuple, list) or len(evidence) != 2:
                raise ValueError("exact evidence pair required")
            if any(type(item) is not bytes or len(item) > MAX_INPUT_BYTES for item in evidence):
                raise ValueError("input byte type or bound mismatch")
            inputs = tuple(evidence)
            if sum(map(len, inputs)) > binding.bounds.max_evidence_bytes:
                raise ValueError("declared byte bound exceeded")
            if tuple("sha256:" + _hash(item) for item in inputs) != binding.evidence_refs:
                raise ValueError("evidence digest mismatch")
            self._unchanged()
        except (ValueError, TypeError, OSError, AttributeError):
            return MechanismDecision(MechanismOutcome.UNKNOWN, "Native invocation not admitted.", observations)

        try:
            directory = Path(tempfile.mkdtemp(prefix="statement-", dir=self._output_root))
            files = {"statement.cose": inputs[0], "public-key.pem": inputs[1]}
            for name, raw in files.items():
                runner._write_new(directory / name, raw)
            self._unchanged()
            if _binding_bytes(binding, self.mechanism_digest) != approved:
                raise ValueError("binding changed before invocation")
            self._check_files(directory, files)
            observations = {"native_invocation_attempted": True,
                "binding": json.loads(approved), "mechanism_coordinate": json.loads(self._coordinate_bytes),
                "command": {"executable_sha256": self._coordinate["go_checker_sha256"], "arguments": list(ARGUMENTS)},
                "input_base64": {name: base64.b64encode(raw).decode("ascii") for name, raw in files.items()},
                "direct_child_timeout_seconds": 20, "channel_byte_limit": 128 * 1024}
            code, reason, stdout, stderr = runner._run_process(
                "bound-statement", [str(self._go_checker), *ARGUMENTS], directory,
                timeout=20, output_limit=128 * 1024)
            if (code is not None and type(code) is not int
                    or reason not in (None, "TIMEOUT", "OUTPUT_LIMIT", "LAUNCH_ERROR")
                    or type(stdout) is not bytes or type(stderr) is not bytes
                    or len(stdout) > 128 * 1024 or len(stderr) > 128 * 1024):
                raise ValueError("unsupported process observation")
            files.update({"stdout.bin": stdout, "stderr.bin": stderr})
            for name in ("stdout.bin", "stderr.bin"):
                runner._write_new(directory / name, files[name])
            observations.update({"exit_code": code, "stop_reason": reason,
                "stdout_base64": base64.b64encode(stdout).decode("ascii"),
                "stderr_base64": base64.b64encode(stderr).decode("ascii"),
                "stdout_sha256": _hash(stdout), "stderr_sha256": _hash(stderr)})
            self._unchanged()
            if _binding_bytes(binding, self.mechanism_digest) != approved:
                raise ValueError("binding changed during invocation")
            self._check_files(directory, files)
            native = decoder.decode_output("go", "statement", stdout, stderr, code, reason)["outcome"]
            observations.update({"native_outcome": native, "pre_post_identity_unchanged": True})
            files["observation.json"] = _json(observations)
            runner._write_new(directory / "observation.json", files["observation.json"])
            self._check_files(directory, files)
            self._unchanged()
            if _binding_bytes(binding, self.mechanism_digest) != approved:
                raise ValueError("binding changed during observation retention")
            outcome = {"NATIVE_TRUE": MechanismOutcome.PASS, "NATIVE_FALSE": MechanismOutcome.FAIL}.get(native, MechanismOutcome.UNKNOWN)
            return MechanismDecision(outcome, "Bound native-acceptance observation: " + native, observations)
        except (ValueError, TypeError, OSError, AttributeError):
            observations["pre_post_identity_unchanged"] = False
            return MechanismDecision(MechanismOutcome.UNKNOWN,
                "Native observation unavailable or changed; partial outputs may remain.", observations)

    @staticmethod
    def _check_files(directory: Path, files: dict[str, bytes]) -> None:
        runner._ordinary(directory, directory=True)
        names = []
        for path in directory.iterdir():
            names.append(path.name)
            if len(names) > len(files):
                raise ValueError("unexpected retained file")
        if set(names) != set(files):
            raise ValueError("retained file inventory changed")
        for name, raw in files.items():
            if runner.read_regular(directory / name, len(raw)) != raw:
                raise ValueError("retained bytes changed")
