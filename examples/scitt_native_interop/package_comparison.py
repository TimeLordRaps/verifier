"""Supply Chain Integrity, Transparency, and Trust (SCITT) recorded comparison.

Concise Binary Object Representation (CBOR); CBOR Object Signing and Encryption (COSE).
Verifier Standard (VSTD) packages retain exact bytes; JavaScript Object Notation
(JSON) projections below compare recorded native outputs, not live execution.
Secure Hash Algorithm 256-bit (SHA-256) binds the complete package and decoder.
This example grants no numbered-profile result, runtime attestation, authority,
independent-operator status, or automatic catalog qualification.
"""

from __future__ import annotations

import argparse
import hashlib
from importlib.metadata import distribution
import json
from pathlib import Path
import re
from typing import Any

from verifier.core.receipt import strict_json_loads
from verifier.interoperability.catalog import (
    ComponentAvailability, ComponentKind, ComponentLifecycle,
    InteroperabilityComponentDescriptor, InteroperabilityComponentRegistry,
)
from verifier.interoperability.storage import (
    ImplementationBinding, PackageArtifact, PackageDependency, StoredComponentPackage,
    load_component_package, save_component_package,
)

from native_runner import (
    EXPECTED_SPECIMEN, PYTHON_DISTRIBUTION_PINS, PYTHON_SOURCE_PINS, build_corpus, read_regular,
)


HERE = Path(__file__).resolve().parent
FORMAT = "SCITT-RECORDED-COMPARISON-1"
UPSTREAM = "https://github.com/action-state-group/scitt-cose"
UPSTREAM_COMMIT = "1fd1cee84c298c0e95fb3273f64709b7face7821"
GO_SOURCES = {
    "main.go": "fcecb3ace6d17bf5a6391231dfde0019c68d4852842e5d8b14a47100b423886b",
    "go.mod": "35b3acb176b9a311f249916be7e6273229bdc7cd1582fc14c1836741c21220a6",
    "go.sum": "a60e2b7147f17b020134df30bf18a62d4587e2293f5731ac53692b3e64167071",
    "LICENSE": "f5e885d3558f4504606b880db279b3956301243ef566085f27c9f272ebf13dd6",
    "NOTICE": "30f38dc8b1b366db3760a1de92ec133b9f795c8152b54f25a9286aa12d03813c",
}
VSTD_NOTICE_PINS = {
    "LICENSE": "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4",
    "NOTICE": "4843948d0633de82e770f75bed6866e90adf20b0abb1e69fd82a38c98437147d",
}
COMPONENTS = {name: "component:scitt-cose-" + name for name in ("python", "go")}
LIMITATIONS = [
    "Recorded output reconstruction is not native reexecution or authenticated execution history.",
    "Source and executable coordinates do not attest build provenance or loaded dependencies.",
    "Two language implementations share upstream authorship; operator independence is NOT_ESTABLISHED.",
    "One fixed single-leaf specimen and key family do not establish general interoperability.",
    "Signature and inclusion observations do not establish issuer authority or payload computational truth.",
    "Upstream draft-status prose in retained raw output is not current standards-status evidence.",
    "NATIVE_FALSE records a false verification flag, not proof of cryptographic invalidity or a diagnosed failure cause.",
]


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def object_fields(value: Any, keys: set[str]) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        raise ValueError("record has missing or unexpected fields")
    return value


def registry() -> InteroperabilityComponentRegistry:
    return InteroperabilityComponentRegistry("example:scitt-native-comparison:1", tuple(
        InteroperabilityComponentDescriptor(
            component_id=COMPONENTS[name], label="scitt-cose " + name + " native checker",
            kind=ComponentKind.VERIFIER, lifecycle=ComponentLifecycle.EXPERIMENTAL,
            implementation_ref="scitt_cose.cli:main" if name == "python" else "scitt-cose-go-verify/main.go:main",
            accepted_schema_ids=(), planning_surface_schema_ids=("VSTD-2",),
            mechanism_ids=("scitt-cose:statement-signature", "scitt-cose:receipt-inclusion"),
            native_system="scitt-cose", native_versions=("0.2.2", UPSTREAM_COMMIT),
            native_inputs=("Retained signed statement or receipt, selected public key, exact receipt leaf bytes",),
            native_outputs=("Native structured signature or inclusion result",),
            native_result_vocabulary=("true", "false", "operational failure"),
            availability=ComponentAvailability.NOT_CHECKED,
            execution_prerequisites=("Separately selected and qualified host runtime; this package executes nothing",),
            claim_boundary="Recorded fixed-specimen observations only; no runtime qualification or independent operator claim.",
        ) for name in COMPONENTS
    ))


def build_package(capture_dir: Path, upstream_dir: Path) -> StoredComponentPackage:
    """Retain only explicit capture/source files; never import or execute their code."""
    artifacts = {name: read_regular(capture_dir / name, 1024 * 1024)
                 for name in ("corpus.json", "observations.json", "runtime.json")}
    corpus = strict_json_loads(artifacts["corpus.json"])
    observations = strict_json_loads(artifacts["observations.json"])
    runtime = strict_json_loads(artifacts["runtime.json"])
    names = {"inputs/" + name for name in EXPECTED_SPECIMEN}
    for case in corpus["cases"]:
        names.update(case[key] for key in ("input_path", "public_key_path", "leaf_path") if case[key] is not None)
    for item in observations["observations"]:
        names.update((item["stdout_path"], item["stderr_path"]))
    if len(names) > 100:
        raise ValueError("capture inventory exceeds the fixed example bound")
    for name in names:
        PackageArtifact(name, "application/octet-stream", b"")  # Validate before joining paths.
        if not name.startswith(("inputs/", "outputs/")):
            raise ValueError("capture path is outside the explicit input/output inventory")
        artifacts[name] = read_regular(capture_dir / name, 1024 * 1024)
    for name, expected in GO_SOURCES.items():
        source = upstream_dir / name
        if name not in ("LICENSE", "NOTICE") and (upstream_dir / "scitt-cose-go-verify").exists():
            source = upstream_dir / "scitt-cose-go-verify" / name
        content = read_regular(source, 1024 * 1024)
        if sha(content) != expected:
            raise ValueError("pinned upstream Go source/license differs")
        artifacts["sources/go/" + name] = content
    dist = distribution("scitt-cose")
    for name, expected in runtime["python_source_sha256"].items():
        if not re.fullmatch(r"scitt_cose/[A-Za-z_][A-Za-z_0-9]*\.py", name):
            raise ValueError("unsupported Python source path")
        content = read_regular(Path(dist.locate_file(name)), 1024 * 1024)
        if sha(content) != expected:
            raise ValueError("captured Python source differs from observed runtime source")
        artifacts["sources/python/" + name] = content
    for name in ("LICENSE", "NOTICE"):
        candidates = [item for item in dist.files or () if str(item).endswith("/licenses/" + name)]
        if len(candidates) != 1:
            raise ValueError("Python distribution license inventory is ambiguous")
        content = read_regular(Path(dist.locate_file(candidates[0])), 1024 * 1024)
        if sha(content) != GO_SOURCES[name]:
            raise ValueError("Python license differs from pinned upstream license")
        artifacts["sources/python/" + name] = content
    for name in ("native_runner.py", "package_comparison.py"):
        artifacts["runners/" + name] = read_regular(HERE / name, 1024 * 1024)
    for name, expected in VSTD_NOTICE_PINS.items():
        content = read_regular(HERE.parents[1] / name, 1024 * 1024)
        if sha(content) != expected:
            raise ValueError("runner license or notice differs from this decoder's fixed pins")
        artifacts["runners/" + name] = content
    package = StoredComponentPackage(
        package_id="example:scitt-native-comparison", package_version="1",
        publisher="Local example host (unsigned declaration)", license="Apache-2.0",
        description="Pinned upstream source and recorded fixed-specimen comparison; unresolved runtime dependencies.",
        registry=registry(),
        artifacts=tuple(PackageArtifact(name, "application/octet-stream", content) for name, content in artifacts.items()),
        implementations=tuple(ImplementationBinding(
            COMPONENTS[name], registry().get(COMPONENTS[name]).implementation_ref,
            tuple(path for path in artifacts if path.startswith("sources/" + name + "/")),
            ("runtime:" + name,),
        ) for name in COMPONENTS),
        dependencies=(
            PackageDependency("runtime:python", "Python, scitt-cose 0.2.2, cbor2 6.1.4, cryptography 50.0.0; loaded runtime not retained or attested", ("runtime.json",)),
            PackageDependency("runtime:go", "Go executable and linked dependencies not retained or attested; module declarations are not resolution", ("runtime.json", "sources/go/go.mod", "sources/go/go.sum")),
        ),
    )
    compare_package(package, expected_digest=package.canonical_digest())
    return package


def decode_output(implementation: str, facet: str, stdout: bytes, stderr: bytes, exit_code: Any, stop_reason: Any) -> dict[str, Any]:
    """Project only fixed native result fields; operational failures stay unknown."""
    unknown = {"outcome": "UNKNOWN", "inclusion": None}
    if stop_reason is not None or stderr or type(exit_code) is not int or exit_code not in (0, 1):
        return unknown
    try:
        raw = strict_json_loads(stdout)
        if type(raw) is not dict:
            return unknown
        if implementation == "python":
            object_fields(raw, {"draft_tracking", "statement", "receipt"})
            if type(raw["draft_tracking"]) is not str or raw["receipt" if facet == "statement" else "statement"] is not None:
                return unknown
            if facet == "statement":
                detail = object_fields(raw["statement"], {"signature_verified", "issuer", "subject", "content_type", "alg", "unverified", "payload_len"})
                flag = detail["signature_verified"]
                if any(detail[key] is not None and type(detail[key]) is not str for key in ("issuer", "subject", "content_type", "alg")):
                    return unknown
                if detail["payload_len"] is not None and (type(detail["payload_len"]) is not int or detail["payload_len"] < 0):
                    return unknown
                if flag is True and (detail["unverified"] is not None or detail["alg"] != "EdDSA"):
                    return unknown
                if flag is False and any(detail[key] is not None for key in ("issuer", "subject", "content_type", "alg", "payload_len")):
                    return unknown
            else:
                detail = object_fields(raw["receipt"], {"ok", "root", "tree_size", "leaf_index", "errors"})
                flag = detail["ok"]
                errors = detail["errors"]
                allowed_errors = [[]] if flag is True else [["receipt signature did not verify: signature verification FAILED (InvalidSignature)"], ["receipt rejected: the COSE_Sign1 message is not valid CBOR (CBORDecodeEOF)"]]
                if errors not in allowed_errors:
                    return unknown
        else:
            allowed = {"valid", "alg", "content_type", "kid", "iss", "sub", "string_claims", "error", "receipt"}
            if not {"valid", "alg", "content_type", "iss", "sub"} <= set(raw) or not set(raw) <= allowed:
                return unknown
            flag = raw["valid"]
            undecoded_statement = (facet == "statement" and raw == {
                "valid": False, "alg": "", "content_type": "", "iss": "", "sub": "",
                "error": "decode COSE_Sign1: unexpected EOF",
            } and type(flag) is bool)
            if (raw["alg"] != "EdDSA" and not undecoded_statement) or any(type(raw[key]) is not str for key in ("content_type", "iss", "sub")):
                return unknown
            if flag is True and "error" in raw:
                return unknown
            detail = raw if facet == "statement" else raw.get("receipt")
            if facet == "statement":
                if "receipt" in raw or (flag is False and raw.get("error") not in {"signature verification failed: verification error", "decode COSE_Sign1: unexpected EOF"}):
                    return unknown
            else:
                if type(detail) is not dict or not {"ok", "tree_size", "leaf_index"} <= set(detail) or not set(detail) <= {"ok", "root", "tree_size", "leaf_index", "error"} or detail["ok"] is not flag:
                    return unknown
                if flag is False and detail.get("error") not in {"receipt signature did not verify over reconstructed root: verification error", "decode receipt COSE_Sign1: unexpected EOF"}:
                    return unknown
                if flag is True and "error" in detail:
                    return unknown
        if type(flag) is not bool or exit_code != (0 if flag else 1):
            return unknown
        inclusion = None
        if facet == "receipt" and flag:
            inclusion = {key: detail[key] for key in ("root", "tree_size", "leaf_index")}
            if type(inclusion["root"]) is not str or not re.fullmatch(r"[0-9a-f]{64}", inclusion["root"]) or any(type(inclusion[key]) is not int or inclusion[key] < 0 for key in ("tree_size", "leaf_index")):
                return unknown
        return {"outcome": "NATIVE_TRUE" if flag else "NATIVE_FALSE", "inclusion": inclusion}
    except (ValueError, TypeError, KeyError):
        return unknown


def compare_package(package: StoredComponentPackage, *, expected_digest: str) -> dict[str, Any]:
    """Reconstruct recorded agreement; perform no native execution or installation."""
    package = StoredComponentPackage.from_dict(package.to_dict())
    if package.canonical_digest() != expected_digest:
        raise ValueError("expected complete package coordinate differs")
    artifacts = {item.path: item.content for item in package.artifacts}
    if package.registry.to_dict() != registry().to_dict():
        raise ValueError("component registry differs from this fixed comparison contract")
    for implementation in package.implementations:
        language = next((name for name in COMPONENTS if COMPONENTS[name] == implementation.component_id), None)
        expected_paths = {path for path in artifacts if path.startswith("sources/" + str(language) + "/")}
        if language is None or set(implementation.artifact_paths) != expected_paths or not expected_paths or implementation.dependency_ids != ("runtime:" + language,):
            raise ValueError("selected implementation source/dependency attribution differs")
    for name, expected in GO_SOURCES.items():
        if sha(artifacts["sources/go/" + name]) != expected:
            raise ValueError("upstream source or license pin differs")
    runtime = object_fields(strict_json_loads(artifacts["runtime.json"]), {
        "schema_version", "platform_system", "platform_machine", "python_version", "python_executable_sha256",
        "python_distributions", "python_source_sha256", "go_checker_sha256", "source_state_unchanged", "runner_sha256",
    })
    if runtime["schema_version"] != "SCITT-NATIVE-RUNTIME-1" or type(runtime["source_state_unchanged"]) is not bool:
        raise ValueError("unsupported runtime observation")
    if runtime["python_distributions"] != PYTHON_DISTRIBUTION_PINS or runtime["python_source_sha256"] != PYTHON_SOURCE_PINS:
        raise ValueError("recorded Python runtime differs from the pinned source/distribution inventory")
    for key in ("python_executable_sha256", "go_checker_sha256", "runner_sha256"):
        if type(runtime[key]) is not str or not re.fullmatch(r"[0-9a-f]{64}", runtime[key]):
            raise ValueError("runtime coordinate must be a canonical digest")
    for key in ("platform_system", "platform_machine", "python_version"):
        if type(runtime[key]) is not str or not runtime[key] or len(runtime[key]) > 256 or any(ord(char) < 32 for char in runtime[key]):
            raise ValueError("runtime observation must be bounded single-line text")
    for name, digest in runtime["python_source_sha256"].items():
        if sha(artifacts["sources/python/" + name]) != digest:
            raise ValueError("retained Python source differs from runtime observation")
    for name in ("LICENSE", "NOTICE"):
        if sha(artifacts["sources/python/" + name]) != GO_SOURCES[name]:
            raise ValueError("retained Python license differs from pinned upstream license")
    for name in ("native_runner.py", "package_comparison.py"):
        if artifacts["runners/" + name] != read_regular(HERE / name, 1024 * 1024):
            raise ValueError("retained runner/decoder differs from this reconstruction contract")
    for name, expected in VSTD_NOTICE_PINS.items():
        content = artifacts.get("runners/" + name)
        if content is None or sha(content) != expected:
            raise ValueError("retained runner license or notice is missing or differs from this decoder's fixed pins")
    if runtime["runner_sha256"] != sha(artifacts["runners/native_runner.py"]):
        raise ValueError("native runner coordinate differs")
    corpus, inputs = build_corpus({name: artifacts["inputs/" + name] for name in EXPECTED_SPECIMEN})
    if canonical(strict_json_loads(artifacts["corpus.json"])) != canonical(corpus) or any(artifacts[name] != content for name, content in inputs.items()):
        raise ValueError("corpus or generated input bytes differ from fixed fixture contract")
    observations = object_fields(strict_json_loads(artifacts["observations.json"]), {"schema_version", "observations"})
    if observations["schema_version"] != "SCITT-NATIVE-OBSERVATIONS-1" or type(observations["observations"]) is not list or len(observations["observations"]) != 24:
        raise ValueError("comparison requires all 24 exact observations")
    rows = []
    for index, case in enumerate(corpus["cases"]):
        results = {}
        for offset, implementation in enumerate(COMPONENTS):
            item = object_fields(observations["observations"][2 * index + offset], {"case_id", "implementation", "exit_code", "stop_reason", "stdout_path", "stderr_path", "stdout_sha256", "stderr_sha256"})
            if item["case_id"] != case["case_id"] or item["implementation"] != implementation:
                raise ValueError("observation identity/order differs from corpus")
            if item["stop_reason"] not in (None, "TIMEOUT", "OUTPUT_LIMIT", "LAUNCH_ERROR") or (item["exit_code"] is not None and type(item["exit_code"]) is not int):
                raise ValueError("malformed native process termination observation")
            channels = {}
            for channel in ("stdout", "stderr"):
                name = "outputs/" + case["case_id"] + "-" + implementation + "." + channel
                if item[channel + "_path"] != name:
                    raise ValueError("native output is attributed to another observation")
                channels[channel] = artifacts[name]
                if len(channels[channel]) > 128 * 1024 or sha(channels[channel]) != item[channel + "_sha256"]:
                    raise ValueError("retained native output is oversized or digest-mismatched")
            results[implementation] = decode_output(implementation, case["facet"], **channels, exit_code=item["exit_code"], stop_reason=item["stop_reason"])
            if not runtime["source_state_unchanged"]:
                results[implementation] = {"outcome": "UNKNOWN", "inclusion": None}
        known = all(item["outcome"] != "UNKNOWN" for item in results.values())
        agreement = "MATCHED" if results["python"] == results["go"] else "CONFLICTED"
        expected = "NATIVE_TRUE" if case["expected_accept"] else "NATIVE_FALSE"
        expected_inclusion = {"root": sha(b"\x00" + inputs[case["leaf_path"]]), "tree_size": 1, "leaf_index": 0} if case["facet"] == "receipt" and case["expected_accept"] else None
        expectation = all(item == {"outcome": expected, "inclusion": expected_inclusion} for item in results.values())
        rows.append({"case_id": case["case_id"], "facet": case["facet"], "input_sha256": sha(inputs[case["input_path"]]),
                     "results": results, "agreement": agreement if known else "NOT_ESTABLISHED",
                     "expectations": ("MATCHED" if expectation else "MISMATCHED") if known else "NOT_ESTABLISHED"})
    def aggregate(field: str, negative: str) -> str:
        values = {row[field] for row in rows}
        return negative if negative in values else "NOT_ESTABLISHED" if "NOT_ESTABLISHED" in values else "MATCHED"
    return {"schema_version": FORMAT, "package_digest": package.canonical_digest(),
            "corpus_sha256": sha(artifacts["corpus.json"]), "decoder_sha256": sha(artifacts["runners/package_comparison.py"]),
            "components": dict(COMPONENTS), "cases": rows, "agreement": aggregate("agreement", "CONFLICTED"),
            "expectations": aggregate("expectations", "MISMATCHED"), "recorded_observation_count": 24,
            "native_execution_performed": False, "native_qualification": "NOT_ESTABLISHED",
            "actor_independence": "NOT_ESTABLISHED", "runtime_observation": runtime, "limitations": list(LIMITATIONS)}


def reconstruct_sidecar(package: StoredComponentPackage, sidecar: dict[str, Any], *, expected_digest: str) -> dict[str, Any]:
    snapshot = canonical(sidecar)
    result = compare_package(package, expected_digest=expected_digest)
    if canonical(result) != snapshot:
        raise ValueError("comparison sidecar does not reconstruct exactly")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    export = commands.add_parser("export")
    export.add_argument("capture", type=Path)
    export.add_argument("upstream", type=Path)
    export.add_argument("package", type=Path)
    export.add_argument("sidecar", type=Path)
    replay = commands.add_parser("reconstruct")
    replay.add_argument("package", type=Path)
    replay.add_argument("sidecar", type=Path)
    replay.add_argument("--expected-package-sha256", required=True)
    args = parser.parse_args()
    if args.command == "export":
        if args.package.absolute() == args.sidecar.absolute() or args.package.exists() or args.sidecar.exists():
            raise ValueError("export destinations must both be absent")
        package = build_package(args.capture, args.upstream)
        report = compare_package(package, expected_digest=package.canonical_digest())
        save_component_package(package, args.package)
        with args.sidecar.open("xb") as output:
            output.write(canonical(report))
    else:
        package = load_component_package(args.package, expected_digest=args.expected_package_sha256)
        report = reconstruct_sidecar(package, strict_json_loads(read_regular(args.sidecar, 1024 * 1024)), expected_digest=args.expected_package_sha256)
    print(json.dumps({key: report[key] for key in ("package_digest", "agreement", "expectations", "native_execution_performed", "native_qualification")}, indent=2))
