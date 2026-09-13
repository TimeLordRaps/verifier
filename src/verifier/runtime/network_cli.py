"""Experimental verification-artifact network command-line interface (CLI).

Terminology: Hypertext Transfer Protocol Secure (HTTPS); JavaScript Object
Notation (JSON); Verifier Standard (VSTD).
Commands operate on local inert bytes.  ``push`` emits a host-neutral request
unless its explicit authenticated transmission mode is selected. Neither mode
installs, imports, renders, executes, moderates, or publishes an artifact.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import stat
from typing import Any, Mapping

from verifier.interoperability.claim_garden import register_publisher, submit_candidate
from verifier.interoperability.network import (
    PUSH_REQUEST_SCHEMA,
    MAX_OBJECT_BYTES,
    ContentAddressedStore,
    NetworkError,
    PublisherRecord,
    SignedHead,
    SiloCommit,
    assess_composition,
    assess_silo,
    build_silo_assessment_receipt,
    canonical_bytes,
    clone_silo,
    diff_commits,
    export_silo,
    publisher_from_private_key,
    rebuild_silo,
    sign_head,
    verify_head,
)


MAX_NETWORK_JSON_BYTES = 16 * 1024 * 1024


def _read_regular_bytes(path: str | Path, maximum: int, label: str) -> bytes:
    source = Path(path)
    try:
        before = source.lstat()
        if not stat.S_ISREG(before.st_mode) or getattr(before, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
            raise NetworkError(f"{label} must be an ordinary non-link file")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        with os.fdopen(os.open(source, flags), "rb") as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise NetworkError(f"{label} changed during open")
            data = stream.read(maximum + 1)
    except OSError as exc:
        raise NetworkError(f"cannot read {label}") from exc
    if len(data) > maximum:
        raise NetworkError(f"{label} exceeds its byte bound")
    return data


def _read_json(path: str | Path) -> Mapping[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise NetworkError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(_read_regular_bytes(path, MAX_NETWORK_JSON_BYTES, "network JSON"), object_pairs_hook=unique,
                           parse_constant=lambda value: (_ for _ in ()).throw(NetworkError(f"non-finite JSON number: {value}")))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise NetworkError(f"cannot read bounded JSON object: {path}") from exc
    if not isinstance(value, Mapping):
        raise NetworkError("JSON input must be an object")
    return value


def _write_exclusive(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        with os.fdopen(os.open(path, flags, 0o600), "wb") as stream:
            stream.write(canonical_bytes(value))
    except OSError as exc:
        raise NetworkError(f"destination must be absent and writable: {path}") from exc


def _publisher_path(root: Path) -> Path:
    return root / "publisher.json"


def _current_head_path(root: Path) -> Path:
    return root / "current-head.json"


def _load_publisher(root: Path) -> PublisherRecord:
    publisher_path = _publisher_path(root)
    try:
        publisher_path.lstat()
    except FileNotFoundError:
        pass
    else:
        return PublisherRecord.from_dict(_read_json(publisher_path))
    manifest = _read_json(root / "export.json")
    if set(manifest) != {
        "schema_version", "publisher_digest", "commit_digest", "head_digest",
        "assessment_receipt_digest",
    }:
        raise NetworkError("portable manifest must have exactly its defined fields")
    return PublisherRecord.from_dict(
        ContentAddressedStore(root).read_record(
            "publishers", manifest["publisher_digest"]
        )
    )


def _load_commit(path: str | Path) -> SiloCommit:
    return SiloCommit.from_dict(_read_json(path))


def _load_head(path: str | Path) -> SignedHead:
    return SignedHead.from_dict(_read_json(path))


def add_network_parsers(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    network = subparsers.add_parser("network", help="Manage experimental complete publisher silos; retained artifacts never execute.")
    commands = network.add_subparsers(dest="network_command", required=True)

    initialize = commands.add_parser("init", help="Initialize a key-derived publisher silo.")
    initialize.add_argument("store")
    initialize.add_argument("--private-key", required=True)
    initialize.add_argument("--display-name", required=True)
    initialize.add_argument("--description", default="Experimental VSTD publisher silo.")

    object_parser = commands.add_parser("object", help="Manage exact content-addressed objects.")
    object_commands = object_parser.add_subparsers(dest="network_object_command", required=True)
    add = object_commands.add_parser("add", help="Retain exact local bytes without interpreting them.")
    add.add_argument("store")
    add.add_argument("source")
    add.add_argument("--media-type", required=True)
    add.add_argument("--artifact-kind", required=True)
    add.add_argument("--declared-schema-id", default="NOT_DECLARED")

    commit = commands.add_parser("commit", help="Store and sign one complete-snapshot commit manifest.")
    commit.add_argument("store")
    commit.add_argument("manifest")
    commit.add_argument("--private-key", required=True)
    commit.add_argument("--issued-at", required=True)

    inspect = commands.add_parser("inspect", help="Assess one complete silo without executing artifacts.")
    inspect.add_argument("store")
    inspect.add_argument("commit")
    inspect.add_argument("--head")

    diff = commands.add_parser("diff", help="Compare exact paths and digests; no semantic contradiction is inferred.")
    diff.add_argument("left")
    diff.add_argument("right")

    clone = commands.add_parser(
        "clone",
        help=(
            "Clone a native local export, bounded local transfer file, or bounded "
            "Hypertext Transfer Protocol Secure (HTTPS) transfer endpoint."
        ),
    )
    clone.add_argument("source")
    clone.add_argument("destination")

    compose = commands.add_parser("compose", help="Assess completeness and authority agency across silos.")
    compose.add_argument("--silo", action="append", nargs=2, required=True, metavar=("STORE", "COMMIT"))
    compose.add_argument("--composite-store")
    compose.add_argument("--composite-commit")

    export = commands.add_parser("export", help="Export a reconstructible silo to an absent directory.")
    export.add_argument("store")
    export.add_argument("commit")
    export.add_argument("head")
    export.add_argument("destination")

    rebuild = commands.add_parser("rebuild", help="Rebuild exact exported bytes at a new local root.")
    rebuild.add_argument("export_root")
    rebuild.add_argument("destination")

    register = commands.add_parser(
        "register",
        help="Enroll an exported publisher with Claim Garden and write its credential to an absent local file.",
    )
    register.add_argument("export_root")
    register.add_argument("--endpoint", required=True, help="Credential-free Claim Garden HTTPS origin.")
    register.add_argument("--private-key", required=True)
    register.add_argument("--issued-at", required=True)
    register.add_argument("--credential-output", required=True)
    register.add_argument(
        "--publisher-endpoint", action="append", default=[],
        help="Optional public silo endpoint to declare; repeat for multiple endpoints.",
    )

    push = commands.add_parser(
        "push",
        help="Emit an inert request by default; --transmit explicitly submits a candidate for human review.",
    )
    push.add_argument("export_root")
    push.add_argument("--endpoint", required=True)
    push.add_argument("--expected-head")
    push.add_argument("--genesis", action="store_true")
    push.add_argument("--credential-file")
    push.add_argument(
        "--transmit", action="store_true",
        help="Perform authenticated Claim Garden submission; requires --credential-file and exactly one lineage selector.",
    )



def handle_network_command(args: argparse.Namespace) -> int:
    command = args.network_command
    if command == "init":
        root = Path(args.store)
        if root.exists():
            raise NetworkError("network store root must be absent")
        publisher = publisher_from_private_key(args.private_key, args.display_name, args.description)
        store = ContentAddressedStore(root)
        store.initialize()
        try:
            _write_exclusive(_publisher_path(root), publisher.to_dict())
            publisher_digest = store.put_record("publishers", publisher.to_dict())
        except Exception:
            shutil.rmtree(root, ignore_errors=True)
            raise
        print(json.dumps({"result": "INITIALIZED", "publisher_id": publisher.publisher_id, "publisher_digest": publisher_digest}, indent=2, sort_keys=True))
        return 0

    if command == "object":
        if args.network_object_command != "add":
            raise NetworkError("unsupported object command")
        try:
            payload = _read_regular_bytes(args.source, MAX_OBJECT_BYTES, "source object")
        except OSError as exc:
            raise NetworkError("cannot read source object") from exc
        record = ContentAddressedStore(args.store).add_object(payload, args.media_type, args.artifact_kind, args.declared_schema_id)
        print(json.dumps(record.to_dict(), indent=2, sort_keys=True))
        return 0

    if command == "commit":
        root = Path(args.store)
        store = ContentAddressedStore(root)
        publisher = _load_publisher(root)
        commit = _load_commit(args.manifest)
        if commit.publisher_id != publisher.publisher_id:
            raise NetworkError("commit publisher does not match the initialized store")
        current = _current_head_path(root)
        previous = _load_head(current) if current.exists() else None
        if previous is not None:
            verify_head(previous, publisher)
            previous_digest = previous.canonical_digest()
            if store.read_record("heads", previous_digest) != previous.to_dict():
                raise NetworkError("current head is not its retained content-addressed head record")
        else:
            try:
                current.lstat()
            except FileNotFoundError:
                pass
            else:
                raise NetworkError("current head must be absent or an ordinary retained head")
        sequence = 0 if previous is None else previous.sequence + 1
        previous_digest = None if previous is None else previous.canonical_digest()
        head = sign_head(commit, args.private_key, sequence, previous_digest, args.issued_at)
        verify_head(head, publisher)
        assessment = assess_silo(commit, store)
        assessment_receipt = build_silo_assessment_receipt(commit, store)
        commit_digest = store.put_record("commits", commit.to_dict())
        head_digest = store.put_record("heads", head.to_dict())
        assessment_receipt_digest = store.put_record("assessments", assessment_receipt.to_dict())
        temporary = current.with_suffix(".tmp")
        try:
            temporary.lstat()
        except FileNotFoundError:
            pass
        else:
            raise NetworkError("temporary head path must be absent")
        _write_exclusive(temporary, head.to_dict())
        if previous is not None:
            if _load_head(current) != previous:
                temporary.unlink(missing_ok=True)
                raise NetworkError("current head changed during commit")
        else:
            try:
                current.lstat()
            except FileNotFoundError:
                pass
            else:
                temporary.unlink(missing_ok=True)
                raise NetworkError("current head appeared during commit")
        temporary.replace(current)
        print(json.dumps({"result": "COMMITTED", "commit_digest": commit_digest, "head_digest": head_digest, "assessment_receipt_digest": assessment_receipt_digest, "assessment": assessment.to_dict()}, indent=2, sort_keys=True))
        return 0

    if command == "inspect":
        root = Path(args.store)
        commit = _load_commit(args.commit)
        result: dict[str, Any] = {"commit_digest": commit.canonical_digest(), "assessment": assess_silo(commit, ContentAddressedStore(root)).to_dict()}
        if args.head:
            head = _load_head(args.head)
            verify_head(head, _load_publisher(root))
            if head.commit_digest != commit.canonical_digest():
                raise NetworkError("head does not select the inspected commit")
            result["head_digest"] = head.canonical_digest()
            result["head_signature"] = "VALID"
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0

    if command == "diff":
        print(json.dumps(diff_commits(_load_commit(args.left), _load_commit(args.right)), indent=2, sort_keys=True))
        return 0

    if command == "clone":
        print(json.dumps(clone_silo(args.source, args.destination), indent=2, sort_keys=True))
        return 0

    if command == "compose":
        if bool(args.composite_store) != bool(args.composite_commit):
            raise NetworkError("composition requires both --composite-store and --composite-commit, or neither")
        commits = []
        stores = []
        for store_text, commit_text in args.silo:
            stores.append(ContentAddressedStore(store_text))
            commits.append(_load_commit(commit_text))
        composite_store = ContentAddressedStore(args.composite_store) if args.composite_store else None
        composite_commit = _load_commit(args.composite_commit) if args.composite_commit else None
        print(json.dumps(assess_composition(commits, stores, composite_commit, composite_store), indent=2, sort_keys=True))
        return 0

    if command == "export":
        root = Path(args.store)
        print(json.dumps(export_silo(_load_commit(args.commit), _load_head(args.head), _load_publisher(root), ContentAddressedStore(root), args.destination), indent=2, sort_keys=True))
        return 0

    if command == "rebuild":
        print(json.dumps(rebuild_silo(args.export_root, args.destination), indent=2, sort_keys=True))
        return 0

    if command == "register":
        result = register_publisher(
            args.export_root,
            args.endpoint,
            args.private_key,
            args.issued_at,
            args.credential_output,
            endpoints=tuple(args.publisher_endpoint),
        )
        public_result = {
            key: result[key]
            for key in (
                "result", "publisher_id", "credential_path",
                "transport_performed", "publication",
            )
            if key in result
        }
        print(json.dumps(public_result, indent=2, sort_keys=True))
        return 0

    if command == "push":
        if args.transmit:
            if not args.credential_file:
                raise NetworkError("authenticated push requires --credential-file")
            if args.genesis == (args.expected_head is not None):
                raise NetworkError("authenticated push requires exactly one of --genesis or --expected-head")
            result = submit_candidate(
                args.export_root,
                args.endpoint,
                args.credential_file,
                expected_head_digest=args.expected_head,
                genesis=args.genesis,
            )
            public_result = {
                key: result[key]
                for key in (
                    "result", "state", "transaction_id", "publisher_id",
                    "commit_digest", "head_digest", "transport_performed",
                    "publication", "reason",
                )
                if key in result
            }
            print(json.dumps(public_result, indent=2, sort_keys=True))
            return 0 if result.get("result") == "SUBMITTED" else 2
        if args.credential_file:
            raise NetworkError("--credential-file requires explicit --transmit")
        if args.genesis:
            raise NetworkError("--genesis is only valid with explicit --transmit")
        manifest = _read_json(Path(args.export_root) / "export.json")
        request = {"schema_version": PUSH_REQUEST_SCHEMA, "endpoint": args.endpoint, "publisher_digest": manifest["publisher_digest"], "commit_digest": manifest["commit_digest"], "head_digest": manifest["head_digest"], "expected_head_digest": args.expected_head, "transport_performed": False, "claim_boundary": "This is a transport-neutral request description. No authentication, acceptance, publication, or network transmission occurred."}
        print(json.dumps(request, indent=2, sort_keys=True))
        return 0
    raise NetworkError("unsupported network command")


__all__ = ["add_network_parsers", "handle_network_command"]
