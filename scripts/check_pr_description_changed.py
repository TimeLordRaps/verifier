#!/usr/bin/env python3
"""Check recorded pull request (PR) push descriptions without inferred push times.

JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256).
An opened event establishes an explicit baseline. A synchronize event compares
its normalized description with the recorded previous head's description. Later
edits cannot repair a failed push; revise the description before another push.

Records contain digests, never description text. Authenticated Actions run and
artifact provenance binds a recorded event observation, not independent platform
attestation, semantic truth, human acceptance, or authorization. Missing, expired,
ambiguous, repeated-head, or mismatched history is UNKNOWN and exits nonzero.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Callable
import zipfile

WORKFLOW = ".github/workflows/pr-description.yml"
BOOTSTRAP_BASE = "fc2a20c68d01920eda7e4e1bf14dfbcb334a7634"
OID = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"[0-9a-f]{64}")
FIELDS = {"schema", "repository", "number", "head", "base", "before", "action", "body_sha256", "run_id", "attempt"}
MAX_RECORD_BYTES = 8192


class Unknown(ValueError):
    """The available recorded evidence cannot establish the required comparison."""


class Missing(Unknown):
    """A complete bounded artifact listing contained no matching observation."""


def words_digest(body: str) -> str:
    return hashlib.sha256(json.dumps(body.split(), ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()


def shape(record: dict, repository: str, number: int, head: str) -> dict:
    if type(record) is not dict or set(record) != FIELDS or record.get("schema") != "pr-description-event-1":
        raise Unknown("malformed event record")
    if record["repository"] != repository or record["number"] != number or record["head"] != head:
        raise Unknown("event coordinate differs")
    if type(number) is not int or number <= 0 or not isinstance(head, str) or not OID.fullmatch(head):
        raise Unknown("invalid event coordinate")
    if any(type(record[key]) is not int or record[key] <= 0 for key in ("run_id", "attempt", "number")):
        raise Unknown("invalid run coordinate")
    if type(record["body_sha256"]) is not str or not DIGEST.fullmatch(record["body_sha256"]):
        raise Unknown("invalid description digest")
    if type(record["base"]) is not str or not OID.fullmatch(record["base"]):
        raise Unknown("invalid captured base")
    if record["action"] == "opened":
        if record["before"] is not None:
            raise Unknown("opened baseline cannot invent an earlier push")
    elif record["action"] == "synchronize":
        if type(record["before"]) is not str or not OID.fullmatch(record["before"]) or record["before"] == head:
            raise Unknown("synchronize event needs a distinct exact prior head")
    else:
        raise Unknown("only opened or synchronize events record push observations")
    return record


def event_record(event: dict, *, repository: str, run_id: int, attempt: int) -> dict:
    try:
        pull = event["pull_request"]
        number, head, action = event["number"], pull["head"]["sha"], event["action"]
        if event["repository"]["full_name"] != repository or pull["base"]["repo"]["full_name"] != repository or pull["number"] != number:
            raise Unknown("event repository or pull request differs")
        if action not in {"opened", "synchronize"}:
            raise Unknown("event is not a push observation")
        if action == "opened" and "before" in event:
            raise Unknown("opened event contains an unexpected prior head")
        before = None if action == "opened" else event["before"]
        if action == "synchronize" and event.get("after") != head:
            raise Unknown("synchronize after-head differs")
        body = pull.get("body") or ""
        if type(body) is not str or len(body.encode()) > 1024 * 1024:
            raise Unknown("description is not bounded text")
        return shape({"schema": "pr-description-event-1", "repository": repository, "number": number,
                      "head": head, "base": pull["base"]["sha"], "before": before, "action": action, "body_sha256": words_digest(body),
                      "run_id": run_id, "attempt": attempt}, repository, number, head)
    except (KeyError, TypeError) as error:
        raise Unknown("incomplete event payload") from error


def evaluate(event: dict, lookup: Callable[[str], dict], *, repository: str, run_id: int, attempt: int) -> tuple[str, dict | None]:
    try:
        action = event["action"]
        if action in {"opened", "synchronize"}:
            current = event_record(event, repository=repository, run_id=run_id, attempt=attempt)
            output = current
            try:
                earlier_current = lookup(current["head"])
            except (Missing, KeyError):
                earlier_current = None
            if earlier_current is not None:
                shape(earlier_current, repository, current["number"], current["head"])
                keys = FIELDS - {"run_id", "attempt"}
                if any(earlier_current[key] != current[key] for key in keys):
                    raise Unknown("repeated head has conflicting push observations")
        elif action in {"edited", "reopened", "ready_for_review"}:
            number, head = event["number"], event["pull_request"]["head"]["sha"]
            if (event["repository"]["full_name"] != repository or event["pull_request"]["number"] != number
                    or event["pull_request"]["base"]["repo"]["full_name"] != repository):
                raise Unknown("event repository differs")
            current = shape(lookup(head), repository, number, head)
            output = None
        else:
            raise Unknown("unsupported event")
        if current["action"] == "opened":
            return "BASELINE", output
        previous = shape(lookup(current["before"]), repository, current["number"], current["before"])
        # Reusing an earlier head cannot identify a unique push by commit alone.
        if previous["before"] == current["head"]:
            raise Unknown("repeated head makes the event chain ambiguous")
        return ("PASS" if previous["body_sha256"] != current["body_sha256"] else "FAIL"), output
    except (KeyError, TypeError) as error:
        raise Unknown("required event history is unavailable") from error


def validate_record(record: dict, artifact: dict, run: dict, workflow: dict, *, repository: str, number: int, head: str,
                    default_head: str | None = None) -> dict:
    shape(record, repository, number, head)
    try:
        name = f"pr-description-push-{number}-{head}"
        if artifact["name"] != name or artifact["expired"] is not False:
            raise Unknown("artifact name or lifetime differs")
        if (artifact["workflow_run"]["id"] != record["run_id"] or artifact["workflow_run"]["head_sha"] != head
                or run["id"] != record["run_id"] or run["run_attempt"] != record["attempt"]):
            raise Unknown("artifact run coordinate differs")
        if (run["event"] not in {"pull_request", "pull_request_target"} or run["head_sha"] != head
                or run["repository"]["full_name"] != repository
                or workflow["id"] != run["workflow_id"] or workflow["path"] != WORKFLOW):
            raise Unknown("recorded event lacks matching platform provenance")
        # Nested pull head/base are mutable current state, not historical run
        # coordinates. Only the stable top-level run head binds artifact bytes.
        pulls = [entry for entry in run["pull_requests"] if entry["number"] == number]
        if len(pulls) != 1:
            raise Unknown("run pull request association is unavailable")
        if run["event"] == "pull_request" and (record["base"] != BOOTSTRAP_BASE or default_head != BOOTSTRAP_BASE):
            raise Unknown("candidate-produced observation is outside the fixed bootstrap")
    except (KeyError, TypeError) as error:
        raise Unknown("incomplete platform provenance") from error
    return record


def unique(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise Unknown("duplicate record field")
        result[key] = value
    return result


def gh(path: str) -> bytes:
    try:
        process = subprocess.run(["gh", "api", path], capture_output=True, timeout=20)
    except (OSError, subprocess.SubprocessError) as error:
        raise Unknown("platform query unavailable") from error
    if process.returncode or len(process.stdout) > 2 * 1024 * 1024:
        raise Unknown("platform query failed or exceeded response bound")
    return process.stdout


def api(path: str) -> dict:
    try:
        return json.loads(gh(path), object_pairs_hook=unique)
    except (ValueError, UnicodeError) as error:
        raise Unknown("platform response is malformed") from error


def read_archive(raw: bytes) -> dict:
    if len(raw) > 65536:
        raise Unknown("record archive byte bound exceeded")
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries = archive.infolist()
            if len(entries) != 1 or entries[0].filename != "description-history.json" or entries[0].file_size > MAX_RECORD_BYTES:
                raise Unknown("record archive must contain one bounded named record")
            with archive.open(entries[0]) as source:
                payload = source.read(MAX_RECORD_BYTES + 1)
            if len(payload) > MAX_RECORD_BYTES:
                raise Unknown("actual record byte bound exceeded")
            return json.loads(payload, object_pairs_hook=unique)
    except (OSError, RuntimeError, zipfile.BadZipFile, ValueError, UnicodeError) as error:
        raise Unknown("record archive is unavailable or malformed") from error


class History:
    def __init__(self, repository: str, number: int):
        self.repository, self.number = repository, number
        self.cache: dict[str, dict | None] = {}

    def __call__(self, head: str) -> dict:
        if head in self.cache:
            if self.cache[head] is None:
                raise Missing("exact recorded push observation unavailable")
            return self.cache[head]
        name = f"pr-description-push-{self.number}-{head}"
        found = []
        for page in range(1, 11):
            response = api(f"repos/{self.repository}/actions/artifacts?name={name}&per_page=100&page={page}")
            artifacts = response.get("artifacts")
            if type(artifacts) is not list:
                raise Unknown("artifact inventory unavailable")
            for item in artifacts:
                if type(item) is not dict or item.get("name") != name:
                    raise Unknown("artifact query did not honor the exact name filter")
                producer = item.get("workflow_run", {}).get("id")
                if type(producer) is not int or producer <= 0:
                    raise Unknown("artifact producer identity unavailable")
                run = api(f"repos/{self.repository}/actions/runs/{producer}")
                workflow = api(f"repos/{self.repository}/actions/workflows/{run['workflow_id']}")
                workflow_path = workflow.get("path")
                event_name = run.get("event")
                run_repository = run.get("repository")
                if (type(workflow_path) is not str or not workflow_path
                        or type(event_name) is not str or not event_name
                        or type(run_repository) is not dict
                        or type(run_repository.get("full_name")) is not str
                        or not run_repository["full_name"]):
                    raise Unknown("producer eligibility metadata is unavailable")
                # Decide eligibility from platform metadata before opening a
                # candidate-controlled payload. Foreign producers cannot deny a
                # valid protected record merely by choosing the same name. An
                # incomplete producer remains unknown, never established foreign.
                if (workflow_path != WORKFLOW or event_name not in {"pull_request", "pull_request_target"}
                        or run_repository["full_name"] != self.repository):
                    continue
                default_head = None
                if run.get("event") == "pull_request":
                    current = api(f"repos/{self.repository}/commits?per_page=1")
                    if type(current) is not list or len(current) != 1:
                        raise Unknown("current default branch coordinate unavailable")
                    default_head = current[0].get("sha")
                    if type(default_head) is not str or not OID.fullmatch(default_head):
                        raise Unknown("current default branch identifier invalid")
                    if default_head != BOOTSTRAP_BASE:
                        continue
                record = read_archive(gh(f"repos/{self.repository}/actions/artifacts/{item['id']}/zip"))
                shape(record, self.repository, self.number, head)
                if record["run_id"] != producer:
                    raise Unknown("record producer differs from platform identity")
                run = api(f"repos/{self.repository}/actions/runs/{producer}/attempts/{record['attempt']}")
                found.append(validate_record(record, item, run, workflow, repository=self.repository,
                                             number=self.number, head=head, default_head=default_head))
            if len(artifacts) < 100:
                break
        else:
            raise Unknown("artifact inventory exceeds bounded history horizon")
        if not found:
            self.cache[head] = None
            raise Missing("exact recorded push observation unavailable")
        stable = [{key: value for key, value in record.items() if key not in {"run_id", "attempt"}} for record in found]
        if any(record != stable[0] for record in stable[1:]):
            raise Unknown("multiple different observations for one head")
        self.cache[head] = found[0]
        return found[0]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--event", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--attempt", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repository) or args.event.stat().st_size > 2 * 1024 * 1024:
            raise Unknown("invalid repository or oversized event")
        event = json.loads(args.event.read_bytes(), object_pairs_hook=unique)
        history = History(args.repository, event["number"])
        # Retain the immutable current observation even when prior evidence is
        # missing or the comparison fails. A later edit never writes this file.
        if event.get("action") in {"opened", "synchronize"}:
            record = event_record(event, repository=args.repository, run_id=args.run_id, attempt=args.attempt)
            try:
                history(record["head"])
            except Missing:
                args.output.write_text(json.dumps(record, sort_keys=True) + "\n", encoding="utf-8")
        status, _record = evaluate(event, history, repository=args.repository,
                                  run_id=args.run_id, attempt=args.attempt)
        print(f"[PR DESCRIPTION CHANGE] {status}: recorded event comparison; no semantic or acceptance claim")
        return int(status not in {"PASS", "BASELINE"})
    except (Unknown, OSError, ValueError, KeyError, TypeError):
        print("[PR DESCRIPTION CHANGE] UNKNOWN: exact unambiguous recorded event evidence is unavailable")
        return 1


if __name__ == "__main__":
    sys.exit(main())
