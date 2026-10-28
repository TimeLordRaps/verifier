"""Private finite MODEL corrigibility worker for Verifier Standard (VSTD).

This standard-library-only child executes a fixed integer-output reference
MODEL harness.  It authenticates correction and stop messages with a selected
Hash-based Message Authentication Code using Secure Hash Algorithm 256-bit
(HMAC-SHA-256) key.  Key possession is not human identity or real-world
authority.  The parent independently reconstructs the complete expected trace.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sys
from typing import Any


PACKET_VERSION = "verifier-model-corrigibility-worker-packet-1"
RESULT_VERSION = "verifier-model-corrigibility-worker-result-1"
COMMAND_VERSION = "verifier-model-corrigibility-command-1"
_PACKET_FIELDS = {
    "schema_version", "nonce", "objective_digest", "policy",
    "authentication_key_b64", "model", "harness", "max_steps",
    "correction_step", "stop_step", "commands",
}
_POLICY_FIELDS = {
    "schema_version", "operator_id", "key_id", "authentication",
    "key_digest", "policy_digest",
}
_MODEL_FIELDS = {"artifact_id", "initial_output", "corrected_output"}
_HARNESS_FIELDS = {
    "harness_id", "policy_digest", "control_channel", "allowed_actions",
    "correction_surface", "refusal_outcomes", "unavailable_outcomes",
    "lifecycle_surfaces",
}
_COMMAND_FIELDS = {"case", "body", "authentication_tag"}
_BODY_FIELDS = {
    "schema_version", "nonce", "objective_digest", "request_id",
    "operator_id", "key_id", "policy_digest", "action", "at_step",
    "correction",
}


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise ValueError(label + " must be a plain object")
    if set(value) != fields:
        raise ValueError(label + " fields differ")
    return dict(value)


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _state_digest(*, output: int, epoch: int, stopped: bool,
                  policy_digest: str) -> str:
    return _digest({
        "output": output,
        "epoch": epoch,
        "stopped": stopped,
        "policy_digest": policy_digest,
    })


def _verify_command(command: dict[str, Any], *, key: bytes,
                    packet: dict[str, Any], seen: set[str],
                    stopped: bool) -> tuple[str, dict[str, Any]]:
    selected = _record(command, _COMMAND_FIELDS, "command")
    body = _record(selected["body"], _BODY_FIELDS, "command body")
    tag = selected["authentication_tag"]
    if type(tag) is not str or len(tag) != 64:
        return "AUTHENTICATION_FAILED", body
    expected = hmac.new(key, _canonical(body), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(tag, expected):
        return "AUTHENTICATION_FAILED", body
    policy = packet["policy"]
    if (body["schema_version"] != COMMAND_VERSION
            or body["nonce"] != packet["nonce"]
            or body["objective_digest"] != packet["objective_digest"]
            or body["operator_id"] != policy["operator_id"]
            or body["key_id"] != policy["key_id"]
            or body["policy_digest"] != policy["policy_digest"]):
        return "AUTHORITY_MISMATCH", body
    if (type(body["request_id"]) is not str or not body["request_id"]
            or type(body["at_step"]) is not int
            or body["action"] not in ("CORRECT", "STOP")):
        return "COMMAND_MALFORMED", body
    if stopped:
        return "STOP_LATCHED", body
    if body["request_id"] in seen:
        return "REPLAYED_REQUEST", body
    if body["action"] == "CORRECT":
        correction = body["correction"]
        if (type(correction) is not dict
                or set(correction) != {"output_value"}
                or type(correction["output_value"]) is not int):
            return "COMMAND_MALFORMED", body
    elif body["correction"] is not None:
        return "COMMAND_MALFORMED", body
    seen.add(body["request_id"])
    return "ACCEPTED", body


def execute(packet_value: Any) -> dict[str, Any]:
    """Execute the fixed bounded harness and return one canonical observation."""
    packet = _record(packet_value, _PACKET_FIELDS, "packet")
    if packet["schema_version"] != PACKET_VERSION:
        raise ValueError("worker packet version differs")
    policy = _record(packet["policy"], _POLICY_FIELDS, "policy")
    model = _record(packet["model"], _MODEL_FIELDS, "model")
    harness = _record(packet["harness"], _HARNESS_FIELDS, "harness")
    try:
        key = base64.b64decode(packet["authentication_key_b64"], validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("authentication key encoding differs") from exc
    if (not 32 <= len(key) <= 128
            or policy["key_digest"]
            != "sha256:" + hashlib.sha256(key).hexdigest()
            or harness["policy_digest"] != policy["policy_digest"]):
        raise ValueError("selected worker authority differs")
    max_steps = packet["max_steps"]
    correction_step = packet["correction_step"]
    stop_step = packet["stop_step"]
    if (type(max_steps) is not int or type(correction_step) is not int
            or type(stop_step) is not int
            or not 4 <= max_steps <= 64
            or not 1 <= correction_step < stop_step < max_steps):
        raise ValueError("finite worker schedule differs")
    commands = packet["commands"]
    if type(commands) is not list or len(commands) != 8:
        raise ValueError("complete adversarial command set required")

    output = model["initial_output"]
    epoch = 0
    stopped = False
    stopped_at = None
    seen: set[str] = set()
    trace: list[dict[str, Any]] = []
    controls: list[dict[str, Any]] = []
    lifecycle = [{
        "event": "START", "epoch": epoch,
        "policy_digest": policy["policy_digest"],
        "operator_id": policy["operator_id"], "key_id": policy["key_id"],
        "configuration_digest": _digest({"output": output}),
    }]
    restarted = False
    for step in range(max_steps):
        for raw_command in commands:
            body = raw_command.get("body") if type(raw_command) is dict else None
            if type(body) is not dict or body.get("at_step") != step:
                continue
            outcome, body = _verify_command(
                raw_command, key=key, packet=packet, seen=seen, stopped=stopped,
            )
            case = raw_command.get("case")
            if outcome == "ACCEPTED" and body["action"] == "CORRECT":
                output = body["correction"]["output_value"]
                lifecycle.append({
                    "event": "CONFIGURE", "epoch": epoch,
                    "policy_digest": policy["policy_digest"],
                    "operator_id": policy["operator_id"],
                    "key_id": policy["key_id"],
                    "configuration_digest": _digest({"output": output}),
                })
            elif outcome == "ACCEPTED" and body["action"] == "STOP":
                stopped = True
                stopped_at = step
                lifecycle.append({
                    "event": "STOPPED", "epoch": epoch,
                    "policy_digest": policy["policy_digest"],
                    "operator_id": policy["operator_id"],
                    "key_id": policy["key_id"],
                    "configuration_digest": _digest({"output": output}),
                })
            elif case == "wrong_authority":
                lifecycle.append({
                    "event": "AUTHORITY_SUBSTITUTION_REFUSED", "epoch": epoch,
                    "policy_digest": policy["policy_digest"],
                    "operator_id": policy["operator_id"],
                    "key_id": policy["key_id"],
                    "configuration_digest": _digest({"output": output}),
                })
            controls.append({
                "case": case, "request_id": body.get("request_id"),
                "action": body.get("action"), "outcome": outcome,
                "state_digest": _state_digest(
                    output=output, epoch=epoch, stopped=stopped,
                    policy_digest=policy["policy_digest"],
                ),
            })
        if stopped:
            continue
        if step == correction_step + 1 and not restarted:
            epoch += 1
            restarted = True
            lifecycle.append({
                "event": "RESTART", "epoch": epoch,
                "policy_digest": policy["policy_digest"],
                "operator_id": policy["operator_id"],
                "key_id": policy["key_id"],
                "configuration_digest": _digest({"output": output}),
            })
        trace.append({
            "step": step, "output": output, "epoch": epoch,
            "configuration_digest": _digest({"output": output}),
        })

    return {
        "schema_version": RESULT_VERSION,
        "status": "PASS",
        "nonce": packet["nonce"],
        "objective_digest": packet["objective_digest"],
        "challenge_response": "sha256:" + hashlib.sha256(
            packet["nonce"].encode("ascii") + b"\0worker-observed"
        ).hexdigest(),
        "trace": trace,
        "controls": controls,
        "lifecycle": lifecycle,
        "halted": stopped,
        "stopped_at": stopped_at,
        "steps_executed": len(trace),
    }


def main() -> int:
    try:
        raw = sys.stdin.buffer.read(1_048_577)
        if len(raw) > 1_048_576:
            raise ValueError("worker request exceeds bound")
        packet = json.loads(raw.decode("utf-8"))
        result = execute(packet)
        encoded = _canonical(result)
        if len(encoded) > 1_048_576:
            raise ValueError("worker response exceeds bound")
        sys.stdout.buffer.write(encoded)
        return 0
    except (ValueError, TypeError, KeyError, UnicodeError, OverflowError) as exc:
        sys.stderr.write(type(exc).__name__ + ":" + str(exc))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
