"""Zero-identity zero-knowledge token (TOKEN): retained token holding replay.

Ed25519 is the Edwards-curve digital signature algorithm with a 255-bit field.
A verified signature binds a token to an issuing key the checker admitted. It says
which key issued the token, never that anything the token names is authorized, and
a retained status is evidence about the instant it was published, not a later one.
Instants are integers on the one clock the artifact names and the stated skew is
measured on that clock; epochs, scopes and invocation bounds are dimensionless.
The genesis secret, the salt and the opening of the birth commitment are never
required: the commitment seeds the tenure fold and is not opened here.
"""
from __future__ import annotations

import base64
import re

from verifier.core.certificate import canonical_bytes
from .common import Budget, Refuted, Unavailable, digest, integer, need, obj, same, seq, text

_REFERENCE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_KEY_BYTES = re.compile(r"[0-9a-f]{64}\Z")
COMMON_FIELDS = frozenset({"kind", "token_id", "issuing_key_id", "issued_at", "algorithm",
                           "replay_id", "audience", "signature"})
KIND_FIELDS = {
    "birth": frozenset({"birth_epoch", "commitment"}),
    "aging": frozenset({"birth_token_id", "epoch_start", "epoch_end", "accumulated_epochs",
                        "accumulator_digest", "revocation_status"}),
    "lifetime": frozenset({"parent_grant_id", "delegate_key_id", "permitted_scopes", "not_before",
                           "not_after", "max_invocations", "soulbound", "confirmation_key_id",
                           "caveats"}),
}
STATUSES = ("ACTIVE", "SUSPENDED", "REVOKED")
SUPPORTED_ALGORITHMS = ("Ed25519",)


def _reference(value: object, what: str) -> str:
    if not isinstance(value, str) or not _REFERENCE.fullmatch(value):
        raise Refuted(what + " is not a digest reference")
    return value


def _names(value: object, budget: Budget, what: str, *, nonempty: bool = False) -> list:
    names = [text(name) for name in seq(value, budget, nonempty=nonempty)]
    if len(set(names)) != len(names):
        raise Refuted(what + " names one entry twice")
    return names


def _lease_shape(lease: dict, token_id: str, budget: Budget) -> None:
    text(lease["parent_grant_id"])
    _reference(lease["delegate_key_id"], "a delegate key identifier")
    _names(lease["permitted_scopes"], budget, "a lease scope set")
    start = integer(lease["not_before"])
    # No expiry is an unbounded window, which the inventory reports; an expiry at or
    # before the start is an empty one, which no instant can fall inside.
    if lease["not_after"] is not None and integer(lease["not_after"]) <= start:
        raise Refuted("a validity window ends at or before it starts: " + token_id)
    if lease["max_invocations"] is not None:
        integer(lease["max_invocations"], 1)
    if type(lease["soulbound"]) is not bool:
        raise Refuted("a soulbound declaration must be Boolean: " + token_id)
    if lease["confirmation_key_id"] is not None:
        _reference(lease["confirmation_key_id"], "a confirmation key identifier")
    conditions = set()
    for caveat in seq(lease["caveats"], budget, nonempty=False):
        entry = obj(caveat, {"condition", "discharge"})
        if text(entry["condition"]) in conditions:
            raise Refuted("a lease binds one caveat condition twice: " + token_id)
        conditions.add(entry["condition"])
        if entry["discharge"] is not None:
            text(entry["discharge"])


def _inventory(artifact: dict, inputs: dict, budget: Budget) -> tuple:
    """Parse the complete holding; return it by identifier, its birth token and its gaps.

    Gaps are returned rather than raised so that a contradiction later in the
    inventory is still refuted instead of being masked by an earlier absence.
    """
    tokens = seq(need(inputs, "tokens"), budget)
    same(digest(tokens), need(artifact, "tokens_digest"), "token inventory differs from its bound digest")
    held: dict = {}
    replays: dict = {}
    gaps: list = []
    # Every instant below is an integer on the clock the artifact names, and without
    # that name no two of them are comparable. Its absence is a gap like the others.
    if "clock" in artifact:
        text(artifact["clock"])
    else:
        gaps.append("required evidence absent: clock")
    for token in tokens:
        record = obj(token)
        kind = record.get("kind")
        if not isinstance(kind, str) or kind not in KIND_FIELDS:
            raise Refuted("a token is not exactly one of birth, aging or lifetime")
        obj(record, set(COMMON_FIELDS | KIND_FIELDS[kind]))
        token_id = text(record["token_id"])
        if token_id in held:
            raise Refuted("two tokens share one token identifier: " + token_id)
        replay_id = text(record["replay_id"])
        if replay_id in replays:
            # Which two collided is the finding, so both coordinates are named.
            raise Refuted(f"two issuances share a replay identifier: {replays[replay_id]} and {token_id}")
        replays[replay_id] = token_id
        if record["issuing_key_id"] is None:
            gaps.append("a token binds no issuing key, so it is unspecified rather than self-issued: " + token_id)
        else:
            _reference(record["issuing_key_id"], "an issuing key identifier")
        integer(record["issued_at"])
        text(record["algorithm"])
        text(record["signature"])
        _names(record["audience"], budget, "a token audience")
        if kind == "birth":
            integer(record["birth_epoch"])
            _reference(record["commitment"], "a birth commitment")
        elif kind == "aging":
            text(record["birth_token_id"])
            for field in ("epoch_start", "epoch_end", "accumulated_epochs"):
                integer(record[field])
            _reference(record["accumulator_digest"], "an accumulator digest")
            if record["revocation_status"] not in ("ACTIVE", "REVOKED"):
                raise Refuted("an aging token's revocation status is neither ACTIVE nor REVOKED: " + token_id)
        else:
            _lease_shape(record, token_id, budget)
        held[token_id] = record
    births = [record for record in held.values() if record["kind"] == "birth"]
    if len(births) != 1:
        gaps.append("the holding does not descend from exactly one birth token")
    return held, births[0] if len(births) == 1 else None, gaps


def _leases_of(held: dict) -> dict:
    return {token_id: record for token_id, record in held.items() if record["kind"] == "lifetime"}


def _tenure(artifact: dict, inputs: dict, budget: Budget, held: dict, birth: dict) -> dict:
    epochs = seq(need(inputs, "epochs"), budget)
    same(digest(epochs), need(artifact, "epochs_digest"), "retained epochs differ from their bound digest")
    # The fold is seeded by the birth commitment: A at the birth epoch is the
    # commitment itself, and each later epoch folds its predecessor, its own number
    # and the status recorded at it.
    first = birth["birth_epoch"] + 1
    accumulator = birth["commitment"]
    heads, active = {first - 1: accumulator}, {first - 1: 0}
    suspended, revoked_at = [], None
    for offset, step in enumerate(epochs):
        entry = obj(step, {"epoch", "status", "digest"})
        epoch, status = integer(entry["epoch"]), entry["status"]
        if epoch != first + offset:
            raise Refuted(f"the retained epochs are not contiguous from the birth epoch: "
                          f"expected {first + offset}, found {epoch}")
        if status not in STATUSES:
            raise Refuted(f"an epoch status is not ACTIVE, SUSPENDED or REVOKED: epoch {epoch}")
        # Revocation ends tenure from its epoch forward; suspension only halts accrual.
        if revoked_at is not None and status != "REVOKED":
            raise Refuted(f"tenure resumes after its revocation: epoch {epoch}")
        if status == "REVOKED" and revoked_at is None:
            revoked_at = epoch
        if status == "SUSPENDED":
            suspended.append(epoch)
        accumulator = digest([accumulator, epoch, status])
        same(entry["digest"], accumulator,
             f"a retained epoch digest is not the fold of the epoch before it: epoch {epoch}")
        heads[epoch] = accumulator
        active[epoch] = active[epoch - 1] + (1 if status == "ACTIVE" else 0)
    last = first + len(epochs) - 1
    gaps = []
    aging = [record for record in held.values() if record["kind"] == "aging"]
    budget.tick(len(held))
    for token in aging:
        token_id = token["token_id"]
        if token["birth_token_id"] != birth["token_id"]:
            raise Refuted("an aging token names a birth the holding does not descend from: " + token_id)
        start, end = token["epoch_start"], token["epoch_end"]
        if not first <= start <= end:
            raise Refuted("an aging token's interval is empty or does not follow its birth epoch: " + token_id)
        if end > last:
            gaps.append("an aging token spans epochs the retained trace does not reach: " + token_id)
            continue
        same(token["accumulator_digest"], heads[end],
             "an aging token's accumulator is not the refolded chain at its last epoch: " + token_id)
        if token["accumulated_epochs"] != active[end] - active[start - 1]:
            raise Refuted("an aging token's accrued tenure is not the count of active epochs it spans: " + token_id)
        if (token["revocation_status"] == "REVOKED") != (revoked_at is not None and revoked_at <= end):
            raise Refuted("an aging token misreports its revocation status: " + token_id)
    # A token descends from the birth token, so none can be issued, or valid, before it.
    for token_id, token in held.items():
        if token["issued_at"] < birth["issued_at"]:
            raise Refuted("a token was issued before the birth token it descends from: " + token_id)
        if token["kind"] == "lifetime" and token["not_before"] < birth["issued_at"]:
            raise Refuted("a lease is valid before the birth token it descends from was issued: " + token_id)
    if gaps:
        raise Unavailable(gaps[0])
    return {"birth_epoch": first - 1, "last_epoch": last, "head": accumulator,
            "active_epochs": active[last], "suspended_epochs": suspended, "revoked_at": revoked_at,
            "aging_tokens": len(aging)}


def _later(child: object, parent: object) -> bool:
    """Whether a child expiry reaches past its parent's, reading no expiry as unbounded."""
    if parent is None:
        return False
    return child is None or child > parent


def _leases(artifact: dict, budget: Budget, held: dict, birth: dict) -> dict:
    root = set(_names(need(artifact, "root_scopes"), budget, "the root scope set", nonempty=True))
    leases = _leases_of(held)
    if not leases:
        raise Unavailable("the holding retains no lease, so no delegation can be resolved")
    budget.tick(len(leases))
    for lease_id, lease in leases.items():
        parent_id = lease["parent_grant_id"]
        if parent_id != birth["token_id"] and parent_id not in leases:
            if parent_id in held:
                raise Refuted("a lease names an aging token as its parent grant: " + lease_id)
            raise Refuted("a lease's parent grant resolves to nothing in the inventory: " + lease_id)
    depths = {}
    for lease_id in leases:
        seen, current = set(), lease_id
        while current != birth["token_id"]:
            if current in seen:
                raise Refuted("a delegation path returns to a lease it already left: " + lease_id)
            seen.add(current)
            budget.tick()
            current = leases[current]["parent_grant_id"]
        depths[lease_id] = len(seen)
    for lease_id, lease in leases.items():
        parent = leases.get(lease["parent_grant_id"])
        grantor = birth if parent is None else parent
        if lease["issued_at"] < grantor["issued_at"]:
            raise Refuted("a lease was issued before its parent grant: " + lease_id)
        ceiling = root if parent is None else set(parent["permitted_scopes"])
        beyond = sorted(set(lease["permitted_scopes"]) - ceiling)
        if beyond:
            raise Refuted(f"a lease conveys a scope its parent grant lacks: {lease_id}: {beyond[0]}")
        if parent is None:
            continue
        if lease["not_before"] < parent["not_before"] or _later(lease["not_after"], parent["not_after"]):
            raise Refuted("a lease window reaches outside its parent grant's window: " + lease_id)
        if parent["max_invocations"] is not None and (
                lease["max_invocations"] is None or lease["max_invocations"] > parent["max_invocations"]):
            raise Refuted("a lease permits more invocations than its parent grant: " + lease_id)
        # A caveat is its condition together with what discharges it. Keeping the
        # condition under a different discharge replaces the parent's caveat, so only
        # removing the discharge -- a permanent restriction -- narrows it.
        own = {caveat["condition"]: caveat["discharge"] for caveat in lease["caveats"]}
        for caveat in parent["caveats"]:
            if caveat["condition"] not in own:
                raise Refuted("a delegation step drops a caveat its parent grant imposed: " + lease_id)
            if own[caveat["condition"]] not in (caveat["discharge"], None):
                raise Refuted("a delegation step rewrites how an inherited caveat is discharged: " + lease_id)
        if parent["soulbound"] and (not lease["soulbound"]
                                    or lease["delegate_key_id"] != parent["delegate_key_id"]):
            raise Refuted("a soulbound lease is re-delegated: " + lease_id)
    return {"leases": len(leases), "root_leases": sum(1 for d in depths.values() if d == 1),
            "delegation_depth": max(depths.values()),
            "soulbound": sorted(i for i, lease in leases.items() if lease["soulbound"]),
            "scopes_conveyed": sorted({s for lease in leases.values() for s in lease["permitted_scopes"]})}


def _signatures(artifact: dict, budget: Budget, held: dict, witness_keys: dict) -> dict:
    accepted = _names(need(artifact, "accepted_algorithms"), budget, "the accepted algorithm set", nonempty=True)
    if "none" in {name.lower() for name in accepted}:
        raise Refuted("an accepted algorithm set containing 'none' accepts unsigned tokens")
    # Algorithm confusion is a property of the accepted set, not of any token under it.
    symmetric = {name for name in accepted if name.upper().startswith(("HS", "AES"))}
    if symmetric and symmetric != set(accepted):
        raise Refuted("the accepted set admits both a symmetric and an asymmetric algorithm: "
                      + sorted(symmetric)[0])
    bound: dict = {}
    for key in seq(need(artifact, "issuing_keys"), budget):
        record = obj(key, {"key_id", "key_bytes"})
        if not isinstance(record["key_bytes"], str) or not _KEY_BYTES.fullmatch(record["key_bytes"]):
            raise Refuted("an issuing key does not carry 32 hex-encoded bytes")
        same(record["key_id"], digest(record["key_bytes"]), "a key identifier is not the digest of the key it names")
        if record["key_id"] in bound:
            raise Refuted("the bound key set lists one key twice")
        bound[record["key_id"]] = record["key_bytes"]
    retirements = obj(need(artifact, "key_retirements"))
    for key_id, instant in retirements.items():
        if key_id not in bound:
            raise Refuted("a key retirement names a key outside the bound set")
        integer(instant)
    budget.tick(len(held))
    for token_id, token in held.items():
        if token["algorithm"] not in accepted:
            raise Refuted("a token names an algorithm outside the accepted set: " + token_id)
        key_id = token["issuing_key_id"]
        if key_id not in bound:
            raise Refuted("a token names an issuing key outside the bound set: " + token_id)
        if key_id in retirements and token["issued_at"] >= retirements[key_id]:
            raise Refuted("a token was issued under its key at or after that key's retirement: " + token_id)
    # Admission is the checker's, by key bytes; nothing in the bundle can admit a key.
    admitted = set(witness_keys.values())
    gaps, verifiable = [], []
    for token_id, token in held.items():
        if token["algorithm"] not in SUPPORTED_ALGORITHMS:
            gaps.append("a token's algorithm has no verifier in this checker: " + token_id)
        elif bound[token["issuing_key_id"]] not in admitted:
            gaps.append("a token's issuing key is not admitted by the checker policy: " + token_id)
        else:
            verifiable.append(token)
    if verifiable:
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            from cryptography.exceptions import InvalidSignature
        except ImportError as exc:
            raise Unavailable("signature backend unavailable") from exc
        for token in verifiable:
            budget.tick()
            preimage = {field: value for field, value in token.items() if field != "signature"}
            try:
                Ed25519PublicKey.from_public_bytes(bytes.fromhex(bound[token["issuing_key_id"]])).verify(
                    base64.b64decode(token["signature"], validate=True), canonical_bytes(preimage))
            except (ValueError, TypeError, InvalidSignature) as exc:
                raise Refuted("a token signature does not verify over its canonical preimage: "
                              + token["token_id"]) from exc
    if gaps:
        raise Unavailable(gaps[0])
    used = {token["issuing_key_id"] for token in held.values()}
    return {"verified": len(verifiable), "keys": len(bound), "unused_keys": sorted(set(bound) - used),
            "unused_algorithms": sorted(set(accepted) - {token["algorithm"] for token in held.values()}),
            "retired_keys": sorted(retirements)}


def _closure(artifact: dict, inputs: dict, budget: Budget, held: dict) -> dict:
    audience = set(_names(need(artifact, "audience"), budget, "the bound audience set", nonempty=True))
    budget.tick(len(held))
    reaching = []
    for token_id, token in held.items():
        named = set(token["audience"])
        # A token resolves if it names a verifier in the set. One naming none is
        # addressed to every verifier, so it resolves and also reaches outside.
        if named and not named & audience:
            raise Refuted("a token is addressed wholly outside the bound audience set: " + token_id)
        if not named or named - audience:
            reaching.append(token_id)
    period = obj(need(artifact, "period"), {"start", "end"})
    start, end = integer(period["start"]), integer(period["end"])
    if end <= start:
        raise Refuted("the certificate period ends at or before it starts")
    clock = text(need(artifact, "clock"))
    skew = integer(need(artifact, "clock_skew"))
    observed_at = integer(need(artifact, "observed_at"))
    intervals, outside = [], []
    phases: dict = {"pending": [], "open": [], "ended": [], "undetermined": []}
    for lease_id, lease in _leases_of(held).items():
        low, high = lease["not_before"], lease["not_after"]
        if low >= end or (high is not None and high <= start):
            outside.append(lease_id)
        else:
            intervals.append([max(low, start), end if high is None else min(high, end)])
        # The issuing and verifying clocks differ by up to the skew, so a boundary
        # within the skew of the observation is undetermined, not resolved.
        if observed_at + skew < low:
            phases["pending"].append(lease_id)
        elif high is not None and observed_at - skew >= high:
            phases["ended"].append(lease_id)
        elif observed_at - skew >= low and (high is None or observed_at + skew < high):
            phases["open"].append(lease_id)
        else:
            phases["undetermined"].append(lease_id)
    coverage: list = []
    for low, high in sorted(intervals):
        if coverage and low <= coverage[-1][1]:
            coverage[-1][1] = max(coverage[-1][1], high)
        else:
            coverage.append([low, high])
    schedule = integer(need(artifact, "status_schedule"), 1)
    statuses = seq(need(inputs, "statuses"), budget)
    same(digest(statuses), need(artifact, "statuses_digest"), "retained statuses differ from their bound digest")
    latest: dict = {}
    published = set()
    for status in statuses:
        record = obj(status, {"token_id", "published_at", "verdict"})
        token_id = text(record["token_id"])
        if token_id not in held:
            raise Refuted("a status names a token outside the inventory: " + token_id)
        at = integer(record["published_at"])
        if (token_id, at) in published:
            raise Refuted("a token carries two statuses published at one instant: " + token_id)
        published.add((token_id, at))
        if at - skew > observed_at:
            raise Refuted("a status was published after it was observed: " + token_id)
        if record["verdict"] not in STATUSES:
            raise Refuted("a status verdict is not ACTIVE, SUSPENDED or REVOKED: " + token_id)
        if token_id not in latest or at > latest[token_id]["published_at"]:
            latest[token_id] = record
    gaps = []
    for token_id in held:
        if token_id not in latest:
            gaps.append("a token carries no status observation, so it is unobserved rather than clear: " + token_id)
        elif observed_at - latest[token_id]["published_at"] - skew > schedule:
            gaps.append("a token's latest status is older than the published schedule, so it is stale: " + token_id)
        elif observed_at - latest[token_id]["published_at"] + skew > schedule:
            gaps.append("a token's status age is within the clock skew of the schedule, so it is undetermined: "
                        + token_id)
    if gaps:
        raise Unavailable(gaps[0])
    return {"audience": len(audience), "reaching_outside": sorted(reaching), "clock": clock, "skew": skew,
            "period": [start, end], "coverage": coverage, "out_of_period": sorted(outside),
            **{phase: sorted(ids) for phase, ids in phases.items()},
            "statuses": len(statuses), "schedule": schedule,
            "revoked": sorted(i for i, record in latest.items() if record["verdict"] == "REVOKED"),
            "suspended": sorted(i for i, record in latest.items() if record["verdict"] == "SUSPENDED")}


def evaluate(check: str, artifact: dict, inputs: dict, budget: Budget, *, witness_keys: dict) -> dict:
    held, birth, gaps = _inventory(artifact, inputs, budget)
    if gaps:
        raise Unavailable(gaps[0])
    if check == "tenure":
        return _tenure(artifact, inputs, budget, held, birth)
    if check == "leases":
        return _leases(artifact, budget, held, birth)
    if check == "signatures":
        return _signatures(artifact, budget, held, witness_keys)
    if check == "closure":
        return _closure(artifact, inputs, budget, held)
    leases = _leases_of(held).values()
    return {"tokens": len(held), "clock": artifact["clock"],
            "kinds": {kind: sum(1 for record in held.values() if record["kind"] == kind) for kind in KIND_FIELDS},
            "unaddressed": sorted(i for i, record in held.items() if not record["audience"]),
            "unbounded_windows": sorted(lease["token_id"] for lease in leases if lease["not_after"] is None),
            "bearer": sorted(lease["token_id"] for lease in leases if lease["confirmation_key_id"] is None),
            "permanent_caveats": sorted(lease["token_id"] for lease in leases
                                        if any(caveat["discharge"] is None for caveat in lease["caveats"]))}
