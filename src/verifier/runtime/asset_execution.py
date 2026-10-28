"""Deterministic in-memory mechanism for the ASSET Tier-0 declaration fields.

The module checks one finite specimen of retained ASSET records. It covers the
twelve declaration fields of ASSET-0.1, ASSET-0.2 and ASSET-0.3: typed
quantities, claim versus backing identity, issuance and redemption authority,
an idempotent supply journal with atomic refusal, custody versus control,
encumbrance, and exact reconciliation diagnostics.

Scope and claim boundary. This module discharges no Verifier Standard (VSTD)
rung and establishes no ASSET conformance. The field statuses in
`FIELD_DECLARATIONS` are this module's own assessment of what its finite
mechanism establishes. They are not the central profile statuses and do not
override them. Real-world issuer authority, signature validity, custody,
holding completeness, redemption terms, application enforcement, supply
conservation and backing remain NOT_ESTABLISHED. Reconciliation here tests
arithmetic consistency against a supplied statement; it does not prove that
statement true.

Route correspondence. The source-owned ASSET-1.1, ASSET-2.1 and ASSET-3.1 routes are
replayed by the TOKEN checker against retained TOKEN subjects, not against this specimen.
`catalog()` therefore lists every declaration field with its tier route as
AUXILIARY_FIELD_MECHANISM with carried_by_route False. `evaluate()` reports in-model
reproduction per route; the route status stays NOT_ESTABLISHED. `check_observations`
accepts an observation only when it strictly equals a fresh evaluation and its route
reproduces in-model. Catalog presence is never PASS.

Implementation constraints. Pure standard-library Python that spawns no
process, opens no connection, and reads no file except this module's own bytes
to bind the report to its source digest. Digests are Secure Hash Algorithm
256-bit (SHA-256) over JavaScript Object Notation (JSON) with sorted keys.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass
from enum import Enum
import hashlib
import json
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


ADAPTER = "verifier-asset-tier0-execution-1"
SCHEMA = "verifier-asset-tier0-report-1"
MAX_QUANTITY = 2**63 - 1
CLAIM_PREFIX = "claim:"
BACKING_PREFIX = "backing:"
INSTRUMENT_PREFIX = "instrument:"
RIGHTS_CLASSES = ("RECORD_CLAIM",)
GRANT_ACTIONS = ("ISSUE", "REDEEM")
OPERATION_KINDS = ("ISSUE", "REDEEM", "TRANSFER", "ENCUMBER", "RELEASE")

MECHANIZED = "MECHANIZED"
PARTIAL = "PARTIAL"
BOUNDARY_EXCLUDED = "BOUNDARY_EXCLUDED"
MISSING = "MISSING"
FIELD_STATUSES = (MECHANIZED, PARTIAL, BOUNDARY_EXCLUDED, MISSING)

CLAIM_BOUNDARY = {
    "issuer_authority": "NOT_ESTABLISHED",
    "signature_validity": "NOT_ESTABLISHED",
    "real_custody": "NOT_ESTABLISHED",
    "holding_completeness": "NOT_ESTABLISHED",
    "redemption": "NOT_ESTABLISHED",
    "application_enforcement": "NOT_ESTABLISHED",
    "supply_conservation": "NOT_ESTABLISHED",
    "backing": "NOT_ESTABLISHED",
}


class Unit(str, Enum):
    """Closed unit vocabulary; claims count instruments, backing counts atoms."""

    INSTRUMENT = "instrument"
    BACKING_ATOM = "backing_atom"


class AssetRefusal(Exception):
    """A refused operation or invalid record, identified by a stable code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class BatchRefused(AssetRefusal):
    """An atomic batch refused at one operation index; no operation applied."""

    def __init__(self, index: int, cause: AssetRefusal) -> None:
        super().__init__("BATCH_REFUSED", f"operation {index} refused as {cause.code}")
        self.index = index
        self.cause_code = cause.code


@dataclass(frozen=True)
class FieldDeclaration:
    status: str
    reason: str


FIELD_DECLARATIONS: dict[str, dict[str, FieldDeclaration]] = {
    "ASSET-0.1-identity-and-quantity": {
        "identity": FieldDeclaration(PARTIAL,
            "Instrument and backing identifiers are typed, separate namespaces and refuse conflation "
            "inside the specimen. That the referenced real-world instrument or backing item exists and "
            "is the named one lies outside the retained records."),
        "rights": FieldDeclaration(PARTIAL,
            "The represented right is a closed-vocabulary class checked for membership only. Its legal "
            "content and enforceability are not established."),
        "units": FieldDeclaration(MECHANIZED,
            "Every quantity carries a closed-enumeration unit. Unit mismatch, unit-less values and "
            "cross-unit arithmetic are refused; backing is recorded only in backing atoms."),
        "precision": FieldDeclaration(MECHANIZED,
            "Quantities are exact nonnegative integers of the declared unit, bounded by MAX_QUANTITY. "
            "Booleans, floats, strings, negatives and overflow are refused before arithmetic; no fractional precision exists."),
    },
    "ASSET-0.2-issuance-and-redemption": {
        "issuance_authority": FieldDeclaration(BOUNDARY_EXCLUDED,
            "An issuance must cite a registered, unrevoked, in-scope grant whose principal is the actor; "
            "missing, forged, out-of-scope and over-budget grants are refused. Legal issuer authority and "
            "whether this registry is the real authority are outside the specimen."),
        "supply_changes": FieldDeclaration(PARTIAL,
            "Issuance and redemption update a conserved in-memory journal with idempotent operation "
            "identifiers and no partial mutation on refusal. Whether the journal matches real supply changes is not observed."),
        "redemption": FieldDeclaration(BOUNDARY_EXCLUDED,
            "Redemption is refused when unauthorized, encumbered or underfunded and debits supply only on "
            "success. Redemption terms, settlement and any promise of delivery are not modeled."),
        "backing_claims": FieldDeclaration(BOUNDARY_EXCLUDED,
            "Recorded backing quantities are compared arithmetically with outstanding claims and with the "
            "supplied statement. Backing existence, custody, availability and sufficiency in the world are not established."),
    },
    "ASSET-0.3-custody-and-encumbrance": {
        "custody": FieldDeclaration(BOUNDARY_EXCLUDED,
            "Each account records a custodian identifier as data only. Physical or legal custody, possession and access lie outside the retained records."),
        "control": FieldDeclaration(PARTIAL,
            "Only the recorded controller may transfer, encumber, release or redeem; a custodian without control is refused. "
            "Operational control such as keys or access channels is not observed."),
        "encumbrances": FieldDeclaration(MECHANIZED,
            "Within the retained holdings, each encumbrance is recorded per account under a unique identifier. "
            "Available quantity is balance minus active encumbrances and gates transfer and redemption; release requires an active identifier. "
            "Encumbrances held outside the retained records are not observed."),
        "reconciliation": FieldDeclaration(MECHANIZED,
            "Exact reconciliation compares issued-minus-redeemed totals, per-account holdings and backing "
            "requirements with a supplied statement. Stale, malformed and mismatched inputs are reported as "
            "UNKNOWN or exact diagnostics. The procedure is fully mechanized; the statement's own truth is outside it."),
    },
}


def _digest(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                         allow_nan=False, default=repr).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def source_digest() -> str:
    """Bind the report to this module's exact current bytes."""
    return "sha256:" + hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def _check_quantity(value: object, unit: str, expected_unit: str) -> int:
    if type(value) is not int:
        raise AssetRefusal("QUANTITY_TYPE", f"quantity must be an integer, not {type(value).__name__}")
    if value < 0:
        raise AssetRefusal("QUANTITY_NEGATIVE", "quantity must be nonnegative")
    if value > MAX_QUANTITY:
        raise AssetRefusal("QUANTITY_OVERFLOW", "quantity exceeds MAX_QUANTITY")
    if unit != expected_unit:
        raise AssetRefusal("UNIT_MISMATCH", f"unit {unit!r} does not match {expected_unit!r}")
    return value


def _checked_add(left: int, right: int) -> int:
    total = left + right
    if total > MAX_QUANTITY:
        raise AssetRefusal("QUANTITY_OVERFLOW", "sum exceeds MAX_QUANTITY")
    return total


@dataclass(frozen=True)
class Quantity:
    value: int
    unit: Unit

    def __post_init__(self) -> None:
        if not isinstance(self.unit, Unit):
            raise AssetRefusal("UNIT_UNKNOWN", "unit must be a declared Unit")
        _check_quantity(self.value, self.unit.value, self.unit.value)


@dataclass(frozen=True)
class ClaimRecord:
    claim_id: str
    instrument_id: str
    backing_id: str
    rights_class: str
    backing_atoms_per_unit: int
    unit: Unit = Unit.INSTRUMENT

    def __post_init__(self) -> None:
        if not self.claim_id.startswith(CLAIM_PREFIX):
            raise AssetRefusal("IDENTITY_NAMESPACE", "claim identifier must use the claim namespace")
        if not self.instrument_id.startswith(INSTRUMENT_PREFIX):
            raise AssetRefusal("IDENTITY_NAMESPACE", "instrument identifier must use the instrument namespace")
        if not self.backing_id.startswith(BACKING_PREFIX):
            raise AssetRefusal("IDENTITY_NAMESPACE", "backing identifier must use the backing namespace")
        if len({self.claim_id, self.instrument_id, self.backing_id}) != 3:
            raise AssetRefusal("IDENTITY_CONFLATION", "claim, instrument and backing identifiers must differ")
        if self.rights_class not in RIGHTS_CLASSES:
            raise AssetRefusal("RIGHTS_UNKNOWN", f"rights class {self.rights_class!r} is not admitted")
        if self.unit is not Unit.INSTRUMENT:
            raise AssetRefusal("UNIT_MISMATCH", "claims are counted in instrument units")
        _check_quantity(self.backing_atoms_per_unit, Unit.BACKING_ATOM.value, Unit.BACKING_ATOM.value)
        if self.backing_atoms_per_unit < 1:
            raise AssetRefusal("RATE_INVALID", "backing atoms per unit must be at least one")

    def payload(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id, "instrument_id": self.instrument_id,
            "backing_id": self.backing_id, "rights_class": self.rights_class,
            "backing_atoms_per_unit": self.backing_atoms_per_unit, "unit": self.unit.value,
        }


@dataclass(frozen=True)
class AuthorityGrant:
    grant_id: str
    principal: str
    action: str
    claim_id: str
    limit: int
    revoked: bool = False

    def __post_init__(self) -> None:
        if self.action not in GRANT_ACTIONS:
            raise AssetRefusal("AUTHORITY_ACTION", f"grant action {self.action!r} is not admitted")
        _check_quantity(self.limit, Unit.INSTRUMENT.value, Unit.INSTRUMENT.value)

    def payload(self) -> dict[str, Any]:
        return {
            "grant_id": self.grant_id, "principal": self.principal, "action": self.action,
            "claim_id": self.claim_id, "limit": self.limit, "revoked": self.revoked,
        }

    def digest(self) -> str:
        return _digest(self.payload())


@dataclass(frozen=True)
class Operation:
    kind: str
    operation_id: str
    actor: str
    claim_id: str
    holder_id: str
    quantity: object = 0
    unit: str = Unit.INSTRUMENT.value
    grant_id: str | None = None
    grant_digest: str | None = None
    counterparty_id: str | None = None
    encumbrance_id: str | None = None

    def payload(self) -> dict[str, Any]:
        return {
            "kind": self.kind, "operation_id": self.operation_id, "actor": self.actor,
            "claim_id": self.claim_id, "holder_id": self.holder_id, "quantity": self.quantity,
            "unit": self.unit, "grant_id": self.grant_id, "grant_digest": self.grant_digest,
            "counterparty_id": self.counterparty_id, "encumbrance_id": self.encumbrance_id,
        }


@dataclass
class Account:
    custodian_id: str
    controller_id: str
    balance: int = 0
    encumbrances: dict[str, int] | None = None

    def __post_init__(self) -> None:
        if self.encumbrances is None:
            self.encumbrances = {}


@dataclass
class _State:
    claims: dict[str, ClaimRecord]
    grants: dict[str, AuthorityGrant]
    backing_claims: dict[str, Quantity]
    accounts: dict[str, dict[str, Account]]
    consumed: dict[str, int]
    issued: dict[str, int]
    redeemed: dict[str, int]
    journal: list[dict[str, Any]]
    operations: dict[str, tuple[str, dict[str, Any]]]


def _state_payload(state: _State) -> dict[str, Any]:
    return {
        "claims": {key: value.payload() for key, value in state.claims.items()},
        "grants": {key: value.payload() for key, value in state.grants.items()},
        "backing_claims": {
            key: {"value": value.value, "unit": value.unit.value}
            for key, value in state.backing_claims.items()
        },
        "accounts": {
            claim: {
                holder: {
                    "custodian_id": account.custodian_id, "controller_id": account.controller_id,
                    "balance": account.balance, "encumbrances": dict(account.encumbrances or {}),
                }
                for holder, account in sorted(accounts.items())
            }
            for claim, accounts in sorted(state.accounts.items())
        },
        "consumed": dict(sorted(state.consumed.items())),
        "issued": dict(sorted(state.issued.items())),
        "redeemed": dict(sorted(state.redeemed.items())),
        "journal": state.journal,
        "operations": {key: value[0] for key, value in sorted(state.operations.items())},
    }


def _account(state: _State, claim_id: str, holder_id: str) -> Account:
    accounts = state.accounts.get(claim_id)
    if accounts is None or holder_id not in accounts:
        raise AssetRefusal("ACCOUNT_UNKNOWN", f"no account for {claim_id!r} and {holder_id!r}")
    return accounts[holder_id]


def _authorize(state: _State, op: Operation, action: str) -> AuthorityGrant:
    if not op.grant_id:
        raise AssetRefusal("AUTHORITY_MISSING", "operation cites no grant")
    grant = state.grants.get(op.grant_id)
    if grant is None:
        raise AssetRefusal("AUTHORITY_MISSING", f"grant {op.grant_id!r} is not registered")
    if op.grant_digest != grant.digest():
        raise AssetRefusal("AUTHORITY_FORGED", "cited grant digest does not match the registry")
    if grant.revoked:
        raise AssetRefusal("AUTHORITY_REVOKED", f"grant {op.grant_id!r} is revoked")
    if grant.action != action:
        raise AssetRefusal("AUTHORITY_ACTION", f"grant {op.grant_id!r} does not admit {action}")
    if grant.claim_id != op.claim_id:
        raise AssetRefusal("AUTHORITY_SCOPE", "grant is scoped to a different claim")
    if grant.principal != op.actor:
        raise AssetRefusal("AUTHORITY_ACTOR_MISMATCH", "actor is not the grant principal")
    return grant


def _require_controller(account: Account, actor: str) -> None:
    if account.controller_id != actor:
        raise AssetRefusal("CONTROL_REQUIRED", "only the recorded controller may direct this operation")


def _available(account: Account, quantity: int) -> None:
    encumbered = sum((account.encumbrances or {}).values())
    if quantity > account.balance - encumbered:
        code = "ENCUMBERED_QUANTITY" if encumbered else "INSUFFICIENT_BALANCE"
        raise AssetRefusal(code, f"quantity {quantity} exceeds available {account.balance - encumbered}")


def _apply(state: _State, op: Operation) -> dict[str, Any]:
    if not isinstance(op, Operation):
        raise AssetRefusal("OPERATION_TYPE", "operation must be an Operation record")
    if op.kind not in OPERATION_KINDS:
        raise AssetRefusal("OPERATION_KIND", f"operation kind {op.kind!r} is not admitted")
    if not isinstance(op.operation_id, str) or not op.operation_id:
        raise AssetRefusal("OPERATION_ID_INVALID", "operation identifier must be a non-empty string")
    digest = _digest(op.payload())
    recorded = state.operations.get(op.operation_id)
    if recorded is not None:
        if recorded[0] != digest:
            raise AssetRefusal("OPERATION_ID_CONFLICT", "identifier was recorded with a different payload")
        return {**recorded[1], "status": "REPLAYED"}
    claim = state.claims.get(op.claim_id)
    if claim is None:
        raise AssetRefusal("CLAIM_UNKNOWN", f"claim {op.claim_id!r} is not registered")
    quantity = 0
    if op.kind != "RELEASE":
        quantity = _check_quantity(op.quantity, op.unit, claim.unit.value)
    account = _account(state, op.claim_id, op.holder_id)
    journal_quantity: Any = quantity
    counterparty = None

    if op.kind == "ISSUE":
        grant = _authorize(state, op, "ISSUE")
        new_issued = _checked_add(state.issued.get(op.claim_id, 0), quantity)
        new_balance = _checked_add(account.balance, quantity)
        new_consumed = _checked_add(state.consumed.get(grant.grant_id, 0), quantity)
        if new_consumed > grant.limit:
            raise AssetRefusal("AUTHORITY_BUDGET", "issuance exceeds the grant limit")
        state.issued[op.claim_id] = new_issued
        state.consumed[grant.grant_id] = new_consumed
        account.balance = new_balance
    elif op.kind == "REDEEM":
        grant = _authorize(state, op, "REDEEM")
        _require_controller(account, op.actor)
        _available(account, quantity)
        new_consumed = _checked_add(state.consumed.get(grant.grant_id, 0), quantity)
        if new_consumed > grant.limit:
            raise AssetRefusal("AUTHORITY_BUDGET", "redemption exceeds the grant limit")
        new_redeemed = _checked_add(state.redeemed.get(op.claim_id, 0), quantity)
        state.consumed[grant.grant_id] = new_consumed
        state.redeemed[op.claim_id] = new_redeemed
        account.balance -= quantity
    elif op.kind == "TRANSFER":
        _require_controller(account, op.actor)
        counterparty = op.counterparty_id
        if not counterparty or counterparty == op.holder_id:
            raise AssetRefusal("TRANSFER_TARGET", "transfer needs a distinct counterparty holder")
        destination = _account(state, op.claim_id, counterparty)
        _available(account, quantity)
        new_destination = _checked_add(destination.balance, quantity)
        account.balance -= quantity
        destination.balance = new_destination
    elif op.kind == "ENCUMBER":
        _require_controller(account, op.actor)
        if not op.encumbrance_id:
            raise AssetRefusal("ENCUMBRANCE_ID_INVALID", "encumbrance identifier is required")
        if op.encumbrance_id in (account.encumbrances or {}):
            raise AssetRefusal("ENCUMBRANCE_EXISTS", "encumbrance identifier is already active")
        encumbered = sum((account.encumbrances or {}).values())
        if quantity > account.balance - encumbered:
            raise AssetRefusal("INSUFFICIENT_AVAILABLE", "encumbrance exceeds available quantity")
        account.encumbrances = {**(account.encumbrances or {}), op.encumbrance_id: quantity}
    else:
        _require_controller(account, op.actor)
        if op.encumbrance_id not in (account.encumbrances or {}):
            raise AssetRefusal("ENCUMBRANCE_UNKNOWN", "no active encumbrance with that identifier")
        released = dict(account.encumbrances or {})
        journal_quantity = released.pop(op.encumbrance_id)
        account.encumbrances = released

    entry = {
        "index": len(state.journal), "operation_id": op.operation_id, "kind": op.kind,
        "claim_id": op.claim_id, "holder_id": op.holder_id, "counterparty_id": counterparty,
        "quantity": journal_quantity, "unit": op.unit, "grant_id": op.grant_id,
        "encumbrance_id": op.encumbrance_id,
    }
    state.journal.append(entry)
    receipt = {"operation_id": op.operation_id, "kind": op.kind, "digest": digest,
               "height": len(state.journal)}
    state.operations[op.operation_id] = (digest, dict(receipt))
    return {**receipt, "status": "APPLIED"}


class AssetLedger:
    """Deterministic retained ASSET specimen with atomic, idempotent operations."""

    def __init__(self, state: _State) -> None:
        self._state = state

    @property
    def height(self) -> int:
        return len(self._state.journal)

    def clone(self) -> AssetLedger:
        return AssetLedger(copy.deepcopy(self._state))

    def claim(self, claim_id: str) -> ClaimRecord:
        return self._state.claims[claim_id]

    def backing_claim(self, backing_id: str) -> Quantity:
        return self._state.backing_claims[backing_id]

    def account(self, claim_id: str, holder_id: str) -> Account:
        return _account(self._state, claim_id, holder_id)

    def balance(self, claim_id: str, holder_id: str) -> int:
        return self.account(claim_id, holder_id).balance

    def issued_total(self, claim_id: str) -> int:
        return self._state.issued.get(claim_id, 0)

    def redeemed_total(self, claim_id: str) -> int:
        return self._state.redeemed.get(claim_id, 0)

    def grant_digest(self, grant_id: str) -> str:
        grant = self._state.grants.get(grant_id)
        if grant is None:
            raise AssetRefusal("AUTHORITY_MISSING", f"grant {grant_id!r} is not registered")
        return grant.digest()

    def state_digest(self) -> str:
        return _digest(_state_payload(self._state))

    def apply(self, operation: Operation) -> dict[str, Any]:
        work = copy.deepcopy(self._state)
        receipt = _apply(work, operation)
        self._state = work
        return receipt

    def apply_batch(self, operations: Sequence[Operation]) -> list[dict[str, Any]]:
        work = copy.deepcopy(self._state)
        receipts: list[dict[str, Any]] = []
        for index, operation in enumerate(operations):
            try:
                receipts.append(_apply(work, operation))
            except AssetRefusal as cause:
                raise BatchRefused(index, cause) from None
        self._state = work
        return receipts

    def reconcile(self, statement: Mapping[str, Any]) -> dict[str, Any]:
        """Compare retained totals with a supplied statement; never coerce invalid input."""
        state = self._state
        base = {"statement_height": None, "height": self.height}
        if not _statement_is_well_formed(statement):
            return {**base, "status": "UNKNOWN", "reason": "STATEMENT_MALFORMED", "diagnostics": []}
        base["statement_height"] = statement["height"]
        if statement["height"] != self.height:
            return {**base, "status": "UNKNOWN", "reason": "STATEMENT_STALE", "diagnostics": []}

        diagnostics: list[dict[str, Any]] = []
        for claim_id in sorted(state.claims):
            accounts = state.accounts.get(claim_id, {})
            outstanding = state.issued.get(claim_id, 0) - state.redeemed.get(claim_id, 0)
            holdings = sum(account.balance for account in accounts.values())
            if outstanding != holdings:
                diagnostics.append({"kind": "CONSERVATION_MISMATCH", "claim_id": claim_id,
                                    "issued_minus_redeemed": outstanding,
                                    "current_holdings": holdings})
            for holder_id, account in sorted(accounts.items()):
                if account.balance < 0 or sum((account.encumbrances or {}).values()) > account.balance:
                    diagnostics.append({"kind": "ENCUMBRANCE_EXCEEDS_BALANCE", "claim_id": claim_id,
                                        "holder_id": holder_id, "balance": account.balance})

        observed_holdings = statement["holdings"]
        for claim_id in sorted(set(state.accounts) | set(observed_holdings)):
            accounts = state.accounts.get(claim_id, {})
            observed_for_claim = observed_holdings.get(claim_id, {})
            for holder_id in sorted(set(accounts) | set(observed_for_claim)):
                expected = accounts[holder_id].balance if holder_id in accounts else None
                observed = observed_for_claim.get(holder_id)
                if expected != observed:
                    delta = observed - expected if isinstance(observed, int) and isinstance(expected, int) else None
                    diagnostics.append({"kind": "HOLDING_MISMATCH", "claim_id": claim_id,
                                        "holder_id": holder_id, "expected": expected,
                                        "observed": observed, "delta": delta})

        required: dict[str, int] = {}
        for claim_id in sorted(state.claims):
            claim = state.claims[claim_id]
            outstanding = state.issued.get(claim_id, 0) - state.redeemed.get(claim_id, 0)
            try:
                needed = _checked_add(0, outstanding * claim.backing_atoms_per_unit)
            except AssetRefusal:
                return {**base, "status": "UNKNOWN", "reason": "BACKING_REQUIREMENT_OVERFLOW",
                        "diagnostics": diagnostics}
            required[claim.backing_id] = _checked_add(required.get(claim.backing_id, 0), needed)

        observed_backing = statement["backing_atoms"]
        for backing_id in sorted(set(state.backing_claims) | set(required) | set(observed_backing)):
            recorded_quantity = state.backing_claims.get(backing_id)
            recorded = recorded_quantity.value if recorded_quantity is not None else None
            needed = required.get(backing_id, 0)
            observed = observed_backing.get(backing_id)
            if recorded is None:
                diagnostics.append({"kind": "BACKING_RECORD_MISSING", "backing_id": backing_id,
                                    "required": needed})
            elif recorded < needed:
                diagnostics.append({"kind": "BACKING_RECORD_SHORTFALL", "backing_id": backing_id,
                                    "required": needed, "recorded": recorded,
                                    "delta": recorded - needed})
            if observed != recorded:
                diagnostics.append({"kind": "BACKING_STATEMENT_MISMATCH", "backing_id": backing_id,
                                    "recorded": recorded, "observed": observed})
            if observed is not None and observed < needed:
                diagnostics.append({"kind": "BACKING_SHORTFALL", "backing_id": backing_id,
                                    "required": needed, "observed": observed,
                                    "delta": observed - needed})

        if not diagnostics:
            return {**base, "status": "PASS", "reason": "EXACT_RECONCILIATION", "diagnostics": []}
        reason = ",".join(sorted({entry["kind"] for entry in diagnostics}))
        return {**base, "status": "FAIL", "reason": reason, "diagnostics": diagnostics}


def _statement_is_well_formed(statement: object) -> bool:
    if not isinstance(statement, Mapping) or set(statement) != {"height", "holdings", "backing_atoms"}:
        return False
    height, holdings, backing = statement["height"], statement["holdings"], statement["backing_atoms"]
    if type(height) is not int or not isinstance(holdings, Mapping) or not isinstance(backing, Mapping):
        return False
    for claim_holdings in holdings.values():
        if not isinstance(claim_holdings, Mapping):
            return False
        if any(type(value) is not int for value in claim_holdings.values()):
            return False
    return all(type(value) is int for value in backing.values())


def _registry() -> _State:
    claims = {
        "claim:note-7": ClaimRecord("claim:note-7", "instrument:note-7", "backing:reserve-7",
                                    "RECORD_CLAIM", 3),
        "claim:note-8": ClaimRecord("claim:note-8", "instrument:note-8", "backing:reserve-8",
                                    "RECORD_CLAIM", 2),
    }
    grants = {
        "grant:issue-note-7": AuthorityGrant("grant:issue-note-7", "principal:issuer", "ISSUE",
                                             "claim:note-7", 100),
        "grant:issue-note-7-revoked": AuthorityGrant("grant:issue-note-7-revoked", "principal:issuer",
                                                     "ISSUE", "claim:note-7", 100, revoked=True),
        "grant:redeem-note-7-alice": AuthorityGrant("grant:redeem-note-7-alice", "principal:alice",
                                                    "REDEEM", "claim:note-7", 50),
        "grant:issue-note-8-max": AuthorityGrant("grant:issue-note-8-max", "principal:issuer",
                                                 "ISSUE", "claim:note-8", MAX_QUANTITY),
    }
    backing = {
        "backing:reserve-7": Quantity(300, Unit.BACKING_ATOM),
        "backing:reserve-8": Quantity(10, Unit.BACKING_ATOM),
    }
    accounts = {
        "claim:note-7": {
            "holder:alice": Account("custodian:vault-1", "principal:alice"),
            "holder:bob": Account("custodian:vault-2", "principal:bob"),
        },
        "claim:note-8": {
            "holder:carol": Account("custodian:vault-1", "principal:carol"),
        },
    }
    return _State(claims=claims, grants=grants, backing_claims=backing, accounts=accounts,
                  consumed={}, issued={}, redeemed={}, journal=[], operations={})


def build_specimen() -> AssetLedger:
    return AssetLedger(_registry())


def _op(kind: str, operation_id: str, actor: str, holder: str, quantity: object, *,
        claim: str = "claim:note-7", grant_id: str | None = None,
        grant_digest: str | None = None, counterparty: str | None = None,
        encumbrance: str | None = None, unit: str = "instrument") -> Operation:
    return Operation(kind=kind, operation_id=operation_id, actor=actor, claim_id=claim,
                     holder_id=holder, quantity=quantity, unit=unit, grant_id=grant_id,
                     grant_digest=grant_digest, counterparty_id=counterparty,
                     encumbrance_id=encumbrance)


def observed_statement(ledger: AssetLedger) -> dict[str, Any]:
    """Mirror the retained state as a statement. This checks arithmetic only, not external truth."""
    state = ledger._state
    return {
        "height": ledger.height,
        "holdings": {
            claim: {holder: account.balance for holder, account in sorted(accounts.items())}
            for claim, accounts in sorted(state.accounts.items())
        },
        "backing_atoms": {key: value.value for key, value in sorted(state.backing_claims.items())},
    }


def _sequence(ledger: AssetLedger) -> list[dict[str, Any]]:
    """Ordered specimen steps; each names the exact expected outcome before execution."""
    issue_digest = ledger.grant_digest("grant:issue-note-7")
    redeem_digest = ledger.grant_digest("grant:redeem-note-7-alice")
    issuer, alice, bob = "principal:issuer", "principal:alice", "principal:bob"
    alice_h, bob_h = "holder:alice", "holder:bob"
    grant = "grant:issue-note-7"
    redeem = "grant:redeem-note-7-alice"

    def issue(op_id: str, quantity: object, holder: str = bob_h, actor: str = issuer,
              grant_id: str = grant, digest: str | None = issue_digest,
              unit: str = "instrument") -> Operation:
        return _op("ISSUE", op_id, actor, holder, quantity, grant_id=grant_id,
                   grant_digest=digest, unit=unit)

    def redeem_op(op_id: str, quantity: object, actor: str = alice) -> Operation:
        return _op("REDEEM", op_id, actor, alice_h, quantity, grant_id=redeem,
                   grant_digest=redeem_digest)

    return [
        {"name": "issue 40 to alice", "expect": "APPLIED",
         "op": issue("op:issue-1", 40, holder=alice_h)},
        {"name": "replay identical issuance", "expect": "REPLAYED",
         "op": issue("op:issue-1", 40, holder=alice_h)},
        {"name": "reuse issuance identifier with different quantity", "expect": "OPERATION_ID_CONFLICT",
         "op": issue("op:issue-1", 41, holder=alice_h)},
        {"name": "issuance cites unregistered grant", "expect": "AUTHORITY_MISSING",
         "op": issue("op:missing", 10, grant_id="grant:none", digest=None)},
        {"name": "issuance cites forged (inflated) grant digest", "expect": "AUTHORITY_FORGED",
         "op": issue("op:forged", 10, digest=AuthorityGrant(grant, issuer, "ISSUE",
                                                             "claim:note-7", 10**6).digest())},
        {"name": "issuance under revoked grant", "expect": "AUTHORITY_REVOKED",
         "op": issue("op:revoked", 10, grant_id="grant:issue-note-7-revoked",
                     digest=ledger.grant_digest("grant:issue-note-7-revoked"))},
        {"name": "issuance by non-principal actor", "expect": "AUTHORITY_ACTOR_MISMATCH",
         "op": issue("op:actor", 10, actor=alice)},
        {"name": "issuance exceeds grant budget (40+70>100)", "expect": "AUTHORITY_BUDGET",
         "op": issue("op:budget", 70)},
        {"name": "issuance in backing unit", "expect": "UNIT_MISMATCH",
         "op": issue("op:unit", 10, unit="backing_atom")},
        {"name": "issuance of negative quantity", "expect": "QUANTITY_NEGATIVE",
         "op": issue("op:negative", -1)},
        {"name": "issuance of boolean quantity", "expect": "QUANTITY_TYPE",
         "op": issue("op:boolean", True)},
        {"name": "issuance of fractional quantity", "expect": "QUANTITY_TYPE",
         "op": issue("op:fraction", 1.0)},
        {"name": "issuance above MAX_QUANTITY", "expect": "QUANTITY_OVERFLOW",
         "op": issue("op:overflow", MAX_QUANTITY + 1)},
        {"name": "issue 25 to bob", "expect": "APPLIED", "op": issue("op:issue-2", 25)},
        {"name": "custodian without control attempts transfer", "expect": "CONTROL_REQUIRED",
         "op": _op("TRANSFER", "op:transfer-custodian", "custodian:vault-1", alice_h, 10,
                   counterparty=bob_h)},
        {"name": "controller transfers 10 alice to bob", "expect": "APPLIED",
         "op": _op("TRANSFER", "op:transfer-1", alice, alice_h, 10, counterparty=bob_h)},
        {"name": "controller encumbers 20 of alice", "expect": "APPLIED",
         "op": _op("ENCUMBER", "op:encumber-1", alice, alice_h, 20, encumbrance="enc:alice-1")},
        {"name": "reuse active encumbrance identifier", "expect": "ENCUMBRANCE_EXISTS",
         "op": _op("ENCUMBER", "op:encumber-2", alice, alice_h, 5, encumbrance="enc:alice-1")},
        {"name": "transfer 15 blocked by encumbrance", "expect": "ENCUMBERED_QUANTITY",
         "op": _op("TRANSFER", "op:transfer-blocked", alice, alice_h, 15, counterparty=bob_h)},
        {"name": "redeem 15 blocked by encumbrance", "expect": "ENCUMBERED_QUANTITY",
         "op": redeem_op("op:redeem-blocked", 15)},
        {"name": "release unknown encumbrance", "expect": "ENCUMBRANCE_UNKNOWN",
         "op": _op("RELEASE", "op:release-unknown", alice, alice_h, 0, encumbrance="enc:none")},
        {"name": "release encumbrance", "expect": "APPLIED",
         "op": _op("RELEASE", "op:release-1", alice, alice_h, 0, encumbrance="enc:alice-1")},
        {"name": "transfer 15 alice to bob after release", "expect": "APPLIED",
         "op": _op("TRANSFER", "op:transfer-2", alice, alice_h, 15, counterparty=bob_h)},
        {"name": "redeem 16 exceeds alice balance", "expect": "INSUFFICIENT_BALANCE",
         "op": redeem_op("op:redeem-over", 16)},
        {"name": "redeem by non-principal actor", "expect": "AUTHORITY_ACTOR_MISMATCH",
         "op": redeem_op("op:redeem-actor", 15, actor=bob)},
        {"name": "redeem 15 alice", "expect": "APPLIED", "op": redeem_op("op:redeem-1", 15)},
        {"name": "grant principal redeems another holder's holding", "expect": "CONTROL_REQUIRED",
         "op": _op("REDEEM", "op:redeem-other-holding", alice, bob_h, 5,
                   grant_id=redeem, grant_digest=redeem_digest)},
        {"name": "issuance under a redemption grant", "expect": "AUTHORITY_ACTION",
         "op": issue("op:wrong-action", 5, actor=alice, grant_id=redeem, digest=redeem_digest)},
        {"name": "issuance to another claim under a claim-scoped grant", "expect": "AUTHORITY_SCOPE",
         "op": _op("ISSUE", "op:wrong-scope", issuer, "holder:carol", 5, claim="claim:note-8",
                   grant_id=grant, grant_digest=issue_digest)},
        {"name": "self transfer refused", "expect": "TRANSFER_TARGET",
         "op": _op("TRANSFER", "op:self-transfer", alice, alice_h, 5, counterparty=alice_h)},
        {"name": "batch with underfunded redemption is atomic", "expect": "BATCH_REFUSED:INSUFFICIENT_BALANCE",
         "batch": [issue("op:batch-issue-refused", 5),
                   redeem_op("op:batch-redeem-refused", 999)]},
        {"name": "batch of issuance and transfer applies together", "expect": "BATCH_APPLIED",
         "batch": [issue("op:batch-issue", 5),
                   _op("TRANSFER", "op:batch-transfer", bob, bob_h, 5, counterparty=alice_h)]},
    ]


def run_specimen() -> tuple[AssetLedger, list[dict[str, Any]]]:
    """Run the ordered specimen steps; the ledger reflects only applied steps."""
    ledger = build_specimen()
    results: list[dict[str, Any]] = []
    for step in _sequence(ledger):
        before = ledger.state_digest()
        try:
            if "batch" in step:
                ledger.apply_batch(step["batch"])
                observed = "BATCH_APPLIED"
            else:
                observed = ledger.apply(step["op"])["status"]
        except BatchRefused as cause:
            observed = f"BATCH_REFUSED:{cause.cause_code}"
        except AssetRefusal as cause:
            observed = cause.code
        changed = ledger.state_digest() != before
        applied = observed in ("APPLIED", "BATCH_APPLIED")
        results.append({
            "name": step["name"], "expected": step["expect"], "observed": observed,
            "state_changed": changed,
            "matched": observed == step["expect"] and changed == applied,
        })
    return ledger, results


def _probe(name: str, action: Callable[[], str], expect: str) -> dict[str, Any]:
    try:
        observed = action()
    except AssetRefusal as cause:
        observed = cause.code
    return {"name": name, "expected": expect, "observed": observed, "matched": observed == expect}


def _identity_and_quantity_probes() -> list[dict[str, Any]]:
    def quantity(value: object, unit: object = Unit.INSTRUMENT) -> Callable[[], str]:
        def run() -> str:
            Quantity(value, unit)  # type: ignore[arg-type]
            return "OK"
        return run

    def claim(claim_id: str, instrument: str, backing: str, rights: str = "RECORD_CLAIM") -> Callable[[], str]:
        def run() -> str:
            ClaimRecord(claim_id, instrument, backing, rights, 2)
            return "OK"
        return run

    return [
        _probe("quantity boolean refused", quantity(True), "QUANTITY_TYPE"),
        _probe("quantity float refused", quantity(1.0), "QUANTITY_TYPE"),
        _probe("quantity negative refused", quantity(-1), "QUANTITY_NEGATIVE"),
        _probe("quantity above bound refused", quantity(MAX_QUANTITY + 1), "QUANTITY_OVERFLOW"),
        _probe("unit given as text refused", quantity(1, "instrument"), "UNIT_UNKNOWN"),
        _probe("claim identifier in backing namespace refused",
               claim("claim:n", "instrument:n", "claim:n"), "IDENTITY_NAMESPACE"),
        _probe("backing identifier as instrument refused",
               claim("claim:n", "backing:n", "backing:n"), "IDENTITY_NAMESPACE"),
        _probe("distinct claim, instrument and backing accepted",
               claim("claim:n", "instrument:n", "backing:n"), "OK"),
        _probe("claim with unadmitted rights class refused",
               claim("claim:n", "instrument:n", "backing:n", "OWNERSHIP"), "RIGHTS_UNKNOWN"),
        _probe("claim counted in backing atoms refused",
               lambda: _claim_in_unit(Unit.BACKING_ATOM), "UNIT_MISMATCH"),
        _probe("zero backing rate refused",
               lambda: _claim_with_rate(0), "RATE_INVALID"),
    ]


def _claim_in_unit(unit: Unit) -> str:
    ClaimRecord("claim:n", "instrument:n", "backing:n", "RECORD_CLAIM", 2, unit)
    return "OK"


def _claim_with_rate(rate: int) -> str:
    ClaimRecord("claim:n", "instrument:n", "backing:n", "RECORD_CLAIM", rate)
    return "OK"


def _refused_probe(name: str, ledger: AssetLedger, action: Callable[[], str], expect: str) -> dict[str, Any]:
    before = ledger.state_digest()
    row = _probe(name, action, expect)
    row["matched"] = row["matched"] and ledger.state_digest() == before
    return row


def _separate_ledger_probes() -> list[dict[str, Any]]:
    probe = build_specimen()
    first = probe.apply(_op("ISSUE", "op:max", "principal:issuer", "holder:carol", MAX_QUANTITY,
                            claim="claim:note-8", grant_id="grant:issue-note-8-max",
                            grant_digest=probe.grant_digest("grant:issue-note-8-max")))
    before = probe.state_digest()
    rows = [{"name": "issue MAX_QUANTITY to carol", "expected": "APPLIED",
             "observed": first["status"], "matched": first["status"] == "APPLIED"}]
    rows.append(_probe(
        "issuance past MAX_QUANTITY refused without mutation",
        lambda: probe.apply(_op("ISSUE", "op:over", "principal:issuer", "holder:carol", 1,
                                claim="claim:note-8", grant_id="grant:issue-note-8-max",
                                grant_digest=probe.grant_digest("grant:issue-note-8-max")))["status"],
        "QUANTITY_OVERFLOW"))
    rows[-1]["matched"] = rows[-1]["matched"] and probe.state_digest() == before

    funded = build_specimen()
    funded.apply(_op("ISSUE", "op:fund-alice", "principal:issuer", "holder:alice", 60,
                     grant_id="grant:issue-note-7",
                     grant_digest=funded.grant_digest("grant:issue-note-7")))
    rows.append(_refused_probe(
        "redemption above its grant limit refused despite sufficient balance", funded,
        lambda: funded.apply(_op("REDEEM", "op:redeem-over-budget", "principal:alice", "holder:alice", 51,
                                 grant_id="grant:redeem-note-7-alice",
                                 grant_digest=funded.grant_digest("grant:redeem-note-7-alice")))["status"],
        "AUTHORITY_BUDGET"))

    unregistered = build_specimen()
    rows.append(_refused_probe(
        "issuance to an unregistered claim refused", unregistered,
        lambda: unregistered.apply(_op("ISSUE", "op:unknown-claim", "principal:issuer", "holder:alice", 1,
                                       claim="claim:note-9", grant_id="grant:issue-note-7",
                                       grant_digest=unregistered.grant_digest("grant:issue-note-7")))["status"],
        "CLAIM_UNKNOWN"))
    return rows


def _reconciliation_rows(ledger: AssetLedger) -> list[dict[str, Any]]:
    honest = observed_statement(ledger)

    def variant(mutate: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
        statement = copy.deepcopy(honest)
        mutate(statement)
        return statement

    def tamper_mutation() -> dict[str, Any]:
        mutated = ledger.clone()
        mutated._state.accounts["claim:note-7"]["holder:alice"].balance += 1
        return mutated.reconcile(honest)

    def record_shortfall() -> dict[str, Any]:
        mutated = ledger.clone()
        mutated._state.backing_claims["backing:reserve-7"] = Quantity(164, Unit.BACKING_ATOM)
        return mutated.reconcile(observed_statement(mutated))

    cases: list[tuple[str, Callable[[], dict[str, Any]], str, str]] = [
        ("honest statement reconciles", lambda: ledger.reconcile(honest), "PASS", "EXACT_RECONCILIATION"),
        ("statement height behind journal", lambda: ledger.reconcile(
            variant(lambda s: s.update(height=ledger.height - 1))), "UNKNOWN", "STATEMENT_STALE"),
        ("bob holding off by one", lambda: ledger.reconcile(
            variant(lambda s: s["holdings"]["claim:note-7"].update({"holder:bob": 51}))),
         "FAIL", "HOLDING_MISMATCH"),
        ("carol holding missing from statement", lambda: ledger.reconcile(
            variant(lambda s: s["holdings"]["claim:note-8"].pop("holder:carol"))),
         "FAIL", "HOLDING_MISMATCH"),
        ("reserve-7 observed one atom under requirement", lambda: ledger.reconcile(
            variant(lambda s: s["backing_atoms"].update({"backing:reserve-7": 164}))),
         "FAIL", "BACKING_SHORTFALL,BACKING_STATEMENT_MISMATCH"),
        ("statement missing backing field", lambda: ledger.reconcile(
            variant(lambda s: s.pop("backing_atoms"))), "UNKNOWN", "STATEMENT_MALFORMED"),
        ("silent internal balance mutation", tamper_mutation, "FAIL",
         "CONSERVATION_MISMATCH,HOLDING_MISMATCH"),
        ("retained backing claim below requirement", record_shortfall, "FAIL",
         "BACKING_RECORD_SHORTFALL,BACKING_SHORTFALL"),
    ]
    rows: list[dict[str, Any]] = []
    for name, action, expect_status, expect_reason in cases:
        report = action()
        observed = (report["status"], report["reason"])
        rows.append({
            "name": name, "expected_status": expect_status, "expected_reason": expect_reason,
            "observed_status": observed[0], "observed_reason": observed[1],
            "matched": observed == (expect_status, expect_reason),
        })
    return rows


def evaluate() -> dict[str, Any]:
    """Callable verifier-style report; PASS means finite expectations were reproduced."""
    ledger, sequence = run_specimen()
    probes = _identity_and_quantity_probes() + _separate_ledger_probes()
    reconciliations = _reconciliation_rows(ledger)
    scenarios = sequence + probes
    unexpected = sorted(
        [row["name"] for row in scenarios if not row["matched"]]
        + [row["name"] for row in reconciliations if not row["matched"]]
    )
    matched = not unexpected
    route_correspondence = _route_correspondence(scenarios + reconciliations)
    return {
        "schema": SCHEMA,
        "adapter": ADAPTER,
        "status": "PASS" if matched else "FAIL",
        "reason": "EVERY_EXPECTED_OUTCOME_REPRODUCED" if matched
        else "UNEXPECTED_OUTCOME:" + ",".join(unexpected),
        "scope": "FINITE_IN_MEMORY_SPECIMEN",
        "conformance": "NOT_ESTABLISHED",
        "obligation_ids": list(FIELD_DECLARATIONS),
        "field_statuses": {
            obligation: {
                field: {"status": decl.status, "reason": decl.reason}
                for field, decl in fields.items()
            }
            for obligation, fields in FIELD_DECLARATIONS.items()
        },
        "scenarios": scenarios,
        "reconciliations": reconciliations,
        "observations": {
            "journal_height": ledger.height,
            "final_balances": {
                claim: {holder: account.balance for holder, account in sorted(accounts.items())}
                for claim, accounts in sorted(ledger._state.accounts.items())
            },
            "issued": dict(sorted(ledger._state.issued.items())),
            "redeemed": dict(sorted(ledger._state.redeemed.items())),
            "backing_recorded": {key: value.value for key, value in sorted(ledger._state.backing_claims.items())},
            "final_state_digest": ledger.state_digest(),
        },
        "source_digest": source_digest(),
        "specimen_digest": build_specimen().state_digest(),
        "claim_boundary": dict(CLAIM_BOUNDARY),
        "route_adapter": ROUTE_ADAPTER,
        "auxiliary_interface": AUXILIARY_INTERFACE,
        "route_correspondence": route_correspondence,
        "route_proposition_digests": dict(ROUTE_PROPOSITION_DIGESTS),
        "route_source": ROUTE_SOURCE,
        "route_source_digest": ROUTE_SOURCE_DIGEST,
    }


# Route correspondence. The source-owned ASSET-1.1, ASSET-2.1 and ASSET-3.1 routes are
# replayed by verifier.runtime.token_asset_execution against retained TOKEN subjects.
# This module's specimen is a claim/instrument/backing record, so no declaration field is
# carried by a route replay. The correspondence below is explicit and auxiliary.
ROUTE_ADAPTER = "verifier-asset-tier0-route-correspondence-1"
AUXILIARY_INTERFACE = "asset-field-mechanism-1"
ROUTE_COORDINATES = ("ASSET-1.1", "ASSET-2.1", "ASSET-3.1")
ROUTE_TIERS = {"ASSET-1.1": 1, "ASSET-2.1": 2, "ASSET-3.1": 3}
ROUTE_CHECKING_MECHANISM = "verifier.runtime.token_asset_execution.evaluate"
ROUTE_REPLAY_SUBJECT = "TOKEN"
ROUTE_SOURCE = "src/verifier/runtime/token_asset_execution.py"
ROUTE_SOURCE_DIGEST = "sha256:c4058569d8d7e138ae75592a794bea2c39516b2fa191f38c547113c7c0ac55c9"
ROUTE_PROPOSITION_DIGESTS = {
    "ASSET-1.1": "sha256:e4c8e0457f3eb56e1a28416e75abac7c04a3119cedaa913ea521674ab9451cd2",
    "ASSET-2.1": "sha256:a7d23079625cb06dfd74a5413da7095927f7b2d84e2effe92372843e275c7b8f",
    "ASSET-3.1": "sha256:0da90d6714bd5cb0ae180cabfaba47d48456340f894416016cfa291bff09127c",
}
NAMED_CLAIM = "NAMED_CLAIM"
NAMED_BOUNDARY = "NAMED_BOUNDARY"
NOT_NAMED = "NOT_NAMED"
IN_MODEL_REPRODUCED = "IN_MODEL_REPRODUCED"
IN_MODEL_UNREPRODUCED = "IN_MODEL_UNREPRODUCED"

_ROUTE_BY_OBLIGATION = {
    "ASSET-0.1-identity-and-quantity": "ASSET-1.1",
    "ASSET-0.2-issuance-and-redemption": "ASSET-2.1",
    "ASSET-0.3-custody-and-encumbrance": "ASSET-3.1",
}

# Verbatim clauses of each route's exact claim, keyed by declaration field. Route text is
# TOKEN-specific, so a clause is correspondence evidence and never field coverage.
_FIELD_ROUTE_CLAUSES: dict[tuple[str, str], tuple[str | None, str]] = {
    ("ASSET-0.1-identity-and-quantity", "identity"): (None, NOT_NAMED),
    ("ASSET-0.1-identity-and-quantity", "rights"): (None, NOT_NAMED),
    ("ASSET-0.1-identity-and-quantity", "units"): ("declared microsecond clock", NAMED_CLAIM),
    ("ASSET-0.1-identity-and-quantity", "precision"): ("dimensionless integer counts", NAMED_CLAIM),
    ("ASSET-0.2-issuance-and-redemption", "issuance_authority"): (None, NOT_NAMED),
    ("ASSET-0.2-issuance-and-redemption", "supply_changes"): (
        "contiguous retained epoch fold", NAMED_CLAIM),
    ("ASSET-0.2-issuance-and-redemption", "redemption"): (
        "redemption and actual application remain explicitly NOT_ESTABLISHED", NAMED_BOUNDARY),
    ("ASSET-0.2-issuance-and-redemption", "backing_claims"): (None, NOT_NAMED),
    ("ASSET-0.3-custody-and-encumbrance", "custody"): (
        "real custody, completeness, supply conservation and backing remain NOT_ESTABLISHED",
        NAMED_BOUNDARY),
    ("ASSET-0.3-custody-and-encumbrance", "control"): (None, NOT_NAMED),
    ("ASSET-0.3-custody-and-encumbrance", "encumbrances"): (None, NOT_NAMED),
    ("ASSET-0.3-custody-and-encumbrance", "reconciliation"): (
        "reconciles narrowing scopes", NAMED_CLAIM),
}

# Every scenario, probe and reconciliation row names the routes whose in-model
# reproduction it contributes to. evaluate() rejects any unlisted row name.
ROUTE_ROW_TAGS: dict[str, tuple[str, ...]] = {
    "issue 40 to alice": ("ASSET-2.1",),
    "replay identical issuance": ("ASSET-2.1",),
    "reuse issuance identifier with different quantity": ("ASSET-2.1",),
    "issuance cites unregistered grant": ("ASSET-2.1",),
    "issuance cites forged (inflated) grant digest": ("ASSET-2.1",),
    "issuance under revoked grant": ("ASSET-2.1",),
    "issuance by non-principal actor": ("ASSET-2.1",),
    "issuance exceeds grant budget (40+70>100)": ("ASSET-2.1",),
    "issuance in backing unit": ("ASSET-1.1",),
    "issuance of negative quantity": ("ASSET-1.1",),
    "issuance of boolean quantity": ("ASSET-1.1",),
    "issuance of fractional quantity": ("ASSET-1.1",),
    "issuance above MAX_QUANTITY": ("ASSET-1.1",),
    "issue 25 to bob": ("ASSET-2.1",),
    "custodian without control attempts transfer": ("ASSET-3.1",),
    "controller transfers 10 alice to bob": ("ASSET-3.1",),
    "controller encumbers 20 of alice": ("ASSET-3.1",),
    "reuse active encumbrance identifier": ("ASSET-3.1",),
    "transfer 15 blocked by encumbrance": ("ASSET-3.1",),
    "redeem 15 blocked by encumbrance": ("ASSET-2.1", "ASSET-3.1"),
    "release unknown encumbrance": ("ASSET-3.1",),
    "release encumbrance": ("ASSET-3.1",),
    "transfer 15 alice to bob after release": ("ASSET-3.1",),
    "redeem 16 exceeds alice balance": ("ASSET-2.1",),
    "redeem by non-principal actor": ("ASSET-2.1",),
    "redeem 15 alice": ("ASSET-2.1",),
    "grant principal redeems another holder's holding": ("ASSET-2.1", "ASSET-3.1"),
    "issuance under a redemption grant": ("ASSET-2.1",),
    "issuance to another claim under a claim-scoped grant": ("ASSET-2.1",),
    "self transfer refused": ("ASSET-3.1",),
    "batch with underfunded redemption is atomic": ("ASSET-2.1", "ASSET-3.1"),
    "batch of issuance and transfer applies together": ("ASSET-2.1", "ASSET-3.1"),
    "quantity boolean refused": ("ASSET-1.1",),
    "quantity float refused": ("ASSET-1.1",),
    "quantity negative refused": ("ASSET-1.1",),
    "quantity above bound refused": ("ASSET-1.1",),
    "unit given as text refused": ("ASSET-1.1",),
    "claim identifier in backing namespace refused": ("ASSET-1.1",),
    "backing identifier as instrument refused": ("ASSET-1.1",),
    "distinct claim, instrument and backing accepted": ("ASSET-1.1",),
    "claim with unadmitted rights class refused": ("ASSET-1.1",),
    "claim counted in backing atoms refused": ("ASSET-1.1",),
    "zero backing rate refused": ("ASSET-1.1",),
    "issue MAX_QUANTITY to carol": ("ASSET-1.1",),
    "issuance past MAX_QUANTITY refused without mutation": ("ASSET-1.1",),
    "redemption above its grant limit refused despite sufficient balance": ("ASSET-2.1",),
    "issuance to an unregistered claim refused": ("ASSET-2.1",),
    "honest statement reconciles": ("ASSET-3.1",),
    "statement height behind journal": ("ASSET-3.1",),
    "bob holding off by one": ("ASSET-3.1",),
    "carol holding missing from statement": ("ASSET-3.1",),
    "reserve-7 observed one atom under requirement": ("ASSET-2.1",),
    "statement missing backing field": ("ASSET-3.1",),
    "silent internal balance mutation": ("ASSET-3.1",),
    "retained backing claim below requirement": ("ASSET-2.1",),
}


def catalog() -> list[dict[str, Any]]:
    """One row per declaration field. Catalog presence is never execution or PASS."""
    rows: list[dict[str, Any]] = []
    for obligation, fields in FIELD_DECLARATIONS.items():
        coordinate = _ROUTE_BY_OBLIGATION[obligation]
        for field, declared in fields.items():
            clause, stance = _FIELD_ROUTE_CLAUSES[(obligation, field)]
            rows.append({
                "field_id": f"{obligation}.{field}",
                "obligation_id": obligation,
                "field": field,
                "tier": ROUTE_TIERS[coordinate],
                "route_coordinate": coordinate,
                "route_proposition_digest": ROUTE_PROPOSITION_DIGESTS[coordinate],
                "route_clause": clause,
                "route_stance": stance,
                "route_replay_subject": ROUTE_REPLAY_SUBJECT,
                "carried_by_route": False,
                "coverage": "AUXILIARY_FIELD_MECHANISM",
                "field_status": declared.status,
                "field_reason": declared.reason,
                "execution_status": "NOT_EXECUTED",
                "auxiliary_interface": AUXILIARY_INTERFACE,
                "adapter": ROUTE_ADAPTER,
            })
    return rows


def route_drift(rows: Sequence[Any]) -> list[str]:
    """Compare caller-supplied route catalog rows with the pinned correspondence.

    An empty list means the rows carry exactly the pinned coordinates, tiers, proposition
    digests, checker symbol and verbatim clauses. Route PASS is decided by the route itself.
    """
    diagnostics: list[str] = []
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, Mapping):
            diagnostics.append("ROW_SHAPE_DIFFERS")
            continue
        coordinate = row.get("coordinate")
        if coordinate not in ROUTE_COORDINATES:
            diagnostics.append(f"UNKNOWN:{coordinate!r}")
            continue
        if coordinate in seen:
            diagnostics.append(f"DUPLICATED:{coordinate}")
            continue
        seen.add(coordinate)
        if row.get("tier") != ROUTE_TIERS[coordinate]:
            diagnostics.append(f"TIER_DRIFT:{coordinate}")
        if row.get("proposition_digest") != ROUTE_PROPOSITION_DIGESTS[coordinate]:
            diagnostics.append(f"PROPOSITION_DRIFT:{coordinate}")
        if row.get("checking_mechanism") != ROUTE_CHECKING_MECHANISM:
            diagnostics.append(f"CHECKER_DRIFT:{coordinate}")
        claim = str(row.get("exact_claim"))
        for (obligation, field), (clause, _) in _FIELD_ROUTE_CLAUSES.items():
            if (_ROUTE_BY_OBLIGATION[obligation] == coordinate and clause is not None
                    and clause not in claim):
                diagnostics.append(f"CLAUSE_DRIFT:{coordinate}:{field}")
    for coordinate in ROUTE_COORDINATES:
        if coordinate not in seen:
            diagnostics.append(f"MISSING:{coordinate}")
    return diagnostics


def _tags(name: str) -> tuple[str, ...]:
    if name not in ROUTE_ROW_TAGS:
        raise ValueError("ASSET_ROUTE_ROW_UNTAGGED")
    return ROUTE_ROW_TAGS[name]


def _route_correspondence(rows: Sequence[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for coordinate in ROUTE_COORDINATES:
        selected = [row for row in rows if coordinate in _tags(row["name"])]
        unmatched = sorted(row["name"] for row in selected if not row["matched"])
        result[coordinate] = {
            "status": IN_MODEL_UNREPRODUCED if unmatched else IN_MODEL_REPRODUCED,
            "rows": len(selected),
            "unmatched": unmatched,
            "fields": [
                f"{obligation}.{field}"
                for obligation, fields in FIELD_DECLARATIONS.items()
                if _ROUTE_BY_OBLIGATION[obligation] == coordinate
                for field in fields
            ],
            "route_proposition_digest": ROUTE_PROPOSITION_DIGESTS[coordinate],
            "route_status": "NOT_ESTABLISHED",
        }
    return result


def _strict_equal(left: Any, right: Any) -> bool:
    """Equality that refuses cross-type coercion such as 1 versus True or tuple versus list."""
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(
            _strict_equal(left[key], right[key]) for key in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _strict_equal(a, b) for a, b in zip(left, right))
    return left == right


def check_observations(coordinate: str, observed: Any) -> bool:
    """Accept an observation only if it equals a fresh evaluation and its route reproduces.

    Stale, forged, reordered, aliased or altered observations return False. The result is
    never a route PASS: the route status stays NOT_ESTABLISHED.
    """
    if coordinate not in ROUTE_COORDINATES:
        raise ValueError("ASSET_ROUTE_COORDINATE_UNREGISTERED")
    if not isinstance(observed, dict):
        raise ValueError("ASSET_ROUTE_OBSERVATION_SHAPE_DIFFERS")
    fresh = evaluate()
    if not _strict_equal(observed, fresh):
        return False
    return fresh["route_correspondence"][coordinate]["status"] == IN_MODEL_REPRODUCED
