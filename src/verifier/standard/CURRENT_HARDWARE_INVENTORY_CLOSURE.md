# Current HARDWARE-4.1 retained inventory closure under independent records

Status: experimental, versioned current-object objective. Verifier Standard
(VSTD) specifies the claim; this Python mechanism is one reference checker.
JavaScript Object Notation (JSON) gives canonical retained bytes, and Secure
Hash Algorithm 256-bit (SHA-256) names commitments. Scope members, entry and
evidence identifiers, identity keys and producer labels are exact bounded
strings. Counts and checking budgets are dimensionless.

## Governing row

`DOMAIN_OBLIGATIONS.md` names this coordinate:

> HARDWARE-4.1 | Physical inventory closure | Complete coverage, nonaliasing
> physical identities and resource isolation require independent bounded
> evidence; a retained inventory alone leaves closure UNKNOWN.

That row states a physical requirement. This objective does not discharge
it. It mechanizes only the decidable record-level part of it:

- no two entries share an identity key;
- every member of an externally selected scope is covered;
- each entry is backed by at least one retained evidence record from a
  producer other than the inventory's author.

An inventory without such records stays `UNKNOWN` and never `PASS`, as the
row requires. Resource isolation and complete physical coverage remain
`NOT_ESTABLISHED`.

## Selection and proposition

The pair `verifier-current-object-obligations-1` / `HARDWARE-4.1` selects
this objective. A coordinate without its semantic version selects nothing,
and the legacy domain-certificate meaning of `HARDWARE-4.1` is unchanged.

The external request selects:
- one exact HARDWARE namespace record and its finite typed collection;
- `members_digest`, a commitment to the scope member list;
- the retained evidence bytes, the policy and finite limits.

Because the request commits to the scope, the inventory's author cannot
choose what "complete" means. The record's payload is exactly
`scope=retained-hardware-records` and `inventory_digest`. The retained
`members` must rehash to the selected commitment, and the retained
`inventory` must rehash to the record's commitment. Members form a nonempty,
sorted, unique list.

The inventory has exactly two fields:
- `author`;
- `entries`. Each entry has exactly `entry_id` (unique), `identity_key`,
  `covers` (a nonempty sorted unique member list) and `evidence`, a list of
  records.

Each evidence record has exactly `evidence_id` (unique across the
inventory), `producer`, `identity_key` and `covers`.

`PASS` requires all of the following:
- **Nonaliasing.** Identity keys are pairwise distinct as exact strings.
  There is no case folding or other normalisation.
- **Coverage.** Every entry covers only selected members, and the union of
  all entries' coverage is every selected member. Two entries may cover the
  same member; that is isolation, which is not checked.
- **Consistency.** Every evidence record states exactly its entry's identity
  key and coverage.
- **Independence.** Every entry has at least one evidence record whose
  producer label differs from the author label. Author-produced records may
  be retained, but they do not count.

## FAIL versus UNKNOWN

`FAIL` is reserved for counterexamples that no added evidence record could
repair, because a record must restate its entry exactly:
- an aliased identity key, even when the author declares it with no
  evidence at all;
- an uncovered selected member;
- coverage outside the selected scope;
- retained members that differ from the selection;
- an evidence record that contradicts its entry;
- a duplicate identifier.

A missing independent record could still be supplied. An entry backed only
by the inventory or by its author is therefore `UNKNOWN`. That includes the
declaration-only inventory with no evidence records.

`UNKNOWN` also covers these cases:
- absent inputs;
- an empty selected scope;
- an exhausted member, entry, evidence-record, operation or item budget.

## Exclusions

`PASS` means only that the retained records meet the decidable form above.

It does not establish any of these:
- complete physical coverage. Devices absent from the inventory, and members
  the selected list omits, are outside the check.
- resource isolation, exclusive occupancy or non-interference;
- physical identity, identity-key normalisation, or the authenticity of any
  evidence record;
- that distinct producer labels name causally, organisationally or
  statistically independent producers;
- measured-boot attestation closure or hardware security module
  verification, which the slot rationale also names.

The result keeps each of these `NOT_ESTABLISHED`, together with the whole
closure tier, object-profile conformance, the legacy `HARDWARE-4.1` result,
privacy, consent, governance and security.

## Relation to other HARDWARE objectives

Current `HARDWARE-1.3` checks that a retained device inventory is consistent:
named supported kinds and typed capacities. It has no scope members, no
identity-key aliasing check, no coverage check and no producer independence.
`1.2` checks containment acyclicity, `2.1` checks reservation occupancy, and
`2.2` checks the measurement envelope.

`HARDWARE-3.1` checks qualified observation records, including measured-boot
replay. Its records are not consumed here. This objective adds the
inventory-level closure properties and does not repeat any of those
checks.

## Retention and invalidation

The certificate retains the request, policy digest, exact evidence bytes and
replay result. Public release of retained contents requires separate
disclosure authority.

Any of these changes invalidates the pinned mechanism and the certificate:
- the installed source of this checker or its shared helpers;
- this specification or `NAMESPACE_OBJECTS.md`;
- the selected scope or the retained bytes.

A digest or producer label is not proof that a device exists or was
independently inspected.
