# Current HARDWARE-3.1 retained qualified substrate observations

Status: experimental, versioned current-object objective. Verifier Standard
(VSTD) specifies the claim; this Python mechanism is one reference checker.
JavaScript Object Notation (JSON) gives canonical retained bytes, and Secure
Hash Algorithm 256-bit (SHA-256) names commitments. Instants and freshness
bounds are integer microseconds, from 0 through `2^53-1`, on one named
clock. Platform configuration register (PCR) values and event digests are
32-byte SHA-256 outputs written as 64 lowercase hexadecimal characters.
Register indices (0 through 65535), counts and checking budgets are
dimensionless.

## Governing row

`DOMAIN_OBLIGATIONS.md` names this coordinate:

> HARDWARE-3.1 | Physical substrate observations | Device identity, physical
> capacity, calibration, sensor accuracy and live availability require
> qualified observations with explicit freshness and trust roots;
> declarations alone remain UNKNOWN.

That row states a physical requirement. This objective does not discharge it.
It mechanizes only the decidable record-level part the row imposes. Every
retained substrate claim must carry a retained observation record whose
explicit freshness interval contains the selected instant and whose
trust-root reference is admitted. Where a measured-boot record is used, its
event log must replay to its quote. A declaration without such a record
stays `UNKNOWN` and never `PASS`, as the row requires.

## Selection and proposition

The pair `verifier-current-object-obligations-1` / `HARDWARE-3.1` selects
this objective. A coordinate without its semantic version selects nothing,
and the legacy domain-certificate meaning of `HARDWARE-3.1` is unchanged.

The external request selects:
- one exact HARDWARE namespace record and its finite typed collection;
- an evaluation clock label and an evaluation instant (`evaluation_at_us`);
- the retained evidence bytes, the policy and finite limits.

The policy's sorted trust-root labels are the **admitted set**. The record's
payload is exactly `scope=retained-hardware-records`, `claims_digest` and
`observations_digest`. The retained `claims` and `observations` must rehash to
those commitments.

Each claim has exactly three fields:
- `claim_id`, unique;
- `category`, one of the five the row names: `device_identity`,
  `physical_capacity`, `calibration`, `sensor_accuracy` or
  `live_availability`;
- `value`, any canonical JSON value.

The label is carried and counted. It never changes the check.

Each observation record has exactly these fields: `observation_id` (unique),
`claim_id`, `value`, `clock`, `fresh_from_us`, `fresh_until_us`, `trust_root`
and `measured_boot` (null or `{"events": [...]}`).

A record **qualifies** when three things hold:
- its clock equals the selected clock;
- its closed interval `[fresh_from_us, fresh_until_us]` contains the
  selected instant;
- its trust-root label is in the admitted set.

`PASS` requires all of these:
- every retained claim has at least one qualifying record;
- every qualifying record's value is byte-for-byte the declared canonical
  value. There is no tolerance, unit conversion or normalisation, so `true`
  and `1` differ.

**Measured-boot records.** For each one, the record's `value` must be a
nonempty, strictly increasing list of `{register, value}` quotes. Each
`{register, event, event_digest}` event must extend a quoted register, and
its digest must equal the SHA-256 of its canonical-base64 bytes. Starting
from 32 zero bytes per quoted register, the log is replayed in order with
`PCR_new = SHA-256(PCR_old || event_digest)`. The replay must reproduce
every quoted value. A quoted register with no event stays all zero.

## FAIL versus UNKNOWN

`FAIL` is reserved for counterexamples that no added observation record could
repair:
- a qualifying record that contradicts its claim;
- a record that names no retained claim;
- an inverted freshness interval;
- a duplicate identifier;
- a measured-boot record whose event bytes, digests or register order do not
  replay to its own quote.

Internal consistency does not depend on time, so it is checked on every
record, including a stale one. Agreement with the declaration is checked only
where a record qualifies. A stale, future, foreign-clock or unadmitted record
therefore leaves its claim unqualified rather than refuted.

`UNKNOWN` covers these cases:
- a claim with no qualifying record, which includes declarations alone;
- an empty claim set;
- absent inputs;
- an exhausted claim, observation, event, event-byte, operation or item
  budget.

## Exclusions

`PASS` means only that the retained records meet the decidable form the row
names, at the selected instant.

It does not establish any of these:
- device identity, physical capacity, calibration, sensor accuracy or live
  availability as physical facts;
- that any observation, quote or event was produced or signed by the trust
  root it names, because the label is compared and never verified;
- event-log completeness, firmware correctness or event-format conformance;
- clock authenticity or synchronisation.

The result keeps each of these `NOT_ESTABLISHED`, together with the whole
statics tier, object-profile conformance, the legacy `HARDWARE-3.1` result,
privacy, consent, governance and security.

## Relation to other HARDWARE objectives

Current `HARDWARE-1.3` checks retained device-inventory consistency. `1.2`
checks containment topology. `2.1` checks declared reservation occupancy
against declared capacity; per its row, that "is not admission of physical
capacity". `2.2` checks that integer observations lie inside declared
capacity, and its row notes that observation authenticity needs a separate
qualified mechanism.

None of those checks freshness, admitted trust-root references or
measured-boot replay, and this objective does not repeat their arithmetic. It
also does not supply the signature verification that `2.2` defers.

Measured-boot replay appears here as one observation form, because the slot
rationale names measured boot constants. Attestation closure stays outside
`HARDWARE-4.1`, which is inventory closure.

## Retention and invalidation

The certificate retains the request, policy digest, exact evidence bytes and
replay result. Public release of retained contents requires separate
disclosure authority.

Any of these changes invalidates the pinned mechanism and the certificate:
- the installed source of this checker or its shared helpers;
- this specification or `NAMESPACE_OBJECTS.md`;
- the selected instant, clock or trust-root set;
- the retained bytes.

A digest or trust-root label is not proof that a device exists or was
observed.
