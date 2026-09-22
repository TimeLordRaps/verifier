# Experimental bounded completeness

Verifier Standard (VSTD) bounded completeness is a direct-module version 0.1
experiment. It asks whether every member of one exact, externally
source-grounded finite denominator has a decisive, replayed disposition. It does
not claim an absolute universe or general logical completeness.

Terminology: JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit
(SHA-256); Unicode Transformation Format, 8-bit (UTF-8); identifier (ID).
Byte limits are measured in bytes; member counts and IDs are dimensionless.

## 1. Denominator and observations

`verifier-bounded-completeness-1` binds an inert profile ID, exact denominator
and observations byte references, one denominator-grounding declaration/receipt
and proposition, and a declarer coordinate. The supported profile is
`source-grounded-finite-disposition-coverage-v1`, retained as
`verifier/profiles/bounded-completeness-mechanism-1.json`.

`verifier-bounded-completeness-denominator-1` contains a subject ID and one to
256 members sorted by UTF-8 member-ID bytes. Each member binds a unique source-
grounding declaration and unique ground-proposition digest. The denominator is
not authoritative merely because this list is finite.

The denominator-grounding source must be distinct from the denominator bytes.
Its `JSON_POINTER_EQUALS` proposition must target `member_census_digest` and
equal the SHA-256 digest of canonical `{members, subject_id}` bytes. This closes
only the census proposition supplied by that independent source; it does not
establish that the source enumerates the real world completely.

`verifier-bounded-completeness-observations-1` binds the exact denominator digest,
same profile, procedure `source-grounding-replay-v1`, and a sorted unique list of
member IDs with grounding declarations and receipts. Missing denominator members
remain incomplete. An observation outside the denominator is invalid, not
ignored.

## 2. Assessment and result

The mechanism binds exact denominator and observation bytes, rechecks denominator
grounding, requires exact member-set correspondence, and independently replays
each member source-grounding receipt. A member is `DISPOSED` only when its
grounding result is decisively `ESTABLISHED` or `REFUTED`; `UNKNOWN` remains
`NOT_CHECKED`, and malformed evidence remains `INVALID`.

The portable `verifier-bounded-completeness-receipt-1` retains six separate check
states, one assessment for every denominator member, exact resource accounting,
the checker and profile coordinate, sorted reasons, and residual obligations.
Its result is:

- `COMPLETE` only when the supported profile, exact bindings, externally grounded
  denominator census, exact member set, and every member replay all pass;
- `INCOMPLETE` when the grounded denominator is available but some declared
  member lacks a decisive disposition;
- `UNKNOWN` when required evidence, profile support, or bounded work is
  unavailable;
- `INVALID` for malformed, substituted, circular, extra-member, or contradictory
  evidence.

Evidence-budget exhaustion is `UNKNOWN`, never `INCOMPLETE`. Structural receipt
decoding rejects a forged `COMPLETE` whose carried checks, members, reasons, or
effectiveness counters contradict completeness. Recheck then rebuilds the full
receipt and requires exact byte equality.

Public JSON Schema validation is structural only. It cannot establish canonical
ordering, source-grounded denominator authority, member disposition, profile
support, effectiveness, or receipt reproduction.

## 3. Bounds and claim boundary

Records are at most 262,144 bytes, each selected object at most 1,048,576 bytes,
aggregate retained evidence at most 8,388,608 bytes, decoded depth at most 24,
decoded values at most 16,384, and denominator members at most 256.

`COMPLETE` means only complete decisive disposition of that exact finite,
source-grounded denominator under this profile. It does not establish an absolute
universe, denominator authority, general semantic completeness, general logical
decidability, producer independence, truth of every proposition, or a numbered
VSTD profile.

