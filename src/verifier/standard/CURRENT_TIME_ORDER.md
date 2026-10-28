# Current TIME retained order

Status: experimental, versioned current-object objective. Verifier Standard
(VSTD) defines the claim language; the Python module is one reference checker.
JavaScript Object Notation (JSON) gives canonical retained bytes and Secure Hash
Algorithm 256-bit (SHA-256) names their commitments. Every `_us` value is an
integer number of microseconds on one **declared** clock. A sample count is
dimensionless. No physical clock, shared epoch or elapsed real time is proved.

The pair `verifier-current-object-obligations-1` / `TIME-2.1` selects one
bounded temporal-dynamics proposition. It does not rename the repository's
`TIME.md` contradiction register or convert current `TIME-1.1` typed structural
facets into temporal semantics. The objective is new current registration;
the coordinate without its semantic version is insufficient to select it.

The proposition is that an externally selected exact TIME namespace record
occurs once in a selected finite typed collection, its digest and complete
collection commitment reproduce, and its retained nonempty sample sequence
rehashes and has unique bounded identifiers and nondecreasing integer instants
inside the declared half-open span `[span_start_us, span_end_us)`. Both span
ends are nonnegative integers no greater than 2^53-1; the start is strictly
less than the end. Equal sample instants are allowed and express no causal
ordering. The payload admits exactly `scope`, `clock`, `unit`, both span ends
and `samples_digest`; `scope=retained-declared-clock-order` and
`unit=microsecond`. An admitted clock is only a nonempty label of at most 256
characters. The retained input has exactly one `samples` list with records
`{id, at_us}`. A retained byte bundle, object and policy are separately
selected and bounded.

`PASS` means only this finite declared-clock consistency proposition replayed.
`FAIL` means the selected retained records contradict it. `UNKNOWN` means
required retained evidence, a nonempty sample sequence or checking capacity is
unavailable. Malformed or substituted requests, policies and certificates are
rejected before a computational verdict. The checker replays the exact retained
bytes and selected policy; source/specification changes invalidate its digest.

The trust-root labels select a policy but authenticate no clock or observer.
Physical-clock authenticity, calibration, cross-clock synchronization, actual
event causality, EVENT validity, elapsed physical duration, privacy, consent,
governance, security and whole TIME tier conformance remain
`NOT_ESTABLISHED`. This check cannot establish decentralized synchronization
or authorize scheduling, spending or publication.

The installed descriptor also binds `retained_selection.py`, the shared plain-value
request and policy capture helper. Native evaluation remains specific to this
objective; shared selection infrastructure does not establish its proposition.

Retained-reader capacity availability is a distinct boundary. Decoder recursion,
overflow and explicitly unavailable checking capacity raise `TimeOrderUnavailable`,
an `OSError` subtype, and current public routes preserve UNKNOWN. This capacity
category does not establish replay or refute the selected predicate. Demonstrated
selection substitutions, malformed semantic bytes and exact-reconstruction
contradictions remain `TimeOrderError` refusals; ordinary `ValueError` is never
downgraded to unavailability. Evaluator capacity exhaustion remains UNKNOWN.
An already observed FAIL is retained; no uninspected later predicate is certified.
Source/mechanism changes require freshly selected policies and certificates;
previous exact bytes and their genuine verdicts are not rewritten.
