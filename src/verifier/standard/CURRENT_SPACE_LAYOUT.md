# Current SPACE retained logical byte layout

Status: experimental, versioned current-object objective. Verifier Standard
(VSTD) defines the claim language; the Python module is one reference checker.
JavaScript Object Notation (JSON) gives canonical retained bytes and Secure Hash
Algorithm 256-bit (SHA-256) names commitments. Offsets, extents and alignments
are measured in bytes. Partition counts and checker budgets are dimensionless.

The pair `verifier-current-object-obligations-1` / `SPACE-3.1` selects one
bounded statics proposition. Current `SPACE-1.1` checks declared namespace
structure only. This new registration does not claim that the full SPACE
statics tier is closed or that any host allocated or isolated these addresses.

The proposition is that an externally selected exact SPACE namespace record
occurs once in a selected finite typed collection, its digest and complete
collection commitment reproduce, and a retained nonempty partition sequence
rehashes. The payload has exactly `scope`, `unit`, `extent_bytes` and
`partitions_digest`; `scope=retained-logical-byte-partitions` and `unit=byte`.
The extent is a positive integer at most 2^53-1 bytes. Each retained partition
has exactly `{id, start_byte, end_byte, alignment_bytes}`. Its identifier is
unique, nonempty and at most 256 characters. The half-open interval
`[start_byte, end_byte)` uses nonnegative integers at most 2^53-1, has positive
length, and ends no later than the declared extent. `alignment_bytes` is a
positive power of two and divides `start_byte`. Partition order in the
retained list does not affect nonoverlap; the checker sorts a bounded copy by
start offset. Gaps and adjacent intervals are allowed. Neither the extent nor
these offsets represent a physical address without separately qualified
evidence.

`PASS` means only that this finite declared logical layout reproduces.
`FAIL` means the selected retained records contradict the claim, including
overlap, out-of-range values, invalid alignment or duplicate identifiers.
`UNKNOWN` means required retained evidence, a nonempty partition sequence or
selected checking capacity is unavailable. Malformed or substituted requests,
policies and certificates are rejected before a computational verdict. The
rechecker reruns the exact retained bytes and selected policy; source and
specification changes invalidate the selected mechanism digest.

Trust-root labels select a policy but do not authenticate an allocator.
Actual memory, storage or network allocation; protection from overlap in a
running process; physical containment; access-control isolation; privacy,
consent, governance, security; and whole SPACE tier conformance remain
`NOT_ESTABLISHED`. This check grants no scheduling, spending or publication
authority.

The installed descriptor also binds `retained_selection.py`, the shared plain-value
request and policy capture helper. Native evaluation remains specific to this
objective; shared selection infrastructure does not establish its proposition.
